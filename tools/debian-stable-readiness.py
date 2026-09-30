#!/usr/bin/env python3
"""Read-only, fail-closed preflight of the pinned Debian stable acceptance input."""

import argparse
import base64
import datetime
import hashlib
import json
import lzma
import os
import pathlib
import platform
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PIN = ROOT / "tools/fixtures/debian-stable-readiness-v1.json"
MAX_RELEASE_BYTES = 256 * 1024
MAX_KEY_BYTES = 32 * 1024
MAX_INDEX_BYTES = 20 * 1024 * 1024
MAX_PACKAGES_BYTES = 128 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url, limit):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("only HTTPS pin sources are permitted")
    with urllib.request.urlopen(url, timeout=90) as response:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise ValueError("pin source redirected away from HTTPS")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("pin source exceeds the input bound")
    return data


def decode_key(armor, pin):
    if sha256(armor) != pin["armor_sha256"]:
        raise ValueError("reviewed signer armor digest changed")
    lines = armor.decode("ascii").splitlines()
    if lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----" or lines[-1] != "-----END PGP PUBLIC KEY BLOCK-----":
        raise ValueError("reviewed signer is not an armored public key")
    begin = lines.index("") + 1
    end = next(i for i in range(begin, len(lines)) if lines[i].startswith(("=", "-----END")))
    key = base64.b64decode("".join(lines[begin:end]), validate=True)
    if sha256(key) != pin["binary_sha256"]:
        raise ValueError("reviewed binary keyring digest changed")
    if len(key) < 4 or key[0] not in (0x98, 0x99):
        raise ValueError("reviewed signer does not start with a v4 primary key")
    size_bytes = 1 if key[0] == 0x98 else 2
    size = int.from_bytes(key[1 : 1 + size_bytes], "big")
    body = key[1 + size_bytes : 1 + size_bytes + size]
    if len(body) != size or body[0] != 4:
        raise ValueError("reviewed signer has malformed v4 key material")
    fingerprint = hashlib.sha1(b"\x99" + size.to_bytes(2, "big") + body).hexdigest()
    if fingerprint != pin["primary_fingerprint"]:
        raise ValueError("reviewed signer fingerprint changed")
    return key


def release_index(armored, pin, architecture, now):
    if sha256(armored) != pin["release"]["inrelease_sha256"]:
        raise ValueError("pinned InRelease digest changed")
    clear = armored.split(b"-----BEGIN PGP SIGNATURE-----", 1)[0].decode("utf-8")
    fields = {}
    for line in clear.splitlines():
        if line and not line[0].isspace() and ": " in line:
            name, value = line.split(": ", 1)
            fields[name] = value
    for field, value in (
        ("Origin", "Debian"),
        ("Suite", "stable"),
        ("Codename", pin["suite"]),
        ("Date", pin["release"]["date"]),
    ):
        if fields.get(field) != value:
            raise ValueError(f"signed Release {field} changed")
    if fields.get("Valid-Until") != pin["release"]["valid_until"]:
        raise ValueError("signed Release Valid-Until changed")
    if pin["component"] not in fields.get("Components", "").split():
        raise ValueError("signed Release no longer contains the selected component")
    date = datetime.datetime.strptime(fields["Date"], "%a, %d %b %Y %H:%M:%S %Z").replace(
        tzinfo=datetime.timezone.utc
    )
    maximum_age = pin["release"]["maximum_release_age_seconds"]
    if pin["release"]["freshness_mode"] != "allow_missing_valid_until_with_max_age_seconds" or maximum_age > 31 * 86400:
        raise ValueError("reviewed freshness policy changed")
    if date > now + datetime.timedelta(minutes=5):
        raise ValueError("signed Release is dated in the future")
    valid_until = fields.get("Valid-Until")
    expiry = (
        datetime.datetime.strptime(valid_until, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=datetime.timezone.utc)
        if valid_until is not None
        else date + datetime.timedelta(seconds=maximum_age)
    )
    if now > expiry:
        raise ValueError("signed Release is not fresh under its bounded policy")
    index = pin["architectures"][architecture]
    sections = {}
    section = None
    for line in clear.splitlines():
        if line in ("MD5Sum:", "SHA256:", "SHA512:"):
            section = line[:-1]
        elif line and not line[0].isspace():
            section = None
        elif section and line.strip().endswith(" " + index["index_path"]):
            tokens = line.split()
            if len(tokens) != 3:
                raise ValueError("signed index checksum line is malformed")
            sections[section] = (tokens[0], int(tokens[1]))
    if sections.get("SHA256") != (index["index_sha256"], index["index_size"]):
        raise ValueError("signed index SHA256 or size differs from the reviewed pin")
    if "SHA512" in sections:
        digest, size = sections["SHA512"]
        if len(digest) != 128 or any(char not in "0123456789abcdef" for char in digest) or size != index["index_size"]:
            raise ValueError("signed index SHA512 identity is malformed")
    return sections


def index_counts(compressed, index, published_sha512=None):
    if len(compressed) != index["index_size"] or sha256(compressed) != index["index_sha256"]:
        raise ValueError("Packages.xz does not match the signed Release identity")
    if published_sha512 is not None and hashlib.sha512(compressed).hexdigest() != published_sha512:
        raise ValueError("Packages.xz does not match the signed Release SHA512")
    decompressor = lzma.LZMADecompressor()
    packages = decompressor.decompress(compressed, max_length=MAX_PACKAGES_BYTES + 1)
    if len(packages) > MAX_PACKAGES_BYTES or not decompressor.eof or decompressor.unused_data:
        raise ValueError("Packages.xz exceeded bounds or was incomplete")
    records = [item for item in packages.split(b"\n\n") if item.startswith(b"Package: ")]
    sha256_count = sum(b"\nSHA256: " in item for item in records)
    sha512_count = sum(b"\nSHA512: " in item for item in records)
    if len(records) != index["package_records"] or sha256_count != len(records):
        raise ValueError("Packages record count or published SHA256 set changed")
    for record in records:
        digest = record.split(b"\nSHA256: ", 1)[1].split(b"\n", 1)[0]
        if len(digest) != 2 * hashlib.sha256().digest_size or any(byte not in b"0123456789abcdef" for byte in digest):
            raise ValueError("Packages record has a malformed published SHA256")
    return len(records), sha256_count, sha512_count


def archive_binding(index_publishes_sha512, records, sha512_count):
    """Classifies the signed archive authority an exact v3 lock may record.

    Every record already carries a SHA256 covered by the signed Release via
    the verified index identity. Per the #261 decision that signed SHA256 is
    the archive binding when SHA512 is absent; the lock then records a locally
    derived SHA512 with explicit `derived_from_signed_sha256` provenance.
    """
    if index_publishes_sha512 and sha512_count == records:
        return "eligible_signed_sha512", "published_digests"
    if sha512_count == 0:
        return "eligible_signed_sha256_derived_sha512", "signed_sha256_derived_sha512"
    return "refused_partial_published_sha512", None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debz", type=pathlib.Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--workspace", type=pathlib.Path, required=True)
    args = parser.parse_args()
    native = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if native != args.architecture:
        raise ValueError(f"native {args.architecture} runner required (observed {platform.machine()})")
    workspace = args.workspace.absolute()
    scratch = ROOT / ".tmp"
    if scratch.is_symlink() or workspace.parent.resolve() != scratch.resolve() or workspace.exists() or workspace.is_symlink():
        raise ValueError("workspace must be a new direct child of this checkout's .tmp directory")
    scratch.mkdir(mode=0o700, exist_ok=True)
    if not scratch.is_dir():
        raise ValueError("disposable .tmp namespace is not a directory")
    binary = args.debz.resolve(strict=True)
    if not binary.is_file():
        raise ValueError("debz executable is not a regular file")
    pin = json.loads(PIN.read_text())
    workspace.mkdir(mode=0o700)
    for name in ("root", "cache", "state", "evidence"):
        (workspace / name).mkdir(mode=0o700)
    key = decode_key(fetch(pin["signer"]["url"], MAX_KEY_BYTES), pin["signer"])
    keyring = ROOT / ".tmp/debian-261-trixie-release-13.gpg"
    if not keyring.exists() and not keyring.is_symlink():
        try:
            descriptor = os.open(keyring, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as output:
                output.write(key)
    if keyring.is_symlink() or not keyring.is_file() or keyring.read_bytes() != key:
        raise ValueError("stable reviewed keyring path differs from the pinned official key")
    source = workspace / "debian.sources"
    source.write_text(
        f"Types: deb\nURIs: {pin['snapshot_uri']}\nSuites: {pin['suite']}\n"
        f"Components: {pin['component']}\nArchitectures: {args.architecture}\nSigned-By: {keyring}\n"
    )
    config = workspace / "debian.json"
    config.write_text(json.dumps({
        "source_path": str(source),
        "priority": 500,
        "default_release": pin["suite"],
        "immutable": True,
        "freshness": {
            "mode": pin["release"]["freshness_mode"],
            "maximum_release_age_seconds": pin["release"]["maximum_release_age_seconds"],
        },
    }, separators=(",", ":")) + "\n")
    result = subprocess.run([
        str(binary), "refresh",
        "--install-root", str(workspace / "root"),
        "--cache-path", str(workspace / "cache"),
        "--state-path", str(workspace / "state"),
        "--architecture", args.architecture,
        "--config", str(config),
        "--keyring", str(keyring),
        "--assume-yes", "--deadline-ms", "300000", "--json",
    ], capture_output=True, text=True, timeout=360, check=False)
    (workspace / "evidence" / "refresh.json").write_text(result.stdout)
    (workspace / "evidence" / "refresh.stderr").write_text(result.stderr)
    if result.returncode != 0 or json.loads(result.stdout)["exit_status"] != 0:
        raise ValueError(f"authenticated debz refresh refused (exit {result.returncode}): {result.stdout[:512]}")
    base = f"{pin['snapshot_uri']}/dists/{pin['suite']}/"
    armored = fetch(base + "InRelease", MAX_RELEASE_BYTES)
    sections = release_index(
        armored, pin, args.architecture, datetime.datetime.now(datetime.timezone.utc)
    )
    index = pin["architectures"][args.architecture]
    compressed = fetch(base + index["index_path"], MAX_INDEX_BYTES)
    records, sha256_count, sha512_count = index_counts(
        compressed, index, sections.get("SHA512", (None,))[0]
    )
    if any((workspace / "root").iterdir()):
        raise ValueError("read-only signed refresh unexpectedly mutated the empty root")
    report = {
        "schema": pin["schema"],
        "architecture": args.architecture,
        "snapshot_uri": pin["snapshot_uri"],
        "suite": pin["suite"],
        "signer_primary_fingerprint": pin["signer"]["primary_fingerprint"],
        "signed_by_path": str(keyring),
        "keyring_sha256": sha256(key),
        "source_sha256": sha256(source.read_bytes()),
        "config_sha256": sha256(config.read_bytes()),
        "program_sha256": sha256(binary.read_bytes()),
        "inrelease_sha256": sha256(armored),
        "index_sha256": sha256(compressed),
        "index_published_sha512": "SHA512" in sections,
        "package_records": records,
        "sha256_package_records": sha256_count,
        "sha512_package_records": sha512_count,
        "root_mutated": False,
        "exact_lock_published": False,
    }
    report["status"], report["archive_binding"] = archive_binding("SHA512" in sections, records, sha512_count)
    (workspace / "evidence" / "readiness.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    if report["archive_binding"] is None:
        print("refusing a repository whose signed index and package records publish SHA512 only partially", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, UnicodeError, lzma.LZMAError, subprocess.TimeoutExpired) as error:
        print(f"debian-stable-readiness: {error}", file=sys.stderr)
        sys.exit(2)
