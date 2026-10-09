#!/usr/bin/env python3
"""Probe, diff, record and check the reviewed real-snapshot pin manifest.

The tool never authenticates repository metadata itself. ``probe`` drives a
``debz`` binary (``refresh``, ``plan --lock-output`` and ``download
--lock-input``) and binds every Release it fetches to public refresh evidence,
requiring contributing exact locks to agree. Package members are read only from
CAS objects that ``debz download`` verified, after re-hashing them against the
lock. ``check`` is offline and is run in CI.
"""

from __future__ import annotations

import argparse
import calendar
import copy
import difflib
import email.utils
import email.parser
import email.policy
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path("tools/fixtures/real-snapshot/pin-v1.json")
MANIFEST_SCHEMA = "io.github.cataggar.debz.real-snapshot-pin.v1"
REPORT_SCHEMA = "io.github.cataggar.debz.real-snapshot-repin-report.v1"
EVIDENCE_SCHEMA = "io.github.cataggar.debz.real-snapshot-source-evidence.v1"
DEFAULT_EVIDENCE = "tools/fixtures/real-snapshot/prestate-sources-v1.zip"
SETTLE_SECONDS = 24 * 60 * 60
WITNESS_WINDOW_SECONDS = 48 * 60 * 60
MAXIMUM_RELEASE_AGE_SECONDS = 31 * 24 * 60 * 60
DEBZ_DEADLINE_MS = "300000"
DEBZ_LOCK_WAIT_MS = "30000"
MAXIMUM_RELEASE_BYTES = 16 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024
MAXIMUM_MEMBER_BYTES = 64 * 1024 * 1024
MAXIMUM_TAR_BYTES = 128 * 1024 * 1024
MAXIMUM_TAR_MEMBERS = 100000
MAXIMUM_EVIDENCE_BYTES = 64 * 1024 * 1024
MAXIMUM_EVIDENCE_FILES = 256
FETCH_TIMEOUT_SECONDS = 120
SHA256_HEX = hashlib.sha256().digest_size * 2
SHA512_HEX = hashlib.sha512().digest_size * 2
DIGEST_ALGORITHMS = {"sha256": SHA256_HEX, "sha512": SHA512_HEX}
TIMESTAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")
REVIEW_REFERENCE = re.compile(r"(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#[1-9][0-9]*")
FINGERPRINT = re.compile(r"[0-9a-f]{40}")
IDENTITY_ID = re.compile(r"[a-z]+:[A-Za-z0-9][A-Za-z0-9+.:/_@-]*")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*")
HEX_LITERAL = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-f]{%d}|[0-9a-f]{%d})(?![0-9A-Za-z])" % (SHA512_HEX, SHA256_HEX))
QUOTED_HEX_LITERAL = re.compile(r'"((?:[0-9a-f]{%d}|[0-9a-f]{%d}))"' % (SHA512_HEX, SHA256_HEX))
KINDS = ("script", "tool_file", "archive", "prestate")
ROLES = ("bounded", "frozen", "witness")
# How each pocket's fetched Release is tied to what debz authenticated, per
# architecture. `exact_lock`: an exact lock names the repository with the same
# cleartext release_sha256. `refresh_identity`: public refresh evidence binds
# even a quiet pocket. `refresh_only` is retained ONLY for historical reports
# made by debz versions that did not expose that evidence.
BINDINGS = ("exact_lock", "refresh_identity", "refresh_only")
CONSUMER_FORMS = ("hex", "zig_bytes", "fixture", "shell")
IDENTITY_COORDINATES = ("digest", "digest_size", "url", "version", "size", "member")
SNAPSHOT_COORDINATES = ("uri", "suite", "witness_suites", "release_sha256")
STATUSES = ("unchanged", "provenance-only", "changed", "missing")
SNAPSHOT_URI = re.compile(r"snapshot\.ubuntu\.com/ubuntu/([0-9]{8}T[0-9]{6}Z)")
SNAPSHOT_CONSTANT = re.compile(
    r"(?m)^\s*(?:pub\s+)?const\s+(snapshot_[a-z0-9_]*sha256)\b[^=]*=\s*"
)
ZIG_BYTE = re.compile(r"0x([0-9a-fA-F]{2})")
DEBZ_SNAPSHOT_CONSTANT_SOURCES = (
    "src/maintainer_script.zig",
    "src/native_alternatives.zig",
    "src/native_unpack.zig",
)
SNAPSHOT_INPUT_ENTRY = re.compile(
    r'\.path = "(?P<path>[^"]+)",\s*(?:\.mode = 0o(?P<leading_mode>[0-7]+),\s*)?'
    r'\.size = (?P<size>[0-9]+),\s*(?:\.mode = 0o(?P<mode>[0-7]+),\s*)?'
    r'\.sha256 = "(?P<hex>[0-9a-f]+)"'
)
SNAPSHOT_ARCHIVE_ENTRY = re.compile(
    r'\.package\s*=\s*\.\{\s*\.name\s*=\s*"(?P<package>[^"]+)",\s*'
    r'\.version\s*=\s*"(?P<version>[^"]+)",\s*\.architecture\s*=\s*"(?P<arch>[^"]+)"\s*\},\s*'
    r'\.size\s*=\s*(?P<size>[0-9]+),\s*\.sha512\s*=\s*"(?P<hex>[0-9a-f]{128})"'
)
FIXTURE_GLOB = "src/fixtures/ubuntu-*"
PIN_SCRIPT_GLOB = "tools/real-snapshot-*.sh"
PROTECTED_STAGE_SCRIPT = "tools/real-snapshot-reference-protected-stage.sh"
REFERENCE_LAUNCHER = "tools/real-snapshot-reference-launcher.zig"
SCRIPT_BINDING_ENTRY = re.compile(
    r'\.\{\s*\.name\s*=\s*"(?P<name>[a-z0-9+.-]+)",\s*'
    r'\.version\s*=\s*"(?P<version>[^"]+)",\s*'
    r'\.size\s*=\s*(?P<size>[0-9]+),\s*'
    r'\.digest\s*=\s*"(?P<digest>[0-9a-f]{%d})"\s*\}' % SHA256_HEX
)
STAGE_PROFILE_LOOP = re.compile(r"(?m)^\s*for\s+profile\s+in\s+(?P<body>[^;\n]+);\s*do")
STAGE_WITNESS_ARRAY = re.compile(
    r"(?ms)^\s*readonly\s+snapshot_witness_suites=\((?P<body>[^)]*)\)"
)

PROFILES: dict[str, dict] = {
    "ubuntu-stonking": {
        "uri_root": "https://snapshot.ubuntu.com/ubuntu",
        "component": "main",
        "architectures": ["amd64", "arm64"],
        "keyring": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        "signer": "f6ecb3762474eda9d21b7022871920d1991bc93c",
        "request": "ubuntu-minimal",
        "pockets": [{"suite": "stonking", "role": "bounded"}],
    },
    "ubuntu-resolute": {
        "uri_root": "https://snapshot.ubuntu.com/ubuntu",
        "component": "main",
        "architectures": ["amd64", "arm64"],
        "keyring": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        "signer": "f6ecb3762474eda9d21b7022871920d1991bc93c",
        "request": "ubuntu-minimal",
        "pockets": [
            {"suite": "resolute", "role": "frozen"},
            {"suite": "resolute-updates", "role": "witness"},
            {"suite": "resolute-security", "role": "witness"},
        ],
    },
}


class RepinError(Exception):
    """A refusal. The message names the failed check."""


def fail(message: str) -> None:
    raise RepinError(message)


# Time.


def timestamp_seconds(text: str) -> int:
    if not isinstance(text, str) or not TIMESTAMP.fullmatch(text):
        fail(f"snapshot timestamp must be YYYYMMDDTHHMMSSZ: {text!r}")
    try:
        parsed = time.strptime(text, "%Y%m%dT%H%M%SZ")
    except ValueError:
        fail(f"invalid snapshot timestamp: {text!r}")
    return calendar.timegm(parsed)


def format_timestamp(seconds: int) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(seconds))


def default_timestamp(now: int) -> str:
    settled = now - SETTLE_SECONDS
    return format_timestamp(settled - settled % 86400)


def validate_timestamp(text: str, now: int, pinned: str | None) -> int:
    """Checks probe rule 1: T is settled and not older than the current pin."""
    seconds = timestamp_seconds(text)
    if now - seconds < SETTLE_SECONDS:
        fail(
            f"snapshot {text} is less than 24 hours old; snapshot timestamps are "
            "mutable until the service has published every pocket for that time"
        )
    if pinned is not None and seconds < timestamp_seconds(pinned):
        fail(f"snapshot {text} is older than the current pin {pinned}")
    return seconds


def release_time(value: str, field: str) -> int:
    parsed = email.utils.parsedate_tz(value)
    if parsed is None or not re.fullmatch(
        r"[A-Z][a-z]{2}, [0-9]{1,2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} (?:UTC|GMT|\+0000)",
        value,
    ):
        fail(f"Release {field} is not an RFC 2822 UTC time: {value!r}")
    return email.utils.mktime_tz(parsed)


# Digests.


def tagged(algorithm: str, data: bytes) -> str:
    return f"{algorithm}:{hashlib.new(algorithm, data).hexdigest()}"


def parse_tagged(text: object, algorithms: tuple[str, ...] = ("sha256", "sha512")) -> tuple[str, str]:
    if not isinstance(text, str) or ":" not in text:
        fail(f"digest must be algorithm-tagged: {text!r}")
    algorithm, value = text.split(":", 1)
    if algorithm not in algorithms or algorithm not in DIGEST_ALGORITHMS:
        fail(f"unsupported digest algorithm in {text!r}")
    if len(value) != DIGEST_ALGORITHMS[algorithm] or not re.fullmatch(r"[0-9a-f]+", value):
        fail(f"digest must be lowercase hexadecimal of the algorithm's length: {text!r}")
    if set(value) == {"0"}:
        fail(f"digest must not be zero: {text!r}")
    return algorithm, value


def lock_digest(value: str, algorithm: str = "sha256") -> str:
    text = f"{algorithm}:{value}"
    parse_tagged(text, (algorithm,))
    return text


# InRelease.


def in_release_cleartext(data: bytes) -> bytes:
    """Returns the display cleartext, as debz records it in exact locks.

    The result is the text between the armor header block and the signature,
    with dash escapes removed and the original line endings kept.
    """
    lines = data.splitlines(keepends=True)
    if not lines or lines[0].rstrip(b"\r\n") != b"-----BEGIN PGP SIGNED MESSAGE-----":
        fail("InRelease does not start with a cleartext signature header")
    index = 1
    while index < len(lines) and lines[index].rstrip(b"\r\n") != b"":
        index += 1
    if index >= len(lines):
        fail("InRelease has no blank line after its armor headers")
    index += 1
    output = bytearray()
    while index < len(lines):
        line = lines[index]
        text = line.rstrip(b"\r\n")
        if text == b"-----BEGIN PGP SIGNATURE-----":
            return bytes(output)
        if not line.endswith(b"\n"):
            fail("InRelease cleartext is truncated")
        ending = line[len(text):]
        if text.startswith(b"- "):
            text = text[2:]
        elif text.startswith(b"-"):
            fail("InRelease cleartext has an invalid dash escape")
        output += text + ending
        index += 1
    fail("InRelease has no signature block")
    raise AssertionError


def release_fields(cleartext: bytes) -> dict:
    fields: dict[str, str] = {}
    hash_fields: list[str] = []
    current = None
    for raw in cleartext.decode("utf-8").splitlines():
        if not raw:
            break
        if raw[0] in " \t":
            if current is None:
                fail("Release continuation line without a field")
            continue
        if ":" not in raw:
            fail(f"invalid Release line: {raw!r}")
        name, value = raw.split(":", 1)
        if name in fields:
            fail(f"duplicate Release field {name}")
        fields[name] = value.strip()
        current = name
        if name in ("MD5Sum", "SHA1", "SHA256", "SHA512"):
            hash_fields.append(name)
    if "Date" not in fields:
        fail("Release has no Date")
    return {
        "suite": fields.get("Suite"),
        "codename": fields.get("Codename"),
        "date": fields["Date"],
        "date_unix": release_time(fields["Date"], "Date"),
        "valid_until": fields.get("Valid-Until"),
        "valid_until_unix": (
            release_time(fields["Valid-Until"], "Valid-Until") if "Valid-Until" in fields else None
        ),
        "hash_fields": hash_fields,
    }


def pocket_deadline(fields: dict) -> int:
    if fields["valid_until_unix"] is not None:
        return fields["valid_until_unix"]
    return fields["date_unix"] + MAXIMUM_RELEASE_AGE_SECONDS


def check_pocket_dates(pockets: list[dict], snapshot: int) -> int:
    """Checks probe rule 4 and returns the admission deadline."""
    for pocket in pockets:
        if pocket["date_unix"] > snapshot:
            fail(f"{pocket['suite']} Date {pocket['date']} is after the snapshot time")
        if pocket["role"] == "witness" and snapshot - pocket["date_unix"] > WITNESS_WINDOW_SECONDS:
            fail(
                f"witness {pocket['suite']} Date {pocket['date']} is more than 48 hours "
                "before the snapshot time; the snapshot service may be stale"
            )
        if pocket["role"] == "frozen" and pocket["valid_until"] is not None:
            fail(f"frozen pocket {pocket['suite']} carries Valid-Until")
    frozen = [pocket for pocket in pockets if pocket["role"] == "frozen"]
    if frozen:
        witnesses = [pocket for pocket in pockets if pocket["role"] == "witness"]
        if not witnesses:
            fail("a frozen pocket requires at least one witness pocket")
        for pocket in frozen:
            pocket["deadline"] = min(pocket_deadline(witness) for witness in witnesses)
    for pocket in pockets:
        if pocket["role"] != "frozen":
            pocket["deadline"] = pocket_deadline(pocket)
    return min(pocket["deadline"] for pocket in pockets)


# Packages.


def ar_members(data: bytes) -> dict[str, bytes]:
    if len(data) > MAXIMUM_ARCHIVE_BYTES:
        fail("package is too large")
    if not data.startswith(b"!<arch>\n"):
        fail("package is not an ar archive")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            fail("package has a malformed ar header")
        try:
            name = header[:16].decode("ascii").strip().rstrip("/")
            size_text = header[48:58].decode("ascii").strip()
        except UnicodeError:
            fail("package has a non-ASCII ar header")
        if not re.fullmatch(r"[0-9]+", size_text):
            fail("package has an invalid ar member size")
        size = int(size_text)
        start = offset + 60
        end = start + size
        if end + (size & 1) > len(data) or name in members:
            fail("package has a truncated or duplicate ar member")
        if size & 1 and data[end:end + 1] != b"\n":
            fail("package has invalid ar padding")
        members[name] = data[start:start + size]
        offset = start + size + (size & 1)
    return members


def decompress(name: str, data: bytes) -> bytes:
    if name.endswith(".tar"):
        if len(data) > MAXIMUM_TAR_BYTES:
            fail(f"{name} is too large")
        return data
    if name.endswith(".tar.gz"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                payload = stream.read(MAXIMUM_TAR_BYTES + 1)
        except (OSError, EOFError) as error:
            fail(f"cannot decompress {name}: {error}")
        if len(payload) > MAXIMUM_TAR_BYTES:
            fail(f"{name} is too large")
        return payload
    if name.endswith(".tar.xz"):
        payload = bytearray()
        remaining = data
        try:
            while remaining:
                decoder = lzma.LZMADecompressor(memlimit=MAXIMUM_TAR_BYTES)
                payload.extend(decoder.decompress(remaining, max_length=MAXIMUM_TAR_BYTES + 1 - len(payload)))
                if len(payload) > MAXIMUM_TAR_BYTES:
                    fail(f"{name} is too large")
                if not decoder.eof:
                    fail(f"cannot decompress truncated {name}")
                remaining = decoder.unused_data
                if remaining and len(remaining) % 4 == 0 and not any(remaining):
                    break
        except lzma.LZMAError as error:
            fail(f"cannot decompress {name}: {error}")
        return bytes(payload)
    if name.endswith(".tar.zst"):
        try:
            from compression import zstd  # type: ignore[import-not-found]

            with zstd.ZstdFile(io.BytesIO(data)) as stream:
                payload = stream.read(MAXIMUM_TAR_BYTES + 1)
        except ImportError:
            if shutil.which("zstd") is None:
                fail(f"{name} needs Python 3.14 compression.zstd or the zstd program")
            with subprocess.Popen(["zstd", "-q", "-d", "-c"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                def feed() -> None:
                    assert process.stdin is not None
                    try:
                        process.stdin.write(data)
                        process.stdin.close()
                    except BrokenPipeError:
                        pass

                writer = threading.Thread(target=feed)
                writer.start()
                try:
                    assert process.stdout is not None
                    payload = process.stdout.read(MAXIMUM_TAR_BYTES + 1)
                    if len(payload) > MAXIMUM_TAR_BYTES:
                        fail(f"{name} is too large")
                    if process.wait(timeout=FETCH_TIMEOUT_SECONDS) != 0:
                        fail(f"cannot decompress {name}")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    writer.join()
                    if process.stdout is not None:
                        process.stdout.close()
        if len(payload) > MAXIMUM_TAR_BYTES:
            fail(f"{name} is too large")
        return payload
    fail(f"unsupported package member {name}")
    raise AssertionError


def package_tar(deb: bytes, prefix: str) -> tarfile.TarFile:
    members = ar_members(deb)
    names = [name for name in members if name == prefix or name.startswith(prefix + ".")]
    if len(names) != 1:
        fail(f"package must contain exactly one {prefix} member")
    payload = decompress(names[0], members[names[0]])
    try:
        return tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError as error:
        fail(f"cannot open {prefix}: {error}")
    raise AssertionError


def validated_tar_members(archive: tarfile.TarFile):
    seen = set()
    try:
        for member in archive:
            name = member.name.removeprefix("./").rstrip("/")
            canonical = str(Path(name))
            if (name.startswith("/") or ".." in name.split("/") or "\n" in name or "\r" in name
                    or canonical in seen or len(seen) >= MAXIMUM_TAR_MEMBERS):
                fail(f"unsafe, duplicate or excessive tar member {member.name!r}")
            seen.add(canonical)
            if member.size < 0 or member.size > MAXIMUM_MEMBER_BYTES:
                fail(f"tar member {member.name!r} is too large")
            yield member
    except tarfile.TarError as error:
        fail(f"malformed tar archive: {error}")


def tar_member(deb: bytes, prefix: str, path: str) -> tuple[bytes, int]:
    wanted = {path, "./" + path}
    result = None
    with package_tar(deb, prefix) as archive:
        for member in validated_tar_members(archive):
            if member.name not in wanted:
                continue
            if not (member.isreg() or member.islnk()):
                fail(f"{prefix} member {path} is not a regular file")
            if member.islnk() and (member.linkname.startswith("/") or ".." in member.linkname.split("/")):
                fail(f"{prefix} member {path} has an unsafe hardlink")
            stream = archive.extractfile(member)
            if stream is None:
                fail(f"cannot read {prefix} member {path}")
            data = stream.read(MAXIMUM_MEMBER_BYTES + 1)
            if len(data) > MAXIMUM_MEMBER_BYTES:
                fail(f"{prefix} member {path} is too large")
            if member.isreg() and len(data) != member.size:
                fail(f"{prefix} member {path} is truncated")
            result = data, member.mode & 0o7777
    if result is not None:
        return result
    fail(f"{prefix} has no member {path}")
    raise AssertionError


def tar_member_dpkg_list_path(name: str) -> str:
    if name in ("", "."):
        return "/."
    if name.startswith("./"):
        name = name[2:]
    if not name.startswith("/"):
        name = "/" + name
    return name.rstrip("/") or "/."


def dpkg_ownership_list(deb: bytes) -> bytes:
    lines = []
    with package_tar(deb, "data.tar") as archive:
        for member in validated_tar_members(archive):
            lines.append(tar_member_dpkg_list_path(member.name))
    return ("\n".join(lines) + "\n").encode()


def prestate_derivation(identity: dict, arch: str) -> str | None:
    if identity["kind"] != "prestate":
        return None
    if identity["path"] == f"var/lib/dpkg/info/{identity['package']}.list":
        return "dpkg-list"
    if identity["path"] in (
        f"var/lib/dpkg/info/{identity['package']}.triggers",
        f"var/lib/dpkg/info/{identity['package']}:{arch}.triggers",
    ):
        return "control-triggers"
    return None


def derive_prestate(identity: dict, arch: str, deb: bytes) -> tuple[bytes, int] | None:
    derivation = prestate_derivation(identity, arch)
    if derivation == "dpkg-list":
        return dpkg_ownership_list(deb), 0o644
    if derivation == "control-triggers":
        return tar_member(deb, "control.tar", "triggers")
    return None


# Manifest.


def load_json(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAXIMUM_RELEASE_BYTES + 1)
        if len(data) > MAXIMUM_RELEASE_BYTES:
            fail(f"{path} JSON document is too large")
        document = json.loads(data)
    except (OSError, ValueError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(document, dict):
        fail(f"{path} is not a JSON object")
    return document


def canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(canonical_json(document), encoding="ascii")
    os.replace(temporary, path)


def exact_keys(value: object, required: set[str], optional: set[str], where: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        fail(f"{where} has missing {sorted(missing)} or unknown {sorted(unknown)} fields")
    return value


def validate_profile(profile: object, where: str = "series") -> dict:
    exact_keys(
        profile,
        {"name", "uri_root", "component", "architectures", "keyring", "signer", "request", "pockets"},
        set(),
        where,
    )
    assert isinstance(profile, dict)
    if not isinstance(profile["name"], str) or not re.fullmatch(r"[a-z0-9-]+", profile["name"]):
        fail(f"{where}.name is invalid")
    uri = urllib.parse.urlsplit(profile["uri_root"]) if isinstance(profile["uri_root"], str) else None
    if uri is None or uri.scheme not in ("https", "file") or uri.query or uri.fragment or profile["uri_root"].endswith("/"):
        fail(f"{where}.uri_root must be an https or file URI without a trailing slash")
    architectures = profile["architectures"]
    if (
        not isinstance(architectures, list)
        or not architectures
        or len(set(architectures)) != len(architectures)
        or any(arch not in ("amd64", "arm64") for arch in architectures)
    ):
        fail(f"{where}.architectures must list distinct amd64/arm64 values")
    if not isinstance(profile["keyring"], str) or not profile["keyring"].startswith("/"):
        fail(f"{where}.keyring must be absolute")
    if not isinstance(profile["signer"], str) or not FINGERPRINT.fullmatch(profile["signer"]):
        fail(f"{where}.signer must be a lowercase v4 fingerprint")
    for field in ("component", "request"):
        if not isinstance(profile[field], str) or not PACKAGE_NAME.fullmatch(profile[field]):
            fail(f"{where}.{field} is invalid")
    pockets = profile["pockets"]
    if not isinstance(pockets, list) or not pockets:
        fail(f"{where}.pockets must be a non-empty list")
    suites = set()
    for index, pocket in enumerate(pockets):
        exact_keys(pocket, {"suite", "role"}, set(), f"{where}.pockets[{index}]")
        if not isinstance(pocket["suite"], str) or not PACKAGE_NAME.fullmatch(pocket["suite"]):
            fail(f"{where}.pockets[{index}].suite is invalid")
        if pocket["role"] not in ROLES or pocket["suite"] in suites:
            fail(f"{where}.pockets[{index}] has an invalid role or duplicate suite")
        suites.add(pocket["suite"])
    roles = [pocket["role"] for pocket in pockets]
    if roles.count("frozen") > 1 or ("frozen" in roles) != ("witness" in roles):
        fail(f"{where} must pair exactly one frozen pocket with witness pockets")
    return profile


def resolve_profile(name: str, profile_path: Path | None) -> dict:
    if profile_path is not None:
        profile = validate_profile(load_json(profile_path), "profile")
        if profile["name"] != name:
            fail(f"profile {profile_path} is for {profile['name']}, not {name}")
        if name in PROFILES:
            fail(f"{name} is a built-in profile; it cannot be replaced")
        return profile
    if name not in PROFILES:
        fail(f"unknown series {name}")
    return {"name": name, **copy.deepcopy(PROFILES[name])}


def validate_consumer(consumer: object, where: str) -> dict:
    exact_keys(consumer, {"path", "form"}, {"name", "bindings"}, where)
    assert isinstance(consumer, dict)
    path = consumer["path"]
    if not isinstance(path, str) or path.startswith("/") or ".." in Path(path).parts or not path:
        fail(f"{where}.path must be repository-relative")
    if consumer["form"] not in CONSUMER_FORMS:
        fail(f"{where}.form is invalid")
    if (consumer["form"] == "zig_bytes") != ("name" in consumer):
        fail(f"{where}: only zig_bytes consumers name a constant")
    if (consumer["form"] == "shell") != ("bindings" in consumer):
        fail(f"{where}: exactly shell consumers list coordinate bindings")
    if consumer["form"] == "shell":
        validate_coordinate_bindings(consumer["bindings"], IDENTITY_COORDINATES, where)
        if not {"digest", "digest_size"} & set(consumer["bindings"]):
            fail(f"{where}: shell consumers must bind their digest")
    return consumer


def validate_coordinate_bindings(bindings: object, coordinates: tuple[str, ...], where: str) -> None:
    if (not isinstance(bindings, dict) or not bindings or set(bindings) - set(coordinates)
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                   for name in bindings.values()) or len(set(bindings.values())) != len(bindings)):
        fail(f"{where}: invalid typed coordinate bindings")


def validate_relative_path(path: object, where: str) -> str:
    if not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts:
        fail(f"{where} must be repository-relative")
    return path


def validate_identity(identity: object, index: int) -> dict:
    where = f"identities[{index}]"
    exact_keys(
        identity,
        {"id", "kind", "package", "architectures", "path", "digest", "size", "mode",
         "version_bound", "provenance", "consumers", "review"},
        {"derived_from", "artifact"},
        where,
    )
    assert isinstance(identity, dict)
    if not isinstance(identity["id"], str) or not IDENTITY_ID.fullmatch(identity["id"]):
        fail(f"{where}.id is invalid")
    if identity["kind"] not in KINDS:
        fail(f"{where}.kind is invalid")
    if not isinstance(identity["package"], str) or not PACKAGE_NAME.fullmatch(identity["package"]):
        fail(f"{where}.package is invalid")
    architectures = identity["architectures"]
    if (
        not isinstance(architectures, list)
        or not architectures
        or len(set(architectures)) != len(architectures)
        or any(arch not in ("amd64", "arm64") for arch in architectures)
    ):
        fail(f"{where}.architectures is invalid")
    algorithm, _ = parse_tagged(identity["digest"])
    if (identity["kind"] == "archive") != (algorithm == "sha512"):
        fail(f"{where}: archives bind SHA-512 and members bind SHA-256")
    if identity["kind"] == "archive":
        if identity["path"] is not None or identity["mode"] is not None:
            fail(f"{where}: an archive identity has no path or mode")
    else:
        path = identity["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/"):
            fail(f"{where}.path is invalid")
        mode = identity["mode"]
        if mode is None and identity["kind"] == "prestate":
            pass
        elif not isinstance(mode, str) or not re.fullmatch(r"0[0-7]{3,4}", mode):
            fail(f"{where}.mode must be an octal string")
    if not isinstance(identity["size"], int) or isinstance(identity["size"], bool) or identity["size"] < 0:
        fail(f"{where}.size is invalid")
    if not isinstance(identity["version_bound"], bool):
        fail(f"{where}.version_bound must be a boolean")
    derived = identity.get("derived_from")
    if (identity["kind"] == "prestate") != (derived is not None):
        fail(f"{where}: exactly the prestate identities list derived_from")
    if derived is not None:
        if not isinstance(derived, list):
            fail(f"{where}.derived_from must be a list")
        for item_index, item in enumerate(derived):
            exact_keys(item, {"package", "version"}, set(), f"{where}.derived_from[{item_index}]")
            if not PACKAGE_NAME.fullmatch(str(item["package"])) or not isinstance(item["version"], str):
                fail(f"{where}.derived_from[{item_index}] is invalid")
    validate_provenance(identity["provenance"], architectures, where)
    artifact = identity.get("artifact")
    if artifact is not None:
        exact_keys(artifact, {"filename", "architecture"}, set(), f"{where}.artifact")
        filename = validate_relative_path(artifact["filename"], f"{where}.artifact.filename")
        if identity["provenance"] == "pending":
            fail(f"{where}.artifact requires recorded provenance")
        artifact_arch = artifact["architecture"]
        if artifact_arch not in ("all", *architectures):
            fail(f"{where}.artifact.architecture is invalid")
        version = identity["provenance"]["version"].split(":", 1)[-1]
        if Path(filename).name != f"{identity['package']}_{version}_{artifact_arch}.deb":
            fail(f"{where}.artifact.filename disagrees with the package, version or architecture")
    if identity["version_bound"] and identity["provenance"] == "pending":
        fail(f"{where}.version_bound requires recorded provenance")
    consumers = identity["consumers"]
    if not isinstance(consumers, list) or not consumers:
        fail(f"{where} has no consumer")
    for consumer_index, consumer in enumerate(consumers):
        validate_consumer(consumer, f"{where}.consumers[{consumer_index}]")
        if consumer["form"] == "shell":
            if "url" in consumer["bindings"] and artifact is None:
                fail(f"{where}: URL bindings require artifact coordinates")
            if "version" in consumer["bindings"] and identity["provenance"] == "pending":
                fail(f"{where}: version bindings require recorded provenance")
            if "member" in consumer["bindings"] and identity["path"] is None:
                fail(f"{where}: member bindings require a member path")
    if artifact is not None:
        required = {"url", "size"} if identity["kind"] == "archive" else {"url", "size", "member"}
        if not any(consumer["form"] == "shell" and required <= set(consumer["bindings"]) for consumer in consumers):
            fail(f"{where}: artifact requires a complete typed URL/size/member consumer")
    if not isinstance(identity["review"], str) or not REVIEW_REFERENCE.fullmatch(identity["review"]):
        fail(f"{where}.review must be a PR or issue reference")
    return identity


def validate_provenance(provenance: object, architectures: list[str], where: str) -> None:
    if provenance == "pending":
        return
    exact_keys(provenance, {"version", "archives"}, set(), f"{where}.provenance")
    assert isinstance(provenance, dict)
    if not isinstance(provenance["version"], str) or not provenance["version"]:
        fail(f"{where}.provenance.version is invalid")
    archives = provenance["archives"]
    if not isinstance(archives, dict) or sorted(archives) != sorted(architectures):
        fail(f"{where}.provenance.archives must cover the identity architectures")
    for value in archives.values():
        parse_tagged(value, ("sha512",))


def validate_snapshot(snapshot: object, profile: dict) -> dict:
    exact_keys(snapshot, {"timestamp", "status"}, {"pockets", "admission_deadline", "closures"}, "snapshot")
    assert isinstance(snapshot, dict)
    timestamp_seconds(snapshot["timestamp"])
    if snapshot["status"] == "pending":
        if set(snapshot) != {"timestamp", "status"}:
            fail("a pending snapshot records only its timestamp")
        return snapshot
    if snapshot["status"] != "probed":
        fail("snapshot.status must be pending or probed")
    exact_keys(snapshot, {"timestamp", "status", "pockets", "admission_deadline", "closures"}, set(), "snapshot")
    pockets = snapshot["pockets"]
    if not isinstance(pockets, list) or [p.get("suite") for p in pockets] != [p["suite"] for p in profile["pockets"]]:
        fail("snapshot.pockets must follow the series pockets")
    for index, pocket in enumerate(pockets):
        exact_keys(
            pocket,
            {"suite", "role", "date", "valid_until", "release_sha256", "in_release_sha256",
             "in_release_sha512", "hash_fields", "signers", "deadline", "binding"},
            {"review"},
            f"snapshot.pockets[{index}]",
        )
        binding = pocket["binding"]
        if (
            not isinstance(binding, dict)
            or sorted(binding) != sorted(profile["architectures"])
            or any(value not in BINDINGS for value in binding.values())
        ):
            fail(f"snapshot.pockets[{index}].binding must give every series architecture one of {', '.join(BINDINGS)}")
        parse_tagged(pocket["release_sha256"], ("sha256",))
        parse_tagged(pocket["in_release_sha256"], ("sha256",))
        parse_tagged(pocket["in_release_sha512"], ("sha512",))
        if pocket["role"] != profile["pockets"][index]["role"]:
            fail(f"snapshot.pockets[{index}].role differs from the series")
        if pocket["signers"] != [profile["signer"]]:
            fail(f"snapshot.pockets[{index}] has an unreviewed signer")
        if pocket["role"] == "frozen":
            if not REVIEW_REFERENCE.fullmatch(str(pocket.get("review", ""))):
                fail("the frozen pocket must carry the review that accepted its Release")
        elif "review" in pocket:
            fail("only the frozen pocket carries a release review")
    if not isinstance(snapshot["admission_deadline"], int):
        fail("snapshot.admission_deadline must be an integer")
    closures = snapshot["closures"]
    if not isinstance(closures, dict) or sorted(closures) != sorted(profile["architectures"]):
        fail("snapshot.closures must cover the series architectures")
    for arch, closure in closures.items():
        exact_keys(closure, {"digest", "package_count", "packages", "pockets"}, set(), f"snapshot.closures.{arch}")
        parse_tagged(closure["digest"], ("sha256",))
        if not isinstance(closure["packages"], dict) or closure["package_count"] != len(closure["packages"]):
            fail(f"snapshot.closures.{arch}.packages does not match package_count")
    return snapshot


def validate_manifest(manifest: dict) -> dict:
    exact_keys(manifest, {"schema", "series", "snapshot", "uri_consumers", "identities", "excluded"},
               {"coordinate_consumers", "prestate_evidence"}, "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        fail("unsupported manifest schema")
    profile = validate_profile(manifest["series"])
    validate_snapshot(manifest["snapshot"], profile)
    uri_consumers = manifest["uri_consumers"]
    if not isinstance(uri_consumers, list) or any(not isinstance(path, str) for path in uri_consumers):
        fail("uri_consumers must be a list of paths")
    identities = manifest["identities"]
    if not isinstance(identities, list):
        fail("identities must be a list")
    seen = set()
    for index, identity in enumerate(identities):
        validate_identity(identity, index)
        if identity["id"] in seen:
            fail(f"duplicate identity {identity['id']}")
        seen.add(identity["id"])
    coordinates = manifest.get("coordinate_consumers", [])
    if not isinstance(coordinates, list):
        fail("coordinate_consumers must be a list")
    for index, consumer in enumerate(coordinates):
        where = f"coordinate_consumers[{index}]"
        exact_keys(consumer, {"path", "bindings"}, set(), where)
        validate_relative_path(consumer["path"], f"{where}.path")
        validate_coordinate_bindings(consumer["bindings"], SNAPSHOT_COORDINATES, where)
    if "prestate_evidence" in manifest:
        validate_relative_path(manifest["prestate_evidence"], "prestate_evidence")
    excluded = manifest["excluded"]
    if not isinstance(excluded, list):
        fail("excluded must be a list")
    for index, item in enumerate(excluded):
        exact_keys(item, {"digest", "reason"}, set(), f"excluded[{index}]")
        parse_tagged(item["digest"])
        if not isinstance(item["reason"], str) or len(item["reason"]) < 16:
            fail(f"excluded[{index}] needs a reason")
    return manifest


def pinned_timestamp(manifest: dict | None, series: str) -> str | None:
    if manifest is None or manifest["series"]["name"] != series:
        return None
    return manifest["snapshot"]["timestamp"]


def frozen_pocket(document: dict) -> dict | None:
    pockets = document.get("pockets") or []
    for pocket in pockets:
        if pocket["role"] == "frozen":
            return pocket
    return None


# Probe.


class Debz:
    def __init__(self, executable: Path, workspace: Path, arch: str, configs: list[Path], keyring: str):
        self.executable = executable
        self.arch = arch
        self.base = workspace / arch
        for name in ("root", "cache", "state"):
            (self.base / name).mkdir(parents=True)
        self.common = [
            "--install-root", str(self.base / "root"),
            "--cache-path", str(self.base / "cache"),
            "--state-path", str(self.base / "state"),
            "--architecture", arch,
        ]
        for config in configs:
            self.common += ["--config", str(config)]
        self.common += [
            "--keyring", keyring,
            "--deadline-ms", DEBZ_DEADLINE_MS,
            "--lock-wait-ms", DEBZ_LOCK_WAIT_MS,
            "--json",
        ]
        self.log = workspace / f"debz-{arch}.jsonl"

    def run(self, operation: str, extra: list[str]) -> dict:
        argv = [str(self.executable), operation, *self.common, *extra]
        result = subprocess.run(argv, capture_output=True, check=False, timeout=900)
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"argv": argv[1:2] + extra, "exit": result.returncode}) + "\n")
        try:
            document = json.loads(result.stdout)
        except ValueError:
            document = None
        if result.returncode != 0 or not isinstance(document, dict) or document.get("exit_status") != 0:
            detail = result.stdout.decode("utf-8", "replace").strip() or result.stderr.decode("utf-8", "replace").strip()
            fail(f"debz {operation} failed for {self.arch} (exit {result.returncode}): {detail[:2000]}")
        return document

    def refresh(self, suites: set[str]) -> dict[str, dict]:
        """Returns every pocket's public authenticated repository evidence."""
        document = self.run("refresh", ["--assume-yes"])
        if (document.get("schema") != "io.github.cataggar.debz.command.v1"
                or type(document.get("api_version")) is not int or document["api_version"] != 1
                or document.get("operation") != "refresh"
                or type(document.get("exit_status")) is not int or document["exit_status"] != 0
                or not isinstance(document.get("items"), list)):
            fail(f"{self.arch} refresh returned an unsupported command result")
        repositories: dict[str, dict] = {}
        for item in document["items"]:
            if (not isinstance(item, dict) or not isinstance(item.get("version"), str)
                    or item["version"] not in suites or item.get("architecture") is not None):
                fail(f"{self.arch} refresh reported an unexpected pocket")
            suite = item["version"]
            if suite in repositories:
                fail(f"{self.arch} refresh reported {suite} twice")
            detail = item.get("detail") or ""
            if not isinstance(detail, str) or not detail.startswith("authenticated") or "stale" in detail:
                fail(f"{self.arch} refresh did not freshly authenticate {suite}: {detail}")
            repository_id = item.get("package")
            if not isinstance(repository_id, str) or not re.fullmatch(r"[0-9a-f]{64}", repository_id):
                fail(f"{suite} refresh has an invalid repository id")
            evidence = validate_refresh_repository(item.get("repository"), suite)
            repositories[suite] = {"id": repository_id, **evidence}
        if sorted(repositories) != sorted(suites):
            fail(f"{self.arch} refresh did not authenticate every pocket")
        if len({value["id"] for value in repositories.values()}) != len(repositories):
            fail(f"{self.arch} refresh reported duplicate repository ids")
        return repositories

    def plan(self, package: str, lock: Path) -> dict:
        self.run("plan", ["--transaction-backend", "native", "--lock-output", str(lock), package])
        return load_json(lock)

    def download(self, package: str, lock: Path) -> None:
        self.run("download", ["--transaction-backend", "native", "--lock-input", str(lock), package])

    def archive(self, package: dict) -> bytes:
        identity = package["archive_identity"]
        if identity.get("primary") != "sha512":
            fail(f"{package['name']} {package['version']} has no SHA-512 archive identity")
        expected = [d["digest"] for d in identity["digests"] if d["algorithm"] == "sha512"]
        if len(expected) != 1:
            fail(f"{package['name']} has an ambiguous SHA-512 archive identity")
        path = self.base / "cache" / "packages-v2" / "objects" / f"sha512-{expected[0]}"
        with path.open("rb") as stream:
            data = stream.read(MAXIMUM_ARCHIVE_BYTES + 1)
        if len(data) != package["declared_size"] or hashlib.sha512(data).hexdigest() != expected[0]:
            fail(f"verified CAS object for {package['name']} no longer matches its lock")
        return data


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "debz-real-snapshot-repin"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            data = response.read(MAXIMUM_RELEASE_BYTES + 1)
    except OSError as error:
        fail(f"cannot fetch {url}: {error}")
    if len(data) > MAXIMUM_RELEASE_BYTES:
        fail(f"{url} is too large")
    return data


def snapshot_uri(profile: dict, timestamp: str) -> str:
    return f"{profile['uri_root']}/{timestamp}"


def write_configs(directory: Path, profile: dict, timestamp: str, arch: str, frozen_digest: str | None) -> list[Path]:
    directory.mkdir(parents=True)
    witnesses = [pocket["suite"] for pocket in profile["pockets"] if pocket["role"] == "witness"]
    configs = []
    for pocket in profile["pockets"]:
        source = directory / f"{pocket['suite']}.sources"
        source.write_text(
            "Types: deb\n"
            f"URIs: {snapshot_uri(profile, timestamp)}\n"
            f"Suites: {pocket['suite']}\n"
            f"Components: {profile['component']}\n"
            f"Architectures: {arch}\n"
            f"Signed-By: {profile['keyring']}\n",
            encoding="utf-8",
        )
        if pocket["role"] == "frozen":
            freshness = {
                "mode": "frozen_release_with_witnesses",
                "frozen_release_digest": frozen_digest,
                "witness_suites": witnesses,
            }
        else:
            freshness = {
                "mode": "allow_missing_valid_until_with_max_age_seconds",
                "maximum_release_age_seconds": MAXIMUM_RELEASE_AGE_SECONDS,
            }
        config = directory / f"{pocket['suite']}.json"
        config.write_text(
            json.dumps({
                "source_path": str(source),
                "priority": 500,
                "immutable": True,
                "freshness": freshness,
            }) + "\n",
            encoding="utf-8",
        )
        configs.append(config)
    return configs


def closure_digest(packages: dict[str, dict]) -> str:
    lines = "".join(
        f"{name}\0{entry['version']}\0{entry['architecture']}\0{entry['archive']}\n"
        for name, entry in sorted(packages.items())
    )
    return tagged("sha256", lines.encode("utf-8"))


def lock_packages(lock: dict, repositories: dict[str, str]) -> dict[str, dict]:
    packages: dict[str, dict] = {}
    for package in lock["packages"]:
        identity = package["archive_identity"]
        sha512 = [d["digest"] for d in identity["digests"] if d["algorithm"] == "sha512"]
        origin = package["origin"].get("repository_id")
        if package["name"] in packages:
            fail(f"lock lists {package['name']} twice")
        packages[package["name"]] = {
            "version": package["version"],
            "architecture": package["architecture"],
            "archive": f"sha512:{sha512[0]}" if identity.get("primary") == "sha512" and len(sha512) == 1 else None,
            "pocket": repositories.get(origin),
            "size": package["declared_size"],
        }
    return packages


def require_sha512(packages: dict[str, dict], arch: str) -> None:
    """Checks probe rule 6."""
    missing = sorted(f"{name} {entry['version']}" for name, entry in packages.items() if entry["archive"] is None)
    if missing:
        fail(f"{arch} closure packages without a signed SHA-512 archive identity: {', '.join(missing)}")


def deb822_fields(data: bytes) -> dict[str, str]:
    message = email.parser.BytesHeaderParser(policy=email.policy.default).parsebytes(data)
    fields = {}
    if message.defects:
        fail("malformed source control/metadata fields")
    for name, value in message.raw_items():
        key = name.lower()
        if key in fields:
            fail(f"duplicate source control/metadata field {name}")
        fields[key] = value.strip()
    return fields


def release_index_entries(data: bytes, algorithm: str) -> dict[str, tuple[str, int]]:
    fields = deb822_fields(in_release_cleartext(data))
    entries = {}
    for line in fields.get(algorithm, "").splitlines():
        words = line.split()
        if not words:
            continue
        if len(words) != 3 or not words[1].isdigit():
            fail("malformed source Release index checksum")
        digest, size, name = words
        parse_tagged(f"{algorithm}:{digest}", (algorithm,))
        validate_relative_path(name, "source Release index path")
        if name in entries:
            fail("duplicate source Release index checksum")
        entries[name] = digest, int(size)
    return entries


def source_index_package(index: bytes, index_path: str, entry: dict) -> dict[str, str]:
    if index_path.endswith((".xz", ".gz", ".zst")):
        data = decompress("source.tar" + Path(index_path).suffix, index)
    else:
        if len(index) > MAXIMUM_TAR_BYTES:
            fail("source Packages index is too large")
        data = index
    matches = []
    for paragraph in data.replace(b"\r\n", b"\n").split(b"\n\n"):
        if not paragraph.strip():
            continue
        fields = deb822_fields(paragraph)
        if (fields.get("package"), fields.get("version"), fields.get("architecture")) == (
                entry["name"], entry["version"], entry["architecture"]):
            matches.append(fields)
    if len(matches) != 1:
        fail(f"source Packages index must name {entry['name']} exactly once")
    fields = matches[0]
    if fields.get("sha512") != source_archive_digest(entry).split(":", 1)[1] or fields.get("size") != str(entry["declared_size"]):
        fail(f"source Packages index for {entry['name']} differs from its authenticated archive lock")
    validate_relative_path(fields.get("filename"), "source package Filename")
    return fields


def retain_source_metadata(
    profile: dict, timestamp: str, first: dict[str, bytes], packages: dict[str, dict],
    locks: list[dict], arch: str, workspace: Path, identities: list[dict],
) -> dict[str, dict]:
    wanted = {identity["package"] for identity in identities if arch in identity["architectures"]}
    sources = {}
    indexes = {}
    for name in sorted(wanted):
        package = packages.get(name)
        if package is None:
            continue
        entry = package["lock_package"]
        repository_id = entry["origin"]["repository_id"]
        repositories = [r for lock in locks for r in lock["repositories"] if r["id"] == repository_id]
        repository = repositories[0]
        identity = repository["index_identity"]
        algorithm = identity["primary"]
        if algorithm not in ("sha256", "sha512"):
            fail("source index needs a signed SHA-256 or SHA-512 identity")
        digests = [d["digest"] for d in identity["digests"] if d["algorithm"] == algorithm]
        if len(digests) != 1:
            fail("source index has an ambiguous signed identity")
        suite = package["pocket"]
        release = first[suite]
        checksums = release_index_entries(release, algorithm)
        stem = f"{profile['component']}/binary-{arch}/Packages"
        choices = [path for path, (digest, _) in checksums.items()
                   if path in (stem, stem + ".xz", stem + ".gz", stem + ".zst") and digest == digests[0]]
        if len(choices) != 1:
            fail(f"source Release has no unique authenticated Packages index for {name}")
        index_path = choices[0]
        if suite not in indexes:
            index = fetch(f"{snapshot_uri(profile, timestamp)}/dists/{suite}/{index_path}")
            digest, size = checksums[index_path]
            if len(index) != size or hashlib.new(algorithm, index).hexdigest() != digest:
                fail(f"source Packages index for {suite} differs from its authenticated Release")
            indexes[suite] = index
            relative = f"indexes/{arch}-{suite}-{Path(index_path).name}"
            target = workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(index)
            target = workspace / f"releases/{suite}.InRelease"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(release)
        fields = source_index_package(indexes[suite], index_path, entry)
        artifact = {"filename": fields["filename"], "architecture": fields["architecture"]}
        package["artifact"] = artifact
        sources[name] = {
            "index_file": f"indexes/{arch}-{suite}-{Path(index_path).name}",
            "index_path": index_path, "release_file": f"releases/{suite}.InRelease",
        }
    return sources


def validate_refresh_repository(value: object, suite: str) -> dict:
    exact_keys(value, {"release_digest", "snapshot_digest", "signer_fingerprints", "frozen"}, set(),
               f"{suite} refresh repository")
    assert isinstance(value, dict)
    parse_tagged(value["release_digest"], ("sha256",))
    parse_tagged(value["snapshot_digest"], ("sha256",))
    signers = value["signer_fingerprints"]
    if (not isinstance(signers, list) or not signers
            or any(not isinstance(s, str) or not re.fullmatch(r"[0-9a-f]{40}", s) for s in signers)
            or signers != sorted(set(signers))):
        fail(f"{suite} refresh has invalid signer fingerprints")
    frozen = value["frozen"]
    if frozen is not None:
        exact_keys(frozen, {"release_digest", "admission_deadline_unix", "witnesses"}, set(),
                   f"{suite} frozen decisions")
        parse_tagged(frozen["release_digest"], ("sha256",))
        if type(frozen["admission_deadline_unix"]) is not int:
            fail(f"{suite} frozen admission deadline must be an integer")
        if not isinstance(frozen["witnesses"], list) or not 1 <= len(frozen["witnesses"]) <= 4:
            fail(f"{suite} frozen decisions need one to four witnesses")
        for witness in frozen["witnesses"]:
            exact_keys(witness, {"repository_id", "snapshot_digest", "release_date_unix",
                                "deadline_unix", "primary_fingerprint"}, set(), f"{suite} frozen witness")
            if (not isinstance(witness["repository_id"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", witness["repository_id"])
                    or not isinstance(witness["primary_fingerprint"], str)
                    or not re.fullmatch(r"[0-9a-f]{40}", witness["primary_fingerprint"])
                    or type(witness["release_date_unix"]) is not int or type(witness["deadline_unix"]) is not int):
                fail(f"{suite} frozen witness has invalid identity or decisions")
            parse_tagged(witness["snapshot_digest"], ("sha256",))
    return value


def bind_pockets(
    pockets: dict[str, dict], locks: list[dict], repositories: dict[str, dict], signer: str, arch: str
) -> set[str]:
    """Binds EVERY fetched pocket to refresh; locks must agree where they contribute."""
    if set(repositories) != set(pockets):
        fail(f"{arch} refresh did not authenticate every pocket")
    for suite, repository in repositories.items():
        exact_keys(repository, {"id", "release_digest", "snapshot_digest", "signer_fingerprints", "frozen"},
                   set(), f"{suite} refresh evidence")
        if not isinstance(repository["id"], str) or not re.fullmatch(r"[0-9a-f]{64}", repository["id"]):
            fail(f"{suite} refresh has an invalid repository id")
    by_id = {value["id"]: suite for suite, value in repositories.items()}
    if len(by_id) != len(repositories):
        fail(f"{arch} refresh reported duplicate repository ids")
    for suite, repository in repositories.items():
        validate_refresh_repository({key: value for key, value in repository.items() if key != "id"}, suite)
        if repository["signer_fingerprints"] != [signer]:
            fail(f"{suite} is signed by {repository['signer_fingerprints']}, not the reviewed signer")
        if repository["release_digest"] != pockets[suite]["release_sha256"]:
            fail(f"{suite} Release fetched by the probe differs from the Release debz authenticated")
        frozen = repository["frozen"]
        if pockets[suite]["role"] != "frozen":
            if frozen is not None:
                fail(f"{suite} unexpectedly reports frozen decisions")
            continue
        witnesses = sorted((p for p in pockets.values() if p["role"] == "witness"), key=lambda p: p["suite"])
        if frozen is None or frozen["release_digest"] != pockets[suite]["release_sha256"]:
            fail(f"{suite} frozen Release differs from the reviewed pin")
        if [w["repository_id"] for w in frozen["witnesses"]] != [repositories[p["suite"]]["id"] for p in witnesses]:
            fail(f"{suite} frozen witnesses differ from configured policy order")
        for decision, pocket in zip(frozen["witnesses"], witnesses):
            witness = repositories[pocket["suite"]]
            date = release_time(pocket["date"], "Date")
            deadline = (release_time(pocket["valid_until"], "Valid-Until") if pocket["valid_until"]
                        else date + MAXIMUM_RELEASE_AGE_SECONDS)
            if (decision["snapshot_digest"] != witness["snapshot_digest"]
                    or decision["primary_fingerprint"] != signer
                    or decision["release_date_unix"] != date or decision["deadline_unix"] != deadline):
                fail(f"{suite} frozen witness {pocket['suite']} differs from its authenticated pocket")
        if frozen["admission_deadline_unix"] != min(w["deadline_unix"] for w in frozen["witnesses"]):
            fail(f"{suite} frozen admission deadline differs from its witnesses")
    bound: set[str] = set()
    for lock in locks:
        for repository in lock["repositories"]:
            suite = by_id.get(repository["id"])
            if suite is None:
                fail(f"{arch} lock names a repository that refresh did not report")
            evidence = repositories[suite]
            if (repository["signer_fingerprints"] != evidence["signer_fingerprints"]
                    or lock_digest(repository["release_sha256"]) != evidence["release_digest"]
                    or lock_digest(repository["snapshot_sha256"]) != evidence["snapshot_digest"]):
                fail(f"{suite} exact lock differs from its authenticated refresh identity")
            bound.add(suite)
    return bound


def observe_identity(identity: dict, arch: str, packages: dict[str, dict], debz: Debz, members: Path) -> dict | None:
    entry = packages.get(identity["package"])
    if entry is None:
        return None
    observed = {
        "version": entry["version"],
        "archive": entry["archive"],
        "derived_versions": {},
    }
    if "artifact" in entry:
        observed["artifact"] = entry["artifact"]
    if identity["kind"] == "archive":
        observed.update(digest=entry["archive"], size=entry["size"], mode=None)
        return observed
    if identity["kind"] == "prestate":
        for item in identity["derived_from"]:
            derived = packages.get(item["package"])
            observed["derived_versions"][item["package"]] = None if derived is None else derived["version"]
        if prestate_derivation(identity, arch) is not None:
            derived = derive_prestate(identity, arch, debz.archive(entry["lock_package"]))
            assert derived is not None
            data, mode = derived
            observed.update(
                digest=tagged("sha256", data),
                size=len(data),
                mode=f"0{mode:03o}",
            )
            return observed
        observed.update(digest=None, size=None, mode=None)
        return observed
    deb = debz.archive(entry["lock_package"])
    prefix = "control.tar" if identity["kind"] == "script" else "data.tar"
    data, mode = tar_member(deb, prefix, identity["path"])
    name = re.sub(r"[^A-Za-z0-9+.-]", "_", identity["id"]) + f"@{arch}"
    (members / name).write_bytes(data)
    observed.update(
        digest=tagged("sha256", data),
        size=len(data),
        mode=f"0{mode:o}" if mode >= 0o1000 else f"0{mode:03o}",
        member_file=f"members/{name}",
    )
    return observed


def probe(args: argparse.Namespace, now: int | None = None) -> int:
    now = int(time.time()) if now is None else now
    manifest = validate_manifest(load_json(args.manifest)) if args.manifest.exists() else None
    profile = resolve_profile(args.series, args.profile)
    timestamp = args.timestamp or default_timestamp(now)
    snapshot_seconds = validate_timestamp(timestamp, now, pinned_timestamp(manifest, profile["name"]))
    debz_path = Path(args.debz).resolve()
    if not debz_path.is_file() or not os.access(debz_path, os.X_OK):
        fail(f"--debz {args.debz} is not an executable file")
    workspace = (args.workspace or ROOT / ".tmp" / "real-snapshot-repin" / timestamp).resolve()
    if workspace.exists():
        fail(f"workspace {workspace} already exists; probes start from a fresh workspace")
    uri = snapshot_uri(profile, timestamp)

    first: dict[str, bytes] = {}
    pockets: dict[str, dict] = {}
    for pocket in profile["pockets"]:
        data = fetch(f"{uri}/dists/{pocket['suite']}/InRelease")
        first[pocket["suite"]] = data
        cleartext = in_release_cleartext(data)
        fields = release_fields(cleartext)
        if pocket["suite"] not in (fields["suite"], fields["codename"]):
            fail(f"{pocket['suite']} Release names suite {fields['suite']}")
        pockets[pocket["suite"]] = {
            "suite": pocket["suite"],
            "role": pocket["role"],
            "date": fields["date"],
            "date_unix": fields["date_unix"],
            "valid_until": fields["valid_until"],
            "valid_until_unix": fields["valid_until_unix"],
            "hash_fields": fields["hash_fields"],
            "in_release_sha256": tagged("sha256", data),
            "in_release_sha512": tagged("sha512", data),
            "release_sha256": tagged("sha256", cleartext),
            "signers": [profile["signer"]],
            "binding": {},
        }
    frozen = next((p for p in pockets.values() if p["role"] == "frozen"), None)
    frozen_change = False
    if frozen is not None:
        pinned = frozen_pocket(manifest["snapshot"]) if manifest and manifest["series"]["name"] == profile["name"] else None
        if pinned is None or pinned["release_sha256"] != frozen["release_sha256"]:
            frozen_change = True
            if not args.accept_frozen_release:
                fail(
                    f"frozen pocket {frozen['suite']} Release {frozen['release_sha256']} differs from the "
                    "reviewed manifest value; review the Release delta and pass --accept-frozen-release"
                )

    workspace.mkdir(parents=True)
    members = workspace / "members"
    members.mkdir()
    locks_directory = workspace / "locks"
    locks_directory.mkdir()
    closures: dict[str, dict] = {}
    identities: dict[str, dict] = {}
    repository_ids: dict[str, dict[str, str]] = {}
    repository_evidence: dict[str, dict[str, dict]] = {}
    unavailable: dict[str, dict[str, str]] = {}
    artifact_sources = {}
    manifest_identities = manifest["identities"] if manifest else []
    for arch in profile["architectures"]:
        configs = write_configs(workspace / "config" / arch, profile, timestamp, arch,
                                frozen["release_sha256"] if frozen else None)
        debz = Debz(debz_path, workspace, arch, configs, profile["keyring"])
        refreshed = debz.refresh(set(pockets))
        bind_pockets(pockets, [], refreshed, profile["signer"], arch)
        refresh_ids = {suite: value["id"] for suite, value in refreshed.items()}
        repository_ids[arch] = refresh_ids
        repository_evidence[arch] = refreshed
        closure_lock_path = locks_directory / f"{arch}.lock.json"
        closure_lock = debz.plan(profile["request"], closure_lock_path)
        debz.download(profile["request"], closure_lock_path)
        locks = [closure_lock]
        by_id = {repository_id: suite for suite, repository_id in refresh_ids.items()}
        packages = lock_packages(closure_lock, by_id)
        lock_entries = {package["name"]: package for package in closure_lock["packages"]}
        require_sha512(packages, arch)
        closure_packages = dict(packages)
        for identity in manifest_identities:
            if arch not in identity["architectures"]:
                continue
            names = [identity["package"]] + [item["package"] for item in identity.get("derived_from", [])]
            for name in names:
                if name in packages:
                    continue
                lock_path = locks_directory / f"{arch}-{name}.lock.json"
                try:
                    extra = debz.plan(name, lock_path)
                except RepinError as error:
                    unavailable.setdefault(arch, {})[name] = str(error)[:500]
                    continue
                debz.download(name, lock_path)
                locks.append(extra)
                extra_packages = lock_packages(extra, by_id)
                require_sha512(extra_packages, arch)
                for package in extra["packages"]:
                    lock_entries.setdefault(package["name"], package)
                for package_name, entry in extra_packages.items():
                    packages.setdefault(package_name, entry)
        bound = bind_pockets(pockets, locks, refreshed, profile["signer"], arch)
        for suite, pocket in pockets.items():
            pocket["binding"][arch] = "exact_lock" if suite in bound else "refresh_identity"
        for name, entry in packages.items():
            entry["lock_package"] = lock_entries[name]
        artifact_sources[arch] = retain_source_metadata(
            profile, timestamp, first, packages, locks, arch, workspace,
            source_evidence_identities(manifest) if manifest else [],
        )
        for identity in manifest_identities:
            if arch in identity["architectures"]:
                identities.setdefault(identity["id"], {})[arch] = observe_identity(
                    identity, arch, packages, debz, members
                )
        counts: dict[str, int] = {}
        for entry in closure_packages.values():
            counts[entry["pocket"]] = counts.get(entry["pocket"], 0) + 1
        closures[arch] = {
            "lock": f"locks/{arch}.lock.json",
            "lock_sha256": tagged("sha256", closure_lock_path.read_bytes()),
            "digest": closure_digest(closure_packages),
            "package_count": len(closure_packages),
            "pockets": dict(sorted(counts.items())),
            "packages": {
                name: {k: entry[k] for k in ("version", "architecture", "archive", "pocket")}
                for name, entry in sorted(closure_packages.items())
            },
        }

    for suite, data in first.items():
        if fetch(f"{uri}/dists/{suite}/InRelease") != data:
            fail(f"{suite} InRelease changed between the first and second fetch; the snapshot is not settled")
    ordered = [pockets[pocket["suite"]] for pocket in profile["pockets"]]
    deadline = check_pocket_dates(ordered, snapshot_seconds)
    report = {
        "schema": REPORT_SCHEMA,
        "series": profile,
        "timestamp": timestamp,
        "uri": uri,
        "probed_at": now,
        "debz_sha256": tagged("sha256", debz_path.read_bytes()),
        "frozen_release_change": frozen_change,
        "pockets": ordered,
        "repository_ids": repository_ids,
        "repository_evidence": repository_evidence,
        "admission_deadline": deadline,
        "closures": closures,
        "unavailable": unavailable,
        "identities": identities,
        "artifact_sources": artifact_sources,
    }
    write_json(workspace / "report.json", report)
    (workspace / "summary.md").write_text(report_summary(report), encoding="utf-8")
    print(f"probe passed: {workspace / 'report.json'}")
    return 0


def unbound_pockets(pockets: list[dict]) -> list[str]:
    lines = []
    for pocket in pockets:
        architectures = [arch for arch, binding in pocket["binding"].items() if binding == "refresh_only"]
        if architectures:
            role = "witness of the frozen pocket" if pocket["role"] == "witness" else f"{pocket['role']} pocket"
            lines.append(f"- `{pocket['suite']}` ({role}) on {', '.join(architectures)}")
    return lines


def report_summary(report: dict) -> str:
    lines = [
        f"## Real-snapshot probe: `{report['series']['name']}` at `{report['timestamp']}`",
        "",
        f"- URI: `{report['uri']}`",
        f"- Admission deadline: {report['admission_deadline']} "
        f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(report['admission_deadline']))})",
        f"- debz: `{report['debz_sha256']}`",
        "",
        "| Pocket | Role | Date | Valid-Until | Hash fields | Release (cleartext) | Deadline | Binding |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for pocket in report["pockets"]:
        binding = ", ".join(f"{arch}: {value}" for arch, value in pocket["binding"].items())
        lines.append(
            f"| `{pocket['suite']}` | {pocket['role']} | {pocket['date']} | {pocket['valid_until'] or 'none'} "
            f"| {', '.join(pocket['hash_fields'])} | `{pocket['release_sha256']}` | {pocket['deadline']} "
            f"| {binding} |"
        )
    lines += ["", "| Architecture | Packages | Pockets | Closure digest |", "|---|---|---|---|"]
    for arch, closure in report["closures"].items():
        pockets = ", ".join(f"{suite}: {count}" for suite, count in closure["pockets"].items())
        lines.append(f"| {arch} | {closure['package_count']} | {pockets} | `{closure['digest']}` |")
    unbound = unbound_pockets(report["pockets"])
    if unbound:
        lines += [
            "",
            "Pockets that contribute no locked package. `debz refresh` authenticated them, but debz emits "
            "no Release digest for a repository outside an exact lock, so their fetched Release is recorded "
            "without that cross-check:",
            "",
            *unbound,
        ]
    quiet = [f"- `{p['suite']}` on {', '.join(a for a, b in p['binding'].items() if b == 'refresh_identity')}"
             for p in report["pockets"] if "refresh_identity" in p["binding"].values()]
    if quiet:
        lines += ["", "Pockets that contribute no locked package. Their fetched Release is bound to "
                  "`debz refresh` repository evidence (no fabricated lock contribution):", "", *quiet]
    return "\n".join(lines) + "\n"


# Diff.


def load_report(path: Path) -> dict:
    report = load_json(path)
    if report.get("schema") != REPORT_SCHEMA:
        fail(f"{path} is not a repin probe report")
    validate_profile(report["series"], "report.series")
    validate_report_pocket_evidence(report)
    return report


def validate_report_pocket_evidence(report: dict) -> None:
    """Never promote historical refresh-only reports without public identity evidence."""
    if ("repository_evidence" not in report
            and not any("refresh_identity" in p["binding"].values() for p in report["pockets"])):
        return
    evidence = report.get("repository_evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(report["series"]["architectures"]):
        fail("report repository evidence must cover every architecture")
    pockets = {p["suite"]: p for p in report["pockets"]}
    for arch, repositories in evidence.items():
        if not isinstance(repositories, dict):
            fail(f"{arch} report repository evidence must be an object")
        bind_pockets(pockets, [], repositories, report["series"]["signer"], arch)
        if report.get("repository_ids", {}).get(arch) != {s: r["id"] for s, r in repositories.items()}:
            fail(f"{arch} report repository ids differ from authenticated evidence")


def identity_status(identity: dict, observed: dict[str, dict | None]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    status = "unchanged"
    for arch in identity["architectures"]:
        value = observed.get(arch)
        if value is None:
            return "missing", [f"{identity['package']} is not in the {arch} snapshot"]
        if identity["kind"] == "prestate":
            stale = [
                f"{item['package']} {item['version']} -> {value['derived_versions'].get(item['package'])}"
                for item in identity["derived_from"]
                if value["derived_versions"].get(item["package"]) != item["version"]
            ]
            if stale:
                return "changed", [f"{arch}: derived state depends on changed packages: {', '.join(stale)}"]
            if value.get("digest") is not None and (
                value["digest"] != identity["digest"]
                or value["size"] != identity["size"]
                or value["mode"] != identity["mode"]
            ):
                return "changed", [f"{arch}: derived prestate changed: {identity['digest']} -> {value['digest']}"]
        elif value["digest"] != identity["digest"] or value["size"] != identity["size"] or value["mode"] != identity["mode"]:
            return "changed", [f"{arch}: bound bytes changed: {identity['digest']} -> {value['digest']}"]
        provenance = identity["provenance"]
        if identity["version_bound"] and provenance != "pending" and value["version"] != provenance["version"]:
            return "changed", [
                f"{arch}: version-bound identity moved from {provenance['version']} to {value['version']}"
            ]
        if provenance == "pending":
            reasons.append(f"{arch}: records first provenance")
            status = "provenance-only"
        elif provenance["archives"].get(arch) != value["archive"] or provenance["version"] != value["version"]:
            reasons.append(f"{arch}: archive {provenance['archives'].get(arch)} -> {value['archive']}")
            status = "provenance-only"
    return status, reasons


def advisory(old: bytes | None, new: bytes | None) -> str:
    if old is None or new is None:
        return "no in-tree bytes to compare; review the new member"

    def code(data: bytes) -> list[str]:
        result = []
        for line in data.decode("utf-8", "replace").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                result.append(" ".join(stripped.split()))
        return result

    if code(old) == code(new):
        return "comments or whitespace only"
    return "behavioral change; review every hunk"


def fixture_bytes(identity: dict, root: Path) -> bytes | None:
    for consumer in identity["consumers"]:
        if consumer["form"] == "fixture":
            path = root / consumer["path"]
            return path.read_bytes() if path.is_file() else None
    return None


def compute_diff(manifest: dict, report: dict, report_directory: Path, root: Path, allow_series_migration: bool = False) -> dict:
    if manifest["series"] != report["series"] and not allow_series_migration:
        fail("the report and manifest describe different series profiles")
    comparison_manifest = manifest
    if manifest["series"] != report["series"]:
        comparison_manifest = copy.deepcopy(manifest)
        comparison_manifest["series"] = copy.deepcopy(report["series"])
        comparison_manifest["snapshot"] = {
            "timestamp": report["timestamp"],
            "status": "pending",
        }
    statuses = []
    reported = report["identities"]
    for identity in comparison_manifest["identities"]:
        observed = reported.get(identity["id"], {})
        status, reasons = identity_status(identity, observed)
        entry = {"id": identity["id"], "status": status, "reasons": reasons}
        if status == "changed" and identity["kind"] in ("script", "tool_file"):
            arch = identity["architectures"][0]
            value = observed.get(arch)
            new = (report_directory / value["member_file"]).read_bytes() if value and value.get("member_file") else None
            old = fixture_bytes(identity, root)
            entry["advisory"] = advisory(old, new)
            if old is not None and new is not None and identity["kind"] == "script":
                entry["unified_diff"] = "".join(difflib.unified_diff(
                    old.decode("utf-8", "replace").splitlines(keepends=True),
                    new.decode("utf-8", "replace").splitlines(keepends=True),
                    fromfile=f"pinned/{identity['id']}",
                    tofile=f"{report['timestamp']}/{identity['id']}",
                ))
        statuses.append(entry)
    closures = {}
    old_closures = comparison_manifest["snapshot"].get("closures", {})
    for arch, closure in report["closures"].items():
        old = old_closures.get(arch, {}).get("packages", {})
        new = {name: entry["version"] for name, entry in closure["packages"].items()}
        closures[arch] = {
            "added": sorted(f"{name} {new[name]}" for name in set(new) - set(old)),
            "removed": sorted(f"{name} {old[name]}" for name in set(old) - set(new)),
            "changed": sorted(
                f"{name} {old[name]} -> {new[name]}" for name in set(old) & set(new) if old[name] != new[name]
            ),
        }
    pinned_frozen = frozen_pocket(comparison_manifest["snapshot"])
    reported_frozen = frozen_pocket(report)
    return {
        "series": report["series"]["name"],
        "from": manifest["snapshot"]["timestamp"],
        "to": report["timestamp"],
        "series_migration": manifest["series"]["name"] if manifest["series"] != report["series"] else None,
        "frozen_release": None if reported_frozen is None else {
            "pinned": None if pinned_frozen is None else pinned_frozen["release_sha256"],
            "probed": reported_frozen["release_sha256"],
        },
        "closures": closures,
        "identities": statuses,
    }


def pinned_strings(manifest: dict) -> dict[str, str]:
    strings = {snapshot_uri(manifest["series"], manifest["snapshot"]["timestamp"]): "uri"}
    strings[manifest["snapshot"]["timestamp"]] = "timestamp"
    snapshot = manifest["snapshot"]
    for pocket in snapshot.get("pockets", []):
        strings[pocket["release_sha256"].split(":", 1)[1]] = f"release:{pocket['suite']}"
        strings[pocket["in_release_sha256"].split(":", 1)[1]] = f"in-release:{pocket['suite']}"
    for arch, closure in snapshot.get("closures", {}).items():
        strings[closure["digest"].split(":", 1)[1]] = f"closure:{arch}"
    for identity in manifest["identities"]:
        strings[identity["digest"].split(":", 1)[1]] = f"identity:{identity['id']}"
        if identity["provenance"] != "pending":
            for arch, archive in identity["provenance"]["archives"].items():
                strings[archive.split(":", 1)[1]] = f"archive:{identity['id']}@{arch}"
    return strings


def scan_pr_diff(text: str, manifest: dict, changed: set[str]) -> list[dict]:
    """Lists added PR lines that pin an identity this repin changes."""
    strings = pinned_strings(manifest)
    findings = []
    path = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for value, label in strings.items():
            if value in line:
                findings.append({"path": path, "pin": label, "stale": label in changed, "line": line[1:].strip()[:200]})
    return findings


def changed_labels(diff: dict, manifest: dict, report: dict) -> set[str]:
    labels = set()
    if manifest["snapshot"]["timestamp"] != report["timestamp"]:
        labels.update({"uri", "timestamp"})
    for pocket in manifest["snapshot"].get("pockets", []):
        new = next((p for p in report["pockets"] if p["suite"] == pocket["suite"]), None)
        if new is None or new["release_sha256"] != pocket["release_sha256"]:
            labels.add(f"release:{pocket['suite']}")
        if new is None or new["in_release_sha256"] != pocket["in_release_sha256"]:
            labels.add(f"in-release:{pocket['suite']}")
    for arch, closure in manifest["snapshot"].get("closures", {}).items():
        if report["closures"].get(arch, {}).get("digest") != closure["digest"]:
            labels.add(f"closure:{arch}")
    for entry in diff["identities"]:
        if entry["status"] in ("changed", "missing"):
            labels.add(f"identity:{entry['id']}")
        if entry["status"] != "unchanged":
            for arch in ("amd64", "arm64"):
                labels.add(f"archive:{entry['id']}@{arch}")
    return labels


def diff_summary(diff: dict, findings: list[dict]) -> str:
    lines = [f"## Real-snapshot diff: `{diff['series']}` `{diff['from']}` -> `{diff['to']}`", ""]
    frozen = diff["frozen_release"]
    if frozen is not None:
        state = "unchanged" if frozen["pinned"] == frozen["probed"] else "CHANGED (needs --accept-frozen-release)"
        lines.append(f"- Frozen release: {state}: `{frozen['probed']}`")
    for arch, closure in diff["closures"].items():
        lines.append(
            f"- {arch}: {len(closure['changed'])} changed, {len(closure['added'])} added, "
            f"{len(closure['removed'])} removed closure packages"
        )
        for key in ("changed", "added", "removed"):
            for item in closure[key]:
                lines.append(f"  - {key}: {item}")
    lines += ["", "| Identity | Status | Detail |", "|---|---|---|"]
    for entry in diff["identities"]:
        detail = "; ".join(entry["reasons"])
        if "advisory" in entry:
            detail += f" ({entry['advisory']})"
        lines.append(f"| `{entry['id']}` | {entry['status']} | {detail} |")
    if findings:
        lines += ["", "| PR file | Pin | Stale |", "|---|---|---|"]
        for finding in findings:
            lines.append(f"| `{finding['path']}` | `{finding['pin']}` | {'yes' if finding['stale'] else 'no'} |")
    return "\n".join(lines) + "\n"


def diff_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    report = load_report(args.report)
    diff = compute_diff(manifest, report, args.report.parent, args.root.resolve(), args.allow_series_migration)
    findings = []
    texts = []
    for number in args.pr or []:
        result = subprocess.run(["gh", "pr", "diff", str(number)], capture_output=True, check=False, timeout=300)
        if result.returncode != 0:
            fail(f"gh pr diff {number} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
        texts.append((f"#{number}", result.stdout.decode("utf-8", "replace")))
    for path in args.pr_diff_file or []:
        texts.append((str(path), path.read_text(encoding="utf-8")))
    labels = changed_labels(diff, manifest, report)
    for source, text in texts:
        for finding in scan_pr_diff(text, manifest, labels):
            finding["pr"] = source
            findings.append(finding)
    diff["pr_findings"] = findings
    write_json(args.report.parent / "diff.json", diff)
    summary = diff_summary(diff, findings)
    (args.report.parent / "diff.md").write_text(summary, encoding="utf-8")
    sys.stdout.write(summary)
    return 0


# Record.


def parse_reviews(values: list[str]) -> dict[str, str]:
    reviews: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            fail(f"--reviewed must be IDENTITY=REFERENCE: {value!r}")
        identity, reference = value.split("=", 1)
        if not REVIEW_REFERENCE.fullmatch(reference):
            fail(f"--reviewed {identity} needs a PR or issue reference such as #330")
        if identity in reviews:
            fail(f"--reviewed {identity} is repeated")
        reviews[identity] = reference
    return reviews


def migrated_fixture_path(identity: dict, series_name: str) -> str:
    member = str(identity["path"] or "").replace("/", "-")
    if not member:
        fail(f"{identity['id']} fixture consumer cannot be renamed without a member path")
    return f"src/fixtures/{series_name}-{identity['package']}.{member}"


def refresh_exclusion_reasons(manifest: dict) -> None:
    reasons = {
        "sha256:0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5":
            "pinned dpkg 1.22.22 private Debian reference prepared by tools/prepare-native-dpkg.py; external oracle, not the resolute snapshot dpkg pin",
        "sha256:b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13":
            "update-alternatives from the pinned dpkg 1.22.22 private Debian reference (amd64); external oracle, not the resolute snapshot dpkg pin",
        "sha256:35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5":
            "update-alternatives from the pinned dpkg 1.22.22 private Debian reference (arm64); external oracle, not the resolute snapshot dpkg pin",
    }
    for item in manifest.get("excluded", []):
        reason = reasons.get(item.get("digest"))
        if reason is not None:
            item["reason"] = reason


def record_manifest(
    manifest: dict,
    report: dict,
    diff: dict,
    reviews: dict[str, str],
    accept_frozen: str | None,
    allow_series_migration: bool = False,
) -> dict:
    validate_report_pocket_evidence(report)
    series_migration = report["series"]["name"] != manifest["series"]["name"]
    if series_migration and not allow_series_migration:
        fail("the report is for a different series")
    if timestamp_seconds(report["timestamp"]) < timestamp_seconds(manifest["snapshot"]["timestamp"]):
        fail(f"the report snapshot {report['timestamp']} is older than the current pin")
    required = {entry["id"] for entry in diff["identities"] if entry["status"] in ("changed", "missing")}
    unreviewed = sorted(required - set(reviews))
    if unreviewed:
        fail("reviewed identities changed without re-review: " + ", ".join(unreviewed) +
             "; pass --reviewed ID=#PR for each after reviewing it")
    unexpected = sorted(set(reviews) - required)
    if unexpected:
        fail("--reviewed names identities that did not change: " + ", ".join(unexpected))
    frozen = diff["frozen_release"]
    frozen_changed = frozen is not None and frozen["pinned"] != frozen["probed"]
    if frozen_changed and accept_frozen is None:
        fail("the frozen release changed; review the Release delta and pass --accept-frozen-release #PR")
    if accept_frozen is not None and not frozen_changed:
        fail("--accept-frozen-release was passed but the frozen release did not change")
    if accept_frozen is not None and not REVIEW_REFERENCE.fullmatch(accept_frozen):
        fail("--accept-frozen-release needs a PR or issue reference")

    updated = copy.deepcopy(manifest)
    if series_migration:
        updated["series"] = copy.deepcopy(report["series"])
    previous_frozen = frozen_pocket(manifest["snapshot"])
    pockets = []
    for pocket in report["pockets"]:
        entry = {key: pocket[key] for key in (
            "suite", "role", "date", "valid_until", "release_sha256", "in_release_sha256",
            "in_release_sha512", "hash_fields", "signers", "deadline", "binding")}
        if pocket["role"] == "frozen":
            entry["review"] = accept_frozen if frozen_changed else previous_frozen["review"]
        pockets.append(entry)
    updated["snapshot"] = {
        "timestamp": report["timestamp"],
        "status": "probed",
        "pockets": pockets,
        "admission_deadline": report["admission_deadline"],
        "closures": {
            arch: {
                "digest": closure["digest"],
                "package_count": closure["package_count"],
                "pockets": closure["pockets"],
                "packages": {name: entry["version"] for name, entry in closure["packages"].items()},
            }
            for arch, closure in report["closures"].items()
        },
    }
    identities = []
    for identity, entry in zip(manifest["identities"], diff["identities"]):
        if entry["status"] == "missing":
            continue
        observed = report["identities"][identity["id"]]
        first = observed[identity["architectures"][0]]
        new = copy.deepcopy(identity)
        if identity["kind"] != "prestate" or first.get("digest") is not None:
            new.update(digest=first["digest"], size=first["size"], mode=first["mode"])
        if series_migration:
            for consumer in new["consumers"]:
                if consumer["form"] == "fixture" and consumer["path"].startswith("src/fixtures/ubuntu-"):
                    consumer["path"] = migrated_fixture_path(identity, report["series"]["name"])
        if identity["version_bound"] and identity["provenance"] != "pending":
            old_name = identity["provenance"]["version"].split(":", 1)[-1]
            new_name = first["version"].split(":", 1)[-1]
            for consumer in new["consumers"]:
                if consumer["form"] == "fixture" and old_name != new_name:
                    consumer["path"] = consumer["path"].replace(old_name, new_name)
        new["provenance"] = {
            "version": first["version"],
            "archives": {arch: observed[arch]["archive"] for arch in identity["architectures"]},
        }
        if "artifact" in new:
            if "artifact" not in first:
                fail(f"{identity['id']} report has no independently observed artifact coordinates")
            new["artifact"] = copy.deepcopy(first["artifact"])
        if identity["kind"] == "prestate":
            new["derived_from"] = [
                {"package": item["package"], "version": first["derived_versions"][item["package"]]}
                for item in identity["derived_from"]
            ]
        if entry["status"] == "changed":
            new["review"] = reviews[identity["id"]]
        identities.append(new)
    updated["identities"] = identities
    refresh_exclusion_reasons(updated)
    return validate_manifest(updated)


def record_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    report = load_report(args.report)
    diff = compute_diff(manifest, report, args.report.parent, args.root.resolve(), args.allow_series_migration)
    updated = record_manifest(
        manifest,
        report,
        diff,
        parse_reviews(args.reviewed or []),
        args.accept_frozen_release,
        args.allow_series_migration,
    )
    if source_evidence_identities(updated):
        updated["prestate_evidence"] = updated.get("prestate_evidence", DEFAULT_EVIDENCE)
        export_prestate_evidence(updated, report, args.report.parent, args.root.resolve())
    write_json(args.manifest, updated)
    counts = {status: sum(1 for entry in diff["identities"] if entry["status"] == status) for status in STATUSES}
    print(f"recorded {report['timestamp']}: " + ", ".join(f"{count} {status}" for status, count in counts.items()))
    return 0


def retained_source_member(
    manifest: dict, evidence: bytes, package: str, architecture: str, prefix: str, path: str,
) -> tuple[dict, bytes, int]:
    try:
        failures = check_prestate_evidence(manifest, evidence)
    except (zipfile.BadZipFile, KeyError, ValueError, TypeError, OSError, EOFError) as error:
        fail(f"binding source evidence refused: {error}")
    if failures:
        fail("binding source evidence refused: " + "; ".join(failures))
    with zipfile.ZipFile(io.BytesIO(evidence)) as archive:
        index = json.loads(archive.read("evidence.json"))
        sources = [source for source in index["sources"]
                   if source["architecture"] == architecture and source["package"] == package]
        if len(sources) != 1:
            fail("binding has no unique independently retained source archive; run a new probe")
        source = sources[0]
        report = json.loads(archive.read("report.json"))
        lock = json.loads(archive.read(source["lock_file"]))
        entry = authenticated_source_package(report, lock, package, architecture)
        data = archive.read(source["archive_file"])
        verify_source_archive(data, entry)
        member, mode = tar_member(data, prefix, path)
    return entry, member, mode


def bind_architecture(
    manifest: dict,
    identity_id: str,
    architecture: str,
    review: str,
    evidence: bytes,
    now: int | None = None,
) -> dict:
    validate_manifest(manifest)
    identities = [item for item in manifest["identities"] if item["id"] == identity_id]
    if len(identities) != 1 or identities[0]["kind"] != "script":
        fail("architecture binding requires an existing script identity")
    identity = identities[0]
    if architecture not in manifest["series"]["architectures"] or architecture in identity["architectures"]:
        fail("architecture binding requires a new architecture from the series profile")
    if not REVIEW_REFERENCE.fullmatch(review):
        fail("architecture binding requires a PR or issue review reference")
    now = int(time.time()) if now is None else now
    if manifest["snapshot"]["status"] != "probed" or now >= manifest["snapshot"]["admission_deadline"]:
        fail("architecture binding requires a currently admissible recorded snapshot")
    entry, member, mode = retained_source_member(
        manifest, evidence, identity["package"], architecture, "control.tar", identity["path"],
    )
    if (tagged("sha256", member) != identity["digest"] or len(member) != identity["size"]
            or f"0{mode:03o}" != identity["mode"] or not isinstance(identity["provenance"], dict)
            or entry["version"] != identity["provenance"]["version"]):
        fail("architecture binding differs in script bytes, size, mode or version; record a separate identity")
    updated = copy.deepcopy(manifest)
    target = next(item for item in updated["identities"] if item["id"] == identity_id)
    target["architectures"].append(architecture)
    target["provenance"]["archives"][architecture] = source_archive_digest(entry)
    target["review"] = review
    validate_manifest(updated)
    failures = check_prestate_evidence(updated, evidence)
    if failures:
        fail("architecture binding recorded source refused: " + "; ".join(failures))
    return updated


def bind_member(
    manifest: dict, archive_id: str, path: str, consumers: list[str], review: str,
    evidence: bytes, now: int | None = None,
) -> dict:
    validate_manifest(manifest)
    archives = [item for item in manifest["identities"] if item["id"] == archive_id]
    if len(archives) != 1 or archives[0]["kind"] != "archive" or len(archives[0]["architectures"]) != 1:
        fail("member binding requires an existing single-architecture archive identity")
    archive = archives[0]
    if not isinstance(archive["provenance"], dict):
        fail("member binding requires recorded archive provenance")
    architecture = archive["architectures"][0]
    validate_relative_path(path, "member binding path")
    if not consumers or len(set(consumers)) != len(consumers) or any(
            consumer not in DEBZ_SNAPSHOT_CONSTANT_SOURCES for consumer in consumers):
        fail("member binding requires distinct snapshot admission source consumers")
    if not REVIEW_REFERENCE.fullmatch(review):
        fail("member binding requires a PR or issue review reference")
    now = int(time.time()) if now is None else now
    if manifest["snapshot"]["status"] != "probed" or now >= manifest["snapshot"]["admission_deadline"]:
        fail("member binding requires a currently admissible recorded snapshot")
    identity_id = f"file:{archive['package']}/{path}@{architecture}"
    if any(item["id"] == identity_id for item in manifest["identities"]):
        fail("member binding identity already exists")
    entry, member, mode = retained_source_member(
        manifest, evidence, archive["package"], architecture, "data.tar", path,
    )
    if (archive["digest"] != source_archive_digest(entry) or archive["size"] != entry["declared_size"]
            or archive["provenance"]["version"] != entry["version"]):
        fail("member binding source disagrees with the reviewed archive identity")
    updated = copy.deepcopy(manifest)
    updated["identities"].append({
        "id": identity_id, "kind": "tool_file", "package": archive["package"], "path": path,
        "architectures": [architecture], "digest": tagged("sha256", member), "size": len(member),
        "mode": f"0{mode:03o}", "version_bound": False, "review": review,
        "provenance": {"version": entry["version"], "archives": {architecture: source_archive_digest(entry)}},
        "consumers": [{"path": consumer, "form": "hex"} for consumer in consumers],
    })
    validate_manifest(updated)
    if updated["identities"][-1] not in source_evidence_identities(updated):
        fail("member binding requires an archive already retained by the offline source gates")
    failures = check_prestate_evidence(updated, evidence)
    if failures:
        fail("member binding recorded source refused: " + "; ".join(failures))
    return updated


def bind_member_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    root = args.root.resolve()
    if "prestate_evidence" not in manifest:
        fail("member binding requires independently retained source evidence")
    evidence = read_source_file(root / manifest["prestate_evidence"], root, MAXIMUM_EVIDENCE_BYTES,
                                "member binding source evidence")
    updated = bind_member(manifest, args.archive_identity, args.member, args.consumer, args.reviewed, evidence)
    write_json(args.manifest, updated)
    print(f"recorded original {args.member} from {args.archive_identity}; no live probe or execution proof claimed")
    return 0


def bind_architecture_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    root = args.root.resolve()
    if "prestate_evidence" not in manifest:
        fail("architecture binding requires independently retained source evidence")
    evidence = read_source_file(root / manifest["prestate_evidence"], root, MAXIMUM_EVIDENCE_BYTES,
                                "architecture binding source evidence")
    updated = bind_architecture(manifest, args.identity, args.architecture, args.reviewed, evidence)
    write_json(args.manifest, updated)
    print(f"recorded original {args.architecture} source binding for {args.identity}; script execution admission is unchanged")
    return 0


# Check.

def source_evidence_identities(manifest: dict) -> list[dict]:
    identities = [
        identity for identity in manifest["identities"]
        if any(prestate_derivation(identity, arch) is not None for arch in identity["architectures"])
        or any(consumer["form"] == "shell" and "url" in consumer["bindings"] for consumer in identity["consumers"])
    ]
    identities.extend(
        identity for identity in manifest["identities"]
        if identity["kind"] == "script" and len(identity["architectures"]) > 1
    )
    retained = {(identity["package"], arch) for identity in identities for arch in identity["architectures"]}
    retained_ids = {identity["id"] for identity in identities}
    identities.extend(
        identity for identity in manifest["identities"]
        if identity["kind"] == "tool_file" and identity["id"] not in retained_ids
        and all((identity["package"], arch) in retained for arch in identity["architectures"])
    )
    return identities


def archive_package_fields(data: bytes) -> dict[str, str]:
    control, _ = tar_member(data, "control.tar", "control")
    fields = deb822_fields(control)
    values = {}
    for field in ("Package", "Version", "Architecture"):
        value = fields.get(field.lower())
        if not value:
            fail(f"source archive has an invalid {field} control field")
        values[field.lower()] = value
    return values


def authenticated_source_package(report: dict, lock: dict, package: str, arch: str) -> dict:
    entries = [entry for entry in lock["packages"] if entry["name"] == package]
    if len(entries) != 1:
        fail(f"source lock must name {package} exactly once for {arch}")
    entry = entries[0]
    if entry["architecture"] not in (arch, "all") or entry["origin"]["type"] != "authenticated_repository":
        fail(f"source lock has an unauthenticated or wrong-architecture {package}")
    origin_id = entry["origin"]["repository_id"]
    repositories = [repository for repository in lock["repositories"] if repository["id"] == origin_id]
    if len(repositories) != 1:
        fail(f"source lock has no unique authenticated repository for {package}")
    by_id = {repository_id: suite for suite, repository_id in report["repository_ids"][arch].items()}
    suite = by_id.get(origin_id)
    pockets = [pocket for pocket in report["pockets"] if pocket["suite"] == suite]
    if len(pockets) != 1:
        fail(f"source lock repository for {package} was not refreshed")
    repository = repositories[0]
    if (repository["signer_fingerprints"] != [report["series"]["signer"]]
            or lock_digest(repository["release_sha256"]) != pockets[0]["release_sha256"]):
        fail(f"source lock repository for {package} differs from the authenticated probe Release")
    origin_snapshot = entry["origin"]["repository_snapshot_sha256"]
    lock_digest(origin_snapshot)
    lock_digest(repository["snapshot_sha256"])
    if origin_snapshot != repository["snapshot_sha256"]:
        fail(f"source lock snapshot for {package} differs from its repository")
    return entry


def source_archive_digest(entry: dict) -> str:
    identity = entry["archive_identity"]
    digests = [value["digest"] for value in identity["digests"] if value["algorithm"] == "sha512"]
    if identity["primary"] != "sha512" or len(digests) != 1:
        fail("source lock has no unique SHA-512 archive identity")
    value = "sha512:" + digests[0]
    parse_tagged(value, ("sha512",))
    return value


def verify_source_archive(data: bytes, entry: dict) -> None:
    if len(data) != entry["declared_size"] or tagged("sha512", data) != source_archive_digest(entry):
        fail(f"source archive for {entry['name']} disagrees with its authenticated lock digest or size")
    control = archive_package_fields(data)
    if control != {"package": entry["name"], "version": entry["version"], "architecture": entry["architecture"]}:
        fail(f"source archive control coordinates for {entry['name']} disagree with its authenticated lock")


def verify_source_metadata(report: dict, lock: dict, source: dict, entry: dict, release: bytes, index: bytes) -> dict:
    stem = f"{report['series']['component']}/binary-{source['architecture']}/Packages"
    if source["index_path"] not in (stem, stem + ".xz", stem + ".gz", stem + ".zst"):
        fail("retained source Packages path has the wrong component or architecture")
    repository_id = entry["origin"]["repository_id"]
    repository = next(r for r in lock["repositories"] if r["id"] == repository_id)
    suite = next(suite for suite, value in report["repository_ids"][source["architecture"]].items()
                 if value == repository_id)
    pocket = next(p for p in report["pockets"] if p["suite"] == suite)
    if (tagged("sha256", release) != pocket["in_release_sha256"]
            or tagged("sha512", release) != pocket["in_release_sha512"]
            or tagged("sha256", in_release_cleartext(release)) != pocket["release_sha256"]):
        fail(f"retained source InRelease for {entry['name']} differs from the authenticated probe")
    identity = repository["index_identity"]
    algorithm = identity["primary"]
    if algorithm not in ("sha256", "sha512"):
        fail("retained source index needs a signed SHA-256 or SHA-512 identity")
    digests = [d["digest"] for d in identity["digests"] if d["algorithm"] == algorithm]
    checksums = release_index_entries(release, algorithm)
    checksum = checksums.get(source["index_path"])
    if (len(digests) != 1 or checksum != (digests[0], len(index))
            or hashlib.new(algorithm, index).hexdigest() != digests[0]):
        fail(f"retained source Packages index for {entry['name']} differs from its signed Release/lock")
    return source_index_package(index, source["index_path"], entry)


def read_source_file(path: Path, root: Path, limit: int, where: str) -> bytes:
    if (not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or path.is_symlink()):
        fail(f"{where} is missing or unsafe")
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as error:
        fail(f"cannot read {where}: {error}")
    if len(data) > limit:
        fail(f"{where} is too large")
    return data


def source_lock_paths(directory: Path) -> list[Path]:
    path = directory / "locks"
    if not path.resolve().is_relative_to(directory.resolve()) or not path.is_dir() or path.is_symlink():
        fail("probe source lock directory is unsafe")
    paths = []
    try:
        with os.scandir(path) as entries:
            for index, entry in enumerate(entries):
                if index >= MAXIMUM_EVIDENCE_FILES:
                    fail("probe source lock directory exceeds its entry bound")
                if entry.name.endswith(".lock.json"):
                    paths.append(Path(entry.path))
    except OSError as error:
        fail(f"cannot read probe source lock directory: {error}")
    return sorted(paths)


def export_prestate_evidence(manifest: dict, report: dict, directory: Path, root: Path) -> None:
    """Retain actual verified CAS objects and original probe locks, not derived hashes."""
    files = {}

    def remaining_bytes() -> int:
        return MAXIMUM_EVIDENCE_BYTES - sum(map(len, files.values()))

    def remember(name: str, data: bytes) -> None:
        if name not in files:
            if len(files) >= MAXIMUM_EVIDENCE_FILES or len(data) > remaining_bytes():
                fail("source evidence exceeds its file or byte bound")
            files[name] = data

    def retain(relative: str, limit: int) -> bytes:
        validate_relative_path(relative, "probe source metadata path")
        if relative not in files:
            data = read_source_file(directory / relative, directory, min(limit, remaining_bytes()),
                                    f"probe source {relative}")
            remember(relative, data)
        return files[relative]

    retain("report.json", MAXIMUM_RELEASE_BYTES)
    lock_paths = source_lock_paths(directory)
    sources = []
    wanted = sorted({(arch, identity["package"]) for identity in source_evidence_identities(manifest)
                     for arch in identity["architectures"]})
    for arch, name in wanted:
        selected = None
        for path in lock_paths:
            if not path.name.startswith(arch):
                continue
            lock_name = "locks/" + path.name
            lock_bytes = files.get(lock_name)
            if lock_bytes is None:
                lock_bytes = read_source_file(path, directory, min(MAXIMUM_RELEASE_BYTES, remaining_bytes()),
                                              f"probe source lock {path.name}")
            try:
                lock = json.loads(lock_bytes)
            except ValueError as error:
                fail(f"probe source lock {path.name} is invalid JSON: {error}")
            if not isinstance(lock, dict):
                fail(f"probe source lock {path.name} must be an object")
            if any(entry["name"] == name for entry in lock["packages"]):
                selected = path, lock_bytes, lock, authenticated_source_package(report, lock, name, arch)
                break
        if selected is None:
            fail(f"probe has no authenticated source lock for {name} on {arch}")
        path, lock_bytes, lock, entry = selected
        digest = source_archive_digest(entry)
        archive_name = "archives/" + digest.replace(":", "-") + ".deb"
        source = directory / arch / "cache/packages-v2/objects" / digest.replace(":", "-")
        lock_name = "locks/" + path.name
        remember(lock_name, lock_bytes)
        data = files.get(archive_name)
        if data is None:
            data = read_source_file(source, directory, remaining_bytes(), f"probe source archive for {name} on {arch}")
        verify_source_archive(data, entry)
        remember(archive_name, data)
        metadata = report.get("artifact_sources", {}).get(arch, {}).get(name)
        if not isinstance(metadata, dict):
            fail(f"probe has no independently retained signed source metadata for {name} on {arch}; run a new probe")
        exact_keys(metadata, {"index_file", "index_path", "release_file"}, set(), "probe source metadata")
        sources.append({
            "package": name, "architecture": arch, "archive_file": archive_name,
            "lock_file": lock_name, "lock_sha256": tagged("sha256", files[lock_name]),
            **metadata,
        })
        for relative in (sources[-1]["index_file"], sources[-1]["release_file"]):
            retain(relative, MAXIMUM_RELEASE_BYTES)
    remember("evidence.json", canonical_json({
        "schema": EVIDENCE_SCHEMA, "report_sha256": tagged("sha256", files["report.json"]), "sources": sources,
    }).encode())
    if len(files) > MAXIMUM_EVIDENCE_FILES or sum(map(len, files.values())) > MAXIMUM_EVIDENCE_BYTES:
        fail("source evidence exceeds its file or byte bound")
    path = root / manifest["prestate_evidence"]
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        fail("source evidence output must stay inside the checkout without a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o100644 << 16
            archive.writestr(member, data)
    # Validate the new retained bytes before replacing a previously reviewed bundle.
    failures = check_prestate_evidence(manifest, stream.getvalue())
    if failures:
        fail("cannot record source evidence: " + "; ".join(failures))
    path.write_bytes(stream.getvalue())


def check_prestate_evidence(manifest: dict, data: bytes) -> list[str]:
    failures = []
    if len(data) > MAXIMUM_EVIDENCE_BYTES:
        fail("source evidence ZIP is too large")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if (len(entries) > MAXIMUM_EVIDENCE_FILES or len({entry.filename for entry in entries}) != len(entries)
                or sum(entry.file_size for entry in entries) > MAXIMUM_EVIDENCE_BYTES):
            fail("source evidence ZIP has duplicate entries or exceeds its file or byte bound")
        for entry in entries:
            validate_relative_path(entry.filename, "source evidence ZIP member")
            mode = entry.external_attr >> 16
            if (entry.is_dir() or entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or mode & 0o170000 not in (0, 0o100000)):
                fail(f"source evidence ZIP has an unsafe member {entry.filename}")

        def read_member(name: str, limit: int | None = None) -> bytes:
            if limit is None:
                limit = MAXIMUM_RELEASE_BYTES
            entry = archive.getinfo(name)
            if entry.file_size > limit:
                fail(f"source evidence member {name} is too large")
            with archive.open(entry) as stream:
                value = stream.read(limit + 1)
            if len(value) > limit or len(value) != entry.file_size:
                fail(f"source evidence member {name} is too large or truncated")
            return value

        def read_json(name: str) -> dict:
            value = json.loads(read_member(name))
            if not isinstance(value, dict):
                fail(f"source evidence {name} must be an object")
            return value

        index = read_json("evidence.json")
        exact_keys(index, {"schema", "report_sha256", "sources"}, set(), "source evidence")
        if index["schema"] != EVIDENCE_SCHEMA or tagged("sha256", read_member("report.json")) != index["report_sha256"]:
            fail("source evidence has an unsupported schema or changed probe report")
        report = read_json("report.json")
        if (report["schema"] != REPORT_SCHEMA or report["series"] != manifest["series"]
                or report["timestamp"] != manifest["snapshot"]["timestamp"]):
            fail("source evidence probe coordinates differ from the current manifest")
        current_pockets = {pocket["suite"]: pocket for pocket in manifest["snapshot"].get("pockets", [])}
        for pocket in report["pockets"]:
            current = current_pockets.get(pocket["suite"])
            if current is None or any(current[key] != pocket[key] for key in (
                    "role", "release_sha256", "in_release_sha256", "in_release_sha512", "signers")):
                fail(f"source evidence Release for {pocket['suite']} differs from the current manifest")
        if not isinstance(index["sources"], list):
            fail("source evidence sources must be a list")
        sources = {}
        used = {"evidence.json", "report.json"}
        for source in index["sources"]:
            exact_keys(source, {"package", "architecture", "archive_file", "lock_file", "lock_sha256",
                                "index_file", "index_path", "release_file"},
                       set(), "source evidence source")
            key = source["architecture"], source["package"]
            if key in sources:
                fail("source evidence has duplicate package/architecture coordinates")
            parse_tagged(source["lock_sha256"], ("sha256",))
            lock_bytes = read_member(source["lock_file"])
            if tagged("sha256", lock_bytes) != source["lock_sha256"]:
                fail("source evidence lock bytes changed")
            lock = json.loads(lock_bytes)
            entry = authenticated_source_package(report, lock, source["package"], source["architecture"])
            archive_bytes = read_member(source["archive_file"], MAXIMUM_EVIDENCE_BYTES)
            verify_source_archive(archive_bytes, entry)
            fields = verify_source_metadata(report, lock, source, entry, read_member(source["release_file"]),
                                            read_member(source["index_file"]))
            sources[key] = entry, archive_bytes, fields
            used.update((source["lock_file"], source["archive_file"], source["release_file"], source["index_file"]))
        if used != {entry.filename for entry in entries}:
            fail("source evidence ZIP has unreferenced members")
        needed = set()
        for identity in source_evidence_identities(manifest):
            for arch in identity["architectures"]:
                where = f"{identity['id']} independent source evidence ({arch})"
                key = arch, identity["package"]
                needed.add(key)
                if key not in sources:
                    failures.append(f"{where} is missing")
                    continue
                entry, archive_bytes, fields = sources[key]
                provenance = identity["provenance"]
                if (not isinstance(provenance, dict) or provenance["version"] != entry["version"]
                        or provenance["archives"][arch] != source_archive_digest(entry)):
                    failures.append(f"{where} disagrees on archive provenance")
                for dependency in identity.get("derived_from", []):
                    dependency_source = sources.get((arch, dependency["package"]))
                    if dependency_source is None or dependency_source[0]["version"] != dependency["version"]:
                        failures.append(f"{where} disagrees on derived source {dependency['package']}")
                derived = derive_prestate(identity, arch, archive_bytes)
                if derived is not None:
                    member, mode = derived
                    if (tagged("sha256", member) != identity["digest"] or len(member) != identity["size"]
                            or f"0{mode:03o}" != identity["mode"]):
                        failures.append(f"{where} derived bytes disagree on digest, size or mode")
                elif identity["kind"] == "archive":
                    if identity["digest"] != source_archive_digest(entry) or identity["size"] != len(archive_bytes):
                        failures.append(f"{where} archive digest or size disagrees")
                else:
                    prefix = "control.tar" if identity["kind"] == "script" else "data.tar"
                    member, mode = tar_member(archive_bytes, prefix, identity["path"])
                    if (tagged("sha256", member) != identity["digest"] or len(member) != identity["size"]
                            or f"0{mode:03o}" != identity["mode"]):
                        failures.append(f"{where} member bytes disagree on digest, size or mode")
                if "artifact" in identity and identity["artifact"] != {
                        "filename": fields["filename"], "architecture": fields["architecture"]}:
                    failures.append(f"{where} artifact filename or architecture disagrees")
        if set(sources) - needed:
            fail("source evidence has unneeded package/architecture coordinates")
    return failures


def prestate_evidence_failures(manifest: dict, root: Path) -> list[str]:
    if not source_evidence_identities(manifest):
        return []
    relative = manifest.get("prestate_evidence")
    if relative is None:
        return ["derivable prestates/artifact coordinates have no retained independent source evidence"]
    path = root / relative
    if (not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve())
            or path.stat().st_size > MAXIMUM_EVIDENCE_BYTES):
        return [f"independent source evidence {relative} is missing, unsafe or too large"]
    try:
        data = read_source_file(path, root, MAXIMUM_EVIDENCE_BYTES, f"independent source evidence {relative}")
        return check_prestate_evidence(manifest, data)
    except (RepinError, zipfile.BadZipFile, KeyError, ValueError, TypeError, OSError, EOFError) as error:
        return [f"independent source evidence {relative}: {error}"]


def zig_bytes_constant(text: str, name: str) -> str | None:
    match = re.search(r"\bconst\s+" + re.escape(name) + r"\b[^=]*=\s*(?:\[32\]u8)?\s*\.?\{(?P<body>[^}]*)\}", text)
    if match is None:
        return None
    values = ZIG_BYTE.findall(match.group("body"))
    if len(values) != hashlib.sha256().digest_size:
        return None
    return "".join(value.lower() for value in values)


def consumer_failures(identity: dict, root: Path, manifest: dict | None = None) -> list[str]:
    failures = []
    hexadecimal = identity["digest"].split(":", 1)[1]
    version = None
    if identity["version_bound"] and identity["provenance"] != "pending":
        version = identity["provenance"]["version"].split(":", 1)[-1]
    version_seen = version is None
    for consumer in identity["consumers"]:
        path = root / consumer["path"]
        where = f"{identity['id']} consumer {consumer['path']}"
        if not path.is_file() or path.is_symlink():
            failures.append(f"{where} does not exist")
            continue
        data = path.read_bytes()
        if consumer["form"] == "fixture":
            if tagged("sha256", data) != identity["digest"] or len(data) != identity["size"]:
                failures.append(f"{where} bytes do not match {identity['digest']} ({identity['size']} bytes)")
            if version is not None and version not in consumer["path"]:
                failures.append(f"{where} name does not carry version {identity['provenance']['version']}")
            version_seen = True
            continue
        text = data.decode("utf-8", "replace")
        if consumer["form"] == "shell":
            expected = {
                "digest": hexadecimal,
                "digest_size": f"{hexadecimal} {identity['size']}",
                "size": str(identity["size"]),
                "version": identity["provenance"].get("version") if isinstance(identity["provenance"], dict) else None,
                "member": "./" + identity["path"] if identity["path"] is not None else None,
            }
            if manifest is not None and "artifact" in identity:
                expected["url"] = snapshot_uri(manifest["series"], manifest["snapshot"]["timestamp"]) + "/" + identity["artifact"]["filename"]
            failures += shell_coordinate_failures(text, consumer["bindings"], expected, where)
            if "version" in consumer["bindings"] or "url" in consumer["bindings"]:
                version_seen = True
            continue
        if version is not None and version in text:
            version_seen = True
        if consumer["form"] == "hex":
            if hexadecimal not in text:
                failures.append(f"{where} does not pin {identity['digest']}")
        elif zig_bytes_constant(text, consumer["name"]) != hexadecimal:
            failures.append(f"{where} constant {consumer['name']} is not {identity['digest']}")
    if not version_seen:
        failures.append(f"{identity['id']} is version-bound but no consumer names {identity['provenance']['version']}")
    return failures


def in_tree_pins(root: Path) -> list[tuple[str, str, dict]]:
    """Returns (location, hex, detail) for every snapshot pin found in the tree.

    Every digest literal in the admission sources and reference scripts counts:
    each must be a manifest identity or an explained exclusion.
    """
    pins: list[tuple[str, str, dict]] = []
    for path in sorted(root.glob(FIXTURE_GLOB)):
        data = path.read_bytes()
        pins.append((str(path.relative_to(root)), hashlib.sha256(data).hexdigest(), {"fixture": True, "size": len(data)}))
    for relative in DEBZ_SNAPSHOT_CONSTANT_SOURCES:
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in SNAPSHOT_CONSTANT.finditer(text):
            name = match.group(1)
            value = zig_bytes_constant(text, name)
            if value is not None:
                pins.append((f"{relative}:{name}", value, {}))
            elif QUOTED_HEX_LITERAL.match(text, match.end()) is None and not re.match(
                r'\s*digestLiteral\(\s*"', text[match.end():match.end() + 64]
            ):
                pins.append((f"{relative}:{name}", "", {"unparsed": True}))
        for match in SNAPSHOT_INPUT_ENTRY.finditer(text):
            mode = match.group("mode") or match.group("leading_mode")
            detail = {"path": match.group("path"), "size": int(match.group("size"))}
            if mode is not None:
                detail["mode"] = "0" + mode
            pins.append((f"{relative}:{match.group('path')}", match.group("hex"), detail))
        for match in SNAPSHOT_ARCHIVE_ENTRY.finditer(text):
            detail = {"package": match.group("package"), "version": match.group("version"),
                      "architecture": match.group("arch"), "archive_size": int(match.group("size"))}
            pins.append((f"{relative}:archive:{match.group('package')}", match.group("hex"), detail))
        for match in QUOTED_HEX_LITERAL.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            pins.append((f"{relative}:{line}", match.group(1), {}))
    for path in sorted(root.glob(PIN_SCRIPT_GLOB)):
        text = path.read_text(encoding="utf-8")
        for match in HEX_LITERAL.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            pins.append((f"{path.relative_to(root)}:{line}", match.group(0), {}))
    return pins


def bound_paths(identity: dict) -> set[str]:
    """Paths under which in-tree admissions may name the identity's bytes."""
    if identity["path"] is None:
        return set()
    if identity["kind"] == "script":
        return {identity["path"], f"var/lib/dpkg/info/{identity['package']}.{identity['path']}"}
    return {identity["path"]}


def shell_readonly_scalars(text: str) -> dict[str, str | None]:
    values = {}
    for line in text.splitlines():
        match = re.match(r"^\s*readonly\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if match is None:
            continue
        name = match.group(1)
        if name in values:
            values[name] = None
            continue
        values[name] = None
        raw = match.group(2).strip()
        if raw.startswith("("):
            continue
        try:
            words = shlex.split(raw, comments=True, posix=True)
        except ValueError:
            continue
        if len(words) == 1:
            values[name] = words[0]
    return values


def shell_readonly_array(text: str, pattern: re.Pattern[str]) -> list[str] | None:
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        return None
    match = matches[0]
    try:
        return shlex.split(match.group("body"), comments=True, posix=True)
    except ValueError:
        return None


def shell_coordinate_failures(text: str, bindings: dict, expected: dict, where: str) -> list[str]:
    failures = []
    scalars = shell_readonly_scalars(text)
    for coordinate, name in bindings.items():
        wanted = expected.get(coordinate)
        declarations = re.findall(r"(?m)^\s*readonly\s+" + re.escape(name) + r"=", text)
        if len(declarations) != 1:
            actual = None
        elif isinstance(wanted, list):
            pattern = re.compile(r"(?ms)^\s*readonly\s+" + re.escape(name) + r"=\((?P<body>[^)]*)\)")
            actual = shell_readonly_array(text, pattern)
        else:
            actual = scalars.get(name)
        if wanted is None or actual != wanted:
            failures.append(f"{where} {coordinate} ({name}) is {actual!r}, expected {wanted!r}")
    return failures


def snapshot_coordinate_failures(manifest: dict, root: Path) -> list[str]:
    failures = []
    frozen = frozen_pocket(manifest["snapshot"])
    frozen_suites = [p["suite"] for p in manifest["series"]["pockets"] if p["role"] == "frozen"]
    expected = {
        "uri": snapshot_uri(manifest["series"], manifest["snapshot"]["timestamp"]),
        "suite": frozen_suites[0] if len(frozen_suites) == 1 else None,
        "witness_suites": [p["suite"] for p in manifest["series"]["pockets"] if p["role"] == "witness"],
        "release_sha256": frozen["release_sha256"].split(":", 1)[1] if frozen is not None else None,
    }
    for consumer in manifest.get("coordinate_consumers", []):
        path = root / consumer["path"]
        where = f"snapshot coordinate consumer {consumer['path']}"
        if not path.is_file() or path.is_symlink():
            failures.append(f"{where} does not exist")
        else:
            failures += shell_coordinate_failures(path.read_text(encoding="utf-8"), consumer["bindings"], expected, where)
    return failures


def protected_stage_profile_coupling_failures(manifest: dict, root: Path) -> list[str]:
    """Check the protected stage, launcher profile pins and manifest agree.

    The amd64 protected stage extracts postinsts from the configured snapshot
    repositories, while the launcher independently pins those same postinsts by
    version, byte size and SHA-256. This local check makes that cross-file
    contract explicit so a suite revert cannot silently strand profile pins on
    another series until the protected CI proof runs.
    """
    stage_path = root / PROTECTED_STAGE_SCRIPT
    launcher_path = root / REFERENCE_LAUNCHER
    if not stage_path.exists() and not launcher_path.exists():
        return []
    failures = []
    if not stage_path.is_file() or stage_path.is_symlink():
        return [f"protected profile coupling: {PROTECTED_STAGE_SCRIPT} does not exist"]
    if not launcher_path.is_file() or launcher_path.is_symlink():
        return [f"protected profile coupling: {REFERENCE_LAUNCHER} does not exist"]
    stage = stage_path.read_text(encoding="utf-8")
    launcher = launcher_path.read_text(encoding="utf-8")

    frozen_pockets = [pocket for pocket in manifest["series"]["pockets"] if pocket["role"] == "frozen"]
    if frozen_pockets:
        if len(frozen_pockets) != 1:
            failures.append("protected stage profile coupling: series must have exactly one frozen pocket")
        else:
            frozen_suite = frozen_pockets[0]["suite"]
            witness_suites = [
                pocket["suite"] for pocket in manifest["series"]["pockets"] if pocket["role"] == "witness"
            ]
            scalars = shell_readonly_scalars(stage)
            if scalars.get("snapshot_uri") != snapshot_uri(manifest["series"], manifest["snapshot"]["timestamp"]):
                failures.append(
                    f"protected stage profile coupling: {PROTECTED_STAGE_SCRIPT} does not pin "
                    f"{snapshot_uri(manifest['series'], manifest['snapshot']['timestamp'])}"
                )
            if scalars.get("snapshot_suite") != frozen_suite:
                failures.append(
                    f"protected stage profile coupling: snapshot_suite={scalars.get('snapshot_suite')!r}, "
                    f"expected frozen suite {frozen_suite!r}"
                )
            stage_witnesses = shell_readonly_array(stage, STAGE_WITNESS_ARRAY)
            if stage_witnesses != witness_suites:
                failures.append(
                    f"protected stage profile coupling: snapshot_witness_suites={stage_witnesses!r}, "
                    f"expected {witness_suites!r}"
                )
            frozen_records = [
                pocket for pocket in manifest["snapshot"].get("pockets", [])
                if pocket["suite"] == frozen_suite and pocket["role"] == "frozen"
            ]
            if frozen_records:
                expected_digest = frozen_records[0]["release_sha256"].split(":", 1)[1]
                if scalars.get("frozen_release_sha256") != expected_digest:
                    failures.append(
                        f"protected stage profile coupling: frozen_release_sha256="
                        f"{scalars.get('frozen_release_sha256')!r}, expected {expected_digest!r}"
                    )

    bindings = [match.groupdict() for match in SCRIPT_BINDING_ENTRY.finditer(launcher)]
    if not bindings:
        failures.append(f"protected stage profile coupling: {REFERENCE_LAUNCHER} has no script_bindings")
        return failures
    profile_match = STAGE_PROFILE_LOOP.search(stage)
    if profile_match is None:
        failures.append(f"protected stage profile coupling: {PROTECTED_STAGE_SCRIPT} has no profile staging loop")
    else:
        try:
            staged_profiles = shlex.split(profile_match.group("body"), comments=True, posix=True)
        except ValueError:
            staged_profiles = []
        binding_names = [binding["name"] for binding in bindings]
        if staged_profiles != binding_names:
            failures.append(
                f"protected stage profile coupling: staged profiles {staged_profiles!r} "
                f"do not match launcher bindings {binding_names!r}"
            )

    identities = {identity["id"]: identity for identity in manifest["identities"]}
    for binding in bindings:
        identity_id = f"script:{binding['name']}/postinst"
        identity = identities.get(identity_id)
        if identity is None:
            failures.append(f"protected stage profile coupling: {identity_id} is not a manifest identity")
            continue
        expected_digest = "sha256:" + binding["digest"]
        if identity["digest"] != expected_digest:
            failures.append(
                f"protected stage profile coupling: {REFERENCE_LAUNCHER} {binding['name']} digest "
                f"{expected_digest} disagrees with {identity_id} {identity['digest']}"
            )
        if identity["size"] != int(binding["size"]):
            failures.append(
                f"protected stage profile coupling: {REFERENCE_LAUNCHER} {binding['name']} size "
                f"{binding['size']} disagrees with {identity_id} {identity['size']}"
            )
        provenance = identity["provenance"]
        version = provenance.get("version") if isinstance(provenance, dict) else None
        if version != binding["version"]:
            failures.append(
                f"protected stage profile coupling: {REFERENCE_LAUNCHER} {binding['name']} version "
                f"{binding['version']!r} disagrees with {identity_id} provenance {version!r}"
            )
        if identity["architectures"] != ["amd64"]:
            failures.append(f"protected stage profile coupling: {identity_id} must be amd64-only")
        if not any(
            consumer["form"] == "hex" and consumer["path"] == REFERENCE_LAUNCHER
            for consumer in identity["consumers"]
        ):
            failures.append(
                f"protected stage profile coupling: {identity_id} does not register "
                f"{REFERENCE_LAUNCHER} as a hex consumer"
            )
    return failures


def check_manifest(manifest: dict, root: Path, profile: dict | None = None) -> list[str]:
    failures: list[str] = []
    series = manifest["series"]
    expected = profile
    if expected is None and series["name"] in PROFILES:
        expected = {"name": series["name"], **PROFILES[series["name"]]}
    if expected is None:
        failures.append(f"series {series['name']} is not a built-in profile; pass --profile")
    elif expected != series:
        failures.append(f"series {series['name']} differs from its reviewed profile")
    uri = snapshot_uri(series, manifest["snapshot"]["timestamp"])
    for relative in manifest["uri_consumers"]:
        path = root / relative
        if not path.is_file():
            failures.append(f"URI consumer {relative} does not exist")
            continue
        text = path.read_text(encoding="utf-8")
        if uri not in text:
            failures.append(f"URI consumer {relative} does not pin {uri}")
        others = {match.group(1) for match in SNAPSHOT_URI.finditer(text)} - {manifest["snapshot"]["timestamp"]}
        for other in sorted(others):
            failures.append(f"URI consumer {relative} pins another snapshot {other}")
    digests: dict[str, dict] = {}
    for pocket in manifest["snapshot"].get("pockets", []):
        digests[pocket["release_sha256"].split(":", 1)[1]] = {"id": f"release:{pocket['suite']}", "path": None, "size": None}
        digests[pocket["in_release_sha256"].split(":", 1)[1]] = {"id": f"in-release:{pocket['suite']}", "path": None, "size": None}
    for arch, closure in manifest["snapshot"].get("closures", {}).items():
        digests[closure["digest"].split(":", 1)[1]] = {"id": f"closure:{arch}", "path": None, "size": None}
    for identity in manifest["identities"]:
        failures += consumer_failures(identity, root, manifest)
        digests.setdefault(identity["digest"].split(":", 1)[1], identity)
    failures += protected_stage_profile_coupling_failures(manifest, root)
    failures += snapshot_coordinate_failures(manifest, root)
    failures += prestate_evidence_failures(manifest, root)
    excluded = {item["digest"].split(":", 1)[1] for item in manifest["excluded"]}
    fixture_consumers = {
        consumer["path"]
        for identity in manifest["identities"]
        for consumer in identity["consumers"]
        if consumer["form"] == "fixture"
    }
    for location, value, detail in in_tree_pins(root):
        if detail.get("unparsed"):
            failures.append(f"cannot parse the snapshot pin {location}")
            continue
        if detail.get("fixture") and location not in fixture_consumers:
            failures.append(f"fixture {location} is not a manifest identity consumer")
            continue
        if value in excluded:
            continue
        identity = digests.get(value)
        if identity is None:
            failures.append(f"in-tree pin {location} {value[:16]}... is absent from the manifest")
            continue
        if "archive_size" in detail and (
            identity.get("kind") != "archive" or identity["package"] != detail["package"]
            or identity["size"] != detail["archive_size"] or detail["architecture"] not in identity["architectures"]
            or not isinstance(identity["provenance"], dict) or identity["provenance"]["version"] != detail["version"]
        ):
            failures.append(f"in-tree pin {location} disagrees with {identity['id']} on archive version, size or architecture")
        if "path" in detail and (
            detail["path"] not in bound_paths(identity)
            or identity["size"] != detail["size"]
            or ("mode" in detail and identity["mode"] not in (None, detail["mode"]))
        ):
            failures.append(f"in-tree pin {location} disagrees with {identity['id']} on path, size or mode")
    return failures


def check_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    profile = None
    if args.profile is not None:
        profile = validate_profile(load_json(args.profile), "profile")
    failures = check_manifest(manifest, args.root.resolve(), profile)
    if failures:
        for failure in failures:
            print(f"check: {failure}", file=sys.stderr)
        return 1
    status = manifest["snapshot"]["status"]
    print(
        f"check passed: {len(manifest['identities'])} identities for {manifest['series']['name']} "
        f"{manifest['snapshot']['timestamp']} ({status})"
    )
    if source_evidence_identities(manifest):
        print(f"offline retained source evidence: {len(source_evidence_identities(manifest))} byte identities verified; no live probe")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    probe_parser = commands.add_parser("probe", help="authenticate and record one settled snapshot")
    probe_parser.add_argument("--series", required=True)
    probe_parser.add_argument("--timestamp")
    probe_parser.add_argument("--debz", required=True)
    probe_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    probe_parser.add_argument("--profile", type=Path)
    probe_parser.add_argument("--workspace", type=Path)
    probe_parser.add_argument("--accept-frozen-release", action="store_true")

    diff_parser = commands.add_parser("diff", help="compare a probe report with the manifest")
    diff_parser.add_argument("--report", type=Path, required=True)
    diff_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    diff_parser.add_argument("--pr", type=int, action="append")
    diff_parser.add_argument("--pr-diff-file", type=Path, action="append")
    diff_parser.add_argument("--root", type=Path, default=ROOT)
    diff_parser.add_argument("--allow-series-migration", action="store_true")

    record_parser = commands.add_parser("record", help="rewrite the manifest from a probe report")
    record_parser.add_argument("--report", type=Path, required=True)
    record_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    record_parser.add_argument("--reviewed", action="append", metavar="ID=REF")
    record_parser.add_argument("--accept-frozen-release", metavar="REF")
    record_parser.add_argument("--root", type=Path, default=ROOT)
    record_parser.add_argument("--allow-series-migration", action="store_true")

    architecture_parser = commands.add_parser(
        "bind-architecture", help="bind a byte-identical script from retained authenticated source archives",
    )
    architecture_parser.add_argument("--identity", required=True)
    architecture_parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    architecture_parser.add_argument("--reviewed", required=True, metavar="REF")
    architecture_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    architecture_parser.add_argument("--root", type=Path, default=ROOT)

    member_parser = commands.add_parser("bind-member", help="derive a member identity from a retained reviewed archive")
    member_parser.add_argument("--archive-identity", required=True)
    member_parser.add_argument("--member", required=True)
    member_parser.add_argument("--consumer", action="append", choices=DEBZ_SNAPSHOT_CONSTANT_SOURCES, required=True)
    member_parser.add_argument("--reviewed", required=True, metavar="REF")
    member_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    member_parser.add_argument("--root", type=Path, default=ROOT)

    check_parser = commands.add_parser("check", help="offline: verify in-tree pins against the manifest")
    check_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    check_parser.add_argument("--root", type=Path, default=ROOT)
    check_parser.add_argument("--profile", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            return probe(args)
        if args.command == "diff":
            return diff_command(args)
        if args.command == "record":
            return record_command(args)
        if args.command == "bind-architecture":
            return bind_architecture_command(args)
        if args.command == "bind-member":
            return bind_member_command(args)
        return check_command(args)
    except RepinError as error:
        print(f"real-snapshot-repin: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
