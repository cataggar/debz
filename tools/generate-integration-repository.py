#!/usr/bin/env python3
"""Build a bounded, deterministic signed Debian repository for integration tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
EPOCH = 1_700_000_000
MAX_REPOSITORY_BYTES = 8 * 1024 * 1024
INTEGRATION_SIGNING = pathlib.Path(os.environ.get(
    "DEBZ_INTEGRATION_SIGNING", ROOT / "zig-out/bin/debz-integration-signing",
))
INTEGRATION_ARCHIVE = pathlib.Path(os.environ.get(
    "DEBZ_INTEGRATION_ARCHIVE", ROOT / "zig-out/bin/debz-integration-archive",
))


def require_native_signing() -> None:
    if not INTEGRATION_SIGNING.is_absolute() or not INTEGRATION_SIGNING.is_file() or not os.access(INTEGRATION_SIGNING, os.X_OK):
        raise FileNotFoundError(f"required absolute native integration signer: {INTEGRATION_SIGNING}")


def native_signing(release: bytes) -> tuple[bytes, bytes, str]:
    require_native_signing()
    if len(release) > MAX_REPOSITORY_BYTES:
        raise RuntimeError("integration signing input exceeds its byte limit")
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="integration-signing-", dir=ROOT / ".tmp") as directory:
        path = pathlib.Path(directory, "Release")
        path.write_bytes(release)
        result = subprocess.run(
            [str(INTEGRATION_SIGNING), str(path)], capture_output=True,
            stdin=subprocess.DEVNULL, timeout=30, check=False,
        )
    if result.returncode:
        raise RuntimeError(f"native integration signing exited {result.returncode}: {result.stderr.decode(errors='replace')}")
    signed = json.loads(result.stdout)
    return bytes.fromhex(signed["keyring"]), bytes.fromhex(signed["in_release"]), signed["fingerprint"]


def require_native_archive() -> None:
    if not INTEGRATION_ARCHIVE.is_file() or not os.access(INTEGRATION_ARCHIVE, os.X_OK):
        raise FileNotFoundError(f"required native integration archive encoder: {INTEGRATION_ARCHIVE}")


def native_archive(
    control: list[tuple[str, bytes, int]], data: list[tuple[str, bytes, int]],
    *, origin: str | None = None,
) -> bytes:
    require_native_archive()

    def entries(values: list[tuple[str, bytes, int]]) -> list[dict[str, str | int]]:
        return [{"name": name, "hex": body.hex(), "mode": mode} for name, body, mode in values]

    document = json.dumps({"control": entries(control), "data": entries(data), "origin": origin}).encode()
    if len(document) > MAX_REPOSITORY_BYTES * 2:
        raise RuntimeError("native integration archive request exceeds its byte limit")
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="integration-archive-", dir=ROOT / ".tmp") as directory:
        pathlib.Path(directory, "request.json").write_bytes(document)
        result = subprocess.run(
            [str(INTEGRATION_ARCHIVE), directory], capture_output=True,
            stdin=subprocess.DEVNULL, timeout=30, check=False,
        )
    if result.returncode:
        raise RuntimeError(f"native integration archive exited {result.returncode}: {result.stderr.decode(errors='replace')}")
    return result.stdout


def build_deb(
    package: str,
    version: str,
    architecture: str,
    fields: dict[str, str],
    *,
    failing_postinst: bool = False,
    conffile: bool = False,
    trigger: str | None = None,
    helper_target: bool = False,
    native_trigger: bool = False,
    literal_paths: bool = False,
    retained_metadata: bool = False,
) -> bytes:
    control_fields = {
        "Package": package,
        "Version": version,
        "Architecture": architecture,
        "Maintainer": "debz fixture <fixture.invalid>",
        "Description": f"debz hermetic fixture {package}",
        **fields,
    }
    control = "".join(f"{name}: {value}\n" for name, value in control_fields.items()).encode()
    control_entries = [("./control", control, 0o644)]
    if retained_metadata:
        control_entries.extend((
            ("./templates", f"Template: {package}/value\nType: string\nDescription: inert metadata\n".encode(), 0o644),
            ("./shlibs", f"libretained 1 {package} (>= {version})\n".encode(), 0o640),
            ("./symbols", f"libretained.so.1 {package} #MINVER#\n symbol@Base 1\n".encode() + b"\x00\xff", 0o644),
        ))
    if failing_postinst:
        control_entries.append(("./postinst", b"#!/bin/sh\nexit 42\n", 0o755))
    if conffile:
        control_entries.append(("./conffiles", b"/etc/debz-fixture.conf\n", 0o644))
    if trigger:
        control_entries.append(("./triggers", f"interest-noawait {trigger}\n".encode(), 0o644))
    if native_trigger:
        control_entries.append(("./triggers", b"interest-noawait native-fixture\nactivate-noawait native-fixture\n", 0o644))
        control_entries.append(("./postinst", (
            b'#!/bin/sh\nset -e\nprintf "%s\\n" "$*" >>/native-trigger-trace\n'
            b'if [ "$1" = configure ]; then /usr/bin/dpkg-trigger --no-await native-fixture; fi\n'
        ), 0o755))
    payload_path = "./etc/debz-fixture.conf" if conffile else f"./usr/share/debz-fixtures/{package}"
    data = f"{package}={version}:{architecture}\n".encode()
    if helper_target:
        payload_path = "./usr/bin/dpkg-trigger"
    if literal_paths:
        payload_path = "./usr/lib/systemd/system/system-debz\\x2dliteral.slice"
    return native_archive(control_entries, [(payload_path, data, 0o644)])


def package_specs(suite: str, architecture: str, *, signed_parity: bool = False):
    suite_version = "1.0-1debian1" if suite == "debian-stable" else "1.0-1ubuntu1"
    specs = [
        ("ca-certificates", "20240203", "all", {}, {}),
        ("base-dep", "1.0-1", architecture, {}, {}),
        ("native-helper-target", "1.0-1", architecture, {}, {"helper_target": True}),
        ("native-trigger-pkg", "1.0-1", architecture, {}, {"native_trigger": True}),
        ("literal-paths-pkg", "1.0-1", architecture, {}, {"literal_paths": True}),
        ("retained-metadata-pkg", "1.0-1", architecture, {"Multi-Arch": "same"}, {"retained_metadata": True}),
        ("pre-app", "1.0-1", architecture, {"Pre-Depends": "base-dep"}, {}),
        ("alt-a", "1.0-1", architecture, {}, {}),
        ("alt-b", "2.0-1", architecture, {}, {}),
        ("alt-consumer", "1.0-1", architecture, {"Depends": "alt-a | alt-b"}, {}),
        ("virtual-provider", "2.0-1", architecture, {"Provides": "virtual-api (= 2.0)"}, {}),
        ("virtual-consumer", "1.0-1", architecture, {"Depends": "virtual-api (>= 2.0)"}, {}),
        ("recommended-addon", "1.0-1", "all", {}, {}),
        ("recommend-app", "1.0-1", architecture, {"Recommends": "recommended-addon"}, {}),
        ("conflict-old", "1.0-1", architecture, {"Conflicts": "conflict-new"}, {}),
        (
            "conflict-new",
            "2.0-1",
            architecture,
            {"Conflicts": "conflict-old", "Breaks": "conflict-old", "Replaces": "conflict-old"},
            {},
        ),
        ("essential-core", "1.0-1", architecture, {"Essential": "yes"}, {}),
        ("protected-core", "1.0-1", architecture, {"Protected": "yes"}, {}),
        ("multi-lib", "1.0-1", architecture, {"Multi-Arch": "same"}, {}),
        ("cycle-a", "1.0-1", architecture, {"Depends": "cycle-b"}, {}),
        ("cycle-b", "1.0-1", architecture, {"Depends": "cycle-a"}, {}),
        ("fixture-upgrade", "1.0-1", architecture, {}, {}),
        ("fixture-upgrade", "2.0-1", architecture, {}, {}),
        ("conffile-pkg", "1.0-1", architecture, {}, {"conffile": True}),
        ("trigger-pkg", suite_version, architecture, {}, {"trigger": "/usr/share/debz-fixtures"}),
        ("fail-script", "1.0-1", architecture, {}, {"failing_postinst": True}),
        (
            "scenario-main",
            "1.0-1",
            architecture,
            {
                "Depends": "base-dep",
                "Recommends": "recommended-addon",
            },
            {},
        ),
    ]
    if signed_parity:
        specs.append(("pre-fail-app", "1.0-1", architecture, {"Pre-Depends": "fail-script"}, {}))
    return specs


def extra_control(deb: bytes) -> str:
    require_native_archive()
    if len(deb) > MAX_REPOSITORY_BYTES:
        raise RuntimeError("extra package exceeds its byte limit")
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="integration-extra-control-", dir=ROOT / ".tmp") as directory:
        path = pathlib.Path(directory, "extra.deb")
        path.write_bytes(deb)
        result = subprocess.run(
            [str(INTEGRATION_ARCHIVE), "--extra-control", str(path)],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=30, check=False,
        )
    if result.returncode:
        raise RuntimeError(f"native extra package parsing exited {result.returncode}: {result.stderr.decode(errors='replace')}")
    return result.stdout.decode("utf-8")


def control_field(text: str, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}: ([^\n]+)$", text)
    if match is None:
        raise RuntimeError(f"extra package control lacks {name}")
    return match.group(1).strip()


def write_repository(
    output: pathlib.Path,
    suite: str,
    architecture: str,
    *,
    signed_parity: bool = False,
    sha256_only: bool = False,
    extra_debs: list[pathlib.Path] | None = None,
) -> None:
    if signed_parity and sha256_only:
        raise ValueError("--signed-parity requires published SHA512 records")
    require_native_signing()
    require_native_archive()
    if output.exists():
        shutil.rmtree(output)
    packages_dir = output / "dists" / suite / "main" / f"binary-{architecture}"
    pool = output / "pool" / "main"
    packages_dir.mkdir(parents=True)
    pool.mkdir(parents=True)

    paragraphs: list[bytes] = []
    for package, version, package_arch, fields, options in package_specs(suite, architecture, signed_parity=signed_parity):
        deb = build_deb(package, version, package_arch, fields, **options)
        filename = f"pool/main/{package}_{version}_{package_arch}.deb"
        path = output / filename
        path.write_bytes(deb)
        digest = hashlib.sha256(deb).hexdigest()
        installed_size = max(1, len(deb) // 1024)
        paragraph = {
            "Package": package,
            "Version": version,
            "Architecture": package_arch,
            "Maintainer": "debz fixture <fixture.invalid>",
            "Installed-Size": str(installed_size),
            **fields,
            "Filename": filename,
            "Size": str(len(deb)),
            "SHA256": digest,
            # Native engine consumers require a SHA-512 archive identity
            # (#261). --sha256-only models Debian's SHA256-only publication.
            **({} if sha256_only else {"SHA512": hashlib.sha512(deb).hexdigest()}),
            "Description": f"debz hermetic fixture {package}",
        }
        paragraphs.append("".join(f"{key}: {value}\n" for key, value in paragraph.items()).encode() + b"\n")

    # Prebuilt packages, such as FIFO payloads written by the real dpkg-deb,
    # keep their exact bytes and control paragraph; only the repository
    # transport fields are appended.
    seen = {(package, version) for package, version, *_ in package_specs(suite, architecture, signed_parity=signed_parity)}
    for extra in extra_debs or []:
        deb = extra.read_bytes()
        control = extra_control(deb)
        package = control_field(control, "Package")
        version = control_field(control, "Version")
        package_arch = control_field(control, "Architecture")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package) or not re.fullmatch(r"[0-9][A-Za-z0-9.+~-]*", version):
            raise RuntimeError(f"extra package identity is not a plain fixture identity: {package} {version}")
        if package_arch not in (architecture, "all"):
            raise RuntimeError(f"extra package architecture {package_arch} is not {architecture} or all")
        if (package, version) in seen:
            raise RuntimeError(f"extra package duplicates {package} {version}")
        seen.add((package, version))
        filename = f"pool/main/{package}_{version}_{package_arch}.deb"
        (output / filename).write_bytes(deb)
        transport = {
            "Filename": filename,
            "Size": str(len(deb)),
            "SHA256": hashlib.sha256(deb).hexdigest(),
            **({} if sha256_only else {"SHA512": hashlib.sha512(deb).hexdigest()}),
        }
        paragraphs.append((control + "".join(f"{key}: {value}\n" for key, value in transport.items())).encode() + b"\n")

    packages = b"".join(paragraphs)
    packages_path = packages_dir / "Packages"
    packages_path.write_bytes(packages)
    relative_packages = f"main/binary-{architecture}/Packages"
    release = (
        f"Origin: debz hermetic {suite}\n"
        f"Label: debz integration fixture\n"
        f"Suite: {suite}\n"
        f"Codename: {suite}\n"
        "Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
        "Valid-Until: Thu, 01 Jan 2037 00:00:00 +0000\n"
        f"Architectures: {architecture}\n"
        "Components: main\n"
        "Acquire-By-Hash: no\n"
        "SHA256:\n"
        f" {hashlib.sha256(packages).hexdigest()} {len(packages)} {relative_packages}\n"
    ).encode()

    keyring, in_release, primary_fingerprint = native_signing(release)
    (output / "dists" / suite / "InRelease").write_bytes(in_release)
    (output / "fixture-keyring.gpg").write_bytes(keyring)
    manifest = (
        f"suite={suite}\narchitecture={architecture}\n"
        f"release_sha256={hashlib.sha256(release).hexdigest()}\n"
        f"packages_sha256={hashlib.sha256(packages).hexdigest()}\n"
        f"signer={primary_fingerprint}\n"
    )
    (output / "fixture-provenance.txt").write_text(manifest)
    total = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    if total > MAX_REPOSITORY_BYTES:
        raise RuntimeError(f"fixture repository exceeds {MAX_REPOSITORY_BYTES} bytes")


def write_repository_descriptor(
    output: pathlib.Path,
    repository_url: str,
    suite: str,
    architecture: str,
    keyring: bytes,
    *,
    scripts: dict[str, bytes] | None = None,
) -> None:
    require_native_archive()
    source_path = "etc/apt/sources.list.d/microsoft-prod.list"
    keyring_path = "usr/share/keyrings/microsoft-prod.gpg"
    package = "packages-microsoft-prod"
    control = (
        f"Package: {package}\n"
        "Version: 1.2-fixture\n"
        "Architecture: all\n"
        "Depends: ca-certificates\n"
        "Maintainer: debz fixture <fixture.invalid>\n"
        "Description: Microsoft-shaped repository descriptor fixture\n"
    ).encode()
    script = b"#!/bin/sh\nset -e\nexit 0\n"
    scripts = scripts or {}
    control_entries = [
        ("./control", control, 0o644),
        ("./conffiles", f"/{source_path}\n".encode(), 0o644),
        ("./preinst", scripts.get("preinst", script), 0o755),
        ("./postinst", scripts.get("postinst", script), 0o755),
        ("./prerm", scripts.get("prerm", script), 0o755),
    ]
    source = (
        f"deb [arch={architecture} signed-by=/{keyring_path}] "
        f"{repository_url} {suite} main\n"
    ).encode()
    data_entries = [
        (f"./{source_path}", source, 0o644),
        (f"./{keyring_path}", keyring, 0o644),
        (
            "./etc/debsig/policies/fixture/packages-microsoft-prod.pol",
            b"<Policy xmlns=\"https://www.debian.org/debsig/1.0/\"/>\n",
            0o644,
        ),
        (
            "./usr/share/debsig/keyrings/fixture/debsig.gpg",
            keyring,
            0o644,
        ),
        (
            f"./usr/share/doc/{package}/README",
            b"Hermetic Microsoft-shaped descriptor fixture.\n",
            0o644,
        ),
    ]
    descriptor = native_archive(control_entries, data_entries, origin="fixture structural signature member")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(descriptor)


def main() -> None:
    global INTEGRATION_SIGNING, INTEGRATION_ARCHIVE
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--suite", required=True, choices=("debian-stable", "ubuntu-26.04"))
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--signed-parity", action="store_true")
    parser.add_argument("--sha256-only", action="store_true")
    parser.add_argument("--extra-deb", action="append", default=[], type=pathlib.Path)
    parser.add_argument("--signing-helper", type=pathlib.Path)
    parser.add_argument("--archive-helper", type=pathlib.Path)
    parser.add_argument("--descriptor-output", type=pathlib.Path)
    parser.add_argument("--descriptor-repository-url")
    parser.add_argument(
        "--descriptor-script-case",
        choices=("default", "trace", "known_failure", "blocked"),
        default="default",
    )
    args = parser.parse_args()
    if args.signing_helper is not None:
        if not args.signing_helper.is_absolute():
            raise SystemExit("--signing-helper must be absolute")
        INTEGRATION_SIGNING = args.signing_helper
    if args.archive_helper is not None:
        if not args.archive_helper.is_absolute():
            raise SystemExit("--archive-helper must be absolute")
        INTEGRATION_ARCHIVE = args.archive_helper
    if not args.output.is_absolute():
        raise SystemExit("--output must be absolute")
    if (args.descriptor_output is None) != (args.descriptor_repository_url is None):
        raise SystemExit("--descriptor-output and --descriptor-repository-url must be used together")
    if args.descriptor_output is not None and not args.descriptor_output.is_absolute():
        raise SystemExit("--descriptor-output must be absolute")
    if args.descriptor_script_case != "default" and args.descriptor_output is None:
        raise SystemExit("--descriptor-script-case requires --descriptor-output")
    if args.signed_parity and args.sha256_only:
        raise SystemExit("--signed-parity and --sha256-only are mutually exclusive")
    if any(not path.is_absolute() for path in args.extra_deb):
        raise SystemExit("--extra-deb must be absolute")
    write_repository(
        args.output,
        args.suite,
        args.architecture,
        signed_parity=args.signed_parity,
        sha256_only=args.sha256_only,
        extra_debs=args.extra_deb,
    )
    if args.descriptor_output is not None:
        scripts = None
        if args.descriptor_script_case != "default":
            postinst = b"#!/bin/sh\nprintf 'postinst\\n' >>/repository-trace\n"
            if args.descriptor_script_case == "known_failure":
                postinst += b"exit 42\n"
            elif args.descriptor_script_case == "blocked":
                postinst += (
                    b"printf entered >/fixture/postinst-entered\n"
                    b"while [ ! -f /fixture/finish-script ]; do /bin/sleep 0.02; done\n"
                )
            scripts = {
                "preinst": b"#!/bin/sh\nprintf 'preinst\\n' >>/repository-trace\n",
                "postinst": postinst,
            }
        write_repository_descriptor(
            args.descriptor_output,
            args.descriptor_repository_url,
            args.suite,
            args.architecture,
            (args.output / "fixture-keyring.gpg").read_bytes(),
            scripts=scripts,
        )


if __name__ == "__main__":
    main()
