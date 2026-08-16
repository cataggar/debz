#!/usr/bin/env python3
"""Build a bounded, deterministic signed Debian repository for integration tests."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import pathlib
import shutil
import tarfile

from cryptography.hazmat.primitives import serialization

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_MODULE = ROOT / "tools/generate-openpgp-fixtures.py"
EPOCH = 1_700_000_000
MAX_REPOSITORY_BYTES = 8 * 1024 * 1024


def load_openpgp_fixture_module():
    spec = importlib.util.spec_from_file_location("debz_openpgp_fixture", FIXTURE_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load OpenPGP fixture generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tar_member(name: str, data: bytes, mode: int = 0o644) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = mode
    member.uid = member.gid = 0
    member.uname = member.gname = "root"
    member.mtime = EPOCH
    return member


def tar_gz(entries: list[tuple[str, bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directories: set[str] = set()
        for name, data, mode in entries:
            parent = pathlib.PurePosixPath(name).parent
            parents: list[pathlib.PurePosixPath] = []
            while str(parent) not in (".", ""):
                parents.append(parent)
                parent = parent.parent
            for directory in reversed(parents):
                directory_name = str(directory)
                if directory_name in directories:
                    continue
                member = tar_member(directory_name, b"", 0o755)
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
                directories.add(directory_name)
            archive.addfile(tar_member(name, data, mode), io.BytesIO(data))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=EPOCH, filename="") as stream:
        stream.write(raw.getvalue())
    return output.getvalue()


def ar_member(name: str, data: bytes) -> bytes:
    header = (
        f"{name}/".ljust(16)
        + str(EPOCH).ljust(12)
        + "0".ljust(6)
        + "0".ljust(6)
        + "100644".ljust(8)
        + str(len(data)).ljust(10)
        + "`\n"
    ).encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def build_deb(
    package: str,
    version: str,
    architecture: str,
    fields: dict[str, str],
    *,
    failing_postinst: bool = False,
    conffile: bool = False,
    trigger: str | None = None,
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
    if failing_postinst:
        control_entries.append(("./postinst", b"#!/bin/sh\nexit 42\n", 0o755))
    if conffile:
        control_entries.append(("./conffiles", b"/etc/debz-fixture.conf\n", 0o644))
    if trigger:
        control_entries.append(("./triggers", f"interest-noawait {trigger}\n".encode(), 0o644))
    payload_path = "./etc/debz-fixture.conf" if conffile else f"./usr/share/debz-fixtures/{package}"
    data = f"{package}={version}:{architecture}\n".encode()
    return (
        b"!<arch>\n"
        + ar_member("debian-binary", b"2.0\n")
        + ar_member("control.tar.gz", tar_gz(control_entries))
        + ar_member("data.tar.gz", tar_gz([(payload_path, data, 0o644)]))
    )


def package_specs(suite: str, architecture: str):
    suite_version = "1.0-1debian1" if suite == "debian-stable" else "1.0-1ubuntu1"
    return [
        ("base-dep", "1.0-1", architecture, {}, {}),
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


def write_repository(output: pathlib.Path, suite: str, architecture: str) -> None:
    if output.exists():
        shutil.rmtree(output)
    packages_dir = output / "dists" / suite / "main" / f"binary-{architecture}"
    pool = output / "pool" / "main"
    packages_dir.mkdir(parents=True)
    pool.mkdir(parents=True)

    paragraphs: list[bytes] = []
    for package, version, package_arch, fields, options in package_specs(suite, architecture):
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
            "Description": f"debz hermetic fixture {package}",
        }
        paragraphs.append("".join(f"{key}: {value}\n" for key, value in paragraph.items()).encode() + b"\n")

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

    fixture = load_openpgp_fixture_module()
    primary = serialization.load_pem_private_key(fixture.PRIMARY_PEM, password=None)
    subkey = serialization.load_pem_private_key(fixture.SUBKEY_PEM, password=None)
    primary_body = fixture.public_body(primary)
    subkey_body = fixture.public_body(subkey)
    primary_fingerprint = fixture.fingerprint(primary_body)
    subkey_fingerprint = fixture.fingerprint(subkey_body)
    primary_packet = fixture.packet(6, primary_body)
    uid_packet = fixture.packet(13, fixture.UID)
    certification = fixture.signature(
        primary,
        0x13,
        [
            fixture.key_prefix(primary_body),
            b"\xb4" + len(fixture.UID).to_bytes(4, "big") + fixture.UID,
        ],
        primary_fingerprint,
        extra_hashed=fixture.subpacket(27, b"\x01"),
    )
    subkey_packet = fixture.packet(14, subkey_body)
    binding_parts = [fixture.key_prefix(primary_body), fixture.key_prefix(subkey_body)]
    primary_binding = fixture.signature(subkey, 0x19, binding_parts, subkey_fingerprint)
    binding = fixture.signature(
        primary,
        0x18,
        binding_parts,
        primary_fingerprint,
        extra_hashed=fixture.subpacket(27, b"\x02") + fixture.subpacket(32, fixture.packet_body(primary_binding)),
    )
    keyring = primary_packet + uid_packet + certification + subkey_packet + binding
    canonical_release = release.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    release_signature = fixture.signature(subkey, 0x01, [canonical_release], subkey_fingerprint)
    in_release = (
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        + release
        + fixture.armor_signature(release_signature)
    )
    (output / "dists" / suite / "InRelease").write_bytes(in_release)
    (output / "fixture-keyring.gpg").write_bytes(keyring)
    manifest = (
        f"suite={suite}\narchitecture={architecture}\n"
        f"release_sha256={hashlib.sha256(release).hexdigest()}\n"
        f"packages_sha256={hashlib.sha256(packages).hexdigest()}\n"
        f"signer={primary_fingerprint.hex()}\n"
    )
    (output / "fixture-provenance.txt").write_text(manifest)
    total = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    if total > MAX_REPOSITORY_BYTES:
        raise RuntimeError(f"fixture repository exceeds {MAX_REPOSITORY_BYTES} bytes")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--suite", required=True, choices=("debian-stable", "ubuntu-26.04"))
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise SystemExit("--output must be absolute")
    write_repository(args.output, args.suite, args.architecture)


if __name__ == "__main__":
    main()
