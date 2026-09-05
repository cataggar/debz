#!/usr/bin/env python3
"""Build a bounded, deterministic signed Debian repository for integration tests."""

from __future__ import annotations

import argparse
import datetime
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
        ("ca-certificates", "20240203", "all", {}, {}),
        ("openssl", "3.0.13-0ubuntu3", architecture, {}, {}),
        ("symcrypt", "103.11.0-1", architecture, {}, {}),
        (
            "symcrypt-openssl",
            "1.9.6-1~3.0",
            architecture,
            {"Depends": "openssl (>= 3.0.0), openssl (<< 3.1.0), symcrypt"},
            {},
        ),
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


def write_repository(
    output: pathlib.Path,
    suite: str,
    architecture: str,
    *,
    missing_valid_until: bool = False,
    release_date_unix: int | None = None,
) -> None:
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
    compressed = io.BytesIO()
    with gzip.GzipFile(
        fileobj=compressed,
        mode="wb",
        mtime=EPOCH,
        filename="Packages",
        compresslevel=9,
    ) as stream:
        stream.write(packages)
    packages_gzip = compressed.getvalue()
    (packages_dir / "Packages.gz").write_bytes(packages_gzip)
    release_date = (
        datetime.datetime.fromtimestamp(release_date_unix, datetime.UTC)
        if missing_valid_until
        else datetime.datetime.fromtimestamp(EPOCH, datetime.UTC)
    ).replace(microsecond=0)
    date_field = release_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    valid_until = (
        ""
        if missing_valid_until
        else "Valid-Until: Thu, 01 Jan 2037 00:00:00 +0000\n"
    )
    release = (
        f"Origin: debz hermetic {suite}\n"
        f"Label: debz integration fixture\n"
        f"Suite: {suite}\n"
        f"Codename: {suite}\n"
        f"Date: {date_field}\n"
        f"{valid_until}"
        f"Architectures: {architecture}\n"
        "Components: main\n"
        "Acquire-By-Hash: no\n"
        "SHA256:\n"
        f" {hashlib.sha256(packages).hexdigest()} {len(packages)} {relative_packages}\n"
        f" {hashlib.sha256(packages_gzip).hexdigest()} {len(packages_gzip)} {relative_packages}.gz\n"
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
    canonical_release = release.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n").removesuffix(b"\r\n")
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


def write_repository_descriptor(
    output: pathlib.Path,
    repository_url: str,
    suite: str,
    architecture: str,
    keyring: bytes,
) -> None:
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
    control_entries = [
        ("./control", control, 0o644),
        ("./conffiles", f"/{source_path}\n".encode(), 0o644),
        ("./preinst", script, 0o755),
        ("./postinst", script, 0o755),
        ("./prerm", script, 0o755),
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
    descriptor = (
        b"!<arch>\n"
        + ar_member("debian-binary", b"2.0\n")
        + ar_member("control.tar.gz", tar_gz(control_entries))
        + ar_member("data.tar.gz", tar_gz(data_entries))
        + ar_member("_gpgorigin", b"fixture structural signature member")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--suite", required=True, choices=("debian-stable", "ubuntu-26.04"))
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--descriptor-output", type=pathlib.Path)
    parser.add_argument("--descriptor-repository-url")
    parser.add_argument("--missing-valid-until", action="store_true")
    parser.add_argument("--release-date-unix", type=int)
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise SystemExit("--output must be absolute")
    if (args.descriptor_output is None) != (args.descriptor_repository_url is None):
        raise SystemExit("--descriptor-output and --descriptor-repository-url must be used together")
    if args.descriptor_output is not None and not args.descriptor_output.is_absolute():
        raise SystemExit("--descriptor-output must be absolute")
    if args.missing_valid_until and args.release_date_unix is None:
        raise SystemExit("--missing-valid-until requires --release-date-unix")
    if args.release_date_unix is not None and args.release_date_unix < 0:
        raise SystemExit("--release-date-unix must be nonnegative")
    write_repository(
        args.output,
        args.suite,
        args.architecture,
        missing_valid_until=args.missing_valid_until,
        release_date_unix=args.release_date_unix,
    )
    if args.descriptor_output is not None:
        write_repository_descriptor(
            args.descriptor_output,
            args.descriptor_repository_url,
            args.suite,
            args.architecture,
            (args.output / "fixture-keyring.gpg").read_bytes(),
        )


if __name__ == "__main__":
    main()
