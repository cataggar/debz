#!/usr/bin/env python3
"""Reproduce genuine signed native-baseline archive fixtures; keys are test-only."""

import importlib.util
import io
import tarfile
from hashlib import sha256, sha512
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            member = tarfile.TarInfo(name)
            member.uid = member.gid = member.mtime = 0
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def deb(name):
    control = (
        f"Package: {name}\nVersion: 1.0\nArchitecture: amd64\n"
        f"Maintainer: Test <test@example.invalid>\nDescription: {name}\n"
    ).encode()
    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar", tar([("./control", control)])),
        ("data.tar", tar([(f"./usr/share/{name}", f"{name} signed payload\n".encode())])),
    ]
    result = bytearray(b"!<arch>\n")
    for name, content in members:
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(content):<10}`\n"
        result.extend(header.encode())
        result.extend(content)
        if len(content) % 2:
            result.extend(b"\n")
    return bytes(result)


def main():
    spec = importlib.util.spec_from_file_location(
        "openpgp_fixture", ROOT / "tools/generate-openpgp-fixtures.py"
    )
    signer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signer)
    key = signer.serialization.load_pem_private_key(signer.PRIMARY_PEM, password=None)
    body = signer.public_body(key)
    fingerprint = signer.fingerprint(body)
    certification = signer.signature(
        key, 0x13,
        [signer.key_prefix(body), b"\xb4" + len(signer.UID).to_bytes(4, "big") + signer.UID],
        fingerprint, extra_hashed=signer.subpacket(27, b"\x03"),
    )
    keyring = signer.packet(6, body) + signer.packet(13, signer.UID) + certification
    destination = ROOT / "src/fixtures/native_baseline"
    destination.mkdir(exist_ok=True)
    packages = bytearray()
    for name in ("alpha", "beta"):
        archive = deb(name)
        (destination / f"{name}.deb").write_bytes(archive)
        packages.extend(
            (
                f"Package: {name}\nVersion: 1.0\nArchitecture: amd64\n"
                f"Maintainer: Test <test@example.invalid>\nDescription: {name}\n"
                f"Filename: pool/{name}_1.0_amd64.deb\nSize: {len(archive)}\n"
                f"SHA256: {sha256(archive).hexdigest()}\n"
                f"SHA512: {sha512(archive).hexdigest()}\n\n"
            ).encode()
        )
    packages = packages[:-1]
    release = (
        "Origin: debz deterministic native baseline fixture\nSuite: stable\n"
        "Codename: stable\nDate: Mon, 07 Sep 2026 00:00:00 +0000\n"
        "Valid-Until: Mon, 14 Sep 2026 00:00:00 +0000\n"
        "Architectures: amd64\nComponents: main\nAcquire-By-Hash: no\n"
        f"SHA256:\n {sha256(packages).hexdigest()} {len(packages)} main/binary-amd64/Packages\n"
        f"SHA512:\n {sha512(packages).hexdigest()} {len(packages)} main/binary-amd64/Packages\n"
    ).encode()
    signature = signer.signature(
        key, 0x01, [release.replace(b"\n", b"\r\n").removesuffix(b"\r\n")],
        fingerprint, created=1_788_739_200,
    )
    (destination / "Packages").write_bytes(packages)
    (destination / "keyring.gpg").write_bytes(keyring)
    (destination / "InRelease").write_bytes(
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        + release + signer.armor_signature(signature)
    )


if __name__ == "__main__":
    main()
