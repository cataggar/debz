#!/usr/bin/env python3
"""Verify a pinned, prehashed minisign signature before root uses an artifact.

The protected reference staging runs this as root, before any Zig exists, to
accept the Zig toolchain archive only when it is the pinned name, size and
SHA256 and both its file and trusted-comment Ed25519 signatures verify against
the pinned public key. Ed25519 verification uses the system OpenSSL CLI.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

OPENSSL = "/usr/bin/openssl"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAXIMUM_ARTIFACT_BYTES = 512 * 1024 * 1024


class VerificationError(Exception):
    pass


def decode(value: bytes, size: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise VerificationError(f"malformed {what}") from error
    if len(raw) != size:
        raise VerificationError(f"malformed {what}")
    return raw


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> None:
    der = ED25519_SPKI_PREFIX + public_key
    with tempfile.TemporaryDirectory(prefix="debz-minisign-") as scratch:
        key = Path(scratch, "key.pem")
        key.write_text(
            "-----BEGIN PUBLIC KEY-----\n"
            + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n"
        )
        Path(scratch, "message").write_bytes(message)
        Path(scratch, "signature").write_bytes(signature)
        result = subprocess.run(
            [OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin",
             "-in", str(Path(scratch, "message")), "-sigfile", str(Path(scratch, "signature"))],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, capture_output=True, text=True,
            timeout=60, check=False,
        )
    if result.returncode != 0 or "Signature Verified Successfully" not in result.stdout:
        raise VerificationError("Ed25519 signature verification failed")


def verify(
    public_key: str, artifact: Path, signature: Path, name: str, sha256: str, size: int,
) -> str:
    raw_key = decode(public_key.encode(), 42, "minisign public key")
    if raw_key[:2] != b"Ed":
        raise VerificationError("unsupported minisign public key algorithm")
    key_id, key = raw_key[2:10], raw_key[10:]
    lines = signature.read_bytes().split(b"\n")
    if (len(lines) not in (4, 5) or (len(lines) == 5 and lines[4] != b"") or
            not lines[0].startswith(b"untrusted comment: ") or
            not lines[2].startswith(b"trusted comment: ")):
        raise VerificationError("malformed minisign signature file")
    blob = decode(lines[1], 74, "minisign signature")
    if blob[:2] != b"ED":
        raise VerificationError("only prehashed (ED) minisign signatures are accepted")
    if blob[2:10] != key_id:
        raise VerificationError("signature key id differs from the pinned key")
    trusted = lines[2][len(b"trusted comment: "):]
    fields = trusted.split(b"\t")
    if (len(fields) != 3 or not re.fullmatch(rb"timestamp:[0-9]{1,20}", fields[0]) or
            fields[1] != b"file:" + name.encode() or fields[2] != b"hashed"):
        raise VerificationError("trusted comment does not name the pinned artifact")
    global_signature = decode(lines[3], 64, "minisign global signature")
    if artifact.name != name:
        raise VerificationError("artifact name differs from the pinned name")
    if not 0 < size <= MAXIMUM_ARTIFACT_BYTES:
        raise VerificationError("artifact size pin is invalid")
    fd = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    prehash = hashlib.blake2b(digest_size=64)
    digest = hashlib.sha256()
    observed = 0
    with os.fdopen(fd, "rb") as stream:
        while block := stream.read(1024 * 1024):
            observed += len(block)
            if observed > size:
                break
            prehash.update(block)
            digest.update(block)
    if observed != size or digest.hexdigest() != sha256:
        raise VerificationError("artifact size or SHA256 differs from the pin")
    ed25519_verify(key, prehash.digest(), blob[10:])
    ed25519_verify(key, blob[10:] + trusted, global_signature)
    return (
        f"verified {name} sha256={sha256} size={size} "
        f"key_id={key_id[::-1].hex().upper()} trusted_comment={trusted.decode()!r}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", type=int, required=True)
    args = parser.parse_args()
    try:
        print(verify(args.public_key, args.artifact, args.signature, args.name, args.sha256, args.size))
    except (OSError, VerificationError) as error:
        print(f"minisign verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
