#!/usr/bin/env python3
"""Prepare a hash-pinned dpkg reference without installing host packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.22.22"
BASE_URL = "https://deb.debian.org/debian/pool/main/d/dpkg"
MAXIMUM_BYTES = 8 * 1024 * 1024
PINS = {
    "amd64": {
        "archive": "3e800c6d75e8e709007ed1c356e5fa8509a75c1694fb0a1183709abc9cfdc1f3",
        "executable": "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
        "update_alternatives": "b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13",
    },
    "arm64": {
        "archive": "1142468e57f69e13d174f517dff739508c61ee97d81c182c120cd6b281d8cdfa",
        "executable": "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
        "update_alternatives": "35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5",
    },
}
RECEIPT = "reference-receipt-v1.json"


def verify_file(path: Path, expected: str) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAXIMUM_BYTES:
        raise RuntimeError(f"invalid pinned reference file: {path}")
    with path.open("rb") as source:
        content = source.read(MAXIMUM_BYTES + 1)
    if len(content) > MAXIMUM_BYTES or hashlib.sha256(content).hexdigest() != expected:
        raise RuntimeError(f"pinned reference digest mismatch: {path}")


def canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def file_binding(path: Path, expected: str) -> dict[str, int | str]:
    verify_file(path, expected)
    return {
        "sha256": expected,
        "size": path.stat().st_size,
    }


def download_archive(architecture: str) -> tuple[str, bytes]:
    name = f"dpkg_{VERSION}_{architecture}.deb"
    url = f"{BASE_URL}/{name}"
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise RuntimeError("reference download redirected away from HTTPS")
        content = response.read(MAXIMUM_BYTES + 1)
    if len(content) > MAXIMUM_BYTES:
        raise RuntimeError("reference archive exceeds its byte limit")
    if hashlib.sha256(content).hexdigest() != PINS[architecture]["archive"]:
        raise RuntimeError("pinned reference archive digest mismatch")
    return url, content


def receipt_document(
    architecture: str,
    archive_url: str,
    archive: bytes,
    prefix: Path,
) -> dict[str, object]:
    return {
        "architecture": architecture,
        "archive": {
            "sha256": PINS[architecture]["archive"],
            "size": len(archive),
            "url": archive_url,
        },
        "dpkg": file_binding(
            prefix / "usr/bin/dpkg",
            PINS[architecture]["executable"],
        ),
        "schema": "https://debz.dev/schema/native-dpkg-reference-receipt-v1",
        "update_alternatives": file_binding(
            prefix / "usr/bin/update-alternatives",
            PINS[architecture]["update_alternatives"],
        ),
        "version": VERSION,
    }


def write_receipt(
    architecture: str,
    archive_url: str,
    archive: bytes,
    prefix: Path,
) -> None:
    path = prefix / RECEIPT
    path.write_text(canonical_json(receipt_document(
        architecture,
        archive_url,
        archive,
        prefix,
    )))


def verify_receipt(path: Path, architecture: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise RuntimeError(f"invalid pinned reference receipt: {path}")
    raw = path.read_bytes()
    receipt = json.loads(raw)
    if raw != canonical_json(receipt).encode():
        raise RuntimeError("pinned reference receipt is not canonical JSON")
    expected = {
        "architecture": architecture,
        "schema": "https://debz.dev/schema/native-dpkg-reference-receipt-v1",
        "version": VERSION,
    }
    if any(receipt.get(name) != value for name, value in expected.items()):
        raise RuntimeError("pinned reference receipt identity mismatch")
    archive = receipt.get("archive")
    expected_url = f"{BASE_URL}/dpkg_{VERSION}_{architecture}.deb"
    if (
        set(receipt) != {
            "architecture",
            "archive",
            "dpkg",
            "schema",
            "update_alternatives",
            "version",
        }
        or not isinstance(archive, dict)
        or set(archive) != {"sha256", "size", "url"}
        or archive.get("sha256") != PINS[architecture]["archive"]
        or archive.get("url") != expected_url
        or not isinstance(archive.get("size"), int)
        or not 0 < archive["size"] <= MAXIMUM_BYTES
    ):
        raise RuntimeError("pinned reference receipt archive mismatch")
    for name, key, relative in (
        ("dpkg", "executable", "usr/bin/dpkg"),
        (
            "update_alternatives",
            "update_alternatives",
            "usr/bin/update-alternatives",
        ),
    ):
        executable = path.parent / relative
        if receipt.get(name) != file_binding(
            executable,
            PINS[architecture][key],
        ):
            raise RuntimeError(
                f"pinned reference receipt {name} mismatch: {executable}"
            )
    return receipt


def version(executable: str) -> tuple[int, int, int]:
    result = subprocess.run(
        [executable, "--version"], check=True, capture_output=True, text=True,
        timeout=10, env={**os.environ, "LC_ALL": "C"},
    )
    match = re.search(r"\bversion (\d+)\.(\d+)\.(\d+)\b", result.stdout.partition("\n")[0])
    if match is None:
        raise RuntimeError(f"unrecognized dpkg reference version: {executable}")
    return tuple(int(part) for part in match.groups())


def update_alternatives_version(executable: str) -> tuple[int, int, int]:
    result = subprocess.run(
        [executable, "--version"], check=True, capture_output=True, text=True,
        timeout=10, env={**os.environ, "LC_ALL": "C"},
    )
    match = re.search(
        r"\bversion (\d+)\.(\d+)\.(\d+)\b",
        result.stdout.partition("\n")[0],
    )
    if match is None:
        raise RuntimeError(
            f"unrecognized update-alternatives reference version: {executable}"
        )
    return tuple(int(part) for part in match.groups())


def select(executable: Path | None, architecture: str, *, root_accounts: bool = False) -> str:
    if architecture not in PINS:
        raise RuntimeError(f"unsupported reference architecture: {architecture}")
    if executable is not None:
        if not executable.is_absolute() or executable.resolve(strict=True) != executable:
            raise RuntimeError("pinned dpkg reference must be an absolute, non-symlink path")
        verify_file(executable, PINS[architecture]["executable"])
        selected = str(executable)
    else:
        selected = shutil.which("dpkg")
        if selected is None:
            raise RuntimeError("missing dpkg reference")
    found = version(selected)
    if executable is not None and found != tuple(int(part) for part in VERSION.split(".")):
        raise RuntimeError("pinned dpkg reference version mismatch")
    if root_accounts and found < (1, 22, 16):
        raise RuntimeError(
            "named statoverride acceptance requires dpkg >= 1.22.16; run "
            "python3 tools/prepare-native-dpkg.py and pass its path with "
            "-Dnative-reference-dpkg=PATH (or --reference-dpkg PATH)"
        )
    print(
        f"Native reference: dpkg ({'.'.join(map(str, found))})",
        file=sys.stderr,
    )
    return selected


def select_update_alternatives(executable: Path, architecture: str) -> str:
    if architecture not in PINS:
        raise RuntimeError(f"unsupported reference architecture: {architecture}")
    if not executable.is_absolute() or executable.resolve(strict=True) != executable:
        raise RuntimeError(
            "pinned update-alternatives reference must be an absolute, non-symlink path"
        )
    verify_file(executable, PINS[architecture]["update_alternatives"])
    found = update_alternatives_version(str(executable))
    if found != tuple(int(part) for part in VERSION.split(".")):
        raise RuntimeError("pinned update-alternatives reference version mismatch")
    print(
        "Alternatives reference: update-alternatives "
        f"({'.'.join(map(str, found))})",
        file=sys.stderr,
    )
    return str(executable)


def prepare(architecture: str) -> Path:
    if os.geteuid() == 0:
        raise RuntimeError("prepare the private reference as the build user, not root")
    if architecture not in PINS:
        raise RuntimeError(f"unsupported reference architecture: {architecture}")
    prefix = ROOT / ".cache/native-dpkg-reference" / VERSION / architecture
    if prefix.resolve() != prefix:
        raise RuntimeError("private reference prefix must not traverse symlinks")
    executable = prefix / "usr/bin/dpkg"
    if prefix.exists():
        select(executable, architecture, root_accounts=True)
        select_update_alternatives(
            prefix / "usr/bin/update-alternatives",
            architecture,
        )
        receipt = prefix / RECEIPT
        if not receipt.exists():
            archive_url, archive = download_archive(architecture)
            write_receipt(architecture, archive_url, archive, prefix)
        verify_receipt(receipt, architecture)
        return executable
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="preparing-", dir=prefix.parent) as temporary:
        workspace = Path(temporary)
        archive = workspace / f"dpkg_{VERSION}_{architecture}.deb"
        archive_url, content = download_archive(architecture)
        archive.write_bytes(content)
        verify_file(archive, PINS[architecture]["archive"])
        staged = workspace / "prefix"
        subprocess.run(["dpkg-deb", "--extract", str(archive), str(staged)], check=True, timeout=60)
        select(staged / "usr/bin/dpkg", architecture, root_accounts=True)
        select_update_alternatives(
            staged / "usr/bin/update-alternatives",
            architecture,
        )
        write_receipt(architecture, archive_url, content, staged)
        staged.rename(prefix)
    verify_receipt(prefix / RECEIPT, architecture)
    return executable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=sorted(PINS))
    arguments = parser.parse_args()
    architecture = arguments.architecture or {
        "x86_64": "amd64",
        "aarch64": "arm64",
    }.get(platform.machine())
    if architecture is None:
        raise RuntimeError(f"unsupported reference machine: {platform.machine()}")
    print(prepare(architecture))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
