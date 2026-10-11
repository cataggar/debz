#!/usr/bin/env python3
# Copyright 2026 debz contributors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, network-free release packaging and validation for debz."""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import lzma
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import zlib

PLATFORMS = ("linux-x64", "linux-arm64")
FORMATS = ("tar.gz", "tar.xz")
DIGEST_POLICY_SCHEMA = "https://debz.dev/security/digest-cutover-policy-v3"
DIGEST_INVENTORY_NAME = "digest-inventory-v1.tsv"
DIGEST_SEMANTIC_ALLOWLIST_NAME = "digest-semantic-allowlist-v1.tsv"
FORBIDDEN_PARTS = {
    ".git",
    ".zig-cache",
    "zig-out",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".worktrees",
}
FORBIDDEN_SUFFIXES = {".o", ".a", ".so", ".dll", ".dylib", ".exe", ".profraw", ".pyc"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
)
class ReleaseError(Exception):
    """A release input or artifact failed validation."""


def native_release(*arguments: str, input: bytes | None = None) -> bytes:
    helper = pathlib.Path(
        os.environ.get("DEBZ_RELEASE", pathlib.Path(__file__).resolve().parent.parent / "zig-out/bin/debz-release")
    )
    try:
        result = subprocess.run(
            [str(helper), *arguments],
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "PATH": "/no-host-interpreters"},
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError(f"native release helper failed: {error}") from error
    if result.returncode:
        raise ReleaseError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def parse_tag(tag: str) -> str:
    return native_release("version", tag).decode().removesuffix("\n")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def write_bytes(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def safe_relative(name: str) -> pathlib.PurePosixPath:
    if "\\" in name:
        raise ReleaseError(f"archive path uses a backslash: {name!r}")
    path = pathlib.PurePosixPath(name)
    if not name or name.startswith("/") or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ReleaseError(f"unsafe archive path: {name!r}")
    return path


def forbidden_path(path: pathlib.PurePosixPath) -> bool:
    return bool(FORBIDDEN_PARTS.intersection(path.parts)) or path.suffix.lower() in FORBIDDEN_SUFFIXES


def validate_payload(path: pathlib.PurePosixPath, data: bytes) -> None:
    if forbidden_path(path):
        raise ReleaseError(f"forbidden generated/cache path: {path}")
    for pattern in SECRET_PATTERNS:
        if pattern.search(data):
            raise ReleaseError(f"possible secret in release input: {path}")


def build_tar(entries: list[tuple[str, bytes | None, int]], epoch: int) -> bytes:
    return native_release(
        "encode-tar",
        "--epoch",
        str(epoch),
        input=canonical_json([
            {"name": name, "data_base64": None if data is None else base64.b64encode(data).decode(), "mode": mode}
            for name, data, mode in entries
        ]),
    )


def compress_tar(tar_data: bytes, archive_format: str) -> bytes:
    if archive_format == "tar.gz":
        output = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as stream:
            stream.write(tar_data)
        return output.getvalue()
    if archive_format == "tar.xz":
        return lzma.compress(tar_data, format=lzma.FORMAT_XZ, preset=9)
    raise ReleaseError(f"unsupported archive format: {archive_format}")


def decompressed_tar(archive_path: pathlib.Path) -> bytes:
    try:
        data = archive_path.read_bytes()
        if archive_path.name.endswith(".tar.gz"):
            if len(data) < 18 or data[:3] != b"\x1f\x8b\x08":
                raise ReleaseError(f"archive is not gzip: {archive_path.name}")
            flags = data[3]
            if flags & 0xE0 or flags != 0:
                raise ReleaseError(f"gzip header is not canonical: {archive_path.name}")
            if data[4:8] != b"\0\0\0\0":
                raise ReleaseError(f"gzip timestamp is not canonical: {archive_path.name}")
            stream = zlib.decompressobj(wbits=31)
            payload = stream.decompress(data) + stream.flush()
            if not stream.eof:
                raise ReleaseError(f"gzip stream is incomplete: {archive_path.name}")
            if stream.unused_data or stream.unconsumed_tail:
                raise ReleaseError(f"gzip stream has trailing data: {archive_path.name}")
            return payload
        if archive_path.name.endswith(".tar.xz"):
            if not data.startswith(b"\xfd7zXZ\x00"):
                raise ReleaseError(f"archive is not xz: {archive_path.name}")
            stream = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            payload = stream.decompress(data)
            if not stream.eof:
                raise ReleaseError(f"xz stream is incomplete: {archive_path.name}")
            if stream.unused_data:
                raise ReleaseError(f"xz stream has trailing data: {archive_path.name}")
            return payload
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        raise ReleaseError(f"invalid compressed archive {archive_path.name}: {error}") from error
    raise ReleaseError(f"unsupported archive format: {archive_path.name}")


def archive_entries(archive_path: pathlib.Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            result: list[tuple[tarfile.TarInfo, bytes | None]] = []
            seen: set[str] = set()
            previous = ""
            timestamp: int | float | None = None
            for member in archive:
                path = safe_relative(member.name.rstrip("/"))
                normalized = str(path)
                if normalized in seen:
                    raise ReleaseError(f"duplicate archive entry: {normalized}")
                if normalized < previous:
                    raise ReleaseError(f"archive entries are not sorted: {normalized}")
                seen.add(normalized)
                previous = normalized
                if member.issym() or member.islnk():
                    raise ReleaseError(f"archive contains a link: {normalized}")
                if not (member.isfile() or member.isdir()):
                    raise ReleaseError(f"archive contains a special file: {normalized}")
                if member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root":
                    raise ReleaseError(f"non-canonical ownership: {normalized}")
                if member.mode not in ({0o755} if member.isdir() else {0o644, 0o755}):
                    raise ReleaseError(f"non-canonical mode: {normalized}")
                if timestamp is None:
                    timestamp = member.mtime
                elif member.mtime != timestamp:
                    raise ReleaseError(f"archive timestamps differ: {normalized}")
                if forbidden_path(path):
                    raise ReleaseError(f"forbidden archive path: {normalized}")
                data = archive.extractfile(member).read() if member.isfile() else None
                if data is not None:
                    validate_payload(path, data)
                result.append((member, data))
            return result
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        raise ReleaseError(f"cannot read archive {archive_path}: {error}") from error


def policy_dependencies(policy_path: pathlib.Path) -> list[dict[str, object]]:
    try:
        policy = json.loads(policy_path.read_text())
        allowed = set(policy["allowed_production_licenses"])
        dependencies = policy["production_dependencies"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid dependency policy: {error}") from error
    if not isinstance(dependencies, list) or not dependencies:
        raise ReleaseError("dependency policy has no production dependencies")
    result = []
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not dependency.get("name") or not dependency.get("license"):
            raise ReleaseError("dependency is missing a name or license")
        if dependency["license"] not in allowed:
            raise ReleaseError(f"{dependency['name']}: license is not allowed")
        if not (dependency.get("version") or dependency.get("minimum_version")):
            raise ReleaseError(f"{dependency['name']}: version is missing")
        if not dependency.get("runtime_linkage"):
            raise ReleaseError(f"{dependency['name']}: runtime linkage is missing")
        result.append(dependency)
    return sorted(result, key=lambda item: str(item["name"]))


def validate_runtime_manifest(data: bytes, dependencies: list[dict[str, object]]) -> None:
    try:
        runtime = json.loads(data)
        linux = runtime["linux_release_runtime"]
        included = linux["included_libraries"]
        expected = {
            "schema_version": 1,
            "package": "debz",
            "linux_release_runtime": {
                "binary_kind": "fully_static",
                "libc": {
                    "implementation": "musl",
                    "linkage": "static",
                    "expectation": (
                        "musl and all required libraries are statically linked; "
                        "no target-system shared libraries are required."
                    ),
                },
                "system_libraries": [],
                "included_libraries": sorted(
                    (
                        {
                            "name": str(item["name"]),
                            "version": str(item["version"]),
                            "linkage": str(item["runtime_linkage"]),
                            "license": str(item["license"]),
                        }
                        for item in dependencies
                    ),
                    key=lambda item: item["name"],
                ),
                "fully_static": True,
            },
        }
        normalized = {
            **runtime,
            "linux_release_runtime": {
                **linux,
                "included_libraries": sorted(included, key=lambda item: str(item["name"])),
            },
        }
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid installed runtime dependency manifest: {error}") from error
    if normalized != expected:
        raise ReleaseError(
            "installed runtime dependency manifest differs from reviewed policy and static linkage model"
        )


def validate_static_elf(binary: bytes, platform: str) -> None:
    native_release("check-elf", "--platform", platform, input=binary)


def create_release_files(
    output: pathlib.Path,
    base_name: str,
    entries: list[tuple[str, bytes, int]],
    epoch: int,
) -> list[pathlib.Path]:
    output.mkdir(parents=True, exist_ok=True)
    tar_data = build_tar(entries, epoch)
    created: list[pathlib.Path] = []
    for archive_format in FORMATS:
        archive = output / f"{base_name}.{archive_format}"
        archive_data = compress_tar(tar_data, archive_format)
        write_bytes(archive, archive_data)
        created.append(archive)
    return created


def binary_entries(prefix: pathlib.Path, root_name: str) -> tuple[list[tuple[str, bytes, int]], bytes]:
    if not prefix.is_dir():
        raise ReleaseError(f"install prefix is not a directory: {prefix}")
    entries = []
    binary = None
    for path in sorted(prefix.rglob("*")):
        relative = pathlib.PurePosixPath(path.relative_to(prefix).as_posix())
        if path.is_symlink():
            raise ReleaseError(f"install prefix contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReleaseError(f"install prefix contains a special file: {relative}")
        data = path.read_bytes()
        validate_payload(relative, data)
        mode = 0o755 if relative == pathlib.PurePosixPath("bin/debz") else 0o644
        entries.append((f"{root_name}/{relative}", data, mode))
        if relative == pathlib.PurePosixPath("bin/debz"):
            binary = data
    required = {
        pathlib.PurePosixPath("bin/debz"),
        pathlib.PurePosixPath("share/doc/debz/LICENSE"),
        pathlib.PurePosixPath("share/doc/debz/THIRD_PARTY_NOTICES"),
        pathlib.PurePosixPath("share/debz/digest-cutover-policy.json"),
        pathlib.PurePosixPath(f"share/debz/{DIGEST_INVENTORY_NAME}"),
        pathlib.PurePosixPath(f"share/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}"),
        pathlib.PurePosixPath("share/debz/legacy-cutover-policy.json"),
        pathlib.PurePosixPath("share/doc/debz/digest-cutover-policy.json"),
        pathlib.PurePosixPath(f"share/doc/debz/{DIGEST_INVENTORY_NAME}"),
        pathlib.PurePosixPath(f"share/doc/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}"),
        pathlib.PurePosixPath("share/doc/debz/legacy-cutover-policy.json"),
        pathlib.PurePosixPath("share/debz/runtime-dependencies.json"),
    }
    present = {pathlib.PurePosixPath(name).relative_to(root_name) for name, _, _ in entries}
    missing = required - present
    if missing:
        raise ReleaseError("install prefix is missing required files: " + ", ".join(map(str, sorted(missing))))
    installed = {
        pathlib.PurePosixPath(name).relative_to(root_name): data
        for name, data, _ in entries
    }
    validate_installed_policies(
        installed[pathlib.PurePosixPath("share/debz/digest-cutover-policy.json")],
        installed[pathlib.PurePosixPath("share/doc/debz/digest-cutover-policy.json")],
        installed[pathlib.PurePosixPath(f"share/debz/{DIGEST_INVENTORY_NAME}")],
        installed[pathlib.PurePosixPath(f"share/doc/debz/{DIGEST_INVENTORY_NAME}")],
        installed[pathlib.PurePosixPath(f"share/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}")],
        installed[pathlib.PurePosixPath(f"share/doc/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}")],
        installed[pathlib.PurePosixPath("share/debz/legacy-cutover-policy.json")],
        installed[pathlib.PurePosixPath("share/doc/debz/legacy-cutover-policy.json")],
    )
    assert binary is not None
    return entries, binary


def expected_asset_names(version: str) -> list[str]:
    return sorted(
        f"debz-{version}-{platform}.{archive_format}"
        for platform in PLATFORMS
        for archive_format in FORMATS
    )


def validate_installed_policies(
    digest_policy: bytes,
    digest_policy_documentation: bytes,
    digest_inventory: bytes,
    digest_inventory_documentation: bytes,
    digest_semantic_allowlist: bytes,
    digest_semantic_allowlist_documentation: bytes,
    legacy_policy: bytes,
    legacy_policy_documentation: bytes,
) -> None:
    if digest_policy != digest_policy_documentation:
        raise ReleaseError("installed digest cutover policy copies differ")
    if digest_inventory != digest_inventory_documentation:
        raise ReleaseError("installed digest inventory copies differ")
    if digest_semantic_allowlist != digest_semantic_allowlist_documentation:
        raise ReleaseError("installed digest semantic allowlist copies differ")
    if legacy_policy != legacy_policy_documentation:
        raise ReleaseError("installed legacy cutover policy copies differ")
    for name, data, schema, version in (
        (
            "digest cutover",
            digest_policy,
            DIGEST_POLICY_SCHEMA,
            3,
        ),
        (
            "legacy cutover",
            legacy_policy,
            "https://debz.dev/schema/legacy-compatibility-policy-v1",
            1,
        ),
    ):
        try:
            document = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseError(f"installed {name} policy is invalid JSON") from error
        if document.get("schema") != schema or document.get("version") != version:
            raise ReleaseError(f"installed {name} policy identity is invalid")
        if name == "digest cutover":
            inventory = document.get("inventory")
            if not isinstance(inventory, dict) or inventory.get("file") != f"security/{DIGEST_INVENTORY_NAME}":
                raise ReleaseError("installed digest cutover policy inventory is invalid")
            semantic = document.get("semantic_allowlist_inventory")
            if not isinstance(semantic, dict) or semantic.get("file") != f"security/{DIGEST_SEMANTIC_ALLOWLIST_NAME}":
                raise ReleaseError("installed digest cutover semantic allowlist inventory is invalid")


def release_plan(tag: str) -> dict[str, object]:
    return json.loads(native_release("dry-run", "--tag", tag))


def audit_archive(
    path: pathlib.Path, version: str, platform: str
) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    entries = archive_entries(path)
    names = {member.name.rstrip("/") for member, _ in entries}
    root = f"debz-{version}-{platform}"
    if not names or any(name != root and not name.startswith(root + "/") for name in names):
        raise ReleaseError(f"archive has an unexpected top-level path: {path.name}")
    required = {
        f"{root}/bin/debz",
        f"{root}/share/doc/debz/LICENSE",
        f"{root}/share/doc/debz/THIRD_PARTY_NOTICES",
        f"{root}/share/debz/digest-cutover-policy.json",
        f"{root}/share/debz/{DIGEST_INVENTORY_NAME}",
        f"{root}/share/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}",
        f"{root}/share/debz/legacy-cutover-policy.json",
        f"{root}/share/doc/debz/digest-cutover-policy.json",
        f"{root}/share/doc/debz/{DIGEST_INVENTORY_NAME}",
        f"{root}/share/doc/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}",
        f"{root}/share/doc/debz/legacy-cutover-policy.json",
        f"{root}/share/debz/runtime-dependencies.json",
    }
    missing = required - names
    if missing:
        raise ReleaseError(f"archive is missing: {', '.join(sorted(missing))}")
    for member, _ in entries:
        name = member.name.rstrip("/")
        relative = pathlib.PurePosixPath(name).relative_to(root)
        if len(relative.parts) > 0 and relative.parts[0] not in {"bin", "lib", "share"}:
            raise ReleaseError(f"unexpected install path in binary archive: {name}")
        if member.isfile() and member.mode == 0o755 and name != f"{root}/bin/debz":
            raise ReleaseError(f"unexpected executable in binary archive: {name}")
    files = [(member.name, data, member.mode) for member, data in entries if member.isfile() and data is not None]
    epoch = int(entries[0][0].mtime)
    if decompressed_tar(path) != build_tar(files, epoch):
        raise ReleaseError(f"decompressed tar payload is not canonical: {path.name}")
    return entries


def validate_archived_binary(
    entries: list[tuple[tarfile.TarInfo, bytes | None]],
    version: str,
    platform: str,
    dependencies: list[dict[str, object]],
) -> None:
    root = f"debz-{version}-{platform}"
    files = {
        member.name: data
        for member, data in entries
        if member.isfile() and data is not None
    }
    binary = files[f"{root}/bin/debz"]
    runtime = files[f"{root}/share/debz/runtime-dependencies.json"]
    validate_installed_policies(
        files[f"{root}/share/debz/digest-cutover-policy.json"],
        files[f"{root}/share/doc/debz/digest-cutover-policy.json"],
        files[f"{root}/share/debz/{DIGEST_INVENTORY_NAME}"],
        files[f"{root}/share/doc/debz/{DIGEST_INVENTORY_NAME}"],
        files[f"{root}/share/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}"],
        files[f"{root}/share/doc/debz/{DIGEST_SEMANTIC_ALLOWLIST_NAME}"],
        files[f"{root}/share/debz/legacy-cutover-policy.json"],
        files[f"{root}/share/doc/debz/legacy-cutover-policy.json"],
    )
    validate_static_elf(binary, platform)
    validate_runtime_manifest(runtime, dependencies)


def native_platform() -> str | None:
    machine = os.uname().machine
    return {"x86_64": "linux-x64", "amd64": "linux-x64", "aarch64": "linux-arm64", "arm64": "linux-arm64"}.get(machine)


def smoke_binary(archive_path: pathlib.Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix=".debz-release-smoke-", dir=archive_path.parent) as directory:
        root = pathlib.Path(directory).resolve()
        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive:
                destination = (root / member.name).resolve()
                if root not in destination.parents:
                    raise ReleaseError(f"unsafe extraction path: {member.name}")
            archive.extractall(root, filter="data")
        binary = next(root.glob("*/bin/debz"))
        for argument, expected in (
            ("version", version),
            ("-h", "debz <command> [options] [packages...]"),
            ("--help", "debz <command> [options] [packages...]"),
        ):
            result = subprocess.run(
                [binary, argument], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            if result.returncode or expected not in result.stdout:
                raise ReleaseError(f"native smoke failed for {argument}: {result.stdout.strip()}")


def command_version(args: argparse.Namespace) -> None:
    version = parse_tag(args.tag)
    for item in args.expect:
        if "=" not in item:
            raise ReleaseError(f"consistency value must be NAME=VERSION: {item!r}")
        name, value = item.split("=", 1)
        if not name or value != version:
            raise ReleaseError(f"version mismatch for {name or '<empty>'}: {value!r} != {version!r}")
    print(version)


def command_binary(args: argparse.Namespace) -> None:
    version = parse_tag(args.tag)
    dependencies = policy_dependencies(args.policy)
    root_name = f"debz-{version}-{args.platform}"
    entries, binary = binary_entries(args.prefix, root_name)
    validate_static_elf(binary, args.platform)
    runtime_data = next(data for name, data, _ in entries if name.endswith("/share/debz/runtime-dependencies.json"))
    validate_runtime_manifest(runtime_data, dependencies)
    for path in create_release_files(args.output, root_name, entries, args.epoch):
        print(path)


def command_audit(args: argparse.Namespace) -> None:
    version = parse_tag(args.tag)
    entries = audit_archive(args.archive, version, args.platform)
    dependencies = policy_dependencies(args.policy)
    validate_archived_binary(entries, version, args.platform, dependencies)
    if args.smoke and args.platform == native_platform():
        smoke_binary(args.archive, version)
    print(f"verified {args.archive}")


def command_verify(args: argparse.Namespace) -> None:
    version = parse_tag(args.tag)
    expected = set(expected_asset_names(version))
    actual = set()
    for path in args.assets.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"release assets contain a non-regular entry: {path.name}")
        actual.add(path.name)
    missing = expected - actual
    if missing:
        raise ReleaseError("release assets are missing: " + ", ".join(sorted(missing)))
    unexpected = actual - expected
    if unexpected:
        raise ReleaseError("release assets are forbidden: " + ", ".join(sorted(unexpected)))
    dependencies = policy_dependencies(args.policy)
    for platform in PLATFORMS:
        for archive_format in FORMATS:
            archive = args.assets / f"debz-{version}-{platform}.{archive_format}"
            entries = audit_archive(archive, version, platform)
            validate_archived_binary(entries, version, platform, dependencies)
    if args.smoke:
        platform = native_platform()
        if platform:
            smoke_binary(args.assets / f"debz-{version}-{platform}.tar.gz", version)
    print(f"verified {len(expected)} release assets")


def command_dry_run(args: argparse.Namespace) -> None:
    print(canonical_json(release_plan(args.tag)).decode(), end="")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    version = subcommands.add_parser("version", help="strictly parse a release tag")
    version.add_argument("tag")
    version.add_argument("--expect", action="append", default=[], metavar="NAME=VERSION")
    version.set_defaults(func=command_version)

    binary = subcommands.add_parser("binary", help="create deterministic binary release assets")
    binary.add_argument("--tag", required=True)
    binary.add_argument("--platform", choices=PLATFORMS, required=True)
    binary.add_argument("--prefix", type=pathlib.Path, required=True)
    binary.add_argument("--output", type=pathlib.Path, required=True)
    binary.add_argument("--epoch", type=int, required=True)
    binary.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("security/dependency-policy.json"))
    binary.set_defaults(func=command_binary)

    audit = subcommands.add_parser("audit", help="audit one binary archive")
    audit.add_argument("--tag", required=True)
    audit.add_argument("--archive", type=pathlib.Path, required=True)
    audit.add_argument("--platform", choices=PLATFORMS, required=True)
    audit.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("security/dependency-policy.json"))
    audit.add_argument("--smoke", action="store_true")
    audit.set_defaults(func=command_audit)

    verify = subcommands.add_parser("verify", help="verify a complete release asset directory")
    verify.add_argument("--tag", required=True)
    verify.add_argument("--assets", type=pathlib.Path, required=True)
    verify.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("security/dependency-policy.json"))
    verify.add_argument("--smoke", action="store_true")
    verify.set_defaults(func=command_verify)

    dry_run = subcommands.add_parser("dry-run", help="print the exact four-archive release plan")
    dry_run.add_argument("--tag", required=True)
    dry_run.set_defaults(func=command_dry_run)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        args.func(args)
        return 0
    except ReleaseError as error:
        print(f"release: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
