#!/usr/bin/env python3
# Copyright 2026 debz contributors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, network-free release packaging and validation for debz."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import uuid

PLATFORMS = ("linux-x64", "linux-arm64")
FORMATS = ("tar.gz", "tar.xz")
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
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
BASE_RUNTIME = {
    "libc.so.6",
    "libm.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
}
DEPENDENCY_SONAMES = {
    "liblzma": {"liblzma.so.5"},
    "libzstd": {"libzstd.so.1"},
    "libsolv": set(),
}


class ReleaseError(Exception):
    """A release input or artifact failed validation."""


def parse_tag(tag: str) -> str:
    if not tag.startswith("v") or not SEMVER.fullmatch(tag[1:]):
        raise ReleaseError(f"invalid release tag: {tag!r}")
    return tag[1:]


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bytes(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def write_checksum(path: pathlib.Path) -> pathlib.Path:
    sidecar = path.with_name(path.name + ".sha256")
    write_bytes(sidecar, f"{sha256_bytes(path.read_bytes())}  {path.name}\n".encode("ascii"))
    return sidecar


def validate_checksum(sidecar: pathlib.Path, asset: pathlib.Path) -> None:
    expected = f"{sha256_bytes(asset.read_bytes())}  {asset.name}\n"
    try:
        actual = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ReleaseError(f"cannot read checksum {sidecar}: {error}") from error
    if actual != expected:
        raise ReleaseError(f"checksum mismatch or non-portable sidecar: {sidecar.name}")


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
    synthetic_fixture = (
        path.parts[-2:] == ("tools", "generate-openpgp-fixtures.py")
        and b"checked-in, non-secret OpenPGP verification fixtures" in data
    )
    for pattern in SECRET_PATTERNS:
        if pattern.search(data) and not synthetic_fixture:
            raise ReleaseError(f"possible secret in release input: {path}")


def tar_info(name: str, mode: int, epoch: int, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name + ("/" if directory and not name.endswith("/") else ""))
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    info.mode = mode
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def build_tar(entries: list[tuple[str, bytes | None, int]], epoch: int) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        directories: set[str] = set()
        for name, _, _ in entries:
            parts = pathlib.PurePosixPath(name).parts[:-1]
            for index in range(1, len(parts) + 1):
                directories.add("/".join(parts[:index]))
        records = [(directory, None, 0o755) for directory in directories] + entries
        for name, data, mode in sorted(records, key=lambda item: item[0]):
            if data is None:
                archive.addfile(tar_info(name, mode, epoch, directory=True))
            else:
                archive.addfile(tar_info(name, mode, epoch, len(data)), io.BytesIO(data))
    return output.getvalue()


def compress_tar(tar_data: bytes, archive_format: str) -> bytes:
    if archive_format == "tar.gz":
        output = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as stream:
            stream.write(tar_data)
        return output.getvalue()
    if archive_format == "tar.xz":
        return lzma.compress(tar_data, format=lzma.FORMAT_XZ, preset=9)
    raise ReleaseError(f"unsupported archive format: {archive_format}")


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
    except (tarfile.TarError, OSError) as error:
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
        result.append(dependency)
    return sorted(result, key=lambda item: str(item["name"]))


def validate_runtime_manifest(data: bytes, dependencies: list[dict[str, object]]) -> None:
    try:
        runtime = json.loads(data)
        linux = runtime["linux_release_runtime"]
        names = {linux["libc"]["implementation"]}
        names.update(item["name"] for item in linux["system_libraries"])
        names.update(item["name"] for item in linux["included_libraries"])
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid installed runtime dependency manifest: {error}") from error
    policy_names = {str(item["name"]) for item in dependencies}
    if names != policy_names | {"glibc"}:
        raise ReleaseError(
            "installed runtime dependency manifest differs from reviewed policy: "
            + ", ".join(sorted(names))
        )


def elf_needed(data: bytes) -> set[str]:
    if not data.startswith(b"\x7fELF"):
        return set()
    elf_class, encoding = data[4], data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise ReleaseError("unsupported ELF encoding")
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        section_offset, section_size, section_count, names_index = header[5], header[10], header[11], header[12]
        section_format = endian + "IIQQQQIIQQ"
    else:
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        section_offset, section_size, section_count, names_index = header[5], header[10], header[11], header[12]
        section_format = endian + "IIIIIIIIII"
    if not section_offset or not section_count or names_index >= section_count:
        return set()
    sections = [
        struct.unpack_from(section_format, data, section_offset + index * section_size)
        for index in range(section_count)
    ]
    names_section = sections[names_index]
    names = data[names_section[4] : names_section[4] + names_section[5]]

    def section_name(section: tuple[int, ...]) -> str:
        start = section[0]
        end = names.find(b"\0", start)
        return names[start:end].decode("ascii", "strict")

    by_name = {section_name(section): section for section in sections}
    dynamic = by_name.get(".dynamic")
    strings = by_name.get(".dynstr")
    if not dynamic or not strings:
        return set()
    string_data = data[strings[4] : strings[4] + strings[5]]
    pair = endian + ("QQ" if elf_class == 2 else "II")
    pair_size = struct.calcsize(pair)
    needed: set[str] = set()
    for offset in range(dynamic[4], dynamic[4] + dynamic[5], pair_size):
        tag, value = struct.unpack_from(pair, data, offset)
        if tag == 0:
            break
        if tag == 1:
            end = string_data.find(b"\0", value)
            needed.add(string_data[value:end].decode("ascii", "strict"))
    return needed


def validate_dynamic_dependencies(binary: bytes, dependencies: list[dict[str, object]]) -> set[str]:
    needed = elf_needed(binary)
    declared = {str(item["name"]) for item in dependencies}
    allowed = set(BASE_RUNTIME)
    for name in declared:
        allowed.update(DEPENDENCY_SONAMES.get(name, set()))
    unexpected = needed - allowed
    if unexpected:
        raise ReleaseError(f"unexpected dynamic dependencies: {', '.join(sorted(unexpected))}")
    return needed


def validate_elf_platform(binary: bytes, platform: str) -> None:
    if len(binary) < 20 or not binary.startswith(b"\x7fELF") or binary[4] != 2 or binary[5] not in (1, 2):
        raise ReleaseError("bin/debz is not a supported 64-bit ELF executable")
    endian = "<" if binary[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", binary, 18)[0]
    expected = {"linux-x64": 62, "linux-arm64": 183}[platform]
    if machine != expected:
        raise ReleaseError(f"ELF architecture {machine} does not match {platform}")


def spdx_document(
    name: str,
    version: str,
    archive_name: str,
    entries: list[tuple[str, bytes, int]],
    dependencies: list[dict[str, object]],
    archive_checksum: str,
) -> dict[str, object]:
    package_id = "SPDXRef-Package-debz"
    files = []
    relationships = []
    file_sha1_values = []
    for index, (path, data, _) in enumerate(sorted(entries), 1):
        digest = sha256_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        file_sha1_values.append(sha1)
        file_id = f"SPDXRef-File-{index:04d}"
        files.append(
            {
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1},
                    {"algorithm": "SHA256", "checksumValue": digest},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": "./" + path,
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
            }
        )
        relationships.append(
            {"spdxElementId": package_id, "relationshipType": "CONTAINS", "relatedSpdxElement": file_id}
        )
    packages = [
        {
            "SPDXID": package_id,
            "checksums": [{"algorithm": "SHA256", "checksumValue": archive_checksum}],
            "copyrightText": "Copyright 2026 debz contributors",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": "debz",
            "packageFileName": archive_name,
            "packageVerificationCode": {
                "packageVerificationCodeValue": hashlib.sha1(
                    "".join(sorted(file_sha1_values)).encode("ascii")
                ).hexdigest()
            },
            "versionInfo": version,
        }
    ]
    for index, dependency in enumerate(dependencies, 1):
        dependency_id = f"SPDXRef-Dependency-{index:04d}"
        packages.append(
            {
                "SPDXID": dependency_id,
                "copyrightText": "NOASSERTION",
                "downloadLocation": str(dependency.get("source", "NOASSERTION")),
                "filesAnalyzed": False,
                "licenseConcluded": str(dependency["license"]),
                "licenseDeclared": str(dependency["license"]),
                "name": str(dependency["name"]),
                "versionInfo": str(dependency.get("version", dependency.get("minimum_version"))),
            }
        )
        relationships.append(
            {"spdxElementId": package_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": dependency_id}
        )
    namespace_seed = canonical_json({"archive": archive_name, "files": files, "packages": packages})
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: debz-release"],
            "licenseListVersion": "3.25",
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [package_id],
        "documentNamespace": f"https://github.com/cataggar/debz/releases/{name}/{uuid.uuid5(uuid.NAMESPACE_URL, sha256_bytes(namespace_seed))}",
        "name": f"{name}-sbom",
        "packages": packages,
        "relationships": sorted(
            relationships, key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
        ),
        "spdxVersion": "SPDX-2.3",
        "files": files,
    }


def verify_sbom(path: pathlib.Path, archive_name: str) -> None:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid SBOM {path.name}: {error}") from error
    for field in ("SPDXID", "spdxVersion", "dataLicense", "documentNamespace", "creationInfo", "packages", "files", "relationships"):
        if field not in document:
            raise ReleaseError(f"SBOM missing {field}: {path.name}")
    if document["spdxVersion"] != "SPDX-2.3" or document["dataLicense"] != "CC0-1.0":
        raise ReleaseError(f"SBOM has unsupported schema identifiers: {path.name}")
    packages = document["packages"]
    if not packages or packages[0].get("packageFileName") != archive_name:
        raise ReleaseError(f"SBOM does not describe {archive_name}")
    names = {item.get("name") for item in packages}
    if not {"debz", "libsolv", "liblzma", "libzstd"}.issubset(names):
        raise ReleaseError(f"SBOM dependency coverage is incomplete: {path.name}")
    file_sha1_values = []
    for file_entry in document["files"]:
        license_info = file_entry.get("licenseInfoInFiles")
        if not isinstance(license_info, list) or not license_info or not all(
            isinstance(item, str) for item in license_info
        ):
            raise ReleaseError(f"SBOM file has invalid licenseInfoInFiles: {path.name}")
        checksums = file_entry.get("checksums")
        if not isinstance(checksums, list):
            raise ReleaseError(f"SBOM file has invalid checksums: {path.name}")
        sha1_values = [
            item.get("checksumValue")
            for item in checksums
            if isinstance(item, dict) and item.get("algorithm") == "SHA1"
        ]
        if len(sha1_values) != 1 or not isinstance(sha1_values[0], str) or not re.fullmatch(
            r"[0-9a-f]{40}", sha1_values[0]
        ):
            raise ReleaseError(f"SBOM file has invalid SHA1 checksum: {path.name}")
        file_sha1_values.append(sha1_values[0])
    expected_verification = hashlib.sha1(
        "".join(sorted(file_sha1_values)).encode("ascii")
    ).hexdigest()
    verification = packages[0].get("packageVerificationCode")
    if not isinstance(verification, dict) or verification.get("packageVerificationCodeValue") != expected_verification:
        raise ReleaseError(f"SBOM packageVerificationCode is invalid: {path.name}")
    if canonical_json(document) != path.read_bytes():
        raise ReleaseError(f"SBOM is not canonical JSON: {path.name}")


def create_release_files(
    output: pathlib.Path,
    base_name: str,
    version: str,
    entries: list[tuple[str, bytes, int]],
    epoch: int,
    dependencies: list[dict[str, object]],
) -> list[pathlib.Path]:
    output.mkdir(parents=True, exist_ok=True)
    tar_data = build_tar(entries, epoch)
    created: list[pathlib.Path] = []
    for archive_format in FORMATS:
        archive = output / f"{base_name}.{archive_format}"
        archive_data = compress_tar(tar_data, archive_format)
        write_bytes(archive, archive_data)
        created.extend((archive, write_checksum(archive)))
        sbom = archive.with_name(archive.name + ".spdx.json")
        write_bytes(
            sbom,
            canonical_json(
                spdx_document(base_name, version, archive.name, entries, dependencies, sha256_bytes(archive_data))
            ),
        )
        created.extend((sbom, write_checksum(sbom)))
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
        pathlib.PurePosixPath("share/debz/runtime-dependencies.json"),
    }
    present = {pathlib.PurePosixPath(name).relative_to(root_name) for name, _, _ in entries}
    missing = required - present
    if missing:
        raise ReleaseError("install prefix is missing required files: " + ", ".join(map(str, sorted(missing))))
    assert binary is not None
    return entries, binary


def git(repo: pathlib.Path, *arguments: str, text: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )
    if result.returncode:
        stderr = result.stderr if text else result.stderr.decode(errors="replace")
        raise ReleaseError(f"git {' '.join(arguments)} failed: {stderr.strip()}")
    return result.stdout


def source_entries(repo: pathlib.Path, commit: str, root_name: str) -> list[tuple[str, bytes, int]]:
    resolved = str(git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}", text=True)).strip()
    listing = bytes(git(repo, "ls-tree", "-rrz", "--full-tree", resolved)).split(b"\0")
    entries = []
    for record in listing:
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        if kind != "blob":
            raise ReleaseError(f"source tree contains unsupported {kind}: {raw_path!r}")
        path_text = raw_path.decode("utf-8", "strict")
        relative = safe_relative(path_text)
        data = bytes(git(repo, "cat-file", "blob", object_id))
        validate_payload(relative, data)
        if data.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
            raise ReleaseError(f"source tree contains a generated binary: {relative}")
        if mode not in {"100644", "100755"}:
            raise ReleaseError(f"source tree contains unsupported mode {mode}: {relative}")
        file_mode = 0o755 if mode == "100755" else 0o644
        entries.append((f"{root_name}/{relative}", data, file_mode))
    return entries


def expected_asset_names(version: str) -> list[str]:
    names = []
    bases = [f"debz-{version}-{platform}" for platform in PLATFORMS] + [f"debz-{version}-source"]
    for base in bases:
        for archive_format in FORMATS:
            archive = f"{base}.{archive_format}"
            names.extend((archive, archive + ".sha256", archive + ".spdx.json", archive + ".spdx.json.sha256"))
    names.extend((f"debz-{version}-release-manifest.json", f"debz-{version}-release-manifest.json.sha256"))
    return sorted(names)


def manifest_document(tag: str) -> dict[str, object]:
    version = parse_tag(tag)
    return {
        "schemaVersion": 1,
        "tag": tag,
        "version": version,
        "platforms": [
            {"architecture": "x86_64", "name": "linux-x64", "os": "linux"},
            {"architecture": "aarch64", "name": "linux-arm64", "os": "linux"},
        ],
        "assets": expected_asset_names(version),
    }


def write_manifest(tag: str, output: pathlib.Path) -> pathlib.Path:
    version = parse_tag(tag)
    path = output / f"debz-{version}-release-manifest.json"
    write_bytes(path, canonical_json(manifest_document(tag)))
    write_checksum(path)
    return path


def audit_archive(
    path: pathlib.Path, kind: str, version: str, platform: str | None
) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    entries = archive_entries(path)
    names = {member.name.rstrip("/") for member, _ in entries}
    root = f"debz-{version}-source" if kind == "source" else f"debz-{version}-{platform}"
    if not names or any(name != root and not name.startswith(root + "/") for name in names):
        raise ReleaseError(f"archive has an unexpected top-level path: {path.name}")
    if kind == "binary":
        required = {
            f"{root}/bin/debz",
            f"{root}/share/doc/debz/LICENSE",
            f"{root}/share/doc/debz/THIRD_PARTY_NOTICES",
            f"{root}/share/debz/runtime-dependencies.json",
        }
    else:
        required = {f"{root}/LICENSE", f"{root}/THIRD_PARTY_NOTICES", f"{root}/build.zig.zon"}
    missing = required - names
    if missing:
        raise ReleaseError(f"archive is missing: {', '.join(sorted(missing))}")
    if kind == "binary":
        for member, _ in entries:
            name = member.name.rstrip("/")
            relative = pathlib.PurePosixPath(name).relative_to(root)
            if len(relative.parts) > 0 and relative.parts[0] not in {"bin", "lib", "share"}:
                raise ReleaseError(f"unexpected install path in binary archive: {name}")
            if member.isfile() and member.mode == 0o755 and name != f"{root}/bin/debz":
                raise ReleaseError(f"unexpected executable in binary archive: {name}")
    files = [(member.name, data, member.mode) for member, data in entries if member.isfile() and data is not None]
    epoch = int(entries[0][0].mtime)
    archive_format = "tar.gz" if path.name.endswith(".tar.gz") else "tar.xz" if path.name.endswith(".tar.xz") else ""
    if not archive_format or compress_tar(build_tar(files, epoch), archive_format) != path.read_bytes():
        raise ReleaseError(f"archive encoding or metadata is not deterministic: {path.name}")
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
    validate_elf_platform(binary, platform)
    validate_runtime_manifest(runtime, dependencies)
    validate_dynamic_dependencies(binary, dependencies)


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
        for argument, expected in (("--version", version), ("--help", "Usage: debz")):
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
    validate_elf_platform(binary, args.platform)
    runtime_data = next(data for name, data, _ in entries if name.endswith("/share/debz/runtime-dependencies.json"))
    validate_runtime_manifest(runtime_data, dependencies)
    validate_dynamic_dependencies(binary, dependencies)
    for path in create_release_files(args.output, root_name, version, entries, args.epoch, dependencies):
        print(path)


def command_source(args: argparse.Namespace) -> None:
    version = parse_tag(args.tag)
    dependencies = policy_dependencies(args.policy)
    resolved = str(git(args.repo, "rev-parse", "--verify", f"{args.commit}^{{commit}}", text=True)).strip()
    epoch = int(str(git(args.repo, "show", "-s", "--format=%ct", resolved, text=True)).strip())
    root_name = f"debz-{version}-source"
    entries = source_entries(args.repo, resolved, root_name)
    for path in create_release_files(args.output, root_name, version, entries, epoch, dependencies):
        print(path)


def command_manifest(args: argparse.Namespace) -> None:
    print(write_manifest(args.tag, args.output))


def command_audit(args: argparse.Namespace) -> None:
    version = parse_tag(args.tag)
    entries = audit_archive(args.archive, args.kind, version, args.platform)
    if args.kind == "binary":
        validate_archived_binary(entries, version, args.platform, policy_dependencies(args.policy))
    validate_checksum(args.archive.with_name(args.archive.name + ".sha256"), args.archive)
    sbom = args.archive.with_name(args.archive.name + ".spdx.json")
    validate_checksum(sbom.with_name(sbom.name + ".sha256"), sbom)
    verify_sbom(sbom, args.archive.name)
    if args.smoke and args.kind == "binary" and args.platform == native_platform():
        smoke_binary(args.archive, version)
    print(f"verified {args.archive}")


def command_verify(args: argparse.Namespace) -> None:
    try:
        manifest = json.loads(args.manifest.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid manifest: {error}") from error
    tag = manifest.get("tag")
    version = parse_tag(tag) if isinstance(tag, str) else ""
    if manifest != manifest_document(tag) or canonical_json(manifest) != args.manifest.read_bytes():
        raise ReleaseError("release manifest is incomplete or non-canonical")
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
        raise ReleaseError("release assets are undeclared: " + ", ".join(sorted(unexpected)))
    expected_manifest = args.assets / args.manifest.name
    if args.manifest.resolve() != expected_manifest.resolve():
        raise ReleaseError("release manifest must be the declared file in the assets directory")
    validate_checksum(args.manifest.with_name(args.manifest.name + ".sha256"), args.manifest)
    dependencies = policy_dependencies(args.policy)
    for platform in PLATFORMS:
        for archive_format in FORMATS:
            archive = args.assets / f"debz-{version}-{platform}.{archive_format}"
            entries = audit_archive(archive, "binary", version, platform)
            validate_archived_binary(entries, version, platform, dependencies)
            validate_checksum(archive.with_name(archive.name + ".sha256"), archive)
            sbom = archive.with_name(archive.name + ".spdx.json")
            validate_checksum(sbom.with_name(sbom.name + ".sha256"), sbom)
            verify_sbom(sbom, archive.name)
    for archive_format in FORMATS:
        archive = args.assets / f"debz-{version}-source.{archive_format}"
        audit_archive(archive, "source", version, None)
        validate_checksum(archive.with_name(archive.name + ".sha256"), archive)
        sbom = archive.with_name(archive.name + ".spdx.json")
        validate_checksum(sbom.with_name(sbom.name + ".sha256"), sbom)
        verify_sbom(sbom, archive.name)
    if args.smoke:
        platform = native_platform()
        if platform:
            smoke_binary(args.assets / f"debz-{version}-{platform}.tar.gz", version)
    print(f"verified {len(expected)} release assets")


def command_dry_run(args: argparse.Namespace) -> None:
    print(canonical_json(manifest_document(args.tag)).decode(), end="")


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

    source = subcommands.add_parser("source", help="create deterministic source release assets")
    source.add_argument("--tag", required=True)
    source.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    source.add_argument("--commit", default="HEAD")
    source.add_argument("--output", type=pathlib.Path, required=True)
    source.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("security/dependency-policy.json"))
    source.set_defaults(func=command_source)

    manifest = subcommands.add_parser("manifest", help="write the exact release asset manifest")
    manifest.add_argument("--tag", required=True)
    manifest.add_argument("--output", type=pathlib.Path, required=True)
    manifest.set_defaults(func=command_manifest)

    audit = subcommands.add_parser("audit", help="audit one archive, checksum and SBOM")
    audit.add_argument("--tag", required=True)
    audit.add_argument("--archive", type=pathlib.Path, required=True)
    audit.add_argument("--kind", choices=("binary", "source"), required=True)
    audit.add_argument("--platform", choices=PLATFORMS)
    audit.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("security/dependency-policy.json"))
    audit.add_argument("--smoke", action="store_true")
    audit.set_defaults(func=command_audit)

    verify = subcommands.add_parser("verify", help="verify a complete release asset directory")
    verify.add_argument("--manifest", type=pathlib.Path, required=True)
    verify.add_argument("--assets", type=pathlib.Path, required=True)
    verify.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("security/dependency-policy.json"))
    verify.add_argument("--smoke", action="store_true")
    verify.set_defaults(func=command_verify)

    dry_run = subcommands.add_parser("dry-run", help="print the exact planned asset manifest")
    dry_run.add_argument("--tag", required=True)
    dry_run.set_defaults(func=command_dry_run)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        if args.command == "audit" and args.kind == "binary" and not args.platform:
            raise ReleaseError("--platform is required for binary archive audit")
        args.func(args)
        return 0
    except ReleaseError as error:
        print(f"release: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
