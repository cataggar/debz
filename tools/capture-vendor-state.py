#!/usr/bin/env python3
"""Capture bounded vendor package state from one explicit reference root."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from collections import deque
from dataclasses import dataclass
from typing import Any

SCHEMA = "https://debz.dev/schema/vendor-state-inventory-v1"
ARCHITECTURES = frozenset({"amd64", "arm64"})
CLASSIFICATIONS = (
    "format",
    "control",
    "ownership-list",
    "checksums",
    "conffiles",
    "triggers",
    "maintainer-script",
    "debconf-config",
    "package-alternatives",
    "retained-metadata",
    "unclassified",
)
MAINTAINER_SCRIPTS = frozenset({"preinst", "postinst", "prerm", "postrm"})
RETAINED_METADATA = frozenset({"templates", "shlibs", "symbols"})
SENSITIVE_PATHS = (
    "dev",
    "proc",
    "sys",
    "run",
    "root",
    "home",
    "tmp",
    "var/tmp",
    "var/log",
    "var/lib/cloud",
    "var/lib/private",
    "etc/shadow",
    "etc/gshadow",
    "etc/sudoers",
    "etc/sudoers.d",
    "etc/ssh",
    "etc/ssl/private",
    "etc/apt/auth.conf",
    "etc/apt/auth.conf.d",
)
PUBLIC_REFERENCE_ROOTS = frozenset(
    {"bin", "etc", "lib", "lib32", "lib64", "libx32", "sbin", "usr"}
)
MAX_JSON_INTEGER = (1 << 53) - 1
MAX_DOCUMENT_PATH_BYTES = 4096
ABSOLUTE_PATH = re.compile(r"(?:^|[\s:=])(/[^\s\x00]+)", re.MULTILINE)


@dataclass(frozen=True)
class Limits:
    max_control_members: int = 100_000
    max_alternatives_records: int = 20_000
    max_metadata_file_bytes: int = 8 * 1024 * 1024
    max_total_metadata_bytes: int = 256 * 1024 * 1024
    max_referenced_paths: int = 50_000
    max_linked_entries: int = 100_000
    max_link_hops: int = 64
    max_link_target_bytes: int = 4096
    max_linked_file_bytes: int = 256 * 1024 * 1024
    max_total_linked_bytes: int = 1024 * 1024 * 1024


class CaptureError(ValueError):
    """The selected reference root cannot be inventoried safely."""


def _path_key(value: str) -> bytes:
    if not isinstance(value, str):
        raise CaptureError(f"path is not text: {value!r}")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise CaptureError(f"path is not valid UTF-8: {value!r}") from error


def _validate_component(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CaptureError(f"unsafe path component: {value!r}")
    _path_key(value)
    return value


def _normalize_relative(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or "\x00" in value
    ):
        raise CaptureError(f"invalid relative path: {value!r}")
    if len(_path_key(value)) > MAX_DOCUMENT_PATH_BYTES:
        raise CaptureError(f"relative path exceeds limit: {value!r}")
    parts = value.split("/")
    for part in parts:
        _validate_component(part)
    return "/".join(parts)


def _absolute_path(
    value: str | os.PathLike[str],
    *,
    label: str,
    allow_root: bool = False,
) -> pathlib.Path:
    try:
        text = os.fspath(value)
    except TypeError as error:
        raise CaptureError(f"{label} must be a path") from error
    if (
        not isinstance(text, str)
        or not text.startswith("/")
        or "\x00" in text
        or "//" in text
        or (text != "/" and text.endswith("/"))
    ):
        raise CaptureError(f"{label} must be a canonical absolute path")
    components = text.split("/")[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise CaptureError(f"{label} contains an ambiguous component")
    if text == "/" and not allow_root:
        raise CaptureError(f"{label} must not be the host root")
    for component in components:
        _validate_component(component)
    return pathlib.Path(text)


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise CaptureError("platform does not support no-follow directory opens")
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _regular_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise CaptureError("platform does not support no-follow regular-file opens")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


_STABLE_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _same_metadata(first: os.stat_result, second: os.stat_result) -> bool:
    return all(
        getattr(first, field) == getattr(second, field)
        for field in _STABLE_STAT_FIELDS
    )


def _open_absolute_directory(
    value: str | os.PathLike[str],
    *,
    label: str,
    allow_root: bool = False,
) -> tuple[pathlib.Path, int]:
    path = _absolute_path(value, label=label, allow_root=allow_root)
    flags = _directory_flags()
    try:
        current = os.open("/", flags)
    except OSError as error:
        raise CaptureError(
            f"cannot open host root while resolving {label}: {error}"
        ) from error
    current_path = pathlib.Path("/")
    try:
        for component in path.parts[1:]:
            current_path /= component
            try:
                expected = os.stat(component, dir_fd=current, follow_symlinks=False)
            except OSError as error:
                raise CaptureError(
                    f"cannot stat {label} component {current_path}: {error}"
                ) from error
            if not stat.S_ISDIR(expected.st_mode) or stat.S_ISLNK(expected.st_mode):
                raise CaptureError(
                    f"{label} component must be a real directory: {current_path}"
                )
            try:
                following = os.open(component, flags, dir_fd=current)
            except OSError as error:
                raise CaptureError(
                    f"cannot open {label} component {current_path}: {error}"
                ) from error
            opened = os.fstat(following)
            if not stat.S_ISDIR(opened.st_mode) or not _same_metadata(expected, opened):
                os.close(following)
                raise CaptureError(
                    f"{label} component changed while opening: {current_path}"
                )
            os.close(current)
            current = following
        return path, current
    except BaseException:
        os.close(current)
        raise


def _open_directory_at(
    root_descriptor: int, relative: str, *, required: bool
) -> int | None:
    normalized = _normalize_relative(relative)
    current = os.dup(root_descriptor)
    for component in normalized.split("/"):
        try:
            expected = os.stat(component, dir_fd=current, follow_symlinks=False)
        except FileNotFoundError:
            os.close(current)
            if required:
                raise CaptureError(f"required directory is missing: {normalized}")
            return None
        except OSError as error:
            os.close(current)
            raise CaptureError(f"cannot stat directory {normalized}: {error}") from error
        if not stat.S_ISDIR(expected.st_mode) or stat.S_ISLNK(expected.st_mode):
            os.close(current)
            raise CaptureError(f"directory is unsafe: {normalized}")
        try:
            following = os.open(component, _directory_flags(), dir_fd=current)
        except OSError as error:
            os.close(current)
            raise CaptureError(f"cannot open directory {normalized}: {error}") from error
        opened = os.fstat(following)
        if not stat.S_ISDIR(opened.st_mode) or not _same_metadata(expected, opened):
            os.close(following)
            os.close(current)
            raise CaptureError(f"directory changed while opening: {normalized}")
        os.close(current)
        current = following
    return current


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "unknown"


def _bounded_children(
    directory_descriptor: int, maximum: int, label: str
) -> tuple[list[str], os.stat_result]:
    before = os.fstat(directory_descriptor)
    children: list[str] = []
    try:
        with os.scandir(directory_descriptor) as iterator:
            for child in iterator:
                children.append(child.name)
                if len(children) > maximum:
                    raise CaptureError(f"{label} count limit exceeded")
    except CaptureError:
        raise
    except OSError as error:
        raise CaptureError(f"cannot scan {label}: {error}") from error
    after = os.fstat(directory_descriptor)
    if not _same_metadata(before, after):
        raise CaptureError(f"{label} directory changed while scanning")
    return sorted(children, key=_path_key), before


def _require_unchanged_directory(
    directory_descriptor: int, expected: os.stat_result, label: str
) -> None:
    try:
        observed = os.fstat(directory_descriptor)
    except OSError as error:
        raise CaptureError(f"cannot restat {label} directory: {error}") from error
    if not _same_metadata(expected, observed):
        raise CaptureError(f"{label} directory changed during capture")


def _metadata(metadata: os.stat_result) -> dict[str, Any]:
    for label, value, maximum in (
        ("uid", metadata.st_uid, 4_294_967_295),
        ("gid", metadata.st_gid, 4_294_967_295),
    ):
        if type(value) is not int or value < 0 or value > maximum:
            raise CaptureError(f"{label} is outside the inventory schema")
    return {
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _read_regular_at(
    directory_descriptor: int,
    name: str,
    display_path: str,
    expected: os.stat_result,
    *,
    maximum: int,
    budget: dict[str, int],
    budget_key: str,
    total_maximum: int,
    retain: bool,
) -> tuple[str, bytes | None]:
    if not stat.S_ISREG(expected.st_mode):
        raise CaptureError(f"not a regular file: {display_path}")
    if expected.st_nlink != 1:
        raise CaptureError(f"hard-linked regular file is unsupported: {display_path}")
    if expected.st_size < 0 or expected.st_size > MAX_JSON_INTEGER:
        raise CaptureError(f"regular-file size is outside the inventory schema: {display_path}")
    if expected.st_size > maximum:
        raise CaptureError(f"regular file exceeds limit: {display_path}")
    total = budget[budget_key] + expected.st_size
    if total > total_maximum or total > MAX_JSON_INTEGER:
        raise CaptureError(f"aggregate regular-file limit exceeded: {budget_key}")
    try:
        descriptor = os.open(name, _regular_flags(), dir_fd=directory_descriptor)
    except OSError as error:
        raise CaptureError(f"cannot open regular file {display_path}: {error}") from error
    digest = hashlib.sha256()
    contents = bytearray() if retain else None
    observed = 0
    try:
        with os.fdopen(descriptor, "rb", buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or not _same_metadata(expected, opened)
            ):
                raise CaptureError(
                    f"regular file changed before hashing: {display_path}"
                )
            remaining = expected.st_size
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise CaptureError(
                        f"regular file changed while hashing: {display_path}"
                    )
                remaining -= len(chunk)
                observed += len(chunk)
                digest.update(chunk)
                if contents is not None:
                    contents.extend(chunk)
            if stream.read(1):
                raise CaptureError(
                    f"regular file grew while hashing: {display_path}"
                )
            finished = os.fstat(stream.fileno())
            if not _same_metadata(opened, finished):
                raise CaptureError(
                    f"regular file changed while hashing: {display_path}"
                )
    except CaptureError:
        raise
    except OSError as error:
        raise CaptureError(f"cannot read regular file {display_path}: {error}") from error
    if observed != expected.st_size:
        raise CaptureError(f"regular file changed while hashing: {display_path}")
    budget[budget_key] = total
    return digest.hexdigest(), bytes(contents) if contents is not None else None


def _classification(name: str) -> str:
    if name == "format":
        return "format"
    if "." not in name:
        return "unclassified"
    suffix = name.rsplit(".", 1)[1]
    if suffix == "control":
        return "control"
    if suffix == "list":
        return "ownership-list"
    if suffix == "md5sums":
        return "checksums"
    if suffix == "conffiles":
        return "conffiles"
    if suffix == "triggers":
        return "triggers"
    if suffix in MAINTAINER_SCRIPTS:
        return "maintainer-script"
    if suffix == "config":
        return "debconf-config"
    if suffix == "alternatives":
        return "package-alternatives"
    if suffix in RETAINED_METADATA:
        return "retained-metadata"
    return "unclassified"


def _allowed_reference(relative: str) -> None:
    if any(
        relative == denied or relative.startswith(denied + "/")
        for denied in SENSITIVE_PATHS
    ):
        raise CaptureError(f"alternative reference enters excluded state: {relative}")
    top_level = relative.split("/", 1)[0]
    if top_level not in PUBLIC_REFERENCE_ROOTS:
        raise CaptureError(f"alternative reference enters excluded state: {relative}")


def _absolute_reference(value: str, maximum_bytes: int) -> str:
    encoded = _path_key(value)
    if (
        not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "//" in value
        or "\x00" in value
        or len(encoded) > maximum_bytes
        or len(encoded) > MAX_DOCUMENT_PATH_BYTES
    ):
        raise CaptureError(f"malformed absolute alternative path: {value!r}")
    relative = _normalize_relative(value[1:])
    _allowed_reference(relative)
    return relative


def _extract_references(
    data: bytes, source: str, maximum: int, maximum_path_bytes: int
) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CaptureError(f"{source} is not UTF-8: {error}") from error
    if "\x00" in text or any(
        ord(character) < 32 and character not in "\n\r\t" for character in text
    ):
        raise CaptureError(f"{source} contains control bytes")
    references: set[str] = set()
    for match in ABSOLUTE_PATH.finditer(text):
        references.add(_absolute_reference(match.group(1), maximum_path_bytes))
        if len(references) > maximum:
            raise CaptureError("alternative reference count limit exceeded")
    return sorted(references, key=_path_key)


def _merge_references(
    destination: set[str], additions: list[str], maximum: int
) -> None:
    destination.update(additions)
    if len(destination) > maximum:
        raise CaptureError("alternative reference count limit exceeded")


def _stat_entry_at(
    directory_descriptor: int, name: str, relative: str
) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as error:
        raise CaptureError(f"cannot stat {relative}: {error}") from error


def _scan_metadata(
    root_descriptor: int, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    budget = {"metadata_bytes": 0}
    references: set[str] = set()
    control_members: list[dict[str, Any]] = []
    info_descriptor = _open_directory_at(
        root_descriptor, "var/lib/dpkg/info", required=True
    )
    assert info_descriptor is not None
    try:
        info_children, info_metadata = _bounded_children(
            info_descriptor, limits.max_control_members, "control-member"
        )
        for child_name in info_children:
            name = _validate_component(child_name)
            relative = _normalize_relative(f"var/lib/dpkg/info/{name}")
            metadata = _stat_entry_at(info_descriptor, name, relative)
            if not stat.S_ISREG(metadata.st_mode):
                raise CaptureError(
                    f"control member is not a regular file: {relative}"
                )
            classification = _classification(name)
            digest, data = _read_regular_at(
                info_descriptor,
                name,
                relative,
                metadata,
                maximum=limits.max_metadata_file_bytes,
                budget=budget,
                budget_key="metadata_bytes",
                total_maximum=limits.max_total_metadata_bytes,
                retain=classification == "package-alternatives",
            )
            referenced = (
                _extract_references(
                    data or b"",
                    relative,
                    limits.max_referenced_paths,
                    limits.max_link_target_bytes,
                )
                if classification == "package-alternatives"
                else []
            )
            _merge_references(references, referenced, limits.max_referenced_paths)
            control_members.append(
                {
                    "path": relative,
                    "classification": classification,
                    **_metadata(metadata),
                    "size": metadata.st_size,
                    "sha256": digest,
                    "referenced_paths": referenced,
                }
            )
        _require_unchanged_directory(
            info_descriptor, info_metadata, "control-member"
        )
    finally:
        os.close(info_descriptor)

    alternatives_records: list[dict[str, Any]] = []
    alternatives_descriptor = _open_directory_at(
        root_descriptor, "var/lib/dpkg/alternatives", required=False
    )
    if alternatives_descriptor is not None:
        try:
            children, alternatives_metadata = _bounded_children(
                alternatives_descriptor,
                limits.max_alternatives_records,
                "alternatives-record",
            )
            for child_name in children:
                name = _validate_component(child_name)
                relative = _normalize_relative(
                    f"var/lib/dpkg/alternatives/{name}"
                )
                metadata = _stat_entry_at(alternatives_descriptor, name, relative)
                if not stat.S_ISREG(metadata.st_mode):
                    raise CaptureError(
                        f"alternatives record is not a regular file: {relative}"
                    )
                digest, data = _read_regular_at(
                    alternatives_descriptor,
                    name,
                    relative,
                    metadata,
                    maximum=limits.max_metadata_file_bytes,
                    budget=budget,
                    budget_key="metadata_bytes",
                    total_maximum=limits.max_total_metadata_bytes,
                    retain=True,
                )
                referenced = _extract_references(
                    data or b"",
                    relative,
                    limits.max_referenced_paths,
                    limits.max_link_target_bytes,
                )
                _merge_references(
                    references, referenced, limits.max_referenced_paths
                )
                alternatives_records.append(
                    {
                        "path": relative,
                        **_metadata(metadata),
                        "size": metadata.st_size,
                        "sha256": digest,
                        "referenced_paths": referenced,
                    }
                )
            _require_unchanged_directory(
                alternatives_descriptor,
                alternatives_metadata,
                "alternatives-record",
            )
        finally:
            os.close(alternatives_descriptor)

    control_members.sort(key=lambda item: _path_key(item["path"]))
    alternatives_records.sort(key=lambda item: _path_key(item["path"]))
    return (
        control_members,
        alternatives_records,
        references,
    )


def _resolve_link_target(parent: list[str], target: str, limits: Limits) -> list[str]:
    encoded = _path_key(target)
    if (
        not target
        or "\x00" in target
        or len(encoded) > limits.max_link_target_bytes
        or len(encoded) > MAX_DOCUMENT_PATH_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
        or "//" in target
    ):
        raise CaptureError(f"unsafe symlink target: {target!r}")
    result = [] if target.startswith("/") else list(parent)
    for component in target.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            if not result:
                raise CaptureError(f"symlink target escapes reference root: {target!r}")
            result.pop()
            continue
        result.append(_validate_component(component))
    if not result:
        raise CaptureError(f"symlink target resolves to reference root: {target!r}")
    relative = _normalize_relative("/".join(result))
    _allowed_reference(relative)
    return relative.split("/")


def _add_entry(
    entries: dict[str, dict[str, Any]],
    identities: dict[str, tuple[int, ...] | None],
    entry: dict[str, Any],
    limits: Limits,
    metadata: os.stat_result | None = None,
) -> None:
    path = entry["path"]
    previous = entries.get(path)
    identity = (
        tuple(getattr(metadata, field) for field in _STABLE_STAT_FIELDS)
        if metadata is not None
        else None
    )
    if previous is not None:
        if previous != entry or identities[path] != identity:
            raise CaptureError(f"linked state changed during capture: {path}")
        return
    if len(entries) >= limits.max_linked_entries:
        raise CaptureError("linked-filesystem entry count limit exceeded")
    entries[path] = entry
    identities[path] = identity


def _open_known_directory_at(
    parent_descriptor: int,
    name: str,
    relative: str,
    expected: os.stat_result,
) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except OSError as error:
        raise CaptureError(f"cannot open linked directory {relative}: {error}") from error
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or not _same_metadata(expected, opened):
        os.close(descriptor)
        raise CaptureError(f"linked directory changed while opening: {relative}")
    return descriptor, opened


def _readlink_stable(
    parent_descriptor: int,
    name: str,
    relative: str,
    expected: os.stat_result,
) -> str:
    if expected.st_nlink != 1:
        raise CaptureError(f"hard-linked symlink is unsupported: {relative}")
    try:
        target = os.readlink(name, dir_fd=parent_descriptor)
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise CaptureError(f"cannot read symlink {relative}: {error}") from error
    if not stat.S_ISLNK(observed.st_mode) or not _same_metadata(expected, observed):
        raise CaptureError(f"symlink changed while reading: {relative}")
    if len(_path_key(target)) != expected.st_size:
        raise CaptureError(f"symlink size changed while reading: {relative}")
    return target


def _capture_reference(
    root_descriptor: int,
    requested: str,
    limits: Limits,
    entries: dict[str, dict[str, Any]],
    identities: dict[str, tuple[int, ...] | None],
    budget: dict[str, int],
) -> None:
    unresolved = deque(_normalize_relative(requested).split("/"))
    resolved: list[str] = []
    seen = {tuple(unresolved)}
    hops = 0
    current_descriptor = os.dup(root_descriptor)
    try:
        while unresolved:
            component = unresolved.popleft()
            current_parts = [*resolved, component]
            relative = _normalize_relative("/".join(current_parts))
            _allowed_reference(relative)
            parent_metadata = os.fstat(current_descriptor)
            try:
                metadata = os.stat(
                    component,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                _add_entry(
                    entries,
                    identities,
                    {"path": relative, "kind": "absent"},
                    limits,
                )
                _require_unchanged_directory(
                    current_descriptor, parent_metadata, relative
                )
                return
            except OSError as error:
                raise CaptureError(
                    f"cannot stat linked path {relative}: {error}"
                ) from error
            kind = _kind(metadata.st_mode)
            if kind == "symlink":
                target = _readlink_stable(
                    current_descriptor, component, relative, metadata
                )
                _require_unchanged_directory(
                    current_descriptor, parent_metadata, relative
                )
                _add_entry(
                    entries,
                    identities,
                    {
                        "path": relative,
                        "kind": "symlink",
                        **_metadata(metadata),
                        "target": target,
                    },
                    limits,
                    metadata,
                )
                hops += 1
                if hops > limits.max_link_hops:
                    raise CaptureError(f"symlink hop limit exceeded: {requested}")
                combined = _normalize_relative(
                    "/".join(
                        [
                            *_resolve_link_target(resolved, target, limits),
                            *unresolved,
                        ]
                    )
                )
                unresolved = deque(combined.split("/"))
                resolved = []
                state = tuple(unresolved)
                if state in seen:
                    raise CaptureError(
                        f"symlink cycle while resolving {requested}"
                    )
                seen.add(state)
                os.close(current_descriptor)
                current_descriptor = os.dup(root_descriptor)
                continue
            if kind == "directory":
                following, opened = _open_known_directory_at(
                    current_descriptor, component, relative, metadata
                )
                _require_unchanged_directory(
                    current_descriptor, parent_metadata, relative
                )
                if unresolved:
                    os.close(current_descriptor)
                    current_descriptor = following
                    resolved.append(component)
                    continue
                os.close(following)
                _add_entry(
                    entries,
                    identities,
                    {
                        "path": relative,
                        "kind": "directory",
                        **_metadata(opened),
                    },
                    limits,
                    opened,
                )
                return
            if kind == "regular":
                if unresolved:
                    raise CaptureError(
                        f"non-directory component in linked path "
                        f"{requested}: {relative}"
                    )
                previous = entries.get(relative)
                if previous is not None:
                    _add_entry(
                        entries,
                        identities,
                        {
                            "path": relative,
                            "kind": "regular",
                            **_metadata(metadata),
                            "size": metadata.st_size,
                            "sha256": previous.get("sha256", ""),
                        },
                        limits,
                        metadata,
                    )
                else:
                    digest, _ = _read_regular_at(
                        current_descriptor,
                        component,
                        relative,
                        metadata,
                        maximum=limits.max_linked_file_bytes,
                        budget=budget,
                        budget_key="linked_bytes",
                        total_maximum=limits.max_total_linked_bytes,
                        retain=False,
                    )
                    _add_entry(
                        entries,
                        identities,
                        {
                            "path": relative,
                            "kind": "regular",
                            **_metadata(metadata),
                            "size": metadata.st_size,
                            "sha256": digest,
                        },
                        limits,
                        metadata,
                    )
                _require_unchanged_directory(
                    current_descriptor, parent_metadata, relative
                )
                return
            raise CaptureError(
                f"linked path is a special file: {relative} ({kind})"
            )
    finally:
        os.close(current_descriptor)


def _capture_linked_filesystem(
    root_descriptor: int,
    references: set[str],
    limits: Limits,
) -> tuple[list[str], list[dict[str, Any]]]:
    alternatives_descriptor = _open_directory_at(
        root_descriptor, "etc/alternatives", required=False
    )
    alternatives_metadata: os.stat_result | None = None
    try:
        if alternatives_descriptor is not None:
            children, alternatives_metadata = _bounded_children(
                alternatives_descriptor,
                limits.max_referenced_paths,
                "etc/alternatives entry",
            )
            for child_name in children:
                name = _validate_component(child_name)
                references.add(
                    _normalize_relative(f"etc/alternatives/{name}")
                )
                if len(references) > limits.max_referenced_paths:
                    raise CaptureError(
                        "alternative reference count limit exceeded"
                    )
        if len(references) > limits.max_referenced_paths:
            raise CaptureError("alternative reference count limit exceeded")
        requested = sorted(references, key=_path_key)
        entries: dict[str, dict[str, Any]] = {}
        identities: dict[str, tuple[int, ...] | None] = {}
        budget = {"linked_bytes": 0}
        for relative in requested:
            _capture_reference(
                root_descriptor,
                relative,
                limits,
                entries,
                identities,
                budget,
            )
        if (
            alternatives_descriptor is not None
            and alternatives_metadata is not None
        ):
            _require_unchanged_directory(
                alternatives_descriptor,
                alternatives_metadata,
                "etc/alternatives entry",
            )
        return requested, sorted(
            entries.values(), key=lambda item: _path_key(item["path"])
        )
    finally:
        if alternatives_descriptor is not None:
            os.close(alternatives_descriptor)


def _validate_limits(limits: Limits) -> None:
    if not isinstance(limits, Limits):
        raise CaptureError("limits must use the Limits schema")
    for field in dataclasses.fields(limits):
        value = getattr(limits, field.name)
        if type(value) is not int or value < 1 or value > MAX_JSON_INTEGER:
            raise CaptureError(
                f"{field.name} must be a positive schema-safe integer"
            )


def capture(
    reference_root: pathlib.Path,
    architecture: str,
    limits: Limits = Limits(),
) -> dict[str, Any]:
    if not isinstance(architecture, str) or architecture not in ARCHITECTURES:
        raise CaptureError(f"unsupported architecture: {architecture!r}")
    _validate_limits(limits)
    _, root_descriptor = _open_absolute_directory(
        reference_root, label="reference root"
    )
    root_metadata = os.fstat(root_descriptor)
    try:
        control_members, alternatives_records, references = _scan_metadata(
            root_descriptor, limits
        )
        requested, linked_entries = _capture_linked_filesystem(
            root_descriptor, references, limits
        )
        _require_unchanged_directory(
            root_descriptor, root_metadata, "reference root"
        )
    finally:
        os.close(root_descriptor)
    counts = {classification: 0 for classification in CLASSIFICATIONS}
    for entry in control_members:
        counts[entry["classification"]] += 1
    if sum(counts.values()) != len(control_members):
        raise AssertionError("control-member classification is incomplete")
    return {
        "schema": SCHEMA,
        "version": 1,
        "architecture": architecture,
        "limits": dataclasses.asdict(limits),
        "control_members": {
            "classification_counts": counts,
            "entries": control_members,
        },
        "alternatives_database": alternatives_records,
        "linked_filesystem": {
            "requested_paths": requested,
            "entries": linked_entries,
        },
    }


def canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_output(
    output: pathlib.Path, reference_root: pathlib.Path, contents: bytes
) -> None:
    output_path = _absolute_path(output, label="output")
    reference_path = _absolute_path(reference_root, label="reference root")
    _, parent_descriptor = _open_absolute_directory(
        output_path.parent, label="output parent", allow_root=True
    )
    name = _validate_component(output_path.name)
    try:
        output_path.relative_to(reference_path)
    except ValueError:
        pass
    else:
        os.close(parent_descriptor)
        raise CaptureError("output must be outside the reference root")
    if not hasattr(os, "O_NOFOLLOW"):
        os.close(parent_descriptor)
        raise CaptureError("platform does not support no-follow output creation")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
    except OSError as error:
        os.close(parent_descriptor)
        raise CaptureError(f"cannot create output {output_path}: {error}") from error
    try:
        view = memoryview(contents)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise CaptureError(f"short write creating output {output_path}")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(contents)
        ):
            raise CaptureError(f"output changed while writing: {output_path}")
    except BaseException:
        try:
            os.unlink(name, dir_fd=parent_descriptor)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-root", required=True, type=pathlib.Path)
    parser.add_argument("--architecture", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    options = parser.parse_args(arguments)
    try:
        root = _absolute_path(
            options.reference_root, label="reference root"
        )
        document = capture(root, options.architecture)
        _write_output(options.output, root, canonical_json(document))
    except (CaptureError, OSError) as error:
        print(f"vendor-state-capture: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
