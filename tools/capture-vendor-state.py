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
    parts = value.split("/")
    for part in parts:
        _validate_component(part)
    return "/".join(parts)


def _validate_absolute_directory(
    value: str | os.PathLike[str],
    *,
    label: str,
    allow_root: bool = False,
) -> pathlib.Path:
    text = os.fspath(value)
    if (
        not text.startswith("/")
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
    current = pathlib.Path("/")
    for component in components:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise CaptureError(f"cannot stat {label} component {current}: {error}") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CaptureError(f"{label} component must be a real directory: {current}")
    return pathlib.Path(text)


def _directory(
    root: pathlib.Path, relative: str, *, required: bool
) -> pathlib.Path | None:
    current = root
    for component in _normalize_relative(relative).split("/"):
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if required:
                raise CaptureError(f"required directory is missing: {relative}")
            return None
        except OSError as error:
            raise CaptureError(f"cannot stat directory {relative}: {error}") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CaptureError(f"directory is unsafe: {relative}")
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
    directory: pathlib.Path, maximum: int, label: str
) -> list[os.DirEntry[str]]:
    children: list[os.DirEntry[str]] = []
    try:
        with os.scandir(directory) as iterator:
            for child in iterator:
                children.append(child)
                if len(children) > maximum:
                    raise CaptureError(f"{label} count limit exceeded")
    except CaptureError:
        raise
    except OSError as error:
        raise CaptureError(f"cannot scan {label}: {error}") from error
    return sorted(children, key=lambda item: _path_key(item.name))


def _metadata(metadata: os.stat_result) -> dict[str, Any]:
    return {
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _read_regular(
    path: pathlib.Path,
    expected: os.stat_result,
    *,
    maximum: int,
    budget: dict[str, int],
    budget_key: str,
    total_maximum: int,
    retain: bool,
) -> tuple[str, bytes | None]:
    if expected.st_size > maximum:
        raise CaptureError(f"regular file exceeds limit: {path}")
    budget[budget_key] += expected.st_size
    if budget[budget_key] > total_maximum:
        raise CaptureError(f"aggregate regular-file limit exceeded: {budget_key}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CaptureError(f"cannot open regular file {path}: {error}") from error
    digest = hashlib.sha256()
    contents = bytearray() if retain else None
    observed = 0
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
            or opened.st_size != expected.st_size
        ):
            raise CaptureError(f"regular file changed before hashing: {path}")
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
            if contents is not None:
                contents.extend(chunk)
    if observed != expected.st_size:
        raise CaptureError(f"regular file changed while hashing: {path}")
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


def _absolute_reference(value: str, maximum_bytes: int) -> str:
    if (
        not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "//" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum_bytes
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


def _scan_metadata(
    root: pathlib.Path, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    budget = {"metadata_bytes": 0}
    references: set[str] = set()
    control_members: list[dict[str, Any]] = []
    info = _directory(root, "var/lib/dpkg/info", required=True)
    assert info is not None
    info_children = _bounded_children(
        info, limits.max_control_members, "control-member"
    )
    for child in info_children:
        name = _validate_component(child.name)
        relative = f"var/lib/dpkg/info/{name}"
        try:
            metadata = child.stat(follow_symlinks=False)
        except OSError as error:
            raise CaptureError(f"cannot stat {relative}: {error}") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise CaptureError(f"control member is not a regular file: {relative}")
        classification = _classification(name)
        digest, data = _read_regular(
            pathlib.Path(child.path),
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

    alternatives_records: list[dict[str, Any]] = []
    alternatives = _directory(
        root, "var/lib/dpkg/alternatives", required=False
    )
    if alternatives is not None:
        children = _bounded_children(
            alternatives,
            limits.max_alternatives_records,
            "alternatives-record",
        )
        for child in children:
            name = _validate_component(child.name)
            relative = f"var/lib/dpkg/alternatives/{name}"
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise CaptureError(f"cannot stat {relative}: {error}") from error
            if not stat.S_ISREG(metadata.st_mode):
                raise CaptureError(
                    f"alternatives record is not a regular file: {relative}"
                )
            digest, data = _read_regular(
                pathlib.Path(child.path),
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

    control_members.sort(key=lambda item: _path_key(item["path"]))
    alternatives_records.sort(key=lambda item: _path_key(item["path"]))
    return (
        control_members,
        alternatives_records,
        references,
    )


def _resolve_link_target(parent: list[str], target: str, limits: Limits) -> list[str]:
    try:
        encoded = target.encode("utf-8")
    except UnicodeEncodeError as error:
        raise CaptureError("symlink target is not valid UTF-8") from error
    if (
        not target
        or "\x00" in target
        or len(encoded) > limits.max_link_target_bytes
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
    relative = "/".join(result)
    _allowed_reference(relative)
    return result


def _add_entry(
    entries: dict[str, dict[str, Any]],
    entry: dict[str, Any],
    limits: Limits,
) -> None:
    path = entry["path"]
    previous = entries.get(path)
    if previous is not None:
        if previous != entry:
            raise CaptureError(f"linked state changed during capture: {path}")
        return
    if len(entries) >= limits.max_linked_entries:
        raise CaptureError("linked-filesystem entry count limit exceeded")
    entries[path] = entry


def _capture_reference(
    root: pathlib.Path,
    requested: str,
    limits: Limits,
    entries: dict[str, dict[str, Any]],
    budget: dict[str, int],
) -> None:
    unresolved = _normalize_relative(requested).split("/")
    resolved: list[str] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    hops = 0
    while unresolved:
        state = (tuple(resolved), tuple(unresolved))
        if state in seen:
            raise CaptureError(f"symlink cycle while resolving {requested}")
        seen.add(state)
        component = unresolved.pop(0)
        current_parts = [*resolved, component]
        relative = "/".join(current_parts)
        _allowed_reference(relative)
        path = root.joinpath(*current_parts)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            _add_entry(entries, {"path": relative, "kind": "absent"}, limits)
            return
        except OSError as error:
            raise CaptureError(f"cannot stat linked path {relative}: {error}") from error
        kind = _kind(metadata.st_mode)
        if kind == "symlink":
            try:
                target = os.readlink(path)
            except OSError as error:
                raise CaptureError(f"cannot read symlink {relative}: {error}") from error
            _add_entry(
                entries,
                {
                    "path": relative,
                    "kind": "symlink",
                    **_metadata(metadata),
                    "target": target,
                },
                limits,
            )
            hops += 1
            if hops > limits.max_link_hops:
                raise CaptureError(f"symlink hop limit exceeded: {requested}")
            unresolved = [
                *_resolve_link_target(resolved, target, limits),
                *unresolved,
            ]
            resolved = []
            continue
        if kind == "directory":
            resolved.append(component)
            if not unresolved:
                _add_entry(
                    entries,
                    {
                        "path": relative,
                        "kind": "directory",
                        **_metadata(metadata),
                    },
                    limits,
                )
            continue
        if kind == "regular":
            if unresolved:
                raise CaptureError(
                    f"non-directory component in linked path {requested}: {relative}"
                )
            if relative not in entries:
                digest, _ = _read_regular(
                    path,
                    metadata,
                    maximum=limits.max_linked_file_bytes,
                    budget=budget,
                    budget_key="linked_bytes",
                    total_maximum=limits.max_total_linked_bytes,
                    retain=False,
                )
                _add_entry(
                    entries,
                    {
                        "path": relative,
                        "kind": "regular",
                        **_metadata(metadata),
                        "size": metadata.st_size,
                        "sha256": digest,
                    },
                    limits,
                )
            return
        raise CaptureError(f"linked path is a special file: {relative} ({kind})")


def _capture_linked_filesystem(
    root: pathlib.Path,
    references: set[str],
    limits: Limits,
) -> tuple[list[str], list[dict[str, Any]]]:
    alternatives = _directory(root, "etc/alternatives", required=False)
    if alternatives is not None:
        children = _bounded_children(
            alternatives, limits.max_referenced_paths, "etc/alternatives entry"
        )
        for child in children:
            name = _validate_component(child.name)
            references.add(f"etc/alternatives/{name}")
            if len(references) > limits.max_referenced_paths:
                raise CaptureError("alternative reference count limit exceeded")
    if len(references) > limits.max_referenced_paths:
        raise CaptureError("alternative reference count limit exceeded")
    requested = sorted(references, key=_path_key)
    entries: dict[str, dict[str, Any]] = {}
    budget = {"linked_bytes": 0}
    for relative in requested:
        _capture_reference(root, relative, limits, entries, budget)
    return requested, sorted(entries.values(), key=lambda item: _path_key(item["path"]))


def capture(
    reference_root: pathlib.Path,
    architecture: str,
    limits: Limits = Limits(),
) -> dict[str, Any]:
    if architecture not in ARCHITECTURES:
        raise CaptureError(f"unsupported architecture: {architecture!r}")
    root = _validate_absolute_directory(reference_root, label="reference root")
    control_members, alternatives_records, references = _scan_metadata(root, limits)
    requested, linked_entries = _capture_linked_filesystem(root, references, limits)
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
    text = os.fspath(output)
    if not text.startswith("/") or text.endswith("/") or "\x00" in text or "//" in text:
        raise CaptureError("output must be a canonical absolute file path")
    if any(component in {"", ".", ".."} for component in text.split("/")[1:]):
        raise CaptureError("output contains an ambiguous component")
    parent = _validate_absolute_directory(
        output.parent, label="output parent", allow_root=True
    )
    _validate_component(output.name)
    try:
        output.relative_to(reference_root)
    except ValueError:
        pass
    else:
        raise CaptureError("output must be outside the reference root")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent / output.name, flags, 0o600)
    except OSError as error:
        raise CaptureError(f"cannot create output {output}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb", buffering=0) as stream:
            stream.write(contents)
    except BaseException:
        try:
            output.unlink()
        except OSError:
            pass
        raise


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-root", required=True, type=pathlib.Path)
    parser.add_argument("--architecture", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    options = parser.parse_args(arguments)
    try:
        root = _validate_absolute_directory(
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
