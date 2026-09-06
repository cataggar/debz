#!/usr/bin/env python3
"""Bounded semantic snapshots for native transaction differential tests."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from dataclasses import dataclass
from typing import Any, Iterable

SCHEMA = "https://debz.dev/test/native-transaction-snapshot-v1"
CORPUS_SCHEMA = "https://debz.dev/test/native-transaction-corpus-v1"
TRACE_PATH = "var/log/debz-native-differential.trace"
DEFAULT_EXCLUDES = (
    "var/lib/debz",
    "var/lib/dpkg",
    TRACE_PATH,
)
LOCK_FILES = frozenset({"lock", "lock-frontend", "triggers/Lock"})
SCENARIO_OPERATIONS = frozenset(
    {
        "install",
        "upgrade",
        "downgrade",
        "reinstall",
        "remove",
        "purge",
        "recover",
    }
)
SCENARIO_EXPECTATIONS = frozenset(
    {
        "success",
        "failure",
        "recovery-required",
        "failure-before-mutation",
        "success-after-recovery",
    }
)
SCENARIO_INITIAL_STATES = frozenset(
    {"fresh", "healthy", "locally-modified", "imported", "corrupt"}
)
SCENARIO_KEYS = frozenset({"id", "initial", "operations", "features", "expected"})
IDENTITY_PATTERN = re.compile(r"^[a-z0-9]+(?:[+.-][a-z0-9]+)*$")


@dataclass(frozen=True)
class Limits:
    max_entries: int = 500_000
    max_total_regular_bytes: int = 16 * 1024 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024 * 1024
    max_database_file_bytes: int = 64 * 1024 * 1024
    max_link_bytes: int = 4096
    max_xattrs_per_entry: int = 64
    max_xattr_bytes_per_entry: int = 1024 * 1024
    max_trace_bytes: int = 16 * 1024 * 1024
    max_differences: int = 100


class SnapshotError(ValueError):
    """The selected root or corpus cannot be represented safely."""


def _sha256_file(path: pathlib.Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    observed = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SnapshotError(f"cannot open regular file {path}: {error}") from error
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
            raise SnapshotError(f"file changed before hashing: {path}")
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
    if observed != expected_size:
        raise SnapshotError(f"file changed while hashing: {path}")
    return digest.hexdigest()


def _xattrs(path: pathlib.Path, limits: Limits) -> list[dict[str, str]]:
    try:
        names = sorted(os.listxattr(path, follow_symlinks=False))
    except OSError as error:
        if error.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return []
        raise SnapshotError(f"cannot list xattrs for {path}: {error}") from error
    if len(names) > limits.max_xattrs_per_entry:
        raise SnapshotError(f"too many xattrs for {path}")
    result: list[dict[str, str]] = []
    total = 0
    for name in names:
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            raise SnapshotError(f"cannot read xattr {name!r} for {path}: {error}") from error
        total += len(name.encode()) + len(value)
        if total > limits.max_xattr_bytes_per_entry:
            raise SnapshotError(f"xattrs exceed limit for {path}")
        result.append({"name": name, "value_hex": value.hex()})
    return result


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "unknown"


def _is_excluded(relative: str, excludes: tuple[str, ...]) -> bool:
    return any(relative == item or relative.startswith(item + "/") for item in excludes)


def capture_tree(
    root: pathlib.Path,
    limits: Limits,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
) -> list[dict[str, Any]]:
    """Capture a root without following symlinks."""

    root = _validated_root(root)
    normalized_excludes = tuple(sorted(_normalize_relative(item) for item in excludes))
    entries: list[dict[str, Any]] = []
    regular_inodes: dict[tuple[int, int], list[str]] = {}
    total_regular_bytes = 0
    pending = [("", root)]
    while pending:
        relative_parent, directory = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as error:
            raise SnapshotError(f"cannot scan {directory}: {error}") from error
        next_directories: list[tuple[str, pathlib.Path]] = []
        for child in children:
            relative = (
                f"{relative_parent}/{child.name}" if relative_parent else child.name
            )
            relative = _normalize_relative(relative)
            if _is_excluded(relative, normalized_excludes):
                continue
            if len(entries) >= limits.max_entries:
                raise SnapshotError("filesystem entry limit exceeded")
            path = directory / child.name
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise SnapshotError(f"cannot stat {path}: {error}") from error
            kind = _kind(metadata.st_mode)
            entry: dict[str, Any] = {
                "path": relative,
                "kind": kind,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "xattrs": _xattrs(path, limits),
            }
            if kind != "directory":
                entry["mtime_ns"] = metadata.st_mtime_ns
            if kind == "regular":
                if metadata.st_size > limits.max_file_bytes:
                    raise SnapshotError(f"file exceeds limit: {relative}")
                total_regular_bytes += metadata.st_size
                if total_regular_bytes > limits.max_total_regular_bytes:
                    raise SnapshotError("aggregate regular-file limit exceeded")
                entry["size"] = metadata.st_size
                entry["sha256"] = _sha256_file(path, metadata.st_size)
                if metadata.st_nlink > 1:
                    regular_inodes.setdefault(
                        (metadata.st_dev, metadata.st_ino), []
                    ).append(relative)
            elif kind == "symlink":
                target = os.readlink(path)
                if len(os.fsencode(target)) > limits.max_link_bytes:
                    raise SnapshotError(f"symlink target exceeds limit: {relative}")
                entry["target"] = target
            elif kind in {"character-device", "block-device"}:
                entry["device_major"] = os.major(metadata.st_rdev)
                entry["device_minor"] = os.minor(metadata.st_rdev)
            elif kind == "directory":
                next_directories.append((relative, path))
            entries.append(entry)
        pending.extend(reversed(next_directories))

    hardlink_first: dict[str, str] = {}
    for paths in regular_inodes.values():
        if len(paths) < 2:
            continue
        first = min(paths, key=os.fsencode)
        for path in paths:
            hardlink_first[path] = first
    for entry in entries:
        if entry["kind"] == "regular":
            entry["hardlink_to"] = hardlink_first.get(entry["path"])
    entries.sort(key=lambda item: os.fsencode(item["path"]))
    return entries


def _normalize_relative(value: str) -> str:
    if not value or value.startswith("/") or "\x00" in value:
        raise SnapshotError(f"invalid relative path: {value!r}")
    path = pathlib.PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotError(f"ambiguous relative path: {value!r}")
    return path.as_posix()


def _validated_root(root: pathlib.Path) -> pathlib.Path:
    if not root.is_absolute():
        raise SnapshotError("root must be absolute")
    current = pathlib.Path(root.anchor)
    for component in root.parts[1:]:
        if component in {"", ".", ".."}:
            raise SnapshotError(f"root contains an ambiguous component: {root}")
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SnapshotError(f"cannot stat root component {current}: {error}") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SnapshotError(f"root component must be a real directory: {current}")
    return root


def _read_bounded(path: pathlib.Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return b""
    if not stat.S_ISREG(metadata.st_mode):
        raise SnapshotError(f"database path is not a regular file: {path}")
    if metadata.st_size > maximum:
        raise SnapshotError(f"database file exceeds limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SnapshotError(f"cannot open database file {path}: {error}") from error
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            raise SnapshotError(f"database file changed before reading: {path}")
        data = stream.read(maximum + 1)
        if len(data) != metadata.st_size:
            raise SnapshotError(f"database file changed while reading: {path}")
        return data


def _parse_deb822(data: bytes, source: str) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{source} is not UTF-8: {error}") from error
    paragraphs: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    current: str | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            if fields:
                paragraphs.append(fields)
                fields = {}
                current = None
            continue
        if line[0] in " \t":
            if current is None:
                raise SnapshotError(f"{source}:{line_number}: orphan continuation")
            fields[current] += "\n" + line[1:]
            continue
        name, separator, value = line.partition(":")
        if not separator or not name or any(character.isspace() for character in name):
            raise SnapshotError(f"{source}:{line_number}: malformed field")
        canonical = name.lower()
        if canonical in fields:
            raise SnapshotError(f"{source}:{line_number}: duplicate field {name}")
        fields[canonical] = value.lstrip(" \t")
        current = canonical
    if fields:
        paragraphs.append(fields)
    return sorted(
        paragraphs,
        key=lambda item: (
            item.get("package", ""),
            item.get("architecture", ""),
            item.get("version", ""),
            json.dumps(item, sort_keys=True),
        ),
    )


def _normalize_lines(data: bytes, source: str) -> list[str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{source} is not UTF-8: {error}") from error
    return sorted(line for line in lines if line)


def _normalize_path_list(data: bytes, source: str) -> list[str]:
    lines = _normalize_lines(data, source)
    if any(not line.startswith("/") or "\x00" in line for line in lines):
        raise SnapshotError(f"{source}: package path list contains an unsafe path")
    if len(lines) != len(set(lines)):
        raise SnapshotError(f"{source}: package path list contains a duplicate")
    return lines


def _normalize_md5sums(data: bytes, source: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for line_number, line in enumerate(_normalize_lines(data, source), 1):
        digest, separator, path = line.partition(" ")
        path = path.lstrip()
        if (
            not separator
            or len(digest) != 32
            or any(character not in "0123456789abcdef" for character in digest)
            or not path
            or path.startswith("/")
        ):
            raise SnapshotError(f"{source}:{line_number}: malformed md5sums entry")
        result.append({"path": path, "md5": digest})
    return sorted(result, key=lambda item: os.fsencode(item["path"]))


def _normalize_diversions(data: bytes, source: str) -> list[dict[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{source} is not UTF-8: {error}") from error
    if len(lines) % 3 != 0:
        raise SnapshotError(f"{source}: incomplete diversion record")
    result: list[dict[str, str]] = []
    for index in range(0, len(lines), 3):
        path, diverted_to, package = lines[index : index + 3]
        if (
            not path.startswith("/")
            or not diverted_to.startswith("/")
            or "\x00" in path
            or "\x00" in diverted_to
            or not package
        ):
            raise SnapshotError(f"{source}: malformed diversion record")
        result.append(
            {"path": path, "diverted_to": diverted_to, "package": package}
        )
    result.sort(key=lambda item: os.fsencode(item["path"]))
    if len({item["path"] for item in result}) != len(result):
        raise SnapshotError(f"{source}: duplicate diversion path")
    return result


def _normalize_statoverride(data: bytes, source: str) -> list[dict[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{source} is not UTF-8: {error}") from error
    result: list[dict[str, str]] = []
    for line in lines:
        owner, separator, remainder = line.partition(" ")
        group, separator_group, remainder = remainder.partition(" ")
        mode, separator_mode, path = remainder.partition(" ")
        if (
            not separator
            or not separator_group
            or not separator_mode
            or not owner
            or not group
            or not re.fullmatch(r"[0-7]{3,6}", mode)
            or not path.startswith("/")
            or "\x00" in path
        ):
            raise SnapshotError(f"{source}: malformed statoverride record")
        result.append(
            {"path": path, "owner": owner, "group": group, "mode": mode}
        )
    result.sort(key=lambda item: os.fsencode(item["path"]))
    if len({item["path"] for item in result}) != len(result):
        raise SnapshotError(f"{source}: duplicate statoverride path")
    return result


def _capture_database_directory(
    directory: pathlib.Path,
    relative_prefix: str,
    limits: Limits,
    budget: dict[str, int],
) -> list[dict[str, Any]]:
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SnapshotError(f"database directory is unsafe: {directory}")
    result: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir(), key=lambda item: os.fsencode(item.name)):
        budget["entries"] += 1
        if budget["entries"] > limits.max_entries:
            raise SnapshotError("database entry limit exceeded")
        relative = f"{relative_prefix}/{path.name}"
        if relative.removeprefix("var/lib/dpkg/") in LOCK_FILES:
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError(f"database entry is not a regular file: {path}")
        data = _read_bounded(path, limits.max_database_file_bytes)
        budget["bytes"] += len(data)
        if budget["bytes"] > limits.max_total_regular_bytes:
            raise SnapshotError("aggregate database byte limit exceeded")
        entry: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if path.name.endswith(".list"):
            entry["kind"] = "path-list"
            entry["lines"] = _normalize_path_list(data, relative)
        elif path.name.endswith(".md5sums"):
            entry["kind"] = "md5sums"
            entry["entries"] = _normalize_md5sums(data, relative)
        elif relative_prefix.endswith("/triggers"):
            entry["kind"] = "line-set"
            entry["lines"] = _normalize_lines(data, relative)
        elif relative_prefix.endswith("/updates"):
            entry["kind"] = "deb822"
            entry["paragraphs"] = _parse_deb822(data, relative)
        else:
            entry["kind"] = "opaque"
            entry["size"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
        result.append(entry)
    return result


def capture_dpkg(root: pathlib.Path, limits: Limits) -> dict[str, Any]:
    admin = root / "var/lib/dpkg"
    try:
        admin_metadata = admin.lstat()
    except FileNotFoundError:
        return {
            "present": False,
            "status": [],
            "status_old": [],
            "info": [],
            "triggers": [],
            "updates": [],
            "alternatives": [],
            "parts": [],
            "files": [],
        }
    if not stat.S_ISDIR(admin_metadata.st_mode) or stat.S_ISLNK(
        admin_metadata.st_mode
    ):
        raise SnapshotError("var/lib/dpkg must be a real directory")
    budget = {"entries": 0, "bytes": 0}
    status = _read_bounded(admin / "status", limits.max_database_file_bytes)
    status_old = _read_bounded(admin / "status-old", limits.max_database_file_bytes)
    budget["bytes"] = len(status) + len(status_old)
    if budget["bytes"] > limits.max_total_regular_bytes:
        raise SnapshotError("aggregate database byte limit exceeded")
    known = {
        "status",
        "status-old",
        "info",
        "triggers",
        "updates",
        "alternatives",
        "parts",
        "lock",
        "lock-frontend",
    }
    files: list[dict[str, Any]] = []
    for path in sorted(admin.iterdir(), key=lambda item: os.fsencode(item.name)):
        if path.name in known:
            continue
        budget["entries"] += 1
        if budget["entries"] > limits.max_entries:
            raise SnapshotError("database entry limit exceeded")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError(f"unknown dpkg entry is not a regular file: {path}")
        data = _read_bounded(path, limits.max_database_file_bytes)
        budget["bytes"] += len(data)
        if budget["bytes"] > limits.max_total_regular_bytes:
            raise SnapshotError("aggregate database byte limit exceeded")
        entry: dict[str, Any] = {
            "path": f"var/lib/dpkg/{path.name}",
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if path.name == "available":
            entry["kind"] = "deb822"
            entry["paragraphs"] = _parse_deb822(data, entry["path"])
        elif path.name == "arch":
            entry["kind"] = "line-set"
            entry["lines"] = _normalize_lines(data, entry["path"])
        elif path.name == "diversions":
            entry["kind"] = "diversions"
            entry["records"] = _normalize_diversions(data, entry["path"])
        elif path.name == "statoverride":
            entry["kind"] = "statoverride"
            entry["records"] = _normalize_statoverride(data, entry["path"])
        else:
            entry["kind"] = "opaque"
            entry["size"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
        files.append(entry)
    return {
        "present": True,
        "status": _parse_deb822(status, "var/lib/dpkg/status"),
        "status_old": _parse_deb822(status_old, "var/lib/dpkg/status-old"),
        "info": _capture_database_directory(
            admin / "info", "var/lib/dpkg/info", limits, budget
        ),
        "triggers": _capture_database_directory(
            admin / "triggers", "var/lib/dpkg/triggers", limits, budget
        ),
        "updates": _capture_database_directory(
            admin / "updates", "var/lib/dpkg/updates", limits, budget
        ),
        "alternatives": _capture_database_directory(
            admin / "alternatives", "var/lib/dpkg/alternatives", limits, budget
        ),
        "parts": _capture_database_directory(
            admin / "parts", "var/lib/dpkg/parts", limits, budget
        ),
        "files": files,
    }


def capture_trace(root: pathlib.Path, limits: Limits) -> list[str]:
    data = _read_bounded(root / TRACE_PATH, limits.max_trace_bytes)
    if not data:
        return []
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{TRACE_PATH} is not UTF-8: {error}") from error


def capture(
    root: pathlib.Path,
    limits: Limits = Limits(),
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
) -> dict[str, Any]:
    root = _validated_root(root)
    return {
        "schema": SCHEMA,
        "version": 1,
        "filesystem": capture_tree(root, limits, excludes),
        "dpkg": capture_dpkg(root, limits),
        "trace": capture_trace(root, limits),
    }


def canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def differences(
    reference: Any,
    candidate: Any,
    maximum: int = Limits.max_differences,
) -> list[str]:
    result: list[str] = []

    def visit(left: Any, right: Any, path: str) -> None:
        if len(result) >= maximum:
            return
        if type(left) is not type(right):
            result.append(
                f"{path}: type {type(left).__name__} != {type(right).__name__}"
            )
            return
        if isinstance(left, dict):
            for key in sorted(set(left) | set(right)):
                child = f"{path}.{key}"
                if key not in left:
                    result.append(f"{child}: missing from reference")
                elif key not in right:
                    result.append(f"{child}: missing from candidate")
                else:
                    visit(left[key], right[key], child)
                if len(result) >= maximum:
                    return
            return
        if isinstance(left, list):
            if len(left) != len(right):
                result.append(f"{path}: length {len(left)} != {len(right)}")
            for index, (left_item, right_item) in enumerate(zip(left, right)):
                visit(left_item, right_item, f"{path}[{index}]")
                if len(result) >= maximum:
                    return
            return
        if left != right:
            result.append(f"{path}: {left!r} != {right!r}")

    visit(reference, candidate, "$")
    if len(result) >= maximum:
        result.append(f"$: stopped after {maximum} differences")
    return result


def validate_corpus(document: dict[str, Any]) -> None:
    if document.get("schema") != CORPUS_SCHEMA or document.get("version") != 1:
        raise SnapshotError("unsupported native transaction corpus")
    architectures = document.get("architectures")
    if architectures != ["amd64", "arm64"]:
        raise SnapshotError("corpus architectures must be amd64 then arm64")
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise SnapshotError("corpus must contain scenarios")
    seen: set[str] = set()
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise SnapshotError(f"scenario {index} must be an object")
        if set(scenario) != SCENARIO_KEYS:
            raise SnapshotError(f"scenario {index} has an unsupported shape")
        identifier = scenario.get("id")
        if (
            not isinstance(identifier, str)
            or not IDENTITY_PATTERN.fullmatch(identifier)
            or identifier in seen
        ):
            raise SnapshotError(f"scenario {index} has invalid or duplicate id")
        seen.add(identifier)
        if scenario.get("initial") not in SCENARIO_INITIAL_STATES:
            raise SnapshotError(f"scenario {identifier} has invalid initial state")
        operations = scenario.get("operations")
        if (
            not isinstance(operations, list)
            or not operations
            or any(operation not in SCENARIO_OPERATIONS for operation in operations)
        ):
            raise SnapshotError(f"scenario {identifier} has invalid operations")
        features = scenario.get("features")
        if (
            not isinstance(features, list)
            or not features
            or any(
                not isinstance(feature, str)
                or not IDENTITY_PATTERN.fullmatch(feature)
                for feature in features
            )
            or len(set(features)) != len(features)
        ):
            raise SnapshotError(f"scenario {identifier} has invalid features")
        if scenario.get("expected") not in SCENARIO_EXPECTATIONS:
            raise SnapshotError(f"scenario {identifier} has invalid expectation")


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("limit must be positive")
    return parsed


def _limits(arguments: argparse.Namespace) -> Limits:
    return Limits(
        max_entries=arguments.max_entries,
        max_total_regular_bytes=arguments.max_total_bytes,
        max_file_bytes=arguments.max_file_bytes,
        max_database_file_bytes=arguments.max_database_file_bytes,
        max_trace_bytes=arguments.max_trace_bytes,
        max_differences=getattr(
            arguments, "max_differences", Limits.max_differences
        ),
    )


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SnapshotError(f"{path} must contain a JSON object")
    return value


def _add_limit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-entries", type=_positive, default=Limits.max_entries)
    parser.add_argument(
        "--max-total-bytes", type=_positive, default=Limits.max_total_regular_bytes
    )
    parser.add_argument(
        "--max-file-bytes", type=_positive, default=Limits.max_file_bytes
    )
    parser.add_argument(
        "--max-database-file-bytes",
        type=_positive,
        default=Limits.max_database_file_bytes,
    )
    parser.add_argument(
        "--max-trace-bytes", type=_positive, default=Limits.max_trace_bytes
    )


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture", help="capture one install root")
    capture_parser.add_argument("--root", type=pathlib.Path, required=True)
    capture_parser.add_argument("--output", type=pathlib.Path, required=True)
    capture_parser.add_argument("--exclude", action="append", default=[])
    _add_limit_arguments(capture_parser)

    compare_parser = commands.add_parser(
        "compare", help="compare canonical reference and candidate snapshots"
    )
    compare_parser.add_argument("--reference", type=pathlib.Path, required=True)
    compare_parser.add_argument("--candidate", type=pathlib.Path, required=True)
    compare_parser.add_argument(
        "--max-differences", type=_positive, default=Limits.max_differences
    )

    corpus_parser = commands.add_parser(
        "validate-corpus", help="validate the versioned scenario contract"
    )
    corpus_parser.add_argument("--corpus", type=pathlib.Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        if arguments.command == "capture":
            excludes = DEFAULT_EXCLUDES + tuple(arguments.exclude)
            snapshot = capture(arguments.root, _limits(arguments), excludes)
            arguments.output.write_text(canonical_json(snapshot))
            return 0
        if arguments.command == "compare":
            reference = _load_json(arguments.reference)
            candidate = _load_json(arguments.candidate)
            if (
                reference.get("schema") != SCHEMA
                or candidate.get("schema") != SCHEMA
            ):
                raise SnapshotError("unsupported differential snapshot")
            found = differences(
                reference, candidate, maximum=arguments.max_differences
            )
            if found:
                print("\n".join(found), file=sys.stderr)
                return 1
            return 0
        if arguments.command == "validate-corpus":
            validate_corpus(_load_json(arguments.corpus))
            return 0
    except (OSError, json.JSONDecodeError, SnapshotError) as error:
        print(f"native-differential: {error}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command {arguments.command}")


if __name__ == "__main__":
    raise SystemExit(main())
