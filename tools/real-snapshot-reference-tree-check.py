#!/usr/bin/env python3
"""Fail-closed ownership and mode checks for the protected reference CI tree.

`ancestry TREE` requires every ancestor to be a root-owned directory without
group/other write and TREE itself to be root-only mode 0700. `tree TREE`
requires every entry beneath TREE to be root-owned and, apart from symlinks,
the template's sticky directories and root-owned /dev/null nodes, not
group/other writable. `packages DIR OUTPUT` verifies Zig's fetched package
sources after staging tightened their modes, then writes a mode and SHA256
manifest: they are compiled as sources and never executed, so executable bits
are recorded rather than trusted.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys

WRITABLE = stat.S_IWGRP | stat.S_IWOTH
SPECIAL = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


def describe(path: str, meta: os.stat_result) -> str:
    return f"{stat.filemode(meta.st_mode)} {meta.st_uid}:{meta.st_gid} {path}"


def ancestry(tree: str) -> list[str]:
    if not os.path.isabs(tree) or os.path.normpath(tree) != tree or tree == "/":
        return [f"tree path is not canonical and absolute: {tree}"]
    failures = []
    current = tree
    while True:
        meta = os.lstat(current)
        print(describe(current, meta))
        if meta.st_uid or meta.st_gid or not stat.S_ISDIR(meta.st_mode) or meta.st_mode & WRITABLE:
            failures.append(f"unprotected ancestor: {describe(current, meta)}")
        if current == tree and stat.S_IMODE(meta.st_mode) != 0o700:
            failures.append(f"protected tree must be mode 0700: {describe(current, meta)}")
        if current == "/":
            return failures
        current = os.path.dirname(current)


def raise_error(error: OSError) -> None:
    raise error


def walk(tree: str):
    for root, directories, files in os.walk(tree, onerror=raise_error):
        for name in directories + files:
            path = os.path.join(root, name)
            yield path, os.lstat(path)


def tree_failures(tree: str) -> list[str]:
    failures = []
    entries = exceptions = 0
    device = os.lstat(tree).st_dev
    for path, meta in walk(tree):
        entries += 1
        if meta.st_dev != device:
            failures.append(f"mount beneath protected tree: {path}")
        if meta.st_uid or meta.st_gid:
            failures.append(f"non-root entry: {describe(path, meta)}")
        elif stat.S_ISLNK(meta.st_mode) or not meta.st_mode & WRITABLE:
            continue
        elif stat.S_ISDIR(meta.st_mode) and meta.st_mode & stat.S_ISVTX:
            exceptions += 1
            print(f"sticky-directory {describe(path, meta)}")
        elif stat.S_ISCHR(meta.st_mode) and meta.st_rdev == os.makedev(1, 3):
            exceptions += 1
            print(f"null-device {describe(path, meta)}")
        else:
            failures.append(f"group/other-writable entry: {describe(path, meta)}")
    print(f"tree={tree} entries={entries} audited_exceptions={exceptions} failures={len(failures)}")
    return failures


def package_failures(directory: str, output: str) -> list[str]:
    failures = []
    lines = []
    executables = 0
    base = os.path.realpath(directory)
    if base != directory:
        return [f"package directory is not canonical: {directory}"]
    for path, meta in sorted(walk(directory)):
        relative = os.path.relpath(path, directory)
        mode = stat.S_IMODE(meta.st_mode)
        if meta.st_uid or meta.st_gid or (
            not stat.S_ISLNK(meta.st_mode) and meta.st_mode & (WRITABLE | SPECIAL)
        ):
            failures.append(f"untightened package entry: {describe(path, meta)}")
        if stat.S_ISLNK(meta.st_mode):
            target = os.readlink(path)
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            if os.path.isabs(target) or os.path.commonpath((resolved, base)) != base:
                failures.append(f"package symlink escapes its tree: {path} -> {target}")
            lines.append(f"link {target} {relative}")
        elif stat.S_ISREG(meta.st_mode):
            digest = hashlib.sha256()
            with open(path, "rb", opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW)) as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)
            executables += bool(mode & 0o111)
            lines.append(f"{mode:04o} {digest.hexdigest()} {relative}")
        elif stat.S_ISDIR(meta.st_mode):
            lines.append(f"{mode:04o} directory {relative}")
        else:
            failures.append(f"unexpected package file type: {describe(path, meta)}")
    if not lines:
        failures.append(f"no fetched packages beneath {directory}")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "w") as manifest:
        manifest.write("\n".join(lines) + "\n")
    print(f"packages={directory} entries={len(lines)} executable_sources={executables} failures={len(failures)}")
    return failures


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "ancestry":
        failures = ancestry(argv[1])
    elif len(argv) == 2 and argv[0] == "tree":
        failures = ancestry(argv[1]) + tree_failures(argv[1])
    elif len(argv) == 3 and argv[0] == "packages":
        failures = package_failures(argv[1], argv[2])
    else:
        print("usage: real-snapshot-reference-tree-check.py ancestry|tree TREE | packages DIR OUTPUT",
              file=sys.stderr)
        return 2
    for failure in failures[:50]:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
