"""Descriptor-rooted, no-follow inputs for the privileged snapshot reference."""

from __future__ import annotations

import os
from pathlib import Path
import stat


def open_beneath(root_fd: int, relative: str, *, directory: bool = False) -> int:
    parts = relative.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"noncanonical reference path: {relative!r}")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        result = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
            (os.O_DIRECTORY if directory else 0),
            dir_fd=current,
        )
        return result
    finally:
        os.close(current)


def open_absolute(path: Path, *, directory: bool = False) -> int:
    if not path.is_absolute() or any(
        part in ("", ".", "..") for part in str(path).split("/")[1:]
    ):
        raise ValueError(f"noncanonical absolute reference path: {path}")
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if str(path) == "/" and directory:
            return os.dup(root_fd)
        return open_beneath(root_fd, str(path)[1:], directory=directory)
    finally:
        os.close(root_fd)


def protected(path: Path, *, directory: bool = False) -> os.stat_result:
    if not path.is_absolute():
        raise ValueError(f"reference path is not absolute: {path}")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(str(path).split("/")[1:]):
            if part in ("", ".", ".."):
                raise ValueError(f"noncanonical protected path: {path}")
            last = index == len(path.parts) - 2
            next_fd = os.open(
                part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                (os.O_DIRECTORY if not last or directory else 0),
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
            meta = os.fstat(current)
            if (meta.st_uid != 0 or meta.st_gid != 0 or
                stat.S_IMODE(meta.st_mode) & 0o022 or
                (not last and not stat.S_ISDIR(meta.st_mode))):
                raise ValueError(f"reference path has writable or non-root ancestor: {path}")
        result = os.fstat(current)
        if ((directory and not stat.S_ISDIR(result.st_mode)) or
            (not directory and not stat.S_ISREG(result.st_mode))):
            raise ValueError(f"reference path has the wrong file type: {path}")
        return result
    finally:
        os.close(current)


def read_root_file(root: Path, relative: str, limit: int) -> bytes:
    if limit < 0:
        raise ValueError("invalid bounded reference read")
    root_fd = open_absolute(root, directory=True)
    try:
        fd = open_beneath(root_fd, relative)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
                raise ValueError(f"invalid reference database file: {relative}")
            data = b""
            while len(data) <= limit:
                block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data += block
            if len(data) != meta.st_size:
                raise ValueError(f"reference file changed while reading: {relative}")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
