"""Shared no-follow writes for disposable signed reference fixtures."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat

from real_snapshot_reference_paths import open_absolute, open_beneath, protected


@contextmanager
def parent_descriptor(root: Path, relative: str):
    parent, separator, name = relative.rpartition("/")
    if name in ("", ".", "..") or relative.startswith("/"):
        raise ValueError("invalid fixture mutation path")
    root_fd = open_absolute(root, directory=True)
    try:
        parent_fd = open_beneath(root_fd, parent, directory=True) if separator else os.dup(root_fd)
        try:
            yield parent_fd, name
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


def regular_metadata(descriptor: int) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
            metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid()):
        raise ValueError("fixture mutation requires an owned single-link regular file")
    return metadata


@contextmanager
def regular_descriptor(root: Path, relative: str):
    with parent_descriptor(root, relative) as (parent, name):
        descriptor = os.open(
            name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            regular_metadata(descriptor)
            yield descriptor
        finally:
            os.close(descriptor)


def replace_contents(descriptor: int, contents: bytes) -> None:
    regular_metadata(descriptor)
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "wb") as output:
        output.write(contents)


def overwrite_regular(root: Path, relative: str, contents: bytes) -> None:
    with regular_descriptor(root, relative) as descriptor:
        replace_contents(descriptor, contents)


def create_exclusive(root: Path, relative: str, contents: bytes, mode: int) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode, dir_fd=parent,
        )
        try:
            regular_metadata(descriptor)
            with os.fdopen(os.dup(descriptor), "wb") as output:
                output.write(contents)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)


def read_regular(root: Path, relative: str, maximum: int = 8 * 1024 * 1024) -> bytes:
    with regular_descriptor(root, relative) as descriptor:
        metadata = regular_metadata(descriptor)
        if metadata.st_size > maximum:
            raise ValueError("fixture source exceeds its byte limit")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            content = stream.read(maximum + 1)
        if len(content) != metadata.st_size:
            raise ValueError("fixture source bytes changed")
        return content


def chmod_regular(root: Path, relative: str, mode: int) -> None:
    with regular_descriptor(root, relative) as descriptor:
        os.fchmod(descriptor, mode)


def directory(root: Path, relative: str, mode: int = 0o755, *, exclusive: bool = False) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        created = False
        try:
            os.mkdir(name, mode, dir_fd=parent)
            created = True
        except FileExistsError:
            if exclusive:
                raise
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid():
                raise ValueError("unsafe fixture directory owner")
            if created:
                os.fchmod(descriptor, mode)
            elif stat.S_IMODE(metadata.st_mode) != mode:
                raise ValueError("unsafe existing fixture directory mode")
        finally:
            os.close(descriptor)


def replace_symlink(root: Path, relative: str, expected: str, target: str) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1 or
                metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid() or
                os.readlink(name, dir_fd=parent) != expected):
            raise ValueError("unexpected fixture alias")
        os.unlink(name, dir_fd=parent)
        os.symlink(target, name, dir_fd=parent)


def copy_exclusive(root: Path, relative: str, source: Path, mode: int) -> None:
    protected(source)
    descriptor = open_absolute(source)
    try:
        metadata = regular_metadata(descriptor)
        if metadata.st_size > 8 * 1024 * 1024:
            raise ValueError("fixture staging source exceeds its byte limit")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            contents = stream.read(metadata.st_size + 1)
        if len(contents) != metadata.st_size:
            raise ValueError("protected fixture source changed")
    finally:
        os.close(descriptor)
    create_exclusive(root, relative, contents, mode)


def mutate_negative_roots(roots: list[Path]) -> None:
    if len(roots) != 5:
        raise ValueError("five distinct negative roots are required")
    for root in roots:
        metadata = protected(root, directory=True)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("fixture root must be protected mode 0700")
    bad_script, bad_mode, bad_tool, bad_alias, bad_prestate = roots
    with regular_descriptor(bad_script, "var/lib/dpkg/info/less.preinst") as descriptor:
        contents = os.read(descriptor, 1024)
        if len(contents) != 292 or b"exit 0" not in contents:
            raise ValueError("unexpected signed-less preinst fixture")
        replace_contents(descriptor, contents.replace(b"exit 0", b"exit 1"))
    with regular_descriptor(bad_mode, "var/lib/dpkg/info/less.preinst") as descriptor:
        os.fchmod(descriptor, 0o644)
    overwrite_regular(bad_tool, "usr/bin/update-alternatives", b"foreign alternatives tool\n")
    with parent_descriptor(bad_alias, "usr/bin/sh") as (parent, name):
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1 or
                metadata.st_uid != 0 or metadata.st_gid != 0 or
                os.readlink(name, dir_fd=parent) != "dash"):
            raise ValueError("unexpected signed-less shell alias")
        os.unlink(name, dir_fd=parent)
        os.symlink("foreign-sh", name, dir_fd=parent)
    create_exclusive(bad_prestate, "etc/ld.so.cache", b"unbound loader cache\n", 0o644)


def stage_dpkg_reference(root: Path, pinned: Path, archive: Path, *,
                         archive_relative: str = "var/lib/dpkg/less-probe.deb") -> None:
    protected(root, directory=True)
    directory(root, "usr/local")
    directory(root, "usr/local/sbin")
    for source, relative, mode in (
        (pinned, "usr/local/sbin/dpkg", 0o755),
        (archive, archive_relative, 0o644),
    ):
        copy_exclusive(root, relative, source, mode)
