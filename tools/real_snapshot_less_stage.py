"""Descriptor-rooted setup of a fresh signed arm64 less replay source."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).parent))
from real_snapshot_less_fixtures import (
    create_exclusive, parent_descriptor, regular_descriptor,
)
from real_snapshot_reference_paths import open_absolute, protected

SOURCE_ARTIFACTS = {
    "less": ("668-1build1", 171138, "f3d538070be0217eec1c5e747f0b6ed05b08b22a006001dafac6c87747ab46e9055fb8bf1985aed2d4010f57d597108dbff22ed73f92959703fffa57ec84e0e8"),
    "dash": ("0.5.12-12ubuntu3", 95716, "c4a44690b1541936c4c85956f8e5bef0c915ce05afe6618230b70f4906803f8710b314b9093b451787b995bcd7b25a3947f51c8efa03dbda16c7eac720f93c6e"),
    "dpkg": ("1.23.7ubuntu1", 1260980, "824a6a3f33837c16dedb4faff92bd15b0dbe82d27dd9b25403f87ec4572acc6332159a6374558185ca503e18de6f637d2a79e7db9fafaab3ccae4ac77427eee5"),
    "libc6": ("2.43-2ubuntu2.4", 1642036, "865127bc2d7d9218e2a3482b7e0b5ae3649c31bcac82d0437a7231c798f56a1939f0f18fc664111a7c446eef6f9864176c040ad78b7aac1a6a3afe4d4b9cbeb7"),
}


def directory(root: Path, relative: str, mode: int = 0o755) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        created = False
        try:
            os.mkdir(name, mode, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid():
                raise ValueError("unsafe source setup directory")
            if created:
                os.fchmod(descriptor, mode)
            elif stat.S_IMODE(metadata.st_mode) != mode:
                raise ValueError("unsafe existing source setup directory mode")
        finally:
            os.close(descriptor)


def alias(root: Path, relative: str, target: str) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        os.symlink(target, name, dir_fd=parent)


def remove_lib64(root: Path) -> None:
    descriptor = open_absolute(root, directory=True)
    try:
        metadata = os.stat("lib64", dir_fd=descriptor, follow_symlinks=False)
        if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1 or
                metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid() or
                os.readlink("lib64", dir_fd=descriptor) != "usr/lib64"):
            raise ValueError("unexpected fresh template lib64 alias")
        os.unlink("lib64", dir_fd=descriptor)
    finally:
        os.close(descriptor)


def archive(lock: dict, cache: Path, package: str) -> Path:
    entries = [entry for entry in lock["packages"]
               if entry["name"] == package and entry["architecture"] == "arm64"]
    if len(entries) != 1:
        raise ValueError(f"ambiguous signed source archive: {package}")
    entry = entries[0]
    identity = entry["archive_identity"]
    digests = [item["digest"] for item in identity["digests"]
               if item["algorithm"] == "sha512"]
    if (entry["origin"]["type"] != "authenticated_repository" or
            identity["primary"] != "sha512" or len(digests) != 1):
        raise ValueError("unauthenticated source archive")
    if package in SOURCE_ARTIFACTS and (
            entry["version"], entry["declared_size"], digests[0]) != SOURCE_ARTIFACTS[package]:
        raise ValueError("source archive differs from exact production authority")
    path = cache / f"sha512-{digests[0]}"
    protected(path)
    descriptor = open_absolute(path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_nlink != 1 or metadata.st_size != entry["declared_size"]:
            raise ValueError("source archive metadata changed")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            digest = hashlib.file_digest(stream, "sha512").hexdigest()
        if digest != digests[0]:
            raise ValueError("source archive bytes changed")
    finally:
        os.close(descriptor)
    return path


def member(archive_path: Path, name: str) -> bytes:
    parent = open_absolute(archive_path.parent, directory=True)
    try:
        descriptor = os.open(
            archive_path.name + ".less-source.tar",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent,
        )
    finally:
        os.close(parent)
    with os.fdopen(descriptor, "w+b") as capture:
        subprocess.run(
            ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(archive_path)],
            check=True, stdout=capture, timeout=60,
            preexec_fn=limit_capture,
        )
        if os.fstat(capture.fileno()).st_size > 64 * 1024 * 1024:
            raise ValueError("signed source data archive exceeds bound")
        capture.seek(0)
        payload = capture.read(64 * 1024 * 1024 + 1)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as data:
        entries = [entry for entry in data if entry.name.removeprefix("./") == name]
        if (len(entries) != 1 or not entries[0].isfile() or
                entries[0].uid != 0 or entries[0].gid != 0 or
                entries[0].size > 2 * 1024 * 1024):
            raise ValueError("unexpected signed runtime member")
        stream = data.extractfile(entries[0])
        if stream is None:
            raise ValueError("missing signed runtime bytes")
        content = stream.read(entries[0].size + 1)
        if len(content) != entries[0].size:
            raise ValueError("short signed runtime member")
        return content


def limit_capture() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))


def prepare(root: Path, lock_path: Path, cache: Path, pinned: Path,
            *additional_locks: Path) -> None:
    if len(additional_locks) not in (0, 3):
        raise ValueError("separate less, dash and util-linux locks must be provided together")
    for path in (lock_path, *additional_locks, pinned, Path("/usr/bin/dpkg-deb")):
        protected(path)
    protected(root, directory=True)
    goals = ("dpkg", "less", "dash", "util-linux")
    paths = (lock_path, *additional_locks) if additional_locks else (lock_path,) * len(goals)
    locks = {}
    for goal, path in zip(goals, paths):
        lock = json.loads(path.read_bytes())
        if lock["target_architecture"] != "arm64":
            raise ValueError(f"source target must be arm64: {path}")
        locks[goal] = lock
    for package in SOURCE_ARTIFACTS:
        archive(locks["dpkg" if package == "libc6" else package], cache, package)
    remove_lib64(root)
    for path in ("etc", "etc/alternatives", "var/lib/dpkg/alternatives",
                 "var/lib/debz-lifecycle-scripts"):
        directory(root, path)
    for package, path, mode in (
        ("dash", "usr/bin/dash", 0o755),
        ("dpkg", "usr/bin/update-alternatives", 0o755),
        ("util-linux", "usr/bin/setpriv", 0o755),
        ("libcap-ng0", "usr/lib/aarch64-linux-gnu/libcap-ng.so.0.0.0", 0o644),
    ):
        lock = locks["util-linux" if package == "libcap-ng0" else package]
        create_exclusive(root, path, member(archive(lock, cache, package), path), mode)
    alias(root, "usr/bin/sh", "dash")
    alias(root, "usr/lib/aarch64-linux-gnu/libcap-ng.so.0", "libcap-ng.so.0.0.0")
    create_exclusive(root, "var/lib/dpkg/producer-dpkg", pinned.read_bytes(), 0o755)
    less = archive(locks["less"], cache, "less")
    create_exclusive(root, "var/lib/dpkg/producer-less.deb", less.read_bytes(), 0o644)


def seal(root: Path) -> None:
    with regular_descriptor(root, "var/lib/dpkg/info/less.list") as descriptor:
        content = os.read(descriptor, 2048)
    if (len(content) != 583 or hashlib.sha256(content).hexdigest() !=
            "0206e202ee08fa90d694df6ee0a0f438258ce7f442ff3bc8db4ead65514c62ae"):
        raise ValueError("signed less ownership path set changed")
    with regular_descriptor(root, "var/lib/dpkg/info/less.preinst") as descriptor:
        script = os.read(descriptor, 1024)
    if (len(script) != 292 or hashlib.sha256(script).hexdigest() !=
            "c72b2f152d56cae58b8f39efe22e6f0d85d676c4ac3060f40cfe0c463f1f8d94"):
        raise ValueError("signed less preinst changed")
    create_exclusive(root, "var/lib/debz-lifecycle-scripts/less.preinst", script, 0o755)


if __name__ == "__main__":
    if os.geteuid() != 0 or os.getegid() != 0:
        raise SystemExit("protected less source setup requires root")
    if sys.argv[1] == "prepare":
        prepare(*(Path(argument) for argument in sys.argv[2:]))
    elif sys.argv[1] == "seal":
        seal(Path(sys.argv[2]))
    else:
        raise SystemExit("unknown source setup stage")
