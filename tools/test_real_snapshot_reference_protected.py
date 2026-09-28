#!/usr/bin/env python3
"""Require real root-owned pinned-dpkg namespace operations, never fixture skips."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

from real_snapshot_reference_paths import protected, read_root_file

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_reference_order", ROOT / "tools/real-snapshot-reference-order.py"
)
assert SPEC and SPEC.loader
ORDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ORDER
SPEC.loader.exec_module(ORDER)


def protected_directory(path: Path, *, empty: bool = False) -> None:
    metadata = protected(path, directory=True)
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError(f"protected proof directory must be root-only 0700: {path}")
    if empty and any(path.iterdir()):
        raise ValueError(f"protected proof workspace must be new and empty: {path}")


def assert_teardown(root: Path) -> None:
    identity = (root.stat().st_dev, root.stat().st_ino)
    for attempt in range(20):
        surviving: list[int] = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                current = (entry / "root").stat()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if (current.st_dev, current.st_ino) == identity:
                surviving.append(int(entry.name))
        if not surviving:
            break
        if attempt == 19:
            raise AssertionError(f"processes retain reference root {root}: {surviving}")
        time.sleep(0.1)
    with Path("/proc/self/mountinfo").open(encoding="utf-8") as stream:
        for line in stream:
            mountpoint = line.split(" ", 5)[4].replace(r"\040", " ").replace(r"\011", "\t")
            if mountpoint == str(root) or mountpoint.startswith(str(root) + "/"):
                raise AssertionError(f"reference mount survived under {root}: {mountpoint}")


def fresh_root(template: Path, workspace: Path, name: str) -> Path:
    destination = workspace / f"{name}-root"

    def copy_member(source: str, target: str) -> str:
        info = os.lstat(source)
        if (Path(source).relative_to(template) == Path("dev/null") and
            stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)):
            os.mknod(target, stat.S_IMODE(info.st_mode) | stat.S_IFCHR, info.st_rdev)
            return target
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"unsupported protected template member: {source}")
        return shutil.copy2(source, target)

    shutil.copytree(template, destination, symlinks=True, copy_function=copy_member)
    destination.chmod(0o700)
    protected_directory(destination)
    if read_root_file(destination, "var/lib/dpkg/status", 4 * 1024 * 1024):
        raise ValueError(f"proof template is not an empty dpkg root: {template}")
    if any((destination / "proc").iterdir()):
        raise ValueError(f"proof template proc mountpoint is not empty: {template}")
    return destination


def operation(
    workspace: Path, name: str, launcher: Path, dpkg: Path, root: Path,
    architecture: str, archive: Path, digest: str, size: int, verb: str,
    *, readable_output: bool = False, inherited_fd: int | None = None,
) -> tuple[int, str]:
    stdout_path = workspace / f"{name}.stdout"
    stderr_path = workspace / f"{name}.stderr"
    stdout_mode = "a+b" if readable_output else "ab"
    with stdout_path.open(stdout_mode) as stdout, stderr_path.open("ab") as stderr:
        command = [
            str(launcher), str(root), str(dpkg), architecture, "none", verb,
            "debz-reference-proof:" + architecture, str(archive), digest, str(size),
        ]
        try:
            result = subprocess.run(
                command, env=ORDER.oracle_environment(), stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, timeout=45,
                pass_fds=() if inherited_fd is None else (inherited_fd,),
                check=False,
            )
            status = result.returncode
        except subprocess.TimeoutExpired:
            status = -1
    assert_teardown(root)
    error = stderr_path.read_text(errors="replace")
    (workspace / f"{name}.json").write_text(json.dumps({
        "argv": command, "exit_status": status, "stderr": error,
    }, indent=2) + "\n")
    return status, error


def require(status: int, error: str, expected: str, name: str) -> None:
    if status == 0 or expected not in error:
        raise AssertionError(
            f"{name}: expected nonzero exit with {expected!r}; "
            f"observed exit={status}, stderr={error!r}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--dpkg", type=Path, required=True)
    parser.add_argument("--root-template", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha512", required=True)
    parser.add_argument("--archive-size", type=int, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.getegid() != 0:
        raise PermissionError("protected reference proof requires UID/GID 0")
    if not all(path.is_absolute() for path in (
        args.launcher, args.dpkg, args.root_template, args.workspace, args.archive,
    )):
        raise ValueError("protected proof inputs must be absolute paths")
    protected(Path(__file__).resolve())
    for path in (args.launcher, args.dpkg, args.archive):
        protected(path)
    protected_directory(args.root_template)
    protected_directory(args.workspace, empty=True)
    proc = protected(args.root_template / "proc", directory=True)
    mountpoint = protected(args.root_template / ".debz-reference-archive")
    if stat.S_IMODE(proc.st_mode) != 0o755 or (
        stat.S_IMODE(mountpoint.st_mode) != 0o600 or mountpoint.st_nlink != 1 or
        mountpoint.st_size != 0 or mountpoint.st_dev != args.root_template.stat().st_dev
    ):
        raise ValueError("protected proof template has invalid proc/archive mountpoints")
    if not re.fullmatch("[a-f0-9]{128}", args.archive_sha512):
        raise ValueError("archive SHA512 must come from the authenticated lock")
    if not 0 < args.archive_size <= 512 * 1024 * 1024:
        raise ValueError("invalid authenticated archive size")
    if args.archive.stat().st_size != args.archive_size:
        raise ValueError("authenticated archive size differs")
    archive_hash = hashlib.sha512()
    with args.archive.open("rb") as source:
        while block := source.read(1024 * 1024):
            archive_hash.update(block)
    if archive_hash.hexdigest() != args.archive_sha512:
        raise ValueError("authenticated archive SHA512 differs")
    identity = hashlib.sha256(args.dpkg.read_bytes()).hexdigest()
    pinned = {
        "amd64": "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
        "arm64": "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
    }
    if identity != pinned[args.architecture]:
        raise ValueError("reference dpkg executable is not the pinned architecture artifact")
    for name, verb in (("probe", "probe_unpack"), ("unpack", "unpack")):
        root = fresh_root(args.root_template, args.workspace, name)
        parent_fd = os.open(args.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            status, error = operation(
                args.workspace, name, args.launcher, args.dpkg, root,
                args.architecture, args.archive, args.archive_sha512,
                args.archive_size, verb, inherited_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
        if status != 0:
            raise AssertionError(f"{name}: pinned dpkg refused {status}: {error}")
        if name == "unpack" and not ORDER.database_packages(root):
            raise AssertionError("pinned dpkg reported success without an installed database entry")

    changed_size = args.archive_size + 1 if args.archive_size < 512 * 1024 * 1024 else args.archive_size - 1
    for name, digest, size, expected in (
        ("wrong-digest", "0" * 128 if args.archive_sha512 != "0" * 128 else "1" * 128,
         args.archive_size, "SourceChanged"),
        ("wrong-size", args.archive_sha512, changed_size, "InvalidSourceFile"),
    ):
        root = fresh_root(args.root_template, args.workspace, name)
        status, error = operation(
            args.workspace, name, args.launcher, args.dpkg, root,
            args.architecture, args.archive, digest, size, "unpack",
        )
        require(status, error, expected, name)
        if read_root_file(root, "var/lib/dpkg/status", 4 * 1024 * 1024):
            raise AssertionError(f"{name}: root database changed after refusal")

    root = fresh_root(args.root_template, args.workspace, "bad-output")
    status, error = operation(
        args.workspace, "bad-output", args.launcher, args.dpkg, root,
        args.architecture, args.archive, args.archive_sha512,
        args.archive_size, "unpack", readable_output=True,
    )
    require(status, error, "InvalidStandardStream", "bad-output")

    root = fresh_root(args.root_template, args.workspace, "symlink")
    link = args.workspace / "symlink-to-root"
    link.symlink_to(root)
    status, error = operation(
        args.workspace, "symlink", args.launcher, args.dpkg, link,
        args.architecture, args.archive, args.archive_sha512, args.archive_size, "unpack",
    )
    require(status, error, "ReferenceSetupFailed", "symlink")

    root = fresh_root(args.root_template, args.workspace, "symlink-archive")
    archive_link = args.workspace / "symlink-to-archive"
    archive_link.symlink_to(args.archive)
    status, error = operation(
        args.workspace, "symlink-archive", args.launcher, args.dpkg, root,
        args.architecture, archive_link, args.archive_sha512,
        args.archive_size, "unpack",
    )
    require(status, error, "ReferenceSetupFailed", "symlink-archive")

    parent = args.workspace / "writable-parent"
    parent.mkdir(mode=0o700)
    root = fresh_root(args.root_template, parent, "writable")
    parent.chmod(0o777)
    try:
        status, error = operation(
            args.workspace, "writable", args.launcher, args.dpkg, root,
            args.architecture, args.archive, args.archive_sha512,
            args.archive_size, "unpack",
        )
        require(status, error, "UnprotectedPath", "writable")
    finally:
        parent.chmod(0o700)
    print("protected pinned-dpkg probe/unpack and six refusals: executed without skips")


if __name__ == "__main__":
    main()
