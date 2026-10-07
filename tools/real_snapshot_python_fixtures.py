"""Python-specific fixture setup using the shared reviewed no-follow writes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import selectors
from contextlib import ExitStack

from real_snapshot_less_fixtures import (
    chmod_regular, create_exclusive, directory, overwrite_regular,
    parent_descriptor, read_regular, regular_descriptor, regular_metadata, replace_contents,
    replace_symlink, stage_dpkg_reference,
)
from real_snapshot_reference_paths import open_absolute, open_beneath, protected


def prepare_empty(root: Path) -> None:
    for path in (root, root / "dev", root / "proc"):
        protected(path, directory=True)
    proc = open_absolute(root / "proc", directory=True)
    try:
        if os.listdir(proc):
            raise ValueError("captured source proc must be empty")
    finally:
        os.close(proc)
    with parent_descriptor(root, "dev/null") as (parent, name):
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISCHR(metadata.st_mode) or metadata.st_rdev != os.makedev(1, 3) or
                metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid() or
                metadata.st_nlink != 1):
            raise ValueError("fresh captured source must have the reference null device")
        os.unlink(name, dir_fd=parent)
    create_exclusive(root, "dev/null", b"", 0o600)
    for name, size, digest in (
        ("python3", 918, "383196acd094063e8e49dc4511deb7094e264a41d872bb889d21b197a550f628"),
        ("python3-minimal", 781, "82003099685ad735bdf486d434276cdb0b82b88f269330f87504a5739008f519"),
    ):
        relative = f"var/lib/dpkg/info/{name}.list"
        content = b"".join(sorted(read_regular(root, relative, 2048).splitlines(keepends=True)))
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError(f"signed Python list path set changed: {name}")
        overwrite_regular(root, relative, content)


def preflight(root: Path) -> None:
    descriptor = open_absolute(root, directory=True)
    try:
        for relative in ("dev", "proc", "usr/bin", "usr/sbin", "var/lib/dpkg/info",
                         "usr/share/doc/python3", "tmp"):
            opened = open_beneath(descriptor, relative, directory=True)
            os.close(opened)
        # These optional directories may be created later, but existing aliases
        # are rejected before cloning, not followed to stage a host executable.
        for relative in ("usr/local", "usr/local/sbin"):
            try:
                opened = open_beneath(descriptor, relative, directory=True)
            except FileNotFoundError:
                continue
            os.close(opened)
    finally:
        os.close(descriptor)
    for relative in ("dev/null", "var/lib/dpkg/info/python3.preinst",
                     "var/lib/dpkg/info/python3-minimal.postinst", "usr/bin/py3compile"):
        read_regular(root, relative)


def basic_negatives(roots: list[Path]) -> None:
    if len(roots) != 8:
        raise ValueError("eight Python negative roots required")
    html, link, shadow, null, null_0640, bad_root, script, proc = roots
    directory(html, "usr/share/doc/python3/html", exclusive=True)
    replace_symlink(link, "usr/bin/python3", "python3.14", "python3.invalid")
    create_exclusive(shadow, "usr/sbin/update-alternatives", b"shadow\n", 0o644)
    chmod_regular(null, "dev/null", 0o666)
    chmod_regular(null_0640, "dev/null", 0o640)
    descriptor = open_absolute(bad_root, directory=True)
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid() or
                stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ValueError("unexpected Python negative root metadata")
        os.fchmod(descriptor, 0o755)
    finally:
        os.close(descriptor)
    overwrite_regular(script, "var/lib/dpkg/info/python3.preinst", b"stale script\n")
    create_exclusive(proc, "proc/unexpected", b"unexpected\n", 0o644)


def strict_negatives(roots: list[Path]) -> None:
    if len(roots) != 4:
        raise ValueError("four strict Python negative roots required")
    bad_hash, bad_mode, postinst, compiler = roots
    overwrite_regular(bad_hash, "dev/null", b"/usr/bin/py3compile ")
    chmod_regular(bad_mode, "dev/null", 0o600)
    with regular_descriptor(postinst, "var/lib/dpkg/info/python3-minimal.postinst") as descriptor:
        content = os.read(descriptor, 1024)
        if (len(content) != 117 or hashlib.sha256(content).hexdigest() !=
                "be10656c9edf975f5dfe48fe5819172e905e14dcd4ff372af5d8b45b26168edd"):
            raise ValueError("unexpected signed minimal producer")
        replace_contents(descriptor, content.replace(b"which", b"false"))
    overwrite_regular(compiler, "usr/bin/py3compile", b"stale compiler\n")


def dispatch(arguments: list[str]) -> None:
    command, *paths = arguments
    if command == "capture":
        root, stdout, stderr, *process = paths
        with ExitStack() as stack:
            outputs = []
            for relative in (stdout, stderr):
                parent, name = stack.enter_context(parent_descriptor(Path(root), relative))
                descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                stack.callback(os.close, descriptor)
                regular_metadata(descriptor)
                outputs.append(descriptor)
            maximum = 16 * 1024 * 1024
            oversized = False
            with subprocess.Popen(process, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child, \
                    selectors.DefaultSelector() as streams:
                counts = [0, 0]
                for index, stream in enumerate((child.stdout, child.stderr)):
                    streams.register(stream, selectors.EVENT_READ, index)
                while streams.get_map():
                    for key, _ in streams.select():
                        content = os.read(key.fd, 65536)
                        if not content:
                            streams.unregister(key.fileobj)
                            continue
                        index = key.data
                        bounded = content[:max(0, maximum - counts[index])]
                        if len(bounded) != len(content):
                            oversized = True
                        with os.fdopen(os.dup(outputs[index]), "wb") as output:
                            output.write(bounded)
                        counts[index] += len(bounded)
                status = child.wait()
            if oversized:
                raise ValueError("Python reference capture exceeds its byte limit")
        raise SystemExit(status if status >= 0 else 128 - status)
    roots = [Path(path) for path in paths]
    if command == "empty":
        prepare_empty(roots[0])
    elif command == "preflight":
        preflight(roots[0])
    elif command == "mode":
        chmod_regular(roots[0], "dev/null", int(paths[1], 8))
    elif command == "basic":
        basic_negatives(roots)
    elif command == "strict":
        strict_negatives(roots)
    elif command == "dpkg":
        stage_dpkg_reference(*roots, archive_relative="var/lib/dpkg/python3-probe.deb")
    elif command == "directory":
        directory(roots[0], paths[1], 0o700)
    else:
        raise ValueError("unknown Python fixture stage")
