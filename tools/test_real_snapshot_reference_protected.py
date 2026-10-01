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

from real_snapshot_reference_paths import open_absolute, open_beneath, protected, read_root_file

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


def assert_teardown(root: Path) -> dict[str, object]:
    identity = (root.stat().st_dev, root.stat().st_ino)
    for attempt in range(20):
        surviving: list[int] = []
        scanned = 0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            scanned += 1
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
    mounts = 0
    with Path("/proc/self/mountinfo").open(encoding="utf-8") as stream:
        for line in stream:
            mounts += 1
            mountpoint = line.split(" ", 5)[4].replace(r"\040", " ").replace(r"\011", "\t")
            if mountpoint == str(root) or mountpoint.startswith(str(root) + "/"):
                raise AssertionError(f"reference mount survived under {root}: {mountpoint}")
    # Detached mounts leave the template's empty archive file and proc directory.
    archive = (root / ".debz-reference-archive").lstat()
    proc_entries = sorted(entry.name for entry in (root / "proc").iterdir())
    if (not stat.S_ISREG(archive.st_mode) or archive.st_size != 0 or
            archive.st_nlink != 1 or proc_entries):
        raise AssertionError(f"reference archive or proc mountpoint changed under {root}")
    return {
        "polls": attempt + 1, "processes_scanned": scanned, "surviving_processes": [],
        "mountinfo_entries": mounts, "mounts_under_root": [],
        "archive_mountpoint": {"size": archive.st_size, "nlink": archive.st_nlink,
                               "mode": oct(stat.S_IMODE(archive.st_mode))},
        "proc_entries": proc_entries,
    }


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


ESCAPE_CHECKS = (
    "pid-namespace", "no-proc-view", "inherited-descriptors", "no-new-privileges",
    "seccomp-filter", "capabilities", "path-escape", "re-chroot-denied",
    "pivot-root-denied", "handle-escape-denied", "mount-denied", "umount-denied",
    "move-mount-denied", "device-node-denied", "module-load-denied",
    "module-file-denied", "module-remove-denied", "host-admin-denied",
    "host-time-denied", "raw-network-denied", "unshare-denied", "setns-denied",
    "clone-user-denied", "clone-network-denied", "clone-mount-denied", "clone3-denied",
)
# Unconfined root must visibly hold each authority the confined probe lacks.
CONTROL_DETECTS = tuple(
    check for check in ESCAPE_CHECKS if check not in ("inherited-descriptors", "path-escape")
)
DESCENDANT_MARKER = ".debz-escape-probe-descendant"
# Confined-only checks: the bound archive and the detached descendant.
CONFINED_CHECKS = ("archive-mount", "descendant-started")
# Signed amd64 configure profiles: the probe is the root's /bin/sh, so the
# kernel starts it for the digest-bound postinst. It reports the profile's proc
# view in place of no-proc-view, then the same escape checks.
PROFILE_ESCAPE_CHECKS = tuple(check for check in ESCAPE_CHECKS if check != "no-proc-view")
PROFILE_COMMON_CHECKS = (
    "proc-mount", "proc-root", "proc-hidepid", "archive-unbound", "descendant-started",
)
PROFILE_VIEW_CHECKS = {
    "systemd": ("proc-read-only", "proc-sys-masked", "proc-boot-id"),
    "udev": ("proc-pid-only",),
    "sudo": ("proc-pid-only",),
}
PROFILE_SCRIPT_LIMIT = 64 * 1024


def probe_detail(output: str, check: str) -> dict[str, str]:
    prefix = f"debz-escape-probe: {check} ok "
    lines = [line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        raise AssertionError(f"escape probe must report {check} exactly once")
    return dict(field.split("=", 1) for field in lines[0].split() if "=" in field)


def probe_results(output: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split(" ", 3)
        if len(fields) < 3 or fields[0] != "debz-escape-probe:" or fields[2] == "info":
            continue
        if fields[1] in results or fields[2] not in ("ok", "FAIL"):
            raise AssertionError(f"ambiguous escape probe report: {line!r}")
        results[fields[1]] = fields[2]
    return results


def operation(
    workspace: Path, name: str, launcher: Path, dpkg: Path, root: Path,
    architecture: str, archive: Path | None, digest: str | None, size: int | None, verb: str,
    *, readable_output: bool = False, inherited_fd: int | None = None,
    package: str = "debz-reference-proof", profile: str = "none",
    selector: str | None = None,
) -> tuple[int, str]:
    stdout_path = workspace / f"{name}.stdout"
    stderr_path = workspace / f"{name}.stderr"
    stdout_mode = "a+b" if readable_output else "ab"
    command = [
        str(launcher), str(root), str(dpkg), architecture, profile, verb,
        selector or f"{package}:{architecture}",
    ]
    if archive is not None:
        command.extend((str(archive), str(digest), str(size)))
    # subprocess.DEVNULL is read-write; the launcher requires a read-only stdin.
    stdin = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with stdout_path.open(stdout_mode) as stdout, stderr_path.open("ab") as stderr:
            try:
                result = subprocess.run(
                    command, env=ORDER.oracle_environment(), stdin=stdin,
                    stdout=stdout, stderr=stderr, timeout=45,
                    pass_fds=() if inherited_fd is None else (inherited_fd,),
                    check=False,
                )
                status = result.returncode
            except subprocess.TimeoutExpired:
                status = -1
    finally:
        os.close(stdin)
    teardown = assert_teardown(root)
    error = stderr_path.read_text(errors="replace")
    (workspace / f"{name}.json").write_text(json.dumps({
        "argv": command, "exit_status": status, "stderr": error,
        "teardown": teardown,
        "database": None if status != 0 else sorted(
            [f"{package}:{arch}", *record]
            for (package, arch), record in ORDER.database_packages(root).items()
        ),
    }, indent=2) + "\n")
    return status, error


def require(status: int, error: str, expected: str, name: str) -> None:
    if status == 0 or expected not in error:
        raise AssertionError(
            f"{name}: expected nonzero exit with {expected!r}; "
            f"observed exit={status}, stderr={error!r}"
        )


def write_beneath(root: Path, relative: str, data: bytes, mode: int, *, replace: bool = False) -> None:
    parent, _, name = relative.rpartition("/")
    root_fd = open_absolute(root, directory=True)
    try:
        directory = open_beneath(root_fd, parent, directory=True)
    finally:
        os.close(root_fd)
    try:
        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        flags |= os.O_TRUNC if replace else os.O_CREAT | os.O_EXCL
        fd = os.open(name, flags, mode, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError(f"profile root member is not a regular file: {relative}")
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def profile_scripts(directory: Path, architecture: str) -> dict[str, bytes]:
    """Load the signed postinsts staged from the authenticated snapshot."""
    protected(directory, directory=True)
    names = sorted(entry.name for entry in directory.iterdir())
    if architecture != "amd64":
        # The launcher binds signed proc profiles to amd64 only.
        if names:
            raise ValueError(f"{architecture} must not stage amd64 profile scripts: {names}")
        return {}
    expected = sorted(f"{profile}.postinst" for profile in PROFILE_VIEW_CHECKS)
    if names != expected:
        raise ValueError(f"amd64 profile scripts must be exactly {expected}: {names}")
    scripts = {}
    for profile in PROFILE_VIEW_CHECKS:
        path = directory / f"{profile}.postinst"
        if protected(path).st_size > PROFILE_SCRIPT_LIMIT:
            raise ValueError(f"profile script exceeds limit: {path}")
        scripts[profile] = path.read_bytes()
    return scripts


def profile_root(
    template: Path, workspace: Path, name: str, profile: str, script: bytes,
    probe: bytes, *, version: str | None = None,
) -> Path:
    """An unpacked signed package whose root /bin/sh is the static probe."""
    root = fresh_root(template, workspace, name)
    write_beneath(root, "var/lib/dpkg/status", (
        f"Package: {profile}\nStatus: install ok unpacked\nPriority: optional\n"
        "Section: admin\nMaintainer: debz reference proof <reference-proof@debz.invalid>\n"
        f"Architecture: amd64\nVersion: {version or ORDER.PROFILE_VERSIONS[profile]}\n"
        "Description: debz protected proc-view proof\n"
    ).encode(), 0o644, replace=True)
    write_beneath(root, f"var/lib/dpkg/info/{profile}.list", b"", 0o644)
    write_beneath(root, f"var/lib/dpkg/info/{profile}.postinst", script, 0o755)
    write_beneath(root, "usr/bin/sh", probe, 0o755)
    return root


def require_unchanged_profile(root: Path, profile: str, name: str) -> None:
    packages = ORDER.database_packages(root)
    if packages.get((profile, "amd64"), ("",))[0] != "install ok unpacked":
        raise AssertionError(f"{name}: refused profile changed the package state: {packages}")
    marker = (root / DESCENDANT_MARKER)
    if marker.exists() or marker.is_symlink():
        raise AssertionError(f"{name}: the probe ran despite the refusal")


def prove_profiles(args: argparse.Namespace, scripts: dict[str, bytes]) -> str:
    probe = args.escape_probe.read_bytes()
    if args.architecture != "amd64":
        for profile in PROFILE_VIEW_CHECKS:
            name = f"profile-{profile}-{args.architecture}"
            root = fresh_root(args.root_template, args.workspace, name)
            status, error = operation(
                args.workspace, name, args.launcher, args.dpkg, root,
                args.architecture, None, None, None, "configure",
                profile=profile, selector=f"{profile}:{args.architecture}",
            )
            require(status, error, "InvalidProfile", name)
        return f"{args.architecture} refusal of the amd64-only signed proc profiles"
    host_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    for profile, view in PROFILE_VIEW_CHECKS.items():
        name = f"profile-{profile}"
        root = profile_root(args.root_template, args.workspace, name, profile, scripts[profile], probe)
        parent_fd = os.open(args.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            status, error = operation(
                args.workspace, name, args.launcher, args.dpkg, root,
                args.architecture, None, None, None, "configure",
                inherited_fd=parent_fd, profile=profile, selector=f"{profile}:amd64",
            )
        finally:
            os.close(parent_fd)
        output = (args.workspace / f"{name}.stdout").read_text(errors="replace")
        results = probe_results(output)
        failed = [check for check in (*PROFILE_ESCAPE_CHECKS, *PROFILE_COMMON_CHECKS, *view, "result")
                  if results.get(check) != "ok"]
        if status != 0 or failed or "no-proc-view" in results:
            raise AssertionError(f"{name}: proc view checks failed {failed}; exit={status}: {error}")
        if probe_detail(output, "result").get("mode") != profile:
            raise AssertionError(f"{name}: the probe did not run as the {profile} postinst")
        if profile == "systemd" and probe_detail(output, "proc-boot-id").get("boot_id") != host_boot_id:
            raise AssertionError(f"{name}: the masked boot ID is not the host boot ID")
        if not read_root_file(root, DESCENDANT_MARKER, 64).strip().isdigit():
            raise AssertionError(f"{name}: detached descendant never started")
        if ORDER.database_packages(root).get((profile, "amd64")) != (
            "install ok installed", ORDER.PROFILE_VERSIONS[profile],
        ):
            raise AssertionError(f"{name}: pinned dpkg did not configure the bound package")
    tampered = bytearray(scripts["systemd"])
    tampered[-2] ^= 0x01
    for name, profile, selector, script, version, expected in (
        ("profile-tampered-script", "systemd", "systemd:amd64", bytes(tampered), None, "SourceChanged"),
        ("profile-wrong-version", "systemd", "systemd:amd64", scripts["systemd"], "261.2-1ubuntu1",
         "ReferenceSetupFailed"),
        ("profile-wrong-selector", "systemd", "udev:amd64", scripts["systemd"], None, "InvalidProfile"),
        ("profile-unbound-configure", "none", "systemd:amd64", scripts["systemd"], None, "InvalidProfile"),
    ):
        bound = "systemd"
        root = profile_root(args.root_template, args.workspace, name, bound, script, probe, version=version)
        status, error = operation(
            args.workspace, name, args.launcher, args.dpkg, root, args.architecture,
            None, None, None, "configure", profile=profile, selector=selector,
        )
        require(status, error, expected, name)
        if name == "profile-wrong-version" and "failed at stage 10" not in error:
            raise AssertionError(f"{name}: the in-root binding did not refuse: {error!r}")
        require_unchanged_profile(root, bound, name)
    return "amd64 systemd boot-ID and udev/sudo PID-only proc views with four binding refusals"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--dpkg", type=Path, required=True)
    parser.add_argument("--root-template", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha512", required=True)
    parser.add_argument("--archive-size", type=int, required=True)
    parser.add_argument("--escape-probe", type=Path, required=True)
    parser.add_argument("--escape-archive", type=Path, required=True)
    parser.add_argument("--escape-archive-sha512", required=True)
    parser.add_argument("--escape-archive-size", type=int, required=True)
    parser.add_argument("--profile-scripts", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.getegid() != 0:
        raise PermissionError("protected reference proof requires UID/GID 0")
    # Launcher output streams must not be group/other writable whatever the caller's umask.
    os.umask(0o077)
    if not all(path.is_absolute() for path in (
        args.launcher, args.dpkg, args.root_template, args.workspace, args.archive,
        args.escape_probe, args.escape_archive, args.profile_scripts,
    )):
        raise ValueError("protected proof inputs must be absolute paths")
    protected(Path(__file__).resolve())
    for path in (args.launcher, args.dpkg, args.archive, args.escape_probe, args.escape_archive):
        protected(path)
    protected_directory(args.root_template)
    protected_directory(args.workspace, empty=True)
    # Bind the claimed architecture to its pinned dpkg before any per-architecture input.
    identity = hashlib.sha256(args.dpkg.read_bytes()).hexdigest()
    pinned = {
        "amd64": "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
        "arm64": "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
    }
    if identity != pinned[args.architecture]:
        raise ValueError("reference dpkg executable is not the pinned architecture artifact")
    scripts = profile_scripts(args.profile_scripts, args.architecture)
    proc = protected(args.root_template / "proc", directory=True)
    mountpoint = protected(args.root_template / ".debz-reference-archive")
    if stat.S_IMODE(proc.st_mode) != 0o755 or (
        stat.S_IMODE(mountpoint.st_mode) != 0o600 or mountpoint.st_nlink != 1 or
        mountpoint.st_size != 0 or mountpoint.st_dev != args.root_template.stat().st_dev
    ):
        raise ValueError("protected proof template has invalid proc/archive mountpoints")
    for archive, digest, size in (
        (args.archive, args.archive_sha512, args.archive_size),
        (args.escape_archive, args.escape_archive_sha512, args.escape_archive_size),
    ):
        if not re.fullmatch("[a-f0-9]{128}", digest):
            raise ValueError("archive SHA512 must come from the authenticated lock")
        if not 0 < size <= 512 * 1024 * 1024:
            raise ValueError("invalid authenticated archive size")
        if archive.stat().st_size != size:
            raise ValueError("authenticated archive size differs")
        archive_hash = hashlib.sha512()
        with archive.open("rb") as source:
            while block := source.read(1024 * 1024):
                archive_hash.update(block)
        if archive_hash.hexdigest() != digest:
            raise ValueError("authenticated archive SHA512 differs")
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

    # The same static probe, unconfined, must observe every authority it checks.
    control_path = args.workspace / "escape-control.stdout"
    with control_path.open("xb") as control_output:
        control = subprocess.run(
            [str(args.escape_probe), "control"], env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            stdin=subprocess.DEVNULL, stdout=control_output, stderr=subprocess.STDOUT,
            timeout=45, check=False,
        )
    control_results = probe_results(control_path.read_text(errors="replace"))
    undetected = [check for check in CONTROL_DETECTS if control_results.get(check) != "FAIL"]
    if control.returncode != 1 or control_results.get("result") != "FAIL" or undetected:
        raise AssertionError(
            f"escape-control: unconfined probe missed authority {undetected}; "
            f"exit={control.returncode}"
        )

    # Pinned dpkg (namespace PID 1) runs the static probe as its preinst; the
    # probe attempts each escape and leaves a detached descendant behind.
    root = fresh_root(args.root_template, args.workspace, "escape")
    parent_fd = os.open(args.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        status, error = operation(
            args.workspace, "escape", args.launcher, args.dpkg, root,
            args.architecture, args.escape_archive, args.escape_archive_sha512,
            args.escape_archive_size, "unpack", inherited_fd=parent_fd,
            package="debz-reference-escape-probe",
        )
    finally:
        os.close(parent_fd)
    escape_output = (args.workspace / "escape.stdout").read_text(errors="replace")
    results = probe_results(escape_output)
    failed = [check for check in (*ESCAPE_CHECKS, *CONFINED_CHECKS, "result")
              if results.get(check) != "ok"]
    if status != 0 or failed:
        raise AssertionError(f"escape: confinement checks failed {failed}; exit={status}: {error}")
    if probe_detail(escape_output, "archive-mount").get("size") != str(args.escape_archive_size):
        raise AssertionError("escape: the bound archive is not the authenticated escape archive")
    if not read_root_file(root, DESCENDANT_MARKER, 64).strip().isdigit():
        raise AssertionError("escape: detached descendant never started")
    if ("debz-reference-escape-probe", args.architecture) not in ORDER.database_packages(root):
        raise AssertionError("escape: pinned dpkg did not record the probe package")
    profiles = prove_profiles(args, scripts)
    print(
        "protected pinned-dpkg probe/unpack, six refusals, unconfined escape control and "
        f"{len(ESCAPE_CHECKS)} confined escape checks, read-only archive mount and "
        f"descendant teardown, {profiles}: executed without skips"
    )


if __name__ == "__main__":
    main()
