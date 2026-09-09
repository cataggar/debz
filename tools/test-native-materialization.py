#!/usr/bin/env python3
"""Execute data-only native unpack and compare disposable roots with real dpkg."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[1]
GUARD = ".debz-native-disposable"
GUARD_CONTENT = "debz native materialization fixture v1\n"
EPOCH = 1_700_000_000
PACKAGE = "debz-native-demo"
PAYLOAD = Path("usr/share") / PACKAGE

SPEC = importlib.util.spec_from_file_location(
    "debz_native_differential", REPOSITORY / "tools/native-differential.py"
)
assert SPEC and SPEC.loader
oracle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = oracle
SPEC.loader.exec_module(oracle)


def run(argv: list[str], environment: dict[str, str], log: Path) -> None:
    with log.open("wb") as output:
        result = subprocess.run(
            argv,
            cwd=REPOSITORY,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    if result.returncode:
        with log.open("rb") as output:
            detail = output.read(12_000).decode(errors="replace")
        raise RuntimeError(f"{argv[0]} exited {result.returncode}; {log}\n{detail}")


def write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def make_package(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    version: str,
    feature: str = "data",
    *,
    package: str = PACKAGE,
    conffile_content: bytes = b"package configuration\n",
    extra_files: dict[str, bytes] | None = None,
) -> Path:
    stem = f"{package}_{version}_{feature}"
    source = workspace / (stem + ".source")
    payload = Path("usr/share") / package
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Maintainer: debz fixture <fixture@example.invalid>\n"
        "Description: native data-only materialization fixture\n"
    )
    write(source / "DEBIAN/control", control.encode())
    write(source / payload / "data", f"data version {version}\n".encode())
    os.link(source / payload / "data", source / payload / "data.link")
    (source / payload / "current").symlink_to("data")
    write(
        source / payload / "mode",
        b"permission-sensitive payload\n",
        0o600 if version == "1" else 0o640,
    )
    write(
        source / payload / ("obsolete" if version == "1" else "introduced"),
        f"only in {version}\n".encode(),
    )
    (source / payload / "empty").mkdir(mode=0o750)
    if feature == "conffile":
        write(source / "etc/debz-native.conf", conffile_content)
        write(source / "DEBIAN/conffiles", b"/etc/debz-native.conf\n")
    elif feature in ("obsolete-conffile", "remove-on-upgrade"):
        (source / "etc").mkdir(mode=0o755)
        if feature == "remove-on-upgrade":
            write(
                source / "DEBIAN/conffiles",
                b"remove-on-upgrade /etc/debz-native.conf\n",
            )
    elif feature == "script":
        write(source / "DEBIAN/preinst", b"#!/bin/sh\nexit 99\n", 0o755)
    elif feature not in ("data", "zero-time"):
        raise ValueError(f"unknown fixture feature: {feature}")
    for path, content in (extra_files or {}).items():
        write(source / path, content)

    checksums = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if relative.parts[0] == "DEBIAN" or path.is_symlink() or not path.is_file():
            continue
        checksums.append(f"{hashlib.md5(path.read_bytes()).hexdigest()}  {relative.as_posix()}\n")
    write(source / "DEBIAN/md5sums", "".join(checksums).encode())
    for path in [*source.rglob("*"), source]:
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o750 if path == source / payload / "empty" else 0o755)
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    if feature == "zero-time":
        os.utime(source / payload / "empty", (0, 0))
    destination = workspace / (stem + ".deb")
    run(
        ["dpkg-deb", "--build", "--uniform-compression", "-Zgzip", "-z1",
         str(source), str(destination)],
        environment,
        workspace / (stem + ".build.log"),
    )
    return destination


def make_root(path: Path, architecture: str) -> None:
    for directory in ("info", "updates", "triggers"):
        (path / "var/lib/dpkg" / directory).mkdir(parents=True, exist_ok=True)
    write(path / GUARD, GUARD_CONTENT.encode(), 0o600)
    write(path / "var/lib/dpkg/status", b"")
    write(path / "var/lib/dpkg/info/format", b"1\n")
    write(path / "var/lib/dpkg/arch", (architecture + "\n").encode())


def reference_command(root: Path) -> list[str]:
    if (
        not root.is_absolute()
        or root == Path("/")
        or root.resolve(strict=True) != root
        or (root / GUARD).is_symlink()
        or (root / GUARD).read_text() != GUARD_CONTENT
    ):
        raise RuntimeError("reference execution requires a disposable fixture root")
    return [
        "dpkg", "--force-not-root", "--force-bad-path", "--no-triggers",
        f"--root={root}",
    ]


def reference(
    root: Path,
    archive: Path,
    environment: dict[str, str],
    log: Path,
    *,
    configure: bool = False,
) -> None:
    run(
        [*reference_command(root), "--install" if configure else "--unpack", str(archive)],
        environment,
        log,
    )


def snapshot(root: Path) -> dict:
    return oracle.capture(root, excludes=(*oracle.DEFAULT_EXCLUDES, GUARD))


def compare_roots(reference_root: Path, candidate: Path, destination: Path) -> None:
    expected = snapshot(reference_root)
    observed = snapshot(candidate)
    write(destination / "reference.snapshot.json", oracle.canonical_json(expected).encode())
    write(destination / "native.snapshot.json", oracle.canonical_json(observed).encode())
    mismatches = oracle.differences(expected, observed, maximum=30)
    if mismatches:
        raise AssertionError("native/dpkg mismatch:\n" + "\n".join(mismatches))


def assert_parity(reference_root: Path, candidate: Path, destination: Path) -> None:
    compare_roots(reference_root, candidate, destination)
    expected_empty = (reference_root / PAYLOAD / "empty").stat()
    observed_empty = (candidate / PAYLOAD / "empty").stat()
    if expected_empty.st_mtime_ns != observed_empty.st_mtime_ns:
        raise AssertionError(
            "archive empty-directory mtime differs: "
            f"{expected_empty.st_mtime_ns} != {observed_empty.st_mtime_ns}"
        )


def native(
    executable: Path,
    root: Path,
    archive: Path | None,
    architecture: str,
    operation: str,
    environment: dict[str, str],
    destination: Path,
    *,
    conffiles: bool = False,
    policy: str = "keep_existing",
    packages: list[dict[str, str]] | None = None,
) -> dict:
    report = destination / "native.report.json"
    request = destination / "native.request.json"
    document = {
        "root": str(root),
        "architecture": architecture,
        "archives": [str(archive)] if archive else [],
        "operation": operation,
        "report": str(report),
    }
    if conffiles:
        document.update(conffiles=True, policy=policy)
    if packages is not None:
        document["packages"] = packages
    write(request, json.dumps(document).encode())
    run(
        [str(executable)],
        {**environment, "DEBZ_NATIVE_MATERIALIZATION_REQUEST": str(request)},
        destination / "native.log",
    )
    if not report.is_file() or report.stat().st_size > 64 * 1024:
        raise AssertionError("native test driver did not produce a bounded outcome report")
    result = json.loads(report.read_bytes())
    if result.get("outcome") not in {
        "applied", "rolled_back", "recovery_required", "handoff", "refused",
    }:
        raise AssertionError(f"invalid native report: {result}")
    return result


def exercise(
    executable: Path | None,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
) -> None:
    archives = {
        version: make_package(workspace, environment, architecture, version)
        for version in ("1", "2")
    }
    scenarios = (
        ("install", None, "1"),
        ("upgrade", "1", "2"),
        ("downgrade", "2", "1"),
        ("reinstall", "1", "1"),
    )
    for operation, initial, final in scenarios:
        case = workspace / operation
        expected, candidate = case / "reference", case / "native"
        make_root(expected, architecture)
        make_root(candidate, architecture)
        if initial:
            for root in (expected, candidate):
                reference(
                    root, archives[initial], environment,
                    case / f"{root.name}.seed.log", configure=True,
                )
                if operation == "reinstall":
                    (root / PAYLOAD / "data").write_bytes(b"local modification\n")
        reference(expected, archives[final], environment, case / "reference.log")
        if executable:
            report = native(
                executable, candidate, archives[final], architecture,
                operation, environment, case,
            )
            if report["outcome"] != "applied":
                raise AssertionError(f"{operation}: native did not apply: {report}")
            assert_parity(expected, candidate, case)
        else:
            reference(candidate, archives[final], environment, case / "candidate.log")
            assert_parity(expected, candidate, case)
        print(f"{operation}: {'native/dpkg parity' if executable else 'oracle fixture'} passed")

    sequence = workspace / "sequence"
    expected, candidate = sequence / "reference", sequence / "native"
    make_root(expected, architecture)
    make_root(candidate, architecture)
    lock_identity = None
    for index, (operation, version) in enumerate(
        (("install", "1"), ("upgrade", "2"), ("downgrade", "1"), ("reinstall", "1"))
    ):
        step = sequence / f"{index}-{operation}"
        step.mkdir()
        reference(expected, archives[version], environment, step / "reference.log")
        if executable:
            report = native(
                executable, candidate, archives[version], architecture,
                operation, environment, step,
            )
            if report["outcome"] != "applied":
                raise AssertionError(f"sequence {operation}: native did not apply: {report}")
            lock = (candidate / "var/lib/debz/root-operation.lock").stat()
            identity = (lock.st_dev, lock.st_ino)
            if lock_identity is not None and identity != lock_identity:
                raise AssertionError("native cleanup replaced the shared lock inode")
            lock_identity = identity
        else:
            reference(candidate, archives[version], environment, step / "candidate.log")
        assert_parity(expected, candidate, step)
    print(f"repeated unpack: {'native/dpkg parity' if executable else 'oracle fixture'} passed")

    if executable:
        for feature in ("conffile", "script", "zero-time"):
            archive = make_package(workspace, environment, architecture, "1", feature)
            case = workspace / feature
            candidate = case / "native"
            make_root(candidate, architecture)
            before = snapshot(candidate)
            report = native(
                executable, candidate, archive, architecture, "install",
                environment, case,
            )
            if report["outcome"] not in ("handoff", "refused"):
                raise AssertionError(f"{feature}: unsafe native outcome: {report}")
            if feature == "zero-time" and report != {
                "outcome": "refused",
                "detail": "zero_directory_timestamp_unsupported",
            }:
                raise AssertionError(f"zero timestamp did not receive its explicit refusal: {report}")
            mismatches = oracle.differences(before, snapshot(candidate), maximum=30)
            if mismatches:
                raise AssertionError(f"{feature}: refusal changed root:\n" + "\n".join(mismatches))
            for name in ("root-operation-v1.json", "root-mutation-v1.json"):
                if (candidate / "var/lib/debz" / name).exists():
                    raise AssertionError(f"{feature}: handoff stranded active evidence: {name}")
            print(f"{feature}: pre-mutation handoff passed")


def fixture_environment(workspace: Path) -> dict[str, str]:
    (workspace / "home").mkdir()
    (workspace / "tmp").mkdir()
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(workspace / "home"),
        "TMPDIR": str(workspace / "tmp"),
        "SOURCE_DATE_EPOCH": str(EPOCH),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", nargs="?", type=Path)
    parser.add_argument(
        "--oracle-only", action="store_true",
        help="check fixture/reference consistency only; does not establish native parity",
    )
    arguments = parser.parse_args()
    if arguments.oracle_only == bool(arguments.native_test):
        parser.error("provide a native test executable or --oracle-only, not both")
    for command in ("dpkg", "dpkg-deb"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required reference tool is missing: {command}")
    executable = arguments.native_test.resolve(strict=True) if arguments.native_test else None
    architecture = subprocess.run(
        ["dpkg", "--print-architecture"], check=True, capture_output=True,
        text=True, timeout=10,
    ).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError(f"unsupported acceptance architecture: {architecture}")
    host_status = Path("/var/lib/dpkg/status").read_bytes()
    temporary_root = REPOSITORY / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="native-materialization-", dir=temporary_root,
    ) as temporary:
        workspace = Path(temporary)
        environment = fixture_environment(workspace)
        exercise(executable, workspace, environment, architecture)
    if Path("/var/lib/dpkg/status").read_bytes() != host_status:
        raise AssertionError("host dpkg status changed during disposable-root acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
