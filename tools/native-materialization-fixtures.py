#!/usr/bin/env python3
"""Reusable disposable-root fixture helpers for Python lifecycle acceptance."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


REPOSITORY = Path(__file__).resolve().parents[1]
GUARD = ".debz-native-disposable"
GUARD_CONTENT = "debz native materialization fixture v1\n"
EPOCH = 1_700_000_000
PACKAGE = "debz-native-demo"
PAYLOAD = Path("usr/share") / PACKAGE
REFERENCE_DPKG = "dpkg"

REFERENCE_SPEC = importlib.util.spec_from_file_location(
    "debz_reference_dpkg", REPOSITORY / "tools/prepare-native-dpkg.py",
)
assert REFERENCE_SPEC and REFERENCE_SPEC.loader
reference_dpkg = importlib.util.module_from_spec(REFERENCE_SPEC)
REFERENCE_SPEC.loader.exec_module(reference_dpkg)

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
    scripts: dict[str, bytes] | None = None,
    control_fields: dict[str, str] | None = None,
    prepare_payload: Callable[[Path], None] | None = None,
    compression: str = "gzip",
    triggers: bytes | None = None,
    archive_builder: Callable[[Path, Path], None] | None = None,
) -> Path:
    if compression not in ("gzip", "none"):
        raise ValueError(f"unsupported fixture compression: {compression}")
    stem = f"{package}_{version}_{feature}"
    source = workspace / (stem + ".source")
    payload = Path("usr/share") / package
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Maintainer: debz fixture <fixture@example.invalid>\n"
        "Description: native data-only materialization fixture\n"
    )
    for name, value in (control_fields or {}).items():
        control += f"{name}: {value}\n"
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
    for name, content in (scripts or {}).items():
        if name not in ("preinst", "postinst", "prerm", "postrm"):
            raise ValueError(f"unsupported maintainer-script fixture: {name}")
        write(source / "DEBIAN" / name, content, 0o755)
    if triggers is not None:
        write(source / "DEBIAN/triggers", triggers)
    if prepare_payload is not None:
        prepare_payload(source)

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
    if archive_builder is None:
        run(
            ["dpkg-deb", "--build", "--uniform-compression", f"-Z{compression}",
             *(["-z1"] if compression == "gzip" else []),
             str(source), str(destination)],
            environment,
            workspace / (stem + ".build.log"),
        )
    else:
        archive_builder(source, destination)
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
        REFERENCE_DPKG, "--force-not-root", "--force-bad-path", "--no-triggers",
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
