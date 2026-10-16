"""Reusable disposable-root fixture helpers for Python lifecycle acceptance."""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import subprocess


REPOSITORY = Path(__file__).resolve().parents[1]
GUARD = ".debz-native-disposable"
GUARD_CONTENT = "debz native materialization fixture v1\n"
EPOCH = 1_700_000_000
PACKAGE = "debz-native-demo"
PAYLOAD = Path("usr/share") / PACKAGE
REFERENCE_DPKG = "dpkg"
DISPOSABLE_RUNTIME = Path(os.environ.get(
    "DEBZ_DISPOSABLE_RUNTIME", REPOSITORY / "zig-out/bin/debz-disposable-runtime",
))

NATIVE_REFERENCE = Path(os.environ.get(
    "DEBZ_NATIVE_DPKG_REFERENCE", REPOSITORY / "zig-out/bin/debz-native-dpkg-reference",
))


def native_reference(*arguments: str) -> str:
    if not NATIVE_REFERENCE.is_absolute():
        raise ValueError(f"native reference helper requires an absolute path: {NATIVE_REFERENCE}")
    return subprocess.run(
        [str(NATIVE_REFERENCE), *arguments], cwd=REPOSITORY,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True,
        env={**os.environ, "LC_ALL": "C"}, timeout=120, check=True,
    ).stdout


@lru_cache(maxsize=1)
def reference_description() -> dict:
    return json.loads(native_reference("--describe"))


def verify_reference(path: Path, architecture: str, tool: str = "dpkg") -> None:
    native_reference("--architecture", architecture, "--verify-binding", str(path), "--tool", tool)


def select_reference(
    executable: Path | None, architecture: str, *, root_accounts: bool = False,
) -> str:
    arguments = ["--architecture", architecture]
    arguments.extend(("--select", str(executable)) if executable is not None else ("--check-host",))
    if root_accounts:
        arguments.append("--root-accounts")
    return native_reference(*arguments).strip()


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


def copy_program(
    root: Path, source: Path, destination: str, *, max_file_bytes: int | None = None,
) -> None:
    command = [str(DISPOSABLE_RUNTIME), str(root), str(source), destination]
    if max_file_bytes is not None:
        command.extend(("--max-file-bytes", str(max_file_bytes)))
    subprocess.run(
        command,
        stdin=subprocess.DEVNULL, timeout=120, check=True,
    )


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


def reference_phase(
    root: Path,
    archives: list[Path],
    operation: str,
    environment: dict[str, str],
    destination: Path,
    *,
    packages: list[dict[str, str]],
    policy: str = "keep_existing",
) -> int:
    command = reference_command(root)
    command.append("--force-confold" if policy == "keep_existing" else "--force-confnew")
    if operation in ("install", "upgrade", "downgrade", "reinstall", "unpack"):
        if not archives:
            raise ValueError("archive lifecycle requires an archive")
        command += ["--unpack" if operation == "unpack" else "--install"]
        command += [str(path) for path in archives]
    elif operation in ("configure", "remove", "purge"):
        if not packages:
            raise ValueError("existing-package lifecycle requires selected packages")
        command += [f"--{operation}"]
        command += [f"{p['name']}:{p['architecture']}" for p in packages]
    else:
        raise ValueError(f"unsupported lifecycle reference operation: {operation}")
    log = destination / "reference.log"
    with log.open("wb") as output:
        result = subprocess.run(
            command, env=environment, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, timeout=120, check=False,
        )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"reference exited unexpectedly: {result.returncode}; {log}")
    return result.returncode


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
