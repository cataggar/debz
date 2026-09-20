#!/usr/bin/env python3
"""Verify bounded dpkg/update-alternatives behavior in disposable roots."""

from __future__ import annotations

import argparse
import base64
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import shlex
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json"
SCHEMA = "https://debz.dev/schema/dpkg-alternatives-reference-v1"
TRACE = "var/log/debz-alternatives-oracle.trace"
FD_ERRORS = "var/log/debz-alternatives-oracle.fd-errors"
FAILURES = "debz-alternatives-oracle.failures"
PAUSE = "debz-alternatives-oracle.pause"
PAUSED = "debz-alternatives-oracle.paused"
DPKG_LOG = "var/log/dpkg.log"
ALT_LOG = "var/log/alternatives.log"
GROUP = "debz-alternatives"
CANONICAL_TASK_INVOCATION = "2026-09-20T12:22:59.658+00:00"
ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
}
IDENTITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
LOG_CLOCK_PATTERN = re.compile(
    rb"(?m)^update-alternatives "
    rb"(?P<clock>[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}):"
)
DPKG_LOG_CLOCK_PATTERN = re.compile(
    rb"(?m)^(?P<clock>[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) "
)


CONFIG_SPEC = importlib.util.spec_from_file_location(
    "debz_alternatives_config", ROOT / "tools/dpkg-config-reference.py",
)
assert CONFIG_SPEC and CONFIG_SPEC.loader
config = importlib.util.module_from_spec(CONFIG_SPEC)
CONFIG_SPEC.loader.exec_module(config)
m = config.m


class OracleError(RuntimeError):
    """The reference fixture or an observation crossed its bounded contract."""


class Limits:
    maximum_groups = 32
    maximum_relationships = 128
    maximum_requested_paths = 256
    maximum_linked_entries = 256
    maximum_record_bytes = 256 * 1024
    maximum_total_record_bytes = 2 * 1024 * 1024
    maximum_output_bytes = 128 * 1024
    maximum_log_bytes = 256 * 1024
    maximum_path_bytes = 4096
    maximum_arguments = 512
    maximum_argument_bytes = 4096
    maximum_cases = 64
    maximum_info_files = 32
    maximum_info_bytes = 1024 * 1024
    maximum_database_files = 64
    maximum_database_bytes = 1024 * 1024
    maximum_payload_files = 64
    maximum_payload_bytes = 1024 * 1024
    maximum_host_entries = 100_000
    maximum_archive_bytes = 8 * 1024 * 1024
    dependency_timeout_seconds = 10
    subprocess_timeout_seconds = 30
    subprocess_cleanup_seconds = 2
    pause_timeout_seconds = 10


def limit_contract() -> dict[str, int]:
    return {
        name: value
        for name, value in vars(Limits).items()
        if not name.startswith("_") and isinstance(value, int)
    }


def canonical_json(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise OracleError(f"required regular file is missing: {path}") from None
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise OracleError(f"path must be a regular non-symlink file: {path}")
    if metadata.st_size > maximum:
        raise OracleError(f"file exceeds its byte limit: {path}")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise OracleError(f"file changed while reading: {path}")
    return data


def optional_regular(path: Path, maximum: int) -> bytes | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return read_regular(path, maximum)


def bounded_scandir(path: Path, maximum: int) -> list[os.DirEntry[str]]:
    count = 0
    with os.scandir(path) as entries:
        for _ in entries:
            count += 1
            if count > maximum:
                raise OracleError(f"directory entry count exceeds its limit: {path}")
    with os.scandir(path) as entries:
        return sorted(entries, key=lambda entry: os.fsencode(entry.name))


def load_reference() -> dict[str, Any]:
    raw = read_regular(REFERENCE, Limits.maximum_total_record_bytes)
    reference = json.loads(raw)
    if reference.get("schema") != SCHEMA or reference.get("version") != 1:
        raise OracleError("unsupported dpkg alternatives reference")
    if raw != canonical_json(reference).encode():
        raise OracleError("dpkg alternatives reference is not canonical JSON")
    return reference


def verify_file_binding(path: Path, binding: dict[str, Any]) -> None:
    data = read_regular(path, Limits.maximum_archive_bytes)
    if len(data) != binding["size"] or sha256_bytes(data) != binding["sha256"]:
        raise OracleError(f"pinned source binding changed: {path}")


def verify_source_bindings(reference: dict[str, Any]) -> dict[str, Any]:
    boundary = reference["boundary"]
    if boundary["limits"] != limit_contract():
        raise OracleError("published oracle limits changed")
    if (
        boundary["invocation_clock"]["task_invocation"]
        != CANONICAL_TASK_INVOCATION
    ):
        raise OracleError("canonical task invocation binding changed")
    source = reference["source"]
    fixtures = ROOT / "tools/fixtures/vendor-state"
    vendor = source["vendor_reference"]
    verify_file_binding(fixtures / vendor["index"]["path"], vendor["index"])
    verify_file_binding(fixtures / vendor["reference"]["path"], vendor["reference"])
    for manifest in vendor["manifests"]:
        verify_file_binding(fixtures / manifest["path"], manifest)
    if [item["architecture"] for item in vendor["manifests"]] != boundary[
        "architectures"
    ]:
        raise OracleError("vendor manifest architecture coverage changed")
    derived = json.loads(
        read_regular(
            fixtures / vendor["reference"]["path"],
            Limits.maximum_archive_bytes,
        )
    )
    alternatives = derived["alternatives"]
    if (
        len(alternatives["groups"]) != 14
        or len(alternatives["requested_paths"]) != 189
        or len(alternatives["linked_entries"]) != 190
        or sum(len(group["links"]) for group in alternatives["groups"]) != 72
    ):
        raise OracleError("pinned vendor alternatives inventory changed")
    projection = reference["vendor_projection"]
    if projection["alternatives_sha256"] != sha256_bytes(
        canonical_json(alternatives).encode()
    ):
        raise OracleError("vendor alternatives projection digest changed")
    if projection["group_names"] != [group["name"] for group in alternatives["groups"]]:
        raise OracleError("vendor alternatives group ordering changed")
    derived_source = derived["source"]
    expected_manifests = [
        {
            "architecture": item["architecture"],
            "path": item["path"],
            "sha256": item["sha256"],
            "size": item["size"],
        }
        for item in derived_source["manifests"]
    ]
    if vendor["manifests"] != expected_manifests:
        raise OracleError("vendor manifest bindings changed")
    if vendor["index"] != derived_source["index"]:
        raise OracleError("vendor index binding changed")
    index_source = derived_source["index_source"]
    if (
        vendor["snapshot"] != index_source["snapshot_uri"]
        or vendor["workflow_run"] != index_source["workflow_run_url"]
    ):
        raise OracleError("vendor invocation provenance changed")

    if source["dpkg"]["version"] != m.reference_dpkg.VERSION:
        raise OracleError("dpkg reference version binding changed")
    if source["dpkg"]["configuration_sha256"] != sha256_bytes(
        config.PINNED_DPKG_CONFIG
    ):
        raise OracleError("dpkg configuration binding changed")
    for architecture, pins in m.reference_dpkg.PINS.items():
        expected = source["dpkg"]["architectures"][architecture]
        if expected != {
            "archive_sha256": pins["archive"],
            "dpkg_sha256": pins["executable"],
            "update_alternatives_sha256": pins["update_alternatives"],
        }:
            raise OracleError(f"dpkg tool pins changed for {architecture}")
    if source["fixture_packages"] != {
        "architectures": ["amd64", "arm64"],
        "baseline_architecture": "amd64",
        "clock_epoch": m.EPOCH,
        "maintainer": "debz fixture <fixture@example.invalid>",
        "namespace": "debz-alt-*",
        "package_builder": "repository deterministic Python ar/tar builder",
    }:
        raise OracleError("fixture package provenance changed")
    config.verify_architecture_evidence(reference)
    return derived


def validate_observation_architecture(
    reference: dict[str, Any],
    architecture: str,
) -> None:
    observed = reference["boundary"].get("observed_architectures")
    if observed is None:
        observed = [reference["boundary"]["observed_architecture"]]
    if architecture not in observed:
        raise OracleError(
            "published alternatives observation is architecture-specific: "
            f"requested={architecture}, observed={','.join(observed)}"
        )


def validate_environment(environment: dict[str, str]) -> None:
    if len(environment) > 16:
        raise OracleError("fixture environment exceeds its variable limit")
    for name, value in environment.items():
        encoded = f"{name}={value}".encode()
        if not name or "=" in name or b"\x00" in encoded or len(encoded) > 4096:
            raise OracleError(f"unsafe fixture environment entry: {name!r}")
    for name in config.FORBIDDEN_FRONTEND_ENV:
        if name in environment:
            raise OracleError(f"frontend environment entered alternatives fixture: {name}")


def validate_absolute_path(value: str) -> str:
    encoded = os.fsencode(value)
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or value == "/"
        or "//" in value
        or len(encoded) > Limits.maximum_path_bytes
        or b"\x00" in encoded
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise OracleError(f"unsafe absolute alternatives path: {value!r}")
    return value


def validate_name(value: str) -> str:
    encoded = value.encode()
    if (
        not IDENTITY_PATTERN.fullmatch(value)
        or len(encoded) > 128
        or "/" in value
    ):
        raise OracleError(f"unsafe alternatives name: {value!r}")
    return value


def validate_root(root: Path) -> Path:
    if not root.is_absolute() or root == Path("/"):
        raise OracleError("alternatives execution requires an absolute disposable root")
    current = Path(root.anchor)
    for component in root.parts[1:]:
        if component in {"", ".", ".."}:
            raise OracleError("alternatives root contains an ambiguous component")
        current /= component
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or current.is_symlink():
            raise OracleError(f"alternatives root component is not a real directory: {current}")
    guard = root / m.GUARD
    if guard.is_symlink() or read_regular(guard, 128) != m.GUARD_CONTENT.encode():
        raise OracleError("alternatives execution requires the disposable-root guard")
    for relative in ("etc/alternatives", "var/lib/dpkg/alternatives"):
        path = root / relative
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise OracleError(f"alternatives state directory is unsafe: {path}")
    return root


def validate_admin_records(root: Path) -> None:
    admin = validate_root(root) / "var/lib/dpkg/alternatives"
    entries = bounded_scandir(admin, Limits.maximum_groups)
    total = 0
    for entry in entries:
        validate_name(entry.name.removesuffix(".dpkg-tmp"))
        metadata = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or entry.is_symlink():
            raise OracleError(f"alternatives record must be regular: {entry.name}")
        total += metadata.st_size
        if (
            metadata.st_size > Limits.maximum_record_bytes
            or total > Limits.maximum_total_record_bytes
        ):
            raise OracleError("alternatives record bytes exceed their limit")


def make_root(path: Path, architecture: str, *, dpkg_runtime: bool = False) -> None:
    m.make_root(path, architecture)
    for relative in (
        "etc/alternatives",
        "usr/bin",
        "usr/lib",
        "usr/share/man/man1",
        "var/lib/dpkg/alternatives",
        "var/log",
    ):
        (path / relative).mkdir(parents=True, exist_ok=True)
        (path / relative).chmod(0o755)
    if dpkg_runtime:
        copy_program(path, Path("/bin/sh"), "/bin/sh")
        copy_program(path, Path("/bin/sleep"), "/bin/sleep")
        for relative in config.FORBIDDEN_FRONTEND_PATHS:
            if os.path.lexists(path / relative):
                raise OracleError(
                    f"ambient frontend contaminated fixture root: {relative}"
                )
        info = path / "var/lib/dpkg/info"
        entries = bounded_scandir(info, 2)
        if (
            [entry.name for entry in entries] != ["format"]
            or read_regular(info / "format", 16) != b"1\n"
        ):
            raise OracleError("ambient package metadata contaminated fixture root")
        if os.path.lexists(path / "var/lib/dpkg/tmp.ci"):
            raise OracleError("ambient control staging contaminated fixture root")


def bound_child_resources() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (Limits.maximum_log_bytes, Limits.maximum_log_bytes),
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def run_bounded_process(
    command: list[str],
    environment: dict[str, str],
    output: Path,
    *,
    timeout: int,
) -> int:
    with output.open("wb") as stream:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            preexec_fn=bound_child_resources,
            start_new_session=True,
            close_fds=True,
        )
        try:
            result = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=Limits.pause_timeout_seconds)
            raise OracleError(
                f"subprocess exceeded its {timeout}-second timeout: {command[0]}"
            ) from error
    deadline = time.monotonic() + Limits.subprocess_cleanup_seconds
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            os.killpg(process.pid, signal.SIGKILL)
            raise OracleError(f"subprocess left a live process group: {command[0]}")
        time.sleep(0.01)
    return result


def copy_program(root: Path, source: Path, destination: str) -> None:
    target = root / validate_absolute_path(destination).lstrip("/")
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_file():
            raise OracleError(f"fixture program destination is unsafe: {target}")
        return
    resolved = source.resolve(strict=True)
    data = read_regular(resolved, Limits.maximum_archive_bytes)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resolved, target)
    if data.startswith(b"#!"):
        interpreter = shlex.split(data.split(b"\n", 1)[0][2:].decode())[0]
        validate_absolute_path(interpreter)
        copy_program(root, Path(interpreter), interpreter)
        return

    output = root / "var/log" / (
        ".debz-alternatives-ldd-" + sha256_bytes(os.fsencode(destination)) + ".log"
    )
    try:
        returncode = run_bounded_process(
            ["ldd", str(resolved)],
            dict(ENVIRONMENT),
            output,
            timeout=Limits.dependency_timeout_seconds,
        )
        dependencies = read_regular(output, Limits.maximum_output_bytes).decode(
            errors="backslashreplace"
        )
    finally:
        output.unlink(missing_ok=True)
    static = any(
        message in dependencies
        for message in ("not a dynamic executable", "statically linked")
    )
    if returncode and not static:
        raise OracleError(f"cannot inspect fixture libraries: {source}: {dependencies}")
    if "=> not found" in dependencies:
        raise OracleError(f"missing fixture library: {source}: {dependencies}")
    for name in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", dependencies, re.MULTILINE):
        library = root / validate_absolute_path(name).lstrip("/")
        library.parent.mkdir(parents=True, exist_ok=True)
        resolved_library = Path(name).resolve(strict=True)
        read_regular(resolved_library, Limits.maximum_archive_bytes)
        shutil.copy2(resolved_library, library)


def normalize_output(data: bytes, workspace: Path) -> str:
    if len(data) > Limits.maximum_output_bytes:
        raise OracleError("subprocess output exceeds its byte limit")
    normalized = data.replace(os.fsencode(workspace), b"<workspace>")
    return normalized.decode(errors="backslashreplace")


def normalize_alternatives_log(data: bytes, workspace: Path) -> str:
    if len(data) > Limits.maximum_log_bytes:
        raise OracleError("alternatives log exceeds its byte limit")
    normalized = data.replace(os.fsencode(workspace), b"<workspace>")
    normalized = LOG_CLOCK_PATTERN.sub(b"update-alternatives <clock>:", normalized)
    return normalized.decode(errors="backslashreplace")


def normalize_dpkg_log(data: bytes, workspace: Path) -> str:
    if len(data) > Limits.maximum_log_bytes:
        raise OracleError("dpkg log exceeds its byte limit")
    normalized = data.replace(os.fsencode(workspace), b"<workspace>")
    normalized = DPKG_LOG_CLOCK_PATTERN.sub(b"<clock> ", normalized)
    return normalized.decode(errors="backslashreplace")


def normalize_command(
    command: list[str],
    workspace: Path,
    executable: str,
    label: str,
) -> list[str]:
    selected = []
    for index, argument in enumerate(command):
        if index == 0:
            if argument != executable:
                raise OracleError(f"{label} command did not select its pinned executable")
            selected.append(f"<pinned-{label}>")
        else:
            selected.append(argument.replace(str(workspace), "<workspace>"))
    return selected


def log_delta(path: Path, before: bytes, maximum: int) -> bytes:
    after = optional_regular(path, maximum) or b""
    if not after.startswith(before):
        raise OracleError(f"subprocess log was replaced instead of appended: {path}")
    return after[len(before) :]


def validate_log_clocks(
    data: bytes,
    pattern: re.Pattern[bytes],
    started: int,
    ended: int,
    label: str,
) -> None:
    for match in pattern.finditer(data):
        clock = time.mktime(
            time.strptime(match.group("clock").decode(), "%Y-%m-%d %H:%M:%S")
        )
        if not started / 1_000_000_000 - 2 <= clock <= ended / 1_000_000_000 + 2:
            raise OracleError(f"{label} log timestamp is outside the invocation window")


def update_command(executable: str, root: Path, arguments: list[str]) -> list[str]:
    validate_root(root)
    if len(arguments) > Limits.maximum_arguments:
        raise OracleError("alternatives argument count exceeds its limit")
    for argument in arguments:
        if len(os.fsencode(argument)) > Limits.maximum_argument_bytes or "\x00" in argument:
            raise OracleError("alternatives argument exceeds its byte limit")
    return [
        executable,
        "--root",
        str(root),
        "--log",
        f"/{ALT_LOG}",
        *arguments,
    ]


def run_update(
    executable: str,
    root: Path,
    arguments: list[str],
    environment: dict[str, str],
    output: Path,
    *,
    workspace: Path,
    raw: bool = False,
    preflight: bool = True,
) -> dict[str, Any]:
    if not raw and preflight:
        validate_admin_records(root)
    command = (
        [
            executable,
            "--root",
            str(root),
            "--log",
            f"/{ALT_LOG}",
            *arguments,
        ]
        if raw
        else update_command(executable, root, arguments)
    )
    log_before = optional_regular(root / ALT_LOG, Limits.maximum_log_bytes) or b""
    started = time.time_ns()
    returncode = run_bounded_process(
        command,
        environment,
        output,
        timeout=Limits.subprocess_timeout_seconds,
    )
    ended = time.time_ns()
    data = read_regular(output, Limits.maximum_output_bytes)
    if returncode not in (0, 2):
        raise OracleError(
            f"update-alternatives exited unexpectedly: {returncode}; {output}"
        )
    log = log_delta(root / ALT_LOG, log_before, Limits.maximum_log_bytes)
    validate_log_clocks(log, LOG_CLOCK_PATTERN, started, ended, "alternatives")
    return {
        "command": normalize_command(
            command,
            workspace,
            executable,
            "update-alternatives",
        ),
        "exit": returncode,
        "output": normalize_output(data, workspace),
        "log": normalize_alternatives_log(log, workspace),
    }


def map_absolute(root: Path, value: str) -> Path:
    return root / validate_absolute_path(value).lstrip("/")


def write_target(root: Path, value: str, content: bytes) -> None:
    path = map_absolute(root, value)
    path.parent.mkdir(parents=True, exist_ok=True)
    m.write(path, content, 0o755)


def regular_fact(
    path: Path,
    maximum: int = Limits.maximum_record_bytes,
) -> dict[str, Any]:
    data = read_regular(path, maximum)
    metadata = path.lstat()
    return {
        "bytes_base64": base64.b64encode(data).decode(),
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "sha256": sha256_bytes(data),
        "size": len(data),
        "uid": metadata.st_uid,
    }


def symlink_fact(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISLNK(metadata.st_mode):
        raise OracleError(f"expected alternatives symlink: {path}")
    target = os.readlink(path)
    if len(os.fsencode(target)) > Limits.maximum_path_bytes:
        raise OracleError(f"alternatives symlink target exceeds its limit: {path}")
    return {
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "target": target,
        "uid": metadata.st_uid,
    }


def optional_path_fact(path: Path) -> dict[str, Any] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISREG(metadata.st_mode) and not path.is_symlink():
        return {"kind": "regular", **regular_fact(path)}
    if stat.S_ISLNK(metadata.st_mode):
        return {"kind": "symlink", **symlink_fact(path)}
    return {
        "gid": metadata.st_gid,
        "kind": (
            "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "fifo"
            if stat.S_ISFIFO(metadata.st_mode)
            else "special"
        ),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
    }


def group_state(
    root: Path,
    name: str,
    generic_paths: list[str],
) -> dict[str, Any]:
    validate_name(name)
    record_path = root / "var/lib/dpkg/alternatives" / name
    selectors = []
    alt_dir = root / "etc/alternatives"
    for entry in bounded_scandir(alt_dir, Limits.maximum_linked_entries):
        if entry.name == "README":
            continue
        fact = optional_path_fact(Path(entry.path))
        selectors.append({"name": entry.name, "fact": fact})
    return {
        "generic_links": [
            {"path": path, "fact": optional_path_fact(map_absolute(root, path))}
            for path in generic_paths
        ],
        "record": optional_path_fact(record_path),
        "selectors": selectors,
    }


def install_arguments(
    group: dict[str, Any],
    *,
    priority: int,
) -> list[str]:
    master = next(link for link in group["links"] if link["relationship"] == "master")
    arguments = [
        "--install",
        f"/{master['link_path']}",
        group["name"],
        master["selector_target"],
        str(priority),
    ]
    for link in group["links"]:
        if link["relationship"] == "slave":
            arguments += [
                "--slave",
                f"/{link['link_path']}",
                PurePosixPath(link["selector_path"]).name,
                link["selector_target"],
            ]
    return arguments


def observe_vendor_projection(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
    derived: dict[str, Any],
) -> dict[str, Any]:
    directory = workspace / "vendor-projection"
    directory.mkdir()
    root = directory / "root"
    make_root(root, architecture)
    (root / "bin").symlink_to("usr/bin")
    alternatives = derived["alternatives"]
    requested = {item["path"] for item in alternatives["requested_paths"]}
    for relative in sorted(requested, key=os.fsencode):
        if relative.startswith("etc/alternatives/"):
            continue
        if any(
            relative == link["link_path"]
            for group in alternatives["groups"]
            for link in group["links"]
        ):
            continue
        path = root / relative
        if not os.path.lexists(path):
            path.parent.mkdir(parents=True, exist_ok=True)
            m.write(path, f"synthetic target:{relative}\n".encode(), 0o755)
    readme = root / "etc/alternatives/README"
    m.write(readme, b"synthetic inert alternatives readme\n")

    observations = []
    for index, group in enumerate(alternatives["groups"]):
        result = run_update(
            executable,
            root,
            install_arguments(group, priority=50),
            environment,
            directory / f"{index:02}-{group['name']}.log",
            workspace=workspace,
        )
        generic_paths = [f"/{link['link_path']}" for link in group["links"]]
        state = group_state(root, group["name"], generic_paths)
        if result["exit"] != 0 or state["record"] is None:
            raise OracleError(f"vendor group projection failed: {group['name']}")
        observations.append(
            {
                "result": result,
                "name": group["name"],
                "record": state["record"],
                "generic_links": state["generic_links"],
                "selectors": [
                    item
                    for item in state["selectors"]
                    if item["name"]
                    in {
                        PurePosixPath(link["selector_path"]).name
                        for link in group["links"]
                    }
                ],
            }
        )

    missing = sorted(
        relative for relative in requested if not os.path.lexists(root / relative)
    )
    if missing:
        raise OracleError(f"vendor requested paths were not materialized: {missing[:5]}")
    observed_links = {
        entry["identity"]: entry
        for entry in alternatives["linked_entries"]
        if entry["kind"] == "symlink"
    }
    for group in alternatives["groups"]:
        for link in group["links"]:
            for relative, expected in (
                (link["link_path"], f"/{link['selector_path']}"),
                (link["selector_path"], link["selector_target"]),
            ):
                fact = symlink_fact(root / relative)
                if fact["target"] != expected:
                    raise OracleError(
                        f"synthetic vendor topology differs at {relative}: {fact}"
                    )
                linked_identity = (
                    f"usr/{relative}" if relative.startswith("bin/") else relative
                )
                vendor = observed_links.get(linked_identity)
                if vendor is None:
                    raise OracleError(
                        f"vendor linked topology lost {relative} ({linked_identity})"
                    )
                if all(
                    architecture_fact["target"] != expected
                    for architecture_fact in vendor["architectures"].values()
                ):
                    raise OracleError(f"vendor selector target changed at {relative}")
    return {
        "group_count": len(observations),
        "groups": observations,
        "relationship_count": sum(
            len(group["links"]) for group in alternatives["groups"]
        ),
        "requested_path_count": len(requested),
        "requested_paths_sha256": sha256_bytes(
            canonical_json(sorted(requested, key=os.fsencode)).encode()
        ),
        "timestamp_contract": {
            "log": "local CLOCK_REALTIME seconds within invocation",
            "records": "filesystem clock at atomic rename",
            "symlinks": "whole-second invocation time set by update-alternatives",
        },
    }


def choice_state(root: Path) -> dict[str, Any]:
    return group_state(
        root,
        "debz-choice",
        ["/usr/bin/debz-choice", "/usr/share/man/man1/debz-choice.1"],
    )


def observe_selection(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
) -> dict[str, Any]:
    directory = workspace / "selection"
    directory.mkdir()
    root = directory / "root"
    make_root(root, architecture)
    for name in ("a", "b", "c"):
        write_target(root, f"/usr/lib/debz-choice/{name}", f"{name}\n".encode())
        write_target(
            root,
            f"/usr/share/man/man1/debz-choice-{name}.1",
            f"{name} manual\n".encode(),
        )
    steps: list[dict[str, Any]] = []

    def run(label: str, arguments: list[str]) -> None:
        result = run_update(
            executable,
            root,
            arguments,
            environment,
            directory / f"{len(steps):02}-{label}.log",
            workspace=workspace,
        )
        steps.append({"operation": label, "result": result, "state": choice_state(root)})

    def install(name: str, priority: int) -> list[str]:
        return [
            "--install",
            "/usr/bin/debz-choice",
            "debz-choice",
            f"/usr/lib/debz-choice/{name}",
            str(priority),
            "--slave",
            "/usr/share/man/man1/debz-choice.1",
            "debz-choice.1",
            f"/usr/share/man/man1/debz-choice-{name}.1",
        ]

    run("install-b-10", install("b", 10))
    run("install-a-10-tie", install("a", 10))
    run("install-c-20", install("c", 20))
    run("set-a-manual", ["--set", "debz-choice", "/usr/lib/debz-choice/a"])
    run("raise-c-30-manual-sticks", install("c", 30))
    run("auto-selects-c", ["--auto", "debz-choice"])
    run("remove-c-tie-selects-a", ["--remove", "debz-choice", "/usr/lib/debz-choice/c"])
    run("remove-a-selects-b", ["--remove", "debz-choice", "/usr/lib/debz-choice/a"])
    run("remove-all", ["--remove-all", "debz-choice"])
    return {"steps": steps}


def observe_missing_and_group_shape(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
) -> dict[str, Any]:
    directory = workspace / "missing-shape"
    directory.mkdir()
    root = directory / "root"
    make_root(root, architecture)
    write_target(root, "/usr/lib/debz-missing/present", b"present\n")
    write_target(root, "/usr/lib/debz-missing/second", b"second\n")
    write_target(
        root,
        "/usr/share/man/man1/debz-missing-second.1",
        b"second manual\n",
    )
    steps = []

    def run(label: str, arguments: list[str], paths: list[str]) -> None:
        result = run_update(
            executable,
            root,
            arguments,
            environment,
            directory / f"{len(steps):02}-{label}.log",
            workspace=workspace,
        )
        steps.append(
            {
                "operation": label,
                "result": result,
                "state": group_state(root, "debz-missing", paths),
            }
        )

    paths = ["/usr/bin/debz-missing", "/usr/share/man/man1/debz-missing.1"]
    run(
        "install-missing-high",
        [
            "--install",
            paths[0],
            "debz-missing",
            "/usr/lib/debz-missing/absent",
            "50",
            "--slave",
            paths[1],
            "debz-missing.1",
            "/usr/share/man/man1/debz-missing-absent.1",
        ],
        paths,
    )
    run(
        "install-present-low",
        [
            "--install",
            paths[0],
            "debz-missing",
            "/usr/lib/debz-missing/present",
            "10",
        ],
        paths,
    )
    run(
        "reregister-present-with-missing-slave",
        [
            "--install",
            paths[0],
            "debz-missing",
            "/usr/lib/debz-missing/present",
            "10",
            "--slave",
            paths[1],
            "debz-missing.1",
            "/usr/share/man/man1/debz-missing-absent.1",
        ],
        paths,
    )
    run(
        "install-second-with-slave",
        [
            "--install",
            paths[0],
            "debz-missing",
            "/usr/lib/debz-missing/second",
            "20",
            "--slave",
            paths[1],
            "debz-missing.1",
            "/usr/share/man/man1/debz-missing-second.1",
        ],
        paths,
    )
    run(
        "reregister-selected-without-slave",
        [
            "--install",
            paths[0],
            "debz-missing",
            "/usr/lib/debz-missing/second",
            "20",
        ],
        paths,
    )
    (root / "usr/lib/debz-missing/second").unlink()
    run("query-prunes-missing-selected", ["--query", "debz-missing"], paths)
    present = root / "usr/lib/debz-missing/present"
    present.unlink()
    run("auto-with-all-targets-missing", ["--auto", "debz-missing"], paths)
    return {"steps": steps}


def malformed_result(
    executable: str,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    label: str,
    content: bytes,
) -> dict[str, Any]:
    directory = workspace / "malformed" / label
    directory.mkdir(parents=True)
    root = directory / "root"
    make_root(root, architecture)
    write_target(root, "/usr/lib/bad", b"bad\n")
    m.write(root / "var/lib/dpkg/alternatives/bad", content)
    result = run_update(
        executable,
        root,
        ["--query", "bad"],
        environment,
        directory / "query.log",
        workspace=workspace,
    )
    return {
        "case": label,
        "input": {
            "sha256": sha256_bytes(content),
            "size": len(content),
        },
        "result": result,
        "state": group_state(root, "bad", ["/usr/bin/bad"]),
    }


def observe_malformed(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
) -> dict[str, Any]:
    cases = [
        malformed_result(executable, workspace, environment, architecture, label, content)
        for label, content in (
            ("empty", b""),
            ("truncated", b"auto\n/usr/bin/bad\n"),
            ("invalid-mode", b"invalid\n/usr/bin/bad\n\n"),
            (
                "invalid-priority",
                b"auto\n/usr/bin/bad\n\n/usr/lib/bad\nnot-a-number\n\n",
            ),
            ("embedded-nul", b"auto\n/usr/bin/bad\x00suffix\n\n"),
        )
    ]
    preflight = workspace / "malformed" / "preflight"
    preflight.mkdir()
    rejections = []
    for label, create in (
        ("directory", lambda path: path.mkdir()),
        ("symlink", lambda path: path.symlink_to("target")),
        ("fifo", os.mkfifo),
    ):
        root = preflight / label
        make_root(root, architecture)
        record = root / "var/lib/dpkg/alternatives/bad"
        create(record)
        try:
            validate_admin_records(root)
        except OracleError as error:
            rejections.append({"case": label, "error": str(error)})
        else:
            raise OracleError(f"non-regular alternatives record was accepted: {label}")
    root = preflight / "oversized"
    make_root(root, architecture)
    m.write(
        root / "var/lib/dpkg/alternatives/bad",
        b"x" * (Limits.maximum_record_bytes + 1),
    )
    try:
        validate_admin_records(root)
    except OracleError as error:
        rejections.append({"case": "oversized", "error": str(error)})
    else:
        raise OracleError("oversized alternatives record was accepted")
    return {"regular_record_cases": cases, "oracle_preflight_rejections": rejections}


def observe_attacks(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
) -> dict[str, Any]:
    results = []
    for value in ("/../escape", "/usr/bin/../escape", "relative", "/", "/a//b"):
        try:
            validate_absolute_path(value)
        except OracleError as error:
            results.append({"case": f"path:{value}", "error": str(error)})
        else:
            raise OracleError(f"unsafe attack path was accepted: {value}")
    for value in ("../escape", "a/b", ".hidden", "A", ""):
        try:
            validate_name(value)
        except OracleError as error:
            results.append({"case": f"name:{value}", "error": str(error)})
        else:
            raise OracleError(f"unsafe attack name was accepted: {value}")

    raw_cases = []
    directory = workspace / "attacks"
    directory.mkdir()

    root = directory / "traversal-root"
    make_root(root, architecture)
    write_target(root, "/usr/lib/provider", b"provider\n")
    result = run_update(
        executable,
        root,
        ["--install", "/../escaped-link", "escape", "/usr/lib/provider", "10"],
        environment,
        directory / "traversal.log",
        workspace=workspace,
        raw=True,
    )
    raw_cases.append(
        {
            "case": "generic-link-traversal",
            "result": result,
            "outside_root": optional_path_fact(directory / "escaped-link"),
            "record": optional_path_fact(root / "var/lib/dpkg/alternatives/escape"),
        }
    )

    root = directory / "symlink-root"
    make_root(root, architecture)
    escaped = directory / "escaped-alt"
    escaped.mkdir()
    (root / "etc/alternatives").rmdir()
    (root / "etc/alternatives").symlink_to(escaped)
    write_target(root, "/usr/lib/provider", b"provider\n")
    result = run_update(
        executable,
        root,
        ["--install", "/usr/bin/escape", "escape", "/usr/lib/provider", "10"],
        environment,
        directory / "symlink.log",
        workspace=workspace,
        raw=True,
    )
    raw_cases.append(
        {
            "case": "alternatives-directory-symlink",
            "result": result,
            "outside_root": optional_path_fact(escaped / "escape"),
            "generic": optional_path_fact(root / "usr/bin/escape"),
        }
    )

    root = directory / "cycle-root"
    make_root(root, architecture)
    result = run_update(
        executable,
        root,
        ["--install", "/usr/bin/cycle", "cycle", "/usr/bin/cycle", "10"],
        environment,
        directory / "cycle.log",
        workspace=workspace,
        raw=True,
    )
    raw_cases.append(
        {
            "case": "self-referential-provider",
            "result": result,
            "state": group_state(root, "cycle", ["/usr/bin/cycle"]),
        }
    )

    root = directory / "indirect-cycle-root"
    make_root(root, architecture)
    write_target(root, "/usr/lib/cycle-provider", b"provider\n")
    setup_result = run_update(
        executable,
        root,
        [
            "--install",
            "/usr/bin/cycle-link",
            "cycle-link",
            "/usr/lib/cycle-provider",
            "10",
        ],
        environment,
        directory / "indirect-cycle-install.log",
        workspace=workspace,
    )
    provider = root / "usr/lib/cycle-provider"
    provider.unlink()
    provider.symlink_to("/usr/bin/cycle-link")
    result = run_update(
        executable,
        root,
        ["--query", "cycle-link"],
        environment,
        directory / "indirect-cycle-query.log",
        workspace=workspace,
    )
    raw_cases.append(
        {
            "case": "indirect-symlink-cycle",
            "setup_result": setup_result,
            "result": result,
            "provider": optional_path_fact(provider),
            "state": group_state(root, "cycle-link", ["/usr/bin/cycle-link"]),
        }
    )
    return {"oracle_rejections": results, "raw_tool_cases": raw_cases}


def observe_atomicity(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
) -> dict[str, Any]:
    results = []
    directory = workspace / "atomicity"
    directory.mkdir()
    for label, blocker in (
        ("database-temporary-blocked", "var/lib/dpkg/alternatives/atomic.dpkg-tmp"),
        ("selector-temporary-blocked", "etc/alternatives/atomic.dpkg-tmp"),
        ("generic-temporary-blocked", "usr/bin/atomic.dpkg-tmp"),
    ):
        root = directory / label
        make_root(root, architecture)
        write_target(root, "/usr/lib/atomic-provider", b"provider\n")
        (root / blocker).mkdir(parents=True)
        result = run_update(
            executable,
            root,
            ["--install", "/usr/bin/atomic", "atomic", "/usr/lib/atomic-provider", "10"],
            environment,
            directory / f"{label}.log",
            workspace=workspace,
            preflight=False,
        )
        results.append(
            {
                "case": label,
                "result": result,
                "state": group_state(root, "atomic", ["/usr/bin/atomic"]),
                "blocker": optional_path_fact(root / blocker),
            }
        )
    return {"failure_injection": results}


def alternatives_member(version: str) -> bytes:
    return f"opaque alternatives metadata {version}\n".encode() + b"\x00\xff"


def package_scripts(
    package: str,
    version: str,
    group: str,
    priority: int,
) -> dict[str, bytes]:
    candidate = f"/usr/lib/debz-alternatives/{package}-{version}"
    manual = f"/usr/share/man/man1/{package}-{version}.1"
    scripts = {}
    for kind in ("preinst", "postinst", "prerm", "postrm"):
        action = ""
        if kind == "postinst":
            action = f"""
case "$1" in
    configure|abort-upgrade|abort-remove|abort-deconfigure)
        /usr/bin/update-alternatives --install /usr/bin/{group} {group} {candidate} {priority} \
            --slave /usr/share/man/man1/{group}.1 {group}.1 {manual}
        ;;
esac
"""
        elif kind == "prerm":
            action = f"""
case "$1" in
    remove|upgrade|deconfigure)
        /usr/bin/update-alternatives --remove {group} {candidate}
        ;;
esac
"""
        identity = f"{package}@{version}:{kind}"
        scripts[kind] = f"""#!/bin/sh
if [ "${{DEBCONF_DB_FALLBACK+x}}" = x ] ||
   [ "${{DEBCONF_DB_OVERRIDE+x}}" = x ] ||
   [ "${{DEBCONF_DEBUG+x}}" = x ] ||
   [ "${{DEBIAN_FRONTEND+x}}" = x ]; then
    exit 24
fi
fds=''
for fd in 0 1 2 3 4 5 6 7 8 9; do
    if ( eval ": <&$fd" ) 2>> /{FD_ERRORS}; then
        if [ -n "$fds" ]; then fds="$fds,"; fi
        fds="$fds$fd"
    fi
done
printf '%s\\t%d' '{identity}' "$#" >> /{TRACE}
for argument do
    printf '\\t%d:%s' "${{#argument}}" "$argument" >> /{TRACE}
done
printf '\\tcwd=%s\\tfds=%s\\n' "$PWD" "$fds" >> /{TRACE}
{action}
marker='{identity}:'"$1"
if [ -f /{PAUSE} ]; then
    IFS= read -r selected < /{PAUSE}
    if [ "$selected" = "$marker" ]; then
        printf '%s\\n' "$marker" > /{PAUSED}
        /bin/sleep 30
    fi
fi
if [ -f /{FAILURES} ]; then
    IFS= read -r selected < /{FAILURES}
    if [ "$selected" = "$marker" ]; then
        exit 23
    fi
fi
exit 0
""".encode()
    return scripts


def make_package(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    package: str,
    version: str,
    group: str,
    priority: int,
    *,
    scripted: bool = True,
) -> Path:
    candidate = f"usr/lib/debz-alternatives/{package}-{version}"
    manual = f"usr/share/man/man1/{package}-{version}.1"

    def prepare(source: Path) -> None:
        m.write(source / "DEBIAN/alternatives", alternatives_member(version), 0o640)

    return m.make_package(
        workspace,
        environment,
        architecture,
        version,
        package=package,
        extra_files={
            candidate: f"provider {package} {version}\n".encode(),
            manual: f"manual {package} {version}\n".encode(),
        },
        scripts=(
            package_scripts(package, version, group, priority)
            if scripted
            else None
        ),
        prepare_payload=prepare,
        archive_builder=config.build_package_archive,
    )


def prepare_dpkg_root(
    root: Path,
    architecture: str,
    update_alternatives: str,
) -> None:
    make_root(root, architecture, dpkg_runtime=True)
    copy_program(
        root,
        Path(update_alternatives),
        "/usr/bin/update-alternatives",
    )
    copied = root / "usr/bin/update-alternatives"
    m.reference_dpkg.verify_file(
        copied,
        m.reference_dpkg.PINS[architecture]["update_alternatives"],
    )
    m.write(root / TRACE, b"")


def package_info(root: Path, package: str) -> list[dict[str, Any]]:
    info = root / "var/lib/dpkg/info"
    selected = []
    total = 0
    prefix = package + "."
    for entry in bounded_scandir(info, Limits.maximum_info_files + 1):
        if not entry.name.startswith(prefix):
            continue
        fact = regular_fact(Path(entry.path))
        total += fact["size"]
        if total > Limits.maximum_info_bytes:
            raise OracleError("package info bytes exceed their aggregate limit")
        selected.append({"name": entry.name.removeprefix(prefix), **fact})
    if len(selected) > Limits.maximum_info_files:
        raise OracleError("package info count exceeds its limit")
    return selected


def trace_lines(root: Path) -> list[dict[str, Any]]:
    data = read_regular(root / TRACE, Limits.maximum_output_bytes)
    lines = data.decode().splitlines()
    if len(lines) > 128:
        raise OracleError("maintainer-script trace exceeds its record limit")
    records = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 4:
            raise OracleError(f"malformed alternatives script trace: {line!r}")
        try:
            count = int(fields[1])
        except ValueError as error:
            raise OracleError("invalid alternatives script argument count") from error
        if count > Limits.maximum_arguments or len(fields) != count + 4:
            raise OracleError("alternatives script argument bounds changed")
        arguments = []
        for field in fields[2 : 2 + count]:
            length, separator, value = field.partition(":")
            if (
                not separator
                or not length.isdigit()
                or int(length) != len(value)
                or len(os.fsencode(value)) > Limits.maximum_argument_bytes
            ):
                raise OracleError("malformed alternatives script argument")
            arguments.append(value)
        attributes = {}
        for field in fields[2 + count :]:
            name, separator, value = field.partition("=")
            if not separator or name in attributes:
                raise OracleError("malformed alternatives script trace attributes")
            attributes[name] = value
        if attributes != {"cwd": "/", "fds": "0,1,2"}:
            raise OracleError(
                f"alternatives script cwd/fd contract changed: {attributes}"
            )
        records.append(
            {
                "script": fields[0],
                "arguments": arguments,
            }
        )
    errors = optional_regular(root / FD_ERRORS, Limits.maximum_output_bytes)
    if errors is not None and len(errors) > Limits.maximum_output_bytes:
        raise OracleError("alternatives script fd probe exceeded its byte limit")
    return records


def bounded_tree_facts(
    root: Path,
    bases: tuple[str, ...],
    *,
    maximum_files: int,
    maximum_bytes: int,
    excluded: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    selected = []
    total = 0
    visited = 0

    def visit(directory: Path) -> None:
        nonlocal total, visited
        for entry in bounded_scandir(directory, maximum_files - visited):
            visited += 1
            item = Path(entry.path)
            relative = item.relative_to(root).as_posix()
            if any(
                relative == prefix or relative.startswith(prefix + "/")
                for prefix in excluded
            ):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not entry.is_symlink():
                visit(item)
                continue
            fact = optional_path_fact(item)
            if fact is None:
                raise OracleError(f"observed fixture file disappeared: {item}")
            if fact["kind"] == "regular":
                total += fact["size"]
            if total > maximum_bytes:
                raise OracleError("observed fixture tree exceeds its byte limit")
            selected.append({"path": relative, "fact": fact})
            if len(selected) > maximum_files:
                raise OracleError("observed fixture tree exceeds its file limit")

    for base in bases:
        path = root / base
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise OracleError(f"observed fixture tree is not a real directory: {path}")
        visit(path)
    return selected


def database_files(root: Path) -> list[dict[str, Any]]:
    return bounded_tree_facts(
        root,
        ("var/lib/dpkg",),
        maximum_files=Limits.maximum_database_files,
        maximum_bytes=Limits.maximum_database_bytes,
        excluded=("var/lib/dpkg/alternatives", "var/lib/dpkg/info"),
    )


def all_info_files(root: Path) -> list[dict[str, Any]]:
    return bounded_tree_facts(
        root,
        ("var/lib/dpkg/info",),
        maximum_files=Limits.maximum_database_files,
        maximum_bytes=Limits.maximum_info_bytes,
    )


def payload_files(root: Path) -> list[dict[str, Any]]:
    return bounded_tree_facts(
        root,
        ("usr/lib/debz-alternatives", "usr/share/man/man1"),
        maximum_files=Limits.maximum_payload_files,
        maximum_bytes=Limits.maximum_payload_bytes,
    )


def dpkg_state(root: Path, package: str, group: str) -> dict[str, Any]:
    return {
        "all_info": all_info_files(root),
        "alternatives": group_state(
            root,
            group,
            [f"/usr/bin/{group}", f"/usr/share/man/man1/{group}.1"],
        ),
        "database": config.database_state(root, package),
        "database_files": database_files(root),
        "info": package_info(root, package),
        "payload": payload_files(root),
        "trace": trace_lines(root),
    }


def run_dpkg(
    executable: str,
    root: Path,
    arguments: list[str],
    environment: dict[str, str],
    output: Path,
    *,
    workspace: Path,
) -> dict[str, Any]:
    validate_root(root)
    if len(arguments) > Limits.maximum_arguments:
        raise OracleError("dpkg argument count exceeds its limit")
    for argument in arguments:
        if "\x00" in argument or len(os.fsencode(argument)) > Limits.maximum_argument_bytes:
            raise OracleError("dpkg argument exceeds its byte limit")
    command = config.direct_dpkg_command(executable, root, arguments)
    log_before = optional_regular(root / DPKG_LOG, Limits.maximum_log_bytes) or b""
    started = time.time_ns()
    returncode = run_bounded_process(
        command,
        environment,
        output,
        timeout=Limits.subprocess_timeout_seconds,
    )
    ended = time.time_ns()
    data = read_regular(output, Limits.maximum_output_bytes)
    if returncode not in (0, 1):
        raise OracleError(f"direct dpkg exited unexpectedly: {returncode}; {output}")
    log = log_delta(root / DPKG_LOG, log_before, Limits.maximum_log_bytes)
    validate_log_clocks(log, DPKG_LOG_CLOCK_PATTERN, started, ended, "dpkg")
    return {
        "command": normalize_command(command, workspace, executable, "dpkg"),
        "exit": returncode,
        "output": normalize_output(data, workspace),
        "log": normalize_dpkg_log(log, workspace),
    }


def set_marker(root: Path, relative: str, value: str | None) -> None:
    path = root / relative
    if value is None:
        if path.exists():
            path.unlink()
    else:
        m.write(path, (value + "\n").encode(), 0o600)


def archive_fact(path: Path) -> dict[str, Any]:
    data = read_regular(path, Limits.maximum_archive_bytes)
    return {"sha256": sha256_bytes(data), "size": len(data)}


def observe_successful_dpkg(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
) -> dict[str, Any]:
    directory = workspace / "dpkg-success"
    directory.mkdir()
    package = "debz-alt-lifecycle"
    group = "debz-alt-lifecycle"
    archives = {
        version: make_package(
            directory / "packages",
            environment,
            architecture,
            package,
            version,
            group,
            10 if version == "1" else 20,
        )
        for version in ("1", "2")
    }
    root = directory / "root"
    prepare_dpkg_root(root, architecture, update_alternatives)
    phases = []
    for label, arguments in (
        ("install", ["--install", str(archives["1"])]),
        ("reinstall", ["--install", str(archives["1"])]),
        ("upgrade", ["--install", str(archives["2"])]),
        ("remove", ["--remove", package]),
        ("purge", ["--purge", package]),
    ):
        result = run_dpkg(
            dpkg,
            root,
            arguments,
            environment,
            directory / f"{label}.log",
            workspace=workspace,
        )
        if result["exit"] != 0:
            raise OracleError(f"successful alternatives lifecycle failed: {label}")
        phases.append(
            {
                "operation": label,
                "result": result,
                "state": dpkg_state(root, package, group),
            }
        )
    return {
        "archives": {
            version: archive_fact(path) for version, path in archives.items()
        },
        "phases": phases,
    }


def observe_scriptless_member(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
) -> dict[str, Any]:
    directory = workspace / "dpkg-scriptless"
    directory.mkdir()
    package = "debz-alt-metadata"
    group = "debz-alt-metadata"
    archive = make_package(
        directory / "packages",
        environment,
        architecture,
        package,
        "1",
        group,
        10,
        scripted=False,
    )
    root = directory / "root"
    prepare_dpkg_root(root, architecture, update_alternatives)
    result = run_dpkg(
        dpkg,
        root,
        ["--install", str(archive)],
        environment,
        directory / "install.log",
        workspace=workspace,
    )
    if result["exit"] != 0:
        raise OracleError("scriptless alternatives-member install failed")
    installed = dpkg_state(root, package, group)
    if installed["alternatives"]["record"] is not None:
        raise OracleError("direct dpkg interpreted a scriptless alternatives member")
    result_remove = run_dpkg(
        dpkg,
        root,
        ["--remove", package],
        environment,
        directory / "remove.log",
        workspace=workspace,
    )
    if result_remove["exit"] != 0:
        raise OracleError("scriptless alternatives-member removal failed")
    removed = dpkg_state(root, package, group)
    result_purge = run_dpkg(
        dpkg,
        root,
        ["--purge", package],
        environment,
        directory / "purge.log",
        workspace=workspace,
    )
    if result_purge["exit"] != 0:
        raise OracleError("scriptless alternatives-member purge failed")
    purged = dpkg_state(root, package, group)
    return {
        "archive": archive_fact(archive),
        "install_result": result,
        "installed": installed,
        "remove_result": result_remove,
        "removed": removed,
        "purge_result": result_purge,
        "purged": purged,
    }


def observe_conflicting_providers(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
) -> dict[str, Any]:
    directory = workspace / "dpkg-providers"
    directory.mkdir()
    group = "debz-alt-provider"
    packages = (("debz-alt-provider-a", 10), ("debz-alt-provider-b", 20))
    archives = {
        package: make_package(
            directory / "packages",
            environment,
            architecture,
            package,
            "1",
            group,
            priority,
        )
        for package, priority in packages
    }
    root = directory / "root"
    prepare_dpkg_root(root, architecture, update_alternatives)
    phases = []
    for label, arguments, observed_package in (
        ("install-a", ["--install", str(archives[packages[0][0]])], packages[0][0]),
        ("install-b", ["--install", str(archives[packages[1][0]])], packages[1][0]),
        ("remove-b", ["--remove", packages[1][0]], packages[1][0]),
        ("purge-a", ["--purge", packages[0][0]], packages[0][0]),
    ):
        result = run_dpkg(
            dpkg,
            root,
            arguments,
            environment,
            directory / f"{label}.log",
            workspace=workspace,
        )
        if result["exit"] != 0:
            raise OracleError(f"conflicting-provider lifecycle failed: {label}")
        phases.append(
            {
                "operation": label,
                "result": result,
                "package": config.database_state(root, observed_package),
                "all_info": all_info_files(root),
                "database_files": database_files(root),
                "info": package_info(root, observed_package),
                "payload": payload_files(root),
                "alternatives": group_state(
                    root,
                    group,
                    [f"/usr/bin/{group}", f"/usr/share/man/man1/{group}.1"],
                ),
                "trace": trace_lines(root),
            }
        )
    return {
        "archives": {
            package: archive_fact(archive) for package, archive in archives.items()
        },
        "phases": phases,
    }


def observe_conflicting_packages(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
) -> dict[str, Any]:
    directory = workspace / "dpkg-package-conflict"
    directory.mkdir()
    shared = "usr/lib/debz-alternatives/package-conflict"

    def build(package: str, content: bytes) -> Path:
        def prepare(source: Path) -> None:
            m.write(source / "DEBIAN/alternatives", b"opaque conflict metadata\n")

        return m.make_package(
            directory / "packages",
            environment,
            architecture,
            "1",
            package=package,
            extra_files={shared: content},
            prepare_payload=prepare,
            archive_builder=config.build_package_archive,
        )

    first_name = "debz-alt-conflict-a"
    second_name = "debz-alt-conflict-b"
    first = build(first_name, b"first owner\n")
    second = build(second_name, b"second owner\n")
    root = directory / "root"
    prepare_dpkg_root(root, architecture, update_alternatives)
    first_result = run_dpkg(
        dpkg,
        root,
        ["--install", str(first)],
        environment,
        directory / "first.log",
        workspace=workspace,
    )
    if first_result["exit"] != 0:
        raise OracleError("failed to seed package file-conflict case")
    second_log = directory / "second.log"
    second_result = run_dpkg(
        dpkg,
        root,
        ["--install", str(second)],
        environment,
        second_log,
        workspace=workspace,
    )
    if second_result["exit"] != 1:
        raise OracleError("conflicting package payload did not fail")
    shared_fact = regular_fact(root / shared)
    if base64.b64decode(shared_fact["bytes_base64"]) != b"first owner\n":
        raise OracleError("package conflict replaced the first owner's bytes")
    second_status = config.package_record(
        read_regular(
            root / "var/lib/dpkg/status",
            config.Limits.maximum_status_bytes,
        ),
        second_name,
        "status",
    )
    return {
        "first_archive": archive_fact(first),
        "first_result": first_result,
        "first_state": config.database_state(root, first_name),
        "second_archive": archive_fact(second),
        "second_result": second_result,
        "second_status": second_status,
        "shared_file": {
            "path": shared,
            "fact": {"kind": "regular", **shared_fact},
        },
        "database_files": database_files(root),
        "all_info": all_info_files(root),
        "payload": payload_files(root),
    }


def failure_case(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
    case: str,
) -> dict[str, Any]:
    directory = workspace / "dpkg-failures" / case
    directory.mkdir(parents=True)
    package = f"debz-alt-{case}"
    group = package
    archives = {
        version: make_package(
            directory / "packages",
            environment,
            architecture,
            package,
            version,
            group,
            10 if version == "1" else 20,
        )
        for version in ("1", "2")
    }
    root = directory / "root"
    prepare_dpkg_root(root, architecture, update_alternatives)
    seed_result = None
    if case != "fresh-postinst":
        seed_result = run_dpkg(
            dpkg,
            root,
            ["--install", str(archives["1"])],
            environment,
            directory / "seed.log",
            workspace=workspace,
        )
        if seed_result["exit"]:
            raise OracleError(f"failed to seed alternatives failure case: {case}")
        m.write(root / TRACE, b"")

    if case == "fresh-postinst":
        marker = f"{package}@1:postinst:configure"
        operation = ["--install", str(archives["1"])]
        recovery = ["--configure", package]
    elif case == "upgrade-prerm":
        marker = f"{package}@1:prerm:upgrade"
        operation = ["--install", str(archives["2"])]
        recovery = ["--install", str(archives["2"])]
    elif case == "upgrade-postinst":
        marker = f"{package}@2:postinst:configure"
        operation = ["--install", str(archives["2"])]
        recovery = ["--configure", package]
    elif case == "remove-postrm":
        marker = f"{package}@1:postrm:remove"
        operation = ["--remove", package]
        recovery = ["--remove", package]
    else:
        raise OracleError(f"unknown dpkg alternatives failure case: {case}")
    set_marker(root, FAILURES, marker)
    operation_result = run_dpkg(
        dpkg,
        root,
        operation,
        environment,
        directory / "failed.log",
        workspace=workspace,
    )
    expected_failed_exit = 0 if case == "upgrade-prerm" else 1
    if operation_result["exit"] != expected_failed_exit:
        raise OracleError(
            f"dpkg failure case exit changed: {case}: "
            f"{operation_result['exit']} != {expected_failed_exit}"
        )
    failed = dpkg_state(root, package, group)
    set_marker(root, FAILURES, None)
    recovery_result = run_dpkg(
        dpkg,
        root,
        recovery,
        environment,
        directory / "recovery.log",
        workspace=workspace,
    )
    if recovery_result["exit"] != 0:
        raise OracleError(f"dpkg failure recovery did not settle: {case}")
    recovered = dpkg_state(root, package, group)
    return {
        "archives": {
            version: archive_fact(path) for version, path in archives.items()
        },
        "case": case,
        "seed_result": seed_result,
        "operation_result": operation_result,
        "failed": failed,
        "recovery_result": recovery_result,
        "recovered": recovered,
    }


def interrupt_dpkg(
    executable: str,
    root: Path,
    arguments: list[str],
    environment: dict[str, str],
    output: Path,
    marker: str,
    *,
    workspace: Path,
) -> dict[str, Any]:
    set_marker(root, PAUSE, marker)
    command = config.direct_dpkg_command(executable, root, arguments)
    log_before = optional_regular(root / DPKG_LOG, Limits.maximum_log_bytes) or b""
    started = time.time_ns()
    with output.open("wb") as stream:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            preexec_fn=bound_child_resources,
            start_new_session=True,
            close_fds=True,
        )
        deadline = time.monotonic() + Limits.pause_timeout_seconds
        while time.monotonic() < deadline:
            if optional_regular(root / PAUSED, 256) is not None:
                break
            if process.poll() is not None:
                raise OracleError("dpkg exited before alternatives interruption")
            time.sleep(0.05)
        else:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=Limits.pause_timeout_seconds)
            raise OracleError("dpkg did not reach alternatives interruption")
        os.killpg(process.pid, signal.SIGKILL)
        result = process.wait(timeout=Limits.pause_timeout_seconds)
    ended = time.time_ns()
    if result != -signal.SIGKILL:
        raise OracleError(f"interrupted dpkg returned unexpectedly: {result}")
    data = read_regular(output, Limits.maximum_output_bytes)
    log = log_delta(root / DPKG_LOG, log_before, Limits.maximum_log_bytes)
    validate_log_clocks(log, DPKG_LOG_CLOCK_PATTERN, started, ended, "dpkg")
    set_marker(root, PAUSE, None)
    (root / PAUSED).unlink()
    return {
        "command": normalize_command(command, workspace, executable, "dpkg"),
        "exit": result,
        "output": normalize_output(data, workspace),
        "log": normalize_dpkg_log(log, workspace),
    }


def observe_interruption(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
) -> dict[str, Any]:
    directory = workspace / "dpkg-interruption"
    directory.mkdir()
    package = "debz-alt-interrupted"
    group = package
    archive = make_package(
        directory / "packages",
        environment,
        architecture,
        package,
        "1",
        group,
        10,
    )
    root = directory / "root"
    prepare_dpkg_root(root, architecture, update_alternatives)
    interruption_result = interrupt_dpkg(
        dpkg,
        root,
        ["--install", str(archive)],
        environment,
        directory / "interrupted.log",
        f"{package}@1:postinst:configure",
        workspace=workspace,
    )
    interrupted = dpkg_state(root, package, group)
    recovery_result = run_dpkg(
        dpkg,
        root,
        ["--configure", package],
        environment,
        directory / "recovery.log",
        workspace=workspace,
    )
    if recovery_result["exit"] != 0:
        raise OracleError("interrupted alternatives package did not recover")
    return {
        "archive": archive_fact(archive),
        "interruption_result": interruption_result,
        "interrupted": interrupted,
        "recovery_result": recovery_result,
        "recovered": dpkg_state(root, package, group),
    }


def observe_dpkg(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
) -> dict[str, Any]:
    return {
        "scriptless_alternatives_member": observe_scriptless_member(
            workspace,
            environment,
            architecture,
            dpkg,
            update_alternatives,
        ),
        "successful_lifecycle": observe_successful_dpkg(
            workspace,
            environment,
            architecture,
            dpkg,
            update_alternatives,
        ),
        "conflicting_providers": observe_conflicting_providers(
            workspace,
            environment,
            architecture,
            dpkg,
            update_alternatives,
        ),
        "conflicting_packages": observe_conflicting_packages(
            workspace,
            environment,
            architecture,
            dpkg,
            update_alternatives,
        ),
        "failure_recovery": [
            failure_case(
                workspace,
                environment,
                architecture,
                dpkg,
                update_alternatives,
                case,
            )
            for case in (
                "fresh-postinst",
                "upgrade-prerm",
                "upgrade-postinst",
                "remove-postrm",
            )
        ],
        "interruption_recovery": observe_interruption(
            workspace,
            environment,
            architecture,
            dpkg,
            update_alternatives,
        ),
    }


def observe(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    dpkg: str,
    update_alternatives: str,
    derived: dict[str, Any],
) -> dict[str, Any]:
    return {
        "direct_dpkg": observe_dpkg(
            workspace,
            environment,
            architecture,
            dpkg,
            update_alternatives,
        ),
        "external_update_alternatives": {
            "atomicity": observe_atomicity(
                workspace,
                environment,
                architecture,
                update_alternatives,
            ),
            "malformed_records": observe_malformed(
                workspace,
                environment,
                architecture,
                update_alternatives,
            ),
            "missing_targets_and_group_shape": observe_missing_and_group_shape(
                workspace,
                environment,
                architecture,
                update_alternatives,
            ),
            "path_and_symlink_attacks": observe_attacks(
                workspace,
                environment,
                architecture,
                update_alternatives,
            ),
            "selection": observe_selection(
                workspace,
                environment,
                architecture,
                update_alternatives,
            ),
            "vendor_projection": observe_vendor_projection(
                workspace,
                environment,
                architecture,
                update_alternatives,
                derived,
            ),
        },
        "separation": {
            "ambient_host_alternatives_used": False,
            "dpkg_invokes_update_alternatives_implicitly": False,
            "maintainer_script_updates_are_external_tool_side_effects": True,
            "package_alternatives_member_is_copied_but_not_interpreted": True,
        },
    }


def select_references(
    dpkg_path: Path | None,
    update_path: Path | None,
    architecture: str,
) -> tuple[str, str]:
    prefix = (
        ROOT
        / ".cache/native-dpkg-reference"
        / m.reference_dpkg.VERSION
        / architecture
        / "usr/bin"
    )
    selected_dpkg = dpkg_path or prefix / "dpkg"
    selected_update = update_path or prefix / "update-alternatives"
    if not selected_dpkg.is_file() or not selected_update.is_file():
        raise OracleError(
            "missing pinned references; run python3 tools/prepare-native-dpkg.py "
            "as the build user"
        )
    for path, key in (
        (selected_dpkg, "executable"),
        (selected_update, "update_alternatives"),
    ):
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise OracleError("pinned reference must be an absolute, non-symlink path")
        m.reference_dpkg.verify_file(path, m.reference_dpkg.PINS[architecture][key])
    return str(selected_dpkg), str(selected_update)


def host_path_signature(path: Path) -> tuple[int, int, int, int, int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise OracleError(f"host alternatives path is not a regular file: {path}")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def host_tree_signature(root: Path) -> tuple[int, str] | None:
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise OracleError(f"host isolation path is not a real directory: {root}")
    digest = hashlib.sha256()
    count = 0

    def visit(path: Path, relative: str) -> None:
        nonlocal count
        item = path.lstat()
        count += 1
        if count > Limits.maximum_host_entries:
            raise OracleError(f"host isolation inventory exceeds its limit: {root}")
        digest.update(os.fsencode(relative))
        digest.update(b"\0")
        digest.update(
            (
                f"{item.st_dev}:{item.st_ino}:{item.st_mode}:{item.st_size}:"
                f"{item.st_mtime_ns}:{item.st_ctime_ns}"
            ).encode()
        )
        digest.update(b"\0")
        if stat.S_ISLNK(item.st_mode):
            target = os.readlink(path)
            if len(os.fsencode(target)) > Limits.maximum_path_bytes:
                raise OracleError(f"host symlink target exceeds its limit: {path}")
            digest.update(os.fsencode(target))
        elif stat.S_ISDIR(item.st_mode):
            for entry in bounded_scandir(
                path,
                Limits.maximum_host_entries - count,
            ):
                child = f"{relative}/{entry.name}" if relative else entry.name
                visit(Path(entry.path), child)

    visit(root, "")
    return count, digest.hexdigest()


def host_any_path_signature(path: Path) -> tuple[Any, ...] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    signature: tuple[Any, ...] = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(path)
        if len(os.fsencode(target)) > Limits.maximum_path_bytes:
            raise OracleError(f"host symlink target exceeds its limit: {path}")
        signature += (target,)
    return signature


def host_alternatives_generic_signature() -> list[tuple[str, tuple[Any, ...] | None]]:
    admin = Path("/var/lib/dpkg/alternatives")
    try:
        entries = bounded_scandir(admin, Limits.maximum_host_entries)
    except FileNotFoundError:
        return []
    paths = set()
    total = 0
    for entry in entries:
        path = Path(entry.path)
        data = read_regular(path, Limits.maximum_record_bytes)
        total += len(data)
        if total > Limits.maximum_total_record_bytes:
            raise OracleError("host alternatives records exceed their aggregate limit")
        lines = data.splitlines()
        if len(lines) < 3 or lines[0] not in (b"auto", b"manual"):
            raise OracleError(f"host alternatives record is malformed: {path}")
        index = 1
        paths.add(os.fsdecode(lines[index]))
        index += 1
        while index < len(lines) and lines[index]:
            if index + 1 >= len(lines):
                raise OracleError(f"host alternatives record is truncated: {path}")
            index += 1
            paths.add(os.fsdecode(lines[index]))
            index += 1
    result = []
    for value in sorted(paths, key=os.fsencode):
        validate_absolute_path(value)
        result.append((value, host_any_path_signature(Path(value))))
    return result


def capture_host_state() -> dict[str, Any]:
    return {
        "alternatives_database": host_tree_signature(
            Path("/var/lib/dpkg/alternatives")
        ),
        "alternatives_generic_links": host_alternatives_generic_signature(),
        "alternatives_links": host_tree_signature(Path("/etc/alternatives")),
        "dpkg_config": host_tree_signature(Path("/etc/dpkg")),
        "dpkg_database": host_tree_signature(Path("/var/lib/dpkg")),
        "alternatives_log": host_path_signature(Path("/var/log/alternatives.log")),
        "dpkg_log": host_path_signature(Path("/var/log/dpkg.log")),
    }


def assert_host_unchanged(expected: dict[str, Any]) -> None:
    observed = capture_host_state()
    for name, signature in expected.items():
        if observed[name] != signature:
            raise OracleError(f"host {name.replace('_', ' ')} changed during observation")


def write_capture(path: Path, observed: dict[str, Any]) -> None:
    temporary_root = (ROOT / ".tmp").resolve()
    destination = path.resolve()
    if destination.parent.parent != temporary_root:
        raise OracleError(
            "captured observation must be a file in a directory directly under .tmp"
        )
    if destination.exists() or destination.is_symlink():
        raise OracleError("captured observation path already exists")
    destination.parent.mkdir(exist_ok=True)
    m.write(destination, canonical_json(observed).encode())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--reference-dpkg", type=Path)
    parser.add_argument("--reference-update-alternatives", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--print-observed", action="store_true")
    parser.add_argument("--update-reference", action="store_true")
    parser.add_argument(
        "--capture-observed",
        type=Path,
        help="write a canonical bounded observation without publishing it",
    )
    arguments = parser.parse_args()
    selected_outputs = sum(
        value is not None and value is not False
        for value in (
            arguments.capture_observed,
            arguments.print_observed,
            arguments.update_reference,
        )
    )
    if selected_outputs > 1:
        parser.error(
            "--capture-observed, --print-observed and --update-reference are "
            "mutually exclusive"
        )
    if os.geteuid() != 0:
        raise OracleError("dpkg alternatives reference execution requires root")
    for command in ("ldd",):
        if shutil.which(command) is None:
            raise OracleError(f"required reference tool is missing: {command}")
    architecture = arguments.architecture

    reference = load_reference()
    derived = verify_source_bindings(reference)
    expected_observation: dict[str, Any] | None = None
    if arguments.capture_observed is None:
        expected_observation = config.published_observation(reference, architecture)
    if arguments.update_reference and architecture != "amd64":
        raise OracleError("only the amd64 baseline observation can be regenerated")
    dpkg, update_alternatives = select_references(
        arguments.reference_dpkg,
        arguments.reference_update_alternatives,
        architecture,
    )
    m.REFERENCE_DPKG = dpkg
    environment = dict(ENVIRONMENT)
    validate_environment(environment)

    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    if arguments.workspace:
        workspace = arguments.workspace.resolve()
        if workspace.parent != temporary_root.resolve():
            parser.error("--workspace must name a new directory directly under .tmp")
        workspace.mkdir()
        context = nullcontext(str(workspace))
    else:
        context = tempfile.TemporaryDirectory(
            prefix="dpkg-alternatives-reference-",
            dir=temporary_root,
        )

    host_state = capture_host_state()
    observed: dict[str, Any] | None = None
    try:
        with context as temporary:
            workspace = Path(temporary)
            environment["HOME"] = str(workspace / "home")
            environment["TMPDIR"] = str(workspace / "tmp")
            environment["SOURCE_DATE_EPOCH"] = str(m.EPOCH)
            (workspace / "home").mkdir()
            (workspace / "tmp").mkdir()
            validate_environment(environment)
            config.validate_host_configuration(Path(environment["HOME"]))
            observed = observe(
                workspace,
                environment,
                architecture,
                dpkg,
                update_alternatives,
                derived,
            )
    finally:
        assert_host_unchanged(host_state)
        m.reference_dpkg.verify_file(
            Path(dpkg),
            m.reference_dpkg.PINS[architecture]["executable"],
        )
        m.reference_dpkg.verify_file(
            Path(update_alternatives),
            m.reference_dpkg.PINS[architecture]["update_alternatives"],
        )

    assert observed is not None
    if arguments.update_reference:
        reference["observed_behavior"] = observed
        REFERENCE.write_text(canonical_json(reference))
    elif arguments.capture_observed is not None:
        write_capture(arguments.capture_observed, observed)
    elif observed != expected_observation:
        raise OracleError(
            "observed alternatives behavior differs from the canonical reference"
        )
    if arguments.print_observed:
        print(canonical_json(observed), end="")
    print(
        "dpkg/update-alternatives reference passed "
        f"({architecture}, {len(derived['alternatives']['groups'])} groups, "
        f"{len(derived['alternatives']['requested_paths'])} requested paths)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
