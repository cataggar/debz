#!/usr/bin/env python3
"""Verify direct dpkg handling of debconf config control members."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tools/fixtures/vendor-state/dpkg-config-reference-v1.json"
SCHEMA = "https://debz.dev/schema/dpkg-config-reference-v1"
PACKAGE = "debz-config-oracle"
TRACE = "var/log/debz-config-oracle.trace"
ENV_TRACE = "var/log/debz-config-oracle.environment"
FD_ERRORS = "var/log/debz-config-oracle.fd-errors"
CONFIG_INVOCATIONS = "var/log/debz-config-oracle.config-invocations"
VENDOR_CONFIG_INVOCATIONS = "config-called"
FAILURES = "debz-config-oracle.failures"
PAUSE = "debz-config-oracle.pause"
PAUSED = "debz-config-oracle.paused"
TOKENS = ("v1", "v1r", "v2")
SCRIPT_KINDS = ("preinst", "postinst", "prerm", "postrm")
FORBIDDEN_FRONTEND_ENV = frozenset(
    {
        "DEBCONF_DB_FALLBACK",
        "DEBCONF_DB_OVERRIDE",
        "DEBCONF_DEBUG",
        "DEBIAN_FRONTEND",
    }
)
FORBIDDEN_FRONTEND_PATHS = (
    "usr/bin/apt",
    "usr/bin/apt-get",
    "usr/sbin/dpkg-preconfigure",
    "usr/bin/debconf",
)
CONTROL_NAMES = frozenset(
    {"control", "conffiles", "md5sums", "config", *SCRIPT_KINDS}
)
IDENTITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
UPDATE_PATTERN = re.compile(r"^[0-9]{4}$")


class OracleError(RuntimeError):
    """The reference fixture or an observation crossed its bounded contract."""


class Limits:
    maximum_packages = 16
    maximum_control_members = 16
    maximum_control_bytes = 256 * 1024
    maximum_file_bytes = 256 * 1024
    maximum_log_bytes = 128 * 1024
    maximum_trace_bytes = 128 * 1024
    maximum_trace_records = 128
    maximum_environment_records = 128
    maximum_environment_variables = 32
    maximum_environment_line_bytes = 4096
    maximum_arguments = 16
    maximum_argument_bytes = 256
    maximum_updates = 32
    maximum_status_bytes = 256 * 1024
    subprocess_timeout_seconds = 60
    pause_timeout_seconds = 10
    pause_script_timeout_seconds = 30


LIFECYCLE_SPEC = importlib.util.spec_from_file_location(
    "debz_config_lifecycle", ROOT / "tools/test-native-lifecycle.py",
)
assert LIFECYCLE_SPEC and LIFECYCLE_SPEC.loader
lifecycle = importlib.util.module_from_spec(LIFECYCLE_SPEC)
LIFECYCLE_SPEC.loader.exec_module(lifecycle)
m = lifecycle.m


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
        raise OracleError(f"fixture path must be a regular non-symlink file: {path}")
    if metadata.st_size > maximum:
        raise OracleError(f"fixture file exceeds its byte limit: {path}")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise OracleError(f"fixture file changed while reading: {path}")
    return data


def optional_regular(path: Path, maximum: int) -> bytes | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return read_regular(path, maximum)


def load_reference() -> dict[str, Any]:
    raw = read_regular(REFERENCE, Limits.maximum_file_bytes)
    reference = json.loads(raw)
    if reference.get("schema") != SCHEMA or reference.get("version") != 1:
        raise OracleError("unsupported dpkg config reference")
    if raw != canonical_json(reference).encode():
        raise OracleError("dpkg config reference is not canonical JSON")
    return reference


def validate_control_name(name: str) -> None:
    if (
        name not in CONTROL_NAMES
        or "/" in name
        or name in {".", ".."}
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        raise OracleError(f"unsafe fixture control member: {name!r}")


def validate_control_tree(source: Path) -> None:
    control = source / "DEBIAN"
    metadata = control.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or control.is_symlink():
        raise OracleError("fixture DEBIAN path must be a real directory")
    members = sorted(os.scandir(control), key=lambda entry: os.fsencode(entry.name))
    if len(members) > Limits.maximum_control_members:
        raise OracleError("fixture control-member count exceeds its limit")
    total = 0
    for member in members:
        validate_control_name(member.name)
        metadata = member.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or member.is_symlink():
            raise OracleError(f"fixture control member must be regular: {member.name}")
        if metadata.st_size > Limits.maximum_file_bytes:
            raise OracleError(f"fixture control member exceeds its byte limit: {member.name}")
        total += metadata.st_size
        if total > Limits.maximum_control_bytes:
            raise OracleError("fixture control bytes exceed their aggregate limit")


def validate_environment(environment: dict[str, str]) -> None:
    contaminated = sorted(FORBIDDEN_FRONTEND_ENV.intersection(environment))
    if contaminated:
        raise OracleError(
            "direct-dpkg fixture contains frontend environment: " + ", ".join(contaminated)
        )
    if len(environment) > Limits.maximum_environment_variables:
        raise OracleError("fixture environment exceeds its variable limit")
    for name, value in environment.items():
        encoded = f"{name}={value}".encode()
        if (
            not name
            or "=" in name
            or b"\x00" in encoded
            or len(encoded) > Limits.maximum_environment_line_bytes
        ):
            raise OracleError(f"unsafe fixture environment entry: {name!r}")


def verify_file_binding(path: Path, binding: dict[str, Any]) -> None:
    data = read_regular(path, Limits.maximum_file_bytes * 8)
    if len(data) != binding["size"] or sha256_bytes(data) != binding["sha256"]:
        raise OracleError(f"pinned source binding changed: {path}")


def vendor_members(reference: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        member
        for member in reference["control_members"]
        if member["classification"] == "debconf-config"
    ]


def verify_source_bindings(reference: dict[str, Any]) -> None:
    source = reference["source"]
    vendor = source["vendor_reference"]
    fixtures = ROOT / "tools/fixtures/vendor-state"
    verify_file_binding(fixtures / vendor["index"]["path"], vendor["index"])
    verify_file_binding(fixtures / vendor["reference"]["path"], vendor["reference"])
    for manifest in vendor["manifests"]:
        verify_file_binding(fixtures / manifest["path"], manifest)

    derived = json.loads(
        read_regular(fixtures / vendor["reference"]["path"], Limits.maximum_file_bytes * 8)
    )
    expected_members = reference["members"]
    observed_members = vendor_members(derived)
    if observed_members != expected_members:
        raise OracleError("pinned config-member identities no longer match the vendor reference")
    requirements = {
        item["id"]: item for item in derived["reference_execution_requirements"]
    }
    requirement = requirements.get(vendor["requirement_id"])
    if requirement is None:
        raise OracleError("vendor reference no longer carries the config execution requirement")
    if requirement["applies_to"]["identities"] != [
        item["identity"] for item in expected_members
    ]:
        raise OracleError("vendor config execution requirement identities changed")

    dpkg = source["dpkg"]
    if dpkg["version"] != lifecycle.m.reference_dpkg.VERSION:
        raise OracleError("dpkg reference version binding changed")
    for architecture, pins in lifecycle.m.reference_dpkg.PINS.items():
        expected = dpkg["architectures"][architecture]
        if (
            pins["archive"] != expected["archive_sha256"]
            or pins["executable"] != expected["executable_sha256"]
        ):
            raise OracleError(f"dpkg pin changed for {architecture}")


def config_body(token: str, exit_code: int, *, invalid_interpreter: bool = False) -> bytes:
    if token not in TOKENS or not 1 <= exit_code <= 125:
        raise OracleError("invalid synthetic config identity")
    interpreter = f"#!/nonexistent-debz-config-{token}" if invalid_interpreter else "#!/bin/sh"
    return f"""{interpreter}
# identity:{token}
printf '%s\\t%s\\t%d' 'config@{token}' "$0" "$#" >> /{CONFIG_INVOCATIONS}
for argument do
    printf '\\t%d:%s' "${{#argument}}" "$argument" >> /{CONFIG_INVOCATIONS}
done
printf '\\tcwd=%s\\n' "$PWD" >> /{CONFIG_INVOCATIONS}
/oracle-env >> /{CONFIG_INVOCATIONS}
exit {exit_code}
""".encode()


def vendor_config_body(package: str, size: int, exit_code: int) -> bytes:
    if not IDENTITY_PATTERN.fullmatch(package) or size > Limits.maximum_file_bytes:
        raise OracleError("invalid pinned vendor config fixture")
    prefix = f"""#!/bin/sh
# identity:{package}
echo {package}:"$*" >> /{VENDOR_CONFIG_INVOCATIONS}
exit {exit_code}
""".encode()
    if len(prefix) > size:
        raise OracleError(f"vendor config fixture does not fit pinned size: {package}")
    return prefix + b"#" * (size - len(prefix))


def maintainer_scripts(token: str) -> dict[str, bytes]:
    if token not in TOKENS:
        raise OracleError("invalid maintainer-script identity")
    result = {}
    for kind in SCRIPT_KINDS:
        result[kind] = f"""#!/bin/sh
read_config_identity() {{
    path="$1"
    value='<absent>'
    if [ -f "$path" ]; then
        marker=''
        {{ IFS= read -r ignored; IFS= read -r marker; }} < "$path"
        case "$marker" in
            '# identity:'*) value="${{marker#*:}}" ;;
            *) value='<invalid>' ;;
        esac
    fi
    printf '%s' "$value"
}}

fds=''
for fd in 0 1 2 3 4 5 6 7 8 9; do
    if ( eval ": <&$fd" ) 2>> /{FD_ERRORS}; then
        if [ -n "$fds" ]; then fds="$fds,"; fi
        fds="$fds$fd"
    fi
done

printf '%s\\t%d' '{kind}@{token}' "$#" >> /{TRACE}
for argument do
    printf '\\t%d:%s' "${{#argument}}" "$argument" >> /{TRACE}
done
printf '\\tinfo=%s\\tstaging=%s\\tcwd=%s\\tfds=%s\\n' \
    "$(read_config_identity /var/lib/dpkg/info/{PACKAGE}.config)" \
    "$(read_config_identity /var/lib/dpkg/tmp.ci/config)" "$PWD" "$fds" >> /{TRACE}

printf 'BEGIN\\t%s\\n' '{kind}@{token}' >> /{ENV_TRACE}
/oracle-env >> /{ENV_TRACE}
printf 'END\\n' >> /{ENV_TRACE}

if [ -f /{FAILURES} ]; then
    while IFS= read -r failure; do
        if [ "$failure" = "{token}:{kind}:$1" ]; then
            exit 23
        fi
    done < /{FAILURES}
fi

if [ -f /{PAUSE} ]; then
    IFS= read -r selected < /{PAUSE}
    if [ "$selected" = "{token}:{kind}:$1" ]; then
        printf '%s\\n' "$selected" > /{PAUSED}
        index=0
        while [ "$index" -lt {Limits.pause_script_timeout_seconds} ]; do
            /oracle-sleep 1
            index=$((index + 1))
        done
        exit 24
    fi
fi
exit 0
""".encode()
    return result


def prepare_control(source: Path, body: bytes) -> None:
    m.write(source / "DEBIAN/config", body, 0o755)


def make_lifecycle_packages(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
) -> tuple[dict[str, Path], dict[str, bytes]]:
    bodies = {
        "v1": config_body("v1", 91),
        "v1r": config_body("v1r", 92),
        "v2": config_body("v2", 93, invalid_interpreter=True),
    }
    versions = {"v1": "1", "v1r": "1", "v2": "2"}
    archives: dict[str, Path] = {}
    for token in TOKENS:
        archive = m.make_package(
            workspace / f"package-{token}",
            environment,
            architecture,
            versions[token],
            "conffile",
            package=PACKAGE,
            scripts=maintainer_scripts(token),
            prepare_payload=lambda source, body=bodies[token]: prepare_control(source, body),
        )
        validate_control_tree(archive.with_suffix(".source"))
        archives[token] = archive
    return archives, bodies


def make_vendor_packages(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    members: list[dict[str, Any]],
) -> tuple[list[Path], dict[str, bytes]]:
    if len(members) > Limits.maximum_packages:
        raise OracleError("vendor config package count exceeds its limit")
    archives = []
    bodies = {}
    for index, member in enumerate(members):
        package = member["owner"]["package"]
        fact = member["architectures"][architecture]
        body = vendor_config_body(package, fact["size"], 70 + index)
        archive = m.make_package(
            workspace / f"vendor-{package}",
            environment,
            architecture,
            "1",
            package=package,
            prepare_payload=lambda source, content=body: prepare_control(source, content),
        )
        validate_control_tree(archive.with_suffix(".source"))
        archives.append(archive)
        bodies[package] = body
    return archives, bodies


def make_root(path: Path, architecture: str, *, instrumented: bool) -> None:
    m.make_root(path, architecture)
    (path / "var/log").mkdir(parents=True, exist_ok=True)
    lifecycle.runtime.copy_program(path, Path("/bin/sh"), "/bin/sh")
    if instrumented:
        lifecycle.runtime.copy_program(path, Path("/usr/bin/env"), "/oracle-env")
        lifecycle.runtime.copy_program(path, Path("/bin/sleep"), "/oracle-sleep")
    for relative in FORBIDDEN_FRONTEND_PATHS:
        if os.path.lexists(path / relative):
            raise OracleError(f"ambient frontend contaminated fixture root: {relative}")


def bounded_log(path: Path) -> None:
    data = read_regular(path, Limits.maximum_log_bytes)
    if len(data) > Limits.maximum_log_bytes:
        raise OracleError("dpkg output exceeded its byte limit")


def run_dpkg(
    executable: str,
    root: Path,
    arguments: list[str],
    environment: dict[str, str],
    log: Path,
) -> int:
    command = m.reference_command(root)
    if command[0] != executable:
        raise OracleError("reference command did not select the pinned dpkg executable")
    command += arguments
    if any(Path(argument).name in {"apt", "apt-get", "debconf", "dpkg-preconfigure"} for argument in command):
        raise OracleError("frontend executable entered the direct-dpkg command")
    with log.open("wb") as output:
        result = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=Limits.subprocess_timeout_seconds,
            check=False,
        )
    bounded_log(log)
    if result.returncode not in (0, 1):
        raise OracleError(f"direct dpkg exited unexpectedly: {result.returncode}; {log}")
    return result.returncode


def interrupt_dpkg(
    executable: str,
    root: Path,
    arguments: list[str],
    selected: str,
    environment: dict[str, str],
    log: Path,
) -> int:
    m.write(root / PAUSE, (selected + "\n").encode(), 0o600)
    command = m.reference_command(root) + arguments
    if command[0] != executable:
        raise OracleError("interruption command did not select pinned dpkg")
    with log.open("wb") as output:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.monotonic() + Limits.pause_timeout_seconds
        while time.monotonic() < deadline:
            if optional_regular(root / PAUSED, 256) is not None:
                break
            if process.poll() is not None:
                raise OracleError(f"dpkg exited before the selected interruption: {selected}")
            time.sleep(0.05)
        else:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=Limits.pause_timeout_seconds)
            raise OracleError(f"dpkg did not reach the selected interruption: {selected}")
        os.killpg(process.pid, signal.SIGKILL)
        returncode = process.wait(timeout=Limits.pause_timeout_seconds)
    bounded_log(log)
    (root / PAUSE).unlink()
    (root / PAUSED).unlink()
    if returncode != -signal.SIGKILL:
        raise OracleError(f"interrupted dpkg returned unexpectedly: {returncode}")
    return returncode


def parse_deb822(data: bytes, label: str) -> list[dict[str, str]]:
    if len(data) > Limits.maximum_status_bytes:
        raise OracleError(f"database text exceeds limit: {label}")
    try:
        text = data.decode()
    except UnicodeDecodeError as error:
        raise OracleError(f"database text is not UTF-8: {label}") from error
    records = []
    for paragraph in text.split("\n\n"):
        if not paragraph:
            continue
        record: dict[str, str] = {}
        current = None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                if current is None:
                    raise OracleError(f"orphan continuation in {label}")
                record[current] += "\n" + line
                continue
            name, separator, value = line.partition(":")
            if not separator or not name or name in record:
                raise OracleError(f"malformed database field in {label}")
            current = name
            record[name] = value.lstrip(" ")
        records.append(record)
    return records


def package_record(data: bytes, package: str, label: str) -> dict[str, str] | None:
    selected = [
        record for record in parse_deb822(data, label) if record.get("Package") == package
    ]
    if len(selected) > 1:
        raise OracleError(f"duplicate package record in {label}")
    return selected[0] if selected else None


def summarize_record(record: dict[str, str] | None) -> dict[str, str] | None:
    if record is None:
        return None
    result = {"status": record["Status"], "version": record["Version"]}
    if "Config-Version" in record:
        result["config_version"] = record["Config-Version"]
    return result


def database_state(root: Path, package: str = PACKAGE) -> dict[str, Any]:
    admin = root / "var/lib/dpkg"
    committed = package_record(
        read_regular(admin / "status", Limits.maximum_status_bytes),
        package,
        "status",
    )
    updates = admin / "updates"
    numeric: list[dict[str, str]] = []
    temporary = False
    entries = sorted(os.scandir(updates), key=lambda entry: os.fsencode(entry.name))
    if len(entries) > Limits.maximum_updates:
        raise OracleError("dpkg update journal exceeds its entry limit")
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or entry.is_symlink():
            raise OracleError(f"dpkg update entry is not regular: {entry.name}")
        if entry.name == "tmp.i":
            read_regular(Path(entry.path), Limits.maximum_status_bytes)
            temporary = True
        elif UPDATE_PATTERN.fullmatch(entry.name):
            record = package_record(
                read_regular(Path(entry.path), Limits.maximum_status_bytes),
                package,
                f"updates/{entry.name}",
            )
            if record is not None:
                numeric.append(record)
        else:
            raise OracleError(f"unexpected dpkg update entry: {entry.name}")
    return {
        "committed": summarize_record(committed),
        "journal_latest": summarize_record(numeric[-1]) if numeric else None,
        "journal_nonempty": bool(numeric),
        "temporary_update": temporary,
    }


def config_identity(path: Path) -> str | None:
    data = optional_regular(path, Limits.maximum_file_bytes)
    if data is None:
        return None
    lines = data.splitlines()
    if len(lines) < 2 or not lines[1].startswith(b"# identity:"):
        raise OracleError(f"config member lacks a fixture identity: {path}")
    return lines[1].removeprefix(b"# identity:").decode()


def assert_config(
    root: Path,
    expected: str | None,
    bodies: dict[str, bytes],
    *,
    staging: str | None = None,
) -> None:
    info = root / f"var/lib/dpkg/info/{PACKAGE}.config"
    temporary = root / "var/lib/dpkg/tmp.ci/config"
    if config_identity(info) != expected or config_identity(temporary) != staging:
        raise OracleError(
            f"wrong config publication: info={config_identity(info)!r}, "
            f"staging={config_identity(temporary)!r}"
        )
    for path, identity in ((info, expected), (temporary, staging)):
        if identity is None:
            if os.path.lexists(path):
                raise OracleError(f"unexpected config path remains: {path}")
            continue
        data = read_regular(path, Limits.maximum_file_bytes)
        metadata = path.stat()
        if data != bodies[identity] or stat.S_IMODE(metadata.st_mode) != 0o755:
            raise OracleError(f"config bytes or mode changed: {path}")


def assert_no_config_invocation(root: Path) -> None:
    for relative in (CONFIG_INVOCATIONS, VENDOR_CONFIG_INVOCATIONS):
        if optional_regular(root / relative, Limits.maximum_trace_bytes) not in (None, b""):
            raise OracleError(f"direct dpkg invoked a config script: {relative}")


def parse_trace(root: Path) -> list[dict[str, Any]]:
    raw = optional_regular(root / TRACE, Limits.maximum_trace_bytes)
    if raw is None:
        return []
    try:
        lines = raw.decode().splitlines()
    except UnicodeDecodeError as error:
        raise OracleError("maintainer-script trace is not UTF-8") from error
    if len(lines) > Limits.maximum_trace_records:
        raise OracleError("maintainer-script trace exceeds its record limit")
    records = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 6:
            raise OracleError(f"malformed maintainer-script trace: {line!r}")
        script = fields[0]
        try:
            count = int(fields[1])
        except ValueError as error:
            raise OracleError("invalid maintainer-script argument count") from error
        if count > Limits.maximum_arguments or len(fields) != count + 6:
            raise OracleError("maintainer-script argument bounds changed")
        arguments = []
        for field in fields[2 : 2 + count]:
            length, separator, value = field.partition(":")
            if not separator or not length.isdigit():
                raise OracleError("malformed length-prefixed maintainer-script argument")
            if int(length) != len(value) or len(value.encode()) > Limits.maximum_argument_bytes:
                raise OracleError("maintainer-script argument length changed")
            arguments.append(value)
        attributes = {}
        for field in fields[2 + count :]:
            name, separator, value = field.partition("=")
            if not separator or name in attributes:
                raise OracleError("malformed maintainer-script trace attributes")
            attributes[name] = value
        if set(attributes) != {"info", "staging", "cwd", "fds"}:
            raise OracleError("maintainer-script trace attribute set changed")
        if attributes["cwd"] != "/" or attributes["fds"] != "0,1,2":
            raise OracleError(f"maintainer-script cwd/fd contract changed: {attributes}")
        records.append(
            {
                "script": script,
                "arguments": arguments,
                "info_config": None
                if attributes["info"] == "<absent>"
                else attributes["info"],
                "staging_config": None
                if attributes["staging"] == "<absent>"
                else attributes["staging"],
            }
        )
    errors = optional_regular(root / FD_ERRORS, Limits.maximum_trace_bytes)
    if errors is not None and len(errors) > Limits.maximum_trace_bytes:
        raise OracleError("fd probe output exceeded its byte limit")
    return records


def expected_environment(
    identity: str,
    workspace: Path,
    architecture: str,
) -> dict[str, str]:
    kind, separator, _ = identity.partition("@")
    if not separator or kind not in SCRIPT_KINDS:
        raise OracleError(f"invalid script environment identity: {identity}")
    return {
        "DPKG_ADMINDIR": "/var/lib/dpkg",
        "DPKG_FORCE": "security-mac,downgrade,not-root,bad-path",
        "DPKG_MAINTSCRIPT_ARCH": architecture,
        "DPKG_MAINTSCRIPT_DEBUG": "0",
        "DPKG_MAINTSCRIPT_NAME": kind,
        "DPKG_MAINTSCRIPT_PACKAGE": PACKAGE,
        "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT": "1",
        "DPKG_ROOT": "",
        "DPKG_RUNNING_VERSION": "1.22.22",
        "HOME": str(workspace / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PWD": "/",
        "SHLVL": "1",
        "SOURCE_DATE_EPOCH": str(m.EPOCH),
        "TMPDIR": str(workspace / "tmp"),
        "_": "/oracle-env",
    }


def validate_environment_trace(
    root: Path,
    trace: list[dict[str, Any]],
    workspace: Path,
    architecture: str,
) -> None:
    raw = optional_regular(root / ENV_TRACE, Limits.maximum_trace_bytes)
    if raw is None:
        if trace:
            raise OracleError("maintainer scripts ran without environment evidence")
        return
    try:
        lines = raw.decode().splitlines()
    except UnicodeDecodeError as error:
        raise OracleError("environment trace is not UTF-8") from error
    records: list[tuple[str, dict[str, str]]] = []
    index = 0
    while index < len(lines):
        begin = lines[index].split("\t")
        if len(begin) != 2 or begin[0] != "BEGIN":
            raise OracleError("malformed environment trace header")
        identity = begin[1]
        index += 1
        values: dict[str, str] = {}
        while index < len(lines) and lines[index] != "END":
            line = lines[index]
            if len(line.encode()) > Limits.maximum_environment_line_bytes:
                raise OracleError("environment trace line exceeds its byte limit")
            name, separator, value = line.partition("=")
            if not separator or name in values:
                raise OracleError("malformed environment trace entry")
            values[name] = value
            if len(values) > Limits.maximum_environment_variables:
                raise OracleError("environment trace variable count exceeds its limit")
            index += 1
        if index >= len(lines):
            raise OracleError("unterminated environment trace")
        index += 1
        records.append((identity, values))
    if len(records) > Limits.maximum_environment_records:
        raise OracleError("environment trace record count exceeds its limit")
    if [identity for identity, _ in records] != [item["script"] for item in trace]:
        raise OracleError("environment evidence is not ordered with script evidence")
    for identity, values in records:
        if values != expected_environment(identity, workspace, architecture):
            raise OracleError(
                f"maintainer-script environment changed for {identity}: "
                f"{canonical_json(values)}"
            )


def validate_instrumentation(
    root: Path,
    workspace: Path,
    architecture: str,
) -> list[dict[str, Any]]:
    trace = parse_trace(root)
    validate_environment_trace(root, trace, workspace, architecture)
    assert_no_config_invocation(root)
    return trace


def set_lines(root: Path, relative: str, lines: tuple[str, ...]) -> None:
    path = root / relative
    if lines:
        m.write(path, ("\n".join(lines) + "\n").encode(), 0o600)
    elif path.exists():
        path.unlink()


def effective_record(state: dict[str, Any]) -> dict[str, str] | None:
    return state["journal_latest"] or state["committed"]


class Scenario:
    def __init__(
        self,
        workspace: Path,
        name: str,
        architecture: str,
        environment: dict[str, str],
        executable: str,
        bodies: dict[str, bytes],
    ) -> None:
        self.directory = workspace / name
        self.directory.mkdir()
        self.root = self.directory / "root"
        make_root(self.root, architecture, instrumented=True)
        self.workspace = workspace
        self.architecture = architecture
        self.environment = environment
        self.executable = executable
        self.bodies = bodies
        self.index = 0

    def run(
        self,
        operation: str,
        arguments: list[str],
        *,
        failures: tuple[str, ...] = (),
        expected_exit: int = 0,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        before = len(parse_trace(self.root))
        set_lines(self.root, FAILURES, failures)
        destination = self.directory / f"{self.index}-{operation}.log"
        self.index += 1
        observed = run_dpkg(
            self.executable,
            self.root,
            arguments,
            self.environment,
            destination,
        )
        if observed != expected_exit:
            raise OracleError(
                f"{self.directory.name}/{operation}: exit {observed}, expected {expected_exit}"
            )
        trace = validate_instrumentation(
            self.root, self.workspace, self.architecture
        )
        return database_state(self.root), trace[before:]

    def interrupt(
        self,
        operation: str,
        arguments: list[str],
        selected: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        before = len(parse_trace(self.root))
        set_lines(self.root, FAILURES, ())
        destination = self.directory / f"{self.index}-{operation}-interrupted.log"
        self.index += 1
        interrupt_dpkg(
            self.executable,
            self.root,
            arguments,
            selected,
            self.environment,
            destination,
        )
        trace = validate_instrumentation(
            self.root, self.workspace, self.architecture
        )
        return database_state(self.root), trace[before:]


def phase_observation(
    operation: str,
    state: dict[str, Any],
    trace: list[dict[str, Any]],
    config: str | None,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "state": effective_record(state),
        "config": config,
        "trace": compact_trace(trace),
    }


def compact_trace(trace: list[dict[str, Any]]) -> list[str]:
    return [
        "\t".join(
            (
                item["script"],
                json.dumps(item["arguments"], separators=(",", ":")),
                item["info_config"] or "-",
                item["staging_config"] or "-",
            )
        )
        for item in trace
    ]


def observe_vendor_cohort(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
    members: list[dict[str, Any]],
) -> dict[str, Any]:
    directory = workspace / "vendor-cohort"
    directory.mkdir()
    archives, bodies = make_vendor_packages(
        directory / "packages", environment, architecture, members
    )
    root = directory / "root"
    make_root(root, architecture, instrumented=False)
    install = run_dpkg(
        executable,
        root,
        ["--install", *(str(path) for path in archives)],
        environment,
        directory / "install.log",
    )
    installed = []
    for member in members:
        package = member["owner"]["package"]
        path = root / f"var/lib/dpkg/info/{package}.config"
        data = read_regular(path, Limits.maximum_file_bytes)
        if data != bodies[package] or stat.S_IMODE(path.stat().st_mode) != 0o755:
            raise OracleError(f"vendor identity config was not retained exactly: {package}")
        installed.append(package)
    assert_no_config_invocation(root)
    remove = run_dpkg(
        executable,
        root,
        ["--remove", *(f"{package}:{architecture}" for package in installed)],
        environment,
        directory / "remove.log",
    )
    for package in installed:
        if os.path.lexists(root / f"var/lib/dpkg/info/{package}.config"):
            raise OracleError(f"vendor identity config survived successful removal: {package}")
    assert_no_config_invocation(root)
    return {
        "install_exit": install,
        "remove_exit": remove,
        "installed_identities": [f"{package}.config" for package in installed],
        "config_invocation_count": 0,
        "retained_after_remove": [],
    }


def observe_success(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
    archives: dict[str, Path],
    bodies: dict[str, bytes],
) -> list[dict[str, Any]]:
    scenario = Scenario(
        workspace, "successful-lifecycle", architecture, environment, executable, bodies
    )
    observations = []
    for operation, arguments, expected_config in (
        ("install", ["--install", str(archives["v1"])], "v1"),
        ("reinstall", ["--install", str(archives["v1r"])], "v1r"),
        ("upgrade", ["--install", str(archives["v2"])], "v2"),
        ("remove", ["--remove", f"{PACKAGE}:{architecture}"], None),
        ("purge", ["--purge", f"{PACKAGE}:{architecture}"], None),
    ):
        state, trace = scenario.run(operation, arguments)
        assert_config(scenario.root, expected_config, bodies)
        observations.append(phase_observation(operation, state, trace, expected_config))
    return observations


def observe_failures(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
    archives: dict[str, Path],
    bodies: dict[str, bytes],
) -> list[dict[str, Any]]:
    results = []

    scenario = Scenario(
        workspace, "failure-postinst-fresh", architecture, environment, executable, bodies
    )
    state, trace = scenario.run(
        "install",
        ["--install", str(archives["v1"])],
        failures=("v1:postinst:configure",),
        expected_exit=1,
    )
    assert_config(scenario.root, "v1", bodies)
    retry_state, retry_trace = scenario.run(
        "configure", ["--configure", f"{PACKAGE}:{architecture}"]
    )
    assert_config(scenario.root, "v1", bodies)
    results.append(
        {
            "case": "fresh-postinst-failure",
            "failed_state": effective_record(state),
            "failed_config": "v1",
            "failed_trace": compact_trace(trace),
            "recovery_state": effective_record(retry_state),
            "recovery_config": "v1",
            "recovery_trace": compact_trace(retry_trace),
        }
    )

    scenario = Scenario(
        workspace, "failure-postinst-upgrade", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.run(
        "upgrade",
        ["--install", str(archives["v2"])],
        failures=("v2:postinst:configure",),
        expected_exit=1,
    )
    assert_config(scenario.root, "v2", bodies)
    retry_state, retry_trace = scenario.run(
        "configure", ["--configure", f"{PACKAGE}:{architecture}"]
    )
    assert_config(scenario.root, "v2", bodies)
    results.append(
        {
            "case": "upgrade-postinst-failure",
            "failed_state": effective_record(state),
            "failed_config": "v2",
            "failed_trace": compact_trace(trace),
            "recovery_state": effective_record(retry_state),
            "recovery_config": "v2",
            "recovery_trace": compact_trace(retry_trace),
        }
    )

    scenario = Scenario(
        workspace, "failure-preinst-upgrade", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.run(
        "upgrade",
        ["--install", str(archives["v2"])],
        failures=("v2:preinst:upgrade",),
        expected_exit=1,
    )
    assert_config(scenario.root, "v1", bodies)
    results.append(
        {
            "case": "incoming-preinst-failure",
            "failed_state": effective_record(state),
            "failed_config": "v1",
            "failed_trace": compact_trace(trace),
        }
    )

    scenario = Scenario(
        workspace, "failure-postrm-upgrade", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.run(
        "upgrade",
        ["--install", str(archives["v2"])],
        failures=(
            "v1:postrm:upgrade",
            "v2:postrm:failed-upgrade",
        ),
        expected_exit=1,
    )
    assert_config(scenario.root, "v1", bodies)
    results.append(
        {
            "case": "double-postrm-upgrade-failure",
            "failed_state": effective_record(state),
            "failed_config": "v1",
            "failed_trace": compact_trace(trace),
        }
    )

    scenario = Scenario(
        workspace, "failure-postrm-remove", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.run(
        "remove",
        ["--remove", f"{PACKAGE}:{architecture}"],
        failures=("v1:postrm:remove",),
        expected_exit=1,
    )
    assert_config(scenario.root, "v1", bodies)
    retry_state, retry_trace = scenario.run(
        "remove-retry", ["--remove", f"{PACKAGE}:{architecture}"]
    )
    assert_config(scenario.root, None, bodies)
    results.append(
        {
            "case": "remove-postrm-failure",
            "failed_state": effective_record(state),
            "failed_config": "v1",
            "failed_trace": compact_trace(trace),
            "recovery_state": effective_record(retry_state),
            "recovery_config": None,
            "recovery_trace": compact_trace(retry_trace),
        }
    )

    scenario = Scenario(
        workspace, "failure-postrm-purge", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.run(
        "purge",
        ["--purge", f"{PACKAGE}:{architecture}"],
        failures=("v1:postrm:purge",),
        expected_exit=1,
    )
    assert_config(scenario.root, None, bodies)
    retry_state, retry_trace = scenario.run(
        "purge-retry", ["--purge", f"{PACKAGE}:{architecture}"]
    )
    assert_config(scenario.root, None, bodies)
    results.append(
        {
            "case": "purge-postrm-failure",
            "failed_state": effective_record(state),
            "failed_config": None,
            "failed_trace": compact_trace(trace),
            "recovery_state": effective_record(retry_state),
            "recovery_config": None,
            "recovery_trace": compact_trace(retry_trace),
        }
    )
    return results


def interruption_observation(
    case: str,
    state: dict[str, Any],
    trace: list[dict[str, Any]],
    config: str | None,
    staging: str | None,
    recovery_state: dict[str, Any],
    recovery_trace: list[dict[str, Any]],
    recovery_config: str | None,
) -> dict[str, Any]:
    return {
        "case": case,
        "interrupted_database": state,
        "interrupted_config": config,
        "interrupted_staging_config": staging,
        "interrupted_trace": compact_trace(trace),
        "recovery_state": effective_record(recovery_state),
        "recovery_config": recovery_config,
        "recovery_trace": compact_trace(recovery_trace),
    }


def observe_interruptions(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
    archives: dict[str, Path],
    bodies: dict[str, bytes],
) -> list[dict[str, Any]]:
    results = []

    scenario = Scenario(
        workspace, "interruption-postinst", architecture, environment, executable, bodies
    )
    state, trace = scenario.interrupt(
        "install",
        ["--install", str(archives["v1"])],
        "v1:postinst:configure",
    )
    assert_config(scenario.root, "v1", bodies)
    recovery_state, recovery_trace = scenario.run(
        "configure", ["--configure", f"{PACKAGE}:{architecture}"]
    )
    assert_config(scenario.root, "v1", bodies)
    results.append(
        interruption_observation(
            "postinst-interruption",
            state,
            trace,
            "v1",
            None,
            recovery_state,
            recovery_trace,
            "v1",
        )
    )

    scenario = Scenario(
        workspace, "interruption-preinst-upgrade", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.interrupt(
        "upgrade",
        ["--install", str(archives["v2"])],
        "v2:preinst:upgrade",
    )
    assert_config(scenario.root, "v1", bodies, staging="v2")
    recovery_state, recovery_trace = scenario.run(
        "upgrade-retry", ["--install", str(archives["v2"])]
    )
    assert_config(scenario.root, "v2", bodies)
    results.append(
        interruption_observation(
            "upgrade-preinst-interruption",
            state,
            trace,
            "v1",
            "v2",
            recovery_state,
            recovery_trace,
            "v2",
        )
    )

    scenario = Scenario(
        workspace, "interruption-postrm-remove", architecture, environment, executable, bodies
    )
    scenario.run("seed", ["--install", str(archives["v1"])])
    state, trace = scenario.interrupt(
        "remove",
        ["--remove", f"{PACKAGE}:{architecture}"],
        "v1:postrm:remove",
    )
    assert_config(scenario.root, "v1", bodies)
    recovery_state, recovery_trace = scenario.run(
        "remove-retry", ["--remove", f"{PACKAGE}:{architecture}"]
    )
    assert_config(scenario.root, None, bodies)
    results.append(
        interruption_observation(
            "remove-postrm-interruption",
            state,
            trace,
            "v1",
            None,
            recovery_state,
            recovery_trace,
            None,
        )
    )
    return results


def observe(
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    executable: str,
    reference: dict[str, Any],
) -> dict[str, Any]:
    archives, bodies = make_lifecycle_packages(
        workspace / "lifecycle-packages", environment, architecture
    )
    result = {
        "vendor_identity_cohort": observe_vendor_cohort(
            workspace, environment, architecture, executable, reference["members"]
        ),
        "successful_lifecycle": observe_success(
            workspace, environment, architecture, executable, archives, bodies
        ),
        "failure_recovery": observe_failures(
            workspace, environment, architecture, executable, archives, bodies
        ),
        "interruption_recovery": observe_interruptions(
            workspace, environment, architecture, executable, archives, bodies
        ),
        "script_context": {
            "cwd": "/",
            "open_fds": [0, 1, 2],
            "closed_probe_fds": [3, 4, 5, 6, 7, 8, 9],
            "environment": "exact-bounded-direct-dpkg-maintscript-environment",
        },
        "config_invocation_count": 0,
        "frontend_invocation_count": 0,
    }
    return result


def select_reference(path: Path | None, architecture: str) -> str:
    selected = path
    if selected is None:
        selected = (
            ROOT
            / ".cache/native-dpkg-reference"
            / lifecycle.m.reference_dpkg.VERSION
            / architecture
            / "usr/bin/dpkg"
        )
        if not selected.is_file():
            raise OracleError(
                "missing pinned dpkg reference; run "
                "python3 tools/prepare-native-dpkg.py as the build user"
            )
    return lifecycle.m.reference_dpkg.select(selected, architecture)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-dpkg", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument(
        "--print-observed",
        action="store_true",
        help="print the canonical bounded observation after it matches the reference",
    )
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise OracleError("dpkg config reference execution requires root")
    for command in ("dpkg", "dpkg-deb", "ldd"):
        if shutil.which(command) is None:
            raise OracleError(f"required reference tool is missing: {command}")
    architecture = subprocess.run(
        ["dpkg", "--print-architecture"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise OracleError(f"unsupported reference architecture: {architecture}")

    reference = load_reference()
    verify_source_bindings(reference)
    executable = select_reference(arguments.reference_dpkg, architecture)
    m.REFERENCE_DPKG = executable
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
            prefix="dpkg-config-reference-", dir=temporary_root
        )
    host_status = Path("/var/lib/dpkg/status").read_bytes()
    try:
        with context as temporary:
            workspace = Path(temporary)
            environment = m.fixture_environment(workspace)
            validate_environment(environment)
            observed = observe(
                workspace, environment, architecture, executable, reference
            )
            if observed != reference["observed_behavior"]:
                diagnostic = workspace / "observed.json"
                m.write(diagnostic, canonical_json(observed).encode())
                raise OracleError(
                    "direct dpkg config behavior changed; bounded observation: "
                    f"{diagnostic}"
                )
            if arguments.print_observed:
                print(canonical_json(observed), end="")
    finally:
        if Path("/var/lib/dpkg/status").read_bytes() != host_status:
            raise OracleError("host dpkg status changed during config reference execution")
    print(
        f"dpkg config reference: direct dpkg {reference['source']['dpkg']['version']} "
        f"{architecture} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
