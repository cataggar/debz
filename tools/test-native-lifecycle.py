#!/usr/bin/env python3
"""Compare native lifecycle execution with real dpkg scripts in disposable chroots."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_lifecycle_materialization", ROOT / "tools/test-native-materialization.py",
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "debz_lifecycle_runtime", ROOT / "tools/test-apt-system-acceptance.py",
)
assert RUNTIME_SPEC and RUNTIME_SPEC.loader
runtime = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(runtime)

KINDS = ("preinst", "postinst", "prerm", "postrm")
FAILURE = "lifecycle-fail"
TRACE = m.oracle.TRACE_PATH
LITERAL_PACKAGE = "literal-paths"
LITERAL_CONFFILE = Path("etc/literal\\config.conf")
METADATA_PACKAGE = "retained-metadata"
METADATA_KINDS = ("templates", "shlibs", "symbols")
CONFFILE_PACKAGE = "conffile-lifecycle"
CONFFILE_PATHS = (Path("etc/debz-native.conf"), Path("etc/conffile\\extra.conf"))
CONFFILE_TRIGGER = "conffile-purge"
STATO_PACKAGE = "statoverride-lifecycle"
STATO_BASE = f"usr/share/{STATO_PACKAGE}"
STATO_PASSWD = b"root:x:0:0:root:/root:/bin/sh\n_debzstat:x:42420:42421:fixture:/:/bin/sh\n"
STATO_GROUP = b"root:x:0:\n_debzstat:x:42421:\n"
STATO_LITERAL = Path("etc/stato\\literal")


def scripts(
    package: str,
    version: str,
    *,
    preinst_requires_configured: str | None = None,
    postinst_requires_payload: str | None = None,
) -> dict[str, bytes]:
    result = {}
    for kind in KINDS:
        identity = f"{package}@{version}:{kind}"
        requirement = ""
        if kind == "preinst" and preinst_requires_configured:
            requirement = f"""
configured=no
while IFS= read -r invocation; do
    case "$invocation" in
        '{preinst_requires_configured}@1:postinst'*) configured=yes ;;
    esac
done < /{TRACE}
[ "$configured" = yes ] || exit 24
"""
        if kind == "postinst" and postinst_requires_payload:
            requirement = f"\n[ -f /usr/share/{postinst_requires_payload}/data ] || exit 24\n"
        result[kind] = f"""#!/bin/sh
printf '%s\\t%s\\t%s\\t%s\\t%d' '{identity}' "$DPKG_MAINTSCRIPT_PACKAGE" "$DPKG_MAINTSCRIPT_NAME" "$DPKG_MAINTSCRIPT_ARCH" "$#" >> /{TRACE}
for argument do
    printf '\\t%d:%s' "${{#argument}}" "$argument" >> /{TRACE}
done
payload='<absent>'
if [ -f /usr/share/{package}/data ]; then
    IFS= read -r payload < /usr/share/{package}/data
fi
printf '\\tpayload=%s' "$payload" >> /{TRACE}
printf '\\n' >> /{TRACE}
if [ -f /{FAILURE} ]; then
    while IFS= read -r failure; do
        if [ "$failure" = "{identity}:$1" ]; then
            exit 23
        fi
    done < /{FAILURE}
fi
{requirement}
exit 0
""".encode()
    return result


def rewrite_database_field(script: bytes, package: str, before: str, after: str) -> bytes:
    return script.removesuffix(b"exit 0\n") + f"""
status=''
selected=no
while IFS= read -r line; do
    case "$line" in
        {shlex.quote("Package: " + package)}) selected=yes ;;
        'Package: '*) selected=no ;;
    esac
    if [ "$selected" = yes ] && [ "$line" = {shlex.quote(before)} ]; then
        line={shlex.quote(after)}
    fi
    status="$status$line
"
done < /var/lib/dpkg/status
printf '%s' "$status" > /var/lib/dpkg/status
exit 0
""".encode()


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
    command = m.reference_command(root)
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


def native(
    executable: Path,
    root: Path,
    archives: list[Path],
    operation: str,
    architecture: str,
    environment: dict[str, str],
    destination: Path,
    *,
    packages: list[dict[str, str]],
    policy: str = "keep_existing",
    ordered_actions: list[dict] | None = None,
    fault: str | None = None,
) -> dict:
    request_path = destination / "native.request.json"
    report_path = destination / "native.report.json"
    request = {
        "root": str(root), "architecture": architecture,
        "archives": [str(path) for path in archives], "operation": operation,
        "packages": packages, "policy": policy, "report": str(report_path),
    }
    if ordered_actions is not None:
        request["ordered_actions"] = ordered_actions
    if fault is not None:
        request["fault"] = fault
    m.write(request_path, json.dumps(request).encode())
    m.run(
        [str(executable)],
        {**environment, "DEBZ_NATIVE_LIFECYCLE_REQUEST": str(request_path)},
        destination / "native.log",
    )
    if not report_path.is_file() or report_path.stat().st_size > 64 * 1024:
        raise AssertionError("lifecycle driver did not produce a bounded outcome report")
    report = json.loads(report_path.read_bytes())
    if report.get("outcome") not in {
        "applied", "script_failed", "recovery_required", "handoff", "refused",
    }:
        raise AssertionError(f"invalid lifecycle report: {report}")
    return report


def ordered(
    architecture: str,
    actions: list[tuple[str, str]],
) -> list[dict]:
    return [
        {
            "sequence": index, "kind": kind, "package": package,
            "version": "1", "architecture": architecture,
        }
        for index, (kind, package) in enumerate(actions)
    ]


def compare_roots(
    expected: Path,
    candidate: Path,
    destination: Path,
    rollback_times: dict[str, int],
    started: int,
    ended: int,
) -> None:
    snapshots = [m.snapshot(expected), m.snapshot(candidate)]
    for label, snapshot in zip(("reference", "native"), snapshots):
        m.write(
            destination / f"{label}.snapshot.json",
            m.oracle.canonical_json(snapshot).encode(),
        )
        for path, original in rollback_times.items():
            entry = next(item for item in snapshot["filesystem"] if item["path"] == path)
            if entry["kind"] != "symlink":
                raise AssertionError(f"rollback changed symlink type: {path}")
            value = entry["mtime_ns"]
            # dpkg recreates this rollback link at wall-clock time; preserving
            # its original mtime is also valid, but an arbitrary timestamp is not.
            if value != original and not started <= value <= ended:
                raise AssertionError(f"unexpected rollback symlink timestamp: {path}: {value}")
            entry["mtime_ns"] = original
    mismatches = m.oracle.differences(*snapshots, maximum=30)
    if mismatches:
        raise AssertionError("native/dpkg mismatch:\n" + "\n".join(mismatches))


class Scenario:
    def __init__(
        self,
        workspace: Path,
        name: str,
        executable: Path | None,
        architecture: str,
        environment: dict[str, str],
        *,
        bootstrap: bool = False,
    ) -> None:
        self.directory = workspace / name
        self.expected = self.directory / "reference"
        self.candidate = self.directory / "native"
        self.executable = executable
        self.architecture = architecture
        self.environment = environment
        self.index = 0
        self.observations: list[dict] = []
        for root in self.roots:
            m.make_root(root, architecture)
            m.write(root / TRACE, b"")
            if not bootstrap:
                runtime.copy_program(root, Path("/bin/sh"), "/bin/sh")

    @property
    def roots(self) -> tuple[Path, Path]:
        return self.expected, self.candidate

    def identities(self, names: tuple[str, ...]) -> list[dict[str, str]]:
        return [{"name": name, "architecture": self.architecture} for name in names]

    def seed(self, archive: Path, *, configure: bool = True) -> None:
        for root in self.roots:
            destination = self.directory / f"seed-{self.index}-{root.name}"
            destination.mkdir()
            result = reference_phase(
                root, [archive], "install" if configure else "unpack",
                self.environment, destination, packages=[],
            )
            if result:
                raise AssertionError(f"reference seed failed: {destination}")
            m.write(root / TRACE, b"")
        self.index += 1

    def fail(self, *identities: str) -> None:
        for root in self.roots:
            path = root / FAILURE
            if identities:
                m.write(path, ("\n".join(identities) + "\n").encode())
                os.utime(path, (m.EPOCH, m.EPOCH))
            elif path.exists():
                path.unlink()

    def phase(
        self,
        operation: str,
        archives: list[Path] | None = None,
        *,
        names: tuple[str, ...] = (m.PACKAGE,),
        failure: bool = False,
        policy: str = "keep_existing",
        ordered_actions: list[dict] | None = None,
        rollback_clock: tuple[str, ...] = (),
        reference_groups: list[list[Path]] | None = None,
    ) -> None:
        destination = self.directory / f"{self.index}-{operation}"
        destination.mkdir()
        self.index += 1
        packages = self.identities(names)
        rollback_times = {
            path: (self.expected / path).lstat().st_mtime_ns for path in rollback_clock
        }
        started = time.time_ns()
        def reference(root: Path, output: Path) -> int:
            for index, group in enumerate(reference_groups or [archives or []]):
                group_output = output
                if reference_groups:
                    group_output = output / f"group-{index}"
                    group_output.mkdir()
                result = reference_phase(
                    root, group, operation, self.environment, group_output,
                    packages=packages, policy=policy,
                )
                if result:
                    return result
            return 0

        result = reference(self.expected, destination)
        if bool(result) != failure:
            raise AssertionError(
                f"{self.directory.name}: reference exit {result}, expected failure={failure}; "
                f"{destination / 'reference.log'}"
            )
        if self.executable:
            report = native(
                self.executable, self.candidate, archives or [], operation,
                self.architecture, self.environment, destination, packages=packages,
                policy=policy, ordered_actions=ordered_actions,
            )
            wanted = "script_failed" if failure else "applied"
            if report["outcome"] != wanted:
                with (destination / "native.log").open("rb") as log:
                    detail = log.read(12_000).decode(errors="replace")
                raise AssertionError(
                    f"{self.directory.name}/{operation}: expected {wanted}: {report}\n{detail}"
                )
            for name in ("root-operation-v1.json", "root-mutation-v1.json"):
                if (self.candidate / "var/lib/debz" / name).exists():
                    raise AssertionError(f"known lifecycle outcome stranded {name}")
        else:
            oracle_destination = destination / "oracle"
            oracle_destination.mkdir()
            observed = reference(self.candidate, oracle_destination)
            if observed != result:
                raise AssertionError("reference fixture is not repeatable")
        compare_roots(
            self.expected, self.candidate, destination,
            rollback_times, started, time.time_ns(),
        )
        snapshot = m.snapshot(self.expected)
        self.observations.append({
            "operation": operation, "exit": result,
            "status": snapshot["dpkg"]["status"],
            "trace": snapshot["trace"],
        })
        m.write(
            self.directory / "observations.json",
            m.oracle.canonical_json({"phases": self.observations}).encode(),
        )

    def complete(self) -> None:
        label = "native/dpkg parity" if self.executable else "oracle fixture"
        print(f"{self.directory.name}: {label} passed", flush=True)


def metadata_scripts(package: str, version: str) -> dict[str, bytes]:
    result = scripts(package, version)
    for kind, source in result.items():
        observation = f"""
printf '%s' 'metadata:{package}@{version}:{kind}' >> /{TRACE}
for member in templates shlibs symbols; do
    path="/var/lib/dpkg/info/{package}.$member"
    if [ ! -f "$path" ]; then
        path="/var/lib/dpkg/info/{package}:$DPKG_MAINTSCRIPT_ARCH.$member"
    fi
    value='<absent>'
    if [ -f "$path" ]; then
        IFS= read -r value < "$path"
    fi
    printf '\\t%s=%s' "$member" "$value" >> /{TRACE}
done
printf '\\n' >> /{TRACE}
""".encode()
        failure_guard = f"if [ -f /{FAILURE} ]; then\n".encode()
        result[kind] = source.replace(failure_guard, observation + failure_guard, 1)
    return result


def metadata_contents(version: str) -> dict[str, bytes]:
    if version == "3":
        return {}
    if version not in ("1", "2"):
        raise ValueError(f"unsupported metadata fixture version: {version}")
    result = {
        "templates": f"Template: {METADATA_PACKAGE}/v{version}\nType: string\nDescription: inert fixture\n".encode(),
        "shlibs": f"libretained-metadata 1 {METADATA_PACKAGE} (>= {version})\n".encode(),
    }
    if version == "1":
        result["symbols"] = f"libretained-metadata.so.1 {METADATA_PACKAGE} #MINVER#\n symbol@Base 1\n".encode() + b"\x00\xff"
    return result


def make_metadata_packages(
    workspace: Path, environment: dict[str, str], architecture: str, *,
    multiarch: bool = False, conffile: bool = True,
) -> dict[str, Path]:
    result = {}
    for version in ("1", "2", "3"):
        def prepare_payload(source: Path, version: str = version) -> None:
            for name, content in metadata_contents(version).items():
                m.write(source / "DEBIAN" / name, content, 0o640 if name == "shlibs" else 0o644)

        result[version] = m.make_package(
            workspace, environment, architecture, version, "conffile" if conffile else "data",
            package=METADATA_PACKAGE, scripts=metadata_scripts(METADATA_PACKAGE, version),
            conffile_content=f"metadata configuration {version}\n".encode(),
            control_fields={"Multi-Arch": "same"} if multiarch else {},
            prepare_payload=prepare_payload,
        )
    return result


def make_literal_packages(
    workspace: Path, environment: dict[str, str], architecture: str,
) -> dict[str, Path]:
    archives = {}
    for version in ("1", "2"):
        def prepare_payload(source: Path, version: str = version) -> None:
            directory = source / "usr/share/literal\\directory"
            m.write(directory / "..\\literal", f"literal payload {version}\n".encode())
            os.link(directory / "..\\literal", directory / "hard\\link")
            (directory / "symbolic\\link").symlink_to("..\\literal")
            m.write(
                source / "usr/lib/systemd/system/system-systemd\\x2dmute.slice",
                f"literal unit {version}\n".encode(),
            )
            m.write(source / LITERAL_CONFFILE, f"literal configuration {version}\n".encode())
            m.write(source / "DEBIAN/conffiles", f"/{LITERAL_CONFFILE.as_posix()}\n".encode())

        archives[version] = m.make_package(
            workspace, environment, architecture, version,
            package=LITERAL_PACKAGE, scripts=scripts(LITERAL_PACKAGE, version),
            prepare_payload=prepare_payload,
        )
    return archives


def conffile_scripts(package: str, version: str) -> dict[str, bytes]:
    result = scripts(package, version)
    paths = " ".join(shlex.quote("/" + path.as_posix()) for path in CONFFILE_PATHS)
    for kind, source in result.items():
        observation = f"""
printf '%s' 'conffiles:{package}@{version}:{kind}' >> /{TRACE}
for path in {paths}; do
    for suffix in '' .dpkg-new .dpkg-old .dpkg-dist; do
        present=no
        if [ -e "$path$suffix" ] || [ -L "$path$suffix" ]; then
            present=yes
        fi
        printf '\\t%s%s=%s' "$path" "$suffix" "$present" >> /{TRACE}
    done
done
if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ] && [ "$1" = purge ]; then
    selected=no
    declared=no
    while IFS= read -r line; do
        case "$line" in
            'Package: {package}') selected=yes ;;
            'Package: '*) selected=no ;;
            'Conffiles:') if [ "$selected" = yes ]; then declared=yes; fi ;;
        esac
    done < /var/lib/dpkg/status
    printf '\\tdeclared=%s' "$declared" >> /{TRACE}
fi
printf '\\n' >> /{TRACE}
if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ] && [ "$1" = purge ] && [ -f /conffile-recreate ]; then
    /ln /administrator-configuration /etc/debz-native.conf || exit 24
fi
if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ] && [ "$1" = purge ] && [ -f /conffile-activate ]; then
    /usr/bin/dpkg-trigger --no-await {CONFFILE_TRIGGER} || exit 25
fi
""".encode()
        guard = f"if [ -f /{FAILURE} ]; then\n".encode()
        result[kind] = source.replace(guard, observation + guard, 1)
    return result


def make_conffile_packages(
    workspace: Path, environment: dict[str, str], architecture: str,
) -> dict[str, Path]:
    result = {}
    for version in ("1", "2"):
        def prepare(source: Path, version: str = version) -> None:
            m.write(source / CONFFILE_PATHS[1], f"extra configuration {version}\n".encode())
            m.write(
                source / "DEBIAN/conffiles",
                "".join(f"/{path.as_posix()}\n" for path in CONFFILE_PATHS).encode(),
            )

        result[version] = m.make_package(
            workspace, environment, architecture, version, "conffile",
            package=CONFFILE_PACKAGE, scripts=conffile_scripts(CONFFILE_PACKAGE, version),
            conffile_content=f"configuration {version}\n".encode(), prepare_payload=prepare,
        )
    return result


def statoverride_scripts(package: str, version: str) -> dict[str, bytes]:
    result = scripts(package, version)
    replacement = b"""
if [ "$DPKG_MAINTSCRIPT_NAME" = preinst ]; then
    if [ -f /statoverride-passwd-replace ]; then
        /stato-mv /statoverride-passwd-replace /etc/passwd || exit 26
    fi
    if [ -f /statoverride-preinst-replace ]; then
        /stato-mv /statoverride-preinst-replace /var/lib/dpkg/statoverride || exit 27
    fi
fi
if [ "$DPKG_MAINTSCRIPT_NAME" = postinst ] && [ "$1" = configure ] && [ -f /statoverride-postinst-replace ]; then
    /stato-mv /statoverride-postinst-replace /var/lib/dpkg/statoverride || exit 28
fi
"""
    guard = f"if [ -f /{FAILURE} ]; then\n".encode()
    for kind, source in result.items():
        result[kind] = source.replace(guard, replacement + guard, 1)
    return result


def make_statoverride_packages(
    workspace: Path, environment: dict[str, str], architecture: str,
) -> dict[str, Path]:
    return {
        version: m.make_package(
            workspace, environment, architecture, version, "conffile",
            package=STATO_PACKAGE, scripts=statoverride_scripts(STATO_PACKAGE, version),
            conffile_content=f"configuration {version}\n".encode(),
            extra_files={STATO_LITERAL.as_posix(): f"literal version {version}\n".encode()},
        )
        for version in ("1", "2")
    }


def seed_statoverrides(root: Path, records: str) -> None:
    for path, data in (
        ("etc/passwd", STATO_PASSWD),
        ("etc/group", STATO_GROUP),
        ("var/lib/dpkg/statoverride", records.encode()),
    ):
        m.write(root / path, data)
        os.utime(root / path, (m.EPOCH, m.EPOCH))


def seed_statoverride_replacement(root: Path, marker: str, content: bytes) -> None:
    runtime.copy_program(root, Path("/bin/mv").resolve(), "/stato-mv")
    m.write(root / marker, content)
    os.utime(root / marker, (m.EPOCH, m.EPOCH))


def exercise_statoverride_lifecycle(
    executable: Path | None, workspace: Path, environment: dict[str, str], architecture: str,
) -> None:
    archives = make_statoverride_packages(workspace / "statoverride-packages", environment, architecture)
    for name, records, path, expected, existing in (
        ("numeric", f"#42420 #42421 4750 /{STATO_BASE}/mode\n", "mode", (0o4750, 42420, 42421), False),
        ("named", f"_debzstat _debzstat 4750 /{STATO_BASE}/mode\n", "mode", (0o4750, 42420, 42421), False),
        ("directory-new", f"#42420 #42421 2710 /{STATO_BASE}/empty\n", "empty", (0o2710, 42420, 42421), False),
        ("directory-existing", f"#42420 #42421 2710 /{STATO_BASE}/empty\n", "empty", (0o700, 0, 0), True),
        ("conffile", "#42420 #42421 0640 /etc/debz-native.conf\n", "/etc/debz-native.conf", (0o640, 42420, 42421), False),
        ("symlink", f"#42420 #42421 0640 /{STATO_BASE}/current\n", "current", (0o777, 42420, 42421), False),
        ("literal", f"#42420 #42421 0640 /{STATO_LITERAL.as_posix()}\n", "/" + STATO_LITERAL.as_posix(), (0o640, 42420, 42421), False),
        ("hardlink-source", f"#42420 #42421 0640 /{STATO_BASE}/data\n", "data", (0o644, 0, 0), False),
        ("hardlink-target", f"#42420 #42421 0640 /{STATO_BASE}/data.link\n", "data.link", (0o640, 42420, 42421), False),
        (
            "hardlink-both",
            f"#42420 #42421 0640 /{STATO_BASE}/data\n#42422 #42423 0600 /{STATO_BASE}/data.link\n",
            "data", (0o600, 42422, 42423), False,
        ),
    ):
        current = Scenario(workspace, f"statoverride-{name}", executable, architecture, environment)
        for root in current.roots:
            seed_statoverrides(root, records)
            if existing:
                (root / STATO_BASE / "empty").mkdir(parents=True)
                (root / STATO_BASE / "empty").chmod(0o700)
        for operation, version in (("install", "1"), ("upgrade", "2"), ("reinstall", "2"), ("downgrade", "1")):
            current.phase(operation, [archives[version]], names=(STATO_PACKAGE,))
            for root in current.roots:
                target = root / (path[1:] if path.startswith("/") else f"{STATO_BASE}/{path}")
                entry = target.lstat()
                assert (entry.st_mode & 0o7777, entry.st_uid, entry.st_gid) == expected
                assert (root / STATO_BASE / "data").samefile(root / STATO_BASE / "data.link")
        current.phase("remove", names=(STATO_PACKAGE,))
        current.phase("purge", names=(STATO_PACKAGE,))
        for root in current.roots:
            assert (root / "var/lib/dpkg/statoverride").read_bytes() == records.encode()
        current.complete()

    named_record = f"_debzstat _debzstat 4750 /{STATO_BASE}/mode\n"
    for name, records, marker, content, next_metadata in (
        ("account-preinst", named_record, "statoverride-passwd-replace", STATO_PASSWD.replace(b":42420:", b":42422:"), (0o4750, 42422, 42421)),
        ("override-preinst", named_record, "statoverride-preinst-replace", f"#42422 #42423 0640 /{STATO_BASE}/mode\n".encode(), (0o640, 42422, 42423)),
        ("override-postinst", named_record, "statoverride-postinst-replace", f"#42422 #42423 0640 /{STATO_BASE}/mode\n".encode(), (0o640, 42422, 42423)),
        ("override-created", "", "statoverride-preinst-replace", named_record.encode(), (0o4750, 42420, 42421)),
    ):
        current = Scenario(workspace, f"statoverride-{name}", executable, architecture, environment)
        for root in current.roots:
            seed_statoverrides(root, records)
            seed_statoverride_replacement(root, marker, content)
        initial_metadata = (0o4750, 42420, 42421) if records else (0o600, 0, 0)
        for operation, expected in (("install", initial_metadata), ("reinstall", next_metadata)):
            current.phase(operation, [archives["1"]], names=(STATO_PACKAGE,))
            for root in current.roots:
                entry = (root / STATO_BASE / "mode").stat()
                assert (entry.st_mode & 0o7777, entry.st_uid, entry.st_gid) == expected
        current.complete()

    alias_archive = m.make_package(
        workspace / "statoverride-alias-package", environment, architecture, "1",
        package=STATO_PACKAGE, scripts=statoverride_scripts(STATO_PACKAGE, "1"),
        extra_files={"usr/bin/statoverride-mode": b"aliased payload\n"},
    )
    for spelling in ("bin", "usr/bin"):
        current = Scenario(workspace, f"statoverride-alias-{spelling.replace('/', '-')}", executable, architecture, environment)
        for root in current.roots:
            (root / "usr").mkdir(exist_ok=True)
            (root / "bin").rename(root / "usr/bin")
            (root / "bin").symlink_to("usr/bin")
            os.utime(root / "bin", (m.EPOCH, m.EPOCH), follow_symlinks=False)
            seed_statoverrides(root, f"#42420 #42421 4750 /{spelling}/statoverride-mode\n")
        current.phase("install", [alias_archive], names=(STATO_PACKAGE,))
        expected = (0o4750, 42420, 42421) if spelling == "usr/bin" else (0o644, 0, 0)
        for root in current.roots:
            entry = (root / "usr/bin/statoverride-mode").stat()
            assert (entry.st_mode & 0o7777, entry.st_uid, entry.st_gid) == expected
        current.complete()

    for policy in ("keep_existing", "use_package_version"):
        current = Scenario(workspace, f"statoverride-conffile-{policy}", executable, architecture, environment)
        for root in current.roots:
            seed_statoverrides(root, "#42420 #42421 0640 /etc/debz-native.conf\n")
        current.seed(archives["1"])
        for root in current.roots:
            path = root / "etc/debz-native.conf"
            m.write(path, b"administrator configuration\n", 0o600)
            os.chown(path, 42424, 42425)
            os.utime(path, (m.EPOCH, m.EPOCH))
        current.phase("upgrade", [archives["2"]], names=(STATO_PACKAGE,), policy=policy)
        for root in current.roots:
            entry = (root / "etc/debz-native.conf").stat()
            assert (entry.st_mode & 0o7777, entry.st_uid, entry.st_gid) == (0o600, 42424, 42425)
        current.complete()

    if executable is not None:
        for name, user, group in (
            ("missing-user", "nobody", "#42421"),
            ("missing-group", "#42420", "nogroup"),
            ("invalid-id", "#4294967295", "#42421"),
        ):
            current = Scenario(workspace, f"statoverride-{name}", executable, architecture, environment)
            for root in current.roots:
                seed_statoverrides(root, f"{user} {group} 0640 /{STATO_BASE}/mode\n")
            before = m.snapshot(current.candidate)
            destination = current.directory / "refusal"
            destination.mkdir()
            report = native(
                executable, current.candidate, [archives["1"]], "install",
                architecture, environment, destination,
                packages=current.identities((STATO_PACKAGE,)),
            )
            assert report["outcome"] == "refused" and report["detail"] == "invalid_stat_override", report
            assert not m.oracle.differences(before, m.snapshot(current.candidate))
            print(f"statoverride-{name}: invalid target-root identities refuse before mutation", flush=True)


def exercise_conffile_lifecycle(
    executable: Path | None, workspace: Path, environment: dict[str, str], architecture: str,
) -> None:
    archives = make_conffile_packages(workspace / "conffile-lifecycle-packages", environment, architecture)
    for removed in (False, True):
        for failed in (False, True):
            current = Scenario(
                workspace, f"conffile-purge-removed-{removed}-failure-{failed}",
                executable, architecture, environment,
            )
            current.seed(archives["1"])
            if removed:
                current.phase("remove", names=(CONFFILE_PACKAGE,))
            if failed:
                current.fail(f"{CONFFILE_PACKAGE}@1:postrm:purge")
            current.phase("purge", names=(CONFFILE_PACKAGE,), failure=failed)
            if failed:
                for root in current.roots:
                    assert all(not (root / path).exists() for path in CONFFILE_PATHS)
                    assert (root / f"var/lib/dpkg/info/{CONFFILE_PACKAGE}.postrm").is_file()
                current.fail()
                current.phase("purge", names=(CONFFILE_PACKAGE,))
            current.complete()

    for failed in (False, True):
        current = Scenario(workspace, f"conffile-purge-script-recreates-failure-{failed}", executable, architecture, environment)
        current.seed(archives["1"])
        for root in current.roots:
            runtime.copy_program(root, Path("/bin/ln").resolve(), "/ln")
            for path, content in (("administrator-configuration", b"administrator configuration\n"), ("conffile-recreate", b"")):
                m.write(root / path, content)
                os.utime(root / path, (m.EPOCH, m.EPOCH))
        if failed:
            current.fail(f"{CONFFILE_PACKAGE}@1:postrm:purge")
        current.phase("purge", names=(CONFFILE_PACKAGE,), failure=failed)
        for root in current.roots:
            assert (root / CONFFILE_PATHS[0]).samefile(root / "administrator-configuration")
        if failed:
            current.fail()
            for root in current.roots:
                (root / "conffile-recreate").unlink()
            current.phase("purge", names=(CONFFILE_PACKAGE,))
        current.complete()

    for policy in ("keep_existing", "use_package_version"):
        for upgrade in (False, True):
            for mutation in ("unchanged", "edited", "missing", "side-files"):
                current = Scenario(
                    workspace, f"conffile-configure-retry-{policy}-upgrade-{upgrade}-{mutation}",
                    executable, architecture, environment,
                )
                version = "2" if upgrade else "1"
                if upgrade:
                    current.seed(archives["1"])
                    for root in current.roots:
                        for path in CONFFILE_PATHS:
                            m.write(root / path, b"administrator configuration\n")
                            os.utime(root / path, (m.EPOCH, m.EPOCH))
                current.fail(f"{CONFFILE_PACKAGE}@{version}:postinst:configure")
                current.phase(
                    "upgrade" if upgrade else "install", [archives[version]],
                    names=(CONFFILE_PACKAGE,), policy=policy, failure=True,
                )
                current.fail()
                for root in current.roots:
                    for path in CONFFILE_PATHS:
                        if mutation == "missing":
                            (root / path).unlink()
                        elif mutation in ("edited", "side-files"):
                            target = root / (Path(str(path) + ".dpkg-new") if mutation == "side-files" else path)
                            m.write(target, b"administrator edit after failure\n")
                            os.utime(target, (m.EPOCH, m.EPOCH))
                current.phase("configure", [archives[version]], names=(CONFFILE_PACKAGE,), policy=policy)
                current.complete()

    if executable is None:
        return
    changed = m.make_package(
        workspace / "conffile-drift-package", environment, architecture, "1", "conffile",
        package=CONFFILE_PACKAGE, scripts=conffile_scripts(CONFFILE_PACKAGE, "1"),
        conffile_content=b"different archive configuration\n",
    )
    for mode in ("unpacked-missing-stage", "unpacked-changed-stage", "configured-changed-archive"):
        current = Scenario(workspace, f"conffile-refusal-{mode}", executable, architecture, environment)
        if mode.startswith("unpacked"):
            current.seed(archives["1"])
            current.seed(archives["2"], configure=False)
            path = current.candidate / (str(CONFFILE_PATHS[0]) + ".dpkg-new")
            if mode.endswith("missing-stage"):
                path.unlink()
            else:
                m.write(path, b"changed staged configuration\n")
            expected = "staged_conffile_mismatch"
        else:
            current.fail(f"{CONFFILE_PACKAGE}@1:postinst:configure")
            current.phase("install", [archives["1"]], names=(CONFFILE_PACKAGE,), failure=True)
            current.fail()
            expected = "configured_conffile_mismatch"
        destination = current.directory / "refusal"
        destination.mkdir()
        before = m.snapshot(current.candidate)
        report = native(
            executable, current.candidate, [changed if mode.startswith("configured") else archives["2"]],
            "configure", architecture, environment, destination,
            packages=current.identities((CONFFILE_PACKAGE,)),
        )
        assert report["outcome"] == "refused" and report["detail"] == expected, report
        assert not m.oracle.differences(before, m.snapshot(current.candidate))
        print(f"conffile-refusal-{mode}: mismatched configuration refuses without mutation", flush=True)


def exercise(
    executable: Path | None,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
) -> None:
    exercise_statoverride_lifecycle(executable, workspace, environment, architecture)
    exercise_conffile_lifecycle(executable, workspace, environment, architecture)
    archives = {
        version: m.make_package(
            workspace / "packages", environment, architecture, version,
            scripts=scripts(m.PACKAGE, version),
        )
        for version in ("1", "2")
    }

    def case(name: str) -> Scenario:
        return Scenario(workspace, name, executable, architecture, environment)

    metadata_archives = make_metadata_packages(workspace / "metadata-packages", environment, architecture)
    qualified_metadata = make_metadata_packages(
        workspace / "metadata-qualified-packages", environment, architecture, multiarch=True,
    )
    data_metadata = make_metadata_packages(
        workspace / "metadata-data-packages", environment, architecture, conffile=False,
    )
    for label, first, later in (
        ("unqualified", metadata_archives, metadata_archives),
        ("qualified", qualified_metadata, qualified_metadata),
        ("stem-change", metadata_archives, qualified_metadata),
    ):
        current = case(f"retained-metadata-{label}")
        for operation, version, metadata_set in (
            ("install", "1", first), ("upgrade", "2", later), ("reinstall", "2", later),
            ("downgrade", "1", first), ("upgrade", "3", later), ("downgrade", "2", later),
        ):
            current.phase(operation, [metadata_set[version]], names=(METADATA_PACKAGE,))
        current.phase("remove", names=(METADATA_PACKAGE,))
        current.phase("purge", names=(METADATA_PACKAGE,))
        current.complete()
    for label, seed, failures, expected_failure in (
        ("fresh-postinst-failure", False, ("1:postinst:configure",), True),
        ("upgrade-old-postrm-compensated", True, ("1:postrm:upgrade",), False),
        ("upgrade-old-postrm-failure", True, ("1:postrm:upgrade", "2:postrm:failed-upgrade"), True),
    ):
        current = case(f"retained-metadata-{label}")
        if seed:
            current.seed(metadata_archives["1"])
        current.fail(*(f"{METADATA_PACKAGE}@{failure}" for failure in failures))
        current.phase(
            "upgrade" if seed else "install", [metadata_archives["2" if seed else "1"]],
            names=(METADATA_PACKAGE,), failure=expected_failure,
            rollback_clock=(f"usr/share/{METADATA_PACKAGE}/current",)
            if "2:postrm:failed-upgrade" in failures else (),
        )
        current.complete()

    current = case("retained-metadata-direct-purge")
    current.seed(metadata_archives["1"])
    current.phase("purge", names=(METADATA_PACKAGE,))
    current.complete()

    for profile, selected in (("data", data_metadata), ("conffile", metadata_archives)):
        current = case(f"retained-metadata-configure-retry-{profile}")
        current.fail(f"{METADATA_PACKAGE}@1:postinst:configure")
        current.phase("install", [selected["1"]], names=(METADATA_PACKAGE,), failure=True)
        current.fail()
        current.phase("configure", [selected["1"]], names=(METADATA_PACKAGE,))
        current.complete()
    for operation, profile, selected in (
        ("remove", "conffile", metadata_archives),
        ("purge", "data", data_metadata),
        ("purge", "conffile", metadata_archives),
    ):
        current = case(f"retained-metadata-{operation}-postrm-failure-{profile}")
        current.seed(selected["1"])
        current.fail(f"{METADATA_PACKAGE}@1:postrm:{operation}")
        current.phase(operation, names=(METADATA_PACKAGE,), failure=True)
        if operation == "purge":
            current.fail()
            current.phase("purge", names=(METADATA_PACKAGE,))
        current.complete()

    literal_archives = make_literal_packages(workspace / "literal-packages", environment, architecture)
    for policy in ("keep_existing", "use_package_version"):
        current = case(f"literal-package-paths-{policy}")
        current.phase("install", [literal_archives["1"]], names=(LITERAL_PACKAGE,))
        for root in current.roots:
            m.write(root / LITERAL_CONFFILE, b"administrator configuration\n")
            os.utime(root / LITERAL_CONFFILE, (m.EPOCH, m.EPOCH))
        current.phase("upgrade", [literal_archives["2"]], names=(LITERAL_PACKAGE,), policy=policy)
        current.phase("reinstall", [literal_archives["2"]], names=(LITERAL_PACKAGE,), policy=policy)
        current.phase("remove", names=(LITERAL_PACKAGE,))
        current.phase("purge", names=(LITERAL_PACKAGE,))
        current.complete()

    for operation, initial, final in (
        ("install", None, "1"), ("upgrade", "1", "2"),
        ("downgrade", "2", "1"), ("reinstall", "1", "1"),
    ):
        current = case(operation)
        if initial:
            current.seed(archives[initial])
        current.phase(operation, [archives[final]])
        current.complete()

    for operation in ("remove", "purge"):
        current = case(operation)
        current.seed(archives["1"])
        current.phase(operation)
        current.phase(operation)
        if operation == "remove":
            current.phase("purge")
        current.complete()

    current = case("upgrade-unconfigured")
    current.seed(archives["1"], configure=False)
    current.phase("upgrade", [archives["2"]])
    current.complete()

    for kind in ("preinst", "postinst"):
        current = case(f"fresh-{kind}-failure")
        argument = "install" if kind == "preinst" else "configure"
        current.fail(f"{m.PACKAGE}@1:{kind}:{argument}")
        current.phase("install", [archives["1"]], failure=True)
        if kind == "postinst":
            current.fail()
            current.phase("configure", [archives["1"]])
        current.complete()

    current = case("fresh-abort-install-failure")
    current.fail(
        f"{m.PACKAGE}@1:preinst:install",
        f"{m.PACKAGE}@1:postrm:abort-install",
    )
    current.phase("install", [archives["1"]], failure=True)
    current.complete()

    no_postrm = m.make_package(
        workspace / "packages/no-postrm", environment, architecture, "1",
        scripts={kind: body for kind, body in scripts(m.PACKAGE, "1").items() if kind != "postrm"},
    )
    current = case("fresh-preinst-failure-no-postrm")
    current.fail(f"{m.PACKAGE}@1:preinst:install")
    current.phase("install", [no_postrm], failure=True)
    current.complete()

    upgrade_failures = (
        ("old-prerm", ("1:prerm:upgrade",), False),
        ("failed-upgrade-prerm", ("1:prerm:upgrade", "2:prerm:failed-upgrade"), True),
        ("new-preinst", ("2:preinst:upgrade",), True),
        ("old-postrm", ("1:postrm:upgrade",), False),
        ("failed-upgrade-postrm", ("1:postrm:upgrade", "2:postrm:failed-upgrade"), True),
        ("new-postinst", ("2:postinst:configure",), True),
        ("abort-upgrade-postinst", ("2:preinst:upgrade", "1:postinst:abort-upgrade"), True),
        ("abort-upgrade-preinst", (
            "1:postrm:upgrade", "2:postrm:failed-upgrade", "1:preinst:abort-upgrade",
        ), True),
        ("abort-upgrade-postrm", (
            "1:postrm:upgrade", "2:postrm:failed-upgrade", "2:postrm:abort-upgrade",
        ), True),
    )
    for name, failures, failed in upgrade_failures:
        current = case(f"upgrade-{name}-failure")
        current.seed(archives["1"])
        current.fail(*(f"{m.PACKAGE}@{item}" for item in failures))
        current.phase(
            "upgrade", [archives["2"]], failure=failed,
            rollback_clock=(str(m.PAYLOAD / "current"),)
            if "2:postrm:failed-upgrade" in failures else (),
        )
        if name == "new-postinst":
            current.fail()
            current.phase("configure", [archives["2"]])
        current.complete()

    for name, operation, failures in (
        ("remove-prerm", "remove", ("1:prerm:remove",)),
        ("remove-abort-remove", "remove", ("1:prerm:remove", "1:postinst:abort-remove")),
        ("remove-postrm", "remove", ("1:postrm:remove",)),
        ("purge-postrm", "purge", ("1:postrm:purge",)),
    ):
        current = case(f"{name}-failure")
        current.seed(archives["1"])
        current.fail(*(f"{m.PACKAGE}@{item}" for item in failures))
        current.phase(operation, failure=True)
        current.complete()

    provider, consumer = "debz-lifecycle-provider", "debz-lifecycle-consumer"
    provider_archive = m.make_package(
        workspace / "packages/provider", environment, architecture, "1",
        package=provider, scripts=scripts(provider, "1"),
    )
    consumer_archive = m.make_package(
        workspace / "packages/consumer", environment, architecture, "1",
        package=consumer,
        scripts=scripts(consumer, "1", preinst_requires_configured=provider),
        control_fields={"Pre-Depends": f"{provider} (= 1)"},
    )
    current = case("pre-depends-barrier")
    current.phase(
        "install", [provider_archive, consumer_archive], names=(provider, consumer),
        ordered_actions=ordered(architecture, [
            ("unpack", provider), ("configure_pending", consumer),
            ("unpack", consumer), ("configure_pending", consumer),
        ]),
        reference_groups=[[provider_archive], [consumer_archive]],
    )
    current.complete()

    cycle_a, cycle_b = "debz-lifecycle-cycle-a", "debz-lifecycle-cycle-b"
    cycle_archives = [
        m.make_package(
            workspace / f"packages/{name}", environment, architecture, "1",
            package=name,
            scripts=scripts(name, "1", postinst_requires_payload=peer),
            control_fields={"Depends": f"{peer} (= 1)"},
        )
        for name, peer in ((cycle_a, cycle_b), (cycle_b, cycle_a))
    ]
    current = case("dependency-cycle")
    current.phase("install", cycle_archives, names=(cycle_a, cycle_b))
    current.complete()

    bootstrap = "debz-lifecycle-essential"
    bootstrap_archive = m.make_package(
        workspace / "packages/bootstrap", environment, architecture, "1",
        package=bootstrap, scripts=scripts(bootstrap, "1"),
        control_fields={"Essential": "yes"},
        prepare_payload=lambda source: runtime.copy_program(source, Path("/bin/sh"), "/bin/sh"),
        compression="none",
    )
    current = Scenario(
        workspace, "essential-bootstrap", executable, architecture, environment,
        bootstrap=True,
    )
    for root in current.roots:
        if (root / "bin/sh").exists():
            raise AssertionError("bootstrap fixture already contains the required interpreter")
    for root in (current.expected,) if executable else current.roots:
        m.reference_command(root)
        m.run(
            ["dpkg-deb", "--extract", str(bootstrap_archive), str(root)],
            environment, current.directory / f"{root.name}-bootstrap.log",
        )
    current.phase(
        "install", [bootstrap_archive], names=(bootstrap,),
        ordered_actions=ordered(architecture, [
            ("bootstrap_extract", bootstrap), ("unpack", bootstrap),
            ("configure_pending", bootstrap),
        ]),
    )
    current.complete()

    for name, operation, version, fault, kind, source, arguments, trace_count in (
        ("script-outcome-unknown", "install", "1", "after_script_before_record",
         "preinst", "new_package", ["install"], 1),
        ("upgrade-postrm-outcome-unknown", "upgrade", "2", "after_upgrade_postrm_before_record",
         "postrm", "installed_package", ["upgrade", "2"], 3),
    ) if executable else ():
        current = case(name)
        if operation == "upgrade":
            current.seed(archives["1"])
        destination = current.directory / "interrupted"
        destination.mkdir()
        report = native(
            executable, current.candidate, [archives[version]], operation, architecture,
            environment, destination, packages=current.identities((m.PACKAGE,)),
            fault=fault,
        )
        if report["outcome"] != "recovery_required":
            raise AssertionError(f"unknown script outcome did not retain recovery evidence: {report}")
        record_path = current.candidate / "var/lib/debz/root-operation-v1.json"
        record_bytes = record_path.read_bytes()
        record = json.loads(record_bytes)
        if (
            record["state"] != "recovery_required"
            or record["phase"] != "script"
            or record["mutation_started"] is not True
            or record["backend"] != "native"
            or record["install_root"] != str(current.candidate)
            or not re.fullmatch(r"[0-9a-f]{64}", record["program_sha256"] or "")
            or record["program_sha256"] == "0" * 64
        ):
            raise AssertionError(f"incomplete durable script binding: {record}")
        script_path = current.candidate / "var/lib/debz/native-lifecycle-script-v1.json"
        script_bytes = script_path.read_bytes()
        script_record = json.loads(script_bytes)
        if (
            script_record["program_sha256"] != record["program_sha256"]
            or script_record["package"] != m.PACKAGE
            or script_record["version"] != "1"
            or script_record["architecture"] != architecture
            or script_record["kind"] != kind
            or script_record["source"] != source
            or script_record["arguments"] != arguments
            or script_record["script_sha256"] != hashlib.sha256(scripts(m.PACKAGE, "1")[kind]).hexdigest()
            or script_record["outcome"] != "in_flight"
            or script_record["exit_code"] is not None
        ):
            raise AssertionError(f"wrong durable invocation: {script_record}")
        before = m.snapshot(current.candidate)
        if len(before["trace"]) != trace_count or not before["trace"][-1].startswith(
            f"{m.PACKAGE}@1:{kind}\t"
        ):
            raise AssertionError("interruption fixture did not actually reach the selected script")
        for retry_name, retry_operation, retry_archives, retry_packages in (
            ("same-operation", operation, [archives[version]], (m.PACKAGE,)),
            ("absent-purge", "purge", [], ("debz-lifecycle-absent",)),
        ):
            retry = current.directory / retry_name
            retry.mkdir()
            report = native(
                executable, current.candidate, retry_archives, retry_operation, architecture,
                environment, retry, packages=current.identities(retry_packages),
            )
            if report["outcome"] != "recovery_required":
                raise AssertionError(f"ambiguous script permitted another operation: {report}")
            if record_path.read_bytes() != record_bytes or script_path.read_bytes() != script_bytes:
                raise AssertionError("blocked mutation overwrote the active script evidence")
            mismatches = m.oracle.differences(before, m.snapshot(current.candidate), maximum=30)
            if mismatches:
                raise AssertionError("blocked mutation reran or changed state:\n" + "\n".join(mismatches))
        print(f"{name}: durable re-entry blocking passed", flush=True)

    if executable:
        unrelated = "debz-lifecycle-unrelated"
        unrelated_archive = m.make_package(
            workspace / "packages/unrelated", environment, architecture, "1",
            package=unrelated,
        )
        changed_database_scripts = scripts(m.PACKAGE, "1")
        changed_database_scripts["postinst"] = rewrite_database_field(
            changed_database_scripts["postinst"], unrelated, "Version: 1", "Version: 9",
        )
        changed_database_archive = m.make_package(
            workspace / "packages/changed-database", environment, architecture, "1",
            scripts=changed_database_scripts,
        )
        current = case("unexpected-final-package-version")
        current.seed(unrelated_archive)
        destination = current.directory / "install"
        destination.mkdir()
        report = native(
            executable, current.candidate, [changed_database_archive], "install", architecture,
            environment, destination, packages=current.identities((m.PACKAGE,)),
        )
        if report["outcome"] != "recovery_required":
            raise AssertionError(f"unexpected final package closure was accepted: {report}")
        record = json.loads(
            (current.candidate / "var/lib/debz/root-operation-v1.json").read_bytes()
        )
        if record["state"] != "recovery_required" or record["phase"] != "verification":
            raise AssertionError(f"final-closure failure lost verification evidence: {record}")
        observed = m.snapshot(current.candidate)
        if not any(
            item.get("package") == unrelated and item.get("version") == "9"
            for item in observed["dpkg"]["status"]
        ):
            raise AssertionError("script did not actually change the unselected package")
        print("unexpected-final-package-version: final verification blocked completion", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", nargs="?", type=Path)
    parser.add_argument(
        "--oracle-only", action="store_true",
        help="check reference fixture consistency only; does not establish native parity",
    )
    parser.add_argument("--workspace", type=Path, help="retain artifacts in a new .tmp directory")
    parser.add_argument("--reference-dpkg", type=Path)
    arguments = parser.parse_args()
    if arguments.oracle_only == bool(arguments.native_test):
        parser.error("provide a native test executable or --oracle-only, not both")
    if os.geteuid() != 0:
        raise RuntimeError("lifecycle acceptance requires root for actual chroot execution")
    for command in ("dpkg", "dpkg-deb", "ldd"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required reference tool is missing: {command}")
    executable = arguments.native_test.resolve(strict=True) if arguments.native_test else None
    architecture = subprocess.run(
        ["dpkg", "--print-architecture"], check=True, capture_output=True,
        text=True, timeout=10,
    ).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError(f"unsupported acceptance architecture: {architecture}")
    m.REFERENCE_DPKG = m.reference_dpkg.select(arguments.reference_dpkg, architecture, root_accounts=True)
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    if arguments.workspace:
        workspace = arguments.workspace.resolve()
        if workspace.parent != temporary_root.resolve():
            parser.error("--workspace must name a new directory directly under this worktree's .tmp")
        workspace.mkdir()
        context = nullcontext(str(workspace))
    else:
        context = tempfile.TemporaryDirectory(prefix="native-lifecycle-", dir=temporary_root)
    host_status = Path("/var/lib/dpkg/status").read_bytes()
    try:
        with context as temporary:
            workspace = Path(temporary)
            environment = m.fixture_environment(workspace)
            exercise(executable, workspace, environment, architecture)
    finally:
        if Path("/var/lib/dpkg/status").read_bytes() != host_status:
            raise AssertionError("host dpkg status changed during lifecycle acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
