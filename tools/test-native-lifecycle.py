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
                raise AssertionError(
                    f"{self.directory.name}/{operation}: expected {wanted}: {report}"
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


def exercise(
    executable: Path | None,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
) -> None:
    archives = {
        version: m.make_package(
            workspace / "packages", environment, architecture, version,
            scripts=scripts(m.PACKAGE, version),
        )
        for version in ("1", "2")
    }

    def case(name: str) -> Scenario:
        return Scenario(workspace, name, executable, architecture, environment)

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
        changed_database_scripts["postinst"] = (
            changed_database_scripts["postinst"].removesuffix(b"exit 0\n") + f"""
status=''
selected=no
while IFS= read -r line; do
    case "$line" in
        'Package: {unrelated}') selected=yes ;;
        'Package: '*) selected=no ;;
    esac
    if [ "$selected" = yes ] && [ "$line" = 'Version: 1' ]; then
        line='Version: 9'
    fi
    status="$status$line
"
done < /var/lib/dpkg/status
printf '%s' "$status" > /var/lib/dpkg/status
exit 0
""".encode()
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
