#!/usr/bin/env python3
"""Compare native trigger queues, package states, and script traces with dpkg."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_trigger_lifecycle", ROOT / "tools/test-native-lifecycle.py",
)
assert SPEC and SPEC.loader
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)
m = lifecycle.m
HELPER = Path("usr/bin/dpkg-trigger")
RECEIVER = "debz-trigger-receiver"
SOURCE = "debz-trigger-source"
TRIGGER = "debz-test-trigger"


def validate_native_helper(helper: Path) -> None:
    if hashlib.sha256(helper.read_bytes()).digest() == hashlib.sha256(
        Path("/usr/bin/dpkg-trigger").read_bytes()
    ).digest():
        raise AssertionError("native acceptance cannot use the reference dpkg-trigger executable")


def snapshot(root: Path) -> dict:
    return m.oracle.capture(
        root, excludes=(*m.oracle.DEFAULT_EXCLUDES, m.GUARD, HELPER.as_posix()),
    )


def reference(
    root: Path,
    operation: str,
    archives: list[Path],
    packages: list[str],
    environment: dict[str, str],
    destination: Path,
    *,
    defer: bool = False,
) -> int:
    command = [arg for arg in m.reference_command(root) if arg != "--no-triggers"]
    if defer:
        command.append("--no-triggers")
    if operation in ("install", "upgrade", "downgrade", "reinstall"):
        if not archives:
            raise ValueError("trigger lifecycle requires archives")
        command += ["--install", *(str(path) for path in archives)]
    elif operation in ("remove", "purge", "configure"):
        if not packages:
            raise ValueError("package phase requires selected packages")
        command += [f"--{operation}", *packages]
    elif operation == "process_triggers":
        command += ["--triggers-only", *(packages or ["--pending"])]
    else:
        raise ValueError(f"unsupported trigger reference operation: {operation}")
    with (destination / "reference.log").open("wb") as output:
        result = subprocess.run(
            command, env=environment, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, timeout=120, check=False,
        )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"unexpected dpkg exit {result.returncode}: {destination}")
    return result.returncode


def native(
    executable: Path,
    root: Path,
    architecture: str,
    operation: str,
    archives: list[Path],
    packages: list[str],
    environment: dict[str, str],
    destination: Path,
    *,
    defer: bool = False,
    fault: str | None = None,
) -> dict:
    request_path = destination / "native.request.json"
    report_path = destination / "native.report.json"
    request = {
        "root": str(root), "architecture": architecture,
        "operation": operation, "archives": [str(path) for path in archives],
        "packages": [{"name": name, "architecture": architecture} for name in packages],
        "triggers": True, "defer_triggers": defer, "report": str(report_path),
    }
    if fault is not None:
        request["fault"] = fault
    m.write(request_path, json.dumps(request).encode())
    m.run(
        [str(executable)],
        {**environment, "DEBZ_NATIVE_LIFECYCLE_REQUEST": str(request_path)},
        destination / "native.log",
    )
    if not report_path.is_file() or report_path.stat().st_size > 64 * 1024:
        raise AssertionError("native trigger driver did not produce a bounded report")
    report = json.loads(report_path.read_bytes())
    if report.get("outcome") not in {
        "applied", "script_failed", "trigger_failed", "recovery_required", "handoff", "refused",
    }:
        raise AssertionError(f"invalid trigger outcome: {report}")
    return report


def script_set(
    name: str,
    version: str,
    *,
    activate: tuple[str, ...] = (),
    activate_kind: str = "postinst",
    activate_when: str = "triggered",
    await_activation: bool = False,
    fail_triggered: bool = False,
) -> dict[str, bytes]:
    scripts = lifecycle.scripts(name, version)
    if fail_triggered:
        scripts["postinst"] = scripts["postinst"].removesuffix(b"exit 0\n") + (
            b'if [ "$1" = triggered ]; then exit 23; fi\nexit 0\n'
        )
    if activate:
        body = scripts[activate_kind].removesuffix(b"exit 0\n")
        body += f'if [ "$1" = "{activate_when}" ]; then\n'.encode()
        for trigger in activate:
            mode = "--await" if await_activation else "--no-await"
            body += f"    /usr/bin/dpkg-trigger {mode} {trigger} || exit $?\n".encode()
        body += b"fi\n"
        scripts[activate_kind] = body + b"exit 0\n"
    return scripts


class Scenario:
    def __init__(
        self,
        workspace: Path,
        name: str,
        executable: Path | None,
        helper: Path | None,
        architecture: str,
        environment: dict[str, str],
    ) -> None:
        self.directory = workspace / name
        self.expected = self.directory / "reference"
        self.candidate = self.directory / "native"
        self.executable = executable
        self.helper = helper
        self.architecture = architecture
        self.environment = environment
        self.index = 0
        self.observations: list[dict] = []
        for root in self.roots:
            m.make_root(root, architecture)
            m.write(root / lifecycle.TRACE, b"")
            lifecycle.runtime.copy_program(root, Path("/bin/sh"), "/bin/sh")
            lifecycle.runtime.copy_program(root, Path("/usr/bin/dpkg-trigger"), "/" + HELPER.as_posix())
        self.install_native_helper()

    @property
    def roots(self) -> tuple[Path, Path]:
        return self.expected, self.candidate

    def install_native_helper(self) -> None:
        if self.helper is not None:
            shutil.copy2(self.helper, self.candidate / HELPER)
            (self.candidate / HELPER).chmod(0o755)
            if hashlib.sha256((self.candidate / HELPER).read_bytes()).digest() != hashlib.sha256(
                self.helper.read_bytes()
            ).digest():
                raise AssertionError("candidate trigger helper differs from the native artifact")

    def seed(self, *archives: Path) -> None:
        for root in self.roots:
            if root == self.candidate and self.helper:
                shutil.copy2("/usr/bin/dpkg-trigger", root / HELPER)
            destination = self.directory / f"seed-{self.index}-{root.name}"
            destination.mkdir()
            if reference(root, "install", list(archives), [], self.environment, destination):
                raise AssertionError(f"reference trigger seed failed: {destination}")
            m.write(root / lifecycle.TRACE, b"")
        self.install_native_helper()
        self.index += 1

    def phase(
        self,
        operation: str,
        archives: list[Path] | None = None,
        packages: list[str] | None = None,
        *,
        defer: bool = False,
        failure: bool = False,
    ) -> None:
        destination = self.directory / f"{self.index}-{operation}"
        destination.mkdir()
        self.index += 1
        result = reference(
            self.expected, operation, archives or [], packages or [],
            self.environment, destination, defer=defer,
        )
        if bool(result) != failure:
            raise AssertionError(
                f"{self.directory.name}: dpkg exit {result}, expected failure={failure}: {destination}"
            )
        if self.executable:
            report = native(
                self.executable, self.candidate, self.architecture,
                operation, archives or [], packages or [], self.environment,
                destination, defer=defer,
            )
            outcomes = ("script_failed", "trigger_failed") if failure else ("applied",)
            if report["outcome"] not in outcomes:
                raise AssertionError(f"{self.directory.name}: unexpected native result: {report}")
            for name in (
                "root-operation-v1.json", "root-mutation-v1.json",
                "native-lifecycle-script-v1.json", "native-trigger-authority-v1.json",
            ):
                if (self.candidate / "var/lib/debz" / name).exists():
                    raise AssertionError(f"known trigger outcome stranded active evidence: {name}")
        else:
            oracle_directory = destination / "oracle"
            oracle_directory.mkdir()
            if reference(
                self.candidate, operation, archives or [], packages or [],
                self.environment, oracle_directory, defer=defer,
            ) != result:
                raise AssertionError("trigger reference fixture is not repeatable")
        expected, observed = snapshot(self.expected), snapshot(self.candidate)
        for name, document in (("reference", expected), ("native", observed)):
            m.write(destination / f"{name}.snapshot.json", m.oracle.canonical_json(document).encode())
        mismatches = m.oracle.differences(expected, observed, maximum=30)
        if mismatches:
            raise AssertionError("native/dpkg trigger mismatch:\n" + "\n".join(mismatches))
        self.observations.append({
            "operation": operation, "defer": defer, "exit": result,
            "status": expected["dpkg"]["status"], "trace": expected["trace"],
            "triggers": {
                path.name: path.read_text()
                for path in sorted((self.expected / "var/lib/dpkg/triggers").iterdir())
                if path.name != "Lock"
            },
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
    helper: Path | None,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
) -> None:
    def package(
        label: str, name: str, declarations: bytes,
        *, version: str = "1", **script_options,
    ) -> Path:
        return m.make_package(
            workspace / "packages" / label, environment, architecture, version,
            package=name, triggers=declarations or None,
            scripts=script_set(name, version, **script_options),
        )

    def case(name: str) -> Scenario:
        return Scenario(workspace, name, executable, helper, architecture, environment)

    for interest in ("interest-await", "interest-noawait"):
        receiver = package(interest, RECEIVER, f"{interest} {TRIGGER}\n".encode())
        for activation in ("activate-await", "activate-noawait"):
            source = package(
                f"{interest}-{activation}", SOURCE, f"{activation} {TRIGGER}\n".encode(),
            )
            for defer in (False, True):
                current = case(f"{interest}-{activation}-{'deferred' if defer else 'immediate'}")
                current.seed(receiver)
                current.phase("install", [source], defer=defer)
                if defer:
                    current.phase("process_triggers")
                current.complete()

    receiver = package("aliases", RECEIVER, f"interest {TRIGGER}\n".encode())
    source = package("aliases-source", SOURCE, f"activate {TRIGGER}\n".encode())
    current = case("default-await-aliases")
    current.seed(receiver)
    current.phase("install", [source])
    current.complete()

    receiver = package("queued-interest", RECEIVER, f"interest-await {TRIGGER}\n".encode())
    source = package("queued-source", SOURCE, b"")
    current = case("existing-unincorporated-queue")
    current.seed(receiver, source)
    for root in current.roots:
        m.reference_command(root)
        for mode in ("--no-await", "--await"):
            m.run(
                ["dpkg-trigger", f"--admindir={root}/var/lib/dpkg",
                 f"--by-package={SOURCE}", mode, TRIGGER],
                environment, current.directory / f"{root.name}-{mode[2:]}.log",
            )
    current.phase("process_triggers")
    current.complete()

    receiver = package(
        "mixed", RECEIVER,
        f"interest-await debz-a\ninterest-noawait debz-b\ninterest-await /usr/share/{SOURCE}\n".encode(),
    )
    source = package("mixed-source", SOURCE, b"activate-await debz-a\nactivate-await debz-b\n")
    current = case("mixed-trigger-order")
    current.seed(receiver)
    current.phase("install", [source], defer=True)
    current.phase("process_triggers")
    current.complete()

    receiver = package("file", RECEIVER, f"interest-noawait /usr/share/{SOURCE}\n".encode())
    first = package("file-source-1", SOURCE, b"")
    second = package("file-source-2", SOURCE, b"", version="2")
    current = case("file-trigger-lifecycle")
    current.seed(receiver)
    current.phase("install", [first])
    current.phase("upgrade", [second])
    current.phase("remove", packages=[SOURCE])
    current.phase("purge", packages=[SOURCE])
    current.phase("purge", packages=[RECEIVER])
    current.complete()

    receiver = package("batch", RECEIVER, f"interest-noawait {TRIGGER}\n".encode())
    source = package("batch-source", SOURCE, f"activate-noawait {TRIGGER}\n".encode())
    for source_first in (False, True):
        current = case(f"new-handler-{'source-first' if source_first else 'receiver-first'}")
        current.phase("install", [source, receiver] if source_first else [receiver, source])
        current.complete()

    receiver = package("script-interest", RECEIVER, f"interest-noawait {TRIGGER}\n".encode())
    source = package(
        "script-source", SOURCE, b"", activate=(TRIGGER, TRIGGER),
        activate_when="configure",
    )
    for defer in (False, True):
        current = case(
            "script-activation-coalesces" + ("-deferred" if defer else ""),
        )
        current.seed(receiver)
        current.phase("install", [source], defer=defer)
        if defer:
            current.phase("process_triggers")
        current.complete()

    source = package(
        "script-removal-source", SOURCE, b"", activate=(TRIGGER,),
        activate_kind="postrm", activate_when="remove",
    )
    current = case("postrm-script-activation")
    current.seed(receiver, source)
    current.phase("remove", packages=[SOURCE])
    current.complete()

    for awaiting in (False, True):
        receiver = package(
            f"failure-{awaiting}", RECEIVER, f"interest-await {TRIGGER}\n".encode(),
            fail_triggered=True,
        )
        kind = "activate-await" if awaiting else "activate-noawait"
        source = package(f"failure-source-{awaiting}", SOURCE, f"{kind} {TRIGGER}\n".encode())
        current = case(f"trigger-failure-{'await' if awaiting else 'noawait'}")
        current.seed(receiver)
        current.phase("install", [source], failure=True)
        current.complete()

    first_name, second_name = "debz-trigger-a", "debz-trigger-b"
    first = package(
        "chain-a", first_name, b"interest-noawait debz-a\n", activate=("debz-b",),
    )
    second = package("chain-b", second_name, b"interest-noawait debz-b\n")
    source = package("chain-source", SOURCE, b"activate-noawait debz-a\n")
    current = case("dynamic-trigger-chain")
    current.seed(first, second)
    current.phase("install", [source])
    current.complete()

    loop = package(
        "loop", RECEIVER, f"interest-noawait {TRIGGER}\n".encode(), activate=(TRIGGER,),
    )
    source = package("loop-source", SOURCE, f"activate-noawait {TRIGGER}\n".encode())
    current = case("self-cycle-no-progress")
    current.seed(loop)
    current.phase("install", [source], failure=True)
    current.complete()

    second = package(
        "cycle-b", second_name, b"interest-noawait debz-b\n", activate=("debz-a",),
    )
    source = package("cycle-source", SOURCE, b"activate-noawait debz-a\n")
    current = case("two-package-cycle")
    current.seed(first, second)
    current.phase("install", [source], failure=True)
    current.complete()

    if executable:
        receiver = package("unknown-interest", RECEIVER, f"interest-await {TRIGGER}\n".encode())
        source = package("unknown-source", SOURCE, f"activate-await {TRIGGER}\n".encode())
        current = case("trigger-script-outcome-unknown")
        current.seed(receiver)
        destination = current.directory / "interrupted"
        destination.mkdir()
        report = native(
            executable, current.candidate, architecture, "install", [source], [],
            environment, destination, fault="after_triggered_postinst_before_record",
        )
        if report["outcome"] != "recovery_required":
            raise AssertionError(f"unknown triggered script did not block mutation: {report}")
        operation_path = current.candidate / "var/lib/debz/root-operation-v1.json"
        script_path = current.candidate / "var/lib/debz/native-lifecycle-script-v1.json"
        authority_path = current.candidate / "var/lib/debz/native-trigger-authority-v1.json"
        operation_bytes, script_bytes = operation_path.read_bytes(), script_path.read_bytes()
        authority_bytes = authority_path.read_bytes()
        if not authority_bytes or len(authority_bytes) > 1024 * 1024:
            raise AssertionError("trigger interruption lost bounded helper-authority evidence")
        authority_record = json.loads(authority_bytes)
        operation_record, script_record = json.loads(operation_bytes), json.loads(script_bytes)
        if (
            operation_record["state"] != "recovery_required"
            or operation_record["phase"] != "script"
            or operation_record["mutation_started"] is not True
            or script_record["program_sha256"] != operation_record["program_sha256"]
            or script_record["package"] != RECEIVER
            or script_record["version"] != "1"
            or script_record["kind"] != "postinst"
            or script_record["source"] != "installed_package"
            or script_record["script_sha256"] != hashlib.sha256(
                script_set(RECEIVER, "1")["postinst"]
            ).hexdigest()
            or script_record["arguments"] != ["triggered", TRIGGER]
            or script_record["outcome"] != "in_flight"
            or script_record["exit_code"] is not None
            or authority_record["schema"] != "https://debz.dev/schema/native-trigger-authority-v1"
            or authority_record["program_sha256"] != operation_record["program_sha256"]
            or authority_record["attempt_id"] != operation_record["attempt_id"]
            or TRIGGER not in authority_record["allowed_triggers"]
            or not any(
                caller["package"] == {
                    "name": RECEIVER, "version": "1", "architecture": architecture,
                }
                and caller["source"] == script_record["source"]
                and caller["kind"] == script_record["kind"]
                and caller["script_sha256"] == script_record["script_sha256"]
                for caller in authority_record["callers"]
            )
        ):
            raise AssertionError(f"trigger interruption lost its exact invocation: {script_record}")
        before = snapshot(current.candidate)
        if len(before["trace"]) != 3 or not before["trace"][-1].startswith(
            f"{RECEIVER}@1:postinst\t"
        ):
            raise AssertionError("trigger interruption did not actually execute the selected handler")
        for operation, packages in (
            ("process_triggers", []), ("purge", ["debz-trigger-absent"]),
        ):
            retry = current.directory / f"blocked-{operation}"
            retry.mkdir()
            report = native(
                executable, current.candidate, architecture, operation, [], packages,
                environment, retry,
            )
            if report["outcome"] != "recovery_required":
                raise AssertionError(f"unknown trigger permitted another mutation: {report}")
            if (
                operation_path.read_bytes() != operation_bytes
                or script_path.read_bytes() != script_bytes
                or authority_path.read_bytes() != authority_bytes
            ):
                raise AssertionError("blocked trigger operation replaced active evidence")
            mismatches = m.oracle.differences(before, snapshot(current.candidate), maximum=30)
            if mismatches:
                raise AssertionError("blocked trigger operation changed state:\n" + "\n".join(mismatches))
        print("trigger-script-outcome-unknown: durable re-entry blocking passed", flush=True)

        current = case("malformed-unincorporated-queue")
        current.seed(receiver)
        m.write(current.candidate / "var/lib/dpkg/triggers/Unincorp", b"invalid\x00trigger -\n")
        before = snapshot(current.candidate)
        destination = current.directory / "refused"
        destination.mkdir()
        report = native(
            executable, current.candidate, architecture, "process_triggers", [], [],
            environment, destination,
        )
        if report["outcome"] not in ("refused", "handoff"):
            raise AssertionError(f"malformed trigger queue was not refused before mutation: {report}")
        mismatches = m.oracle.differences(before, snapshot(current.candidate), maximum=30)
        if mismatches:
            raise AssertionError("malformed trigger queue refusal changed state:\n" + "\n".join(mismatches))
        if (current.candidate / "var/lib/debz/root-operation-v1.json").exists():
            raise AssertionError("malformed trigger queue stranded an active operation")
        print("malformed-unincorporated-queue: pre-mutation refusal passed", flush=True)

        unrelated = "debz-trigger-unrelated"
        unrelated_archive = package("unrelated", unrelated, b"")
        changed_scripts = script_set(SOURCE, "1")
        changed_scripts["postinst"] = lifecycle.rewrite_database_field(
            changed_scripts["postinst"], unrelated,
            "Status: install ok installed", "Status: hold ok installed",
        )
        changed_archive = m.make_package(
            workspace / "packages/changed-state", environment, architecture, "1",
            package=SOURCE, scripts=changed_scripts,
        )
        current = case("deferred-unrelated-selection-change")
        current.seed(receiver, unrelated_archive)
        destination = current.directory / "install"
        destination.mkdir()
        report = native(
            executable, current.candidate, architecture, "install", [changed_archive], [],
            environment, destination, defer=True,
        )
        if report["outcome"] != "recovery_required":
            raise AssertionError(f"deferred publication masked an unrelated state change: {report}")
        operation = json.loads(
            (current.candidate / "var/lib/debz/root-operation-v1.json").read_bytes()
        )
        if (
            operation["state"] not in ("mutating", "recovery_required")
            or operation["mutation_started"] is not True
            or operation["program_sha256"] != report["program_sha256"]
        ):
            raise AssertionError(f"deferred closure mismatch lost recovery evidence: {operation}")
        if not any(
            record.get("package") == unrelated
            and record.get("status") == "hold ok installed"
            for record in snapshot(current.candidate)["dpkg"]["status"]
        ):
            raise AssertionError("deferred publication rewrote the unrelated package state")
        before = snapshot(current.candidate)
        retry = current.directory / "blocked"
        retry.mkdir()
        report = native(
            executable, current.candidate, architecture, "process_triggers", [], [],
            environment, retry,
        )
        if report["outcome"] != "recovery_required":
            raise AssertionError("unexpected deferred state permitted another operation")
        if m.oracle.differences(before, snapshot(current.candidate)):
            raise AssertionError("blocked deferred operation changed package or script state")
        print("deferred-unrelated-selection-change: unexpected selection was not overwritten", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", nargs="?", type=Path)
    parser.add_argument("--native-helper", type=Path)
    parser.add_argument(
        "--oracle-only", action="store_true",
        help="check reference fixture consistency only; not native parity",
    )
    parser.add_argument("--workspace", type=Path)
    arguments = parser.parse_args()
    if arguments.oracle_only == bool(arguments.native_test):
        parser.error("provide a native test executable or --oracle-only, not both")
    if bool(arguments.native_helper) != bool(arguments.native_test):
        parser.error("native execution requires a native trigger-helper artifact")
    if os.geteuid() != 0:
        raise RuntimeError("trigger acceptance requires root for actual chroot execution")
    for command in ("dpkg", "dpkg-deb", "dpkg-trigger", "ldd"):
        if shutil.which(command) is None:
            raise RuntimeError(f"missing reference prerequisite: {command}")
    executable = arguments.native_test.resolve(strict=True) if arguments.native_test else None
    helper = arguments.native_helper.resolve(strict=True) if arguments.native_helper else None
    if helper is not None:
        validate_native_helper(helper)
    architecture = subprocess.run(
        ["dpkg", "--print-architecture"], check=True, capture_output=True,
        text=True, timeout=10,
    ).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError(f"unsupported trigger acceptance architecture: {architecture}")
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    if arguments.workspace:
        workspace = arguments.workspace.resolve()
        if workspace.parent != temporary_root.resolve():
            parser.error("--workspace must name a new direct child of this worktree's .tmp")
        workspace.mkdir()
        context = nullcontext(str(workspace))
    else:
        context = tempfile.TemporaryDirectory(prefix="native-triggers-", dir=temporary_root)
    host_status = Path("/var/lib/dpkg/status").read_bytes()
    try:
        with context as temporary:
            workspace = Path(temporary)
            environment = m.fixture_environment(workspace)
            exercise(executable, helper, workspace, environment, architecture)
    finally:
        if Path("/var/lib/dpkg/status").read_bytes() != host_status:
            raise AssertionError("host dpkg status changed during trigger acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
