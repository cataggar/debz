#!/usr/bin/env python3
"""Exercise actual native-process crashes, recovery, and bound provenance."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from functools import cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_recovery_triggers", ROOT / "tools/test-native-triggers.py",
)
assert SPEC and SPEC.loader
triggers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(triggers)
lifecycle = triggers.lifecycle
m = triggers.m
CRASH_EXIT = 86
NAMESPACE = Path("var/lib/debz")
OPERATION = NAMESPACE / "root-operation-v1.json"
INTENT = NAMESPACE / "native-execution-intent-v1.json"
SCRIPT = NAMESPACE / "native-lifecycle-script-v1.json"
PROGRESS = NAMESPACE / "native-execution-progress-v1.log"
RECOVERY_ARTIFACTS = NAMESPACE / "native-recovery-v1/artifacts"
PROVENANCE_SCHEMA = "native-transaction-provenance-v1"
BINDING_FIELDS = (
    "attempt_id", "program_sha256", "authorization_sha256",
    "root_identity_sha256", "install_root", "root_inode", "operation",
    "request_sha256", "policy_sha256", "exact_lock_sha256",
    "artifact_evidence_sha256", "initial_database_generation_sha256",
    "execution_intent_sha256",
)
EVIDENCE_SCHEMAS = {
    "authorization": "native-transaction-authorization-v1",
    "program": "native-transaction-program-v1",
    "intent": "native-execution-intent-v1",
    "progress": "native-execution-progress-v1",
    "managed_state": "native-managed-state-v1",
    "trigger_events": "native-trigger-events-v1",
    "script_outcome": "native-script-outcome-v1",
}


def document(path: Path, maximum: int = 1024 * 1024) -> dict:
    value = json.loads(m.oracle._read_bounded(path, maximum))
    if not isinstance(value, dict):
        raise AssertionError(f"expected a bounded JSON object: {path}")
    return value


def native(
    executable: Path,
    root: Path,
    architecture: str,
    operation: str,
    archives: list[Path],
    environment: dict[str, str],
    destination: Path,
    *,
    packages: tuple[str, ...] = (),
    trigger_execution: bool = False,
    defer: bool = False,
    crash_at: str | None = None,
) -> dict | None:
    m.reference_command(root)
    if operation == "recover" and (archives or packages or crash_at is not None):
        raise ValueError("recovery consumes persisted evidence, not caller archives or a new crash")
    request_path = destination / "native.request.json"
    report_path = destination / "native.report.json"
    request = {
        "root": str(root), "architecture": architecture,
        "operation": operation, "archives": [str(path) for path in archives],
        "packages": [{"name": name, "architecture": architecture} for name in packages],
        "recovery": True, "triggers": trigger_execution,
        "defer_triggers": defer, "report": str(report_path),
    }
    if crash_at is not None:
        request["crash_at"] = crash_at
    m.write(request_path, json.dumps(request).encode())
    with (destination / "native.log").open("wb") as output:
        result = subprocess.run(
            [str(executable)],
            env={**environment, "DEBZ_NATIVE_LIFECYCLE_REQUEST": str(request_path)},
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            timeout=120, check=False,
        )
    expected_exit = CRASH_EXIT if crash_at is not None else 0
    if result.returncode != expected_exit:
        raise AssertionError(
            f"native {operation}: exit {result.returncode}, expected {expected_exit}; {destination}"
        )
    if crash_at is not None:
        if report_path.exists():
            raise AssertionError("crash produced a normal completion report")
        return None
    report = document(report_path, 64 * 1024)
    if report.get("outcome") not in {
        "applied", "script_failed", "trigger_failed", "recovery_required", "refused", "handoff",
    }:
        raise AssertionError(f"invalid recovery report: {report}")
    return report


def assert_binding(provenance: dict, binding: dict) -> None:
    for field in BINDING_FIELDS:
        if provenance.get(field) != binding[field]:
            raise AssertionError(f"native provenance does not bind the original {field}")
    if provenance.get("backend") != "native":
        raise AssertionError("recovery provenance does not identify the native backend")


def intent_binding(intent: dict) -> dict:
    operation = {
        "configure": "install", "process_triggers": "install",
        "downgrade": "install", "purge": "remove",
    }.get(intent["operation"], intent["operation"])
    return {
        **intent,
        "operation": {"package_transaction": operation},
        "initial_database_generation_sha256": intent["database_generation_sha256"],
        "execution_intent_sha256": intent["digest_sha256"],
    }


def canonical(value: object) -> bytes:
    # Native digests preserve wire field order, unlike comparison snapshots.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode() + canonical(value)).hexdigest()


def assert_digest(value: dict, schema: str) -> None:
    payload = dict(value)
    expected = payload["digest_sha256"]
    if schema == "native-transaction-authorization-v1":
        del payload["digest_sha256"]
        found = digest("", payload)
    else:
        payload["digest_sha256"] = "0" * 64
        found = digest(f"debz-{schema}\0", payload)
    if found != expected:
        raise AssertionError(f"{schema}: canonical digest mismatch")


@cache
def validator(schema: str) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(document(ROOT / "schema" / f"{schema}.json"))


def namespace_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        relative.is_absolute() or ".." in relative.parts
        or relative.parts[:3] != ("var", "lib", "debz")
        or str(relative) != name
    ):
        raise AssertionError("provenance path escapes the native namespace")
    path = root / relative
    if path.resolve(strict=True) != path:
        raise AssertionError("provenance path contains a symbolic link")
    return path


def retained_documents(root: Path, proof: dict) -> dict[str, list[dict]]:
    expected_root = f"var/lib/debz/native-receipts-v1/{proof['attempt_id']}"
    if proof["evidence_root"] != expected_root:
        raise AssertionError("receipt directory does not bind the original attempt")
    if digest("debz-native-retained-evidence-v1\0", proof["evidence_files"]) != proof["evidence_files_sha256"]:
        raise AssertionError("retained evidence manifest digest mismatch")
    documents: dict[str, list[dict]] = {}
    paths: set[str] = set()
    total = 0
    for entry in proof["evidence_files"]:
        if entry["path"] in paths or not entry["path"].startswith(expected_root + "/"):
            raise AssertionError("duplicate or cross-attempt receipt path")
        paths.add(entry["path"])
        raw = m.oracle._read_bounded(namespace_path(root, entry["path"]), 128 * 1024 * 1024)
        if raw is None or len(raw) != entry["size"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise AssertionError("retained evidence bytes do not match the receipt")
        total += len(raw)
        if total > 512 * 1024 * 1024:
            raise AssertionError("retained evidence exceeds its aggregate bound")
        kind = entry["kind"]
        if kind not in EVIDENCE_SCHEMAS:
            continue
        value = json.loads(raw)
        schema = EVIDENCE_SCHEMAS[kind]
        validator(schema).validate(value)
        assert_digest(value, schema)
        if value["digest_sha256"] != entry["document_sha256"]:
            raise AssertionError("retained semantic digest differs from the manifest")
        if kind == "script_outcome" and value["action"] != entry["action"]:
            raise AssertionError("retained script has a different invocation identity")
        if kind not in ("authorization", "program", "intent"):
            if value["intent_sha256"] != proof["execution_intent_sha256"]:
                raise AssertionError("retained evidence belongs to another execution intent")
        documents.setdefault(kind, []).append(value)
    for kind in EVIDENCE_SCHEMAS.keys() - {"script_outcome"}:
        if len(documents.get(kind, [])) != 1:
            raise AssertionError(f"missing or duplicated retained {kind}")
    return documents


def action_key(action: dict) -> tuple:
    return tuple(action[field] for field in ("kind", "program_step", "substep", "ordinal"))


def assert_progress(proof: dict, progress: dict, scripts: list[dict]) -> None:
    previous = "0" * 64
    outcomes = {}
    script_hash = hashlib.sha256(b"debz-native-script-outcomes-v1\0")
    for sequence, record in enumerate(progress["records"]):
        if record["sequence"] != sequence or record["previous_sha256"] != previous:
            raise AssertionError("native progress chain is broken")
        assert_digest(record, "native-execution-progress-record-v1")
        previous = record["digest_sha256"]
        if record["action"]["kind"] in ("script", "compensation", "trigger") and record["stage"] == "outcome":
            key = action_key(record["action"])
            if key in outcomes:
                raise AssertionError("script invocation has duplicate recorded outcomes")
            outcomes[key] = record["evidence_sha256"]
            script_hash.update(record["digest_sha256"].encode())
            if record["evidence_sha256"] is not None:
                script_hash.update(record["evidence_sha256"].encode())
    if previous != progress["head_sha256"] or previous != proof["progress_head_sha256"]:
        raise AssertionError("provenance does not bind the progress head")
    if len(progress["records"]) != proof["progress_record_count"]:
        raise AssertionError("provenance does not bind the progress length")
    if sum(record["result"] == "recovered" for record in progress["records"]) != proof["recovered_phase_count"]:
        raise AssertionError("provenance lost recovery history")
    if script_hash.hexdigest() != proof["script_outcomes_sha256"]:
        raise AssertionError("provenance lost script outcome history")
    retained = {action_key(script["action"]): script["digest_sha256"] for script in scripts}
    if len(retained) != len(scripts) or retained != outcomes:
        raise AssertionError("exact script outcomes did not survive cleanup")
    if proof["outcome"] != "recovery_required" and progress["records"][-1]["stage"] != "terminal":
        raise AssertionError("completed provenance has no terminal progress")


def assert_output_streams(script: dict) -> None:
    output = {}
    for stream in ("stdout", "stderr", "combined"):
        output[stream] = bytes.fromhex(script[f"{stream}_hex"])
        if hashlib.sha256(output[stream]).hexdigest() != script[f"{stream}_sha256"]:
            raise AssertionError("retained script output digest mismatch")
    if output["combined"] and (output["stdout"] or output["stderr"]):
        raise AssertionError("retained script output mixes capture modes")
    if script["output_bytes"] != sum(map(len, output.values())) or script["output_bytes"] > script["output_limit"]:
        raise AssertionError("retained script output accounting differs")


def assert_script_output(script: dict) -> None:
    assert_output_streams(script)
    environment = {entry["key"]: entry["value"] for entry in script["environment"]}
    if len(environment) != len(script["environment"]) or list(environment) != sorted(environment):
        raise AssertionError("retained script environment is not canonical")
    expected = {
        "DPKG_MAINTSCRIPT_ARCH": script["architecture"],
        "DPKG_MAINTSCRIPT_NAME": script["kind"],
        "DPKG_MAINTSCRIPT_PACKAGE": script["package"],
        "DPKG_ROOT": "", "DPKG_ADMINDIR": "/var/lib/dpkg",
        "DEBIAN_FRONTEND": "noninteractive", "DPKG_COLORS": "never",
        "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
    if any(environment.get(key) != value for key, value in expected.items()):
        raise AssertionError("retained script environment differs from the invocation")
    if not script["spawned"] or script["disposition"] != "exited" or script["signal"] is not None:
        raise AssertionError("fixture script receipt lost its actual exit disposition")
    if script["package"] in ("debz-recovery-a", "debz-recovery-b", triggers.SOURCE):
        source = triggers.script_set(
            script["package"], script["package_version"],
            activate=("debz-b",) if script["package"] == "debz-recovery-a" else (),
        )
    else:
        source = lifecycle.scripts(script["package"], script["package_version"])
    if hashlib.sha256(source[script["kind"]]).hexdigest() != script["script_sha256"]:
        raise AssertionError("retained outcome identifies different script bytes")


def assert_final_database(root: Path, architecture: str, proof: dict) -> None:
    database = root / "var/lib/dpkg"
    files = {}
    names = [
        "status", "status-old", "arch", "diversions", "statoverride",
        "triggers/File", "triggers/Unincorp",
    ]
    for directory in ("info", "updates", "triggers"):
        names.extend(
            f"{directory}/{path.name}" for path in (database / directory).iterdir()
            if directory != "triggers" or path.name not in ("File", "Unincorp", "Lock")
        )
    for name in sorted(names):
        path = database / name
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        raw = m.oracle._read_bounded(path, 16 * 1024 * 1024)
        if not stat.S_ISREG(metadata.st_mode):
            raise AssertionError("database receipt describes a nonregular fixture entry")
        if name == "arch" and raw == f"{architecture}\n".encode():
            continue
        files[name] = {"bytes": raw.decode(), "kind": "regular", "mode": stat.S_IMODE(metadata.st_mode)}
    closure = {
        "status": files["status"], "arch": files.get("arch"),
        "triggers_file": files.get("triggers/File"),
        "triggers_unincorp": files.get("triggers/Unincorp"),
        "triggers_named": [
            {"name": name.removeprefix("triggers/"), **entry}
            for name, entry in files.items()
            if name.startswith("triggers/") and name not in ("triggers/File", "triggers/Unincorp")
        ],
    }
    if digest("debz-native-package-database-closure-v1\0", closure) != proof["final_state_sha256"]:
        raise AssertionError("provenance final-state digest differs from the actual database closure")
    generation = hashlib.sha256(b"debz.package-database.generation.v1\n")
    for name, entry in files.items():
        raw = entry["bytes"].encode()
        generation.update(
            f"{name}\0regular\0{entry['mode']:o}\0{len(raw)}\0{hashlib.sha256(raw).hexdigest()}\n".encode()
        )
    if generation.hexdigest() != proof["final_database_generation_sha256"]:
        raise AssertionError("provenance generation differs from the actual complete database")


def assert_script_trace(root: Path, proof: dict, scripts: list[dict]) -> None:
    if not scripts:
        return
    lines = m.oracle._read_bounded(root / lifecycle.TRACE, 16 * 1024 * 1024).decode().splitlines()
    if proof["outcome"] == "recovery_required":
        lines = lines[:-1]
    lines = lines[-len(scripts):]
    if len(lines) != len(scripts):
        raise AssertionError("retained script outcomes have no matching invocation trace")
    for script, line in zip(scripts, lines, strict=True):
        prefix = [
            f"{script['package']}@{script['package_version']}:{script['kind']}",
            script["package"], script["kind"], script["architecture"],
            str(len(script["arguments"])),
            *(f"{len(argument.encode())}:{argument}" for argument in script["arguments"]),
        ]
        if not line.startswith("\t".join(prefix) + "\tpayload="):
            raise AssertionError("retained script arguments or identity differ from the actual trace")


def provenance(root: Path, report: dict, binding: dict) -> tuple[Path, bytes]:
    path = namespace_path(root, report["provenance_path"])
    value = document(path, 16 * 1024 * 1024)
    validator(PROVENANCE_SCHEMA).validate(value)
    assert_digest(value, PROVENANCE_SCHEMA)
    assert_binding(value, binding)
    if value["root_inode"] != root.stat().st_ino:
        raise AssertionError("provenance describes a different physical root")
    if report["attempt_id"] != binding["attempt_id"]:
        raise AssertionError("recovery report invented a new execution attempt")
    if report["program_sha256"] != binding["program_sha256"]:
        raise AssertionError("recovery report reauthorized a different program")
    expected = {
        "applied": "succeeded", "script_failed": "failed",
        "trigger_failed": "failed", "recovery_required": "recovery_required",
    }[report["outcome"]]
    if value["outcome"] != expected:
        raise AssertionError("provenance disagrees with the actual terminal outcome")
    retained = retained_documents(root, value)
    intent = retained["intent"][0]
    assert_binding(value, intent_binding(intent))
    for kind, field in (
        ("authorization", "authorization_sha256"), ("program", "program_sha256"),
        ("intent", "execution_intent_sha256"), ("trigger_events", "trigger_evidence_sha256"),
    ):
        if retained[kind][0]["digest_sha256"] != value[field]:
            raise AssertionError(f"provenance does not bind retained {kind}")
    scripts = retained.get("script_outcome", [])
    assert_progress(value, retained["progress"][0], scripts)
    for script in scripts:
        assert_script_output(script)
    assert_script_trace(root, value, scripts)
    managed = retained["managed_state"][0]
    for snapshot in (managed["stable"], managed["transient"]):
        if snapshot is not None:
            assert_digest(snapshot, "native-managed-snapshot-v1")
            if not any(boundary["snapshot_sha256"] == snapshot["digest_sha256"] for boundary in managed["history"]):
                raise AssertionError("managed state lost its checkpoint history")
    if value["final_state_kind"] != "package_database_closure_v1":
        raise AssertionError("provenance uses an unspecified final-state digest")
    if value["final_state_sha256"] == value["final_database_generation_sha256"]:
        raise AssertionError("provenance substituted database generation for final state")
    assert_final_database(root, intent["architecture"], value)
    return path, m.oracle._read_bounded(path, 16 * 1024 * 1024)


def compare(expected: Path, candidate: Path) -> None:
    mismatches = m.oracle.differences(
        triggers.snapshot(expected), triggers.snapshot(candidate), maximum=30,
    )
    if mismatches:
        raise AssertionError("recovered native/dpkg mismatch:\n" + "\n".join(mismatches))


class Scenario(triggers.Scenario):
    def crash(
        self,
        operation: str,
        archives: list[Path],
        boundary: str,
        *,
        trigger_execution: bool = False,
        defer: bool = False,
        failure: bool = False,
        compare_reference: bool = True,
    ) -> dict:
        destination = self.directory / "crash"
        destination.mkdir()
        if compare_reference:
            code = triggers.reference(
                self.expected, operation, archives, [], self.environment,
                destination, defer=defer or not trigger_execution,
            )
            if bool(code) != failure:
                raise AssertionError(f"unexpected reference result {code}: {self.directory}")
        native(
            self.executable, self.candidate, self.architecture,
            operation, archives, self.environment, destination,
            trigger_execution=trigger_execution, defer=defer, crash_at=boundary,
        )
        binding = intent_binding(document(self.candidate / INTENT, 16 * 1024 * 1024))
        if boundary != "after_active_clear" and document(self.candidate / OPERATION)["backend"] != "native":
            raise AssertionError("crashed process lost native operation evidence")
        for archive in archives:
            archive.unlink()
        m.write(
            destination / "after-crash.snapshot.json",
            m.oracle.canonical_json(triggers.snapshot(self.candidate)).encode(),
        )
        return binding

    def recover(self, *, trigger_execution: bool = False, label: str = "recover") -> dict:
        destination = self.directory / label
        destination.mkdir()
        report = native(
            self.executable, self.candidate, self.architecture, "recover", [],
            self.environment, destination, trigger_execution=trigger_execution,
        )
        assert report is not None
        return report

    def completed(self, binding: dict, *, trigger_execution: bool = False, failure: bool = False) -> None:
        report = self.recover(trigger_execution=trigger_execution)
        if report["outcome"] not in (("script_failed", "trigger_failed") if failure else ("applied",)):
            raise AssertionError(f"known work did not recover deterministically: {report}")
        compare(self.expected, self.candidate)
        for name in (
            OPERATION, NAMESPACE / "root-mutation-v1.json",
            SCRIPT, NAMESPACE / "native-trigger-authority-v1.json",
        ):
            if (self.candidate / name).exists():
                raise AssertionError(f"completed recovery stranded active evidence: {name}")
        proof_path, proof_bytes = provenance(self.candidate, report, binding)
        before = triggers.snapshot(self.candidate)
        repeat = self.recover(trigger_execution=trigger_execution, label="recover-again")
        if repeat["outcome"] != report["outcome"]:
            raise AssertionError("repeated recovery changed the terminal outcome")
        if m.oracle.differences(before, triggers.snapshot(self.candidate)):
            raise AssertionError("repeated recovery reran package or script work")
        provenance(self.candidate, repeat, binding)
        if m.oracle._read_bounded(proof_path, 16 * 1024 * 1024) != proof_bytes:
            raise AssertionError("repeated recovery replaced terminal provenance")
        print(f"{self.directory.name}: crash/recovery parity and provenance passed", flush=True)

    def blocked(self, binding: dict, *, unknown_script: bool = False) -> None:
        before = triggers.snapshot(self.candidate)
        script_bytes = m.oracle._read_bounded(self.candidate / SCRIPT, 1024 * 1024)
        if unknown_script and document(self.candidate / SCRIPT)["outcome"] != "in_flight":
            raise AssertionError("unknown-outcome fixture did not reach the in-flight boundary")
        report = self.recover()
        if report["outcome"] not in ("recovery_required", "refused"):
            raise AssertionError(f"unresolved evidence permitted recovery: {report}")
        if m.oracle.differences(before, triggers.snapshot(self.candidate)):
            raise AssertionError("unresolved recovery modified package or script state")
        if unknown_script:
            if report.get("detail") != "script_outcome_unknown":
                raise AssertionError(f"unknown script was not classified precisely: {report}")
            proof_path, _ = provenance(self.candidate, report, binding)
            proof = document(proof_path, 16 * 1024 * 1024)
            unresolved = {entry["kind"]: entry for entry in proof["evidence_files"]}
            if unresolved["active_script"]["sha256"] != hashlib.sha256(script_bytes).hexdigest():
                raise AssertionError("receipt did not retain the unresolved invocation")
            journal = self.candidate / NAMESPACE / "root-mutation-v1.json"
            if journal.exists():
                raw = m.oracle._read_bounded(journal, 128 * 1024 * 1024)
                if unresolved["root_mutation_journal"]["sha256"] != hashlib.sha256(raw).hexdigest():
                    raise AssertionError("receipt did not retain the unresolved mutation")
        if unknown_script and m.oracle._read_bounded(
            self.candidate / SCRIPT, 1024 * 1024,
        ) != script_bytes:
            raise AssertionError("unknown invocation evidence was rewritten")
        destination = self.directory / "blocked-new-operation"
        destination.mkdir()
        retry = native(
            self.executable, self.candidate, self.architecture, "purge", [],
            self.environment, destination, packages=("debz-recovery-absent",),
        )
        if retry is None or retry["outcome"] != "recovery_required":
            raise AssertionError(f"unresolved recovery allowed another mutation: {retry}")
        if m.oracle.differences(before, triggers.snapshot(self.candidate)):
            raise AssertionError("blocked mutation changed the interrupted root")
        print(f"{self.directory.name}: unresolved evidence stayed blocked", flush=True)


def exercise(executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str) -> None:
    def case(name: str) -> Scenario:
        return Scenario(workspace, name, executable, helper, architecture, environment)

    def package(label: str, *, name: str = m.PACKAGE, version: str = "1", scripts: bool = True) -> Path:
        return m.make_package(
            workspace / "packages" / label, environment, architecture, version,
            package=name, scripts=lifecycle.scripts(name, version) if scripts else None,
        )

    for boundary in (
        "after_execution_intent", "during_filesystem_publication",
        "during_database_publication", "after_script_prepared",
        "after_script_outcome", "after_provenance", "after_active_clear",
    ):
        current = case(boundary)
        archive = package(boundary)
        binding = current.crash("install", [archive], boundary)
        current.completed(binding)
        if boundary == "after_active_clear":
            previous_proof = document(
                current.candidate / NAMESPACE / "native-transaction-provenance-v1.json",
                16 * 1024 * 1024,
            )
            following = package("after-clear-next", version="2")
            destination = current.directory / "next-operation"
            destination.mkdir()
            if triggers.reference(
                current.expected, "upgrade", [following], [], environment,
                destination, defer=True,
            ):
                raise AssertionError("reference follow-up operation failed")
            report = native(
                executable, current.candidate, architecture, "upgrade", [following],
                environment, destination,
            )
            if report is None or report["outcome"] != "applied":
                raise AssertionError(f"completed workspace blocked the next operation: {report}")
            if report["attempt_id"] == binding["attempt_id"]:
                raise AssertionError("a new operation reused the completed attempt")
            compare(current.expected, current.candidate)
            retained_documents(current.candidate, previous_proof)
            untracked = package("after-clear-untracked", version="3")
            destination = current.directory / "untracked-active"
            destination.mkdir()
            interrupted = lifecycle.native(
                executable, current.candidate, [untracked], "upgrade", architecture,
                environment, destination,
                packages=[{"name": m.PACKAGE, "architecture": architecture}],
                fault="after_script_before_record",
            )
            if interrupted["outcome"] != "recovery_required":
                raise AssertionError("legacy private path did not leave active script evidence")
            before = triggers.snapshot(current.candidate)
            recovered = current.recover(label="recover-untracked-active")
            if recovered["outcome"] not in ("recovery_required", "refused"):
                raise AssertionError(f"old provenance masked a newer active attempt: {recovered}")
            if m.oracle.differences(before, triggers.snapshot(current.candidate)):
                raise AssertionError("untracked active recovery changed the interrupted root")
            (current.candidate / OPERATION).unlink()
            orphaned = current.recover(label="recover-orphaned-script")
            if orphaned["outcome"] not in ("recovery_required", "refused"):
                raise AssertionError(f"old provenance masked orphaned script evidence: {orphaned}")
            if m.oracle.differences(before, triggers.snapshot(current.candidate)):
                raise AssertionError("orphaned evidence recovery changed the interrupted root")

    current = case("known-failure-compensation")
    archive = package("failure")
    lifecycle.Scenario.fail(current, f"{m.PACKAGE}@1:preinst:install")
    binding = current.crash("install", [archive], "after_failure_outcome", failure=True)
    current.completed(binding, failure=True)

    for upgrade in (False, True):
        current = case("unknown-upgrade-postrm" if upgrade else "unknown-script")
        if upgrade:
            current.seed(package("unknown-old"))
        archive = package("unknown-upgrade" if upgrade else "unknown-fresh", version="2" if upgrade else "1")
        binding = current.crash(
            "upgrade" if upgrade else "install", [archive],
            "after_upgrade_postrm_return_before_outcome" if upgrade else "after_script_return_before_outcome",
            compare_reference=False,
        )
        current.blocked(binding, unknown_script=True)

    current = case("known-trigger-outcome")
    first_name, second_name = "debz-recovery-a", "debz-recovery-b"
    first = m.make_package(
        workspace / "packages/trigger-a", environment, architecture, "1",
        package=first_name, triggers=b"interest-noawait debz-a\n",
        scripts=triggers.script_set(first_name, "1", activate=("debz-b",)),
    )
    second = m.make_package(
        workspace / "packages/trigger-b", environment, architecture, "1",
        package=second_name, triggers=b"interest-noawait debz-b\n",
        scripts=triggers.script_set(second_name, "1"),
    )
    source = m.make_package(
        workspace / "packages/trigger-source", environment, architecture, "1",
        package=triggers.SOURCE, triggers=b"activate-noawait debz-a\n",
        scripts=triggers.script_set(triggers.SOURCE, "1"),
    )
    current.seed(first, second)
    binding = current.crash(
        "install", [source], "after_trigger_outcome", trigger_execution=True,
    )
    current.completed(binding, trigger_execution=True)
    trigger_proof = document(
        current.candidate / NAMESPACE / "native-transaction-provenance-v1.json",
        16 * 1024 * 1024,
    )
    events = retained_documents(current.candidate, trigger_proof)["trigger_events"][0]["events"]
    activations = [
        (event["origin"], event["source_package"], event["trigger"]) for event in events
    ]
    if activations != [
        ("automatic", triggers.SOURCE, "debz-a"), ("dynamic", first_name, "debz-b"),
    ]:
        raise AssertionError(f"receipt lost or replayed trigger activations: {activations}")

    for changed in ("intent", "progress", "artifact", "managed-root", "completed-phase"):
        current = case(f"changed-{changed}")
        if changed == "completed-phase":
            archive = m.make_package(
                workspace / "packages/changed-completed-phase", environment, architecture, "1",
                scripts={"postinst": lifecycle.scripts(m.PACKAGE, "1")["postinst"]},
            )
            boundary = "after_script_prepared"
        else:
            archive = package(f"changed-{changed}", scripts=False)
            boundary = "during_filesystem_publication" if changed == "managed-root" else "after_execution_intent"
        binding = current.crash(
            "install", [archive], boundary, compare_reference=False,
        )
        if changed == "intent":
            path = current.candidate / INTENT
            data = m.oracle._read_bounded(path, 1024 * 1024)
            m.write(path, data[:len(data) // 2])
        elif changed == "progress":
            path = current.candidate / PROGRESS
            m.write(path, m.oracle._read_bounded(path, 16 * 1024 * 1024) + b"corrupt\n")
        elif changed == "artifact":
            artifacts = list((current.candidate / RECOVERY_ARTIFACTS).glob("*.deb"))
            if len(artifacts) != 1:
                raise AssertionError("execution did not persist exactly the supplied archive")
            data = m.oracle._read_bounded(artifacts[0], 16 * 1024 * 1024)
            m.write(artifacts[0], b"X" + data[1:])
        else:
            m.write(current.candidate / f"usr/share/{m.PACKAGE}/data", b"external replacement\n")
        current.blocked(binding)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", type=Path)
    parser.add_argument("--native-helper", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("recovery acceptance requires root for actual chroot execution")
    for command in ("dpkg", "dpkg-deb", "dpkg-trigger", "ldd"):
        if shutil.which(command) is None:
            raise RuntimeError(f"missing reference prerequisite: {command}")
    executable = arguments.native_test.resolve(strict=True)
    helper = arguments.native_helper.resolve(strict=True)
    triggers.validate_native_helper(helper)
    architecture = subprocess.run(
        ["dpkg", "--print-architecture"], check=True, capture_output=True,
        text=True, timeout=10,
    ).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError(f"unsupported recovery acceptance architecture: {architecture}")
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    if arguments.workspace:
        workspace = arguments.workspace.resolve()
        if workspace.parent != temporary_root.resolve():
            parser.error("--workspace must name a new direct child of this worktree's .tmp")
        workspace.mkdir()
        context = nullcontext(str(workspace))
    else:
        context = tempfile.TemporaryDirectory(prefix="native-recovery-", dir=temporary_root)
    host_status = Path("/var/lib/dpkg/status").read_bytes()
    try:
        with context as temporary:
            workspace = Path(temporary)
            exercise(executable, helper, workspace, m.fixture_environment(workspace), architecture)
    finally:
        if Path("/var/lib/dpkg/status").read_bytes() != host_status:
            raise AssertionError("host dpkg status changed during recovery acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
