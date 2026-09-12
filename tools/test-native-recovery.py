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
try:
    from referencing import Registry, Resource
except ModuleNotFoundError as error:
    if error.name != "referencing":
        raise
    Registry = None
    Resource = None


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
    "execution_request": "native-execution-request-v1",
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
    caller_owned: bool = False,
    acknowledge_native: bool = False,
    isolated_helper: bool = False,
    core_product: bool = False,
    completion_crash: str | None = None,
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
    if caller_owned:
        request["caller_owned"] = True
    if core_product:
        if not caller_owned or not isolated_helper:
            raise ValueError("core recovery requires a typed helper-bound caller")
        request["core_product"] = True
    if completion_crash is not None:
        if not core_product or operation != "recover":
            raise ValueError("completion crashes belong to core recovery")
        request["core_completion_crash"] = completion_crash
    if isolated_helper:
        if not caller_owned:
            raise ValueError("isolated helper belongs to the native caller")
        request["isolated_helper"] = True
    if acknowledge_native:
        if not caller_owned or operation != "recover":
            raise ValueError("native acknowledgment belongs to the recovering caller")
        request["acknowledge_native"] = True
    m.write(request_path, json.dumps(request).encode())
    with (destination / "native.log").open("wb") as output:
        result = subprocess.run(
            [str(executable)],
            env={**environment, "DEBZ_NATIVE_LIFECYCLE_REQUEST": str(request_path)},
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            timeout=120, check=False,
        )
    expected_exit = CRASH_EXIT if crash_at is not None or completion_crash is not None else 0
    if result.returncode != expected_exit:
        raise AssertionError(
            f"native {operation}: exit {result.returncode}, expected {expected_exit}; {destination}"
        )
    if crash_at is not None or completion_crash is not None:
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


def caller_binding(root: Path) -> dict:
    binding = intent_binding(document(root / INTENT, 16 * 1024 * 1024))
    caller = document(root / OPERATION)
    binding.update({field: caller[field] for field in ("request_sha256", "policy_sha256")})
    binding["operation"] = {caller["surface"]: caller["operation"]}
    return binding


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
    definition = document(ROOT / "schema" / f"{schema}.json")
    execution = document(ROOT / "schema/native-execution-request-v1.json")
    if Registry is not None and Resource is not None:
        registry = Registry().with_resource(execution["$id"], Resource.from_contents(execution))
        return jsonschema.Draft202012Validator(definition, registry=registry)
    return jsonschema.Draft202012Validator(
        definition,
        resolver=jsonschema.RefResolver.from_schema(
            definition, store={execution["$id"]: execution},
        ),
    )


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
        if kind == "execution_request" and value.get("version") == 2:
            schema = "native-execution-request-v2"
        validator(schema).validate(value)
        assert_digest(value, schema)
        if value["digest_sha256"] != entry["document_sha256"]:
            raise AssertionError("retained semantic digest differs from the manifest")
        if kind == "script_outcome" and value["action"] != entry["action"]:
            raise AssertionError("retained script has a different invocation identity")
        if kind not in ("authorization", "program", "intent", "execution_request"):
            if value["intent_sha256"] != proof["execution_intent_sha256"]:
                raise AssertionError("retained evidence belongs to another execution intent")
        documents.setdefault(kind, []).append(value)
    for kind in EVIDENCE_SCHEMAS.keys() - {"script_outcome", "execution_request"}:
        if len(documents.get(kind, [])) != 1:
            raise AssertionError(f"missing or duplicated retained {kind}")
    request_blobs = [blob for blob in documents["intent"][0]["blobs"] if blob["kind"] == "request"]
    if len(request_blobs) != 1:
        raise AssertionError("intent did not retain exactly one request binding")
    if request_blobs[0]["logical_path"] in (
        "request/native-execution-request-v1.json", "request/native-execution-request-v2.json",
    ):
        requests = documents.get("execution_request", [])
        if len(requests) != 1:
            raise AssertionError("missing or duplicated retained execution_request")
        request_bytes = canonical(requests[0]) + b"\n"
        if hashlib.sha256(request_bytes).hexdigest() != request_blobs[0]["sha256"]:
            raise AssertionError("retained production request differs from the execution intent")
        if requests[0]["version"] == 2:
            helper = requests[0]["helper"]
            binaries = [entry for entry in proof["evidence_files"] if entry["kind"] == "helper_binary"]
            if len(binaries) != 1 or binaries[0]["sha256"] != helper["sha256"] or binaries[0]["size"] != helper["size"]:
                raise AssertionError("retained helper differs from the original request")
            assert_digest(requests[0]["execution"], "native-execution-request-v1")
    elif "execution_request" in documents:
        raise AssertionError("private intent cannot substitute a production request")
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


def assert_helper_invocations(request: dict, program: dict, scripts: list[dict]) -> None:
    def text(value: str) -> bytes:
        encoded = value.encode()
        return len(encoded).to_bytes(8, "little") + encoded

    helper = request["helper"]
    for script in scripts:
        name, architecture, kind = script["package"], script["architecture"], script["kind"]
        staged_name = name if script["source"] == "new_package" else f"{name}:{architecture}"
        paths = (
            f"var/lib/debz-lifecycle-scripts/{staged_name}.{kind}",
            f"var/lib/dpkg/info/{name}.{kind}",
            f"var/lib/dpkg/info/{name}:{architecture}.{kind}",
        )
        environment = hashlib.sha256(
            b"debz-maintainer-script-environment-v1\0"
            + b"".join(text(entry["key"]) + text(entry["value"]) for entry in script["environment"])
        ).digest()
        matched = False
        for path in paths:
            argv = hashlib.sha256(
                b"debz-maintainer-script-argv-v1\0"
                + b"".join(text(argument) for argument in ["/" + path, *script["arguments"]])
            ).digest()
            invocation = (
                b"debz-maintainer-script-invocation-v1\0"
                + b"".join(text(value) for value in (
                    request["execution"]["install_root"], "chroot", name,
                    script["package_version"], architecture, kind, path,
                ))
                + bytes.fromhex(script["script_sha256"]) + argv + environment
                + bytes.fromhex(program["script_policy_sha256"])
                + b"debz-maintainer-script-helper-mount-v1\0"
                + text(helper["source_path"]) + text(helper["target_path"])
                + bytes.fromhex(helper["sha256"])
            )
            matched |= hashlib.sha256(invocation).hexdigest() == script["invocation_sha256"]
        if not matched:
            raise AssertionError("script invocation did not bind the isolated helper")


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
    retained_binding = intent_binding(intent)
    if "execution_request" in retained:
        request = retained["execution_request"][0]
        if request["version"] == 2:
            request = request["execution"]
        caller = request["caller"]
        program = retained["program"][0]
        for field in ("request_sha256", "solver_policy_sha256", "executor_policy_sha256", "plan_sha256", "script_policy_sha256"):
            if request["program"][field] != program[field]:
                raise AssertionError(f"production request lost its native {field}")
        if request["program"]["program_sha256"] != program["digest_sha256"]:
            raise AssertionError("production request lost its native program")
        if caller["attempt_id"] != intent["attempt_id"]:
            raise AssertionError("production request lost its caller attempt")
        retained_binding.update({field: caller[field] for field in ("operation", "request_sha256", "policy_sha256")})
        if caller["request_sha256"] == program["request_sha256"]:
            raise AssertionError("fixture did not exercise distinct caller and native request hashes")
    assert_binding(value, retained_binding)
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
    if retained.get("execution_request", [{}])[0].get("version") == 2:
        assert_helper_invocations(retained["execution_request"][0], retained["program"][0], scripts)
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
        caller_owned: bool = False,
        isolated_helper: bool = False,
        core_product: bool = False,
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
            caller_owned=caller_owned,
            isolated_helper=isolated_helper,
            core_product=core_product,
        )
        binding = caller_binding(self.candidate) if caller_owned else intent_binding(
            document(self.candidate / INTENT, 16 * 1024 * 1024),
        )
        if boundary != "after_active_clear" and document(self.candidate / OPERATION)["backend"] != "native":
            raise AssertionError("crashed process lost native operation evidence")
        for archive in archives:
            archive.unlink()
        m.write(
            destination / "after-crash.snapshot.json",
            m.oracle.canonical_json(triggers.snapshot(self.candidate)).encode(),
        )
        return binding

    def recover(self, *, trigger_execution: bool = False, label: str = "recover",
                caller_owned: bool = False, acknowledge_native: bool = False,
                isolated_helper: bool = False, core_product: bool = False) -> dict:
        destination = self.directory / label
        destination.mkdir()
        report = native(
            self.executable, self.candidate, self.architecture, "recover", [],
            self.environment, destination, trigger_execution=trigger_execution,
            caller_owned=caller_owned, acknowledge_native=acknowledge_native,
            isolated_helper=isolated_helper,
            core_product=core_product,
        )
        assert report is not None
        return report

    def caller_completed(self, binding: dict, *, failure: bool = False, isolated_helper: bool = False) -> None:
        helper_path = self.candidate / triggers.HELPER
        helper_before = helper_path.read_bytes() if isolated_helper else None
        helper_inode = helper_path.stat().st_ino if isolated_helper else None
        report = self.recover(caller_owned=True, isolated_helper=isolated_helper)
        expected_outcome = "script_failed" if failure else "applied"
        if report["outcome"] != expected_outcome:
            raise AssertionError(f"caller-owned recovery failed: {report}")
        compare(self.expected, self.candidate)
        proof_path, proof_bytes = provenance(self.candidate, report, binding)
        caller = document(self.candidate / OPERATION)
        if caller["state"] not in ("mutating", "recovering") or caller["outcome"] != "pending":
            raise AssertionError("native program completed the caller's operation")
        if not (self.candidate / INTENT).exists():
            raise AssertionError("native recovery cleaned evidence before caller acknowledgment")
        completion = self.candidate / NAMESPACE / "root-operation-completion-v1.json"
        if completion.exists():
            raise AssertionError("native program published outer completion")
        before = triggers.snapshot(self.candidate)
        repeated = self.recover(caller_owned=True, isolated_helper=isolated_helper, label="repeat-before-ack")
        if repeated["outcome"] != expected_outcome or m.oracle.differences(before, triggers.snapshot(self.candidate)):
            raise AssertionError("caller-owned repeated recovery reran package work")
        acknowledged = self.recover(caller_owned=True, isolated_helper=isolated_helper, acknowledge_native=True, label="caller-ack")
        if acknowledged["outcome"] != expected_outcome:
            raise AssertionError(f"caller acknowledgment failed: {acknowledged}")
        for path in (OPERATION, INTENT, NAMESPACE / "native-recovery-v1"):
            if (self.candidate / path).exists():
                raise AssertionError(f"acknowledgment left active evidence: {path}")
        if m.oracle.differences(before, triggers.snapshot(self.candidate)):
            raise AssertionError("acknowledgment reran package work")
        if m.oracle._read_bounded(proof_path, 16 * 1024 * 1024) != proof_bytes:
            raise AssertionError("acknowledgment replaced native provenance")
        if document(completion)["attempt_id"] != binding["attempt_id"]:
            raise AssertionError("caller completion changed the original attempt")
        if isolated_helper and (helper_path.read_bytes() != helper_before or helper_path.stat().st_ino != helper_inode):
            raise AssertionError("isolated helper changed the package-owned target")
        print(f"{self.directory.name}: caller-owned crash/recovery and acknowledgment passed", flush=True)

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

    def blocked(self, binding: dict, *, unknown_script: bool = False,
                caller_owned: bool = False, isolated_helper: bool = False) -> None:
        before = triggers.snapshot(self.candidate)
        script_bytes = m.oracle._read_bounded(self.candidate / SCRIPT, 1024 * 1024)
        if unknown_script and document(self.candidate / SCRIPT)["outcome"] != "in_flight":
            raise AssertionError("unknown-outcome fixture did not reach the in-flight boundary")
        report = self.recover(caller_owned=caller_owned, isolated_helper=isolated_helper)
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

    current = case("typed-runtime-completed-install")
    helper_path = current.candidate / triggers.HELPER
    shutil.copy2("/usr/bin/dpkg-trigger", helper_path)
    original = helper_path.read_bytes()
    original_inode = helper_path.stat().st_ino
    archive = package("typed-runtime-completed-install")
    destination = current.directory / "execute"
    destination.mkdir()
    if triggers.reference(current.expected, "install", [archive], [], environment, destination, defer=True) != 0:
        raise AssertionError("typed runtime reference installation failed")
    report = native(executable, current.candidate, architecture, "install", [archive],
                    environment, destination, caller_owned=True, isolated_helper=True)
    if report is None or report["outcome"] != "applied":
        raise AssertionError(f"typed runtime installation failed: {report}")
    binding = caller_binding(current.candidate)
    provenance(current.candidate, report, binding)
    intent = document(current.candidate / INTENT, 16 * 1024 * 1024)
    request_blob = next(blob for blob in intent["blobs"] if blob["kind"] == "request")
    request = document(current.candidate / request_blob["storage_path"])
    helper_source = current.candidate / request["helper"]["source_path"]
    caller_before = document(current.candidate / OPERATION)
    saved_target = helper_path.with_name("dpkg-trigger.saved")
    saved_source = helper_source.with_suffix(".saved")
    helper_path.rename(saved_target)
    try:
        helper_source.rename(saved_source)
        try:
            terminal = current.recover(
                caller_owned=True, isolated_helper=True, label="terminal-without-live-helper",
            )
            if terminal["outcome"] != "applied" or document(current.candidate / OPERATION) != caller_before:
                raise AssertionError("terminal receipt recovery required live helper deployment or changed caller state")
        finally:
            saved_source.rename(helper_source)
    finally:
        saved_target.rename(helper_path)
    archive.unlink()
    current.caller_completed(binding, isolated_helper=True)
    if helper_path.read_bytes() != original or helper_path.stat().st_ino != original_inode:
        raise AssertionError("typed runtime replaced the package-owned helper target")

    for boundary in ("after_execution_intent", "after_script_outcome", "after_provenance"):
        current = case(f"isolated-helper-{boundary}")
        shutil.copy2("/usr/bin/dpkg-trigger", current.candidate / triggers.HELPER)
        original = (current.candidate / triggers.HELPER).read_bytes()
        original_inode = (current.candidate / triggers.HELPER).stat().st_ino
        archive = package(f"isolated-helper-{boundary}")
        binding = current.crash("install", [archive], boundary, caller_owned=True, isolated_helper=True)
        if (current.candidate / triggers.HELPER).read_bytes() != original or (current.candidate / triggers.HELPER).stat().st_ino != original_inode:
            raise AssertionError("helper exposure changed the target before interruption")
        current.caller_completed(binding, isolated_helper=True)

    current = case("isolated-helper-target-absent")
    (current.candidate / triggers.HELPER).unlink()
    archive = package("isolated-helper-target-absent")
    destination = current.directory / "refuse"
    destination.mkdir()
    before = triggers.snapshot(current.candidate)
    report = native(executable, current.candidate, architecture, "install", [archive],
                    environment, destination, caller_owned=True, isolated_helper=True)
    if report is None or report["detail"] != "NativeHelperTargetMissing":
        raise AssertionError(f"missing target was not refused: {report}")
    if document(current.candidate / OPERATION)["mutation_started"]:
        raise AssertionError("missing target crossed the mutation boundary")
    for path in (triggers.HELPER, INTENT, NAMESPACE / "native-helper-cache-v1"):
        if (current.candidate / path).exists():
            raise AssertionError(f"missing target created unexpected state: {path}")
    if m.oracle.differences(before, triggers.snapshot(current.candidate)):
        raise AssertionError("missing target refusal changed package state")
    print("isolated-helper-target-absent: refused before mutation without a placeholder", flush=True)

    for changed in ("downgrade", "bytes"):
        current = case(f"isolated-helper-changed-{changed}")
        shutil.copy2("/usr/bin/dpkg-trigger", current.candidate / triggers.HELPER)
        archive = package(f"isolated-helper-changed-{changed}")
        current.crash("install", [archive], "after_execution_intent", caller_owned=True, isolated_helper=True)
        intent = document(current.candidate / INTENT, 16 * 1024 * 1024)
        request_blob = next(blob for blob in intent["blobs"] if blob["kind"] == "request")
        request = document(current.candidate / request_blob["storage_path"])
        if changed == "bytes":
            m.write(current.candidate / request["helper"]["source_path"], b"changed helper\n", 0o500)
        before = triggers.snapshot(current.candidate)
        report = current.recover(caller_owned=True, isolated_helper=changed != "downgrade")
        expected_detail = "HelperDigestMismatch" if changed == "bytes" else "NativeHelperBindingRequired"
        if report["outcome"] != "recovery_required" or report["detail"] != expected_detail:
            raise AssertionError(f"unsafe helper recovery was not refused: {report}")
        if m.oracle.differences(before, triggers.snapshot(current.candidate)):
            raise AssertionError("unsafe helper recovery changed package state")
        print(f"isolated-helper-changed-{changed}: recovery stayed blocked", flush=True)

    for boundary in ("after_execution_intent", "during_filesystem_publication",
                     "after_script_outcome", "after_provenance"):
        current = case(f"caller-{boundary}")
        archive = package(f"caller-{boundary}")
        binding = current.crash("install", [archive], boundary, caller_owned=True)
        current.caller_completed(binding)

    for isolated_helper in (False, True):
        label = "typed-runtime-known-failure" if isolated_helper else "caller-known-failure"
        current = case(label)
        if isolated_helper:
            shutil.copy2("/usr/bin/dpkg-trigger", current.candidate / triggers.HELPER)
        archive = package(label)
        lifecycle.Scenario.fail(current, f"{m.PACKAGE}@1:preinst:install")
        binding = current.crash(
            "install", [archive], "after_failure_outcome", failure=True,
            caller_owned=True, isolated_helper=isolated_helper,
        )
        current.caller_completed(binding, failure=True, isolated_helper=isolated_helper)

    current = case("typed-runtime-unknown-script")
    shutil.copy2("/usr/bin/dpkg-trigger", current.candidate / triggers.HELPER)
    archive = package("typed-runtime-unknown-script")
    binding = current.crash(
        "install", [archive], "after_script_return_before_outcome",
        compare_reference=False, caller_owned=True, isolated_helper=True,
    )
    current.blocked(binding, unknown_script=True, caller_owned=True, isolated_helper=True)

    current = case("caller-changed-request")
    archive = package("caller-changed-request")
    current.crash("install", [archive], "after_execution_intent", caller_owned=True)
    intent = document(current.candidate / INTENT, 16 * 1024 * 1024)
    request_blob = next(blob for blob in intent["blobs"] if blob["kind"] == "request")
    request_path = current.candidate / request_blob["storage_path"]
    request = document(request_path)
    request["caller"]["policy_sha256"] = "f" * 64
    request["digest_sha256"] = "0" * 64
    request["digest_sha256"] = digest("debz-native-execution-request-v1\0", request)
    request_bytes = canonical(request) + b"\n"
    m.write(request_path, request_bytes)
    request_blob["sha256"] = hashlib.sha256(request_bytes).hexdigest()
    request_blob["size"] = len(request_bytes)
    intent["digest_sha256"] = "0" * 64
    intent["digest_sha256"] = digest("debz-native-execution-intent-v1\0", intent)
    m.write(current.candidate / INTENT, canonical(intent) + b"\n")
    before = triggers.snapshot(current.candidate)
    report = current.recover(caller_owned=True)
    if report["outcome"] != "recovery_required" or report["detail"] != "RecoveryRequestBindingMismatch":
        raise AssertionError(f"rehashed production request was not refused against its caller: {report}")
    if m.oracle.differences(before, triggers.snapshot(current.candidate)):
        raise AssertionError("changed production request allowed package mutation")
    print("caller-changed-request: rehashed caller substitution stayed blocked", flush=True)

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

    isolated = case("isolated-helper-trigger-outcome")
    isolated.seed(first, second)
    shutil.copy2("/usr/bin/dpkg-trigger", isolated.candidate / triggers.HELPER)
    isolated_source = m.make_package(
        workspace / "packages/isolated-trigger-source", environment, architecture, "1",
        package=triggers.SOURCE, triggers=b"activate-noawait debz-a\n",
        scripts=triggers.script_set(triggers.SOURCE, "1"),
    )
    isolated_binding = isolated.crash(
        "install", [isolated_source], "after_trigger_outcome", trigger_execution=True,
        caller_owned=True, isolated_helper=True,
    )
    isolated.caller_completed(isolated_binding, isolated_helper=True)

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


def exercise_core(executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str) -> None:
    for boundary in (
        "after_native_receipt", "after_completed_record", "after_owed_provenance_document",
        "after_provenance_published", "after_native_acknowledged",
    ):
        current = Scenario(workspace, f"core-{boundary}", executable, helper, architecture, environment)
        shutil.copy2("/usr/bin/dpkg-trigger", current.candidate / triggers.HELPER)
        archive = m.make_package(
            workspace / "packages" / boundary, environment, architecture, "1",
            scripts=lifecycle.scripts(m.PACKAGE, "1"),
        )
        binding = current.crash(
            "install", [archive], "after_execution_intent",
            caller_owned=True, isolated_helper=True, core_product=True,
        )
        destination = current.directory / "completion-crash"
        destination.mkdir()
        native(executable, current.candidate, architecture, "recover", [], environment, destination,
               caller_owned=True, isolated_helper=True, core_product=True, completion_crash=boundary)
        assert (current.candidate / OPERATION).exists()
        assert (current.candidate / INTENT).exists() == (boundary != "after_native_acknowledged")
        before = triggers.snapshot(current.candidate)
        report = current.recover(caller_owned=True, isolated_helper=True, core_product=True)
        if report["outcome"] != "applied":
            raise AssertionError(f"core completion did not converge: {report}")
        compare(current.expected, current.candidate)
        if m.oracle.differences(before, triggers.snapshot(current.candidate)):
            raise AssertionError("core completion recovery reran package work")
        proof_path, proof_bytes = provenance(current.candidate, report, binding)
        receipt = document(proof_path, 16 * 1024 * 1024)
        completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
        assert completion["attempt_id"] == binding["attempt_id"]
        assert completion["transaction_provenance"]["document_sha256"] == receipt["digest_sha256"]
        assert completion["journal"]["status"] == "absent"
        for path in (OPERATION, INTENT, NAMESPACE / "native-recovery-v1"):
            assert not (current.candidate / path).exists(), path
        repeated = current.recover(caller_owned=True, isolated_helper=True, core_product=True, label="repeat")
        assert repeated["outcome"] == "applied"
        assert proof_path.read_bytes() == proof_bytes
        print(f"core-{boundary}: receipt-backed completion and acknowledgment passed", flush=True)

    for known in (True, False):
        name = "core-known-failure" if known else "core-unknown-script"
        current = Scenario(workspace, name, executable, helper, architecture, environment)
        shutil.copy2("/usr/bin/dpkg-trigger", current.candidate / triggers.HELPER)
        archive = m.make_package(
            workspace / "packages" / name, environment, architecture, "1",
            scripts=lifecycle.scripts(m.PACKAGE, "1"),
        )
        if known:
            lifecycle.Scenario.fail(current, f"{m.PACKAGE}@1:preinst:install")
        binding = current.crash(
            "install", [archive],
            "after_failure_outcome" if known else "after_script_return_before_outcome",
            failure=known, compare_reference=known,
            caller_owned=True, isolated_helper=True, core_product=True,
        )
        before = triggers.snapshot(current.candidate)
        report = current.recover(caller_owned=True, isolated_helper=True, core_product=True)
        if known:
            assert report["outcome"] == "script_failed", report
            compare(current.expected, current.candidate)
            provenance(current.candidate, report, binding)
            completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
            assert completion["outcome"] == "failed_after_mutation"
            assert not (current.candidate / OPERATION).exists()
            assert not (current.candidate / INTENT).exists()
        else:
            assert report["outcome"] == "recovery_required", report
            assert (current.candidate / INTENT).exists()
            assert document(current.candidate / OPERATION)["attempt_id"] == binding["attempt_id"]
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        print(f"{name}: native outcome and original evidence preserved", flush=True)


def workflow(
    executable: Path, request: dict, destination: Path, environment: dict,
    *, completion_crash: str | None = None, owner_evidence: Path | None = None,
    acknowledgment: str | None = None, reconciliation_owner_output: Path | None = None,
) -> dict | None:
    m.reference_command(Path(request["options"]["install_root"]))
    destination.mkdir()
    request_path = destination / "workflow.request.json"
    report_path = destination / "workflow.report.json"
    m.write(request_path, json.dumps({
        "workflow": request, "report": str(report_path),
        "completion_crash": completion_crash,
        "owner_evidence": str(owner_evidence) if owner_evidence else None,
        "reconciliation_owner_output": str(reconciliation_owner_output) if reconciliation_owner_output else None,
        "acknowledgment": acknowledgment,
    }).encode())
    with (destination / "workflow.log").open("wb") as output:
        result = subprocess.run(
            [str(executable)],
            env={**environment, "DEBZ_NATIVE_WORKFLOW_REQUEST": str(request_path)},
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            timeout=120, check=False,
        )
    expected = CRASH_EXIT if completion_crash else 0
    if result.returncode != expected:
        with (destination / "workflow.log").open("rb") as output:
            output.seek(0, os.SEEK_END)
            output.seek(max(0, output.tell() - 8192))
            detail = output.read(8192).decode(errors="replace")
        raise AssertionError(f"workflow exited {result.returncode}, expected {expected}: {destination}\n{detail}")
    if completion_crash:
        assert not report_path.exists()
        return None
    return document(report_path, 64 * 1024)


def exercise_workflows(
    executable: Path, workspace: Path, environment: dict, architecture: str,
    result_cli: Path | None = None,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "debz_workflow_repository", ROOT / "tools/generate-integration-repository.py",
    )
    assert spec and spec.loader
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    repository = workspace / "workflow-repository"
    generator.write_repository(repository, "debian-stable", architecture)
    source = workspace / "workflow.sources"
    keyring = repository / "fixture-keyring.gpg"
    m.write(source, (
        f"Types: deb\nURIs: file://{repository}\nSuites: debian-stable\n"
        f"Components: main\nArchitectures: {architecture}\nSigned-By: {keyring}\n"
    ).encode())

    def archive(name: str) -> Path:
        return repository / f"pool/main/{name}_1.0-1_{architecture}.deb"

    def scenario(name: str) -> lifecycle.Scenario:
        current = lifecycle.Scenario(workspace, name, executable, architecture, environment)
        current.seed(archive("native-helper-target"))
        current.seed(archive("essential-core"))
        return current

    def request(current: lifecycle.Scenario, operation: str, mode: str, names: list[str]) -> dict:
        options = {
            "install_root": str(current.candidate),
            "cache_path": str(current.directory / ("unused-cache" if mode == "recover" else "cache")),
            "state_path": str(current.directory / ("unused-state" if mode == "recover" else "state")),
            "architecture": architecture, "assume_yes": True,
            "conffile": "keep_existing", "noninteractive": True,
        }
        if mode != "recover":
            options.update(source_paths=[str(source)], keyring_paths=[str(keyring)])
            options["lock_output_path" if mode == "plan_only" else "lock_input_path"] = str(
                current.directory / "workflow.lock.json"
            )
        return {
            "operation": operation, "mode": mode,
            "selectors": [{"name": name} for name in names], "options": options,
        }

    def run(current: lifecycle.Scenario, label: str, value: dict, *, exit_status: int = 0, **options) -> dict:
        result = workflow(executable, value, current.directory / label, environment, **options)
        assert result["exit_status"] == exit_status, result
        return result

    def assert_completion(current: lifecycle.Scenario, lock: dict) -> None:
        receipt = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
        validator(PROVENANCE_SCHEMA).validate(receipt)
        assert_digest(receipt, PROVENANCE_SCHEMA)
        retained_documents(current.candidate, receipt)
        completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
        assert receipt["exact_lock_sha256"] == lock["digest_sha256"]
        assert completion["attempt_id"] == receipt["attempt_id"]
        assert completion["transaction_provenance"]["document_sha256"] == receipt["digest_sha256"]
        assert completion["journal"]["status"] == "absent"
        assert_final_database(current.candidate, architecture, receipt)
        for path in (OPERATION, INTENT, NAMESPACE / "native-recovery-v1"):
            assert not (current.candidate / path).exists(), path
        if result_cli is not None:
            verify_result(
                current, lock,
                receipt["outcome"] == "succeeded" and
                not (current.candidate / NAMESPACE / "root-operation-deferred-ack-v1.json").exists(),
            )

    def verify_result(
        current: lifecycle.Scenario, lock: dict, succeeds: bool = True,
        selected_architecture: str | None = None,
    ) -> None:
        assert result_cli is not None

        def inventory() -> list[tuple]:
            return sorted(
                (str(path.relative_to(current.candidate)), entry.st_mode, entry.st_size, entry.st_mtime_ns)
                for path in (current.candidate / NAMESPACE).rglob("*")
                for entry in [path.lstat()]
            )

        before = inventory()
        result = subprocess.run(
            [
                str(result_cli), "transaction-result", "verify", "--transaction-backend", "native",
                "--install-root", str(current.candidate),
                "--lock-input", str(current.directory / "workflow.lock.json"),
                "--architecture", selected_architecture or architecture, "--json",
            ],
            env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
        )
        assert before == inventory(), "native verification changed root-operation evidence"
        assert result.returncode == (0 if succeeds else 7), result.stderr.decode(errors="replace")
        if not succeeds:
            assert result.stdout == b""
            return
        assert result.stderr == b""
        summary = json.loads(result.stdout)
        validator("transaction-result-summary-v2").validate(summary)
        assert result.stdout == json.dumps(summary, separators=(",", ":")).encode() + b"\n"
        assert summary["backend"] == "native"
        assert summary["lock_sha256"] == lock["digest_sha256"]
        assert summary["request_sha256"] == lock["request_sha256"]
        assert summary["solver_policy_sha256"] == lock["policy_sha256"]
        assert summary["package_count"] == len(lock["packages"])
        receipt = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
        completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
        assert summary["transaction_digest_sha256"] == receipt["digest_sha256"]
        assert summary["completion_digest_sha256"] == completion["digest_sha256"]
        assert summary["caller_request_sha256"] == completion["request_sha256"]
        assert summary["caller_policy_sha256"] == completion["policy_sha256"]
        assert summary["program_sha256"] == receipt["program_sha256"]

    names = ["scenario-main", "conffile-pkg"]
    current = scenario("workflow-batch")
    planned = run(current, "plan-install", request(current, "install", "plan_only", names))
    assert {item["package"] for item in planned["items"]} == {*names, "base-dep"}
    lock = document(current.directory / "workflow.lock.json")
    assert lock["version"] == 2
    installed = run(current, "install", request(current, "install", "execute", list(reversed(names))))
    assert installed["changed"]
    reference_dir = current.directory / "reference-install"
    reference_dir.mkdir()
    assert lifecycle.reference_phase(
        current.expected, [archive(name) for name in ["base-dep", *names]], "install",
        environment, reference_dir, packages=[],
    ) == 0
    compare(current.expected, current.candidate)
    assert_completion(current, lock)
    if result_cli is not None:
        capability_result = subprocess.run(
            [str(result_cli), "transaction-result", "capabilities", "--transaction-backend", "native", "--json"],
            env=environment, capture_output=True, timeout=30, check=True,
        )
        validator("transaction-result-capability-v1").validate(json.loads(capability_result.stdout))
        verify_result(current, lock, False, "arm64" if architecture == "amd64" else "amd64")
        lock_path = current.directory / "workflow.lock.json"
        original_lock = lock_path.read_bytes()
        different_lock = dict(lock)
        different_lock.pop("digest_sha256")
        different_lock["request_sha256"] = "0" * 64
        different_lock["digest_sha256"] = hashlib.sha256(
            json.dumps(different_lock, separators=(",", ":")).encode()
        ).hexdigest()
        try:
            lock_path.write_bytes(json.dumps(different_lock, separators=(",", ":")).encode())
            verify_result(current, different_lock, False)
        finally:
            lock_path.write_bytes(original_lock)
        m.write(current.candidate / OPERATION, b"unsettled operation\n")
        try:
            verify_result(current, lock, False)
        finally:
            (current.candidate / OPERATION).unlink()
        receipt = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
        program_path = current.candidate / next(
            entry["path"] for entry in receipt["evidence_files"] if entry["kind"] == "program"
        )
        for path in (
            program_path,
            current.candidate / NAMESPACE / "native-transaction-provenance-v1.json",
            current.candidate / NAMESPACE / "root-operation-completion-v1.json",
            current.candidate / "var/lib/dpkg/status",
        ):
            original = path.read_bytes()
            try:
                path.write_bytes(b"invalid completed evidence\n")
                verify_result(current, lock, False)
            finally:
                path.write_bytes(original)
        verify_result(current, lock)
    receipt_before = (current.candidate / NAMESPACE / "native-transaction-provenance-v1.json").read_bytes()
    run(current, "plan-unchanged", request(current, "upgrade_all", "plan_only", []))
    unchanged = run(current, "unchanged", request(current, "upgrade_all", "execute", []))
    assert not unchanged["changed"]
    assert receipt_before == (current.candidate / NAMESPACE / "native-transaction-provenance-v1.json").read_bytes()
    run(current, "plan-remove", request(current, "remove", "plan_only", names))
    removal_lock = document(current.directory / "workflow.lock.json")
    removed = run(current, "remove", request(current, "remove", "execute", names))
    assert removed["changed"]
    reference_dir = current.directory / "reference-remove"
    reference_dir.mkdir()
    assert lifecycle.reference_phase(
        current.expected, [], "remove", environment, reference_dir,
        packages=[{"name": name, "architecture": architecture} for name in names],
    ) == 0
    compare(current.expected, current.candidate)
    assert_completion(current, removal_lock)
    print("workflow-batch: v2 install/remove parity and unchanged closure passed", flush=True)

    current = scenario("workflow-known-failure")
    failed_names = ["scenario-main", "fail-script"]
    run(current, "plan", request(current, "install", "plan_only", failed_names))
    failure_lock = document(current.directory / "workflow.lock.json")
    failed = run(
        current, "execute", request(current, "install", "execute", failed_names), exit_status=7,
    )
    assert failed["changed"]
    assert_completion(current, failure_lock)
    receipt = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
    assert receipt["outcome"] == "failed"
    completed = run(current, "recover", request(current, "install", "recover", failed_names))
    assert not completed["changed"]
    print("workflow-known-failure: terminal failure receipt and cleanup passed", flush=True)

    for boundary in (
        "after_native_receipt", "after_completed_record", "after_owed_provenance_document",
        "after_provenance_published", "after_native_acknowledged",
    ):
        current = scenario(f"workflow-{boundary}")
        run(current, "plan", request(current, "install", "plan_only", names))
        lock = document(current.directory / "workflow.lock.json")
        workflow(
            executable, request(current, "install", "execute", names),
            current.directory / "crash", environment, completion_crash=boundary,
        )
        record_before = (current.candidate / OPERATION).read_bytes()
        state_before = triggers.snapshot(current.candidate)
        recovery = request(current, "install", "recover", list(reversed(names)))
        if boundary == "after_native_receipt":
            run(current, "deferred-owner", {**recovery, "defer_recovery_clear": True}, exit_status=2)
            assert (current.candidate / OPERATION).read_bytes() == record_before
            for index, change in enumerate((
                {"operation": "remove"},
                {"selectors": [{"name": "different"}]},
                {"options": {**recovery["options"], "recommends": True}},
                {"options": {**recovery["options"], "conffile": "use_package_version"}},
            )):
                run(current, f"wrong-original-{index}", {**recovery, **change}, exit_status=8)
                assert (current.candidate / OPERATION).read_bytes() == record_before
            for index, (field, value) in enumerate((
                ("lock_input_path", str(current.directory / "workflow.lock.json")),
                ("source_paths", [str(source)]),
                ("keyring_paths", [str(keyring)]),
                ("force", ["overwrite"]),
            )):
                run(current, f"replacement-{index}", {
                    **recovery, "options": {**recovery["options"], field: value},
                }, exit_status=2)
                assert (current.candidate / OPERATION).read_bytes() == record_before
        result = run(current, "recover", recovery)
        assert result["changed"]
        assert not m.oracle.differences(state_before, triggers.snapshot(current.candidate))
        assert_completion(current, lock)
        repeated = run(current, "recover-again", recovery)
        assert not repeated["changed"]
        assert not (current.directory / "unused-cache").exists()
        assert not (current.directory / "unused-state").exists()
        print(f"workflow-{boundary}: original-request recovery and receipt completion passed", flush=True)

    owner_path = NAMESPACE / "root-operation-deferred-ack-v1.json"

    def owned_request(current, operation, mode, selected):
        return {**request(current, operation, mode, selected), "orchestration_id": [17] * 32}

    def retain_owner(current, label):
        path = current.directory / f"{label}.owner.json"
        m.write(path, m.oracle._read_bounded(current.candidate / owner_path, 1024 * 1024))
        return path

    current = scenario("workflow-owned-success")
    run(current, "plan", request(current, "install", "plan_only", names))
    lock = document(current.directory / "workflow.lock.json")
    run(current, "reserve", {
        **owned_request(current, "install", "reserve", names), "root_attempt_id": [34] * 32,
    })
    bound = retain_owner(current, "bound")
    reserved = (current.candidate / OPERATION).read_bytes()
    assert document(bound)["state"] == "bound"
    assert document(bound)["attempt_id"] == "22" * 32
    assert not (current.candidate / INTENT).exists()
    run(current, "changed-request", owned_request(current, "install", "execute", ["different"]),
        owner_evidence=bound, exit_status=8)
    assert (current.candidate / OPERATION).read_bytes() == reserved
    run(current, "execute", owned_request(current, "install", "execute", list(reversed(names))),
        owner_evidence=bound)
    assert_completion(current, lock)
    released = retain_owner(current, "released")
    assert document(released)["state"] == "released"
    finalization = owned_request(current, "install", "recover", names)
    run(current, "finalize", finalization, owner_evidence=released, acknowledgment="ownership")
    run(current, "finalize-again", finalization, owner_evidence=released, acknowledgment="ownership")
    assert not (current.candidate / owner_path).exists()
    print("workflow-owned-success: reservation, native receipt, and exact owner finalization passed", flush=True)

    for boundary in ("after_provenance_published", "after_ownership_terminal_publish", "after_ownership_record_clear"):
        current = scenario(f"workflow-finalize-{boundary}")
        run(current, "plan", request(current, "install", "plan_only", names))
        lock = document(current.directory / "workflow.lock.json")
        run(current, "reserve", owned_request(current, "install", "reserve", names))
        bound = retain_owner(current, "bound")
        workflow(executable, owned_request(current, "install", "execute", names),
                 current.directory / "execute-crash", environment, completion_crash=boundary,
                 owner_evidence=bound)
        retained = retain_owner(current, "terminal")
        finalization = owned_request(current, "install", "recover", names)
        before = triggers.snapshot(current.candidate)
        if boundary == "after_provenance_published":
            completion_path = current.candidate / NAMESPACE / "root-operation-completion-v1.json"
            original_completion = completion_path.read_bytes()
            m.write(completion_path, b"{}\n")
            run(current, "damaged-completion", finalization, owner_evidence=retained,
                acknowledgment="ownership", exit_status=8)
            m.write(completion_path, original_completion)
            workflow(executable, finalization, current.directory / "finalize-crash", environment,
                     completion_crash="after_native_acknowledged", owner_evidence=retained,
                     acknowledgment="ownership")
        else:
            run(current, "recover", {**finalization, "defer_recovery_clear": True},
                owner_evidence=retained, exit_status=8 if boundary == "after_ownership_record_clear" else 0)
        run(current, "finalize", finalization, owner_evidence=retained, acknowledgment="ownership")
        assert_completion(current, lock)
        assert not (current.candidate / owner_path).exists()
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        print(f"workflow-finalize-{boundary}: exact owner cleanup converged without replay", flush=True)

    for preflight_failure in (False, True):
        current = scenario(f"workflow-owned-abandon-{preflight_failure}")
        selected = names if preflight_failure else []
        operation = "install" if preflight_failure else "upgrade_all"
        run(current, "plan", request(current, operation, "plan_only", selected))
        run(current, "reserve", owned_request(current, operation, "reserve", selected))
        bound = retain_owner(current, "bound")
        execution = owned_request(current, operation, "execute", selected)
        if preflight_failure:
            invalid_source = current.directory / "invalid.sources"
            m.write(invalid_source, b"not-an-apt-source\n")
            execution["options"]["source_paths"] = [str(invalid_source)]
        result = run(current, "execute", execution, owner_evidence=bound,
                     exit_status=2 if preflight_failure else 0)
        assert not result["changed"]
        abandoned = retain_owner(current, "abandoned")
        assert document(abandoned)["state"] == "abandoned"
        assert not (current.candidate / OPERATION).exists()
        run(current, "finalize", owned_request(current, operation, "recover", selected),
            owner_evidence=abandoned, acknowledgment="ownership")
        assert not (current.candidate / owner_path).exists()
    print("workflow-owned-abandon: unchanged and refused attempts preserve exact owner handoff", flush=True)

    for execution_boundary, acknowledgment_boundary in zip((
        "after_native_receipt", "after_completed_record", "after_owed_provenance_document",
        "after_provenance_published", "after_native_acknowledged",
    ), (
        "after_native_acknowledged", "after_deferred_acknowledged",
        "before_deferred_record_cleared", "after_deferred_record_cleared",
        "after_deferred_marker_cleared",
    ), strict=True):
        current = scenario(f"workflow-owned-{execution_boundary}")
        run(current, "plan", request(current, "install", "plan_only", names))
        lock = document(current.directory / "workflow.lock.json")
        run(current, "reserve", owned_request(current, "install", "reserve", names))
        bound = retain_owner(current, "bound")
        workflow(executable, owned_request(current, "install", "execute", names),
                 current.directory / "execute-crash", environment,
                 completion_crash=execution_boundary, owner_evidence=bound)
        original = (current.candidate / OPERATION).read_bytes()
        recovery = {**owned_request(current, "install", "recover", names), "defer_recovery_clear": True}
        run(current, "foreign-recovery", {**recovery, "orchestration_id": [18] * 32},
            owner_evidence=bound, exit_status=8)
        assert (current.candidate / OPERATION).read_bytes() == original
        before = triggers.snapshot(current.candidate)
        recovery_owner = bound
        if execution_boundary == "after_completed_record":
            workflow(executable, recovery, current.directory / "pending-publication-crash", environment,
                     completion_crash="after_owed_provenance_document", owner_evidence=bound)
            recovery_owner = retain_owner(current, "pending-prepublication")
            assert document(recovery_owner)["state"] == "pending"
            assert document(current.candidate / OPERATION)["provenance"] == "pending"
        run(current, "recover", recovery, owner_evidence=recovery_owner)
        pending = retain_owner(current, "pending")
        assert document(pending)["state"] == "pending"
        published = (current.candidate / OPERATION).read_bytes()
        run(current, "recover-again", recovery, owner_evidence=pending)
        assert (current.candidate / OPERATION).read_bytes() == published
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        run(current, "foreign-acknowledgment", {**recovery, "orchestration_id": [18] * 32},
            owner_evidence=pending, acknowledgment="recovery", exit_status=2)
        assert (current.candidate / OPERATION).read_bytes() == published
        if execution_boundary == "after_native_receipt":
            run(current, "wrong-operation-acknowledgment", {**recovery, "operation": "remove"},
                owner_evidence=pending, acknowledgment="recovery", exit_status=8)
            receipt_path = current.candidate / NAMESPACE / "native-transaction-provenance-v1.json"
            original_receipt = receipt_path.read_bytes()
            m.write(receipt_path, b"{}\n")
            run(current, "damaged-receipt", recovery, owner_evidence=pending,
                acknowledgment="recovery", exit_status=8)
            assert (current.candidate / OPERATION).read_bytes() == published
            assert (current.candidate / owner_path).read_bytes() == pending.read_bytes()
            assert (current.candidate / INTENT).exists()
            m.write(receipt_path, original_receipt)
        workflow(executable, recovery, current.directory / "acknowledgment-crash", environment,
                 completion_crash=acknowledgment_boundary, owner_evidence=pending,
                 acknowledgment="recovery")
        run(current, "acknowledge", recovery, owner_evidence=pending, acknowledgment="recovery")
        run(current, "acknowledge-again", recovery, owner_evidence=pending, acknowledgment="recovery")
        assert_completion(current, lock)
        assert not (current.candidate / owner_path).exists()
        assert not (current.directory / "unused-cache").exists()
        assert not (current.directory / "unused-state").exists()
        print(f"workflow-owned-{execution_boundary}: deferred receipt acknowledgment crash convergence passed", flush=True)

    current = scenario("workflow-owned-known-failure")
    run(current, "plan", request(current, "install", "plan_only", failed_names))
    lock = document(current.directory / "workflow.lock.json")
    run(current, "reserve", owned_request(current, "install", "reserve", failed_names))
    bound = retain_owner(current, "bound")
    workflow(executable, owned_request(current, "install", "execute", failed_names),
             current.directory / "pending-publication-crash", environment,
             completion_crash="after_owed_provenance_document", owner_evidence=bound)
    pending = retain_owner(current, "pending")
    assert document(pending)["state"] == "pending"
    assert document(current.candidate / OPERATION)["outcome"] == "failed_after_mutation"
    assert document(current.candidate / OPERATION)["provenance"] == "pending"
    recovery = {**owned_request(current, "install", "recover", failed_names), "defer_recovery_clear": True}
    run(current, "recover", recovery, owner_evidence=pending, exit_status=7)
    run(current, "acknowledge", recovery, owner_evidence=pending, acknowledgment="recovery")
    assert_completion(current, lock)
    assert not (current.candidate / owner_path).exists()
    print("workflow-owned-known-failure: honest failure outcome retained through acknowledgment", flush=True)

    for pre_mutation in (True, False):
        for claim_boundary, finalize_boundary in (
            ("before_reconciliation_marker_publish", "before_ownership_marker_clear"),
            ("after_reconciliation_marker_publish", "after_ownership_marker_clear"),
        ):
            current = scenario(f"workflow-reconciliation-{pre_mutation}-{claim_boundary}")
            run(current, "plan", request(current, "upgrade_all", "plan_only", []))
            lock = document(current.directory / "workflow.lock.json")
            recovery = owned_request(current, "upgrade_all", "recover", [])
            binding = {"exact_lock_sha256": list(bytes.fromhex(lock["digest_sha256"]))}
            if pre_mutation:
                binding.update(
                    outer_generation=1, outer_state_sha256=[31] * 32,
                    profile_sha256=[32] * 32, profile_reference_sha256=[33] * 32,
                )
            else:
                binding["evidence_sha256"] = [34] * 32
            claim = {**recovery, "reconciliation_claim": {
                "pre_mutation" if pre_mutation else "post_mutation": binding,
            }}
            proof = current.directory / "trusted-reconciliation.owner.json"
            before = triggers.snapshot(current.candidate)
            workflow(executable, claim, current.directory / "claim-crash", environment,
                     completion_crash=claim_boundary, reconciliation_owner_output=proof)
            expected = document(proof)
            assert expected["state"] == ("pre_mutation_reconciliation_claim" if pre_mutation else "released")
            if claim_boundary == "before_reconciliation_marker_publish":
                assert not (current.candidate / owner_path).exists()
                run(current, "changed-request", {**claim, "operation": "remove", "selectors": [{"name": "different"}]},
                    owner_evidence=proof, exit_status=8)
                run(current, "claim", claim, owner_evidence=proof)
            assert (current.candidate / owner_path).read_bytes() == proof.read_bytes()
            run(current, "repeat-claim", claim, owner_evidence=proof, exit_status=8)
            workflow(executable, recovery, current.directory / "finalize-crash", environment,
                     completion_crash=finalize_boundary, owner_evidence=proof, acknowledgment="ownership")
            run(current, "finalize", recovery, owner_evidence=proof, acknowledgment="ownership")
            run(current, "finalize-again", recovery, owner_evidence=proof, acknowledgment="ownership")
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            for path in (OPERATION, INTENT, owner_path, NAMESPACE / "root-operation-completion-v1.json",
                         NAMESPACE / "native-transaction-provenance-v1.json"):
                assert not (current.candidate / path).exists(), path
            assert not (current.directory / "unused-cache").exists()
            assert not (current.directory / "unused-state").exists()
            print(f"workflow-reconciliation-{pre_mutation}-{claim_boundary}: exact exclusion and finalization passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", type=Path)
    parser.add_argument("--native-helper", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--core-only", action="store_true")
    parser.add_argument("--result-cli", type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("recovery acceptance requires root for actual chroot execution")
    for command in ("dpkg", "dpkg-deb", "dpkg-trigger", "ldd"):
        if shutil.which(command) is None:
            raise RuntimeError(f"missing reference prerequisite: {command}")
    executable = arguments.native_test.resolve(strict=True)
    helper = arguments.native_helper.resolve(strict=True)
    result_cli = arguments.result_cli.resolve(strict=True) if arguments.result_cli else None
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
            environment = m.fixture_environment(workspace)
            if not arguments.core_only:
                exercise(executable, helper, workspace, environment, architecture)
            exercise_core(executable, helper, workspace, environment, architecture)
            exercise_workflows(executable, workspace, environment, architecture, result_cli)
    finally:
        if Path("/var/lib/dpkg/status").read_bytes() != host_status:
            raise AssertionError("host dpkg status changed during recovery acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
