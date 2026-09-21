#!/usr/bin/env python3
"""Exercise actual native-process crashes, recovery, and bound provenance."""

from __future__ import annotations

import argparse
import base64
from contextlib import nullcontext
import fcntl
from functools import cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

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
    "diversion_cache": "native-diversion-cache-v1",
    "unpack_diversion_cache": "native-unpack-diversion-v1",
    "trigger_events": "native-trigger-events-v1",
    "script_outcome": "native-script-outcome-v1",
}


def document(path: Path, maximum: int = 1024 * 1024) -> dict:
    value = json.loads(m.oracle._read_bounded(path, maximum))
    if not isinstance(value, dict):
        raise AssertionError(f"expected a bounded JSON object: {path}")
    return value


def diagnostic_inspection(report: dict, evidence: dict, root: Path) -> dict:
    assert report["schema"] == "io.github.cataggar.debz.package-family.result.v2"
    assert report["version"] == 2 and report["operation"] == "inspect"
    assert report["succeeded"] and report["exit_status"] == "success" and not report["changed"]
    assert report["lock_path"] is None and report["provenance_path"] is None
    assert evidence["native_install"] is None and evidence["native_completion"] is None
    value = evidence["native_inspection"]
    assert value["diagnostic_only"] is True and value["root"] == str(root)
    assert isinstance(value["status_database_present"], bool) and isinstance(value["native_active_evidence"], bool)
    identities = [(package["name"], package["architecture"]) for package in value["packages"]]
    assert identities == sorted(identities) and len(set(identities)) == len(identities)
    for package in value["packages"]:
        assert set(package) == {"name", "version", "architecture", "status"}
        assert set(package["status"]) == {"want", "error_state", "current"}
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
    recovery_crash: str | None = None,
    deadline_after_ms: int | None = None,
    policy: str | None = None,
) -> dict | None:
    m.reference_command(root)
    if operation == "recover" and (archives or packages or crash_at is not None or policy is not None):
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
    if recovery_crash is not None:
        if operation != "recover" or not caller_owned or not isolated_helper or core_product or recovery_crash not in (
            "during_known_unpack_rollback", "after_known_unpack_rollback",
        ):
            raise ValueError("rollback crashes require a recovering helper-bound runtime caller")
        request["crash_at"] = recovery_crash
    if policy is not None:
        request["policy"] = policy
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
    if deadline_after_ms is not None:
        if deadline_after_ms < 0 or not caller_owned or not isolated_helper or core_product:
            raise ValueError("execution deadlines require a typed helper-bound caller")
        request["deadline_after_ms"] = deadline_after_ms
    m.write(request_path, json.dumps(request).encode())
    with (destination / "native.log").open("wb") as output:
        result = subprocess.run(
            [str(executable)],
            env={**environment, "DEBZ_NATIVE_LIFECYCLE_REQUEST": str(request_path)},
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            timeout=120, check=False,
        )
    crashing = crash_at is not None or completion_crash is not None or recovery_crash is not None
    expected_exit = CRASH_EXIT if crashing else 0
    if result.returncode != expected_exit:
        raise AssertionError(
            f"native {operation}: exit {result.returncode}, expected {expected_exit}; {destination}"
        )
    if crashing:
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


def assert_cached_diversion_contents(cached: dict) -> None:
    if cached["loaded"] is None:
        if cached["observed"] is not None or cached["contents_base64"] is not None:
            raise AssertionError("absent diversion cache has inconsistent evidence")
        return
    raw = base64.b64decode(cached["contents_base64"], validate=True)
    if base64.b64encode(raw).decode() != cached["contents_base64"]:
        raise AssertionError("diversion cache bytes are not canonically encoded")
    if hashlib.sha256(raw).digest() != bytes(cached["loaded"]["sha256"]):
        raise AssertionError("cached diversion bytes differ from their loaded digest")
    observed = cached["observed"]
    if observed is None or any(cached["loaded"][key] != observed[key] for key in ("device", "inode")):
        raise AssertionError("cached and observed diversion file identities differ")


def assert_unpack_backup_contents(envelope: dict) -> None:
    if "deferred_removals" in envelope:
        assert envelope["deferred_removals"] is True and "backups" in envelope, "invalid deferred-removal protocol"
    if "settlement" in envelope:
        assert envelope.get("deferred_removals") is True and "backups" in envelope, "invalid settlement protocol"
        settlement = envelope["settlement"]
        assert isinstance(settlement, dict) and settlement["version"] == 1, "invalid settlement recipe"
        writes = settlement["writes"]
        assert 0 < len(writes) <= 200000
        paths, size = set(), 0
        for write in writes:
            assert len(write) == 1
            kind, value = next(iter(write.items()))
            assert kind in ("file", "metadata", "remove", "remove_directory")
            path = value["path"]
            assert path not in paths and all(part not in ("", ".", "..") for part in path.split("/"))
            paths.add(path)
            if kind == "file":
                assert path.startswith("var/lib/dpkg/")
                contents = bytes.fromhex(value["bytes_hex"])
                assert contents.hex() == value["bytes_hex"]
                assert hashlib.sha256(contents).hexdigest() == value["sha256"]
                size += len(contents)
        assert size <= 64 * 1024 * 1024
        final = writes[-1]["file"]
        assert final["path"] == "var/lib/dpkg/status"
        assert final["sha256"] == settlement["resulting_status_sha256"]
        assert len(final["bytes_hex"]) // 2 == settlement["resulting_status_size"]
    if "backups" not in envelope:
        return
    backups = envelope["backups"]
    if not isinstance(backups, list):
        raise AssertionError("backup-capable inputs require an explicit array")
    paths = [entry["path"] for entry in backups]
    if paths != sorted(set(paths)):
        raise AssertionError("backup paths must be unique and sorted")
    path_set = set(paths)
    identities = {}
    for entry in backups:
        for path in (entry["path"], entry["logical_path"], entry["path"] + ".dpkg-tmp"):
            if not path or len(path.encode()) > 4096 or any(part in ("", ".", "..") for part in path.split("/")):
                raise AssertionError("backup paths must be canonical and root-relative")
        if entry["path"] + ".dpkg-tmp" in path_set:
            raise AssertionError("backup collides with an original path")
        if entry["kind"] == "regular":
            if entry["backup_modified_nanoseconds"] != entry["modified_nanoseconds"]:
                raise AssertionError("regular backup changed the original timestamp")
        elif entry["size"] != len(entry["link_target"].encode()):
            raise AssertionError("symlink backup size differs from its target")
        identity = (entry["device"], entry["inode"])
        metadata = tuple(entry.get(key) for key in (
            "kind", "mode", "uid", "gid", "size", "modified_nanoseconds", "content_sha256", "link_target",
        ))
        if identity in identities and identities[identity] != metadata:
            raise AssertionError("hard-linked originals have contradictory metadata")
        identities[identity] = metadata


def assert_visible_unpack_backups(root: Path, envelope: dict) -> None:
    assert_unpack_backup_contents(envelope)
    assert envelope["backups"], "backup probe did not bind any original paths"
    for entry in envelope["backups"]:
        original, backup = root / entry["path"], root / (entry["path"] + ".dpkg-tmp")
        before, saved = original.lstat(), backup.lstat()
        for observed in (before, saved):
            assert (stat.S_IMODE(observed.st_mode), observed.st_uid, observed.st_gid, observed.st_size) == (
                entry["mode"], entry["uid"], entry["gid"], entry["size"],
            )
        device = (os.major(before.st_dev) << 32) | os.minor(before.st_dev)
        assert (device, before.st_ino, before.st_mtime_ns) == (
            entry["device"], entry["inode"], entry["modified_nanoseconds"],
        )
        assert saved.st_mtime_ns == entry["backup_modified_nanoseconds"]
        if entry["kind"] == "regular":
            assert stat.S_ISREG(before.st_mode) and stat.S_ISREG(saved.st_mode)
            assert original.samefile(backup)
            assert hashlib.sha256(backup.read_bytes()).hexdigest() == entry["content_sha256"]
        else:
            assert stat.S_ISLNK(before.st_mode) and stat.S_ISLNK(saved.st_mode)
            assert before.st_ino != saved.st_ino
            assert os.readlink(original) == os.readlink(backup) == entry["link_target"]


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
    for kind in EVIDENCE_SCHEMAS.keys() - {
        "script_outcome", "execution_request", "diversion_cache", "unpack_diversion_cache",
    }:
        if len(documents.get(kind, [])) != 1:
            raise AssertionError(f"missing or duplicated retained {kind}")
    managed = documents["managed_state"][0]
    snapshot = managed["transient"] or managed["stable"]
    managed_entries = {entry["path"]: entry for entry in snapshot["entries"]} if snapshot else {}
    cache_entry = managed_entries.get("var/lib/debz/native-diversion-cache-v1.json")
    caches = documents.get("diversion_cache", [])
    if cache_entry is None:
        if caches:
            raise AssertionError("retained diversion cache has no managed binding")
    else:
        if len(caches) != 1:
            raise AssertionError("managed diversion cache has no unique retained evidence")
        cache_file = next(entry for entry in proof["evidence_files"] if entry["kind"] == "diversion_cache")
        if cache_entry["kind"] != "regular" or cache_entry["content_sha256"] != cache_file["sha256"]:
            raise AssertionError("retained diversion cache differs from its managed checkpoint")
        cached = caches[0]
        assert_cached_diversion_contents(cached)
        live = managed_entries["var/lib/dpkg/diversions"]
        if cached["loaded"] is None:
            if live["kind"] != "absent":
                raise AssertionError("absent diversion cache has inconsistent evidence")
        else:
            observed = cached["observed"]
            if live["kind"] != "regular" or any(live[key] != observed[key] for key in ("device", "inode")):
                raise AssertionError("diversion cache does not bind the managed live file")
            if live["content_sha256"] != bytes(observed["sha256"]).hex():
                raise AssertionError("observed diversion bytes differ from the managed checkpoint")
    unpack_steps = {
        step["sequence"] for step in documents["program"][0]["steps"]
        if "unpack_package" in step["operation"]
    }
    unpack_entries = {}
    unpack_prefix = "var/lib/debz/native-unpack-diversion-v1-"
    actions = {
        tuple(record["action"][key] for key in ("kind", "program_step", "substep", "ordinal"))
        for record in documents["progress"][0]["records"]
    }
    for path, entry in managed_entries.items():
        if not path.startswith(unpack_prefix):
            continue
        step = int(path.removeprefix(unpack_prefix).removesuffix(".json"))
        if path != f"{unpack_prefix}{step}.json" or step not in unpack_steps:
            raise AssertionError("unpack cache does not bind an original unpack step")
        if entry["kind"] not in ("absent", "regular"):
            raise AssertionError("invalid managed unpack cache kind")
        if entry["kind"] == "absent" and ("filesystem", step, 0, 0) in actions:
            raise AssertionError("executed unpack step has no frozen cache")
        unpack_entries[step] = entry
    seen_unpack = set()
    unpack_files = [entry for entry in proof["evidence_files"] if entry["kind"] == "unpack_diversion_cache"]
    for envelope, evidence in zip(documents.get("unpack_diversion_cache", []), unpack_files, strict=True):
        step = envelope["program_step"]
        if step in seen_unpack or step not in unpack_entries:
            raise AssertionError("unpack cache has a duplicate or absent managed binding")
        seen_unpack.add(step)
        if evidence["action"] != {"kind": "filesystem", "program_step": step, "substep": 0, "ordinal": 0}:
            raise AssertionError("unpack cache has a different action binding")
        entry = unpack_entries[step]
        if entry["kind"] != "regular" or entry["content_sha256"] != evidence["sha256"] or entry["size"] != evidence["size"]:
            raise AssertionError("unpack cache differs from its managed checkpoint")
        cached = json.loads(envelope["cache_json"])
        validator("native-diversion-cache-v1").validate(cached)
        assert_digest(cached, "native-diversion-cache-v1")
        assert_cached_diversion_contents(cached)
        if canonical(cached).decode() != envelope["cache_json"] or cached["intent_sha256"] != proof["execution_intent_sha256"]:
            raise AssertionError("unpack cache has noncanonical or foreign cached inputs")
        assert_unpack_backup_contents(envelope)
    if seen_unpack != {step for step, entry in unpack_entries.items() if entry["kind"] == "regular"}:
        raise AssertionError("managed unpack cache has no retained evidence")
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


def assert_script_output(script: dict, script_sources: dict | None = None) -> None:
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
    supplied = (script_sources or {}).get((script["package"], script["package_version"]))
    if supplied is not None:
        source = supplied
    elif script["package"] in ("debz-recovery-a", "debz-recovery-b", triggers.SOURCE):
        source = triggers.script_set(
            script["package"], script["package_version"],
            activate=("debz-b",) if script["package"] == "debz-recovery-a" else (),
        )
    elif script["package"] == lifecycle.METADATA_PACKAGE:
        source = lifecycle.metadata_scripts(script["package"], script["package_version"])
    elif script["package"] == lifecycle.CONFFILE_PACKAGE:
        source = lifecycle.conffile_scripts(script["package"], script["package_version"])
    elif script["package"] == lifecycle.STATO_PACKAGE:
        source = lifecycle.statoverride_scripts(script["package"], script["package_version"])
    elif script["package"] == lifecycle.DIVERSION_PACKAGE:
        source = lifecycle.diversion_scripts(script["package"], script["package_version"])
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
        files[name] = {
            "bytes": raw,
            "kind": "regular",
            "mode": stat.S_IMODE(metadata.st_mode),
        }
        if name.startswith("info/") and name.endswith(".config"):
            files[name]["uid"] = metadata.st_uid
            files[name]["gid"] = metadata.st_gid
    if "status" not in files:
        raise AssertionError("final database has no status document")

    def text_file(name: str) -> dict | None:
        entry = files.get(name)
        return {**entry, "bytes": entry["bytes"].decode()} if entry is not None else None

    closure = {
        "status": text_file("status"), "arch": text_file("arch"),
        "triggers_file": text_file("triggers/File"),
        "triggers_unincorp": text_file("triggers/Unincorp"),
        "triggers_named": [
            {"name": name.removeprefix("triggers/"), **text_file(name)}
            for name, entry in files.items()
            if name.startswith("triggers/") and name not in ("triggers/File", "triggers/Unincorp")
        ],
    }
    if digest("debz-native-package-database-closure-v1\0", closure) != proof["final_state_sha256"]:
        raise AssertionError("provenance final-state digest differs from the actual database closure")
    generation = hashlib.sha256(b"debz.package-database.generation.v1\n")
    for name, entry in files.items():
        raw = entry["bytes"]
        generation.update(f"{name}\0regular\0{entry['mode']:o}\0{len(raw)}\0".encode())
        if name.startswith("info/") and name.endswith(".config"):
            generation.update(f"owner={entry['uid']}:{entry['gid']}\0".encode())
        generation.update(f"{hashlib.sha256(raw).hexdigest()}\n".encode())
    if generation.hexdigest() != proof["final_database_generation_sha256"]:
        raise AssertionError("provenance generation differs from the actual complete database")


def assert_script_trace(root: Path, proof: dict, scripts: list[dict]) -> None:
    if not scripts:
        return
    lines = m.oracle._read_bounded(root / lifecycle.TRACE, 16 * 1024 * 1024).decode().splitlines()
    if any(script["package"] == lifecycle.METADATA_PACKAGE for script in scripts):
        lines = [line for line in lines if not line.startswith(f"metadata:{lifecycle.METADATA_PACKAGE}@")]
    if any(script["package"] == lifecycle.CONFFILE_PACKAGE for script in scripts):
        lines = [line for line in lines if not line.startswith(f"conffiles:{lifecycle.CONFFILE_PACKAGE}@")]
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


def provenance(root: Path, report: dict, binding: dict, *, script_sources: dict | None = None) -> tuple[Path, bytes]:
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
        assert_script_output(script, script_sources)
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


def compare(
    expected: Path, candidate: Path, *, rollback_times: dict[str, int] | None = None,
    started: int = 0, ended: int = 0,
) -> None:
    snapshots = [triggers.snapshot(expected), triggers.snapshot(candidate)]
    if rollback_times:
        for snapshot in snapshots:
            lifecycle.normalize_rollback_times(snapshot, rollback_times, started, ended, require_clock=True)
    mismatches = m.oracle.differences(*snapshots, maximum=30)
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
        policy: str | None = None,
        packages: tuple[str, ...] = (),
    ) -> dict:
        destination = self.directory / "crash"
        destination.mkdir()
        if compare_reference:
            code = triggers.reference(
                self.expected, operation, archives, list(packages), self.environment,
                destination, defer=defer or not trigger_execution, policy=policy,
            )
            if bool(code) != failure:
                raise AssertionError(f"unexpected reference result {code}: {self.directory}")
        native(
            self.executable, self.candidate, self.architecture,
            operation, archives, self.environment, destination,
            packages=packages,
            trigger_execution=trigger_execution, defer=defer, crash_at=boundary,
            caller_owned=caller_owned,
            isolated_helper=isolated_helper,
            core_product=core_product,
            policy=policy,
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
                isolated_helper: bool = False, core_product: bool = False,
                deadline_after_ms: int | None = None) -> dict:
        destination = self.directory / label
        destination.mkdir()
        report = native(
            self.executable, self.candidate, self.architecture, "recover", [],
            self.environment, destination, trigger_execution=trigger_execution,
            caller_owned=caller_owned, acknowledge_native=acknowledge_native,
            isolated_helper=isolated_helper,
            core_product=core_product,
            deadline_after_ms=deadline_after_ms,
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


def exercise_deadlines(executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str) -> None:
    deadline_seconds = 30
    current = Scenario(workspace, "deadline-before-execution", executable, helper, architecture, environment)
    archive = m.make_package(
        workspace / "packages/deadline-before", environment, architecture, "1",
        scripts=lifecycle.scripts(m.PACKAGE, "1"),
    )
    (current.candidate / triggers.HELPER).unlink()
    destination = current.directory / "execute"
    destination.mkdir()
    before = triggers.snapshot(current.candidate)
    report = native(
        executable, current.candidate, architecture, "install", [archive], environment, destination,
        caller_owned=True, isolated_helper=True, deadline_after_ms=0,
    )
    if report is None or report["outcome"] != "refused" or report["detail"] != "deadline_exceeded":
        raise AssertionError(f"expired execution was not refused before helper deployment: {report}")
    if document(current.candidate / OPERATION)["mutation_started"]:
        raise AssertionError("expired execution crossed the mutation boundary")
    for path in (INTENT, NAMESPACE / "native-helper-cache-v1"):
        if (current.candidate / path).exists():
            raise AssertionError(f"expired execution published native evidence: {path}")
    if m.oracle.differences(before, triggers.snapshot(current.candidate)):
        raise AssertionError("expired execution changed package state")

    current = Scenario(workspace, "deadline-script-cumulative", executable, helper, architecture, environment)
    lifecycle.runtime.copy_program(current.candidate, Path("/bin/sleep"), "/bin/sleep")
    helper_target = current.candidate / triggers.HELPER
    shutil.copy2("/usr/bin/dpkg-trigger", helper_target)
    helper_bytes, helper_inode = helper_target.read_bytes(), helper_target.stat().st_ino
    scripts = lifecycle.scripts(m.PACKAGE, "1")
    # Leave setup headroom on loaded runners. Each script fits the budget
    # alone, but their combined sleep must exceed the one shared deadline.
    for kind, seconds in (("preinst", 8), ("postinst", 25)):
        scripts[kind] = scripts[kind].removesuffix(b"exit 0\n") + f"""
printf '%s\\n' '{kind}-begin' >> /deadline-markers
/bin/sleep {seconds}
printf '%s\\n' '{kind}-end' >> /deadline-markers
exit 0
""".encode()
    archive = m.make_package(
        workspace / "packages/deadline-script",
        environment,
        architecture,
        "1",
        scripts=scripts,
        prepare_payload=lambda source: m.write(
            source / "DEBIAN/config",
            lifecycle.metadata_contents("1")["config"],
            0o755,
        ),
    )
    destination = current.directory / "execute"
    destination.mkdir()
    started = time.monotonic()
    report = native(
        executable, current.candidate, architecture, "install", [archive], environment, destination,
        caller_owned=True, isolated_helper=True, deadline_after_ms=deadline_seconds * 1000,
    )
    elapsed = time.monotonic() - started
    if report is None or report["outcome"] != "recovery_required" or report["detail"] != "deadline_exceeded":
        raise AssertionError(f"cumulative script deadline did not retain recovery: {report}")
    config = current.candidate / f"var/lib/dpkg/info/{m.PACKAGE}.config"
    if config.read_bytes() != lifecycle.metadata_contents("1")["config"]:
        raise AssertionError("unknown postinst outcome did not retain published config")
    if (current.candidate / "var/lib/dpkg/tmp.ci/config").exists():
        raise AssertionError("unknown postinst outcome retained staged config after publication")
    markers = (current.candidate / "deadline-markers").read_text().splitlines()
    if markers != ["preinst-begin", "preinst-end", "postinst-begin"] or elapsed > deadline_seconds + 15:
        raise AssertionError(f"script deadline was reset, missed, or not polled: {markers}, {elapsed:.2f}s")
    binding = caller_binding(current.candidate)
    before = triggers.snapshot(current.candidate)
    recovered = current.recover(
        caller_owned=True, isolated_helper=True, deadline_after_ms=deadline_seconds * 1000, label="fresh-script-recovery",
    )
    if recovered["outcome"] != "recovery_required" or recovered["detail"] != "script_outcome_unknown":
        raise AssertionError(f"fresh recovery did not retain the cancelled script: {recovered}")
    if m.oracle.differences(before, triggers.snapshot(current.candidate)):
        raise AssertionError("fresh recovery changed the cancelled script's state")
    outcomes = [
        document(path) for path in sorted((current.candidate / NAMESPACE).glob("native-script-outcome-v1-*.json"))
    ]
    for outcome in outcomes:
        validator("native-script-outcome-v1").validate(outcome)
        assert_digest(outcome, "native-script-outcome-v1")
        assert_output_streams(outcome)
        if not outcome["spawned"] or outcome["script_sha256"] != hashlib.sha256(scripts[outcome["kind"]]).hexdigest():
            raise AssertionError("deadline evidence did not retain the actual script invocation")
    if {(script["kind"], script["disposition"], script["exit_code"]) for script in outcomes} != {
        ("preinst", "exited", 0), ("postinst", "cancelled", None),
    } or len(outcomes) != 2:
        raise AssertionError("deadline cancellation lost or fabricated a script outcome")
    intent = document(current.candidate / INTENT, 16 * 1024 * 1024)
    blobs = {blob["kind"]: blob["storage_path"] for blob in intent["blobs"]}
    request = document(namespace_path(current.candidate, blobs["request"]), 16 * 1024 * 1024)
    program = document(current.candidate / NAMESPACE / "native-transaction-program-v1.json", 16 * 1024 * 1024)
    assert_helper_invocations(request, program, outcomes)
    current.blocked(binding, caller_owned=True, isolated_helper=True)
    if (current.candidate / "deadline-markers").read_text().splitlines() != markers:
        raise AssertionError("fresh recovery replayed a deadline-cancelled script")
    if helper_target.read_bytes() != helper_bytes or helper_target.stat().st_ino != helper_inode:
        raise AssertionError("deadline handling replaced the package-owned helper target")

    current = Scenario(workspace, "deadline-persisted-recovery", executable, helper, architecture, environment)
    archive = m.make_package(
        workspace / "packages/deadline-recovery", environment, architecture, "1",
        scripts=lifecycle.scripts(m.PACKAGE, "1"),
    )
    binding = current.crash(
        "install", [archive], "after_execution_intent", caller_owned=True, isolated_helper=True,
    )
    before_record = (current.candidate / OPERATION).read_bytes()
    before = triggers.snapshot(current.candidate)
    expired = current.recover(
        caller_owned=True, isolated_helper=True, deadline_after_ms=0, label="expired-recovery",
    )
    if expired["outcome"] != "recovery_required" or expired["detail"] != "deadline_exceeded":
        raise AssertionError(f"expired persisted recovery did not refuse: {expired}")
    if (current.candidate / OPERATION).read_bytes() != before_record:
        raise AssertionError("expired pre-mutation recovery rewrote caller authority")
    if m.oracle.differences(before, triggers.snapshot(current.candidate)):
        raise AssertionError("expired recovery changed package state")
    recovered = current.recover(
        caller_owned=True, isolated_helper=True, deadline_after_ms=deadline_seconds * 1000, label="fresh-recovery",
    )
    if recovered["outcome"] != "applied":
        raise AssertionError(f"fresh bounded recovery did not resume persisted inputs: {recovered}")
    provenance(current.candidate, recovered, binding)
    print("native deadlines: startup refusal, cumulative script cancellation, and persisted recovery passed", flush=True)


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
    config_bytes = lifecycle.metadata_contents("1")["config"]
    archive = m.make_package(
        workspace / "packages/typed-runtime-unknown-script",
        environment,
        architecture,
        "1",
        scripts=lifecycle.scripts(m.PACKAGE, "1"),
        prepare_payload=lambda source: m.write(
            source / "DEBIAN/config",
            config_bytes,
            0o755,
        ),
    )
    binding = current.crash(
        "install", [archive], "after_script_return_before_outcome",
        compare_reference=False, caller_owned=True, isolated_helper=True,
    )
    staged_config = current.candidate / "var/lib/dpkg/tmp.ci/config"
    if staged_config.read_bytes() != config_bytes:
        raise AssertionError("unknown preinst outcome did not retain staged config")
    if (current.candidate / f"var/lib/dpkg/info/{m.PACKAGE}.config").exists():
        raise AssertionError("unknown preinst outcome published config before unpack")
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
            family = {
                "schema": "io.github.cataggar.debz.package-family.request.v2",
                "version": 2, "operation": "recover", "root": str(current.candidate),
                "architecture": architecture, "sources": [], "keyrings": [],
                "cache": str(current.directory / "unused-family-cache"),
                "state": str(current.directory / "unused-family-state"),
            }
            envelope = {
                "operation": "install", "mode": "recover", "selectors": [{"name": m.PACKAGE}],
                "options": {
                    "install_root": family["root"], "architecture": architecture,
                    "cache_path": family["cache"], "state_path": family["state"],
                },
            }
            refused = workflow(
                executable, envelope, current.directory / "family-unknown-recovery", environment,
                family_execution=family, capture_evidence=True,
            )
            assert refused["exit_status"] == "recovery" and not refused["succeeded"] and refused["changed"], refused
            assert refused["provenance_path"] is None and refused["diagnostic"]["recoverable"]
            assert "unknown" in refused["diagnostic"]["message"].lower()
            assert document(current.directory / "family-unknown-recovery/native-evidence.json")["native_completion"] is None
            assert document(current.candidate / OPERATION)["attempt_id"] == binding["attempt_id"]
            assert (current.candidate / INTENT).exists()
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            inspected = workflow(
                executable, envelope, current.directory / "family-unknown-inspection", environment,
                family_execution={**family, "operation": "inspect"}, capture_evidence=True,
            )
            observed = diagnostic_inspection(
                inspected, document(current.directory / "family-unknown-inspection/native-evidence.json"),
                current.candidate,
            )
            assert observed["native_active_evidence"]
            assert observed["observed_operation"]["state"] == document(current.candidate / OPERATION)["state"]
            assert document(current.candidate / OPERATION)["attempt_id"] == binding["attempt_id"]
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        print(f"{name}: native outcome and original evidence preserved", flush=True)


def workflow(
    executable: Path, request: dict, destination: Path, environment: dict,
    *, completion_crash: str | None = None, owner_evidence: Path | None = None,
    acknowledgment: str | None = None, reconciliation_owner_output: Path | None = None,
    owned_verification: dict | None = None,
    family_verification: dict | None = None,
    family_execution: dict | None = None,
    family_update_planning: bool = False,
    capture_evidence: bool = False,
) -> dict | None:
    m.reference_command(Path(request["options"]["install_root"]))
    if family_update_planning and family_execution is None:
        raise ValueError("family update planning requires a family request")
    destination.mkdir()
    request_path = destination / "workflow.request.json"
    report_path = destination / "workflow.report.json"
    m.write(request_path, json.dumps({
        "workflow": request, "report": str(report_path),
        "completion_crash": completion_crash,
        "owner_evidence": str(owner_evidence) if owner_evidence else None,
        "reconciliation_owner_output": str(reconciliation_owner_output) if reconciliation_owner_output else None,
        "acknowledgment": acknowledgment,
        "owned_verification": owned_verification,
        "family_verification": family_verification,
        "family_execution": family_execution,
        "family_update_planning": family_update_planning,
        "native_evidence_output": str(destination / "native-evidence.json") if capture_evidence else None,
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
        assert not (destination / "native-evidence.json").exists()
        return None
    return document(report_path, 64 * 1024)


def reference_helper_package(
    workspace: Path, environment: dict, architecture: str, *, package: str,
) -> Path:
    return m.make_package(
        workspace, environment, architecture, "1", package=package,
        extra_files={triggers.HELPER.as_posix(): Path("/usr/bin/dpkg-trigger").read_bytes()},
        prepare_payload=lambda source: (source / triggers.HELPER).chmod(0o755),
    )


def exercise_diversion_recovery(
    executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    package = lifecycle.DIVERSION_PACKAGE
    source = f"{lifecycle.DIVERSION_BASE}/mode"
    destination = source + ".distrib"
    records = (
        lifecycle.diversion_records(source, destination)
        + lifecycle.diversion_records(lifecycle.DIVERSION_LITERAL, lifecycle.DIVERSION_LITERAL + ".distrib")
        + lifecycle.diversion_records("etc/debz-native.conf", "etc/debz-native.conf.distrib")
    )
    for operation, boundary, mutation in (
        ("install", "after_execution_intent", None),
        ("install", "during_filesystem_publication", None),
        ("install", "after_script_outcome", None),
        ("install", "after_failure_outcome", None),
        ("upgrade", "during_database_publication", None),
        ("upgrade", "after_script_outcome", None),
        ("remove", "after_script_outcome", None),
        ("purge", "after_script_prepared", None),
        ("install", "after_script_outcome", "preinst"),
        ("install", "after_script_outcome", "created"),
        ("install", "after_script_outcome", "helper"),
        ("install", "after_script_prepared", "inplace"),
        ("install", "after_script_outcome", "inplace"),
        ("install", "after_failure_outcome", "inplace"),
        ("install", "after_script_return_before_outcome", "inplace-unknown"),
        ("upgrade", "during_filesystem_publication", "inplace"),
        ("remove", "after_script_outcome", "inplace-prerm"),
        ("purge", "after_script_prepared", "inplace-postrm"),
        ("install", "after_script_outcome", "inplace-empty"),
        ("install", "after_trigger_outcome", "atomic-then-inplace"),
        ("upgrade", "during_filesystem_publication", "mid-unpack"),
        ("upgrade", "after_script_prepared", "mid-unpack"),
        ("upgrade", "after_upgrade_postrm_route_publication", "mid-unpack"),
        ("upgrade", "after_upgrade_postrm_outcome", "mid-unpack"),
        ("upgrade", "during_filesystem_publication", "mid-cached-route"),
        ("upgrade", "after_script_prepared", "mid-cached-route"),
        ("upgrade", "after_upgrade_postrm_route_publication", "mid-cached-route"),
        ("upgrade", "after_upgrade_postrm_outcome", "mid-cached-route"),
        ("install", "after_trigger_outcome", "postinst"),
        ("install", "after_execution_intent", "database-drift"),
        ("install", "after_trigger_outcome", "destination-drift"),
        ("purge", "after_script_prepared", "conffile-drift"),
        ("install", "after_execution_intent", "cache-file-drift"),
        ("install", "after_execution_intent", "cache-mode-drift"),
        ("install", "after_execution_intent", "cache-missing-drift"),
        ("install", "after_trigger_outcome", "unpack-cache-file-drift"),
        ("install", "after_trigger_outcome", "unpack-cache-mode-drift"),
        ("install", "after_trigger_outcome", "unpack-cache-missing-drift"),
        ("install", "after_provenance", "unpack-retained-file-drift"),
        ("install", "after_provenance", "unpack-retained-missing-drift"),
        ("upgrade", "after_unpack_backups", "backup-probe"),
        ("upgrade", "before_unpack_backup_cleanup", "backup-probe"),
        ("upgrade", "after_unpack_backup_cleanup", "backup-probe"),
        ("upgrade", "after_upgrade_postrm_return_before_outcome", "backup-unknown"),
        ("upgrade", "after_unpack_backups", "backup-file-drift"),
        ("upgrade", "after_unpack_backups", "backup-mode-drift"),
        ("upgrade", "after_unpack_backups", "backup-missing-drift"),
        ("upgrade", "after_unpack_backups", "backup-source-drift"),
        ("upgrade", "before_unpack_backup_cleanup", "backup-failure"),
        ("upgrade", "after_unpack_backup_cleanup", "backup-failure"),
        ("upgrade", "before_failed_unpack_publication", "backup-failure"),
        ("upgrade", "after_failed_unpack_publication", "backup-failure"),
        ("upgrade", "during_unpack_backup_publication", "backup-probe"),
        ("upgrade", "during_unpack_backup_cleanup", "backup-probe"),
        ("upgrade", "during_failed_unpack_publication", "backup-failure"),
        ("upgrade", "during_unpack_backup_cleanup", "backup-failure"),
        ("upgrade", "after_failure_outcome", "backup-failure"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-probe"),
        ("upgrade", "after_upgrade_unwind_outcome", "backup-unwind"),
        ("upgrade", "after_upgrade_unwind_outcome", "backup-failure"),
        ("upgrade", "after_upgrade_pre_rollback_compensation_outcome", "backup-failure"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-probe-atomic"),
        ("upgrade", "after_failure_outcome", "backup-failure-atomic"),
        ("upgrade", "after_failure_outcome", "backup-failure-rollback-crash"),
        ("upgrade", "after_failure_outcome", "backup-failure-rollback-finished"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-postrm-payload-drift"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-postrm-backup-drift"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-postrm-cache-drift"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-postrm-route-drift"),
        ("upgrade", "after_upgrade_postrm_outcome", "backup-postrm-route-missing-drift"),
        ("upgrade", "after_upgrade_postrm_marker_cleared", "backup-probe"),
        ("upgrade", "after_upgrade_postrm_marker_cleared", "backup-failure"),
        ("upgrade", "after_upgrade_postrm_completed", "backup-probe-atomic"),
        ("upgrade", "after_upgrade_postrm_completed", "backup-failure"),
        ("upgrade", "after_upgrade_unwind_completed", "backup-unwind"),
        ("upgrade", "after_upgrade_unwind_completed", "backup-failure"),
        ("upgrade", "after_upgrade_pre_rollback_compensation_completed", "backup-failure"),
        ("upgrade", "during_unpack_obsolete_removal", "backup-probe"),
        ("upgrade", "during_unpack_obsolete_removal", "backup-probe-atomic"),
        ("upgrade", "during_unpack_obsolete_removal", "backup-unwind"),
        ("upgrade", "during_unpack_obsolete_removal", "backup-probe-rollback-crash"),
        ("upgrade", "during_unpack_obsolete_removal", "backup-probe-rollback-finished"),
        ("upgrade", "during_unpack_obsolete_removal", "backup-postrm-directory-drift"),
        ("upgrade", "after_unpack_payload", "backup-probe"),
        ("upgrade", "after_unpack_payload", "backup-probe-atomic"),
        ("upgrade", "after_unpack_payload", "backup-unwind"),
        ("upgrade", "after_unpack_payload_commit", "backup-probe"),
        ("upgrade", "during_unpack_settlement", "backup-probe"),
        ("upgrade", "during_unpack_settlement", "backup-probe-atomic"),
        ("upgrade", "during_unpack_settlement", "backup-unwind"),
        ("upgrade", "during_unpack_settlement", "backup-probe-rollback-crash"),
        ("upgrade", "during_unpack_settlement", "backup-probe-rollback-finished"),
        ("upgrade", "after_unpack_settlement", "backup-probe"),
        ("upgrade", "after_unpack_settlement", "backup-unwind"),
        ("upgrade", "after_unpack_settlement_commit", "backup-probe"),
        ("upgrade", "after_unpack_settlement_rollback", "backup-probe"),
        ("upgrade", "after_unpack_settlement_rollback", "backup-unwind"),
        ("upgrade", "after_unpack_payload", "backup-postrm-payload-drift"),
        ("upgrade", "after_unpack_payload", "backup-settlement-input-drift"),
        ("upgrade", "during_unpack_settlement", "backup-postrm-directory-drift"),
    ):
        name = f"diversion-{operation}-{boundary}" + (f"-{mutation}" if mutation else "")
        backup_failure = bool(mutation and mutation.startswith("backup-failure"))
        current = Scenario(workspace, name, executable, helper, architecture, environment)
        if mutation and mutation.startswith("backup-"):
            archives = {
                version: m.make_package(
                    current.directory / "backup-packages", environment, architecture, version, "conffile",
                    package=package, scripts=lifecycle.backup_probe_scripts(version, mode_suffix=".distrib"),
                    conffile_content=f"configuration {version}\n".encode(),
                    extra_files={
                        lifecycle.DIVERSION_LITERAL: f"literal version {version}\n".encode(),
                        **({f"{lifecycle.DIVERSION_BASE}/tracked/child": b"tracked directory\n"}
                           if version == "2" and mutation == "backup-postrm-directory-drift" else {}),
                    },
                )
                for version in ("1", "2")
            }
            for root in current.roots:
                lifecycle.install_backup_probe(root)
        else:
            archives = lifecycle.make_diversion_packages(current.directory / "packages", environment, architecture)
        for root in current.roots:
            if mutation != "created":
                lifecycle.seed_diversions(root, records)
        interests = (f"/{lifecycle.DIVERSION_BASE}",)
        if mutation in ("postinst", "atomic-then-inplace"):
            interests = (f"/{destination}", f"/{source}.changed", f"/{source}.atomic")
        receiver = m.make_package(
            current.directory / "receiver", environment, architecture, "1", package="diversion-receiver",
            triggers="".join(f"interest-noawait {path}\n" for path in interests).encode(),
            scripts=lifecycle.scripts("diversion-receiver", "1"),
        )
        target = reference_helper_package(
            current.directory / "helper", environment, architecture, package="diversion-helper-target",
        )
        current.seed(receiver, target, *([archives["1"]] if operation != "install" else []))
        if mutation in ("backup-probe-atomic", "backup-failure-atomic"):
            for root in current.roots:
                lifecycle.seed_diversion_replacement(root, "postrm", records)
        if mutation in ("preinst", "created", "postinst"):
            for root in current.roots:
                lifecycle.seed_diversion_replacement(
                    root, "postinst" if mutation == "postinst" else "preinst",
                    records.replace(destination.encode(), (source + ".changed").encode()),
                )
        if mutation == "helper":
            for root in current.roots:
                lifecycle.seed_diversion_helper(root, source, source + ".changed")
        if mutation in ("inplace", "inplace-prerm", "inplace-empty", "inplace-unknown"):
            for root in current.roots:
                lifecycle.seed_diversion_inplace(
                    root, "prerm" if mutation == "inplace-prerm" else "preinst",
                    b"" if mutation == "inplace-empty" else records.replace(b".distrib", b".changed"),
                )
        if mutation == "atomic-then-inplace":
            for root in current.roots:
                lifecycle.seed_diversion_replacement(root, "preinst", records.replace(b".distrib", b".atomic"))
                lifecycle.seed_diversion_inplace(root, "postinst", records.replace(b".distrib", b".changed"))
        if mutation == "mid-unpack":
            for root in current.roots:
                lifecycle.seed_diversion_replacement(
                    root, "postrm", records.replace(destination.encode(), (source + ".changed").encode()),
                )
        if mutation == "mid-cached-route":
            for root in current.roots:
                changed = records.replace(destination.encode(), (source + ".changed").encode())
                lifecycle.seed_diversion_inplace(root, "preinst", changed)
                lifecycle.seed_diversion_replacement(root, "postrm", changed)
        if operation == "purge":
            current.phase("remove", packages=[package])
        if mutation == "inplace-postrm":
            for root in current.roots:
                lifecycle.seed_diversion_inplace(root, "postrm", records.replace(b".distrib", b".changed"))
        failure = boundary == "after_failure_outcome" or backup_failure
        if failure or mutation == "backup-unwind":
            for root in current.roots:
                failures = (
                    f"{package}@1:postrm:upgrade\n{package}@2:postrm:failed-upgrade\n"
                    if backup_failure else f"{package}@1:postinst:configure\n"
                )
                if mutation == "backup-unwind":
                    failures = f"{package}@1:postrm:upgrade\n"
                m.write(root / lifecycle.FAILURE, failures.encode())
                os.utime(root / lifecycle.FAILURE, (m.EPOCH, m.EPOCH))
        helper_path = current.candidate / triggers.HELPER
        shutil.copy2("/usr/bin/dpkg-trigger", helper_path)
        helper_before, helper_inode = helper_path.read_bytes(), helper_path.stat().st_ino
        version = "2" if operation == "upgrade" else "1"
        rollback_times = {
            f"{lifecycle.DIVERSION_BASE}/current":
                (current.expected / lifecycle.DIVERSION_BASE / "current").lstat().st_mtime_ns,
        } if backup_failure else {}
        control_path = current.candidate / "var/lib/dpkg/info" / f"{package}.postrm"
        original_control = control_path.read_bytes() if operation == "upgrade" else None
        started = time.time_ns()
        binding = current.crash(
            operation, [archives[version]] if operation in ("install", "upgrade") else [], boundary,
            failure=failure, trigger_execution=True, caller_owned=True,
            isolated_helper=True, core_product=True, policy="keep_existing", packages=(package,),
        )
        committed_payload = None
        if boundary in (
            "after_unpack_payload", "during_unpack_settlement", "after_unpack_settlement",
            "after_unpack_payload_commit", "after_unpack_settlement_commit", "after_unpack_settlement_rollback",
        ):
            payload = current.candidate / lifecycle.DIVERSION_BASE / "data"
            staged = current.candidate / "etc/debz-native.conf.distrib.dpkg-new"
            committed_payload = {
                path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (payload, staged)
            }
        if boundary in (
            "after_unpack_backups", "after_unpack_payload", "after_unpack_payload_commit",
            "after_unpack_settlement_rollback",
        ):
            caches = list((current.candidate / NAMESPACE).glob("native-unpack-diversion-v1-*.json"))
            assert len(caches) == 1
            envelope = document(caches[0], 128 * 1024 * 1024)
            assert "settlement" in envelope
            assert_unpack_backup_contents(envelope)
            if boundary == "after_unpack_backups":
                assert_visible_unpack_backups(current.candidate, envelope)
            else:
                assert control_path.read_bytes() == original_control
                status = (current.candidate / "var/lib/dpkg/status").read_bytes()
                assert hashlib.sha256(status).hexdigest() == envelope["settlement"]["base_status_sha256"]
                assert (current.candidate / lifecycle.DIVERSION_BASE / "obsolete").read_bytes() == b"only in 1\n"
        for archive in archives.values():
            if archive.exists():
                archive.unlink()
            assert not archive.exists()
        if mutation in (
            "backup-failure-rollback-crash", "backup-failure-rollback-finished",
            "backup-probe-rollback-crash", "backup-probe-rollback-finished",
        ):
            destination_directory = current.directory / "interrupted-recovery"
            destination_directory.mkdir()
            native(
                executable, current.candidate, architecture, "recover", [], environment, destination_directory,
                trigger_execution=True, caller_owned=True, isolated_helper=True,
                recovery_crash="during_known_unpack_rollback" if mutation.endswith("-crash") else "after_known_unpack_rollback",
            )
        if mutation == "database-drift":
            lifecycle.seed_diversions(current.candidate, records.replace(b".distrib", b".changed"))
        elif mutation == "destination-drift":
            m.write(current.candidate / destination, b"external destination drift\n")
        elif mutation == "conffile-drift":
            m.write(current.candidate / "etc/debz-native.conf.distrib", b"external conffile drift\n")
        elif mutation == "cache-file-drift":
            m.write(current.candidate / NAMESPACE / "native-diversion-cache-v1.json", b"external cache drift\n")
        elif mutation == "cache-mode-drift":
            (current.candidate / NAMESPACE / "native-diversion-cache-v1.json").chmod(0o644)
        elif mutation == "cache-missing-drift":
            (current.candidate / NAMESPACE / "native-diversion-cache-v1.json").unlink()
        elif mutation and mutation.startswith("backup-") and mutation.endswith("-drift"):
            path = current.candidate / lifecycle.DIVERSION_BASE / "data.dpkg-tmp"
            if mutation == "backup-file-drift":
                m.write(path, b"external backup bytes\n")
            elif mutation == "backup-mode-drift":
                path.chmod(0o600)
            elif mutation == "backup-missing-drift":
                path.unlink()
            elif mutation == "backup-source-drift":
                m.write(path.with_name("data"), b"external original source bytes\n")
            elif mutation == "backup-postrm-payload-drift":
                m.write(path.with_name("data"), b"external published payload\n")
            elif mutation == "backup-postrm-backup-drift":
                m.write(path, b"external old backup\n")
            elif mutation == "backup-postrm-cache-drift":
                m.write(current.candidate / NAMESPACE / "native-diversion-cache-v1.json", b"external cached inputs\n")
            elif mutation == "backup-postrm-route-drift":
                routes = list((current.candidate / NAMESPACE).glob("native-unpack-route-settlement-v1-*.json"))
                assert len(routes) == 1
                m.write(routes[0], b"external route evidence\n")
            elif mutation == "backup-postrm-route-missing-drift":
                routes = list((current.candidate / NAMESPACE).glob("native-unpack-route-settlement-v1-*.json"))
                assert len(routes) == 1
                routes[0].unlink()
            elif mutation == "backup-postrm-directory-drift":
                m.write(current.candidate / lifecycle.DIVERSION_BASE / "tracked/unrecorded", b"external directory member\n")
            elif mutation == "backup-settlement-input-drift":
                caches = list((current.candidate / NAMESPACE).glob("native-unpack-diversion-v1-*.json"))
                assert len(caches) == 1
                m.write(caches[0], b"external late settlement recipe\n")
            else:
                raise AssertionError(f"unknown backup mutation: {mutation}")
        elif mutation and mutation.startswith("unpack-cache-"):
            caches = list((current.candidate / NAMESPACE).glob("native-unpack-diversion-v1-*.json"))
            assert len(caches) == 1, caches
            if mutation == "unpack-cache-file-drift":
                m.write(caches[0], b"external unpack cache drift\n")
            elif mutation == "unpack-cache-mode-drift":
                caches[0].chmod(0o644)
            elif mutation == "unpack-cache-missing-drift":
                caches[0].unlink()
            else:
                raise AssertionError(f"unknown unpack cache mutation: {mutation}")
        elif mutation and mutation.startswith("unpack-retained-"):
            proof = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
            files = [entry for entry in proof["evidence_files"] if entry["kind"] == "unpack_diversion_cache"]
            assert len(files) == 1, files
            path = namespace_path(current.candidate, files[0]["path"])
            if mutation == "unpack-retained-file-drift":
                m.write(path, b"external retained unpack cache drift\n")
            elif mutation == "unpack-retained-missing-drift":
                path.unlink()
            else:
                raise AssertionError(f"unknown retained unpack cache mutation: {mutation}")
        before = triggers.snapshot(current.candidate)
        report = current.recover(trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True)
        assert helper_path.read_bytes() == helper_before and helper_path.stat().st_ino == helper_inode
        if mutation in ("inplace-unknown", "backup-unknown"):
            assert report["outcome"] == "recovery_required", report
            if mutation == "inplace-unknown":
                assert not (current.candidate / destination).exists()
            assert not (current.candidate / (source + ".changed")).exists()
            blocked = triggers.snapshot(current.candidate)
            repeated = current.recover(
                trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True,
                label=f"recover-blocked-{mutation}",
            )
            assert repeated["outcome"] in ("recovery_required", "refused"), repeated
            assert not m.oracle.differences(blocked, triggers.snapshot(current.candidate))
            print(f"{name}: unsupported updates and repeated recovery stay blocked", flush=True)
            continue
        if mutation and mutation.endswith("-drift"):
            assert report["outcome"] in ("recovery_required", "refused"), report
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            print(f"{name}: diversion database and destination drift blocks mutation", flush=True)
            continue
        assert report["outcome"] == ("script_failed" if failure else "applied"), report
        if committed_payload is not None:
            payload = current.candidate / lifecycle.DIVERSION_BASE / "data"
            assert (payload.read_bytes(), payload.stat().st_ino, payload.stat().st_mtime_ns) == committed_payload[payload]
            staged = current.candidate / "etc/debz-native.conf.distrib.dpkg-new"
            installed = staged.with_name("debz-native.conf.distrib")
            assert (installed.read_bytes(), installed.stat().st_mtime_ns) == (
                committed_payload[staged][0], committed_payload[staged][2],
            )
        compare(
            current.expected, current.candidate, rollback_times=rollback_times,
            started=started, ended=time.time_ns(),
        )
        proof_path, proof_bytes = provenance(
            current.candidate, report, binding,
            script_sources={
                (package, version): lifecycle.backup_probe_scripts(version, mode_suffix=".distrib")
                for version in ("1", "2")
            } if mutation and mutation.startswith("backup-") else None,
        )
        if backup_failure:
            proof = json.loads(proof_bytes)
            evidence = [entry for entry in proof["evidence_files"] if entry["kind"] == "unpack_diversion_cache"]
            assert len(evidence) == 1
            envelope = document(namespace_path(current.candidate, evidence[0]["path"]), 128 * 1024 * 1024)
            restored_link = f"{lifecycle.DIVERSION_BASE}/current"
            original = next(entry for entry in envelope["backups"] if entry["path"] == restored_link)
            assert (current.candidate / restored_link).lstat().st_mtime_ns == original["backup_modified_nanoseconds"]
        completion_path = current.candidate / NAMESPACE / "root-operation-completion-v1.json"
        completion_bytes = completion_path.read_bytes()
        assert document(completion_path)["outcome"] == ("failed_after_mutation" if failure else "succeeded")
        assert not (current.candidate / OPERATION).exists() and not (current.candidate / INTENT).exists()
        before = triggers.snapshot(current.candidate)
        repeated = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True, label="recover-again",
        )
        assert repeated["outcome"] == "applied", repeated
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        assert proof_path.read_bytes() == proof_bytes and completion_path.read_bytes() == completion_bytes
        print(f"{name}: diversion lifecycle and archive-evicted core recovery passed", flush=True)


def exercise_statoverride_recovery(
    executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    for operation, boundary, drift in (
        ("install", "after_execution_intent", None),
        ("install", "during_filesystem_publication", None),
        ("install", "after_script_outcome", None),
        ("install", "after_failure_outcome", None),
        ("upgrade", "during_filesystem_publication", None),
        ("upgrade", "after_script_outcome", None),
        ("remove", "after_script_outcome", None),
        ("purge", "after_script_prepared", None),
        ("install-account", "after_script_outcome", None),
        ("install-override", "after_script_outcome", None),
        ("install-created", "after_script_outcome", None),
        ("install", "after_execution_intent", "passwd-blob"),
        ("install", "after_execution_intent", "group-blob-missing"),
        ("install", "after_execution_intent", "passwd"),
        ("install", "during_filesystem_publication", "group"),
        ("install", "after_script_prepared", "statoverride"),
        ("upgrade", "after_trigger_outcome", "owner"),
    ):
        name = f"statoverride-{operation}-{boundary}" + (f"-{drift}-drift" if drift else "")
        changed_by_script = operation.removeprefix("install-") if operation.startswith("install-") else None
        if changed_by_script is not None:
            operation = "install"
        current = Scenario(workspace, name, executable, helper, architecture, environment)
        archives = lifecycle.make_statoverride_packages(current.directory / "packages", environment, architecture)
        records = (
            f"_debzstat _debzstat 4750 /{lifecycle.STATO_BASE}/mode\n"
            f"#42420 #42421 0640 /{lifecycle.STATO_LITERAL.as_posix()}\n"
            "_debzstat _debzstat 0640 /etc/debz-native.conf\n"
        )
        for root in current.roots:
            lifecycle.seed_statoverrides(root, "" if changed_by_script == "created" else records)
        receiver_name = "statoverride-receiver"
        receiver = m.make_package(
            current.directory / "receiver", environment, architecture, "1", package=receiver_name,
            triggers=f"interest-noawait /{lifecycle.STATO_BASE}\n".encode(),
            scripts=lifecycle.scripts(receiver_name, "1"),
        )
        target = reference_helper_package(
            current.directory / "helper", environment, architecture, package="statoverride-helper-target",
        )
        current.seed(receiver, target, *([archives["1"]] if operation != "install" else []))
        if changed_by_script is not None:
            for root in current.roots:
                lifecycle.seed_statoverride_replacement(
                    root,
                    "statoverride-passwd-replace" if changed_by_script == "account" else "statoverride-preinst-replace",
                    lifecycle.STATO_PASSWD.replace(b":42420:", b":42422:")
                    if changed_by_script == "account" else records.replace("4750", "0750").encode(),
                )
        if operation == "purge":
            current.phase("remove", packages=[lifecycle.STATO_PACKAGE])
        failure = boundary == "after_failure_outcome"
        if failure:
            for root in current.roots:
                m.write(root / lifecycle.FAILURE, f"{lifecycle.STATO_PACKAGE}@1:postinst:configure\n".encode())
                os.utime(root / lifecycle.FAILURE, (m.EPOCH, m.EPOCH))
        helper_path = current.candidate / triggers.HELPER
        shutil.copy2("/usr/bin/dpkg-trigger", helper_path)
        helper_before, helper_inode = helper_path.read_bytes(), helper_path.stat().st_ino
        version = "2" if operation == "upgrade" else "1"
        binding = current.crash(
            operation, [archives[version]] if operation in ("install", "upgrade") else [], boundary,
            failure=failure, trigger_execution=True, caller_owned=True,
            isolated_helper=True, core_product=True, policy="keep_existing",
            packages=(lifecycle.STATO_PACKAGE,),
        )
        intent = document(current.candidate / INTENT, 16 * 1024 * 1024)
        identity_blobs = {blob["key"]: blob for blob in intent["blobs"] if blob["key"].startswith("statoverride-")}
        assert set(identity_blobs) == (set() if changed_by_script == "created" else {"statoverride-passwd", "statoverride-group"})
        for key, original in (("statoverride-passwd", lifecycle.STATO_PASSWD), ("statoverride-group", lifecycle.STATO_GROUP)):
            if key in identity_blobs:
                blob = identity_blobs[key]
                assert blob["kind"] == "database" and blob["entry_kind"] == "regular"
                assert blob["logical_path"] == ("etc/passwd" if key.endswith("passwd") else "etc/group")
                assert (current.candidate / blob["storage_path"]).read_bytes() == original
        for archive in archives.values():
            if archive.exists():
                archive.unlink()
            assert not archive.exists()
        if drift == "passwd":
            m.write(current.candidate / "etc/passwd", lifecycle.STATO_PASSWD.replace(b":42420:", b":42422:"))
        elif drift == "group":
            m.write(current.candidate / "etc/group", lifecycle.STATO_GROUP.replace(b":42421:", b":42423:"))
        elif drift == "statoverride":
            m.write(current.candidate / "var/lib/dpkg/statoverride", records.replace("4750", "0750").encode())
        elif drift == "owner":
            os.chown(current.candidate / lifecycle.STATO_BASE / "mode", 42422, 42423)
        elif drift == "passwd-blob":
            m.write(current.candidate / identity_blobs["statoverride-passwd"]["storage_path"], lifecycle.STATO_PASSWD.replace(b":42420:", b":42422:"))
        elif drift == "group-blob-missing":
            (current.candidate / identity_blobs["statoverride-group"]["storage_path"]).unlink()
        before = triggers.snapshot(current.candidate)
        report = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True,
        )
        assert helper_path.read_bytes() == helper_before and helper_path.stat().st_ino == helper_inode
        if drift is not None:
            assert report["outcome"] in ("recovery_required", "refused"), report
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            print(f"{name}: statoverride identity and metadata drift blocks mutation", flush=True)
            continue
        assert report["outcome"] == ("script_failed" if failure else "applied"), report
        compare(current.expected, current.candidate)
        proof_path, proof_bytes = provenance(current.candidate, report, binding)
        completion_path = current.candidate / NAMESPACE / "root-operation-completion-v1.json"
        completion_bytes = completion_path.read_bytes()
        assert document(completion_path)["outcome"] == ("failed_after_mutation" if failure else "succeeded")
        assert not (current.candidate / OPERATION).exists() and not (current.candidate / INTENT).exists()
        before = triggers.snapshot(current.candidate)
        repeated = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True, label="recover-again",
        )
        assert repeated["outcome"] == "applied", repeated
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        assert proof_path.read_bytes() == proof_bytes and completion_path.read_bytes() == completion_bytes
        print(f"{name}: statoverride lifecycle and archive-evicted core recovery passed", flush=True)


def exercise_conffile_lifecycle_recovery(
    executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    for operation, boundary, failure, drift in (
        ("purge", "after_execution_intent", False, False),
        ("purge", "during_database_publication", False, False),
        ("purge", "after_script_prepared", False, False),
        ("purge", "after_script_outcome", False, False),
        ("purge", "after_failure_outcome", True, False),
        ("purge", "after_trigger_outcome", True, False),
        ("purge-deferred", "after_failure_outcome", True, False),
        ("purge-helper", "after_failure_outcome", True, False),
        ("purge-helper", "after_trigger_outcome", True, False),
        ("purge-helper-deferred", "after_failure_outcome", True, False),
        ("purge", "after_script_return_before_outcome", False, False),
        ("purge", "after_script_prepared", False, True),
        ("configure", "after_script_prepared", False, False),
        ("configure", "during_database_publication", False, False),
        ("configure", "during_database_publication", False, True),
        ("configure", "after_script_outcome", False, False),
        ("configure", "after_script_prepared", False, True),
        ("configure-upgrade", "after_script_prepared", False, False),
        ("configure-upgrade", "after_script_outcome", False, False),
        ("configure-upgrade", "during_database_publication", False, False),
    ):
        name = f"conffile-{operation}-{boundary}" + ("-failure" if failure else "") + ("-drift" if drift else "")
        upgrading = operation == "configure-upgrade"
        deferred = operation.endswith("-deferred")
        activate_helper = operation.startswith("purge-helper")
        if upgrading:
            operation = "configure"
        elif operation.startswith("purge-"):
            operation = "purge"
        version = "2" if upgrading else "1"
        current = Scenario(workspace, name, executable, helper, architecture, environment)
        archives = lifecycle.make_conffile_packages(current.directory / "packages", environment, architecture)
        receiver_name = "conffile-receiver"
        receiver = m.make_package(
            current.directory / "receiver", environment, architecture, "1", package=receiver_name,
            triggers=(
                f"interest-noawait /{lifecycle.CONFFILE_PATHS[0].as_posix()}\n"
                f"interest-noawait {lifecycle.CONFFILE_TRIGGER}\n"
            ).encode(),
            scripts=lifecycle.scripts(receiver_name, "1"),
        )
        target = reference_helper_package(
            current.directory / "helper", environment, architecture, package="conffile-helper-target",
        )
        current.seed(receiver, target, *([archives["1"]] if operation == "purge" or upgrading else []))
        if operation == "purge":
            current.phase("remove", packages=[lifecycle.CONFFILE_PACKAGE])
        else:
            for root in current.roots:
                m.write(root / lifecycle.FAILURE, f"{lifecycle.CONFFILE_PACKAGE}@{version}:postinst:configure\n".encode())
                os.utime(root / lifecycle.FAILURE, (m.EPOCH, m.EPOCH))
            current.phase("upgrade" if upgrading else "install", [archives[version]], failure=True)
            for root in current.roots:
                (root / lifecycle.FAILURE).unlink()
                for path in lifecycle.CONFFILE_PATHS:
                    m.write(root / path, b"administrator configuration after failure\n")
                    os.utime(root / path, (m.EPOCH, m.EPOCH))
        if failure:
            for root in current.roots:
                m.write(root / lifecycle.FAILURE, f"{lifecycle.CONFFILE_PACKAGE}@1:postrm:purge\n".encode())
                os.utime(root / lifecycle.FAILURE, (m.EPOCH, m.EPOCH))
                if activate_helper:
                    m.write(root / "conffile-activate", b"")
                    os.utime(root / "conffile-activate", (m.EPOCH, m.EPOCH))
        helper_path = current.candidate / triggers.HELPER
        shutil.copy2("/usr/bin/dpkg-trigger", helper_path)
        helper_before, helper_inode = helper_path.read_bytes(), helper_path.stat().st_ino
        binding = current.crash(
            operation, [archives[version]] if operation == "configure" else [], boundary,
            failure=failure, trigger_execution=True, caller_owned=True,
            isolated_helper=True, core_product=True, policy="keep_existing",
            defer=deferred,
            packages=(lifecycle.CONFFILE_PACKAGE,),
        )
        if operation == "purge" and boundary == "during_database_publication":
            assert any(not (current.candidate / path).exists() for path in lifecycle.CONFFILE_PATHS)
        for archive in archives.values():
            if archive.exists():
                archive.unlink()
            assert not archive.exists()
        if drift:
            m.write(current.candidate / lifecycle.CONFFILE_PATHS[0], b"changed during interruption\n")
        before = triggers.snapshot(current.candidate)
        report = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True,
        )
        assert helper_path.read_bytes() == helper_before and helper_path.stat().st_ino == helper_inode
        unknown = boundary == "after_script_return_before_outcome"
        if drift or unknown:
            assert report["outcome"] in ("recovery_required", "refused"), report
            if unknown:
                assert report["detail"] == "native recovery_required: script_outcome_unknown", report
                provenance(current.candidate, report, binding)
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            print(f"{name}: interrupted conffile evidence blocks mutation", flush=True)
            continue
        assert report["outcome"] == ("script_failed" if failure else "applied"), report
        compare(current.expected, current.candidate)
        proof_path, proof_bytes = provenance(current.candidate, report, binding)
        proof = document(proof_path, 16 * 1024 * 1024)
        assert proof["outcome"] == ("failed" if failure else "succeeded")
        completion_path = current.candidate / NAMESPACE / "root-operation-completion-v1.json"
        completion_bytes = completion_path.read_bytes()
        completion = document(completion_path)
        assert completion["outcome"] == ("failed_after_mutation" if failure else "succeeded")
        assert completion["attempt_id"] == binding["attempt_id"]
        assert completion["transaction_provenance"]["document_sha256"] == proof["digest_sha256"]
        assert not (current.candidate / OPERATION).exists() and not (current.candidate / INTENT).exists()
        before = triggers.snapshot(current.candidate)
        repeated = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True, label="recover-again",
        )
        assert repeated["outcome"] == "applied", repeated
        assert repeated["detail"] == "no native execution requires recovery", repeated
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        assert proof_path.read_bytes() == proof_bytes
        assert completion_path.read_bytes() == completion_bytes
        print(f"{name}: conffile lifecycle, receipt and archive-evicted recovery passed", flush=True)


def exercise_metadata_recovery(
    executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    trigger_path = f"/usr/share/{lifecycle.METADATA_PACKAGE}"
    for operation, boundary, drift in (
        ("install", "during_filesystem_publication", None),
        ("upgrade", "after_trigger_outcome", None),
        ("remove", "after_script_outcome", None),
        ("purge", "after_script_outcome", None),
        ("install", "after_trigger_outcome", "bytes"),
        ("install", "after_trigger_outcome", "mode"),
        ("install", "after_trigger_outcome", "missing"),
        ("install", "after_trigger_outcome", "config-bytes"),
        ("install", "after_trigger_outcome", "config-mode"),
        ("install", "after_trigger_outcome", "config-owner"),
        ("install", "after_trigger_outcome", "config-missing"),
    ):
        name = f"metadata-{operation}-{boundary}" + (f"-{drift}-drift" if drift else "")
        current = Scenario(workspace, name, executable, helper, architecture, environment)
        packages = lifecycle.make_metadata_packages(current.directory / "packages", environment, architecture)
        receiver_name = "metadata-receiver"
        receiver = m.make_package(
            current.directory / "receiver", environment, architecture, "1", package=receiver_name,
            triggers=f"interest-noawait {trigger_path}\n".encode(),
            scripts=lifecycle.scripts(receiver_name, "1"),
        )
        target = reference_helper_package(
            current.directory / "helper", environment, architecture, package="metadata-helper-target",
        )
        current.seed(receiver, target, *([packages["1"]] if operation != "install" else []))
        if operation == "purge":
            current.phase("remove", packages=[lifecycle.METADATA_PACKAGE])
        helper_path = current.candidate / triggers.HELPER
        shutil.copy2("/usr/bin/dpkg-trigger", helper_path)
        helper_before, helper_inode = helper_path.read_bytes(), helper_path.stat().st_ino
        incoming = [packages["2" if operation == "upgrade" else "1"]] if operation in ("install", "upgrade") else []
        binding = current.crash(
            operation, incoming, boundary, trigger_execution=True,
            caller_owned=True, isolated_helper=True, core_product=True, policy="keep_existing",
            packages=(lifecycle.METADATA_PACKAGE,) if not incoming else (),
        )
        for archive in packages.values():
            if archive.exists():
                archive.unlink()
        if drift:
            member, _, mutation = drift.partition("-")
            path = current.candidate / (
                f"var/lib/dpkg/info/{lifecycle.METADATA_PACKAGE}.config"
                if member == "config"
                else f"var/lib/dpkg/info/{lifecycle.METADATA_PACKAGE}.symbols"
            )
            assert path.is_file() and not path.is_symlink()
            if mutation == "bytes" or drift == "bytes":
                m.write(path, b"changed during interruption\n", stat.S_IMODE(path.stat().st_mode))
            elif mutation == "mode":
                path.chmod(0o700)
            elif drift == "mode":
                path.chmod(0o640)
            elif mutation == "owner":
                os.chown(path, 1, 1)
            elif mutation == "missing" or drift == "missing":
                path.unlink()
            else:
                raise AssertionError(f"unknown metadata drift: {drift}")
        before = triggers.snapshot(current.candidate)
        report = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True,
        )
        assert helper_path.read_bytes() == helper_before and helper_path.stat().st_ino == helper_inode
        if drift:
            assert report["outcome"] in ("recovery_required", "refused"), report
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            print(f"{name}: inert metadata drift blocks recovery without mutation", flush=True)
            continue
        assert report["outcome"] == "applied", report
        compare(current.expected, current.candidate)
        proof_path, _ = provenance(current.candidate, report, binding)
        proof = document(proof_path, 16 * 1024 * 1024)
        retained = retained_documents(current.candidate, proof)
        if operation in ("upgrade", "remove"):
            for member in ("config", "symbols"):
                original = lifecycle.metadata_contents("1")[member]
                assert any(
                    blob["kind"] == "database"
                    and blob["logical_path"].endswith(f"{lifecycle.METADATA_PACKAGE}.{member}")
                    and blob["sha256"] == hashlib.sha256(original).hexdigest()
                    and blob["size"] == len(original)
                    for blob in retained["intent"][0]["blobs"]
                )
        completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
        assert completion["attempt_id"] == binding["attempt_id"]
        assert completion["transaction_provenance"]["document_sha256"] == proof["digest_sha256"]
        assert not (current.candidate / OPERATION).exists() and not (current.candidate / INTENT).exists()
        before = triggers.snapshot(current.candidate)
        repeated = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True, label="recover-again",
        )
        assert repeated["outcome"] == "applied", repeated
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        print(f"{name}: metadata bytes, original evidence and archive-evicted recovery passed", flush=True)


def exercise_literal_path_recovery(
    executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    trigger_path = "/usr/share/literal\\directory"
    for version, boundary, drift in (
        ("1", "during_filesystem_publication", None),
        ("1", "after_trigger_outcome", None),
        ("2", "after_trigger_outcome", None),
        ("1", "after_trigger_outcome", "conffile"),
        ("2", "after_trigger_outcome", "staged-script"),
    ):
        name = f"literal-paths-v{version}-{boundary}" + (f"-{drift}-drift" if drift else "")
        current = Scenario(workspace, name, executable, helper, architecture, environment)
        packages = lifecycle.make_literal_packages(
            current.directory / "packages", environment, architecture,
        )
        receiver_name = "literal-receiver"
        receiver = m.make_package(
            current.directory / "receiver", environment, architecture, "1",
            package=receiver_name, triggers=f"interest-noawait {trigger_path}\n".encode(),
            scripts=lifecycle.scripts(receiver_name, "1"),
        )
        helper_target = reference_helper_package(
            current.directory / "helper", environment, architecture,
            package="literal-helper-target",
        )
        current.seed(receiver, helper_target, *([packages["1"]] if version == "2" else []))
        if version == "2":
            for root in current.roots:
                config = root / lifecycle.LITERAL_CONFFILE
                m.write(config, b"locally edited literal conffile\n")
                os.utime(config, (946684800, 946684800))
        helper_path = current.candidate / triggers.HELPER
        shutil.copy2("/usr/bin/dpkg-trigger", helper_path)
        helper_before, helper_inode = helper_path.read_bytes(), helper_path.stat().st_ino
        archive = packages[version]
        binding = current.crash(
            "upgrade" if version == "2" else "install", [archive], boundary, trigger_execution=True,
            caller_owned=True, isolated_helper=True, core_product=True, policy="keep_existing",
        )
        assert not archive.exists()
        drift_path = None
        if drift == "conffile":
            drift_path = current.candidate / lifecycle.LITERAL_CONFFILE
        elif drift == "staged-script":
            drift_path = current.candidate / f"var/lib/debz-lifecycle-scripts/{lifecycle.LITERAL_PACKAGE}:{architecture}.prerm"
        if drift_path is not None:
            assert drift_path.is_file()
            m.write(drift_path, b"changed after interruption\n")
        before = triggers.snapshot(current.candidate)
        report = current.recover(
            trigger_execution=True, caller_owned=True, isolated_helper=True, core_product=True,
        )
        if drift:
            assert report["outcome"] in ("recovery_required", "refused"), report
            assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
            assert drift_path is not None
            assert drift_path.read_bytes() == b"changed after interruption\n"
            print(f"{name}: {drift} drift blocks recovery without mutation", flush=True)
            continue
        assert report["outcome"] == "applied", report
        compare(current.expected, current.candidate)
        proof_path, _ = provenance(current.candidate, report, binding)
        proof = document(proof_path, 16 * 1024 * 1024)
        retained = retained_documents(current.candidate, proof)
        assert trigger_path in retained["authorization"][0]["trigger_authority"]["allowed_triggers"]
        assert any(
            "\\" in entry["path"]
            for snapshot in (retained["managed_state"][0]["stable"], retained["managed_state"][0]["transient"])
            if snapshot is not None for entry in snapshot["entries"]
        )
        completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
        assert completion["attempt_id"] == binding["attempt_id"]
        assert completion["transaction_provenance"]["document_sha256"] == proof["digest_sha256"]
        assert not (current.candidate / OPERATION).exists()
        assert not (current.candidate / INTENT).exists()
        assert helper_path.read_bytes() == helper_before and helper_path.stat().st_ino == helper_inode
        print(f"{name}: exact literal paths, trigger evidence and evicted-archive recovery passed", flush=True)


def exercise_scriptless_recovery(
    executable: Path, helper: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    receiver_name = "debz-no-handler-receiver"
    for new_handler in (False, True):
        for boundary, drift in (
            ("before_scriptless_trigger_completion", False),
            ("after_scriptless_trigger_completion", False),
            ("before_scriptless_trigger_completion", True),
        ):
            name = f"no-handler-{'new' if new_handler else 'installed'}-{boundary}" + ("-drift" if drift else "")
            current = Scenario(workspace, name, executable, helper, architecture, environment)
            receiver = m.make_package(
                current.directory / "receiver", environment, architecture, "1",
                package=receiver_name, triggers=b"interest-await debz-no-handler\n", scripts={},
            )
            second = m.make_package(
                current.directory / "receiver-second", environment, architecture, "1",
                package=receiver_name + "-second", triggers=b"interest-await debz-no-handler\n", scripts={},
            )
            scripted_name = "debz-no-handler-z-scripted"
            scripted = m.make_package(
                current.directory / "receiver-scripted", environment, architecture, "1",
                package=scripted_name, triggers=b"interest-await debz-no-handler\n",
                scripts=lifecycle.scripts(scripted_name, "1"),
            )
            source = m.make_package(
                current.directory / "source", environment, architecture, "1",
                package=triggers.SOURCE, triggers=b"activate-await debz-no-handler\n",
                scripts=triggers.script_set(triggers.SOURCE, "1"),
            )
            if not new_handler:
                current.seed(receiver, second, scripted)
            binding = current.crash(
                "install", [receiver, second, scripted, source] if new_handler else [source], boundary, trigger_execution=True,
            )
            assert not (current.candidate / SCRIPT).exists(), "absence invented an in-flight script"
            authority = document(current.candidate / NAMESPACE / "native-trigger-authority-v1.json")
            assert [
                handler["postinst_sha256"] for handler in authority["handlers"]
                if handler["package"]["name"] == receiver_name
            ] == [None]
            assert not any(caller["package"]["name"] == receiver_name for caller in authority["callers"])
            status = next(record for record in triggers.snapshot(current.candidate)["dpkg"]["status"]
                          if record["package"] == receiver_name)
            pending = status.get("triggers-pending") == "debz-no-handler"
            assert pending == (boundary == "before_scriptless_trigger_completion")
            if drift:
                m.write(current.candidate / f"var/lib/dpkg/info/{receiver_name}.postinst", b"#!/bin/sh\nexit 0\n", 0o755)
                current.blocked(binding)
                print(f"{name}: changed postinst presence blocks recovery without mutation", flush=True)
                continue
            current.completed(binding, trigger_execution=True)
            proof = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
            retained = retained_documents(current.candidate, proof)
            for name in (receiver_name, receiver_name + "-second"):
                assert not any(script["package"] == name for script in retained.get("script_outcome", []))
                assert not (current.candidate / f"var/lib/dpkg/info/{name}.postinst").exists()
            assert len([script for script in retained["script_outcome"]
                        if script["package"] == scripted_name and script["arguments"][0] == "triggered"]) == 1


CONSUMER_PARITY_SUITES = ("debian-stable", "ubuntu-26.04")
CONSUMER_PARITY_CASES = (
    {"id": "pre-depends", "package": "pre-app", "archives": ("base-dep", "pre-app"),
     "reference_phases": (("base-dep",), ("pre-app",))},
    {"id": "virtual-provides", "package": "virtual-consumer", "archives": ("virtual-provider=2.0-1", "virtual-consumer")},
    {"id": "dependency-cycle", "package": "cycle-a", "archives": ("cycle-a", "cycle-b")},
    {"id": "without-recommends", "package": "scenario-main", "archives": ("base-dep", "scenario-main")},
    {"id": "with-recommends", "package": "scenario-main", "archives": ("base-dep", "recommended-addon", "scenario-main"),
     "recommends": True},
    {"id": "multiarch-package", "package": "multi-lib", "archives": ("multi-lib",)},
    {"id": "literal-package-paths", "package": "literal-paths-pkg", "archives": ("literal-paths-pkg",)},
    {"id": "retained-metadata", "package": "retained-metadata-pkg", "archives": ("retained-metadata-pkg",)},
    {"id": "suite-trigger", "package": "trigger-pkg", "archives": ("trigger-pkg",)},
    {"id": "upgrade-all", "package": None, "archives": ("fixture-upgrade=2.0-1",),
     "seeds": ("fixture-upgrade",), "update": True},
    {"id": "held-unchanged", "package": None, "archives": (), "seeds": ("fixture-upgrade",),
     "update": True, "hold": "fixture-upgrade"},
    {"id": "conffile-keep", "package": "conffile-pkg", "archives": ("conffile-pkg",), "conffile": "keep_existing"},
    {"id": "conffile-replace", "package": "conffile-pkg", "archives": ("conffile-pkg",), "conffile": "use_package_version"},
    {"id": "known-script-failure", "package": "fail-script", "archives": ("fail-script",), "exit_status": 7},
)


def consumer_parity_coverage(rows: list[dict], architecture: str) -> dict:
    expected = {(suite, case["id"]) for suite in CONSUMER_PARITY_SUITES for case in CONSUMER_PARITY_CASES}
    observed = [(row["suite"], row["case"]) for row in rows]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise AssertionError("native consumer parity matrix is incomplete or duplicated")
    if architecture not in ("amd64", "arm64") or any(
        row["architecture"] != architecture or row["consumers"] != ["core-cli", "family", "dpkg-reference"]
        or row["matched"] is not True for row in rows
    ):
        raise AssertionError("native consumer parity matrix lacks actual matching consumers")
    return {"architecture": architecture, "scope": "signed-hermetic-fixtures", "cases": rows}


def exercise_consumer_parity(
    executable: Path, cli: Path, workspace: Path, environment: dict, architecture: str,
) -> None:
    spec = importlib.util.spec_from_file_location("debz_consumer_repository", ROOT / "tools/generate-integration-repository.py")
    assert spec and spec.loader
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    rows = []
    for suite in CONSUMER_PARITY_SUITES:
        repository = workspace / f"consumer-{suite}-repository"
        generator.write_repository(repository, suite, architecture)
        source = workspace / f"consumer-{suite}.sources"
        keyring = repository / "fixture-keyring.gpg"
        m.write(source, (
            f"Types: deb\nURIs: file://{repository}\nSuites: {suite}\n"
            f"Components: main\nArchitectures: {architecture}\nSigned-By: {keyring}\n"
        ).encode())

        def archive(selector: str) -> Path:
            name, separator, version = selector.partition("=")
            if not separator:
                version = ("1.0-1debian1" if suite == "debian-stable" else "1.0-1ubuntu1") if name == "trigger-pkg" else "1.0-1"
            matches = list((repository / "pool/main").glob(f"{name}_{version}_*.deb"))
            assert len(matches) == 1, selector
            return matches[0]

        for case in CONSUMER_PARITY_CASES:
            current = lifecycle.Scenario(workspace, f"consumer-{suite}-{case['id']}", executable, architecture, environment)
            core = current.directory / "core"
            m.make_root(core, architecture)
            lifecycle.runtime.copy_program(core, Path("/bin/sh"), "/bin/sh")
            m.write(core / lifecycle.TRACE, b"")
            roots = (*current.roots, core)
            seeds = [archive(name) for name in ("native-helper-target", "essential-core", *case.get("seeds", ()))]
            policy = case.get("conffile", "keep_existing")
            if "conffile" in case:
                previous = current.directory / "previous-conffile.deb"
                m.write(previous, generator.build_deb("conffile-pkg", "0.1-1", architecture, {}, conffile=True))
                seeds.append(previous)
            for index, seed in enumerate(seeds):
                current.seed(seed)
                destination = current.directory / f"seed-core-{index}"
                destination.mkdir()
                assert lifecycle.reference_phase(core, [seed], "install", environment, destination, packages=[]) == 0
            for root in roots:
                if "conffile" in case:
                    m.write(root / "etc/debz-fixture.conf", b"local user configuration\n")
                    os.utime(root / "etc/debz-fixture.conf", (m.EPOCH, m.EPOCH))
                if "hold" in case:
                    subprocess.run(
                        [*m.reference_command(root), "--set-selections"], input=f"{case['hold']} hold\n".encode(),
                        env=environment, capture_output=True, check=True, timeout=30,
                    )
            helper_before = {root: ((root / triggers.HELPER).read_bytes(), (root / triggers.HELPER).stat().st_ino) for root in roots}
            core_lock = current.directory / "core.lock.json"
            family_lock = current.directory / "family.lock.json"
            package = case["package"]
            expected_status = case.get("exit_status", 0)
            options = [
                "--install-root", str(core), "--architecture", architecture,
                "--cache-path", str(current.directory / "core-cache"), "--state-path", str(current.directory / "core-state"),
                "--source", str(source), "--keyring", str(keyring), "--transaction-backend", "native",
                "--conffile", policy.replace("_", "-"), "--json",
            ]
            if case.get("recommends"):
                options.append("--recommends")

            def public(label: str, args: list[str], expected: int = 0) -> dict:
                m.reference_command(core)
                destination = current.directory / label
                destination.mkdir()
                with (destination / "stdout.json").open("wb") as stdout, (destination / "stderr").open("wb") as stderr:
                    process = subprocess.run([str(cli), *args], env=environment, stdin=subprocess.DEVNULL,
                                             stdout=stdout, stderr=stderr, timeout=120)
                assert process.returncode == expected, (case["id"], label, (destination / "stdout.json").read_text())
                assert not (destination / "stderr").read_bytes()
                result = document(destination / "stdout.json", 1024 * 1024)
                if args[0] != "transaction-result":
                    assert result["exit_status"] == expected and result["operation"] == args[0]
                return result

            template = {
                "schema": "io.github.cataggar.debz.package-family.request.v2", "version": 2,
                "root": str(current.candidate), "architecture": architecture, "sources": [str(source)],
                "keyrings": [str(keyring)], "cache": str(current.directory / "family-cache"),
                "state": str(current.directory / "family-state"), "package": package,
                "conffile": policy, "recommends": case.get("recommends", False),
            }
            envelope = {"operation": "install", "mode": "execute", "selectors": [{"name": package or "fixture-upgrade"}],
                        "options": {"install_root": str(current.candidate), "architecture": architecture,
                                    "cache_path": template["cache"], "state_path": template["state"]}}
            initial = {root: triggers.snapshot(root) for root in roots}
            public("core-plan", ["plan", *options, "--lock-output", str(core_lock), *([package] if package else [])])
            plan = workflow(
                executable, envelope, current.directory / "family-plan", environment,
                family_execution={**template, "operation": "resolve_lock", "lock_output": str(family_lock)},
                family_update_planning=case.get("update", False), capture_evidence=True,
            )
            assert plan["succeeded"] and not plan["changed"], plan
            assert core_lock.read_bytes() == family_lock.read_bytes(), "consumer plans differ for identical installed inputs"
            lock = document(core_lock)
            validator("exact-closure-lock-v2").validate(lock)
            for root in roots:
                assert not m.oracle.differences(initial[root], triggers.snapshot(root)), "planning changed installed state"
            operation = "upgrade-all" if case.get("update") else "install"
            core_result = public("core-execute", [
                operation, *options, "--lock-input", str(core_lock), "--assume-yes", "--noninteractive",
                *([package] if package else []),
            ], expected_status)
            family_result = workflow(
                executable, envelope, current.directory / "family-execute", environment,
                family_execution={**template, "operation": "update" if case.get("update") else "create",
                                  "lock_input": str(family_lock)}, capture_evidence=True,
            )
            assert family_result["exit_status"] == ("transaction" if expected_status else "success"), family_result
            assert family_result["succeeded"] == (expected_status == 0)
            assert family_result["changed"] == core_result["changed"] == bool(case["archives"])
            assert not (current.directory / "family-state/transaction-result.json").exists()
            if case["archives"]:
                for index, names in enumerate(case.get("reference_phases", (case["archives"],))):
                    destination = current.directory / f"reference-execute-{index}"
                    destination.mkdir()
                    status = lifecycle.reference_phase(
                        current.expected, [archive(name) for name in names], "install",
                        environment, destination, packages=[], policy=policy,
                    )
                    assert status == (1 if expected_status else 0), (
                        case["id"], (destination / "reference.log").read_text(),
                    )
            compare(current.expected, core)
            compare(current.expected, current.candidate)
            evidence = document(current.directory / "family-execute/native-evidence.json")
            for root in roots:
                assert (root / triggers.HELPER).read_bytes() == helper_before[root][0]
                assert (root / triggers.HELPER).stat().st_ino == helper_before[root][1]
            for root in (core, current.candidate):
                assert not (root / OPERATION).exists() and not (root / INTENT).exists()
                if not case["archives"]:
                    assert not (root / NAMESPACE / "native-transaction-provenance-v1.json").exists()
                    continue
                receipt = document(root / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
                completion = document(root / NAMESPACE / "root-operation-completion-v1.json")
                validator(PROVENANCE_SCHEMA).validate(receipt)
                assert_digest(receipt, PROVENANCE_SCHEMA)
                retained_documents(root, receipt)
                assert_final_database(root, architecture, receipt)
                assert receipt["outcome"] == ("failed" if expected_status else "succeeded")
                assert receipt["exact_lock_sha256"] == lock["digest_sha256"]
                assert completion["transaction_provenance"]["document_sha256"] == receipt["digest_sha256"]
                assert receipt["attempt_id"] == completion["attempt_id"]
            if case["archives"]:
                assert evidence["native_completion"]["outcome"] == ("failed" if expected_status else "succeeded")
                if expected_status == 0:
                    public("core-proof", ["transaction-result", "verify", "--transaction-backend", "native",
                                         "--install-root", str(core), "--architecture", architecture,
                                         "--lock-input", str(core_lock), "--json"])
            else:
                assert evidence["native_completion"] is None and evidence["native_install"] is None
                assert family_result["provenance_path"] is None
            rows.append({"suite": suite, "case": case["id"], "architecture": architecture,
                         "consumers": ["core-cli", "family", "dpkg-reference"], "matched": True})
            print(f"consumer-parity-{suite}-{case['id']}: public core, family, dpkg and native evidence matched", flush=True)
    m.write(workspace / "native-consumer-parity.json", canonical(consumer_parity_coverage(rows, architecture)))


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

    def family_request(current: lifecycle.Scenario, operation: str, package: str | None = None) -> dict:
        options = request(current, "install", "recover" if operation in {"recover", "inspect"} else "execute", [])["options"]
        value = {
            "schema": "io.github.cataggar.debz.package-family.request.v2",
            "version": 2, "operation": operation, "root": str(current.candidate),
            "architecture": architecture, "sources": options.get("source_paths", []),
            "keyrings": options.get("keyring_paths", []),
            "cache": options["cache_path"], "state": options["state_path"],
        }
        if operation not in {"recover", "inspect"}:
            value["package"] = package
            value["lock_output" if operation == "resolve_lock" else "lock_input"] = str(current.directory / "workflow.lock.json")
        return value

    def run_family(
        current: lifecycle.Scenario, label: str, value: dict, status: str | None = "success",
        *, update_planning: bool = False,
    ) -> dict:
        result = workflow(
            executable, request(current, "install", "execute", [value.get("package") or "scenario-main"]),
            current.directory / label, environment, family_execution=value,
            family_update_planning=update_planning, capture_evidence=True,
        )
        assert result["schema"] == "io.github.cataggar.debz.package-family.result.v2"
        assert result["version"] == 2 and result["operation"] == value["operation"]
        if status is not None:
            assert result["exit_status"] == status, result
            assert result["succeeded"] == (status == "success"), result
        assert not (current.directory / "state/transaction-result.json").exists()
        if result["provenance_path"] is not None:
            assert result["provenance_path"] == str(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json")
            assert Path(result["provenance_path"]).is_file()
        return result

    def inspect_family(current: lifecycle.Scenario, label: str) -> dict:
        def inventory() -> list[tuple]:
            return sorted(
                (str(path.relative_to(current.candidate)), entry.st_mode, entry.st_ino, entry.st_size, entry.st_mtime_ns)
                for path in current.candidate.rglob("*")
                for entry in [path.lstat()]
            )

        before = inventory()
        original = triggers.snapshot(current.candidate)
        value = family_request(current, "inspect")
        report = run_family(current, label, value)
        observed = diagnostic_inspection(
            report, document(current.directory / label / "native-evidence.json"), current.candidate,
        )
        assert inventory() == before, "diagnostic inspection changed the staged root"
        assert not m.oracle.differences(original, triggers.snapshot(current.candidate))
        assert not Path(value["cache"]).exists() and not Path(value["state"]).exists()
        return observed

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

    current = scenario("family-completed-verification")
    family_names = ["scenario-main"]
    original_workflow = request(current, "install", "execute", family_names)
    original_family = {
        "schema": "io.github.cataggar.debz.package-family.request.v2",
        "version": 2, "operation": "create", "root": str(current.candidate),
        "architecture": architecture, "sources": [str(source)], "keyrings": [str(keyring)],
        "cache": original_workflow["options"]["cache_path"],
        "state": original_workflow["options"]["state_path"],
        "package": family_names[0], "lock_input": original_workflow["options"]["lock_input_path"],
    }

    def completion_evidence(current: lifecycle.Scenario, label: str, outcome: str, settlement: str) -> dict:
        captured = document(current.directory / label / "native-evidence.json")
        returned = captured["native_completion"]
        receipt = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
        completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
        assert completion["surface"] == "package_transaction"
        assert returned["operation"] == completion["operation"]
        assert returned["outcome"] == outcome == receipt["outcome"]
        assert returned["settlement"] == settlement
        for name, expected in (
            ("attempt_id", receipt["attempt_id"]),
            ("lock_sha256", receipt["exact_lock_sha256"]),
            ("caller_request_sha256", completion["request_sha256"]),
            ("caller_policy_sha256", completion["policy_sha256"]),
            ("transaction_digest_sha256", receipt["digest_sha256"]),
            ("completion_digest_sha256", completion["digest_sha256"]),
            ("program_sha256", receipt["program_sha256"]),
        ):
            # Zig's test transport emits valid UTF-8 byte arrays as strings.
            raw = returned[name]
            value = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
            assert value.hex() == expected, name
            returned[name] = list(value)
        return returned

    def verify_family(label: str, original: dict, succeeds: bool = True, returned: dict | None = None) -> dict:
        def inventory() -> list[tuple]:
            return sorted(
                (str(path.relative_to(current.candidate)), entry.st_mode, entry.st_size, entry.st_mtime_ns)
                for path in current.candidate.rglob("*")
                for entry in [path.lstat()]
            )

        before = inventory()
        result = workflow(
            executable, request(current, "install", "execute", [original.get("package") or "scenario-main"]),
            current.directory / label, environment,
            family_verification={"request": original, "expect_failure": not succeeds, "completion": returned},
        )
        assert before == inventory(), "family verification changed the staged root"
        assert not (current.directory / "state/transaction-result.json").exists()
        if succeeds:
            validator("transaction-result-summary-v2").validate(result)
            lock = document(Path(original["lock_input"]))
            receipt = document(current.candidate / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
            completion = document(current.candidate / NAMESPACE / "root-operation-completion-v1.json")
            expected_operation = (
                ("upgrade" if original.get("package") is not None else "upgrade-all")
                if original["operation"] == "update" else "install"
            )
            assert result["operation"] == expected_operation
            assert result["lock_sha256"] == lock["digest_sha256"]
            assert result["transaction_digest_sha256"] == receipt["digest_sha256"]
            assert result["completion_digest_sha256"] == completion["digest_sha256"]
            assert result["caller_request_sha256"] == completion["request_sha256"]
            assert result["caller_policy_sha256"] == completion["policy_sha256"]
        else:
            assert result["verified"] is False
        return result

    run(current, "plan", request(current, "install", "plan_only", family_names), capture_evidence=True)
    assert document(current.directory / "plan/native-evidence.json")["native_completion"] is None
    verify_family("before-execution", original_family, False)
    run(current, "install", original_workflow, capture_evidence=True)
    returned = completion_evidence(current, "install", "succeeded", "cleared")
    first = verify_family("verified", original_family)
    assert first == verify_family("verified-result", original_family, returned=returned)
    for field in (
        "attempt_id", "lock_sha256", "caller_request_sha256", "caller_policy_sha256",
        "transaction_digest_sha256", "completion_digest_sha256", "program_sha256",
    ):
        changed = {**returned, field: [returned[field][0] ^ 1, *returned[field][1:]]}
        refused = verify_family(f"wrong-result-{field}", original_family, False, changed)
        assert refused["error"] == "NativeFamilyCompletionMismatch", refused
    for field, value in (("outcome", "failed"), ("settlement", "retained")):
        refused = verify_family(f"invalid-result-{field}", original_family, False, {**returned, field: value})
        assert refused["error"] == "InvalidNativeFamilyCompletion", refused
    refused = verify_family("wrong-result-operation", original_family, False, {**returned, "operation": "upgrade"})
    assert refused["error"] == "NativeFamilyCompletionMismatch", refused
    assert first == verify_family("verified-again", original_family)
    assert first == verify_family("customize-equivalent", {**original_family, "operation": "customize"})
    for field, value in (
        ("package", "another-package"),
        ("operation", "update"),
        ("conffile", "use_package_version"),
        ("allow_downgrade", True),
        ("recommends", True),
        ("foreign_architectures", ["arm64" if architecture == "amd64" else "amd64"]),
    ):
        result = verify_family(f"mismatch-{field}", {**original_family, field: value}, False)
        assert result["error"] == "NativeFamilyRequestMismatch", result
    for name, path in (
        ("receipt", current.candidate / NAMESPACE / "native-transaction-provenance-v1.json"),
        ("completion", current.candidate / NAMESPACE / "root-operation-completion-v1.json"),
        ("database", current.candidate / "var/lib/dpkg/status"),
        ("lock", Path(original_family["lock_input"])),
    ):
        contents = path.read_bytes()
        try:
            path.write_bytes(b"invalid completed evidence\n")
            verify_family(f"invalid-{name}", original_family, False)
        finally:
            path.write_bytes(contents)
    m.write(current.candidate / OPERATION, b"unsettled operation\n")
    try:
        verify_family("unsettled", original_family, False)
    finally:
        (current.candidate / OPERATION).unlink()
    assert first == verify_family("final-verified", original_family)
    original_workflow = request(current, "install", "execute", ["fail-script"])
    failed_family = {**original_family, "package": "fail-script"}
    run(current, "plan-failure", request(current, "install", "plan_only", ["fail-script"]))
    failed = run(current, "known-failure", original_workflow, exit_status=7, capture_evidence=True)
    assert failed["changed"]
    failed_completion = completion_evidence(current, "known-failure", "failed", "cleared")
    verify_family("failed-result-not-success", failed_family, False, failed_completion)
    verify_family("relabeled-failure-not-success", failed_family, False, {**failed_completion, "outcome": "succeeded"})
    verify_family("failed-not-success", failed_family, False)
    recovered = run(current, "clean-recovery", request(current, "install", "recover", ["fail-script"]), capture_evidence=True)
    assert not recovered["changed"]
    assert document(current.directory / "clean-recovery/native-evidence.json")["native_completion"] is None
    print("family-completed-verification: real receipts, semantic request binding and read-only refusals passed", flush=True)

    current = scenario("family-recovered-verification")
    original_workflow = request(current, "install", "execute", family_names)
    original_family = {
        **original_family, "root": str(current.candidate),
        "cache": original_workflow["options"]["cache_path"],
        "state": original_workflow["options"]["state_path"],
        "lock_input": original_workflow["options"]["lock_input_path"],
    }
    run(current, "plan", request(current, "install", "plan_only", family_names))
    workflow(
        executable, original_workflow, current.directory / "receipt-interruption", environment,
        completion_crash="after_native_receipt", capture_evidence=True,
    )
    verify_family("pending-not-success", original_family, False)
    recovery_request = family_request(current, "recover")
    pending_bytes = (current.candidate / OPERATION).read_bytes()
    for field, value in (
        ("sources", [str(source)]),
        ("keyrings", [str(keyring)]),
        ("lock_input", original_family["lock_input"]),
        ("lock_output", original_family["lock_input"]),
        ("package", family_names[0]),
    ):
        refused = run_family(current, f"family-reject-{field}", {**recovery_request, field: value}, "usage")
        assert not refused["changed"] and refused["provenance_path"] is None
        assert (current.candidate / OPERATION).read_bytes() == pending_bytes
    original_cache = current.directory / "cache"
    original_cache.rename(current.directory / "evicted-cache")
    lock_path = Path(original_family["lock_input"])
    retained_lock = current.directory / "reviewed.lock"
    lock_path.rename(retained_lock)
    try:
        recovered = run_family(current, "recover", recovery_request)
    finally:
        retained_lock.rename(lock_path)
    assert recovered["changed"] and recovered["lock_path"] is None
    assert not Path(recovery_request["cache"]).exists()
    assert not Path(recovery_request["state"]).exists()
    recovered_completion = completion_evidence(current, "recover", "succeeded", "cleared")
    assert document(current.directory / "recover/native-evidence.json")["native_install"] is None
    verify_family("recovered-result-success", original_family, returned=recovered_completion)
    wrong_attempt = verify_family("foreign-result-not-success", original_family, False, returned)
    assert wrong_attempt["error"] == "NativeFamilyCompletionMismatch", wrong_attempt
    verify_family("recovered-success", original_family)
    print("family-recovered-verification: pending refusal and original completed request proof passed", flush=True)

    current = scenario("family-native-install")
    initial = inspect_family(current, "inspect-initial")
    assert initial["observed_operation"] is None and not initial["native_active_evidence"]
    assert {package["name"] for package in initial["packages"]} == {"essential-core", "native-helper-target"}
    planned = run_family(current, "family-plan", family_request(current, "resolve_lock", "scenario-main"))
    assert not planned["changed"] and planned["provenance_path"] is None
    assert document(Path(planned["lock_path"]))["version"] == 2
    create_request = family_request(current, "create", "scenario-main")
    created = run_family(current, "family-create", create_request)
    assert created["changed"]
    completion_evidence(current, "family-create", "succeeded", "cleared")
    reference_dir = current.directory / "reference-create"
    reference_dir.mkdir()
    assert lifecycle.reference_phase(
        current.expected, [archive("base-dep"), archive("scenario-main")], "install",
        environment, reference_dir, packages=[],
    ) == 0
    compare(current.expected, current.candidate)
    with (current.candidate / NAMESPACE / "root-operation.lock").open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inspected = inspect_family(current, "inspect-with-root-lock-held")
    assert "scenario-main" in {package["name"] for package in inspected["packages"]}
    run_family(current, "family-plan-customize", family_request(current, "resolve_lock", "conffile-pkg"))
    customized = run_family(current, "family-customize", family_request(current, "customize", "conffile-pkg"))
    assert customized["changed"]
    completion_evidence(current, "family-customize", "succeeded", "cleared")
    reference_dir = current.directory / "reference-customize"
    reference_dir.mkdir()
    assert lifecycle.reference_phase(
        current.expected, [archive("conffile-pkg")], "install",
        environment, reference_dir, packages=[],
    ) == 0
    compare(current.expected, current.candidate)
    run_family(current, "family-plan-failure", family_request(current, "resolve_lock", "fail-script"))
    failed = run_family(current, "family-failure", family_request(current, "customize", "fail-script"), "transaction")
    assert failed["changed"] and failed["diagnostic"]["recoverable"]
    completion_evidence(current, "family-failure", "failed", "cleared")
    failed_bytes = Path(failed["provenance_path"]).read_bytes()
    clean = run_family(current, "family-clean-recovery", family_request(current, "recover"))
    assert not clean["changed"] and clean["provenance_path"] is None and clean["lock_path"] is None
    assert document(current.directory / "family-clean-recovery/native-evidence.json")["native_completion"] is None
    assert Path(failed["provenance_path"]).read_bytes() == failed_bytes
    inspected = inspect_family(current, "inspect-known-failure")
    assert next(package for package in inspected["packages"] if package["name"] == "fail-script")["status"]["current"] != "installed"
    print("family-native-install: genuine create/customize, known failure and clean recovery passed", flush=True)

    current = lifecycle.Scenario(workspace, "family-missing-helper", executable, architecture, environment)
    current.seed(archive("essential-core"))
    assert not (current.candidate / triggers.HELPER).exists()
    inspected = inspect_family(current, "inspect-without-helper")
    assert [package["name"] for package in inspected["packages"]] == ["essential-core"]
    original_status = (current.candidate / "var/lib/dpkg/status").read_bytes()
    run_family(current, "family-plan", family_request(current, "resolve_lock", "scenario-main"))
    refused = run_family(current, "family-refused", family_request(current, "create", "scenario-main"), None)
    assert not refused["succeeded"] and not refused["changed"] and refused["provenance_path"] is None
    assert "helper" in refused["diagnostic"]["message"].lower(), refused
    assert not (current.candidate / triggers.HELPER).exists()
    assert (current.candidate / "var/lib/dpkg/status").read_bytes() == original_status
    assert document(current.directory / "family-refused/native-evidence.json")["native_completion"] is None
    print("family-missing-helper: refusal before mutation without a placeholder passed", flush=True)

    for selected in (f"fixture-upgrade:{architecture}", None):
        current = scenario("family-update-selected" if selected else "family-update-all")
        current.seed(archive("fixture-upgrade"))
        original_status = (current.candidate / "var/lib/dpkg/status").read_bytes()
        run_family(current, "install-plan", family_request(current, "resolve_lock", "fixture-upgrade"))
        install_lock = document(current.directory / "workflow.lock.json")
        update_request = family_request(current, "update", selected)
        refused = run_family(current, "reject-install-lock", update_request, "planning")
        assert not refused["changed"] and refused["provenance_path"] is None
        assert "semantic request" in refused["diagnostic"]["message"]
        assert (current.candidate / "var/lib/dpkg/status").read_bytes() == original_status
        plan_request = family_request(current, "resolve_lock", selected)
        planned = run_family(current, "update-plan", plan_request, update_planning=True)
        assert not planned["changed"] and planned["provenance_path"] is None
        lock = document(Path(planned["lock_path"]))
        validator("exact-closure-lock-v2").validate(lock)
        assert lock["request_sha256"] != install_lock["request_sha256"]
        assert document(current.directory / "update-plan/native-evidence.json") == {
            "native_install": None, "native_completion": None,
        }
        assert (current.candidate / "var/lib/dpkg/status").read_bytes() == original_status
        for label, wrong in (
            ("install-operation", {**update_request, "operation": "create", "package": "fixture-upgrade"}),
            ("update-selector", {**update_request, "package": "essential-core"}),
            ("update-policy", {**update_request, "recommends": True}),
        ):
            refused = run_family(current, f"reject-{label}", wrong, "planning")
            assert not refused["changed"] and refused["provenance_path"] is None
            assert (current.candidate / "var/lib/dpkg/status").read_bytes() == original_status
        updated = run_family(current, "update", update_request)
        assert updated["changed"]
        returned = completion_evidence(current, "update", "succeeded", "cleared")
        assert returned["operation"] == ("upgrade" if selected else "upgrade_all")
        assert document(current.directory / "update/native-evidence.json")["native_install"] is None
        reference_dir = current.directory / "reference-update"
        reference_dir.mkdir()
        assert lifecycle.reference_phase(
            current.expected, [repository / f"pool/main/fixture-upgrade_2.0-1_{architecture}.deb"],
            "install", environment, reference_dir, packages=[],
        ) == 0
        compare(current.expected, current.candidate)
        verify_family("verified-update", update_request, returned=returned)
        verify_family("update-not-install", {**update_request, "operation": "create", "package": "fixture-upgrade"}, False)
        receipt_before = Path(updated["provenance_path"]).read_bytes()
        run_family(current, "unchanged-plan", plan_request, update_planning=True)
        unchanged = run_family(current, "unchanged-update", update_request)
        assert not unchanged["changed"] and unchanged["provenance_path"] is None
        assert document(current.directory / "unchanged-update/native-evidence.json") == {
            "native_install": None, "native_completion": None,
        }
        assert Path(updated["provenance_path"]).read_bytes() == receipt_before
        assert not (current.candidate / OPERATION).exists()
        compare(current.expected, current.candidate)
        print(f"{current.directory.name}: bound update, dpkg parity and genuine unchanged result passed", flush=True)

    current = scenario("family-update-recovery")
    current.seed(archive("fixture-upgrade"))
    selected = f"fixture-upgrade:{architecture}"
    run_family(current, "update-plan", family_request(current, "resolve_lock", selected), update_planning=True)
    update_request = family_request(current, "update", selected)
    pending = request(current, "upgrade", "execute", [])
    pending["selectors"] = [{"name": "fixture-upgrade", "architecture": architecture}]
    workflow(
        executable, pending, current.directory / "interrupted-update", environment,
        completion_crash="after_native_receipt", capture_evidence=True,
    )
    verify_family("pending-update-not-success", update_request, False)
    (current.directory / "cache").rename(current.directory / "evicted-cache")
    lock_path = Path(update_request["lock_input"])
    retained_lock = current.directory / "retained-update.lock"
    lock_path.rename(retained_lock)
    try:
        recovered = run_family(current, "recover-update", family_request(current, "recover"))
    finally:
        retained_lock.rename(lock_path)
    assert recovered["changed"] and recovered["lock_path"] is None
    returned = completion_evidence(current, "recover-update", "succeeded", "cleared")
    assert returned["operation"] == "upgrade"
    verify_family("verified-recovered-update", update_request, returned=returned)
    print("family-update-recovery: original update completion after cache/lock eviction passed", flush=True)

    current = scenario("family-update-failure")
    previous_failure = current.directory / "fail-script-previous.deb"
    m.write(previous_failure, generator.build_deb("fail-script", "0.1-1", architecture, {}))
    current.seed(previous_failure)
    run_family(current, "update-plan", family_request(current, "resolve_lock", "fail-script"), update_planning=True)
    update_request = family_request(current, "update", "fail-script")
    failed = run_family(current, "failed-update", update_request, "transaction")
    assert failed["changed"] and failed["diagnostic"]["recoverable"]
    returned = completion_evidence(current, "failed-update", "failed", "cleared")
    assert returned["operation"] == "upgrade"
    verify_family("failed-update-not-success", update_request, False, returned)
    verify_family("relabeled-update-not-success", update_request, False, {**returned, "outcome": "succeeded"})
    print("family-update-failure: failed terminal update is not successful completion", flush=True)

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
    unchanged = run(current, "unchanged", request(current, "upgrade_all", "execute", []), capture_evidence=True)
    assert not unchanged["changed"]
    assert document(current.directory / "unchanged/native-evidence.json")["native_completion"] is None
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

    def verify_owned(current, label, owner, *, state, outcome="succeeded", expected_error=None, change=None):
        before = triggers.snapshot(current.candidate)
        before_evidence = sorted(
            (str(path.relative_to(current.candidate)), stat.st_mode, stat.st_size, stat.st_mtime_ns)
            for path in (current.candidate / NAMESPACE).rglob("*")
            for stat in [path.lstat()]
        )
        verification = owned_request(current, "install", "recover", names)
        if change:
            verification.update(change)
        result = workflow(
            executable, verification, current.directory / label, environment, owner_evidence=owner,
            owned_verification={
                "lock_path": str(current.directory / "workflow.lock.json"),
                "expected_error": expected_error,
                "state": state,
                "outcome": outcome,
            },
        )
        assert result == ({"verified": False} if expected_error else {"verified": True, "outcome": outcome})
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        after_evidence = sorted(
            (str(path.relative_to(current.candidate)), stat.st_mode, stat.st_size, stat.st_mtime_ns)
            for path in (current.candidate / NAMESPACE).rglob("*")
            for stat in [path.lstat()]
        )
        assert before_evidence == after_evidence, "owned verification changed durable evidence"

    def verify_pending(current, label, owner, **options):
        verify_owned(current, label, owner, state="pending", **options)

    def verify_released(current, label, owner, **options):
        verify_owned(current, label, owner, state="released", **options)

    def verify_failed(current, label, owner, **options):
        verify_owned(current, label, owner, state="pending", outcome="failed", **options)

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
        owner_evidence=bound, exit_status=8, capture_evidence=True)
    assert document(current.directory / "changed-request/native-evidence.json")["native_completion"] is None
    assert (current.candidate / OPERATION).read_bytes() == reserved
    run(current, "execute", owned_request(current, "install", "execute", list(reversed(names))),
        owner_evidence=bound, capture_evidence=True)
    completion_evidence(current, "execute", "succeeded", "retained")
    retained_bytes = (current.candidate / NAMESPACE / "root-operation-deferred-ack-v1.json").read_bytes()
    refused = run_family(current, "family-cannot-finalize-owner", family_request(current, "recover"), "recovery")
    assert not refused["changed"] and refused["provenance_path"] is None
    assert (current.candidate / NAMESPACE / "root-operation-deferred-ack-v1.json").read_bytes() == retained_bytes
    inspected = inspect_family(current, "inspect-retained-owner")
    assert inspected["deferred_owner"] == document(current.candidate / NAMESPACE / "root-operation-deferred-ack-v1.json")["state"]
    assert (current.candidate / NAMESPACE / "root-operation-deferred-ack-v1.json").read_bytes() == retained_bytes
    assert_completion(current, lock)
    released = retain_owner(current, "released")
    assert document(released)["state"] == "released"
    verify_released(current, "verify-released", released)
    verify_released(current, "verify-released-again", released)
    verify_pending(current, "verify-released-as-pending", released, expected_error="PendingOwnerRequired")
    verify_released(current, "verify-bound-as-released", bound, expected_error="ReleasedOwnerRequired")
    verify_released(current, "verify-released-wrong-operation", released,
                    expected_error="InvalidCompletion", change={"operation": "remove"})
    verify_released(current, "verify-released-wrong-request", released,
                    expected_error="InvalidCompletion", change={"selectors": [{"name": "different"}]})
    original_options = owned_request(current, "install", "recover", names)["options"]
    verify_released(current, "verify-released-wrong-policy", released,
                    expected_error="InvalidCompletion",
                    change={"options": {**original_options, "recommends": True}})
    m.write(current.candidate / OPERATION, reserved)
    verify_released(current, "verify-released-unfinished-record", released, expected_error="InvalidCompletion")
    (current.candidate / OPERATION).unlink()
    for name, relative in (
        ("intent", INTENT),
        ("script", NAMESPACE / "native-lifecycle-script-v1.json"),
        ("progress", PROGRESS),
        ("staging", NAMESPACE / ".debz-native-foreign"),
    ):
        active = current.candidate / relative
        assert not active.exists()
        m.write(active, b"{}\n")
        verify_released(current, f"verify-released-active-{name}", released, expected_error="OperationNotSettled")
        active.unlink()
    completion_path = current.candidate / NAMESPACE / "root-operation-completion-v1.json"
    original_completion = completion_path.read_bytes()
    m.write(completion_path, b"{}\n")
    verify_released(current, "verify-released-damaged-completion", released, expected_error="NonCanonicalDocument")
    m.write(completion_path, original_completion)
    receipt_path = current.candidate / NAMESPACE / "native-transaction-provenance-v1.json"
    original_receipt = receipt_path.read_bytes()
    m.write(receipt_path, b"{}\n")
    verify_released(current, "verify-released-damaged-receipt", released, expected_error="MissingField")
    m.write(receipt_path, original_receipt)
    finalization = owned_request(current, "install", "recover", names)
    run(current, "finalize", finalization, owner_evidence=released, acknowledgment="ownership")
    run(current, "finalize-again", finalization, owner_evidence=released, acknowledgment="ownership")
    assert not (current.candidate / owner_path).exists()
    verify_released(current, "verify-finalized-as-released", released, expected_error="ReleasedOwnerRequired")
    if result_cli is not None:
        verify_result(current, lock)
    print("workflow-owned-success: reservation, native receipt, and exact owner finalization passed", flush=True)
    first_released = released

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
            verify_released(current, "verify-terminal-owner", retained)
            if result_cli is not None:
                verify_result(current, lock, False)
            if boundary == "after_ownership_record_clear":
                assert document(first_released)["attempt_id"] != document(retained)["attempt_id"]
                m.write(current.candidate / owner_path, first_released.read_bytes())
                verify_released(current, "verify-terminal-foreign-attempt", first_released,
                                expected_error="InvalidCompletion")
                m.write(current.candidate / owner_path, retained.read_bytes())
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
            verify_pending(current, "verify-unpublished", recovery_owner, expected_error="InvalidCompletion")
        run(current, "recover", recovery, owner_evidence=recovery_owner)
        pending = retain_owner(current, "pending")
        assert document(pending)["state"] == "pending"
        published = (current.candidate / OPERATION).read_bytes()
        run(current, "recover-again", recovery, owner_evidence=pending)
        assert (current.candidate / OPERATION).read_bytes() == published
        assert not m.oracle.differences(before, triggers.snapshot(current.candidate))
        verify_pending(current, "verify-pending", pending)
        verify_failed(current, "verify-success-as-failure", pending, expected_error="TransactionNotFailed")
        verify_released(current, "verify-pending-as-released", pending, expected_error="ReleasedOwnerRequired")
        if result_cli is not None:
            verify_result(current, lock, False)
        run(current, "foreign-acknowledgment", {**recovery, "orchestration_id": [18] * 32},
            owner_evidence=pending, acknowledgment="recovery", exit_status=2)
        assert (current.candidate / OPERATION).read_bytes() == published
        if execution_boundary == "after_native_receipt":
            verify_pending(current, "verify-bound-owner", bound, expected_error="PendingOwnerRequired")
            verify_pending(current, "verify-wrong-operation", pending,
                           expected_error="InvalidCompletion", change={"operation": "remove"})
            verify_pending(current, "verify-wrong-request", pending,
                           expected_error="InvalidCompletion",
                           change={"selectors": [{"name": "different"}]})
            verify_pending(current, "verify-wrong-policy", pending,
                           expected_error="InvalidCompletion",
                           change={"options": {**recovery["options"], "recommends": True}})
            for name, relative, failure in (
                ("intent", INTENT, "EvidenceChanged"),
                ("progress", PROGRESS, "EvidenceChanged"),
                ("authorization", NAMESPACE / "native-transaction-authorization-v1.json", "EvidenceChanged"),
                ("program", NAMESPACE / "native-transaction-program-v1.json", "EvidenceChanged"),
                ("triggers", NAMESPACE / "native-trigger-events-v1.json", "EvidenceChanged"),
                ("managed", NAMESPACE / "native-managed-state-v1.json", "EvidenceChanged"),
            ):
                active = current.candidate / relative
                original_active = active.read_bytes()
                m.write(active, b"{}\n")
                verify_pending(current, f"verify-damaged-{name}", pending, expected_error=failure)
                m.write(active, original_active)
            active_progress = current.candidate / PROGRESS
            original_progress = active_progress.read_bytes()
            active_progress.unlink()
            verify_pending(current, "verify-partial-acknowledgment", pending)
            m.write(active_progress, original_progress)
            completion_path = current.candidate / NAMESPACE / "root-operation-completion-v1.json"
            original_completion = completion_path.read_bytes()
            m.write(completion_path, b"{}\n")
            verify_pending(current, "verify-damaged-completion", pending, expected_error="NonCanonicalDocument")
            m.write(completion_path, original_completion)
            for name, relative in (
                ("script", "native-lifecycle-script-v1.json"),
                ("trigger-authority", "native-trigger-authority-v1.json"),
                ("foreign-outcome", "native-script-outcome-v1-foreign.json"),
                ("staging", ".debz-native-foreign"),
            ):
                active = current.candidate / NAMESPACE / relative
                assert not active.exists()
                m.write(active, b"{}\n")
                verify_pending(current, f"verify-unresolved-{name}", pending,
                               expected_error="UnresolvedNativeEvidence")
                active.unlink()
            run(current, "wrong-operation-acknowledgment", {**recovery, "operation": "remove"},
                owner_evidence=pending, acknowledgment="recovery", exit_status=8)
            receipt_path = current.candidate / NAMESPACE / "native-transaction-provenance-v1.json"
            original_receipt = receipt_path.read_bytes()
            m.write(receipt_path, b"{}\n")
            verify_pending(current, "verify-damaged-receipt", pending, expected_error="MissingField")
            run(current, "damaged-receipt", recovery, owner_evidence=pending,
                acknowledgment="recovery", exit_status=8)
            assert (current.candidate / OPERATION).read_bytes() == published
            assert (current.candidate / owner_path).read_bytes() == pending.read_bytes()
            assert (current.candidate / INTENT).exists()
            m.write(receipt_path, original_receipt)
        workflow(executable, recovery, current.directory / "acknowledgment-crash", environment,
                 completion_crash=acknowledgment_boundary, owner_evidence=pending,
                 acknowledgment="recovery")
        if acknowledgment_boundary == "after_native_acknowledged":
            verify_pending(current, "verify-native-acknowledged", pending)
            if result_cli is not None:
                verify_result(current, lock, False)
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
    verify_failed(current, "verify-failed-unpublished", pending, expected_error="InvalidCompletion",
                  change={"selectors": recovery["selectors"]})
    run(current, "recover", recovery, owner_evidence=pending, exit_status=7)
    verify_pending(current, "verify-known-failure", pending, expected_error="TransactionNotSuccessful",
                   change={"selectors": recovery["selectors"]})
    failed_request = {"selectors": recovery["selectors"]}
    verify_failed(current, "verify-failed", pending, change=failed_request)
    verify_failed(current, "verify-failed-again", pending, change=failed_request)
    status_path = current.candidate / "var/lib/dpkg/status"
    original_status = status_path.read_bytes()
    assert b"Status: install ok half-configured" in original_status
    changed_status = original_status.replace(b"Version: 1.0-1", b"Version: 1.0-2", 1)
    assert changed_status != original_status
    m.write(status_path, changed_status)
    verify_failed(current, "verify-failed-changed-database", pending,
                  expected_error="FinalStateMismatch", change=failed_request)
    m.write(status_path, original_status)
    verify_failed(current, "verify-failed-wrong-request", pending,
                  expected_error="InvalidCompletion", change={"selectors": [{"name": "different"}]})
    active = current.candidate / INTENT
    original_intent = active.read_bytes()
    m.write(active, b"{}\n")
    verify_failed(current, "verify-failed-changed-intent", pending,
                  expected_error="EvidenceChanged", change=failed_request)
    m.write(active, original_intent)
    if result_cli is not None:
        verify_result(current, lock, False)
    workflow(executable, recovery, current.directory / "failed-acknowledgment-crash", environment,
             completion_crash="after_native_acknowledged", owner_evidence=pending,
             acknowledgment="recovery")
    verify_failed(current, "verify-failed-after-native-acknowledgment", pending, change=failed_request)
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

    for outcome in ("success", "recovered", "failed"):
        current = scenario(f"workflow-projected-{outcome}")
        root = current.candidate
        fixture = root / "fixture"
        fixture.mkdir()
        (root / "proc").mkdir(exist_ok=True)
        (root / "run").mkdir(exist_ok=True)
        (root / "tmp").mkdir(exist_ok=True)
        (root / "dev").mkdir(exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        m.write(root / ".debz-native-projection", b"debz native projection fixture v1\n")
        lifecycle.runtime.copy_program(root, executable, "/fixture/native-test")
        shutil.copytree(repository, fixture / "repository")
        m.write(fixture / "workflow.sources", (
            "Types: deb\nURIs: file:///fixture/repository\nSuites: debian-stable\n"
            f"Components: main\nArchitectures: {architecture}\n"
            "Signed-By: /fixture/repository/fixture-keyring.gpg\n"
        ).encode())
        selected = ["fail-script"] if outcome == "failed" else ["scenario-main", "conffile-pkg"]

        def projected_request(mode: str) -> dict:
            options = {
                "install_root": "/run/debz/system-root",
                "cache_path": "/fixture/unused-cache" if mode == "recover" else "/fixture/cache",
                "state_path": "/fixture/unused-state" if mode == "recover" else "/fixture/state",
                "architecture": architecture, "assume_yes": True,
                "conffile": "keep_existing", "noninteractive": True,
            }
            if mode != "recover":
                options.update(
                    source_paths=["/fixture/workflow.sources"],
                    keyring_paths=["/fixture/repository/fixture-keyring.gpg"],
                )
                options["lock_output_path" if mode == "plan_only" else "lock_input_path"] = "/fixture/lock.json"
            value = {
                "operation": "install", "mode": mode,
                "selectors": [{"name": name} for name in selected], "options": options,
            }
            if mode not in ("plan_only", "download_only"):
                value["orchestration_id"] = [23] * 32
            if mode == "recover" and outcome != "success":
                value["defer_recovery_clear"] = True
            return value

        def projected_run(mode: str, *, expected_exit: int | None = 0, **extra) -> dict | None:
            report = fixture / "report.json"
            report.unlink(missing_ok=True)
            m.write(fixture / "request.json", json.dumps({
                "workflow": projected_request(mode), "projected": True,
                "report": "/fixture/report.json", **extra,
            }).encode())
            result = projected_process(root, workflow=True)
            assert result.returncode == (CRASH_EXIT if "completion_crash" in extra else 0), (
                result.returncode, result.stderr,
            )
            assert not list((root / "run/debz/system-root").iterdir()), "projected workflow mount leaked"
            if "completion_crash" in extra:
                assert not report.exists()
                return None
            value = document(report)
            if "owned_verification" in extra:
                expected = (
                    {"verified": False} if extra["owned_verification"].get("expected_error")
                    else {"verified": True, "outcome": "failed" if outcome == "failed" else "succeeded"}
                )
                assert value == expected, value
            elif expected_exit is None:
                assert value["exit_status"] != 0 and not value["changed"], value
            else:
                assert value["exit_status"] == expected_exit, value
            return value

        def projected_owner() -> None:
            m.write(fixture / "owner.json", (root / owner_path).read_bytes())

        projected_run("plan_only")
        projected_lock = document(fixture / "lock.json")
        initial_status = (root / "var/lib/dpkg/status").read_bytes()
        projected_run("reserve", expected_exit=None, withhold_projection=True)
        assert not (root / OPERATION).exists() and not (root / owner_path).exists()
        assert (root / "var/lib/dpkg/status").read_bytes() == initial_status
        projected_run("reserve")
        projected_owner()
        execution = {"owner_evidence": "/fixture/owner.json"}
        if outcome != "success":
            execution["completion_crash"] = "after_native_receipt"
        projected_run("execute", **execution)
        projected_owner()
        if outcome != "success":
            projected_run("recover", facade_recover=True, owner_evidence="/fixture/owner.json",
                          expected_exit=7 if outcome == "failed" else 0)
            projected_owner()
            completion = document(root / NAMESPACE / "root-operation-completion-v1.json")
            assert completion["discharge"]["operation"] == "recover", completion
            projected_run("recover", facade_recover=True, owner_evidence="/fixture/owner.json",
                          expected_exit=7 if outcome == "failed" else 0)
        proof = document(root / NAMESPACE / "native-transaction-provenance-v1.json", 16 * 1024 * 1024)
        assert proof["install_root"] == "/run/debz/system-root"
        assert proof["outcome"] == ("failed" if outcome == "failed" else "succeeded")
        retained_documents(root, proof)
        assert_final_database(root, architecture, proof)
        status_before = (root / "var/lib/dpkg/status").read_bytes()
        evidence_before = {
            str(path.relative_to(root)): path.read_bytes()
            for path in (root / NAMESPACE).rglob("*") if path.is_file()
        }
        verification = {
            "lock_path": "/fixture/lock.json",
            "lock_sha256": list(bytes.fromhex(projected_lock["digest_sha256"])),
            "state": "released" if outcome == "success" else "pending",
            "outcome": "failed" if outcome == "failed" else "succeeded",
        }
        if outcome == "success":
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
                **verification, "review": "transfer", "expected_error": "OperationalVerificationFailure",
            })
            m.write(fixture / "owner.json", (fixture / "owner.json.review-owner").read_bytes())
            assert document(fixture / "owner.json")["version"] == 2
            evidence_before = {
                str(path.relative_to(root)): path.read_bytes()
                for path in (root / NAMESPACE).rglob("*") if path.is_file()
            }
        for _ in range(2):
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification=verification)
        for invalid in (
            {"backend": "legacy_dpkg"},
            {"lock_version": 1},
            {"lock_schema": "https://debz.dev/schema/exact-closure-lock-v1"},
            {"lock_sha256": [0] * 32},
            {"outcome": "succeeded" if outcome == "failed" else "failed"},
        ):
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
                **verification, **invalid, "expected_error": "OperationalVerificationFailure",
            })
        for changed in ("policy", "selectors", "architecture"):
            changed_request = projected_request("recover")
            if changed == "policy":
                changed_request["options"]["recommends"] = True
            elif changed == "selectors":
                changed_request["selectors"] = [{"name": "different-package"}]
            else:
                changed_request["options"]["architecture"] = "arm64" if architecture == "amd64" else "amd64"
            projected_run("recover", workflow=changed_request, owner_evidence="/fixture/owner.json",
                          owned_verification={**verification, "expected_error": "OperationalVerificationFailure"})
        for damaged in (
            fixture / "lock.json",
            root / NAMESPACE / "native-transaction-provenance-v1.json",
            root / "var/lib/dpkg/status",
        ):
            original = damaged.read_bytes()
            try:
                damaged.write_bytes(b"{}\n")
                projected_run("recover", owner_evidence="/fixture/owner.json",
                              owned_verification={**verification, "expected_error": "OperationalVerificationFailure"})
            finally:
                damaged.write_bytes(original)
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "publish", "expected_error": "OperationalVerificationFailure",
        })
        reviewed_evidence = {
            str(path.relative_to(root)): path.read_bytes()
            for path in (root / NAMESPACE).rglob("*") if path.is_file()
        }
        if verification["state"] == "pending":
            refused = projected_run(
                "recover", owner_evidence="/fixture/owner.json",
                acknowledgment="recovery", expected_exit=8,
            )
            assert not refused["changed"]
            assert reviewed_evidence == {
                str(path.relative_to(root)): path.read_bytes()
                for path in (root / NAMESPACE).rglob("*") if path.is_file()
            }, "unconfirmed acknowledgment changed native evidence beneath an active review"
        for _ in range(2):
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
                **verification, "review": "authorized",
            })
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "foreign", "expected_error": "OperationalVerificationFailure",
        })
        assert reviewed_evidence == {
            str(path.relative_to(root)): path.read_bytes()
            for path in (root / NAMESPACE).rglob("*") if path.is_file()
        }, "review-bound verification changed lower evidence"
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "clear",
        })
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "publish_stale", "expected_error": "OperationalVerificationFailure",
        })
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "authorized", "expected_error": "OperationalVerificationFailure",
        })
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "clear",
        })
        assert (root / "var/lib/dpkg/status").read_bytes() == status_before
        assert evidence_before == {
            str(path.relative_to(root)): path.read_bytes()
            for path in (root / NAMESPACE).rglob("*") if path.is_file()
        }, "projected verification changed retained evidence"
        original_owner = (fixture / "owner.json").read_bytes()
        review_arguments = {"review_evidence": "/fixture/owner.json.review-claim"}
        for generation in (2, 3):
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
                **verification, "review": "publish", "review_generation": generation,
                "expected_error": "OperationalVerificationFailure",
            })
            projected_run(
                "recover", owner_evidence="/fixture/owner.json", **review_arguments,
                acknowledgment="ownership" if outcome == "success" else "recovery",
                completion_crash=(
                    "before_ownership_marker_clear" if outcome == "success"
                    else "before_deferred_acknowledged"
                ),
            )
            assert (root / owner_path).read_bytes() == original_owner, (
                "interrupted reviewed acknowledgment changed the retained native owner"
            )
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification=verification)
            assert (root / "var/lib/dpkg/status").read_bytes() == status_before
        projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
            **verification, "review": "publish", "review_generation": 4,
            "expected_error": "OperationalVerificationFailure",
        })
        if outcome in ("recovered", "failed"):
            projected_run(
                "recover", owner_evidence="/fixture/owner.json", **review_arguments,
                acknowledgment="recovery", completion_crash="after_deferred_acknowledged",
            )
            acknowledged_owner = (root / owner_path).read_bytes()
            assert document(root / owner_path)["state"] == "acknowledged"
            assert document(fixture / "owner.json")["state"] == "pending"
            projected_run("recover", owner_evidence="/fixture/owner.json", owned_verification={
                **verification, "expected_error": "OperationalVerificationFailure",
            })
            terminal_review = {
                "lock_path": "/fixture/lock.json",
                "lock_sha256": verification["lock_sha256"], "generation": 5,
            }
            projected_run(
                "recover", owner_evidence="/fixture/owner.json", **review_arguments,
                acknowledgment="recovery", prepare_acknowledged_review=terminal_review,
                completion_crash="after_deferred_record_cleared",
            )
            assert not (root / OPERATION).exists()
            assert (root / owner_path).read_bytes() == acknowledged_owner
            assert (fixture / "owner.json").read_bytes() == original_owner
            assert (root / "var/lib/dpkg/status").read_bytes() == status_before
            terminal_review["generation"] = 6
            projected_run(
                "recover", owner_evidence="/fixture/owner.json", **review_arguments,
                acknowledgment="recovery", prepare_acknowledged_review=terminal_review,
            )
            review_arguments = {}
        for _ in range(2):
            projected_run("recover", owner_evidence="/fixture/owner.json",
                          acknowledgment="ownership" if outcome == "success" else "recovery",
                          **review_arguments)
        for path in (OPERATION, INTENT, owner_path):
            assert not (root / path).exists(), path
        shared_receipt = root / NAMESPACE / "native-transaction-provenance-v1.json"
        shared_receipt.write_bytes(b"{}\n")
        completion_path = root / NAMESPACE / "root-operation-completion-v1.json"
        completion_bytes = completion_path.read_bytes()
        if outcome != "success":
            completion_path.unlink()
        cleared_arguments = {
            "owner_evidence": "/fixture/owner.json",
            "review_evidence": "/fixture/owner.json.review-claim",
            "acknowledgment": "ownership" if outcome == "success" else "recovery",
        }
        cleared_review = {
            "lock_path": "/fixture/lock.json", "lock_sha256": verification["lock_sha256"],
            "receipt_sha256": list(bytes.fromhex(proof["digest_sha256"])), "generation": 7,
        }
        for index, boundary in enumerate(
            ("before_ownership_marker_clear", "after_ownership_marker_clear")
            if outcome == "success" else
            ("before_deferred_marker_cleared", "after_deferred_marker_cleared")
        ):
            setup = {"prepare_cleared_review": cleared_review} if index == 0 else {}
            projected_run("recover", **cleared_arguments, **setup,
                          completion_crash=boundary)
            assert not (root / OPERATION).exists()
            if index == 0:
                reviewed_bytes = (root / owner_path).read_bytes()
                if outcome == "success":
                    completion_path.unlink()
                else:
                    completion_path.write_bytes(completion_bytes)
                projected_run("recover", **cleared_arguments, expected_exit=8)
                assert (root / owner_path).read_bytes() == reviewed_bytes
                if outcome == "success":
                    completion_path.write_bytes(completion_bytes)
                else:
                    completion_path.unlink()
                orphan = root / INTENT
                orphan.write_bytes(b"{}\n")
                projected_run("recover", **cleared_arguments, expected_exit=8)
                assert (root / owner_path).read_bytes() == reviewed_bytes
                assert orphan.read_bytes() == b"{}\n"
                orphan.unlink()
        cleared_review["generation"] += 1
        assert not (root / owner_path).exists(), "cleared review fabricated replacement ownership"
        projected_run("recover", **cleared_arguments, expected_exit=8)
        projected_run("recover", **cleared_arguments, prepare_cleared_review=cleared_review)
        assert not (root / owner_path).exists()
        assert shared_receipt.read_bytes() == b"{}\n"
        assert (fixture / "owner.json").read_bytes() == original_owner
        assert (root / "var/lib/dpkg/status").read_bytes() == status_before
        assert not (fixture / "unused-cache").exists()
        assert not (fixture / "unused-state").exists()
        print(f"workflow-projected-{outcome}: scoped execution, fresh-owner verification, and acknowledgment passed", flush=True)


def projection_inside(root: Path, workflow: bool = False, repository: bool = False,
                      repository_execution: bool = False, repository_cli: bool = False) -> None:
    if sum((workflow, repository, repository_execution, repository_cli)) > 1:
        raise ValueError("projection fixtures are mutually exclusive")
    root = root.resolve(strict=True)
    if (
        os.getpid() != 1 or os.geteuid() != 0
        or root.name not in ("root", "native")
        or root.parent.parent.parent != (ROOT / ".tmp").resolve()
        or (root / ".debz-native-projection").read_text() != "debz native projection fixture v1\n"
    ):
        raise RuntimeError("projection entry requires a disposable root and private PID namespace")
    subprocess.run(["mount", "--bind", str(root), str(root)], check=True, timeout=10)
    subprocess.run(["mount", "-t", "proc", "proc", str(root / "proc")], check=True, timeout=10)
    os.chroot(root)
    os.chdir("/")
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
        "TMPDIR": "/tmp", "XDG_CACHE_HOME": "/tmp/.cache",
    }
    if repository_cli:
        repository_cli_inside(environment)
        return
    environment.update(
        {"DEBZ_NATIVE_REPOSITORY_EXECUTION_FIXTURE": "1"} if repository_execution
        else {"DEBZ_NATIVE_REPOSITORY_PROJECTION_FIXTURE": "1"} if repository
        else {"DEBZ_NATIVE_WORKFLOW_REQUEST": "/fixture/request.json"} if workflow
        else {"DEBZ_NATIVE_PROJECTION_FIXTURE": "1"}
    )
    os.execve("/fixture/native-test", ["/fixture/native-test"], environment)


def projected_process(root: Path, workflow: bool = False, repository: bool = False,
                      repository_execution: bool = False, repository_cli: bool = False) -> subprocess.CompletedProcess:
    if sum((workflow, repository, repository_execution, repository_cli)) > 1:
        raise ValueError("projection fixtures are mutually exclusive")
    return subprocess.run(
        [
            "unshare", "--mount", "--pid", "--fork",
            sys.executable, str(Path(__file__).resolve()),
            "--repository-cli-inside" if repository_cli
            else "--repository-execution-inside" if repository_execution
            else "--repository-projection-inside" if repository
            else "--projected-workflow-inside" if workflow else "--projection-inside", str(root),
        ],
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
            "TMPDIR": str(root.parent), "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120, check=False,
    )


def repository_cli_inside(environment: dict[str, str]) -> None:
    arguments = json.loads(Path("/fixture/cli-arguments.json").read_text())
    case = Path("/fixture/cli-case").read_text()
    calls = 1 if case in ("lock_wait", "lock_signal", "unsafe_runtime", "deadline") else 3
    step = int(Path("/fixture/cli-step").read_text())
    assert 0 <= step < calls, (case, step)
    deadline_seconds = int(arguments[arguments.index("--deadline-ms") + 1]) / 1000
    watchdog_seconds = deadline_seconds + 5
    assert 0 < watchdog_seconds < 120, watchdog_seconds
    release = Path("/fixture/repository/dists/debian-stable/InRelease")
    backup = release.with_name("InRelease.saved")
    lock = None
    if case in ("lock_wait", "lock_signal"):
        Path("/run/debz").mkdir(mode=0o700)
        lock = Path("/run/debz/live-root.lock").open("wb")
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
    elif case == "unsafe_runtime":
        Path("/run/debz").mkdir(mode=0o700)
        Path("/run/debz").chmod(0o777)
    try:
        started = time.monotonic()
        process = subprocess.Popen(
            ["/fixture/debz", *arguments], env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            if case == "lock_signal":
                until = time.monotonic() + 10
                descriptors = Path(f"/proc/{process.pid}/fd")
                while True:
                    found = False
                    for path in descriptors.iterdir():
                        try:
                            target = path.readlink()
                        except FileNotFoundError:
                            continue
                        found |= target == Path("/run/debz/live-root.lock")
                    if found:
                        break
                    if process.poll() is not None or time.monotonic() >= until:
                        raise AssertionError("native CLI did not enter the projection lock wait")
                    time.sleep(0.01)
                process.send_signal(signal.SIGTERM)
            if step == 0 and case in ("refresh_failure", "signal"):
                until = started + deadline_seconds
                while not Path("/fixture/postinst-entered").exists():
                    if process.poll() is not None or time.monotonic() >= until:
                        raise AssertionError("native CLI did not reach the actual package script")
                    time.sleep(0.01)
                if case == "refresh_failure":
                    release.rename(backup)
                    Path("/fixture/finish-script").touch()
                else:
                    process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=max(0, watchdog_seconds - (time.monotonic() - started)))
        except subprocess.TimeoutExpired as error:
            states = [
                (str(path), json.loads(path.read_bytes())["phase"])
                for path in Path("/var/lib/debz/repository/operations").glob("*/repo-add-state-v1.json")
            ]
            raise AssertionError(
                f"native CLI {case} invocation {step} exceeded its {watchdog_seconds}s watchdog; "
                f"exit={process.poll()}, states={states}, script_entered={Path('/fixture/postinst-entered').exists()}"
            ) from error
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        elapsed = time.monotonic() - started
        Path(f"/fixture/cli-{step}.json").write_bytes(stdout)
        Path(f"/fixture/cli-{step}.stderr").write_bytes(stderr)
        Path(f"/fixture/cli-{step}.exit").write_text(str(process.returncode))
        Path(f"/fixture/cli-{step}.elapsed").write_text(str(elapsed))
        assert stderr == b"", (process.returncode, stderr)
        value = json.loads(stdout)
        assert value["exit_status"] == process.returncode, value
        if case in ("lock_wait", "lock_signal"):
            assert elapsed < 3, elapsed
        if case == "deadline":
            assert elapsed < 8, elapsed
        if step == 0 and calls > 1:
            # Recovery/history must use retained inputs, not fresh acquisition.
            Path("/fixture/descriptor.deb").unlink()
            if case == "refresh_failure":
                backup.rename(release)
            if case == "signal":
                Path("/fixture/finish-script").touch()
    finally:
        if lock is not None:
            lock.close()


def exercise_repository_cli(cli: Path, workspace: Path, architecture: str, environment: dict[str, str]) -> None:
    network_root = workspace / "repository-cli-network/root/fixture"
    network_root.mkdir(parents=True)
    port_file = workspace / "native-cli-http.port"
    request_log = workspace / "native-cli-http.requests"
    with (workspace / "native-cli-http.stderr").open("wb") as stderr:
        server = subprocess.Popen(
            [sys.executable, str(ROOT / "tools/http-fixture-server.py"),
             "--root", str(network_root), "--port-file", str(port_file),
             "--request-log", str(request_log)],
            env={**environment, "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
        )
        try:
            until = time.monotonic() + 10
            while not port_file.exists() or port_file.stat().st_size == 0:
                if server.poll() is not None or time.monotonic() >= until:
                    raise AssertionError("native CLI fixture server did not start")
                time.sleep(0.01)
            url = f"http://127.0.0.1:{int(port_file.read_text())}"
            local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with local_http.open(url + "/", timeout=5) as response:
                assert response.status == 200
                response.read(4096)
            repository_cli_cases(cli, workspace, architecture, environment, url)
            requests = request_log.read_text().splitlines()
            assert requests.count("/descriptor.deb") == 1, requests
            assert any(path.startswith("/bootstrap-repository/") for path in requests), requests
            assert any(path.startswith("/repository/") for path in requests), requests
            assert "native-query-secret" not in request_log.read_text()
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)


def repository_cli_cases(
    cli: Path, workspace: Path, architecture: str, environment: dict[str, str], network_url: str,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "debz_native_cli_repository", ROOT / "tools/generate-integration-repository.py",
    )
    assert spec and spec.loader
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    repository = workspace / "cli-repository"
    generator.write_repository(repository, "debian-stable", architecture)
    keyring = (repository / "fixture-keyring.gpg").read_bytes()
    for case in ("success", "no_refresh", "unchanged", "unchanged_no_refresh",
                 "known_failure", "refresh_failure", "signal", "lock_wait", "lock_signal",
                 "unsafe_runtime", "deadline", "network"):
        root = workspace / f"repository-cli-{case}" / "root"
        m.make_root(root, architecture)
        for directory in ("proc", "run", "tmp", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        (root / ".debz-native-projection").write_text("debz native projection fixture v1\n")
        lifecycle.runtime.copy_program(root, cli, "/fixture/debz")
        lifecycle.runtime.copy_program(root, Path("/bin/sh"), "/bin/sh")
        lifecycle.runtime.copy_program(root, Path("/usr/bin/dpkg-trigger"), "/" + triggers.HELPER.as_posix())
        helper = root / triggers.HELPER
        helper_bytes, helper_inode = helper.read_bytes(), helper.stat().st_ino
        shutil.copytree(repository, root / "fixture/repository")
        shutil.copytree(repository, root / "fixture/bootstrap-repository")
        transport = network_url if case == "network" else "file:///fixture"
        m.write(root / "usr/share/keyrings/bootstrap.gpg", keyring)
        m.write(root / "etc/apt/sources.list.d/bootstrap.sources", (
            f"Types: deb\nURIs: {transport}/bootstrap-repository\nSuites: debian-stable\n"
            f"Components: main\nArchitectures: {architecture}\n"
            "Signed-By: /usr/share/keyrings/bootstrap.gpg\n"
        ).encode())
        postinst = b"#!/bin/sh\nprintf 'postinst\\n' >>/repository-trace\n"
        if case == "known_failure":
            postinst += b"exit 42\n"
        if case in ("refresh_failure", "signal", "deadline"):
            lifecycle.runtime.copy_program(root, Path("/bin/sleep"), "/bin/sleep")
            postinst += (
                b"printf entered >/fixture/postinst-entered\n"
                b"while [ ! -f /fixture/finish-script ]; do /bin/sleep 0.02; done\n"
            )
        descriptor = root / "fixture/descriptor.deb"
        generator.write_repository_descriptor(
            descriptor, transport + "/repository", "debian-stable", architecture, keyring,
            scripts={"preinst": b"#!/bin/sh\nprintf 'preinst\\n' >>/repository-trace\n", "postinst": postinst},
        )
        unchanged = case in ("unchanged", "unchanged_no_refresh")
        no_refresh = case in ("no_refresh", "unchanged_no_refresh")
        if unchanged:
            m.run(
                [*m.reference_command(root), "--install",
                 str(repository / "pool/main/ca-certificates_20240203_all.deb"), str(descriptor)],
                environment, root.parent / "seed.log",
            )
            status = root / "var/lib/dpkg/status"
            text = status.read_text()
            assert "Package: packages-microsoft-prod\nStatus: install ok installed\n" in text
            status.write_text(text.replace(
                "Package: packages-microsoft-prod\nStatus: install ok installed\n",
                "Package: packages-microsoft-prod\nStatus: hold ok installed\n",
            ))
            (root / "repository-trace").unlink()
        original_status = (root / "var/lib/dpkg/status").read_bytes()
        arguments = [
            "repo", "add", "--url", transport + "/descriptor.deb" + ("?token=native-query-secret" if case == "network" else ""),
            "--sha256", hashlib.sha256(descriptor.read_bytes()).hexdigest(),
            "--root", "/", "--architecture", architecture,
            "--transaction-backend", "native", "--json",
            "--deadline-ms", "75" if case == "lock_wait" else "3000" if case == "deadline" else "60000",
        ]
        if no_refresh:
            arguments.append("--no-refresh")
        if case in ("lock_wait", "deadline"):
            arguments += ["--connect-timeout-ms", "50", "--read-timeout-ms", "50"]
        (root / "fixture/cli-arguments.json").write_text(json.dumps(arguments))
        (root / "fixture/cli-case").write_text(case)
        calls = 1 if case in ("lock_wait", "lock_signal", "unsafe_runtime", "deadline") else 3
        for step in range(calls):
            (root / "fixture/cli-step").write_text(str(step))
            result = projected_process(root, repository_cli=True)
            assert result.returncode == 0, (case, step, result.returncode, result.stdout, result.stderr)
            elapsed = float((root / f"fixture/cli-{step}.elapsed").read_text())
            print(f"native-repository-cli-{case}[{step}]: {elapsed:.2f}s", flush=True)
        responses = [document(root / f"fixture/cli-{step}.json") for step in range(calls)]
        for step, response in enumerate(responses):
            validator("repository-operation-result-v1").validate(response)
            payload = dict(response)
            digest = payload.pop("digest_sha256")
            assert hashlib.sha256(canonical(payload)).hexdigest() == digest
            assert (root / f"fixture/cli-{step}.json").read_bytes() == canonical(response)
        first = responses[0]
        if case in ("lock_wait", "lock_signal", "unsafe_runtime", "deadline", "signal"):
            assert all(value["exit_status"] != 0 for value in responses), responses
            if case in ("lock_wait", "lock_signal", "unsafe_runtime"):
                assert not (root / OPERATION).exists()
                assert (root / "var/lib/dpkg/status").read_bytes() == original_status
            if case in ("lock_wait", "deadline"):
                assert first["diagnostics"][0]["id"] == "resource_limit_exceeded", first
            if case == "signal":
                assert (root / OPERATION).exists(), "interrupted script lost its native caller"
                assert all(value["exit_status"] == 9 for value in responses), responses
                assert responses[-1]["summary"] == "script_outcome_unknown", responses[-1]
                assert (root / "repository-trace").read_text() == "preinst\npostinst\n"
        else:
            if case == "known_failure":
                assert all(value["exit_status"] == 7 for value in responses), responses
            else:
                assert responses[-1]["exit_status"] == responses[1]["exit_status"] == 0, responses
                assert first["exit_status"] == (8 if case == "refresh_failure" else 0), first
                assert responses[-1]["installed"] and not responses[-1]["changed"]
                assert responses[-1]["refreshed_phase"] == ("skipped" if no_refresh else "complete")
            assert not (root / OPERATION).exists(), case
            assert not (root / INTENT).exists() and not (root / PROGRESS).exists()
            evidence = root / responses[-1]["paths"]["provenance"].lstrip("/")
            if unchanged:
                assert evidence.name == "native-repository-unchanged-v1.json"
                proof = document(evidence)
                assert proof["receipt"] is None and proof["action_count"] == 0 and not proof["changed"]
                assert not first["changed"] and first["installed"]
                assert (root / "var/lib/dpkg/status").read_bytes() == original_status
                assert not (root / "repository-trace").exists()
            else:
                proof = document(evidence, 16 * 1024 * 1024)
                validator(PROVENANCE_SCHEMA).validate(proof)
                assert_digest(proof, PROVENANCE_SCHEMA)
                assert (root / "repository-trace").read_text() == "preinst\npostinst\n"
        mountpoint = root / "run/debz/system-root"
        assert not mountpoint.exists() or not list(mountpoint.iterdir()), "public native projection leaked"
        assert helper.read_bytes() == helper_bytes and helper.stat().st_ino == helper_inode
        assert not (root / "usr/bin/dpkg").exists() and not (root / "usr/bin/dpkg-deb").exists()
        if case == "network":
            for directory in ("var/lib/debz", "var/cache/debz", "etc/apt"):
                for path in (root / directory).rglob("*"):
                    if path.is_file():
                        assert b"native-query-secret" not in path.read_bytes(), path
        print(f"native-repository-cli-{case}: actual public supervised CLI passed", flush=True)


def exercise_projection(executable: Path, workspace: Path) -> None:
    root = workspace / "projection" / "root"
    for directory in ("proc", "run", "tmp", "var/lib/debz"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / ".debz-native-projection").write_text("debz native projection fixture v1\n")
    lock = root / NAMESPACE / "root-operation.lock"
    lock.write_bytes(b"")
    lifecycle.runtime.copy_program(root, executable, "/fixture/native-test")
    result = projected_process(root)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert b"native_transaction_result.test.projected root external fixture...OK" in result.stderr, result.stderr
    assert b"apt_system_orchestrator.test.projected native dispatch external fixture...OK" in result.stderr, result.stderr
    assert lock.read_bytes() == b""
    assert list((root / NAMESPACE).iterdir()) == [lock], "read-only verification created root evidence"
    assert not list((root / "run/debz/system-root").iterdir()), "private projection leaked"
    print("native-projection: exact invocation-bound read-only authority and refusal passed", flush=True)


def exercise_repository_projection(executable: Path, workspace: Path, architecture: str) -> None:
    root = workspace / "repository-projection" / "root"
    m.make_root(root, architecture)
    for directory in ("proc", "run", "tmp"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / ".debz-native-projection").write_text("debz native projection fixture v1\n")
    lifecycle.runtime.copy_program(root, executable, "/fixture/native-test")
    result = projected_process(root, repository=True)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert (root / "fixture/repository-projection-complete").read_text() == "native repository projection fixture complete\n"
    assert set((root / NAMESPACE).iterdir()) == {root / NAMESPACE / "root-operation.lock"}
    assert not list((root / "run/debz/system-root").iterdir()), "repository projection leaked"
    assert (root / "usr/share/held").read_bytes() == b"untouched\n"
    assert "Status: hold ok installed\n" in (root / "var/lib/dpkg/status").read_text()
    assert not (root / "var/lib/dpkg/info/packages-microsoft-prod.list").exists()
    print("native-repository-projection: scoped caller preparation, adoption, and cleanup passed", flush=True)


def exercise_repository_execution(executable: Path, workspace: Path, architecture: str) -> None:
    cases = [(case, False) for case in ("success", "known_failure", "interrupted", "missing_helper", "unchanged", "diagnostic", "expired")]
    cases += [(case, True) for case in ("success", "known_failure", "interrupted", "unchanged")]
    for case, resume in cases:
        name = f"repository-{'resume' if resume else 'execution'}-{case}"
        root = workspace / name / "root"
        m.make_root(root, architecture)
        for directory in ("proc", "run", "tmp", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        (root / ".debz-native-projection").write_text("debz native projection fixture v1\n")
        lifecycle.runtime.copy_program(root, executable, "/fixture/native-test")
        (root / "fixture/repository-execution-case").write_text(case)
        if resume:
            (root / "fixture/repository-resume").touch()
        terminal = case in ("success", "known_failure", "interrupted")
        helper_target = root / triggers.HELPER
        if terminal:
            lifecycle.runtime.copy_program(root, Path("/bin/sh"), "/bin/sh")
            lifecycle.runtime.copy_program(root, Path("/usr/bin/dpkg-trigger"), "/" + triggers.HELPER.as_posix())
            helper_bytes, helper_inode = helper_target.read_bytes(), helper_target.stat().st_ino
        result = projected_process(root, repository_execution=True)
        assert result.returncode == 0, (name, result.returncode, result.stdout, result.stderr)
        assert (root / "fixture/repository-execution-complete").read_text() == case
        assert not list((root / "run/debz/system-root").iterdir()), "repository execution projection leaked"
        assert not list((root / "fixture/package-cache/packages-v1/objects").iterdir()), "repository recovery reused CAS inputs"
        assert not (root / OPERATION).exists(), "repository completion did not clear its caller"
        if terminal:
            caller = document(root / "fixture/repository-pending-caller.json")
            assert caller["outcome"] == "pending"
            assert caller["surface"] == "repository_bootstrap" and caller["operation"] == "add"
            proof = document(root / "fixture/repository-native-receipt.json", 16 * 1024 * 1024)
            validator(PROVENANCE_SCHEMA).validate(proof)
            assert_digest(proof, PROVENANCE_SCHEMA)
            retained_logical = (root / "fixture/repository-retained-receipt-path").read_text()
            assert retained_logical.startswith("/var/lib/debz/repository/operations/")
            retained_path = root / retained_logical.lstrip("/")
            assert retained_path.name == "native-transaction-provenance-v1.json"
            assert retained_path.parent.parent == root / NAMESPACE / "repository/operations"
            assert len(retained_path.parent.name) == 64 and all(value in "0123456789abcdef" for value in retained_path.parent.name)
            assert retained_path.read_bytes() == (root / "fixture/repository-native-receipt.json").read_bytes()
            assert stat.S_IMODE(retained_path.stat().st_mode) == 0o600
            assert not (retained_path.parent / "transaction-result-v2.json").exists()
            checkpoint_path = retained_path.parent / "repo-add-state-v1.json"
            checkpoint = document(checkpoint_path)
            validator("repository-add-state-v1").validate(checkpoint)
            payload = dict(checkpoint)
            digest = payload.pop("digest_sha256")
            assert hashlib.sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == digest
            original = document(root / "fixture/repository-original-locked-state.json")
            for field in ("root", "architecture", "no_refresh", "descriptor", "managed_files",
                          "plan_path", "plan_sha256", "exact_lock_path"):
                assert checkpoint[field] == original[field]
            assert checkpoint["plan_sha256"] == caller["plan_sha256"]
            assert checkpoint["phase"] == ("failed" if case == "known_failure" else "complete")
            assert checkpoint["installed"] == (case != "known_failure")
            assert checkpoint["diagnostic_id"] == ("transaction_failed" if case == "known_failure" else None)
            assert checkpoint["provenance_path"] == retained_logical
            assert checkpoint["refreshed"] == (case == "success")
            if case == "known_failure":
                assert checkpoint["manifest_path"] is None
                assert not (retained_path.parent / "apt-config-snapshot-v1.json").exists()
            else:
                manifest_path = root / checkpoint["manifest_path"].lstrip("/")
                assert manifest_path == retained_path.parent / "apt-config-snapshot-v1.json"
                manifest = document(manifest_path)
                validator("apt-config-snapshot-v1").validate(manifest)
                assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
                for expected in checkpoint["managed_files"]:
                    installed_path = root / expected["logical_path"].lstrip("/")
                    assert installed_path.stat().st_size == expected["size"]
                    assert hashlib.sha256(installed_path.read_bytes()).hexdigest() == expected["sha256"]
                    imported = next(value for value in manifest["sources"] + manifest["keyrings"]
                                    if value["logical_path"] == expected["logical_path"])
                    assert imported["sha256"] == expected["sha256"]
                if case == "interrupted":
                    assert checkpoint["no_refresh"]
                    assert not (root / "var/cache/debz/metadata-v1").exists()
                else:
                    assert not checkpoint["no_refresh"]
                    assert (root / "var/cache/debz/metadata-v1").is_dir()
            assert stat.S_IMODE(checkpoint_path.stat().st_mode) == 0o600
            completion_path = root / NAMESPACE / "root-operation-completion-v1.json"
            local_completion = retained_path.parent / completion_path.name
            assert completion_path.read_bytes() == local_completion.read_bytes()
            assert stat.S_IMODE(completion_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(local_completion.stat().st_mode) == 0o600
            completion = document(completion_path)
            validator("root-operation-completion-v1").validate(completion)
            completion_payload = dict(completion)
            completion_digest = completion_payload.pop("digest_sha256")
            assert hashlib.sha256(json.dumps(completion_payload, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == completion_digest
            completed_caller = document(root / "fixture/repository-completed-caller.json")
            assert completed_caller["state"] == "completed" and completed_caller["provenance"] == "published"
            assert completed_caller["provenance_sha256"] == completion_digest
            assert completion["outcome"] == ("failed_after_mutation" if case == "known_failure" else "succeeded")
            for field in ("attempt_id", "request_sha256", "policy_sha256", "program_sha256",
                          "authorization_sha256", "exact_lock", "plan_sha256", "foreign_architectures"):
                assert completed_caller[field] == completion[field] == caller[field]
            assert completion["record_generation"] + 1 == completed_caller["generation"]
            if resume:
                historical_caller = document(root / "fixture/repository-history-caller.json")
                assert historical_caller["attempt_id"] != caller["attempt_id"]
                assert not historical_caller["mutation_started"] and historical_caller["program_sha256"] is None
                assert historical_caller["outcome"] == "pending"
                for field in ("request_sha256", "policy_sha256", "target_architecture", "foreign_architectures"):
                    assert historical_caller[field] == caller[field]
                if case == "success":
                    preserved = json.loads((root / "fixture/repository-history-preserved.json").read_text())
                    assert len(preserved) == 8 and len({value["path"] for value in preserved}) == 8
                    for value in preserved:
                        path = root / value["path"]
                        assert path.stat().st_ino == value["inode"]
                        assert list(hashlib.sha256(path.read_bytes()).digest()) == value["sha256"]
            assert completion["transaction_provenance"]["schema"] == proof["schema"]
            assert completion["transaction_provenance"]["document_sha256"] == proof["digest_sha256"]
            assert completion["journal"]["status"] == "absent" and completion["journal"]["document_sha256"] is None
            discharge = hashlib.sha256(b"debz-native-repository-completion-request-v1\0")
            for field in ("attempt_id", "request_sha256", "policy_sha256"):
                discharge.update(bytes.fromhex(caller[field]))
            discharge.update(proof["digest_sha256"].encode())
            discharge.update(bytes.fromhex(checkpoint["digest_sha256"]))
            discharge.update(bytes([case != "known_failure"]))
            if case != "known_failure":
                discharge.update(bytes.fromhex(manifest["digest_sha256"]))
            assert completion["discharge"] == {
                "surface": "repository_bootstrap", "operation": "add", "request_sha256": discharge.hexdigest(),
            }
            assert not (root / INTENT).exists() and not (root / PROGRESS).exists()
            assert not (root / NAMESPACE / "native-recovery-v1").exists()
            assert not list((root / NAMESPACE).glob("native-recovery-v1-blob-*"))
            retained = retained_documents(root, proof)
            execution = retained["execution_request"][0]
            for field in ("request_sha256", "policy_sha256"):
                assert execution["execution"]["caller"][field] == caller[field]
            assert execution["execution"]["caller"]["attempt_id"] == caller["attempt_id"]
            scripts = retained["script_outcome"]
            assert len(scripts) == 2
            for script in scripts:
                assert_output_streams(script)
                expected_script = f"#!/bin/sh\nprintf '{script['kind']}\\n' >> /repository-trace\n"
                if script["kind"] == "postinst" and case == "known_failure":
                    expected_script += "exit 12\n"
                assert script["script_sha256"] == hashlib.sha256(expected_script.encode()).hexdigest()
                assert script["spawned"] and script["disposition"] == "exited"
                assert script["exit_code"] == (12 if script["kind"] == "postinst" and case == "known_failure" else 0)
            assert_helper_invocations(execution, retained["program"][0], scripts)
            assert (root / "repository-trace").read_text() == "preinst\npostinst\n"
            assert helper_target.read_bytes() == helper_bytes and helper_target.stat().st_ino == helper_inode
            status = (root / "var/lib/dpkg/status").read_text()
            package = next(value for value in status.split("\n\n") if value.startswith("Package: debz-native-repository\n"))
            assert ("Status: install ok half-configured\n" if case == "known_failure" else "Status: install ok installed\n") in package
        else:
            assert not (root / OPERATION).exists() and not (root / INTENT).exists()
            assert not helper_target.exists() and not (root / NAMESPACE / "native-helper-cache-v1").exists()
            assert not (root / "fixture/repository-native-receipt.json").exists()
            assert not (root / "fixture/repository-retained-receipt-path").exists()
            assert not (root / NAMESPACE / "root-operation-completion-v1.json").exists()
            assert not (root / NAMESPACE / "repository").exists()
            assert not (root / "repository-trace").exists()
            assert not (root / "usr/share/doc/debz-native-repository/README").exists()
        assert (root / "usr/share/held").read_bytes() == b"untouched\n"
        print(f"native-{name}: typed outcomes and caller-owned recovery passed", flush=True)

    for no_refresh in (False, True):
        root = workspace / f"repository-unchanged-{no_refresh}" / "root"
        m.make_root(root, architecture)
        for directory in ("proc", "run", "tmp", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        (root / ".debz-native-projection").write_text("debz native projection fixture v1\n")
        lifecycle.runtime.copy_program(root, executable, "/fixture/native-test")
        (root / "fixture/repository-execution-case").write_text("unchanged")
        (root / "fixture/repository-unchanged-bootstrap").write_text("no-refresh" if no_refresh else "refresh")
        result = projected_process(root, repository_execution=True)
        assert result.returncode == 0, (no_refresh, result.returncode, result.stdout, result.stderr)
        assert (root / "fixture/repository-execution-complete").read_text() == "unchanged"
        assert not list((root / "run/debz/system-root").iterdir())
        assert not (root / "fixture/unchanged-descriptor.deb").exists()
        assert not list((root / "fixture/package-cache/packages-v1/objects").iterdir())
        assert (root / "var/lib/dpkg/status").read_bytes() == (root / "fixture/unchanged-original-status").read_bytes()
        assert not (root / "repository-trace").exists()
        for path in (OPERATION, INTENT, PROGRESS, triggers.HELPER,
                     NAMESPACE / "native-transaction-provenance-v1.json",
                     NAMESPACE / "root-operation-completion-v1.json",
                     NAMESPACE / "native-helper-cache-v1"):
            assert not (root / path).exists(), path
        callers = document(root / "fixture/repository-unchanged-caller.json")
        assert callers["outcome"] == "abandoned_before_mutation" and not callers["mutation_started"]
        assert callers["program_sha256"] is None and callers["authorization_sha256"] is None
        operations = list((root / NAMESPACE / "repository/operations").iterdir())
        assert len(operations) == 1
        operation = operations[0]
        state = document(operation / "repo-add-state-v1.json")
        validator("repository-add-state-v1").validate(state)
        assert state["phase"] == "complete" and state["installed"]
        assert state["refreshed"] == (not no_refresh) and state["no_refresh"] == no_refresh
        assert state["provenance_path"].endswith("/native-repository-unchanged-v1.json") and state["diagnostic_id"] is None
        evidence = document(root / state["provenance_path"].lstrip("/"))
        validator("native-repository-unchanged-v1").validate(evidence)
        payload = dict(evidence)
        evidence_digest = payload.pop("digest_sha256")
        assert hashlib.sha256(canonical(payload)).hexdigest() == evidence_digest
        assert evidence["changed"] is False and evidence["receipt"] is None and evidence["action_count"] == 0
        assert evidence["caller_request_sha256"] == callers["request_sha256"]
        assert evidence["caller_policy_sha256"] == callers["policy_sha256"]
        publisher = document(root / "fixture/unchanged-proof-caller.json")
        assert evidence["caller_attempt_id"] == publisher["attempt_id"] != callers["attempt_id"]
        assert publisher["outcome"] == "pending" and not publisher["mutation_started"]
        assert publisher["program_sha256"] is None and publisher["authorization_sha256"] is None
        assert evidence["root_inode"] == root.stat().st_ino
        assert evidence["plan_sha256"] == state["plan_sha256"]
        lock = document(operation / "exact-lock-v2.json")
        assert evidence["exact_lock_sha256"] == lock["digest_sha256"]
        assert evidence["descriptor_sha256"] == state["descriptor"]["sha256"]
        manifest = document(operation / "apt-config-snapshot-v1.json")
        validator("apt-config-snapshot-v1").validate(manifest)
        archive = operation / "native-unchanged-descriptor.deb"
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == state["descriptor"]["sha256"]
        assert stat.S_IMODE(archive.stat().st_mode) == 0o600
        for expected in state["managed_files"]:
            path = root / expected["logical_path"].lstrip("/")
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected["sha256"]
        assert not (operation / "native-transaction-provenance-v1.json").exists()
        assert not (operation / "root-operation-completion-v1.json").exists()
        assert (root / "usr/share/held").read_bytes() == b"untouched\n"
        print(f"native-repository-unchanged-{no_refresh}: genuine no-receipt completion passed", flush=True)

    for case in ("success", "no_refresh", "unchanged", "unchanged_no_refresh",
                 "known_failure", "interrupted", "completion_interrupted",
                 "locked_interrupted", "scope_lost", "refresh_failure", "expired"):
        root = workspace / f"repository-dispatch-{case}" / "root"
        m.make_root(root, architecture)
        for directory in ("proc", "run", "tmp", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        (root / ".debz-native-projection").write_text("debz native projection fixture v1\n")
        lifecycle.runtime.copy_program(root, executable, "/fixture/native-test")
        (root / "fixture/repository-execution-case").write_text("success")
        (root / "fixture/repository-dispatch").write_text(case)
        unchanged = case in ("unchanged", "unchanged_no_refresh")
        no_refresh = case in ("no_refresh", "unchanged_no_refresh")
        if not unchanged:
            lifecycle.runtime.copy_program(root, Path("/bin/sh"), "/bin/sh")
            lifecycle.runtime.copy_program(root, Path("/usr/bin/dpkg-trigger"), "/" + triggers.HELPER.as_posix())
            helper_bytes = (root / triggers.HELPER).read_bytes()
            helper_inode = (root / triggers.HELPER).stat().st_ino
        result = projected_process(root, repository_execution=True)
        assert result.returncode == 0, (case, result.returncode, result.stdout, result.stderr)
        assert (root / "fixture/repository-execution-complete").read_text() == case
        results = [document(root / f"fixture/native-dispatch-{step}.json") for step in range(3)]
        for response in results:
            validator("repository-operation-result-v1").validate(response)
            payload = dict(response)
            digest = payload.pop("digest_sha256")
            assert hashlib.sha256(canonical(payload)).hexdigest() == digest
        first, recovered, repeated = results
        if case == "known_failure":
            assert all(value["exit_status"] == 7 and not value["installed"] for value in results)
        else:
            assert recovered["exit_status"] == repeated["exit_status"] == 0
            assert recovered["installed"] and repeated["installed"] and not repeated["changed"]
            assert repeated["refreshed_phase"] == ("skipped" if no_refresh else "complete")
            assert repeated["refreshed"] == (not no_refresh)
        if case in ("interrupted", "completion_interrupted", "locked_interrupted",
                    "scope_lost", "refresh_failure", "expired"):
            assert first["exit_status"] != 0
        if case == "refresh_failure":
            assert first["exit_status"] == 8 and first["installed"] and first["changed"]
            assert first["diagnostics"][0]["id"] == "refresh_failed"
        assert not (root / OPERATION).exists()
        assert not (root / INTENT).exists() and not (root / PROGRESS).exists()
        assert not list((root / "run/debz/system-root").iterdir())
        assert not list((root / "var/cache/debz/packages-v1/objects").iterdir())
        assert (root / "usr/share/held").read_bytes() == b"untouched\n"
        state_path = root / repeated["paths"]["operation_state"].lstrip("/")
        state = document(state_path)
        validator("repository-add-state-v1").validate(state)
        assert state["phase"] == ("failed" if case == "known_failure" else "complete")
        assert not (state_path.parent / "transaction-result-v2.json").exists()
        evidence_path = root / repeated["paths"]["provenance"].lstrip("/")
        evidence = document(evidence_path, 16 * 1024 * 1024)
        if unchanged:
            assert all(not value["changed"] for value in results)
            assert (root / "var/lib/dpkg/status").read_bytes() == (root / "fixture/dispatch-original-status").read_bytes()
            assert not (root / "repository-trace").exists()
            assert not (root / triggers.HELPER).exists()
            assert not (root / NAMESPACE / "root-operation-completion-v1.json").exists()
            validator("native-repository-unchanged-v1").validate(evidence)
            assert evidence["receipt"] is None and evidence["action_count"] == 0
            lock = document(root / state["exact_lock_path"].lstrip("/"))
            assert len(lock["packages"]) == 1 and lock["packages"][0]["dpkg_selection_hold"]
        else:
            validator(PROVENANCE_SCHEMA).validate(evidence)
            assert_digest(evidence, PROVENANCE_SCHEMA)
            assert evidence["outcome"] == ("failed" if case == "known_failure" else "succeeded")
            assert (root / "repository-trace").read_text() == "preinst\npostinst\n"
            assert (root / triggers.HELPER).read_bytes() == helper_bytes
            assert (root / triggers.HELPER).stat().st_ino == helper_inode
        print(f"native-repository-dispatch-{case}: original request lifecycle and typed results passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", type=Path)
    parser.add_argument("--native-helper", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--reference-dpkg", type=Path)
    parser.add_argument("--core-only", action="store_true")
    parser.add_argument("--deadline-only", action="store_true")
    parser.add_argument("--repository-projection-only", action="store_true")
    parser.add_argument("--repository-execution-only", action="store_true")
    parser.add_argument("--repository-cli-only", action="store_true")
    parser.add_argument("--consumer-parity-only", action="store_true")
    parser.add_argument("--diversions-only", action="store_true")
    parser.add_argument("--result-cli", type=Path)
    arguments = parser.parse_args()
    if sum((arguments.core_only, arguments.deadline_only, arguments.repository_projection_only,
            arguments.repository_execution_only, arguments.repository_cli_only, arguments.consumer_parity_only,
            arguments.diversions_only)) > 1:
        parser.error("native recovery workload selectors are mutually exclusive")
    if os.geteuid() != 0:
        raise RuntimeError("recovery acceptance requires root for actual chroot execution")
    for command in ("dpkg", "dpkg-deb", "dpkg-trigger", "ldd", "unshare", "mount"):
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
    m.REFERENCE_DPKG = m.reference_dpkg.select(arguments.reference_dpkg, architecture, root_accounts=True)
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
            if arguments.diversions_only:
                exercise_diversion_recovery(executable, helper, workspace, environment, architecture)
            elif arguments.consumer_parity_only:
                if result_cli is None:
                    parser.error("consumer parity requires --result-cli")
                exercise_diversion_recovery(executable, helper, workspace, environment, architecture)
                exercise_statoverride_recovery(executable, helper, workspace, environment, architecture)
                exercise_conffile_lifecycle_recovery(executable, helper, workspace, environment, architecture)
                exercise_metadata_recovery(executable, helper, workspace, environment, architecture)
                exercise_literal_path_recovery(executable, helper, workspace, environment, architecture)
                exercise_scriptless_recovery(executable, helper, workspace, environment, architecture)
                exercise_consumer_parity(executable, result_cli, workspace, environment, architecture)
            elif arguments.repository_cli_only:
                if result_cli is None:
                    parser.error("repository CLI acceptance requires --result-cli")
                exercise_repository_cli(result_cli, workspace, architecture, environment)
            elif arguments.repository_execution_only:
                exercise_repository_execution(executable, workspace, architecture)
                if result_cli is None:
                    parser.error("repository execution acceptance requires --result-cli")
                exercise_repository_cli(result_cli, workspace, architecture, environment)
            elif arguments.repository_projection_only:
                exercise_projection(executable, workspace)
                exercise_repository_projection(executable, workspace, architecture)
                exercise_repository_execution(executable, workspace, architecture)
                if result_cli is None:
                    parser.error("repository projection acceptance requires --result-cli")
                exercise_repository_cli(result_cli, workspace, architecture, environment)
            else:
                if not arguments.core_only:
                    exercise_deadlines(executable, helper, workspace, environment, architecture)
                if not arguments.deadline_only:
                    exercise_diversion_recovery(executable, helper, workspace, environment, architecture)
                    exercise_statoverride_recovery(executable, helper, workspace, environment, architecture)
                    exercise_conffile_lifecycle_recovery(executable, helper, workspace, environment, architecture)
                    exercise_metadata_recovery(executable, helper, workspace, environment, architecture)
                    exercise_literal_path_recovery(executable, helper, workspace, environment, architecture)
                    exercise_projection(executable, workspace)
                    if not arguments.core_only:
                        exercise_repository_projection(executable, workspace, architecture)
                        if result_cli is not None:
                            exercise_repository_cli(result_cli, workspace, architecture, environment)
                        exercise(executable, helper, workspace, environment, architecture)
                        exercise_scriptless_recovery(executable, helper, workspace, environment, architecture)
                    exercise_core(executable, helper, workspace, environment, architecture)
                    exercise_workflows(executable, workspace, environment, architecture, result_cli)
                    if not arguments.core_only:
                        if result_cli is None:
                            parser.error("full native acceptance requires --result-cli for consumer parity")
                        exercise_consumer_parity(executable, result_cli, workspace, environment, architecture)
    finally:
        if Path("/var/lib/dpkg/status").read_bytes() != host_status:
            raise AssertionError("host dpkg status changed during recovery acceptance")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] in (
        "--projection-inside", "--projected-workflow-inside", "--repository-projection-inside", "--repository-execution-inside",
        "--repository-cli-inside",
    ):
        projection_inside(
            Path(sys.argv[2]), workflow=sys.argv[1] == "--projected-workflow-inside",
            repository=sys.argv[1] == "--repository-projection-inside",
            repository_execution=sys.argv[1] == "--repository-execution-inside",
            repository_cli=sys.argv[1] == "--repository-cli-inside",
        )
    else:
        raise SystemExit(main())
