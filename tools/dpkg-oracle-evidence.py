#!/usr/bin/env python3
"""Create and verify bounded native dpkg oracle execution evidence."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ID = "https://debz.dev/schema/dpkg-oracle-execution-evidence-v1"
SCHEMA_PATH = ROOT / "schema/dpkg-oracle-execution-evidence-v1.json"
CONFIG_REFERENCE = (
    ROOT / "tools/fixtures/vendor-state/dpkg-config-reference-v1.json"
)
ALTERNATIVES_REFERENCE = (
    ROOT / "tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json"
)
MAXIMUM_OBSERVATION_BYTES = 2 * 1024 * 1024
MAXIMUM_OUTPUT_BYTES = 32 * 1024
MAXIMUM_EVIDENCE_BYTES = 128 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
PRIVATE = (
    re.compile(rb"/home/runner/work/"),
    re.compile(rb"/Users/runner/"),
    re.compile(rb"github_pat_[A-Za-z0-9_]+"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?i)authorization:[^\r\n]+"),
    re.compile(rb"ACTIONS_ID_TOKEN"),
    re.compile(rb"RUNNER_TRACKING_ID"),
)


PREPARE_SPEC = importlib.util.spec_from_file_location(
    "debz_prepare_native_dpkg",
    ROOT / "tools/prepare-native-dpkg.py",
)
assert PREPARE_SPEC and PREPARE_SPEC.loader
prepare = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(prepare)


class EvidenceError(RuntimeError):
    """Execution evidence crossed its bounded contract."""


def canonical_json(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise EvidenceError(f"required evidence input is missing: {path}") from None
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise EvidenceError(f"evidence input must be a regular file: {path}")
    if metadata.st_size > maximum:
        raise EvidenceError(f"evidence input exceeds its byte limit: {path}")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise EvidenceError(f"evidence input changed while reading: {path}")
    return data


def validate_privacy(label: str, data: bytes) -> None:
    for pattern in PRIVATE:
        if pattern.search(data):
            raise EvidenceError(f"{label} contains private runner or credential data")


def canonical_document(path: Path, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path, maximum)
    validate_privacy(str(path), raw)
    document = json.loads(raw)
    if raw != canonical_json(document).encode():
        raise EvidenceError(f"evidence JSON is not canonical: {path}")
    return document, raw


def artifact_binding(path: Path, artifact_root: Path, maximum: int) -> dict[str, Any]:
    resolved_root = artifact_root.resolve()
    resolved = path.resolve()
    if resolved.parent != resolved_root or not SAFE_NAME.fullmatch(resolved.name):
        raise EvidenceError("oracle artifacts must be direct files with safe names")
    raw = read_regular(resolved, maximum)
    validate_privacy(resolved.name, raw)
    return {
        "path": resolved.name,
        "sha256": sha256_bytes(raw),
        "size": len(raw),
    }


def text_output(path: Path) -> dict[str, Any]:
    raw = read_regular(path, MAXIMUM_OUTPUT_BYTES)
    validate_privacy(str(path), raw)
    try:
        text = raw.decode()
    except UnicodeDecodeError as error:
        raise EvidenceError(f"oracle output is not UTF-8: {path}") from error
    return {
        "sha256": sha256_bytes(raw),
        "size": len(raw),
        "text": text,
    }


def validate_clock(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise EvidenceError("invocation clock is not ISO 8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceError("invocation clock must include a UTC offset")


def validate_observation(
    path: Path,
    reference_path: Path,
    architecture: str,
) -> bytes:
    observed, raw = canonical_document(path, MAXIMUM_OBSERVATION_BYTES)
    reference, _ = canonical_document(reference_path, MAXIMUM_OBSERVATION_BYTES)
    expected = reference["observed_behavior"]
    if set(observed) != set(expected):
        raise EvidenceError(f"captured observation shape changed: {path}")
    package_inputs = observed.get("package_inputs")
    if package_inputs is not None and package_inputs.get("architecture") != architecture:
        raise EvidenceError("config observation architecture is not explicit")
    direct = observed.get("direct_dpkg")
    if direct is not None:
        encoded = canonical_json(direct).encode()
        if f'"architecture": "{architecture}"'.encode() not in encoded:
            raise EvidenceError("alternatives observation lacks the requested architecture")
    return raw


def relative_tool_path(path: Path, architecture: str) -> str:
    expected = (
        ROOT
        / ".cache/native-dpkg-reference"
        / prepare.VERSION
        / architecture
        / "usr/bin"
        / path.name
    )
    if path.resolve(strict=True) != expected.resolve(strict=True):
        raise EvidenceError(f"pinned tool is outside its architecture prefix: {path}")
    return expected.relative_to(ROOT).as_posix()


def tool_binding(path: Path, architecture: str, pin: str) -> dict[str, Any]:
    prepare.verify_file(path, pin)
    return {
        "path": relative_tool_path(path, architecture),
        "sha256": pin,
        "size": path.stat().st_size,
        "version": prepare.VERSION,
    }


def receipt_binding(path: Path, architecture: str) -> dict[str, Any]:
    expected = (
        ROOT
        / ".cache/native-dpkg-reference"
        / prepare.VERSION
        / architecture
        / prepare.RECEIPT
    )
    if path.resolve(strict=True) != expected.resolve(strict=True):
        raise EvidenceError("pinned receipt is outside its architecture prefix")
    raw = read_regular(path, 4096)
    return {
        "path": expected.relative_to(ROOT).as_posix(),
        "sha256": sha256_bytes(raw),
        "size": len(raw),
    }


def oracle_record(
    *,
    architecture: str,
    artifact_root: Path,
    observation: Path,
    reference: Path,
    schema: str,
    stdout: Path,
    stderr: Path,
    command: list[str],
) -> dict[str, Any]:
    validate_observation(observation, reference, architecture)
    reference_raw = read_regular(reference, MAXIMUM_OBSERVATION_BYTES)
    return {
        "command": command,
        "exit": 0,
        "observation": artifact_binding(
            observation,
            artifact_root,
            MAXIMUM_OBSERVATION_BYTES,
        ),
        "published_reference": {
            "path": reference.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(reference_raw),
            "size": len(reference_raw),
        },
        "reference_schema": schema,
        "stderr": text_output(stderr),
        "stdout": text_output(stdout),
    }


def create(arguments: argparse.Namespace) -> dict[str, Any]:
    if not COMMIT.fullmatch(arguments.source_commit):
        raise EvidenceError("source commit must be a full lowercase SHA-1")
    validate_clock(arguments.invocation_clock)
    artifact_root = arguments.output.parent.resolve()
    if arguments.output.exists() or arguments.output.is_symlink():
        raise EvidenceError("evidence output already exists")
    if artifact_root.parent != (ROOT / ".tmp").resolve():
        raise EvidenceError("evidence output must be in a directory directly under .tmp")
    receipt = prepare.verify_receipt(arguments.receipt, arguments.architecture)
    receipt_schema = json.loads(read_regular(
        ROOT / "schema/native-dpkg-reference-receipt-v1.json",
        MAXIMUM_EVIDENCE_BYTES,
    ))
    jsonschema.Draft202012Validator(
        receipt_schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(receipt)
    dpkg = tool_binding(
        arguments.dpkg,
        arguments.architecture,
        prepare.PINS[arguments.architecture]["executable"],
    )
    update_alternatives = tool_binding(
        arguments.update_alternatives,
        arguments.architecture,
        prepare.PINS[arguments.architecture]["update_alternatives"],
    )
    prefix = (
        f".cache/native-dpkg-reference/{prepare.VERSION}/"
        f"{arguments.architecture}/usr/bin"
    )
    output_prefix = ".tmp/arm64-dpkg-oracles"
    config_command = [
        "sudo", "-n",
        "/usr/bin/unshare", "--mount", "--propagation", "private",
        "/usr/bin/env", "-i",
        "PATH=/usr/bin:/bin",
        "LANG=C",
        "LC_ALL=C",
        "PYTHONDONTWRITEBYTECODE=1",
        "TMPDIR=$REPOSITORY/.tmp",
        "XDG_CACHE_HOME=$REPOSITORY/.cache",
        "/bin/sh",
        "tools/run-dpkg-oracle-isolated.sh",
        "$REPOSITORY",
        "config",
        arguments.architecture,
        f"$REPOSITORY/{prefix}/dpkg",
        f"$REPOSITORY/{output_prefix}/{arguments.config_observation.name}",
    ]
    alternatives_command = [
        "sudo", "-n",
        "/usr/bin/unshare", "--mount", "--propagation", "private",
        "/usr/bin/env", "-i",
        "PATH=/usr/bin:/bin",
        "LANG=C",
        "LC_ALL=C",
        "PYTHONDONTWRITEBYTECODE=1",
        "TMPDIR=$REPOSITORY/.tmp",
        "XDG_CACHE_HOME=$REPOSITORY/.cache",
        "/bin/sh",
        "tools/run-dpkg-oracle-isolated.sh",
        "$REPOSITORY",
        "alternatives",
        arguments.architecture,
        f"$REPOSITORY/{prefix}/dpkg",
        f"$REPOSITORY/{output_prefix}/{arguments.alternatives_observation.name}",
        f"$REPOSITORY/{prefix}/update-alternatives",
    ]
    evidence = {
        "architecture": arguments.architecture,
        "invocation_clock": arguments.invocation_clock,
        "oracles": {
            "direct_dpkg_config": oracle_record(
                architecture=arguments.architecture,
                artifact_root=artifact_root,
                observation=arguments.config_observation,
                reference=CONFIG_REFERENCE,
                schema="https://debz.dev/schema/dpkg-config-reference-v1",
                stdout=arguments.config_stdout,
                stderr=arguments.config_stderr,
                command=config_command,
            ),
            "dpkg_update_alternatives": oracle_record(
                architecture=arguments.architecture,
                artifact_root=artifact_root,
                observation=arguments.alternatives_observation,
                reference=ALTERNATIVES_REFERENCE,
                schema="https://debz.dev/schema/dpkg-alternatives-reference-v1",
                stdout=arguments.alternatives_stdout,
                stderr=arguments.alternatives_stderr,
                command=alternatives_command,
            ),
        },
        "runner": {
            "label": arguments.runner_label,
            "machine": arguments.machine,
            "runner_arch": arguments.runner_arch,
        },
        "schema": SCHEMA_ID,
        "source": {
            "commit": arguments.source_commit,
            "job": arguments.job,
            "repository": arguments.repository,
            "run_attempt": arguments.run_attempt,
            "run_id": arguments.run_id,
            "workflow": arguments.workflow,
            "workflow_path": ".github/workflows/ci.yml",
        },
        "tools": {
            "archive": receipt["archive"],
            "dpkg": dpkg,
            "receipt": receipt_binding(arguments.receipt, arguments.architecture),
            "update_alternatives": update_alternatives,
        },
        "version": 1,
    }
    schema = json.loads(read_regular(SCHEMA_PATH, MAXIMUM_EVIDENCE_BYTES))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(evidence)
    arguments.output.write_text(canonical_json(evidence))
    return evidence


def verify(path: Path, artifact_root: Path) -> dict[str, Any]:
    evidence, raw = canonical_document(path, MAXIMUM_EVIDENCE_BYTES)
    schema = json.loads(read_regular(SCHEMA_PATH, MAXIMUM_EVIDENCE_BYTES))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(evidence)
    for oracle in evidence["oracles"].values():
        binding = oracle["observation"]
        observed = read_regular(artifact_root / binding["path"], MAXIMUM_OBSERVATION_BYTES)
        if len(observed) != binding["size"] or sha256_bytes(observed) != binding["sha256"]:
            raise EvidenceError("oracle observation binding mismatch")
        validate_privacy(binding["path"], observed)
    if raw != canonical_json(evidence).encode():
        raise EvidenceError("execution evidence is not canonical")
    return evidence


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="operation", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--architecture", required=True, choices=sorted(prepare.PINS))
    create_parser.add_argument("--source-commit", required=True)
    create_parser.add_argument("--invocation-clock", required=True)
    create_parser.add_argument("--repository", required=True)
    create_parser.add_argument("--workflow", required=True)
    create_parser.add_argument("--run-id", required=True, type=int)
    create_parser.add_argument("--run-attempt", required=True, type=int)
    create_parser.add_argument("--job", required=True)
    create_parser.add_argument("--runner-label", required=True)
    create_parser.add_argument("--runner-arch", required=True)
    create_parser.add_argument("--machine", required=True)
    create_parser.add_argument("--dpkg", required=True, type=Path)
    create_parser.add_argument("--update-alternatives", required=True, type=Path)
    create_parser.add_argument("--receipt", required=True, type=Path)
    create_parser.add_argument("--config-observation", required=True, type=Path)
    create_parser.add_argument("--config-stdout", required=True, type=Path)
    create_parser.add_argument("--config-stderr", required=True, type=Path)
    create_parser.add_argument("--alternatives-observation", required=True, type=Path)
    create_parser.add_argument("--alternatives-stdout", required=True, type=Path)
    create_parser.add_argument("--alternatives-stderr", required=True, type=Path)
    create_parser.add_argument("--output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--evidence", required=True, type=Path)
    verify_parser.add_argument("--artifact-root", required=True, type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    if arguments.operation == "create":
        create(arguments)
    else:
        verify(arguments.evidence, arguments.artifact_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
