#!/usr/bin/env python3
"""Repository-local, network-free security and policy audit."""

from __future__ import annotations

import pathlib
import re
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAILURES: list[str] = []

DIGEST_POLICY_SCHEMA = "https://debz.dev/security/digest-cutover-policy-v3"
DIGEST_POLICY_VERSION = 3
DIGEST_POLICY_PATH = pathlib.Path("security/digest-cutover-policy.json")
DIGEST_INVENTORY_PATH = pathlib.Path("security/digest-inventory-v1.tsv")
DIGEST_INVENTORY_FORMAT = "tsv-v1"
DIGEST_SEMANTIC_ALLOWLIST_PATH = pathlib.Path("security/digest-semantic-allowlist-v1.tsv")
DIGEST_SEMANTIC_ALLOWLIST_FORMAT = "tsv-v1"
DIGEST_SCOPE_ROOTS = (
    ".github",
    "actions",
    "build",
    "doc",
    "fuzz",
    "schema",
    "security",
    "src",
    "test",
    "tools",
)
DIGEST_TOP_LEVEL_FILES = {"README.md", "build.zig", "build.zig.zon"}
DIGEST_FINDING_KINDS = (
    "cas_layout",
    "digest_version",
    "fixed_64_hex",
    "raw_32_byte",
    "sha256_token",
)
DIGEST_POLICY_EXCLUDED_FINDINGS = {
    DIGEST_POLICY_PATH.as_posix(),
    DIGEST_INVENTORY_PATH.as_posix(),
    DIGEST_SEMANTIC_ALLOWLIST_PATH.as_posix(),
    "tools/security-audit.py",
}
DIGEST_INVENTORY_COLUMNS = (
    "path",
    "scope",
    *DIGEST_FINDING_KINDS,
    "sha512",
)
DIGEST_SEMANTIC_ALLOWLIST_COLUMNS = (
    "id",
    "path",
    "count",
    "sha512",
)
REMOVED_TEST_ENTRY_POINTS = {
    "tools/test_release.py",
    "tools/test_security_audit.py",
    "tools/test_real_snapshot_acceptance.py",
}

SHA256_TOKEN = re.compile(
    r"(?i)(?:sha-256|sha256|[A-Za-z_][A-Za-z0-9_]*(?:sha_256|sha256)[A-Za-z0-9_]*)"
)
RAW_32_BYTE = re.compile(r"\[\s*32\s*\](?:const\s+)?u8")
FIXED_64_HEX = re.compile(
    r"(?i)(?:\^\[0-9a-f\]\{64\}\$|\{64\}|"
    r"(?:hex|digest|sha256|artifact_id|cache_key)[^\n]{0,64}"
    r"(?:==|!=|<=|>=|<|>)\s*64|"
    r"(?:==|!=|<=|>=|<|>)\s*64[^\n]{0,64}"
    r"(?:hex|digest|sha256|artifact_id|cache_key)|"
    r"(?:artifact_id|sha256_hex|cache_key)\s*:\s*\[64\]u8)"
)
CAS_LAYOUT = re.compile(
    r"(?i)(?:packages-v[0-9]+|metadata-v[0-9]+|"
    r"(?:objects|staging|locks)/<[^>]*(?:digest|identity|sha256)[^>]*>|"
    r"\b(?:cacheKey|cache_key)\b|sha256-|"
    r"\bCAS\b.{0,80}\b(?:digest|identity|layout|path|key)\b|"
    r"\b(?:digest|identity|layout|path|key)\b.{0,80}\bCAS\b)"
)
DIGEST_VERSION = re.compile(
    r"(?i)(?:"
    r"(?:digest|identity|checksum|hash)[A-Za-z0-9_-]*(?:version|v[0-9]+)|"
    r"(?:version|v[0-9]+)[A-Za-z0-9_-]*(?:digest|identity|checksum|hash)|"
    r"(?:schema|format|namespace)[A-Za-z0-9_-]*v[0-9]+)"
)
RAW_32_FIELD = re.compile(
    r"(?m)^\s*(?:pub\s+)?"
    r"(?P<name>(?:sha256|digest|hash|checksum|identity)|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:sha256|digest|hash|checksum|identity)"
    r"[A-Za-z0-9_]*)\s*:\s*\??\[\s*32\s*\]u8\b",
    re.IGNORECASE,
)
FIXED_SHA256_CAS = re.compile(
    r"(?i)(?:"
    r"(?:objects|staging|locks)[/\\](?:\{|\$\{|<)?sha256(?:_hex)?|"
    r"sha256(?:_hex)?\s*\[\s*0\s*\.\.\s*(?:2|64)\s*\]|"
    r"cache_key\s*:\s*\[(?:64|65|71)\]u8|"
    r"packages-v1|metadata-v1)"
)
AUTHORITY_FIELD = re.compile(
    r"(?i)(?:package_(?:sha256|digest)|cas_sha256|index_sha256|"
    r"archive_(?:sha256|digest)|artifact_(?:sha256|digest))"
)

CURRENT_TYPED_SCHEMA_REQUIREMENTS = {
    "schema/exact-closure-lock-v3.json": {
        "archive_identity": 3,
        "artifact_id": 2,
        "index_identity": 1,
    },
    "schema/native-transaction-authorization-v2.json": {
        "archive_identity": 2,
        "artifact_id": 1,
    },
    "schema/native-transaction-program-v2.json": {
        "archive_identity": 3,
        "artifact_id": 1,
    },
    "schema/transaction-plan-v4.json": {
        "archive_identity": 2,
        "artifact_id": 1,
    },
    "schema/transaction-result-v3.json": {
        "archive_identity": 1,
        "artifact_id": 1,
    },
}

TYPED_SOURCE_REQUIREMENTS = {
    "src/content_digest.zig": (
        "pub const Value = union(Algorithm)",
        "pub const Set = struct",
        "pub const Identity = struct",
        "pub const JsonValue = struct",
        "pub const JsonIdentity = struct",
        "pub fn cacheKey(self: Identity",
    ),
    "src/exact_lock_v3.zig": (
        "index_identity: content_digest.Identity",
        "archive_identity: content_digest.Identity",
    ),
    "src/package_acquisition.zig": (
        'pub const namespace = "packages-v2"',
        "pub const Digest = content_digest.Identity",
        "digest.cacheKey(&name_buffer)",
    ),
    "src/package_origin.zig": (
        "artifact_id: content_digest.Value",
        "archive_identity: content_digest.Identity",
    ),
    "src/repository_refresh.zig": (
        "index_identity: content_digest.Identity",
    ),
}


def fail(message: str) -> None:
    FAILURES.append(message)


def tracked_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]
    # Unstaged deleted tests remain in the index; other missing tracked files must still fail audit.
    return [
        path for path in paths
        if path.exists()
        or path.is_symlink()
        or path.relative_to(ROOT).as_posix() not in REMOVED_TEST_ENTRY_POINTS
    ]


def untracked_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def repository_digest_files(files: list[pathlib.Path]) -> list[pathlib.Path]:
    candidates = [*files, *untracked_files()]
    for required in (
        DIGEST_POLICY_PATH,
        DIGEST_INVENTORY_PATH,
        DIGEST_SEMANTIC_ALLOWLIST_PATH,
    ):
        required_path = ROOT / required
        if required_path.is_file():
            candidates.append(required_path)
    return sorted(set(candidates))


def digest_relevant_path(relative: str) -> bool:
    path = pathlib.PurePosixPath(relative)
    if relative in DIGEST_TOP_LEVEL_FILES:
        return True
    if not path.parts or path.parts[0] not in DIGEST_SCOPE_ROOTS:
        return False
    if "__pycache__" in path.parts or "node_modules" in path.parts:
        return False
    return path.suffix not in {".pyc", ".pyo"}


def tracked_digest_texts(files: list[pathlib.Path]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for path in repository_digest_files(files):
        relative = path.relative_to(ROOT).as_posix()
        if not digest_relevant_path(relative):
            continue
        try:
            texts[relative] = path.read_text(errors="strict")
        except FileNotFoundError:
            continue  # A tracked file may be deleted in the working tree before commit.
        except UnicodeDecodeError:
            continue
    return texts


def digest_scope(relative: str) -> str:
    if relative in DIGEST_TOP_LEVEL_FILES:
        return "build"
    return pathlib.PurePosixPath(relative).parts[0]


def canonical_sha512(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha512(encoded).hexdigest()


def normalized_line(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end < 0:
        end = len(text)
    return " ".join(text[start:end].strip().split())


def digest_findings(texts: dict[str, str]) -> list[dict[str, str]]:
    patterns = {
        "cas_layout": CAS_LAYOUT,
        "digest_version": DIGEST_VERSION,
        "fixed_64_hex": FIXED_64_HEX,
        "raw_32_byte": RAW_32_BYTE,
        "sha256_token": SHA256_TOKEN,
    }
    findings: list[dict[str, str]] = []
    for relative, text in sorted(texts.items()):
        if relative in DIGEST_POLICY_EXCLUDED_FINDINGS:
            continue
        for kind, pattern in patterns.items():
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "context": normalized_line(text, match.start()),
                        "kind": kind,
                        "path": relative,
                        "token": match.group(),
                    }
                )
    return sorted(
        findings,
        key=lambda item: (
            item["path"],
            item["kind"],
            item["context"],
            item["token"],
        ),
    )


def schema_sha256_candidates(relative: str, text: str) -> list[dict[str, str]]:
    if not relative.startswith("schema/") or not relative.endswith(".json"):
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    candidates: list[dict[str, str]] = []

    def walk(value: object, pointer: str) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                for name, definition in properties.items():
                    if not isinstance(name, str):
                        continue
                    encoded = json.dumps(
                        definition,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    if "sha256" in name.lower() or "#/$defs/sha256" in encoded:
                        candidates.append(
                            {
                                "context": encoded,
                                "kind": "schema_sha256_field",
                                "path": relative,
                                "selector": f"{pointer}/properties/{name}",
                            }
                        )
            for name, child in value.items():
                walk(child, f"{pointer}/{name}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}")

    walk(document, "")
    return candidates


def digest_semantic_candidates(texts: dict[str, str]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for relative, text in sorted(texts.items()):
        if relative in DIGEST_POLICY_EXCLUDED_FINDINGS:
            continue
        for match in RAW_32_FIELD.finditer(text):
            candidates.append(
                {
                    "context": normalized_line(text, match.start()),
                    "kind": "raw_32_byte_field",
                    "path": relative,
                    "selector": match.group("name"),
                }
            )
        candidates.extend(schema_sha256_candidates(relative, text))
        for match in FIXED_64_HEX.finditer(text):
            candidates.append(
                {
                    "context": normalized_line(text, match.start()),
                    "kind": "fixed_64_hex_assumption",
                    "path": relative,
                    "selector": match.group(),
                }
            )
        for match in FIXED_SHA256_CAS.finditer(text):
            candidates.append(
                {
                    "context": normalized_line(text, match.start()),
                    "kind": "fixed_sha256_cas",
                    "path": relative,
                    "selector": match.group(),
                }
            )
    return sorted(
        candidates,
        key=lambda item: (
            item["kind"],
            item["path"],
            item["selector"],
            item["context"],
        ),
    )


def exact_policy_path(value: object) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/"):
        return False
    if any(character in value for character in "*?[]{}"):
        return False
    path = pathlib.PurePosixPath(value)
    return ".." not in path.parts and path.as_posix() == value


def digest_policy_identity_failure(policy: dict[str, object]) -> str | None:
    if (
        policy.get("schema") != DIGEST_POLICY_SCHEMA
        or policy.get("version") != DIGEST_POLICY_VERSION
        or policy.get("fingerprint_algorithm") != "sha512"
    ):
        return "digest cutover policy identity changed"
    return None


def digest_count_by_kind(findings: list[dict[str, str]]) -> dict[str, int]:
    return {
        kind: sum(finding["kind"] == kind for finding in findings)
        for kind in DIGEST_FINDING_KINDS
    }


def digest_inventory_record_map(texts: dict[str, str]) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    findings_by_path: dict[str, list[dict[str, str]]] = {}
    for finding in digest_findings(texts):
        findings_by_path.setdefault(finding["path"], []).append(finding)
    for path, findings in sorted(findings_by_path.items()):
        records[path] = {
            "path": path,
            "scope": digest_scope(path),
            "counts": digest_count_by_kind(findings),
            "sha512": canonical_sha512(findings),
        }
    return records


def digest_inventory_line(record: dict[str, object]) -> str:
    counts = record["counts"]
    assert isinstance(counts, dict)
    return "\t".join(
        [
            str(record["path"]),
            str(record["scope"]),
            *(str(counts[kind]) for kind in DIGEST_FINDING_KINDS),
            str(record["sha512"]),
        ]
    )


def render_digest_inventory(texts: dict[str, str]) -> str:
    lines = [
        digest_inventory_line(record)
        for _, record in sorted(digest_inventory_record_map(texts).items())
    ]
    return "".join(f"{line}\n" for line in lines)


def parse_digest_inventory(text: str) -> tuple[dict[str, dict[str, object]], list[str]]:
    failures: list[str] = []
    records: dict[str, dict[str, object]] = {}
    paths: list[str] = []
    if text and not text.endswith("\n"):
        failures.append("digest inventory is not line-oriented")
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != len(DIGEST_INVENTORY_COLUMNS):
            failures.append(f"digest inventory line {line_number} is malformed")
            continue
        path, scope, *count_fields, sha512 = fields
        if not exact_policy_path(path) or not digest_relevant_path(path):
            failures.append(f"digest inventory line {line_number} has an invalid path")
            continue
        if scope != digest_scope(path):
            failures.append(f"digest inventory line {line_number} has an invalid scope")
            continue
        if not re.fullmatch(r"[0-9a-f]{128}", sha512):
            failures.append(f"digest inventory line {line_number} has an invalid sha512")
            continue
        counts: dict[str, int] = {}
        malformed_count = False
        for kind, count in zip(DIGEST_FINDING_KINDS, count_fields):
            if not re.fullmatch(r"(?:0|[1-9][0-9]*)", count):
                malformed_count = True
                break
            counts[kind] = int(count)
        if malformed_count:
            failures.append(f"digest inventory line {line_number} has an invalid count")
            continue
        if path in records:
            failures.append(f"digest inventory contains a duplicate record: {path}")
        paths.append(path)
        records[path] = {
            "path": path,
            "scope": scope,
            "counts": counts,
            "sha512": sha512,
        }
    if paths != sorted(paths):
        failures.append("digest inventory records are not sorted")
    return records, failures


def digest_inventory_failures(
    texts: dict[str, str],
    policy: dict[str, object],
    inventory_text: str,
) -> list[str]:
    failures: list[str] = []
    identity_failure = digest_policy_identity_failure(policy)
    if identity_failure is not None:
        return [identity_failure]
    scoped_paths = sorted(texts)
    inventory = policy.get("inventory")
    if not isinstance(inventory, dict):
        return ["digest policy inventory is missing"]
    if (
        inventory.get("file") != DIGEST_INVENTORY_PATH.as_posix()
        or inventory.get("format") != DIGEST_INVENTORY_FORMAT
        or inventory.get("columns") != list(DIGEST_INVENTORY_COLUMNS)
    ):
        failures.append("digest policy inventory metadata changed")

    classifications = inventory.get("classifications")
    if not isinstance(classifications, list):
        failures.append("digest policy classifications are missing")
        return failures
    actual_scopes = sorted({digest_scope(path) for path in scoped_paths})
    seen_scopes: set[str] = set()
    for entry in classifications:
        if not isinstance(entry, dict):
            failures.append("digest policy contains a malformed classification")
            continue
        scope = entry.get("scope")
        classification = entry.get("classification")
        rationale = entry.get("rationale")
        if (
            not isinstance(scope, str)
            or scope not in actual_scopes
            or scope in seen_scopes
            or not isinstance(classification, str)
            or not classification
            or not isinstance(rationale, str)
            or len(rationale.strip()) < 40
        ):
            failures.append("digest policy contains an invalid or duplicate classification")
            continue
        seen_scopes.add(scope)
    if sorted(seen_scopes) != actual_scopes:
        failures.append("digest policy does not classify every tracked audit scope")
    expected_records, parse_failures = parse_digest_inventory(inventory_text)
    failures.extend(parse_failures)
    actual_records = digest_inventory_record_map(texts)
    for path in sorted(set(actual_records) - set(expected_records)):
        failures.append(f"digest inventory is missing a record: {path}")
    for path in sorted(set(expected_records) - set(actual_records)):
        failures.append(f"digest inventory contains an unexpected record: {path}")
    for path in sorted(set(actual_records) & set(expected_records)):
        if expected_records[path] != actual_records[path]:
            failures.append(
                f"digest inventory record changed: {path} "
                f"({digest_inventory_line(actual_records[path])})"
            )
    return failures


def semantic_allowlist_record(
    identifier: str,
    path: str,
    candidates: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "id": identifier,
        "path": path,
        "count": len(candidates),
        "sha512": canonical_sha512(candidates),
    }


def semantic_allowlist_line(record: dict[str, object]) -> str:
    return "\t".join(
        [
            str(record["id"]),
            str(record["path"]),
            str(record["count"]),
            str(record["sha512"]),
        ]
    )


def parse_semantic_allowlist_inventory(
    text: str,
) -> tuple[dict[tuple[str, str], dict[str, object]], list[str]]:
    failures: list[str] = []
    records: dict[tuple[str, str], dict[str, object]] = {}
    keys: list[tuple[str, str]] = []
    if text and not text.endswith("\n"):
        failures.append("digest semantic allowlist inventory is not line-oriented")
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != len(DIGEST_SEMANTIC_ALLOWLIST_COLUMNS):
            failures.append(f"digest semantic allowlist line {line_number} is malformed")
            continue
        identifier, path, count_text, sha512 = fields
        if not identifier or any(character.isspace() for character in identifier):
            failures.append(f"digest semantic allowlist line {line_number} has an invalid id")
            continue
        if not exact_policy_path(path) or not digest_relevant_path(path):
            failures.append(f"digest semantic allowlist line {line_number} has an invalid path")
            continue
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)", count_text):
            failures.append(f"digest semantic allowlist line {line_number} has an invalid count")
            continue
        if not re.fullmatch(r"[0-9a-f]{128}", sha512):
            failures.append(f"digest semantic allowlist line {line_number} has an invalid sha512")
            continue
        key = (identifier, path)
        if key in records:
            failures.append(
                f"digest semantic allowlist contains a duplicate record: {identifier}:{path}"
            )
        keys.append(key)
        records[key] = {
            "id": identifier,
            "path": path,
            "count": int(count_text),
            "sha512": sha512,
        }
    if keys != sorted(keys):
        failures.append("digest semantic allowlist records are not sorted")
    return records, failures


def semantic_allowlist_inventory_records(
    candidates_by_kind: dict[str, list[tuple[int, dict[str, str]]]],
    entries: list[dict[str, object]],
) -> dict[tuple[str, str], dict[str, object]]:
    records: dict[tuple[str, str], dict[str, object]] = {}
    for entry in entries:
        identifier = entry.get("id")
        kind = entry.get("kind")
        paths = entry.get("paths")
        if not isinstance(identifier, str) or not isinstance(kind, str) or not isinstance(paths, list):
            continue
        for path in paths:
            if not isinstance(path, str):
                continue
            selected = [
                candidate
                for _, candidate in candidates_by_kind.get(kind, [])
                if candidate["path"] == path
            ]
            records[(identifier, path)] = semantic_allowlist_record(
                identifier,
                path,
                selected,
            )
    return records


def render_semantic_allowlist_inventory(
    candidates: list[dict[str, str]],
    policy: dict[str, object],
) -> str:
    candidates_by_kind: dict[str, list[tuple[int, dict[str, str]]]] = {}
    for index, candidate in enumerate(candidates):
        candidates_by_kind.setdefault(candidate["kind"], []).append((index, candidate))
    entries = policy.get("semantic_allowlist")
    records = semantic_allowlist_inventory_records(
        candidates_by_kind,
        entries if isinstance(entries, list) else [],
    )
    return "".join(
        f"{semantic_allowlist_line(record)}\n"
        for _, record in sorted(records.items())
    )


def semantic_allowlist_failures(
    candidates: list[dict[str, str]],
    policy: dict[str, object],
    inventory_text: str,
) -> list[str]:
    failures: list[str] = []
    entries = policy.get("semantic_allowlist")
    if not isinstance(entries, list) or not entries:
        return ["digest semantic allowlist is missing"]
    metadata = policy.get("semantic_allowlist_inventory")
    if (
        not isinstance(metadata, dict)
        or metadata.get("file") != DIGEST_SEMANTIC_ALLOWLIST_PATH.as_posix()
        or metadata.get("format") != DIGEST_SEMANTIC_ALLOWLIST_FORMAT
        or metadata.get("columns") != list(DIGEST_SEMANTIC_ALLOWLIST_COLUMNS)
    ):
        failures.append("digest semantic allowlist inventory metadata changed")
    candidates_by_kind: dict[str, list[tuple[int, dict[str, str]]]] = {}
    for index, candidate in enumerate(candidates):
        candidates_by_kind.setdefault(candidate["kind"], []).append(
            (index, candidate)
        )
    expected_records, parse_failures = parse_semantic_allowlist_inventory(inventory_text)
    failures.extend(parse_failures)
    actual_records: dict[tuple[str, str], dict[str, object]] = {}
    covered: set[int] = set()
    seen_ids: set[str] = set()
    allowed_classes = {
        "fixed_control_and_versioned_compatibility",
        "fixed_control_protocol",
        "generated_external_protocol",
        "historical_versioned_compatibility",
        "typed_identity_internal",
    }
    for entry in entries:
        if not isinstance(entry, dict):
            failures.append("digest semantic allowlist contains a malformed entry")
            continue
        identifier = entry.get("id")
        kind = entry.get("kind")
        classification = entry.get("classification")
        rationale = entry.get("rationale")
        paths = entry.get("paths")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in seen_ids
            or not isinstance(kind, str)
            or classification not in allowed_classes
            or not isinstance(rationale, str)
            or len(rationale.strip()) < 40
            or not isinstance(paths, list)
            or not paths
            or paths != sorted(set(paths))
            or not all(exact_policy_path(path) for path in paths)
            or "count" in entry
            or "sha512" in entry
        ):
            failures.append("digest semantic allowlist contains an invalid or overbroad entry")
            continue
        seen_ids.add(identifier)
        selected_pairs = [
            (index, candidate)
            for index, candidate in candidates_by_kind.get(kind, [])
            if candidate["path"] in paths
        ]
        selected = [candidate for _, candidate in selected_pairs]
        if not selected or {candidate["path"] for candidate in selected} != set(paths):
            failures.append(f"digest semantic allowlist changed: {identifier}")
            continue
        for path in paths:
            path_selected = [
                candidate for candidate in selected if candidate["path"] == path
            ]
            actual_records[(identifier, path)] = semantic_allowlist_record(
                identifier,
                path,
                path_selected,
            )
        for index, candidate in selected_pairs:
            if index in covered:
                failures.append(
                    f"digest semantic candidate is multiply classified: "
                    f"{candidate['path']}:{candidate['selector']}"
                )
            covered.add(index)
        if classification != "historical_versioned_compatibility":
            for candidate in selected:
                if (
                    candidate["kind"] in {"raw_32_byte_field", "schema_sha256_field"}
                    and AUTHORITY_FIELD.search(candidate["selector"])
                ):
                    failures.append(
                        f"{candidate['path']}:{candidate['selector']}: "
                        "SHA256-only package/repository/artifact authority is forbidden"
                    )
                if candidate["kind"] == "fixed_sha256_cas":
                    failures.append(
                        f"{candidate['path']}:{candidate['selector']}: "
                        "fixed SHA256 CAS layout is forbidden"
                    )
    for key in sorted(set(actual_records) - set(expected_records)):
        failures.append(
            f"digest semantic allowlist is missing a record: {key[0]}:{key[1]}"
        )
    for key in sorted(set(expected_records) - set(actual_records)):
        failures.append(
            f"digest semantic allowlist contains an unexpected record: {key[0]}:{key[1]}"
        )
    for key in sorted(set(actual_records) & set(expected_records)):
        if expected_records[key] != actual_records[key]:
            failures.append(
                f"digest semantic allowlist record changed: {key[0]}:{key[1]} "
                f"({semantic_allowlist_line(actual_records[key])})"
            )
    if covered != set(range(len(candidates))):
        for index, candidate in enumerate(candidates):
            if index not in covered:
                failures.append(
                    f"{candidate['path']}:{candidate['selector']}: "
                    f"unreviewed {candidate['kind'].replace('_', ' ')}"
                )
    return failures


def typed_digest_authority_failures(texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for relative, required in TYPED_SOURCE_REQUIREMENTS.items():
        text = texts.get(relative)
        if text is None or any(token not in text for token in required):
            failures.append(
                f"{relative}: versioned typed digest authority implementation changed"
            )

    for relative, required_fields in CURRENT_TYPED_SCHEMA_REQUIREMENTS.items():
        text = texts.get(relative)
        if text is None:
            failures.append(f"{relative}: current typed digest schema is missing")
            continue
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            failures.append(f"{relative}: current typed digest schema is invalid JSON")
            continue
        observed: dict[str, int] = {}

        def walk(value: object) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    for name, definition in properties.items():
                        if name not in {"archive_identity", "artifact_id", "index_identity"}:
                            continue
                        observed[name] = observed.get(name, 0) + 1
                        encoded = json.dumps(
                            definition,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        expected_ref = (
                            "#/$defs/digest"
                            if name == "artifact_id"
                            else "#/$defs/digestIdentity"
                        )
                        if expected_ref not in encoded:
                            failures.append(
                                f"{relative}:{name}: current authority is not algorithm-tagged"
                            )
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(document)
        if observed != required_fields:
            failures.append(
                f"{relative}: typed package/repository/artifact authority fields changed"
            )
        for forbidden in (
            "package_sha256",
            "package_digest",
            "cas_sha256",
            "index_sha256",
            "archive_sha256",
            "archive_digest",
        ):
            if f'"{forbidden}"' in text:
                failures.append(
                    f"{relative}:{forbidden}: current schema reintroduced SHA256-only authority"
                )
    return failures


def digest_cutover_failures(
    texts: dict[str, str],
    policy: dict[str, object],
    inventory_text: str,
    semantic_inventory_text: str,
) -> list[str]:
    failures = digest_inventory_failures(texts, policy, inventory_text)
    failures.extend(
        semantic_allowlist_failures(
            digest_semantic_candidates(texts),
            policy,
            semantic_inventory_text,
        )
    )
    failures.extend(typed_digest_authority_failures(texts))
    return failures


def audit_digest_cutover(files: list[pathlib.Path]) -> None:
    policy_path = ROOT / DIGEST_POLICY_PATH
    inventory_path = ROOT / DIGEST_INVENTORY_PATH
    semantic_inventory_path = ROOT / DIGEST_SEMANTIC_ALLOWLIST_PATH
    if not policy_path.is_file():
        fail("digest cutover policy is missing")
        return
    if not inventory_path.is_file():
        fail("digest inventory is missing")
        return
    if not semantic_inventory_path.is_file():
        fail("digest semantic allowlist inventory is missing")
        return
    try:
        policy = json.loads(policy_path.read_text())
    except json.JSONDecodeError:
        fail("digest cutover policy is invalid JSON")
        return
    identity_failure = digest_policy_identity_failure(policy)
    if identity_failure is not None:
        fail(identity_failure)
        return
    if policy.get("scope") != {
        "roots": list(DIGEST_SCOPE_ROOTS),
        "top_level_files": sorted(DIGEST_TOP_LEVEL_FILES),
        "excluded_finding_paths": sorted(DIGEST_POLICY_EXCLUDED_FINDINGS),
        "exclusion_rationale": (
            "The repository manifest includes tracked and non-ignored untracked "
            "files so pre-commit audit results remain stable after commit. The "
            "policy, per-file inventory, semantic allowlist inventory, and "
            "audit/canary implementation are excluded from token findings to "
            "avoid recursive self-classification; they do not define repository "
            "digest authority."
        ),
    }:
        fail("digest cutover policy scope or self-exclusion changed")
        return
    if policy.get("authority_policy") != {
        "current_package_repository_artifact_authority": (
            "content_digest.Identity, content_digest.Value, content_digest.Set, "
            "or their versioned algorithm-tagged serialized forms"
        ),
        "sha256_only_authority": "forbidden",
        "raw_32_byte_authority": "forbidden",
        "fixed_64_hex_authority": "forbidden",
        "fixed_sha256_cas_layout": "forbidden",
        "historical_and_control_exception_rule": (
            "exact-path, exact-fingerprint, version-specific or frozen-control "
            "classification with a non-empty rationale"
        ),
    }:
        fail("digest cutover authority policy changed")
        return
    texts = tracked_digest_texts(files)
    try:
        inventory_text = inventory_path.read_text()
    except UnicodeDecodeError:
        fail("digest inventory is not UTF-8")
        return
    try:
        semantic_inventory_text = semantic_inventory_path.read_text()
    except UnicodeDecodeError:
        fail("digest semantic allowlist inventory is not UTF-8")
        return
    for message in digest_cutover_failures(
        texts,
        policy,
        inventory_text,
        semantic_inventory_text,
    ):
        fail(message)


def normalized_digest_policy_for_inventory(policy: dict[str, object]) -> dict[str, object]:
    inventory = policy.get("inventory")
    classifications = inventory.get("classifications") if isinstance(inventory, dict) else []
    normalized_classifications: list[dict[str, str]] = []
    if isinstance(classifications, list):
        for entry in classifications:
            if not isinstance(entry, dict):
                normalized_classifications.append({})
                continue
            normalized_classifications.append(
                {
                    "scope": entry.get("scope"),
                    "classification": entry.get("classification"),
                    "rationale": entry.get("rationale"),
                }
            )
    semantic_entries = policy.get("semantic_allowlist")
    normalized_semantic_entries: list[dict[str, object]] = []
    if isinstance(semantic_entries, list):
        for entry in semantic_entries:
            if not isinstance(entry, dict):
                normalized_semantic_entries.append({})
                continue
            normalized_semantic_entries.append(
                {
                    "id": entry.get("id"),
                    "kind": entry.get("kind"),
                    "classification": entry.get("classification"),
                    "rationale": entry.get("rationale"),
                    "paths": entry.get("paths"),
                }
            )
    policy = dict(policy)
    policy["schema"] = DIGEST_POLICY_SCHEMA
    policy["version"] = DIGEST_POLICY_VERSION
    policy["fingerprint_algorithm"] = "sha512"
    policy["scope"] = {
        "roots": list(DIGEST_SCOPE_ROOTS),
        "top_level_files": sorted(DIGEST_TOP_LEVEL_FILES),
        "excluded_finding_paths": sorted(DIGEST_POLICY_EXCLUDED_FINDINGS),
        "exclusion_rationale": (
            "The repository manifest includes tracked and non-ignored untracked "
            "files so pre-commit audit results remain stable after commit. The "
            "policy, per-file inventory, semantic allowlist inventory, and "
            "audit/canary implementation are excluded from token findings to "
            "avoid recursive self-classification; they do not define repository "
            "digest authority."
        ),
    }
    policy["inventory"] = {
        "file": DIGEST_INVENTORY_PATH.as_posix(),
        "format": DIGEST_INVENTORY_FORMAT,
        "columns": list(DIGEST_INVENTORY_COLUMNS),
        "classifications": normalized_classifications,
    }
    policy["semantic_allowlist_inventory"] = {
        "file": DIGEST_SEMANTIC_ALLOWLIST_PATH.as_posix(),
        "format": DIGEST_SEMANTIC_ALLOWLIST_FORMAT,
        "columns": list(DIGEST_SEMANTIC_ALLOWLIST_COLUMNS),
    }
    policy["semantic_allowlist"] = normalized_semantic_entries
    return policy


def write_digest_inventory(check: bool) -> int:
    policy_path = ROOT / DIGEST_POLICY_PATH
    inventory_path = ROOT / DIGEST_INVENTORY_PATH
    semantic_inventory_path = ROOT / DIGEST_SEMANTIC_ALLOWLIST_PATH
    try:
        original_policy = policy_path.read_text()
        policy = json.loads(original_policy)
    except FileNotFoundError:
        print("security-audit: digest cutover policy is missing", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"security-audit: digest cutover policy is invalid JSON: {error}", file=sys.stderr)
        return 2
    if not isinstance(policy, dict):
        print("security-audit: digest cutover policy is malformed", file=sys.stderr)
        return 2
    texts = tracked_digest_texts(tracked_files())
    inventory_text = render_digest_inventory(texts)
    normalized_policy = normalized_digest_policy_for_inventory(policy)
    semantic_inventory_text = render_semantic_allowlist_inventory(
        digest_semantic_candidates(texts),
        normalized_policy,
    )
    policy_text = json.dumps(normalized_policy, indent=2) + "\n"
    try:
        original_inventory = inventory_path.read_text()
    except FileNotFoundError:
        original_inventory = ""
    try:
        original_semantic_inventory = semantic_inventory_path.read_text()
    except FileNotFoundError:
        original_semantic_inventory = ""
    changed = (
        policy_text != original_policy
        or inventory_text != original_inventory
        or semantic_inventory_text != original_semantic_inventory
    )
    failures = digest_cutover_failures(
        texts,
        json.loads(policy_text),
        inventory_text,
        semantic_inventory_text,
    )
    if check:
        print("stale" if changed else "unchanged")
        for failure in failures:
            print("remaining:", failure)
        return int(changed or bool(failures))
    policy_path.write_text(policy_text)
    inventory_path.write_text(inventory_text)
    semantic_inventory_path.write_text(semantic_inventory_text)
    print("rewritten" if changed else "unchanged")
    for failure in failures:
        print("remaining:", failure)
    return int(bool(failures))


def synthetic_digest_inventory_policy(
    texts: dict[str, str],
    *,
    omit_scope: str | None = None,
    old_schema: bool = False,
) -> dict[str, object]:
    classifications = []
    for scope in sorted({digest_scope(path) for path in texts}):
        if scope == omit_scope:
            continue
        classifications.append(
            {
                "scope": scope,
                "classification": "synthetic_test_scope",
                "rationale": (
                    f"Synthetic digest inventory test classification for {scope}; "
                    "this rationale is intentionally long enough for policy checks."
                ),
            }
        )
    return {
        "schema": (
            "https://debz.dev/security/digest-cutover-policy-v2"
            if old_schema
            else DIGEST_POLICY_SCHEMA
        ),
        "version": 2 if old_schema else DIGEST_POLICY_VERSION,
        "fingerprint_algorithm": "sha512",
        "inventory": {
            "file": DIGEST_INVENTORY_PATH.as_posix(),
            "format": DIGEST_INVENTORY_FORMAT,
            "columns": list(DIGEST_INVENTORY_COLUMNS),
            "classifications": classifications,
        },
    }


def digest_inventory_line_for_path(inventory_text: str, path: str) -> str:
    for line in inventory_text.splitlines():
        if line.startswith(path + "\t"):
            return line
    raise ValueError(f"missing synthetic inventory line: {path}")


def replace_digest_inventory_line(
    inventory_text: str,
    path: str,
    replacement: str,
) -> str:
    lines = inventory_text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(path + "\t"):
            lines[index] = replacement
            return "\n".join(lines) + "\n"
    raise ValueError(f"missing synthetic inventory line: {path}")


def replace_digest_inventory_path(
    inventory_text: str,
    path: str,
    replacement_path: str,
) -> str:
    line = digest_inventory_line_for_path(inventory_text, path)
    fields = line.split("\t")
    fields[0] = replacement_path
    return replace_digest_inventory_line(inventory_text, path, "\t".join(fields))


def replace_digest_inventory_scope(
    inventory_text: str,
    path: str,
    replacement_scope: str,
) -> str:
    line = digest_inventory_line_for_path(inventory_text, path)
    fields = line.split("\t")
    fields[1] = replacement_scope
    return replace_digest_inventory_line(inventory_text, path, "\t".join(fields))


def digest_inventory_synthetic_failures(case: str) -> list[str]:
    texts = {
        "doc/digest-synthetic.md": "Documentation sha256 compatibility marker.\n",
        "doc/empty-digest-synthetic.md": "Plain documentation without findings.\n",
        "src/digest_synthetic.zig": (
            "pub const package_sha256 = \"sha256\";\n"
            "pub const digest_bytes: [32]u8 = undefined;\n"
        ),
        "tools/digest_synthetic.py": "sha256 = 'fixture'\n",
    }
    expected_texts = dict(texts)
    policy = synthetic_digest_inventory_policy(texts)
    inventory_text = render_digest_inventory(expected_texts)
    zero_sha512 = "0" * 128

    if case == "valid":
        pass
    elif case == "added":
        texts["src/digest_synthetic.zig"] += "\n// added sha256 canary\n"
    elif case == "removed":
        texts["src/digest_synthetic.zig"] = texts["src/digest_synthetic.zig"].replace(
            "sha256", "sha-512", 1
        )
    elif case == "edited":
        texts["src/digest_synthetic.zig"] = texts["src/digest_synthetic.zig"].replace(
            "package_sha256", "package_sha256_changed", 1
        )
    elif case == "missing-record":
        line = digest_inventory_line_for_path(inventory_text, "src/digest_synthetic.zig")
        inventory_text = inventory_text.replace(line + "\n", "")
    elif case == "extra-missing-file":
        inventory_text += (
            "tools/zzzz_digest_inventory_canary.py\ttools\t0\t0\t0\t0\t1\t"
            f"{zero_sha512}\n"
        )
    elif case == "extra-no-findings":
        lines = inventory_text.splitlines()
        lines.insert(
            1,
            "doc/empty-digest-synthetic.md\tdoc\t0\t0\t0\t0\t0\t"
            f"{zero_sha512}",
        )
        inventory_text = "\n".join(lines) + "\n"
    elif case == "unsorted":
        first, second, *rest = inventory_text.splitlines()
        inventory_text = "\n".join([second, first, *rest]) + "\n"
    elif case == "duplicate":
        first = inventory_text.splitlines()[0]
        inventory_text += first + "\n"
    elif case == "malformed":
        inventory_text += "malformed\n"
    elif case == "absolute-path":
        inventory_text = replace_digest_inventory_path(
            inventory_text, "src/digest_synthetic.zig", "/absolute"
        )
    elif case == "parent-path":
        inventory_text = replace_digest_inventory_path(
            inventory_text, "src/digest_synthetic.zig", "../escape"
        )
    elif case == "glob-path":
        inventory_text = replace_digest_inventory_path(
            inventory_text, "src/digest_synthetic.zig", "src/*.zig"
        )
    elif case == "outside-scope-path":
        inventory_text = replace_digest_inventory_path(
            inventory_text, "src/digest_synthetic.zig", "LICENSE"
        )
    elif case == "invalid-scope":
        inventory_text = replace_digest_inventory_scope(
            inventory_text, "src/digest_synthetic.zig", "tools"
        )
    elif case == "old-schema":
        policy = synthetic_digest_inventory_policy(texts, old_schema=True)
    elif case == "unclassified-scope":
        policy = synthetic_digest_inventory_policy(texts, omit_scope="src")
    else:
        raise ValueError(f"unknown digest inventory synthetic case: {case}")

    return digest_inventory_failures(texts, policy, inventory_text)


def synthetic_semantic_allowlist_policy() -> dict[str, object]:
    return {
        "semantic_allowlist_inventory": {
            "file": DIGEST_SEMANTIC_ALLOWLIST_PATH.as_posix(),
            "format": DIGEST_SEMANTIC_ALLOWLIST_FORMAT,
            "columns": list(DIGEST_SEMANTIC_ALLOWLIST_COLUMNS),
        },
        "semantic_allowlist": [
            {
                "id": "synthetic-raw-controls",
                "kind": "raw_32_byte_field",
                "classification": "fixed_control_protocol",
                "rationale": (
                    "Synthetic semantic allowlist control fields are reviewed "
                    "test-only controls and not package authority."
                ),
                "paths": [
                    "src/member.zig",
                    "tools/member.py",
                ],
            }
        ],
    }


def synthetic_semantic_allowlist_candidates() -> list[dict[str, str]]:
    return [
        {
            "context": "control_bytes: [32]u8",
            "kind": "raw_32_byte_field",
            "path": "src/member.zig",
            "selector": "control_bytes",
        },
        {
            "context": "other_control: [32]u8",
            "kind": "raw_32_byte_field",
            "path": "tools/member.py",
            "selector": "other_control",
        },
    ]


def semantic_allowlist_synthetic_failures(case: str) -> list[str]:
    policy = synthetic_semantic_allowlist_policy()
    candidates = synthetic_semantic_allowlist_candidates()
    inventory_text = render_semantic_allowlist_inventory(candidates, policy)
    first = inventory_text.splitlines()[0]
    zero_sha512 = "0" * 128

    if case == "valid":
        pass
    elif case == "missing":
        inventory_text = inventory_text.replace(first + "\n", "")
    elif case == "extra":
        inventory_text += (
            "synthetic-raw-controls\tsrc/not-member.zig\t1\t"
            f"{zero_sha512}\n"
        )
    elif case == "unsorted":
        first_line, second_line = inventory_text.splitlines()
        inventory_text = f"{second_line}\n{first_line}\n"
    elif case == "duplicate":
        inventory_text += first + "\n"
    elif case == "malformed":
        inventory_text += "malformed\n"
    elif case == "non-member-candidate":
        candidates.append(
            {
                "context": "new_control: [32]u8",
                "kind": "raw_32_byte_field",
                "path": "src/not_member.zig",
                "selector": "new_control",
            }
        )
    elif case == "member-without-candidates":
        candidates = candidates[:1]
    elif case == "changed-count":
        fields = first.split("\t")
        fields[2] = str(int(fields[2]) + 1)
        inventory_text = inventory_text.replace(first, "\t".join(fields), 1)
    elif case == "changed-sha512":
        fields = first.split("\t")
        fields[3] = zero_sha512
        inventory_text = inventory_text.replace(first, "\t".join(fields), 1)
    elif case == "missing-entry":
        inventory_text += f"missing-entry\tsrc/member.zig\t1\t{zero_sha512}\n"
    else:
        raise ValueError(f"unknown digest semantic allowlist synthetic case: {case}")

    return semantic_allowlist_failures(candidates, policy, inventory_text)


def dependency_options(build: str, dependency: str) -> dict[str, str] | None:
    blocks = re.findall(
        rf'\bb\.dependency\(\s*"{re.escape(dependency)}"\s*,\s*\.\{{(.*?)\}}\s*\)',
        build,
        re.DOTALL,
    )
    if len(blocks) != 1:
        return None
    options: dict[str, str] = {}
    for match in re.finditer(
        r'(?m)^\s*\.(?P<name>[A-Za-z][A-Za-z0-9_-]*|@"[^"]+")\s*=\s*(?P<value>[^,\n]+)\s*,?\s*$',
        blocks[0],
    ):
        name = match.group("name")
        if name.startswith('@"'):
            name = name[2:-1]
        if name in options:
            return None
        options[name] = match.group("value").strip()
    return options


def dependency_option_failures(build: str, dependency: str, expected: dict[str, str]) -> list[str]:
    options = dependency_options(build, dependency)
    if options is None:
        return [f"{dependency}: build dependency options are missing or ambiguous"]
    return [
        f"{dependency}: build option .{name} must be {value}"
        for name, value in expected.items()
        if options.get(name) != value
    ]


def expected_runtime_metadata(
    dependencies: dict[str, dict[str, object]],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "package": "debz",
        "linux_release_runtime": {
            "binary_kind": "fully_static",
            "libc": {
                "implementation": "musl",
                "linkage": "static",
                "expectation": (
                    "musl and all required libraries are statically linked; "
                    "no target-system shared libraries are required."
                ),
            },
            "system_libraries": [],
            "included_libraries": sorted(
                (
                    {
                        "name": name,
                        "version": dependency["version"],
                        "linkage": dependency["runtime_linkage"],
                        "license": dependency["license"],
                    }
                    for name, dependency in dependencies.items()
                ),
                key=lambda item: item["name"],
            ),
            "fully_static": True,
        },
    }


def runtime_metadata_failures(
    runtime: dict[str, object],
    dependencies: dict[str, dict[str, object]],
) -> list[str]:
    if runtime == expected_runtime_metadata(dependencies):
        return []
    return ["Linux runtime metadata does not exactly identify fully static musl release binaries"]


def release_install_metadata_failures(build: str) -> list[str]:
    failures = []
    source = '"security/runtime-dependencies.json"'
    if build.count(source) != 1:
        failures.append("runtime metadata install source is missing or ambiguous")
    regular_start = build.find("const regular_files =")
    regular_end = build.find("\n    };", regular_start)
    if (
        regular_start < 0
        or regular_end < 0
        or source in build[regular_start:regular_end]
    ):
        failures.append("ordinary install graph contains static-musl runtime metadata")
    required = (
        "const runtime_metadata = b.addInstallFile(",
        'b.path("security/runtime-dependencies.json")',
        '"share/debz/runtime-dependencies.json"',
        "target.result.abi != .musl",
        "release-install requires a Linux musl target",
        "release_install.dependOn(&runtime_metadata_mode.step);",
    )
    if any(item not in build for item in required):
        failures.append("release-install graph does not install static-musl runtime metadata")
    return failures


def audit_production_sources() -> None:
    forbidden = {
        r"\b(?:getEnvVarOwned|getEnvMap)\b": "ambient environment access",
        r'(?:"|\b)(?:sh|bash)(?:"|\b)\s*,\s*"-c"': "shell command construction",
        r"\b(?:system|popen)\s*\(": "shell/process string execution",
        r"/etc/apt(?:/|$)": "ambient APT configuration",
        r"/var/lib/apt(?:/|$)": "ambient APT state",
        r"\bGNUPGHOME\b": "ambient GnuPG home",
    }
    allowed_test_canaries = {
        ("src/repository_policy.zig", "/etc/apt/", '&.{"/etc/apt/trusted.gpg"}'),
    }
    target_apt_paths = {
        'const sources_list_path = "/etc/apt/sources.list";',
        'const sources_directory_path = "/etc/apt/sources.list.d";',
        'const global_keyring_path = "/etc/apt/trusted.gpg";',
        'const global_keyring_directory_path = "/etc/apt/trusted.gpg.d";',
    }
    # A reviewed profile names a target-root logical path; it never opens it.
    reviewed_profile_paths = {
        '.source_path = "/etc/apt/sources.list.d/microsoft-prod.list",',
    }
    process_calls: list[str] = []
    child_calls: list[str] = []
    namespace_calls: list[str] = []
    capability_calls: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.zig")):
        text = path.read_text(errors="strict")
        relative = str(path.relative_to(ROOT))
        first_test = text.find('\ntest "')
        if relative == "src/target_apt_config.zig":
            fixture_start = text.find("\nconst test_fixture =")
            if fixture_start >= 0:
                first_test = fixture_start
        for pattern, reason in forbidden.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                value = match.group()
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                line_text = text[line_start : line_end if line_end >= 0 else len(text)]
                if any(
                    relative == allowed_path
                    and value == allowed_value
                    and exact_line in line_text
                    and first_test >= 0
                    and match.start() > first_test
                    for allowed_path, allowed_value, exact_line in allowed_test_canaries
                ):
                    continue
                if (
                    relative == "src/target_apt_config.zig"
                    and reason == "ambient APT configuration"
                    and (
                        line_text.strip() in target_apt_paths
                        or (first_test >= 0 and match.start() > first_test)
                    )
                ):
                    continue
                if (
                    relative == "src/reviewed_repository_profile.zig"
                    and reason == "ambient APT configuration"
                    and line_text.strip() in reviewed_profile_paths
                ):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                fail(f"{relative}:{line}: forbidden {reason}")
        for match in re.finditer(r"\bstd\.process\.run\s*\(", text):
            if relative == "src/production_backend.zig":
                fixture_start = text.find('\ntest "production native baseline signed batch receipt zero-op replay and owned process crash"')
                fixture_end = text.find('\ntest "', fixture_start + 1)
                if (
                    fixture_start >= 0
                    and fixture_start < match.start() < fixture_end
                    and text.count("std.process.run(") == 1
                    and '.argv = &.{"/proc/self/exe"}' in text[fixture_start:fixture_end]
                    and "CompletionPoint.after_native_receipt" in text[fixture_start:fixture_end]
                ):
                    continue
            process_calls.append(f"{relative}:{text.count(chr(10), 0, match.start()) + 1}")
        for match in re.finditer(r"\blinux\.(?:fork|clone2|execve|chroot)\s*\(", text):
            if relative == "src/native_unpack.zig" and match.group() == "linux.fork(":
                helper_start = text.find("fn testFreshDatabaseInstall(")
                helper_end = text.find(
                    '\ntest "native_unpack.test.caller-owned install initializes an absent database"',
                    helper_start,
                )
                if (
                    helper_start >= 0
                    and helper_start < match.start() < helper_end
                    and text.count("linux.fork(") == 1
                ):
                    continue
            if (
                relative in (
                    "src/apt_system_command.zig",
                    "src/apt_system_orchestrator.zig",
                    "src/production_backend.zig",
                )
                and first_test >= 0
                and match.start() > first_test
                and match.group() == "linux.fork("
            ):
                continue
            child_calls.append(f"{relative}:{text.count(chr(10), 0, match.start()) + 1}")
        for match in re.finditer(
            r"\blinux\.(?:clone2|unshare|setns|mount|move_mount|umount2)\s*\(", text
        ):
            if (
                relative == "src/apt_system_orchestrator.zig"
                and first_test >= 0
                and match.start() > first_test
            ):
                continue
            namespace_calls.append(
                f"{relative}:{text.count(chr(10), 0, match.start()) + 1}"
            )
        for match in re.finditer(
            r"\blinux\.(?:capget|capset|prctl)\s*\("
            r"|\blinux\.syscall2\s*\(\s*\.(?:capget|capset)\s*,",
            text,
        ):
            capability_calls.append(
                f"{relative}:{text.count(chr(10), 0, match.start()) + 1}"
            )
    process_paths = [call.rsplit(":", 1)[0] for call in process_calls]
    if sorted(process_paths) != [
        "src/target_apt_config.zig",
        "src/transaction_executor.zig",
    ]:
        fail(f"production process boundary changed: {process_calls!r}")
    child_paths = sorted({call.rsplit(":", 1)[0] for call in child_calls})
    if child_paths not in (
        [],
        ["src/live_root.zig", "src/maintainer_script.zig"],
    ):
        fail(f"native child-process boundary changed: {child_calls!r}")
    namespace_paths = sorted({call.rsplit(":", 1)[0] for call in namespace_calls})
    if namespace_paths not in ([], ["src/live_root.zig", "src/maintainer_script.zig"]):
        fail(f"native namespace boundary changed: {namespace_calls!r}")
    if {call.rsplit(":", 1)[0] for call in capability_calls} - {
        "src/maintainer_script.zig",
    }:
        fail(f"native capability boundary changed: {capability_calls!r}")
    runner = (ROOT / "src/maintainer_script.zig").read_text(errors="strict")
    for required in (
        "const clone_flags = linux.CLONE.NEWNET |",
        "linux.CLONE.NEWNS | linux.CLONE.NEWPID",
        "fn setupPrivateLoopback() linux.E",
        '"private-network-loopback-v1\\x00"',
        "fn sealInheritedDescriptors() linux.E",
        "linux.PR.SET_PDEATHSIG",
        "linux.PR.CAPBSET_DROP",
        "linux.PR.SET_NO_NEW_PRIVS",
        "linux.syscall2(\n        .capget,",
        "linux.syscall2(\n        .capset,",
        '@offsetOf(KernelCapabilityHeader, "pid")',
        "linux.MS.REMOUNT | proc_mount_flags",
        "linux.syscall3(\n        .close_range,",
        'snapshotUdevIdentity(identity, invocation.argv[1..])',
        'snapshotSudoIdentity(identity, invocation.argv[1..])',
        '"hidepid=2,subset=pid"',
        '"/proc/sys/kernel/random/boot_id"',
        '"etc/tmpfiles.d/static-nodes-permissions.conf"',
        '"etc/tmpfiles.d/sudo.conf"',
        '"etc/sysusers.d/debian-udev.conf"',
        '"usr/sbin/systemd-tmpfiles"',
        '"usr/sbin/update-alternatives"',
        '"usr/bin/gnuchmod"',
        '"usr/share/dpkg/sh/dpkg-error.sh"',
        '"d4d4fd7712da692dbb21a10795f7e62046c90b506338768b5a93cf9f1897f528"',
        "return restrictScriptPrivileges(failure_stage, true);",
        "const restricted = restrictScriptPrivileges(null, false);",
        "childFail(streams.status, .capability_policy, restricted);",
        "maskScriptCapabilities(&data);",
        "scriptCapabilityAllowed(capability)",
        "linux.PR.CAP_AMBIENT",
        "linux.SECCOMP.SET_MODE_FILTER",
        "linux.SECCOMP.RET.KILL_PROCESS",
        "linux.CLONE.NEWNET",
        "if (count == 64) return .RANGE;",
        "if (required) return error.SignedProcRootRequired;",
        "return error.SkipZigTest;",
    ):
        if required not in runner:
            fail(f"reviewed exact-script proc isolation changed: {required}")
    build = (ROOT / "build.zig").read_text(errors="strict")
    for required in (
        '"test-native-signed-proc"',
        '"DEBZ_REQUIRE_SIGNED_PROC_ROOTS=1"',
        '"signed-systemd-proc-root"',
        '"signed-udev-proc-root"',
        '"signed-sudo-proc-root"',
        "signed_proc_run.addArtifactArg(signed_proc_tests);",
    ):
        if required not in build:
            fail(f"required signed proc fixture gate changed: {required}")
    alternatives = (ROOT / "src/native_alternatives.zig").read_text(errors="strict")
    unpack = (ROOT / "src/native_unpack.zig").read_text(errors="strict")
    for required in (
        "matchesStructuralLink(fact, authority.structural_links)",
        "parsed_records.append(allocator, parsed) catch |err|",
        ".structural_links = if (snapshot_sudo_postinst and",
        "verifySnapshotSudoStructuralOwner(allocator, root, program)",
        "verifySnapshotSudoPostinstPaths(",
        ".snapshot_sudo_proc = true",
    ):
        if required not in alternatives and required not in unpack:
            fail(f"reviewed signed sudo alternatives admission changed: {required}")
    for required in (
        "if (matchesSnapshotPython3Preinst(bytes)) {",
        '.paths = &.{"dev/null"}',
        '"/usr/share/doc/python3/html"',
    ):
        if required not in alternatives:
            fail(f"reviewed signed python3 inert script grammar changed: {required}")
    for required in (
        "snapshotPython3PreinstIsBound(",
        "snapshotPython3PreinstIsInert(",
        "verifySnapshotPython3PreinstPaths(",
        "verifySnapshotPython3PreinstInputs(allocator, root, program)",
        "verifySnapshotPython3NullOutput(allocator, root)",
        "observed.entry.mode != 0o600 and observed.entry.mode != 0o644",
        "verifySnapshotPython3NullInput(allocator, root, program)",
        'if (!std.mem.eql(u8, architecture, "amd64"))',
        'try verifySnapshotPython3PreinstArtifacts(program.artifacts, "amd64");',
        "for (snapshot_python3_minimal_null_sources) |binding| try verifySignedDebconfControlFile(",
        'const snapshot_python3_minimal_null_input = SignedDebconfControlFile{\n'
        '    .path = "dev/null",\n    .size = 20,\n    .mode = 0o644,\n'
        '    .sha256 = "e212fd644ebc9508a5494c1d69e26c62e23b5695d797588603dd870af154751e",',
        'const snapshot_python3_minimal_postinst = SignedDebconfControlFile{\n'
        '    .path = "var/lib/dpkg/info/python3-minimal.postinst",\n'
        '    .size = 117,\n    .mode = 0o755,\n'
        '    .sha256 = "be10656c9edf975f5dfe48fe5819172e905e14dcd4ff372af5d8b45b26168edd",',
        '        .path = "usr/bin/py3compile",\n        .size = 13312,\n'
        '        .mode = 0o755,\n'
        '        .sha256 = "a94b6fd8fb7f801f564da4dbb3e2d646b54713b58349d725c650885a5a0c6ccc",',
        '        .size = 0,\n        .mode = @intCast(entry.mode),\n'
        '        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",',
        'root,\n        96,\n        "3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc"',
        '"usr/sbin/rm"',
    ):
        if required not in unpack:
            fail(f"reviewed signed python3 root and output proof changed: {required}")
    for required in (
        "fn appendAutomaticFileTriggerEvent(",
        "std.mem.eql(u8, interest.package.name, source.name)",
        "interest.package.architecture.len == 0 and",
        "std.mem.eql(u8, source.architecture, native_architecture)",
        "try eligible.append(allocator, interest);",
        "const FileTriggerPathEvents = struct",
        "while (cursor) |component| : (cursor = std.fs.path.dirname(component)) {",
        "if (self.work > (Limits{}).max_work) return error.TriggerWorkLimit;",
        "const trigger = self.paths.get(component) orelse continue;",
        "if ((try self.noted.getOrPut(self.allocator, trigger)).found_existing) continue;",
        "try appendAutomaticFileTriggerEvent(sink.allocator, sink.events, sink.source, architecture, trigger, self.interests);",
        "for (model.files) |file| {\n        try file_events.activate(.{",
        "}, architecture, diversions.physical(file.path, model.facts.package));",
        "try file_events.activate(sink, model.native_architecture, names.get(physical) orelse physical);",
        "persistRuntimeTriggerEvents(&resumed, testing.allocator, root, &.{forged})",
    ):
        if required not in unpack:
            fail(f"reviewed automatic file-trigger self-interest boundary changed: {required}")
    for required in (
        'const arm64 = std.mem.eql(u8, architecture, "arm64") and\n'
        '        std.mem.eql(u8, package.architecture, "arm64");',
        "if ((!amd64 and !arm64) or",
        "const SnapshotAlternativesArm64Artifact = struct {",
        "const snapshot_less_arm64_artifacts = [_]SnapshotAlternativesArm64Artifact{",
        "const snapshot_less_arm64_controls = [_]SignedDebconfControlFile{",
        "const snapshot_less_arm64_postinst_controls = [_]SignedDebconfControlFile{",
        "if ((less_inert or snapshot_postinst) and std.mem.eql(u8, architecture, \"arm64\")) {",
        'if (action_kind != .script or !std.mem.eql(u8, program.target_architecture, "arm64"))',
        "try verifySnapshotLessArm64Inputs(allocator, root, program.artifacts, program.target_architecture, kind);",
        "try bindSnapshotLessArm64ImmutableInputs(&script, kind);",
        'stat.uid != 0 or stat.gid != 0 or stat.mode != 0o40700)',
        '"etc/ld.so.preload",',
        'const snapshot_less_arm64_absent = snapshot_loader_arm64_absent ++ [_][]const u8{"etc/ld.so.cache"};',
        "var contents = try proc.observeAlloc(allocator, 0, 0);",
        "entry.mode != 0o777 or entry.uid != 0 or entry.gid != 0 or",
        "try attempt.requireRecovery(allocator, .script);",
    ):
        if required not in unpack:
            fail(f"reviewed exact arm64 less callback boundary changed: {required}")
    for required in (
        'if (snapshot_bash_postinst and std.mem.eql(u8, architecture, "arm64")) {',
        'bash_cache_fact = try verifySnapshotBashArm64Inputs(allocator, root, program.artifacts, program.target_architecture);',
        'native_alternatives.matchesSnapshotBashPostinst(script_bytes))\n'
        '            _ = verifySnapshotBashArm64Inputs(',
        'const snapshot_bash_arm64_artifacts = [_]SnapshotAlternativesArm64Artifact{',
        'const snapshot_bash_arm64_controls = [_]SignedDebconfControlFile{',
        '.path = "var/lib/dpkg/info/libtinfo6:arm64.list"',
        '"usr/bin/update-menus",\n    "usr/sbin/update-menus",',
    ):
        if required not in unpack:
            fail(f"reviewed exact arm64 bash callback boundary changed: {required}")
    less_reference = (ROOT / "tools/real-snapshot-less-reference.sh").read_text(errors="strict")
    for required in (
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_ROOT="$source_root"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_PREINST_ROOT="$source_root"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_SCRIPT_AFTER="$script_root"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_DPKG_AFTER="$dpkg_root"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_SCRIPT_ROOT="$bad_script"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_MODE_ROOT="$bad_mode"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_TOOL_ROOT="$bad_tool"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_ALIAS_ROOT="$bad_alias"',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_PRESTATE_ROOT="$bad_prestate"',
        '"$zig" build test-native-unpack -Doptimize=ReleaseSafe -j2 --summary all',
        "unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private --",
        "/bin/sh /var/lib/debz-lifecycle-scripts/less.preinst install",
    ):
        if required not in less_reference:
            fail(f"protected arm64 less activated proof wiring changed: {required}")
    if ("\ncheck_source_inputs\n" not in less_reference or
            less_reference.index("\ncheck_source_inputs\n") > less_reference.index("cp -a --reflink=auto")):
        fail("protected arm64 less source guard must run before fixture copies/mutations")
    less_fixtures = (ROOT / "tools/real_snapshot_less_fixtures.py").read_text(errors="strict")
    for required in (
        "parent_fd = open_beneath(root_fd, parent, directory=True)",
        "os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC",
        "metadata = os.fstat(descriptor)",
        "not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1",
        "regular_metadata(descriptor)\n    os.ftruncate(descriptor, 0)",
        "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC",
        "protected(root, directory=True)",
    ):
        if required not in less_fixtures:
            fail(f"protected arm64 less no-follow fixture mutation boundary changed: {required}")
    if "os.O_TRUNC" in less_fixtures:
        fail("protected arm64 less fixture must check opened metadata before truncation")
    live_root = (ROOT / "src/live_root.zig").read_text(errors="strict")
    if "linux.syscall3(\n        .open_tree," not in live_root:
        fail("live-root detached open_tree boundary changed")
    if "linux.syscall5(\n        .mount_setattr," not in live_root:
        fail("live-root detached propagation boundary changed")


def audit_dependencies() -> None:
    policy = json.loads((ROOT / "security/dependency-policy.json").read_text())
    runtime = json.loads((ROOT / "security/runtime-dependencies.json").read_text())
    reviewed_on = date.fromisoformat(policy["reviewed_on"])
    if reviewed_on > date.today():
        fail("dependency review date is in the future")
    if date.today() > date.fromisoformat(policy["review_expires"]):
        fail("dependency vulnerability/license review has expired")
    allowed_licenses = set(policy["allowed_production_licenses"])
    dependencies = {item["name"]: item for item in policy["production_dependencies"]}
    if set(dependencies) != {"libsolv", "liblzma", "libzstd", "musl"}:
        fail("dependency policy does not exactly enumerate production dependencies")
    for dependency in dependencies.values():
        if dependency["license"] not in allowed_licenses:
            fail(f"{dependency['name']}: license is outside the production allowlist")
        if not dependency.get("runtime_linkage"):
            fail(f"{dependency['name']}: runtime linkage is missing")
        if not dependency["vulnerability_sources"] or not all(
            source.startswith("https://") for source in dependency["vulnerability_sources"]
        ):
            fail(f"{dependency['name']}: vulnerability review sources are missing")
        review = dependency.get("vulnerability_review", {})
        if review.get("reviewed_on") != policy["reviewed_on"]:
            fail(f"{dependency['name']}: vulnerability review evidence is stale")
        if review.get("result") not in {"no_known_unresolved_advisories", "reviewed_exceptions"}:
            fail(f"{dependency['name']}: vulnerability review result is missing")
        if review.get("result") == "reviewed_exceptions" and not dependency["reviewed_exceptions"]:
            fail(f"{dependency['name']}: vulnerability exceptions are not enumerated")

    musl = dependencies["musl"]
    if {
        "source": musl.get("source"),
        "upstream_version": musl.get("upstream_version"),
        "zig_musl_baseline_commit": musl.get("zig_musl_baseline_commit"),
        "toolchain_version": musl.get("toolchain_version"),
        "toolchain_commit": musl.get("toolchain_commit"),
        "toolchain_source_archive": musl.get("toolchain_source_archive"),
        "toolchain_source_sha256": musl.get("toolchain_source_sha256"),
        "version": musl.get("version"),
        "license": musl.get("license"),
        "runtime_linkage": musl.get("runtime_linkage"),
    } != {
        "source": "https://codeberg.org/ziglang/zig/src/tag/0.16.0/lib/libc/musl",
        "upstream_version": "1.2.5",
        "zig_musl_baseline_commit": "0098e650fbceae74c8c468716c0810476f72ec47",
        "toolchain_version": "0.16.0",
        "toolchain_commit": "24fdd5b7a4c1c8b5deb5b56756b9dbc8e08c86a8",
        "toolchain_source_archive": "https://ziglang.org/download/0.16.0/zig-0.16.0.tar.xz",
        "toolchain_source_sha256": "43186959edc87d5c7a1be7b7d2a25efffd22ce5807c7af99067f86f99641bfdf",
        "version": "1.2.5+zig.0.16.0.24fdd5b7a4c1",
        "license": "MIT",
        "runtime_linkage": "static_libc_in_debz",
    }:
        fail("musl provenance differs from the reviewed Zig 0.16.0 toolchain snapshot")
    musl_exceptions = {
        item.get("id"): item.get("disposition")
        for item in musl.get("reviewed_exceptions", [])
        if isinstance(item, dict)
    }
    if musl_exceptions != {
        "CVE-2025-26519": "patched_in_toolchain",
        "CVE-2026-40200": "not_affected",
        "CVE-2026-6042": "not_linked",
    }:
        fail("musl vulnerability review exceptions are incomplete")
    if any(
        not isinstance(item, dict) or not item.get("rationale")
        for item in musl.get("reviewed_exceptions", [])
    ):
        fail("musl vulnerability review exceptions lack rationale")

    zon = (ROOT / "build.zig.zon").read_text()
    dependency_blocks = re.findall(
        r"\.(\w+)\s*=\s*\.\{\s*\.url\s*=\s*\"([^\"]+)\"\s*,\s*"
        r"\.hash\s*=\s*\"([^\"]+)\"",
        zon,
        re.DOTALL,
    )
    expected = {
        "libsolv": (
            "git+https://github.com/cataggar/libsolv.git#"
            "e190ef1433e5df60a2238b01438927eb76c285f5",
            "libsolv-0.7.39-PoNzeg2EIACYnSAYc3_WneVukScmmV-vyo_5guzBzqdO",
            "libsolv",
            "e190ef1433e5df60a2238b01438927eb76c285f5",
        ),
        "xz": (
            "https://github.com/tukaani-project/xz/archive/"
            "4b73f2ec19a99ef465282fbce633e8deb33691b3.tar.gz",
            "N-V-__8AAPy-ZQDvb3F10PKDTFyFXk7kwDjstLisczD0n9Fs",
            "liblzma",
            "4b73f2ec19a99ef465282fbce633e8deb33691b3",
        ),
        "zstd": (
            "https://github.com/cataggar/zstd/archive/"
            "45b6dfcd9d0ffdba99fb653c66b233179b9f7229.tar.gz",
            "zstd-1.6.0-Nyx42oXYOwBmgYjxuZ626Tlfrk3xMm0DYTwXB2nkhQBc",
            "libzstd",
            "45b6dfcd9d0ffdba99fb653c66b233179b9f7229",
        ),
    }
    found = {name: (url, digest) for name, url, digest in dependency_blocks}
    expected_pins = {name: values[:2] for name, values in expected.items()}
    if found != expected_pins:
        fail(f"build.zig.zon dependencies differ from reviewed exact pins: {found!r}")
    for manifest_name, (url, digest, policy_name, commit) in expected.items():
        dependency = dependencies[policy_name]
        if (
            dependency.get("commit") != commit
            or dependency.get("zig_hash") != digest
            or commit not in url
        ):
            fail(f"{policy_name}: manifest pin differs from dependency policy")
        if not (
            re.search(r"#[0-9a-f]{40}$", url)
            or re.search(r"/[0-9a-f]{40}\.tar\.gz$", url)
        ):
            fail(f"{manifest_name}: dependency URL is not pinned to an exact commit")

    build = (ROOT / "build.zig").read_text()
    zon_version = re.search(r'\.version\s*=\s*"([^"]+)"', zon)
    build_version = re.search(r'const package_version\s*=\s*"([^"]+)"', build)
    if zon_version is None or build_version is None or zon_version.group(1) != build_version.group(1):
        fail("default build version differs from build.zig.zon")
    system_libraries = set(re.findall(r'linkSystemLibrary\("([^"]+)"', build))
    if system_libraries:
        fail(f"unreviewed system libraries: {sorted(system_libraries)}")
    for message in runtime_metadata_failures(runtime, dependencies):
        fail(message)
    for message in release_install_metadata_failures(build):
        fail(message)
    if "const target = b.standardTargetOptions(.{});" not in build:
        fail("ordinary builds must preserve standard target option propagation")
    for message in dependency_option_failures(build, "libsolv", {"shared": "false"}):
        fail(message)
    for message in dependency_option_failures(
        build,
        "zstd",
        {
            "target": "target",
            "optimize": "optimize",
            "shared": "false",
            "tools": "false",
            "multithread": "false",
        },
    ):
        fail(message)
    if (
        "debz.link_libc = true" not in build
        or 'b.dependency("xz"' not in build
        or "liblzma_build.addStaticLibrary" not in build
        or "debz.linkLibrary(liblzma)" not in build
        or "debz.linkLibrary(zstd)" not in build
    ):
        fail("build linkage differs from documented runtime dependency model")
    liblzma_build = (ROOT / "build/liblzma.zig").read_text()
    if (
        "stream_decoder_mt.c" in liblzma_build
        or "encoder.c" in liblzma_build
        or '"HAVE_DECODERS"' not in liblzma_build
        or '"HAVE_CHECK_SHA256"' not in liblzma_build
    ):
        fail("repository-local liblzma build is not the reviewed single-threaded decoder configuration")

    notices = (ROOT / "THIRD_PARTY_NOTICES").read_text()
    for required in (
        "libsolv",
        "BSD-3-Clause",
        "XZ Utils liblzma",
        "Zstandard libzstd",
        "0BSD",
        "musl libc",
        "1.2.5+zig.0.16.0.24fdd5b7a4c1",
        "43186959edc87d5c7a1be7b7d2a25efffd22ce5807c7af99067f86f99641bfdf",
        "MIT",
    ):
        if required not in notices:
            fail(f"THIRD_PARTY_NOTICES is missing {required!r}")
    production_notices = notices.split("OpenPGP fixture", 1)[0]
    if re.search(r"\b(?:GPL|LGPL|AGPL)(?:-|\b)", production_notices):
        fail("GPL/LGPL/AGPL production dependency is not permitted")


def audit_release_targets() -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    expected = ("x86_64-linux-musl", "aarch64-linux-musl")
    jobs = (
        ("release.yml binaries", re.search(r"(?ms)^  binaries:\n(.*?)(?=^  \S|\Z)", release)),
        (
            "ci.yml release-dry-run",
            re.search(r"(?ms)^  release-dry-run:\n(.*?)(?=^  \S|\Z)", ci),
        ),
    )
    for workflow, match in jobs:
        if match is None:
            fail(f"{workflow}: release job is missing")
            continue
        text = match.group(1)
        for target in expected:
            if text.count(f"target: {target}") != 1:
                fail(f"{workflow}: release matrix must contain exactly one {target} target")
        for target in ("x86_64-linux-gnu", "aarch64-linux-gnu"):
            if f"target: {target}" in text:
                fail(f"{workflow}: release matrix retains dynamic GNU target {target}")


def workflow_failure_handling_failures(text: str, label: str) -> list[str]:
    failures = []
    native_negative_steps = {
        "Refuse legacy lock in native action": ("native-foreign-lock", "NATIVE"),
        "Refuse native lock in default legacy action": ("legacy-foreign-lock", "LEGACY"),
    }
    allowed_negative_steps = {
        "Reject corrupt package object",
        "Reject package-only offline restore",
        *native_negative_steps,
    }
    allowed_continue = 0
    for match in re.finditer(
        r"(?ms)^\s*-\s+name:\s*(?P<name>[^\n]+)\n(?P<body>(?:\s{8,}[^\n]*\n)*)",
        text,
    ):
        body = match.group("body")
        if not re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", body):
            continue
        name = match.group("name").strip()
        if name not in allowed_negative_steps:
            failures.append(f"{label}: workflow hides a failing command")
        if name in native_negative_steps:
            step_id, prefix = native_negative_steps[name]
            required = (
                "Validate explicit backend refusal",
                f"{prefix}_OUTCOME: ${{{{ steps.{step_id}.outcome }}}}",
                f"{prefix}_PATH: ${{{{ steps.{step_id}.outputs.cache-path }}}}",
                f'test "${prefix}_OUTCOME" = failure',
                f'test -z "${prefix}_PATH"',
            )
            if (
                f"id: {step_id}" not in body
                or "uses: ./actions/download" not in body
                or any(token not in text for token in required)
            ):
                failures.append(
                    f"{label}: native backend refusal coverage lacks bound outcome assertions"
                )
        allowed_continue += 1
    if text.count("continue-on-error: true") != allowed_continue:
        failures.append(f"{label}: workflow has an unaudited continue-on-error")
    if allowed_continue and (
        "Validate corrupt-object failure" not in text
        or "Validate offline metadata failure" not in text
        or 'test "$OUTCOME" = failure' not in text
    ):
        failures.append(f"{label}: expected-failure action coverage lacks outcome assertions")
    return failures


DIVERSION_CASE_SHARDS = ((1, 25), (26, 50), (51, 75), (76, 100))

RECOVERY_ZIG_SHARDS = {
    "native-recovery-zig-workflows": (
        "Native crash recovery Zig core (${{ matrix.name }})",
        "Exercise Zig core recovery",
        ("test-native-recovery-zig",),
    ),
    "native-recovery-zig-repository": (
        "Native crash recovery Zig repository (${{ matrix.name }})",
        "Exercise Zig repository recovery",
        ("test-native-recovery-zig-repository",),
    ),
    "native-recovery-zig-helper": (
        "Native crash recovery Zig helper, bootstrap, parity and rollback (${{ matrix.name }})",
        "Exercise Zig helper, bootstrap, parity and rollback recovery",
        (
            "test-native-recovery-helper-zig",
            "test-native-recovery-zig-bootstrap",
            "test-native-recovery-zig-parity",
            "test-native-recovery-zig-rollback-clock",
        ),
    ),
    "native-recovery-zig-family": (
        "Native crash recovery Zig signed FAMILY (${{ matrix.name }})",
        "Exercise Zig signed FAMILY recovery",
        ("test-native-recovery-zig-family",),
    ),
    "native-recovery-zig-scenarios": (
        "Native crash recovery Zig scenario matrices (${{ matrix.name }})",
        "Exercise Zig recovery scenario and mutation matrices",
        (
            "test-native-recovery-zig-scriptless",
            "test-native-recovery-zig-statoverride",
            "test-native-recovery-zig-literal",
            "test-native-recovery-zig-metadata",
            "test-native-recovery-zig-publication",
            "test-native-recovery-zig-conffile",
            "test-native-recovery-zig-final-gaps",
            "test-native-recovery-zig-mutation-boundaries",
        ),
    ),
    "native-recovery-zig-diversions": (
        "Native crash recovery Zig diversion shard (${{ matrix.name }} / ${{ matrix.shard }})",
        "Exercise counted Zig diversion recovery shard",
        ("test-native-recovery-zig-diversions",),
    ),
}


ROOT_IMPORT_STEP = "Compare pinned-dpkg root import and copied-root refusals"
ROOT_IMPORT_COMMANDS = [
    "mkdir -p .tmp",
    'reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
    'zig build test-native-root-import -Dnative-reference-dpkg="$reference_dpkg" -j2 --summary all',
    'zig build test-native-root-import -Dnative-reference-dpkg="$reference_dpkg" -Doptimize=ReleaseSafe -j2 --summary all',
]


def recovery_zig_commands(targets: tuple[str, ...], *, sharded: bool = False) -> list[str]:
    shard_option = ' -Dnative-zig-recovery-diversion-shard="${{ matrix.shard }}"' if sharded else ""
    return [
        f'zig build {target}{shard_option} -Dnative-reference-dpkg="$reference_dpkg"{mode} -j2 --summary all'
        for target in targets
        for mode in ("", " -Doptimize=ReleaseSafe")
    ]


WORKLOAD_TIMEOUT_MINUTES = 45
WORKLOAD_PARTITIONS = {
    "workload_core": ("test-workload-core", (
        "run_tests", "run_repository_cli_tests", "cli_tests", "no_args_help",
        "positional_help", "removed_version_flag", "consumer_tests",
        "run_real_snapshot_comparator_tests", "run_reference_runtime_tests",
        "run_script_network_probe_tests",
        "run_http_fixture_tests",
        "run_debian_closure_inventory_tests",
        "run_apt_acceptance_unit_tests", "repository_add_tests",
    )),
    "workload_production": ("test-workload-production", (
        "run_package_family_tests", "run_production_backend_tests",
        "run_required_production_security_tests", "run_production_customize_tests",
    )),
    "workload_apt_system": ("test-workload-apt-system", (
        "run_system_profile_tests", "run_apt_system_api_tests", "run_apt_system_cli_tests",
        "run_apt_system_command_tests", "run_apt_system_state_tests",
        "run_apt_system_orchestrator_tests", "run_required_orchestrator_security_tests",
    )),
    "workload_native": ("test-workload-native", (
        "run_native_program_corpus_tests",
        "run_native_alternatives_tests", "run_native_alternatives_oracle_tests",
        "run_native_snapshot_tests", "run_native_differential_zig_tests",
        "run_native_fixture_tests", "run_native_conffile_zig_tests",
        "dpkg_config_reference_tests", "dpkg_alternatives_reference_tests",
        "dpkg_oracle_evidence_tests", "signed_proc_compare_tests", "run_sha512_e2e_tests",
        "run_native_trigger_queue_tests", "run_lifecycle_zig_tests",
        "run_trigger_zig_tests", "run_settlement_tests", "run_recovery_unit_tests",
        "run_native_recovery_tests", "phase_telemetry_step", "run_repository_recovery_unit",
        "run_package_cache_archive_tests",
    )),
    "workload_release": ("test-workload-release", (
        "run_apt_schema_tests", "native_only_rehearsal", "run_snapshot_repin_tests",
    )),
}
WORKLOAD_HELP_BINDING = "addHelpFlagTests(b, workload_core, cli, case.args, case.usage);"


def workload_partition_failures(build: str) -> list[str]:
    """Prove `zig build test` is exactly the disjoint union of the CI partitions."""
    failures: list[str] = []
    if build.count('const test_step = b.step("test", ') != 1:
        failures.append("build.zig: aggregate test step must be declared exactly once")
    aggregate = re.findall(r"(?m)^[ \t]*test_step\.dependOn\(([^\n]*)\);[ \t]*$", build)
    if aggregate != list(WORKLOAD_PARTITIONS) or len(re.findall(r"\btest_step\b", build)) != 1 + len(WORKLOAD_PARTITIONS):
        failures.append("build.zig: aggregate test step must depend only on every workload partition")
    expected = []
    for variable, (step_name, members) in WORKLOAD_PARTITIONS.items():
        declaration = f'const {variable} = b.step("{step_name}", '
        if build.count(declaration) != 1 or build.count(f'"{step_name}"') != 1:
            failures.append(f"build.zig: workload partition {step_name} must be declared exactly once")
        references = len(re.findall(rf"\b{variable}\b", build))
        if references != 2 + len(members) + (variable == "workload_core"):
            failures.append(f"build.zig: workload partition {step_name} has an unreviewed binding")
        expected.extend((variable, member) for member in members)
    actual = re.findall(
        r"(?m)^[ \t]*(workload_[a-z_]+)\.dependOn\(&?([A-Za-z_][A-Za-z0-9_]*)(?:\.step)?\);[ \t]*$",
        build,
    )
    members = [member for _, member in actual]
    if sorted(actual) != sorted(expected) or len(members) != len(set(members)):
        failures.append("build.zig: every former test member must run in exactly one workload partition")
    if build.count(WORKLOAD_HELP_BINDING) != 1 or build.count("addHelpFlagTests(") != 2:
        failures.append("build.zig: CLI help flag tests must run only in the core workload partition")
    return failures


WORKLOAD_MATRIX = (
    "      fail-fast: false\n"
    "      matrix:\n"
    "        name: [linux-x64, linux-arm64]\n"
    "        optimize: [Debug, ReleaseSafe]\n"
    "        include:\n"
    "          - os: ubuntu-24.04\n"
    "            name: linux-x64\n"
    "            architecture: amd64\n"
    "          - os: ubuntu-24.04-arm\n"
    "            name: linux-arm64\n"
    "            architecture: arm64\n"
)
WORKLOAD_SETUP_STEPS = (
    "Install Zig via ghr", "Validate Zig version", "Install metadata decompression dependency",
)
WORKLOAD_SETUP_LINES = (
    "          persist-credentials: false",
    "        uses: cataggar/ghr/actions/install@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e # v0.8.1",
    "          ghr-version: v0.8.1",
    "            cataggar/zig@v0.16.0",
    "            RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U",
    '        run: test "$(zig version)" = 0.16.0',
    "            sudo apt-get install --yes --no-install-recommends liblzma-dev libzstd-dev python3-jsonschema",
)
# Only the sudo-free core partition may use the trusted self-hosted pool; every
# root-requiring workload keeps the disposable GitHub-hosted runner.
WORKLOAD_RUNS_ON = "    runs-on: ${{ matrix.os }}"
WORKLOAD_CORE_RUNS_ON = (
    "    runs-on: ${{ (github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository) && "
    "fromJSON(format('[\"self-hosted\",\"Linux\",\"{0}\",\"ubuntu2604\"]', "
    "matrix.os == 'ubuntu-24.04-arm' && 'ARM64' || 'X64')) || matrix.os }}"
)
WORKLOAD_DEBUG = "${{ matrix.optimize == 'Debug' }}"
WORKLOAD_RELEASESAFE = "${{ matrix.optimize == 'ReleaseSafe' }}"
WORKLOAD_PREPARE_DPKG = 'reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"'
WORKLOAD_DPKG_MODE = '-Dnative-reference-dpkg="$reference_dpkg" -Doptimize="$OPTIMIZE" -j2 --summary all'
WORKLOAD_MODE = '-Doptimize="$OPTIMIZE" -j2 --summary all'
WORKLOAD_SELECTOR_COMMANDS = [
    WORKLOAD_PREPARE_DPKG,
    f"zig build build-native-acceptance-zig {WORKLOAD_MODE}",
    'lifecycle="$PWD/.tmp/zig-lifecycle-workspace-$OPTIMIZE"',
    'trigger="$PWD/.tmp/zig-trigger-workspace-$OPTIMIZE"',
    'sudo -n env TMPDIR="$PWD/.tmp" XDG_CACHE_HOME="$PWD/.cache" '
    "zig-out/bin/native-lifecycle-zig-acceptance --oracle-only --diversions-only "
    '--reference-dpkg "$reference_dpkg" --workspace "$lifecycle"',
    'sudo -n env TMPDIR="$PWD/.tmp" XDG_CACHE_HOME="$PWD/.cache" '
    "zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only "
    '--reference-dpkg "$reference_dpkg" --workspace "$trigger"',
    'test -d "$lifecycle" && test -d "$trigger"',
    'if sudo -n env TMPDIR="$PWD/.tmp" XDG_CACHE_HOME="$PWD/.cache" '
    "zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only "
    '--diversions-only --reference-dpkg "$reference_dpkg" '
    '2>"$PWD/.tmp/zig-invalid-selector.log"; then exit 1; fi',
    "grep -Fxq 'error: InvalidSettlementSelection' \"$PWD/.tmp/zig-invalid-selector.log\"",
    'if sudo -n env TMPDIR="$PWD/.tmp" XDG_CACHE_HOME="$PWD/.cache" '
    "zig-out/bin/native-lifecycle-zig-acceptance --oracle-only "
    '--reference-dpkg "$reference_dpkg" --workspace "$lifecycle" '
    '2>"$PWD/.tmp/zig-existing-workspace.log"; then exit 1; fi',
    "grep -Fxq 'error: PathAlreadyExists' \"$PWD/.tmp/zig-existing-workspace.log\"",
]
# Every step after the shared setup: (condition, exact logical commands or None, required lines).
WORKLOAD_JOBS = {
    "build-and-test-workload": ("core", {
        "Build and test workload core": (None, [
            f"zig build {WORKLOAD_MODE}",
            f"zig build test-workload-core {WORKLOAD_MODE}",
        ], ()),
        "Check ReleaseSafe CLI help": (WORKLOAD_RELEASESAFE, [
            "zig build -Doptimize=ReleaseSafe -j2 run -- --help",
        ], ()),
        "Prepare native download action fixture": (WORKLOAD_RELEASESAFE, None, (
            "        id: download-fixture",
            "          python3 tools/generate-integration-repository.py \\",
            "          zig-out/bin/debz plan \\",
            '          printf \'%s\\n\' "$PWD/zig-out/bin" >>"$GITHUB_PATH"',
        )),
        "Prepare native exact-lock package closure": (WORKLOAD_RELEASESAFE, None, (
            "        id: download",
            "        uses: ./actions/download",
            "          lock-input: ${{ steps.download-fixture.outputs.lock }}",
            "          cache: 'false'",
        )),
        "Validate native download action outputs": (WORKLOAD_RELEASESAFE, [
            'test "$CACHE_HIT" = false',
            'test -d "$CACHE_PATH"',
            'test "$DOWNLOADED" -gt 0',
            'test "$REUSED" -eq 0',
        ], ()),
    }),
    "build-and-test-workload-production": ("production", {
        "Build and test workload production": (None, [
            f"zig build test-workload-production {WORKLOAD_MODE}",
        ], ()),
        "Compare native triggers and diversion settlement with dpkg": (None, [
            "mkdir -p .tmp",
            WORKLOAD_PREPARE_DPKG,
            f"zig build test-native-triggers-zig test-native-diversion-settlement-zig {WORKLOAD_DPKG_MODE}",
        ], ()),
    }),
    "build-and-test-workload-apt-system": ("apt system", {
        "Build and test workload apt system": (None, [
            f"zig build test-workload-apt-system {WORKLOAD_MODE}",
        ], ()),
        "Run required real apt facade acceptance": (None, [
            'sudo env PATH="$PATH" TMPDIR="$PWD/.zig-cache" '
            'PYTHONPYCACHEPREFIX="$PWD/.zig-cache/pycache" '
            'ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-cache/apt-system-acceptance-global" '
            'ZIG_LOCAL_CACHE_DIR="$PWD/.zig-cache/apt-system-acceptance-local" '
            f'"$(command -v zig)" build test-apt-system-acceptance {WORKLOAD_MODE}',
        ], ()),
        "Normalize apt facade acceptance diagnostics": ("${{ always() }}", [
            'sudo chown -R "$USER:$USER" .zig-cache/apt-system-acceptance-global '
            ".zig-cache/apt-system-acceptance-local 2>/dev/null || true",
        ], ()),
        "Run required privileged orchestration crash suite": (WORKLOAD_DEBUG, [
            "sudo rm -rf /run/debz",
            'sudo env ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-global-cache-orchestration-required" '
            'ZIG_LOCAL_CACHE_DIR="$PWD/.zig-cache-orchestration-required" '
            '"$(command -v zig)" build test-apt-system '
            "-Drequire-privileged-orchestration-tests=true -j2 --summary all",
        ], ()),
        "Normalize privileged orchestration diagnostics": ("${{ always() && matrix.optimize == 'Debug' }}", [
            'sudo chown -R "$USER:$USER" .zig-cache-orchestration-required '
            ".zig-global-cache-orchestration-required 2>/dev/null || true",
            "sudo rm -rf /run/debz",
        ], ()),
    }),
    "build-and-test-workload-native": ("native", {
        "Build and test workload native": (None, [
            f"zig build test-workload-native {WORKLOAD_MODE}",
        ], ()),
        "Compare native materialization, conffiles, differential, and lifecycle with dpkg": (None, [
            "mkdir -p .tmp",
            WORKLOAD_PREPARE_DPKG,
            "zig build test-native-materialization test-native-conffiles test-native-differential "
            f"{WORKLOAD_DPKG_MODE}",
            f"zig build test-native-lifecycle-zig {WORKLOAD_DPKG_MODE}",
        ], ()),
        "Require private native helper namespaces": (None, [
            f"zig build test-native-helper-namespace {WORKLOAD_MODE}",
        ], ()),
    }),
    "build-and-test-workload-release": ("release", {
        "Build and test workload release": (None, [
            f"zig build test-workload-release {WORKLOAD_MODE}",
            f"zig build fuzz {WORKLOAD_MODE}",
        ], ()),
        "Test release packaging": (WORKLOAD_DEBUG, [
            "zig build test-release -j2 --summary all",
        ], ()),
        "Run pinned dpkg lifecycle and trigger reference oracles": (None, [
            "mkdir -p .tmp",
            WORKLOAD_PREPARE_DPKG,
            "zig build test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle "
            f"test-native-triggers-zig-settlement-reference {WORKLOAD_DPKG_MODE}",
        ], ()),
        "Exercise standalone Zig workspace selectors and fail-closed combinations": (
            None, WORKLOAD_SELECTOR_COMMANDS, (),
        ),
    }),
}
# The retired single workload ran these Zig targets once per mode; each must stay exactly once.
WORKLOAD_ZIG_TARGETS = (
    "install", "run", "test-release", "fuzz", "build-native-acceptance-zig",
    "test-native-materialization", "test-native-conffiles", "test-native-differential",
    "test-native-lifecycle-zig", "test-native-triggers-zig", "test-native-diversion-settlement-zig",
    "test-native-lifecycle-zig-oracle", "test-native-triggers-zig-oracle",
    "test-native-triggers-zig-settlement-reference", "test-native-helper-namespace",
    "test-apt-system-acceptance", "test-apt-system",
    *(step_name for step_name, _ in WORKLOAD_PARTITIONS.values()),
)
WORKLOAD_RESULTS = (
    ("BUILD_RESULT", "build-and-test-workload"),
    ("BUILD_PRODUCTION_RESULT", "build-and-test-workload-production"),
    ("BUILD_APT_SYSTEM_RESULT", "build-and-test-workload-apt-system"),
    ("BUILD_NATIVE_RESULT", "build-and-test-workload-native"),
    ("BUILD_RELEASE_RESULT", "build-and-test-workload-release"),
)
CI_FULL_MATRIX_INPUT = """\
      run_full_matrix:
        description: "Run the standard build/test matrix (off for snapshot-only validation)"
        required: true
        type: boolean
        default: true
"""
CI_FULL_MATRIX_CONDITION = "github.event_name != 'workflow_dispatch' || inputs.run_full_matrix"
CI_BUILD_AGGREGATE_CONDITION = "${{ always() && (" + CI_FULL_MATRIX_CONDITION + ") }}"
CI_FULL_INTEGRATION_CONDITION = (
    "github.event_name == 'schedule' || "
    "(github.event_name == 'workflow_dispatch' && inputs.run_full_matrix)"
)


def ci_dispatch_matrix_failures(text: str, jobs: dict[str, str]) -> list[str]:
    failures: list[str] = []
    dispatch = re.search(
        r"(?m)^  workflow_dispatch:\n    inputs:\n((?: {6,}[^\n]*\n)*)", text,
    )
    if (
        dispatch is None or dispatch.group(1).count(CI_FULL_MATRIX_INPUT) != 1
        or re.findall(r"(?m)^      run_full_matrix:[^\n]*$", text)
        != ["      run_full_matrix:"]
    ):
        failures.append("ci.yml: run_full_matrix must be a required boolean dispatch input defaulting to true")
    conditions = {
        **{name: CI_FULL_MATRIX_CONDITION for name in (*WORKLOAD_JOBS, *RECOVERY_ZIG_SHARDS)},
        "build-and-test": CI_BUILD_AGGREGATE_CONDITION,
        "integration-full": CI_FULL_INTEGRATION_CONDITION,
    }
    for name, condition in conditions.items():
        if re.findall(r"(?m)^    if:[^\n]*$", jobs.get(name, "")) != [f"    if: {condition}"]:
            failures.append(f"ci.yml: {name} must retain its exact dispatch matrix condition")
    if re.search(r"(?m)^    if:", jobs.get("integration-required", "")):
        failures.append("ci.yml: required integration roots must remain unconditional")
    return failures


def workflow_logical_commands(step: str) -> list[str] | None:
    """Return a step's shell commands with continuations joined and comments dropped."""
    single = re.findall(r"(?m)^        run: (?!\|)([^\n]+)$", step)
    if single:
        return [single[0].strip()] if len(single) == 1 and "        run: |\n" not in step else None
    script = step.split("        run: |\n")
    if len(script) != 2:
        return None
    commands: list[str] = []
    pending = ""
    for raw in script[1].splitlines():
        line = raw.strip()
        if not line or (not pending and line.startswith("#")):
            continue
        pending = f"{pending} {line}".strip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        commands.append(pending)
        pending = ""
    if pending:
        commands.append(pending)
    return commands


def workload_zig_targets(command: str) -> list[str] | None:
    match = re.search(r'(?:^|\s)(?:zig|"\$\(command -v zig\)") build(?=\s|$)(.*)$', command)
    if match is None:
        return None
    targets = []
    tokens = iter(match.group(1).split())
    for token in tokens:
        if token == "--":
            break
        if token in ("--summary", "--prefix", "--cache-dir", "--global-cache-dir", "--build-file", "-p"):
            next(tokens, None)
        elif not token.startswith("-"):
            targets.append(token)
    return targets or ["install"]


def workflow_zig_invocations(text: str) -> list[list[str]]:
    """Return the targets of every zig build invocation in a workflow."""
    invocations: list[list[str]] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not pending and line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        targets = workload_zig_targets(pending)
        if targets is not None:
            invocations.append(targets)
        pending = ""
    return invocations


def workload_ci_failures(jobs: dict[str, str], text: str) -> list[str]:
    failures: list[str] = []
    shared_setup = None
    inventory: list[str] = []
    for name, (label, expected_steps) in WORKLOAD_JOBS.items():
        body = jobs.get(name, "")
        lines = body.splitlines()
        header = body.split("    steps:\n", 1)[0]
        if (
            f"    name: Build and test workload {label} (${{{{ matrix.name }}}}, ${{{{ matrix.optimize }}}})" not in lines
            or re.findall(r"(?m)^    runs-on:[^\n]*$", body)
            != [WORKLOAD_CORE_RUNS_ON if label == "core" else WORKLOAD_RUNS_ON]
            or re.findall(r"(?m)^    timeout-minutes:[^\n]*$", body)
            != [f"    timeout-minutes: {WORKLOAD_TIMEOUT_MINUTES}"]
            or header.count("    strategy:\n") != 1
            or body.count("    steps:\n") != 1
            or header.split("    strategy:\n", 1)[-1].split("    env:\n", 1)[0] != WORKLOAD_MATRIX
            or header.split("    env:\n", 1)[-1] != "      OPTIMIZE: ${{ matrix.optimize }}\n"
            or re.search(r"(?m)^    (?:needs|continue-on-error):", body)
            or "continue-on-error:" in body
        ):
            failures.append(
                f"ci.yml: {name} must require both architectures and optimization modes "
                f"within {WORKLOAD_TIMEOUT_MINUTES} minutes"
            )
        first_step = next(iter(expected_steps))
        setup = body.split("    steps:\n", 1)[-1].split(f"      - name: {first_step}\n", 1)[0]
        if shared_setup is None:
            shared_setup = setup
        if setup != shared_setup or not setup.startswith(
            "      - uses: actions/checkout@"
        ) or any(f"      - name: {step}\n" not in setup for step in WORKLOAD_SETUP_STEPS) or any(
            line not in setup.splitlines() for line in WORKLOAD_SETUP_LINES
        ) or re.search(r"(?m)^        if:", setup):
            failures.append(f"ci.yml: {name} must retain pinned Zig and metadata dependencies")
        steps = re.findall(r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", body)
        if [step for step, _ in steps] != [*WORKLOAD_SETUP_STEPS, *expected_steps]:
            failures.append(f"ci.yml: {name} has a missing, reordered or unreviewed workload step")
        actual_steps = dict(steps)
        for step_name, (condition, commands, required) in expected_steps.items():
            step = actual_steps.get(step_name, "")
            conditions = re.findall(r"(?m)^        if: ([^\n]*)$", step)
            actual = workflow_logical_commands(step)
            if (
                conditions != ([condition] if condition else [])
                or (commands is not None and actual != commands)
                or (commands is None and actual is not None and any(
                    workload_zig_targets(command) is not None for command in actual
                ))
                or any(line not in step.splitlines() for line in required)
            ):
                mode = {
                    WORKLOAD_DEBUG: "Debug", WORKLOAD_RELEASESAFE: "ReleaseSafe",
                }.get(condition, "every mode")
                failures.append(f"ci.yml: {name} must execute {step_name} exactly as reviewed in {mode}")
        for step in actual_steps.values():
            for command in workflow_logical_commands(step) or []:
                targets = workload_zig_targets(command)
                if targets is not None:
                    inventory.extend(targets)
    if sorted(inventory) != sorted(WORKLOAD_ZIG_TARGETS):
        failures.append("ci.yml: every former build workload target must execute exactly once across the workload jobs")
    invocations = [target for targets in workflow_zig_invocations(text) for target in targets]
    for step_name, _ in WORKLOAD_PARTITIONS.values():
        if invocations.count(step_name) != 1:
            failures.append(f"ci.yml: workload partition {step_name} must execute exactly once")
    if "test" in invocations:
        failures.append("ci.yml: aggregate zig build test must not duplicate the workload partitions")
    return failures


REFERENCE_ROOT_PATHS = (
    ".github/workflows/ci.yml",
    "build.zig",
    "tools/real-snapshot-reference-launcher.zig",
    "tools/real-snapshot-reference-launcher-root-test.zig",
)
REFERENCE_ROOT_STEP = (
    "      - name: Prove root reference capability transition\n"
    "        run: zig build test-real-snapshot-reference-launcher-root --summary all\n"
)


def reference_launcher_root_wiring_failures(
    ci: str, build: str, launcher: str, root_test: str,
) -> list[str]:
    """The root capability proof runs in CI, outside the sudo-free security audit."""
    failures: list[str] = []
    jobs = dict(re.findall(
        r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)", ci,
    ))
    job = jobs.get("security-audit", "")
    step = re.search(
        r"(?ms)^      - name: Prove root reference capability transition\n.*?(?=^      - |^\n|\Z)",
        job,
    )
    if (
        any(line not in job.splitlines() for line in (
            "    name: Security and dependency policy",
            "    runs-on: ubuntu-24.04",
            "        run: zig build security-audit",
        ))
        or re.search(r"(?m)^    (?:if|continue-on-error|strategy):", job)
        or "continue-on-error:" in job
        or step is None or step.group(0) != REFERENCE_ROOT_STEP
        or ci.count("test-real-snapshot-reference-launcher-root") != 1
    ):
        failures.append(
            "ci.yml: the security job must unconditionally prove the root reference capability transition"
        )
    for token in (
        'const run_reference_launcher_tests = b.addRunArtifact(reference_launcher_tests);',
        'audit_step.dependOn(&run_reference_launcher_tests.step);',
        'b.path("tools/real-snapshot-reference-launcher-root-test.zig")',
        'const run_reference_launcher_root_tests = b.addSystemCommand(&.{ "sudo", "-n", "--" });',
        'run_reference_launcher_root_tests.addArtifactArg(reference_launcher_root_tests);',
        'b.step("test-real-snapshot-reference-launcher-root", ',
        '.dependOn(&run_reference_launcher_root_tests.step);',
    ):
        if build.count(token) != 1:
            failures.append(f"build.zig: root reference capability step lost {token}")
    if re.search(r"audit_step\.dependOn\(&run_reference_launcher_root_tests\.step\)", build):
        failures.append("build.zig: security-audit must not require passwordless sudo")
    for token in (
        "pub fn capabilityTransitionProbe() !void {",
        "if (linux.geteuid() != 0 or linux.getuid() != 0) linux.exit(14);",
        "if (linux.W.EXITSTATUS(status) == 14) return error.CapabilityProbeRequiresRoot;",
        'test "reference capability transition fails closed without root authority" {\n'
        "    try unprivilegedTransitionProbe();\n}",
        "if (restrictReferencePrivileges() != .PERM) linux.exit(4);",
    ):
        if launcher.count(token) != 1:
            failures.append(f"reference launcher: root capability refusal lost {token}")
    if (
        "SkipZigTest" in launcher
        or launcher.count("capabilityTransitionProbe(") != 1
        or re.search(r"\.unshare,\s*linux\.CLONE\.NEWUSER", launcher)
    ):
        failures.append(
            "reference launcher: the capability transition must run only in the root step, never skip or use a user namespace"
        )
    expected_root_test = (
        'const launcher = @import("real-snapshot-reference-launcher.zig");\n\n'
        'test "reference capability transition clears ambient and high bounding privileges as root" {\n'
        "    try launcher.capabilityTransitionProbe();\n}\n"
    )
    code = "\n".join(
        line for line in root_test.splitlines() if not line.startswith("//!")
    ).strip() + "\n"
    if code != expected_root_test:
        failures.append("reference launcher root test: must run the capability transition without conditions or skips")
    return failures


PROTECTED_REFERENCE_PATHS = (
    ".github/workflows/ci.yml",
    "build.zig",
    "tools/real-snapshot-reference-protected-ci.sh",
    "tools/real-snapshot-reference-protected-stage.sh",
    "tools/test_real_snapshot_reference_protected.py",
    "tools/real-snapshot-reference-escape-probe.zig",
    "tools/real-snapshot-reference-launcher.zig",
    "tools/real-snapshot-reference-order.py",
    "src/private_network.zig",
    "src/fixtures/script_network_probe.zig",
    "src/maintainer_script.zig",
    "tools/verify-minisign.py",
    "tools/real-snapshot-reference-tree-check.py",
    "tools/real-snapshot-protected-native-ci.sh",
    "tools/real-snapshot-acceptance.sh",
    "tools/real-snapshot-reference.sh",
    "tools/real_snapshot_reference_paths.py",
    "tools/real_snapshot_outcome.py",
    "tools/real-snapshot-python3-protected-stage.sh",
    "tools/real-snapshot-python3-reference.sh",
    "tools/real-snapshot-signed-proc-bindings.sh",
    "tools/real-snapshot-signed-proc-prestates.sh",
    "src/native_unpack.zig",
    "src/native_alternatives.zig",
    "tools/real-snapshot-less-protected-stage.sh",
    "tools/real-snapshot-bash-protected-stage.sh",
    "tools/real-snapshot-less-reference.sh",
    "tools/real_snapshot_less_stage.py",
    "tools/real_snapshot_less_fixtures.py",
    "tools/real_snapshot_python_fixtures.py",
    "tools/prepare-native-dpkg.py",
)
PROTECTED_REFERENCE_INPUT = (
    '      run_protected_reference:\n'
    '        description: "Stage root-owned inputs and run the protected pinned-dpkg reference proof on amd64 and arm64"\n'
    '        required: true\n'
    '        type: boolean\n'
    '        default: false\n'
)

PROTECTED_REFERENCE_HEADER = (
    '  protected-reference:\n'
    "    if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_protected_reference)\n"
    '    name: Protected pinned-dpkg reference (${{ matrix.architecture }})\n'
    '    runs-on: ${{ matrix.runner }}\n'
    '    # Root-run staging: Zig download and package fetch 5, debz build 15,\n'
    '    # snapshot staging 15, preflight refusals 5 and the proof 45 (its own\n'
    '    # timeout), plus amd64 Python staging/replay 40 and Zig guards 10,\n'
    '    # leaving 5 for evidence, upload and cleanup.\n'
    '    timeout-minutes: 140\n'
    '    strategy:\n'
    '      fail-fast: false\n'
    '      matrix:\n'
    '        include:\n'
    '          - architecture: amd64\n'
    '            runner: ubuntu-24.04\n'
    '          - architecture: arm64\n'
    '            runner: ubuntu-24.04-arm\n'
    '    env:\n'
    '      ARCHITECTURE: ${{ matrix.architecture }}\n'
    '      PROTECTED_TREE: /srv/debz-protected/ci-${{ github.run_id }}-${{ github.run_attempt }}-${{ matrix.architecture }}\n'
    '    steps:\n'
    '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n'
    '        with:\n'
    '          persist-credentials: false\n'
)

PROTECTED_REFERENCE_BOOTSTRAP = (
    '      - name: Stage the reviewed commit in a root-owned tree and run the protected proof\n'
    '        timeout-minutes: 130\n'
    '        run: |\n'
    '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"\n'
    '          test -z "$(git status --porcelain)"\n'
    '          bundle="$RUNNER_TEMP/debz-protected-$ARCHITECTURE.bundle"\n'
    '          git bundle create "$bundle" HEAD\n'
    '          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n'
    '            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \\\n'
    "            bash -euo pipefail -c '\n"
    '            tree=$1 architecture=$2 expected=$3 bundle=$4\n'
    '            [[ $tree =~ ^/srv/debz-protected/ci-[0-9]+-[0-9]+-(amd64|arm64)$ ]]\n'
    '            [[ ${BASH_REMATCH[1]} == "$architecture" && $expected =~ ^[0-9a-f]{40}$ ]]\n'
    '            umask 022\n'
    '            [[ -e /srv/debz-protected ]] || mkdir -m 0755 /srv/debz-protected\n'
    '            for ancestor in / /srv /srv/debz-protected; do\n'
    '              [[ -d $ancestor && ! -L $ancestor && $(stat -c %u:%g "$ancestor") == 0:0 ]]\n'
    '              (( ($(stat -c 0%a "$ancestor") & 022) == 0 ))\n'
    '            done\n'
    '            mkdir -m 0700 -- "$tree"\n'
    '            install -o root -g root -m 0600 -- "$bundle" "$tree/debz.bundle"\n'
    '            git init --quiet --bare "$tree/bare.git"\n'
    '            printf "%s\\n" "$expected" >"$tree/bare.git/shallow"\n'
    '            git --git-dir="$tree/bare.git" bundle verify "$tree/debz.bundle"\n'
    '            git --git-dir="$tree/bare.git" fetch --quiet "$tree/debz.bundle" HEAD:refs/heads/protected\n'
    '            test "$(git --git-dir="$tree/bare.git" rev-parse refs/heads/protected)" = "$expected"\n'
    '            git --git-dir="$tree/bare.git" symbolic-ref HEAD refs/heads/protected\n'
    '            git --git-dir="$tree/bare.git" fsck --full --no-dangling\n'
    '            git clone --quiet --no-hardlinks "file://$tree/bare.git" "$tree/checkout"\n'
    '            test "$(git -C "$tree/checkout" rev-parse HEAD)" = "$expected"\n'
    '            exec bash "$tree/checkout/tools/real-snapshot-reference-protected-ci.sh" "$tree" "$architecture" "$expected"\n'
    '            \' protected-bootstrap "$PROTECTED_TREE" "$ARCHITECTURE" "$GITHUB_SHA" "$bundle"\n'
)

PROTECTED_REFERENCE_COPY = (
    '      - name: Copy bounded protected evidence\n'
    '        if: always()\n'
    '        run: |\n'
    '          output="$RUNNER_TEMP/protected-reference-$ARCHITECTURE"\n'
    '          mkdir -p "$output"\n'
    '          sudo -n test -d "$PROTECTED_TREE/upload"\n'
    '          sudo -n tar -C "$PROTECTED_TREE/upload" -cf - . >"$RUNNER_TEMP/protected-evidence.tar"\n'
    '          tar --no-same-owner --no-same-permissions -C "$output" -xf "$RUNNER_TEMP/protected-evidence.tar"\n'
    '          test -s "$output/result.txt"\n'
    '          cat "$output/result.txt"\n'
)

PROTECTED_REFERENCE_UPLOAD = (
    '      - name: Upload protected reference evidence\n'
    '        if: always()\n'
    '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n'
    '        with:\n'
    '          name: protected-reference-${{ matrix.architecture }}\n'
    '          path: ${{ runner.temp }}/protected-reference-${{ matrix.architecture }}/\n'
    '          if-no-files-found: error\n'
    '          retention-days: 14\n'
)

PROTECTED_REFERENCE_CLEANUP = (
    '      - name: Kill protected descendants and remove the named tree\n'
    '        if: always()\n'
    '        run: |\n'
    "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C bash -euo pipefail -c '\n"
    '            tree=$1\n'
    '            [[ $tree =~ ^/srv/debz-protected/ci-[0-9]+-[0-9]+-(amd64|arm64)$ ]]\n'
    '            [[ -e $tree || -L $tree ]] || exit 0\n'
    '            [[ -d $tree && ! -L $tree ]]\n'
    '            for attempt in 1 2 3 4 5; do\n'
    '              victims=()\n'
    '              for process in /proc/[0-9]*; do\n'
    '                root=$(readlink "$process/root" 2>/dev/null) || continue\n'
    '                cwd=$(readlink "$process/cwd" 2>/dev/null) || cwd=\n'
    '                case "$root/ $cwd/" in\n'
    '                  *"$tree/"*) victims+=("${process#/proc/}") ;;\n'
    '                esac\n'
    '              done\n'
    '              (( ${#victims[@]} )) || break\n'
    '              echo "killing protected descendants: ${victims[*]}"\n'
    '              kill -KILL "${victims[@]}" 2>/dev/null || true\n'
    '              sleep 1\n'
    '            done\n'
    '            (( ${#victims[@]} == 0 ))\n'
    '            if grep -F " $tree" /proc/self/mountinfo; then\n'
    '              echo "mounts remain beneath $tree" >&2\n'
    '              exit 1\n'
    '            fi\n'
    '            rm -rf --one-file-system -- "$tree"\n'
    '            test ! -e "$tree"\n'
    '            \' protected-cleanup "$PROTECTED_TREE"\n'
)


PROTECTED_REFERENCE_SCRIPT_TOKENS = (
    "set -euo pipefail",
    'if [[ ${1:-} == --check-keyring && $# == 2 ]]; then',
    'print(verify_keyring(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))',
    'if [[ ${1:-} == --stage-native ]]; then',
    "  mode=native-staging\n",
    '[[ $mode == proof ]] || prefix=native-ci',
    'if [[ $mode == native-staging ]]; then\n  stage_native_inputs\n',
    'module.verify_extracted_bindings(prefix, architecture)',
    'print(toolchain(Path(sys.argv[2])))',
    "readonly zig_public_key=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U",
    "readonly archive_keyring_deb_url=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb",
    "readonly archive_keyring_deb_sha512=80446b4521a3cc100d797a7ed03532f4358c028f1c0c110e00cfc6e1db3b2795e2f98f92a4077baea0cee3c82b292f9eeb20f7f1dc06ce28b6b46e661b1fad35",
    "readonly archive_keyring_deb_size=11228",
    "readonly archive_keyring_member=./usr/share/keyrings/ubuntu-archive-keyring.gpg",
    "readonly archive_keyring_sha256=80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
    "readonly archive_keyring_size=3607",
    "    zig_sha256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00\n    zig_size=55478392\n",
    "    zig_sha256=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17\n    zig_size=51211944\n",
    '[[ $tree =~ ^/srv/debz-protected/$prefix-[0-9]+-[0-9]+-(amd64|arm64)$ && ${BASH_REMATCH[1]} == "$architecture" &&',
    '[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/real-snapshot-reference-protected-ci.sh" ]] || {',
    'test "$(git -C "$checkout" rev-parse HEAD)" = "$commit"',
    "trap collect EXIT",
    'step zig-verify 0 "" python3 -I tools/verify-minisign.py --public-key "$zig_public_key" \\',
    '    archive.extractall(sys.argv[2], filter="data")',
    "[[ ! -e zig-pkg && ! -L zig-pkg ]]",
    'chmod -R go-w zig-pkg "$tree/zig-global"',
    'step zig-pkg-verify 0 "" python3 -I tools/real-snapshot-reference-tree-check.py packages \\',
    "stage_verified_archive_keyring()",
    "printf 'path\\trole\\tuid:gid:mode:size\\talgorithm\\tdigest\\n'",
    "urllib.request.urlopen(request, timeout=300)",
    "fd = os.open(deb_path, flags)",
    "verify_fd = os.open(target, flags)",
    "actual_deb_sha512 != expected_deb_sha512",
    'parse_ar_member(deb_bytes, "data.tar.zst")',
    "library.ZSTD_decompress(output, output_limit, source, len(payload))",
    "keyring = extract_tar_member(data_tar, member)",
    "actual_keyring_sha256 != expected_keyring_sha256",
    'require_root_owned_file("staged-keyring", target, target_stat, 0o644)',
    "os.unlink(target)",
    'staged_archive_keyring=\nstage_verified_archive_keyring\nreadonly staged_archive_keyring',
    'step stage 0 "" "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring"',
    'step tree-final 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"',
    "mutable=$negatives/mutable-ancestor\n[[ ! -e \"$mutable\" && ! -L \"$mutable\" ]]\ninstall -d -o root -g root -m 0777 \"$mutable\"",
    'negative mutable-ancestor "writable or non-root ancestor" \\',
    'negative swapped-dpkg "reference dpkg executable is not the pinned architecture artifact" \\',
    'negative swapped-archive "authenticated archive SHA512 differs" \\',
    'negative wrong-architecture "reference dpkg executable is not the pinned architecture artifact" \\',
    'negative unbound-profile-scripts "profile scripts" \\',
    'step negative-reused-workspace refused "must be new and empty"',
    """step negative-swapped-keyring refused '"summary":"WrongSigningKey"' swapped_keyring_stage""",
    '    echo "negative-$name launched before refusing" >&2',
    'step proof 0 "executed without skips" timeout --signal=TERM --kill-after=60s 45m \\',
    '"${zenv[@]}" "$zig" build test-real-snapshot-reference-protected "${proof_arguments[@]}" \\',
    "[[ ${#proof_arguments[@]} == 15 ]]",
)
PROTECTED_REFERENCE_SOURCE_TOKENS = {
    "tools/real-snapshot-bash-protected-stage.sh": (
        '$(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64',
        '"$workspace" == "$checkout/.real-snapshot/bash-arm64"',
        'toolchain(Path(sys.argv[3]))',
        '--check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING"',
        'bash tools/real-snapshot-reference-protected-stage.sh --arm64-bash-source',
        'python3 -B -I tools/real_snapshot_less_stage.py prepare-bash',
        'python3 -B -I tools/real_snapshot_less_stage.py seal-bash',
        '--force-depends --no-triggers --unpack /var/lib/dpkg/producer-libtinfo6.deb /var/lib/dpkg/producer-bash.deb',
        '--force-depends --no-triggers --configure bash',
        "'5.3-2ubuntu1 arm64 install ok installed'",
        '"$zig" build test-real-snapshot-arm64-bash-source-protected',
        'grep -Fx "signed arm64 bash source guard executed without skips"',
        'replace_symlink(root / "bad-alias", "usr/lib/aarch64-linux-gnu/libtinfo.so.6", "libtinfo.so.6.6", "foreign-tinfo")',
        'create_exclusive(root / "bad-prestate", "usr/bin/update-menus"',
        '/var/lib/dpkg/producer-ldconfig -i -X -C /etc/ld.so.cache -f /dev/null /usr/lib/aarch64-linux-gnu',
        'cache.replace(b"/lib/aarch64-linux-gnu/libc.so.6", b"/bad/aarch64-linux-gnu/libc.so.6")',
        'bytes <= 8 * 1024 * 1024 * 1024',
    ),
    "tools/prepare-native-dpkg.py": (
        'with path.open("x", encoding="utf-8") as output:',
    ),
    "tools/real-snapshot-less-protected-stage.sh": (
        '$(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64',
        '"$workspace" == "$checkout/.real-snapshot/less-arm64"',
        'toolchain(Path(sys.argv[3]))',
        '--check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING"',
        'bash tools/real-snapshot-reference-protected-stage.sh --arm64-less-source',
        'python3 -B -I tools/real_snapshot_less_stage.py prepare',
        '"$workspace/evidence/less.lock.json" "$workspace/evidence/dash.lock.json" "$workspace/evidence/util-linux.lock.json"',
        'python3 -B -I tools/real_snapshot_less_stage.py seal',
        '--force-depends --no-triggers --unpack /var/lib/dpkg/producer-less.deb',
        'bash tools/real-snapshot-less-reference.sh',
        'bytes <= 8 * 1024 * 1024 * 1024',
    ),
    "tools/real_snapshot_less_stage.py": (
        'def alias(root: Path, relative: str, target: str) -> None:\n    with parent_descriptor(root, relative) as (parent, name):',
        'os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW',
        'entry["origin"]["type"] != "authenticated_repository"',
        'raise ValueError("source archive differs from exact production authority")',
        'for path in (lock_path, *additional_locks, pinned, Path("/usr/bin/dpkg-deb")):',
        'for package in SOURCE_ARTIFACTS:\n            archive(locks["dpkg" if package == "libc6" else package], cache, package)',
        'f3d538070be0217eec1c5e747f0b6ed05b08b22a006001dafac6c87747ab46e9055fb8bf1985aed2d4010f57d597108dbff22ed73f92959703fffa57ec84e0e8',
        'c4a44690b1541936c4c85956f8e5bef0c915ce05afe6618230b70f4906803f8710b314b9093b451787b995bcd7b25a3947f51c8efa03dbda16c7eac720f93c6e',
        '824a6a3f33837c16dedb4faff92bd15b0dbe82d27dd9b25403f87ec4572acc6332159a6374558185ca503e18de6f637d2a79e7db9fafaab3ccae4ac77427eee5',
        '865127bc2d7d9218e2a3482b7e0b5ae3649c31bcac82d0437a7231c798f56a1939f0f18fc664111a7c446eef6f9864176c040ad78b7aac1a6a3afe4d4b9cbeb7',
        'regular_descriptor(root, "var/lib/dpkg/info/less.list")',
        'content = os.read(descriptor, 2048)',
        'if (len(content) != 583 or hashlib.sha256(content).hexdigest() !=',
        'raise ValueError("signed less ownership path set changed")',
        'create_exclusive(root, "var/lib/debz-lifecycle-scripts/less.preinst", preinst, 0o755)',
        'create_exclusive(root, "var/lib/debz-lifecycle-scripts/less.postinst", script, 0o755)',
        'regular_descriptor(root, "var/lib/dpkg/info/less.postinst")',
        'raise ValueError("signed less postinst changed")',
        'if selected_package == "bash":',
        'archive(source_lock, cache, name)',
        'raise ValueError("signed bash ownership path set changed")',
        'raise ValueError("signed bash postinst changed")',
        'create_exclusive(root, "var/lib/debz-lifecycle-scripts/bash.postinst", script, 0o755)',
        'member(archive(locks["libc-bin"], cache, "libc-bin"), "usr/sbin/ldconfig")',
        'raise ValueError("signed ldconfig cache producer changed")',
        'resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))',
    ),
    "tools/real-snapshot-less-reference.sh": (
        'for file in "$pinned" "$lock" "$less_lock" "$dash_lock" "$archive" "$zig";',
        'for path in "$pinned" "$source_root" "$lock" "$less_lock" "$dash_lock" "$archive" "$script_root" "$dpkg_root";',
        'require_lock_artifact less 668-1build1 171138 "$digest" "$less_lock"',
        '\ncheck_source_inputs\n',
        'mutate_negative_roots([Path(root) for root in sys.argv[1:]])',
        'stage_dpkg_reference(*(Path(path) for path in sys.argv[1:]))',
        'stage_dpkg_reference(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))',
    ),
    "tools/real_snapshot_less_fixtures.py": (
        'parent_fd = open_beneath(root_fd, parent, directory=True)',
        'regular_metadata(descriptor)\n    os.ftruncate(descriptor, 0)',
        'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC',
    ),
    "tools/real-snapshot-protected-native-ci.sh": (
        "export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root",
        "unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR",
        "protected(Path(sys.argv[2]))",
        '"tools/real_snapshot_outcome.py",',
        '[[ ${#inputs[@]} == 3 ]]',
        "export DEBZ_ZIG=${inputs[0]} REFERENCE_DPKG=${inputs[1]} DEBZ_REAL_SNAPSHOT_KEYRING=${inputs[2]}",
        'exec bash "$checkout/tools/real-snapshot-acceptance.sh" "$checkout/zig-out/bin/debz"',
        'exec bash tools/real-snapshot-reference.sh "$REFERENCE_DPKG"',
        'timeout --signal=TERM --kill-after=30s 5m python3 tools/capture-vendor-state.py',
        'if [[ -d "$work/root/var/lib/dpkg/info" ]]; then',
        'reference_snapshot_present=%s\\nnative_snapshot_present=%s',
        "not stat.S_ISREG(meta.st_mode) or meta.st_size > 128 * 1024 * 1024",
        "total > 512 * 1024 * 1024",
        "os.open(name, flags | os.O_NOFOLLOW)",
        'python3 -I tools/real_snapshot_outcome.py "$evidence" "${NATIVE_STEP_OUTCOME:-unavailable}" \\',
        '>"$evidence/acceptance-outcome-v1.json" || outcome_status=$?',
        'python3 -I - "$checkout/tools" "$work/root" "$evidence" >"$evidence/native-coordination-capture.log" 2>&1 <<\'PY\' || coordination_status=$?',
        'source_fd = open_beneath(root_fd, "var/lib/debz", directory=True)',
        'fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=source_fd)',
        "not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 128 * 1024 * 1024",
        "coordination_bytes > 512 * 1024 * 1024",
        'inventory["capture_complete"] = True',
        '(( capture_status == 0 && differential_status == 0 && forbidden_exec_status == 0 && outcome_status == 0 && copy_status == 0 && coordination_status == 0 ))',
    ),
    "tools/real-snapshot-acceptance.sh": (
        "readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-}",
        '--check-keyring "$keyring" >/dev/null',
        'python3 -I - "$repository_root/tools" "$repository_root" "$debz"',
        'protected(repository, directory=True)',
        'protected(repository / ".real-snapshot", directory=True)',
        'local wrapper_status=$?',
        'printf \'%s\\n\' "$wrapper_status" >"$evidence/native-wrapper-exit-status.txt"',
        'printf \'{"stage":"%s","command_exit_status":null}\\n\' "$name" >"$evidence/native-stage-v1.json"',
        'printf \'{"stage":"%s","command_exit_status":%s}\\n\' "$name" "$status" >"$evidence/native-stage-v1.json"',
    ),
    "tools/real_snapshot_outcome.py": (
        'read_root_file(evidence, "native-stage-v1.json", 4096)',
        'read_root_file(evidence, f"{stage}.json", 128 * 1024 * 1024)',
        'read_root_file(evidence, "native-wrapper-exit-status.txt", 32)',
        'if workflow_outcome == "success":',
        'if wrapper_status != 0 or not expected_refusal:',
        'if command_status is None:',
        '"id": f"native_acceptance_evidence_{kind}"',
    ),
    "tools/real-snapshot-python3-protected-stage.sh": (
        '$(id -u) == 0 && $(id -g) == 0 && $(uname -m) == x86_64',
        '"$workspace" == "$checkout/.real-snapshot/python3-amd64"',
        'toolchain(Path(sys.argv[3]))',
        '--check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING"',
        'bash tools/real-snapshot-signed-proc-bindings.sh "$debz" "$workspace"',
        'bash tools/real-snapshot-signed-proc-prestates.sh --python3 "$pinned" "$workspace"',
        'fixture empty "$before"',
        'fixture mode "$before_0644" 0644',
        'fixture capture "$workspace" "evidence/replay-$mode.txt" "evidence/replay-$mode.stderr"',
        'fixture basic "$workspace/bad-html" "$workspace/bad-link" "$workspace/bad-shadow"',
        'create_exclusive(root, "evidence/python3-reference.args", content, 0o600)',
        'for mode in 0600 0644; do',
        'bash tools/real-snapshot-python3-reference.sh "$pinned" "$input" "$lock" "$archive"',
        '"-Dpython3-reference-root-py3compile=$after-py3compile-before"',
        '"-Dpython3-reference-after-py3compile=$after-py3compile-after"',
        '"-Dpython3-reference-bad-minimal-compiler=$after-py3compile-bad-compiler"',
        '"-Dpython3-reference-inputs-proof=$evidence/inputs-proof.txt"',
        '"-Dpython3-reference-alternatives-proof=$evidence/alternatives-proof.txt"',
        'bytes <= 16 * 1024 * 1024 * 1024',
    ),
    "tools/real-snapshot-python3-reference.sh": (
        'unset ZIG_LIB_DIR',
        '--zig-lib-dir "$(dirname -- "$zig")/lib"',
        'fixture preflight "$source_root"',
        '"$zig" build test-real-snapshot-python3-source-protected',
        '"-Dpython3-source-root=$source_root" "-Dpython3-source-proof=$source_proof"',
        'grep -Fx "signed Python source guard executed before fixture mutation" "$source_proof"',
        'fixture dpkg "$dpkg_root" "$pinned" "$archive"',
        'fixture dpkg "$py3compile_dpkg" "$pinned" "$archive"',
        'fixture mode "$py3compile_before" 0644',
        'fixture strict "$py3compile_bad_hash" "$py3compile_bad_mode"',
        'require_protected_file "$source_root/dev/null"',
        '0:0:600:0:1',
        '0:0:644:0:1',
        '0:0:644:20:1',
        """[[ $(stat -c '%u:%g:%a:%s:%h' "$py3compile_after/dev/null") == 0:0:644:96:1 ]]""",
        'e212fd644ebc9508a5494c1d69e26c62e23b5695d797588603dd870af154751e',
        '[[ $(sha256sum "$py3compile_after/dev/null" | cut -d\' \' -f1) == \\\n'
        '  3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc ]]',
    ),
    "tools/real_snapshot_python_fixtures.py": (
        'maximum = 16 * 1024 * 1024',
        'raise ValueError("Python reference capture exceeds its byte limit")',
        'content = read_regular(root, relative, 2048)',
        'if len(content) != size or hashlib.sha256(content).hexdigest() != digest:',
        'raise ValueError(f"signed Python list path set changed: {name}")',
        'not stat.S_ISCHR(metadata.st_mode) or metadata.st_rdev != os.makedev(1, 3)',
        'create_exclusive(root, "dev/null", b"", 0o600)',
        'create_exclusive(shadow, "usr/sbin/update-alternatives", b"shadow\\n", 0o644)',
        'stage_dpkg_reference(*roots, archive_relative="var/lib/dpkg/python3-probe.deb")',
        'with regular_descriptor(postinst, "var/lib/dpkg/info/python3-minimal.postinst") as descriptor:',
    ),
    "tools/real-snapshot-signed-proc-prestates.sh": (
        'if [[ ${1:-} == --python3 ]]; then',
        'require_protected_file "$snapshot/evidence/refresh.json"',
        '--slurpfile refreshed "$snapshot/evidence/refresh.json"',
        '([$frozen.witnesses[].repository_id] | sort) ==',
        '.repository.snapshot_digest == ("sha256:" + $repository.snapshot_sha256)',
        '.repository.release_digest == ("sha256:" + $repository.release_sha256)',
        '--zig-lib-dir "$(dirname -- "$zig")/lib"',
        '--prestate "python3:amd64=unpacked:$prestates/python3"',
        'protected Python pre-configure source captured; no full reference completion claimed',
        'actual_record=$(LC_ALL=C sort -- "$prestates/prestates.tsv")',
        '[[ $actual_record == "$expected_record" ]]',
        'signed prestate record differs from exact requested selectors/statuses/destinations',
        'readonly setpriv_sha256=86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993',
        '  require_control "$target" "usr/bin/setpriv:47576:755:$setpriv_sha256"',
        'list=$prestates/sudo/var/lib/dpkg/info/sudo.list',
        'var/lib/dpkg/info/sudo.list:2376:644:39fe94bdbeab0a80b3aaeae4cfa258be578949b791aeb06875ddf9d488387bc8',
    ),
    "src/native_unpack.zig": (
        'std.c.getenv("DEBZ_REQUIRE_SIGNED_PYTHON3_INPUTS_PROOF")',
        'signed Python empty0600/0644 and amd64 20/96 input/output guards executed without skips',
    ),
    "src/native_alternatives.zig": (
        'std.c.getenv("DEBZ_REQUIRE_SIGNED_PYTHON3_ALTERNATIVES_PROOF")',
        'signed Python alternatives records and selectors executed without skips',
    ),
    "tools/real-snapshot-reference-launcher.zig": (
        "const reference_namespaces = linux.CLONE.NEWNS | linux.CLONE.NEWPID | linux.CLONE.NEWNET;",
        "const clone_result = linux.clone2(\n        reference_namespaces | @intFromEnum(linux.SIG.CHLD)",
        "const network_ready = private_network.setupLoopback();",
        "if (network_ready != .SUCCESS) fail(status, 15, network_ready);",
        "if (failure[0] == 15) return error.ReferenceNetworkSetupFailed;",
        "if (linux.errno(result) != .SUCCESS) return error.ReferenceNamespaceUnavailable;",
        "if (private_network.setupLoopback() != .PERM) linux.exit(16);",
        'if ((options.verb == .break_kbd_cycle) != (options.kbd_archives != null))',
        '!std.mem.eql(u8, options.selector.?, "kbd:amd64")',
        'for (paths, kbd_cycle) |path, binding| {',
        'if (child.options.verb == .break_kbd_cycle)\n        verifyCycle(.kbd)',
        '.kbd => .{ "kbd", "kbd:amd64" },',
        '.break_kbd_cycle => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--force-depends", "--configure", "kbd:amd64", null },',
    ),
    "tools/real-snapshot-reference-order.py": (
        'def verify_kbd_cycle(root: Path, cycle: tuple[Package, ...]) -> dict:',
        'before = verify_kbd_cycle(root, cycle)',
        'expected = "install ok unpacked" if index < 3 else "install ok installed"',
        'activation is None or activation.read(1025) != KBD_TRIGGERS',
        'for name in ("kbd", "kbd:amd64") for script in MAINTAINER_SCRIPTS',
        'expected[("kbd", "amd64")]["status"] = "install ok installed"',
        'CycleNoProgress: database changed beyond the one reviewed kbd transition',
        'if (not kbd_configured and',
        'kbd_configured = True',
        '"reference trigger closure refused: the launcher has no exact triggered "',
    ),
    "src/private_network.zig": (
        "pub fn setupLoopback() linux.E {",
        "request.ifru.flags.UP = true;",
        "if (applied != .SUCCESS) return applied;",
        "if (!request.ifru.flags.UP or !request.ifru.flags.LOOPBACK) return .NODEV;",
    ),
    "src/maintainer_script.zig": (
        'return @import("private_network.zig").setupLoopback();',
    ),
    "tools/real-snapshot-reference.sh": (
        "unset ZIG_LIB_DIR",
        'zig=${DEBZ_ZIG:-$(command -v zig || true)}',
        "toolchain(Path(sys.argv[6]))",
        '"$zig" build-exe -O ReleaseSafe -lc --dep private_network',
        '-Mroot=tools/real-snapshot-reference-launcher.zig -Mprivate_network=src/private_network.zig',
        '--zig-lib-dir "$(dirname -- "$zig")/lib"',
    ),
    "tools/real_snapshot_reference_paths.py": (
        "def open_protected(",
        "def verify_keyring(",
        "fd = open_protected(path)",
        "meta.st_size != size or len(payload) != size or actual != digest",
        "def toolchain(",
        "protected(library, directory=True)",
        "if not target.is_relative_to(library):",
    ),
    "build.zig": (
        'b.step("test-real-snapshot-python3-source-protected",',
        'run_python3_source_tests.has_side_effects = true;',
        'run_python3_source_tests.setEnvironmentVariable("DEBZ_REQUIRE_SIGNED_PYTHON3_SOURCE_ROOT", b.option([]const u8, "python3-source-root", "Required protected Python source") orelse "");',
        'run_python3_source_tests.setEnvironmentVariable("DEBZ_REQUIRE_SIGNED_PYTHON3_SOURCE_PROOF", b.option([]const u8, "python3-source-proof", "Exclusive pre-mutation Python source proof") orelse "");',
        'b.step("test-real-snapshot-python3-protected",',
        'run_python3_reference_tests.has_side_effects = true;',
        'run_python3_alternatives_tests.has_side_effects = true;',
        'python3_reference_step.dependOn(&run_python3_reference_tests.step);',
        'python3_reference_step.dependOn(&run_python3_alternatives_tests.step);',
        '"native_unpack.test.protected signed python3 inputs and redirected tool witness are exact"',
        '"native_alternatives.test.protected signed python3 preinst preserves all records and selectors"',
        'for (python3_coordinates, &python3_values)',
        'for (python3_coordinates, python3_values)',
        '"Required protected Python proof coordinate") orelse ""',
        'b.fmt("DEBZ_REQUIRE_SIGNED_PYTHON3_{s}", .{coordinate.environment}),\n'
        '            value.*,',
        '        "--profile-scripts",\n'
        '        b.option([]const u8, "reference-protected-profile-scripts", ',
        'b.step("test-real-snapshot-reference-protected", ',
    ),
    "tools/real-snapshot-reference-protected-stage.sh": (
        '  packages=(less dash util-linux)',
        'if [[ $purpose == arm64-bash ]]; then packages=(bash dash util-linux libc-bin); fi',
        '  for package in "${packages[@]}"; do',
        '    authenticated_lock "$package_lock"',
        'module.receipt_from_extracted_archive(\n    sys.argv[2], pathlib.Path(sys.argv[4]), pathlib.Path(sys.argv[3]).parents[2])',
        '--architecture "$architecture" --verify-only "$dpkg_prefix/usr/bin/dpkg"',
        "  for profile in systemd udev sudo; do\n",
        """  printf -- '-Dreference-protected-profile-scripts=%s\\n' "$profiles"\n""",
        "staging path is not root-owned and protected: $current (uid:gid:mode=$metadata; expected 0:0 with no group/world write bits)",
        "staging file is not root-owned and protected: $1 (uid:gid:mode=$metadata; expected 0:0 with no group/world write bits)",
    ),
    "tools/test_real_snapshot_reference_protected.py": (
        'with network_control(args.workspace, "escape", root, args.escape_probe) as inherited:',
        'with network_control(args.workspace, name, root, args.escape_probe) as inherited:',
        'if control.returncode != 0 or control.stdout != expected:',
        'failed = [check for check in (*ESCAPE_CHECKS, *CONFINED_CHECKS, "private-network", "result")',
        'parser.add_argument("--profile-scripts", type=Path, required=True)',
        "scripts = profile_scripts(args.profile_scripts, args.architecture)",
        "profiles = prove_profiles(args, scripts)",
        '"systemd": ("proc-read-only", "proc-sys-masked", "proc-boot-id"),',
        '"udev": ("proc-pid-only",),',
        '"sudo": ("proc-pid-only",),',
        'probe_detail(output, "proc-boot-id").get("boot_id") != host_boot_id',
        'require(status, error, "InvalidProfile", name)',
    ),
    "tools/real-snapshot-reference-escape-probe.zig": (
        "try network_probe.observe(",
        'report("private-network", false, "error={s}"',
        'if (confined) {\n        networkControl(profile) catch |err|',
        'const pid_one_root = statIdentity("/proc/1/root", 0);',
        'report("proc-root", same_root, ',
        'report("proc-boot-id", ',
        'report("proc-pid-only", ',
        'report("proc-sys-masked", ',
        '"subset=pid"',
    ),
    "tools/verify-minisign.py": (
        'raise VerificationError("only prehashed (ED) minisign signatures are accepted")',
        "ed25519_verify(key, prehash.digest(), blob[10:])",
        "ed25519_verify(key, blob[10:] + trusted, global_signature)",
        'fields[1] != b"file:" + name.encode()',
    ),
    "tools/real-snapshot-reference-tree-check.py": (
        "not stat.S_ISLNK(meta.st_mode) and meta.st_mode & (WRITABLE | SPECIAL)",
        'failures.append(f"group/other-writable entry: {describe(path, meta)}")',
        'failures.append(f"protected tree must be mode 0700: {describe(current, meta)}")',
    ),
}


def protected_reference_ci_failures(texts: dict[str, str]) -> list[str]:
    """The protected reference job stages only reviewed, root-owned inputs and cannot skip."""
    failures: list[str] = []
    python_alternatives = texts.get("src/native_alternatives.zig", "").partition(
        'test "native_alternatives.test.protected signed python3 preinst preserves all records and selectors" {'
    )[2].partition('\ntest "')[0]
    for token in (
        '"DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_ROOT_0644", "DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_AFTER_0644"',
        "try testing.expect(listed.names.len != 0);",
        "try testing.expectEqualDeep(listed.names, listed_after.names);",
        "try validateScriptTransition(testing.allocator, before, same, script, authority);",
        "try validateScriptTransition(testing.allocator, after, after_same, script, authority);",
        "try testing.expectEqualDeep(old_group.record, new_group.record);",
        "try testing.expectEqualDeep(old_group.links, new_group.links);",
        "try testing.expectEqualDeep(old_group.missing_master_targets, new_group.missing_master_targets);",
        "try testing.expectEqual(old_group.facts.len, new_group.facts.len);",
        "try testing.expect(testClonedEntryFactEqual(left, right));",
        "try testing.expectEqualSlices(u8, old_record, new_record);",
        "errdefer |err| std.debug.print(",
        "protected Python alternatives: coordinate={s} phase={s} group={s} error={s}",
    ):
        if token not in python_alternatives:
            failures.append(f"protected Python alternatives must preserve complete inventories in both modes: {token}")
    for path, count in (
        ("tools/real-snapshot-less-protected-stage.sh", 1),
        ("tools/real-snapshot-less-reference.sh", 3),
        ("tools/real-snapshot-bash-protected-stage.sh", 3),
    ):
        commands = re.findall(
            r"timeout --signal=TERM --kill-after=5s 120s \\\n.*?\n  '\n",
            texts.get(path, ""), re.DOTALL,
        )
        if len(commands) != count or any(
                "/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C" not in command or
                command.find("/usr/bin/env -i") > command.find("chroot ") or
                "env -i" in command.partition("chroot ")[2] or
                "--bounding-set=-sys_admin --no-new-privs" not in command
                for command in commands):
            failures.append(f"protected less environment must be sanitized before chroot without guest env: {path}")
    arm_ci = texts.get("tools/real-snapshot-reference-protected-ci.sh", "")
    arm_start = 'elif [[ $architecture == arm64 ]]; then\n  less_workspace='
    arm_body = arm_ci.partition(arm_start)[2].partition('\n# The protected proof on the staged new empty workspace')[0]
    for token in (
        '$checkout/.real-snapshot/less-arm64',
        'step arm64-less-stage 0 "fifteen replay roots staged" timeout --signal=TERM --kill-after=60s 30m',
        'bash tools/real-snapshot-less-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" "$less_workspace"',
        'step arm64-less-guards 0 "" timeout --signal=TERM --kill-after=60s 10m',
        '"$zig" build test-real-snapshot-arm64-less-protected',
        '"-Darm64-less-reference-bad-prestate=$less_workspace/script-after-bad-prestate"',
        '"$less_workspace/evidence/less-source-proof.txt"',
        '"$less_workspace/evidence/less-replay-proof.txt"',
        'step arm64-less-postinst 0 "" timeout --signal=TERM --kill-after=60s 10m',
        '"$zig" build test-real-snapshot-arm64-less-postinst-protected',
        '"-Darm64-less-postinst-bad-prestate=$less_workspace/script-after-postinst-bad-prestate"',
        '"$less_workspace/evidence/less-postinst-proof.txt"',
        'grep -Fx "signed arm64 less native postinst and independent pinned dpkg agree without skips"',
        'grep -F " $less_workspace" /proc/self/mountinfo',
        'rm -rf --one-file-system -- "$less_workspace"',
        '$checkout/.real-snapshot/bash-arm64',
        'step arm64-bash-stage 0 "nine replay roots staged" timeout --signal=TERM --kill-after=60s 30m',
        'step arm64-bash-postinst 0 "" timeout --signal=TERM --kill-after=60s 10m',
        '"$zig" build test-real-snapshot-arm64-bash-postinst-protected',
        '"-Darm64-bash-postinst-dpkg-root=$bash_workspace/dpkg-after"',
        '"-Darm64-bash-postinst-bad-prestate=$bash_workspace/bad-prestate"',
        '"-Darm64-bash-postinst-bad-cache=$bash_workspace/bad-cache"',
        'grep -Fx "signed arm64 bash native postinst and independent pinned dpkg agree without skips"',
        'grep -F " $bash_workspace" /proc/self/mountinfo',
        'rm -rf --one-file-system -- "$bash_workspace"',
    ):
        if token not in arm_body:
            failures.append(f"protected arm64 less activation lost {token}")
    if "|| true" in arm_body or "SkipZigTest" in arm_body:
        failures.append("protected arm64 less activation must not skip or swallow errors")
    arm_build = texts.get("build.zig", "")
    for token in (
        'b.step("test-real-snapshot-arm64-less-protected",',
        'run_arm64_less_tests.has_side_effects = true;',
        '"Required protected ARM less proof coordinate") orelse ""',
        'setEnvironmentVariable("DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_ROOT", value)',
        'b.step("test-real-snapshot-arm64-less-postinst-protected",',
        'run_arm64_less_postinst_tests.has_side_effects = true;',
        'DEBZ_REQUIRE_SIGNED_ARM64_LESS_POSTINST_{s}',
        'b.step("test-real-snapshot-arm64-bash-source-protected",',
        'run_arm64_bash_source_tests.has_side_effects = true;',
        'b.step("test-real-snapshot-arm64-bash-postinst-protected",',
        'run_arm64_bash_postinst_tests.has_side_effects = true;',
        'DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_{s}',
    ):
        if token not in arm_build:
            failures.append(f"protected arm64 less build lost {token}")
    for name, calls in (
        ("source is validated before fixture mutation", (
            'try verifySnapshotLessArm64Inputs(testing.allocator, root.root, &artifacts, "arm64", .preinst);',
            'try verifySnapshotLessArm64Inputs(testing.allocator, root.root, &artifacts, "arm64", .postinst);',
            'DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_PROOF',
        )),
        ("inert input and replay roots are exact", (
            'prepareAlternativesScriptBoundary(',
            'try testing.expectEqualDeep(before.record, after.record);',
            'try testing.expectError(error.InvalidAlternativesScriptAuthority, verifySnapshotLessArm64Inputs(',
            'DEBZ_REQUIRE_SIGNED_ARM64_LESS_REPLAY_PROOF',
        )),
        ("postinst runs natively and matches pinned dpkg", (
            'maintainer_script.SystemLauncher',
            'maintainer_script.run(testing.allocator,',
            'try testing.expect(report.succeeded());',
            '.policy = lifecycleInvocationPolicy(false, false, false)',
            'try verifySnapshotLessArm64Inputs(testing.allocator, native.root, &artifacts, "arm64", .postinst);',
            'native_alternatives.validateScriptInputs(',
            'native_alternatives.validateScriptTransition(',
            'try testing.expectEqualDeep(actual.record, expected.record);',
            'try testing.expectEqualStrings("/usr/bin/less", actual.selected);',
            'DEBZ_REQUIRE_SIGNED_ARM64_LESS_POSTINST_BAD_PRESTATE_ROOT',
            'DEBZ_REQUIRE_SIGNED_ARM64_LESS_POSTINST_PROOF',
        )),
    ):
        text = texts.get("src/native_unpack.zig", "")
        body = text.partition(f'test "native_unpack.test.protected signed arm64 less {name}" {{')[2].partition('\n}\n')[0]
        for token in (*calls, '.exclusive = true', 'try proof.writeStreamingAll('):
            if token not in body:
                failures.append(f"protected arm64 less test body lost {token}")
    less_reference = texts.get("tools/real-snapshot-less-reference.sh", "")
    for name, calls in (
        ("source is validated before fixture mutation", (
            'try verifySnapshotBashArm64Inputs(testing.allocator, root.root, &artifacts, "arm64");',
            'DEBZ_REQUIRE_SIGNED_ARM64_BASH_SOURCE_PROOF',
        )),
        ("postinst runs natively and matches pinned dpkg", (
            'maintainer_script.SystemLauncher',
            'maintainer_script.run(testing.allocator,',
            'try testing.expect(report.succeeded());',
            '.policy = lifecycleInvocationPolicy(false, false, false)',
            'try verifySnapshotBashArm64Inputs(testing.allocator, native.root, &artifacts, "arm64");',
            'native_alternatives.validateScriptInputs(',
            'native_alternatives.validateScriptTransition(',
            'try testing.expectEqualDeep(actual.record, expected.record);',
            'try testing.expectEqualStrings("/usr/share/man/man7/bash-builtins.7.gz", actual.selected);',
            'try testing.expectEqualDeep(actual.links, expected.links);',
            'try testing.expectEqualDeep(actual.missing_master_targets, expected.missing_master_targets);',
            'try expectAlternativesReplayFactEqual(actual.record_fact, expected.record_fact);',
            'try expectAlternativesReplayFactEqual(left, right);',
            'DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_BAD_PRESTATE_ROOT',
            'DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_BAD_CACHE_ROOT',
            'DEBZ_REQUIRE_SIGNED_ARM64_BASH_POSTINST_PROOF',
        )),
    ):
        text = texts.get("src/native_unpack.zig", "")
        body = text.partition(f'test "native_unpack.test.protected signed arm64 bash {name}" {{')[2].partition('\n}\n')[0]
        for token in (*calls, '.exclusive = true', 'try proof.writeStreamingAll('):
            if token not in body:
                failures.append(f"protected arm64 bash test body lost {token}")
    bash_stage = texts.get("tools/real-snapshot-bash-protected-stage.sh", "")
    unpack = texts.get("src/native_unpack.zig", "")
    for token in (
        'if (snapshot_bash_postinst and std.mem.eql(u8, architecture, "arm64")) {',
        'bash_cache_fact = try verifySnapshotBashArm64Inputs(allocator, root, program.artifacts, program.target_architecture);',
        'native_alternatives.matchesSnapshotBashPostinst(script_bytes))\n'
        '            _ = verifySnapshotBashArm64Inputs(',
        'try verifySnapshotBashArm64CacheInput(allocator, root);',
        'targets[script.immutable_targets.len] = "/etc/ld.so.cache";',
        'if (!std.meta.eql(observed, expected_cache)) return error.AlternativesInputChanged;',
    ):
        if token not in unpack:
            failures.append(f"protected arm64 bash production input revalidation lost {token}")
    source_guard = bash_stage.find('"$zig" build test-real-snapshot-arm64-bash-source-protected')
    copies = bash_stage.find('for name in native dpkg-after bad-script')
    if source_guard < 0 or copies < 0 or source_guard > copies:
        failures.append("protected bash source guard must execute before copies/mutations")
    for token in (
        'mutate_negative_roots([Path(root) for root in sys.argv[1:]], kind="postinst")',
        '--force-depends --no-triggers --configure less',
        "'668-1build1 arm64 install ok installed'",
    ):
        if token not in less_reference:
            failures.append(f"protected arm64 less independent configure lost {token}")
    python_ci = texts.get("tools/real-snapshot-reference-protected-ci.sh", "")
    python_start = 'if [[ $architecture == amd64 ]]; then\n  python3_workspace='
    python_end = '\n# The protected proof on the staged new empty workspace'
    python_body = python_ci.partition(python_start)[2].partition(python_end)[0]
    for token in (
        '$checkout/.real-snapshot/python3-amd64',
        'step python3-stage 0 "all 18 root coordinates staged" timeout --signal=TERM --kill-after=60s 40m',
        '"DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring"',
        'bash tools/real-snapshot-python3-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz"',
        '[[ ${#python3_arguments[@]} == 20 ]]',
        'step python3-guards 0 "" timeout --signal=TERM --kill-after=60s 10m',
        '"$zig" build test-real-snapshot-python3-protected "${python3_arguments[@]}"',
        '-Doptimize=ReleaseSafe -j2 --summary all',
        '"$python3_workspace/evidence/inputs-proof.txt"',
        '"$python3_workspace/evidence/alternatives-proof.txt"',
        'grep -F " $python3_workspace" /proc/self/mountinfo',
        'rm -rf --one-file-system -- "$python3_workspace"',
    ):
        if token not in python_body:
            failures.append(f"protected amd64 Python activation lost {token}")
    if ("|| true" in python_body or "SkipZigTest" in python_body or
            "test-integration-arm64" in python_body):
        failures.append("protected Python activation must not skip, swallow errors or activate ARM397")
    for path, name, tokens in (
        ("src/native_unpack.zig",
         "native_unpack.test.protected signed python3 source is validated before fixture mutation", (
             "try verifySnapshotPython3PreinstInputs(testing.allocator, root.root, &program);",
             'std.c.getenv("DEBZ_REQUIRE_SIGNED_PYTHON3_SOURCE_PROOF")',
             ".exclusive = true",
             "try proof.writeStreamingAll(",
         )),
        ("src/native_unpack.zig",
         "native_unpack.test.protected signed python3 inputs and redirected tool witness are exact", (
             "try verifySnapshotPython3PreinstInputs(testing.allocator, before.root, &program);",
             "try verifySnapshotPython3PreinstInputs(testing.allocator, before_0644.root, &program);",
             "try verifySnapshotPython3PreinstInputs(testing.allocator, before_py3compile.root, &program);",
             "try verifySnapshotPython3NullOutput(testing.allocator, after.root);",
             "try verifySnapshotPython3NullOutput(testing.allocator, after_0644.root);",
             "try verifySnapshotPython3NullOutput(testing.allocator, after_py3compile.root);",
             "error.DirectoryTooLarge",
             'std.c.getenv("DEBZ_REQUIRE_SIGNED_PYTHON3_INPUTS_PROOF")',
             ".exclusive = true",
             "try proof.writeStreamingAll(",
         )),
        ("src/native_alternatives.zig",
         "native_alternatives.test.protected signed python3 preinst preserves all records and selectors", (
             "try validateScriptInputs(",
             "try validateScriptTransition(",
             "try testing.expectEqualSlices(u8, old_record, new_record);",
             'std.c.getenv("DEBZ_REQUIRE_SIGNED_PYTHON3_ALTERNATIVES_PROOF")',
             ".exclusive = true",
             "try proof.writeStreamingAll(",
         )),
    ):
        body = texts.get(path, "").partition(f'test "{name}" {{')[2].partition('\ntest "')[0]
        for token in tokens:
            if token not in body:
                failures.append(f"{path}: protected Python test body lost {token}")
    python_reference = texts.get("tools/real-snapshot-python3-reference.sh", "")
    guard = 'grep -Fx "signed Python source guard executed before fixture mutation" "$source_proof"'
    if (guard not in python_reference or
            python_reference.index(guard) > python_reference.index("cp -a --reflink=auto")):
        failures.append("protected Python source guard must execute before copies/mutations")
    fixtures = texts.get("tools/real_snapshot_less_fixtures.py", "")
    if "os.O_TRUNC" in fixtures:
        failures.append("shared reference mutations must inspect the descriptor before truncation")
    for path, name in (
        ("tools/real_snapshot_less_stage.py", "seal"),
        ("tools/real_snapshot_python_fixtures.py", "prepare_empty"),
    ):
        body = texts.get(path, "").partition(f"def {name}(")[2].partition("\ndef ")[0]
        if not body or re.search(
            r"\b(?:sorted|overwrite_regular|replace_contents|ftruncate|write|write_bytes|write_text)\s*\(",
            body,
        ):
            failures.append(f"{path}: fixture lists must retain authenticated original bytes without rewriting")
    sudo_list = texts.get("tools/real-snapshot-signed-proc-prestates.sh", "").partition(
        "list=$prestates/sudo/var/lib/dpkg/info/sudo.list\n"
    )[2].partition("# The pre-sudo record")[0]
    if not sudo_list or re.search(r"\b(?:sort|chmod|mv|cp|install|tee|dd)\b|>", sudo_list):
        failures.append("signed sudo fixture list must retain authenticated original bytes without rewriting")
    binding_list = texts.get("tools/real-snapshot-signed-proc-bindings.sh", "").partition(
        """awk -F'\\t' '$1 == "sudo" { print "/" $2 }' "$listing" | sed 's#^/$#/.#'"""
    )[2].partition("\ncopy_input()")[0]
    if (not binding_list or re.search(r"\bsort\b", binding_list) or
            '>"$source_root/var/lib/dpkg/info/sudo.list"' not in binding_list):
        failures.append("signed sudo binding list must retain authenticated archive member order")
    producer = texts.get("tools/prepare-native-dpkg.py", "").partition(
        "def receipt_from_extracted_archive("
    )[2].partition("\ndef ")[0]
    for token in ("verify_file(archive, PINS[architecture][\"archive\"])",
                  "verify_archive_metadata(archive, architecture)",
                  "verify_extracted_bindings(prefix, architecture)", "write_receipt(",
                  "verify_receipt(prefix / RECEIPT, architecture)",
                  "metadata.st_nlink != 1 or metadata.st_mode & 0o022",
                  "path.resolve(strict=True) != path"):
        if token not in producer:
            failures.append(f"protected extracted reference receipt producer lost {token}")
    ci = texts.get(".github/workflows/ci.yml", "")
    jobs = dict(re.findall(
        r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)", ci,
    ))
    native_job = jobs.get("ubuntu-real-snapshot", "")
    for token in (
        "    if: github.event_name == 'workflow_dispatch' && inputs.run_native_real_snapshot\n",
        "    timeout-minutes: 320\n",
        "      max-parallel: 1\n",
        "          - architecture: amd64\n            runner: ubuntu-24.04\n",
        "          - architecture: arm64\n            runner: ubuntu-24.04-arm\n",
        "      PROTECTED_TREE: /srv/debz-protected/native-ci-${{ github.run_id }}-${{ github.run_attempt }}-${{ matrix.architecture }}\n",
        '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"\n          test -z "$(git status --porcelain)"\n',
        '          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n'
        '            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \\\n',
        '            mkdir -m 0700 -- "$tree"\n',
        '            git --git-dir="$tree/bare.git" fsck --full --no-dangling\n',
        '            test "$(git -C "$tree/checkout" rev-parse HEAD)" = "$expected"\n',
        '            exec bash "$tree/checkout/tools/real-snapshot-reference-protected-ci.sh" --stage-native "$tree" "$architecture" "$expected"\n',
        "      - name: Create and replay exact native Ubuntu root\n        id: native\n        timeout-minutes: 220\n",
        '            native "$PROTECTED_TREE" "$ARCHITECTURE" "$GITHUB_SHA" "$SNAPSHOT_URI" "$SNAPSHOT_SUITE"\n',
        "      - name: Install exact closure with pinned dpkg reference\n        timeout-minutes: 50\n        run: |\n",
        '            reference "$PROTECTED_TREE" "$ARCHITECTURE" "$GITHUB_SHA"\n',
        "      - name: Collect bounded protected native diagnostics\n        if: always()\n        timeout-minutes: 15\n"
        "        env:\n          NATIVE_STEP_OUTCOME: ${{ steps.native.outcome }}\n",
        '            NATIVE_STEP_OUTCOME="$NATIVE_STEP_OUTCOME" \\\n',
        '            collect "$PROTECTED_TREE" "$ARCHITECTURE" "$GITHUB_SHA"\n',
        "      - name: Copy bounded native evidence\n        if: always()\n",
        '            sudo -n tar -C "$PROTECTED_TREE/native-upload" -cf - . >"$PWD/.native-evidence.tar"\n',
        "      - name: Kill native descendants and remove only the named tree\n        if: always()\n        timeout-minutes: 3\n",
        '              kill -KILL "${victims[@]}" 2>/dev/null || true\n',
        '            rm -rf --one-file-system -- "$tree"\n',
        "      - name: Upload real acceptance evidence\n        if: always()\n",
        "          path: .real-snapshot/${{ matrix.architecture }}/evidence/\n",
        "          if-no-files-found: error\n          retention-days: 14\n",
    ):
        if native_job.count(token) != 1:
            failures.append(f"native snapshot CI lost protected wiring: {token.strip()}")
    if ("continue-on-error" in native_job or "cataggar/ghr" in native_job
        or "chown" in native_job or re.search(r"\bsudo (?!-n )", native_job)):
        failures.append("native snapshot CI must retain protected tools and failures without ownership transfer")
    job = jobs.get("protected-reference")
    on = ci.partition("\nconcurrency:\n")[0]
    if (
        ci.count(PROTECTED_REFERENCE_INPUT) != 1 or ci.count("run_protected_reference") != 2
        or '  schedule:\n    - cron: "23 3 * * 1"\n' not in on
        or not re.search(r"(?m)^  workflow_dispatch:$", on)
    ):
        failures.append(
            "ci.yml: the protected reference job must run only on the weekly schedule or an explicit dispatch input"
        )
    if job is None:
        failures.append("ci.yml: the protected reference job is missing")
        job = ""
    steps = re.split(r"(?m)^(?=      - )", job.partition("    steps:\n")[2])
    expected_steps = (
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n"
        "        with:\n          persist-credentials: false\n",
        PROTECTED_REFERENCE_BOOTSTRAP,
        PROTECTED_REFERENCE_COPY,
        PROTECTED_REFERENCE_UPLOAD,
        PROTECTED_REFERENCE_CLEANUP,
    )
    if ci.count("\n" + PROTECTED_REFERENCE_HEADER) != 1 or [step for step in steps if step] != list(expected_steps):
        failures.append(
            "ci.yml: the protected reference job must keep its exact root bootstrap, evidence copy, upload and cleanup"
        )
    if "continue-on-error" in job or "cataggar/ghr" in job or re.search(r"\bsudo (?!-n )", job):
        failures.append("ci.yml: the protected reference job must not hide failures or use unprotected tools")
    script = texts.get("tools/real-snapshot-reference-protected-ci.sh", "")
    for token in PROTECTED_REFERENCE_SCRIPT_TOKENS:
        if script.count(token) != 1:
            failures.append(f"protected reference CI script lost {token.strip()}")
    if re.search(r"(?m)^\s*exit 0\b|\|\|\s*true\b|SkipTest|--skip", script) or script.count(
        'python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"'
    ) != 5:
        failures.append("protected reference CI script must not skip and must check the tree at every stage")
    for path, tokens in PROTECTED_REFERENCE_SOURCE_TOKENS.items():
        for token in tokens:
            if texts.get(path, "").count(token) != 1:
                failures.append(f"{path}: protected reference wiring lost {token.strip()}")
    harness = texts.get("tools/test_real_snapshot_reference_protected.py", "")
    if "SkipTest" in harness or "skipTest" in harness:
        failures.append("protected reference proof must not skip")
    return failures


def native_recovery_ci_failures(text: str) -> list[str]:
    jobs = dict(re.findall(
        r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        text,
    ))
    failures = []
    failures.extend(ci_dispatch_matrix_failures(text, jobs))
    failures.extend(workload_ci_failures(jobs, text))
    architectures = (
        "          - os: ubuntu-24.04\n"
        "            name: linux-x64\n"
        "          - os: ubuntu-24.04-arm\n"
        "            name: linux-arm64\n"
    )
    diversion_architectures = "".join(
        f"          - os: {os}\n            name: {arch}\n            shard: {shard}\n"
        for os, arch in (("ubuntu-24.04", "linux-x64"), ("ubuntu-24.04-arm", "linux-arm64"))
        for shard in range(1, len(DIVERSION_CASE_SHARDS) + 1)
    )
    if "native-recovery" in jobs or re.search(
        r"(?m)^\s+zig build test-native-recovery(?:\s|$)", text,
    ):
        failures.append("ci.yml: retired recovery job or duplicate complete aggregate is present")
    recovery_jobs = {}
    for name, (display_name, step_name, targets) in RECOVERY_ZIG_SHARDS.items():
        expected_steps = {}
        if name == "native-recovery-zig-workflows":
            expected_steps["Exercise Zig recovery units in both modes"] = (
                None,
                [
                    "mkdir -p .tmp",
                    "zig build test-native-recovery-zig-unit -j2 --summary all",
                    "zig build test-native-recovery-zig-unit -Doptimize=ReleaseSafe -j2 --summary all",
                ],
            )
        expected_steps[step_name] = (
            None,
            [
                *(["mkdir -p .tmp"] if name in (
                    "native-recovery-zig-workflows",
                    "native-recovery-zig-repository",
                    "native-recovery-zig-helper",
                    "native-recovery-zig-family",
                ) else []),
                'reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
                *recovery_zig_commands(targets, sharded=name == "native-recovery-zig-diversions"),
            ],
        )
        if name == "native-recovery-zig-workflows":
            expected_steps[ROOT_IMPORT_STEP] = (None, ROOT_IMPORT_COMMANDS)
        recovery_jobs[name] = (
            display_name,
            diversion_architectures if name == "native-recovery-zig-diversions" else architectures,
            expected_steps,
        )
    expected_commands = []
    shared_setup = None
    for name, (display_name, matrix_rows, expected_steps) in recovery_jobs.items():
        body = jobs.get(name, "")
        timeout_minutes = 75 if name in (
            "native-recovery-zig-scenarios", "native-recovery-zig-diversions",
        ) else 35
        strategy = (
            "      fail-fast: false\n"
            "      matrix:\n"
            "        include:\n"
            f"{matrix_rows}"
        )
        if (
            f"    name: {display_name}" not in body.splitlines()
            or "    runs-on: ${{ matrix.os }}" not in body.splitlines()
            or re.findall(r"(?m)^    timeout-minutes:[^\n]*$", body)
            != [f"    timeout-minutes: {timeout_minutes}"]
            or body.count("    strategy:\n") != 1
            or body.count("    steps:\n") != 1
            or body.split("    strategy:\n", 1)[-1].split("    steps:\n", 1)[0] != strategy
            or re.search(r"(?m)^    continue-on-error:", body)
            or "continue-on-error:" in body
        ):
            failures.append(f"ci.yml: {name} must require every reviewed architecture and mode within {timeout_minutes} minutes")
        steps = dict(re.findall(
            r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", body,
        ))
        first_step = next(iter(expected_steps))
        setup = body.split("    steps:\n", 1)[-1].split(f"      - name: {first_step}\n", 1)[0]
        if shared_setup is None:
            shared_setup = setup
        if setup != shared_setup or any(line not in setup for line in (
            "      - name: Install Zig via ghr\n",
            "      - name: Validate Zig version\n",
            "      - name: Install metadata decompression and signed fixture dependencies\n",
            "liblzma-dev libzstd-dev python3-cryptography python3-jsonschema",
        )) or re.search(r"(?m)^        if:", setup):
            failures.append(f"ci.yml: {name} must retain pinned Zig and signed fixture dependencies")
        if len(steps) != len(expected_steps) + 3:
            failures.append(f"ci.yml: {name} has an unreviewed recovery step")
        for step_name, (condition, commands) in expected_steps.items():
            step = steps.get(step_name, "")
            lines = step.splitlines()
            script = step.split("        run: |\n", 1)
            actual = [
                line.strip() for line in script[1].splitlines() if line.strip()
            ] if len(script) == 2 else []
            if (
                [line for line in lines if line.startswith("        if:")]
                != ([condition] if condition else [])
                or actual != commands
            ):
                failures.append(f"ci.yml: {name} must execute {step_name} without skips or missing commands")
            expected_commands.extend(commands)
        actual_commands = re.findall(
            r"(?m)^          (zig build test-native-recovery[^\n]+)$", body,
        )
        required_commands = [
            line for _, commands in expected_steps.values()
            for line in commands if line.startswith("zig build test-native-recovery")
        ]
        if actual_commands != required_commands:
            failures.append(f"ci.yml: {name} must execute every recovery target exactly once per mode")
    inventory_commands = [
        command for command in expected_commands
        if command.startswith("zig build test-native-recovery")
    ]
    if len(inventory_commands) != 34 or len(inventory_commands) != len(set(inventory_commands)):
        failures.append("ci.yml: recovery command inventory contains duplicate targets")
    actual_commands = re.findall(
        r"(?m)^[ \t]+(zig build test-native-recovery[^\n]+)$", text,
    )
    if sorted(actual_commands) != sorted(inventory_commands):
        failures.append("ci.yml: recovery targets must execute only in the six required Zig shards")
    if re.findall(r"(?m)^[ \t]+(zig build test-native-root-import[^\n]*)$", text) != [
        command for command in ROOT_IMPORT_COMMANDS
        if command.startswith("zig build test-native-root-import")
    ]:
        failures.append("ci.yml: pinned-dpkg root import must run once per mode only in the required core shard")
    gate = jobs.get("build-and-test", "")
    gate_steps = dict(re.findall(
        r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", gate,
    ))
    gate_step = gate_steps.get("Require every build and native recovery shard", "")
    gate_script = gate_step.split("        run: |\n", 1)
    required_results = [
        *(f'test "${variable}" = success' for variable, _ in WORKLOAD_RESULTS),
        'test "$RECOVERY_WORKFLOWS_RESULT" = success',
        'test "$RECOVERY_REPOSITORY_RESULT" = success',
        'test "$RECOVERY_HELPER_RESULT" = success',
        'test "$RECOVERY_FAMILY_RESULT" = success',
        'test "$RECOVERY_SCENARIOS_RESULT" = success',
        'test "$RECOVERY_DIVERSIONS_RESULT" = success',
    ]
    if any(line not in gate.splitlines() for line in (
        "    name: Build and test (${{ matrix.name }})",
        "    needs: [build-and-test-workload, build-and-test-workload-production, build-and-test-workload-apt-system, build-and-test-workload-native, build-and-test-workload-release, native-recovery-zig-workflows, native-recovery-zig-repository, native-recovery-zig-helper, native-recovery-zig-family, native-recovery-zig-scenarios, native-recovery-zig-diversions]",
        f"    if: {CI_BUILD_AGGREGATE_CONDITION}",
        "      fail-fast: false",
        "        name: [linux-x64, linux-arm64]",
        *(f"          {variable}: ${{{{ needs.{job}.result }}}}" for variable, job in WORKLOAD_RESULTS),
        "          RECOVERY_WORKFLOWS_RESULT: ${{ needs.native-recovery-zig-workflows.result }}",
        "          RECOVERY_REPOSITORY_RESULT: ${{ needs.native-recovery-zig-repository.result }}",
        "          RECOVERY_HELPER_RESULT: ${{ needs.native-recovery-zig-helper.result }}",
        "          RECOVERY_FAMILY_RESULT: ${{ needs.native-recovery-zig-family.result }}",
        "          RECOVERY_SCENARIOS_RESULT: ${{ needs.native-recovery-zig-scenarios.result }}",
        "          RECOVERY_DIVERSIONS_RESULT: ${{ needs.native-recovery-zig-diversions.result }}",
        *(f'          test "${variable}" = success' for variable, _ in WORKLOAD_RESULTS),
        '          test "$RECOVERY_WORKFLOWS_RESULT" = success',
        '          test "$RECOVERY_REPOSITORY_RESULT" = success',
        '          test "$RECOVERY_HELPER_RESULT" = success',
        '          test "$RECOVERY_FAMILY_RESULT" = success',
        '          test "$RECOVERY_SCENARIOS_RESULT" = success',
        '          test "$RECOVERY_DIVERSIONS_RESULT" = success',
    )) or "continue-on-error:" in gate or re.search(r"(?m)^        if:", gate) or (
        len(gate_steps) != 1
        or len(gate_script) != 2
        or [line.strip() for line in gate_script[-1].splitlines() if line.strip()]
        != required_results
        or len(re.findall(r"(?m)^    needs:", gate)) != 1
    ):
        failures.append("ci.yml: existing required build checks must reject any incomplete workload")
    return failures


SIGNED_PROC_CI_JOB = (
    "    name: Signed proc replay in protected amd64 roots (${{ matrix.optimize }})",
    "    runs-on: ubuntu-24.04",
    "    timeout-minutes: 35",
    "      fail-fast: false",
    "        optimize: [Debug, ReleaseSafe]",
    "      OPTIMIZE: ${{ matrix.optimize }}",
    "      PROTECTED: /srv/debz-protected/signed-proc",
    "      UBUNTU_ARCHIVE_KEYRING_SHA256: 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
)
SIGNED_PROC_CI_STEPS = {
    "Install Zig via ghr": (),
    "Validate Zig version": ('        run: test "$(zig version)" = 0.16.0',),
    "Bind the reviewed commit to a hosted amd64 runner": (
        '          test "$RUNNER_ARCH" = X64',
        '          test "$(uname -m)" = x86_64',
        '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        '          test ! -e "$PROTECTED" && test ! -L "$PROTECTED"',
    ),
    "Install metadata decompression dependency": (),
    "Prepare pinned dpkg as the runner user": (
        '          reference_dpkg="$(python3 tools/prepare-native-dpkg.py --architecture amd64)"',
        '          test "$reference_dpkg" = "$PWD/.cache/native-dpkg-reference/1.22.22/amd64/usr/bin/dpkg"',
    ),
    "Refuse unprotected and incomplete signed replay inputs": (
        "          set -euo pipefail",
        "          grep -Fq 'prestate path is writable by an unprivileged user' .tmp/unprotected-prestates.log",
        "          grep -Fq 'fixture path is writable by an unprivileged user' .tmp/unprotected-bindings.log",
        "          grep -Fq 'signed proc replay requires -Dsigned-systemd-proc-root' .tmp/missing-roots.log",
        "          grep -Fq 'three distinct absolute disposable root paths' .tmp/relative-roots.log",
    ),
    "Stage the reviewed commit, Zig and pinned dpkg under root-owned ancestry": (
        "          set -euo pipefail",
        "          git -c tar.umask=0022 archive --format=tar -o .tmp/protected-checkout.tar HEAD",
        '          sudo -n tar -C "$PROTECTED/checkout" --no-same-owner -xf "$PROTECTED/checkout.tar"',
        "          sudo -n install -o root -g root -m 0644 /usr/share/keyrings/ubuntu-archive-keyring.gpg \\",
        '            <<<"$UBUNTU_ARCHIVE_KEYRING_SHA256  $PROTECTED/keyrings/ubuntu-archive-keyring.gpg"',
        '          sudo -n chmod -R go-w "$PROTECTED"',
        '          sudo -n find "$PROTECTED" -xdev \\( ! -uid 0 -o ! -gid 0 -o -perm /022 \\) ! -type l \\',
        "          test ! -s .tmp/protected-writable.txt",
        '          for path in / /srv /srv/debz-protected "$PROTECTED"; do',
        "            test \"$(stat -c '%u:%g' \"$path\")\" = 0:0",
        "            test $(( 8#$(stat -c '%a' \"$path\") & 022 )) -eq 0",
        '          sudo -n cmp -- "$zig_binary" "$PROTECTED/zig/zig"',
        '            --verify-only "$PROTECTED/checkout/.real-snapshot/pinned-dpkg/usr/bin/dpkg"',
    ),
    "Build the protected snapshot client": (
        "        working-directory: ${{ env.PROTECTED }}/checkout",
        "            zig build -Doptimize=Debug -j2 --summary all",
    ),
    "Authenticate the snapshot closure and generate fresh signed prestates": (
        "        working-directory: ${{ env.PROTECTED }}/checkout",
        '            DEBZ_REAL_SNAPSHOT_KEYRING="$PROTECTED/keyrings/ubuntu-archive-keyring.gpg" \\',
        '            tools/real-snapshot-signed-proc-bindings.sh "$PWD/zig-out/bin/debz" \\',
        "            tools/real-snapshot-signed-proc-prestates.sh \\",
        '            "$PWD/.real-snapshot/pinned-dpkg/usr/bin/dpkg" "$PWD/.real-snapshot/ws"',
        '          sudo -n test -s "$PWD/.real-snapshot/ws/prestate-build/evidence/base-cycle-proof/comparison.json"',
        '          sudo -n test -s "$PWD/.real-snapshot/ws/prestate-build/evidence/openssl-cycle-after.json"',
    ),
    "Run pinned dpkg proofs on separate prestate copies": (
        "        working-directory: ${{ env.PROTECTED }}/checkout",
        '                cp -a -- "$ws/prestates/$target" "$ws/native/$target"',
        '                cp -a -- "$ws/prestates/$target" "$ws/proof-sources/$target"',
        '              ln -sfn -- sudo.ws "$ws/native/sudo/usr/bin/sudoedit"',
        '              ln -sfn -- sudo.ws.8.gz "$ws/native/sudo/usr/share/man/man8/sudoedit.8.gz"',
        '              test "$(readlink -- "$ws/native/sudo/usr/bin/sudoedit")" = sudo.ws',
        '              test "$(readlink -- "$ws/native/sudo/usr/share/man/man8/sudoedit.8.gz")" = sudo.ws.8.gz',
        '              tools/real-snapshot-systemd-proc-reference.sh "$pinned" \\',
        '                "$ws/proof-sources/systemd" "$ws/proofs/systemd"',
        '              tools/real-snapshot-udev-reference.sh "$pinned" \\',
        '                "$ws/proof-sources/udev" "$ws/proofs/udev"',
        '              tools/real-snapshot-sudo-reference.sh "$pinned" \\',
        '                "$ws/proof-sources/sudo" "$ws/proofs/sudo"',
    ),
    "Replay signed systemd, udev and sudo postinsts natively without skips": (
        "        working-directory: ${{ env.PROTECTED }}/checkout",
        "          set -euo pipefail",
        '            zig build test-native-signed-proc -Doptimize="$OPTIMIZE" -j2 --summary all \\',
        '              -Dsigned-systemd-proc-root="$ws/native/systemd" \\',
        '              -Dsigned-udev-proc-root="$ws/native/udev" \\',
        '              -Dsigned-sudo-proc-root="$ws/native/sudo" \\',
        '          test "${status:-0}" -eq 0',
        "          grep -Fxq 'All 4 tests passed.' \"$GITHUB_WORKSPACE/.tmp/signed-proc-replay.log\"",
        "          for name in 'systemd postinst uses scoped masked proc' \\",
        "            'udev postinst uses only PID proc and applies static permissions' \\",
        "            'sudo postinst repairs only pinned alternatives with PID-only proc'; do",
        '            grep -Fq "maintainer_script.test.signed $name...OK" "$GITHUB_WORKSPACE/.tmp/signed-proc-replay.log"',
        '          for target in systemd udev; do',
        '            sudo -n cat "$PROTECTED/checkout/.tmp/signed-network-$target.proof" >"$proof"',
        '            grep -Fxq "domain=$target" "$proof"',
        "            grep -Fxq 'DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open' \"$proof\"",
        '            case "$target" in',
        "              systemd) proc_net=private ;;",
        "              udev) proc_net=absent ;;",
        "              *) exit 1 ;;",
        '            grep -Fxq "DEBZ_SIGNED_NETWORK_PROOF proc_net=$proc_net interfaces=lo default_route=false host_tcp=denied abstract_unix=denied inherited_fd=sealed loopback=ok" "$proof"',
    ),
    "Compare native replays with pinned dpkg proofs": (
        "        working-directory: ${{ env.PROTECTED }}/checkout",
        "              python3 -m unittest tools/test_real_snapshot_signed_proc_compare.py",
        "              for target in systemd udev sudo; do",
        '                python3 tools/real-snapshot-signed-proc-compare.py "$target" \\',
        '                  "$ws/native/$target" "$ws/proofs/$target" "$ws/compare/$target.json"',
    ),
    "Execute signed binding refusal fixtures": (
        "        working-directory: ${{ env.PROTECTED }}/checkout",
        "          set -euo pipefail",
        "            DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE=1 \\",
        '            sh "$PWD/.real-snapshot/ws/bindings.env" "$OPTIMIZE" \\',
        '          test "${status:-0}" -eq 0',
        "          grep -Eq '^[1-9][0-9]* passed; 3 skipped; 0 failed\\.$' "
        '"$GITHUB_WORKSPACE/.tmp/signed-bindings.log"',
    ),
    "Copy bounded evidence and remove named protected roots": (
        "        if: ${{ always() }}",
        "          set -euo pipefail",
        '          if grep -F "$PROTECTED" .tmp/signed-proc-mounts.txt; then',
        '          sudo -n rm -rf --one-file-system -- "$PROTECTED"',
        '          test ! -e "$PROTECTED"',
        "                snapshot/evidence/refresh.json snapshot/evidence/refresh.stderr \\",
        "                snapshot/evidence/plan.json snapshot/evidence/plan.stderr \\",
        "                snapshot/evidence/download.json snapshot/evidence/download.stderr \\",
        "                prestate-build/evidence/base-cycle-before.json \\",
        "                prestate-build/evidence/base-cycle-after.json \\",
        "                prestate-build/evidence/openssl-cycle-before.json \\",
        "                prestate-build/evidence/openssl-cycle-after.json \\",
        "                prestate-build/evidence/openssl-cycle-refusals.json \\",
        "                prestate-build/evidence/reference-no-progress.json \\",
        "                prestate-build/evidence/base-cycle-proof/comparison.json \\",
        "                native/systemd/var/log/dpkg.log native/udev/var/log/dpkg.log \\",
        "                native/sudo/var/log/dpkg.log \\",
        "                native/systemd/var/lib/dpkg/status native/udev/var/lib/dpkg/status \\",
        "                native/sudo/var/lib/dpkg/status \\",
        "                native/systemd/var/lib/dpkg/status-old native/udev/var/lib/dpkg/status-old \\",
        "                native/sudo/var/lib/dpkg/status-old \\",
        "                proofs/systemd/var/lib/dpkg/status proofs/udev/var/lib/dpkg/status \\",
        "                proofs/sudo/var/lib/dpkg/status \\",
        "                proofs/systemd/var/lib/dpkg/status-old proofs/udev/var/lib/dpkg/status-old \\",
        "                proofs/sudo/var/lib/dpkg/status-old \\",
        "                native/udev/etc/group proofs/udev/etc/group \\",
    ),
    "Upload bounded signed replay evidence": (
        "        if: ${{ always() }}",
        "          if-no-files-found: error",
    ),
}


def signed_proc_ci_failures(text: str) -> list[str]:
    """Require the hosted amd64 non-skipped signed proc replay job as reviewed.

    The job is deliberately outside the required aggregate: the pinned
    snapshot's Valid-Until and the #262 repin change the signed identities.
    """
    jobs = dict(re.findall(
        r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        text,
    ))
    body = jobs.get("signed-proc-protected-replay", "")
    lines = body.splitlines()
    failures = []
    if (
        any(line not in lines for line in SIGNED_PROC_CI_JOB)
        or re.search(r"(?m)^    (if|needs|continue-on-error):", body)
        or re.search(r"(?m)^        (include|exclude):", body)
        or "continue-on-error" in body
    ):
        failures.append("ci.yml: signed proc replay job must run both modes on hosted amd64 within 35 minutes")
    steps = re.findall(r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", body)
    if [name for name, _ in steps] != list(SIGNED_PROC_CI_STEPS):
        failures.append("ci.yml: signed proc replay steps changed from the reviewed sequence")
    for name, step_body in steps:
        required = SIGNED_PROC_CI_STEPS.get(name, ())
        step_lines = step_body.splitlines()
        conditions = [line for line in step_lines if re.match(r"^        if:", line)]
        if (
            any(line not in step_lines for line in required)
            or conditions not in ([], ["        if: ${{ always() }}"])
            or (conditions and "        if: ${{ always() }}" not in required)
            or any(
                not 1 <= int(minutes) <= 25
                for minutes in re.findall(r"(?m)^        timeout-minutes: ([0-9]+)$", step_body)
            )
        ):
            failures.append(f"ci.yml: signed proc replay step changed: {name}")
    if "--report-only" in body or "DEBZ_REQUIRE_SIGNED_PROC_ROOTS=0" in body:
        failures.append("ci.yml: signed proc replay comparison and roots must fail closed")
    return failures


REPORT_PATH_ORACLE_FILES = (
    "test/native_recovery_oracle.zig",
    "test/native_recovery_unit.zig",
    "test/native_recovery_acceptance.zig",
    "test/native_recovery_scriptless.zig",
    "test/native_recovery_conffile.zig",
    "test/native_recovery_literal.zig",
    "test/native_recovery_metadata.zig",
    "test/native_recovery_statoverride.zig",
)


def native_report_path_wiring_failures(texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    required = {
        "test/native_recovery_oracle.zig": (
            ('pub fn reportProvenancePath(reported: []const u8, expected: []const u8) ![]const u8 {', 1),
            ('if (!std.mem.eql(u8, reported, expected)) return error.UnboundRecoveryProof;', 1),
            ("return expected;", 1),
        ),
        "test/native_recovery_acceptance.zig": (
            ('_ = try oracle.reportProvenancePath(report.provenance_path orelse return error.MissingReportBinding, provenance_path);', 1),
        ),
        "test/native_recovery_scriptless.zig": (
            ("pub fn reportProvenancePath(reported: ?[]const u8) ![]const u8 {", 1),
            ("return oracle.reportProvenancePath(reported orelse return error.MissingRecoveryProof, provenance_path);", 1),
            ("const proof_path = try reportProvenancePath(report.value.provenance_path);", 1),
        ),
        "test/native_recovery_conffile.zig": (
            ("const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);", 2),
        ),
        "test/native_recovery_literal.zig": (
            ("const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);", 1),
        ),
        "test/native_recovery_metadata.zig": (
            ("const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);", 1),
        ),
        "test/native_recovery_statoverride.zig": (
            ("const proof_path = try process.reportProvenancePath(report.value.provenance_path);", 1),
        ),
    }
    for path, tokens in required.items():
        source = texts.get(path, "")
        for token, count in tokens:
            if source.count(token) < count:
                failures.append(f"{path}: report provenance path is no longer bound before reading: {token}")
    unit = texts.get("test/native_recovery_unit.zig", "")
    case = unit.partition('test "recovery-unit.report path is bound before reading provenance" {')[2].partition('\ntest "')[0]
    for token in (
        '"/etc/passwd"', '"var/lib/debz/../../outside"',
        '"var/lib/debz-other/proof.json"', '"var/lib/debz/proof.json"',
        "provenance.document_path", "error.UnboundRecoveryProof",
        'try sandbox.dir.symLink(sandbox.io, external, "var/lib/debz/proof.json", .{});',
        "try std.testing.expect((try provenance.read(allocator, root)) == null);",
    ):
        if token not in case:
            failures.append(f"test/native_recovery_unit.zig: missing report-path refusal: {token}")
    return failures

def native_recovery_gate_wiring_failures(
    build: str, helper: str, family: str, projected: str, repository: str, diversions: str,
) -> list[str]:
    failures: list[str] = []
    for path in ("tools/test-native-recovery.py", "tools/test_native_recovery.py"):
        if f'"{path}"' in build:
            failures.append(f"build.zig: retired Python recovery gate was restored: {path}")
    start = 'const native_recovery = b.step("test-native-recovery",'
    graph = build.partition(start)[2].partition('    if (b.option(\n        []const u8,\n        "native-reference-architecture"')[0]
    if not graph:
        return failures + ["build.zig: complete Zig recovery gate is missing"]
    selectors = re.search(r"const selectors = \[_\]bool\{([^}]+)\};", graph)
    if selectors is None or tuple(re.findall(r"[a-z_]+", selectors[1])) != (
        "native_core_only", "native_deadline_only", "native_script_failure_only",
        "repository_projection_only", "repository_execution_only", "repository_cli_only",
        "native_parity_only", "native_helper_only", "native_diversions_only",
    ):
        failures.append("build.zig: nine public recovery workload selectors must remain exclusive")
    for token in (
        "native_recovery.dependOn(&run_native_recovery_tests.step);",
        "native_recovery.dependOn(&run_recovery_unit_tests.step);",
        "native_recovery.dependOn(&run_repository_recovery_unit.step);",
        "if (selected > 1 or focused)",
        "focused Zig case options cannot narrow the complete test-native-recovery gate",
        "zig_core_only or zig_deadline_only or family_executed_only or",
        "parity_case != null or bootstrap_case != null or repository_case != null or",
        "diversion_case != null or route_case != null or diversion_shard != null or mutation_boundary_case != null",
        'b.option([]const u8, "native-zig-recovery-diversion-shard",',
        'recovery_diversions.addArgs(&.{ "--shard", shard });',
        'if (native_core_only or zig_core_only) recovery_zig.addArg("--core-only");',
        'if (native_deadline_only or zig_deadline_only) recovery_zig.addArg("--deadline-only");',
        'if (native_script_failure_only or native_core_only) recovery_helper.addArg("--script-failure-only");',
        'if (repository_projection_only) recovery_family.addArg("--projection-only");',
        'if (repository_projection_only) repository_recovery.addArg("--projection-only");',
        'if (repository_execution_only) repository_recovery.addArg("--execution-only");',
        'if (repository_cli_only) repository_recovery.addArg("--cli-only");',
        'recovery_family.addArtifactArg(native_trigger_helper);',
        'recovery_family.addArtifactArg(cli);',
        'recovery_bootstrap.addArtifactArg(native_trigger_helper);',
        'repository_recovery.addArtifactArg(cli);',
        'const repository_fixture_parent = b.addSystemCommand(&.{ "mkdir", "-p", b.pathFromRoot(".tmp") });',
        'run_repository_recovery_unit.step.dependOn(&repository_fixture_parent.step);',
        'repository_recovery.step.dependOn(&repository_fixture_parent.step);',
        'recovery_parity.addArtifactArg(cli);',
        'recovery_parity.addArtifactArg(native_trigger_helper);',
        '}) |runner| runner.addArgs(&.{ "--reference-dpkg", path });',
    ):
        if token not in graph:
            failures.append(f"build.zig: complete Zig recovery gate lost {token}")
    branch = graph.partition("if (selected > 1 or focused) {")[2].partition('    if (b.option([]const u8, "native-reference-dpkg"')[0]
    for token in (
        "if (native_deadline_only) {\n            native_recovery.dependOn(&recovery_zig.step);",
        "if (native_script_failure_only) {\n            native_recovery.dependOn(&recovery_helper.step);",
        "if (native_helper_only) {\n            native_recovery.dependOn(&recovery_bootstrap.step);",
        "if (native_diversions_only) {\n            native_recovery.dependOn(&recovery_diversions.step);",
        "if (repository_projection_only) {\n            native_recovery.dependOn(&recovery_family.step);\n            native_recovery.dependOn(&repository_recovery.step);",
        "if (repository_execution_only or repository_cli_only) {\n            native_recovery.dependOn(&repository_recovery.step);",
    ):
        if token not in branch:
            failures.append(f"build.zig: recovery selector graph lost {token}")
    arrays = re.findall(
        r"for \(\[_\]\*std\.Build\.Step\.Run\{([^}]+)\}\) \|runner\| native_recovery\.dependOn\(&runner\.step\);",
        branch,
    )
    expected = (
        ("recovery_parity", "recovery_diversions", "statoverride_recovery", "conffile_recovery",
         "metadata_recovery", "literal_recovery", "scriptless_recovery", "publication_recovery"),
        ("recovery_zig", "recovery_helper", "recovery_bootstrap", "recovery_family",
         "recovery_diversions", "statoverride_recovery", "conffile_recovery",
         "metadata_recovery", "literal_recovery", "mutation_boundaries", "publication_recovery"),
        ("recovery_zig", "recovery_family", "recovery_parity", "recovery_helper",
         "final_gaps", "recovery_bootstrap", "repository_recovery", "rollback_clock",
         "scriptless_recovery", "statoverride_recovery", "literal_recovery",
         "metadata_recovery", "conffile_recovery", "recovery_diversions",
         "mutation_boundaries", "publication_recovery"),
    )
    if tuple(tuple(re.findall(r"[a-z_]+", group)) for group in arrays) != expected:
        failures.append("build.zig: parity, core, or default recovery workload lost an executed runner")
    pinned = graph.partition('if (b.option([]const u8, "native-reference-dpkg",')[2]
    pinned_runners = re.search(
        r'for \(\[_\]\*std\.Build\.Step\.Run\{([^}]+)\}\) \|runner\| '
        r'runner\.addArgs\(&\.\{ "--reference-dpkg", path \}\);',
        pinned,
    )
    if pinned_runners is None or tuple(re.findall(r"[a-z_]+", pinned_runners[1])) != expected[-1]:
        failures.append("build.zig: pinned dpkg must reach every default recovery acceptance runner")
    shard_block = diversions.partition("const case_shards = [_]CaseShard{")[2].partition("\n};")[0]
    actual_shards = tuple(
        (int(first), int(last))
        for first, last in re.findall(r"\.\{ \.first = (\d+), \.last = (\d+) \},", shard_block)
    )
    if actual_shards != DIVERSION_CASE_SHARDS:
        failures.append("test/native_recovery_diversions.zig: numbered shard partitions must cover 001-100 exactly once")
    for token in (
        "if (cases.len != 100) @compileError(",
        "if (c.number <= previous or c.number > 100) @compileError(",
        "if (shard.first != next or shard.last < shard.first or shard.last > cases.len)",
        "if (next != cases.len + 1) @compileError(",
        "if (route_cases.len != 2) @compileError(",
        '.{ .name = "cache-refresh", .crash = "after_upgrade_postrm_cache_refresh" },',
        '.{ .name = "route-checkpoint", .crash = "after_upgrade_postrm_route_checkpoint" },',
        "if (selected != null or selected_route != null or selected_shard != null) return error.DuplicateCase;",
        "if (selected_shard.? == 0 or selected_shard.? > case_shards.len) return error.InvalidDiversionShard;",
        "const shard = if (selected_shard) |number| case_shards[number - 1] else null;",
        "if (c.number < bounds.first or c.number > bounds.last) continue;",
        "if (executed != expected_cases)",
        "const run_routes = selected == null and (selected_shard == null or selected_shard.? == case_shards.len);",
        "if (run_routes) for (route_cases) |c| {",
        "if (route_executed != (if (!run_routes)",
        "try lifecycle.assertHostUnchanged(a, init.io, reference.before);",
    ):
        if token not in diversions:
            failures.append(f"test/native_recovery_diversions.zig: required numbered or named shard behavior lost {token}")
    for option, variable, runner in (
        ("native-zig-recovery-family-fixture-python", "path", "recovery_family"),
        ("native-zig-recovery-parity-fixture-python", "path", "recovery_parity"),
        ("native-repository-fixture-python", "python", "repository_recovery"),
    ):
        handoff = re.search(
            rf'if \(b\.option\(\[\]const u8, "{re.escape(option)}", [^\n]+\)\) \|{variable}\|\s*'
            + re.escape(f'{runner}.addArgs(&.{{ "--fixture-python", {variable} }});'),
            graph,
        )
        if handoff is None:
            failures.append(f"build.zig: signed recovery fixture interpreter lost {option} handoff")
    for source, tokens in (
        (helper, ("if (script_failure_only) {", '"after_failure_outcome", "after_script_failure_state"')),
        (family, ('if (projection_only) {', "try projected.runReadOnly(&fixture, self orelse return error.MissingSelf, driver, reference.architecture);")),
        (projected, ("try readOnlyProjection(fixture, runner, driver, arch);",)),
        (repository, ("const selected = try selectMode(false, projection_only, execution_only, cli_only);",
                      "selected == null or selected == .projection or selected == .execution or selected == .cli")),
    ):
        for token in tokens:
            if token not in source:
                failures.append(f"Zig recovery selector lost an executed case: {token}")
    script_branch = helper.partition("if (script_failure_only) {")[2].partition("\n    try crashTransport(")[0]
    if "try knownScriptFailures(&fixture, driver, reference.executable, reference.architecture);" not in script_branch:
        failures.append("Zig recovery script-failure selector lost both unowned postinst crashes")
    return failures


def native_core_completion_wiring_failures(
    build: str, helper: str, support: str,
) -> list[str]:
    failures: list[str] = []
    for token in (
        'recovery_helper.addArtifactArg(recovery_helper_executable);',
        'recovery_helper.addArtifactArg(native_lifecycle_tests);',
        'b.step("test-native-recovery-helper-zig",',
    ):
        if token not in build:
            failures.append(f"build.zig: required core completion target lost {token}")
    for token in (
        "try completedWithoutLiveHelper(&fixture, driver, reference.executable, reference.architecture);",
        "try missingPackageOwnedHelper(&fixture, driver, reference.architecture);",
        "try rehashedCallerPolicy(&fixture, driver, reference.architecture);",
        "try afterActiveClearLegacyEvidence(&fixture, driver, reference.executable, reference.architecture);",
        '"NativeHelperBootstrapOwnerMissing"',
        '"RecoveryRequestBindingMismatch"',
        '"after_active_clear"',
        'try sealJsonDigest(fixture, &persisted.value, "debz-native-execution-request-v1\\x00");',
        "debz.native_recovery.sealIntent(&altered_intent);",
        'const orphaned = try projected.rootInventory(fixture, root, false);',
        'try std.testing.expectEqualSlices(u8, orphaned, try projected.rootInventory(fixture, root, false));',
        'try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, directory), old_proof.document);',
        '.config_content = config,',
        'const config = "#!/bin/sh\\n# config:1\\nprintf \'%s\\\\n\' \'config:1\' >> /config-invoked\\nexit 97\\n";',
    ):
        if token not in helper:
            failures.append(f"native_recovery_helper.zig: required executed core completion lost {token}")
    for token in (
        "config_content: ?[]const u8 = null,",
        'try fixture.write(config, configuration, 0o755);',
    ):
        if token not in support:
            failures.append(f"native_lifecycle_support.zig: real staged config fixture lost {token}")
    for token in (
        'try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));',
        'try same(try bytes(fixture, root, "var/lib/dpkg/tmp.ci/config", 64 * 1024), config);',
        'try missing(fixture, root, "var/lib/dpkg/info/" ++ foundation.package ++ ".config");',
        'try missing(fixture, root, "config-invoked");',
    ):
        if helper.count(token) != 3:
            failures.append(f"native_recovery_helper.zig: executed core checks lost {token}")
    caller_case = helper.split("fn rehashedCallerPolicy(", 1)[-1].split(
        "\nfn afterActiveClearLegacyEvidence(", 1,
    )[0]
    if caller_case.count(".isolated_helper = false,") != 2:
        failures.append("native_recovery_helper.zig: rehashed caller refusal must run without isolated helper")
    ordinary = helper.split("fn recoveredOrdinary(", 1)[-1].split("\n}\n", 1)[0]
    for token in (
        "if (try invoke(fixture, driver, root, arch, crash_output, .{",
        "try fixture.dir.deleteFile(fixture.io, archive_relative);",
        "const request = try originalRequestFor(fixture, root, intent.intent, case.isolated_helper, case.caller_owned, archive);",
        "if (reference_exit != (if (case.known_preinst_failure)",
        "try foundation.compare(fixture.*, expected, root, comparison);",
        "try verifyProofFor(fixture, root, repeated.value, intent.intent, request, proof_outcome, true, case.isolated_helper, case.caller_owned);",
        "try std.testing.expectEqualSlices(u8, root_before, try projected.rootInventory(fixture, root, case.caller_owned));",
        "try sameHelper(fixture, root, helper_before);",
        ".acknowledge = true,",
    ):
        if token not in ordinary:
            failures.append(f"native_recovery_helper.zig: ordinary real-process parity lost {token}")
    for token in (
        "try foundation.compare(fixture.*, expected, root, comparison);",
        "try sameHelper(fixture, root, helper_before);",
    ):
        if ordinary.count(token) != 2:
            failures.append(f"native_recovery_helper.zig: ordinary first/last checks lost {token}")
    main = helper.split("pub fn main(", 1)[-1]
    if main.count("try recoveredOrdinary(") != 5:
        failures.append("native_recovery_helper.zig: ordinary caller, failure and crash matrices not all executed")
    for token in (
        '"after_execution_intent", "during_filesystem_publication",\n        "after_script_outcome",   "after_provenance",',
        '"typed-runtime-known-failure" else "caller-known-failure"',
        '"after_execution_intent", "during_filesystem_publication", "during_database_publication",\n        "after_script_prepared",  "after_script_outcome",          "after_provenance",',
        '.name = "known-failure-compensation",',
    ):
        if token not in main:
            failures.append(f"native_recovery_helper.zig: ordinary executed matrix lost {token}")
    return failures


def native_exercise_final_wiring_failures(
    helper: str, support: str, unpack: str,
) -> list[str]:
    failures: list[str] = []
    main = helper.split("pub fn main(", 1)[-1]
    for token in (
        "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, false);",
        "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, true);",
        "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
        "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
        "try noInterestOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
        "try noInterestOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
        "for ([_]Corruption{ .intent, .progress, .artifact, .managed_root, .completed_phase }) |which|",
        "try corruptedOrdinary(&fixture, driver, reference.architecture, which);",
    ):
        if token not in main:
            failures.append(f"native_recovery_helper.zig: final exercise matrix lost {token}")
    if ('if (!claim.value.object.swapRemove(changing)) return error.InvalidRootClaim;' not in helper or
        '"generation", "state", "phase", "step", "updated_unix", "digest_sha256"' not in helper):
        failures.append("native_recovery_helper.zig: sticky root claim normalization lost")
    for start, end, tokens in (
        ("fn blockedUnknown(", "\nfn triggerOutcome(", (
            "if (try invoke(fixture, driver, scenario.native_root, arch,",
            '"after_upgrade_postrm_return_before_outcome" else "after_script_return_before_outcome"',
            'try same(try text(script.value, "outcome"), "in_flight");',
            "try verifyProofFor(fixture, scenario.native_root, refused.value, intent.intent, request, .recovery_required, false, false, false);",
            "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, scenario.native_root));",
            "try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);",
            "try unchanged(fixture, scenario.native_root, package_before);",
            "try sameHelper(fixture, scenario.native_root, original_helper);",
        )),
        ("fn triggerOutcome(", "\nfn noInterestOutcome(", (
            '"after_trigger_outcome"',
            "try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);",
            "if (events.value.events.len != 2) return error.IncorrectTriggerEventCount;",
            "observed[0].origin != .automatic or observed[1].origin != .dynamic",
            'try same(observed[0].trigger, "debz-a");',
            'try same(observed[1].trigger, "debz-b");',
            ".acknowledge = true,",
        )),
        ("fn noInterestOutcome(", "\nconst Corruption =", (
            '"after_script_outcome"',
            '.activations = &.{ "debz-unwatched", "/usr/share/debz-unwatched/child" },',
            ".activation_await = true,",
            '"debz-unwatched "',
            'std.mem.indexOf(u8, line, "debz-trigger-source") == null',
            'std.mem.indexOf(u8, status, "Triggers-Awaited:") != null or',
            'std.mem.indexOf(u8, status, "Triggers-Pending:") != null',
            ".acknowledge = true,",
        )),
        ("fn corruptedOrdinary(", "\nfn caseRun(", (
            '.no_scripts = corruption != .completed_phase,',
            '.scripts = .{ .only_postinst = corruption == .completed_phase },',
            "if (artifact != null) return error.DuplicateRetainedArtifact;",
            'raw[0] = \'X\';',
            '"corrupt\\n"',
            '"external replacement\\n"',
            "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, root));",
            "try same(try stickyActiveClaim(fixture, root), original_claim);",
            "try unchanged(fixture, root, package_before);",
            "try sameHelper(fixture, root, helper_before);",
        )),
    ):
        body = helper.split(start, 1)[-1].split(end, 1)[0]
        for token in tokens:
            if token not in body:
                failures.append(f"native_recovery_helper.zig: final real-process case lost {token}")
        if start in ("fn blockedUnknown(", "fn corruptedOrdinary("):
            root = "scenario.native_root" if start == "fn blockedUnknown(" else "root"
            sticky = f"try same(try stickyActiveClaim(fixture, {root}), original_claim);"
            if body.count(sticky) != 3:
                failures.append(f"native_recovery_helper.zig: initial, repeat and blocked sticky claim checks lost {sticky}")
    for token in (
        "only_postinst: bool = false,",
        'if (options.only_postinst and !std.mem.eql(u8, kind, "postinst")) continue;',
    ):
        if token not in support:
            failures.append(f"native_lifecycle_support.zig: postinst-only corruption fixture lost {token}")
    if "var preexisting = try completion_store.read(allocator);" not in unpack:
        failures.append("native_unpack.zig: proof-bound completion must read the original receipt")
    production = unpack.split("var preexisting = try completion_store.read(allocator);", 1)[-1].split(
        "if (record.provenance == .pending)", 1,
    )[0]
    for token in (
        "previous.bindsRecord(record)",
        "record.provenance == .published",
        "record.generation - previous.record_generation != 1",
        "record.provenance_sha256 == null",
        "root_operation.provenanceDigest(record, .{",
        ".document_sha256 = previous.digest_sha256,",
        "!std.mem.eql(u8, &record.provenance_sha256.?, &published_digest)",
        "!std.mem.eql(u8, prior_evidence, current_evidence)",
        "if (!retained_completion) try completion_store.publish(allocator, statement.document);",
    ):
        if token not in production:
            failures.append(f"native_unpack.zig: proof-bound post-provenance completion lost {token}")
    completion_read = unpack.split("fn readProductionCompletion(", 1)[-1].split("\nfn ", 1)[0]
    for token in (
        "nativeAction(.provenance, std.math.maxInt(u32), 0, 0),\n    ) orelse return error.InvalidRecoveryProvenance;",
        "if (terminal.stage != .terminal or switch (receipt.document.outcome) {",
        ".succeeded => terminal.result != .succeeded and terminal.result != .recovered,",
        ".failed => terminal.result != .failed,",
        ".recovery_required => true,\n    }) return error.InvalidRecoveryProvenance;",
    ):
        if token not in completion_read:
            failures.append(f"native_unpack.zig: terminal receipt must bind retained terminal provenance progress lost {token}")
    for token in (
        "if (!std.mem.eql(u8, &retained_progress.document.head_sha256, &receipt.document.progress_head_sha256) or\n"
        "        retained_progress.document.records.len != receipt.document.progress_record_count)\n"
        "        return error.InvalidRecoveryProgress;",
        "try native_provenance.verifyScriptOutcomes(receipt.document, retained_progress.document);",
    ):
        if token not in completion_read:
            failures.append(f"native_unpack.zig: terminal receipt must bind retained script outcomes lost {token}")
    if ") catch |err| return .{ .outcome = .refused, .detail = @errorName(err) };" not in unpack.split("fn callerOwnedLifecycleFixture(", 1)[-1].split("\nfn ", 1)[0]:
        failures.append("native_unpack.zig: caller lifecycle verification must report typed refusals")
    for token in (
        "try completedScriptComponents(&fixture, driver, reference.executable, reference.architecture);",
        '.name = "caller-script-components-recovered",\n'
        '        .crash = "after_script_outcome",\n'
        "        .caller_owned = true,\n"
        "        .isolated_helper = true,\n"
        "        .script_components = true,",
    ):
        if token not in main:
            failures.append(f"native_recovery_helper.zig: completed and recovered script component matrices lost {token}")
    if "try callerScriptComponents(fixture, driver, root, arch, case.name, true);" not in helper.split("\nfn recoveredOrdinary(", 1)[-1].split("\n}\n", 1)[0]:
        failures.append("native_recovery_helper.zig: recovered attempts lost the script component matrix")
    if "try callerScriptComponents(fixture, driver, root, arch, name, false);" not in helper.split("\nfn completedScriptComponents(", 1)[-1].split("\nfn ", 1)[0]:
        failures.append("native_recovery_helper.zig: completed attempts lost the script component matrix")
    scripts = helper.split("\nfn callerScriptComponents(", 1)[-1].split("\nfn ", 1)[0]
    for token in (
        "if (recovered != (receipt.document.recovered_phase_count != 0)) return error.UnexpectedRecoveredPhaseCount;",
        '"changed-script_outcome-{d}"',
        '"EvidenceChanged"',
        '"deleted-script_outcome-{d}"',
        '"FileNotFound"',
        "if (scripts < 2) return error.MissingRetainedScriptOutcome;",
        "for (std.enums.values(ScriptReceiptTamper)) |tamper| {",
        'break :omitted "EvidenceMissing";',
        'break :duplicated "InvalidRecoveryProgress";',
        'break :rebound "EvidenceMismatch";',
        'break :reindexed "EvidenceMissing";',
        'break :summary "EvidenceMismatch";',
        'break :phases "InvalidRecoveryProgress";',
        'break :head "InvalidRecoveryProgress";',
        "forged.evidence_files_sha256 = provenance.evidenceDigest(forged.evidence_files);",
    ):
        if token not in scripts:
            failures.append(f"native_recovery_helper.zig: script component tamper matrix lost {token}")
    refused = helper.split("\nfn scriptComponentRefused(", 1)[-1].split("\nfn ", 1)[0]
    for token in (
        '        .caller_verification = expected_receipt,\n    }), "refused", expected_error);',
        '        .acknowledge = true,\n    }), "recovery_required", expected_error);',
    ):
        if token not in refused:
            failures.append(f"native_recovery_helper.zig: script component refusal lost {token}")
    if refused.count("try held.owed(fixture, root, receipt);") != 2:
        failures.append("native_recovery_helper.zig: script component refusals must leave the attempt owed after verification and recovery")
    return failures


def native_entry_point_shape_failures(core: str, projected: str, ci: str) -> list[str]:
    failures: list[str] = []
    for token in (
        'const archive = try support.makePackage(fixture, arch, "1", foundation.package, packages, .{});',
        'const archive = try support.makePackage(fixture, arch, "1", foundation.package, "deadline-startup/packages", .{});',
        'const archive = try support.makePackage(fixture, arch, "1", foundation.package, "deadline-persisted/packages", .{});',
        'try support.scripts(fixture, source, foundation.package, "1");',
        'try rootAbsent(fixture, root, "config-invoked");',
        'try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, guarded), typed_proof.document);',
        'var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);',
        'if (scripts == 0) return error.MissingCoreScriptOutcome;',
        'try debz.native_recovery.validateScriptOutcome(outcome.value);',
        'try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,',
        'try oracle.validateScriptTrace(fixture.allocator, trace, &invocations);',
        'if (!std.mem.eql(u8, before, try evidenceInventory(fixture, root, true)))',
    ):
        source = projected if "evidenceInventory" in token else core
        doubled = (
            'foundation.package, packages, .{});',
            'var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);',
            'try debz.native_recovery.validateScriptOutcome(outcome.value);',
            'try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,',
        )
        if source.count(token) < (2 if any(token.endswith(item) for item in doubled) else 1):
            failures.append(f"Zig recovery entry point: required executed shape check lost {token}")
    for token in (
        "try readOnlyProjection(fixture, runner, driver, arch);",
        "DEBZ_NATIVE_PROJECTION_FIXTURE=1",
        "native_transaction_result.test.projected root external fixture...OK",
        "apt_system_orchestrator.test.projected native dispatch external fixture...OK",
    ):
        if token not in projected:
            failures.append(f"projected recovery entry point: read-only child lost {token}")
    for command in recovery_zig_commands(("test-native-recovery-zig",)):
        if len(re.findall(r"(?m)^          " + re.escape(command) + r"$", ci)) != 1:
            failures.append("ci.yml: both sharded core recovery entry-point modes must execute exactly once")
    return failures


def native_consumer_receipt_wiring_failures(parity: str, evidence: str) -> list[str]:
    failures: list[str] = []
    for token in (
        'const retained = @import("native_recovery_parity_evidence.zig");',
        "try retained.verify(fixture, root, arch, digest, case.exit_status != 0);",
        "try support.absent(fixture, try relative(fixture, root, completion_path));",
        "return error.HeldConsumerMutatedRoot;",
        "try verifyFifoLock(fixture, signed.repository, lock.lock, version, fifos);",
        "try fifoReceipt(fixture, scenario.native_root, arch, lock_relative);",
        "try support.compare(fixture, scenario.reference_root, scenario.native_root, remove_compare, true);",
        "try fifoReceipt(fixture, scenario.native_root, arch, remove_relative);",
        'try scenario.phase(.{ .operation = "purge", .packages = &selected }, false);',
        "if (fifo_closures != oracle.parity_suites.len) return error.MissingSignedFifoClosure;",
    ):
        if token not in parity:
            failures.append(f"native_recovery_parity.zig: required per-case receipt check lost {token}")
    for token in (
        "try debz.native_provenance.verifyEvidence(allocator, root, proof);",
        "try manifestDocument(entry, intent.?.intent.digest_sha256);",
        "try manifestDocument(entry, progress.?.document.digest_sha256);",
        "try manifestDocument(entry, managed.?.document.digest_sha256);",
        "try manifestDocument(entry, triggers.?.document.digest_sha256);",
        "try manifestDocument(entry, script.digest_sha256);",
        "try equal(&proof.request_sha256, &caller.caller.request_sha256);",
        "try oracle.validateHelperInvocation(",
        "try scriptTrace(allocator, root, scripts.items);",
        "try finalDatabase(allocator, root, architecture, proof);",
        "const generation = try database.generation(allocator, snapshot);",
        "try equal(&std.fmt.bytesToHex(sink.hasher.finalResult(), .lower), &proof.final_state_sha256);",
    ):
        if token not in evidence:
            failures.append(f"native_recovery_parity_evidence.zig: required retained evidence check lost {token}")
    return failures


def native_repository_evidence_wiring_failures(source: str) -> list[str]:
    failures: list[str] = []
    for token in (
        "try terminalEvidence(fixture, root, relative, case, resuming, logical, retained_bytes, helper_before.?);",
        "try parity_evidence.verifyProjected(fixture, root, debz.live_root.logical_root_path, state.state.architecture,",
        "try managedFiles(fixture, root, state.state, manifest.manifest);",
        "completion.discharge.request_sha256, &expected_discharge",
        "try oracle.validateHelperInvocation(",
        "if (script_count != 2) return error.MissingRepositoryScripts;",
        "if (preserved.value.len != 8) return error.RepositoryHistoryEvidenceChanged;",
        "try unchangedBindings(fixture, root, state.state, abandoned.record, publisher.record);",
        "try unchangedEvidence(fixture, bytes);",
        "try checkpointAt(fixture, root, checkpoint);",
        "try checkHelper(fixture, root, original_helper orelse return error.MissingRepositoryHelper);",
        "lock.lock.packages.len != 1 or !lock.lock.packages[0].dpkg_selection_hold",
        "if (first.exit_status == .success) return error.RepositoryDispatchIgnoredInterruption;",
        "try scanQuerySecret(fixture.io, fixture.dir, path);",
        "const count = reader.interface.readSliceShort(buffer[overlap .. overlap + 64 * 1024]) catch return reader.err.?;",
        "if (std.mem.indexOf(u8, buffer[0 .. overlap + count], secret) != null)",
        "std.mem.copyForwards(u8, buffer[0..next_overlap], buffer[end - next_overlap .. end]);",
        "if (scanned != before.size or before.size != after.size or before.inode != after.inode)",
        'test "repository network evidence scans large files and split secrets"',
        "for ([_]usize{ 64 * 1024 - 7, 2 * 1024 * 1024 + 64 * 1024 - 7 }) |offset|",
        "try std.testing.expectError(error.NetworkFixtureLeakedCredential, assertNoQuerySecret(&fixture, root));",
    ):
        if token not in source:
            failures.append(f"native_recovery_repository.zig: required executed repository evidence lost {token}")
    deadline_case = source.partition("fn cliScenario(")[2].partition("\nfn cliCase(")[0]
    for token in (
        'else if (std.mem.eql(u8, case, "deadline")) "15000" else "60000"',
        '(std.mem.eql(u8, case, "deadline") and elapsed >= 20000)',
    ):
        if token not in deadline_case:
            failures.append(f"native_recovery_repository.zig: bounded blocked-postinst deadline lost {token}")
    diagnostic = source.partition("fn verifyCliScenario(")[2].partition("\nfn cliScenario(")[0]
    for token in (
        "if (first.diagnostic_count == 0 or first.diagnostics[0].id != .resource_limit_exceeded)",
        'std.debug.print("repository CLI {s}: exit={s}, diagnostic={s}; expected resource limit\\n", .{',
        "return error.InvalidRepositoryDeadlineDiagnostic;",
    ):
        if token not in diagnostic:
            failures.append(f"native_recovery_repository.zig: deadline refusal diagnostic lost {token}")
    if 'try std.testing.expectEqual(@as(u64, 20), try cliWatchdog(&.{ "--deadline-ms", "15000" }, 0, "deadline"));' not in source:
        failures.append("native_recovery_repository.zig: deadline watchdog regression lost")
    for token in (
        'const limit_seconds: i64 = if (std.mem.eql(u8, name, "repository-execution-success")) 240 else 120;',
        "const progress_ceiling_factor = 2;",
        "const ceiling_seconds = if (progress_watched) limit_seconds * progress_ceiling_factor else limit_seconds;",
        "if (stalled_ms == null and elapsed >= deadline_ms and deadline_ms < ceiling_seconds * 1000) {",
        "previous = snapshotProcessTree(fixture, name, log, pid, deadline_ms, elapsed, host_before, previous);",
        "const timed_out = stalled_ms != null or term == .exited and term.exited == 124 or wall_ms >= ceiling_seconds * 1000;",
        "reportRunner(init.io, allocator);",
        'test "repository watchdog bounds time between fixture passes by a fixed ceiling"',
        'test "repository watchdog samples a blocked child tree and host CPU"',
    ):
        if token not in source:
            failures.append(f"native_recovery_repository.zig: bounded progress watchdog or its diagnostics lost {token}")
    return failures


def native_workflow_acceptance_wiring_failures(
    build: str, family: str, projected: str,
) -> list[str]:
    failures: list[str] = []
    for token in (
        'recovery_family.addArtifactArg(recovery_family_executable);',
        'recovery_family.addArg("--self");',
        'recovery_family.addArtifactArg(native_lifecycle_tests);',
        'recovery_family.addArg("--cli");',
        'recovery_family.addArtifactArg(cli);',
    ):
        if token not in build:
            failures.append(f"build.zig: required signed workflow acceptance lost {token}")
    for token in (
        'if (std.mem.eql(u8, driver, "--inside-projected"))',
        "return projected.inside(init, allocator, root);",
        "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);",
        "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);",
        "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        'try verificationRefusals(fixture, driver, request, returned, original_summary, "executed");',
        "try verificationRefusals(fixture, driver, original, first_completion, summary, name);",
        'const no_result_path = try support.path(fixture.allocator, name, "verify-first-without-result");',
        'const equivalent_path = try support.path(fixture.allocator, name, "verify-create-as-customize");',
        'try assertFamilySummary(fixture, driver, original, first_completion, summary, try support.path(fixture.allocator, name, "verify-final"));',
        "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        'try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-after-refusals", true);',
        "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        'try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-recovered"), true);',
        "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);",
        'try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-unsettled-verified-again"));',
        "const root_before = try projected.rootInventory(fixture, request.root, true);",
        "const pending_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
        "const before_evidence = try projected.rootInventory(fixture, update.native_root, true);",
        '"executed/{s}-verify-without-result"',
        '"executed/{s}-verify-as-install"',
        "const failed_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
        ".force = invocation.force,",
        '"wrong-conffile"',
        '"{s}/replacement-{s}"',
        '"changed-request"',
        '"verify-damaged-{s}"',
        '"verify-unresolved-{s}"',
        '"verify-partial-acknowledgment"',
        '"acknowledge-damaged-receipt"',
        '"verify-public-owner-retained"',
        '"verify-terminal-foreign-attempt"',
        '"verify-public-pending"',
        '"verify-public-native-acknowledged"',
        '"verify-public-pending-failure"',
        '"verify-public-failed-acknowledgment"',
        '"verify-public-final-failure"',
        '"verify-success-as-failure"',
        '"verify-pending-as-released"',
        '"executed/workflow-owned-success/verify-finalized-as-released"',
        'try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, "executed/inspect-initial", "essential-core", true, false);',
        '"executed/inspect-while-root-lock-held"',
        '"executed/inspect-failed-same-root"',
        '"executed/missing-helper-inspection"',
        'const reference_failure = "executed/same-root-failure-reference";',
        "linux.flock(holder.handle, 2 | 4)",
        '"verify-before-execution"',
        '"verify-failed-result"',
        '"verify-relabeled-failure"',
        '"verify-failed-without-result"',
        '"ordinary-to-FAMILY same-root timeline: signed success, full verification refusals, failed install and clean recovery matched pinned dpkg',
        '"semantic request") == null',
        'try std.testing.expectEqual(@as(i64, 3), (try field(update_lock_document.value, "version")).integer);',
        "try std.testing.expectEqual(@as(usize, 24), parsed.value.object.count());",
        "try std.testing.expectEqual(@as(usize, 13), capability.value.object.count());",
        "try std.testing.expectEqual(@as(usize, 24), verified.report.value.object.count());",
        "try std.testing.expectEqual(@as(i64, 3), (try field(install_lock.value, \"version\")).integer);",
    ):
        if token not in family:
            failures.append(f"native_recovery_family.zig: required signed workflow acceptance lost {token}")
    for token in (
        'const source = try fixture.absolute("executed/workflow.sources");\n    const keyring = try fixture.absolute("executed/repository/fixture-keyring.gpg");\n    var phase_arena: std.heap.ArenaAllocator = .init(init.gpa);',
        "fixture.allocator = phase_arena.allocator();",
        "defer fixture.allocator = allocator;",
        'const lock = try persistent_allocator.dupe(u8, try fixture.absolute("executed/lock.json"));',
        "first_completion = try std.json.parseFromSlice(std.json.Value, persistent_allocator,",
        "    for ([_]bool{ true, false }) |selected| {\n        _ = phase_arena.reset(.free_all);",
    ):
        if token not in family:
            failures.append(f"native_recovery_family.zig: bounded signed workflow allocation lost {token}")
    for token in (
        "try refusals(&fixture, reference.architecture);",
        "try transport(&fixture, driver, reference.architecture);",
        "try planning(&fixture, driver);",
        "try activeInspection(&fixture, driver, reference.architecture);",
        "try archiveExecution(&fixture, allocator, &phase_arena, driver, helper orelse return error.MissingHelper, reference.executable, reference.architecture, python, source, keyring);",
        "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedAbandon(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);",
        "try missingHelper(&fixture, driver, reference.executable, reference.architecture);",
        "try failedTransaction(&fixture, driver, reference.executable, reference.architecture, false);",
    ):
        if token + "\n    _ = phase_arena.reset(.free_all);" not in family and token + "\n        _ = phase_arena.reset(.free_all);" not in family:
            failures.append(f"native_recovery_family.zig: scenario allocations retained after {token}")
    for token in (
        "    }\n    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);",
        "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);\n    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);",
    ):
        if token not in family:
            failures.append(f"native_recovery_family.zig: interrupted signed workflow allocations retained after {token}")
    if family.count("try referenceSingleFailure(fixture, reference, scenario.reference_root, arch, name)") != 2:
        failures.append("native_recovery_family.zig: both failed workflows require single-invocation pinned dpkg parity")
    if family.count('"verify-public-finalized"') != 2:
        failures.append("native_recovery_family.zig: pending recovery and terminal-owner finalization require public CLI proof")
    if family.count('try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/same-root-failure-comparison", true);') != 2:
        failures.append("native_recovery_family.zig: same-root failed customize must preserve pinned dpkg parity through recovery")
    for token in (
        'for ([_][]const u8{ "success", "recovered", "failed" }) |outcome|',
        '"/usr/bin/unshare", "--mount", "--pid", "--fork"',
        'if (linux.errno(linux.execve("/fixture/native-test", &argv, envp.ptr)) != .SUCCESS)',
        '.prepare_acknowledged_review = .{ .lock_sha256 = lock_digest, .generation = 6 },',
        '.prepare_cleared_review = .{ .lock_sha256 = lock_digest, .receipt_sha256 = receipt_digest, .generation = 8 },',
        "const evidence_before = if (step.verification) |check|",
        "const review_baseline = try evidenceInventory(fixture, scenario.native_root, false);",
        "return inventory(fixture, root, \".\", include_metadata);",
        "const damaged_state = try evidenceInventory(fixture, scenario.native_root, true);",
        "const orphan_state = try evidenceInventory(fixture, scenario.native_root, true);",
        "try std.testing.expectEqual(@as(i64, 2), (try field(owner_v2.value, \"version\")).integer);",
        'try support.absent(fixture, withheld_operation);',
    ):
        if token not in projected:
            failures.append(f"native_recovery_projected_workflows.zig: private projected workflow execution lost {token}")
    if projected.count('"/usr/bin/unshare", "--mount", "--pid", "--fork"') != 2:
        failures.append("native_recovery_projected_workflows.zig: read-only and signed workflow children both require private PID/mount projections")
    components = family.split("\nfn ownedComponents(", 1)[-1].split("\nfn ", 1)[0]
    for token in (
        "const retained_kinds = [_]provenance.EvidenceKind{ .authorization, .program, .execution_request, .intent, .progress, .managed_state, .trigger_events, .script_outcome };",
        "if (!observed_kinds.contains(kind) and (kind != .script_outcome or check.scripts))",
        '"retained-{s}-{d}"',
        '"EvidenceChanged"',
        "outcome_other_terminal,\n        outcome_recovery_required,",
        "final_database_generation,\n        final_state,",
        'if (check.outcome == .failed) "TransactionNotFailed" else "TransactionNotSuccessful"',
        'else => "EvidenceMismatch",',
        '.expected_error = "ReceiptMissing"',
        '.expected_error = "CompletionMissing"',
        '.expected_error = "OwnershipMismatch"',
        '"live-payload-bytes", selected, lock, check, "LivePayloadChanged"',
        '"live-payload-removed", selected, lock, check, "LivePayloadChanged"',
        '"administrator-conffile-edit", selected, lock, check',
        '"receipt-script_outcome-duplicated" else "receipt-script_outcome-omitted"',
    ):
        if token not in components:
            failures.append(f"native_recovery_family.zig: owned component tamper matrix lost {token}")
    for token in (
        '        .state = "released",\n        .outcome = .succeeded,\n        .scripts = false,',
        '        .state = "released",\n        .outcome = .succeeded,\n        .scripts = true,',
        '        .state = "pending",\n        .outcome = .failed,\n        .scripts = true,',
    ):
        if "    try ownedComponents(fixture, driver, &scenario, arch, name, selected, lock, .{\n        .owner_evidence = " not in family or token not in family:
            failures.append(f"native_recovery_family.zig: owned success and failed attempts require component tamper coverage lost {token}")
    if family.count("    try ownedComponents(fixture, driver, &scenario, arch, name, selected, lock, .{") != 3:
        failures.append("native_recovery_family.zig: owned success, scripted success and failed attempts all require the component tamper matrix")
    if "    try ownedScriptedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);" not in family:
        failures.append("native_recovery_family.zig: owned scripted success no longer runs")
    return failures


def native_provenance_binding_wiring_failures(
    build: str, e2e: str, binding: str, transaction: str, repository: str,
    recovery: str, unpack: str, production: str,
) -> list[str]:
    failures: list[str] = []
    if '            "native_provenance_binding.test.",\n        },\n    });\n    const run_sha512_e2e_tests = b.addRunArtifact(sha512_e2e_tests);' not in build:
        failures.append("build.zig: hermetic native provenance binding tests lost their sha512 e2e filter")
    if "    workload_native.dependOn(&run_sha512_e2e_tests.step);" not in build:
        failures.append("build.zig: hermetic native provenance binding tests lost required test wiring")
    if 'test {\n    _ = @import("native_provenance_binding_test.zig");\n}' not in e2e:
        failures.append("sha512_transaction_e2e_test.zig: hermetic native provenance binding tests are no longer imported")
    for token in (
        'test "native_provenance_binding.test.completed attempt binds every acceptance component" {',
        'test "native_provenance_binding.test.recovered attempt binds every acceptance component" {',
        'test "native_provenance_binding.test.recovery_required attempt keeps typed evidence without success-shaped settlement" {',
        "try testing.expect(settled.recovered_phase_count >= 1);",
        "for ([_]native_provenance.Outcome{ .succeeded, .failed }) |outcome| {",
        '"receipt.evidence_files[{s}] omitted"',
        '"retained {s} bytes"',
        '"completion.transaction_provenance=provenanceDigest"',
        '"live pending trigger claim"',
        '"deferred owner reinstated"',
        "try testing.expect(!std.mem.eql(u8, &receipt_digest, &provenance_digest));",
        '"live payload bytes", error.LivePayloadChanged',
        '"live payload removed", error.LivePayloadChanged',
        "for (std.enums.values(PayloadReplacement)) |replacement|",
        '"caller verify of live payload", error.LivePayloadChanged',
        "try expectCallerPayloadBound(env, attempt, receipt.digest_sha256);",
        "native_transaction_result.verifyCallerSuccessReporting(allocator, attempt, receipt_digest, &change),",
        'try testing.expectEqualStrings("demo", owner.package);',
        'try testing.expectEqualStrings("1.0", owner.version);',
    ):
        if token not in binding:
            failures.append(f"native_provenance_binding_test.zig: component tamper coverage lost {token}")
    for token in ("try tamperSettled(&env, &settled);", "try env.expectSecondOperationRefused();"):
        if binding.count(token) != 2:
            failures.append(f"native_provenance_binding_test.zig: completed/recovered and recovery_required coverage requires two {token}")
    state = transaction.split("\nfn verifyStateEvidence(", 1)[-1].split("\nfn ", 1)[0]
    for token in (
        "        &route_conffiles,\n    );",
        "    _ = try native_runtime.verifySettledPayload(\n        allocator,\n        root,\n        program.program,\n        managed.document,\n        route_conffiles.items,\n        payload_change,\n    );\n}",
    ):
        if token not in state:
            failures.append(f"native_transaction_result.zig: settled verification must bind the live managed payload lost {token}")
    caller = transaction.split("\nfn verifyCaller(", 1)[-1].split("\nfn ", 1)[0]
    if "        null,\n        payload_change,\n    );\n    try verifyPendingEvidence(allocator, root, proof);" not in caller:
        failures.append("native_transaction_result.zig: held caller verification must describe a changed live payload")
    for start, end, tokens, message in (
        ("\npub fn verifySettledManagedStateReporting(", "\n}\n", (
            "            if (change) |out| out.* = SettledPayloadChange.init(allocator, expected, reason) catch null;",
        ), "native_recovery.zig: a changed live payload must be described"),
        ('\ntest "native_recovery.test.settled managed state binds live payload kind, mode and bytes" {', "\n}\n", (
            "try testing.expectEqual(expected.reason, found.reason);",
            "try testing.expectEqualSlices(u8, &hexDigest(bytes_digest), &found.expected_sha256.?);",
            "try testing.expectEqual(found.reason, parsed.value.reason);",
        ), "native_recovery.zig: live payload change description coverage lost"),
    ):
        body = recovery.split(start, 1)[-1].split(end, 1)[0]
        for token in tokens:
            if token not in body:
                failures.append(f"{message} {token}")
    for start, tokens in (
        ("\n    pub fn verifySettledPayload(", (
            "                describeSettledPayloadOwner(allocator, root, program.target_architecture, found) catch {};",
        )),
        ("\n    fn describeSettledPayloadOwner(", (
            "        const owners = ownership.ownersOf(change.path);",
            "        if (owners.len != 1) return;",
        )),
    ):
        body = unpack.split(start, 1)[-1].split("\n    }\n", 1)[0]
        for token in tokens:
            if token not in body:
                failures.append(f"native_unpack.zig: a changed live payload must name its installed owner lost {token}")
    for start, end, tokens in (
        ("\n    fn recoverNative(", "\n    fn ", (
            "                .add => return repositoryOwnedRecovery(.recover, attempt.record(), repository_recovery_resume),",
        )),
        ("\nfn repositoryOwnedRecovery(", "\n}\n", (
            "        .surface = .repository_bootstrap,",
            "        .resume_path = .rerun_same_repository_add,",
        )),
        ('\ntest "production native recovery names the repository bootstrap that owns a held attempt" {', "\n}\n", (
            "try std.testing.expectEqual(api.RecoveryOwner.Surface.repository_bootstrap, owner.surface);",
            "try std.testing.expectEqual(api.RecoveryOwner.ResumePath.rerun_same_repository_add, owner.resume_path);",
            "try std.testing.expectEqualStrings(before, after);",
        )),
    ):
        body = production.split(start, 1)[-1].split(end, 1)[0]
        for token in tokens:
            if token not in body:
                failures.append(f"production_backend.zig: recovery of a repository-owned attempt must name its surface and resume path lost {token}")
    for start, tokens in (
        ("\nfn nativeRepositoryCheckpointLoaded(", (
            "    var package_state = verifyNativePackageStateReporting(allocator, input, &payload_change) catch |err| {",
            "        if (err == error.LivePayloadChanged)\n            return refuseNativeLivePayload(allocator, input, observer, stage, original, err, if (payload_change) |*change| change else null);",
        )),
        ("\nfn refuseNativeLivePayload(", (
            "    if (retained.receipt.document.outcome != .succeeded or !nativeStageImports(stage, prior.phase)) return cause;",
            "    publication.persist(allocator, current.state, original.paths) catch |err| return err;",
            "    const detail: ?[]u8 = if (payload_change) |change| (change.diagnostic(allocator) catch null) else null;",
            "    return publication.failMessage(allocator, &current, original.paths, .installed_verification_failed, cause, detail orelse @errorName(cause));",
        )),
        ("\nfn testProjectedNativeImport(", (
            "try std.testing.expectError(error.LivePayloadChanged, importAndRefreshNative(allocator, input, reporting));",
            "try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, reported.diagnostics[0].id);",
            "try expectLivePayloadDiagnostic(allocator, reported.diagnostics[0].message, state.state.managed_files[0], state.state.descriptor.?);",
            "try std.testing.expectError(error.LivePayloadChanged, completeNative(allocator, input));",
            "try std.testing.expectEqual(root_operation.ProvenanceState.pending, attempt.record().provenance);",
            "try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, failed.state.diagnostic_id.?);",
            "try expectLivePayloadDiagnostic(allocator, failed.state.diagnostic, state.state.managed_files[0], state.state.descriptor.?);",
        )),
        ("\nfn expectLivePayloadDiagnostic(", (
            "    var parsed = try native_recovery.parseSettledPayloadDiagnostic(allocator, message);",
            "    try std.testing.expectEqualStrings(removed.logical_path[1..], fields.path);",
            "    try std.testing.expectEqualStrings(&expected_sha256, fields.expected_sha256.?);",
            "    try std.testing.expectEqualStrings(descriptor.package, fields.package.?);",
            "    try std.testing.expectEqualStrings(descriptor.version, fields.version.?);",
        )),
    ):
        body = repository.split(start, 1)[-1].split("\nfn ", 1)[0]
        for token in tokens:
            if token not in body:
                failures.append(f"repository_backend.zig: repository add must record a changed live payload as installed_verification_failed lost {token}")
    return failures


GHR_ZIG_INSTALL = """\
      - name: Install Zig via ghr
        uses: cataggar/ghr/actions/install@c4be68b52d67d7acd2a7fe6c1e5f126e1754176e # v0.8.1
        env:
          GH_TOKEN: ${{ github.token }}
        with:
          ghr-version: v0.8.1
          tools: >-
            cataggar/zig@v0.16.0
            RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
      - name: Validate Zig version
        run: test "$(zig version)" = 0.16.0
"""

CI_CONCURRENCY = """\
concurrency:
  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}
  cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}
"""


def ci_concurrency_failures(text: str, label: str) -> list[str]:
    failures: list[str] = []
    if text.count(CI_CONCURRENCY) != 1:
        failures.append(
            f"{label}: CI concurrency must exactly isolate push, pull_request, schedule, and workflow_dispatch runs"
        )
    if not re.search(
        r"(?ms)^on:\n.*?\n\n"
        + re.escape(CI_CONCURRENCY)
        + r"\npermissions:\n",
        text,
    ):
        failures.append(f"{label}: CI concurrency must be a top-level workflow policy before permissions")
    return failures


def ghr_zig_workflow_failures(
    text: str, label: str, expected_count: int
) -> list[str]:
    failures: list[str] = []
    if "mlugg/setup-zig" in text or "use-cache:" in text:
        failures.append(f"{label}: obsolete setup-zig installation or cache input remains")
    count = text.count(GHR_ZIG_INSTALL)
    if count != expected_count:
        failures.append(
            f"{label}: expected {expected_count} exact verified ghr Zig install blocks, found {count}"
        )
    return failures


def native_lifecycle_migration_failures(build: str, trigger: str) -> list[str]:
    failures: list[str] = []
    for entrypoint in (
        "tools/test-native-lifecycle.py",
        "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",
        "tools/test_native_triggers.py",
    ):
        if f'"{entrypoint}"' in build:
            failures.append(f"build.zig: retired Python acceptance gate was restored: {entrypoint}")
    for binding in (
        'const native_lifecycle_step = b.step("test-native-lifecycle",',
        'const native_triggers_step = b.step("test-native-triggers",',
        "native_lifecycle_step.dependOn(&lifecycle_zig.step);",
        "native_triggers_step.dependOn(&trigger_zig.step);",
        "native_triggers_step.dependOn(&run_native_trigger_queue_tests.step);",
        "lifecycle_zig.addArtifactArg(native_lifecycle_tests);",
        "trigger_zig.addArtifactArg(native_lifecycle_tests);",
        'trigger_zig.addArg("--native-helper");',
        "trigger_zig.addArtifactArg(native_trigger_helper);",
        "workload_native.dependOn(&run_lifecycle_zig_tests.step);",
        "workload_native.dependOn(&run_trigger_zig_tests.step);",
        "workload_native.dependOn(&run_settlement_tests.step);",
        'b.step("test-native-lifecycle-zig-oracle",',
        'b.step("test-native-triggers-zig-oracle",',
        'b.step("test-native-triggers-zig-settlement-reference",',
        'settlement_oracle_zig.addArgs(&.{ "--oracle-only", "--diversion-settlement-reference-only" });',
        "settlement_unit_step.dependOn(&run_settlement_lowering_tests.step);",
    ):
        if binding not in build:
            failures.append(f"build.zig: missing required lifecycle/trigger gate binding: {binding}")
    marker = "fn failedPostinstUnconfiguredListener("
    body = trigger.partition(marker)[2].partition("\nfn refuseMalformedQueue(")[0]
    required = (
        "for ([_]bool{ false, true }) |awaiting|",
        ".no_scripts = true",
        "Status: install ok unpacked",
        "Status: install ok half-configured",
        "Triggers-Pending:",
        "Triggers-Awaited:",
        "queue.len != 0",
        "exit 1",
    )
    if (not body or any(value not in body for value in required)
        or body.count("support.reference(fixture, dpkg, root") != 2
        or body.count("activation-returned") != 2
        or "support.native(" in body):
        failures.append(
            "native_trigger_acceptance.zig: keep both failed-postinst "
            "unconfigured-listener cases as reference-only observations"
        )
    if "failedPostinstUnconfiguredListener(&fixture, reference.executable, reference.architecture)" not in trigger:
        failures.append(
            "native_trigger_acceptance.zig: invoke both unconfigured-listener "
            "references in the required trigger suite"
        )
    refusal = trigger.partition("fn refuseUnconfiguredListenerProgram(")[2].partition("\nfn interruptedTriggerHandler(")[0]
    if not refusal or any(value not in refusal for value in (
        "for ([_]bool{ false, true }) |awaiting|",
        "case.seedWith(handler, false)",
        'report.value.detail, "program_compile_rejected"',
        "support.assertNoActiveEvidence(",
    )) or refusal.count("foundation.captureRealRoot(") != 2 or (
        "refuseUnconfiguredListenerProgram(&fixture, native_driver, selected, reference.executable, reference.architecture)"
        not in trigger
    ):
        failures.append(
            "native_trigger_acceptance.zig: both unsupported listener programs "
            "must refuse before mutation and leave no active authority"
        )
    if any(token not in trigger for token in (
        "if (oracle_only == (driver != null) or (helper != null) != (driver != null))",
        "if (settlement_reference_only and (!oracle_only or diversions_only))",
        "if (fixture.oracle_only) return;",
        "settlement.run(&fixture, native_driver, reference.executable, selected, reference.architecture)",
    )):
        failures.append("native_trigger_acceptance.zig: selector or helper reference isolation removed")
    return failures


def native_lifecycle_fixture_failures(texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    retired = (
        "tools/test-native-lifecycle.py",
        "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",
        "tools/test_native_triggers.py",
        "tools/test-native-recovery.py",
        "tools/test_native_recovery.py",
    )
    for relative in retired:
        if relative in texts:
            failures.append(f"{relative}: retired Python test entry point still exists")
    for relative in (
        "tools/native-lifecycle-fixtures.py",
        "tools/native-trigger-fixtures.py",
    ):
        source = texts.get(relative)
        if source is None:
            failures.append(f"{relative}: required import-only fixture module is missing")
        elif (
            source.startswith("#!")
            or re.search(r"(?m)^import argparse\b|^from argparse\b|^def main\(|^if __name__\s*==", source)
        ):
            failures.append(f"{relative}: fixture module restored a Python CLI entry point")
    for consumer, fixture in (
        ("tools/native-trigger-fixtures.py", "native-lifecycle-fixtures.py"),
        ("tools/dpkg-config-reference.py", "native-lifecycle-fixtures.py"),
        ("actions/install/__tests__/integration.test.ts", "native-lifecycle-fixtures.py"),
    ):
        if fixture not in texts.get(consumer, ""):
            failures.append(f"{consumer}: required fixture import is missing: {fixture}")
    return failures


def audit_ci_pins() -> None:
    for failure in native_exercise_final_wiring_failures(
        (ROOT / "test/native_recovery_helper.zig").read_text(),
        (ROOT / "test/native_lifecycle_support.zig").read_text(),
        (ROOT / "src/native_unpack.zig").read_text(),
    ):
        fail(failure)
    for failure in native_core_completion_wiring_failures(
        (ROOT / "build.zig").read_text(),
        (ROOT / "test/native_recovery_helper.zig").read_text(),
        (ROOT / "test/native_lifecycle_support.zig").read_text(),
    ):
        fail(failure)
    for failure in native_entry_point_shape_failures(
        (ROOT / "test/native_recovery_acceptance.zig").read_text(),
        (ROOT / "test/native_recovery_projected_workflows.zig").read_text(),
        (ROOT / ".github/workflows/ci.yml").read_text(),
    ):
        fail(failure)
    for failure in native_consumer_receipt_wiring_failures(
        (ROOT / "test/native_recovery_parity.zig").read_text(),
        (ROOT / "test/native_recovery_parity_evidence.zig").read_text(),
    ):
        fail(failure)
    for failure in native_repository_evidence_wiring_failures(
        (ROOT / "test/native_recovery_repository.zig").read_text(),
    ):
        fail(failure)
    for failure in native_workflow_acceptance_wiring_failures(
        (ROOT / "build.zig").read_text(),
        (ROOT / "test/native_recovery_family.zig").read_text(),
        (ROOT / "test/native_recovery_projected_workflows.zig").read_text(),
    ):
        fail(failure)
    for failure in native_provenance_binding_wiring_failures(
        (ROOT / "build.zig").read_text(),
        (ROOT / "src/sha512_transaction_e2e_test.zig").read_text(),
        (ROOT / "src/native_provenance_binding_test.zig").read_text(),
        (ROOT / "src/native_transaction_result.zig").read_text(),
        (ROOT / "src/repository_backend.zig").read_text(),
        (ROOT / "src/native_recovery.zig").read_text(),
        (ROOT / "src/native_unpack.zig").read_text(),
        (ROOT / "src/production_backend.zig").read_text(),
    ):
        fail(failure)
    for failure in native_report_path_wiring_failures({
        path: (ROOT / path).read_text() for path in REPORT_PATH_ORACLE_FILES
    }):
        fail(failure)
    for failure in native_recovery_gate_wiring_failures(
        (ROOT / "build.zig").read_text(),
        (ROOT / "test/native_recovery_helper.zig").read_text(),
        (ROOT / "test/native_recovery_family.zig").read_text(),
        (ROOT / "test/native_recovery_projected_workflows.zig").read_text(),
        (ROOT / "test/native_recovery_repository.zig").read_text(),
        (ROOT / "test/native_recovery_diversions.zig").read_text(),
    ):
        fail(failure)
    for failure in native_lifecycle_migration_failures(
        (ROOT / "build.zig").read_text(),
        (ROOT / "test/native_trigger_acceptance.zig").read_text(),
    ):
        fail(failure)
    for failure in workload_partition_failures((ROOT / "build.zig").read_text()):
        fail(failure)
    fixture_paths = (
        "tools/test-native-lifecycle.py",
        "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",
        "tools/test_native_triggers.py",
        "tools/test-native-recovery.py",
        "tools/test_native_recovery.py",
        "tools/native-lifecycle-fixtures.py",
        "tools/native-trigger-fixtures.py",
        "tools/dpkg-config-reference.py",
        "actions/install/__tests__/integration.test.ts",
    )
    fixture_texts = {
        relative: path.read_text()
        for relative in fixture_paths
        if (path := ROOT / relative).exists() and path.is_file() and not path.is_symlink()
    }
    for relative in fixture_paths[:6]:
        if (ROOT / relative).is_symlink() or (ROOT / relative).is_dir():
            fixture_texts[relative] = ""
    for failure in native_lifecycle_fixture_failures(fixture_texts):
        fail(failure)
    for relative in fixture_paths[6:8]:
        path = ROOT / relative
        if path.is_symlink() or (path.is_file() and path.stat().st_mode & 0o111):
            fail(f"{relative}: import-only fixture must not be executable or a symlink")
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    for workflow in workflows:
        text = workflow.read_text()
        relative = workflow.relative_to(ROOT)
        if re.search(r"(?m)^\s*pull_request_target\s*:", text):
            fail(f"{relative}: pull_request_target executes untrusted changes with base privileges")
        if re.search(r"\$\{\{\s*secrets\.", text):
            fail(f"{relative}: workflow exposes repository secrets")
        for failure in workflow_failure_handling_failures(text, str(relative)):
            fail(failure)
        if workflow.name == "ci.yml":
            for failure in ci_concurrency_failures(text, str(relative)):
                fail(failure)
            for failure in native_recovery_ci_failures(text):
                fail(failure)
            for failure in reference_launcher_root_wiring_failures(*(
                (ROOT / path).read_text() if (ROOT / path).is_file() else ""
                for path in REFERENCE_ROOT_PATHS
            )):
                fail(failure)
            for failure in protected_reference_ci_failures({
                path: (ROOT / path).read_text()
                for path in PROTECTED_REFERENCE_PATHS if (ROOT / path).is_file()
            }):
                fail(failure)
            for failure in signed_proc_ci_failures(text):
                fail(failure)
        expected_ghr_installs = {"ci.yml": 21, "release.yml": 1}.get(workflow.name)
        if expected_ghr_installs is not None:
            for failure in ghr_zig_workflow_failures(
                text, str(relative), expected_ghr_installs
            ):
                fail(failure)
        if not re.search(
            r"(?m)^permissions:\s*\n"
            r"\s{2}contents:\s*read\s*\n"
            r"\s{2}attestations:\s*read\s*$",
            text,
        ):
            fail(
                f"{relative}: top-level permissions must be contents and attestations read"
            )
        checkout_blocks = re.findall(
            r"(?ms)^\s*-\s+uses:\s*actions/checkout@[^\n]+\n(?P<body>(?:\s{8,}[^\n]*\n)*)",
            text,
        )
        if not checkout_blocks or any(
            not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", block)
            for block in checkout_blocks
        ):
            fail(f"{relative}: every checkout must disable persisted credentials")
        for line_number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if " | " in stripped and not stripped.startswith("#"):
                fail(f"{relative}:{line_number}: shell pipeline requires an explicit pipefail wrapper")
        for action in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", text):
            name, revision = action
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                fail(f"{relative}: {name} is not commit-pinned")


def action_pin_failures(text: str, label: str) -> list[str]:
    return [
        f"{label}: {name} is not commit-pinned"
        for name, revision in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", text)
        if not re.fullmatch(r"[0-9a-f]{40}", revision)
    ]


def audit_composite_action_pins() -> None:
    for manifest in sorted((ROOT / "actions").glob("*/action.y*ml")):
        text = manifest.read_text()
        if not re.search(r"(?m)^\s*using:\s*composite\s*$", text):
            continue
        relative = manifest.relative_to(ROOT)
        for failure in action_pin_failures(text, str(relative)):
            fail(failure)


def audit_setup_action_dependencies() -> None:
    setup = ROOT / "actions/setup"
    package_path = setup / "package.json"
    lock_path = setup / "package-lock.json"
    notices_path = setup / "THIRD_PARTY_NOTICES.md"
    if not package_path.is_file() or not lock_path.is_file() or not notices_path.is_file():
        fail("setup action dependency manifests or notices are missing")
        return

    package = json.loads(package_path.read_text())
    lock = json.loads(lock_path.read_text())
    expected_runtime = {
        "@actions/core",
        "@sigstore/bundle",
        "@sigstore/protobuf-specs",
        "@sigstore/tuf",
        "@sigstore/verify",
        "semver",
        "undici",
    }
    dependencies = package.get("dependencies")
    if not isinstance(dependencies, dict) or set(dependencies) != expected_runtime:
        fail("setup action runtime dependencies differ from the reviewed allowlist")
    allowed_licenses = {
        "0BSD",
        "Apache-2.0",
        "(Apache-2.0 AND BSD-3-Clause)",
        "BlueOak-1.0.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MIT",
    }
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        fail("setup action lockfile packages table is missing")
        return
    for name, metadata in packages.items():
        if not name:
            continue
        if not isinstance(metadata, dict):
            fail(f"setup action lock entry is malformed: {name}")
            continue
        if metadata.get("license") not in allowed_licenses:
            fail(f"setup action dependency has an unreviewed license: {name}")
        if metadata.get("hasInstallScript"):
            fail(f"setup action dependency has an install script: {name}")
        if not str(metadata.get("resolved", "")).startswith("https://registry.npmjs.org/"):
            fail(f"setup action dependency is not resolved from the npm registry: {name}")
        if not str(metadata.get("integrity", "")).startswith("sha512-"):
            fail(f"setup action dependency lacks SHA-512 lock integrity: {name}")

    notices = notices_path.read_text()
    for name in sorted(expected_runtime):
        if name not in notices:
            fail(f"setup action notices omit direct dependency {name}")
    for relative in ("dist/main/licenses.txt", "dist/post/licenses.txt"):
        license_path = setup / relative
        if not license_path.is_file() or license_path.stat().st_size == 0:
            fail(f"setup action bundled licenses are missing: actions/setup/{relative}")


def audit_download_action() -> None:
    action = ROOT / "actions/download"
    required = (
        action / "action.yml",
        action / "package.json",
        action / "package-lock.json",
        action / "THIRD_PARTY_NOTICES.md",
        action / "dist/index.js",
        action / "dist/package.json",
        action / "dist/licenses.txt",
    )
    for path in required:
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"download action file is missing or empty: {path.relative_to(ROOT)}")
    if any(not path.is_file() for path in required):
        return

    manifest = (action / "action.yml").read_text()
    for token in (
        "using: node24",
        "main: dist/index.js",
        "lock-input:",
        "architecture:",
        "keyring:",
        "cache-hit:",
        "cache-matched-key:",
        "downloaded-count:",
        "reused-count:",
        "backend-capability:",
        "maximum-repository-records:",
    ):
        if token not in manifest:
            fail(f"download action metadata is missing policy token: {token}")
    for forbidden in ("install-root:", "state-path:", "\n  args:"):
        if forbidden in manifest:
            fail(f"download action exposes forbidden transaction input: {forbidden.strip()}")

    source_requirements = {
        "src/inputs.ts": (
            "cache-root must be an absolute child of RUNNER_TEMP",
            "must not traverse a symbolic link",
            "must be outside cache-root",
        ),
        "src/runner.ts": (
            "execFile(",
            "LANG: 'C'",
            "LC_ALL: 'C'",
            "package-cache",
            "fingerprint",
            "prepare",
            "--restored-cache",
            "--archive-input",
            "--archive-output",
            "outside the CLI-provided restore prefix",
        ),
        "src/cache.ts": (
            "debz-package-cache-opaque-archive-v1",
            "GetCacheEntryDownloadURL",
            "BlockBlobClient",
            "downloadToFile(",
            "uploadFile(",
            "createTransferArea(",
            "matched cache blob could not be safely staged",
        ),
        "src/action.ts": (
            "fingerprintCache(",
            "requires the maintained Node 24 runtime",
            "delete process.env.DEBZ_DOWNLOAD_CREDENTIAL_REFERENCE",
            "delete process.env['INPUT_CREDENTIAL-REFERENCE']",
            "delete process.env.DEBZ_DOWNLOAD_EXECUTABLE",
            "verifyExecutableIdentity(executableIdentity)",
            "cache.save(exportArchive, fingerprint.primary_key, archiveLimit)",
            "core.setOutput('cache-hit'",
            "core.setOutput('downloaded-count'",
            "core.setOutput(\n    'backend-capability'",
            "legacy-dpkg-execution-deprecated-v1",
        ),
    }
    for relative, tokens in source_requirements.items():
        path = action / relative
        if not path.is_file():
            fail(f"download action source is missing: actions/download/{relative}")
            continue
        text = path.read_text()
        for token in tokens:
            if token not in text:
                fail(f"download action {relative} is missing policy token: {token}")
    source_text = "\n".join(
        path.read_text() for path in sorted((action / "src").glob("*.ts"))
    )
    for forbidden in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        ".npmrc",
        "@actions/cache",
        "extractTar(",
        "createTar(",
        "process.chdir(",
    ):
        if forbidden in source_text:
            fail(f"download action source reads forbidden ambient input: {forbidden}")
    action_source = (action / "src/action.ts").read_text()
    prepare_index = action_source.find("const prepared = await prepareCache(")
    save_index = action_source.find("await cache.save(")
    cleanup_index = action_source.find("await transfer?.cleanup()")
    output_index = action_source.find("core.setOutput('cache-hit'")
    if min(prepare_index, save_index, cleanup_index, output_index) < 0 or not (
        prepare_index < save_index < cleanup_index < output_index
    ):
        fail("download action must prepare, save, clean staging, and only then publish outputs")

    package = json.loads((action / "package.json").read_text())
    lock = json.loads((action / "package-lock.json").read_text())
    dependencies = package.get("dependencies")
    if dependencies != {
        "@actions/core": "3.0.1",
        "@azure/storage-blob": "12.31.0",
    }:
        fail("download action runtime dependencies differ from the reviewed allowlist")
    for group in ("dependencies", "devDependencies"):
        values = package.get(group)
        if not isinstance(values, dict) or not values:
            fail(f"download action {group} are missing")
            continue
        for name, version in values.items():
            if not isinstance(version, str) or not re.fullmatch(
                r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version
            ):
                fail(f"download action dependency {name} is not exactly pinned: {version!r}")
    if lock.get("lockfileVersion") != 3:
        fail("download action package-lock.json must use lockfileVersion 3")
    root_package = lock.get("packages", {}).get("")
    if not isinstance(root_package, dict):
        fail("download action lockfile has no root package")
    else:
        for group in ("dependencies", "devDependencies"):
            if root_package.get(group) != package.get(group):
                fail(f"download action lockfile {group} differ from package.json")

    allowed_licenses = {
        "0BSD",
        "Apache-2.0",
        "(Apache-2.0 AND BSD-3-Clause)",
        "ISC",
        "MIT",
    }
    for name, metadata in lock.get("packages", {}).items():
        if not name:
            continue
        if not isinstance(metadata, dict):
            fail(f"download action lock entry is malformed: {name}")
            continue
        if metadata.get("license") not in allowed_licenses:
            fail(f"download action dependency has an unreviewed license: {name}")
        if metadata.get("hasInstallScript"):
            fail(f"download action dependency has an install script: {name}")
        if not str(metadata.get("resolved", "")).startswith("https://registry.npmjs.org/"):
            fail(f"download action dependency is not resolved from the npm registry: {name}")
        if not str(metadata.get("integrity", "")).startswith("sha512-"):
            fail(f"download action dependency lacks SHA-512 lock integrity: {name}")

    notices = (action / "THIRD_PARTY_NOTICES.md").read_text()
    for name in ("@actions/core", "@azure/storage-blob"):
        if name not in notices:
            fail(f"download action notices omit direct dependency {name}")
    tracked = subprocess.run(
        ["git", "ls-files", "actions/download/node_modules"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if tracked.strip():
        fail("download action node_modules must not be tracked")

    archive_path = ROOT / "src/package_cache_archive.zig"
    if not archive_path.is_file():
        fail("CLI-owned package cache archive implementation is missing")
    else:
        archive = archive_path.read_text()
        for token in (
            'pub const format_id = "debz-package-cache-archive-v1"',
            "error.NonCanonicalOrder",
            "error.DuplicateObject",
            "error.ArchiveDigestMismatch",
            "maximum_total_object_bytes",
            "cache.publish(",
        ):
            if token not in archive:
                fail(f"package cache archive is missing policy token: {token}")


def audit_install_action() -> None:
    action = ROOT / "actions/install"
    required = (
        action / "action.yml",
        action / "package.json",
        action / "package-lock.json",
        action / "THIRD_PARTY_NOTICES.md",
        action / "dist/index.js",
        action / "dist/package.json",
        action / "dist/licenses.txt",
    )
    for path in required:
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"install action file is missing or empty: {path.relative_to(ROOT)}")
    if any(not path.is_file() for path in required):
        return

    manifest = (action / "action.yml").read_text()
    for token in (
        "using: node24",
        "main: dist/index.js",
        "package:",
        "lock-input:",
        "install-root:",
        "assume-yes:",
        "noninteractive:",
        "conffile:",
        "use-sudo:",
        "package-cache-hit:",
        "transaction-result:",
        "installed-count:",
        "backend-capability:",
    ):
        if token not in manifest:
            fail(f"install action metadata is missing policy token: {token}")
    for forbidden in ("\n  args:", "status-path:", "allow-host-root:"):
        if forbidden in manifest:
            fail(f"install action exposes forbidden input: {forbidden.strip()}")

    source_requirements = {
        "src/inputs.ts": (
            "assume-yes must be exactly 'true'",
            "install-root must not be the host root",
            "must not overlap",
            "must not traverse a symbolic link",
            "architecture must match the native",
        ),
        "src/subprocess.ts": (
            "setup', 'dist', 'main', 'index.js",
            "download', 'dist', 'index.js",
            "DEBZ_DOWNLOAD_EXECUTABLE",
            "['-n', '--', executable",
            "spawn(",
        ),
        "src/runner.ts": (
            "'--cache-only'",
            "'transaction-result'",
            "'verify'",
            "lock_evidence",
        ),
        "src/action.ts": (
            "const download = await composition.download",
            "buildInstallArguments(inputs)",
            "requireFreshResult",
            "validateTransactionSummary",
            "await composition.saveSetupCache()",
            "io.setOutput('transaction-result'",
            "io.setOutput(\n    'backend-capability'",
            "legacy-dpkg-execution-deprecated-v1",
        ),
    }
    for relative, tokens in source_requirements.items():
        path = action / relative
        if not path.is_file():
            fail(f"install action source is missing: actions/install/{relative}")
            continue
        text = path.read_text()
        for token in tokens:
            if token not in text:
                fail(f"install action {relative} is missing policy token: {token}")
    source_text = "\n".join(
        path.read_text() for path in sorted((action / "src").glob("*.ts"))
    )
    for forbidden in (
        "shell: true",
        "execFile(",
        "eval(",
        "status-path",
        "allow-host-root",
        "HTTP_PROXY",
        "HTTPS_PROXY",
    ):
        if forbidden in source_text:
            fail(f"install action source contains forbidden mechanism: {forbidden}")
    action_source = (action / "src/action.ts").read_text()
    download_index = action_source.find("const download = await composition.download")
    install_index = action_source.find("buildInstallArguments(inputs)")
    summary_index = action_source.find("validateTransactionSummary(")
    output_index = action_source.find("io.setOutput('transaction-result'")
    if min(download_index, install_index, summary_index, output_index) < 0 or not (
        download_index < install_index < summary_index < output_index
    ):
        fail(
            "install action must download, always install, verify the result, and only then publish outputs"
        )

    package = json.loads((action / "package.json").read_text())
    lock = json.loads((action / "package-lock.json").read_text())
    if package.get("dependencies") != {"@actions/core": "3.0.1"}:
        fail("install action runtime dependencies differ from the reviewed allowlist")
    for group in ("dependencies", "devDependencies"):
        values = package.get(group)
        if not isinstance(values, dict) or not values:
            fail(f"install action {group} are missing")
            continue
        for name, version in values.items():
            if not isinstance(version, str) or not re.fullmatch(
                r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version
            ):
                fail(f"install action dependency {name} is not exactly pinned: {version!r}")
    if lock.get("lockfileVersion") != 3:
        fail("install action package-lock.json must use lockfileVersion 3")
    root_package = lock.get("packages", {}).get("")
    if not isinstance(root_package, dict):
        fail("install action lockfile has no root package")
    else:
        for group in ("dependencies", "devDependencies"):
            if root_package.get(group) != package.get(group):
                fail(f"install action lockfile {group} differ from package.json")
    allowed_licenses = {"0BSD", "Apache-2.0", "ISC", "MIT"}
    for name, metadata in lock.get("packages", {}).items():
        if not name:
            continue
        if not isinstance(metadata, dict):
            fail(f"install action lock entry is malformed: {name}")
            continue
        if metadata.get("license") not in allowed_licenses:
            fail(f"install action dependency has an unreviewed license: {name}")
        if metadata.get("hasInstallScript"):
            fail(f"install action dependency has an install script: {name}")
        if not str(metadata.get("resolved", "")).startswith("https://registry.npmjs.org/"):
            fail(f"install action dependency is not resolved from the npm registry: {name}")
        if not str(metadata.get("integrity", "")).startswith("sha512-"):
            fail(f"install action dependency lacks SHA-512 lock integrity: {name}")
    notices = (action / "THIRD_PARTY_NOTICES.md").read_text()
    if "@actions/core" not in notices:
        fail("install action notices omit direct dependency @actions/core")
    tracked = subprocess.run(
        ["git", "ls-files", "actions/install/node_modules"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if tracked.strip():
        fail("install action node_modules must not be tracked")
    summary_schema = ROOT / "schema/transaction-result-summary-v1.json"
    if not summary_schema.is_file():
        fail("transaction-result summary schema is missing")


def actions_native_only_candidate_failures(action: str, texts: dict[str, str]) -> list[str]:
    """Opt-in pre-cutover contract; never used by the shipped legacy-capable audit."""
    base = f"actions/{action}/"
    manifest = texts[base + "action.yml"]
    inputs = texts[base + "src/inputs.ts"]
    runtime = texts[base + "src/action.ts"]
    bundle = texts[base + "dist/index.js"]
    runner = texts[base + "src/runner.ts"]
    failures: list[str] = []
    section = re.search(r"(?m)^  transaction-backend:\n((?:    [^\n]*\n)+)", manifest)
    if section is None or not re.search(r"(?m)^    default: native$", section.group(1)):
        failures.append(f"{action} action.yml: candidate transaction-backend default must be native")
    if "backend-capability:" not in manifest:
        failures.append(f"{action} action.yml: candidate must publish backend-capability")
    if not re.search(
        r"(?:optionalScalar|exactScalar)\(\s*environment,\s*'TRANSACTION_BACKEND'\s*\)"
        r"\s*(?:\?\?|\|\|)\s*'native'", inputs
    ):
        failures.append(f"{action} inputs.ts: candidate omitted backend must select native")
    guard = re.search(r"if\s*\(\s*transactionBackend\s*!==\s*'native'\s*\)", inputs)
    lock = inputs.find("const lockInput =")
    if guard is None or lock < 0 or guard.start() > lock:
        failures.append(f"{action} inputs.ts: candidate must refuse legacy before reading lock or preparing roots/cache")
    if ">=0.3.0,<0.4.0" not in inputs:
        failures.append(f"{action} inputs.ts: candidate legacy refusal needs versioned recovery guidance")
    bundled_defaults = re.findall(
        r'(?:optionalScalar|exactScalar)\([^)]*"TRANSACTION_BACKEND"\)'
        r'\s*(?:\?\?|\|\|)"([^"]+)"', bundle
    )
    if bundled_defaults != ["native"] or not re.search(
        r'(?:optionalScalar|exactScalar)\([^)]*"TRANSACTION_BACKEND"\)'
        r'\s*(?:\?\?|\|\|)"native";if\([A-Za-z_$][\w$]*!=="native"\)', bundle
    ):
        failures.append(f"{action} dist/index.js: checked-in bundle is stale or accepts legacy")
    if "backend-capability" not in runtime or "native-transaction-execution-v1" not in runtime:
        failures.append(f"{action} action.ts: native backend-capability output is missing")
    action_guard = runtime.find("if (inputs.transactionBackend !== 'native')")
    first_work = runtime.find(
        "const executable = await findDebz()" if action == "download" else "const protectedFiles ="
    )
    if action_guard < 0 or first_work < 0 or action_guard > first_work:
        failures.append(f"{action} action.ts: candidate must reject a forged legacy input before work")
    if "backend-capability" not in bundle or "native-transaction-execution-v1" not in bundle:
        failures.append(f"{action} dist/index.js: native backend-capability evidence is missing")

    if action == "download":
        for token in (
            "exact-closure-lock-v3", "package-cache-v5", "debz-package-cas-v5-",
            "validateFingerprint(expected, inputs, version)", "validatePrepare(",
        ):
            if token not in runner:
                failures.append(f"download runner.ts: native lock/fingerprint/cache contract is missing: {token}")
        if runtime.find("fingerprintCache(") > runtime.find("cache.restore(") or "restoredCacheState(" not in runtime:
            failures.append("download action.ts: fingerprint must bind cache restore before preparation")
    else:
        child = texts[base + "src/subprocess.ts"]
        if "DEBZ_DOWNLOAD_TRANSACTION_BACKEND: this.inputs.transactionBackend" not in child:
            failures.append("install subprocess.ts: selected backend is not handed to download")
        if "requiredOutput(outputs, 'backend-capability')" not in child or (
            "backendCapability !== expectedBackendCapability" not in child
        ) or not re.search(
            r"const expectedBackendCapability\s*=\s*'native-transaction-execution-v1'", child
        ):
            failures.append("install subprocess.ts: missing or foreign download capability must refuse")
        if "debz-package-cas-v5-" not in child or "lockDigest" not in child:
            failures.append("install subprocess.ts: native cache key and lock digest handoff is missing")
        probe = runtime.find("buildNativeCapabilityArguments()")
        download = runtime.find("const download = await composition.download")
        if probe < 0 or download < 0 or probe > download:
            failures.append("install action.ts: native CLI capability must precede download")
        for token in (
            "validateNativeInstallResult(", "validateTransactionSummary(",
            "nativeResult.changed", "download.lockDigest", "outputs.changed",
        ):
            if token not in runtime:
                failures.append(f"install action.ts: native receipt/completion/unchanged binding is missing: {token}")
        if "receipt_evidence" not in runner or "completion_digest_sha256" not in runner:
            failures.append("install runner.ts: verified native receipt/completion binding is missing")
    return failures


def audit_legacy_cutover_policy() -> None:
    policy_path = ROOT / "security/legacy-cutover-policy.json"
    schema_path = ROOT / "schema/legacy-compatibility-policy-v1.json"
    if not policy_path.is_file() or not schema_path.is_file():
        fail("legacy cutover policy or schema is missing")
        return
    policy = json.loads(policy_path.read_text())
    if (
        policy.get("schema")
        != "https://debz.dev/schema/legacy-compatibility-policy-v1"
        or policy.get("version") != 1
        or policy.get("issue") != 86
        or policy.get("current_release_mode") != "legacy_capable"
    ):
        fail("legacy cutover policy identity or current release mode changed")
    blockers = policy.get("cutover_blockers")
    if policy.get("native_only_cutover_ready") is not False or not isinstance(blockers, list) or not blockers:
        fail("legacy cutover policy cannot claim native-only readiness while blockers remain")
    invariants = policy.get("invariants")
    required_invariants = {
        "legacy_is_never_native_authority",
        "active_legacy_requires_legacy_capable_recovery",
        "native_only_must_not_clear_active_legacy",
        "completed_history_is_read_only",
        "historical_bytes_are_never_rewritten",
        "no_fallback_after_native_mutation",
        "no_success_shaped_default",
        "single_root_operation_namespace",
    }
    if not isinstance(invariants, dict) or {
        key for key, value in invariants.items() if value is True
    } != required_invariants:
        fail("legacy cutover invariants are incomplete or not fail-closed")

    artifacts = policy.get("artifact_policy")
    if not isinstance(artifacts, list):
        fail("legacy artifact inventory is missing")
        artifacts = []
    required_artifacts = {
        "https://debz.dev/schema/system-profile-v1": ((1,), "legacy_dpkg"),
        "https://debz.dev/schema/system-profile-v2": ((2,), "explicit"),
        "https://debz.dev/schema/exact-closure-lock-v1": ((1,), "legacy_dpkg"),
        "https://debz.dev/schema/exact-closure-lock-v2": ((2,), "explicit_context"),
        "https://debz.dev/schema/transaction-result-v1": ((1,), "legacy_dpkg"),
        "https://debz.dev/schema/transaction-result-v2": ((2,), "legacy_dpkg"),
        "io.github.cataggar.debz.transaction-result-summary.v1": ((1,), "legacy_dpkg"),
        "io.github.cataggar.debz.transaction-result-summary.v2": ((2,), "native"),
        "io.github.cataggar.debz.transaction-result-capability.v1": ((1,), "native"),
        "debz:transaction-journal": ((1, 2, 3, 4), "legacy_dpkg"),
        "https://debz.dev/schema/root-operation-record-v1": ((1,), "explicit"),
        "https://debz.dev/schema/root-operation-completion-v1": ((1,), "explicit"),
        "https://debz.dev/schema/apt-system-operation-state-v1": (
            (1,),
            "explicit_context",
        ),
        "https://debz.dev/schema/apt-system-result-v1": ((1,), "explicit_context"),
        "https://debz.dev/schema/apt-system-result-v2": ((2,), "explicit_context"),
        "https://debz.dev/schema/apt-system-result-v3": ((3,), "explicit_context"),
        "https://debz.dev/schema/apt-system-execution-completion-v1": (
            (1,),
            "native",
        ),
        "io.github.cataggar.debz.command.v1": ((1,), "explicit"),
        "https://debz.dev/schema/repository-add-state-v1": ((1,), "explicit"),
        "https://debz.dev/schema/repository-operation-result-v1": (
            (1,),
            "explicit",
        ),
        "io.github.cataggar.debz.package-cache-fingerprint.v1": (
            (1,),
            "legacy_dpkg",
        ),
        "io.github.cataggar.debz.package-cache-fingerprint.v2": ((2,), "native"),
        "io.github.cataggar.debz.package-cache-result.v1": (
            (1,),
            "legacy_dpkg",
        ),
        "io.github.cataggar.debz.package-cache-result.v2": ((2,), "native"),
        "io.github.cataggar.debz.package-cache-error.v1": ((1,), "explicit"),
        "io.github.cataggar.debz.package-family.capabilities.v1": (
            (1,),
            "legacy_dpkg",
        ),
        "io.github.cataggar.debz.package-family.capabilities.v2": ((2,), "native"),
        "io.github.cataggar.debz.package-family.request.v1": (
            (1,),
            "legacy_dpkg",
        ),
        "io.github.cataggar.debz.package-family.request.v2": ((2,), "native"),
        "io.github.cataggar.debz.package-family.result.v1": (
            (1,),
            "legacy_dpkg",
        ),
        "io.github.cataggar.debz.package-family.result.v2": ((2,), "native"),
        "https://debz.dev/schema/native-transaction-provenance-v1": (
            (1,),
            "native",
        ),
        "io.github.cataggar.debz.native-install-capability.v1": ((1,), "native"),
        "io.github.cataggar.debz.native-install-result.v1": ((1,), "native"),
        "https://debz.dev/schema/native-repository-unchanged-v1": (
            (1,),
            "native",
        ),
        "https://debz.dev/schema/legacy-capability-evidence-v1": (
            (1,),
            "legacy_dpkg_non_authoritative",
        ),
    }
    actual_artifacts: dict[str, tuple[tuple[int, ...], str]] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            fail("legacy artifact inventory contains a malformed entry")
            continue
        schema = item.get("schema")
        versions = item.get("versions")
        backend = item.get("backend")
        if (
            not isinstance(schema, str)
            or not isinstance(versions, list)
            or not all(isinstance(version, int) for version in versions)
            or not isinstance(backend, str)
        ):
            fail("legacy artifact inventory contains an invalid identity tuple")
            continue
        if schema in actual_artifacts:
            fail(f"legacy artifact identity is multiply classified: {schema}")
            continue
        actual_artifacts[schema] = (tuple(versions), backend)
    if actual_artifacts != required_artifacts:
        fail("legacy artifact version/backend inventory is incomplete or ambiguous")
    classifier = (ROOT / "src/legacy_compat.zig").read_text(errors="strict")
    for schema in required_artifacts:
        if schema not in classifier:
            fail(f"normative Zig classifier omits policy artifact: {schema}")

    classified: set[str] = set()
    for section in (
        "production_execution_paths",
        "compatibility_guard_paths",
        "historical_reference_paths",
        "test_reference_paths",
    ):
        entries = policy.get(section)
        if not isinstance(entries, list) or not entries:
            fail(f"legacy cutover policy has no {section}")
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                fail(f"legacy cutover policy contains malformed {section} entry")
                continue
            relative = entry["path"]
            if relative in classified:
                fail(f"legacy cutover path is multiply classified: {relative}")
            classified.add(relative)
            if not (ROOT / relative).is_file():
                fail(f"legacy cutover inventory path is missing: {relative}")
            if section in ("historical_reference_paths", "test_reference_paths"):
                if entry.get("retain_after_cutover") is not True:
                    fail(f"legacy retained path lacks explicit retention: {relative}")
            elif not isinstance(entry.get("cutover"), str):
                fail(f"legacy executable/guard path lacks a cutover disposition: {relative}")
    required_selectors = {
        "src/transaction_engine.zig",
        "src/production_backend.zig",
        "src/repository_backend.zig",
        "src/package_family_backend.zig",
        "src/package_cache_workflow.zig",
        "src/system_profile.zig",
        "src/main.zig",
        "src/repository_cli.zig",
        "src/apt_system_orchestrator.zig",
        "src/target_apt_config.zig",
        "actions/download/src/inputs.ts",
        "actions/download/src/action.ts",
        "actions/download/src/runner.ts",
        "actions/download/action.yml",
        "actions/install/src/inputs.ts",
        "actions/install/src/action.ts",
        "actions/install/src/errors.ts",
        "actions/install/action.yml",
    }
    production_paths = {
        entry.get("path")
        for entry in policy.get("production_execution_paths", [])
        if isinstance(entry, dict)
    }
    if not required_selectors.issubset(production_paths):
        fail(
            "legacy cutover policy omits production selectors: "
            f"{sorted(required_selectors - production_paths)!r}"
        )
    for relative in required_selectors:
        text = (ROOT / relative).read_text(errors="strict")
        if "legacy_dpkg" not in text and "dpkg" not in text:
            fail(f"legacy production selector lost its auditable identity: {relative}")

    marker_patterns = (
        re.compile(r"legacy_dpkg"),
        re.compile(r"legacy-dpkg-execution"),
        re.compile(r"legacy-capability"),
        re.compile(r"\bdpkg-query\b"),
        re.compile(r'\.\{\s*"dpkg"'),
        re.compile(r'"/usr/bin/dpkg"'),
        re.compile(
            r"exact-closure-lock-v1|transaction-result-v1|system-profile-v1|"
            r"package-cache-(?:fingerprint|result)\.v1|"
            r"package-family\.(?:capabilities|request|result)\.v1"
        ),
    )
    marked_paths: set[str] = set()
    for directory, patterns in (
        (ROOT / "src", ("*.zig",)),
        (ROOT / "actions", ("*.ts", "*.yml")),
    ):
        for pattern in patterns:
            for path in directory.rglob(pattern):
                if "dist" in path.parts or "node_modules" in path.parts:
                    continue
                text = path.read_text(errors="strict")
                if any(marker.search(text) for marker in marker_patterns):
                    marked_paths.add(str(path.relative_to(ROOT)))
    unclassified = marked_paths - classified
    if unclassified:
        fail(
            "legacy cutover policy has unclassified production/test paths: "
            f"{sorted(unclassified)!r}"
        )

    contracts = policy.get("generated_contracts")
    if not isinstance(contracts, list) or len(contracts) != 2:
        fail("legacy cutover generated Actions inventory is incomplete")
    else:
        for contract in contracts:
            path = ROOT / str(contract.get("path", ""))
            if (
                contract.get("required_evidence") != "backend-capability"
                or not path.is_file()
            ):
                fail("legacy cutover generated Actions contract is malformed")
                continue
            bundle = path.read_text(errors="strict")
            for token in (
                "backend-capability",
                "legacy-dpkg-execution-deprecated-v1",
                "native-transaction-execution-v1",
                "Recover this operation with debz >=0.3.0,<0.4.0 before installing a native-only release.",
            ):
                if token not in bundle:
                    fail(f"{path.relative_to(ROOT)} lacks cutover capability evidence: {token}")


def audit_docs() -> None:
    if (ROOT / "docs").exists():
        fail("stale docs/ directory exists; documentation belongs under doc/")
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in sorted(ROOT.rglob("*.md")):
        relative = path.relative_to(ROOT)
        if any(
            part
            in {
                ".cache",
                ".git",
                ".real-snapshot",
                ".tmp",
                ".tools",
                ".zig-cache",
                "lib",
                "node_modules",
                "zig-out",
                "zig-pkg",
            }
            for part in relative.parts
        ):
            continue
        for target in link_pattern.findall(path.read_text(errors="strict")):
            target = target.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = (path.parent / target).resolve()
            if ROOT not in resolved.parents and resolved != ROOT:
                fail(f"{path.relative_to(ROOT)}: link escapes repository: {target}")
            elif not resolved.exists():
                fail(f"{path.relative_to(ROOT)}: stale local link: {target}")


def audit_secrets_and_artifacts(files: list[pathlib.Path]) -> None:
    generated_roots = {"zig-out", ".zig-cache", "zig-pkg"}
    generated_suffixes = {".o", ".a", ".so", ".dll", ".dylib", ".exe", ".profraw"}
    secret_patterns = {
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"): "private key",
        re.compile(b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----"): "OpenPGP private key",
        re.compile(rb"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{12,}"): "bearer credential",
        re.compile(rb"AKIA[0-9A-Z]{16}"): "AWS access key",
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"): "GitHub token",
    }
    synthetic_key_path = pathlib.Path("tools/generate-openpgp-fixtures.py")
    synthetic_key_count = 0
    for path in files:
        relative = path.relative_to(ROOT)
        if "__pycache__" in relative.parts or path.suffix.lower() in {".pyc", ".pyo"}:
            continue
        if any(part in generated_roots for part in relative.parts):
            fail(f"tracked generated artifact: {relative}")
        if path.suffix.lower() in generated_suffixes:
            fail(f"tracked generated binary artifact: {relative}")
        data = path.read_bytes()
        for pattern, description in secret_patterns.items():
            matches = list(pattern.finditer(data))
            if not matches:
                continue
            if relative == synthetic_key_path and description == "private key":
                synthetic_key_count += len(matches)
                continue
            fail(f"{relative}: possible {description}")
    if synthetic_key_count != 2:
        fail("synthetic OpenPGP fixture generator must contain exactly two declared test keys")


def main() -> int:
    files = tracked_files()
    audit_digest_cutover(files)
    audit_production_sources()
    audit_dependencies()
    audit_release_targets()
    audit_ci_pins()
    audit_composite_action_pins()
    audit_setup_action_dependencies()
    audit_download_action()
    audit_install_action()
    audit_legacy_cutover_policy()
    audit_docs()
    audit_secrets_and_artifacts(files)
    if FAILURES:
        for failure in FAILURES:
            print(f"security-audit: {failure}", file=sys.stderr)
        return 1
    print("security-audit: all gates passed")
    return 0


def check_policy_input(kind: str, input_path: pathlib.Path) -> int:
    """Apply a production policy validator to one bounded, external input."""
    limit = 2 * 1024 * 1024 if kind in ("native-final", "native-only-candidate", "native-provenance") else 1024 * 1024
    try:
        descriptor = os.open(input_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("not a regular file")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("too large")
        text = data.decode("utf-8")
    except (OSError, UnicodeError, ValueError):
        print(f"security-audit: check input must be a regular file of at most {limit // (1024 * 1024)} MiB", file=sys.stderr)
        return 2
    if kind == "action-pin":
        failures = action_pin_failures(text, "action.yml")
    elif kind == "native-only-candidate":
        import native_only_candidate

        try:
            fixture = json.loads(text)
            if (
                not isinstance(fixture, dict)
                or set(fixture) != {"overrides"}
                or not isinstance(fixture["overrides"], dict)
                or any(
                    not isinstance(key, str)
                    or (value is not None and not isinstance(value, str))
                    for key, value in fixture["overrides"].items()
                )
            ):
                raise ValueError("invalid overrides")
        except (ValueError, TypeError):
            print("security-audit: invalid native-only candidate fixture", file=sys.stderr)
            return 2
        failures = native_only_candidate.candidate_failures(
            ROOT, fixture["overrides"], actions_native_only_candidate_failures,
        )
    elif kind == "actions-native-only":
        try:
            fixture = json.loads(text)
            if not isinstance(fixture, dict) or set(fixture) != {"action", "overrides"}:
                raise ValueError("invalid fixture")
            action = fixture["action"]
            overrides = fixture["overrides"]
            if action not in ("download", "install") or not isinstance(overrides, dict):
                raise ValueError("invalid action")
            paths = tuple(
                f"actions/{action}/{relative}" for relative in (
                    "action.yml", "src/inputs.ts", "src/action.ts",
                    "src/runner.ts", "dist/index.js",
                    *(("src/subprocess.ts",) if action == "install" else ()),
                )
            )
            if any(key not in paths or not isinstance(value, str) for key, value in overrides.items()):
                raise ValueError("invalid override")
            texts = {
                path: overrides.get(path, (ROOT / path).read_text(errors="strict"))
                for path in paths
            }
        except (ValueError, TypeError, KeyError, UnicodeError, OSError):
            print("security-audit: invalid Actions native-only candidate fixture", file=sys.stderr)
            return 2
        failures = actions_native_only_candidate_failures(action, texts)
    elif kind == "ghr-ci":
        failures = ghr_zig_workflow_failures(text, "ci.yml", 21)
    elif kind == "ghr-release":
        failures = ghr_zig_workflow_failures(text, "release.yml", 1)
    elif kind == "workflow-failure":
        failures = workflow_failure_handling_failures(text, "ci.yml")
    elif kind == "ci-concurrency":
        failures = ci_concurrency_failures(text, "ci.yml")
    elif kind == "ci-recovery":
        failures = native_recovery_ci_failures(text)
    elif kind == "workload-build":
        failures = workload_partition_failures(text)
    elif kind == "ci-signed-proc":
        failures = signed_proc_ci_failures(text)
    elif kind in {
        "native-core", "native-final", "native-entry", "native-consumer",
        "native-repository", "native-workflow", "native-report",
        "native-lifecycle", "native-fixtures", "native-gate", "native-provenance",
        "reference-root", "protected-reference",
    }:
        sources = {
            "native-core": ("build.zig", "test/native_recovery_helper.zig", "test/native_lifecycle_support.zig"),
            "native-final": ("test/native_recovery_helper.zig", "test/native_lifecycle_support.zig", "src/native_unpack.zig"),
            "native-entry": ("test/native_recovery_acceptance.zig", "test/native_recovery_projected_workflows.zig", ".github/workflows/ci.yml"),
            "native-consumer": ("test/native_recovery_parity.zig", "test/native_recovery_parity_evidence.zig"),
            "native-repository": ("test/native_recovery_repository.zig",),
            "native-workflow": ("build.zig", "test/native_recovery_family.zig", "test/native_recovery_projected_workflows.zig"),
            "native-report": REPORT_PATH_ORACLE_FILES,
            "native-lifecycle": ("build.zig", "test/native_trigger_acceptance.zig"),
            "native-provenance": (
                "build.zig", "src/sha512_transaction_e2e_test.zig",
                "src/native_provenance_binding_test.zig",
                "src/native_transaction_result.zig",
                "src/repository_backend.zig",
                "src/native_recovery.zig",
                "src/native_unpack.zig",
                "src/production_backend.zig",
            ),
            "reference-root": REFERENCE_ROOT_PATHS,
            "protected-reference": PROTECTED_REFERENCE_PATHS,
            "native-gate": (
                "build.zig", "test/native_recovery_helper.zig",
                "test/native_recovery_family.zig", "test/native_recovery_projected_workflows.zig",
                "test/native_recovery_repository.zig",
                "test/native_recovery_diversions.zig",
            ),
            "native-fixtures": (
                "tools/native-lifecycle-fixtures.py", "tools/native-trigger-fixtures.py",
                "tools/dpkg-config-reference.py",
                "actions/install/__tests__/integration.test.ts",
                "tools/test-native-lifecycle.py", "tools/test_native_lifecycle.py",
                "tools/test-native-triggers.py", "tools/test_native_triggers.py",
                "tools/test-native-recovery.py", "tools/test_native_recovery.py",
            ),
        }
        fixture = json.loads(text)
        paths = sources[kind]
        if (
            not isinstance(fixture, dict) or set(fixture) != {"path", "text"}
            or fixture["path"] not in paths
            or (fixture["text"] is not None and not isinstance(fixture["text"], str))
        ):
            print("security-audit: invalid native wiring input", file=sys.stderr)
            return 2
        texts = {
            path: (ROOT / path).read_text()
            for path in paths if (ROOT / path).is_file()
        }
        if fixture["text"] is None:
            texts.pop(fixture["path"], None)
        else:
            texts[fixture["path"]] = fixture["text"]
        if kind == "native-core":
            failures = native_core_completion_wiring_failures(*(texts[path] for path in paths))
        elif kind == "native-final":
            failures = native_exercise_final_wiring_failures(*(texts[path] for path in paths))
        elif kind == "native-entry":
            failures = native_entry_point_shape_failures(*(texts[path] for path in paths))
        elif kind == "native-consumer":
            failures = native_consumer_receipt_wiring_failures(*(texts[path] for path in paths))
        elif kind == "native-repository":
            failures = native_repository_evidence_wiring_failures(texts[paths[0]])
        elif kind == "native-workflow":
            failures = native_workflow_acceptance_wiring_failures(*(texts[path] for path in paths))
        elif kind == "native-report":
            failures = native_report_path_wiring_failures(texts)
        elif kind == "native-lifecycle":
            failures = native_lifecycle_migration_failures(*(texts[path] for path in paths))
        elif kind == "native-gate":
            failures = native_recovery_gate_wiring_failures(*(texts[path] for path in paths))
        elif kind == "native-provenance":
            failures = native_provenance_binding_wiring_failures(*(texts[path] for path in paths))
        elif kind == "reference-root":
            failures = reference_launcher_root_wiring_failures(*(texts.get(path, "") for path in paths))
        elif kind == "protected-reference":
            failures = protected_reference_ci_failures(texts)
        else:
            failures = native_lifecycle_fixture_failures(texts)
    elif kind == "release-install-metadata":
        failures = release_install_metadata_failures(text)
    elif kind == "dependency-zstd":
        failures = dependency_option_failures(text, "zstd", {
            "target": "target",
            "optimize": "optimize",
            "shared": "false",
            "tools": "false",
            "multithread": "false",
        })
    elif kind == "runtime-metadata":
        policy = json.loads((ROOT / "security/dependency-policy.json").read_text())
        dependencies = {item["name"]: item for item in policy["production_dependencies"]}
        failures = runtime_metadata_failures(json.loads(text), dependencies)
    elif kind == "digest-semantic":
        fixture = json.loads(text)
        if not isinstance(fixture, dict) or set(fixture) != {"path", "text"} or not isinstance(fixture["path"], str) or not isinstance(fixture["text"], str):
            print("security-audit: invalid digest semantic input", file=sys.stderr)
            return 2
        policy = json.loads((ROOT / DIGEST_POLICY_PATH).read_text())
        files = repository_digest_files(tracked_files())
        if len(files) > 1024 or any(path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024 for path in files):
            print("security-audit: digest check input exceeds repository bounds", file=sys.stderr)
            return 2
        texts = tracked_digest_texts(tracked_files())
        texts[fixture["path"]] = fixture["text"]
        candidates = digest_semantic_candidates(texts)
        failures = semantic_allowlist_failures(
            candidates,
            policy,
            (ROOT / DIGEST_SEMANTIC_ALLOWLIST_PATH).read_text(),
        )
    elif kind == "digest-inventory":
        fixture = json.loads(text)
        if (
            not isinstance(fixture, dict)
            or "path" not in fixture
            or not isinstance(fixture["path"], str)
            or ("append" in fixture and "text" in fixture)
            or ("append" not in fixture and "text" not in fixture)
            or ("append" in fixture and (not isinstance(fixture["append"], str) or len(fixture["append"]) > 4096))
            or ("text" in fixture and not isinstance(fixture["text"], str))
            or ("policy" in fixture and not isinstance(fixture["policy"], str))
            or ("inventory" in fixture and not isinstance(fixture["inventory"], str))
            or not set(fixture).issubset({"path", "append", "text", "policy", "inventory"})
        ):
            print("security-audit: invalid digest inventory input", file=sys.stderr)
            return 2
        policy = json.loads(fixture.get("policy", (ROOT / DIGEST_POLICY_PATH).read_text()))
        inventory_text = fixture.get("inventory", (ROOT / DIGEST_INVENTORY_PATH).read_text())
        texts = tracked_digest_texts(tracked_files())
        if fixture["path"] not in texts:
            print("security-audit: digest inventory path is not audited", file=sys.stderr)
            return 2
        if "append" in fixture:
            texts[fixture["path"]] += fixture["append"]
        else:
            texts[fixture["path"]] = fixture["text"]
        failures = digest_inventory_failures(texts, policy, inventory_text)
    elif kind == "digest-inventory-synthetic":
        fixture = json.loads(text)
        if (
            not isinstance(fixture, dict)
            or set(fixture) != {"case"}
            or not isinstance(fixture["case"], str)
        ):
            print("security-audit: invalid digest inventory synthetic input", file=sys.stderr)
            return 2
        try:
            failures = digest_inventory_synthetic_failures(fixture["case"])
        except ValueError as error:
            print(f"security-audit: {error}", file=sys.stderr)
            return 2
    elif kind == "digest-semantic-allowlist-synthetic":
        fixture = json.loads(text)
        if (
            not isinstance(fixture, dict)
            or set(fixture) != {"case"}
            or not isinstance(fixture["case"], str)
        ):
            print("security-audit: invalid digest semantic allowlist synthetic input", file=sys.stderr)
            return 2
        try:
            failures = semantic_allowlist_synthetic_failures(fixture["case"])
        except ValueError as error:
            print(f"security-audit: {error}", file=sys.stderr)
            return 2
    elif kind == "digest-allowlist":
        policy = json.loads(text)
        texts = tracked_digest_texts(tracked_files())
        failures = semantic_allowlist_failures(
            digest_semantic_candidates(texts),
            policy,
            (ROOT / DIGEST_SEMANTIC_ALLOWLIST_PATH).read_text(),
        )
    elif kind == "digest-untracked":
        fixture = json.loads(text)
        if not isinstance(fixture, dict) or set(fixture) != {"root"} or not isinstance(fixture["root"], str):
            print("security-audit: invalid untracked fixture", file=sys.stderr)
            return 2
        root = pathlib.Path(fixture["root"]).resolve()
        try:
            root.relative_to(ROOT / ".zig-cache/tmp")
        except ValueError:
            print("security-audit: untracked fixture must be in the repository test cache", file=sys.stderr)
            return 2
        if not (root / ".git").is_dir():
            print("security-audit: untracked fixture needs its own Git root", file=sys.stderr)
            return 2
        count = 0
        for directory, directories, files in os.walk(root, followlinks=False):
            directories[:] = [name for name in directories if name != ".git"]
            count += len(directories) + len(files)
            if count > 128 or len(pathlib.Path(directory).relative_to(root).parts) > 8:
                print("security-audit: untracked fixture exceeds traversal bounds", file=sys.stderr)
                return 2
        original_root = ROOT
        try:
            globals()["ROOT"] = root
            paths = repository_digest_files([])
        finally:
            globals()["ROOT"] = original_root
        if len(paths) > 128:
            print("security-audit: untracked fixture exceeds file bounds", file=sys.stderr)
            return 2
        print("\n".join(path.relative_to(root).as_posix() for path in paths))
        failures = []
    elif kind == "docs-links":
        fixture = json.loads(text)
        if not isinstance(fixture, dict) or set(fixture) != {"root"} or not isinstance(fixture["root"], str):
            print("security-audit: invalid docs fixture", file=sys.stderr)
            return 2
        root = pathlib.Path(fixture["root"]).resolve()
        try:
            root.relative_to(ROOT / ".zig-cache/tmp")
        except ValueError:
            print("security-audit: docs fixture must be in the repository test cache", file=sys.stderr)
            return 2
        if not root.is_dir():
            print("security-audit: docs fixture root is not a directory", file=sys.stderr)
            return 2
        count = 0
        for directory, directories, files in os.walk(root, followlinks=False):
            count += len(directories) + len(files)
            if count > 256 or len(pathlib.Path(directory).relative_to(root).parts) > 16:
                print("security-audit: docs fixture exceeds traversal bounds", file=sys.stderr)
                return 2
            if any((pathlib.Path(directory) / name).is_symlink() for name in directories + files):
                print("security-audit: docs fixture contains a symlink", file=sys.stderr)
                return 2
            if any((pathlib.Path(directory) / name).stat().st_size > 1024 * 1024 for name in files):
                print("security-audit: docs fixture file is too large", file=sys.stderr)
                return 2
        original_root = ROOT
        try:
            globals()["ROOT"] = root
            FAILURES.clear()
            audit_docs()
            failures = list(FAILURES)
        finally:
            globals()["ROOT"] = original_root
            FAILURES.clear()
    else:
        print(f"security-audit: unknown check kind: {kind}", file=sys.stderr)
        return 2
    for failure in failures:
        print(f"security-audit: {failure}", file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--write-digest-inventory":
        raise SystemExit(write_digest_inventory(check=False))
    if len(sys.argv) == 2 and sys.argv[1] == "--check-digest-inventory":
        raise SystemExit(write_digest_inventory(check=True))
    if len(sys.argv) == 4 and sys.argv[1] == "check":
        raise SystemExit(check_policy_input(sys.argv[2], pathlib.Path(sys.argv[3])))
    if len(sys.argv) == 2 and sys.argv[1] == "native-only-candidate":
        import native_only_candidate

        failures = native_only_candidate.candidate_failures(
            ROOT, {}, actions_native_only_candidate_failures,
        )
        for failure in failures:
            print(f"security-audit: {failure}", file=sys.stderr)
        if failures:
            raise SystemExit(1)
        print("security-audit: native-only candidate passed")
        raise SystemExit(0)
    raise SystemExit(main())
