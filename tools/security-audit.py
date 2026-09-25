#!/usr/bin/env python3
"""Repository-local, network-free security and policy audit."""

from __future__ import annotations

import pathlib
import re
import hashlib
import json
import subprocess
import sys
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAILURES: list[str] = []

DIGEST_POLICY_PATH = pathlib.Path("security/digest-cutover-policy.json")
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
    "tools/security-audit.py",
    "tools/test_security_audit.py",
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
    return [
        path
        for item in result.stdout.split(b"\0")
        if item
        for path in (ROOT / item.decode(),)
        if path.exists() or path.is_symlink()
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
    required_policy = ROOT / DIGEST_POLICY_PATH
    candidates = [*files, *untracked_files()]
    if required_policy.is_file():
        candidates.append(required_policy)
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


def digest_inventory_failures(
    texts: dict[str, str],
    policy: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    scoped_paths = sorted(texts)
    findings = digest_findings(texts)
    inventory = policy.get("inventory")
    if not isinstance(inventory, dict):
        return ["digest policy inventory is missing"]
    expected_files = inventory.get("tracked_files")
    if not isinstance(expected_files, dict):
        failures.append("digest policy tracked-file inventory is missing")
    elif (
        expected_files.get("count") != len(scoped_paths)
        or expected_files.get("sha512") != canonical_sha512(scoped_paths)
    ):
        failures.append(
            "digest policy tracked-file inventory changed "
            f"(count={len(scoped_paths)}, sha512={canonical_sha512(scoped_paths)})"
        )
    expected_findings = inventory.get("findings")
    actual_counts = {
        kind: sum(finding["kind"] == kind for finding in findings)
        for kind in DIGEST_FINDING_KINDS
    }
    if not isinstance(expected_findings, dict):
        failures.append("digest policy finding inventory is missing")
    elif (
        expected_findings.get("count") != len(findings)
        or expected_findings.get("counts") != actual_counts
        or expected_findings.get("sha512") != canonical_sha512(findings)
    ):
        failures.append(
            "digest policy finding inventory changed "
            f"(count={len(findings)}, sha512={canonical_sha512(findings)})"
        )

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
        scoped_findings = [
            finding for finding in findings if digest_scope(finding["path"]) == scope
        ]
        scoped_counts = {
            kind: sum(finding["kind"] == kind for finding in scoped_findings)
            for kind in DIGEST_FINDING_KINDS
        }
        if (
            entry.get("count") != len(scoped_findings)
            or entry.get("counts") != scoped_counts
            or entry.get("sha512") != canonical_sha512(scoped_findings)
        ):
            failures.append(
                f"digest policy classification changed: {scope} "
                f"(count={len(scoped_findings)}, "
                f"sha512={canonical_sha512(scoped_findings)})"
            )
    if sorted(seen_scopes) != actual_scopes:
        failures.append("digest policy does not classify every tracked audit scope")
    return failures


def semantic_allowlist_failures(
    candidates: list[dict[str, str]],
    policy: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    entries = policy.get("semantic_allowlist")
    if not isinstance(entries, list) or not entries:
        return ["digest semantic allowlist is missing"]
    candidates_by_kind: dict[str, list[tuple[int, dict[str, str]]]] = {}
    for index, candidate in enumerate(candidates):
        candidates_by_kind.setdefault(candidate["kind"], []).append(
            (index, candidate)
        )
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
            or kind not in candidates_by_kind
            or classification not in allowed_classes
            or not isinstance(rationale, str)
            or len(rationale.strip()) < 40
            or not isinstance(paths, list)
            or not paths
            or paths != sorted(set(paths))
            or not all(exact_policy_path(path) for path in paths)
        ):
            failures.append("digest semantic allowlist contains an invalid or overbroad entry")
            continue
        seen_ids.add(identifier)
        selected_pairs = [
            (index, candidate)
            for index, candidate in candidates_by_kind[kind]
            if candidate["path"] in paths
        ]
        selected = [candidate for _, candidate in selected_pairs]
        if (
            not selected
            or {candidate["path"] for candidate in selected} != set(paths)
            or entry.get("count") != len(selected)
            or entry.get("sha512") != canonical_sha512(selected)
        ):
            failures.append(f"digest semantic allowlist changed: {identifier}")
            continue
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
) -> list[str]:
    failures = digest_inventory_failures(texts, policy)
    failures.extend(
        semantic_allowlist_failures(digest_semantic_candidates(texts), policy)
    )
    failures.extend(typed_digest_authority_failures(texts))
    return failures


def audit_digest_cutover(files: list[pathlib.Path]) -> None:
    policy_path = ROOT / DIGEST_POLICY_PATH
    if not policy_path.is_file():
        fail("digest cutover policy is missing")
        return
    try:
        policy = json.loads(policy_path.read_text())
    except json.JSONDecodeError:
        fail("digest cutover policy is invalid JSON")
        return
    if (
        policy.get("schema")
        != "https://debz.dev/security/digest-cutover-policy-v1"
        or policy.get("version") != 1
        or policy.get("fingerprint_algorithm") != "sha512"
    ):
        fail("digest cutover policy identity changed")
        return
    if policy.get("scope") != {
        "roots": list(DIGEST_SCOPE_ROOTS),
        "top_level_files": sorted(DIGEST_TOP_LEVEL_FILES),
        "excluded_finding_paths": sorted(DIGEST_POLICY_EXCLUDED_FINDINGS),
        "exclusion_rationale": (
            "The repository manifest includes tracked and non-ignored untracked "
            "files so pre-commit audit results remain stable after commit. The "
            "policy and its audit/canary implementation are excluded from token "
            "findings to avoid recursive self-classification; they do not define "
            "repository digest authority."
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
    for message in digest_cutover_failures(texts, policy):
        fail(message)


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
    process_calls: list[str] = []
    child_calls: list[str] = []
    namespace_calls: list[str] = []
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
                line = text.count("\n", 0, match.start()) + 1
                fail(f"{relative}:{line}: forbidden {reason}")
        for match in re.finditer(r"\bstd\.process\.run\s*\(", text):
            process_calls.append(f"{relative}:{text.count(chr(10), 0, match.start()) + 1}")
        for match in re.finditer(r"\blinux\.(?:fork|execve|chroot)\s*\(", text):
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
            r"\blinux\.(?:unshare|setns|mount|move_mount|umount2)\s*\(", text
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


def native_recovery_ci_failures(text: str) -> list[str]:
    jobs = dict(re.findall(
        r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        text,
    ))
    failures = []
    timeout_lines = {
        "build-and-test-workload": "    timeout-minutes: 90",
        "native-recovery": "    timeout-minutes: 180",
    }
    for name, timeout_line in timeout_lines.items():
        body = jobs.get(name, "")
        lines = body.splitlines()
        if any(line not in lines for line in (
            timeout_line,
            "      fail-fast: false",
            "          - os: ubuntu-24.04",
            "            name: linux-x64",
            "          - os: ubuntu-24.04-arm",
            "            name: linux-arm64",
        )) or re.search(r"(?m)^    if:", body) or "continue-on-error:" in body:
            failures.append(f"ci.yml: {name} must require both architectures within its reviewed job limit")
    workload = jobs.get("build-and-test-workload", "")
    if any(line not in workload.splitlines() for line in (
        "    name: Build and test workload (${{ matrix.name }}, ${{ matrix.optimize }})",
        "        name: [linux-x64, linux-arm64]",
        "        optimize: [Debug, ReleaseSafe]",
        "      OPTIMIZE: ${{ matrix.optimize }}",
    )) or re.search(r"(?m)^        exclude:", workload):
        failures.append("ci.yml: build workloads must require both optimization modes on both architectures")
    steps = dict(re.findall(
        r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", workload,
    ))
    shared_steps = {
        "Build and test": (
            '          zig build -Doptimize="$OPTIMIZE" -j2 --summary all',
            '          zig build test -Doptimize="$OPTIMIZE" -j2 --summary all',
            '          zig build fuzz -Doptimize="$OPTIMIZE" -j2 --summary all',
        ),
        "Run required real apt facade acceptance": (
            "        run: |",
            "          sudo env \\",
            '            PATH="$PATH" \\',
            '            TMPDIR="$PWD/.zig-cache" \\',
            '            PYTHONPYCACHEPREFIX="$PWD/.zig-cache/pycache" \\',
            '            ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-cache/apt-system-acceptance-global" \\',
            '            ZIG_LOCAL_CACHE_DIR="$PWD/.zig-cache/apt-system-acceptance-local" \\',
            '            "$(command -v zig)" build test-apt-system-acceptance \\',
            '              -Doptimize="$OPTIMIZE" -j2 --summary all',
        ),
        "Compare native materialization, conffiles, differential, lifecycle, and triggers with dpkg": (
            '          reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
            "          zig build test-native-materialization test-native-conffiles test-native-differential test-native-lifecycle test-native-triggers \\",
            '            -Dnative-reference-dpkg="$reference_dpkg" -Doptimize="$OPTIMIZE" -j2 --summary all',
        ),
        "Require private native helper namespaces": (
            '          zig build test-native-helper-namespace -Doptimize="$OPTIMIZE" -j2 --summary all',
        ),
    }
    for name, commands in shared_steps.items():
        body = steps.get(name, "")
        if any(line not in body.splitlines() for line in commands) or re.search(r"(?m)^        if:", body):
            failures.append(f"ci.yml: {name} must run in every build workload")
    normalized = steps.get("Normalize apt facade acceptance diagnostics", "")
    if any(line not in normalized.splitlines() for line in (
        "        if: ${{ always() }}",
        '            .zig-cache/apt-system-acceptance-global \\',
        '            .zig-cache/apt-system-acceptance-local 2>/dev/null || true',
    )):
        failures.append("ci.yml: apt acceptance caches must be normalized for both modes")
    compare_name = (
        "Compare native materialization, conffiles, differential, "
        "lifecycle, and triggers with dpkg"
    )
    compare = steps.get(compare_name, "")
    script = compare.split("        run: |\n", 1)
    compare_commands = (
        [
            line.strip() for line in script[1].splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(script) == 2
        else []
    )
    expected_compare_commands = [
        *(line.strip() for line in shared_steps[compare_name]),
        "zig build test-native-lifecycle-zig test-native-triggers-zig test-native-diversion-settlement-zig \\",
        shared_steps[compare_name][2].strip(),
        "zig build test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle test-native-triggers-zig-settlement-reference \\",
        shared_steps[compare_name][2].strip(),
    ]
    if compare_commands != expected_compare_commands:
        failures.append(
            "ci.yml: both native differential suites must execute with "
            "the pinned dpkg in every build workload"
        )
    selectors = steps.get(
        "Exercise standalone Zig workspace selectors and fail-closed combinations", ""
    )
    if re.search(r"(?m)^        if:", selectors) or selectors.count(
        '            zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only \\'
    ) != 2 or any(
        command not in selectors.splitlines()
        for command in (
            '          reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
            '          zig build build-native-acceptance-zig -Doptimize="$OPTIMIZE" -j2 --summary all',
            '            zig-out/bin/native-lifecycle-zig-acceptance --oracle-only --diversions-only \\',
            '            zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only \\',
            '            --reference-dpkg "$reference_dpkg" --workspace "$lifecycle"',
            '            --reference-dpkg "$reference_dpkg" --workspace "$trigger"',
            '          test -d "$lifecycle" && test -d "$trigger"',
            "          grep -Fq 'error.InvalidSettlementSelection' \"$PWD/.tmp/zig-invalid-selector.log\"",
            "          grep -Fq 'error.PathAlreadyExists' \"$PWD/.tmp/zig-existing-workspace.log\"",
        )
    ):
        failures.append("ci.yml: standalone Zig workspace selectors and refusals must run in every mode")
    selected_steps = {
        "Test release packaging": ("Debug", (
            "        run: zig build test-release -j2 --summary all",
        )),
        "Check ReleaseSafe CLI help": ("ReleaseSafe", (
            "        run: zig build -Doptimize=ReleaseSafe -j2 run -- --help",
        )),
        "Run required privileged orchestration crash suite": ("Debug", (
            '            "$(command -v zig)" build test-apt-system \\',
            "              -Drequire-privileged-orchestration-tests=true \\",
            "              -j2 --summary all",
        )),
        "Prepare native download action fixture": ("ReleaseSafe", (
            "          python3 tools/generate-integration-repository.py \\",
        )),
        "Prepare native exact-lock package closure": ("ReleaseSafe", (
            "        uses: ./actions/download",
        )),
        "Validate native download action outputs": ("ReleaseSafe", (
            '          test "$CACHE_HIT" = false',
            '          test -d "$CACHE_PATH"',
            '          test "$DOWNLOADED" -gt 0',
            '          test "$REUSED" -eq 0',
        )),
    }
    for name, (mode, commands) in selected_steps.items():
        lines = steps.get(name, "").splitlines()
        if any(line not in lines for line in (
            f"        if: ${{{{ matrix.optimize == '{mode}' }}}}", *commands,
        )):
            failures.append(f"ci.yml: {name} must remain required in {mode}")
    recovery = jobs.get("native-recovery", "")
    if any(line not in recovery.splitlines() for line in (
        '          reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
        '          zig build test-native-recovery -Dnative-reference-dpkg="$reference_dpkg" -j2 --summary all',
        '          zig build test-native-recovery -Dnative-reference-dpkg="$reference_dpkg" -Doptimize=ReleaseSafe -j2 --summary all',
    )) or re.search(r"(?m)^        if:", recovery):
        failures.append("ci.yml: native recovery must run the full Debug and ReleaseSafe targets")
    gate = jobs.get("build-and-test", "")
    if any(line not in gate.splitlines() for line in (
        "    name: Build and test (${{ matrix.name }})",
        "    needs: [build-and-test-workload, native-recovery]",
        "    if: ${{ always() }}",
        "      fail-fast: false",
        "        name: [linux-x64, linux-arm64]",
        "          BUILD_RESULT: ${{ needs.build-and-test-workload.result }}",
        "          RECOVERY_RESULT: ${{ needs.native-recovery.result }}",
        '          test "$BUILD_RESULT" = success',
        '          test "$RECOVERY_RESULT" = success',
    )) or "continue-on-error:" in gate or re.search(r"(?m)^        if:", gate):
        failures.append("ci.yml: existing required build checks must reject any incomplete workload")
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
        if f'"{entrypoint}"' not in build:
            failures.append(f"build.zig: retain {entrypoint} until Zig has full equivalent coverage")
    for binding in (
        "native_lifecycle.addArtifactArg(native_lifecycle_tests);",
        "native_lifecycle.step.dependOn(&native_lifecycle_oracle_tests.step);",
        "test_step.dependOn(&native_lifecycle_oracle_tests.step);",
        "native_triggers.addArtifactArg(native_lifecycle_tests);",
        'native_triggers.addArg("--native-helper");',
        "native_triggers.addArtifactArg(native_trigger_helper);",
        "native_triggers.step.dependOn(&native_trigger_oracle_tests.step);",
        "test_step.dependOn(&native_trigger_oracle_tests.step);",
        ".dependOn(&native_lifecycle.step);",
        ".dependOn(&native_triggers.step);",
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
        "support.reference(fixture, dpkg, root",
        "Status: install ok unpacked",
        "Status: install ok half-configured",
        "Triggers-Pending:",
        "Triggers-Awaited:",
        "queue.len != 0",
        "activation-returned",
        "exit 1",
    )
    if not body or any(value not in body for value in required) or "support.native(" in body:
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
        "foundation.captureRealRoot(",
        "support.assertNoActiveEvidence(",
    )) or "refuseUnconfiguredListenerProgram(&fixture, native_driver, selected, reference.executable, reference.architecture)" not in trigger:
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


def audit_ci_pins() -> None:
    for failure in native_lifecycle_migration_failures(
        (ROOT / "build.zig").read_text(),
        (ROOT / "test/native_trigger_acceptance.zig").read_text(),
    ):
        fail(failure)
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
            for failure in native_recovery_ci_failures(text):
                fail(failure)
        expected_ghr_installs = {"ci.yml": 11, "release.yml": 1}.get(workflow.name)
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
        "debz:transaction-journal": ((1, 2, 3), "legacy_dpkg"),
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


if __name__ == "__main__":
    raise SystemExit(main())
