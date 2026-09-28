"""Opt-in source/process inventory for #274; never a shipped-mode gate."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
from collections import Counter
from collections.abc import Callable

INVENTORY = "security/native-only-production-policy.json"
LEGACY_POLICY = "security/legacy-cutover-policy.json"

# These are executable routes or new-artifact writers, not historical parsers.
# Each finding names the deletion/default task; the separate launch scan covers
# changed or newly introduced process APIs even when these markers disappear.
CUTOVER_ROUTES = {
    "src/transaction_executor.zig": (r"pub fn execute\s*\(|fn buildArgv\s*\(", "remove legacy dpkg/dpkg-deb executor (#281)"),
    "src/exact_lock.zig": (r"pub fn create\s*\(", "stop creating exact-lock v1; retain decode/verify (#282)"),
    "src/transaction_provenance.zig": (r"pub fn createFromExecution\s*\(|pub fn createFromRecovery\s*\(", "stop creating legacy result v1; retain verification (#282)"),
    "src/transaction_provenance_v2.zig": (r"pub fn createFromExecution\s*\(|pub fn createFromRecovery\s*\(", "stop creating repository legacy result v2; retain verification (#282)"),
    "src/transaction_recovery.zig": (r"pub fn persist\s*\(|pub fn archive\s*\(|pub fn encode\s*\(", "remove active legacy journal v4 publication/replay; retain v1-v4 decode (#285)"),
    "src/transaction_engine.zig": (r"\.legacy_dpkg\s*=>\s*legacy_dpkg", "remove legacy executor selection (#281)"),
    "src/production_backend.zig": (r"transaction_backend:\s*transaction_engine\.Kind\s*=\s*\.legacy_dpkg", "remove product legacy route/default (#284)"),
    "src/repository_backend.zig": (r"transaction_backend:\s*transaction_engine\.Kind\s*=\s*\.legacy_dpkg", "remove repository legacy route/default (#280)"),
    "src/package_family_backend.zig": (r"if\s*\(arguments\.len\s*==\s*0\)\s*return\s*\.legacy_dpkg", "remove package-family legacy route/default (#284)"),
    "src/package_cache_workflow.zig": (r"pub fn createFingerprint\s*\(|pub fn prepare\s*\(", "stop creating legacy cache v1 contracts; retain historical verification (#282)"),
    "src/transaction_result_summary.zig": (r"pub fn canonicalJson\s*\(", "stop creating legacy result summary v1; retain historical verification (#282)"),
    "src/system_profile.zig": (r"transaction_backend:\s*TransactionBackend\s*=\s*\.legacy_dpkg", "stop executing profile v1/default; retain exact-byte decoder (#282)"),
    "src/main.zig": (r"var transaction_backend:\s*debz\.transaction_engine\.Kind\s*=\s*\.legacy_dpkg", "remove CLI legacy selection/default (#283)"),
    "src/repository_cli.zig": (r"transaction_backend:\s*debz\.transaction_engine\.Kind\s*=\s*\.legacy_dpkg", "remove repository CLI legacy default (#280/#283)"),
    "src/apt_system_orchestrator.zig": (r"transaction_backend:\s*system_profile\.TransactionBackend\s*=\s*\.legacy_dpkg|\.legacy_capable\s*,\s*switch\s*\(loaded\.profile\.transaction_backend\)", "remove apt/root legacy profile execution (#280)"),
    "src/target_apt_config.zig": (r'const argv\s*=\s*\[_\]\[\]const u8\{\s*"/usr/bin/dpkg",\s*"--print-architecture"\s*\}', "replace host-root dpkg architecture probe (#280)"),
    "actions/download/src/inputs.ts": (r"(?:\?\?|\|\|)\s*'legacy_dpkg'", "remove download Action legacy input/default (#283)"),
    "actions/download/src/action.ts": (r"inputs\.transactionBackend\s*===\s*'legacy_dpkg'", "remove download Action legacy dispatch (#283)"),
    "actions/download/src/runner.ts": (r"legacy_dpkg:\s*\{", "remove download Action legacy execution contract (#283)"),
    "actions/download/action.yml": (r"(?m)^\s+default:\s*legacy_dpkg\s*$", "change download Action shipped default (#283)"),
    "actions/install/src/inputs.ts": (r"(?:\?\?|\|\|)\s*'legacy_dpkg'", "remove install Action legacy input/default (#283)"),
    "actions/install/src/action.ts": (r"inputs\.transactionBackend\s*===\s*'legacy_dpkg'", "remove install Action legacy dispatch (#283)"),
    "actions/install/src/subprocess.ts": (r"inputs\.transactionBackend\s*===\s*'legacy_dpkg'", "remove nested download legacy handoff (#283)"),
    "actions/install/src/errors.ts": (r"=\s*'legacy_dpkg'", "remove install Action legacy error default (#283)"),
    "actions/install/src/runner.ts": (r"'io\.github\.cataggar\.debz\.transaction-result-summary\.v1'", "remove install Action legacy execution verifier; retain historical-only verifier if needed (#283)"),
    "actions/install/action.yml": (r"(?m)^\s+default:\s*legacy_dpkg\s*$", "change install Action shipped default (#283)"),
}
GUARD_CUTOVER_ROUTES = {
    "src/root_operation.zig": (
        r"legacy_execution_capable:\s*bool\s*=\s*true",
        "remove root-operation active legacy publication default; retain historical decoder and typed refusal (#279/#285)",
    ),
}
GUARD_PATHS = {
    "src/legacy_compat.zig", "src/native_authorization.zig",
    "src/exact_lock_v2.zig", "src/exact_lock_v3.zig",
    "src/native_transaction_result.zig", "src/native_execution_request.zig",
    "src/native_program.zig", "src/maintainer_script.zig",
    "src/native_unpack.zig", "src/root_operation.zig",
    "src/root_operation_completion.zig",
}
NATIVE_OPERATORS = {
    "src/maintainer_script.zig": {"linux.clone2", "linux.fork", "linux.execve"},
    "src/live_root.zig": {"linux.fork"},
    "actions/setup/src/runner.ts": {"execFileAsync"},
    "actions/download/src/runner.ts": {"execFile"},
    "actions/install/src/subprocess.ts": {"spawn"},
}
LEGACY_OPERATORS = {
    "src/transaction_executor.zig": {"std.process.run"},
    "src/target_apt_config.zig": {"std.process.run"},
}

ZIG_LAUNCH = re.compile(
    r"\bstd\.process\.(?:run|Child(?:Process)?)\s*(?:\(|\.|\{)"
    r"|\b(?:std\.os\.)?linux\.(?:fork|clone2|execve|execveat)\s*\("
    r"|\b(?:std\.os\.)?linux\.syscall[0-9]*\s*\(\s*\.(?:execve|execveat)\s*,"
    r"|\b(?:posix_spawn|execv|execvp|execve|execveat|system|popen)\s*\("
    r"|\b@field\s*\([^;\n]*[\"']execveat[\"']"
)
TS_LAUNCH = re.compile(r"\b(?:spawn|spawnSync|execFile|execFileAsync|execSync|fork)\s*\(")


def read_exact(root: pathlib.Path, relative: str, overrides: dict[str, str | None]) -> str:
    path = pathlib.PurePosixPath(relative)
    if not relative or path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
        raise ValueError("unsafe inventory path")
    if relative in overrides:
        if overrides[relative] is None:
            raise ValueError("missing")
        return overrides[relative]
    descriptor = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not a regular file")
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("exceeds 16 MiB")
    return data.decode("utf-8")


def production_part(relative: str, text: str) -> str:
    if not relative.endswith(".zig"):
        return text
    end = re.search(r'(?m)^test\s+"', text)
    if relative == "src/native_unpack.zig":
        helper = text.find("\nfn testFreshDatabaseInstall(")
        if helper >= 0 and (end is None or helper < end.start()):
            return text[:helper]
    return text[:end.start()] if end else text


def launch_sites(relative: str, text: str) -> Counter[str]:
    pattern = ZIG_LAUNCH if relative.endswith(".zig") else TS_LAUNCH
    sites: Counter[str] = Counter()
    for match in pattern.finditer(production_part(relative, text)):
        line_start = text.rfind("\n", 0, match.start()) + 1
        if text[line_start:match.start()].lstrip().startswith(("//", "*", "\\\\")):
            continue
        token = match.group()
        if "syscall" in token:
            kind = token.split(".")[-1].split(",", 1)[0].strip()
            kind = "syscall." + kind
        elif token.startswith(("linux.", "std.os.linux.")):
            kind = "linux." + token.split(".")[-1].split("(", 1)[0]
        elif token.startswith("std.process."):
            kind = "std.process." + token.split(".")[-1].split("(", 1)[0].split("{", 1)[0]
        else:
            kind = token.split("(", 1)[0]
        sites[kind] += 1
    return sites


def candidate_failures(
    root: pathlib.Path,
    overrides: dict[str, str | None],
    action_check: Callable[[str, dict[str, str]], list[str]],
) -> list[str]:
    failures: list[str] = []
    texts: dict[str, str] = {}

    def source(relative: str) -> str | None:
        if relative not in texts:
            try:
                texts[relative] = read_exact(root, relative, overrides)
            except (OSError, ValueError, UnicodeError) as error:
                failures.append(f"{relative}: missing/unreadable candidate inventory path ({error})")
                return None
        return texts[relative]

    try:
        policy = json.loads(source(LEGACY_POLICY) or "")
        inventory = json.loads(source(INVENTORY) or "")
    except (ValueError, TypeError) as error:
        return [*failures, f"candidate inventory is malformed: {error}"]
    if not isinstance(policy, dict) or not isinstance(inventory, dict):
        return [*failures, "candidate inventories must be objects"]
    if inventory.get("schema") != "https://debz.dev/schema/native-only-production-candidate-v1" or inventory.get("issue") != 276:
        failures.append(f"{INVENTORY}: candidate identity changed")
    removed = inventory.get("removed_production_paths")
    if not isinstance(removed, list) or not all(isinstance(path, str) for path in removed) or len(removed) != len(set(removed)):
        return [*failures, f"{INVENTORY}: missing/malformed cutover deletion inventory"]
    removed_paths = set(removed)
    production = policy.get("production_execution_paths")
    guards = policy.get("compatibility_guard_paths")
    references = policy.get("historical_reference_paths")
    contracts = policy.get("generated_contracts")
    if not all(isinstance(section, list) for section in (production, guards, references, contracts)):
        return [*failures, f"{LEGACY_POLICY}: missing production/guard/reference/generated path inventory"]
    sections = (production, guards, references, contracts)
    if any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("path"), str)
        or not entry["path"]
        or entry["path"].startswith("/")
        or ".." in pathlib.PurePosixPath(entry["path"]).parts
        for section in sections for entry in section
    ):
        return [*failures, f"{LEGACY_POLICY}: malformed or unsafe candidate path classification"]
    production_paths = {entry["path"] for entry in production}
    guard_paths = {entry["path"] for entry in guards}
    reference_paths = {entry["path"] for entry in references}
    contract_paths = {entry["path"] for entry in contracts}
    if sum(map(len, sections)) != len(production_paths | guard_paths | reference_paths | contract_paths):
        failures.append(f"{LEGACY_POLICY}: duplicate/multiply classified candidate path")
    if production_paths & removed_paths or production_paths | removed_paths != set(CUTOVER_ROUTES):
        failures.append(f"{LEGACY_POLICY}: missing/unreviewed candidate production path classification: {sorted((production_paths | removed_paths) ^ set(CUTOVER_ROUTES))}")
    for path in sorted(removed_paths):
        if (root / path).exists() or (root / path).is_symlink():
            failures.append(f"{path}: declared deleted but production path still exists")
    if guard_paths != GUARD_PATHS:
        failures.append(f"{LEGACY_POLICY}: missing/unreviewed compatibility guard paths: {sorted(guard_paths ^ GUARD_PATHS)}")
    if reference_paths != {"tools/native-differential.py", "tools/prepare-native-dpkg.py"}:
        failures.append(f"{LEGACY_POLICY}: reference-only paths must be exact, not a dpkg basename allowance")
    if contract_paths != {"actions/download/dist/index.js", "actions/install/dist/index.js"}:
        failures.append(f"{LEGACY_POLICY}: missing or unclassified generated Actions bundle")
    if any(
        not isinstance(entry.get("role"), str) or not entry["role"]
        or not isinstance(entry.get("cutover"), str) or not entry["cutover"]
        for section in (production, guards) for entry in section
    ) or any(entry.get("retain_after_cutover") is not True for entry in references) or any(
        entry.get("required_evidence") != "backend-capability" for entry in contracts
    ):
        failures.append(f"{LEGACY_POLICY}: missing disposition or generated-contract evidence")
    journal = [
        entry for entry in policy.get("artifact_policy", [])
        if isinstance(entry, dict) and entry.get("schema") == "debz:transaction-journal"
    ] if isinstance(policy.get("artifact_policy"), list) else []
    if len(journal) != 1 or journal[0].get("versions") != [1, 2, 3, 4] or journal[0].get("backend") != "legacy_dpkg":
        failures.append(f"{LEGACY_POLICY}: journal v1-v4 historical legacy decoding is unclassified")
    if production_paths & removed_paths or production_paths | removed_paths != set(CUTOVER_ROUTES) or guard_paths != GUARD_PATHS or reference_paths != {
        "tools/native-differential.py", "tools/prepare-native-dpkg.py",
    } or contract_paths != {"actions/download/dist/index.js", "actions/install/dist/index.js"}:
        return failures

    allowances = inventory.get("launch_allowances")
    fingerprints = inventory.get("reviewed_fingerprints")
    if not isinstance(allowances, dict) or not isinstance(fingerprints, dict):
        return [*failures, f"{INVENTORY}: missing launch allowances or reviewed fingerprints"]
    missing_native = set(NATIVE_OPERATORS) - set(allowances)
    unknown_allowances = set(allowances) - set(NATIVE_OPERATORS) - set(LEGACY_OPERATORS)
    if missing_native or unknown_allowances:
        failures.append(
            f"{INVENTORY}: missing/unknown child-process allowance paths: "
            f"{sorted(missing_native | unknown_allowances)}"
        )
    for path, operators in sorted({**NATIVE_OPERATORS, **LEGACY_OPERATORS}.items()):
        if path in allowances and (
            not isinstance(allowances[path], dict)
            or set(allowances[path]) != operators
        ):
            failures.append(f"{path}: unreviewed child-process operator; no indirect execveat or dpkg basename allowance")
    required_hashes = set(allowances) | reference_paths | contract_paths | {
        "src/main.zig", "src/transaction_recovery.zig", *GUARD_CUTOVER_ROUTES,
    }
    if set(fingerprints) != required_hashes:
        failures.append(f"{INVENTORY}: missing/stale fingerprint path classification: {sorted(set(fingerprints) ^ required_hashes)}")
    allowed_paths = production_paths | guard_paths | reference_paths | contract_paths | {
        "actions/setup/src/runner.ts", "src/live_root.zig", LEGACY_POLICY, INVENTORY,
    }
    if any(path not in allowed_paths for path in overrides):
        failures.append(f"candidate fixture has unknown override path: {sorted(set(overrides) - allowed_paths)}")
    for relative in sorted(production_paths | guard_paths | reference_paths | contract_paths | set(allowances) | set(fingerprints)):
        source(relative)
    for relative, expected in sorted(fingerprints.items()):
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{128}", expected):
            failures.append(f"{INVENTORY}: missing fingerprint for {relative}")
        elif relative in texts and hashlib.sha512(texts[relative].encode()).hexdigest() != expected:
            failures.append(f"{relative}: stale reviewed inventory fingerprint; re-review this exact path")

    exception = inventory.get("signed_script_exception")
    if exception != {
        "path": "src/maintainer_script.zig",
        "identity": "snapshotSudoIdentity",
        "script": "var/lib/dpkg/info/sudo.postinst",
        "tool": "usr/bin/dpkg-query",
    }:
        failures.append(f"{INVENTORY}: signed sudo dpkg-query exception must be exact")
    runner = texts.get("src/maintainer_script.zig", "")
    if not all(token in runner for token in (
        "fn snapshotSudoIdentity(", '"var/lib/dpkg/info/sudo.postinst"',
        'snapshotSudoIdentity(identity, invocation.argv[1..])',
        '.{ .path = "usr/bin/dpkg-query", .size = 142160, .mode = 0o755,',
        "linux.execve(child.program.ptr, child.argv, child.envp)",
    )):
        failures.append("src/maintainer_script.zig: signed sudo query exception lost exact identity/tool/exec binding")

    scoped = [
        *sorted((root / "src").rglob("*.zig")),
        *(path for action in ("setup", "download", "install")
          for path in sorted((root / "actions" / action / "src").rglob("*.ts"))),
    ]
    seen_launches: set[str] = set()
    for path in scoped:
        relative = path.relative_to(root).as_posix()
        text = source(relative)
        if text is None:
            continue
        found = launch_sites(relative, text)
        if relative in allowances:
            seen_launches.add(relative)
            expected = allowances[relative]
            if not isinstance(expected, dict) or not expected or any(
                not isinstance(count, int) or isinstance(count, bool) or count < 1
                for count in expected.values()
            ):
                failures.append(f"{INVENTORY}: invalid/missing child-process allowance for {relative}")
            elif found != Counter(expected):
                failures.append(f"{relative}: unreviewed/stale child-process allowance: expected {expected}, found {dict(found)}")
        elif found:
            failures.append(f"{relative}: unreviewed production child-process launch: {dict(found)}")
    for relative in sorted(set(allowances) - seen_launches):
        failures.append(f"{relative}: missing production child-process allowance path")
    for relative in ("src/transaction_executor.zig", "src/target_apt_config.zig"):
        if relative in allowances and texts.get(relative) is not None and launch_sites(relative, texts[relative]):
            failures.append(f"{relative}: legacy production dpkg/dpkg-deb command adapter remains (#281/#280)")
    executor = production_part("src/transaction_executor.zig", texts.get("src/transaction_executor.zig", ""))
    if re.search(r"pub fn recover\s*\(", executor) and re.search(
        r"(?s)pub fn recover\s*\(.*?dependencies\.process\.run\s*\(", executor,
    ):
        failures.append("src/transaction_executor.zig: active legacy journal recovery still launches dpkg (#285)")

    for relative, (pattern, task) in CUTOVER_ROUTES.items():
        if relative in texts and re.search(pattern, production_part(relative, texts[relative])):
            failures.append(f"{relative}: candidate cutover task: {task}")
    for relative, (pattern, task) in GUARD_CUTOVER_ROUTES.items():
        if relative in texts and re.search(pattern, production_part(relative, texts[relative])):
            failures.append(f"{relative}: candidate cutover task: {task}")
    for action in ("download", "install"):
        paths = [
            f"actions/{action}/{item}" for item in (
                "action.yml", "src/inputs.ts", "src/action.ts", "src/runner.ts",
                "dist/index.js", *(("src/subprocess.ts",) if action == "install" else ()),
            )
        ]
        if all(path in texts for path in paths):
            failures.extend(action_check(action, {path: texts[path] for path in paths}))
    return failures
