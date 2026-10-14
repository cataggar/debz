#!/usr/bin/env python3
"""Read-only checks for tools/system-install-live-proof.sh on a disposable hosted runner.

prestate ARCH            the healthy installed-database contract debz plans against
snapshot                 a listing of /var/lib/dpkg that must never change
repo-add OUT DESCRIPTOR ARCH
                         the pinned descriptor and its APT configuration snapshot
verify OUT ARCH          every install run, its exact evidence chain and the cache

Run as root: the evidence, locks and package cache are root-only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys

ROOT = "/"
DPKG = "var/lib/dpkg"
STATUS = DPKG + "/status"
STATE = "var/lib/debz"
EVIDENCE = STATE + "/system-install"
OPERATIONS = EVIDENCE + "/operations"
LOCKS = STATE + "/locks"
CACHE = "var/cache/debz"
LOGICAL_ROOT = "/run/debz/system-root"
SCHEMA = "https://debz.dev/schema/"
GENERATION = "system-install-execution-v1"
BOUND = 1209600
MICROSOFT = {
    "uri": "https://packages.microsoft.com/ubuntu/24.04/prod",
    "suite": "noble",
    "component": "main",
}
SIGNER = "BC528686B50D79E339D3721CEB3E94ADBE1229CF"
SOURCE = "/etc/apt/sources.list.d/microsoft-prod.list"
KEYRING = "/usr/share/keyrings/microsoft-prod.gpg"
DERIVED = "signed_sha256_derived_sha512"
CLASS_TEXT = {
    DERIVED: "signed SHA-256; SHA-512 derived locally from the signed SHA-256 match "
    "(derived_from_signed_sha256; not independently signed)",
    "signed_sha256_only": "signed SHA-256 only; no SHA-512 published by the signed index",
}
PRIVILEGE = "system install requires root privilege (run with sudo); nothing was changed"
ABSENT_PACKAGE = "debz-live-proof-absent"
ABSENT = "package has no available candidate; nothing was changed"
PENDING = GENERATION + " is not available in this build; nothing was changed; the exact lock is retained"
EXPECTED_ARCHIVES = {
    "symcrypt": [("symcrypt", "requested")],
    "symcrypt-openssl": [("symcrypt", "dependency"), ("symcrypt-openssl", "requested")],
}
PLANNED_FILES = {"request-v1.json", "progress-v1.json", "program-v1.json", "authorization-v1.json", "receipt-v1.json"}
REJECTED_FILES = {"request-v1.json", "progress-v1.json", "receipt-v1.json"}
SNAPSHOT_EXCLUDED = {DPKG + "/lock", DPKG + "/lock-frontend", DPKG + "/triggers/Lock"}
SHA512_HEX = hashlib.sha512().digest_size * 2
MIB = 1024 * 1024
FILE_LIMIT = 64 * MIB
TREE_LIMIT = 256 * MIB
ENVELOPE = re.compile(rb'\{"payload":(.*),"digest_sha512":"([0-9a-f]+)"\}', re.S)
LOWER_HEX = re.compile(r"[0-9a-f]+")


class ProofFailure(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise ProofFailure(message)


def host(relative: str) -> str:
    return os.path.join(ROOT, relative.lstrip("/"))


def read_bytes(relative: str) -> bytes:
    with open(host(relative), "rb") as handle:
        return handle.read()


def sha512_value(value: object) -> bool:
    return isinstance(value, str) and len(value) == SHA512_HEX and LOWER_HEX.fullmatch(value) is not None


def paragraphs(text: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    name = None
    for line in text.split("\n"):
        if not line.strip():
            if fields:
                result.append(fields)
            fields, name = {}, None
            continue
        if line[0] in " \t":
            require(name is not None, "status continuation line without a field")
            fields[name] += "\n" + line
            continue
        key, separator, value = line.partition(":")
        require(separator == ":", f"malformed status line {line!r}")
        name = key.strip().lower()
        fields[name] = value.strip()
    if fields:
        result.append(fields)
    return result


def status_packages(text: str) -> list[dict[str, str]]:
    packages = []
    for fields in paragraphs(text):
        words = fields.get("status", "").split()
        require(len(words) == 3, f"status stanza without want/flag/current: {fields.get('package')!r}")
        packages.append(
            {
                "name": fields.get("package", ""),
                "version": fields.get("version", ""),
                "architecture": fields.get("architecture", ""),
                "want": words[0],
                "flag": words[1],
                "current": words[2],
                "triggers": fields.get("triggers-pending", "") + fields.get("triggers-awaited", ""),
            }
        )
    return packages


def health_problems(packages: list[dict[str, str]]) -> list[str]:
    problems = []
    for package in packages:
        label = f"{package['name']}:{package['architecture']} {package['want']} {package['flag']} {package['current']}"
        if package["flag"] != "ok":
            problems.append(f"{label}: error flag")
        elif package["current"] == "installed":
            if package["want"] not in ("install", "hold"):
                problems.append(f"{label}: installed without install or hold selection")
        elif package["current"] != "config-files" or package["want"] not in ("deinstall", "purge"):
            problems.append(f"{label}: unfinished state")
        if package["triggers"].strip():
            problems.append(f"{label}: pending or awaited triggers")
    return problems


def installed_facts(packages: list[dict[str, str]]) -> list[dict[str, str]]:
    facts = [
        {
            "name": package["name"],
            "version": package["version"],
            "architecture": package["architecture"],
            "selection": package["want"],
        }
        for package in packages
        if package["flag"] == "ok" and package["current"] == "installed"
    ]
    return sorted(facts, key=lambda fact: (fact["name"].encode(), fact["architecture"].encode()))


def walk(relative: str, depth: int = 0):
    info = os.lstat(host(relative))
    yield relative, info, depth
    if stat.S_ISDIR(info.st_mode):
        for name in sorted(os.listdir(host(relative)), key=os.fsencode):
            yield from walk(relative + "/" + name, depth + 1)


def tree_problems() -> tuple[list[str], dict[str, int]]:
    owner = os.lstat(ROOT).st_uid
    problems: list[str] = []
    totals = {"entries": 0, "files": 0, "bytes": 0, "depth": 0}
    for relative, info, depth in walk(DPKG):
        totals["entries"] += 1
        totals["depth"] = max(totals["depth"], depth)
        if depth > 32 or len(relative) > 4096:
            problems.append(f"{relative}: deeper or longer than the baseline limits")
        if info.st_uid != owner or info.st_mode & 0o022:
            problems.append(f"{relative}: not root owned or group/other writable")
        if stat.S_ISDIR(info.st_mode):
            if relative == DPKG + "/updates" and os.listdir(host(relative)):
                problems.append(f"{relative}: pending dpkg updates")
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            problems.append(f"{relative}: not a singly linked regular file")
            continue
        totals["files"] += 1
        totals["bytes"] += info.st_size
        if info.st_size > FILE_LIMIT:
            problems.append(f"{relative}: larger than the per-file baseline limit")
        if relative == DPKG + "/triggers/Unincorp" and read_bytes(relative).strip():
            problems.append(f"{relative}: unincorporated triggers")
    if totals["entries"] > 200_000 or totals["files"] > 100_000 or totals["bytes"] > TREE_LIMIT:
        problems.append("the dpkg database exceeds the baseline entry, file or byte limits")
    return problems, totals


def command_prestate(arch: str) -> int:
    packages = status_packages(read_bytes(STATUS).decode())
    problems = health_problems(packages)
    tree, totals = tree_problems()
    problems += tree
    facts = installed_facts(packages)
    architectures = {}
    for name in ("arch", "arch-native"):
        if os.path.isfile(host(DPKG + "/" + name)):
            architectures[name] = read_bytes(DPKG + "/" + name).decode().split()
    report = {
        "architecture": arch,
        "healthy": not problems,
        "problems": problems,
        "status_stanzas": len(packages),
        "installed_facts": len(facts),
        "held": [fact for fact in facts if fact["selection"] == "hold"],
        "dpkg_architectures": architectures,
        "tree": totals,
    }
    json.dump(report, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if not problems else 1


def file_sha512(path: str) -> str:
    digest = hashlib.sha512()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def command_snapshot() -> int:
    lines = []
    for relative, info, _ in walk(DPKG):
        if relative in SNAPSHOT_EXCLUDED:
            continue
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            entry = ["directory", mode, info.st_uid, info.st_gid, 0, info.st_mtime_ns, "", relative]
        elif stat.S_ISREG(info.st_mode):
            entry = ["file", mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, file_sha512(host(relative)), relative]
        elif stat.S_ISLNK(info.st_mode):
            entry = ["symlink", mode, info.st_uid, info.st_gid, 0, info.st_mtime_ns, os.readlink(host(relative)), relative]
        else:
            entry = ["other", mode, info.st_uid, info.st_gid, 0, info.st_mtime_ns, "", relative]
        lines.append(json.dumps(entry))
    sys.stdout.write("".join(line + "\n" for line in sorted(lines)))
    return 0


def captured(out: str, name: str) -> tuple[str, str, int]:
    with open(os.path.join(out, name + ".stdout"), encoding="utf-8") as handle:
        stdout = handle.read()
    with open(os.path.join(out, name + ".stderr"), encoding="utf-8") as handle:
        stderr = handle.read()
    with open(os.path.join(out, name + ".exit"), encoding="utf-8") as handle:
        status = int(handle.read())
    return stdout, stderr, status


def command_repo_add(out: str, descriptor: str, arch: str) -> int:
    stdout, _, status = captured(out, "repo-add")
    require(status == 0, f"repo add exited {status}")
    result = json.loads(stdout)
    for key, expected in (("exit_status", 0), ("installed", True), ("refreshed", True), ("refreshed_phase", "complete")):
        require(result.get(key) == expected, f"repo add {key}: {result.get(key)!r}, expected {expected!r}")
    require(result["descriptor"]["sha256"] == descriptor, "repo add installed an unreviewed descriptor")
    raw = read_bytes(result["paths"]["target_manifest"])
    snapshot = json.loads(raw)
    require(snapshot.get("schema") == SCHEMA + "apt-config-snapshot-v3" and snapshot.get("version") == 3,
            "the APT configuration snapshot is not version 3")
    require(snapshot["native_architecture"] == arch, "the snapshot names another native architecture")
    bounded = {"mode": "allow_missing_valid_until_with_max_age_seconds", "maximum_release_age_seconds": BOUND}
    sources = snapshot["sources"]
    require(len(sources) == 1, f"expected only the reviewed Microsoft source, found {len(sources)}")
    source = sources[0]
    require(source["logical_path"] == SOURCE and source["format"] == "legacy", f"unexpected source {source!r}")
    require(source["freshness"] == bounded, f"the Microsoft source lost its explicit {BOUND} s bound")
    require(source["archive_binding"] == DERIVED, "the Microsoft source is not the reviewed derived SHA-512 opt-in")
    policies = snapshot["repository_policies"]
    require(policies, "no repository policy was recorded")
    for policy in policies:
        require(policy["freshness"] == bounded and policy["archive_binding"] == DERIVED,
                f"unexpected repository policy {policy!r}")
    require(sorted(policy["repository_id"] for policy in policies) == sorted(snapshot["repository_ids"]),
            "repository policies do not cover exactly the configured repositories")
    keyrings = [keyring for keyring in snapshot["keyrings"] if keyring["logical_path"] == KEYRING]
    require(len(keyrings) == 1, "the Microsoft keyring is not recorded")
    require(keyrings[0]["primary_fingerprints"] == [SIGNER.lower()], "the Microsoft keyring names another signer")
    require(keyrings[0]["use"] in ("declared", "declared_and_global"), "the Microsoft keyring is not declared")
    sys.stdout.write(raw.decode())
    return 0


def envelope(relative: str) -> tuple[dict, str]:
    data = read_bytes(relative)
    match = ENVELOPE.fullmatch(data)
    require(match is not None, f"{relative}: not a digest envelope")
    payload_bytes, recorded = match.group(1), match.group(2).decode()
    require(sha512_value(recorded) and hashlib.sha512(payload_bytes).hexdigest() == recorded,
            f"{relative}: the envelope digest does not cover its payload")
    payload = json.loads(payload_bytes)
    require(json.loads(data) == {"payload": payload, "digest_sha512": recorded}, f"{relative}: unexpected envelope")
    return payload, recorded


def request_sha512(package: str, backend: str) -> str:
    return hashlib.sha512(b"debz system install request v1\x00" + package.encode() + b"\x00" + backend.encode() + b"\x00/").hexdigest()


def profile(arch: str) -> dict:
    return {
        "name": "system_default",
        "root": "/",
        "cache_path": "/var/cache/debz",
        "state_path": "/var/lib/debz",
        "locks_path": "/var/lib/debz/locks",
        "evidence_path": "/var/lib/debz/system-install",
        "architecture": arch,
        "conffile": "keep_existing",
        "noninteractive": True,
    }


def freshness_text(freshness: dict) -> str:
    require(freshness == {"policy": "bounded_missing_valid_until", "maximum_release_age_seconds": BOUND},
            f"unexpected repository freshness {freshness!r}")
    return f"missing Valid-Until accepted for at most {BOUND} s (explicit repository bound)"


def render(result: dict) -> str:
    """The human report system_install.render writes for a failed run."""
    lines = [f"install: {result['summary']}"]
    if "attempt_id" in result:
        lines.append(f"attempt: {result['attempt_id']}" + (" (resumed)" if result["resumed"] else ""))
    if "backend" in result:
        lines.append(f"backend: {result['backend']}")
    if "lock" in result:
        lines.append(f"exact lock: {result['lock']}")
    if "evidence_path" in result:
        lines.append(f"evidence: {result['evidence_path']}")
    plan = result.get("plan")
    if plan is not None:
        lines.append(f"actions ({len(plan['archives'])}):")
        for archive in plan["archives"]:
            lines.append(
                f"  install {archive['package']} {archive['version']} [{archive['architecture']}] "
                f"{archive['retention']}: {CLASS_TEXT[archive['archive_authentication']]}"
            )
        for repository in plan["repositories"]:
            lines.append(
                f"repository {repository['uri']} {repository['suite']} {repository['component']}: "
                + freshness_text(repository["freshness"])
            )
        lines.append(
            f"installed facts: {plan['installed']['fact_count']} from the healthy installed package database "
            "(no archive origin)"
        )
        for fact in plan["installed"]["held"]:
            lines.append(f"  held {fact['name']} {fact['version']} [{fact['architecture']}] (no archive origin)")
    for diagnostic in result["diagnostics"]:
        lines.append(f"debz[{diagnostic['id']}]: {diagnostic['message']}")
    return "".join(line + "\n" for line in lines)


class Cache:
    """Regular files under /var/cache/debz, hashed on demand."""

    def __init__(self) -> None:
        self.by_size: dict[int, list[str]] = {}
        for directory, _, names in os.walk(host(CACHE)):
            for name in names:
                path = os.path.join(directory, name)
                info = os.lstat(path)
                if stat.S_ISREG(info.st_mode):
                    self.by_size.setdefault(info.st_size, []).append(path)
        self.hashed: dict[str, tuple[str, str]] = {}

    def matches(self, size: int, signed: str) -> list[str]:
        derived = []
        for path in self.by_size.get(size, []):
            if path not in self.hashed:
                with open(path, "rb") as handle:
                    data = handle.read()
                self.hashed[path] = (hashlib.sha256(data).hexdigest(), hashlib.sha512(data).hexdigest())
            if self.hashed[path][0] == signed:
                derived.append(self.hashed[path][1])
        return derived


class Verifier:
    def __init__(self, out: str, arch: str) -> None:
        self.out = out
        self.arch = arch
        self.packages = status_packages(read_bytes(STATUS).decode())
        require(not health_problems(self.packages), "the installed package database is not healthy")
        self.facts = installed_facts(self.packages)
        self.cache = Cache()
        self.attempts: list[str] = []
        self.locks: set[str] = set()
        self.signed: dict[tuple[str, str, str], str] = {}
        self.derived: dict[tuple[str, str, str], str] = {}
        self.databases: set[str] = set()
        self.reports: list[dict] = []

    def run(self, name: str, user: str, output: str, backend: str, package: str) -> None:
        stdout, stderr, status = captured(os.path.join(self.out, "runs"), name)
        require("upstream" not in (stdout + stderr).lower(), f"{name}: output mentions an upstream digest")
        if output == "json":
            require(stderr == "", f"{name}: unexpected stderr {stderr!r}")
            require(stdout.endswith("\n") and stdout.count("\n") == 1, f"{name}: not one JSON line")
            result = json.loads(stdout)
        else:
            require(stdout == "", f"{name}: a refused human run wrote stdout")
            result = None
        backend = "legacy_dpkg" if backend == "default" else backend
        if user != "root":
            self.unprivileged(name, result, status, package)
            return
        if output == "json":
            attempt = result.get("attempt_id", "")
        else:
            found = re.search(r"^attempt: ([0-9a-f]+)$", stderr, re.M)
            require(found is not None, f"{name}: the human report names no attempt")
            attempt = found.group(1)
        require(re.fullmatch(r"[0-9a-f]{32}", attempt) is not None, f"{name}: invalid attempt id {attempt!r}")
        require(attempt not in self.attempts, f"{name}: attempt {attempt} was reused")
        self.attempts.append(attempt)
        if package == ABSENT_PACKAGE:
            expected = self.absent(name, attempt, backend, package, status)
        else:
            expected = self.planned(name, attempt, backend, package, status)
        if result is not None:
            require(result == expected, f"{name}: the JSON result differs from its evidence")
        else:
            require(stderr == render(expected), f"{name}: the human report differs from its evidence")
        self.reports.append({"name": name, "exit_status": status, "outcome": expected["outcome"], "attempt_id": attempt,
                             "backend": backend, "package": package,
                             "archives": [self.describe(archive) for archive in expected.get("plan", {}).get("archives", [])]})

    @staticmethod
    def describe(archive: dict) -> dict:
        return {
            "package": archive["package"],
            "version": archive["version"],
            "architecture": archive["architecture"],
            "retention": archive["retention"],
            "archive_authentication": archive["archive_authentication"],
            "signed_sha256": archive["published_digests"][0]["value"],
            "derived_sha512": archive.get("derived_sha512"),
        }

    def unprivileged(self, name: str, result: dict | None, status: int, package: str) -> None:
        require(status == 3, f"{name}: exited {status}, expected 3")
        require(result == {
            "schema": SCHEMA + "system-install-result-v1",
            "version": 1,
            "operation": "install",
            "exit_status": 3,
            "outcome": "rejected",
            "changed": False,
            "package": package,
            "summary": PRIVILEGE,
            "resumed": False,
            "documents": [],
            "diagnostics": [{"id": "transaction_backend_unavailable", "message": PRIVILEGE}],
        }, f"{name}: unexpected unprivileged result {result!r}")
        self.reports.append({"name": name, "exit_status": status, "outcome": "rejected", "package": package})

    def chain(self, attempt: str, backend: str, package: str, files: set[str]) -> tuple[dict, str, dict, str]:
        operation = f"{OPERATIONS}/{attempt}"
        require(set(os.listdir(host(operation))) == files, f"{operation}: unexpected documents")
        command = f"debz install --transaction-backend {backend} {package}"
        request, request_digest = envelope(f"{operation}/request-v1.json")
        require(request == {
            "schema": SCHEMA + "system-install-request-v1",
            "version": 1,
            "attempt_id": attempt,
            "operation": "install",
            "package": package,
            "backend": backend,
            "profile": profile(self.arch),
            "command": command,
            "request_sha512": request_sha512(package, backend),
        }, f"{operation}: unexpected request {request!r}")
        progress, progress_digest = envelope(f"{operation}/progress-v1.json")
        require(sha512_value(progress.get("previous_progress_sha512")), f"{operation}: progress is not chained")
        return progress, progress_digest, {"command": command, "operation": operation}, request_digest

    def documents(self, attempt: str, digests: list[tuple[str, str]]) -> list[dict]:
        paths = {"lock": f"/{LOCKS}/install-{attempt}.json"}
        return [
            {"kind": kind, "path": paths.get(kind, f"/{OPERATIONS}/{attempt}/{kind}-v1.json"), "document_sha512": value}
            for kind, value in digests
        ]

    def absent(self, name: str, attempt: str, backend: str, package: str, status: int) -> dict:
        require(status == 5, f"{name}: exited {status}, expected 5")
        progress, progress_digest, context, request_digest = self.chain(attempt, backend, package, REJECTED_FILES)
        require(not os.path.exists(host(f"{LOCKS}/install-{attempt}.json")), f"{name}: a refused plan published a lock")
        terminal = {"outcome": "rejected", "changed": False, "exit_status": 5, "id": "planning_failed", "message": ABSENT}
        progress.pop("previous_progress_sha512")
        require(progress == {
            "schema": SCHEMA + "system-install-progress-v1",
            "version": 1,
            "attempt_id": attempt,
            "generation": 2,
            "request_document_sha512": request_digest,
            "phase": "terminal",
            "terminal": terminal,
        }, f"{name}: unexpected progress {progress!r}")
        receipt, receipt_digest = envelope(f"{context['operation']}/receipt-v1.json")
        require(receipt == {
            "schema": SCHEMA + "system-install-receipt-v1",
            "version": 1,
            "attempt_id": attempt,
            "request_document_sha512": request_digest,
            "progress_document_sha512": progress_digest,
            "terminal": terminal,
        }, f"{name}: unexpected receipt {receipt!r}")
        return {
            "schema": SCHEMA + "system-install-result-v1",
            "version": 1,
            "operation": "install",
            "exit_status": 5,
            "outcome": "rejected",
            "changed": False,
            "package": package,
            "summary": ABSENT,
            "backend": backend,
            "command": context["command"],
            "attempt_id": attempt,
            "resumed": False,
            "profile": profile(self.arch),
            "evidence_path": "/" + context["operation"],
            "documents": self.documents(attempt, [
                ("request", request_digest), ("progress", progress_digest), ("receipt", receipt_digest)]),
            "diagnostics": [{"id": "planning_failed", "message": ABSENT}],
        }

    def planned(self, name: str, attempt: str, backend: str, package: str, status: int) -> dict:
        require(status == 3, f"{name}: exited {status}, expected 3")
        progress, progress_digest, context, request_digest = self.chain(attempt, backend, package, PLANNED_FILES)
        operation = context["operation"]
        lock_relative = f"{LOCKS}/install-{attempt}.json"
        lock_bytes = read_bytes(lock_relative)
        lock_reference = {"path": lock_relative, "document_sha512": hashlib.sha512(lock_bytes).hexdigest()}
        lock, _ = envelope(lock_relative)
        self.locks.add(os.path.basename(lock_relative))
        program, program_digest = envelope(f"{operation}/program-v1.json")
        authorization, authorization_digest = envelope(f"{operation}/authorization-v1.json")
        receipt, receipt_digest = envelope(f"{operation}/receipt-v1.json")
        summary = f"{package} is planned and authorized by exact lock /{lock_relative}; {PENDING}"
        terminal = {"outcome": "refused_before_mutation", "changed": False, "exit_status": 3,
                    "id": "transaction_backend_unavailable", "message": summary}
        progress.pop("previous_progress_sha512")
        require(progress == {
            "schema": SCHEMA + "system-install-progress-v1",
            "version": 1,
            "attempt_id": attempt,
            "generation": 4,
            "request_document_sha512": request_digest,
            "phase": "terminal",
            "lock": lock_reference,
            "program_document_sha512": program_digest,
            "authorization_document_sha512": authorization_digest,
            "terminal": terminal,
        }, f"{name}: unexpected progress {progress!r}")
        require(receipt == {
            "schema": SCHEMA + "system-install-receipt-v1",
            "version": 1,
            "attempt_id": attempt,
            "request_document_sha512": request_digest,
            "progress_document_sha512": progress_digest,
            "terminal": terminal,
            "lock": lock_reference,
            "program_document_sha512": program_digest,
            "authorization_document_sha512": authorization_digest,
        }, f"{name}: unexpected receipt {receipt!r}")
        require(authorization == {
            "schema": SCHEMA + "system-install-authorization-v1",
            "version": 1,
            "authority": "system_install_invocation",
            "attempt_id": attempt,
            "command": context["command"],
            "request_document_sha512": request_digest,
            "program_document_sha512": program_digest,
            "lock": lock_reference,
            "backend": backend,
            "conffile": "keep_existing",
            "noninteractive": True,
            "execution_generation": GENERATION,
        }, f"{name}: unexpected authorization {authorization!r}")
        archives, repositories = self.program(name, program, attempt, backend, package, request_digest, lock_reference)
        facts = program["installed"]["facts"]
        self.lock(name, lock, backend, program, facts)
        held = [fact for fact in facts if fact["selection"] == "hold"]
        return {
            "schema": SCHEMA + "system-install-result-v1",
            "version": 1,
            "operation": "install",
            "exit_status": 3,
            "outcome": "refused_before_mutation",
            "changed": False,
            "package": package,
            "summary": summary,
            "backend": backend,
            "command": context["command"],
            "attempt_id": attempt,
            "resumed": False,
            "profile": profile(self.arch),
            "lock": "/" + lock_relative,
            "evidence_path": "/" + operation,
            "documents": self.documents(attempt, [
                ("request", request_digest), ("progress", progress_digest), ("lock", lock_reference["document_sha512"]),
                ("program", program_digest), ("authorization", authorization_digest), ("receipt", receipt_digest)]),
            "plan": {
                "target_architecture": self.arch,
                "archives": archives,
                "installed": {
                    "authority": "healthy_installed_prestate",
                    "origin": "installed_package_database",
                    "database_sha512": program["installed"]["database_sha512"],
                    "fact_count": len(facts),
                    "held": held,
                },
                "repositories": repositories,
            },
            "diagnostics": [{"id": "transaction_backend_unavailable", "message": summary}],
        }

    def program(self, name: str, program: dict, attempt: str, backend: str, package: str,
                request_digest: str, lock_reference: dict) -> tuple[list, list]:
        native = backend == "native"
        binding = DERIVED if native else "published_digests"
        repositories = program["repositories"]
        require(repositories, f"{name}: the program names no repository")
        for repository in repositories:
            require(LOWER_HEX.fullmatch(repository["id"]) is not None, f"{name}: invalid repository id")
            require(repository == {"id": repository["id"], **MICROSOFT, "archive_binding": binding,
                                   "signers": [SIGNER], "freshness": {"policy": "bounded_missing_valid_until",
                                                                       "maximum_release_age_seconds": BOUND}},
                    f"{name}: unexpected repository authority {repository!r}")
        identities = {repository["id"] for repository in repositories}
        archives = program["archives"]
        require([(archive["package"], archive["retention"]) for archive in archives] == EXPECTED_ARCHIVES[package],
                f"{name}: unexpected archive closure {archives!r}")
        for archive in archives:
            require(archive["architecture"] in (self.arch, "all") and archive["version"], f"{name}: unexpected archive")
            require(archive["repository_id"] in identities, f"{name}: an archive names an unlisted repository")
            require(archive["dpkg_selection_hold"] is False and archive["declared_size"] > 0, f"{name}: unexpected archive")
            published = archive["published_digests"]
            require(len(published) == 1 and published[0]["algorithm"] == "sha256" and archive["primary"] == "sha256",
                    f"{name}: the signed index should publish only SHA-256 for {archive['package']}")
            signed = published[0]["value"]
            key = (archive["package"], archive["version"], archive["architecture"])
            require(self.signed.setdefault(key, signed) == signed, f"{name}: {key} changed its signed SHA-256")
            if native:
                derived = archive.get("derived_sha512")
                require(archive["archive_authentication"] == DERIVED and isinstance(derived, dict)
                        and set(derived) == {"value", "provenance"}
                        and derived["provenance"] == "derived_from_signed_sha256"
                        and sha512_value(derived["value"]), f"{name}: {key} is not derived_from_signed_sha256")
                require(self.derived.setdefault(key, derived["value"]) == derived["value"],
                        f"{name}: {key} changed its derived SHA-512")
                found = self.cache.matches(archive["declared_size"], signed)
                require(found, f"{name}: no cached archive matches the signed SHA-256 of {key}")
                require(all(value == derived["value"] for value in found),
                        f"{name}: the derived SHA-512 of {key} is not over the signed SHA-256 bytes")
            else:
                require(archive["archive_authentication"] == "signed_sha256_only" and "derived_sha512" not in archive,
                        f"{name}: the legacy plan of {key} claims a SHA-512")
        planned = {(archive["package"], archive["architecture"]) for archive in archives}
        facts = [fact for fact in self.facts if (fact["name"], fact["architecture"]) not in planned]
        installed = program["installed"]
        require(sha512_value(installed.get("database_sha512")), f"{name}: no installed database identity")
        self.databases.add(installed["database_sha512"])
        require(installed == {
            "authority": "healthy_installed_prestate",
            "origin": "installed_package_database",
            "database_sha512": installed["database_sha512"],
            "facts": facts,
        }, f"{name}: the program's installed facts differ from /var/lib/dpkg/status")
        require(program == {
            "schema": SCHEMA + "system-install-program-v1",
            "version": 1,
            "attempt_id": attempt,
            "request_document_sha512": request_digest,
            "lock": lock_reference,
            "backend": backend,
            "target_architecture": self.arch,
            "execution_generation": GENERATION,
            "archives": archives,
            "installed": installed,
            "repositories": repositories,
        }, f"{name}: unexpected program fields")
        return archives, repositories

    def lock(self, name: str, lock: dict, backend: str, program: dict, facts: list) -> None:
        require(lock.get("schema") == SCHEMA + "exact-closure-lock-v5" and lock.get("version") == 5,
                f"{name}: the exact lock is not version 5")
        require(lock["backend"] == backend and lock["usage"] == "healthy_prestate_planning_only",
                f"{name}: the exact lock names another backend or usage")
        prestate = lock["installed_prestate"]
        require(prestate.get("schema") == SCHEMA + "healthy-installed-prestate-v1"
                and prestate.get("authority") == "healthy_installed_prestate", f"{name}: no healthy prestate")
        observed = prestate["observed"]
        require(observed["root_path"] == LOGICAL_ROOT and observed["native_architecture"] == self.arch,
                f"{name}: the prestate names another root or architecture")
        require(observed["database_identity"] == {"algorithm": "sha512",
                                                  "value": program["installed"]["database_sha512"]},
                f"{name}: the lock and program bind different installed databases")
        require(observed["packages"] == facts, f"{name}: the lock and program bind different installed facts")
        archive_lock = json.loads(lock["archive_lock_json"])
        require(archive_lock["schema"] == SCHEMA + "exact-closure-lock-v3" and archive_lock["version"] == 3,
                f"{name}: the archive closure is not an exact v3 lock")
        require(archive_lock["target_architecture"] == self.arch and archive_lock["local_artifacts"] == [],
                f"{name}: unexpected archive closure scope")
        locked = {repository["id"]: repository for repository in archive_lock["repositories"]}
        require(sorted(locked) == [repository["id"] for repository in program["repositories"]],
                f"{name}: the lock and program name different repositories")
        for repository in program["repositories"]:
            entry = locked[repository["id"]]
            require(entry.get("archive_binding", "published_digests") == repository["archive_binding"],
                    f"{name}: the lock and program bind {repository['id']} differently")
            require([value.upper() for value in entry["signer_fingerprints"]] == repository["signers"],
                    f"{name}: the lock and program name different signers")
        packages = archive_lock["packages"]
        require(len(packages) == len(program["archives"]), f"{name}: the lock and program differ in size")
        for entry, archive in zip(packages, program["archives"]):
            signed = archive["published_digests"][0]["value"]
            require(entry["name"] == archive["package"] and entry["version"] == archive["version"]
                    and entry["architecture"] == archive["architecture"]
                    and entry["retention"] == archive["retention"]
                    and entry["declared_size"] == archive["declared_size"]
                    and entry["dpkg_selection_hold"] == archive["dpkg_selection_hold"]
                    and entry["origin"]["type"] == "authenticated_repository"
                    and entry["origin"]["repository_id"] == archive["repository_id"]
                    and entry["archive_identity"] == {"primary": "sha256",
                                                      "digests": [{"algorithm": "sha256", "digest": signed}]},
                    f"{name}: the lock and program differ for {archive['package']}")
            derived = archive.get("derived_sha512")
            if derived is None:
                require("derived_archive_identity" not in entry, f"{name}: the legacy lock records a SHA-512")
            else:
                require(entry.get("derived_archive_identity") == {"provenance": "derived_from_signed_sha256",
                                                                  "algorithm": "sha512",
                                                                  "digest": derived["value"]},
                        f"{name}: the lock and program differ in the derived SHA-512 of {archive['package']}")

    def finish(self, root_runs: int) -> dict:
        require(not os.path.exists(host(EVIDENCE + "/active-v1.json")), "an owned attempt was left unsettled")
        require(len(self.attempts) == root_runs, "a root run left no attempt")
        require(sorted(os.listdir(host(OPERATIONS))) == sorted(self.attempts),
                "the evidence directory holds attempts no run reported")
        published = {name for name in os.listdir(host(LOCKS)) if name.startswith("install-") and name.endswith(".json")}
        require(published == self.locks, "the locks directory holds install locks no planned run reported")
        return {
            "architecture": self.arch,
            "runs": self.reports,
            "installed_facts": len(self.facts),
            "held": [fact for fact in self.facts if fact["selection"] == "hold"],
            "database_identities": sorted(self.databases),
            "archive_identities": [
                {"package": key[0], "version": key[1], "architecture": key[2], "signed_sha256": value,
                 "derived_sha512": self.derived.get(key)}
                for key, value in sorted(self.signed.items())
            ],
        }


def command_verify(out: str, arch: str) -> int:
    verifier = Verifier(out, arch)
    root_runs = 0
    with open(os.path.join(out, "runs", "index"), encoding="utf-8") as handle:
        for line in handle:
            name, user, output, backend, package = line.split()
            verifier.run(name, user, output, backend, package)
            root_runs += user == "root"
    json.dump(verifier.finish(root_runs), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def main(arguments: list[str]) -> int:
    commands = {
        ("prestate", 1): command_prestate,
        ("snapshot", 0): command_snapshot,
        ("repo-add", 3): command_repo_add,
        ("verify", 2): command_verify,
    }
    if not arguments or (arguments[0], len(arguments) - 1) not in commands:
        sys.stderr.write(__doc__)
        return 2
    try:
        return commands[(arguments[0], len(arguments) - 1)](*arguments[1:])
    except (ProofFailure, KeyError, OSError, ValueError) as error:
        sys.stderr.write(f"system-install-live-proof: {type(error).__name__}: {error}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
