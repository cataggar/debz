#!/usr/bin/env python3
"""Repository-local, network-free security and policy audit."""

from __future__ import annotations

import pathlib
import re
import json
import subprocess
import sys
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def tracked_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


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
    process_calls: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.zig")):
        text = path.read_text(errors="strict")
        relative = str(path.relative_to(ROOT))
        first_test = text.find('\ntest "')
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
                line = text.count("\n", 0, match.start()) + 1
                fail(f"{relative}:{line}: forbidden {reason}")
        for match in re.finditer(r"\bstd\.process\.run\s*\(", text):
            process_calls.append(f"{relative}:{text.count(chr(10), 0, match.start()) + 1}")
    if len(process_calls) != 1 or not process_calls[0].startswith("src/transaction_executor.zig:"):
        fail(f"production process boundary changed: {process_calls!r}")


def audit_dependencies() -> None:
    policy = json.loads((ROOT / "security/dependency-policy.json").read_text())
    reviewed_on = date.fromisoformat(policy["reviewed_on"])
    if reviewed_on > date.today():
        fail("dependency review date is in the future")
    if date.today() > date.fromisoformat(policy["review_expires"]):
        fail("dependency vulnerability/license review has expired")
    allowed_licenses = set(policy["allowed_production_licenses"])
    dependencies = {item["name"]: item for item in policy["production_dependencies"]}
    if set(dependencies) != {"libsolv", "liblzma"}:
        fail("dependency policy does not exactly enumerate production dependencies")
    for dependency in dependencies.values():
        if dependency["license"] not in allowed_licenses:
            fail(f"{dependency['name']}: license is outside the production allowlist")
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
        )
    }
    found = {name: (url, digest) for name, url, digest in dependency_blocks}
    if found != expected:
        fail(f"build.zig.zon dependencies differ from reviewed exact pins: {found!r}")
    libsolv_policy = dependencies["libsolv"]
    if (
        libsolv_policy["commit"] not in expected["libsolv"][0]
        or libsolv_policy["zig_hash"] != expected["libsolv"][1]
    ):
        fail("libsolv manifest pin differs from dependency policy")
    for name, (url, _) in found.items():
        if not re.search(r"#[0-9a-f]{40}$", url):
            fail(f"{name}: dependency URL is not pinned to an exact commit")

    build = (ROOT / "build.zig").read_text()
    system_libraries = set(re.findall(r'linkSystemLibrary\("([^"]+)"', build))
    if system_libraries != {"lzma"}:
        fail(f"unreviewed system libraries: {sorted(system_libraries)}")
    version_result = subprocess.run(
        ["pkg-config", "--modversion", "liblzma"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if version_result.returncode != 0:
        fail("liblzma version is unavailable through pkg-config")
    else:
        def version_tuple(value: str) -> tuple[int, ...]:
            return tuple(int(part) for part in re.findall(r"\d+", value))

        installed = version_tuple(version_result.stdout.strip())
        minimum = version_tuple(dependencies["liblzma"]["minimum_version"])
        if installed < minimum or installed[0] >= dependencies["liblzma"]["maximum_major_exclusive"]:
            fail(f"liblzma {version_result.stdout.strip()} is outside reviewed bounds")

    notices = (ROOT / "THIRD_PARTY_NOTICES").read_text()
    for required in ("libsolv", "BSD-3-Clause", "XZ Utils liblzma", "0BSD"):
        if required not in notices:
            fail(f"THIRD_PARTY_NOTICES is missing {required!r}")
    production_notices = notices.split("OpenPGP fixture", 1)[0]
    if re.search(r"\b(?:GPL|LGPL|AGPL)(?:-|\b)", production_notices):
        fail("GPL/LGPL/AGPL production dependency is not permitted")


def audit_ci_pins() -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    for workflow in workflows:
        text = workflow.read_text()
        relative = workflow.relative_to(ROOT)
        if re.search(r"(?m)^\s*pull_request_target\s*:", text):
            fail(f"{relative}: pull_request_target executes untrusted changes with base privileges")
        if re.search(r"\$\{\{\s*secrets\.", text):
            fail(f"{relative}: workflow exposes repository secrets")
        if re.search(r"(?m)^\s*continue-on-error\s*:\s*true\s*$", text):
            fail(f"{relative}: workflow hides a failing command")
        if not re.search(r"(?m)^permissions:\s*\n\s{2}contents:\s*read\s*$", text):
            fail(f"{relative}: top-level permissions must be contents: read")
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


def audit_docs() -> None:
    if (ROOT / "docs").exists():
        fail("stale docs/ directory exists; documentation belongs under doc/")
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in sorted(ROOT.rglob("*.md")):
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
    generated_roots = {"zig-out", ".zig-cache"}
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
        if relative.parts and relative.parts[0] in generated_roots:
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
    audit_production_sources()
    audit_dependencies()
    audit_ci_pins()
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
