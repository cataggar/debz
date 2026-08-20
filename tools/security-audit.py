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
    runtime = json.loads((ROOT / "security/runtime-dependencies.json").read_text())
    reviewed_on = date.fromisoformat(policy["reviewed_on"])
    if reviewed_on > date.today():
        fail("dependency review date is in the future")
    if date.today() > date.fromisoformat(policy["review_expires"]):
        fail("dependency vulnerability/license review has expired")
    allowed_licenses = set(policy["allowed_production_licenses"])
    dependencies = {item["name"]: item for item in policy["production_dependencies"]}
    if set(dependencies) != {"libsolv", "liblzma", "libzstd"}:
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
    linux_runtime = runtime.get("linux_release_runtime", {})
    if (
        runtime.get("schema_version") != 1
        or runtime.get("package") != "debz"
        or linux_runtime.get("binary_kind") != "dynamically_linked"
        or linux_runtime.get("fully_static") is not False
        or linux_runtime.get("libc", {}).get("implementation") != "glibc"
        or linux_runtime.get("libc", {}).get("linkage") != "dynamic"
    ):
        fail("Linux runtime metadata does not identify dynamic glibc requirements")
    runtime_system = {
        (item.get("name"), item.get("linkage"))
        for item in linux_runtime.get("system_libraries", [])
    }
    if runtime_system:
        fail("Linux runtime metadata differs from linked system libraries")
    included = linux_runtime.get("included_libraries", [])
    if included != [
        {
            "name": "libsolv",
            "version": dependencies["libsolv"]["version"],
            "linkage": "static_archive_in_debz",
            "license": "BSD-3-Clause",
        },
        {
            "name": "liblzma",
            "version": dependencies["liblzma"]["version"],
            "linkage": "static_archive_in_debz",
            "license": "0BSD",
        },
        {
            "name": "libzstd",
            "version": dependencies["libzstd"]["version"],
            "linkage": "static_archive_in_debz",
            "license": "BSD-3-Clause",
        },
    ]:
        fail("Linux runtime metadata does not identify statically included libraries")
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
    for required in ("libsolv", "BSD-3-Clause", "XZ Utils liblzma", "Zstandard libzstd", "0BSD"):
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
        relative = path.relative_to(ROOT)
        if any(part in {".git", ".zig-cache", "zig-out", "zig-pkg"} for part in relative.parts):
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
