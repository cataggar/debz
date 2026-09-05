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
    process_paths = [call.rsplit(":", 1)[0] for call in process_calls]
    if sorted(process_paths) != [
        "src/target_apt_config.zig",
        "src/transaction_executor.zig",
    ]:
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


def audit_ci_pins() -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    for workflow in workflows:
        text = workflow.read_text()
        relative = workflow.relative_to(ROOT)
        if re.search(r"(?m)^\s*pull_request_target\s*:", text):
            fail(f"{relative}: pull_request_target executes untrusted changes with base privileges")
        if re.search(r"\$\{\{\s*secrets\.", text):
            fail(f"{relative}: workflow exposes repository secrets")
        allowed_negative_steps = {
            "Reject corrupt package object",
            "Reject package-only offline restore",
        }
        allowed_continue = 0
        for match in re.finditer(
            r"(?ms)^\s*-\s+name:\s*(?P<name>[^\n]+)\n(?P<body>(?:\s{8,}[^\n]*\n)*)",
            text,
        ):
            if not re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", match.group("body")):
                continue
            if match.group("name").strip() not in allowed_negative_steps:
                fail(f"{relative}: workflow hides a failing command")
            allowed_continue += 1
        if text.count("continue-on-error: true") != allowed_continue:
            fail(f"{relative}: workflow has an unaudited continue-on-error")
        if allowed_continue and (
            "Validate corrupt-object failure" not in text
            or "Validate offline metadata failure" not in text
            or 'test "$OUTCOME" = failure' not in text
        ):
            fail(f"{relative}: expected-failure action coverage lacks outcome assertions")
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
            "verifyExecutableIdentity(executableIdentity)",
            "cache.save(exportArchive, fingerprint.primary_key, archiveLimit)",
            "core.setOutput('cache-hit'",
            "core.setOutput('downloaded-count'",
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
    audit_release_targets()
    audit_ci_pins()
    audit_composite_action_pins()
    audit_setup_action_dependencies()
    audit_download_action()
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
