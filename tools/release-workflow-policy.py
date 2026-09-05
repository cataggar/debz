#!/usr/bin/env python3
"""Network-free policy audit for release workflows."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github/workflows/release.yml"
CI = ROOT / ".github/workflows/ci.yml"
SETUP = ROOT / "actions/setup"
DOWNLOAD = ROOT / "actions/download"
FAILURES: list[str] = []


def require(pattern: str, message: str, text: str, flags: int = 0) -> None:
    if not re.search(pattern, text, flags):
        FAILURES.append(message)


def audit_actions(text: str, workflow: pathlib.Path) -> None:
    for action, revision in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", text):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            FAILURES.append(f"{workflow.name}: {action} is not pinned to a full commit")
    checkout_blocks = re.findall(
        r"(?ms)^\s*-\s+uses:\s*actions/checkout@[^\n]+\n(?P<body>(?:\s{8,}[^\n]*\n)*)",
        text,
    )
    if not checkout_blocks or any("persist-credentials: false" not in block for block in checkout_blocks):
        FAILURES.append(f"{workflow.name}: every checkout must disable persisted credentials")


def audit_setup_action(ci: str, release: str) -> None:
    required_files = (
        SETUP / "action.yml",
        SETUP / "package.json",
        SETUP / "package-lock.json",
        SETUP / "dist/main/index.js",
        SETUP / "dist/main/package.json",
        SETUP / "dist/main/licenses.txt",
        SETUP / "dist/post/index.js",
        SETUP / "dist/post/package.json",
        SETUP / "dist/post/licenses.txt",
    )
    for path in required_files:
        if not path.is_file() or path.stat().st_size == 0:
            FAILURES.append(f"setup action file is missing or empty: {path.relative_to(ROOT)}")

    action_path = SETUP / "action.yml"
    if action_path.is_file():
        action = action_path.read_text()
        for token in (
            "using: node24",
            "main: dist/main/index.js",
            "post: dist/post/index.js",
            "post-if: success()",
            "debz-version:",
            "sha256:",
            "token:",
            "cache:",
            "debz-path:",
            "debz-version:",
            "target:",
            "cache-hit:",
        ):
            if token not in action:
                FAILURES.append(f"setup action metadata is missing policy token: {token}")
    source_tokens = {
        "src/action.ts": (
            "delete process.env.INPUT_TOKEN",
            "verifyInstallation(",
            "io.setOutput('debz-path'",
        ),
        "src/cache.ts": (
            "restore_keys: []",
            "'x-ms-blob-type': 'BlockBlob'",
            "exact cache archive size mismatch",
        ),
        "src/post.ts": (
            "delete process.env.INPUT_TOKEN",
            "verifyCachedInstallation(",
            "sha256Bytes(archive)",
        ),
    }
    for relative, tokens in source_tokens.items():
        source_path = SETUP / relative
        if not source_path.is_file():
            FAILURES.append(f"setup action source is missing: actions/setup/{relative}")
            continue
        source = source_path.read_text()
        for token in tokens:
            if token not in source:
                FAILURES.append(f"setup action {relative} is missing policy token: {token}")

    package_path = SETUP / "package.json"
    lock_path = SETUP / "package-lock.json"
    if package_path.is_file() and lock_path.is_file():
        package = json.loads(package_path.read_text())
        lock = json.loads(lock_path.read_text())
        for group in ("dependencies", "devDependencies"):
            dependencies = package.get(group)
            if not isinstance(dependencies, dict) or not dependencies:
                FAILURES.append(f"setup action {group} are missing")
                continue
            for name, version in dependencies.items():
                if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
                    FAILURES.append(f"setup action dependency {name} is not exactly pinned: {version!r}")
        if lock.get("lockfileVersion") != 3:
            FAILURES.append("setup action package-lock.json must use lockfileVersion 3")
        root_package = lock.get("packages", {}).get("")
        if not isinstance(root_package, dict):
            FAILURES.append("setup action lockfile has no root package")
        else:
            for group in ("dependencies", "devDependencies"):
                if root_package.get(group) != package.get(group):
                    FAILURES.append(f"setup action lockfile {group} differ from package.json")

    tracked = subprocess.run(
        ["git", "ls-files", "actions/setup/node_modules"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if tracked.strip():
        FAILURES.append("setup action node_modules must not be tracked")

    for token in (
        "Setup action unit and bundle checks",
        "npm --prefix actions/setup ci",
        "npm --prefix actions/setup audit --audit-level=high",
        "npm --prefix actions/setup test",
        "npm --prefix actions/setup run bundle",
        "git diff --exit-code -- actions/setup/dist",
        "Setup action native (${{ matrix.target }})",
        "Setup action in bare Ubuntu container",
        "uses: ./actions/setup",
        "debz-version: v0.2.0",
        "sha256: ${{ matrix.digest }}",
    ):
        if token not in ci:
            FAILURES.append(f"CI setup action coverage is missing policy token: {token}")
    for token in (
        "Install exact release with the first-party setup action",
        "uses: ./actions/setup",
        "debz-version: ${{ github.ref_name }}",
        'test "$("$DEBZ_PATH" version)" = "$VERSION"',
        '"$DEBZ_PATH" --help',
    ):
        if token not in release:
            FAILURES.append(f"release setup smoke is missing policy token: {token}")
    if not re.search(
        r"(?ms)^  smoke:\n.*?^\s{4}permissions:\n\s{6}contents: read\n\s{6}attestations: read$",
        release,
    ):
        FAILURES.append("release setup smoke must have contents and attestations read permissions")
    if not re.search(
        r"(?m)^permissions:\n  contents: read\n  attestations: read$",
        ci,
    ):
        FAILURES.append("CI setup jobs require top-level attestations: read permission")


def audit_download_action(ci: str, release: str) -> None:
    required_files = (
        DOWNLOAD / "action.yml",
        DOWNLOAD / "package.json",
        DOWNLOAD / "package-lock.json",
        DOWNLOAD / "THIRD_PARTY_NOTICES.md",
        DOWNLOAD / "dist/index.js",
        DOWNLOAD / "dist/package.json",
        DOWNLOAD / "dist/licenses.txt",
        ROOT / "src/package_cache_archive.zig",
    )
    for path in required_files:
        if not path.is_file() or path.stat().st_size == 0:
            FAILURES.append(f"download action file is missing or empty: {path.relative_to(ROOT)}")

    manifest_path = DOWNLOAD / "action.yml"
    if manifest_path.is_file():
        manifest = manifest_path.read_text()
        for action, revision in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", manifest):
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                FAILURES.append(f"download action dependency {action} is not commit-pinned")
        for token in (
            "using: node24",
            "main: dist/index.js",
            "cache-hit:",
            "cache-matched-key:",
            "cache-path:",
            "cache-root:",
            "lock-digest:",
            "downloaded-count:",
            "reused-count:",
        ):
            if token not in manifest:
                FAILURES.append(f"download action metadata is missing policy token: {token}")

    package_path = DOWNLOAD / "package.json"
    lock_path = DOWNLOAD / "package-lock.json"
    if package_path.is_file() and lock_path.is_file():
        package = json.loads(package_path.read_text())
        lock = json.loads(lock_path.read_text())
        if package.get("dependencies") != {
            "@actions/core": "3.0.1",
            "@azure/storage-blob": "12.31.0",
        }:
            FAILURES.append("download action runtime dependencies differ from policy")
        for group in ("dependencies", "devDependencies"):
            dependencies = package.get(group)
            if not isinstance(dependencies, dict) or not dependencies:
                FAILURES.append(f"download action {group} are missing")
                continue
            for name, version in dependencies.items():
                if not isinstance(version, str) or not re.fullmatch(
                    r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version
                ):
                    FAILURES.append(
                        f"download action dependency {name} is not exactly pinned: {version!r}"
                    )
        if lock.get("lockfileVersion") != 3:
            FAILURES.append("download action package-lock.json must use lockfileVersion 3")
        root_package = lock.get("packages", {}).get("")
        if not isinstance(root_package, dict):
            FAILURES.append("download action lockfile has no root package")
        else:
            for group in ("dependencies", "devDependencies"):
                if root_package.get(group) != package.get(group):
                    FAILURES.append(
                        f"download action lockfile {group} differ from package.json"
                    )

    tracked = subprocess.run(
        ["git", "ls-files", "actions/download/node_modules"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if tracked.strip():
        FAILURES.append("download action node_modules must not be tracked")

    for token in (
        "Download action unit and bundle checks",
        "npm --prefix actions/download ci",
        "npm --prefix actions/download audit --audit-level=high",
        "npm --prefix actions/download test",
        "npm --prefix actions/download run bundle",
        "git diff --exit-code -- actions/download/dist",
        "Download action cache semantics",
        "uses: ./actions/download",
        "cache-matched-key",
        "downloaded-count",
        "reused-count",
        "Reject corrupt package object",
        "Reject package-only offline restore",
        'test "$OUTCOME" = failure',
    ):
        if token not in ci:
            FAILURES.append(f"CI download action coverage is missing policy token: {token}")
    for token in (
        "Prepare release smoke package closure",
        "uses: ./actions/download",
        "cache: 'false'",
        "downloaded-count",
        "reused-count",
    ):
        if token not in release:
            FAILURES.append(f"release download smoke is missing policy token: {token}")


def main() -> None:
    release = RELEASE.read_text()
    ci = CI.read_text()
    require(r"(?m)^on:\n  push:\n    tags:\n      - 'v\*'\n", "trigger must be only v* tag pushes", release)
    if re.search(r"(?m)^  (pull_request|workflow_dispatch|schedule):", release):
        FAILURES.append("release workflow has a non-tag trigger")
    require(r"(?m)^permissions:\n  contents: read$", "top-level permissions must be contents: read", release)
    require(
        r"(?ms)^  release:.*?permissions:\n      contents: write\n      id-token: write\n      attestations: write",
        "release job must hold publication permissions",
        release,
    )
    audit_actions(release, RELEASE)
    audit_actions(ci, CI)
    audit_setup_action(ci, release)
    audit_download_action(ci, release)

    required_release_tokens = (
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "fetch-depth: 0",
        "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
        'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
        'python3 tools/release.py version "$GITHUB_REF_NAME" --expect "zon=$zon_version"',
        '--expect "binary=$(release-root/bin/debz version)"',
        "-Doptimize=ReleaseSafe",
        '-Dversion="$VERSION"',
        "python3 tools/release.py binary",
        "python3 tools/release.py audit",
        "python3 tools/release.py verify",
        "--assets release-assets --smoke",
        "subject-path: release-assets/*.tar.gz",
        "subject-path: release-assets/*.tar.xz",
        "release-assets-${{ matrix.platform }}",
        "merge-multiple: true",
        "ghr-bin==0.7.0",
        "ghr install cataggar/debz@v$VERSION",
        "'```sh'",
        "--generate-notes",
        "--fail-on-no-commits",
        "--verify-tag",
        "release-assets/debz-$VERSION-linux-x64.tar.gz",
        "release-assets/debz-$VERSION-linux-x64.tar.xz",
        "release-assets/debz-$VERSION-linux-arm64.tar.gz",
        "release-assets/debz-$VERSION-linux-arm64.tar.xz",
    )
    for token in required_release_tokens:
        if token not in release:
            FAILURES.append(f"release workflow is missing policy token: {token}")
    for token in (
        "python3 tools/release.py binary",
        "python3 tools/release.py audit",
        "python3 tools/release.py verify",
        "Required release dry-run exact verification",
    ):
        if token not in ci:
            FAILURES.append(f"CI release dry-run is missing policy token: {token}")
    release_jobs = (
        ("release.yml binaries", re.search(r"(?ms)^  binaries:\n(.*?)(?=^  \S|\Z)", release)),
        (
            "ci.yml release-dry-run",
            re.search(r"(?ms)^  release-dry-run:\n(.*?)(?=^  \S|\Z)", ci),
        ),
    )
    for workflow_name, match in release_jobs:
        if match is None:
            FAILURES.append(f"{workflow_name}: release job is missing")
            continue
        text = match.group(1)
        for target in ("x86_64-linux-musl", "aarch64-linux-musl"):
            if text.count(f"target: {target}") != 1:
                FAILURES.append(
                    f"{workflow_name}: release matrix must contain exactly one {target} target"
                )
        for target in ("x86_64-linux-gnu", "aarch64-linux-gnu"):
            if f"target: {target}" in text:
                FAILURES.append(
                    f"{workflow_name}: release matrix retains dynamic GNU target {target}"
                )
    if release.count("actions/attest-build-provenance@") != 2:
        FAILURES.append("release workflow must separately attest gzip and xz archives")
    if "${{ secrets." in release:
        FAILURES.append("release workflow must not reference repository secrets")
    if "timeout-minutes:" not in release or "concurrency:" not in release:
        FAILURES.append("release workflow requires timeouts and concurrency")
    for forbidden in (
        ".sha256",
        ".spdx",
        "-release-manifest.json",
        "-source.tar",
        "tools/release.py source",
        "tools/release.py manifest",
        "release-assets-source",
    ):
        if forbidden in release or forbidden in ci:
            FAILURES.append(f"forbidden release asset or command remains: {forbidden}")
    for obsolete in ("validate-tag", "package-binary", "package-source", "verify-assets", "audit-runtime"):
        if obsolete in release or obsolete in ci:
            FAILURES.append(f"obsolete release tool command remains: {obsolete}")
    if (ROOT / "tools/release-assets.json").exists() or (ROOT / "tools/release-dry-run.sh").exists():
        FAILURES.append("obsolete static release assets or dry-run implementation remains")

    plan = json.loads(
        subprocess.run(
            ["python3", str(ROOT / "tools/release.py"), "dry-run", "--tag", "v0.1.0"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
    )
    assets = plan.get("assets")
    expected_assets = {
        "debz-0.1.0-linux-x64.tar.gz",
        "debz-0.1.0-linux-x64.tar.xz",
        "debz-0.1.0-linux-arm64.tar.gz",
        "debz-0.1.0-linux-arm64.tar.xz",
    }
    if not isinstance(assets, list) or set(assets) != expected_assets or len(assets) != 4:
        FAILURES.append("release plan must declare exactly four binary archives")

    if FAILURES:
        raise SystemExit("\n".join(f"release policy: {failure}" for failure in FAILURES))
    print("release workflow policy audit passed")


if __name__ == "__main__":
    main()
