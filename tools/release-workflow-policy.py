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

    required_release_tokens = (
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "fetch-depth: 0",
        "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
        'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
        'python3 tools/release.py version "$GITHUB_REF_NAME" --expect "zon=$zon_version"',
        '--expect "binary=$(release-root/bin/debz --version)"',
        "-Doptimize=ReleaseSafe",
        '-Dversion="$VERSION"',
        "python3 tools/release.py binary",
        "python3 tools/release.py source",
        "python3 tools/release.py manifest",
        "python3 tools/release.py audit",
        "python3 tools/release.py verify",
        "--assets release-assets --smoke",
        "subject-path: release-assets/*.tar.gz",
        "subject-path: release-assets/*.tar.xz",
        "release-assets-${{ matrix.platform }}",
        "name: release-assets-source",
        "merge-multiple: true",
        "ghr-bin==0.7.0",
        "ghr install cataggar/debz@v$VERSION",
    )
    for token in required_release_tokens:
        if token not in release:
            FAILURES.append(f"release workflow is missing policy token: {token}")
    for token in (
        "python3 tools/release.py binary",
        "python3 tools/release.py source",
        "python3 tools/release.py manifest",
        "python3 tools/release.py audit",
        "python3 tools/release.py verify",
        "Required release dry-run exact verification",
    ):
        if token not in ci:
            FAILURES.append(f"CI release dry-run is missing policy token: {token}")
    if release.count("actions/attest-build-provenance@") != 2:
        FAILURES.append("release workflow must separately attest gzip and xz archives")
    if "${{ secrets." in release:
        FAILURES.append("release workflow must not reference repository secrets")
    if "timeout-minutes:" not in release or "concurrency:" not in release:
        FAILURES.append("release workflow requires timeouts and concurrency")
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
    if not isinstance(assets, list) or len(assets) != 26 or len(set(assets)) != 26:
        FAILURES.append("merged release manifest must declare exactly 26 unique assets")
    elif not all(
        any(name.endswith(suffix) for name in assets)
        for suffix in (".tar.gz", ".tar.xz", ".spdx.json", ".sha256", "-release-manifest.json")
    ):
        FAILURES.append("merged release manifest lacks required archive, SBOM, checksum, or manifest assets")

    if FAILURES:
        raise SystemExit("\n".join(f"release policy: {failure}" for failure in FAILURES))
    print("release workflow policy audit passed")


if __name__ == "__main__":
    main()
