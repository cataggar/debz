#!/usr/bin/env python3
"""Network-free policy audit for the tag release workflow."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
FAILURES: list[str] = []


def require(pattern: str, message: str, text: str, flags: int = 0) -> None:
    if not re.search(pattern, text, flags):
        FAILURES.append(message)


def main() -> None:
    text = WORKFLOW.read_text()
    require(r"(?m)^on:\n  push:\n    tags:\n      - 'v\*'\n", "trigger must be only v* tag pushes", text)
    if re.search(r"(?m)^  (pull_request|workflow_dispatch|schedule):", text):
        FAILURES.append("release workflow has a non-tag trigger")
    require(r"(?m)^permissions:\n  contents: read$", "top-level permissions must be contents: read", text)
    require(r"(?ms)^  release:.*?permissions:\n      contents: write\n      id-token: write\n      attestations: write", "release job must hold publication permissions", text)
    for action, revision in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", text):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            FAILURES.append(f"{action} is not pinned to a full commit")
    checkout_blocks = re.findall(
        r"(?ms)^\s*-\s+uses:\s*actions/checkout@[^\n]+\n(?P<body>(?:\s{8,}[^\n]*\n)*)",
        text,
    )
    if not checkout_blocks or any("persist-credentials: false" not in block for block in checkout_blocks):
        FAILURES.append("every checkout must disable persisted credentials")
    for required in (
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "-Doptimize=ReleaseSafe",
        '-Dversion="$VERSION"',
        "liblzma-dev",
        "liblzma5",
        "libzstd-dev",
        "libzstd1",
        "actions/attest-build-provenance",
        "ghr-bin==0.7.0",
        "ghr install cataggar/debz@v$VERSION",
        "tools/release.py verify-assets",
    ):
        if required not in text:
            FAILURES.append(f"missing release policy token: {required}")
    if "${{ secrets." in text:
        FAILURES.append("release workflow must not reference repository secrets")
    if "timeout-minutes:" not in text or "concurrency:" not in text:
        FAILURES.append("release workflow requires timeouts and concurrency")
    if FAILURES:
        raise SystemExit("\n".join(f"release policy: {failure}" for failure in FAILURES))
    print("release workflow policy audit passed")


if __name__ == "__main__":
    main()
