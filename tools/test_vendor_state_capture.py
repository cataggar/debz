#!/usr/bin/env python3
"""Synthetic tests for bounded pre-cleanup vendor-state capture."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/capture-vendor-state.py"
SPEC = importlib.util.spec_from_file_location("vendor_state_capture", TOOL)
assert SPEC and SPEC.loader
vendor_state_capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vendor_state_capture
SPEC.loader.exec_module(vendor_state_capture)


class VendorStateCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vendor-state-capture-", dir=temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.workspace = pathlib.Path(self.temporary.name)

    def minimal_root(self, name: str) -> pathlib.Path:
        root = self.workspace / name
        (root / "var/lib/dpkg/info").mkdir(parents=True)
        return root

    def fixture_root(self, name: str, reverse: bool = False) -> pathlib.Path:
        root = self.minimal_root(name)
        info = root / "var/lib/dpkg/info"
        alternatives = root / "var/lib/dpkg/alternatives"
        etc_alternatives = root / "etc/alternatives"
        binaries = root / "usr/bin"
        manuals = root / "usr/share/man/man1"
        for directory in (alternatives, etc_alternatives, binaries, manuals):
            directory.mkdir(parents=True, exist_ok=True)

        members = [
            ("format", b"1\n", 0o644),
            ("demo.control", b"Package: demo\n", 0o644),
            ("demo.list", b"/usr/bin/editor\n", 0o644),
            ("demo.md5sums", b"0" * 32 + b"  usr/bin/editor\n", 0o644),
            ("demo.conffiles", b"/etc/demo.conf\n", 0o644),
            ("demo.triggers", b"interest /usr/share/demo\n", 0o644),
            ("demo.preinst", b"#!/bin/sh\nexit 0\n", 0o755),
            ("demo.config", b"#!/bin/sh\nexit 0\n", 0o755),
            (
                "demo.alternatives",
                (
                    b"Name: editor\n"
                    b"Link: /usr/bin/editor\n"
                    b"Alternative: /usr/bin/editor.real\n"
                ),
                0o644,
            ),
            ("demo.templates", b"Template: demo/question\n", 0o644),
            ("demo.vendor-state", b"\x00opaque vendor metadata\n", 0o640),
        ]
        for filename, contents, mode in reversed(members) if reverse else members:
            path = info / filename
            path.write_bytes(contents)
            path.chmod(mode)

        (alternatives / "editor").write_text(
            "auto\n"
            "/usr/bin/editor\n"
            "editor.1.gz\n"
            "/usr/share/man/man1/editor.1.gz\n"
            "\n"
            "/usr/bin/editor.real\n"
            "50\n"
            "/usr/share/man/man1/editor.real.1.gz\n"
        )
        editor = binaries / "editor.real"
        editor.write_bytes(b"fixture editor\n")
        editor.chmod(0o755)
        manual = manuals / "editor.real.1.gz"
        manual.write_bytes(b"fixture manual\n")
        (binaries / "editor").symlink_to("/etc/alternatives/editor")
        (manuals / "editor.1.gz").symlink_to(
            "/etc/alternatives/editor.1.gz"
        )
        (etc_alternatives / "editor").symlink_to("/usr/bin/editor.real")
        (etc_alternatives / "editor.1.gz").symlink_to(
            "/usr/share/man/man1/editor.real.1.gz"
        )
        return root

    def capture(self, root: pathlib.Path, architecture: str = "amd64", **limits: int) -> dict:
        return vendor_state_capture.capture(
            root, architecture, vendor_state_capture.Limits(**limits)
        )

    def test_capture_is_deterministic_architecture_tagged_and_complete(self) -> None:
        first = self.capture(self.fixture_root("first"))
        second = self.capture(self.fixture_root("second", reverse=True))
        self.assertEqual(
            vendor_state_capture.canonical_json(first),
            vendor_state_capture.canonical_json(second),
        )
        self.assertEqual(first["schema"], vendor_state_capture.SCHEMA)
        self.assertEqual(first["architecture"], "amd64")
        self.assertEqual(first["version"], 1)
        members = first["control_members"]["entries"]
        paths = [entry["path"] for entry in members]
        self.assertEqual(paths, sorted(paths, key=lambda value: value.encode()))
        classifications = {
            pathlib.PurePosixPath(entry["path"]).name: entry["classification"]
            for entry in members
        }
        self.assertEqual(classifications["demo.config"], "debconf-config")
        self.assertEqual(
            classifications["demo.alternatives"], "package-alternatives"
        )
        self.assertEqual(classifications["demo.vendor-state"], "unclassified")
        counts = first["control_members"]["classification_counts"]
        self.assertEqual(sum(counts.values()), len(members))
        self.assertEqual(set(counts), set(vendor_state_capture.CLASSIFICATIONS))
        linked = {
            entry["path"]: entry for entry in first["linked_filesystem"]["entries"]
        }
        self.assertEqual(
            linked["usr/bin/editor"]["target"], "/etc/alternatives/editor"
        )
        self.assertEqual(
            linked["etc/alternatives/editor"]["target"], "/usr/bin/editor.real"
        )
        self.assertEqual(linked["usr/bin/editor.real"]["kind"], "regular")
        self.assertEqual(len(linked["usr/bin/editor.real"]["sha256"]), 64)
        self.assertNotIn(str(self.workspace), json.dumps(first))

        arm64 = self.capture(self.fixture_root("arm64"), "arm64")
        self.assertEqual(arm64["architecture"], "arm64")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "unsupported architecture"
        ):
            self.capture(self.fixture_root("bad-architecture"), "s390x")

    def test_bounds_fail_closed(self) -> None:
        root = self.fixture_root("bounds")
        cases = (
            (
                {"max_control_members": 1},
                "control-member count limit exceeded",
            ),
            (
                {"max_metadata_file_bytes": 1},
                "regular file exceeds limit",
            ),
            (
                {"max_total_metadata_bytes": 1},
                "aggregate regular-file limit exceeded",
            ),
            (
                {"max_referenced_paths": 1},
                "alternative reference count limit exceeded",
            ),
            (
                {"max_link_target_bytes": 5},
                "malformed absolute alternative path",
            ),
            (
                {"max_linked_entries": 1},
                "linked-filesystem entry count limit exceeded",
            ),
            (
                {"max_linked_file_bytes": 1},
                "regular file exceeds limit",
            ),
        )
        defaults = vendor_state_capture.Limits()
        for override, message in cases:
            values = {
                field.name: getattr(defaults, field.name)
                for field in vendor_state_capture.dataclasses.fields(defaults)
            }
            values.update(override)
            with self.subTest(override=override), self.assertRaisesRegex(
                vendor_state_capture.CaptureError, message
            ):
                vendor_state_capture.capture(
                    root, "amd64", vendor_state_capture.Limits(**values)
                )

    def test_malformed_traversal_and_credential_references_are_rejected(self) -> None:
        cases = (
            (b"\xff\n", "not UTF-8"),
            (b"Link: /usr/../etc/shadow\n", "unsafe path component"),
            (b"Link: /etc/shadow\n", "excluded state"),
            (b"Link: /usr//bin/editor\n", "malformed absolute"),
            (b"Link: /usr/bin/editor\x01\n", "control bytes"),
        )
        for index, (contents, message) in enumerate(cases):
            root = self.minimal_root(f"malformed-{index}")
            path = root / "var/lib/dpkg/info/demo.alternatives"
            path.write_bytes(contents)
            with self.subTest(contents=contents), self.assertRaisesRegex(
                vendor_state_capture.CaptureError, message
            ):
                self.capture(root)

    def test_symlinks_special_files_and_ambiguous_roots_fail_closed(self) -> None:
        outside = self.workspace / "outside"
        outside.write_text("must not be read")

        info_link_root = self.minimal_root("info-link")
        (info_link_root / "var/lib/dpkg/info/demo.config").symlink_to(outside)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "not a regular file"
        ):
            self.capture(info_link_root)

        record_link_root = self.minimal_root("record-link")
        records = record_link_root / "var/lib/dpkg/alternatives"
        records.mkdir()
        (records / "editor").symlink_to(outside)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "not a regular file"
        ):
            self.capture(record_link_root)

        unsafe_link_root = self.minimal_root("unsafe-link")
        etc_alternatives = unsafe_link_root / "etc/alternatives"
        etc_alternatives.mkdir(parents=True)
        (etc_alternatives / "editor").symlink_to("../../../outside")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "escapes reference root"
        ):
            self.capture(unsafe_link_root)

        fifo_root = self.minimal_root("fifo")
        os.mkfifo(fifo_root / "var/lib/dpkg/info/demo.config")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "not a regular file"
        ):
            self.capture(fifo_root)

        linked_fifo_root = self.minimal_root("linked-fifo")
        linked_records = linked_fifo_root / "var/lib/dpkg/alternatives"
        linked_records.mkdir()
        (linked_records / "editor").write_text("/usr/bin/editor\n")
        (linked_fifo_root / "usr/bin").mkdir(parents=True)
        os.mkfifo(linked_fifo_root / "usr/bin/editor")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "linked path is a special file"
        ):
            self.capture(linked_fifo_root)

        root_link = self.workspace / "root-link"
        root_link.symlink_to(self.minimal_root("linked-root"), target_is_directory=True)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "must be a real directory"
        ):
            self.capture(root_link)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "ambiguous component"
        ):
            self.capture(self.workspace / "linked-root/../linked-root")

    def test_cli_requires_explicit_root_and_writes_one_new_external_artifact(self) -> None:
        root = self.fixture_root("cli")
        output = self.workspace / "vendor-state.json"
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())["architecture"], "amd64")
        repeated = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn("cannot create output", repeated.stderr)
        inside = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(root / "capture.json"),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(inside.returncode, 0)
        self.assertIn("outside the reference root", inside.stderr)
        missing_root = subprocess.run(
            [sys.executable, str(TOOL)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(missing_root.returncode, 0)

    def test_schema_identity_and_workflow_capture_order_are_pinned(self) -> None:
        schema = json.loads(
            (ROOT / "schema/vendor-state-inventory-v1.json").read_text()
        )
        self.assertEqual(schema["$id"], vendor_state_capture.SCHEMA)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow[workflow.index("  ubuntu-real-snapshot:") :]
        capture = job.index("python3 tools/capture-vendor-state.py")
        cleanup = job.index('sudo rm -rf "$work/root" "$work/cache"')
        upload = job.index("      - name: Upload real acceptance evidence")
        self.assertLess(capture, cleanup)
        self.assertLess(cleanup, upload)
        self.assertIn(
            "path: .real-snapshot/${{ matrix.architecture }}/evidence/", job
        )


if __name__ == "__main__":
    unittest.main()
