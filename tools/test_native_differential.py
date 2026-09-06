#!/usr/bin/env python3
"""Tests for the native transaction differential contract and comparator."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_native_differential", ROOT / "tools/native-differential.py"
)
assert SPEC and SPEC.loader
native_differential = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native_differential
SPEC.loader.exec_module(native_differential)


class NativeDifferentialTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="native-differential-", dir=temporary_root
        )
        self.workspace = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def root(self, name: str) -> pathlib.Path:
        root = self.workspace / name
        (root / "var/lib/dpkg/info").mkdir(parents=True)
        (root / "var/lib/dpkg/triggers").mkdir()
        (root / "var/lib/dpkg/updates").mkdir()
        return root

    @staticmethod
    def write_status(root: pathlib.Path, fields: list[tuple[str, str]]) -> None:
        text = "".join(f"{name}: {value}\n" for name, value in fields) + "\n"
        (root / "var/lib/dpkg/status").write_text(text)

    def test_semantic_database_order_is_normalized(self) -> None:
        reference = self.root("reference")
        candidate = self.root("candidate")
        self.write_status(
            reference,
            [
                ("Package", "demo"),
                ("Status", "install ok installed"),
                ("Architecture", "amd64"),
                ("Version", "1"),
            ],
        )
        self.write_status(
            candidate,
            [
                ("Version", "1"),
                ("Architecture", "amd64"),
                ("Status", "install ok installed"),
                ("Package", "demo"),
            ],
        )
        (reference / "var/lib/dpkg/info/demo.list").write_text("/usr/bin/z\n/etc/a\n")
        (candidate / "var/lib/dpkg/info/demo.list").write_text("/etc/a\n/usr/bin/z\n")
        (reference / "var/lib/dpkg/triggers/File").write_text("/z demo\n/a demo\n")
        (candidate / "var/lib/dpkg/triggers/File").write_text("/a demo\n/z demo\n")
        (reference / "var/lib/dpkg/diversions").write_text(
            "/usr/bin/z\n/usr/bin/z.distrib\npackage-z\n"
            "/usr/bin/a\n/usr/bin/a.distrib\npackage-a\n"
        )
        (candidate / "var/lib/dpkg/diversions").write_text(
            "/usr/bin/a\n/usr/bin/a.distrib\npackage-a\n"
            "/usr/bin/z\n/usr/bin/z.distrib\npackage-z\n"
        )
        (reference / "var/lib/dpkg/statoverride").write_text(
            "root root 4755 /usr/bin/z\nroot root 0755 /usr/bin/a\n"
        )
        (candidate / "var/lib/dpkg/statoverride").write_text(
            "root root 0755 /usr/bin/a\nroot root 4755 /usr/bin/z\n"
        )

        self.assertEqual(
            native_differential.capture(reference),
            native_differential.capture(candidate),
        )

    def test_filesystem_content_and_metadata_difference_is_reported(self) -> None:
        reference = self.root("reference")
        candidate = self.root("candidate")
        for root, content in ((reference, b"reference"), (candidate, b"candidate")):
            path = root / "usr/share/demo"
            path.parent.mkdir(parents=True)
            path.write_bytes(content)
            os.chmod(path, 0o640)
            os.utime(path, ns=(1_700_000_000_000_000_000,) * 2)

        found = native_differential.differences(
            native_differential.capture(reference),
            native_differential.capture(candidate),
        )
        self.assertTrue(any(".sha256:" in difference for difference in found))

    def test_symlinks_are_not_followed_and_hardlinks_are_semantic(self) -> None:
        root = self.root("root")
        payload = root / "usr/lib/demo"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"same inode")
        os.link(payload, root / "usr/lib/demo-link")
        os.symlink("../../outside", root / "usr/lib/escape")
        outside = self.workspace / "outside"
        outside.write_text("must not be read")
        fixed = 1_700_000_000_000_000_000
        os.utime(payload, ns=(fixed, fixed))
        os.utime(root / "usr/lib/demo-link", ns=(fixed, fixed))

        snapshot = native_differential.capture(root)
        entries = {entry["path"]: entry for entry in snapshot["filesystem"]}
        self.assertEqual(entries["usr/lib/demo"]["hardlink_to"], "usr/lib/demo")
        self.assertEqual(
            entries["usr/lib/demo-link"]["hardlink_to"], "usr/lib/demo"
        )
        self.assertEqual(entries["usr/lib/escape"]["target"], "../../outside")

    def test_limits_fail_closed(self) -> None:
        root = self.root("root")
        payload = root / "large"
        payload.write_bytes(b"1234")
        with self.assertRaisesRegex(
            native_differential.SnapshotError, "file exceeds limit"
        ):
            native_differential.capture(
                root, native_differential.Limits(max_file_bytes=3)
            )

        (root / "large").unlink()
        (root / "var/lib/dpkg/info/one.list").write_text("/one\n")
        (root / "var/lib/dpkg/info/two.list").write_text("/two\n")
        (root / "var/lib/dpkg/info/three.list").write_text("/three\n")
        with self.assertRaisesRegex(
            native_differential.SnapshotError, "database entry limit"
        ):
            native_differential.capture(
                root, native_differential.Limits(max_entries=2)
            )

    def test_corpus_covers_required_v1_transitions(self) -> None:
        corpus = json.loads(
            (ROOT / "test/native-transaction/corpus-v1.json").read_text()
        )
        native_differential.validate_corpus(corpus)
        scenarios = {scenario["id"]: scenario for scenario in corpus["scenarios"]}
        required = {
            "fresh-install",
            "essential-bootstrap",
            "pre-depends-order",
            "dependency-cycle",
            "upgrade",
            "downgrade",
            "reinstall",
            "remove",
            "purge",
            "file-ownership-conflict",
            "conffile-keep-existing",
            "conffile-use-package-version",
            "preinst-failure",
            "postinst-failure",
            "prerm-failure",
            "postrm-failure",
            "trigger-await",
            "trigger-noawait",
            "trigger-failure",
            "healthy-root-import",
            "corrupt-root-rejected",
            "filesystem-interruption",
            "database-interruption",
            "script-outcome-unknown",
        }
        self.assertEqual(set(), required - scenarios.keys())

        invalid = json.loads(json.dumps(corpus))
        invalid["scenarios"][0]["typo"] = True
        with self.assertRaisesRegex(
            native_differential.SnapshotError, "unsupported shape"
        ):
            native_differential.validate_corpus(invalid)


if __name__ == "__main__":
    unittest.main()
