"""Regression tests for the real native/dpkg materialization oracle."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_native_materialization", ROOT / "tools/test-native-materialization.py"
)
assert SPEC and SPEC.loader
materialization = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materialization)


class MaterializationOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="materialization-oracle-", dir=temporary_root,
        )
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def root(self, name: str) -> Path:
        root = self.workspace / name
        materialization.make_root(root, "amd64")
        materialization.write(root / materialization.PAYLOAD / "data", b"payload\n")
        empty = root / materialization.PAYLOAD / "empty"
        empty.mkdir(mode=0o750)
        os.utime(empty, (materialization.EPOCH, materialization.EPOCH))
        return root

    def test_identical_roots_compare_equal(self) -> None:
        left, right = self.root("left"), self.root("right")
        for root in (left, right):
            os.utime(
                root / materialization.PAYLOAD / "data",
                (materialization.EPOCH, materialization.EPOCH),
            )
        materialization.assert_parity(left, right, self.workspace)

    def test_payload_difference_is_not_ignored(self) -> None:
        left, right = self.root("left"), self.root("right")
        (right / materialization.PAYLOAD / "data").write_bytes(b"wrong bytes\n")
        with self.assertRaisesRegex(AssertionError, "native/dpkg mismatch"):
            materialization.assert_parity(left, right, self.workspace)

    def test_empty_directory_timestamp_is_not_ignored(self) -> None:
        left, right = self.root("left"), self.root("right")
        for root in (left, right):
            os.utime(
                root / materialization.PAYLOAD / "data",
                (materialization.EPOCH, materialization.EPOCH),
            )
        os.utime(right / materialization.PAYLOAD / "empty", (1, 1))
        with self.assertRaisesRegex(AssertionError, "empty-directory mtime differs"):
            materialization.assert_parity(left, right, self.workspace)

    def test_reference_requires_disposable_root(self) -> None:
        root = self.root("wrong-guard")
        (root / materialization.GUARD).write_text("not a disposable root\n")
        with mock.patch.object(materialization, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                materialization.reference(
                    root, self.workspace / "fixture.deb", {},
                    self.workspace / "unused.log",
                )
            with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                materialization.reference(
                    Path("/"), self.workspace / "fixture.deb", {},
                    self.workspace / "unused.log",
                )
            run.assert_not_called()

    def test_skipped_native_fixture_cannot_pass_without_report(self) -> None:
        root = self.root("native")
        with mock.patch.object(materialization, "run"):
            with self.assertRaisesRegex(AssertionError, "outcome report"):
                materialization.native(
                    self.workspace / "test", root, self.workspace / "fixture.deb",
                    "amd64", "install", {}, self.workspace,
                )

    def test_archive_fixture_has_explicit_modes_and_link_manifest(self) -> None:
        with mock.patch.object(materialization, "run"):
            archive = materialization.make_package(
                self.workspace, {}, "amd64", "1",
            )
        source = archive.with_suffix(".source")
        self.assertEqual((source / "DEBIAN").stat().st_mode & 0o777, 0o755)
        data = source / materialization.PAYLOAD / "data"
        link = source / materialization.PAYLOAD / "data.link"
        self.assertEqual(data.stat().st_ino, link.stat().st_ino)
        manifest = (source / "DEBIAN/md5sums").read_text()
        self.assertIn(f"  {materialization.PAYLOAD}/data\n", manifest)
        self.assertIn(f"  {materialization.PAYLOAD}/data.link\n", manifest)
        self.assertNotIn(f"  {materialization.PAYLOAD}/current\n", manifest)


if __name__ == "__main__":
    unittest.main()
