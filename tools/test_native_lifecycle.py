"""Regression coverage for the independent lifecycle oracle."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_lifecycle_acceptance", ROOT / "tools/test-native-lifecycle.py",
)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)
m = acceptance.m


class LifecycleOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="lifecycle-oracle-", dir=ROOT / ".tmp",
        )
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def roots(self) -> tuple[Path, Path]:
        roots = self.workspace / "reference", self.workspace / "native"
        for root in roots:
            m.make_root(root, "amd64")
        return roots

    def test_reference_refuses_host_and_unguarded_roots_before_spawn(self) -> None:
        unguarded = self.workspace / "unguarded"
        unguarded.mkdir()
        with mock.patch.object(acceptance.subprocess, "run") as run:
            for root in (Path("/"), unguarded):
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    acceptance.reference_phase(
                        root, [], "purge", {}, self.workspace,
                        packages=[{"name": m.PACKAGE, "architecture": "amd64"}],
                    )
            run.assert_not_called()

    def test_fixture_scripts_record_exact_arguments_and_visible_payload(self) -> None:
        bodies = acceptance.scripts(m.PACKAGE, "2")
        self.assertEqual(set(bodies), set(acceptance.KINDS))
        for kind, body in bodies.items():
            self.assertIn(f"{m.PACKAGE}@2:{kind}".encode(), body)
            self.assertIn(b'"$#"', body)
            self.assertIn(b'"${#argument}" "$argument"', body)
            self.assertIn(b"payload='<absent>'", body)
            self.assertIn(b"exit 23", body)

    def test_script_and_bootstrap_payload_are_part_of_real_archive_source(self) -> None:
        def prepare(source: Path) -> None:
            m.write(source / "bin/sh", b"fixture interpreter\n", 0o755)

        with mock.patch.object(m, "run"):
            archive = m.make_package(
                self.workspace, {}, "amd64", "1",
                scripts=acceptance.scripts(m.PACKAGE, "1"),
                control_fields={"Essential": "yes"},
                prepare_payload=prepare,
            )
        source = archive.with_suffix(".source")
        self.assertIn(b"Essential: yes\n", (source / "DEBIAN/control").read_bytes())
        self.assertIn(b"  bin/sh\n", (source / "DEBIAN/md5sums").read_bytes())
        self.assertEqual((source / "bin/sh").stat().st_mode & 0o777, 0o755)
        for kind in acceptance.KINDS:
            self.assertEqual((source / "DEBIAN" / kind).stat().st_mode & 0o777, 0o755)

    def test_bootstrap_fixture_can_use_uncompressed_archive_without_runtime_fallback(self) -> None:
        with mock.patch.object(m, "run") as run:
            m.make_package(self.workspace, {}, "amd64", "1", compression="none")
        self.assertIn("-Znone", run.call_args.args[0])
        self.assertNotIn("-z1", run.call_args.args[0])

    def test_published_schema_accepts_and_bounds_compensations(self) -> None:
        schema = json.loads((ROOT / "schema/native-transaction-program-v1.json").read_bytes())
        validator = jsonschema.Draft202012Validator({
            "$ref": "#/$defs/scriptFailure", "$defs": schema["$defs"],
        })
        compensation = {
            "kind": "postinst", "source": "installed_package",
            "script_sha256": "a" * 64, "arguments": ["abort-upgrade", "2"],
        }
        failure = {
            "state": "half_installed", "unwind": None,
            "resume_after_unwind": False, "compensations": [compensation],
            "rollback_after_compensations": 0, "recovery_required": True,
        }
        validator.validate(failure)
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate({**failure, "compensations": [compensation] * 9})
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate({
                **failure,
                "compensations": [{**compensation, "script_sha256": "not-a-digest"}],
            })
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate({**failure, "rollback_after_compensations": 9})

    def test_empty_argument_and_payload_differences_cannot_be_normalized_away(self) -> None:
        expected, candidate = self.roots()
        m.write(expected / acceptance.TRACE, b"postinst\t2\t9:configure\t0:\tpayload=v1\n")
        for trace in (
            b"postinst\t1\t9:configure\tpayload=v1\n",
            b"postinst\t2\t9:configure\t0:\tpayload=v2\n",
        ):
            m.write(candidate / acceptance.TRACE, trace)
            with self.assertRaisesRegex(AssertionError, "native/dpkg mismatch"):
                acceptance.compare_roots(expected, candidate, self.workspace, {}, 0, 0)

    def test_rollback_clock_exception_is_path_type_and_time_bounded(self) -> None:
        expected, candidate = self.roots()
        for root, timestamp in ((expected, 110), (candidate, 120)):
            (root / "link").symlink_to("target")
            os.utime(root / "link", ns=(timestamp, timestamp), follow_symlinks=False)
        acceptance.compare_roots(expected, candidate, self.workspace, {"link": 100}, 105, 125)
        os.utime(candidate / "link", ns=(999, 999), follow_symlinks=False)
        with self.assertRaisesRegex(AssertionError, "unexpected rollback symlink timestamp"):
            acceptance.compare_roots(expected, candidate, self.workspace, {"link": 100}, 105, 125)
        (candidate / "link").unlink()
        m.write(candidate / "link", b"not a symlink")
        with self.assertRaisesRegex(AssertionError, "rollback changed symlink type"):
            acceptance.compare_roots(expected, candidate, self.workspace, {"link": 100}, 105, 125)

    def test_nonrollback_metadata_is_still_exact(self) -> None:
        expected, candidate = self.roots()
        for root, timestamp in ((expected, 100), (candidate, 110)):
            m.write(root / "file", b"same bytes")
            os.utime(root / "file", ns=(timestamp, timestamp))
        with self.assertRaisesRegex(AssertionError, "mtime_ns"):
            acceptance.compare_roots(expected, candidate, self.workspace, {}, 0, 200)

    def test_native_request_preserves_reviewed_order_and_fault_boundary(self) -> None:
        root = self.workspace / "root"
        m.make_root(root, "amd64")
        actions = acceptance.ordered("amd64", [
            ("unpack", "provider"), ("configure_pending", "consumer"),
            ("unpack", "consumer"), ("configure_pending", "consumer"),
        ])
        with mock.patch.object(m, "run") as run:
            m.write(self.workspace / "native.report.json", b'{"outcome":"applied"}')
            acceptance.native(
                self.workspace / "driver", root, [self.workspace / "package.deb"],
                "install", "amd64", {}, self.workspace, packages=[],
                ordered_actions=actions, fault="after_script_before_record",
            )
        request = json.loads((self.workspace / "native.request.json").read_bytes())
        self.assertEqual(request["ordered_actions"], actions)
        self.assertEqual(request["fault"], "after_script_before_record")
        self.assertIn("DEBZ_NATIVE_LIFECYCLE_REQUEST", run.call_args.args[1])

    def test_success_report_cannot_hide_wrong_state(self) -> None:
        with mock.patch.object(acceptance.runtime, "copy_program"):
            case = acceptance.Scenario(
                self.workspace, "wrong-state", self.workspace / "driver", "amd64", {},
            )
        m.write(case.expected / "unexpected-payload", b"missing in candidate")
        with (
            mock.patch.object(acceptance, "reference_phase", return_value=0),
            mock.patch.object(acceptance, "native", return_value={"outcome": "applied"}),
        ):
            with self.assertRaisesRegex(AssertionError, "native/dpkg mismatch"):
                case.phase("install", [self.workspace / "package.deb"])


if __name__ == "__main__":
    unittest.main()
