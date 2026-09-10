"""Regression coverage for independent native trigger acceptance."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_trigger_acceptance", ROOT / "tools/test-native-triggers.py",
)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)
m = acceptance.m


class TriggerOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="trigger-oracle-", dir=ROOT / ".tmp")
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_trigger_only_reference_still_requires_disposable_root(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                acceptance.reference(Path("/"), "process_triggers", [], [], {}, self.workspace)
            run.assert_not_called()

    def test_reference_processing_and_deferral_are_explicit(self) -> None:
        root = self.workspace / "root"
        m.make_root(root, "amd64")
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], 0),
        ) as run:
            acceptance.reference(root, "process_triggers", [], [], {}, self.workspace)
            self.assertIn("--triggers-only", run.call_args.args[0])
            self.assertIn("--pending", run.call_args.args[0])
            self.assertNotIn("--no-triggers", run.call_args.args[0])
            acceptance.reference(
                root, "install", [self.workspace / "source.deb"], [],
                {}, self.workspace, defer=True,
            )
            self.assertIn("--no-triggers", run.call_args.args[0])

    def test_real_package_contains_exact_trigger_declarations(self) -> None:
        declarations = b"interest-noawait debz-trigger\nactivate-await debz-other\n"
        with mock.patch.object(m, "run"):
            archive = m.make_package(self.workspace, {}, "amd64", "1", triggers=declarations)
        self.assertEqual(
            (archive.with_suffix(".source") / "DEBIAN/triggers").read_bytes(),
            declarations,
        )

    def test_native_trigger_only_request_does_not_fake_archive_reinstall(self) -> None:
        root = self.workspace / "root"
        m.make_root(root, "amd64")
        with mock.patch.object(m, "run"):
            m.write(self.workspace / "native.report.json", b'{"outcome":"applied"}')
            acceptance.native(
                self.workspace / "driver", root, "amd64", "process_triggers",
                [], [], {}, self.workspace,
            )
        request = json.loads((self.workspace / "native.request.json").read_bytes())
        self.assertEqual(request["operation"], "process_triggers")
        self.assertEqual(request["archives"], [])
        self.assertTrue(request["triggers"])
        self.assertFalse(request["defer_triggers"])

    def test_scripts_use_real_helper_and_propagate_its_failure(self) -> None:
        script = acceptance.script_set(
            "receiver", "1", activate=("first-trigger", "second-trigger"),
        )["postinst"]
        self.assertIn(b"/usr/bin/dpkg-trigger --no-await first-trigger || exit $?", script)
        self.assertIn(b"/usr/bin/dpkg-trigger --no-await second-trigger || exit $?", script)
        self.assertIn(b'if [ "$1" = "triggered" ]', script)

    def test_removal_activation_is_in_postrm_not_postinst(self) -> None:
        scripts = acceptance.script_set(
            "source", "1", activate=("named-trigger",),
            activate_kind="postrm", activate_when="remove",
        )
        self.assertIn(
            b"/usr/bin/dpkg-trigger --no-await named-trigger || exit $?",
            scripts["postrm"],
        )
        self.assertIn(b'if [ "$1" = "remove" ]', scripts["postrm"])
        self.assertNotIn(b"/usr/bin/dpkg-trigger", scripts["postinst"])

    def test_helper_exclusion_does_not_hide_package_or_trigger_changes(self) -> None:
        expected, candidate = self.workspace / "reference", self.workspace / "native"
        for root in (expected, candidate):
            m.make_root(root, "amd64")
        m.write(expected / acceptance.HELPER, b"reference")
        m.write(candidate / acceptance.HELPER, b"native")
        self.assertFalse(
            m.oracle.differences(acceptance.snapshot(expected), acceptance.snapshot(candidate))
        )
        m.write(candidate / "var/lib/dpkg/triggers/named-trigger", b"unexpected-package\n")
        self.assertTrue(
            m.oracle.differences(acceptance.snapshot(expected), acceptance.snapshot(candidate))
        )

    def test_success_report_cannot_hide_a_wrong_trigger_database(self) -> None:
        with mock.patch.object(acceptance.lifecycle.runtime, "copy_program"):
            case = acceptance.Scenario(
                self.workspace, "wrong-trigger-state", self.workspace / "driver",
                None, "amd64", {},
            )
        m.write(case.expected / "var/lib/dpkg/triggers/named-trigger", b"receiver/noawait\n")
        with (
            mock.patch.object(acceptance, "reference", return_value=0),
            mock.patch.object(acceptance, "native", return_value={"outcome": "applied"}),
        ):
            with self.assertRaisesRegex(AssertionError, "native/dpkg trigger mismatch"):
                case.phase("process_triggers")

    def test_order_and_noawait_markers_remain_observable(self) -> None:
        expected, candidate = self.workspace / "reference", self.workspace / "native"
        for root in (expected, candidate):
            m.make_root(root, "amd64")
        for path, before, after in (
            (
                "var/lib/dpkg/triggers/named-trigger",
                b"receiver\n", b"receiver/noawait\n",
            ),
            (
                "var/lib/dpkg/triggers/Unincorp",
                b"named-trigger source -\n", b"named-trigger source\n",
            ),
            (
                "var/lib/dpkg/status",
                b"Package: receiver\nStatus: install ok triggers-pending\n"
                b"Version: 1\nArchitecture: amd64\nTriggers-Pending: b a\n\n",
                b"Package: receiver\nStatus: install ok triggers-pending\n"
                b"Version: 1\nArchitecture: amd64\nTriggers-Pending: a b\n\n",
            ),
            (
                acceptance.lifecycle.TRACE,
                b"receiver@1:postinst\t[triggered]\t[a b]\n",
                b"receiver@1:postinst\t[triggered]\t[b a]\n",
            ),
            (
                acceptance.lifecycle.TRACE,
                b"receiver@1:postinst\t[triggered]\t[a b]\n",
                b"receiver@1:postinst\t[triggered]\t[a]\t[b]\n",
            ),
        ):
            with self.subTest(path=path, after=after):
                for root in (expected, candidate):
                    m.write(root / path, before)
                self.assertFalse(
                    m.oracle.differences(acceptance.snapshot(expected), acceptance.snapshot(candidate))
                )
                m.write(candidate / path, after)
                self.assertTrue(
                    m.oracle.differences(acceptance.snapshot(expected), acceptance.snapshot(candidate))
                )
                m.write(candidate / path, before)

    def test_known_outcome_cannot_leave_helper_authority_active(self) -> None:
        with mock.patch.object(acceptance.lifecycle.runtime, "copy_program"):
            case = acceptance.Scenario(
                self.workspace, "stranded-trigger-authority", self.workspace / "driver",
                None, "amd64", {},
            )
        m.write(case.candidate / "var/lib/debz/native-trigger-authority-v1.json", b"{}")
        with (
            mock.patch.object(acceptance, "reference", return_value=0),
            mock.patch.object(acceptance, "native", return_value={"outcome": "applied"}),
        ):
            with self.assertRaisesRegex(AssertionError, "stranded active evidence"):
                case.phase("process_triggers")

    def test_malformed_queue_can_be_observed_without_normalizing_it(self) -> None:
        root = self.workspace / "root"
        m.make_root(root, "amd64")
        before = acceptance.snapshot(root)
        m.write(root / "var/lib/dpkg/triggers/Unincorp", b"invalid\x00trigger -\n")
        observed = acceptance.snapshot(root)
        self.assertTrue(m.oracle.differences(before, observed))
        self.assertFalse(m.oracle.differences(observed, acceptance.snapshot(root)))

    def test_reference_binary_cannot_be_supplied_as_native_helper(self) -> None:
        driver, helper = self.workspace / "driver", self.workspace / "helper"
        for path in (driver, helper):
            m.write(path, b"fixture")
        with (
            mock.patch("sys.argv", [
                "test-native-triggers.py", str(driver), "--native-helper", str(helper),
            ]),
            mock.patch.object(acceptance.os, "geteuid", return_value=0),
            mock.patch.object(acceptance.shutil, "which", return_value="/fixture"),
            mock.patch.object(Path, "read_bytes", return_value=b"identical binary"),
            mock.patch.object(acceptance.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(AssertionError, "reference dpkg-trigger executable"):
                acceptance.main()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
