"""Regression coverage for independent native trigger acceptance."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
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

    def test_settlement_reference_selector_cannot_claim_native_parity(self) -> None:
        with (
            mock.patch("sys.argv", [
                "test-native-triggers.py", "/driver", "--native-helper", "/helper",
                "--diversion-settlement-reference-only",
            ]),
            mock.patch("sys.stderr", new_callable=io.StringIO),
            mock.patch.object(acceptance.subprocess, "run") as run,
        ):
            with self.assertRaises(SystemExit) as failure:
                acceptance.main()
            self.assertEqual(failure.exception.code, 2)
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


class SettlementOracleTests(unittest.TestCase):
    epoch = 1000
    architecture = "amd64"
    controls = {"1": {"postrm": "old"}, "2": {"postrm": "new"}}

    def observation(self, update="atomic", member="regular") -> dict:
        oracle = acceptance.settlement
        source = oracle.MEMBERS[member]
        original = source + ".original"
        old = oracle.payload("1", self.epoch)
        before = copy.deepcopy(old)
        before[original] = before.pop(source)
        inodes = {path: 100 + index for index, path in enumerate(before)}
        before_rows = [{"path": path, **row} for path, row in before.items()]
        observed = oracle.payload("1" if update == "rollback" else "2", self.epoch)
        observed[f"{oracle.BASE}/current"]["mtime_ns"] = 2000 * 10**9
        data = {
            "case": [update, member], "exit": int(update == "rollback"),
            "started_ns": 2000 * 10**9, "finished_ns": 2001 * 10**9,
            "before": {"filesystem": before_rows}, "before_inodes": inodes,
            "before_diversions": {
                "device": 1, "inode": 1, "bytes": f"/{source}\n/{original}\n:\n",
            },
            "diversions": {"device": 1, "inode": 2, "bytes": oracle.diversion_bytes(update, source)},
            "after": {"filesystem": [{"path": path, **row} for path, row in observed.items()]},
        }
        data["after"]["filesystem"] = [
            {"path": path, **row} for path, row in oracle.expected_upgrade(data, self.epoch).items()
        ]
        trace = []
        for identity, arguments in oracle.expected_calls(update, member):
            package = identity.split("@")[0]
            kind = identity.rsplit(":", 1)[1]
            trace.append("\t".join([
                identity, package, kind, self.architecture, str(len(arguments)),
                *(f"{len(arg)}:{arg}" for arg in arguments), "payload=fixture",
            ]))
            if identity == f"{oracle.PACKAGE}@1:postrm":
                for path, row in before.items():
                    logical = source if path == original else path
                    if logical not in oracle.payload("2", self.epoch) or logical == oracle.CONFFILE or row["kind"] == "directory":
                        continue
                    inode = inodes[path] + (1000 if row["kind"] == "symlink" else 0)
                    seconds = 2000 if row["kind"] == "symlink" else self.epoch
                    trace.append(f"backup-stat:/{path}.dpkg-tmp:{row['mode'].lstrip('0')}:0:0:{seconds}:{inode}")
        data["trace"] = "\n".join(trace) + "\n"
        version = "1" if update == "rollback" else "2"
        digest = hashlib.md5(f"configuration {version}\n".encode()).hexdigest()
        data["after"]["dpkg"] = {"status": [{
            "package": oracle.PACKAGE, "version": version, "status": "install ok installed",
            "conffiles": f"\n/{oracle.CONFFILE} {digest}",
        }]}
        data["list"] = "\n".join([
            "/.", "/etc", "/usr", "/usr/share", *("/" + path for path in oracle.payload(version, 0)),
        ]) + "\n"
        data["controls"] = self.controls[version].copy()
        oracle.assert_upgrade(data, self.epoch, self.architecture, self.controls)
        return data

    def check(self, data: dict) -> None:
        acceptance.settlement.assert_upgrade(data, self.epoch, self.architecture, self.controls)

    def test_reference_matrix_preserves_full_failure_scope(self) -> None:
        cases = acceptance.settlement.CASES
        self.assertEqual(len(cases), 24)
        self.assertEqual(len(set(cases)), 24)
        self.assertEqual(sum(update not in ("rollback", "postinst-failure") for update, _ in cases), 16)
        self.assertIn(("rollback", "introduced"), cases)
        self.assertIn(("rollback", "conffile"), cases)
        self.assertIn(("rollback", "hardlink-source"), cases)

    def test_success_lowering_corpus_is_derived_from_the_reference_profiles(self) -> None:
        corpus = json.loads(
            (
                ROOT
                / "src/fixtures/native-diversion-success-settlement-v1.json"
            ).read_bytes()
        )
        expected = [
            acceptance.settlement.successful_route_profile(update, member)
            for update, member in acceptance.settlement.SUCCESSFUL_POSTRM_CASES
        ]
        self.assertEqual(corpus, expected)
        self.assertEqual(len(corpus), 15)

    def test_failure_and_unwind_profiles_cannot_enter_success_lowering(self) -> None:
        for case in (
            ("unwind-success", "regular"),
            ("rollback", "regular"),
            ("postinst-failure", "conffile"),
        ):
            with self.subTest(case=case), self.assertRaisesRegex(
                ValueError, "not a successful old-postrm"
            ):
                acceptance.settlement.successful_route_profile(*case)

    def test_subsequent_directory_trigger_does_not_invent_an_obsolete_removal(self) -> None:
        oracle = acceptance.settlement
        self.assertEqual(
            oracle.expected_calls("atomic", "directory", reinstall=True)[-1],
            (f"{oracle.WATCHER}@1:postinst", ["triggered", "/" + oracle.BASE + ".changed"]),
        )

    def test_retained_backup_cannot_be_missing_or_replaced(self) -> None:
        data = self.observation()
        path = acceptance.settlement.MEMBERS["regular"] + ".original.dpkg-tmp"
        for field, value in (("mode", "0640"), ("sha256", "0" * 64), ("uid", 1), ("mtime_ns", 0)):
            changed = copy.deepcopy(data)
            row = next(row for row in changed["after"]["filesystem"] if row["path"] == path)
            row[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, "settled filesystem"):
                self.check(changed)
        data["after"]["filesystem"] = [row for row in data["after"]["filesystem"] if row["path"] != path]
        with self.assertRaisesRegex(AssertionError, "settled filesystem"):
            self.check(data)

    def test_backup_visibility_requires_the_original_inode_during_postrm(self) -> None:
        data = self.observation()
        path = acceptance.settlement.MEMBERS["regular"] + ".original"
        data["before_inodes"][path] += 1
        with self.assertRaisesRegex(AssertionError, "regular backup inode"):
            self.check(data)

    def test_backup_visibility_cannot_be_deferred_until_postinst(self) -> None:
        data = self.observation()
        lines = data["trace"].splitlines()
        data["trace"] = "\n".join(
            [line for line in lines if not line.startswith("backup-stat:")]
            + [line for line in lines if line.startswith("backup-stat:")]
        )
        with self.assertRaisesRegex(AssertionError, "old postrm visible backups"):
            self.check(data)

    def test_trigger_cannot_be_rerouted_after_publication(self) -> None:
        data = self.observation()
        route = "/" + acceptance.settlement.MEMBERS["regular"]
        old, new = route + ".original", route + ".changed"
        data["trace"] = data["trace"].replace(f"{len(old)}:{old}", f"{len(new)}:{new}")
        with self.assertRaisesRegex(AssertionError, "trigger routes"):
            self.check(data)

    def test_status_and_control_publication_are_not_inferred_from_exit(self) -> None:
        data = self.observation()
        for key, value in (("version", "1"), ("status", "install ok half-configured"), ("conffiles", "")):
            changed = copy.deepcopy(data)
            changed["after"]["dpkg"]["status"][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check(changed)
        data["controls"]["postrm"] = "old"
        with self.assertRaisesRegex(AssertionError, "installed control bytes"):
            self.check(data)

    def test_full_rollback_cannot_replace_reference_partial_rollback(self) -> None:
        oracle = acceptance.settlement
        data = self.observation("rollback", "hardlink-source")
        path = oracle.MEMBERS["hardlink-source"] + ".original"
        row = next(row for row in data["after"]["filesystem"] if row["path"] == path)
        row["sha256"] = oracle.payload("1", self.epoch)[oracle.MEMBERS["hardlink-source"]]["sha256"]
        with self.assertRaisesRegex(AssertionError, "settled filesystem"):
            self.check(data)

    def test_partial_rollback_preserves_the_old_backup_hard_link(self) -> None:
        data = self.observation("rollback", "hardlink-source")
        path = acceptance.settlement.MEMBERS["hardlink-source"] + ".original.dpkg-tmp"
        row = next(row for row in data["after"]["filesystem"] if row["path"] == path)
        row["hardlink_to"] = None
        with self.assertRaisesRegex(AssertionError, "settled filesystem"):
            self.check(data)

    def test_partial_rollback_does_not_publish_the_incoming_file_list(self) -> None:
        data = self.observation("rollback", "hardlink-source")
        data["list"] += f"/{acceptance.settlement.BASE}/introduced\n"
        with self.assertRaisesRegex(AssertionError, "logical installed file list"):
            self.check(data)

    def test_partial_rollback_requires_the_complete_compensation_sequence(self) -> None:
        data = self.observation("rollback", "hardlink-source")
        data["trace"] = "\n".join(
            line for line in data["trace"].splitlines()
            if not line.startswith(f"{acceptance.settlement.PACKAGE}@1:preinst")
        )
        with self.assertRaisesRegex(AssertionError, "script order"):
            self.check(data)

    def test_known_failure_cannot_be_relabelled_success(self) -> None:
        data = self.observation("rollback", "hardlink-source")
        data["exit"] = 0
        with self.assertRaisesRegex(AssertionError, "upgrade exit"):
            self.check(data)

    def test_atomic_replacement_is_not_an_in_place_edit_or_an_unchanged_database(self) -> None:
        data = self.observation()
        data["diversions"]["inode"] = data["before_diversions"]["inode"]
        with self.assertRaisesRegex(AssertionError, "diversion database identity"):
            self.check(data)
        data = self.observation()
        data["diversions"]["bytes"] = data["before_diversions"]["bytes"]
        with self.assertRaisesRegex(AssertionError, "live diversion bytes"):
            self.check(data)

    def test_recreated_symlink_time_is_bounded_not_ignored(self) -> None:
        data = self.observation("rollback", "hardlink-source")
        row = next(row for row in data["after"]["filesystem"] if row["kind"] == "symlink")
        row["mtime_ns"] = self.epoch * 10**9
        with self.assertRaisesRegex(AssertionError, "invocation clock"):
            self.check(data)


if __name__ == "__main__":
    unittest.main()
