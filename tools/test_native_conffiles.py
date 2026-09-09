"""Regression coverage for phase-by-phase conffile acceptance."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conffile_acceptance", ROOT / "tools/test-native-conffiles.py",
)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)
materialization = acceptance.materialization


class ConffileOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="conffile-oracle-", dir=ROOT / ".tmp",
        )
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_reference_phases_require_a_disposable_root(self) -> None:
        with mock.patch.object(materialization, "run") as run:
            for operation in ("configure", "remove", "purge"):
                with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                    acceptance.reference_phase(
                        Path("/"), None, operation, "keep_existing", {}, self.workspace,
                    )
            run.assert_not_called()

    def test_remove_on_upgrade_declares_but_does_not_ship_conffile(self) -> None:
        with mock.patch.object(materialization, "run"):
            archive = materialization.make_package(
                self.workspace, {}, "amd64", "2", "remove-on-upgrade",
            )
        source = archive.with_suffix(".source")
        self.assertFalse((source / acceptance.CONFIG).exists())
        self.assertEqual(
            (source / "DEBIAN/conffiles").read_bytes(),
            b"remove-on-upgrade /etc/debz-native.conf\n",
        )

    def test_fixture_can_change_conffile_without_changing_its_path(self) -> None:
        with mock.patch.object(materialization, "run"):
            archive = materialization.make_package(
                self.workspace, {}, "amd64", "2", "conffile",
                conffile_content=acceptance.NEW_CONFIG,
            )
        self.assertEqual(
            (archive.with_suffix(".source") / acceptance.CONFIG).read_bytes(),
            acceptance.NEW_CONFIG,
        )

    def test_native_request_binds_phase_policy_and_selected_packages(self) -> None:
        root = self.workspace / "root"
        materialization.make_root(root, "amd64")
        packages = [{"name": materialization.PACKAGE, "architecture": "amd64"}]
        with mock.patch.object(materialization, "run"):
            materialization.write(
                self.workspace / "native.report.json", b'{"outcome":"applied"}',
            )
            materialization.native(
                self.workspace / "driver", root, None, "amd64", "purge",
                {}, self.workspace, conffiles=True, policy="use_package_version",
                packages=packages,
            )
        request = json.loads((self.workspace / "native.request.json").read_bytes())
        self.assertEqual(request["operation"], "purge")
        self.assertEqual(request["archives"], [])
        self.assertEqual(request["packages"], packages)
        self.assertTrue(request["conffiles"])
        self.assertEqual(request["policy"], "use_package_version")

    def test_success_report_cannot_hide_a_wrong_resulting_root(self) -> None:
        case = acceptance.Scenario(
            self.workspace, "wrong-root", self.workspace / "driver", "amd64", {},
        )
        for root in case.roots:
            materialization.write(root / acceptance.CONFIG, acceptance.OLD_CONFIG)

        def reference(root: Path, *_args: object, **_kwargs: object) -> None:
            (root / acceptance.CONFIG).unlink()

        with (
            mock.patch.object(acceptance, "reference_phase", side_effect=reference),
            mock.patch.object(materialization, "native", return_value={"outcome": "applied"}),
        ):
            with self.assertRaisesRegex(AssertionError, "native/dpkg mismatch"):
                case.phase("purge")


if __name__ == "__main__":
    unittest.main()
