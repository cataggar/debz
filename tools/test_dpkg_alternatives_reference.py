"""Regression coverage for the bounded dpkg/update-alternatives reference."""

from __future__ import annotations

import base64
from collections import Counter
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_dpkg_alternatives_reference",
    ROOT / "tools/dpkg-alternatives-reference.py",
)
assert SPEC and SPEC.loader
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


def record_text(state: dict) -> str | None:
    record = state["record"]
    if record is None:
        return None
    return base64.b64decode(record["bytes_base64"]).decode()


def selector_target(state: dict, name: str) -> str | None:
    selected = [
        item["fact"]["target"]
        for item in state["selectors"]
        if item["name"] == name and item["fact"] is not None
    ]
    if len(selected) > 1:
        raise AssertionError(f"duplicate selector in observation: {name}")
    return selected[0] if selected else None


class DpkgAlternativesReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="dpkg-alternatives-reference-unit-",
            dir=ROOT / ".tmp",
        )
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_reference_is_canonical_schema_valid_and_source_bound(self) -> None:
        reference = oracle.load_reference()
        schema = json.loads(
            (ROOT / "schema/dpkg-alternatives-reference-v1.json").read_bytes()
        )
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(reference)
        self.assertEqual(
            (
                ROOT
                / "tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json"
            ).read_bytes(),
            oracle.canonical_json(reference).encode(),
        )
        derived = oracle.verify_source_bindings(reference)
        alternatives = derived["alternatives"]
        self.assertEqual(len(alternatives["groups"]), 14)
        self.assertEqual(len(alternatives["requested_paths"]), 189)
        self.assertEqual(len(alternatives["linked_entries"]), 190)
        self.assertEqual(
            sum(len(group["links"]) for group in alternatives["groups"]),
            72,
        )
        self.assertEqual(
            reference["source"]["dpkg"]["architectures"],
            {
                architecture: {
                    "archive_sha256": pins["archive"],
                    "dpkg_sha256": pins["executable"],
                    "update_alternatives_sha256": pins["update_alternatives"],
                }
                for architecture, pins in oracle.m.reference_dpkg.PINS.items()
            },
        )
        self.assertEqual(
            reference["source"]["dpkg"]["configuration_sha256"],
            hashlib.sha256(oracle.config.PINNED_DPKG_CONFIG).hexdigest(),
        )
        self.assertEqual(
            reference["boundary"]["invocation_clock"]["task_invocation"],
            oracle.CANONICAL_TASK_INVOCATION,
        )

        invalid = copy.deepcopy(reference)
        del invalid["observed_behavior"]["external_update_alternatives"][
            "selection"
        ]["steps"][0]["result"]["command"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(invalid)

    def test_publication_has_exact_dual_architecture_evidence(self) -> None:
        reference = oracle.load_reference()
        oracle.validate_observation_architecture(reference, "amd64")
        oracle.validate_observation_architecture(reference, "arm64")
        with self.assertRaisesRegex(oracle.OracleError, "architecture-specific"):
            oracle.validate_observation_architecture(reference, "riscv64")
        self.assertEqual(
            reference["boundary"]["observed_architectures"],
            ["amd64", "arm64"],
        )
        evidence = reference["architecture_evidence"]["arm64"]
        self.assertEqual(evidence["difference_count"], 190)
        self.assertEqual(
            evidence["difference_summary"],
            {
                "architecture_derived_bytes_base64": 64,
                "architecture_derived_logs": 26,
                "architecture_derived_sha256": 80,
                "architecture_fields": 20,
            },
        )
        self.assertEqual(
            Counter(
                difference["path"].rsplit("/", 1)[-1]
                for difference in evidence["differences_from_baseline"]
            ),
            Counter(
                {
                    "Architecture": 1,
                    "architecture": 19,
                    "bytes_base64": 64,
                    "log": 26,
                    "sha256": 80,
                }
            ),
        )
        arm64 = oracle.config.verify_architecture_evidence(reference)
        self.assertEqual(
            arm64["external_update_alternatives"],
            reference["observed_behavior"]["external_update_alternatives"],
        )
        self.assertEqual(
            arm64["separation"],
            reference["observed_behavior"]["separation"],
        )

    def test_vendor_projection_covers_every_pinned_group_and_requested_path(self) -> None:
        reference = oracle.load_reference()
        projection = reference["observed_behavior"][
            "external_update_alternatives"
        ]["vendor_projection"]
        self.assertEqual(projection["group_count"], 14)
        self.assertEqual(projection["relationship_count"], 72)
        self.assertEqual(projection["requested_path_count"], 189)
        self.assertEqual(
            [group["name"] for group in projection["groups"]],
            reference["vendor_projection"]["group_names"],
        )
        for group in projection["groups"]:
            record = group["record"]
            self.assertEqual(
                (record["kind"], record["mode"], record["uid"], record["gid"]),
                ("regular", "0644", 0, 0),
            )
            self.assertEqual(record_text({"record": record}).splitlines()[0], "auto")
            for item in [*group["generic_links"], *group["selectors"]]:
                self.assertEqual(
                    (
                        item["fact"]["kind"],
                        item["fact"]["mode"],
                        item["fact"]["uid"],
                        item["fact"]["gid"],
                    ),
                    ("symlink", "0777", 0, 0),
                )

    def test_auto_manual_priority_ties_and_removal_are_exact(self) -> None:
        steps = oracle.load_reference()["observed_behavior"][
            "external_update_alternatives"
        ]["selection"]["steps"]
        by_name = {step["operation"]: step for step in steps}
        self.assertTrue(all(step["result"]["exit"] == 0 for step in steps))
        self.assertEqual(
            selector_target(
                by_name["install-a-10-tie"]["state"],
                "debz-choice",
            ),
            "/usr/lib/debz-choice/b",
        )
        self.assertEqual(
            selector_target(
                by_name["remove-c-tie-selects-a"]["state"],
                "debz-choice",
            ),
            "/usr/lib/debz-choice/a",
        )
        self.assertEqual(
            selector_target(
                by_name["raise-c-30-manual-sticks"]["state"],
                "debz-choice",
            ),
            "/usr/lib/debz-choice/a",
        )
        self.assertTrue(
            record_text(by_name["set-a-manual"]["state"]).startswith("manual\n")
        )
        self.assertTrue(
            record_text(by_name["auto-selects-c"]["state"]).startswith("auto\n")
        )
        self.assertEqual(by_name["remove-all"]["state"]["record"], None)
        self.assertEqual(by_name["remove-all"]["state"]["selectors"], [])

    def test_missing_targets_shape_changes_and_corrupt_records_are_observed(self) -> None:
        external = oracle.load_reference()["observed_behavior"][
            "external_update_alternatives"
        ]
        steps = {
            step["operation"]: step
            for step in external["missing_targets_and_group_shape"]["steps"]
        }
        self.assertEqual(steps["install-missing-high"]["result"]["exit"], 2)
        self.assertIsNone(steps["install-missing-high"]["state"]["record"])
        self.assertIn(
            "doesn't exist",
            steps["install-missing-high"]["result"]["output"],
        )
        self.assertEqual(
            selector_target(
                steps["install-second-with-slave"]["state"],
                "debz-missing",
            ),
            "/usr/lib/debz-missing/second",
        )
        self.assertIsNone(
            selector_target(
                steps["reregister-selected-without-slave"]["state"],
                "debz-missing.1",
            )
        )
        self.assertIsNone(steps["auto-with-all-targets-missing"]["state"]["record"])

        malformed = external["malformed_records"]
        self.assertEqual(
            {
                item["case"]: item["result"]["exit"]
                for item in malformed["regular_record_cases"]
            },
            {
                "embedded-nul": 2,
                "empty": 2,
                "invalid-mode": 2,
                "invalid-priority": 2,
                "truncated": 2,
            },
        )
        self.assertEqual(
            {item["case"] for item in malformed["oracle_preflight_rejections"]},
            {"directory", "fifo", "oversized", "symlink"},
        )

    def test_attack_and_atomicity_partial_states_are_canonical(self) -> None:
        external = oracle.load_reference()["observed_behavior"][
            "external_update_alternatives"
        ]
        attacks = {
            item["case"]: item
            for item in external["path_and_symlink_attacks"]["raw_tool_cases"]
        }
        self.assertEqual(attacks["generic-link-traversal"]["result"]["exit"], 0)
        self.assertEqual(
            attacks["generic-link-traversal"]["outside_root"]["target"],
            "/etc/alternatives/escape",
        )
        self.assertEqual(
            attacks["alternatives-directory-symlink"]["outside_root"]["target"],
            "/usr/lib/provider",
        )
        self.assertEqual(attacks["self-referential-provider"]["result"]["exit"], 2)
        self.assertEqual(attacks["indirect-symlink-cycle"]["result"]["exit"], 0)
        self.assertIn(
            "doesn't exist",
            attacks["indirect-symlink-cycle"]["result"]["output"],
        )
        self.assertEqual(
            attacks["indirect-symlink-cycle"]["provider"]["target"],
            "/usr/bin/cycle-link",
        )
        self.assertIsNotNone(
            attacks["indirect-symlink-cycle"]["state"]["record"]
        )

        failures = external["atomicity"]["failure_injection"]
        self.assertTrue(all(item["result"]["exit"] == 2 for item in failures))
        self.assertTrue(all(item["state"]["record"] is None for item in failures))
        self.assertTrue(
            all(
                any(
                    selector["name"] == "atomic.dpkg-tmp"
                    for selector in item["state"]["selectors"]
                )
                for item in failures
            )
        )
        self.assertTrue(
            all("link group atomic updated" in item["result"]["log"] for item in failures)
        )

    def test_direct_dpkg_member_lifecycle_scripts_failures_and_recovery(self) -> None:
        direct = oracle.load_reference()["observed_behavior"]["direct_dpkg"]
        scriptless = direct["scriptless_alternatives_member"]
        self.assertIsNone(scriptless["installed"]["alternatives"]["record"])
        installed_member = next(
            item for item in scriptless["installed"]["info"]
            if item["name"] == "alternatives"
        )
        self.assertEqual((installed_member["mode"], installed_member["uid"], installed_member["gid"]), ("0640", 0, 0))
        self.assertEqual(scriptless["removed"]["info"], [])
        self.assertEqual(scriptless["purged"]["info"], [])

        phases = {
            phase["operation"]: phase
            for phase in direct["successful_lifecycle"]["phases"]
        }
        self.assertTrue(all(phase["result"]["exit"] == 0 for phase in phases.values()))
        self.assertEqual(phases["install"]["state"]["database"]["committed"]["status"], "install ok installed")
        self.assertEqual(phases["upgrade"]["state"]["database"]["committed"]["version"], "2")
        self.assertIsNotNone(phases["upgrade"]["state"]["alternatives"]["record"])
        self.assertIsNone(phases["remove"]["state"]["alternatives"]["record"])
        self.assertEqual(
            [item["name"] for item in phases["remove"]["state"]["info"]],
            ["list", "postrm"],
        )
        self.assertEqual(phases["purge"]["state"]["info"], [])

        conflict = direct["conflicting_packages"]
        self.assertEqual(conflict["first_result"]["exit"], 0)
        self.assertEqual(conflict["second_result"]["exit"], 1)
        self.assertIn(
            "trying to overwrite",
            conflict["second_result"]["output"],
        )
        self.assertEqual(
            base64.b64decode(conflict["shared_file"]["fact"]["bytes_base64"]),
            b"first owner\n",
        )
        self.assertEqual(
            conflict["shared_file"]["path"],
            "usr/lib/debz-alternatives/package-conflict",
        )

        failures = {item["case"]: item for item in direct["failure_recovery"]}
        self.assertEqual(failures["fresh-postinst"]["operation_result"]["exit"], 1)
        self.assertEqual(
            failures["fresh-postinst"]["failed"]["database"]["committed"]["status"],
            "install ok half-configured",
        )
        self.assertIsNotNone(
            failures["fresh-postinst"]["failed"]["alternatives"]["record"]
        )
        self.assertEqual(failures["upgrade-prerm"]["operation_result"]["exit"], 0)
        self.assertIn(
            "failed-upgrade",
            "\n".join(
                " ".join([item["script"], *item["arguments"]])
                for item in failures["upgrade-prerm"]["failed"]["trace"]
            ),
        )
        self.assertEqual(failures["upgrade-postinst"]["operation_result"]["exit"], 1)
        self.assertEqual(failures["remove-postrm"]["operation_result"]["exit"], 1)
        self.assertIsNone(
            failures["remove-postrm"]["failed"]["alternatives"]["record"]
        )
        self.assertTrue(
            all(item["recovery_result"]["exit"] == 0 for item in failures.values())
        )
        self.assertTrue(all(len(item["archives"]) == 2 for item in failures.values()))

        interruption = direct["interruption_recovery"]
        self.assertEqual(interruption["interruption_result"]["exit"], -9)
        self.assertTrue(interruption["interrupted"]["database"]["journal_nonempty"])
        self.assertTrue(interruption["interrupted"]["database"]["temporary_update"])
        self.assertIsNotNone(interruption["interrupted"]["alternatives"]["record"])
        self.assertEqual(interruption["recovery_result"]["exit"], 0)
        self.assertFalse(interruption["recovered"]["database"]["journal_nonempty"])
        self.assertEqual(
            interruption["recovered"]["database"]["committed"]["status"],
            "install ok installed",
        )

    def test_every_execution_binds_command_outcome_and_relevant_filesystem(self) -> None:
        reference = oracle.load_reference()
        results = []

        def collect(value: object) -> None:
            if isinstance(value, dict):
                if set(value) == {"command", "exit", "log", "output"}:
                    results.append(value)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(reference["observed_behavior"])
        self.assertEqual(len(results), 70)
        self.assertTrue(
            all(
                result["command"][0]
                in {"<pinned-dpkg>", "<pinned-update-alternatives>"}
                for result in results
            )
        )
        self.assertTrue(
            all(str(ROOT) not in argument for result in results for argument in result["command"])
        )
        self.assertNotIn(str(ROOT), oracle.canonical_json(reference))

        direct = reference["observed_behavior"]["direct_dpkg"]
        states = [
            phase["state"] for phase in direct["successful_lifecycle"]["phases"]
        ]
        self.assertTrue(all(state["database_files"] for state in states))
        self.assertIn(
            "var/lib/dpkg/lock",
            {item["path"] for item in states[0]["database_files"]},
        )
        self.assertIn(
            "var/lib/dpkg/info/debz-alt-lifecycle.alternatives",
            {item["path"] for item in states[0]["all_info"]},
        )
        self.assertTrue(all(state["trace"] for state in states[:-2]))
        self.assertTrue(
            any(
                item["path"].startswith("usr/lib/debz-alternatives/")
                for item in states[0]["payload"]
            )
        )

    def test_paths_records_scripts_and_root_guards_fail_closed(self) -> None:
        for path in ("/../escape", "/usr/bin/../escape", "relative", "/", "/a//b"):
            with self.assertRaises(oracle.OracleError):
                oracle.validate_absolute_path(path)
        for name in ("../escape", "a/b", ".hidden", "A", ""):
            with self.assertRaises(oracle.OracleError):
                oracle.validate_name(name)

        body = oracle.package_scripts("debz-alt-test", "1", "debz-alt-test", 10)
        for script in body.values():
            result = oracle.subprocess.run(
                ["/bin/sh", "-n"],
                input=script,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        root = self.workspace / "root"
        oracle.make_root(root, "amd64")
        oracle.validate_root(root)
        escaped = self.workspace / "escaped"
        escaped.mkdir()
        (root / "etc/alternatives").rmdir()
        (root / "etc/alternatives").symlink_to(escaped)
        with self.assertRaisesRegex(oracle.OracleError, "state directory is unsafe"):
            oracle.validate_root(root)

    def test_subprocess_timeout_kills_the_complete_process_group(self) -> None:
        output = self.workspace / "timeout.log"
        with self.assertRaisesRegex(oracle.OracleError, "1-second timeout"):
            oracle.run_bounded_process(
                ["/bin/sh", "-c", "sleep 30"],
                dict(oracle.ENVIRONMENT),
                output,
                timeout=1,
            )


if __name__ == "__main__":
    unittest.main()
