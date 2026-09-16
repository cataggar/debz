"""Regressions for actual-process native recovery acceptance."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_recovery_acceptance", ROOT / "tools/test-native-recovery.py",
)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)
m = acceptance.m


class RecoveryOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="recovery-oracle-", dir=ROOT / ".tmp")
        self.workspace = Path(self.temporary.name)
        self.root = self.workspace / "root"
        m.make_root(self.root, "amd64")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_consumer_parity_requires_every_suite_case_and_actual_consumer(self) -> None:
        rows = [
            {"suite": suite, "case": case["id"], "architecture": "amd64",
             "consumers": ["core-cli", "family", "dpkg-reference"], "matched": True}
            for suite in acceptance.CONSUMER_PARITY_SUITES for case in acceptance.CONSUMER_PARITY_CASES
        ]
        report = acceptance.consumer_parity_coverage(rows, "amd64")
        self.assertEqual(report["scope"], "signed-hermetic-fixtures")
        self.assertEqual(len(report["cases"]), 24)
        for incomplete in ([], rows[:-1], [*rows, rows[0]], [{**rows[0], "case": "unreviewed"}, *rows[1:]]):
            with self.assertRaisesRegex(AssertionError, "incomplete or duplicated"):
                acceptance.consumer_parity_coverage(incomplete, "amd64")
        for changed in (
            {"architecture": "arm64"}, {"consumers": ["core-cli", "dpkg-reference"]}, {"matched": False},
        ):
            with self.assertRaisesRegex(AssertionError, "actual matching consumers"):
                acceptance.consumer_parity_coverage([{**rows[0], **changed}, *rows[1:]], "amd64")
        with self.assertRaises(AssertionError):
            acceptance.consumer_parity_coverage(rows, "other")

    def test_consumer_parity_keeps_policy_noop_failure_and_suite_cases(self) -> None:
        cases = {case["id"]: case for case in acceptance.CONSUMER_PARITY_CASES}
        self.assertEqual(acceptance.CONSUMER_PARITY_SUITES, ("debian-stable", "ubuntu-26.04"))
        self.assertTrue(cases["with-recommends"]["recommends"])
        self.assertNotIn("recommends", cases["without-recommends"])
        self.assertEqual(cases["held-unchanged"]["archives"], ())
        self.assertTrue(cases["held-unchanged"]["update"])
        self.assertEqual(cases["held-unchanged"]["hold"], "fixture-upgrade")
        self.assertEqual(cases["known-script-failure"]["exit_status"], 7)
        self.assertEqual(cases["conffile-keep"]["conffile"], "keep_existing")
        self.assertEqual(cases["conffile-replace"]["conffile"], "use_package_version")
        self.assertEqual(cases["suite-trigger"]["package"], "trigger-pkg")

    def test_handler_schemas_require_explicit_absence_or_a_real_digest(self) -> None:
        for schema, definition in (
            ("native-transaction-authorization-v1", "triggerHandler"),
            ("native-transaction-program-v1", "triggerHandlerBinding"),
        ):
            validator = acceptance.validator(schema)
            handler_validator = validator.evolve(schema={
                "$defs": validator.schema["$defs"], "$ref": f"#/$defs/{definition}",
            })
            handler = {
                "package": {"name": "receiver", "version": "1", "architecture": "amd64"},
                "source": "installed_package", "postinst_sha256": None, "declarations_sha256": "b" * 64,
            }
            handler_validator.validate(handler)
            handler_validator.validate({**handler, "postinst_sha256": "a" * 64})
            for invalid in (
                {key: value for key, value in handler.items() if key != "postinst_sha256"},
                {**handler, "postinst_sha256": ""},
                {**handler, "postinst_sha256": "not-a-digest"},
                {**handler, "declarations_sha256": None},
            ):
                self.assertFalse(handler_validator.is_valid(invalid))

    def test_recovery_still_refuses_host_root_before_spawn(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                acceptance.native(
                    self.workspace / "driver", Path("/"), "amd64", "recover",
                    [], {}, self.workspace,
                )
            run.assert_not_called()

    def test_family_verification_preserves_expected_request_without_execution_flags(self) -> None:
        request = {"options": {"install_root": str(self.root)}}
        family = {"request": {"root": str(self.root)}, "expect_failure": True}
        destination = self.workspace / "family-verification"
        with (
            mock.patch.object(acceptance.subprocess, "run", return_value=mock.Mock(returncode=0)) as run,
            mock.patch.object(acceptance, "document", return_value={"verified": False}),
        ):
            result = acceptance.workflow(
                self.workspace / "driver", request, destination, {},
                family_verification=family,
            )
        self.assertEqual(result, {"verified": False})
        transport = json.loads((destination / "workflow.request.json").read_bytes())
        self.assertEqual(transport["family_verification"], family)
        self.assertIsNone(transport["completion_crash"])
        self.assertIsNone(transport["owned_verification"])
        self.assertIsNone(transport["native_evidence_output"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_native_completion_capture_is_separate_from_command_report(self) -> None:
        destination = self.workspace / "completion-output"
        with (
            mock.patch.object(acceptance.subprocess, "run", return_value=mock.Mock(returncode=0)),
            mock.patch.object(acceptance, "document", return_value={}),
        ):
            acceptance.workflow(
                self.workspace / "driver", {"options": {"install_root": str(self.root)}},
                destination, {}, capture_evidence=True,
            )
        transport = json.loads((destination / "workflow.request.json").read_bytes())
        self.assertEqual(transport["native_evidence_output"], str(destination / "native-evidence.json"))
        self.assertNotEqual(transport["native_evidence_output"], transport["report"])
        self.assertIsNone(transport["family_verification"])

    def test_family_execution_preserves_request_and_separate_evidence(self) -> None:
        destination = self.workspace / "family-execution"
        family = {"root": str(self.root), "operation": "create"}
        with (
            mock.patch.object(acceptance.subprocess, "run", return_value=mock.Mock(returncode=0)),
            mock.patch.object(acceptance, "document", return_value={"succeeded": True}),
        ):
            acceptance.workflow(
                self.workspace / "driver", {"options": {"install_root": str(self.root)}},
                destination, {}, family_execution=family, capture_evidence=True,
            )
        transport = json.loads((destination / "workflow.request.json").read_bytes())
        self.assertEqual(transport["family_execution"], family)
        self.assertIsNone(transport["family_verification"])
        self.assertIsNone(transport["completion_crash"])
        self.assertEqual(transport["native_evidence_output"], str(destination / "native-evidence.json"))

    def test_family_execution_refuses_host_root_before_spawn(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                acceptance.workflow(
                    self.workspace / "driver", {"options": {"install_root": "/"}},
                    self.workspace / "refused-execution", {},
                    family_execution={"root": "/", "operation": "create"},
                )
            run.assert_not_called()

    def test_family_update_planning_preserves_explicit_method_and_request(self) -> None:
        destination = self.workspace / "family-update-plan"
        family = {"root": str(self.root), "operation": "resolve_lock", "package": None}
        with (
            mock.patch.object(acceptance.subprocess, "run", return_value=mock.Mock(returncode=0)),
            mock.patch.object(acceptance, "document", return_value={"succeeded": True}),
        ):
            acceptance.workflow(
                self.workspace / "driver", {"options": {"install_root": str(self.root)}},
                destination, {}, family_execution=family, family_update_planning=True,
                capture_evidence=True,
            )
        transport = json.loads((destination / "workflow.request.json").read_bytes())
        self.assertEqual(transport["family_execution"], family)
        self.assertTrue(transport["family_update_planning"])
        self.assertIsNone(transport["completion_crash"])
        self.assertIsNone(transport["family_verification"])

    def test_family_update_planning_requires_family_request_before_spawn(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "requires a family request"):
                acceptance.workflow(
                    self.workspace / "driver", {"options": {"install_root": str(self.root)}},
                    self.workspace / "refused-update-plan", {}, family_update_planning=True,
                )
            run.assert_not_called()

    def test_diagnostic_inspection_retains_partial_package_states_without_success_proof(self) -> None:
        report = {
            "schema": "io.github.cataggar.debz.package-family.result.v2", "version": 2,
            "operation": "inspect", "succeeded": True, "exit_status": "success",
            "changed": False, "lock_path": None, "provenance_path": None,
        }
        inspection = {
            "root": str(self.root), "diagnostic_only": True, "status_database_present": True,
            "native_active_evidence": True, "observed_operation": {"state": "recovering"},
            "deferred_owner": None, "packages": [{
                "name": "partial", "version": "1", "architecture": "amd64",
                "status": {"want": "install", "error_state": "reinst_required", "current": "half_configured"},
            }],
        }
        evidence = {"native_install": None, "native_completion": None, "native_inspection": inspection}
        self.assertEqual(acceptance.diagnostic_inspection(report, evidence, self.root), inspection)
        for changed in (
            {**report, "changed": True},
            {**report, "provenance_path": "/invented/receipt"},
            {**report, "lock_path": "/invented/lock"},
            {**report, "operation": "create"},
        ):
            with self.assertRaises(AssertionError):
                acceptance.diagnostic_inspection(changed, evidence, self.root)

    def test_diagnostic_inspection_refuses_completion_or_authoritative_relabelling(self) -> None:
        report = {
            "schema": "io.github.cataggar.debz.package-family.result.v2", "version": 2,
            "operation": "inspect", "succeeded": True, "exit_status": "success",
            "changed": False, "lock_path": None, "provenance_path": None,
        }
        inspection = {
            "root": str(self.root), "diagnostic_only": True, "status_database_present": False,
            "native_active_evidence": False, "observed_operation": None,
            "deferred_owner": None, "packages": [],
        }
        original = {"native_install": None, "native_completion": None, "native_inspection": inspection}
        for changed in (
            {**original, "native_install": {}},
            {**original, "native_completion": {}},
            {**original, "native_inspection": {**inspection, "diagnostic_only": False}},
            {**original, "native_inspection": {**inspection, "root": "/other-root"}},
        ):
            with self.assertRaises(AssertionError):
                acceptance.diagnostic_inspection(report, changed, self.root)

    def test_family_verification_still_refuses_host_root_before_spawn(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "disposable fixture root"):
                acceptance.workflow(
                    self.workspace / "driver", {"options": {"install_root": "/"}},
                    self.workspace / "refused", {},
                    family_verification={"request": {"root": "/"}},
                )
            run.assert_not_called()

    def test_projection_requires_private_disposable_root_before_mounting(self) -> None:
        projected = self.workspace / "projection/root"
        projected.mkdir(parents=True)
        marker = projected / ".debz-native-projection"
        for root, pid, uid, contents in (
            (Path("/"), 1, 0, "debz native projection fixture v1\n"),
            (self.root, 1, 0, "debz native projection fixture v1\n"),
            (projected, 123, 0, "debz native projection fixture v1\n"),
            (projected, 1, 1000, "debz native projection fixture v1\n"),
            (projected, 1, 0, "not a projection fixture\n"),
        ):
            with self.subTest(root=root, pid=pid, uid=uid, contents=contents):
                marker.write_text(contents)
                with (
                    mock.patch.object(acceptance.os, "getpid", return_value=pid),
                    mock.patch.object(acceptance.os, "geteuid", return_value=uid),
                    mock.patch.object(acceptance.subprocess, "run") as run,
                    mock.patch.object(acceptance.os, "chroot") as chroot,
                    mock.patch.object(acceptance.os, "execve") as execute,
                ):
                    with self.assertRaisesRegex(RuntimeError, "disposable root and private PID namespace"):
                        acceptance.projection_inside(root)
                    run.assert_not_called()
                    chroot.assert_not_called()
                    execute.assert_not_called()

    def test_recovery_has_no_caller_work_or_fault(self) -> None:
        for arguments in (
            {"archives": [self.workspace / "replacement.deb"]},
            {"archives": [], "packages": ("replacement",)},
            {"archives": [], "crash_at": "after_execution_intent"},
        ):
            with self.subTest(arguments=arguments):
                with mock.patch.object(acceptance.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "persisted evidence"):
                        acceptance.native(
                            self.workspace / "driver", self.root, "amd64", "recover",
                            environment={}, destination=self.workspace, **arguments,
                        )
                    run.assert_not_called()

    def test_projection_fixture_modes_cannot_be_combined(self) -> None:
        for function in (acceptance.projection_inside, acceptance.projected_process):
            for arguments in (
                {"workflow": True, "repository": True},
                {"workflow": True, "repository_execution": True},
                {"repository": True, "repository_execution": True},
                {"workflow": True, "repository_cli": True},
                {"repository": True, "repository_cli": True},
                {"repository_execution": True, "repository_cli": True},
            ):
                with self.subTest(function=function.__name__, arguments=arguments), mock.patch.object(acceptance.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                        function(self.root, **arguments)
                    run.assert_not_called()

    def test_repository_projection_uses_its_own_guarded_entry(self) -> None:
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], 0),
        ) as run:
            acceptance.projected_process(self.root, repository=True)
        command = run.call_args.args[0]
        self.assertIn("--repository-projection-inside", command)
        self.assertNotIn("--projected-workflow-inside", command)
        self.assertEqual(command[-1], str(self.root))

    def test_repository_cli_keeps_the_existing_projection_timeout(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            acceptance.projected_process(self.root, repository_cli=True)
        self.assertIn("--repository-cli-inside", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_repository_cli_runs_one_invocation_with_watchdog_after_its_deadline(self) -> None:
        fixture = self.root / "fixture"
        fixture.mkdir()
        (fixture / "cli-arguments.json").write_text(json.dumps(["repo", "add", "--deadline-ms", "60000"]))
        (fixture / "cli-case").write_text("success")
        (fixture / "cli-step").write_text("1")
        child = mock.Mock(returncode=0)
        child.poll.return_value = 0
        child.communicate.return_value = (b'{"exit_status":0}', b"")
        with (
            mock.patch.object(acceptance, "Path", side_effect=lambda path: self.root / str(path).lstrip("/")),
            mock.patch.object(acceptance.subprocess, "Popen", return_value=child) as spawn,
            mock.patch.object(acceptance.time, "monotonic", return_value=100),
        ):
            acceptance.repository_cli_inside({})
        spawn.assert_called_once()
        child.communicate.assert_called_once_with(timeout=65)
        self.assertTrue((fixture / "cli-1.json").is_file())
        self.assertFalse((fixture / "cli-0.json").exists())
        self.assertFalse((fixture / "cli-2.json").exists())

    def test_repository_cli_rejects_invalid_invocation_or_unbounded_watchdog_before_spawn(self) -> None:
        fixture = self.root / "fixture"
        fixture.mkdir()
        (fixture / "cli-case").write_text("success")
        for step, deadline in ((-1, 60000), (3, 60000), (0, 115000)):
            with self.subTest(step=step, deadline=deadline):
                (fixture / "cli-arguments.json").write_text(json.dumps(["--deadline-ms", str(deadline)]))
                (fixture / "cli-step").write_text(str(step))
                with (
                    mock.patch.object(acceptance, "Path", side_effect=lambda path: self.root / str(path).lstrip("/")),
                    mock.patch.object(acceptance.subprocess, "Popen") as spawn,
                ):
                    with self.assertRaises(AssertionError):
                        acceptance.repository_cli_inside({})
                spawn.assert_not_called()

    def test_repository_projection_refuses_host_root_before_entering(self) -> None:
        with (
            mock.patch.object(acceptance.subprocess, "run") as run,
            mock.patch.object(acceptance.os, "chroot") as chroot,
            mock.patch.object(acceptance.os, "execve") as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "disposable root and private PID namespace"):
                acceptance.projection_inside(Path("/"), repository=True)
            run.assert_not_called()
            chroot.assert_not_called()
            execute.assert_not_called()

    def test_repository_execution_uses_its_own_guarded_entry(self) -> None:
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], 0),
        ) as run:
            acceptance.projected_process(self.root, repository_execution=True)
        command = run.call_args.args[0]
        self.assertIn("--repository-execution-inside", command)
        self.assertNotIn("--repository-projection-inside", command)
        self.assertNotIn("--projected-workflow-inside", command)

    def test_repository_execution_refuses_host_root_before_entering(self) -> None:
        with (
            mock.patch.object(acceptance.subprocess, "run") as run,
            mock.patch.object(acceptance.os, "chroot") as chroot,
            mock.patch.object(acceptance.os, "execve") as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "disposable root and private PID namespace"):
                acceptance.projection_inside(Path("/"), repository_execution=True)
            run.assert_not_called()
            chroot.assert_not_called()
            execute.assert_not_called()

    def test_execution_deadline_requires_typed_helper_bound_caller(self) -> None:
        for arguments in (
            {"deadline_after_ms": 0},
            {"deadline_after_ms": 0, "caller_owned": True},
            {"deadline_after_ms": -1, "caller_owned": True, "isolated_helper": True},
            {"deadline_after_ms": 0, "caller_owned": True, "isolated_helper": True, "core_product": True},
        ):
            with self.subTest(arguments=arguments), mock.patch.object(acceptance.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "execution deadlines require"):
                    acceptance.native(
                        self.workspace / "driver", self.root, "amd64", "recover",
                        [], {}, self.workspace, **arguments,
                    )
                run.assert_not_called()

    def test_execution_deadline_preserves_zero_in_private_fixture(self) -> None:
        m.write(self.workspace / "native.report.json", b'{"outcome":"refused"}')
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], 0),
        ):
            acceptance.native(
                self.workspace / "driver", self.root, "amd64", "recover", [], {}, self.workspace,
                caller_owned=True, isolated_helper=True, deadline_after_ms=0,
            )
        request = json.loads((self.workspace / "native.request.json").read_bytes())
        self.assertEqual(request["deadline_after_ms"], 0)

    def test_ignored_crash_selector_cannot_pass_as_a_crash(self) -> None:
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], 0),
        ):
            with self.assertRaisesRegex(AssertionError, "expected 86"):
                acceptance.native(
                    self.workspace / "driver", self.root, "amd64", "install",
                    [], {}, self.workspace, crash_at="after_script_outcome",
                )

    def test_crash_uses_actual_process_exit_without_normal_report(self) -> None:
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], acceptance.CRASH_EXIT),
        ) as run:
            self.assertIsNone(acceptance.native(
                self.workspace / "driver", self.root, "amd64", "install",
                [], {}, self.workspace, crash_at="after_script_outcome",
            ))
        request = json.loads((self.workspace / "native.request.json").read_bytes())
        self.assertTrue(request["recovery"])
        self.assertEqual(request["crash_at"], "after_script_outcome")
        self.assertNotIn("fault", request)
        self.assertIn("DEBZ_NATIVE_LIFECYCLE_REQUEST", run.call_args.kwargs["env"])

    def test_crash_with_a_success_report_is_rejected(self) -> None:
        m.write(self.workspace / "native.report.json", b'{"outcome":"applied"}')
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], acceptance.CRASH_EXIT),
        ):
            with self.assertRaisesRegex(AssertionError, "normal completion report"):
                acceptance.native(
                    self.workspace / "driver", self.root, "amd64", "install",
                    [], {}, self.workspace, crash_at="after_active_clear",
                )

    def test_recovery_request_does_not_reauthorize_an_archive(self) -> None:
        m.write(self.workspace / "native.report.json", b'{"outcome":"applied"}')
        with mock.patch.object(
            acceptance.subprocess, "run",
            return_value=acceptance.subprocess.CompletedProcess([], 0),
        ):
            acceptance.native(
                self.workspace / "driver", self.root, "amd64", "recover",
                [], {}, self.workspace,
            )
        request = json.loads((self.workspace / "native.request.json").read_bytes())
        self.assertEqual(request["operation"], "recover")
        self.assertEqual(request["archives"], [])
        self.assertEqual(request["packages"], [])

    def test_native_acknowledgment_requires_recovering_caller(self) -> None:
        for operation, caller in (("install", True), ("recover", False)):
            with self.subTest(operation=operation, caller=caller):
                with mock.patch.object(acceptance.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "recovering caller"):
                        acceptance.native(
                            self.workspace / "driver", self.root, "amd64", operation,
                            [], {}, self.workspace, caller_owned=caller, acknowledge_native=True,
                        )
                    run.assert_not_called()

    def test_isolated_helper_requires_caller_ownership(self) -> None:
        with mock.patch.object(acceptance.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "native caller"):
                acceptance.native(
                    self.workspace / "driver", self.root, "amd64", "install",
                    [], {}, self.workspace, isolated_helper=True,
                )
            run.assert_not_called()

    def test_empty_exact_lock_v2_schema_preserves_required_bindings(self) -> None:
        value = {
            "schema": "https://debz.dev/schema/exact-closure-lock-v2",
            "version": 2, "target_architecture": "amd64",
            "request_sha256": "07" * 32, "policy_sha256": "08" * 32,
            "repositories": [], "local_artifacts": [], "packages": [],
        }
        value["digest_sha256"] = acceptance.digest("", value)
        self.assertEqual(value["digest_sha256"],
                         "cd84da2b85532fb27bbcd53a085a4446bd3c25c9b816808d8ce8c9e3c12b60e6")
        validator = acceptance.validator("exact-closure-lock-v2")
        validator.validate(value)
        for field in ("target_architecture", "request_sha256", "policy_sha256", "packages", "digest_sha256"):
            with self.subTest(field=field):
                invalid = dict(value)
                del invalid[field]
                self.assertFalse(validator.is_valid(invalid))
        legacy = {**value, "schema": "https://debz.dev/schema/exact-closure-lock-v1", "version": 1}
        del legacy["local_artifacts"]
        self.assertFalse(acceptance.validator("exact-closure-lock-v1").is_valid(legacy))

    def test_isolated_invocation_evidence_cannot_be_omitted(self) -> None:
        request = {
            "execution": {"install_root": "/fixture"},
            "helper": {"source_path": "var/lib/debz/helper", "target_path": "usr/bin/dpkg-trigger", "sha256": "a" * 64},
        }
        script = {
            "package": "example", "architecture": "amd64", "kind": "postinst",
            "source": "new_package", "package_version": "1", "environment": [],
            "arguments": ["configure", ""], "script_sha256": "b" * 64, "invocation_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(AssertionError, "isolated helper"):
            acceptance.assert_helper_invocations(request, {"script_policy_sha256": "c" * 64}, [script])

    def test_helper_request_schema_supports_jsonschema_without_referencing(self) -> None:
        compatibility = importlib.util.module_from_spec(SPEC)
        with mock.patch.dict("sys.modules", {"referencing": None}):
            SPEC.loader.exec_module(compatibility)
        self.assertIsNone(compatibility.Registry)
        self.assertIsNone(compatibility.Resource)

        execution = {
            "schema": "https://debz.dev/schema/native-execution-request-v1",
            "version": 1, "backend": "native", "completion_owner": "caller",
            "install_root": str(self.root), "root_identity_sha256": "a" * 64,
            "root_inode": self.root.stat().st_ino, "architecture": "amd64",
            "caller": {
                "attempt_id": "b" * 64, "operation": {"package_transaction": "install"},
                "request_sha256": "c" * 64, "policy_sha256": "d" * 64,
            },
            "program": {
                field: "e" * 64 for field in (
                    "request_sha256", "solver_policy_sha256", "executor_policy_sha256",
                    "plan_sha256", "authorization_sha256", "program_sha256",
                    "exact_lock_sha256", "artifact_evidence_sha256",
                    "database_generation_sha256", "script_policy_sha256",
                )
            },
            "operation": "install", "policy": "keep_existing", "triggers": True,
            "defer_triggers": False, "digest_sha256": "f" * 64,
        }
        request = {
            "schema": "https://debz.dev/schema/native-execution-request-v2",
            "version": 2, "execution": execution,
            "helper": {
                "source_path": f"var/lib/debz/native-helper-cache-v1/{'a' * 64}.bin",
                "target_path": "usr/bin/dpkg-trigger", "sha256": "a" * 64, "size": 1,
            },
            "digest_sha256": "b" * 64,
        }
        for module in (acceptance, compatibility):
            with self.subTest(registry=module.Registry is not None):
                with mock.patch("socket.socket.connect") as connect:
                    connect.side_effect = AssertionError("schema resolution must remain local")
                    module.validator("native-execution-request-v1").validate(execution)
                    validator = module.validator("native-execution-request-v2")
                    validator.validate(request)
                    invalid = {
                        **execution,
                        "program": {**execution["program"], "script_policy_sha256": "invalid"},
                    }
                    with self.assertRaises(module.jsonschema.ValidationError) as error:
                        validator.validate({**request, "execution": invalid})
                    self.assertEqual(
                        list(error.exception.absolute_path),
                        ["execution", "program", "script_policy_sha256"],
                    )
                    connect.assert_not_called()

    def test_provenance_is_bound_to_original_execution(self) -> None:
        binding = {
            "attempt_id": "a" * 64, "program_sha256": "b" * 64,
            "authorization_sha256": "c" * 64, "root_identity_sha256": "d" * 64,
            "install_root": str(self.root),
        }
        binding.update({field: "e" * 64 for field in acceptance.BINDING_FIELDS if field not in binding})
        binding.update(root_inode=self.root.stat().st_ino, operation="install")
        value = {**binding, "backend": "native"}
        acceptance.assert_binding(value, binding)
        for key in binding:
            with self.subTest(key=key):
                with self.assertRaisesRegex(AssertionError, key):
                    acceptance.assert_binding({**value, key: "different"}, binding)
        with self.assertRaisesRegex(AssertionError, "native backend"):
            acceptance.assert_binding({**value, "backend": "legacy_dpkg"}, binding)

    def test_caller_binding_preserves_outer_operation_and_hash_domains(self) -> None:
        m.write(self.root / acceptance.INTENT, json.dumps({
            "operation": "install",
            "request_sha256": "a" * 64, "policy_sha256": "b" * 64,
            "database_generation_sha256": "c" * 64, "digest_sha256": "d" * 64,
        }).encode())
        m.write(self.root / acceptance.OPERATION, json.dumps({
            "surface": "repository_bootstrap", "operation": "add",
            "request_sha256": "e" * 64, "policy_sha256": "f" * 64,
        }).encode())
        binding = acceptance.caller_binding(self.root)
        self.assertEqual(binding["operation"], {"repository_bootstrap": "add"})
        self.assertEqual(binding["request_sha256"], "e" * 64)
        self.assertEqual(binding["policy_sha256"], "f" * 64)
        self.assertEqual(binding["initial_database_generation_sha256"], "c" * 64)
        self.assertEqual(binding["execution_intent_sha256"], "d" * 64)

    def test_report_cannot_point_outside_native_namespace(self) -> None:
        for path in ("/etc/passwd", "var/lib/debz/../../outside", "var/lib/debz-other/proof.json"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(AssertionError, "escapes"):
                    acceptance.provenance(self.root, {"provenance_path": path}, {})

    def test_report_cannot_follow_a_provenance_symlink(self) -> None:
        target = self.workspace / "outside.json"
        m.write(target, b"{}")
        path = self.root / acceptance.NAMESPACE / "proof.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        with self.assertRaisesRegex(AssertionError, "symbolic link"):
            acceptance.provenance(self.root, {"provenance_path": str(path.relative_to(self.root))}, {})

    def test_claimed_recovery_cannot_hide_duplicate_script_invocation(self) -> None:
        expected = self.workspace / "reference"
        m.make_root(expected, "amd64")
        m.write(expected / acceptance.lifecycle.TRACE, b"postinst configure\n")
        m.write(self.root / acceptance.lifecycle.TRACE, b"postinst configure\npostinst configure\n")
        with self.assertRaisesRegex(AssertionError, "recovered native/dpkg mismatch"):
            acceptance.compare(expected, self.root)

    def test_caller_archive_is_removed_before_recovery(self) -> None:
        with mock.patch.object(acceptance.lifecycle.runtime, "copy_program"):
            case = acceptance.Scenario(
                self.workspace, "persisted-archive", self.workspace / "driver",
                None, "amd64", {},
            )
        archive = self.workspace / "input.deb"
        m.write(archive, b"fixture archive")
        m.write(case.candidate / acceptance.OPERATION, b'{"backend":"native"}')
        m.write(case.candidate / acceptance.INTENT, json.dumps({
            "operation": "install", "database_generation_sha256": "a" * 64, "digest_sha256": "b" * 64,
        }).encode())

        with mock.patch.object(acceptance, "native", return_value=None):
            case.crash(
                "install", [archive], "after_execution_intent", compare_reference=False,
            )
        self.assertFalse(archive.exists())

    def test_unknown_script_cannot_be_hidden_by_rolling_back_payload(self) -> None:
        with mock.patch.object(acceptance.lifecycle.runtime, "copy_program"):
            case = acceptance.Scenario(
                self.workspace, "unknown-with-mutation", self.workspace / "driver",
                None, "amd64", {},
            )
        m.write(case.candidate / acceptance.SCRIPT, b'{"outcome":"in_flight"}')
        payload = case.candidate / "usr/share/package/data"
        m.write(payload, b"new payload")

        def incorrect_recovery(*args, **kwargs):
            m.write(payload, b"old payload")
            return {"outcome": "recovery_required", "detail": "script_outcome_unknown"}

        with (
            mock.patch.object(acceptance, "native", side_effect=incorrect_recovery),
            mock.patch.object(acceptance, "provenance"),
        ):
            with self.assertRaisesRegex(AssertionError, "modified package or script state"):
                case.blocked({}, unknown_script=True)

    def test_native_document_reads_are_bounded_and_objects_only(self) -> None:
        path = self.workspace / "proof.json"
        m.write(path, b"[]" * 8)
        with self.assertRaises(m.oracle.SnapshotError):
            acceptance.document(path, maximum=4)
        m.write(path, b"[]")
        with self.assertRaisesRegex(AssertionError, "JSON object"):
            acceptance.document(path)

    def test_canonical_self_digest_cannot_hide_changed_receipt(self) -> None:
        for schema in (acceptance.PROVENANCE_SCHEMA, "native-transaction-authorization-v1"):
            with self.subTest(schema=schema):
                payload = {"schema": f"https://debz.dev/schema/{schema}", "outcome": "failed"}
                if schema == "native-transaction-authorization-v1":
                    sha256 = acceptance.digest("", payload)
                else:
                    sha256 = acceptance.digest(
                        f"debz-{schema}\0", {**payload, "digest_sha256": "0" * 64},
                    )
                value = {**payload, "digest_sha256": sha256}
                acceptance.assert_digest(value, schema)
                with self.assertRaisesRegex(AssertionError, "canonical digest"):
                    acceptance.assert_digest({**value, "outcome": "succeeded"}, schema)

    def receipt_manifest(self, entries: list[dict]) -> dict:
        return {
            "attempt_id": "a" * 64,
            "evidence_root": f"var/lib/debz/native-receipts-v1/{'a' * 64}",
            "evidence_files": entries,
            "evidence_files_sha256": acceptance.digest(
                "debz-native-retained-evidence-v1\0", entries,
            ),
        }

    def test_digest_summary_cannot_replace_missing_detailed_evidence(self) -> None:
        with self.assertRaisesRegex(AssertionError, "missing or duplicated retained"):
            acceptance.retained_documents(self.root, self.receipt_manifest([]))

    def test_receipt_rejects_changed_bytes_and_cross_attempt_paths(self) -> None:
        path = f"var/lib/debz/native-receipts-v1/{'a' * 64}/active-script.json"
        m.write(self.root / path, b"{}")
        entry = {
            "kind": "active_script", "path": path, "size": 2,
            "sha256": "b" * 64, "document_sha256": None, "action": None,
        }
        with self.assertRaisesRegex(AssertionError, "evidence bytes"):
            acceptance.retained_documents(self.root, self.receipt_manifest([entry]))
        entry["path"] = f"var/lib/debz/native-receipts-v1/{'c' * 64}/active-script.json"
        with self.assertRaisesRegex(AssertionError, "cross-attempt"):
            acceptance.retained_documents(self.root, self.receipt_manifest([entry]))

    def test_progress_requires_exact_retained_outcomes(self) -> None:
        record = {
            "sequence": 0,
            "action": {"kind": "script", "program_step": 1, "substep": 0, "ordinal": 0},
            "stage": "outcome", "result": "exited", "evidence_sha256": "c" * 64,
            "previous_sha256": "0" * 64, "digest_sha256": "0" * 64,
        }
        record["digest_sha256"] = acceptance.digest(
            "debz-native-execution-progress-record-v1\0", record,
        )
        script_hash = acceptance.hashlib.sha256(
            b"debz-native-script-outcomes-v1\0"
            + record["digest_sha256"].encode() + record["evidence_sha256"].encode(),
        ).hexdigest()
        proof = {
            "progress_head_sha256": record["digest_sha256"], "progress_record_count": 1,
            "recovered_phase_count": 0, "script_outcomes_sha256": script_hash,
            "outcome": "recovery_required",
        }
        progress = {"records": [record], "head_sha256": record["digest_sha256"]}
        script = {"action": record["action"], "digest_sha256": record["evidence_sha256"]}
        acceptance.assert_progress(proof, progress, [script])
        with self.assertRaisesRegex(AssertionError, "did not survive cleanup"):
            acceptance.assert_progress(proof, progress, [])
        with self.assertRaisesRegex(AssertionError, "did not survive cleanup"):
            acceptance.assert_progress(proof, progress, [script, script])
        record["previous_sha256"] = "d" * 64
        with self.assertRaisesRegex(AssertionError, "progress chain"):
            acceptance.assert_progress(proof, progress, [script])

    def test_receipt_arguments_must_match_the_actual_script_trace(self) -> None:
        script = {
            "package": "example", "package_version": "1", "architecture": "amd64",
            "kind": "postinst", "arguments": ["configure", ""],
        }
        m.write(
            self.root / acceptance.lifecycle.TRACE,
            b"example@1:postinst\texample\tpostinst\tamd64\t2\t9:configure\t0:\tpayload=new\n",
        )
        proof = {"outcome": "succeeded"}
        acceptance.assert_script_trace(self.root, proof, [script])
        script["arguments"] = ["configure", "2"]
        with self.assertRaisesRegex(AssertionError, "arguments or identity"):
            acceptance.assert_script_trace(self.root, proof, [script])

    def test_retained_output_supports_separate_and_combined_capture(self) -> None:
        for output in (
            {"stdout": b"out", "stderr": b"err", "combined": b""},
            {"stdout": b"", "stderr": b"", "combined": b"outerr"},
        ):
            with self.subTest(output=output):
                script = {"output_bytes": 6, "output_limit": 100}
                for stream, raw in output.items():
                    script[f"{stream}_hex"] = raw.hex()
                    script[f"{stream}_sha256"] = acceptance.hashlib.sha256(raw).hexdigest()
                acceptance.assert_output_streams(script)
                script["output_bytes"] = 0
                with self.assertRaisesRegex(AssertionError, "output accounting"):
                    acceptance.assert_output_streams(script)


if __name__ == "__main__":
    unittest.main()
