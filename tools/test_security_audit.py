#!/usr/bin/env python3
"""Tests for repository-local security audit helpers."""

from __future__ import annotations

import importlib.util
import itertools
import copy
from collections import Counter
import json
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_security_audit", ROOT / "tools/security-audit.py"
)
assert SPEC and SPEC.loader
security_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_audit)


class SecurityAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.digest_texts = security_audit.tracked_digest_texts(
            security_audit.tracked_files()
        )
        cls.digest_policy = json.loads(
            (ROOT / "security/digest-cutover-policy.json").read_text()
        )

    def test_digest_cutover_rejects_new_raw_package_authority(self) -> None:
        candidates = security_audit.digest_semantic_candidates(
            {
                "src/new_package_authority.zig": (
                    "pub const Package = struct {\n"
                    "    package_sha256: [32]u8,\n"
                    "};\n"
                )
            }
        )
        failures = security_audit.semantic_allowlist_failures(
            candidates, self.digest_policy
        )
        self.assertTrue(any("raw 32 byte field" in failure for failure in failures))

    def test_digest_cutover_rejects_new_sha256_only_schema_field(self) -> None:
        schema = {
            "$id": "https://debz.dev/schema/example-v3",
            "type": "object",
            "properties": {
                "package_digest": {"$ref": "#/$defs/sha256"},
            },
            "$defs": {
                "sha256": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                }
            },
        }
        candidates = security_audit.digest_semantic_candidates(
            {"schema/example-v3.json": json.dumps(schema)}
        )
        failures = security_audit.semantic_allowlist_failures(
            candidates, self.digest_policy
        )
        self.assertTrue(
            any("schema sha256 field" in failure for failure in failures)
        )

    def test_digest_cutover_rejects_fixed_sha256_cas_path(self) -> None:
        candidates = security_audit.digest_semantic_candidates(
            {
                "src/new_cache.zig": (
                    'const object_path = "objects/{sha256}";\n'
                )
            }
        )
        failures = security_audit.semantic_allowlist_failures(
            candidates, self.digest_policy
        )
        self.assertTrue(any("fixed sha256 cas" in failure for failure in failures))

    def test_digest_cutover_rejects_unreviewed_raw_control_field(self) -> None:
        candidates = security_audit.digest_semantic_candidates(
            {
                "src/new_control.zig": (
                    "const Control = struct {\n"
                    "    policy_sha256: [32]u8,\n"
                    "};\n"
                )
            }
        )
        failures = security_audit.semantic_allowlist_failures(
            candidates, self.digest_policy
        )
        self.assertTrue(any("raw 32 byte field" in failure for failure in failures))

    def test_digest_cutover_rejects_inventory_drift(self) -> None:
        changed = dict(self.digest_texts)
        changed["src/content_digest.zig"] += "\n// sha256 inventory drift canary\n"
        failures = security_audit.digest_inventory_failures(
            changed, self.digest_policy
        )
        self.assertTrue(any("finding inventory changed" in failure for failure in failures))

    def test_fresh_helper_bootstrap_inventory_rejects_mutation(self) -> None:
        changed = dict(self.digest_texts)
        source = "test/native_recovery_bootstrap.zig"
        self.assertIn(source, changed)
        changed[source] += "\n// sha256 bootstrap mutation canary\n"
        failures = security_audit.digest_inventory_failures(
            changed, self.digest_policy
        )
        self.assertTrue(any("finding inventory changed" in failure for failure in failures))

    def test_signed_consumer_per_receipt_checks_refuse_mutation(self) -> None:
        parity = (ROOT / "test/native_recovery_parity.zig").read_text()
        evidence = (ROOT / "test/native_recovery_parity_evidence.zig").read_text()
        self.assertEqual(
            [],
            security_audit.native_consumer_receipt_wiring_failures(parity, evidence),
        )
        for altered_parity, altered_evidence in (
            (parity.replace("try retained.verify(fixture, root, arch, digest, case.exit_status != 0);", ""), evidence),
            (parity, evidence.replace("try debz.native_provenance.verifyEvidence(allocator, root, proof);", "")),
            (parity, evidence.replace("try finalDatabase(allocator, root, architecture, proof);", "")),
            (parity, evidence.replace("try equal(&proof.request_sha256, &caller.caller.request_sha256);", "")),
        ):
            self.assertNotEqual(
                [],
                security_audit.native_consumer_receipt_wiring_failures(altered_parity, altered_evidence),
            )

    def test_signed_consumer_evidence_inventory_rejects_mutation(self) -> None:
        changed = dict(self.digest_texts)
        source = "test/native_recovery_parity_evidence.zig"
        self.assertIn(source, changed)
        changed[source] += "\n// sha256 consumer evidence mutation canary\n"
        self.assertTrue(any(
            "finding inventory changed" in failure
            for failure in security_audit.digest_inventory_failures(changed, self.digest_policy)
        ))

    def test_projected_repository_evidence_wiring_refuses_mutation(self) -> None:
        source = (ROOT / "test/native_recovery_repository.zig").read_text()
        self.assertEqual([], security_audit.native_repository_evidence_wiring_failures(source))
        for token in (
            "try terminalEvidence(fixture, root, relative, case, resuming, logical, retained_bytes, helper_before.?);",
            "try parity_evidence.verifyProjected(fixture, root, debz.live_root.logical_root_path, state.state.architecture,",
            "try unchangedBindings(fixture, root, state.state, abandoned.record, publisher.record);",
            "try checkpointAt(fixture, root, checkpoint);",
            "try checkHelper(fixture, root, original_helper orelse return error.MissingRepositoryHelper);",
            "try scanQuerySecret(fixture.io, fixture.dir, path);",
            "const count = reader.interface.readSliceShort(buffer[overlap .. overlap + 64 * 1024]) catch return reader.err.?;",
            "if (std.mem.indexOf(u8, buffer[0 .. overlap + count], secret) != null)",
            "std.mem.copyForwards(u8, buffer[0..next_overlap], buffer[end - next_overlap .. end]);",
            'test "repository network evidence scans large files and split secrets"',
            "try std.testing.expectError(error.NetworkFixtureLeakedCredential, assertNoQuerySecret(&fixture, root));",
        ):
            with self.subTest(token=token):
                self.assertNotEqual(
                    [],
                    security_audit.native_repository_evidence_wiring_failures(source.replace(token, "")),
                )

    def test_projected_repository_evidence_inventory_refuses_mutation(self) -> None:
        changed = dict(self.digest_texts)
        source = "test/native_recovery_repository.zig"
        self.assertIn(source, changed)
        changed[source] += "\n// sha256 repository evidence mutation canary\n"
        self.assertTrue(any(
            "finding inventory changed" in failure
            for failure in security_audit.digest_inventory_failures(changed, self.digest_policy)
        ))

    def test_digest_cutover_includes_nonignored_untracked_files(self) -> None:
        candidate = ROOT / "src/sha512_transaction_e2e_test.zig"
        with mock.patch.object(
            security_audit,
            "untracked_files",
            return_value=[candidate],
        ):
            files = security_audit.repository_digest_files([])
        self.assertIn(candidate, files)
        self.assertIn(ROOT / "security/digest-cutover-policy.json", files)

    def test_digest_cutover_rejects_malformed_or_overbroad_allowlist(self) -> None:
        policy = copy.deepcopy(self.digest_policy)
        policy["semantic_allowlist"][0]["paths"] = ["src/*"]
        failures = security_audit.semantic_allowlist_failures(
            security_audit.digest_semantic_candidates(self.digest_texts),
            policy,
        )
        self.assertIn(
            "digest semantic allowlist contains an invalid or overbroad entry",
            failures,
        )

    def test_digest_cutover_accepts_typed_authority_and_frozen_compatibility(self) -> None:
        self.assertEqual(
            [],
            security_audit.digest_cutover_failures(
                self.digest_texts,
                self.digest_policy,
            ),
        )
        allowlist = {
            entry["id"]: entry
            for entry in self.digest_policy["semantic_allowlist"]
        }
        self.assertEqual(
            "historical_versioned_compatibility",
            allowlist["raw-historical-authority-fields"]["classification"],
        )
        self.assertIn(
            "pub const Identity = struct",
            self.digest_texts["src/content_digest.zig"],
        )

    def test_docs_ignore_disposable_snapshot_payloads_not_repository_docs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="debz-snapshot-docs-") as directory:
            root = pathlib.Path(directory)
            for relative in ("doc/local.md", ".real-snapshot/root/usr/share/doc/vendor.md"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("[missing](missing.md)\n")
            with mock.patch.object(security_audit, "ROOT", root), \
                    mock.patch.object(security_audit, "fail") as fail:
                security_audit.audit_docs()
            fail.assert_called_once_with("doc/local.md: stale local link: missing.md")

    def test_zstd_static_option_is_scoped_to_zstd_dependency(self) -> None:
        expected = {
            "target": "target",
            "optimize": "optimize",
            "shared": "false",
            "tools": "false",
            "multithread": "false",
        }
        previous = """
            const libsolv_dependency = b.dependency("libsolv", .{
                .shared = false,
            });
            const zstd_dependency = b.dependency("zstd", .{
                .target = target,
                .optimize = optimize,
                .tools = false,
                .multithread = false,
            });
        """
        failures = security_audit.dependency_option_failures(previous, "zstd", expected)
        self.assertIn("zstd: build option .shared must be false", failures)

        current = (ROOT / "build.zig").read_text()
        self.assertEqual([], security_audit.dependency_option_failures(current, "zstd", expected))

    def test_runtime_metadata_rejects_previous_dynamic_glibc_model(self) -> None:
        policy = json.loads((ROOT / "security/dependency-policy.json").read_text())
        dependencies = {
            item["name"]: item for item in policy["production_dependencies"]
        }
        current = json.loads((ROOT / "security/runtime-dependencies.json").read_text())
        self.assertEqual(
            [], security_audit.runtime_metadata_failures(current, dependencies)
        )

        previous = json.loads(json.dumps(current))
        linux = previous["linux_release_runtime"]
        linux["binary_kind"] = "dynamically_linked"
        linux["libc"] = {
            "implementation": "glibc",
            "linkage": "dynamic",
            "expectation": "The target glibc ABI must be provided by the destination Linux system.",
        }
        linux["fully_static"] = False
        self.assertNotEqual(
            [], security_audit.runtime_metadata_failures(previous, dependencies)
        )

    def test_runtime_metadata_is_release_install_only(self) -> None:
        current = (ROOT / "build.zig").read_text()
        self.assertEqual(
            [], security_audit.release_install_metadata_failures(current)
        )

        previous = current.replace(
            '.{ .source = "THIRD_PARTY_NOTICES", .destination = "share/doc/debz/THIRD_PARTY_NOTICES" },',
            '.{ .source = "THIRD_PARTY_NOTICES", .destination = "share/doc/debz/THIRD_PARTY_NOTICES" },\n'
            '        .{ .source = "security/runtime-dependencies.json", .destination = "share/debz/runtime-dependencies.json" },',
        )
        self.assertIn(
            "ordinary install graph contains static-musl runtime metadata",
            security_audit.release_install_metadata_failures(previous),
        )

    def test_musl_is_in_runtime_policy_metadata(self) -> None:
        policy = json.loads((ROOT / "security/dependency-policy.json").read_text())
        dependencies = {
            item["name"]: item for item in policy["production_dependencies"]
        }
        musl = dependencies["musl"]
        self.assertEqual(musl["upstream_version"], "1.2.5")
        self.assertEqual(musl["toolchain_version"], "0.16.0")
        self.assertEqual(
            musl["toolchain_commit"],
            "24fdd5b7a4c1c8b5deb5b56756b9dbc8e08c86a8",
        )
        self.assertEqual(
            {
                item["id"]: item["disposition"]
                for item in musl["reviewed_exceptions"]
            },
            {
                "CVE-2025-26519": "patched_in_toolchain",
                "CVE-2026-40200": "not_affected",
                "CVE-2026-6042": "not_linked",
            },
        )
        expected = security_audit.expected_runtime_metadata(dependencies)
        included = {
            item["name"]: item
            for item in expected["linux_release_runtime"]["included_libraries"]
        }
        self.assertEqual(included["musl"]["linkage"], "static_libc_in_debz")
        self.assertEqual(included["musl"]["license"], "MIT")

    def test_target_apt_import_is_the_only_additional_process_and_apt_boundary(self) -> None:
        source = (ROOT / "src/target_apt_config.zig").read_text()
        self.assertEqual(source.count("std.process.run("), 1)
        self.assertIn(".environ_map = &environ", source)
        self.assertIn('const sources_list_path = "/etc/apt/sources.list";', source)
        self.assertIn(
            'const global_keyring_directory_path = "/etc/apt/trusted.gpg.d";',
            source,
        )

    def test_native_child_process_boundaries_are_explicit(self) -> None:
        sources = {
            path.relative_to(ROOT).as_posix(): path.read_text()
            for path in sorted((ROOT / "src").rglob("*.zig"))
        }
        owners = sorted(
            relative
            for relative, text in sources.items()
            if re.search(r"\blinux\.(?:fork|execve|chroot)\s*\(", text)
        )
        self.assertEqual(
            [
                "src/apt_system_command.zig",
                "src/apt_system_orchestrator.zig",
                "src/live_root.zig",
                "src/maintainer_script.zig",
                "src/native_unpack.zig",
                "src/production_backend.zig",
            ],
            owners,
        )
        production_backend = sources["src/production_backend.zig"]
        self.assertEqual(production_backend.count("linux.fork()"), 1)
        self.assertGreater(
            production_backend.index("linux.fork()"),
            production_backend.index('\ntest "'),
        )
        apt_system_command = sources["src/apt_system_command.zig"]
        self.assertEqual(apt_system_command.count("linux.fork()"), 1)
        self.assertGreater(
            apt_system_command.index("linux.fork()"),
            apt_system_command.index('\ntest "'),
        )
        native_unpack = sources["src/native_unpack.zig"]
        self.assertEqual(native_unpack.count("linux.fork()"), 1)
        self.assertGreater(
            native_unpack.index("linux.fork()"),
            native_unpack.index('\ntest "'),
        )
        self.assertLess(
            native_unpack.index("fn testFreshDatabaseInstall("),
            native_unpack.index("linux.fork()"),
        )
        self.assertLess(
            native_unpack.index("linux.fork()"),
            native_unpack.index(
                '\ntest "native_unpack.test.caller-owned install initializes an absent database"'
            ),
        )
        apt_system_orchestrator = sources["src/apt_system_orchestrator.zig"]
        self.assertEqual(apt_system_orchestrator.count("linux.fork()"), 1)
        first_test = apt_system_orchestrator.index('\ntest "')
        self.assertTrue(
            all(
                match.start() > first_test
                for match in re.finditer(
                    r"\blinux\.fork\s*\(",
                    apt_system_orchestrator,
                )
            )
        )
        self.assertIn("_ = linux.kill(pid, .KILL);", production_backend)
        self.assertIn("linux.waitpid(pid, &status, 0)", production_backend)
        runner = sources["src/maintainer_script.zig"]
        self.assertNotIn("std.process.run(", runner)
        self.assertIn('linux.open("/dev/null"', runner)
        self.assertIn('linux.chroot(".")', runner)
        live_root = sources["src/live_root.zig"]
        self.assertNotIn("std.process.run(", live_root)
        self.assertIn("linux.unshare(linux.CLONE.NEWNS)", live_root)
        self.assertIn("linux.mount(", live_root)
        self.assertIn(".open_tree,", live_root)
        self.assertIn(".mount_setattr,", live_root)
        self.assertIn("linux.move_mount(", live_root)
        orchestrator = sources["src/apt_system_orchestrator.zig"]
        first_orchestrator_test = orchestrator.index('\ntest "')
        self.assertTrue(
            all(
                match.start() > first_orchestrator_test
                for match in re.finditer(
                    r"\blinux\.(?:unshare|setns|mount|move_mount|umount2)\s*\(",
                    orchestrator,
                )
            )
        )
        namespace_owners = sorted(
            relative
            for relative, text in sources.items()
            if relative != "src/apt_system_orchestrator.zig"
            if re.search(
                r"\blinux\.(?:unshare|setns|mount|move_mount|umount2)\s*\(",
                text,
            )
        )
        self.assertEqual(["src/live_root.zig", "src/maintainer_script.zig"], namespace_owners)
        self.assertIn("linux.unshare(linux.CLONE.NEWNS)", runner)
        self.assertIn("live_root.cloneMountDescriptor(", runner)
        self.assertIn("live_root.setMountAttributes(", runner)
        self.assertIn("linux.move_mount(", runner)

    def test_composite_action_pin_audit_rejects_movable_refs(self) -> None:
        self.assertEqual(
            [],
            security_audit.action_pin_failures(
                "uses: actions/cache/restore@5a3ec84eff668545956fd18022155c47e93e2684\n",
                "action.yml",
            ),
        )
        failures = security_audit.action_pin_failures(
            "uses: actions/cache/restore@v4\n",
            "action.yml",
        )
        self.assertEqual(
            ["action.yml: actions/cache/restore is not commit-pinned"],
            failures,
        )

    def test_workflows_pin_verified_ghr_zig_installation(self) -> None:
        for workflow_name, expected_count in (("ci.yml", 13), ("release.yml", 1)):
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text()
            self.assertEqual(
                [],
                security_audit.ghr_zig_workflow_failures(
                    workflow, workflow_name, expected_count
                ),
            )
            self.assertNotEqual(
                [],
                security_audit.ghr_zig_workflow_failures(
                    workflow.replace("ghr-version: v0.8.1", "ghr-version: v0.8.0", 1),
                    workflow_name,
                    expected_count,
                ),
            )
            self.assertNotEqual(
                [],
                security_audit.ghr_zig_workflow_failures(
                    workflow + "\nuses: mlugg/setup-zig@deadbeef\n",
                    workflow_name,
                    expected_count,
                ),
            )

    def test_download_cache_uses_opaque_cli_owned_archive(self) -> None:
        package = json.loads(
            (ROOT / "actions/download/package.json").read_text()
        )
        self.assertNotIn("@actions/cache", package["dependencies"])
        self.assertEqual(
            package["dependencies"]["@azure/storage-blob"],
            "12.31.0",
        )
        cache_source = (ROOT / "actions/download/src/cache.ts").read_text()
        self.assertIn("GetCacheEntryDownloadURL", cache_source)
        self.assertIn("downloadToFile(", cache_source)
        self.assertNotIn("restoreCache(", cache_source)
        archive_source = (ROOT / "src/package_cache_archive.zig").read_text()
        self.assertIn(
            'pub const format_id = "debz-package-cache-archive-v1"',
            archive_source,
        )

    def test_native_download_negative_cases_require_bound_outcome_assertions(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(
            [],
            security_audit.workflow_failure_handling_failures(workflow, "ci.yml"),
        )
        for prefix, step_id in (
            ("NATIVE", "native-foreign-lock"),
            ("LEGACY", "legacy-foreign-lock"),
        ):
            for token in (
                f"id: {step_id}",
                f"{prefix}_OUTCOME: ${{{{ steps.{step_id}.outcome }}}}",
                f"{prefix}_PATH: ${{{{ steps.{step_id}.outputs.cache-path }}}}",
                f'test "${prefix}_OUTCOME" = failure',
                f'test -z "${prefix}_PATH"',
            ):
                with self.subTest(token=token):
                    self.assertIn(token, workflow)
                    self.assertIn(
                        "ci.yml: native backend refusal coverage lacks bound outcome assertions",
                        security_audit.workflow_failure_handling_failures(
                            workflow.replace(token, ""), "ci.yml"
                        ),
                    )
        self.assertIn(
            "ci.yml: workflow hides a failing command",
            security_audit.workflow_failure_handling_failures(
                workflow.replace("Refuse legacy lock in native action", "Ignore arbitrary failure"),
                "ci.yml",
            ),
        )
        self.assertIn(
            "ci.yml: expected-failure action coverage lacks outcome assertions",
            security_audit.workflow_failure_handling_failures(
                workflow.replace('test "$OUTCOME" = failure', ""), "ci.yml"
            ),
        )

    def test_native_recovery_keeps_existing_required_checks_fail_closed(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual([], security_audit.native_recovery_ci_failures(workflow))
        jobs = dict(re.findall(
            r"(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        ))
        recovery_jobs = tuple(security_audit.RECOVERY_ZIG_SHARDS)
        commands = []
        for name in recovery_jobs:
            body = jobs[name]
            commands.extend(re.findall(
                r"(?m)^          (zig build test-native-recovery[^\n]+)$", body,
            ))
            tokens = [
                "    timeout-minutes: 35",
                "      fail-fast: false",
                "          - os: ubuntu-24.04",
                "          - os: ubuntu-24.04-arm",
                "      - name: Install Zig via ghr\n",
                "      - name: Install metadata decompression and signed fixture dependencies\n",
                "python3-cryptography python3-jsonschema",
                'reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
                *[f"          {command}" for command in re.findall(
                    r"(?m)^          (zig build test-native-recovery[^\n]+)$", body,
                )],
            ]
            if name == "native-recovery-zig-workflows":
                tokens.extend((
                    "          zig build test-native-recovery-zig-unit -j2 --summary all",
                    "          zig build test-native-recovery-zig-unit -Doptimize=ReleaseSafe -j2 --summary all",
                ))
            if name in ("native-recovery-zig-workflows", "native-recovery-zig-family"):
                tokens.append("          mkdir -p .tmp")
            for token in tokens:
                with self.subTest(job=name, removed=token):
                    self.assertIn(token, body)
                    changed = workflow.replace(body, body.replace(token, "", 1), 1)
                    self.assertTrue(security_audit.native_recovery_ci_failures(changed))
            for step in re.findall(r"(?m)^      - name: (Exercise [^\n]+)$", body):
                with self.subTest(job=name, skipped=step):
                    changed = workflow.replace(
                        body,
                        body.replace(
                            f"      - name: {step}\n",
                            f"      - name: {step}\n        if: false\n",
                            1,
                        ),
                        1,
                    )
                    self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        workflows = jobs["native-recovery-zig-workflows"]
        acceptance = (
            "      - name: Exercise Zig core, repository, and helper recovery\n"
            "        run: |\n          mkdir -p .tmp\n"
        )
        self.assertIn(acceptance, workflows)
        changed = workflow.replace(
            workflows, workflows.replace(acceptance, acceptance.replace("          mkdir -p .tmp\n", ""), 1), 1
        )
        self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        targets = {
            "test-native-recovery-zig-unit",
            "test-native-recovery-zig", "test-native-recovery-zig-family",
            "test-native-recovery-zig-repository", "test-native-recovery-helper-zig",
            "test-native-recovery-zig-bootstrap", "test-native-recovery-zig-parity",
            "test-native-recovery-zig-rollback-clock", "test-native-recovery-zig-scriptless",
            "test-native-recovery-zig-statoverride", "test-native-recovery-zig-literal",
            "test-native-recovery-zig-metadata", "test-native-recovery-zig-conffile",
            "test-native-recovery-zig-final-gaps", "test-native-recovery-zig-diversions",
        }
        inventory = Counter(
            (
                command.split()[2],
                "ReleaseSafe" if "-Doptimize=ReleaseSafe" in command else "Debug",
            )
            for command in commands
        )
        self.assertEqual(inventory, Counter({
            (target, mode): 1 for target in targets for mode in ("Debug", "ReleaseSafe")
        }))
        self.assertNotIn("  native-recovery:\n", workflow)
        extra_gate = workflow.replace(
            "  native-recovery-zig-workflows:\n",
            "      - name: Duplicate complete recovery suite\n        run: |\n"
            "          zig build test-native-recovery -j2 --summary all\n\n"
            "  native-recovery-zig-workflows:\n",
        )
        self.assertTrue(security_audit.native_recovery_ci_failures(extra_gate))
        extra_focused = workflow + (
            "\n  duplicate-recovery:\n    runs-on: ubuntu-24.04\n    steps:\n"
            "      - name: Duplicate signed FAMILY recovery\n        run: |\n"
            '          zig build test-native-recovery-zig-family -Dnative-reference-dpkg="$reference_dpkg" -j2 --summary all\n'
        )
        self.assertIn(
            "ci.yml: recovery targets must execute only in the two required Zig shards",
            security_audit.native_recovery_ci_failures(extra_focused),
        )
        for name in recovery_jobs:
            body = jobs[name]
            if "          zig build test-native-recovery" not in body:
                continue
            command = re.search(r"(?m)^          zig build test-native-recovery[^\n]+$", body)[0]
            with self.subTest(job=name, duplicate=command):
                changed = workflow.replace(body, body.replace(command, f"{command}\n{command}", 1), 1)
                self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        gate = jobs["build-and-test"]
        for token in (
            "    needs: [build-and-test-workload, native-recovery-zig-workflows, native-recovery-zig-family, native-recovery-zig-scenarios]",
            "    if: ${{ always() }}",
            "        name: [linux-x64, linux-arm64]",
            "          BUILD_RESULT: ${{ needs.build-and-test-workload.result }}",
            "          RECOVERY_WORKFLOWS_RESULT: ${{ needs.native-recovery-zig-workflows.result }}",
            "          RECOVERY_FAMILY_RESULT: ${{ needs.native-recovery-zig-family.result }}",
            "          RECOVERY_SCENARIOS_RESULT: ${{ needs.native-recovery-zig-scenarios.result }}",
            '          test "$BUILD_RESULT" = success',
            '          test "$RECOVERY_WORKFLOWS_RESULT" = success',
            '          test "$RECOVERY_FAMILY_RESULT" = success',
            '          test "$RECOVERY_SCENARIOS_RESULT" = success',
        ):
            with self.subTest(gate=token):
                self.assertIn(token, gate)
                changed = workflow.replace(gate, gate.replace(token, "", 1), 1)
                self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        gate = re.search(
            r"(?ms)^  build-and-test:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        )
        self.assertIsNotNone(gate)
        script = gate[1].split("        run: |\n", 1)[1]
        statuses = ("success", "failure", "cancelled", "skipped", "unknown")
        for build, workflows, family, scenarios in itertools.product(
            statuses, repeat=4,
        ):
            with self.subTest(build=build, workflows=workflows, family=family, scenarios=scenarios):
                result = subprocess.run(
                    ["bash", "-e", "-c", textwrap.dedent(script)],
                    env={
                        **os.environ,
                        "BUILD_RESULT": build,
                        "RECOVERY_WORKFLOWS_RESULT": workflows,
                        "RECOVERY_FAMILY_RESULT": family,
                        "RECOVERY_SCENARIOS_RESULT": scenarios,
                    },
                    stdin=subprocess.DEVNULL, capture_output=True, check=False,
                )
                self.assertEqual(
                    result.returncode == 0,
                    all(status == "success" for status in (build, workflows, family, scenarios)),
                )

    def test_report_path_reader_refusals_are_mutation_enforced(self) -> None:
        paths = security_audit.REPORT_PATH_ORACLE_FILES
        texts = {path: (ROOT / path).read_text() for path in paths}
        check = security_audit.native_report_path_wiring_failures
        self.assertEqual([], check(texts))
        for path, token in (
            ("test/native_recovery_oracle.zig", "if (!std.mem.eql(u8, reported, expected)) return error.UnboundRecoveryProof;"),
            ("test/native_recovery_acceptance.zig", "_ = try oracle.reportProvenancePath(report.provenance_path orelse return error.MissingReportBinding, provenance_path);"),
            ("test/native_recovery_scriptless.zig", "const proof_path = try reportProvenancePath(report.value.provenance_path);"),
            ("test/native_recovery_conffile.zig", "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);"),
            ("test/native_recovery_literal.zig", "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);"),
            ("test/native_recovery_metadata.zig", "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);"),
            ("test/native_recovery_statoverride.zig", "const proof_path = try process.reportProvenancePath(report.value.provenance_path);"),
            ("test/native_recovery_unit.zig", 'try sandbox.dir.symLink(sandbox.io, external, "var/lib/debz/proof.json", .{});'),
        ):
            with self.subTest(path=path, token=token):
                self.assertIn(token, texts[path])
                self.assertTrue(check({**texts, path: texts[path].replace(token, "", 1)}))
    def test_recovery_gate_selector_graph_is_mutation_enforced(self) -> None:
        paths = (
            "build.zig",
            "test/native_recovery_helper.zig",
            "test/native_recovery_family.zig",
            "test/native_recovery_projected_workflows.zig",
            "test/native_recovery_repository.zig",
        )
        sources = [(ROOT / path).read_text() for path in paths]
        check = security_audit.native_recovery_gate_wiring_failures
        self.assertEqual([], check(*sources))
        build = sources[0]
        for token in (
            "native_recovery.dependOn(&run_native_recovery_tests.step);",
            "native_recovery.dependOn(&run_recovery_unit_tests.step);",
            "native_recovery.dependOn(&run_repository_recovery_unit.step);",
            "if (selected > 1 or focused)",
            "focused Zig case options cannot narrow the complete test-native-recovery gate",
            "native_core_only,           native_deadline_only,      native_script_failure_only,",
            'if (native_core_only or zig_core_only) recovery_zig.addArg("--core-only");',
            'if (native_deadline_only or zig_deadline_only) recovery_zig.addArg("--deadline-only");',
            "native_recovery.dependOn(&recovery_zig.step);",
            "native_recovery.dependOn(&recovery_helper.step);",
            "native_recovery.dependOn(&recovery_bootstrap.step);",
            "native_recovery.dependOn(&recovery_diversions.step);",
            "native_recovery.dependOn(&recovery_family.step);",
            "native_recovery.dependOn(&repository_recovery.step);",
            "recovery_family.addArtifactArg(native_trigger_helper);",
            "recovery_family.addArtifactArg(cli);",
            "repository_recovery.addArtifactArg(cli);",
            "recovery_parity.addArtifactArg(native_trigger_helper);",
            "}) |runner| runner.addArgs(&.{ \"--reference-dpkg\", path });",
            "recovery_zig,       recovery_family,     recovery_parity,   recovery_helper,     final_gaps,",
            "recovery_parity,   recovery_diversions, statoverride_recovery, conffile_recovery,",
            "recovery_zig,        recovery_helper,       recovery_bootstrap, recovery_family,",
        ):
            with self.subTest(build=token):
                self.assertIn(token, build)
                self.assertTrue(check(build.replace(token, "", 1), *sources[1:]))
        for index, token in (
            (1, "try knownScriptFailures(&fixture, driver, reference.executable, reference.architecture);"),
            (2, "try projected.runReadOnly(&fixture, self orelse return error.MissingSelf, driver, reference.architecture);"),
            (3, "try readOnlyProjection(fixture, runner, driver, arch);"),
            (4, "const selected = try selectMode(false, projection_only, execution_only, cli_only);"),
        ):
            with self.subTest(source=paths[index], token=token):
                changed = sources.copy()
                changed[index] = changed[index].replace(token, "", 1)
                self.assertTrue(check(*changed))
        pinned_start = '    if (b.option([]const u8, "native-reference-dpkg",'
        before, marker, pinned = build.partition(pinned_start)
        self.assertTrue(marker)
        for runner in (
            "recovery_zig", "recovery_family", "recovery_parity", "recovery_helper",
            "final_gaps", "recovery_bootstrap", "repository_recovery", "rollback_clock",
            "scriptless_recovery", "statoverride_recovery", "literal_recovery",
            "metadata_recovery", "conffile_recovery", "recovery_diversions",
        ):
            with self.subTest(pinned_runner=runner):
                changed, count = re.subn(rf"\b{runner}\b", "omitted_runner", pinned, count=1)
                self.assertEqual(1, count)
                self.assertTrue(check(before + marker + changed, *sources[1:]))
        for option, variable, runner in (
            ("native-zig-recovery-family-fixture-python", "path", "recovery_family"),
            ("native-zig-recovery-parity-fixture-python", "path", "recovery_parity"),
            ("native-repository-fixture-python", "python", "repository_recovery"),
        ):
            with self.subTest(fixture_option=option):
                self.assertTrue(check(build.replace(f'"{option}"', '"missing-fixture-option"', 1), *sources[1:]))
            handoff = f'{runner}.addArgs(&.{{ "--fixture-python", {variable} }});'
            with self.subTest(fixture_handoff=runner):
                self.assertIn(handoff, build)
                self.assertTrue(check(build.replace(handoff, "", 1), *sources[1:]))
        for retired in ("tools/test-native-recovery.py", "tools/test_native_recovery.py"):
            with self.subTest(restored=retired):
                self.assertTrue(check(build + f'\n"{retired}"', *sources[1:]))

    def test_native_core_completion_wiring_is_mutation_enforced(self) -> None:
        build = (ROOT / "build.zig").read_text()
        helper = (ROOT / "test/native_recovery_helper.zig").read_text()
        support = (ROOT / "test/native_lifecycle_support.zig").read_text()
        check = security_audit.native_core_completion_wiring_failures
        self.assertEqual([], check(build, helper, support))
        for token in (
            'recovery_helper.addArtifactArg(recovery_helper_executable);',
            'recovery_helper.addArtifactArg(native_lifecycle_tests);',
            'b.step("test-native-recovery-helper-zig",',
        ):
            with self.subTest(build=token):
                self.assertIn(token, build)
                self.assertTrue(check(build.replace(token, "", 1), helper, support))
        for token in (
            "try completedWithoutLiveHelper(&fixture, driver, reference.executable, reference.architecture);",
            "try missingPackageOwnedHelper(&fixture, driver, reference.architecture);",
            "try rehashedCallerPolicy(&fixture, driver, reference.architecture);",
            "try afterActiveClearLegacyEvidence(&fixture, driver, reference.executable, reference.architecture);",
            '"NativeHelperBootstrapOwnerMissing"',
            '"RecoveryRequestBindingMismatch"',
            '"after_active_clear"',
            'try sealJsonDigest(fixture, &persisted.value, "debz-native-execution-request-v1\\x00");',
            "debz.native_recovery.sealIntent(&altered_intent);",
            'const orphaned = try projected.rootInventory(fixture, root, false);',
            'try std.testing.expectEqualSlices(u8, orphaned, try projected.rootInventory(fixture, root, false));',
            'try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, directory), old_proof.document);',
            '.config_content = config,',
            'const config = "#!/bin/sh\\n# config:1\\nprintf \'%s\\\\n\' \'config:1\' >> /config-invoked\\nexit 97\\n";',
            'try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));',
            'try same(try bytes(fixture, root, "var/lib/dpkg/tmp.ci/config", 64 * 1024), config);',
            'try missing(fixture, root, "var/lib/dpkg/info/" ++ foundation.package ++ ".config");',
            'try missing(fixture, root, "config-invoked");',
        ):
            with self.subTest(helper=token):
                self.assertIn(token, helper)
                self.assertTrue(check(build, helper.replace(token, "", 1), support))
        self.assertTrue(
            check(build, helper.replace("            .isolated_helper = false,", "", 1), support)
        )
        for token in (
            "config_content: ?[]const u8 = null,",
            'try fixture.write(config, configuration, 0o755);',
        ):
            with self.subTest(support=token):
                self.assertIn(token, support)
                self.assertTrue(check(build, helper, support.replace(token, "", 1)))
        start = helper.index("fn recoveredOrdinary(")
        end = helper.index("\nfn caseRun(", start)
        for token in (
            "if (try invoke(fixture, driver, root, arch, crash_output, .{",
            "try fixture.dir.deleteFile(fixture.io, archive_relative);",
            "const request = try originalRequestFor(fixture, root, intent.intent, case.isolated_helper, case.caller_owned, archive);",
            "if (reference_exit != (if (case.known_preinst_failure)",
            "try foundation.compare(fixture.*, expected, root, comparison);",
            "try verifyProofFor(fixture, root, repeated.value, intent.intent, request, proof_outcome, true, case.isolated_helper, case.caller_owned);",
            "try std.testing.expectEqualSlices(u8, root_before, try projected.rootInventory(fixture, root, case.caller_owned));",
            "try sameHelper(fixture, root, helper_before);",
            ".acknowledge = true,",
        ):
            with self.subTest(ordinary=token):
                self.assertIn(token, helper[start:end])
                changed = helper[:start] + helper[start:end].replace(token, "", 1) + helper[end:]
                self.assertTrue(check(build, changed, support))
        main_start = helper.index("pub fn main(")
        for token in (
            "try recoveredOrdinary(",
            '"after_execution_intent", "during_filesystem_publication",\n        "after_script_outcome",   "after_provenance",',
            '"typed-runtime-known-failure" else "caller-known-failure"',
            '"after_execution_intent", "during_filesystem_publication", "during_database_publication",\n        "after_script_prepared",  "after_script_outcome",          "after_provenance",',
            '.name = "known-failure-compensation",',
        ):
            with self.subTest(main=token):
                self.assertIn(token, helper[main_start:])
                changed = helper[:main_start] + helper[main_start:].replace(token, "", 1)
                self.assertTrue(check(build, changed, support))

    def test_native_entry_point_output_shapes_are_mutation_enforced(self) -> None:
        core = (ROOT / "test/native_recovery_acceptance.zig").read_text()
        projected = (ROOT / "test/native_recovery_projected_workflows.zig").read_text()
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        check = security_audit.native_entry_point_shape_failures
        self.assertEqual([], check(core, projected, ci))
        for token in (
            'const archive = try support.makePackage(fixture, arch, "1", foundation.package, packages, .{});',
            'const archive = try support.makePackage(fixture, arch, "1", foundation.package, "deadline-startup/packages", .{});',
            'const archive = try support.makePackage(fixture, arch, "1", foundation.package, "deadline-persisted/packages", .{});',
            'try support.scripts(fixture, source, foundation.package, "1");',
            'try rootAbsent(fixture, root, "config-invoked");',
            'try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, guarded), typed_proof.document);',
            'var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);',
            'if (scripts == 0) return error.MissingCoreScriptOutcome;',
            'try debz.native_recovery.validateScriptOutcome(outcome.value);',
            'try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,',
            'try oracle.validateScriptTrace(fixture.allocator, trace, &invocations);',
        ):
            with self.subTest(core=token):
                self.assertIn(token, core)
                self.assertTrue(check(core.replace(token, "", 1), projected, ci))
        for token in (
            "try readOnlyProjection(fixture, runner, driver, arch);",
            "DEBZ_NATIVE_PROJECTION_FIXTURE=1",
            "native_transaction_result.test.projected root external fixture...OK",
            "apt_system_orchestrator.test.projected native dispatch external fixture...OK",
            "if (!std.mem.eql(u8, before, try evidenceInventory(fixture, root, true)))",
        ):
            with self.subTest(projection=token):
                self.assertIn(token, projected)
                self.assertTrue(check(core, projected.replace(token, "", 1), ci))
        for token in (
            '          zig build test-native-recovery-zig -Dnative-reference-dpkg="$reference_dpkg" -j2 --summary all',
            '          zig build test-native-recovery-zig -Dnative-reference-dpkg="$reference_dpkg" -Doptimize=ReleaseSafe -j2 --summary all',
        ):
            with self.subTest(ci=token):
                self.assertIn(token, ci)
                self.assertTrue(check(core, projected, ci.replace(token, "", 1)))

    def test_native_exercise_final_matrix_and_completion_guard_are_mutation_enforced(self) -> None:
        helper = (ROOT / "test/native_recovery_helper.zig").read_text()
        support = (ROOT / "test/native_lifecycle_support.zig").read_text()
        unpack = (ROOT / "src/native_unpack.zig").read_text()
        check = security_audit.native_exercise_final_wiring_failures
        self.assertEqual([], check(helper, support, unpack))
        for token in (
            'if (!claim.value.object.swapRemove(changing)) return error.InvalidRootClaim;',
            '"generation", "state", "phase", "step", "updated_unix", "digest_sha256"',
        ):
            with self.subTest(claim=token):
                self.assertIn(token, helper)
                self.assertTrue(check(helper.replace(token, "", 1), support, unpack))
        main = helper.index("pub fn main(")
        for token in (
            "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, false);",
            "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, true);",
            "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
            "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
            "for ([_]Corruption{ .intent, .progress, .artifact, .managed_root, .completed_phase }) |which|",
            "try corruptedOrdinary(&fixture, driver, reference.architecture, which);",
        ):
            with self.subTest(main=token):
                self.assertIn(token, helper[main:])
                changed = helper[:main] + helper[main:].replace(token, "", 1)
                self.assertTrue(check(changed, support, unpack))
        for start, end, tokens in (
            ("fn blockedUnknown(", "\nfn triggerOutcome(", (
                '"after_upgrade_postrm_return_before_outcome" else "after_script_return_before_outcome"',
                'try same(try text(script.value, "outcome"), "in_flight");',
                "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, scenario.native_root));",
                "try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);",
            )),
            ("fn triggerOutcome(", "\nconst Corruption =", (
                '"after_trigger_outcome"',
                "if (events.value.events.len != 2) return error.IncorrectTriggerEventCount;",
                "observed[0].origin != .automatic or observed[1].origin != .dynamic",
                'try same(observed[1].trigger, "debz-b");',
                ".acknowledge = true,",
            )),
            ("fn corruptedOrdinary(", "\nfn caseRun(", (
                '.scripts = .{ .only_postinst = corruption == .completed_phase },',
                "if (artifact != null) return error.DuplicateRetainedArtifact;",
                "raw[0] = 'X';",
                '"corrupt\\n"',
                '"external replacement\\n"',
                "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, root));",
                "try same(try stickyActiveClaim(fixture, root), original_claim);",
            )),
        ):
            head = helper.index(start)
            tail = helper.index(end, head)
            for token in tokens:
                with self.subTest(case=start, token=token):
                    self.assertIn(token, helper[head:tail])
                    changed = helper[:head] + helper[head:tail].replace(token, "", 1) + helper[tail:]
                    self.assertTrue(check(changed, support, unpack))
        for token in (
            "only_postinst: bool = false,",
            'if (options.only_postinst and !std.mem.eql(u8, kind, "postinst")) continue;',
        ):
            with self.subTest(support=token):
                self.assertIn(token, support)
                self.assertTrue(check(helper, support.replace(token, "", 1), unpack))
        start = unpack.index("var preexisting = try completion_store.read(allocator);")
        end = unpack.index("if (record.provenance == .pending)", start)
        for token in (
            "var preexisting = try completion_store.read(allocator);",
            "previous.bindsRecord(record)",
            "record.provenance == .published",
            "record.generation - previous.record_generation != 1",
            "record.provenance_sha256 == null",
            "root_operation.provenanceDigest(record, .{",
            ".document_sha256 = previous.digest_sha256,",
            "!std.mem.eql(u8, &record.provenance_sha256.?, &published_digest)",
            "!std.mem.eql(u8, prior_evidence, current_evidence)",
            "if (!retained_completion) try completion_store.publish(allocator, statement.document);",
        ):
            with self.subTest(production=token):
                self.assertIn(token, unpack[start:end])
                changed = unpack[:start] + unpack[start:end].replace(token, "", 1) + unpack[end:]
                self.assertTrue(check(helper, support, changed))

    def test_native_workflow_acceptance_wiring_is_mutation_enforced(self) -> None:
        build = (ROOT / "build.zig").read_text()
        family = (ROOT / "test/native_recovery_family.zig").read_text()
        projected = (ROOT / "test/native_recovery_projected_workflows.zig").read_text()
        check = security_audit.native_workflow_acceptance_wiring_failures
        self.assertEqual([], check(build, family, projected))
        for token in (
            'recovery_family.addArg("--self");',
            'recovery_family.addArtifactArg(native_lifecycle_tests);',
            'recovery_family.addArg("--cli");',
            'recovery_family.addArtifactArg(cli);',
        ):
            with self.subTest(build=token):
                self.assertTrue(check(build.replace(token, "", 1), family, projected))
        for token in (
            "return projected.inside(init, allocator, root);",
            "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
            'try verificationRefusals(fixture, driver, request, returned, original_summary, "executed");',
            "try verificationRefusals(fixture, driver, original, first_completion, summary, name);",
            'const no_result_path = try support.path(fixture.allocator, name, "verify-first-without-result");',
            'const equivalent_path = try support.path(fixture.allocator, name, "verify-create-as-customize");',
            'try assertFamilySummary(fixture, driver, original, first_completion, summary, try support.path(fixture.allocator, name, "verify-final"));',
            "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
            "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
            "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
            'try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-after-refusals", true);',
            "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
            "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
            'try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-recovered"), true);',
            "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
            "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
            "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
            "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);",
            'try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-unsettled-verified-again"));',
            "const root_before = try projected.rootInventory(fixture, request.root, true);",
            "const pending_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
            "const before_evidence = try projected.rootInventory(fixture, update.native_root, true);",
            '"executed/{s}-verify-without-result"',
            '"executed/{s}-verify-as-install"',
            "const failed_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
            ".force = invocation.force,",
            '"wrong-conffile"',
            '"{s}/replacement-{s}"',
            '"changed-request"',
            '"verify-damaged-{s}"',
            '"verify-unresolved-{s}"',
            '"verify-partial-acknowledgment"',
            '"acknowledge-damaged-receipt"',
            '"verify-public-owner-retained"',
            '"verify-terminal-foreign-attempt"',
            '"verify-public-pending"',
            '"verify-public-native-acknowledged"',
            '"verify-public-pending-failure"',
            '"verify-public-failed-acknowledgment"',
            '"verify-public-final-failure"',
            '"verify-success-as-failure"',
            '"verify-pending-as-released"',
            '"executed/workflow-owned-success/verify-finalized-as-released"',
            'try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, "executed/inspect-initial", "essential-core", true, false);',
            '"executed/inspect-while-root-lock-held"',
            '"executed/inspect-failed-same-root"',
            '"executed/missing-helper-inspection"',
            'const reference_failure = "executed/same-root-failure-reference";',
            "linux.flock(holder.handle, 2 | 4)",
            '"verify-before-execution"',
            '"verify-failed-result"',
            '"verify-relabeled-failure"',
            '"verify-failed-without-result"',
            '"ordinary-to-FAMILY same-root timeline: signed success, full verification refusals, failed install and clean recovery matched pinned dpkg',
            '"semantic request") == null',
            'try std.testing.expectEqual(@as(i64, 3), (try field(update_lock_document.value, "version")).integer);',
            "try std.testing.expectEqual(@as(usize, 24), parsed.value.object.count());",
            "try std.testing.expectEqual(@as(usize, 13), capability.value.object.count());",
            "try std.testing.expectEqual(@as(usize, 24), verified.report.value.object.count());",
            "try std.testing.expectEqual(@as(i64, 3), (try field(install_lock.value, \"version\")).integer);",
        ):
            with self.subTest(family=token):
                self.assertTrue(check(build, family.replace(token, "", 1), projected))
        for original, weakened in (
            ("fixture.allocator = phase_arena.allocator();", ""),
            ("defer fixture.allocator = allocator;", ""),
            ("first_completion = try std.json.parseFromSlice(std.json.Value, persistent_allocator,", "first_completion = try std.json.parseFromSlice(std.json.Value, fixture.allocator,"),
            ("    _ = phase_arena.reset(.free_all);\n    try ordinaryFamilyTimeline", "    try ordinaryFamilyTimeline"),
            ("    _ = phase_arena.reset(.free_all);\n    try ownedSuccess", "    try ownedSuccess"),
            ("        _ = phase_arena.reset(.free_all);\n        const label:", "        const label:"),
            ("    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);", "    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);"),
        ):
            with self.subTest(allocation=original):
                self.assertIn(original, family)
                self.assertTrue(check(build, family.replace(original, weakened, 1), projected))
        dpkg = "try referenceSingleFailure(fixture, reference, scenario.reference_root, arch, name)"
        self.assertEqual(2, family.count(dpkg))
        self.assertTrue(check(build, family.replace(dpkg, "", 1), projected))
        finalized = '"verify-public-finalized"'
        self.assertEqual(2, family.count(finalized))
        self.assertTrue(check(build, family.replace(finalized, "", 1), projected))
        same_root = 'try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/same-root-failure-comparison", true);'
        self.assertEqual(2, family.count(same_root))
        self.assertTrue(check(build, family.replace(same_root, "", 1), projected))
        for token in (
            'for ([_][]const u8{ "success", "recovered", "failed" }) |outcome|',
            '"/usr/bin/unshare", "--mount", "--pid", "--fork"',
            '.prepare_acknowledged_review = .{ .lock_sha256 = lock_digest, .generation = 6 },',
            '.prepare_cleared_review = .{ .lock_sha256 = lock_digest, .receipt_sha256 = receipt_digest, .generation = 8 },',
            "const evidence_before = if (step.verification) |check|",
            "const review_baseline = try evidenceInventory(fixture, scenario.native_root, false);",
            "return inventory(fixture, root, \".\", include_metadata);",
            "const damaged_state = try evidenceInventory(fixture, scenario.native_root, true);",
            "const orphan_state = try evidenceInventory(fixture, scenario.native_root, true);",
            "try std.testing.expectEqual(@as(i64, 2), (try field(owner_v2.value, \"version\")).integer);",
            'try support.absent(fixture, withheld_operation);',
        ):
            with self.subTest(projected=token):
                self.assertTrue(check(build, family, projected.replace(token, "", 1)))
    def test_lifecycle_migration_retires_four_python_gates_without_weakening_reference_refusal(self) -> None:
        build = (ROOT / "build.zig").read_text()
        trigger = (ROOT / "test/native_trigger_acceptance.zig").read_text()
        check = security_audit.native_lifecycle_migration_failures
        self.assertEqual([], check(build, trigger))
        for entrypoint in (
            "tools/test-native-lifecycle.py",
            "tools/test_native_lifecycle.py",
            "tools/test-native-triggers.py",
            "tools/test_native_triggers.py",
        ):
            with self.subTest(entrypoint=entrypoint):
                self.assertTrue(check(build + f' \"{entrypoint}\"', trigger))
        for binding in (
            'const native_lifecycle_step = b.step("test-native-lifecycle",',
            'const native_triggers_step = b.step("test-native-triggers",',
            "native_lifecycle_step.dependOn(&lifecycle_zig.step);",
            "native_triggers_step.dependOn(&trigger_zig.step);",
            "native_triggers_step.dependOn(&run_native_trigger_queue_tests.step);",
            "lifecycle_zig.addArtifactArg(native_lifecycle_tests);",
            "trigger_zig.addArtifactArg(native_lifecycle_tests);",
            'trigger_zig.addArg("--native-helper");',
            "trigger_zig.addArtifactArg(native_trigger_helper);",
            "test_step.dependOn(&run_lifecycle_zig_tests.step);",
            "test_step.dependOn(&run_trigger_zig_tests.step);",
            "test_step.dependOn(&run_settlement_tests.step);",
            'b.step("test-native-lifecycle-zig-oracle",',
            'b.step("test-native-triggers-zig-oracle",',
            'b.step("test-native-triggers-zig-settlement-reference",',
            'settlement_oracle_zig.addArgs(&.{ "--oracle-only", "--diversion-settlement-reference-only" });',
            "settlement_unit_step.dependOn(&run_settlement_lowering_tests.step);",
        ):
            with self.subTest(binding=binding):
                self.assertTrue(check(build.replace(binding, ""), trigger))
        for token in (
            "for ([_]bool{ false, true }) |awaiting|",
            ".no_scripts = true",
            "support.reference(fixture, dpkg, root",
            "Status: install ok unpacked",
            "Status: install ok half-configured",
            "Triggers-Pending:",
            "Triggers-Awaited:",
            "queue.len != 0",
            "activation-returned",
            "exit 1",
            "failedPostinstUnconfiguredListener(&fixture, reference.executable, reference.architecture)",
        ):
            with self.subTest(token=token):
                self.assertTrue(check(build, trigger.replace(token, "")))
        for token in (
            "fn refuseUnconfiguredListenerProgram(",
            "case.seedWith(handler, false)",
            'report.value.detail, "program_compile_rejected"',
            "foundation.captureRealRoot(",
            "support.assertNoActiveEvidence(",
            "refuseUnconfiguredListenerProgram(&fixture, native_driver, selected, reference.executable, reference.architecture)",
            "if (oracle_only == (driver != null) or (helper != null) != (driver != null))",
            "if (settlement_reference_only and (!oracle_only or diversions_only))",
            "if (fixture.oracle_only) return;",
            "settlement.run(&fixture, native_driver, reference.executable, selected, reference.architecture)",
        ):
            with self.subTest(refusal=token):
                self.assertTrue(check(build, trigger.replace(token, "")))

    def test_lifecycle_migration_removes_entrypoints_and_preserves_fixture_imports(self) -> None:
        retired = (
            "tools/test-native-lifecycle.py",
            "tools/test_native_lifecycle.py",
            "tools/test-native-triggers.py",
            "tools/test_native_triggers.py",
            "tools/test-native-recovery.py",
            "tools/test_native_recovery.py",
        )
        fixture_paths = (
            "tools/native-lifecycle-fixtures.py",
            "tools/native-trigger-fixtures.py",
        )
        consumers = (
            "tools/dpkg-config-reference.py",
            "actions/install/__tests__/integration.test.ts",
        )
        texts = {path: (ROOT / path).read_text() for path in (*fixture_paths, *consumers)}
        check = security_audit.native_lifecycle_fixture_failures
        self.assertEqual([], check(texts))
        for path in retired:
            with self.subTest(restored=path):
                self.assertTrue(check({**texts, path: ""}))
        for path in fixture_paths:
            with self.subTest(missing=path):
                self.assertTrue(check({name: body for name, body in texts.items() if name != path}))
            for entrypoint in (
                "#!/usr/bin/env python3\n",
                "\nimport argparse\n",
                "\ndef main() -> int:\n",
                '\nif __name__ == "__main__":\n',
            ):
                with self.subTest(fixture=path, entrypoint=entrypoint):
                    changed = (
                        entrypoint + texts[path]
                        if entrypoint.startswith("#!")
                        else texts[path] + entrypoint
                    )
                    self.assertTrue(check({**texts, path: changed}))
        for path in (fixture_paths[1], *consumers):
            with self.subTest(importer=path):
                self.assertTrue(check({**texts, path: texts[path].replace("native-lifecycle-fixtures.py", "missing.py")}))

    def test_build_workloads_keep_both_modes_and_all_existing_suites(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual([], security_audit.native_recovery_ci_failures(workflow))
        match = re.search(
            r"(?ms)^  build-and-test-workload:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        )
        self.assertIsNotNone(match)
        workload = match[1]
        for token, replacement in (
            ("    timeout-minutes: 90", "    timeout-minutes: 180"),
            ("name: [linux-x64, linux-arm64]", "name: [linux-x64]"),
            ("optimize: [Debug, ReleaseSafe]", "optimize: [Debug]"),
            ("optimize: [Debug, ReleaseSafe]", "optimize: [ReleaseSafe]"),
            ("      OPTIMIZE: ${{ matrix.optimize }}", "      OPTIMIZE: Debug"),
            ("        include:", "        exclude:"),
            ('          zig build test -Doptimize="$OPTIMIZE" -j2 --summary all', ""),
            ('          zig build fuzz -Doptimize="$OPTIMIZE" -j2 --summary all', ""),
            ("      - name: Build and test\n", "      - name: Build and test\n        if: false\n"),
            ("-Doptimize=\"$OPTIMIZE\"", "-Doptimize=Debug"),
            ("test-native-materialization test-native-conffiles", "test-native-materialization"),
            ("test-native-differential", ""),
            (
                "test-native-lifecycle-zig test-native-triggers-zig "
                "test-native-diversion-settlement-zig",
                "test-native-lifecycle-zig test-native-triggers-zig",
            ),
            (
                "test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle "
                "test-native-triggers-zig-settlement-reference",
                "test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle",
            ),
            (
                'test-native-diversion-settlement-zig \\\n'
                '            -Dnative-reference-dpkg="$reference_dpkg"',
                'test-native-diversion-settlement-zig \\\n'
                '            -Dnative-reference-dpkg="$untrusted_dpkg"',
            ),
            (
                "      - name: Exercise standalone Zig workspace selectors and fail-closed combinations\n",
                "      - name: Exercise standalone Zig workspace selectors and fail-closed combinations\n        if: false\n",
            ),
            ('          zig build build-native-acceptance-zig -Doptimize="$OPTIMIZE" -j2 --summary all', ""),
            ('            zig-out/bin/native-lifecycle-zig-acceptance --oracle-only --diversions-only \\', ""),
            ('            zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only \\', ""),
            ("          grep -Fxq 'error: InvalidSettlementSelection' \"$PWD/.tmp/zig-invalid-selector.log\"", ""),
            ("          grep -Fxq 'error: PathAlreadyExists' \"$PWD/.tmp/zig-existing-workspace.log\"", ""),
            ('reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"', "reference_dpkg=/usr/bin/dpkg"),
            ('-Dnative-reference-dpkg="$reference_dpkg"', ""),
            ("test-native-helper-namespace", "test"),
            ("        run: zig build test-release -j2 --summary all", ""),
            ("        run: zig build -Doptimize=ReleaseSafe -j2 run -- --help", ""),
            ('            "$(command -v zig)" build test-apt-system-acceptance \\', ""),
            ('              -Doptimize="$OPTIMIZE" -j2 --summary all', ""),
            ("              -Drequire-privileged-orchestration-tests=true \\", ""),
            ("          python3 tools/generate-integration-repository.py \\", ""),
            ("        uses: ./actions/download", ""),
            ('          test "$DOWNLOADED" -gt 0', ""),
        ):
            with self.subTest(token=token, replacement=replacement):
                self.assertIn(token, workload)
                changed = workflow.replace(workload, workload.replace(token, replacement, 1), 1)
                self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        steps = dict(re.findall(
            r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", workload,
        ))
        root_step = steps["Run required real apt facade acceptance"]
        for token in (
            "          sudo env \\",
            '            TMPDIR="$PWD/.zig-cache" \\',
            '            PYTHONPYCACHEPREFIX="$PWD/.zig-cache/pycache" \\',
            '            ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-cache/apt-system-acceptance-global" \\',
            '            ZIG_LOCAL_CACHE_DIR="$PWD/.zig-cache/apt-system-acceptance-local" \\',
        ):
            with self.subTest(root_fixture_isolation=token):
                changed = workflow.replace(root_step, root_step.replace(token, "", 1), 1)
                self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        normalization = steps["Normalize apt facade acceptance diagnostics"]
        changed = workflow.replace(
            normalization,
            normalization.replace("        if: ${{ always() }}", "        if: false", 1),
            1,
        )
        self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        for name, body in steps.items():
            if "        if: ${{ matrix.optimize ==" not in body:
                continue
            with self.subTest(step=name):
                changed = workflow.replace(
                    body, re.sub(r"(?m)^        if:.*$", "        if: false", body), 1,
                )
                self.assertTrue(security_audit.native_recovery_ci_failures(changed))
        script = textwrap.dedent(steps["Build and test"].split("        run: |\n", 1)[1])
        for mode in ("Debug", "ReleaseSafe"):
            commands = [
                f"build{target} -Doptimize={mode} -j2 --summary all"
                for target in ("", " test", " fuzz")
            ]
            with self.subTest(mode=mode):
                result = subprocess.run(
                    ["bash", "-e", "-c", 'zig() { printf "%s\\n" "$*"; }\n' + script],
                    env={**os.environ, "OPTIMIZE": mode},
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), commands)
            for command in commands:
                with self.subTest(mode=mode, failing_command=command):
                    result = subprocess.run(
                        ["bash", "-e", "-c", 'zig() { test "$*" != "$FAIL_COMMAND"; }\n' + script],
                        env={**os.environ, "OPTIMIZE": mode, "FAIL_COMMAND": command},
                        stdin=subprocess.DEVNULL, capture_output=True, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_install_action_reuses_pinned_bundles_and_never_short_circuits(self) -> None:
        package = json.loads((ROOT / "actions/install/package.json").read_text())
        self.assertEqual(package["dependencies"], {"@actions/core": "3.0.1"})
        subprocess_source = (ROOT / "actions/install/src/subprocess.ts").read_text()
        self.assertIn("setup', 'dist', 'main', 'index.js", subprocess_source)
        self.assertIn("download', 'dist', 'index.js", subprocess_source)
        self.assertIn("DEBZ_DOWNLOAD_EXECUTABLE", subprocess_source)
        self.assertNotIn("shell: true", subprocess_source)
        action_source = (ROOT / "actions/install/src/action.ts").read_text()
        self.assertLess(
            action_source.index("const download = await composition.download"),
            action_source.index("buildInstallArguments(inputs)"),
        )
        self.assertLess(
            action_source.index("validateTransactionSummary("),
            action_source.index("io.setOutput('transaction-result'"),
        )


if __name__ == "__main__":
    unittest.main()
