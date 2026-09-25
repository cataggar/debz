#!/usr/bin/env python3
"""Tests for repository-local security audit helpers."""

from __future__ import annotations

import importlib.util
import itertools
import copy
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
        for workflow_name, expected_count in (("ci.yml", 12), ("release.yml", 1)):
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
        for token in (
            "    timeout-minutes: 180",
            "    needs: [build-and-test-workload, apt-system-tests, native-recovery]",
            "    if: ${{ always() }}",
            "        name: [linux-x64, linux-arm64]",
            "          BUILD_RESULT: ${{ needs.build-and-test-workload.result }}",
            "          APT_SYSTEM_RESULT: ${{ needs.apt-system-tests.result }}",
            "          RECOVERY_RESULT: ${{ needs.native-recovery.result }}",
            '          test "$BUILD_RESULT" = success',
            '          test "$APT_SYSTEM_RESULT" = success',
            '          test "$RECOVERY_RESULT" = success',
            '          reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"',
            '          zig build test-native-recovery -Dnative-reference-dpkg="$reference_dpkg" -j2 --summary all',
            '          zig build test-native-recovery -Dnative-reference-dpkg="$reference_dpkg" -Doptimize=ReleaseSafe -j2 --summary all',
            "          - os: ubuntu-24.04-arm",
        ):
            with self.subTest(token=token):
                self.assertTrue(security_audit.native_recovery_ci_failures(
                    workflow.replace(token, ""),
                ))
        self.assertTrue(security_audit.native_recovery_ci_failures(
            workflow.replace(
                "      matrix:\n        name: [linux-x64, linux-arm64]\n    steps:\n",
                "      matrix:\n        name: [linux-x64, linux-arm64]\n"
                "        exclude:\n          - name: linux-arm64\n    steps:\n",
            )
        ))
        gate = re.search(
            r"(?ms)^  build-and-test:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        )
        self.assertIsNotNone(gate)
        script = gate[1].split("        run: |\n", 1)[1]
        for build, apt_system, recovery in itertools.product(
            ("success", "failure", "cancelled", "skipped", "unknown"), repeat=3,
        ):
            with self.subTest(build=build, apt_system=apt_system, recovery=recovery):
                result = subprocess.run(
                    ["bash", "-e", "-c", textwrap.dedent(script)],
                    env={
                        **os.environ, "BUILD_RESULT": build,
                        "APT_SYSTEM_RESULT": apt_system, "RECOVERY_RESULT": recovery,
                    },
                    stdin=subprocess.DEVNULL, capture_output=True, check=False,
                )
                self.assertEqual(
                    result.returncode == 0, build == apt_system == recovery == "success"
                )

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
            ("    timeout-minutes: 60", "    timeout-minutes: 180"),
            ("name: [linux-x64, linux-arm64]", "name: [linux-x64]"),
            ("optimize: [Debug, ReleaseSafe]", "optimize: [Debug]"),
            ("optimize: [Debug, ReleaseSafe]", "optimize: [ReleaseSafe]"),
            ("            architecture: arm64", "            architecture: amd64"),
            ("      OPTIMIZE: ${{ matrix.optimize }}", "      OPTIMIZE: Debug"),
            ("        include:", "        exclude:"),
            ('          zig build test -Dci-split-apt-system-tests=true -Doptimize="$OPTIMIZE" -j2 --summary all', ""),
            ('          zig build fuzz -Doptimize="$OPTIMIZE" -j2 --summary all', ""),
            ("      - name: Build and test\n", "      - name: Build and test\n        if: false\n"),
            ("-Doptimize=\"$OPTIMIZE\"", "-Doptimize=Debug"),
            ("test-native-materialization test-native-conffiles", "test-native-materialization"),
            ("test-native-lifecycle test-native-triggers", "test-native-lifecycle"),
            ('reference_dpkg="$(python3 tools/prepare-native-dpkg.py)"', "reference_dpkg=/usr/bin/dpkg"),
            ('-Dnative-reference-dpkg="$reference_dpkg"', ""),
            ("test-native-helper-namespace", "test"),
            ("        run: zig build test-release -j2 --summary all", ""),
            ("        run: zig build -Doptimize=ReleaseSafe -j2 run -- --help", ""),
            ("            python3 tools/test-apt-system-acceptance.py zig-out/bin/debz", ""),
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
                for target in ("", " fuzz")
            ]
            commands.insert(1, f"build test -Dci-split-apt-system-tests=true -Doptimize={mode} -j2 --summary all")
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

    def test_apt_system_shard_and_default_build_graph_are_fail_closed(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        build = (ROOT / "build.zig").read_text()
        self.assertEqual([], security_audit.apt_system_ci_failures(workflow, build))
        shard = re.search(
            r"(?ms)^  apt-system-tests:\n.*?(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        )
        self.assertIsNotNone(shard)
        for original, replacement in (
            (shard[0], ""),
            ("  apt-system-tests:\n", "  apt-system-tests:\n    if: false\n"),
            ("        name: [linux-x64, linux-arm64]", "        name: [linux-x64]"),
            ("        optimize: [Debug, ReleaseSafe]", "        optimize: [Debug]"),
            ("        include:\n", "        exclude:\n"),
            ("          - os: ubuntu-24.04-arm", "          - os: ubuntu-24.04"),
            ("      fail-fast: false", "      fail-fast: true"),
            ("    timeout-minutes: 60", "    timeout-minutes: 30"),
            ("      - name: Run apt/system contract and orchestration tests\n",
             "      - name: Run apt/system contract and orchestration tests\n        if: false\n"),
            ('        run: zig build test-apt-system -Doptimize="$OPTIMIZE" -j2 --summary all',
             "        run: true"),
            ("      - name: Install metadata decompression dependency\n", ""),
        ):
            with self.subTest(original=original[:70]):
                changed = workflow.replace(shard[0], shard[0].replace(original, replacement, 1), 1)
                self.assertTrue(security_audit.apt_system_ci_failures(changed, build))
        for original, replacement in (
            ('"ci-split-apt-system-tests",', '"ci-split-apt-system-tests-old",'),
            ('"CI only: run the six apt/system test binaries in the separate test-apt-system job",\n    ) orelse false;',
             '"CI only: run the six apt/system test binaries in the separate test-apt-system job",\n    ) orelse true;'),
            ('"Fail instead of skipping privileged production orchestration tests",\n    ) orelse false;',
             '"Fail instead of skipping privileged production orchestration tests",\n    ) orelse true;'),
            ('    if (!ci_split_apt_system_tests) {', '    if (ci_split_apt_system_tests) {'),
            ('    apt_system_test_step.dependOn(&run_apt_system_cli_tests.step);', ""),
            ('        test_step.dependOn(&run_apt_system_state_tests.step);', ""),
            ('.filters = &.{"system_profile.test."}', '.filters = &.{}'),
            ('&.{"apt_system_command.test."},', '&.{"apt_system_command.test.no_match."},'),
            ('&.{ "apt_system_orchestrator.test.", "apt_system_lower_ownership_token.test." },',
             '&.{"apt_system_orchestrator.test.no_match."},'),
        ):
            with self.subTest(original=original):
                changed = build.replace(original, replacement, 1)
                self.assertNotEqual(changed, build)
                self.assertTrue(security_audit.apt_system_ci_failures(workflow, changed))
        for name in (
            "system_profile", "apt_system_api", "apt_system_cli",
            "apt_system_command", "apt_system_state", "apt_system_orchestrator",
        ):
            for step in ("apt_system_test_step", "test_step"):
                edge = f"{step}.dependOn(&run_{name}_tests.step);"
                with self.subTest(binary=name, step=step):
                    changed = build.replace(edge, "", 1)
                    self.assertTrue(security_audit.apt_system_ci_failures(workflow, changed))
        release_spec = importlib.util.spec_from_file_location(
            "debz_release_policy", ROOT / "tools/release-workflow-policy.py"
        )
        assert release_spec and release_spec.loader
        release_policy = importlib.util.module_from_spec(release_spec)
        release_spec.loader.exec_module(release_policy)
        self.assertEqual([], release_policy.audit_ci_apt_shard(workflow, build))
        self.assertTrue(release_policy.audit_ci_apt_shard(workflow.replace(shard[0], ""), build))
        self.assertTrue(release_policy.audit_ci_apt_shard(
            workflow.replace('          test "$APT_SYSTEM_RESULT" = success', ""), build
        ))
        self.assertTrue(release_policy.audit_ci_apt_shard(
            workflow, build.replace('    if (!ci_split_apt_system_tests) {', "")
        ))

    def test_apt_system_shard_runs_every_optimization_and_propagates_failures(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        shard = re.search(
            r"(?ms)^  apt-system-tests:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        )
        self.assertIsNotNone(shard)
        command = 'zig build test-apt-system -Doptimize="$OPTIMIZE" -j2 --summary all'
        self.assertIn("        run: " + command, shard[1])
        for mode in ("Debug", "ReleaseSafe"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    ["bash", "-e", "-c", 'zig() { printf "%s\\n" "$*"; }\n' + command],
                    env={**os.environ, "OPTIMIZE": mode},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(
                    result.stdout.strip(),
                    f"build test-apt-system -Doptimize={mode} -j2 --summary all",
                )
                self.assertEqual(result.returncode, 0)
                failed = subprocess.run(
                    ["bash", "-e", "-c", "zig() { return 1; }\n" + command],
                    env={**os.environ, "OPTIMIZE": mode},
                    capture_output=True, check=False,
                )
                self.assertNotEqual(failed.returncode, 0)

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
