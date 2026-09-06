#!/usr/bin/env python3
"""Tests for repository-local security audit helpers."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_security_audit", ROOT / "tools/security-audit.py"
)
assert SPEC and SPEC.loader
security_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_audit)


class SecurityAuditTests(unittest.TestCase):
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

    def test_maintainer_script_owns_the_native_child_process_boundary(self) -> None:
        sources = {
            path.relative_to(ROOT).as_posix(): path.read_text()
            for path in sorted((ROOT / "src").rglob("*.zig"))
        }
        owners = sorted(
            relative
            for relative, text in sources.items()
            if re.search(r"\blinux\.(?:fork|execve|chroot)\s*\(", text)
        )
        self.assertEqual(["src/maintainer_script.zig"], owners)
        runner = sources["src/maintainer_script.zig"]
        self.assertNotIn("std.process.run(", runner)
        self.assertIn('linux.open("/dev/null"', runner)
        self.assertIn('linux.chroot(".")', runner)

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
