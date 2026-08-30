#!/usr/bin/env python3
"""Tests for repository-local security audit helpers."""

from __future__ import annotations

import importlib.util
import json
import pathlib
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


if __name__ == "__main__":
    unittest.main()
