#!/usr/bin/env python3
"""Tests for repository-local security audit helpers."""

from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
