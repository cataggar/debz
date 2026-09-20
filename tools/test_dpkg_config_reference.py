"""Regression coverage for the bounded direct-dpkg config reference."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_dpkg_config_reference", ROOT / "tools/dpkg-config-reference.py",
)
assert SPEC and SPEC.loader
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


class DpkgConfigReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="dpkg-config-reference-unit-", dir=ROOT / ".tmp",
        )
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_published_reference_is_canonical_and_schema_valid(self) -> None:
        reference = oracle.load_reference()
        schema = json.loads(
            (ROOT / "schema/dpkg-config-reference-v1.json").read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(reference)
        self.assertEqual(
            (ROOT / "tools/fixtures/vendor-state/dpkg-config-reference-v1.json").read_bytes(),
            oracle.canonical_json(reference).encode(),
        )
        self.assertEqual(
            [member["identity"] for member in reference["members"]],
            [
                "chrony.config",
                "console-setup.config",
                "debconf.config",
                "iproute2.config",
                "keyboard-configuration.config",
                "locales.config",
                "tzdata.config",
            ],
        )

    def test_source_digests_and_dpkg_pins_are_revalidated(self) -> None:
        reference = oracle.load_reference()
        oracle.verify_source_bindings(reference)
        self.assertEqual(
            reference["source"]["dpkg"]["architectures"],
            {
                architecture: {
                    "archive_sha256": pins["archive"],
                    "executable_sha256": pins["executable"],
                }
                for architecture, pins in oracle.m.reference_dpkg.PINS.items()
            },
        )

    def test_adversarial_config_scripts_are_bounded_and_observable(self) -> None:
        for token, exit_code, invalid in (
            ("v1", 91, False),
            ("v1r", 92, False),
            ("v2", 93, True),
        ):
            body = oracle.config_body(
                token, exit_code, invalid_interpreter=invalid
            )
            self.assertLessEqual(len(body), oracle.Limits.maximum_file_bytes)
            self.assertIn(f"# identity:{token}\n".encode(), body)
            self.assertIn(f"exit {exit_code}\n".encode(), body)
            self.assertIn(oracle.CONFIG_INVOCATIONS.encode(), body)
            result = oracle.subprocess.run(
                ["/bin/sh", "-n"],
                input=body,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_vendor_config_fixtures_match_all_pinned_sizes(self) -> None:
        reference = oracle.load_reference()
        for architecture in ("amd64", "arm64"):
            for index, member in enumerate(reference["members"]):
                package = member["owner"]["package"]
                fact = member["architectures"][architecture]
                body = oracle.vendor_config_body(package, fact["size"], 70 + index)
                self.assertEqual(len(body), fact["size"])
                self.assertIn(f"# identity:{package}\n".encode(), body)
                self.assertIn(oracle.VENDOR_CONFIG_INVOCATIONS.encode(), body)
        self.assertTrue(
            all(
                member["architectures"]["amd64"]
                == member["architectures"]["arm64"]
                for member in reference["members"]
            )
        )

    def control_source(self) -> Path:
        source = self.workspace / "source"
        (source / "DEBIAN").mkdir(parents=True)
        oracle.m.write(
            source / "DEBIAN/config",
            oracle.config_body("v1", 91),
            0o755,
        )
        return source

    def test_fixture_control_tree_rejects_traversal_symlinks_and_special_files(
        self,
    ) -> None:
        source = self.control_source()
        oracle.validate_control_tree(source)
        for name in ("../config", "/config", "nested/config", ".", ""):
            with self.assertRaises(oracle.OracleError):
                oracle.validate_control_name(name)

        (source / "DEBIAN/config").unlink()
        (source / "target").write_bytes(b"target")
        (source / "DEBIAN/config").symlink_to("../target")
        with self.assertRaisesRegex(oracle.OracleError, "must be regular"):
            oracle.validate_control_tree(source)

        (source / "DEBIAN/config").unlink()
        os.mkfifo(source / "DEBIAN/config")
        with self.assertRaisesRegex(oracle.OracleError, "must be regular"):
            oracle.validate_control_tree(source)

    def test_frontend_environment_is_refused(self) -> None:
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }
        oracle.validate_environment(environment)
        for name in oracle.FORBIDDEN_FRONTEND_ENV:
            with self.assertRaisesRegex(oracle.OracleError, "frontend environment"):
                oracle.validate_environment({**environment, name: "contaminated"})

    def test_trace_parser_preserves_empty_arguments_and_bounds_output(self) -> None:
        root = self.workspace / "root"
        (root / "var/log").mkdir(parents=True)
        line = (
            "postinst@v1\t2\t9:configure\t0:"
            "\tinfo=v1\tstaging=<absent>\tcwd=/\tfds=0,1,2\n"
        ).encode()
        oracle.m.write(root / oracle.TRACE, line)
        self.assertEqual(
            oracle.parse_trace(root),
            [
                {
                    "script": "postinst@v1",
                    "arguments": ["configure", ""],
                    "info_config": "v1",
                    "staging_config": None,
                }
            ],
        )
        oracle.m.write(
            root / oracle.TRACE,
            b"x" * (oracle.Limits.maximum_trace_bytes + 1),
        )
        with self.assertRaisesRegex(oracle.OracleError, "byte limit"):
            oracle.parse_trace(root)

    def test_reference_roots_and_native_guards_remain_fail_closed(self) -> None:
        unguarded = self.workspace / "unguarded"
        unguarded.mkdir()
        for root in (Path("/"), unguarded):
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                oracle.m.reference_command(root)

        native_unpack = (ROOT / "src/native_unpack.zig").read_text()
        self.assertIn(
            "if (database.model.opaque_info.len != 0)",
            native_unpack,
        )
        self.assertIn(
            '.{ .outcome = .handoff, .detail = "unsupported_archive_metadata" }',
            native_unpack,
        )
        archive_application = (ROOT / "src/archive_application.zig").read_text()
        self.assertIn(
            "V1 models and preserves it but never",
            archive_application,
        )
        self.assertIn("return self != .config;", archive_application)

    def test_reference_records_exact_direct_dpkg_outcome(self) -> None:
        observed = oracle.load_reference()["observed_behavior"]
        self.assertEqual(observed["config_invocation_count"], 0)
        self.assertEqual(observed["frontend_invocation_count"], 0)
        self.assertEqual(
            [phase["operation"] for phase in observed["successful_lifecycle"]],
            ["install", "reinstall", "upgrade", "remove", "purge"],
        )
        self.assertEqual(
            [case["case"] for case in observed["failure_recovery"]],
            [
                "fresh-postinst-failure",
                "upgrade-postinst-failure",
                "incoming-preinst-failure",
                "double-postrm-upgrade-failure",
                "remove-postrm-failure",
                "purge-postrm-failure",
            ],
        )
        self.assertEqual(
            [case["case"] for case in observed["interruption_recovery"]],
            [
                "postinst-interruption",
                "upgrade-preinst-interruption",
                "remove-postrm-interruption",
            ],
        )


if __name__ == "__main__":
    unittest.main()
