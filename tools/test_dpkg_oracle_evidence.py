"""Regression coverage for bounded dpkg oracle execution evidence."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_dpkg_oracle_evidence",
    ROOT / "tools/dpkg-oracle-evidence.py",
)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class DpkgOracleEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="dpkg-oracle-evidence-unit-",
            dir=ROOT / ".tmp",
        )
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_evidence_and_receipt_schemas_are_valid(self) -> None:
        for name in (
            "dpkg-oracle-execution-evidence-v1.json",
            "native-dpkg-reference-receipt-v1.json",
        ):
            schema = json.loads((ROOT / "schema" / name).read_bytes())
            jsonschema.Draft202012Validator.check_schema(schema)

        result = subprocess.run(
            ["/bin/sh", "-n", "tools/run-dpkg-oracle-isolated.sh"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_published_observations_have_the_expected_shape(self) -> None:
        config = json.loads(evidence.CONFIG_REFERENCE.read_bytes())
        alternatives = json.loads(evidence.ALTERNATIVES_REFERENCE.read_bytes())
        config_path = self.workspace / "config.json"
        alternatives_path = self.workspace / "alternatives.json"
        config_path.write_text(evidence.canonical_json(config["observed_behavior"]))
        alternatives_path.write_text(
            evidence.canonical_json(alternatives["observed_behavior"])
        )
        evidence.validate_observation(
            config_path,
            evidence.CONFIG_REFERENCE,
            "amd64",
        )
        evidence.validate_observation(
            alternatives_path,
            evidence.ALTERNATIVES_REFERENCE,
            "amd64",
        )

    def test_artifact_binding_is_canonical_bounded_and_private(self) -> None:
        artifact = self.workspace / "observation.json"
        artifact.write_text(evidence.canonical_json({"architecture": "arm64"}))
        binding = evidence.artifact_binding(
            artifact,
            self.workspace,
            evidence.MAXIMUM_OBSERVATION_BYTES,
        )
        self.assertEqual(binding["path"], artifact.name)
        self.assertEqual(binding["size"], artifact.stat().st_size)

        artifact.write_text('{"path":"/home/runner/work/private"}\n')
        with self.assertRaisesRegex(evidence.EvidenceError, "private runner"):
            evidence.artifact_binding(
                artifact,
                self.workspace,
                evidence.MAXIMUM_OBSERVATION_BYTES,
            )

    def test_invocation_clock_and_commit_are_strict(self) -> None:
        evidence.validate_clock("2026-09-20T16:29:21.965+00:00")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_clock("2026-09-20T16:29:21.965")
        self.assertIsNotNone(evidence.COMMIT.fullmatch("a" * 40))
        self.assertIsNone(evidence.COMMIT.fullmatch("A" * 40))


if __name__ == "__main__":
    unittest.main()
