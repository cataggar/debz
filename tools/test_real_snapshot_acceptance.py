#!/usr/bin/env python3
"""Offline driver regressions, not real-package or native-backend acceptance."""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/real-snapshot-acceptance.sh"
URI = "https://snapshot.ubuntu.com/ubuntu/20260816T000000Z"
SIGNER = "f6ecb3762474eda9d21b7022871920d1991bc93c"


def fixture_cli() -> int:
    args = sys.argv[2:]
    operation = args[0]

    def option(name: str) -> pathlib.Path:
        return pathlib.Path(args[args.index(name) + 1])

    def write(path: pathlib.Path, value: dict) -> None:
        path.write_text(json.dumps(value) + "\n")

    with pathlib.Path(os.environ["SNAPSHOT_TEST_CALLS"]).open("a") as log:
        log.write(json.dumps(args) + "\n")
    scenario = os.environ.get("SNAPSHOT_TEST_SCENARIO", "")
    lock_input = (
        json.loads(option("--lock-input").read_text())
        if "--lock-input" in args else None
    )
    if operation == "plan" and lock_input and lock_input["digest_sha256"].startswith("0"):
        print('{"exit_status":5}')
        return 5
    if operation == "plan":
        intent = "install" if args[-1] == "ubuntu-minimal" else "upgrade-all"
        lock = lock_input or {
            "target_architecture": str(option("--architecture")),
            "packages": [{"name": "ubuntu-minimal", "declared_size": 1}],
            "repositories": [{"signer_fingerprints": [
                "unreviewed" if scenario == "unreviewed-signer"
                or (scenario == "unreviewed-update-signer" and intent == "upgrade-all")
                else SIGNER
            ]}],
            "digest_sha256": ("a" if intent == "install" else "b") * 64,
            "fixture_intent": intent,
        }
        write(option("--lock-output"), lock)
    if operation in ("install", "upgrade-all"):
        assert lock_input is not None and lock_input["fixture_intent"] == operation
        status = option("--install-root") / "var/lib/dpkg/status"
        if operation == "install":
            status.write_text(
                "Package: ubuntu-minimal\nStatus: install ok installed\n"
                f"Architecture: {option('--architecture')}\nVersion: 1.0\n"
                "Description: offline driver fixture\n\n"
            )
        elif scenario == "changed-status":
            status.write_text(status.read_text().replace("Version: 1.0", "Version: 2.0"))
        write(option("--state-path") / "transaction-result.json", {
            "outcome": "succeeded",
            "commands": ["fixture-install"] if operation == "install"
            or scenario == "update-command" else [],
            "fixture_lock_digest": lock_input["digest_sha256"],
        })
    if operation == "transaction-result":
        assert args[1] == "verify" and lock_input is not None
        receipt = json.loads((option("--state-path") / "transaction-result.json").read_text())
        assert receipt["fixture_lock_digest"] == lock_input["digest_sha256"]
        print(json.dumps({"outcome": "failed" if scenario == "failed-verification"
                          else receipt["outcome"]}))
    else:
        print('{"exit_status":0,"changed":true}')
    return 0


class RealSnapshotAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="debz-snapshot-driver-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name).resolve()
        self.workspace = self.directory / ".real-snapshot/fresh"
        self.keyring = self.directory / "fixture-keyring.gpg"
        self.keyring.write_bytes(b"offline validation fixture, not trust material")
        self.calls = self.directory / "calls.jsonl"
        self.cli = self.directory / "fixture-debz"
        self.cli.write_text(
            "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
            + shlex.quote(str(pathlib.Path(__file__).resolve())) + ' --fixture-cli "$@"\n'
        )
        self.cli.chmod(0o700)
        self.architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
        self.env = {
            **os.environ,
            "DEBZ_REAL_SNAPSHOT_KEYRING": str(self.keyring),
            "SNAPSHOT_TEST_CALLS": str(self.calls),
            "SNAPSHOT_TEST_SCENARIO": "",
        }

    def run_driver(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *arguments],
            cwd=self.directory, env=self.env, capture_output=True, text=True, timeout=30,
        )

    def run_acceptance(self) -> subprocess.CompletedProcess[str]:
        return self.run_driver(str(self.cli), URI, "resolute", self.architecture,
                               str(self.workspace))

    def test_explicit_keyring_requires_an_absolute_regular_non_symlink_file(self) -> None:
        symlink = self.directory / "linked.gpg"
        symlink.symlink_to(self.keyring)
        for keyring in (self.directory / "missing.gpg", self.directory, symlink,
                        pathlib.Path(self.keyring.name)):
            with self.subTest(keyring=keyring):
                self.env["DEBZ_REAL_SNAPSHOT_KEYRING"] = str(keyring)
                result = self.run_driver("--validate", URI, "resolute", self.architecture)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("explicit regular Ubuntu archive keyring", result.stderr)
        self.env["DEBZ_REAL_SNAPSHOT_KEYRING"] = str(self.keyring)
        result = self.run_driver("--validate", URI, "resolute", self.architecture)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_workspace_refuses_before_cli_or_mutation(self) -> None:
        self.workspace.mkdir(parents=True)
        marker = self.workspace / "retained"
        marker.write_text("unchanged")
        result = self.run_acceptance()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot workspace must be new", result.stderr)
        self.assertEqual(marker.read_text(), "unchanged")
        self.assertFalse(self.calls.exists())

    def test_legacy_zero_command_update_keeps_its_own_verified_receipt(self) -> None:
        result = self.run_acceptance()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.workspace / "evidence"
        create = json.loads((evidence / "create-transaction-result.json").read_text())
        update = json.loads((evidence / "update-transaction-result.json").read_text())
        self.assertNotEqual(create["fixture_lock_digest"], update["fixture_lock_digest"])
        self.assertEqual(update["commands"], [])
        self.assertTrue(json.loads((evidence / "update.json").read_text())["changed"])
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        verifications = [call for call in calls if call[:2] == ["transaction-result", "verify"]]
        self.assertEqual(len(verifications), 2)
        self.assertIn(str(evidence / "ubuntu-minimal.lock.json"), verifications[0])
        self.assertIn(str(evidence / "ubuntu-minimal.update.lock.json"), verifications[1])
        update_plans = [call for call in calls if call[0] == "plan"
                        and str(evidence / "ubuntu-minimal.update.lock.json") in call]
        self.assertEqual(len(update_plans), 1)
        self.assertNotIn("ubuntu-minimal", update_plans[0])
        self.assertNotIn("--lock-input", update_plans[0])
        self.assertEqual((evidence / "update-zero-actions.txt").read_text(),
                         "command_count=0\nstatus_unchanged=true\n")

    def test_dangling_workspace_symlink_refuses_before_cli_or_mutation(self) -> None:
        self.workspace.parent.mkdir()
        target = self.workspace.parent / "missing"
        self.workspace.symlink_to(target, target_is_directory=True)
        result = self.run_acceptance()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot workspace must be new", result.stderr)
        self.assertFalse(target.exists())
        self.assertFalse(self.calls.exists())

    def test_unreviewed_signer_refuses_before_download(self) -> None:
        self.env["SNAPSHOT_TEST_SCENARIO"] = "unreviewed-signer"
        result = self.run_acceptance()
        self.assertNotEqual(result.returncode, 0)
        calls = [json.loads(line)[0] for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls, ["refresh", "plan"])

    def test_failed_receipt_verification_refuses(self) -> None:
        self.env["SNAPSHOT_TEST_SCENARIO"] = "failed-verification"
        self.assertNotEqual(self.run_acceptance().returncode, 0)
        self.assertFalse((self.workspace / "evidence/create-transaction-result.json").exists())

    def test_unreviewed_update_signer_refuses_before_update(self) -> None:
        self.env["SNAPSHOT_TEST_SCENARIO"] = "unreviewed-update-signer"
        self.assertNotEqual(self.run_acceptance().returncode, 0)
        calls = [json.loads(line)[0] for line in self.calls.read_text().splitlines()]
        self.assertNotIn("upgrade-all", calls)
        self.assertEqual(calls[-1], "plan")

    def test_update_commands_refuse_zero_action_evidence(self) -> None:
        self.env["SNAPSHOT_TEST_SCENARIO"] = "update-command"
        self.assertNotEqual(self.run_acceptance().returncode, 0)
        self.assertFalse((self.workspace / "evidence/update-zero-actions.txt").exists())

    def test_update_status_change_refuses_zero_action_evidence(self) -> None:
        self.env["SNAPSHOT_TEST_SCENARIO"] = "changed-status"
        self.assertNotEqual(self.run_acceptance().returncode, 0)
        self.assertFalse((self.workspace / "evidence/update-zero-actions.txt").exists())


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture-cli"]:
        raise SystemExit(fixture_cli())
    unittest.main()
