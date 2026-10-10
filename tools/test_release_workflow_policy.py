#!/usr/bin/env python3
"""Regression tests for pinned Zig installation in required CI jobs."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_workflow_policy", ROOT / "tools/release-workflow-policy.py"
)
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


class ZigInstallPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ci = policy.CI.read_text()
        self.release = policy.RELEASE.read_text()
        policy.FAILURES.clear()
        self.addCleanup(policy.FAILURES.clear)

    def failures(self, ci: str, release: str | None = None) -> list[str]:
        policy.FAILURES.clear()
        policy.audit_zig_installation(ci, self.release if release is None else release)
        return list(policy.FAILURES)

    def concurrency_failures(self, ci: str) -> list[str]:
        policy.FAILURES.clear()
        policy.audit_ci_concurrency(ci)
        return list(policy.FAILURES)

    def job(self, name: str) -> str:
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            self.ci.partition("\njobs:\n")[2],
        )
        self.assertIsNotNone(match)
        return match.group()

    def test_reviewed_jobs_have_one_exact_verified_install_each(self) -> None:
        self.assertEqual(len(policy.CI_GHR_ZIG_JOBS), 21)
        self.assertEqual(self.failures(self.ci), [])

    def test_balanced_move_between_new_jobs_still_fails(self) -> None:
        repository = self.job("native-recovery-zig-repository")
        helper = self.job("native-recovery-zig-helper")
        changed = self.ci.replace(
            repository, repository.replace(policy.GHR_ZIG_INSTALL, "", 1), 1
        ).replace(helper, helper + policy.GHR_ZIG_INSTALL, 1)
        self.assertEqual(changed.count(policy.GHR_ZIG_INSTALL), 21)
        self.assertIn("reviewed CI job inventory", " ".join(self.failures(changed)))

    def test_balanced_move_out_of_diversion_shard_still_fails(self) -> None:
        diversions = self.job("native-recovery-zig-diversions")
        helper = self.job("native-recovery-zig-helper")
        changed = self.ci.replace(
            diversions, diversions.replace(policy.GHR_ZIG_INSTALL, "", 1), 1
        ).replace(helper, helper + policy.GHR_ZIG_INSTALL, 1)
        self.assertEqual(changed.count(policy.GHR_ZIG_INSTALL), 21)
        self.assertIn("reviewed CI job inventory", " ".join(self.failures(changed)))

    def test_balanced_move_between_workload_jobs_still_fails(self) -> None:
        jobs = (
            "build-and-test-workload",
            *(f"build-and-test-workload-{name}" for name in ("production", "apt-system", "native", "release")),
        )
        for source, target in zip(jobs, jobs[1:] + jobs[:1]):
            with self.subTest(source=source, target=target):
                moved_from = self.job(source)
                moved_to = self.job(target)
                changed = self.ci.replace(
                    moved_from, moved_from.replace(policy.GHR_ZIG_INSTALL, "", 1), 1
                ).replace(moved_to, moved_to + policy.GHR_ZIG_INSTALL, 1)
                self.assertEqual(changed.count(policy.GHR_ZIG_INSTALL), 21)
                self.assertIn("reviewed CI job inventory", " ".join(self.failures(changed)))

    def test_balanced_move_out_of_native_oracle_evidence_job_still_fails(self) -> None:
        oracle = self.job("arm64-dpkg-oracles")
        helper = self.job("native-recovery-zig-helper")
        changed = self.ci.replace(
            oracle, oracle.replace(policy.GHR_ZIG_INSTALL, "", 1), 1
        ).replace(helper, helper + policy.GHR_ZIG_INSTALL, 1)
        self.assertEqual(changed.count(policy.GHR_ZIG_INSTALL), 21)
        self.assertIn("reviewed CI job inventory", " ".join(self.failures(changed)))

    def test_unverified_or_duplicate_install_refuses(self) -> None:
        changed = self.ci.replace("ghr-version: v0.8.1", "ghr-version: v0.8.0", 1)
        self.assertIn("exact verified ghr Zig install blocks", " ".join(self.failures(changed)))
        extra = self.ci + "\nuses: cataggar/ghr/actions/install@deadbeef\n"
        self.assertIn("unverified or duplicate ghr Zig installer use", " ".join(self.failures(extra)))

    def test_release_install_remains_exact(self) -> None:
        changed = self.release.replace(policy.GHR_ZIG_INSTALL, "", 1)
        self.assertIn("release.yml: expected 1 exact verified ghr Zig install blocks", " ".join(self.failures(self.ci, changed)))

    def test_ci_concurrency_remains_exact(self) -> None:
        self.assertEqual(self.concurrency_failures(self.ci), [])
        without = self.ci.replace(policy.CI_CONCURRENCY + "\n", "", 1)
        self.assertIn("workflow concurrency", " ".join(self.concurrency_failures(without)))
        weakened = self.ci.replace(
            "cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}",
            "cancel-in-progress: false",
            1,
        )
        self.assertIn("workflow concurrency", " ".join(self.concurrency_failures(weakened)))


class StandaloneGhrSmokePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ci = policy.CI.read_text()
        self.release = policy.RELEASE.read_text()
        policy.FAILURES.clear()
        self.addCleanup(policy.FAILURES.clear)

    def failures(self, ci: str, release: str) -> list[str]:
        policy.FAILURES.clear()
        policy.audit_ghr_smoke(ci, release)
        return list(policy.FAILURES)

    def test_both_native_smoke_consumers_use_the_verified_standalone_bootstrap(self) -> None:
        self.assertEqual(self.failures(self.ci, self.release), [])
        for index, original in enumerate((self.ci, self.release)):
            for changed in (
                original.replace(policy.GHR_STANDALONE_SETUP, "", 1),
                original.replace(policy.GHR_STANDALONE_SETUP, policy.GHR_STANDALONE_SETUP.replace("v0.8.1", "latest"), 1),
                original.replace(policy.GHR_STANDALONE_SETUP, policy.GHR_STANDALONE_SETUP + "          sha256: unreviewed\n", 1),
                original.replace('          PATH=/no-host-interpreters "$GHR_PATH" install "cataggar/debz@v$VERSION"\n', "", 1),
                original.replace('          test "$(PATH=/no-host-interpreters "$GHR_PATH" version)" = 0.8.1\n', "", 1),
                original.replace("          GHR_BIN_DIR: ${{ runner.temp }}/debz-release-ghr-bin\n", "", 1),
                original.replace('          test "$bin_dir" = "$GHR_BIN_DIR"\n', "", 1),
            ):
                with self.subTest(workflow=index, mutation=changed):
                    workflows = [self.ci, self.release]
                    workflows[index] = changed
                    self.assertTrue(self.failures(*workflows))

    def test_balanced_setup_move_to_an_unrelated_job_and_python_bootstrap_restore_refuse(self) -> None:
        for index, original in enumerate((self.ci, self.release)):
            moved = original.replace(policy.GHR_STANDALONE_SETUP, "", 1)
            moved += "\n  unrelated-ghr:\n    steps:\n" + policy.GHR_STANDALONE_SETUP
            self.assertEqual(moved.count(policy.GHR_STANDALONE_SETUP), 1)
            for changed in (moved, original + "\n# python3 -m venv .zig-cache/ghr\n",
                            original + "\n# pip install ghr-bin==0.7.0\n"):
                with self.subTest(workflow=index):
                    workflows = [self.ci, self.release]
                    workflows[index] = changed
                    self.assertTrue(self.failures(*workflows))


if __name__ == "__main__":
    unittest.main()
