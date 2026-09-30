#!/usr/bin/env python3
"""Offline fail-closed checks for the bounded pinned-dpkg reference."""

from __future__ import annotations

import importlib.util
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from real_snapshot_reference_paths import open_absolute, protected, read_root_file

ROOT = TOOLS.parent
SPEC = importlib.util.spec_from_file_location(
    "debz_reference_order", TOOLS / "real-snapshot-reference-order.py"
)
assert SPEC and SPEC.loader
ORDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ORDER
SPEC.loader.exec_module(ORDER)


class ReferenceLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="debz-reference-negative-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_no_follow_database_rejects_symlinked_ancestors(self) -> None:
        (self.root / "var/lib").mkdir(parents=True)
        (self.root / "var/lib/dpkg").symlink_to("/etc")
        with self.assertRaises(OSError):
            read_root_file(self.root, "var/lib/dpkg/passwd", 1024 * 1024)
        (self.root / "var/lib/dpkg").unlink()
        (self.root / "var/lib/dpkg").mkdir()
        (self.root / "var/lib/dpkg/status").symlink_to("/etc/passwd")
        with self.assertRaises(OSError):
            read_root_file(self.root, "var/lib/dpkg/status", 1024 * 1024)

    def test_reference_paths_reject_mutable_ancestry_and_dotdot(self) -> None:
        path = self.root / "archive"
        path.write_bytes(b"signed bytes")
        with self.assertRaisesRegex(ValueError, "non-root ancestor"):
            protected(path)
        with self.assertRaises(ValueError):
            open_absolute(self.root / "../etc/passwd")
        with self.assertRaises(ValueError):
            read_root_file(self.root, "../etc/passwd", 1024)
        (self.root / "link").symlink_to(path)
        with self.assertRaises(OSError):
            open_absolute(self.root / "link")

    def test_shared_checkout_refuses_before_reference_root_creation(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("test requires a non-root caller")
        workspace = ROOT / ".real-snapshot" / "offline-reference-refusal-only"
        self.assertFalse(workspace.exists())
        result = subprocess.run(
            ["bash", str(TOOLS / "real-snapshot-reference.sh"),
             "/usr/bin/true", "/etc/passwd", str(self.root), "amd64", str(workspace)],
            cwd=ROOT, text=True, capture_output=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-root or writable reference path", result.stderr)
        self.assertFalse(workspace.exists())

    def test_protected_proof_target_refuses_shared_checkout_without_fixture_skips(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "test_real_snapshot_reference_protected.py"),
             "--launcher", str(self.root / "launcher"),
             "--dpkg", str(self.root / "dpkg"),
             "--root-template", str(self.root / "root"),
             "--workspace", str(self.root / "workspace"),
             "--archive", str(self.root / "archive"),
             "--archive-sha512", "0" * 128,
             "--archive-size", "1",
             "--escape-probe", str(self.root / "escape-probe"),
             "--escape-archive", str(self.root / "escape-archive"),
             "--escape-archive-sha512", "0" * 128,
             "--escape-archive-size", "1",
             "--architecture", "amd64"],
            cwd=ROOT, text=True, capture_output=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, "PermissionError|writable or non-root ancestor")
        self.assertNotIn("SKIP", result.stderr)

    def test_escape_probe_report_parsing_refuses_ambiguity(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "debz_reference_protected", TOOLS / "test_real_snapshot_reference_protected.py"
        )
        assert spec and spec.loader
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        report = "\n".join((
            "Preparing to unpack /.debz-reference-archive ...",
            "debz-escape-probe: mount-denied ok errno=PERM",
            "debz-escape-probe: shared-network-namespace info inet_socket=SUCCESS",
            "debz-escape-probe: result ok failures=0 mode=install",
        ))
        self.assertEqual(harness.probe_results(report), {"mount-denied": "ok", "result": "ok"})
        for ambiguous in (
            "debz-escape-probe: mount-denied ok\ndebz-escape-probe: mount-denied FAIL",
            "debz-escape-probe: mount-denied skipped",
        ):
            with self.assertRaises(AssertionError):
                harness.probe_results(ambiguous)
        self.assertEqual(
            set(harness.CONTROL_DETECTS) | {"inherited-descriptors", "path-escape"},
            set(harness.ESCAPE_CHECKS),
        )
        probe = (TOOLS / "real-snapshot-reference-escape-probe.zig").read_text()
        for check in (*harness.ESCAPE_CHECKS, "descendant-started", "result"):
            self.assertIn(f'"{check}"', probe)

    def test_same_named_script_in_different_checkout_refuses_before_preflight(self) -> None:
        other_tools = self.root / "tools"
        other_tools.mkdir()
        other_script = other_tools / "real-snapshot-reference.sh"
        shutil.copyfile(TOOLS / "real-snapshot-reference.sh", other_script)
        workspace = self.root / ".real-snapshot" / "unused"
        result = subprocess.run(
            ["bash", str(other_script),
             "/usr/bin/true", "/etc/passwd", str(self.root), "amd64", str(workspace)],
            cwd=ROOT, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, "run the protected reference script from its checkout root\n")
        self.assertFalse(workspace.exists())

    def test_status_read_refuses_duplicate_or_redirected_identity(self) -> None:
        database = self.root / "var/lib/dpkg"
        database.mkdir(parents=True)
        status = database / "status"
        status.write_text(
            "Package: demo\nArchitecture: amd64\nVersion: 1\n"
            "Status: install ok unpacked\nDescription: fixture\n more text\n\n"
        )
        self.assertEqual(
            ORDER.database_packages(self.root),
            {("demo", "amd64"): ("install ok unpacked", "1")},
        )
        status.write_text(status.read_text().replace(
            "Package: demo", "Package: demo\npackage: other"
        ))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ORDER.database_packages(self.root)
        status.unlink()
        status.symlink_to("/etc/passwd")
        with self.assertRaises(OSError):
            ORDER.database_packages(self.root)

    def test_launcher_invocation_stays_single_package(self) -> None:
        package = ORDER.Package(
            "demo", "1", "amd64", "a" * 128, 42, self.root / "package.deb",
        )
        command = ORDER.dpkg_command(
            self.root / "launcher", self.root / "dpkg", self.root / "root",
            "amd64", "none", "unpack", package,
        )
        self.assertEqual(command[3:7], ["amd64", "none", "unpack", "demo:amd64"])
        self.assertEqual(command[7:], [str(package.archive), package.digest, "42"])
        self.assertNotIn("--pending", command)

    def test_trigger_verbs_refuse_without_a_triggered_script_profile(self) -> None:
        package = ORDER.Package(
            "sudo", "1.9.17p2-7ubuntu3", "amd64",
            "a" * 128, 42, self.root / "sudo.deb",
        )

        def command(profile: str, verb: str, selected: ORDER.Package = package) -> list[str]:
            return ORDER.dpkg_command(
                self.root / "launcher", self.root / "dpkg", self.root / "root",
                "amd64", profile, verb, selected,
            )

        self.assertEqual(command("sudo", "configure")[3:7],
                         ["amd64", "sudo", "configure", "sudo:amd64"])
        for profile in ("sudo", "none"):
            with self.subTest(profile=profile):
                with self.assertRaisesRegex(ValueError, "single-script binding"):
                    command(profile, "triggers_only")
        with self.assertRaisesRegex(ValueError, "single-script binding"):
            command("sudo", "triggers_pending")
        with self.assertRaisesRegex(ValueError, "requires one signed package"):
            ORDER.dpkg_command(
                self.root / "launcher", self.root / "dpkg", self.root / "root",
                "amd64", "none", "configure",
            )
        with self.assertRaisesRegex(ValueError, "missing exact configure profile"):
            command("none", "configure")
        with self.assertRaisesRegex(ValueError, "unauthorized reference script profile"):
            command("sudo", "configure", ORDER.Package(
                "sudo", "different", "amd64", package.digest, package.size, package.archive,
            ))
        with self.assertRaisesRegex(ValueError, "unauthorized reference script profile"):
            command("sudo", "configure", ORDER.Package(
                "sudo", package.version, "all", package.digest, package.size, package.archive,
            ))
        with self.assertRaisesRegex(ValueError, "unauthorized reference script profile"):
            command("sudo", "configure", ORDER.Package(
                "not-sudo", package.version, "amd64", package.digest, package.size, package.archive,
            ))
        with self.assertRaisesRegex(ValueError, "unauthorized reference script profile"):
            command("sudo", "probe_configure")
        with self.assertRaisesRegex(ValueError, "unauthorized reference script profile"):
            ORDER.dpkg_command(
                self.root / "launcher", self.root / "dpkg", self.root / "root",
                "arm64", "sudo", "configure", package,
            )

    def test_archive_identity_preflight_checks_bytes_and_declared_size(self) -> None:
        archive = self.root / "fixture.deb"
        archive.write_bytes(b"exact fixture bytes")
        package = ORDER.Package(
            "fixture", "1", "amd64",
            hashlib.sha512(archive.read_bytes()).hexdigest(), archive.stat().st_size,
            archive,
        )
        with mock.patch.object(ORDER, "protected", side_effect=lambda path: path.stat()):
            ORDER.verify_archive(package)
            archive.write_bytes(b"x" * package.size)
            with self.assertRaisesRegex(ValueError, "digest changed"):
                ORDER.verify_archive(package)
            archive.write_bytes(b"different-size")
            with self.assertRaisesRegex(ValueError, "size changed"):
                ORDER.verify_archive(package)

    def test_configured_closure_cannot_route_unbound_trigger_action(self) -> None:
        package = ORDER.Package("fixture", "1", "amd64", "a" * 128, 42,
                                self.root / "fixture.deb")
        evidence = self.root / "evidence"
        evidence.mkdir()
        with (
            mock.patch.object(ORDER, "packages_from_manifest", return_value=[package]),
            mock.patch.object(ORDER, "probe", return_value=(0, b"")),
            mock.patch.object(ORDER, "verify_archive"),
            mock.patch.object(ORDER, "database_packages",
                              return_value={("fixture", "amd64"): ("install ok unpacked", "1")}),
            mock.patch.object(ORDER, "apply") as applied,
        ):
            with self.assertRaisesRegex(RuntimeError, "no exact triggered postinst identity"):
                ORDER.install(self.root / "launcher", self.root / "dpkg",
                              self.root, self.root / "cache", evidence, "amd64")
        self.assertEqual([args.args[0][5] for args in applied.call_args_list],
                         ["unpack", "configure"])

    def test_dry_run_hands_child_only_write_only_append_output_fds(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        script = self.root / "check-probe.py"
        script.write_text(
            "import fcntl, os, stat, sys\n"
            "assert stat.S_ISCHR(os.fstat(0).st_mode) and os.fstat(0).st_rdev == os.makedev(1, 3)\n"
            "assert all(stat.S_ISREG(os.fstat(fd).st_mode) and "
            "(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE) == os.O_WRONLY and "
            "(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_APPEND) "
            "for fd in (1, 2))\n"
            "print('stdout witness')\n"
            "print('stderr witness', file=sys.stderr)\n"
        )
        status, output = ORDER.probe([sys.executable, str(script)],
                                     ORDER.oracle_environment(), evidence)
        self.assertEqual(status, 0, output)
        self.assertEqual(sorted(output.splitlines()), [b"stderr witness", b"stdout witness"])
        self.assertEqual(list(evidence.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
