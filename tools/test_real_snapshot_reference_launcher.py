#!/usr/bin/env python3
"""Offline fail-closed checks for the bounded pinned-dpkg reference."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from real_snapshot_reference_paths import open_absolute, protected, read_root_file
import real_snapshot_less_fixtures as LESS_FIXTURES
import real_snapshot_less_stage as LESS_STAGE
import real_snapshot_python_fixtures as PYTHON_FIXTURES

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

    def test_python_dpkg_staging_refuses_parent_and_leaf_aliases(self) -> None:
        pinned, archive = self.root / "pinned", self.root / "archive"
        pinned.write_bytes(b"pinned bytes")
        archive.write_bytes(b"archive bytes")
        for alias in ("usr", "usr/local", "usr/local/sbin", "usr/local/sbin/dpkg",
                      "var/lib/dpkg/python3-probe.deb"):
            with self.subTest(alias=alias):
                root = self.root / alias.replace("/", "-")
                (root / "usr").mkdir(parents=True)
                (root / "var/lib/dpkg").mkdir(parents=True)
                outside = self.root / (root.name + "-outside")
                outside.mkdir()
                witness = outside / "witness"
                witness.write_bytes(b"outside must survive")
                target = root / alias
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_dir():
                    target.rmdir()
                target.symlink_to(outside if alias != "usr/local/sbin/dpkg" and
                                  alias != "var/lib/dpkg/python3-probe.deb" else witness)
                with mock.patch.object(LESS_FIXTURES, "protected"), self.assertRaises((OSError, ValueError)):
                    PYTHON_FIXTURES.dispatch(["dpkg", str(root), str(pinned), str(archive)])
                self.assertEqual(witness.read_bytes(), b"outside must survive")
                self.assertEqual(sorted(path.name for path in outside.iterdir()), ["witness"])

    def test_python_shadow_negative_refuses_copied_leaf_alias(self) -> None:
        roots = [self.root / f"negative-{index}" for index in range(8)]
        (roots[0] / "usr/share/doc/python3").mkdir(parents=True)
        (roots[1] / "usr/bin").mkdir(parents=True)
        (roots[1] / "usr/bin/python3").symlink_to("python3.14")
        (roots[2] / "usr/sbin").mkdir(parents=True)
        outside = self.root / "outside-shadow"
        outside.write_bytes(b"preserved outside shadow")
        (roots[2] / "usr/sbin/update-alternatives").symlink_to(outside)
        with self.assertRaises(FileExistsError):
            PYTHON_FIXTURES.basic_negatives(roots)
        self.assertEqual(outside.read_bytes(), b"preserved outside shadow")

    def test_python_mutators_refuse_hardlink_and_nonregular_before_changes(self) -> None:
        outside = self.root / "outside-null"
        outside.write_bytes(b"untouched")
        outside.chmod(0o644)
        for kind in ("hardlink", "fifo", "directory", "alias", "parent-alias"):
            with self.subTest(kind=kind):
                root = self.root / kind
                (root / "dev").mkdir(parents=True)
                leaf = root / "dev/null"
                if kind == "hardlink":
                    os.link(outside, leaf)
                elif kind == "fifo":
                    os.mkfifo(leaf)
                elif kind == "directory":
                    leaf.mkdir()
                elif kind == "alias":
                    leaf.symlink_to(outside)
                else:
                    (root / "dev").rmdir()
                    (root / "dev").symlink_to(self.root)
                with mock.patch.object(LESS_FIXTURES.os, "ftruncate") as truncate, \
                        mock.patch.object(LESS_FIXTURES.os, "fchmod") as chmod:
                    for mutate in (
                        lambda: PYTHON_FIXTURES.strict_negatives([root] * 4),
                        lambda: PYTHON_FIXTURES.dispatch(["mode", str(root), "0600"]),
                    ):
                        with self.assertRaises((ValueError, OSError)):
                            mutate()
                    truncate.assert_not_called()
                    chmod.assert_not_called()
                self.assertEqual(outside.read_bytes(), b"untouched")
                self.assertEqual(outside.stat().st_mode & 0o777, 0o644)

    def test_python_staging_and_capture_create_exclusive_files(self) -> None:
        root = self.root / "safe"
        (root / "usr").mkdir(parents=True)
        (root / "var/lib/dpkg").mkdir(parents=True)
        pinned, archive = self.root / "pinned", self.root / "archive"
        pinned.write_bytes(b"pinned bytes")
        archive.write_bytes(b"archive bytes")
        with mock.patch.object(LESS_FIXTURES, "protected"):
            PYTHON_FIXTURES.dispatch(["dpkg", str(root), str(pinned), str(archive)])
            with self.assertRaises(FileExistsError):
                PYTHON_FIXTURES.dispatch(["dpkg", str(root), str(pinned), str(archive)])
        self.assertEqual((root / "usr/local/sbin/dpkg").read_bytes(), b"pinned bytes")
        self.assertEqual((root / "var/lib/dpkg/python3-probe.deb").read_bytes(), b"archive bytes")
        command = ["capture", str(root), "stdout", "stderr",
                   sys.executable, "-B", "-c", "print('captured')"]
        with self.assertRaises(SystemExit) as result:
            PYTHON_FIXTURES.dispatch(command)
        self.assertEqual(result.exception.code, 0)
        self.assertEqual((root / "stdout").read_bytes(), b"captured\n")
        with self.assertRaises(FileExistsError):
            PYTHON_FIXTURES.dispatch(command)
        with self.assertRaisesRegex(ValueError, "capture exceeds"):
            PYTHON_FIXTURES.dispatch([
                "capture", str(root), "oversized", "oversized-stderr",
                sys.executable, "-B", "-c", "import sys; sys.stdout.buffer.write(b'x' * (17 * 1024 * 1024))",
            ])
        self.assertEqual((root / "oversized").stat().st_size, 16 * 1024 * 1024)

    def test_less_source_setup_directories_refuse_aliases_and_handle_private_umask(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "usr").mkdir()
        (self.root / "usr/local").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            LESS_STAGE.directory(self.root, "usr/local")
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / "usr/local").unlink()
        previous = os.umask(0o077)
        try:
            LESS_STAGE.directory(self.root, "usr/local")
        finally:
            os.umask(previous)
        self.assertEqual((self.root / "usr/local").stat().st_mode & 0o777, 0o755)

    def test_less_source_setup_refuses_unreviewed_archive_before_opening_cache(self) -> None:
        version, size, digest = LESS_STAGE.SOURCE_ARTIFACTS["less"]
        entry = {"name": "less", "architecture": "arm64", "version": version,
                 "declared_size": size, "origin": {"type": "authenticated_repository"},
                 "archive_identity": {"primary": "sha512", "digests": [
                     {"algorithm": "sha512", "digest": digest}]}}
        for field, changed in (("version", "other"), ("declared_size", size + 1)):
            with self.subTest(field=field):
                wrong = dict(entry); wrong[field] = changed
                with mock.patch.object(LESS_STAGE, "protected") as opened:
                    with self.assertRaisesRegex(ValueError, "exact production authority"):
                        LESS_STAGE.archive({"packages": [wrong]}, self.root, "less")
                    opened.assert_not_called()

    def test_less_source_capture_is_exclusive_without_following_an_existing_alias(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"must stay intact")
        archive = self.root / "archive"
        (self.root / "archive.less-source.tar").symlink_to(outside)
        with mock.patch.object(LESS_STAGE.subprocess, "run") as executed:
            with self.assertRaises(FileExistsError):
                LESS_STAGE.member(archive, "usr/bin/dash")
            executed.assert_not_called()
        self.assertEqual(outside.read_bytes(), b"must stay intact")

    def test_less_negative_writes_refuse_leaf_aliases_without_touching_outside_bytes(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"must remain intact\n")
        for relative, create in (("usr/bin/update-alternatives", False), ("etc/ld.so.cache", True)):
            with self.subTest(relative=relative):
                target = self.root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(outside)
                with self.assertRaises(OSError):
                    if create:
                        LESS_FIXTURES.create_exclusive(self.root, relative, b"bad cache\n", 0o644)
                    else:
                        LESS_FIXTURES.overwrite_regular(self.root, relative, b"bad tool\n")
                self.assertEqual(outside.read_bytes(), b"must remain intact\n")

    def test_less_negative_writes_refuse_redirected_parent_components(self) -> None:
        outside = self.root / "outside"
        (outside / "bin").mkdir(parents=True)
        tool = outside / "bin/update-alternatives"
        tool.write_bytes(b"outside tool\n")
        cache = outside / "ld.so.cache"
        cache.write_bytes(b"outside cache\n")
        fixture = self.root / "fixture"
        fixture.mkdir()
        (fixture / "usr").symlink_to(outside)
        (fixture / "etc").symlink_to(outside)
        with self.assertRaises(OSError):
            LESS_FIXTURES.overwrite_regular(fixture, "usr/bin/update-alternatives", b"bad tool\n")
        with self.assertRaises(OSError):
            LESS_FIXTURES.create_exclusive(fixture, "etc/ld.so.cache", b"bad cache\n", 0o644)
        self.assertEqual(tool.read_bytes(), b"outside tool\n")
        self.assertEqual(cache.read_bytes(), b"outside cache\n")

    def test_less_negative_file_type_and_hardlinks_refuse_before_truncation(self) -> None:
        directory = self.root / "usr/bin"
        directory.mkdir(parents=True)
        outside = self.root / "outside"
        outside.write_bytes(b"must not truncate\n")
        target = directory / "update-alternatives"
        os.link(outside, target)
        with mock.patch.object(LESS_FIXTURES.os, "ftruncate", wraps=os.ftruncate) as truncate:
            with self.assertRaises(ValueError):
                LESS_FIXTURES.overwrite_regular(self.root, "usr/bin/update-alternatives", b"bad tool\n")
            truncate.assert_not_called()
            self.assertEqual(outside.read_bytes(), b"must not truncate\n")
            target.unlink()
            os.mkfifo(target)
            with self.assertRaises(ValueError):
                LESS_FIXTURES.overwrite_regular(self.root, "usr/bin/update-alternatives", b"bad tool\n")
            truncate.assert_not_called()

    def test_less_safe_fixture_writes_preserve_regular_and_exclusive_contract(self) -> None:
        tool = self.root / "usr/bin/update-alternatives"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"original tool with longer contents\n")
        (self.root / "etc").mkdir()
        LESS_FIXTURES.overwrite_regular(self.root, "usr/bin/update-alternatives", b"bad tool\n")
        self.assertEqual(tool.read_bytes(), b"bad tool\n")
        LESS_FIXTURES.create_exclusive(self.root, "etc/ld.so.cache", b"bad cache\n", 0o644)
        with self.assertRaises(FileExistsError):
            LESS_FIXTURES.create_exclusive(self.root, "etc/ld.so.cache", b"replacement\n", 0o644)
        self.assertEqual((self.root / "etc/ld.so.cache").read_bytes(), b"bad cache\n")

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

    def test_reference_compiler_stanza_uses_explicit_absolute_tool_and_library_without_path_widening(self) -> None:
        compiler_directory = self.root / "staged toolchain"
        compiler_directory.mkdir()
        compiler = compiler_directory / "zig"
        compiler.write_text(
            "#!/usr/bin/python3\nimport json, os, sys\n"
            "with open(os.environ['COMPILER_LOG'], 'w') as output:\n"
            "    json.dump(sys.argv, output)\n"
        )
        compiler.chmod(0o755)
        source = (TOOLS / "real-snapshot-reference.sh").read_text()
        resolve = next(line for line in source.splitlines() if line.startswith("zig=${DEBZ_ZIG:"))
        start = source.index('"$zig" build-exe ')
        command = source[start:source.index('chmod 0500 "$launcher"', start)]
        log = self.root / "compiler.json"
        environment = {
            "DEBZ_ZIG": str(compiler), "COMPILER_LOG": str(log),
            "ZIG_LIB_DIR": "/untrusted/library",
        }
        result = subprocess.run(
            ["/usr/bin/bash", "-euo", "pipefail", "-c",
             'export PATH=/usr/sbin:/usr/bin:/sbin:/bin\nunset ZIG_LIB_DIR\n'
             + resolve + '\nworkspace=$1\nlauncher=$workspace/launcher\n' + command,
             "reference-compiler-fixture", str(self.root)],
            env=environment, cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(log.read_text())
        self.assertEqual(arguments[0], str(compiler))
        self.assertEqual(arguments[1:3], ["build-exe", "tools/real-snapshot-reference-launcher.zig"])
        self.assertEqual(arguments[arguments.index("--zig-lib-dir") + 1], str(compiler_directory / "lib"))
        self.assertIn(f"-femit-bin={self.root}/launcher", arguments)

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
             "--profile-scripts", str(self.root / "profiles"),
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
        self.assertFalse(set(harness.CONFINED_CHECKS) & set(harness.ESCAPE_CHECKS))
        probe = (TOOLS / "real-snapshot-reference-escape-probe.zig").read_text()
        for check in (*harness.ESCAPE_CHECKS, *harness.CONFINED_CHECKS, "result"):
            self.assertIn(f'"{check}"', probe)
        mounted = "debz-escape-probe: archive-mount ok size=4096 mount_root=true write=ROFS"
        self.assertEqual(harness.probe_detail(mounted, "archive-mount")["size"], "4096")
        for missing in ("", mounted.replace(" ok ", " FAIL "), f"{mounted}\n{mounted}"):
            with self.assertRaises(AssertionError):
                harness.probe_detail(missing, "archive-mount")

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

    def test_status_read_accepts_valueless_fields(self) -> None:
        database = self.root / "var/lib/dpkg"
        database.mkdir(parents=True)
        status = database / "status"
        # dpkg writes Conffiles with no value on the field line; the value is
        # carried entirely by the continuation lines beneath it.
        status.write_text(
            "Package: demo\nArchitecture: amd64\nVersion: 1\n"
            "Status: install ok unpacked\n"
            "Conffiles:\n /etc/demo.conf 0123456789abcdef\n\n"
        )
        self.assertEqual(
            ORDER.database_packages(self.root),
            {("demo", "amd64"): ("install ok unpacked", "1")},
        )
        for malformed in ("Priority:optional", "Bad Key: x", "Conffiles"):
            status.write_text(
                "Package: demo\nArchitecture: amd64\nVersion: 1\n"
                f"Status: install ok unpacked\n{malformed}\n\n"
            )
            with self.assertRaisesRegex(ValueError, "malformed"):
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
            "sudo", "1.9.17p2-1ubuntu3.1", "amd64",
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

    def cycle_fixture(self) -> tuple[tuple, dict, dict]:
        fixture = json.loads((TOOLS / "fixtures/real-snapshot/base-cycle-controls-v1.json").read_text())
        packages = []
        records, controls = {}, {}
        for index, entry in enumerate(fixture["packages"]):
            fields, = ORDER.control_fields(entry["control"].encode())
            package = ORDER.Package(fields["package"], fields["version"], fields["architecture"],
                                    entry["archive_sha512"], entry["archive_size"],
                                    self.root / f'{fields["package"]}.deb')
            packages.append(package)
            records[(package.name, "amd64")] = {
                **fields, "status": entry["status"],
            }
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as archive:
                entries = {"./control": "".join(
                    f"{key}: {value}\n" for key, value in fields.items()
                ).encode()}
                if index == 1:
                    entries.update({".": b"", "./md5sums": b"", "./shlibs": b"",
                                    "./symbols": b"", "./triggers": ORDER.LIBGCC_TRIGGERS})
                for name, content in entries.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            controls[str(package.archive)] = data.getvalue()
        info = self.root / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (self.root / "var/lib/dpkg/triggers").mkdir()
        (self.root / "var/lib/dpkg/updates").mkdir()
        (self.root / "var/lib/dpkg/status").write_bytes(b"synthetic unit fixture only\n")
        (info / "libgcc-s1:amd64.triggers").write_bytes(ORDER.LIBGCC_TRIGGERS)
        return tuple(packages), records, controls

    def pending_oracle_fixture(self, stderr: bytes, *, returncode: int = 1,
                               configured: bool = True) -> Path:
        cycle, records, _ = self.cycle_fixture()
        image, evidence, tools = (self.root / name for name in ("image", "evidence", "tools"))
        image.mkdir()
        evidence.mkdir()
        tools.mkdir()
        shutil.copytree(self.root / "var", image / "var")
        (image / "usr/bin").mkdir(parents=True)
        (image / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
        postinst = b"#!/bin/sh\nexit 0\n"
        (image / "var/lib/dpkg/info/libc6:amd64.postinst").write_bytes(postinst)
        dpkg, setpriv = tools / "dpkg", tools / "setpriv"
        dpkg.write_bytes(b"unit dpkg")
        setpriv.write_bytes(b"unit signed setpriv")
        library = b"unit signed libcap-ng".ljust(26928, b"\0")
        source = tools / "libcap-ng.so.0.0.0"
        source.write_bytes(library)
        source.chmod(0o644)
        real_sha256 = hashlib.sha256

        def identity(data: bytes):
            approved = {
                library: "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f",
                b"unit signed setpriv":
                    "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993",
            }
            return mock.Mock(hexdigest=lambda: approved[data]) if data in approved else real_sha256(data)

        overrides = {}

        def fields(path: Path) -> dict:
            return {key: {**record, "status": overrides.get((path.name, key), record["status"])}
                    for key, record in records.items()}

        def packages(path: Path) -> dict:
            return {} if path == image else {
                key: (record["status"], record["version"]) for key, record in fields(path).items()
            }

        def breaker(*args) -> None:
            overrides[("candidate", ("libgcc-s1", "amd64"))] = "install ok installed"

        def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
            if command[0] == "cp":
                shutil.copytree(command[-2], command[-1])
            elif command[0] == "rm":
                shutil.rmtree(command[-1])
            elif command[0] == "unshare":
                baseline = Path(command[command.index("chroot") + 1])
                relative = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0"
                self.assertEqual(command[-3:], ["--no-triggers", "--configure", "--pending"])
                if configured:
                    self.assertEqual((baseline / relative).read_bytes(), library)
                    self.assertFalse((image / relative).exists())
                    self.assertFalse((baseline.parent / "candidate" / relative).exists())
                    overrides[("pending", ("libgcc-s1", "amd64"))] = "install ok installed"
                    overrides[("pending", ("libc6", "amd64"))] = "install ok half-configured"
                return subprocess.CompletedProcess(command, returncode, b"pending stdout witness", stderr)
            else:
                self.assertIn(command[0], ("mount", "umount"))
            return subprocess.CompletedProcess(command, 0)

        control = io.BytesIO()
        with tarfile.open(fileobj=control, mode="w") as archive:
            member = tarfile.TarInfo("./postinst")
            member.size = len(postinst)
            archive.addfile(member, io.BytesIO(postinst))
        with (
            mock.patch.object(ORDER.os, "uname", return_value=mock.Mock(machine="x86_64")),
            mock.patch.object(ORDER, "protected", side_effect=lambda path, **kw: path.stat()),
            mock.patch.object(ORDER, "packages_from_manifest", return_value=list(cycle)),
            mock.patch.object(ORDER, "database_fields", side_effect=fields),
            mock.patch.object(ORDER, "database_packages", side_effect=packages),
            mock.patch.object(ORDER, "verify_archive"),
            mock.patch.object(ORDER, "verify_base_cycle"),
            mock.patch.object(ORDER, "apply"),
            mock.patch.object(ORDER, "break_base_cycle", side_effect=breaker),
            mock.patch.object(ORDER, "probe", side_effect=[
                (1, b"dependency problems"), (1, b"dependency problems"), (1, b"stage 11"),
            ]),
            mock.patch.object(ORDER.hashlib, "sha256", side_effect=identity),
            mock.patch.object(ORDER.subprocess, "check_output", return_value=control.getvalue()),
            mock.patch.object(ORDER.subprocess, "run", side_effect=run),
        ):
            ORDER.prove_base_cycle(tools / "launcher", dpkg, image, tools, evidence, setpriv)
        return evidence / "base-cycle-proof"

    def test_pending_oracle_stages_helper_runtime_without_registering_or_widening_candidate(self) -> None:
        proof = self.pending_oracle_fixture(b"post-installation script: Permission denied")
        comparison = json.loads((proof / "comparison.json").read_text())
        self.assertEqual(len(comparison["pending"]), 4)
        self.assertFalse(comparison["parity_claim"])
        self.assertEqual(comparison["callbacks_executed"], [])
        self.assertEqual(comparison["pending_setpriv_runtime"]["size"], 26928)

    def test_pending_loader_refusal_retains_evidence_but_never_counts_as_callback_denial(self) -> None:
        stderr = (b"setpriv: error while loading shared libraries: libcap-ng.so.0: "
                  b"cannot open shared object file: No such file or directory\n")
        with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleProofCallbackChanged"):
            self.pending_oracle_fixture(stderr, returncode=127, configured=False)
        proof = self.root / "evidence/base-cycle-proof"
        self.assertEqual((proof / "pending.stderr").read_bytes(), stderr)
        self.assertEqual((proof / "pending.stdout").read_bytes(), b"pending stdout witness")
        result = json.loads((proof / "pending-result.json").read_text())
        self.assertEqual(result["returncode"], 127)
        self.assertFalse(result["output_truncated"])
        status = json.loads((proof / "pending-status.json").read_text())
        self.assertEqual(status["before"], status["after"])
        self.assertFalse((proof / "comparison.json").exists())

    def test_pending_oversized_output_is_retained_bounded_and_still_refuses(self) -> None:
        stderr = b"post-installation script: Permission denied\n" + b"x" * ORDER.MAXIMUM_PROBE_OUTPUT
        with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleProofCallbackChanged"):
            self.pending_oracle_fixture(stderr)
        proof = self.root / "evidence/base-cycle-proof"
        self.assertEqual((proof / "pending.stderr").read_bytes(), stderr[:ORDER.MAXIMUM_PROBE_OUTPUT])
        result = json.loads((proof / "pending-result.json").read_text())
        self.assertTrue(result["output_truncated"])
        self.assertEqual(result["stderr_bytes"], len(stderr))
        self.assertFalse((proof / "comparison.json").exists())

    def test_pending_runtime_rejects_changed_source_metadata_and_existing_target(self) -> None:
        (self.root / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
        setpriv = self.root / "setpriv"
        library = self.root / "libcap-ng.so.0.0.0"
        target = self.root / "usr/lib/x86_64-linux-gnu/libcap-ng.so.0"
        approved = b"unit signed library".ljust(26928, b"\0")
        real_sha256 = hashlib.sha256

        def identity(data: bytes):
            return (mock.Mock(hexdigest=lambda:
                    "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f")
                    if data == approved else real_sha256(data))

        with (mock.patch.object(ORDER, "protected", side_effect=lambda path, **kw: path.stat()),
              mock.patch.object(ORDER.hashlib, "sha256", side_effect=identity)):
            for mutation in ("missing", "changed", "writable", "setgid", "existing-target"):
                with self.subTest(mutation=mutation):
                    if mutation != "missing":
                        library.write_bytes(b"x" * 26928 if mutation == "changed" else approved)
                        library.chmod({"writable": 0o666, "setgid": 0o2644}.get(mutation, 0o644))
                    if mutation == "existing-target":
                        target.write_bytes(b"unbound existing runtime")
                    with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleProofRuntimeChanged"):
                        ORDER.stage_pending_runtime(self.root, setpriv)
                    if mutation == "existing-target":
                        self.assertEqual(target.read_bytes(), b"unbound existing runtime")
                    else:
                        self.assertFalse(target.exists())

    def test_cycle_operation_requires_exact_four_archives_and_dedicated_profile(self) -> None:
        cycle, _, _ = self.cycle_fixture()
        command = ORDER.dpkg_command(self.root / "launcher", self.root / "dpkg",
                                     self.root, "amd64", ORDER.BASE_CYCLE_PROFILE,
                                     "break_base_cycle", cycle[1], cycle)
        self.assertEqual(command[3:7],
                         ["amd64", "libgcc_cycle", "break_base_cycle", "libgcc-s1:amd64"])
        self.assertEqual(command[7:], [str(p.archive) for p in cycle])
        for architecture, profile, selected, archives in (
            ("arm64", "libgcc_cycle", cycle[1], cycle),
            ("amd64", "none", cycle[1], cycle),
            ("amd64", "libgcc_cycle", cycle[0], cycle),
            ("amd64", "libgcc_cycle", cycle[1], cycle[:2]),
        ):
            with self.subTest(architecture=architecture, profile=profile, selected=selected.name):
                with self.assertRaises(ORDER.CycleRefusal):
                    ORDER.dpkg_command(self.root / "launcher", self.root / "dpkg",
                                       self.root, architecture, profile, "break_base_cycle",
                                       selected, archives)
        with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleIdentityChanged"):
            ORDER.base_cycle_packages([*cycle[:-1]], "amd64")

    def test_signed_cycle_graph_and_callback_mutations_refuse_before_apply(self) -> None:
        cycle, records, controls = self.cycle_fixture()
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, controls[command[2]], b"")
        with (mock.patch.object(ORDER, "verify_archive"),
              mock.patch.object(ORDER, "database_fields", return_value=records),
              mock.patch.object(ORDER.subprocess, "run", side_effect=run),
              mock.patch.object(ORDER, "apply") as applied):
            self.assertEqual(ORDER.verify_base_cycle(self.root, cycle)["callbacks"], [])
            for name, field, changed, reason in (
                ("libc6", "depends", "another-package", "CycleControlChanged"),
                ("libgcc-s1", "pre-depends", "libc6", "CycleControlChanged"),
                ("gcc-16-base", "status", "install ok unpacked", "CycleOutsideDependency"),
                ("gcc-16-base", "multi-arch", "foreign", "CycleControlChanged"),
                ("libc-gconv-modules-extra", "multi-arch", "", "CycleControlChanged"),
                ("libgcc-s1", "status", "install ok triggers-pending", "CycleStateChanged"),
                ("libgcc-s1", "triggers-pending", "ldconfig", "CycleCallbackChanged"),
            ):
                record = records[(name, "amd64")]
                saved = dict(record)
                record[field] = changed
                with self.subTest(name=name, field=field):
                    with self.assertRaisesRegex(ORDER.CycleRefusal, reason):
                        ORDER.break_base_cycle(self.root / "launcher", self.root / "dpkg",
                                               self.root, self.root, "amd64", list(cycle),
                                               {}, self.root / "out", self.root / "err")
                record.clear()
                record.update(saved)
            for name in ("libgcc-s1.postinst", "libgcc-s1:amd64.postinst"):
                path = self.root / "var/lib/dpkg/info" / name
                path.symlink_to("/does-not-exist")
                with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                    ORDER.verify_base_cycle(self.root, cycle)
                path.unlink()
            triggers = self.root / "var/lib/dpkg/info/libgcc-s1:amd64.triggers"
            triggers.write_bytes(b"activate-noawait another-handler\n")
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                ORDER.verify_base_cycle(self.root, cycle)
            triggers.write_bytes(ORDER.LIBGCC_TRIGGERS)
            updates = self.root / "var/lib/dpkg/updates/0000"
            updates.write_text("unincorporated state\n")
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleStateChanged"):
                ORDER.verify_base_cycle(self.root, cycle)
            updates.unlink()
            unincorp = self.root / "var/lib/dpkg/triggers/Unincorp"
            unincorp.write_text("ldconfig libc-bin\n")
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                ORDER.verify_base_cycle(self.root, cycle)
            applied.assert_not_called()

    def test_cycle_transition_requires_exact_progress_not_only_successful_exit(self) -> None:
        cycle, records, _ = self.cycle_fixture()
        before = {"records": records, "callbacks": [], "graph": {}, "trigger_database": {}}
        after = {key: dict(value) for key, value in records.items()}
        after[("libgcc-s1", "amd64")]["status"] = "install ok installed"
        with (mock.patch.object(ORDER, "verify_base_cycle", return_value=before),
              mock.patch.object(ORDER, "database_fields", return_value=after),
              mock.patch.object(ORDER, "apply") as applied):
            selected = ORDER.break_base_cycle(self.root / "launcher", self.root / "dpkg",
                                              self.root, self.root, "amd64", list(cycle),
                                              {}, self.root / "out", self.root / "err")
            self.assertEqual(selected, cycle[1])
            self.assertEqual(applied.call_args.args[0][5], "break_base_cycle")
            evidence = json.loads((self.root / "base-cycle-after.json").read_text())
            self.assertEqual(evidence["callbacks"], [])
            after[("libc6", "amd64")]["status"] = "install ok installed"
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                ORDER.break_base_cycle(self.root / "launcher", self.root / "dpkg",
                                       self.root, self.root, "amd64", list(cycle),
                                       {}, self.root / "out", self.root / "err")

    def test_second_stall_never_reuses_cycle_authority(self) -> None:
        cycle, _, _ = self.cycle_fixture()
        def probe(command, *_):
            return (0, b"") if command[5] == "probe_unpack" else (1, b"dependency problems")
        with (mock.patch.object(ORDER, "packages_from_manifest", return_value=list(cycle)),
              mock.patch.object(ORDER, "probe", side_effect=probe),
              mock.patch.object(ORDER, "verify_archive"),
              mock.patch.object(ORDER, "apply"),
              mock.patch.object(ORDER, "break_base_cycle", return_value=cycle[1]) as breaker):
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                ORDER.install(self.root / "launcher", self.root / "dpkg", self.root,
                              self.root / "cache", self.root, "amd64")
        breaker.assert_called_once()

    def test_cycle_break_retries_normal_schedule_without_configuring_prestate_target(self) -> None:
        cycle, _, _ = self.cycle_fixture()
        target = ORDER.Package("systemd", ORDER.PROFILE_VERSIONS["systemd"], "amd64",
                               "a" * 128, 42, self.root / "systemd.deb")
        broken = False
        def dependency_probe(command, *_):
            if not broken and (
                command[5] == "probe_configure" and command[6] in ("libc6:amd64", "libgcc-s1:amd64")
                or command[5] == "probe_unpack" and command[6] == "systemd:amd64"
            ):
                return 1, (b"pre-dependency problem" if command[5] == "probe_unpack"
                           and command[6] == "systemd:amd64" else b"dependency problems")
            return 0, b""
        def breaker(*_):
            nonlocal broken
            broken = True
            return cycle[1]
        def state(_):
            return {(p.name, p.architecture): ("install ok unpacked", p.version)
                    for p in (*cycle, target)}
        with (mock.patch.object(ORDER, "packages_from_manifest", return_value=[*cycle, target]),
              mock.patch.object(ORDER, "probe", side_effect=dependency_probe),
              mock.patch.object(ORDER, "verify_archive"),
              mock.patch.object(ORDER, "database_packages", side_effect=state),
              mock.patch.object(ORDER, "break_base_cycle", side_effect=breaker) as break_cycle,
              mock.patch.object(ORDER, "apply") as applied,
              mock.patch.object(ORDER, "capture_prestate") as captured):
            ORDER.install(self.root / "launcher", self.root / "dpkg", self.root,
                          self.root / "cache", self.root, "amd64",
                          (ORDER.Prestate(target.selector, "half-configured", self.root / "saved"),))
        break_cycle.assert_called_once()
        captured.assert_called_once()
        configurations = [call.args[0][6] for call in applied.call_args_list
                          if call.args[0][5] == "configure"]
        self.assertIn("libc6:amd64", configurations)
        self.assertNotIn("libgcc-s1:amd64", configurations)
        self.assertNotIn("systemd:amd64", configurations)


if __name__ == "__main__":
    unittest.main()
