#!/usr/bin/env python3
"""Offline fail-closed checks for the bounded pinned-dpkg reference."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tarfile
import unittest
import zipfile
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
REPIN_SPEC = importlib.util.spec_from_file_location(
    "debz_reference_repin", TOOLS / "real-snapshot-repin.py"
)
assert REPIN_SPEC and REPIN_SPEC.loader
REPIN = importlib.util.module_from_spec(REPIN_SPEC)
sys.modules[REPIN_SPEC.name] = REPIN
REPIN_SPEC.loader.exec_module(REPIN)


class ReferenceLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="debz-reference-negative-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.launcher = ORDER.Launcher(self.root / "launcher", self.root / "runtime")

    def retained_list(self, name: str, architecture: str) -> tuple[bytes, bytes]:
        manifest = json.loads((TOOLS / "fixtures/real-snapshot/pin-v1.json").read_text())
        identity = next(i for i in manifest["identities"] if i["kind"] == "prestate"
                        and i["path"] == f"var/lib/dpkg/info/{name}.list")
        with zipfile.ZipFile(TOOLS / "fixtures/real-snapshot/prestate-sources-v2.zip") as archive:
            sources = json.loads(archive.read("evidence.json"))["sources"]
            source = next(s for s in sources if (s["package"], s["architecture"]) ==
                          (name, architecture))
            deb = archive.read(source["archive_file"])
        self.assertEqual("sha512:" + hashlib.sha512(deb).hexdigest(),
                         identity["provenance"]["archives"][architecture])
        content, mode = REPIN.derive_prestate(identity, architecture, deb)
        self.assertEqual((len(content), "sha256:" + hashlib.sha256(content).hexdigest(), mode),
                         (identity["size"], identity["digest"], int(identity["mode"], 8)))
        return content, deb

    def test_less_seal_preserves_retained_archive_list_order_and_identity(self) -> None:
        content, deb = self.retained_list("less", "arm64")
        stage_source = (TOOLS / "real-snapshot-stage.zig").read_text()
        self.assertIn(f"content.len != {len(content)}", stage_source)
        self.assertIn(hashlib.sha256(content).hexdigest(), stage_source)
        for kind in ("preinst", "postinst"):
            script, _ = REPIN.tar_member(deb, "control.tar", kind)
            self.assertIn(hashlib.sha256(script).hexdigest(), stage_source)

    def test_signed_sudo_guard_preserves_retained_archive_list_bytes_and_inode(self) -> None:
        content, _ = self.retained_list("sudo", "amd64")
        listing = self.root / "sudo/var/lib/dpkg/info/sudo.list"
        listing.parent.mkdir(parents=True)
        source = (TOOLS / "real-snapshot-signed-proc-prestates.sh").read_text()
        helper = "require_control() {" + source.split("require_control() {", 1)[1].split(
            "\nrequire_prestate()", 1)[0]
        start = source.index("list=$prestates/sudo/var/lib/dpkg/info/sudo.list\n")
        end = source.index("\n", source.index(
            "'var/lib/dpkg/info/sudo.list:2376:644:", start))
        guard = (helper + "\n" + source[start:end]).replace("0:0:", f"{os.getuid()}:{os.getgid()}:")
        for changed in (content, b"".join(sorted(content.splitlines(keepends=True))),
                        content.replace(b"/usr/bin/", b"/../bin/")):
            with self.subTest(original=changed == content):
                listing.write_bytes(changed)
                listing.chmod(0o644)
                before = listing.stat()
                result = subprocess.run(
                    ["bash", "-c",
                     'set -euo pipefail\nprestates=$1\n'
                     'require_protected_file() { [[ -f $1 && ! -L $1 ]]; }\n' + guard,
                     "sudo-list-guard-test", str(self.root)],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, changed == content, result.stderr)
                self.assertEqual(listing.read_bytes(), changed)
                after = listing.stat()
                self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                                 (before.st_ino, before.st_mtime_ns, before.st_ctime_ns))

    def test_prestate_setpriv_guard_requires_exact_unchanged_regular_package_data(self) -> None:
        source = (TOOLS / "real-snapshot-signed-proc-prestates.sh").read_text()
        helper = "require_control() {" + source.split("require_control() {", 1)[1].split(
            "\nrequire_prestate()", 1)[0]
        guard = source.split('  require_control "$target" "$signed_dpkg"\n', 1)[1].split(
            "\n}", 1)[0]
        # Unit metadata uses our uid/gid and a synthetic known digest, never an executable.
        helper = helper.replace("0:0:", f"{os.getuid()}:{os.getgid()}:")
        content = b"unit closure setpriv metadata only\n".ljust(47576, b"\0")
        digest = hashlib.sha256(content).hexdigest()
        for changed in ("unchanged", "missing", "bytes", "mode", "symlink", "hardlink"):
            with self.subTest(changed=changed):
                target = self.root / changed
                binary = target / "usr/bin/setpriv"
                binary.parent.mkdir(parents=True)
                if changed != "missing":
                    binary.write_bytes(content if changed != "bytes" else b"wrong" + content[5:])
                    binary.chmod(0o644 if changed == "mode" else 0o755)
                    if changed == "symlink":
                        original = binary.with_name("original")
                        binary.rename(original)
                        binary.symlink_to(original)
                    elif changed == "hardlink":
                        os.link(binary, binary.with_name("alias"))
                before = binary.lstat() if changed != "missing" else None
                result = subprocess.run(
                    ["bash", "-c",
                     'set -euo pipefail\ntarget=$1\nsetpriv_sha256=$2\n'
                     'require_protected_file() { [[ -f $1 && ! -L $1 ]]; }\n'
                     + helper + "\n" + guard, "setpriv-data-guard-test", str(target), digest],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, changed == "unchanged", result.stderr)
                if before is not None:
                    after = binary.lstat()
                    self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                                     (before.st_ino, before.st_mtime_ns, before.st_ctime_ns))
                    self.assertEqual(binary.read_bytes(),
                                     content if changed != "bytes" else b"wrong" + content[5:])
                else:
                    self.assertFalse(binary.exists())

    def test_python_prepare_empty_preserves_both_retained_lists_on_both_architectures(self) -> None:
        stage_source = (TOOLS / "real-snapshot-stage.zig").read_text()
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                for name in ("python3", "python3-minimal"):
                    content, _ = self.retained_list(name, architecture)
                    self.assertIn(f".size = {len(content)}", stage_source)
                    self.assertIn(hashlib.sha256(content).hexdigest(), stage_source)

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
        self.assertEqual(arguments[1], "build-exe")
        self.assertEqual(arguments[arguments.index("--dep") + 1], "private_network")
        self.assertIn("-Mroot=tools/real-snapshot-reference-launcher.zig", arguments)
        self.assertIn("-Mprivate_network=src/private_network.zig", arguments)
        self.assertEqual(arguments[arguments.index("--zig-lib-dir") + 1], str(compiler_directory / "lib"))
        self.assertIn(f"-femit-bin={self.root}/launcher", arguments)

    def test_protected_proof_target_refuses_shared_checkout_without_fixture_skips(self) -> None:
        protected = os.environ.get(
            "DEBZ_REFERENCE_PROTECTED",
            str(ROOT / "zig-out/bin/debz-reference-protected"),
        )
        result = subprocess.run(
            [protected,
             "--launcher", str(self.root / "launcher"),
             "--runtime", str(self.root / "runtime"),
             "--runtime-tool", str(self.root / "runtime-tool"),
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
        self.assertRegex(result.stderr, "PermissionError|writable or non-root ancestor|UnprotectedAncestor")
        self.assertNotIn("SKIP", result.stderr)

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
            self.launcher, self.root / "dpkg", self.root / "root",
            "amd64", "none", "unpack", package,
        )
        self.assertEqual(command[3:7], ["amd64", "none", "unpack", "demo:amd64"])
        self.assertEqual(command[7], str(self.launcher.runtime))
        self.assertEqual(command[8:], [str(package.archive), package.digest, "42"])
        self.assertNotIn("--pending", command)

    def test_trigger_verbs_refuse_without_a_triggered_script_profile(self) -> None:
        package = ORDER.Package(
            "sudo", "1.9.17p2-1ubuntu3.1", "amd64",
            "a" * 128, 42, self.root / "sudo.deb",
        )

        def command(profile: str, verb: str, selected: ORDER.Package = package) -> list[str]:
            return ORDER.dpkg_command(
                self.launcher, self.root / "dpkg", self.root / "root",
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
                self.launcher, self.root / "dpkg", self.root / "root",
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
                self.launcher, self.root / "dpkg", self.root / "root",
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
                ORDER.install(self.launcher, self.root / "dpkg",
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

    def cycle_fixture(self, openssl: bool = False, kbd: bool = False) -> tuple[tuple, dict, dict]:
        filename = ("kbd-cycle-controls-v1.json" if kbd else
                    "openssl-cycle-controls-v1.json" if openssl else "base-cycle-controls-v1.json")
        fixture = json.loads((TOOLS / "fixtures/real-snapshot" / filename).read_text())
        packages = []
        records, controls = {}, {}
        for index, entry in enumerate(fixture["packages"]):
            fields, = ORDER.control_fields(entry["control"].encode())
            package = ORDER.Package(fields["package"], fields["version"], fields["architecture"],
                                    entry["archive_sha512"], entry["archive_size"],
                                    self.root / f'{fields["package"]}.deb')
            packages.append(package)
            records[(package.name, package.architecture)] = {
                **fields, "status": entry["status"],
            }
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as archive:
                entries = {"./control": "".join(
                    f"{key}: {value}\n" for key, value in fields.items()
                ).encode()}
                if kbd:
                    entries.update({name: b"" for name in entry["control_members"] if name != "./control"})
                    if index == 0:
                        entries["./triggers"] = ORDER.KBD_TRIGGERS
                elif (openssl and index == 0) or (not openssl and index == 1):
                    entries.update({".": b"", "./md5sums": b"", "./shlibs": b"",
                                    "./symbols": b"", "./triggers": ORDER.LIBGCC_TRIGGERS})
                elif openssl and index == 1:
                    entries.update({".": b"", "./md5sums": b""})
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
        trigger = "kbd" if kbd else "libssl3t64" if openssl else "libgcc-s1"
        activation = f"{trigger}.triggers" if kbd else f"{trigger}:amd64.triggers"
        (info / activation).write_bytes(ORDER.KBD_TRIGGERS if kbd else ORDER.LIBGCC_TRIGGERS)
        return tuple(packages), records, controls

    def test_kbd_operation_requires_exact_original_archives_and_only_its_scriptless_selector(self) -> None:
        cycle, _, _ = self.cycle_fixture(kbd=True)
        command = ORDER.dpkg_command(self.launcher, self.root / "dpkg", self.root,
                                     "amd64", "kbd_cycle", "break_kbd_cycle", cycle[0], cycle)
        self.assertEqual(command[3:7], ["amd64", "kbd_cycle", "break_kbd_cycle", "kbd:amd64"])
        for architecture, profile, selected, archives in (
            ("arm64", "kbd_cycle", cycle[0], cycle),
            ("amd64", "none", cycle[0], cycle),
            ("amd64", "kbd_cycle", cycle[1], cycle),
            ("amd64", "kbd_cycle", cycle[0], cycle[:3]),
            ("amd64", "kbd_cycle", cycle[0], (cycle[0], cycle[2], cycle[1], cycle[3])),
        ):
            with self.subTest(architecture=architecture, profile=profile, selected=selected.name):
                with self.assertRaises(ORDER.CycleRefusal):
                    ORDER.dpkg_command(self.launcher, self.root / "dpkg", self.root,
                                       architecture, profile, "break_kbd_cycle", selected, archives)
        changed = ORDER.Package(cycle[0].name, cycle[0].version, cycle[0].architecture,
                                "0" * 128, cycle[0].size, cycle[0].archive)
        with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleIdentityChanged"):
            ORDER.kbd_cycle_packages([changed, *cycle[1:]], "amd64")

    def test_kbd_cycle_refuses_changed_peers_outside_libc_callback_and_pending_activation(self) -> None:
        cycle, records, controls = self.cycle_fixture(kbd=True)
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, controls[command[2]], b"")
        with (mock.patch.object(ORDER, "verify_archive"),
              mock.patch.object(ORDER, "database_fields", return_value=records),
              mock.patch.object(ORDER.subprocess, "run", side_effect=run),
              mock.patch.object(ORDER, "apply") as applied):
            self.assertEqual(ORDER.verify_kbd_cycle(self.root, cycle)["callbacks"], [])
            for name, arch, field, changed in (
                ("kbd", "amd64", "depends", "unknown"),
                ("kbd", "amd64", "triggers-pending", "update-initramfs"),
                ("console-setup-linux", "all", "multi-arch", "same"),
                ("console-setup", "all", "pre-depends", ""),
                ("console-setup", "all", "status", "install ok installed"),
                ("libc6", "amd64", "status", "install ok unpacked"),
            ):
                record = records[(name, arch)]
                saved = dict(record)
                record[field] = changed
                with self.subTest(name=name, field=field):
                    with self.assertRaises(ORDER.CycleRefusal):
                        ORDER.break_kbd_cycle(self.launcher, self.root / "dpkg", self.root, self.root,
                                              "amd64", list(cycle), {}, self.root / "out", self.root / "err")
                record.clear()
                record.update(saved)
            for name in ("kbd.postinst", "kbd:amd64.config", "kbd:amd64.triggers"):
                path = self.root / "var/lib/dpkg/info" / name
                path.symlink_to("/missing-unreviewed-callback")
                with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                    ORDER.verify_kbd_cycle(self.root, cycle)
                path.unlink()
            activation = self.root / "var/lib/dpkg/info/kbd.triggers"
            activation.write_bytes(b"activate update-initramfs\n")
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                ORDER.verify_kbd_cycle(self.root, cycle)
            activation.write_bytes(ORDER.KBD_TRIGGERS)
            (self.root / "var/lib/dpkg/triggers/Unincorp").write_bytes(b"update-initramfs kbd\n")
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                ORDER.verify_kbd_cycle(self.root, cycle)
            applied.assert_not_called()

    def test_kbd_success_requires_only_its_one_real_transition_and_unchanged_trigger_database(self) -> None:
        cycle, records, _ = self.cycle_fixture(kbd=True)
        before = {"records": records, "callbacks": [], "graph": {}, "trigger_database": {}}
        after = {key: dict(value) for key, value in records.items()}
        after[("kbd", "amd64")]["status"] = "install ok installed"
        refusal = (1, b"dependency problems: Package console-setup is not configured yet.")
        with (mock.patch.object(ORDER, "verify_kbd_cycle", return_value=before),
              mock.patch.object(ORDER, "probe", return_value=refusal),
              mock.patch.object(ORDER, "database_fields", return_value=after),
              mock.patch.object(ORDER, "apply") as applied):
            selected = ORDER.break_kbd_cycle(self.launcher, self.root / "dpkg", self.root, self.root,
                                             "amd64", list(cycle), {}, self.root / "out", self.root / "err")
            self.assertEqual(selected, cycle[0])
            self.assertEqual(applied.call_args.args[0][5:7], ["break_kbd_cycle", "kbd:amd64"])
            after[("console-setup-linux", "all")]["status"] = "install ok installed"
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                ORDER.break_kbd_cycle(self.launcher, self.root / "dpkg", self.root, self.root,
                                      "amd64", list(cycle), {}, self.root / "out", self.root / "err")
            after[("console-setup-linux", "all")]["status"] = "install ok unpacked"
            with mock.patch.object(ORDER, "trigger_database", return_value={"unexpected": {}}):
                with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                    ORDER.break_kbd_cycle(self.launcher, self.root / "dpkg", self.root, self.root,
                                          "amd64", list(cycle), {}, self.root / "out", self.root / "err")

    def test_kbd_production_activation_retains_exact_selector_before_exec_and_state_conservation(self) -> None:
        spec = importlib.util.spec_from_file_location("kbd_production_audit", TOOLS / "security-audit.py")
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        texts = {path: (ROOT / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        for path, token in (
            ("tools/real-snapshot-reference-launcher.zig", 'if ((options.verb == .break_kbd_cycle) != (options.kbd_archives != null))'),
            ("tools/real-snapshot-reference-launcher.zig", 'for (paths, kbd_cycle) |path, binding| {'),
            ("tools/real-snapshot-reference-launcher.zig", 'if (child.options.verb == .break_kbd_cycle)\n        verifyCycle(.kbd)'),
            ("tools/real-snapshot-reference-launcher.zig", 'if ((options.verb == .triggers_only) != (options.trigger_archive != null))'),
            ("tools/real-snapshot-reference-launcher.zig", 'if (child.options.verb == .triggers_only)\n        verifyTriggerHandler(child.options.selector.?)'),
            ("tools/real-snapshot-reference-order.py", 'before = verify_kbd_cycle(root, cycle)'),
            ("tools/real-snapshot-reference-order.py", 'expected[("kbd", "amd64")]["status"] = "install ok installed"'),
            ("tools/real-snapshot-reference-order.py", 'before = verify_trigger_handlers(root, handlers)'),
            ("tools/real-snapshot-reference-order.py", 'expected[(package.name, "amd64")].pop("triggers-pending", None)'),
            ("tools/real-snapshot-reference-order.py", '"reference trigger closure refused: no exact triggered postinst identity/profile "'),
        ):
            with self.subTest(path=path, token=token):
                changed = dict(texts)
                changed[path] = texts[path].replace(token, "", 1)
                self.assertTrue(audit.protected_reference_ci_failures(changed))

    def trigger_handler_fixture(self) -> tuple[tuple[ORDER.Package, ...], dict[tuple[str, str], dict[str, str]], dict[str, dict[str, bytes]]]:
        packages: list[ORDER.Package] = []
        records: dict[tuple[str, str], dict[str, str]] = {
            ("base-files", "amd64"): {
                "package": "base-files", "version": "14ubuntu1",
                "architecture": "amd64", "status": "install ok installed",
            },
        }
        controls: dict[str, dict[str, bytes]] = {}
        (self.root / "var/lib/dpkg/info").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/dpkg/updates").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/dpkg/triggers").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/dpkg/triggers/Unincorp").write_bytes(b"")
        (self.root / "var/lib/dpkg/triggers/ldconfig").write_bytes(b"libc-bin\n")
        (self.root / "var/lib/dpkg/triggers/File").write_bytes(b"/usr/lib/sysctl.d procps/noawait\n")
        for (name, version, arch, size, digest, _, pending,
             postinst_size, _, triggers_size, _) in ORDER.TRIGGER_HANDLERS:
            archive = self.root / f"{name}.deb"
            archive.write_bytes(b"deb")
            packages.append(ORDER.Package(name, version, arch, digest, size, archive))
            records[(name, arch)] = {
                "package": name, "version": version, "architecture": arch,
                "status": "install ok triggers-pending",
                "config-version": version, "triggers-pending": pending,
            }
            postinst = (f"#!/bin/sh\n# {name}\n".encode() + b"x" * postinst_size)[:postinst_size]
            triggers = (f"# {name}\n".encode() + b"y" * triggers_size)[:triggers_size]
            controls[name] = {
                "./control": (
                    f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n"
                    f"Maintainer: Test <test@example.invalid>\nDescription: {name}\n"
                ).encode(),
                "./postinst": postinst,
                "./triggers": triggers,
            }
            postinst_path = self.root / f"var/lib/dpkg/info/{name}.postinst"
            postinst_path.write_bytes(postinst)
            postinst_path.chmod(0o755)
            triggers_path = self.root / f"var/lib/dpkg/info/{name}.triggers"
            triggers_path.write_bytes(triggers)
            triggers_path.chmod(0o644)
        return tuple(packages), records, controls

    def test_trigger_handlers_process_one_signed_handler_at_a_time_and_refuse_drift(self) -> None:
        handlers, records, controls = self.trigger_handler_fixture()
        for handler, binding in zip(handlers, ORDER.TRIGGER_HANDLERS):
            self.assertEqual(
                ORDER.dpkg_command(
                    self.launcher, self.root / "dpkg", self.root, "amd64",
                    "none", "triggers_only", handler,
                )[3:],
                ["amd64", "none", "triggers_only", handler.selector,
                 str(self.launcher.runtime), str(handler.archive)],
            )
            with self.assertRaisesRegex(ValueError, "unauthorized reference script profile"):
                ORDER.dpkg_command(
                    self.launcher, self.root / "dpkg", self.root, "amd64",
                    "sudo", "triggers_only", handler,
                )
            with self.assertRaisesRegex(ValueError, "single-script binding"):
                ORDER.dpkg_command(
                    self.launcher, self.root / "dpkg", self.root, "arm64",
                    "none", "triggers_only", handler,
                )
            with self.assertRaisesRegex(ValueError, "single-script binding"):
                ORDER.dpkg_command(
                    self.launcher, self.root / "dpkg", self.root, "amd64",
                    "none", "triggers_only",
                    ORDER.Package(handler.name, "0", "amd64", handler.digest, handler.size, handler.archive),
                )
        real_sha256 = hashlib.sha256
        approved_sha256 = {
            controls["libc-bin"]["./postinst"]: ORDER.TRIGGER_HANDLERS[0][8],
            controls["libc-bin"]["./triggers"]: ORDER.TRIGGER_HANDLERS[0][10],
            controls["procps"]["./postinst"]: ORDER.TRIGGER_HANDLERS[1][8],
            controls["procps"]["./triggers"]: ORDER.TRIGGER_HANDLERS[1][10],
        }

        def fake_sha256(data: bytes = b""):
            if data in approved_sha256:
                return mock.Mock(hexdigest=lambda: approved_sha256[data])
            return real_sha256(data)

        evidence = self.root / "trigger-evidence"
        evidence.mkdir()
        (self.root / "var/lib/dpkg/status").write_bytes(b"status\n")
        state = {key: dict(value) for key, value in records.items()}
        commands: list[list[str]] = []

        def apply_trigger(command: list[str], *_args) -> None:
            commands.append(command)
            selector = command[6]
            name, arch = selector.split(":")
            self.assertEqual(state[(name, arch)]["status"], "install ok triggers-pending")
            if name == "procps":
                self.assertEqual(state[("libc-bin", "amd64")]["status"], "install ok installed")
            state[(name, arch)]["status"] = "install ok installed"
            state[(name, arch)].pop("triggers-pending", None)
            state[(name, arch)].pop("config-version", None)

        with (
            mock.patch.object(ORDER, "protected", side_effect=lambda path, directory=False: path.stat()),
            mock.patch.object(ORDER, "open_absolute", side_effect=lambda path, directory=False: os.open(path, os.O_RDONLY)),
            mock.patch.object(ORDER, "read_root_file", side_effect=lambda root, rel, _max: (root / rel).read_bytes()),
            mock.patch.object(ORDER, "verify_archive"),
            mock.patch.object(ORDER, "control_members", side_effect=lambda pkg: controls[pkg.name]),
            mock.patch.object(ORDER, "database_fields", side_effect=lambda _root: {k: dict(v) for k, v in state.items()}),
            mock.patch.object(ORDER.hashlib, "sha256", side_effect=fake_sha256),
            mock.patch.object(ORDER, "apply", side_effect=apply_trigger),
        ):
            ORDER.process_triggers(
                self.launcher, self.root / "dpkg", self.root, evidence, "amd64",
                list(handlers), {}, self.root / "out", self.root / "err",
            )
            self.assertEqual(
                [cmd[5:7] for cmd in commands],
                [["triggers_only", "libc-bin:amd64"], ["triggers_only", "procps:amd64"]],
            )
            after_doc = json.loads((evidence / "triggers-after.json").read_text())
            self.assertEqual(len(after_doc["steps"]), 2)

            # Negative: wrong architecture
            with self.assertRaisesRegex(ORDER.TriggerRefusal, "no exact triggered postinst identity"):
                ORDER.trigger_handler_packages(list(handlers), "arm64")

            # Negative: unexpected third triggers-pending package
            bad_state = {k: dict(v) for k, v in records.items()}
            bad_state[("extra", "amd64")] = {
                "package": "extra", "version": "1", "architecture": "amd64",
                "status": "install ok triggers-pending", "config-version": "1",
                "triggers-pending": "other",
            }
            with mock.patch.object(ORDER, "database_fields", return_value=bad_state):
                with self.assertRaisesRegex(ORDER.TriggerRefusal, "extra"):
                    ORDER.verify_trigger_handlers(self.root, handlers)

            # Negative: modified installed postinst mode
            state = {k: dict(v) for k, v in records.items()}
            (self.root / "var/lib/dpkg/info/libc-bin.postinst").chmod(0o644)
            with self.assertRaisesRegex(ORDER.TriggerRefusal, "libc-bin installed"):
                ORDER.verify_trigger_handlers(self.root, handlers)
            (self.root / "var/lib/dpkg/info/libc-bin.postinst").chmod(0o755)

            # Negative: post-step state conservation failure if another package changes
            def corrupt_apply(command: list[str], *_args) -> None:
                apply_trigger(command)
                state[("base-files", "amd64")]["status"] = "install ok unpacked"

            with mock.patch.object(ORDER, "apply", side_effect=corrupt_apply):
                with self.assertRaisesRegex(ORDER.TriggerRefusal, "database changed beyond the one reviewed"):
                    ORDER.process_triggers(
                        self.launcher, self.root / "dpkg", self.root, evidence, "amd64",
                        list(handlers), {}, self.root / "out", self.root / "err",
                    )

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
            ORDER.prove_base_cycle(ORDER.Launcher(tools / "launcher", tools / "runtime"),
                                   dpkg, image, tools, evidence, setpriv)
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
        command = ORDER.dpkg_command(self.launcher, self.root / "dpkg",
                                     self.root, "amd64", ORDER.BASE_CYCLE_PROFILE,
                                     "break_base_cycle", cycle[1], cycle)
        self.assertEqual(command[3:7],
                         ["amd64", "libgcc_cycle", "break_base_cycle", "libgcc-s1:amd64"])
        self.assertEqual(command[8:], [str(p.archive) for p in cycle])
        for architecture, profile, selected, archives in (
            ("arm64", "libgcc_cycle", cycle[1], cycle),
            ("amd64", "none", cycle[1], cycle),
            ("amd64", "libgcc_cycle", cycle[0], cycle),
            ("amd64", "libgcc_cycle", cycle[1], cycle[:2]),
        ):
            with self.subTest(architecture=architecture, profile=profile, selected=selected.name):
                with self.assertRaises(ORDER.CycleRefusal):
                    ORDER.dpkg_command(self.launcher, self.root / "dpkg",
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
                        ORDER.break_base_cycle(self.launcher, self.root / "dpkg",
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
            selected = ORDER.break_base_cycle(self.launcher, self.root / "dpkg",
                                              self.root, self.root, "amd64", list(cycle),
                                              {}, self.root / "out", self.root / "err")
            self.assertEqual(selected, cycle[1])
            self.assertEqual(applied.call_args.args[0][5], "break_base_cycle")
            evidence = json.loads((self.root / "base-cycle-after.json").read_text())
            self.assertEqual(evidence["callbacks"], [])
            after[("libc6", "amd64")]["status"] = "install ok installed"
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                ORDER.break_base_cycle(self.launcher, self.root / "dpkg",
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
                ORDER.install(self.launcher, self.root / "dpkg", self.root,
                              self.root / "cache", self.root, "amd64")
        breaker.assert_called_once()

    def test_openssl_operation_refuses_different_selectors_archives_and_profiles(self) -> None:
        cycle, _, _ = self.cycle_fixture(openssl=True)
        command = ORDER.dpkg_command(
            self.launcher, self.root / "dpkg", self.root, "amd64",
            "openssl_cycle", "configure_openssl_cycle", cycle[0], cycle,
        )
        self.assertEqual(command[3:7],
                         ["amd64", "openssl_cycle", "configure_openssl_cycle", "libssl3t64:amd64"])
        for architecture, profile, selected, archives in (
            ("arm64", "openssl_cycle", cycle[0], cycle),
            ("amd64", "none", cycle[0], cycle),
            ("amd64", "sudo", cycle[0], cycle),
            ("amd64", "openssl_cycle", cycle[1], cycle),
            ("amd64", "openssl_cycle", cycle[0], cycle[:2]),
            ("amd64", "openssl_cycle", cycle[0], (*cycle[1:], cycle[0])),
        ):
            with self.subTest(architecture=architecture, profile=profile, selected=selected.name):
                with self.assertRaises(ORDER.CycleRefusal):
                    ORDER.dpkg_command(
                        self.launcher, self.root / "dpkg", self.root, architecture,
                        profile, "configure_openssl_cycle", selected, archives,
                    )
        changed = ORDER.Package(cycle[0].name, cycle[0].version, "amd64",
                                "0" * 128, cycle[0].size, cycle[0].archive)
        with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleIdentityChanged"):
            ORDER.openssl_cycle_packages([changed, *cycle[1:]], "amd64")

    def test_openssl_cycle_refuses_graph_callbacks_triggers_and_outside_state_before_apply(self) -> None:
        cycle, records, controls = self.cycle_fixture(openssl=True)
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, controls[command[2]], b"")
        with (mock.patch.object(ORDER, "verify_archive"),
              mock.patch.object(ORDER, "database_fields", return_value=records),
              mock.patch.object(ORDER.subprocess, "run", side_effect=run),
              mock.patch.object(ORDER, "apply") as applied):
            verified = ORDER.verify_openssl_cycle(self.root, cycle)
            self.assertEqual(verified["callbacks"], [])
            self.assertEqual(verified["graph"]["libssl3t64"]["multi_arch"], "same")
            self.assertEqual(verified["graph"]["openssl-provider-legacy"]["multi_arch"], "foreign")
            for name, field, changed, reason in (
                ("libssl3t64", "depends", "unknown-package", "CycleControlChanged"),
                ("openssl-provider-legacy", "pre-depends", "libssl3t64", "CycleControlChanged"),
                ("libc6", "status", "install ok unpacked", "CycleOutsideDependency"),
                ("libzstd1", "version", "other", "CycleStateChanged"),
                ("zlib1g", "conflicts", "", "CycleControlChanged"),
                ("openssl-provider-legacy", "multi-arch", "same", "CycleControlChanged"),
                ("libssl3t64", "triggers-pending", "ldconfig", "CycleCallbackChanged"),
                ("openssl-provider-legacy", "config-version", "other", "CycleCallbackChanged"),
            ):
                record = records[(name, "amd64")]
                saved = dict(record)
                record[field] = changed
                with self.subTest(name=name, field=field):
                    with self.assertRaisesRegex(ORDER.CycleRefusal, reason):
                        ORDER.configure_openssl_cycle(
                            self.launcher, self.root / "dpkg", self.root, self.root,
                            "amd64", list(cycle), {}, self.root / "out", self.root / "err",
                        )
                record.clear()
                record.update(saved)
            for name in ("libssl3t64.postinst", "libssl3t64:amd64.postinst",
                         "openssl-provider-legacy.postinst", "openssl-provider-legacy:amd64.config",
                         "openssl-provider-legacy:amd64.triggers"):
                path = self.root / "var/lib/dpkg/info" / name
                path.symlink_to("/does-not-exist")
                with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                    ORDER.verify_openssl_cycle(self.root, cycle)
                path.unlink()
            activation = self.root / "var/lib/dpkg/info/libssl3t64:amd64.triggers"
            activation.write_bytes(b"activate ldconfig\n")
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                ORDER.verify_openssl_cycle(self.root, cycle)
            activation.write_bytes(ORDER.LIBGCC_TRIGGERS)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as output:
                script = tarfile.TarInfo("./postinst")
                script.size = 7
                output.addfile(script, io.BytesIO(b"callback"))
                with tarfile.open(fileobj=io.BytesIO(controls[str(cycle[1].archive)])) as original:
                    for member in original:
                        output.addfile(member, original.extractfile(member))
            controls[str(cycle[1].archive)] = archive.getvalue()
            with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleCallbackChanged"):
                ORDER.verify_openssl_cycle(self.root, cycle)
            applied.assert_not_called()

    def test_openssl_transition_requires_both_refusals_and_exact_two_package_progress(self) -> None:
        cycle, records, _ = self.cycle_fixture(openssl=True)
        before = {"records": records, "callbacks": [],
                  "graph": {p.name: {"multi_arch": records[(p.name, "amd64")].get("multi-arch", "")}
                            for p in cycle}, "trigger_database": {},
                  "force": []}
        after = {key: dict(value) for key, value in records.items()}
        for package in cycle[:2]:
            after[(package.name, "amd64")]["status"] = "install ok installed"
        def probe(command, *_):
            peer = cycle[1] if command[6] == cycle[0].selector else cycle[0]
            peer_name = peer.name if peer == cycle[1] else peer.selector
            return 1, f"dependency problems: Package {peer_name} is not configured yet.".encode()
        with (mock.patch.object(ORDER, "verify_openssl_cycle", return_value=before),
              mock.patch.object(ORDER, "probe", side_effect=probe),
              mock.patch.object(ORDER, "database_fields", return_value=after),
              mock.patch.object(ORDER, "trigger_database", return_value={}),
              mock.patch.object(ORDER, "apply") as applied):
            self.assertEqual(ORDER.configure_openssl_cycle(
                self.launcher, self.root / "dpkg", self.root, self.root, "amd64",
                list(cycle), {}, self.root / "out", self.root / "err",
            ), cycle[:2])
            evidence = json.loads((self.root / "openssl-cycle-after.json").read_text())
            self.assertEqual(evidence["callbacks"], [])
            self.assertEqual(evidence["force"], [])
            for name in ("libssl3t64", "openssl-provider-legacy", "libc6"):
                saved = dict(after[(name, "amd64")])
                after[(name, "amd64")]["status"] = "install ok half-configured"
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                        ORDER.configure_openssl_cycle(
                            self.launcher, self.root / "dpkg", self.root, self.root,
                            "amd64", list(cycle), {}, self.root / "out", self.root / "err",
                        )
                after[(name, "amd64")] = saved
            with mock.patch.object(ORDER, "trigger_database", return_value={"ldconfig": {}}):
                with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                    ORDER.configure_openssl_cycle(
                        self.launcher, self.root / "dpkg", self.root, self.root, "amd64",
                        list(cycle), {}, self.root / "out", self.root / "err",
                    )
            applied.reset_mock()
            for selected, response in (
                (cycle[0], (0, b"")),
                (cycle[0], (1, b"dependency problems: Package unknown-package is not configured yet.")),
                (cycle[0], (1, b"dependency problems: Package openssl-provider-legacy:amd64 is not configured yet.")),
                (cycle[1], (1, b"dependency problems: Package libssl3t64 is not configured yet.")),
                (cycle[1], (1, b"dependency problems: Package unknown-package:amd64 is not configured yet.")),
            ):
                with mock.patch.object(ORDER, "probe", side_effect=lambda command, *_:
                                       response if command[6] == selected.selector else probe(command)):
                    with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleProbeChanged"):
                        ORDER.configure_openssl_cycle(
                            self.launcher, self.root / "dpkg", self.root, self.root,
                            "amd64", list(cycle), {}, self.root / "out", self.root / "err",
                        )
            applied.assert_not_called()

    def test_three_target_capture_continues_only_exact_half_configured_systemd_and_udev(self) -> None:
        packages = [ORDER.Package(n, ORDER.PROFILE_VERSIONS[n], "amd64", "a" * 128, 42,
                                  self.root / f"{n}.deb") for n in ("systemd", "udev", "sudo")]
        targets = tuple(ORDER.Prestate(p.selector, "unpacked" if p.name == "sudo" else
                                      "half-configured", self.root / f"saved-{p.name}")
                        for p in packages)
        packages.insert(0, ORDER.Package("sudo-rs", "0.2.13-0ubuntu1.2", "amd64",
                                        "a" * 128, 42, self.root / "sudo-rs.deb"))
        for captured_state in ("half-configured", "unpacked", "installed"):
            with self.subTest(captured_state=captured_state):
                states = {}
                captures = {}
                continuations = []
                def apply(command, *_):
                    verb, selector = command[5:7]
                    package = next(p for p in packages if p.selector == selector)
                    key = (package.name, "amd64")
                    if verb == "unpack":
                        states[key] = ("install ok unpacked", package.version)
                    elif package.name == "sudo-rs":
                        self.assertEqual(verb, "configure")
                        self.assertEqual(command[4], "none")
                        states[key] = ("install ok installed", package.version)
                    else:
                        self.assertEqual(verb, "continue_prestate")
                        self.assertIn(package.name, ("systemd", "udev"))
                        self.assertEqual(command[4], package.name)
                        self.assertEqual(states[key], ("install ok half-configured", package.version))
                        continuations.append(selector)
                        states[key] = ("install ok installed", package.version)
                def capture(*args):
                    package, target = args[4:6]
                    key = (package.name, "amd64")
                    self.assertEqual(states[key], ("install ok unpacked", package.version))
                    states[key] = (f"install ok {captured_state}" if target.status ==
                                   "half-configured" else "install ok unpacked", package.version)
                    captures[package.name] = dict(states)
                with (mock.patch.object(ORDER, "packages_from_manifest", return_value=packages),
                      mock.patch.object(ORDER, "verify_archive"),
                      mock.patch.object(ORDER, "probe", return_value=(0, b"")),
                      mock.patch.object(ORDER, "database_packages", side_effect=lambda _: dict(states)),
                      mock.patch.object(ORDER, "capture_prestate", side_effect=capture),
                      mock.patch.object(ORDER, "apply", side_effect=apply)):
                    if captured_state == "half-configured":
                        ORDER.install(self.launcher, self.root / "dpkg", self.root,
                                      self.root, self.root, "amd64", targets)
                    else:
                        with self.assertRaisesRegex(ValueError, "captured prestate state/version changed"):
                            ORDER.install(self.launcher, self.root / "dpkg", self.root,
                                          self.root, self.root, "amd64", targets)
                if captured_state == "half-configured":
                    self.assertEqual(continuations, ["systemd:amd64", "udev:amd64"])
                    self.assertEqual([captures[p.name][(p.name, "amd64")][0] for p in packages[1:]],
                                     ["install ok half-configured", "install ok half-configured",
                                      "install ok unpacked"])
                    self.assertEqual(states[("sudo", "amd64")][0], "install ok unpacked")
                else:
                    self.assertEqual(continuations, [])

    def prestate_record_guard(self, record: bytes) -> subprocess.CompletedProcess:
        script = (TOOLS / "real-snapshot-signed-proc-prestates.sh").read_text()
        block = "expected_record=$(printf" + script.partition("expected_record=$(printf")[2].partition(
            "\nrequire_control()"
        )[0]
        fixture = (TOOLS / "fixtures/real-snapshot/signed-proc-capture-record-v1.tsv").read_bytes()
        prefix = fixture.decode().splitlines()[0].split("\t")[2].rsplit("/", 1)[0]
        receipt = self.root / "prestates.tsv"
        receipt.write_bytes(record)
        result = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", block.replace('"$prestates/prestates.tsv"', '"$receipt"')],
            env={"PATH": "/usr/bin:/bin", "prestates": prefix, "receipt": str(receipt)},
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(receipt.read_bytes(), record)
        return result

    def test_actual_ci_receipt_accepts_all_capture_orders_without_rewriting(self) -> None:
        fixture = (TOOLS / "fixtures/real-snapshot/signed-proc-capture-record-v1.tsv").read_bytes()
        for order in itertools.permutations(fixture.splitlines(keepends=True)):
            with self.subTest(order=[line.split(b"\t")[0] for line in order]):
                result = self.prestate_record_guard(b"".join(order))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_capture_receipt_rejects_missing_duplicate_and_mutated_exact_records(self) -> None:
        fixture = (TOOLS / "fixtures/real-snapshot/signed-proc-capture-record-v1.tsv").read_bytes()
        lines = fixture.splitlines(keepends=True)
        for changed in (
            b"".join(lines[1:]), fixture + lines[0], fixture.replace(lines[1], lines[0]),
            fixture.replace(b"sudo:amd64\t", b"sudo:arm64\t"),
            fixture.replace(b"1.9.17p2-1ubuntu3.1", b"1.9.17p2-1ubuntu3.2"),
            fixture.replace(b"install ok unpacked", b"install ok installed"),
            fixture.replace(b"prestates/sudo\n", b"prestates/other\n"),
            fixture + b"\n", fixture + b"unknown:amd64\t1 install ok unpacked\t/outside\n",
        ):
            with self.subTest(record=changed):
                result = self.prestate_record_guard(changed)
                self.assertEqual(result.returncode, 1)
                self.assertIn("signed prestate record differs", result.stderr)

    def test_sudo_prestate_waits_for_companion_without_changing_normal_configure_order(self) -> None:
        sudo = ORDER.Package("sudo", ORDER.PROFILE_VERSIONS["sudo"], "amd64",
                             "a" * 128, 42, self.root / "sudo.deb")
        companion = ORDER.Package("sudo-rs", "0.2.13-0ubuntu1.2", "amd64",
                                  "b" * 128, 42, self.root / "sudo-rs.deb")
        for capture_requested in (True, False):
            with self.subTest(capture_requested=capture_requested):
                states = {}
                configured = []
                def apply(command, *_):
                    verb, selector = command[5:7]
                    package = sudo if selector == sudo.selector else companion
                    states[(package.name, "amd64")] = (
                        "install ok unpacked" if verb == "unpack" else "install ok installed",
                        package.version,
                    )
                    if verb == "configure":
                        configured.append(package.name)
                def capture(*_):
                    self.assertEqual(states[("sudo-rs", "amd64")],
                                     ("install ok installed", companion.version))
                    self.assertEqual(states[("sudo", "amd64")],
                                     ("install ok unpacked", sudo.version))
                with (mock.patch.object(ORDER, "packages_from_manifest", return_value=[sudo, companion]),
                      mock.patch.object(ORDER, "verify_archive"),
                      mock.patch.object(ORDER, "probe", return_value=(0, b"")),
                      mock.patch.object(ORDER, "database_packages", side_effect=lambda _: dict(states)),
                      mock.patch.object(ORDER, "apply", side_effect=apply),
                      mock.patch.object(ORDER, "capture_prestate", side_effect=capture) as captured):
                    targets = (ORDER.Prestate(sudo.selector, "unpacked", self.root / "saved"),) \
                        if capture_requested else ()
                    if capture_requested:
                        ORDER.install(self.launcher, self.root / "dpkg", self.root,
                                      self.root, self.root, "amd64", targets)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "reference trigger closure refused"):
                            ORDER.install(self.launcher, self.root / "dpkg", self.root,
                                          self.root, self.root, "amd64", targets)
                self.assertEqual(configured, ["sudo-rs"] if capture_requested else ["sudo", "sudo-rs"])
                self.assertEqual(captured.call_count, int(capture_requested))

    def test_sudo_prestate_refuses_missing_or_changed_companion_before_mutation(self) -> None:
        sudo = ORDER.Package("sudo", ORDER.PROFILE_VERSIONS["sudo"], "amd64",
                             "a" * 128, 42, self.root / "sudo.deb")
        for architecture, version in ((None, None), ("amd64", "wrong"), ("arm64", "0.2.13-0ubuntu1.2")):
            packages = [sudo] if architecture is None else [
                sudo, ORDER.Package("sudo-rs", version, architecture, "b" * 128, 42, self.root / "companion"),
            ]
            with (self.subTest(architecture=architecture, version=version),
                  mock.patch.object(ORDER, "packages_from_manifest", return_value=packages),
                  mock.patch.object(ORDER, "apply") as applied,
                  self.assertRaisesRegex(ValueError, "exact reviewed sudo-rs companion")):
                ORDER.install(self.launcher, self.root / "dpkg", self.root,
                              self.root, self.root, "amd64",
                              (ORDER.Prestate(sudo.selector, "unpacked", self.root / "saved"),))
            applied.assert_not_called()

    def test_sudo_prestate_refuses_companion_state_drift_after_successful_configure(self) -> None:
        sudo = ORDER.Package("sudo", ORDER.PROFILE_VERSIONS["sudo"], "amd64",
                             "a" * 128, 42, self.root / "sudo.deb")
        companion = ORDER.Package("sudo-rs", "0.2.13-0ubuntu1.2", "amd64",
                                  "b" * 128, 42, self.root / "companion.deb")
        for changed in (
            ("install ok unpacked", companion.version),
            ("install ok half-configured", companion.version),
            ("install ok installed", "wrong"),
        ):
            states = {}
            def apply(command, *_):
                package = sudo if command[6] == sudo.selector else companion
                states[(package.name, "amd64")] = ("install ok unpacked", package.version) \
                    if command[5] == "unpack" else changed
            with (self.subTest(changed=changed),
                  mock.patch.object(ORDER, "packages_from_manifest", return_value=[sudo, companion]),
                  mock.patch.object(ORDER, "verify_archive"),
                  mock.patch.object(ORDER, "probe", return_value=(0, b"")),
                  mock.patch.object(ORDER, "database_packages", side_effect=lambda _: dict(states)),
                  mock.patch.object(ORDER, "apply", side_effect=apply),
                  mock.patch.object(ORDER, "capture_prestate") as captured,
                  self.assertRaisesRegex(ValueError, "companion state/version changed")):
                ORDER.install(self.launcher, self.root / "dpkg", self.root,
                              self.root, self.root, "amd64",
                              (ORDER.Prestate(sudo.selector, "unpacked", self.root / "saved"),))
            captured.assert_not_called()

    def test_half_configured_continuation_rejects_unbound_package_operations(self) -> None:
        for name, architecture, version, profile in (
            ("systemd", "amd64", ORDER.PROFILE_VERSIONS["systemd"], "none"),
            ("sudo", "amd64", ORDER.PROFILE_VERSIONS["sudo"], "sudo"),
            ("udev", "amd64", ORDER.PROFILE_VERSIONS["udev"], "systemd"),
            ("systemd", "arm64", ORDER.PROFILE_VERSIONS["systemd"], "systemd"),
            ("systemd", "amd64", "wrong", "systemd"),
        ):
            with self.subTest(name=name, architecture=architecture, version=version, profile=profile):
                package = ORDER.Package(name, version, architecture, "a" * 128, 42,
                                        self.root / f"{name}.deb")
                with self.assertRaisesRegex(ValueError, "unauthorized"):
                    ORDER.dpkg_command(self.launcher, self.root / "dpkg", self.root,
                                       architecture, profile, "continue_prestate", package)

    def test_openssl_cycle_resumes_single_package_capture_and_never_repeats_authority(self) -> None:
        cycle, _, _ = self.cycle_fixture(openssl=True)
        extra = [ORDER.Package(n, v, "amd64", d, s, self.root / n)
                 for n, v, s, d, _ in ORDER.BASE_CYCLE if n != "libc6"]
        target = ORDER.Package("systemd", ORDER.PROFILE_VERSIONS["systemd"], "amd64",
                               "a" * 128, 42, self.root / "systemd.deb")
        packages = [*cycle, *extra, target]
        phase = 0
        def probe(command, *_):
            if command[5] == "probe_unpack":
                return 0, b""
            if phase == 0 or command[6] in (cycle[0].selector, cycle[1].selector):
                return 1, b"dependency problems"
            if command[6] == target.selector and phase != 2:
                return 1, b"dependency problems"
            return 0, b""
        def base_break(*_):
            nonlocal phase
            phase = 1
            return extra[0]
        def ssl_break(*_):
            nonlocal phase
            phase = 2
            return cycle[:2]
        with (mock.patch.object(ORDER, "packages_from_manifest", return_value=packages),
              mock.patch.object(ORDER, "probe", side_effect=probe),
              mock.patch.object(ORDER, "verify_archive"),
              mock.patch.object(ORDER, "database_packages", return_value={
                  (p.name, p.architecture): ("install ok unpacked", p.version) for p in packages}),
              mock.patch.object(ORDER, "break_base_cycle", side_effect=base_break) as base,
              mock.patch.object(ORDER, "configure_openssl_cycle", side_effect=ssl_break) as ssl,
              mock.patch.object(ORDER, "apply") as applied,
              mock.patch.object(ORDER, "capture_prestate") as capture):
            ORDER.install(self.launcher, self.root / "dpkg", self.root, self.root,
                          self.root, "amd64", (ORDER.Prestate(
                              target.selector, "half-configured", self.root / "saved"),))
            base.assert_called_once()
            ssl.assert_called_once()
            capture.assert_called_once()
            self.assertNotIn(target.selector, [c.args[0][6] for c in applied.call_args_list
                                               if c.args[0][5] == "configure"])
            phase = 0
            base.reset_mock()
            ssl.reset_mock()
            with mock.patch.object(ORDER, "probe", side_effect=lambda command, *_:
                                   (0, b"") if command[5] == "probe_unpack"
                                   else (1, b"dependency problems")):
                with self.assertRaisesRegex(ORDER.CycleRefusal, "CycleNoProgress"):
                    ORDER.install(self.launcher, self.root / "dpkg", self.root,
                                  self.root, self.root, "amd64")
            base.assert_called_once()
            ssl.assert_called_once()
            refusal = json.loads((self.root / "reference-no-progress.json").read_text())
            self.assertTrue(refusal["base_cycle_applied"])
            self.assertTrue(refusal["openssl_cycle_applied"])
            self.assertIn(target.selector, refusal["deferred"])
            self.assertEqual(bytes.fromhex(refusal["refusals"][0]["output_prefix_hex"]),
                             b"dependency problems")

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
            ORDER.install(self.launcher, self.root / "dpkg", self.root,
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
