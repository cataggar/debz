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
            ("tools/real-snapshot-reference-order.zig", "pub fn verifyKbdCycle("),
            ("tools/real-snapshot-reference-order.zig", "pub fn breakKbdCycle("),
            ("tools/real-snapshot-reference-order.zig", "pub fn verifyTriggerHandlers("),
            ("tools/real-snapshot-reference-order.zig", "pub fn processTriggers("),
            ("tools/real-snapshot-reference-order.zig", "fn execBreakKbdCycle("),
            ("tools/real-snapshot-reference-order.zig", "fn execProcessTriggers("),
        ):
            with self.subTest(path=path, token=token):
                changed = dict(texts)
                changed[path] = texts[path].replace(token, "", 1)
                self.assertTrue(audit.protected_reference_ci_failures(changed))

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


if __name__ == "__main__":
    unittest.main()
