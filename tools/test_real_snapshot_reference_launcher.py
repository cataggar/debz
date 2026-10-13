#!/usr/bin/env python3
"""Offline fail-closed checks for the bounded pinned-dpkg reference."""

from __future__ import annotations

import importlib.util
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import real_snapshot_less_fixtures as LESS_FIXTURES
import real_snapshot_less_stage as LESS_STAGE
import real_snapshot_python_fixtures as PYTHON_FIXTURES

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
        info = self.root / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (self.root / "var/lib/debz-lifecycle-scripts").mkdir()
        listing = info / "less.list"
        listing.write_bytes(content)
        preinst, _ = REPIN.tar_member(deb, "control.tar", "preinst")
        (info / "less.preinst").write_bytes(preinst)
        postinst, _ = REPIN.tar_member(deb, "control.tar", "postinst")
        (info / "less.postinst").write_bytes(postinst)
        before = listing.stat()
        LESS_STAGE.seal(self.root)
        after = listing.stat()
        self.assertEqual(listing.read_bytes(), content)
        self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                         (before.st_ino, before.st_mtime_ns, before.st_ctime_ns))
        staged = self.root / "var/lib/debz-lifecycle-scripts/less.preinst"
        self.assertEqual(staged.read_bytes(), preinst)
        for changed in (b"".join(sorted(content.splitlines(keepends=True))),
                        content.replace(b"/usr/bin/less\n", b"/../bin/less\n")):
            self.assertNotEqual(changed, content)
            listing.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "signed less ownership path set changed"):
                LESS_STAGE.seal(self.root)
            self.assertEqual(listing.read_bytes(), changed)
            self.assertEqual(staged.read_bytes(), preinst)

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
        real_stat = os.stat
        def captured_null_metadata(path, *args, **kwargs):
            metadata = real_stat(path, *args, **kwargs)
            if path == "null" and kwargs.get("dir_fd") is not None:
                return mock.Mock(st_mode=stat.S_IFCHR | 0o666, st_rdev=os.makedev(1, 3),
                                 st_uid=metadata.st_uid, st_gid=metadata.st_gid, st_nlink=1)
            return metadata
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                root = self.root / architecture
                (root / "proc").mkdir(parents=True)
                (root / "dev").mkdir()
                info = root / "var/lib/dpkg/info"
                info.mkdir(parents=True)
                original = {}
                for name in ("python3", "python3-minimal"):
                    content, _ = self.retained_list(name, architecture)
                    listing = info / f"{name}.list"
                    listing.write_bytes(content)
                    original[name] = content, listing.stat()
                null = root / "dev/null"
                null.write_bytes(b"captured null boundary")
                with (mock.patch.object(PYTHON_FIXTURES, "protected"),
                      mock.patch.object(PYTHON_FIXTURES.os, "stat",
                                        side_effect=captured_null_metadata)):
                    PYTHON_FIXTURES.prepare_empty(root)
                self.assertEqual(null.read_bytes(), b"")
                self.assertEqual(stat.S_IMODE(null.stat().st_mode), 0o600)
                for name, (content, before) in original.items():
                    listing = info / f"{name}.list"
                    after = listing.stat()
                    self.assertEqual(listing.read_bytes(), content)
                    self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                                     (before.st_ino, before.st_mtime_ns, before.st_ctime_ns))
                    for changed in (b"".join(sorted(content.splitlines(keepends=True))),
                                    content.replace(b"/usr/bin/", b"/../bin/")):
                        self.assertNotEqual(changed, content)
                        listing.write_bytes(changed)
                        null.write_bytes(b"not removed on invalid list")
                        with (mock.patch.object(PYTHON_FIXTURES, "protected"),
                              mock.patch.object(PYTHON_FIXTURES.os, "unlink") as unlink,
                              self.assertRaisesRegex(ValueError, f"signed Python list path set changed: {name}")):
                            PYTHON_FIXTURES.prepare_empty(root)
                        unlink.assert_not_called()
                        self.assertEqual(listing.read_bytes(), changed)
                        self.assertEqual(null.read_bytes(), b"not removed on invalid list")
                        listing.write_bytes(content)

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

    def test_less_source_setup_checks_all_goal_locks_before_mutation(self) -> None:
        goals = {"dpkg": ("dpkg", "libc6"), "less": ("less",),
                 "dash": ("dash",), "util-linux": ("util-linux", "libcap-ng0")}
        locks = {goal: self.root / f"{goal}.json" for goal in goals}
        archive_path = self.root / "cached-archive"
        archive_path.write_bytes(b"unit fixture archive bytes")
        verified = []
        def check_archive(document, cache, package):
            self.assertIn(package, [entry["name"] for entry in document["packages"]])
            verified.append(package)
            return archive_path
        def before_mutation(root):
            self.assertEqual(set(verified), set(LESS_STAGE.SOURCE_ARTIFACTS))
        for separate in (False, True):
            with self.subTest(separate=separate):
                for goal, names in goals.items():
                    packages = names if separate else tuple(name for members in goals.values() for name in members)
                    locks[goal].write_text(json.dumps({
                        "target_architecture": "arm64", "packages": [{"name": name} for name in packages]}))
                verified.clear()
                additional = tuple(locks[goal] for goal in ("less", "dash", "util-linux")) if separate else ()
                with mock.patch.object(LESS_STAGE, "protected"), \
                     mock.patch.object(LESS_STAGE, "archive", side_effect=check_archive), \
                     mock.patch.object(LESS_STAGE, "remove_lib64", side_effect=before_mutation), \
                     mock.patch.object(LESS_STAGE, "directory"), \
                     mock.patch.object(LESS_STAGE, "member", return_value=b"unit runtime bytes"), \
                     mock.patch.object(LESS_STAGE, "create_exclusive"), \
                     mock.patch.object(LESS_STAGE, "alias"):
                    LESS_STAGE.prepare(self.root, locks["dpkg"], self.root, archive_path, *additional)

    def test_less_source_setup_refuses_missing_or_wrong_arch_goal_lock_before_mutation(self) -> None:
        paths = [self.root / f"{name}.json" for name in ("dpkg", "less", "dash", "util-linux")]
        for mutation in ("missing", "wrong-architecture"):
            with self.subTest(mutation=mutation):
                for path in paths:
                    path.write_text(json.dumps({"target_architecture": "arm64", "packages": []}))
                if mutation == "missing":
                    paths[2].unlink()
                    expected = FileNotFoundError
                else:
                    paths[2].write_text(json.dumps({"target_architecture": "amd64", "packages": []}))
                    expected = ValueError
                with mock.patch.object(LESS_STAGE, "protected"), \
                     mock.patch.object(LESS_STAGE, "archive") as archive, \
                     mock.patch.object(LESS_STAGE, "remove_lib64") as mutate:
                    with self.assertRaises(expected):
                        LESS_STAGE.prepare(self.root, paths[0], self.root, self.root / "pinned", *paths[1:])
                    archive.assert_not_called()
                    mutate.assert_not_called()

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
            ("tools/real-snapshot-reference-order.zig", 'const before = try self.verifyCycle(root, cycle, kind);'),
            ("tools/real-snapshot-reference-order.zig", 'const selected = if (kind == .openssl) cycle[0..2] else cycle[kind.selected()..][0..1];'),
            ("tools/real-snapshot-reference-order.zig", 'return processTriggers(self, packages);'),
            ("tools/real-snapshot-reference-order.zig", 'ctx.run(&.{ authority, "verify-transition", "amd64", before_path, after_path }, 60, maximum_control_bytes)'),
            ("tools/real-snapshot-reference-order.zig", ': no reviewed signed handler; --pending and multi-package trigger processing are not authorized"'),
            ("tools/real-snapshot-reference-launcher.zig", 'if (child.options.verb == .trigger_libc_bin)\n        verifyTrigger() catch |err| {'),
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
