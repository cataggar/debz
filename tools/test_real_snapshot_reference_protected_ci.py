#!/usr/bin/env python3
"""Offline checks for the protected reference CI staging tools (#268)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MINISIGN = load("debz_verify_minisign", "verify-minisign.py")
TREE = load("debz_reference_tree_check", "real-snapshot-reference-tree-check.py")
HARNESS = load("debz_reference_protected", "test_real_snapshot_reference_protected.py")
DPKG = load("debz_reference_receipt", "prepare-native-dpkg.py")
from real_snapshot_reference_paths import toolchain, verify_keyring
from real_snapshot_outcome import collect_outcome

ZIG_KEY = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
# The published signature of the pinned x86_64 Zig 0.16.0 archive.
ZIG_X86_64_MINISIG = (
    "untrusted comment: signature from minisign secret key\n"
    "RUSGOq2NVecA2YgO2yM1ni51DC/wp3MuUk5nX9mRT+i07G0aLo26+XusTZAn5zOewoAiWLoo/N73C9+jlA3Y9LFDZz7AnxOfFQc=\n"
    "trusted comment: timestamp:1776173777\tfile:zig-x86_64-linux-0.16.0.tar.xz\thashed\n"
    "E8nJ7jSGa4zwOaGg1cn+gbKJK73F0aRyCCObkifI1f7ZF61MAVnb8HdsEZsJQTSUbierXPeDdj/q5gYcQbpsCQ==\n"
)


class Signer:
    """A throwaway Ed25519 minisign signer built with the OpenSSL CLI."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.key = directory / "secret.pem"
        subprocess.run([MINISIGN.OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        der = subprocess.run([MINISIGN.OPENSSL, "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
        self.key_id = bytes(range(1, 9))
        self.public = base64.b64encode(b"Ed" + self.key_id + der[-32:]).decode()

    def sign(self, message: bytes) -> bytes:
        path = self.directory / "message"
        path.write_bytes(message)
        return subprocess.run(
            [MINISIGN.OPENSSL, "pkeyutl", "-sign", "-inkey", str(self.key), "-rawin", "-in", str(path)],
            check=True, capture_output=True,
        ).stdout

    def minisig(self, payload: bytes, name: str, *, algorithm: bytes = b"ED",
                key_id: bytes | None = None, comment: str | None = None) -> str:
        signed = (hashlib.blake2b(payload, digest_size=64).digest() if algorithm == b"ED" else payload)
        blob = algorithm + (key_id or self.key_id) + self.sign(signed)
        trusted = (comment or f"timestamp:1\tfile:{name}\thashed").encode()
        return (
            "untrusted comment: test\n" + base64.b64encode(blob).decode() + "\n"
            + "trusted comment: " + trusted.decode() + "\n"
            + base64.b64encode(self.sign(blob[10:] + trusted)).decode() + "\n"
        )


class MinisignTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-minisign-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.signer = Signer(self.root)
        self.name = "zig-test-linux-0.16.0.tar.xz"
        self.payload = b"pinned toolchain bytes\n" * 64
        self.artifact = self.root / self.name
        self.artifact.write_bytes(self.payload)
        self.signature = self.root / f"{self.name}.minisig"

    def verify(self, minisig: str, **overrides) -> str:
        self.signature.write_text(minisig)
        arguments = {
            "public_key": self.signer.public, "artifact": self.artifact,
            "signature": self.signature, "name": self.name,
            "sha256": hashlib.sha256(self.payload).hexdigest(), "size": len(self.payload),
        }
        arguments.update(overrides)
        return MINISIGN.verify(**arguments)

    def other_key(self) -> str:
        other = self.root / "other"
        other.mkdir()
        return Signer(other).public

    def test_published_zig_trusted_comment_signature_verifies_with_the_pinned_key(self) -> None:
        lines = ZIG_X86_64_MINISIG.encode().split(b"\n")
        raw_key = base64.b64decode(ZIG_KEY)
        blob = base64.b64decode(lines[1])
        self.assertEqual((blob[:2], blob[2:10]), (b"ED", raw_key[2:10]))
        trusted = lines[2][len(b"trusted comment: "):]
        MINISIGN.ed25519_verify(raw_key[10:], blob[10:] + trusted, base64.b64decode(lines[3]))
        with self.assertRaises(MINISIGN.VerificationError):
            MINISIGN.ed25519_verify(raw_key[10:], blob[10:] + trusted + b"x", base64.b64decode(lines[3]))

    def test_prehashed_signature_binds_bytes_name_size_and_digest(self) -> None:
        self.assertIn("verified zig-test-linux", self.verify(self.signer.minisig(self.payload, self.name)))
        good = self.signer.minisig(self.payload, self.name)
        for overrides, message in (
            ({"sha256": "0" * 64}, "SHA256"),
            ({"sha256": hashlib.sha256(self.payload).hexdigest().upper()}, "SHA256"),
            ({"sha256": ""}, "SHA256"),
            ({"size": len(self.payload) - 1}, "size or SHA256"),
            ({"name": "zig-other-linux-0.16.0.tar.xz"}, "trusted comment"),
            ({"public_key": self.other_key()}, "Ed25519"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(MINISIGN.VerificationError, message):
                self.verify(good, **overrides)

    def test_tampered_or_legacy_signatures_refuse(self) -> None:
        good = self.signer.minisig(self.payload, self.name)
        self.artifact.write_bytes(self.payload[:-1] + b"?")
        with self.assertRaisesRegex(MINISIGN.VerificationError, "SHA256"):
            self.verify(good)
        with self.assertRaisesRegex(MINISIGN.VerificationError, "Ed25519"):
            self.verify(good, sha256=hashlib.sha256(self.artifact.read_bytes()).hexdigest())
        self.artifact.write_bytes(self.payload)
        lines = good.split("\n")
        lines[2] = lines[2].replace("timestamp:1", "timestamp:2")
        with self.assertRaisesRegex(MINISIGN.VerificationError, "Ed25519"):
            self.verify("\n".join(lines))
        with self.assertRaisesRegex(MINISIGN.VerificationError, "prehashed"):
            self.verify(self.signer.minisig(self.payload, self.name, algorithm=b"Ed"))
        with self.assertRaisesRegex(MINISIGN.VerificationError, "key id"):
            self.verify(self.signer.minisig(self.payload, self.name, key_id=b"\0" * 8))
        with self.assertRaisesRegex(MINISIGN.VerificationError, "trusted comment"):
            self.verify(self.signer.minisig(self.payload, self.name, comment=f"file:{self.name}"))
        self.artifact.unlink()
        self.artifact.symlink_to(self.root / "secret.pem")
        with self.assertRaises(OSError):
            self.verify(good)


class TreeCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-tree-check-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_unprotected_ancestry_and_tree_refuse(self) -> None:
        self.root.chmod(0o755)
        failures = TREE.ancestry(str(self.root))
        self.assertTrue(any(failure.startswith("protected tree must be mode 0700: drwxr-xr-x")
                            for failure in failures), failures)
        temp_root = os.path.realpath(tempfile.gettempdir())
        self.assertTrue(any(failure.startswith("unprotected ancestor: ")
                            and failure.endswith(f" {temp_root}")
                            for failure in failures), failures)
        self.assertEqual(TREE.ancestry("relative"), ["tree path is not canonical and absolute: relative"])
        (self.root / "writable").write_text("x")
        (self.root / "writable").chmod(0o666)
        with mock.patch.object(TREE.os, "lstat", side_effect=root_owned_lstat):
            failures = TREE.tree_failures(str(self.root))
        self.assertEqual(len(failures), 1)
        self.assertIn("group/other-writable entry", failures[0])

    def test_package_sources_must_be_tightened_and_stay_inside(self) -> None:
        packages = self.root / "zig-pkg"
        (packages / "pkg").mkdir(parents=True)
        script = packages / "pkg/autogen.sh"
        script.write_text("#!/bin/sh\nexit 1\n")
        script.chmod(0o777)
        (packages / "pkg/inside").symlink_to("autogen.sh")
        with mock.patch.object(TREE.os, "lstat", side_effect=root_owned_lstat):
            failures = TREE.package_failures(str(packages), str(self.root / "loose.txt"))
            self.assertEqual([failure.split(":")[0] for failure in failures], ["untightened package entry"])
            script.chmod(0o755)
            self.assertEqual(TREE.package_failures(str(packages), str(self.root / "tight.txt")), [])
            manifest = (self.root / "tight.txt").read_text()
            self.assertIn("0755 " + hashlib.sha256(script.read_bytes()).hexdigest() + " pkg/autogen.sh", manifest)
            self.assertIn("link autogen.sh pkg/inside", manifest)
            (packages / "pkg/escape").symlink_to("../../outside")
            failures = TREE.package_failures(str(packages), str(self.root / "escape.txt"))
            self.assertEqual(len(failures), 1)
            self.assertIn("escapes its tree", failures[0])
            with self.assertRaises(FileExistsError):
                TREE.package_failures(str(packages), str(self.root / "tight.txt"))


REAL_LSTAT = os.lstat


def root_owned_lstat(path: str) -> os.stat_result:
    values = list(REAL_LSTAT(path))
    values[4:6] = [0, 0]
    return os.stat_result(values)


class ProfileStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-profile-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        patch = mock.patch.object(HARNESS, "protected",
                                  side_effect=lambda path, directory=False: path.stat())
        patch.start()
        self.addCleanup(patch.stop)

    def test_arm64_stages_no_amd64_profile_scripts(self) -> None:
        self.assertEqual(HARNESS.profile_scripts(self.root, "arm64"), {})
        (self.root / "systemd.postinst").write_text("#!/bin/sh\n")
        with self.assertRaisesRegex(ValueError, "must not stage amd64 profile scripts"):
            HARNESS.profile_scripts(self.root, "arm64")

    def test_amd64_requires_exactly_the_bound_postinsts(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile scripts must be exactly"):
            HARNESS.profile_scripts(self.root, "amd64")
        for profile in ("systemd", "udev", "sudo"):
            (self.root / f"{profile}.postinst").write_text(f"#!/bin/sh\n# {profile}\n")
        self.assertEqual(sorted(HARNESS.profile_scripts(self.root, "amd64")), ["sudo", "systemd", "udev"])
        (self.root / "extra.postinst").write_text("#!/bin/sh\n")
        with self.assertRaisesRegex(ValueError, "profile scripts must be exactly"):
            HARNESS.profile_scripts(self.root, "amd64")
        (self.root / "extra.postinst").unlink()
        (self.root / "udev.postinst").write_bytes(b"#" * (HARNESS.PROFILE_SCRIPT_LIMIT + 1))
        with self.assertRaisesRegex(ValueError, "exceeds limit"):
            HARNESS.profile_scripts(self.root, "amd64")

    def test_profile_checks_are_reported_by_the_probe(self) -> None:
        probe = (TOOLS / "real-snapshot-reference-escape-probe.zig").read_text()
        views = {check for checks in HARNESS.PROFILE_VIEW_CHECKS.values() for check in checks}
        for check in (*HARNESS.PROFILE_ESCAPE_CHECKS, *HARNESS.PROFILE_COMMON_CHECKS, *views):
            self.assertIn(f'"{check}"', probe)
        self.assertNotIn("no-proc-view", HARNESS.PROFILE_ESCAPE_CHECKS)
        self.assertEqual(set(HARNESS.PROFILE_VIEW_CHECKS), set(HARNESS.ORDER.PROFILE_VERSIONS))


class ExtractedReferenceReceiptTests(unittest.TestCase):
    def test_archive_receipt_producer_and_verify_only_both_architectures(self) -> None:
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                package, prefix, archive = base / "package", base / "prefix", base / "dpkg.deb"
                (package / "DEBIAN").mkdir(parents=True)
                (package / "DEBIAN/control").write_text(
                    f"Package: dpkg\nVersion: {DPKG.VERSION}\nArchitecture: {architecture}\n"
                    "Maintainer: Fixture <fixture@example.invalid>\nDescription: Receipt fixture\n"
                )
                (package / "usr/bin").mkdir(parents=True)
                pins = {}
                for name, key in (("dpkg", "executable"), ("dpkg-query", "dpkg_query"),
                                  ("update-alternatives", "update_alternatives")):
                    executable = package / "usr/bin" / name
                    executable.write_text(f"#!/bin/sh\necho 'Debian dpkg version {DPKG.VERSION}'\n")
                    executable.chmod(0o755)
                    pins[key] = hashlib.sha256(executable.read_bytes()).hexdigest()
                subprocess.run(["dpkg-deb", "--build", str(package), str(archive)],
                               stdout=subprocess.DEVNULL, check=True)
                subprocess.run(["dpkg-deb", "--extract", str(archive), str(prefix)], check=True)
                pins["archive"] = hashlib.sha256(archive.read_bytes()).hexdigest()
                receipt = prefix / DPKG.RECEIPT
                with mock.patch.dict(DPKG.PINS, {architecture: pins}):
                    DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    DPKG.verify_receipt(receipt, architecture)
                    with mock.patch.object(sys, "argv", [
                        "prepare-native-dpkg.py", "--architecture", architecture,
                        "--verify-only", str(prefix / "usr/bin/dpkg"),
                    ]):
                        self.assertEqual(DPKG.main(), 0)
                    with self.assertRaises(FileExistsError):
                        DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    receipt.unlink()
                    with self.assertRaises(RuntimeError):
                        DPKG.verify_receipt(receipt, architecture)
                    DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    receipt.write_text("{}\n")
                    with self.assertRaises(RuntimeError):
                        DPKG.verify_receipt(receipt, architecture)
                    receipt.unlink()
                    query = prefix / "usr/bin/dpkg-query"
                    query.chmod(0o777)
                    with self.assertRaisesRegex(RuntimeError, "protected regular"):
                        DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    query.chmod(0o755)
                    os.link(query, prefix / "hardlink")
                    with self.assertRaisesRegex(RuntimeError, "protected regular"):
                        DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    (prefix / "hardlink").unlink()
                    (prefix / "usr/bin").rename(prefix / "usr/aliased-bin")
                    (prefix / "usr/bin").symlink_to("aliased-bin")
                    with self.assertRaisesRegex(RuntimeError, "protected regular"):
                        DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    (prefix / "usr/bin").unlink()
                    (prefix / "usr/aliased-bin").rename(prefix / "usr/bin")
                    for name in ("dpkg-query", "update-alternatives"):
                        tool = prefix / "usr/bin" / name
                        original = tool.read_bytes()
                        tool.write_bytes(b"corrupted binding")
                        with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                            DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                        self.assertFalse(receipt.exists())
                        tool.write_bytes(original)
                    DPKG.receipt_from_extracted_archive(architecture, archive, prefix)
                    (prefix / "usr/bin/dpkg-query").write_bytes(b"corrupted after receipt")
                    with self.assertRaises(RuntimeError):
                        DPKG.verify_receipt(receipt, architecture)


class ProtectedCiScriptTests(unittest.TestCase):
    def test_receipt_and_python_premutation_guards_cannot_be_removed(self) -> None:
        audit = load("debz_receipt_python_guards", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        for path, token in (
            ("tools/prepare-native-dpkg.py", "    verify_extracted_bindings(prefix, architecture)\n"),
            ("tools/prepare-native-dpkg.py", "    verify_archive_metadata(archive, architecture)\n"),
            ("tools/real-snapshot-reference-protected-stage.sh", "module.receipt_from_extracted_archive(\n"),
            ("tools/real-snapshot-python3-reference.sh", 'fixture preflight "$source_root"\n'),
            ("tools/real_snapshot_python_fixtures.py",
             '    create_exclusive(shadow, "usr/sbin/update-alternatives", b"shadow\\n", 0o644)\n'),
            ("src/native_unpack.zig",
             "    try verifySnapshotPython3PreinstInputs(testing.allocator, root.root, &program);\n"),
        ):
            with self.subTest(path=path, token=token):
                changed = dict(texts)
                self.assertIn(token, changed[path])
                changed[path] = changed[path].replace(token, "", 1)
                self.assertTrue(audit.protected_reference_ci_failures(changed))
        changed = dict(texts)
        path = "tools/real-snapshot-python3-reference.sh"
        token = 'grep -Fx "signed Python source guard executed before fixture mutation" "$source_proof"\n'
        changed[path] = changed[path].replace(token, "", 1) + "\n" + token
        self.assertIn("protected Python source guard must execute before copies/mutations",
                      audit.protected_reference_ci_failures(changed))

    def test_arm_less_receipts_require_real_source_and_replay_assertions(self) -> None:
        audit = load("debz_arm_less_activation_policy", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        for path, token in (
            ("src/native_unpack.zig", '    try verifySnapshotLessArm64Inputs(testing.allocator, root.root, &artifacts, "arm64");\n'),
            ("src/native_unpack.zig", '        try testing.expectEqualDeep(before.record, after.record);\n'),
            ("src/native_unpack.zig", '        try proof.writeStreamingAll(testing.io, "signed arm64 less eight replay roots executed without skips\\n");\n'),
            ("tools/real-snapshot-reference-protected-ci.sh", '"$zig" build test-real-snapshot-arm64-less-protected'),
            ("tools/real_snapshot_less_stage.py", '    for package in SOURCE_ARTIFACTS:\n        archive(lock, cache, package)\n'),
        ):
            with self.subTest(token=token):
                self.assertIn(token, texts[path])
                changed = dict(texts)
                changed[path] = texts[path].replace(token, "", 1)
                self.assertTrue(audit.protected_reference_ci_failures(changed))

    def test_arm_less_activation_refuses_unprivileged_or_incomplete_staging(self) -> None:
        script = TOOLS / "real-snapshot-less-protected-stage.sh"
        for arguments in ((), ("/usr/bin/zig", "/usr/bin/debz",
                               str(TOOLS.parent / ".real-snapshot/less-arm64"))):
            result = subprocess.run(["bash", str(script), *arguments], capture_output=True,
                                    text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("replay roots staged", result.stdout)

    def test_python_input_receipt_requires_actual_strict_root_assertions(self) -> None:
        audit = load("debz_python_activation_policy", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        path = "src/native_unpack.zig"
        # This source exceeds the generic mutation CLI's 1 MiB input cap.
        # Exercise the same real policy directly; do not widen that cap.
        for token in (
            "    try verifySnapshotPython3PreinstInputs(testing.allocator, before_py3compile.root, &program);\n",
            "    try verifySnapshotPython3NullOutput(testing.allocator, after_py3compile.root);\n",
            '        try proof.writeStreamingAll(testing.io, "signed Python empty0600/0644 '
            'and amd64 20/96 input/output guards executed without skips\\n");\n',
        ):
            with self.subTest(token=token):
                self.assertIn(token, texts[path])
                changed = dict(texts)
                changed[path] = texts[path].replace(token, "", 1)
                self.assertTrue(any("protected Python test body lost" in failure for failure in
                                    audit.protected_reference_ci_failures(changed)))

    def test_python_activation_refuses_unprivileged_or_incomplete_staging(self) -> None:
        script = TOOLS / "real-snapshot-python3-protected-stage.sh"
        for arguments in ((), ("/usr/bin/zig", "/usr/bin/debz", "/usr/bin/dpkg",
                               str(TOOLS.parent / ".real-snapshot/python3-amd64"))):
            result = subprocess.run(["bash", str(script), *arguments], capture_output=True,
                                    text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("coordinates staged", result.stdout)

    def test_refuses_outside_its_root_owned_tree(self) -> None:
        script = TOOLS / "real-snapshot-reference-protected-ci.sh"
        for arguments in ((), ("/srv/debz-protected/ci-1-1-amd64", "arm64", "0" * 40),
                          ("/tmp/elsewhere", "amd64", "0" * 40)):
            result = subprocess.run(["bash", str(script), *arguments], capture_output=True,
                                    text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("protected reference CI: commit=", result.stdout)

    def test_acceptance_has_no_ambient_keyring_fallback(self) -> None:
        environment = dict(os.environ)
        environment.pop("DEBZ_REAL_SNAPSHOT_KEYRING", None)
        architecture = "arm64" if os.uname().machine == "aarch64" else "amd64"
        result = subprocess.run(
            ["bash", str(TOOLS / "real-snapshot-acceptance.sh"), "--validate",
             "https://snapshot.ubuntu.com/ubuntu/20261001T000000Z", "resolute", architecture],
            env=environment, capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit regular Ubuntu archive keyring", result.stderr)


class ProtectedInputTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-protected-input-", dir=TOOLS.parent / ".zig-cache")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.real_fstat = os.fstat

    def root_owned_fstat(self, fd: int) -> os.stat_result:
        values = list(self.real_fstat(fd))
        values[4:6] = [0, 0]
        path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        if not path.is_relative_to(self.root):
            values[0] &= ~0o022
        return os.stat_result(values)

    def test_keyring_refuses_unprotected_writable_symlinked_and_wrong_bytes(self) -> None:
        keyring = self.root / "keyring"
        payload = b"reviewed fixture bytes"
        keyring.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(ValueError, "non-root ancestor"):
            verify_keyring(keyring, len(payload), digest)
        with mock.patch.object(os, "fstat", side_effect=self.root_owned_fstat):
            self.assertEqual(verify_keyring(keyring, len(payload), digest), digest)
            for size, expected in ((len(payload) + 1, digest), (len(payload), "0" * 64)):
                with self.subTest(size=size), self.assertRaisesRegex(ValueError, "pin mismatch"):
                    verify_keyring(keyring, size, expected)
            keyring.write_bytes(payload[:-1] + b"?")
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                verify_keyring(keyring, len(payload), digest)
            keyring.write_bytes(payload)
            keyring.chmod(0o666)
            with self.assertRaisesRegex(ValueError, "writable"):
                verify_keyring(keyring, len(payload), digest)
            keyring.chmod(0o644)
            link = self.root / "linked"
            link.symlink_to(keyring)
            with self.assertRaises(OSError):
                verify_keyring(link, len(payload), digest)
            directory_link = self.root / "linked-dir"
            directory_link.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(OSError):
                verify_keyring(directory_link / "keyring", len(payload), digest)
            self.root.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "writable"):
                verify_keyring(keyring, len(payload), digest)

    def test_compiler_binds_protected_library_ancestry_without_resolving_input_links(self) -> None:
        compiler = self.root / "zig"
        compiler.write_text("#!/bin/sh\nexit 0\n")
        compiler.chmod(0o755)
        library = self.root / "lib"
        library.mkdir()
        source = library / "std.zig"
        source.write_text("fixture")
        with self.assertRaisesRegex(ValueError, "non-root ancestor"):
            toolchain(compiler)
        with mock.patch.object(os, "fstat", side_effect=self.root_owned_fstat):
            self.assertEqual(toolchain(compiler), library)
            compiler.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "writable"):
                toolchain(compiler)
            compiler.chmod(0o755)
            source.chmod(0o666)
            with self.assertRaisesRegex(ValueError, "writable"):
                toolchain(compiler)
            source.chmod(0o644)
            (library / "escape").symlink_to(compiler)
            with self.assertRaisesRegex(ValueError, "symlink escapes"):
                toolchain(compiler)
            (library / "escape").unlink()
            linked = self.root / "linked-zig"
            linked.symlink_to(compiler)
            with self.assertRaises(OSError):
                toolchain(linked)
            library.rename(self.root / "real-lib")
            library.symlink_to(self.root / "real-lib", target_is_directory=True)
            with self.assertRaises(OSError):
                toolchain(compiler)


class NativeOutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        cache = TOOLS.parent / ".zig-cache"
        cache.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="debz-native-outcome-", dir=cache)
        self.addCleanup(temporary.cleanup)
        self.evidence = Path(temporary.name)
        self.refresh = self.result("refresh", 0, changed=True)
        self.write_json("refresh.json", self.refresh)

    @staticmethod
    def result(operation: str, status: int, *, changed: bool = False) -> dict:
        return {"operation": operation, "exit_status": status, "changed": changed,
                "summary": f"{operation} result", "diagnostics": []}

    def write_json(self, name: str, value: object) -> None:
        (self.evidence / name).write_text(json.dumps(value))

    def attempt(self, stage: str, status: int | None, result: dict,
                wrapper_status: int | None) -> None:
        self.write_json("native-stage-v1.json", {"stage": stage, "command_exit_status": status})
        self.write_json(f"{stage}.json", result)
        receipt = self.evidence / "native-wrapper-exit-status.txt"
        if wrapper_status is None:
            receipt.unlink(missing_ok=True)
        else:
            receipt.write_text(f"{wrapper_status}\n")

    def test_failed_create_preserves_install_diagnostic_not_successful_refresh(self) -> None:
        result = self.result("install", 8, changed=True)
        result["diagnostics"] = [{"id": "native_backend_unavailable",
                                  "message": "python3_preinst reason=control_file_mismatch "
                                  "path=dev/null field=size expected=0 observed=20"}]
        self.attempt("create", 8, result, 8)
        outcome, status = collect_outcome(self.evidence, "failure")
        self.assertEqual(status, 0)
        self.assertEqual((outcome["operation"], outcome["stage"], outcome["exit_status"]),
                         ("install", "create", 8))
        self.assertTrue(outcome["changed"])
        self.assertEqual(outcome["diagnostics"][0], result["diagnostics"][0])
        self.assertEqual(outcome["workflow_step_outcome"], "failure")

    def test_later_failure_and_post_command_failure_keep_latest_attempt(self) -> None:
        for stage, result, command, wrapper in (
            ("update", self.result("upgrade-all", 8), 8, 8),
            ("create-summary", {"backend": "native", "outcome": "failed"}, 7, 7),
            ("update", self.result("upgrade-all", 0), 0, 90),
            ("update", self.result("upgrade-all", 0), 0, 0),
        ):
            with self.subTest(stage=stage, command=command, wrapper=wrapper):
                self.attempt(stage, command, result, wrapper)
                outcome, status = collect_outcome(self.evidence, "failure")
                self.assertEqual(status, 0)
                self.assertEqual(outcome["stage"], stage)
                self.assertEqual(outcome["command_exit_status"], command)
                self.assertEqual(outcome["wrapper_exit_status"], wrapper)
                self.assertEqual(outcome["exit_status"], wrapper or 1)
                self.assertNotEqual(outcome["operation"], "refresh")
                if stage == "create-summary":
                    self.assertIsNone(outcome["result_exit_status"])

    def test_missing_empty_corrupt_and_unsafe_latest_result_never_fall_back(self) -> None:
        self.attempt("update", 1, self.result("upgrade-all", 1), 1)
        path = self.evidence / "update.json"
        for data in (None, b"", b"{broken", b"null", b"[]", b"{}",
                     b'{"operation":"upgrade-all","exit_status":false,"changed":false,'
                     b'"summary":"bad","diagnostics":[]}'):
            with self.subTest(data=data):
                path.unlink(missing_ok=True)
                if data is not None:
                    path.write_bytes(data)
                outcome, status = collect_outcome(self.evidence, "failure")
                self.assertEqual(status, 1)
                self.assertEqual(outcome["stage"], "update")
                self.assertEqual(outcome["operation"], "upgrade-all")
                self.assertFalse(outcome["result_available"])
                self.assertNotEqual(outcome["exit_status"], 0)
                self.assertTrue(outcome["diagnostics"][-1]["id"].startswith("native_acceptance_evidence_"))
        path.unlink()
        path.symlink_to(self.evidence / "refresh.json")
        outcome, status = collect_outcome(self.evidence, "failure")
        self.assertEqual(status, 1)
        self.assertFalse(outcome["result_available"])

    def test_unrecorded_attempt_exit_and_missing_marker_are_explicitly_unavailable(self) -> None:
        self.attempt("create", None, self.result("install", 0), None)
        outcome, status = collect_outcome(self.evidence, "cancelled")
        self.assertEqual(status, 1)
        self.assertEqual(outcome["stage"], "create")
        self.assertIsNone(outcome["command_exit_status"])
        self.assertEqual(outcome["diagnostics"][-1]["id"], "native_acceptance_evidence_unavailable")
        (self.evidence / "native-stage-v1.json").unlink()
        outcome, status = collect_outcome(self.evidence, "failure")
        self.assertEqual(status, 1)
        self.assertIsNone(outcome["stage"])
        self.assertNotEqual(outcome["operation"], "refresh")

    def test_expected_negative_control_is_not_wrapper_success_without_completion(self) -> None:
        self.attempt("injected-failure", 5, self.result("plan", 5), 0)
        outcome, status = collect_outcome(self.evidence, "success")
        self.assertEqual(status, 0)
        self.assertEqual((outcome["exit_status"], outcome["command_exit_status"],
                          outcome["result_exit_status"]), (0, 5, 5))
        self.assertTrue(outcome["expected_refusal"])
        self.attempt("injected-failure", 5, self.result("plan", 5), 1)
        outcome, status = collect_outcome(self.evidence, "failure")
        self.assertEqual(status, 0)
        self.assertEqual(outcome["exit_status"], 1)
        self.assertTrue(outcome["expected_refusal"])
        for workflow in ("success", "skipped", "unavailable"):
            with self.subTest(workflow=workflow):
                outcome, status = collect_outcome(self.evidence, workflow)
                self.assertEqual(status, 1)
                self.assertNotEqual(outcome["exit_status"], 0)

    def test_latest_result_operation_must_match_recorded_attempt(self) -> None:
        for stage, command, wrapper, workflow in (
            ("create", 0, 1, "failure"),
            ("injected-failure", 5, 0, "success"),
        ):
            with self.subTest(stage=stage):
                self.attempt(stage, command, self.result("refresh", command), wrapper)
                outcome, status = collect_outcome(self.evidence, workflow)
                self.assertEqual(status, 1)
                self.assertEqual(outcome["operation"], "install" if stage == "create" else "plan")
                self.assertFalse(outcome["result_available"])
                self.assertNotEqual(outcome["exit_status"], 0)
                self.assertEqual(outcome["diagnostics"][-1]["id"], "native_acceptance_evidence_invalid")


if __name__ == "__main__":
    unittest.main()
