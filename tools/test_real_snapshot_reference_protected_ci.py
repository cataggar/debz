#!/usr/bin/env python3
"""Offline checks for the protected reference CI staging tools (#268)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

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
    def test_reference_network_controls_require_reachable_host_and_retain_refusals(self) -> None:
        receipt = b"DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open\n"
        for status, stdout in ((0, receipt), (1, receipt), (0, b""), (0, receipt + b"extra\n")):
            with self.subTest(status=status, stdout=stdout), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                root = workspace / "root"
                root.mkdir()
                result = subprocess.CompletedProcess([], status, stdout, b"original diagnostic\n")
                with mock.patch.object(HARNESS.subprocess, "run", return_value=result) as run:
                    if status == 0 and stdout == receipt:
                        with HARNESS.network_control(workspace, "fixture", root, workspace / "probe") as fd:
                            self.assertGreaterEqual(fd, 200)
                            self.assertEqual(run.call_args.kwargs["pass_fds"], (fd,))
                            port, name, inherited = (root / ".debz-network-control").read_text().splitlines()
                            self.assertGreater(int(port), 0)
                            self.assertTrue(name.startswith("debz-reference-"))
                            self.assertEqual(inherited, str(fd))
                    else:
                        with self.assertRaisesRegex(AssertionError, "not genuinely reachable"):
                            with HARNESS.network_control(workspace, "fixture", root, workspace / "probe"):
                                self.fail("unverified host control authorized reference execution")
                        self.assertFalse((root / ".debz-network-control").exists())
                self.assertEqual((workspace / "fixture.network-host.stdout").read_bytes(), stdout)
                self.assertEqual((workspace / "fixture.network-host.stderr").read_bytes(), result.stderr)
                self.assertEqual(
                    json.loads((workspace / "fixture.network-host.json").read_text())["exit_status"],
                    status,
                )

    def test_less_orchestration_cleans_environment_before_entering_minimal_guest(self) -> None:
        for filename, count in (("real-snapshot-less-protected-stage.sh", 1),
                                ("real-snapshot-less-reference.sh", 3)):
            source = (TOOLS / filename).read_text()
            commands = re.findall(
                r"timeout --signal=TERM --kill-after=5s 120s \\\n.*?\n  '\n",
                source, re.DOTALL,
            )
            self.assertEqual(len(commands), count)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                log = root / "calls"
                chroot = root / "mock-chroot"
                chroot.write_text(
                    "#!/bin/bash\nset -euo pipefail\n"
                    '[[ ! -v UNTRUSTED_TEST_ENV && $HOME == / && $LC_ALL == C ]]\n'
                    '[[ $PATH == /usr/sbin:/usr/bin:/sbin:/bin && $DPKG_COLORS == never ]]\n'
                    '[[ $DEBIAN_FRONTEND == noninteractive && $4 != *"env -i"* ]]\n'
                    '[[ $4 == *"--bounding-set=-sys_admin --no-new-privs"* ]]\n'
                    f'printf "%s\\n" "$1" >>{shlex.quote(str(log))}\n'
                )
                chroot.chmod(0o755)
                setup = """
source=/unit-source
script_root=/unit-script
dpkg_root=/unit-dpkg
post_dpkg=/unit-postinst-dpkg
timeout() { while [[ $1 != unshare ]]; do shift; done; "$@"; }
unshare() { while [[ $1 != -- ]]; do shift; done; shift; "$@"; }
"""
                for command in commands:
                    with self.subTest(filename=filename, command=command.splitlines()[-2]):
                        command = command.replace("chroot ", shlex.quote(str(chroot)) + " ")
                        result = subprocess.run(
                            ["bash", "-euo", "pipefail", "-c", setup + command],
                            env=dict(os.environ, UNTRUSTED_TEST_ENV="must-not-enter-guest"),
                            capture_output=True, text=True,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(log.is_file(), "guest entry must receive the sanitized environment")
                self.assertEqual(len(log.read_text().splitlines()), count)

    def test_python_alternatives_fingerprint_covers_inventory_and_fails_closed_in_substitution(self) -> None:
        source = (TOOLS / "real-snapshot-python3-reference.sh").read_text()
        function = "alternatives_fingerprint() {" + source.split(
            "alternatives_fingerprint() {", 1
        )[1].split("\nbefore=$(alternatives_fingerprint", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "var/lib/dpkg/alternatives"
            selectors = root / "etc/alternatives"
            records.mkdir(parents=True)
            selectors.mkdir(parents=True)
            (root / "usr/bin").mkdir(parents=True)
            (root / "usr/bin/python3").symlink_to("python3.14")
            (records / "editor").write_bytes(b"unchanged record\n")
            (selectors / "editor").symlink_to("/usr/bin/editor")
            def fingerprint() -> subprocess.CompletedProcess:
                return subprocess.run(
                    ["bash", "-euo", "pipefail", "-c",
                     function + '\nvalue=$(alternatives_fingerprint "$1")\nprintf "%s\\n" "$value"\n',
                     "python-alternatives-fingerprint-test", str(root)],
                    capture_output=True, text=True,
                )
            original = fingerprint()
            self.assertEqual(original.returncode, 0, original.stderr)
            (records / "pager").write_bytes(b"additional record\n")
            changed = fingerprint()
            self.assertEqual(changed.returncode, 0, changed.stderr)
            self.assertNotEqual(original.stdout, changed.stdout)
            (records / "pager").unlink()
            (selectors / "editor").unlink()
            (selectors / "editor").symlink_to("/usr/bin/other-editor")
            self.assertNotEqual(original.stdout, fingerprint().stdout)
            for mutation in ("missing-records", "missing-selectors", "missing-python-link"):
                with self.subTest(mutation=mutation):
                    if mutation == "missing-records":
                        records.rename(records.with_name("saved-records"))
                    elif mutation == "missing-selectors":
                        selectors.rename(selectors.with_name("saved-selectors"))
                    else:
                        (root / "usr/bin/python3").unlink()
                    result = fingerprint()
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(result.stdout, "")
                    if mutation == "missing-records":
                        records.with_name("saved-records").rename(records)
                    elif mutation == "missing-selectors":
                        selectors.with_name("saved-selectors").rename(selectors)

    def test_selected_prestate_origins_require_all_fresh_authenticated_witnesses(self) -> None:
        source = (TOOLS / "real-snapshot-signed-proc-prestates.sh").read_text()
        predicate = re.search(r"jq -e --arg release .*? '\n(.*?)\n' \"\$lock\"",
                              source, re.DOTALL).group(1)
        pins = {name: re.search(rf"^readonly {name}=([a-f0-9]+)$", source, re.MULTILINE).group(1)
                for name in ("release_sha256", "updates_release_sha256",
                             "security_release_sha256", "release_signer")}
        repositories = [
            {"id": character * 64, "snapshot_sha256": str(index) * 64,
             "release_sha256": pins[name], "index_identity": {"primary": "sha256"},
             "signer_fingerprints": [pins["release_signer"]]}
            for index, (character, name) in enumerate((
                ("a", "release_sha256"), ("b", "updates_release_sha256"),
                ("c", "security_release_sha256")), 1)
        ]
        sources = [
            {"package": entry["id"], "repository": {
                "release_digest": "sha256:" + entry["release_sha256"],
                "snapshot_digest": "sha256:" + entry["snapshot_sha256"],
                "signer_fingerprints": entry["signer_fingerprints"], "frozen": None}}
            for entry in repositories
        ]
        sources[0]["repository"]["frozen"] = {
            "release_digest": "sha256:" + pins["release_sha256"],
            "witnesses": [
                {"repository_id": item["package"],
                 "snapshot_digest": item["repository"]["snapshot_digest"],
                 "primary_fingerprint": pins["release_signer"]}
                for item in sources[1:]
            ],
        }
        versions = json.loads((TOOLS / "fixtures/real-snapshot/pin-v1.json").read_text())[
            "snapshot"]["closures"]["amd64"]["packages"]
        lock = {
            "schema": "https://debz.dev/schema/exact-closure-lock-v3", "version": 3,
            "target_architecture": "amd64", "repositories": repositories,
            "packages": [
                {"name": name, "version": versions[name], "architecture": "amd64",
                 "archive_identity": {"primary": "sha512", "digests": [
                     {"algorithm": "sha512", "digest": hashlib.sha512(name.encode()).hexdigest()}]}}
                for name in ("systemd", "udev", "sudo", "sudo-rs", "util-linux", "libcap-ng0")
            ],
        }
        report = {"schema": "io.github.cataggar.debz.command.v1", "api_version": 1,
                  "operation": "refresh", "exit_status": 0, "items": sources}
        arguments = []
        for flag, name in (("release", "release_sha256"), ("updates", "updates_release_sha256"),
                           ("security", "security_release_sha256"), ("signer", "release_signer")):
            arguments.extend(("--arg", flag, pins[name]))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def check(candidate: dict, admission: dict) -> subprocess.CompletedProcess:
                (root / "lock.json").write_text(json.dumps(candidate))
                (root / "refresh.json").write_text(json.dumps(admission))
                return subprocess.run(
                    ["jq", "-e", *arguments, "--slurpfile", "refreshed",
                     str(root / "refresh.json"), predicate, str(root / "lock.json")],
                    capture_output=True, text=True,
                )
            for count in (2, 3):
                with self.subTest(selected=count):
                    candidate = dict(lock, repositories=repositories[:count])
                    result = check(candidate, report)
                    self.assertEqual(result.returncode, 0, result.stderr)
            for mutation in ("missing-witness", "unknown-signer", "changed-witness",
                             "changed-id", "changed-snapshot", "unknown-release",
                             "duplicate-origin", "missing-base", "extra-source", "failed-refresh"):
                with self.subTest(mutation=mutation):
                    candidate = json.loads(json.dumps(dict(lock, repositories=repositories[:2])))
                    admission = json.loads(json.dumps(report))
                    if mutation == "missing-witness":
                        admission["items"].pop()
                    elif mutation == "unknown-signer":
                        admission["items"][2]["repository"]["signer_fingerprints"] = ["0" * 40]
                    elif mutation == "changed-witness":
                        admission["items"][0]["repository"]["frozen"]["witnesses"][0][
                            "snapshot_digest"] = "sha256:" + "0" * 64
                    elif mutation == "changed-id":
                        candidate["repositories"][0]["id"] = "0" * 64
                    elif mutation == "changed-snapshot":
                        candidate["repositories"][0]["snapshot_sha256"] = "0" * 64
                    elif mutation == "unknown-release":
                        candidate["repositories"][0]["release_sha256"] = "0" * 64
                    elif mutation == "duplicate-origin":
                        candidate["repositories"][1] = candidate["repositories"][0]
                    elif mutation == "missing-base":
                        candidate["repositories"] = repositories[1:]
                    elif mutation == "extra-source":
                        admission["items"].append(admission["items"][0])
                    else:
                        admission["exit_status"] = 4
                    result = check(candidate, admission)
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_protected_staging_plan_and_download_use_separate_single_root_locks(self) -> None:
        source = (TOOLS / "real-snapshot-reference-protected-stage.sh").read_text()
        selection = 'closure_args=("$closure_root")' + source.split(
            'closure_args=("$closure_root")', 1
        )[1].split("\nexport PATH=", 1)[0]
        calls = "debz_step plan plan " + source.split(
            "debz_step plan plan ", 1
        )[1].split("\ntemplate=", 1)[0]
        setup = """
closure_root=dpkg
purpose=$1
architecture=$2
snapshot=/protected-test/snapshot
lock=/protected-test/runtime.lock.json
evidence=/protected-test/evidence
authenticated_lock() { :; }
debz_step() { printf '%s\\t' "$@"; printf '\\n'; }
"""
        for purpose, architecture in (("proof", "amd64"), ("proof", "arm64"),
                                       ("arm64-less", "arm64"), ("arm64-bash", "arm64")):
            with self.subTest(purpose=purpose, architecture=architecture):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", setup + selection + "\n" + calls,
                     "protected-staging-roots-test", purpose, architecture],
                    check=True, capture_output=True, text=True,
                )
                rows = [line.rstrip("\t").split("\t") for line in result.stdout.splitlines()]
                goals = (("dpkg", "less", "dash", "util-linux") if purpose == "arm64-less" else
                         ("dpkg", "bash", "dash", "util-linux") if purpose == "arm64-bash" else ("dpkg",))
                self.assertEqual(len(rows), 2 * len(goals))
                for index, package in enumerate(goals):
                    for offset, command in enumerate(("plan", "download")):
                        row = rows[2 * index + offset]
                        name = command if package == "dpkg" else f"{package}-{command}"
                        self.assertEqual(row[:2], [name, command])
                        self.assertEqual(row[7:], [package])
                        expected_lock = ("/protected-test/runtime.lock.json" if package == "dpkg"
                                         else f"/protected-test/evidence/{package}.lock.json")
                        self.assertEqual(row[6], expected_lock)

    def test_less_reference_pins_use_separate_locks_and_retain_combined_lock_support(self) -> None:
        stage = load("debz_less_source_lock_pins", "real_snapshot_less_stage.py")
        source = (TOOLS / "real-snapshot-less-reference.sh").read_text()
        checks = "require_lock_artifact() {" + source.split(
            "require_lock_artifact() {", 1
        )[1].split("\n[[ $(stat -c '%s'", 1)[0]
        records = {
            name: {"name": name, "version": version, "architecture": "arm64",
                   "declared_size": size, "origin": {"type": "authenticated_repository"},
                   "archive_identity": {"primary": "sha512", "digests": [
                       {"algorithm": "sha512", "digest": digest}]}}
            for name, (version, size, digest) in stage.SOURCE_ARTIFACTS.items()
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for separate in (False, True):
                with self.subTest(separate=separate):
                    runtime = [records[name] for name in ("dpkg", "libc6")] if separate else list(records.values())
                    (root / "runtime.json").write_text(json.dumps({"packages": runtime}))
                    (root / "less.json").write_text(json.dumps({"packages": [records["less"]]}))
                    (root / "dash.json").write_text(json.dumps({"packages": [records["dash"]]}))
                    setup = """
lock=$1/runtime.json
less_lock=$lock
dash_lock=$lock
if [[ $2 == separate ]]; then
  less_lock=$1/less.json
  dash_lock=$1/dash.json
fi
"""
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", setup + checks,
                         "less-reference-source-locks-test", str(root),
                         "separate" if separate else "combined"],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    wrong = dict(records["dash"], declared_size=records["dash"]["declared_size"] + 1)
                    if separate:
                        (root / "dash.json").write_text(json.dumps({"packages": [wrong]}))
                    else:
                        (root / "runtime.json").write_text(json.dumps({
                            "packages": [wrong if entry["name"] == "dash" else entry for entry in runtime]}))
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", setup + checks,
                         "less-reference-source-locks-test", str(root),
                         "separate" if separate else "combined"],
                        capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_binding_step_failure_reports_stage_preserves_exit_and_raw_evidence(self) -> None:
        source = (TOOLS / "real-snapshot-signed-proc-bindings.sh").read_text()
        loop = "for step in refresh plan download; do" + source.split(
            "for step in refresh plan download; do", 1
        )[1].split("\ndone\n", 1)[0] + "\ndone\n"
        setup = """
snapshot=$1
fail_step=$2
lock=$snapshot/evidence/ubuntu-minimal.lock.json
debz=unused-test-binary
common=()
timeout() {
  printf '%s\\n' "$5" >>"$snapshot/calls"
  printf '{"stage":"%s"}\\n' "$5"
  printf 'raw diagnostic for %s\\n' "$5" >&2
  [[ "$5" != "$fail_step" ]] || return 6
}
"""
        for failed in ("refresh", "plan", "download", ""):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "evidence").mkdir()
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", setup + loop,
                     "signed-binding-diagnostic-test", str(root), failed],
                    capture_output=True, text=True,
                )
                steps = ["refresh", "plan", "download"]
                attempted = steps[:steps.index(failed) + 1] if failed else steps
                self.assertEqual(result.returncode, 6 if failed else 0, result.stderr)
                self.assertEqual((root / "calls").read_text().splitlines(), attempted)
                for step in attempted:
                    self.assertEqual((root / f"evidence/{step}.json").read_text(),
                                     f'{{"stage":"{step}"}}\n')
                    self.assertEqual((root / f"evidence/{step}.stderr").read_text(),
                                     f"raw diagnostic for {step}\n")
                if failed:
                    self.assertIn(f"signed proc bindings {failed} failed with exit 6", result.stderr)
                else:
                    self.assertEqual(result.stderr, "")

    def test_signed_sudo_binding_list_preserves_original_archive_member_order(self) -> None:
        source = (TOOLS / "real-snapshot-signed-proc-bindings.sh").read_text()
        prefix = "awk -F'\\t' '$1 == \"sudo\""
        command = prefix + source.split(prefix, 1)[1].split("\nchmod 0644", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "var/lib/dpkg/info").mkdir(parents=True)
            (root / "members.tsv").write_text(
                "sudo\t\nsudo\tusr\nother\tunrelated\nsudo\tusr/bin/z\nsudo\tusr/bin/a\n"
            )
            subprocess.run(
                ["bash", "-euo", "pipefail", "-c",
                 'source_root=$1\nlisting=$1/members.tsv\n' + command,
                 "signed-sudo-binding-list-test", str(root)],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual((root / "var/lib/dpkg/info/sudo.list").read_bytes(),
                             b"/.\n/usr\n/usr/bin/z\n/usr/bin/a\n")

    def test_list_preparation_cannot_normalize_or_rewrite_authenticated_original_bytes(self) -> None:
        audit = load("debz_original_fixture_list_guards", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        for path, read, listing in (
            ("tools/real_snapshot_less_stage.py", "        content = os.read(descriptor, 2048)\n",
             "var/lib/dpkg/info/less.list"),
            ("tools/real_snapshot_python_fixtures.py", "        content = read_regular(root, relative, 2048)\n",
             "var/lib/dpkg/info/python3.list"),
        ):
            for mutation in (
                '        content = b"".join(sorted(content.splitlines(keepends=True)))\n',
                f'        overwrite_regular(root, "{listing}", content)\n',
            ):
                with self.subTest(path=path, mutation=mutation):
                    self.assertIn(read, texts[path])
                    changed = dict(texts)
                    changed[path] = changed[path].replace(read, read + mutation, 1)
                    self.assertTrue(any("retain authenticated original bytes without rewriting" in failure
                                        for failure in audit.protected_reference_ci_failures(changed)))
        path = "tools/real-snapshot-signed-proc-bindings.sh"
        output = "sed 's#^/$#/.#' \\\n" + '  >"$source_root/var/lib/dpkg/info/sudo.list"\n'
        for mutation in (
            "sed 's#^/$#/.#' |\n" + '  LC_ALL=C sort >"$source_root/var/lib/dpkg/info/sudo.list"\n',
            "sed 's#^/$#/.#' \\\n" + '  >"$source_root/var/lib/dpkg/info/sudo.list.sorted"\n',
        ):
            with self.subTest(path=path, mutation=mutation):
                changed = dict(texts)
                self.assertIn(output, changed[path])
                changed[path] = changed[path].replace(output, mutation, 1)
                subprocess.run(["bash", "-n"], input=changed[path], text=True,
                               check=True, capture_output=True)
                self.assertIn("signed sudo binding list must retain authenticated archive member order",
                              audit.protected_reference_ci_failures(changed))
        path = "tools/real-snapshot-signed-proc-prestates.sh"
        read = 'require_protected_file "$list"\n'
        for mutation in ('LC_ALL=C sort -- "$list" >"$list.sorted"\n',
                         'mv -- "$list.sorted" "$list"\n',
                         'printf changed >"$list"\n'):
            with self.subTest(path=path, mutation=mutation):
                changed = dict(texts)
                self.assertIn(read, changed[path])
                changed[path] = changed[path].replace(read, read + mutation, 1)
                self.assertTrue(any("retain authenticated original bytes without rewriting" in failure
                                    for failure in audit.protected_reference_ci_failures(changed)))

    def test_receipt_and_python_premutation_guards_cannot_be_removed(self) -> None:
        audit = load("debz_receipt_python_guards", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        for path, token in (
            ("src/native_alternatives.zig",
             '        try testing.expectEqualDeep(listed.names, listed_after.names);\n'),
            ("src/native_alternatives.zig",
             '        try validateScriptTransition(testing.allocator, before, same, script, authority);\n'),
            ("src/native_alternatives.zig",
             '        try validateScriptTransition(testing.allocator, after, after_same, script, authority);\n'),
            ("src/native_alternatives.zig",
             '            try testing.expectEqualDeep(old_group.record, new_group.record);\n'),
            ("src/native_alternatives.zig",
             '            try testing.expectEqualDeep(old_group.links, new_group.links);\n'),
            ("src/native_alternatives.zig",
             '                try testing.expect(testClonedEntryFactEqual(left, right));\n'),
            ("src/native_alternatives.zig",
             '        errdefer |err| std.debug.print(\n'),
            ("src/native_alternatives.zig",
             '        .{ "DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_ROOT_0644", "DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_AFTER_0644" },\n'),
            ("tools/real-snapshot-less-protected-stage.sh",
             '    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \\\n'),
            ("tools/real-snapshot-less-reference.sh",
             '    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \\\n'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             'require_protected_file "$snapshot/evidence/refresh.json"\n'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             '  --slurpfile refreshed "$snapshot/evidence/refresh.json"'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             '  ([$frozen.witnesses[].repository_id] | sort) =='),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             '      .repository.snapshot_digest == ("sha256:" + $repository.snapshot_sha256)'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             '      .repository.release_digest == ("sha256:" + $repository.release_sha256)'),
            ("tools/real-snapshot-reference-protected-stage.sh",
             '  for package in "${packages[@]}"; do'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             'actual_record=$(LC_ALL=C sort -- "$prestates/prestates.tsv")\n'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             '[[ $actual_record == "$expected_record" ]] || {\n'),
            ("tools/real-snapshot-signed-proc-prestates.sh",
             '  require_control "$target" "usr/bin/setpriv:47576:755:$setpriv_sha256"\n'),
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
            ("src/native_unpack.zig", '    try verifySnapshotLessArm64Inputs(testing.allocator, root.root, &artifacts, "arm64", .preinst);\n'),
            ("src/native_unpack.zig", '        try testing.expectEqualDeep(before.record, after.record);\n'),
            ("src/native_unpack.zig", '        try proof.writeStreamingAll(testing.io, "signed arm64 less eight replay roots executed without skips\\n");\n'),
            ("tools/real-snapshot-reference-protected-ci.sh", '"$zig" build test-real-snapshot-arm64-less-protected'),
            ("tools/real_snapshot_less_stage.py", '        for package in SOURCE_ARTIFACTS:\n            archive(locks["dpkg" if package == "libc6" else package], cache, package)\n'),
        ):
            with self.subTest(token=token):
                self.assertIn(token, texts[path])
                changed = dict(texts)
                changed[path] = texts[path].replace(token, "", 1)
                self.assertTrue(audit.protected_reference_ci_failures(changed))

    def test_arm_bash_receipt_requires_actual_native_callback_and_independent_oracle(self) -> None:
        audit = load("debz_arm_bash_activation_policy", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        for path, token in (
            ("src/native_unpack.zig", 'try verifySnapshotBashArm64Inputs(allocator, root, program.artifacts, program.target_architecture);'),
            ("src/native_unpack.zig", 'native_alternatives.matchesSnapshotBashPostinst(script_bytes))\n            verifySnapshotBashArm64Inputs('),
            ("src/native_unpack.zig", 'try verifySnapshotBashArm64Inputs(testing.allocator, native.root, &artifacts, "arm64");'),
            ("src/native_unpack.zig", 'try testing.expectEqualStrings("/usr/share/man/man7/bash-builtins.7.gz", actual.selected);'),
            ("tools/real-snapshot-bash-protected-stage.sh", '"$zig" build test-real-snapshot-arm64-bash-source-protected'),
            ("tools/real-snapshot-bash-protected-stage.sh", "--force-depends --no-triggers --configure bash"),
            ("tools/real-snapshot-reference-protected-ci.sh", '"$zig" build test-real-snapshot-arm64-bash-postinst-protected'),
        ):
            with self.subTest(path=path, token=token):
                self.assertIn(token, texts[path])
                changed = dict(texts)
                changed[path] = texts[path].replace(token, "", 1)
                self.assertTrue(audit.protected_reference_ci_failures(changed))

    def test_arm_less_postinst_receipt_requires_actual_callback_inputs_transition_and_oracle(self) -> None:
        audit = load("debz_arm_less_postinst_policy", "security-audit.py")
        texts = {path: (TOOLS.parent / path).read_text() for path in audit.PROTECTED_REFERENCE_PATHS}
        self.assertEqual(audit.protected_reference_ci_failures(texts), [])
        path = "src/native_unpack.zig"
        source = texts[path]
        start = source.index('test "native_unpack.test.protected signed arm64 less postinst runs natively and matches pinned dpkg"')
        end = source.index("\nfn prepareAlternativesScriptBoundary(", start)
        body = source[start:end]
        for token in (
            "maintainer_script.run(testing.allocator,",
            ".policy = lifecycleInvocationPolicy(false, false, false)",
            "try testing.expect(report.succeeded());",
            'try verifySnapshotLessArm64Inputs(testing.allocator, native.root, &artifacts, "arm64", .postinst);',
            "native_alternatives.validateScriptTransition(",
            "try testing.expectEqualDeep(actual.record, expected.record);",
        ):
            with self.subTest(token=token):
                self.assertIn(token, body)
                changed = dict(texts)
                changed[path] = source.replace(body, body.replace(token, "", 1), 1)
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


class SignedBindingSummaryTests(unittest.TestCase):
    def test_gate_reads_actual_test_result_not_opaque_env_build_summary(self) -> None:
        workflow = (TOOLS.parent / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - name: Execute signed binding refusal fixtures\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        gate = next(line.strip() for line in step.splitlines() if "grep -Eq" in line)
        command = shlex.split(gate)
        cases = (
            ("56 passed; 3 skipped; 0 failed.\nBuild Summary: 13/13 steps succeeded\n"
             "+- run env success 4s\n", True),
            ("56 passed; 4 skipped; 0 failed.\n+- run env success 4s\n", False),
            ("55 passed; 3 skipped; 1 failed.\n+- run env success 4s\n", False),
            ("Build Summary: 13/13 steps succeeded\n+- run env success 4s\n", False),
            ("0 passed; 3 skipped; 0 failed.\n+- run env success 4s\n", False),
        )
        with tempfile.TemporaryDirectory(prefix="debz-signed-summary-test-") as temporary:
            log = Path(temporary) / "signed-bindings.log"
            for contents, accepted in cases:
                with self.subTest(contents=contents):
                    log.write_text(contents)
                    result = subprocess.run(
                        [*command[:-1], str(log)], capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0 if accepted else 1, result.stderr)


class NativeEvidenceExportTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-native-export-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "evidence"
        self.target = self.root / "upload"
        self.source.mkdir()
        self.target.mkdir()
        wrapper = (TOOLS / "real-snapshot-protected-native-ci.sh").read_text()
        self.exporter = wrapper.split(
            'python3 -I - "$evidence" "$upload" <<\'PY\'\n', 1
        )[1].split("\nPY\n", 1)[0]
        self.candidate = self.root / "candidate"
        self.namespace = self.candidate / "var/lib/debz"
        self.namespace.mkdir(parents=True)
        self.collector = wrapper.split(
            '<<\'PY\' || coordination_status=$?\n', 1
        )[1].split("\nPY\n", 1)[0]

    def export(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-", str(self.source), str(self.target)],
            input=self.exporter, capture_output=True, text=True, timeout=30,
        )

    def verify_index(self) -> None:
        rows = (self.target / "SHA256SUMS").read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, relative = row.split("  ", 1)
            self.assertEqual(
                hashlib.sha256((self.target / relative).read_bytes()).hexdigest(),
                digest,
            )

    def test_native_export_retains_raw_failure_bytes_and_nested_staging(self) -> None:
        files = {
            "create.json": b'{"exit_status":8,"changed":true}\n',
            "create.stderr": b"original native refusal\x00\xff\n",
            "staging/compiler.txt": b"original compiler provenance\n",
        }
        for relative, payload in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative, payload in files.items():
            self.assertEqual((self.target / relative).read_bytes(), payload)
        self.assertEqual(
            (self.target / "artifact-summary.txt").read_text(),
            f"bytes_before_index={sum(map(len, files.values()))}\n",
        )
        self.assertFalse((self.target / "export-failure.txt").exists())
        self.verify_index()

    def test_native_export_refuses_symlinked_files_and_directories(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"must not be exported\n")
        for destination in (outside / "secret", outside):
            with self.subTest(destination=destination):
                link = self.source / "untrusted"
                link.symlink_to(destination)
                result = self.export()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe or oversized evidence member", result.stderr)
                self.assertIn(
                    "unsafe or oversized evidence member",
                    (self.target / "export-failure.txt").read_text(),
                )
                self.assertFalse((self.target / "untrusted").exists())
                self.verify_index()
                link.unlink()

    def test_native_export_refuses_oversized_input_and_indexes_failure(self) -> None:
        with (self.source / "oversized").open("wb") as payload:
            payload.truncate(128 * 1024 * 1024 + 1)
        result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe or oversized evidence member", result.stderr)
        self.assertFalse((self.target / "oversized").exists())
        self.assertTrue((self.target / "export-failure.txt").is_file())
        self.verify_index()


    def capture(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-", str(TOOLS), str(self.candidate), str(self.source)],
            input=self.collector, capture_output=True, text=True, timeout=30,
        )

    def inventory(self) -> dict:
        return json.loads((self.source / "native-coordination-inventory-v1.json").read_bytes())

    def test_failed_attempt_original_coordinates_survive_export_without_blobs(self) -> None:
        files = {
            "root-operation-v1.json": b'{"phase":"script","disposition":"recovery_required"}\n',
            "native-execution-progress-v1.log": b'{"records":[{"action":{"program_step":123},"stage":"prepared"}]}\n',
            "native-transaction-program-v3.json": b'{"steps":[{"package":"original-package","kind":"preinst"}]}\n',
            "native-lifecycle-script-v1.json": b"original unresolved callback\x00\xff\n",
        }
        for name, payload in files.items():
            (self.namespace / name).write_bytes(payload)
        (self.namespace / "native-recovery-v1-blob-unselected").write_bytes(b"not a coordination document")
        result = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = self.inventory()
        self.assertTrue(inventory["capture_complete"])
        self.assertEqual({row["source"].split("/")[-1] for row in inventory["files"] if row["status"] == "present"}, set(files))
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, payload in files.items():
            self.assertEqual((self.target / "native-coordination" / name).read_bytes(), payload)
        self.assertFalse((self.target / "native-coordination/native-recovery-v1-blob-unselected").exists())
        self.verify_index()

    def test_absent_early_prestate_is_explicit_not_reconstructed(self) -> None:
        self.namespace.rmdir()
        result = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = self.inventory()
        self.assertTrue(inventory["capture_complete"])
        self.assertTrue(inventory["files"])
        self.assertTrue(all(row["status"] == "absent" for row in inventory["files"]))
        self.assertEqual(list((self.source / "native-coordination").iterdir()), [])

    def test_capture_never_follows_output_alias_or_overwrites_previous_inventory(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        original = self.source
        self.source = self.root / "output-alias"
        self.source.symlink_to(outside, target_is_directory=True)
        result = self.capture()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])
        self.source = original
        self.assertEqual(self.capture().returncode, 0)
        inventory = (self.source / "native-coordination-inventory-v1.json").read_bytes()
        result = self.capture()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.source / "native-coordination-inventory-v1.json").read_bytes(), inventory)

    def test_symlinked_ancestor_or_leaf_refuses_without_exporting_external_bytes(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "native-execution-progress-v1.log").write_bytes(b"external bytes")
        for ancestor in (False, True):
            with self.subTest(ancestor=ancestor), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                self.source = Path(temporary)
                if ancestor:
                    self.namespace.rmdir()
                    self.namespace.symlink_to(outside, target_is_directory=True)
                else:
                    (self.namespace / "native-execution-progress-v1.log").symlink_to(outside / "native-execution-progress-v1.log")
                result = self.capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.inventory()["capture_complete"])
                self.assertFalse((self.source / "native-coordination/native-execution-progress-v1.log").exists())
                if ancestor:
                    self.namespace.unlink()
                    self.namespace.mkdir()
                else:
                    (self.namespace / "native-execution-progress-v1.log").unlink()

    def test_nonregular_hardlinked_and_oversized_members_refuse_without_blocking(self) -> None:
        for kind in ("fifo", "hardlink", "oversized"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                self.source = Path(temporary)
                member = self.namespace / "native-execution-progress-v1.log"
                if kind == "fifo":
                    os.mkfifo(member)
                elif kind == "hardlink":
                    outside = self.root / "external"
                    outside.write_bytes(b"external bytes")
                    os.link(outside, member)
                else:
                    with member.open("wb") as payload:
                        payload.truncate(128 * 1024 * 1024 + 1)
                result = self.capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe or oversized native coordination member", result.stderr)
                self.assertFalse(self.inventory()["capture_complete"])
                self.assertFalse((self.source / "native-coordination/native-execution-progress-v1.log").exists())
                member.unlink()


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


class SignedLessStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-less-seal-", dir=TOOLS.parent / ".zig-cache")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.info = self.root / "var/lib/dpkg/info"
        self.info.mkdir(parents=True)
        self.lifecycle = self.root / "var/lib/debz-lifecycle-scripts"
        self.lifecycle.mkdir()
        repin = load("debz_less_original_members", "real-snapshot-repin.py")
        manifest = repin.load_json(TOOLS.parent / repin.DEFAULT_MANIFEST)
        with zipfile.ZipFile(TOOLS.parent / manifest["prestate_evidence"]) as archive:
            index = json.loads(archive.read("evidence.json"))
            source = next(item for item in index["sources"]
                          if item["architecture"] == "arm64" and item["package"] == "less")
            original = archive.read(source["archive_file"])
        (self.info / "less.list").write_bytes(repin.dpkg_ownership_list(original))
        for kind in ("preinst", "postinst"):
            script, mode = repin.tar_member(original, "control.tar", kind)
            path = self.info / f"less.{kind}"
            path.write_bytes(script)
            path.chmod(mode)
        self.stage = load("debz_less_seal", "real_snapshot_less_stage.py")

    def test_seal_retains_original_controls_and_stages_both_callbacks_exclusively(self) -> None:
        def unchanged_metadata(path: Path) -> tuple:
            metadata = path.stat()
            return path.read_bytes(), metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_nlink

        before = {path.name: unchanged_metadata(path) for path in self.info.iterdir()}
        self.stage.seal(self.root)
        for kind in ("preinst", "postinst"):
            path = self.lifecycle / f"less.{kind}"
            self.assertEqual(path.read_bytes(), before[path.name][0])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
        for path in self.info.iterdir():
            self.assertEqual(unchanged_metadata(path), before[path.name])
        with self.assertRaises(FileExistsError):
            self.stage.seal(self.root)

    def test_changed_or_symlinked_postinst_cannot_publish_callback_copies(self) -> None:
        path = self.info / "less.postinst"
        path.write_bytes(path.read_bytes() + b"unreviewed")
        with self.assertRaisesRegex(ValueError, "signed less postinst changed"):
            self.stage.seal(self.root)
        self.assertEqual(list(self.lifecycle.iterdir()), [])
        path.unlink()
        path.symlink_to(self.info / "less.preinst")
        with self.assertRaises(OSError):
            self.stage.seal(self.root)
        self.assertEqual(list(self.lifecycle.iterdir()), [])


class SignedBashStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="debz-bash-seal-", dir=TOOLS.parent / ".zig-cache")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.info = self.root / "var/lib/dpkg/info"
        self.info.mkdir(parents=True)
        self.lifecycle = self.root / "var/lib/debz-lifecycle-scripts"
        self.lifecycle.mkdir()
        repin = load("debz_bash_original_members", "real-snapshot-repin.py")
        manifest = repin.load_json(TOOLS.parent / repin.DEFAULT_MANIFEST)
        with zipfile.ZipFile(TOOLS.parent / manifest["prestate_evidence"]) as archive:
            index = json.loads(archive.read("evidence.json"))
            source = next(item for item in index["sources"]
                          if item["architecture"] == "arm64" and item["package"] == "bash")
            original = archive.read(source["archive_file"])
        (self.info / "bash.list").write_bytes(repin.dpkg_ownership_list(original))
        script, mode = repin.tar_member(original, "control.tar", "postinst")
        (self.info / "bash.postinst").write_bytes(script)
        (self.info / "bash.postinst").chmod(mode)
        self.stage = load("debz_bash_seal", "real_snapshot_less_stage.py")

    def test_successful_stage_receipt_is_accepted_only_with_zero_exit_status(self) -> None:
        stage = (TOOLS / "real-snapshot-bash-protected-stage.sh").read_text()
        receipt = stage.strip().splitlines()[-1]
        ci = (TOOLS / "real-snapshot-reference-protected-ci.sh").read_text()
        helper = re.search(r"^step\(\) \{\n.*?^\}$", ci, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(helper)
        activation = next(line for line in ci.splitlines()
                          if line.startswith("  step arm64-bash-stage "))
        arguments = shlex.split(activation.removesuffix("\\"))[:4]
        with tempfile.TemporaryDirectory(dir=TOOLS.parent / ".zig-cache") as temporary:
            environment = {**os.environ, "evidence": temporary,
                           "codes": str(Path(temporary) / "exit-codes.tsv")}
            for command, accepted in ((receipt, True), (receipt + "\nexit 1", False),
                                      ('echo "stage exited without its receipt"', False)):
                with self.subTest(command=command):
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c",
                         helper.group(0) + '\nstep "$1" "$2" "$3" bash -c "$4"\n',
                         arguments[0], *arguments[1:], command],
                        env=environment, capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_fresh_replays_preserve_existing_pinned_dpkg_directory_and_refuse_reuse(self) -> None:
        script = (TOOLS / "real-snapshot-bash-protected-stage.sh").read_text()
        copies = re.search(r"^for name in [^\n]+; do\n.*?^done$", script, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(copies)
        with tempfile.TemporaryDirectory(dir=TOOLS.parent / ".zig-cache") as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            source.mkdir()
            original = (self.info / "bash.postinst").read_bytes()
            (source / "bash.postinst").write_bytes(original)
            pinned = workspace / "dpkg/usr/bin/dpkg"
            pinned.parent.mkdir(parents=True)
            pinned.write_bytes(b"retained pinned dpkg artifact\n")
            before = (pinned.read_bytes(), pinned.stat())
            environment = {**os.environ, "workspace": str(workspace), "source": str(source)}
            command = ["bash", "-euo", "pipefail", "-c", copies.group(0)]
            subprocess.run(command, env=environment, capture_output=True, check=True, timeout=10)
            replays = [path for path in workspace.iterdir() if path.name not in ("source", "dpkg")]
            self.assertEqual(len(replays), 7)
            for replay in replays:
                self.assertEqual((replay / "bash.postinst").read_bytes(), original)
            self.assertEqual(len({(path / "bash.postinst").stat().st_ino
                                  for path in (source, *replays)}), 8)
            self.assertEqual((pinned.read_bytes(), pinned.stat()), before)
            result = subprocess.run(command, env=environment, capture_output=True,
                                    check=False, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((pinned.read_bytes(), pinned.stat()), before)

    def test_seal_preserves_original_controls_and_refuses_overwriting_staged_callback(self) -> None:
        before = {path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mode)
                  for path in self.info.iterdir()}
        self.stage.seal_bash(self.root)
        staged = self.lifecycle / "bash.postinst"
        self.assertEqual(staged.read_bytes(), before[staged.name][0])
        self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o755)
        for path in self.info.iterdir():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mode), before[path.name])
        with self.assertRaises(FileExistsError):
            self.stage.seal_bash(self.root)

    def test_altered_list_or_aliased_script_refuses_before_publishing_callback(self) -> None:
        listing = self.info / "bash.list"
        original = listing.read_bytes()
        listing.write_bytes(original + b"/unreviewed\n")
        with self.assertRaisesRegex(ValueError, "signed bash ownership path set changed"):
            self.stage.seal_bash(self.root)
        self.assertEqual(list(self.lifecycle.iterdir()), [])
        listing.write_bytes(original)
        script = self.info / "bash.postinst"
        script.unlink()
        script.symlink_to(listing)
        with self.assertRaises(OSError):
            self.stage.seal_bash(self.root)
        self.assertEqual(list(self.lifecycle.iterdir()), [])


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
