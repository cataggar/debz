"""Regression coverage for the reviewed signed proc native/proof differences."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_real_snapshot_signed_proc_compare",
    ROOT / "tools/real-snapshot-signed-proc-compare.py",
)
assert SPEC and SPEC.loader
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


def regular(data: bytes, mode: str = "0o644") -> dict[str, object]:
    return {
        "type": "file", "uid": 0, "gid": 0, "mode": mode, "links": 1,
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
    }


def md5(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


SUDO_CONF = b"Set disable_coredump false\n"
BEFORE = (
    b"Package: sudo-rs\nStatus: install ok installed\nArchitecture: amd64\n"
    b"Version: 0.2.14-1ubuntu2\n\n"
    b"Package: sudo\nStatus: install ok unpacked\nPriority: optional\n"
    b"Architecture: amd64\nVersion: 1.9.17p2-7ubuntu3\n"
    b"Conffiles:\n /etc/pam.d/sudo 0123456789abcdef0123456789abcdef\n"
    b" /etc/sudo.conf newconffile\n"
    b"Description: classic sudo\n continued line\n\n"
)
AFTER = BEFORE.replace(b"install ok unpacked", b"install ok installed").replace(
    b"/etc/sudo.conf newconffile", b"/etc/sudo.conf " + md5(SUDO_CONF).encode(),
)
DPKG_LOG = (
    b"2026-09-30 18:09:19 startup packages configure\n"
    b"2026-09-30 18:09:19 configure sudo:amd64 1.9.17p2-7ubuntu3 <none>\n"
    b"2026-09-30 18:09:19 status unpacked sudo:amd64 1.9.17p2-7ubuntu3\n"
    b"2026-09-30 18:09:19 status half-configured sudo:amd64 1.9.17p2-7ubuntu3\n"
    b"2026-09-30 18:09:19 status installed sudo:amd64 1.9.17p2-7ubuntu3\n"
)
ALTERNATIVES = b"update-alternatives 2026-09-30 18:09:17: run with --install /usr/bin/sudo sudo /usr/bin/sudo.ws 40\n"


class SignedProcCompareTests(unittest.TestCase):
    def classify(
        self,
        path: str,
        native_files: dict[str, bytes],
        proof_files: dict[str, bytes],
        target: str = "sudo",
        native_extra: dict[str, dict] | None = None,
        proof_extra: dict[str, dict] | None = None,
    ) -> str | None:
        native = {name: regular(data) for name, data in native_files.items()}
        proof = {name: regular(data) for name, data in proof_files.items()}
        native.update(native_extra or {})
        proof.update(proof_extra or {})
        pending = compare.pending_conffiles(target, native_files.get("var/lib/dpkg/status", b""))
        return compare.classify(
            target, path, native, proof,
            lambda name: native_files[name], lambda name: proof_files[name], pending,
        )

    def test_unknown_difference_is_unexpected(self) -> None:
        self.assertIsNone(self.classify("etc/shadow", {"etc/shadow": b"a"}, {"etc/shadow": b"b"}))

    def test_harness_tools_require_exact_pins(self) -> None:
        setpriv = regular(b"setpriv", "0o755")
        self.assertIsNone(self.classify("usr/bin/setpriv", {}, {}, proof_extra={"usr/bin/setpriv": setpriv}))
        setpriv["sha256"] = compare.SETPRIV_SHA256
        self.assertIsNotNone(self.classify("usr/bin/setpriv", {}, {}, proof_extra={"usr/bin/setpriv": setpriv}))
        pinned = {**regular(b"dpkg", "0o755"), "sha256": compare.PINNED_DPKG_SHA256}
        snapshot = {**regular(b"dpkg", "0o755"), "sha256": compare.SNAPSHOT_DPKG_SHA256}
        extra = {"usr/local/sbin/dpkg": pinned}
        self.assertIsNotNone(self.classify("usr/local/sbin/dpkg", {}, {}, "udev", proof_extra=extra))
        self.assertIsNone(self.classify("usr/local/sbin/dpkg", {}, {}, "systemd", proof_extra=extra))
        self.assertIsNotNone(self.classify(
            "usr/bin/dpkg", {}, {}, "systemd",
            native_extra={"usr/bin/dpkg": snapshot}, proof_extra={"usr/bin/dpkg": pinned},
        ))
        self.assertIsNone(self.classify(
            "usr/bin/dpkg", {}, {}, "sudo",
            native_extra={"usr/bin/dpkg": snapshot}, proof_extra={"usr/bin/dpkg": pinned},
        ))

    def test_dpkg_log_mentions_only_the_target_configure(self) -> None:
        native = {"var/lib/dpkg/status": BEFORE}
        self.assertIsNotNone(self.classify("var/log/dpkg.log", native, {"var/log/dpkg.log": DPKG_LOG}))
        other = DPKG_LOG + b"2026-09-30 18:09:19 status installed sudo-rs:amd64 0.2.14-1ubuntu2\n"
        self.assertIsNone(self.classify("var/log/dpkg.log", native, {"var/log/dpkg.log": other}))
        self.assertIsNone(self.classify("var/log/dpkg.log", native, {"var/log/dpkg.log": DPKG_LOG}, "udev"))

    def test_full_closure_dpkg_log_requires_unchanged_prefix_and_only_target_append(self) -> None:
        path = "var/log/dpkg.log"
        before = (
            b"2026-10-09 00:50:32 status installed sudo-rs:amd64 0.2.13-0ubuntu1.2\n"
            b"2026-10-09 00:50:33 configure sudo:amd64 1.9.17p2-1ubuntu3.1 <none>\n"
        )
        native = {path: before, "var/lib/dpkg/status": BEFORE}
        self.assertIsNotNone(self.classify(path, native, {path: before + DPKG_LOG}))
        for changed in (
            DPKG_LOG, before.replace(b"installed", b"unpacked") + DPKG_LOG,
            before + DPKG_LOG.replace(b"sudo:amd64", b"udev:amd64"),
            before + DPKG_LOG + before, before + DPKG_LOG.rstrip(b"\n"),
            before + DPKG_LOG.replace(b"1.9.17p2-7ubuntu3", b"1.9.17p2-5ubuntu1.2"),
            b"".join(before.splitlines(keepends=True)[::-1]) + DPKG_LOG,
            before + DPKG_LOG + DPKG_LOG,
            before + b"\n".join(DPKG_LOG.split(b"\n")[:-3][::-1] + DPKG_LOG.split(b"\n")[-3:]),
        ):
            self.assertIsNone(self.classify(path, native, {path: changed}))
        for changed in ({"mode": "0o600"}, {"uid": 1}, {"links": 2}):
            for side, content in (("native_extra", before), ("proof_extra", before + DPKG_LOG)):
                self.assertIsNone(self.classify(
                    path, native, {path: before + DPKG_LOG},
                    **{side: {path: {**regular(content), **changed}}},
                ))

    def test_half_configured_log_does_not_replay_an_unpacked_transition(self) -> None:
        path = "var/log/dpkg.log"
        native = {"var/lib/dpkg/status": BEFORE.replace(b"install ok unpacked", b"install ok half-configured")}
        half = DPKG_LOG.replace(
            b"2026-09-30 18:09:19 status unpacked sudo:amd64 1.9.17p2-7ubuntu3\n", b"",
        )
        self.assertIsNotNone(self.classify(path, native, {path: half}))
        self.assertIsNone(self.classify(path, native, {path: DPKG_LOG}))
        self.assertIsNone(self.classify(path, native, {path: half.replace(b" <none>", b" 1.0")}))
        installed = {"var/lib/dpkg/status": AFTER}
        self.assertIsNone(self.classify(path, installed, {path: half}))

    def test_current_authenticated_tool_descriptors_refuse_obsolete_pins(self) -> None:
        snapshot = {**regular(b"snapshot", "0o755"),
                    "sha256": "972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517"}
        pinned = {**regular(b"pinned", "0o755"), "sha256": compare.PINNED_DPKG_SHA256}
        self.assertIsNotNone(self.classify(
            "usr/bin/dpkg", {}, {}, "systemd",
            native_extra={"usr/bin/dpkg": snapshot}, proof_extra={"usr/bin/dpkg": pinned},
        ))
        stale = {**snapshot, "sha256": "6587ef9e2ef69b1a0426d69d667bfd7cbcec6c3be5f0560cc4c219f95d65739f"}
        self.assertIsNone(self.classify(
            "usr/bin/dpkg", {}, {}, "systemd",
            native_extra={"usr/bin/dpkg": stale}, proof_extra={"usr/bin/dpkg": pinned},
        ))
        setpriv = {**regular(b"setpriv", "0o755"),
                   "sha256": "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993"}
        self.assertIsNotNone(self.classify(
            "usr/bin/setpriv", {}, {}, proof_extra={"usr/bin/setpriv": setpriv},
        ))
        setpriv["sha256"] = "9e0d70d26a02c1cb4b984ab6f49a582b7a2c3508b1063ac23adc60073292ae7e"
        self.assertIsNone(self.classify(
            "usr/bin/setpriv", {}, {}, proof_extra={"usr/bin/setpriv": setpriv},
        ))

    def test_status_accepts_only_the_target_configure(self) -> None:
        files = {"var/lib/dpkg/status": BEFORE}
        proof = {"var/lib/dpkg/status": AFTER, "etc/sudo.conf": SUDO_CONF}
        self.assertIsNotNone(self.classify("var/lib/dpkg/status", files, proof))
        other = {**proof, "var/lib/dpkg/status": AFTER.replace(b"0.2.14-1ubuntu2", b"0.2.15")}
        self.assertIsNone(self.classify("var/lib/dpkg/status", files, other))
        field = {**proof, "var/lib/dpkg/status": AFTER.replace(b"Priority: optional", b"Priority: required")}
        self.assertIsNone(self.classify("var/lib/dpkg/status", files, field))
        changed = {**proof, "etc/sudo.conf": b"changed\n"}
        self.assertIsNone(self.classify("var/lib/dpkg/status", files, changed))
        self.assertIsNone(self.classify("var/lib/dpkg/status", files, proof, "udev"))
        half = BEFORE.replace(b"install ok unpacked", b"install ok half-configured")
        self.assertIsNotNone(self.classify("var/lib/dpkg/status", {"var/lib/dpkg/status": half}, proof))
        config = AFTER.replace(b"Version: 1.9.17p2-7ubuntu3\n", b"Version: 1.9.17p2-7ubuntu3\nConfig-Version: 1.0\n")
        self.assertIsNone(self.classify("var/lib/dpkg/status", files, {**proof, "var/lib/dpkg/status": config}))

    def test_status_backup_is_the_unconfigured_status(self) -> None:
        native = {"var/lib/dpkg/status": BEFORE, "var/lib/dpkg/status-old": b"older"}
        self.assertIsNotNone(self.classify("var/lib/dpkg/status-old", native, {"var/lib/dpkg/status-old": BEFORE}))
        self.assertIsNone(self.classify("var/lib/dpkg/status-old", native, {"var/lib/dpkg/status-old": AFTER}))

    def test_mount_utab_directory_must_be_empty_and_private(self) -> None:
        directory = {"type": "directory", "uid": 0, "gid": 0, "mode": "0o700"}
        self.assertIsNotNone(self.classify("run/mount", {}, {}, proof_extra={"run/mount": directory}))
        self.assertIsNone(self.classify(
            "run/mount", {}, {"run/mount/utab": b""}, proof_extra={"run/mount": directory},
        ))
        self.assertIsNone(self.classify(
            "run/mount", {}, {}, proof_extra={"run/mount": {**directory, "mode": "0o755"}},
        ))
        self.assertIsNone(self.classify(
            "run/mount", {}, {}, native_extra={"run/mount": {**directory, "mode": "0o755"}},
            proof_extra={"run/mount": directory},
        ))

    def test_machine_id_is_random_only_for_systemd(self) -> None:
        native = {"etc/machine-id": b"0123456789abcdef0123456789abcdef\n"}
        proof = {"etc/machine-id": b"fedcba9876543210fedcba9876543210\n"}
        extra = {name: regular(data, "0o444") for name, data in native.items()}
        proof_extra = {name: regular(data, "0o444") for name, data in proof.items()}
        self.assertIsNotNone(self.classify(
            "etc/machine-id", native, proof, "systemd", native_extra=extra, proof_extra=proof_extra,
        ))
        self.assertIsNone(self.classify(
            "etc/machine-id", native, proof, "udev", native_extra=extra, proof_extra=proof_extra,
        ))
        bad = {"etc/machine-id": b"uninitialized\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"}
        self.assertIsNone(self.classify(
            "etc/machine-id", native, bad, "systemd", native_extra=extra,
            proof_extra={name: regular(data, "0o444") for name, data in bad.items()},
        ))

    def test_alternatives_log_differs_only_in_timestamps(self) -> None:
        later = ALTERNATIVES.replace(b"18:09:17", b"18:09:58")
        path = "var/log/alternatives.log"
        self.assertIsNotNone(self.classify(path, {path: ALTERNATIVES}, {path: later}))
        extra = ALTERNATIVES + ALTERNATIVES.replace(b"--install", b"--remove")
        self.assertIsNone(self.classify(path, {path: ALTERNATIVES}, {path: extra}))
        changed = later.replace(b"sudo.ws", b"sudo.xy")
        self.assertIsNone(self.classify(path, {path: ALTERNATIVES}, {path: changed}))

    def test_pending_conffile_must_match_the_installed_proof_conffile(self) -> None:
        native = {"var/lib/dpkg/status": BEFORE, "etc/sudo.conf.dpkg-new": SUDO_CONF}
        proof = {"var/lib/dpkg/status": AFTER, "etc/sudo.conf": SUDO_CONF}
        self.assertEqual(compare.pending_conffiles("sudo", BEFORE), ["etc/sudo.conf"])
        for path in ("etc/sudo.conf", "etc/sudo.conf.dpkg-new"):
            self.assertIsNotNone(self.classify(path, native, proof))
        changed = {**proof, "etc/sudo.conf": b"changed\n"}
        self.assertIsNone(self.classify("etc/sudo.conf", native, changed))
        staged = {**proof, "etc/sudo.conf.dpkg-new": SUDO_CONF}
        self.assertIsNone(self.classify("etc/sudo.conf", native, staged))
        installed = {**native, "etc/sudo.conf": SUDO_CONF}
        self.assertIsNone(self.classify("etc/sudo.conf.dpkg-new", installed, proof))
        self.assertIsNone(self.classify("etc/pam.d/sudo", native, {**proof, "etc/pam.d/sudo": b"x"}))


if __name__ == "__main__":
    unittest.main()
