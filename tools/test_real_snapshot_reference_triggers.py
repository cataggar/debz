#!/usr/bin/env python3
"""Non-privileged pinned-dpkg trigger scheduling proof, not a privileged root run."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PINNED_DPKG = Path(
    os.environ.get("DEBZ_PINNED_DPKG_FIXTURE", "/nonexistent/pinned-dpkg")
)
EXPECTED_DPKG_SHA256 = {
    "x86_64": "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
    "aarch64": "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
}


class PinnedDpkgTriggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() == 0:
            raise RuntimeError("trigger scheduling fixture must not run as root")
        if not PINNED_DPKG.is_absolute() or PINNED_DPKG.is_symlink() or not PINNED_DPKG.is_file():
            raise FileNotFoundError("set DEBZ_PINNED_DPKG_FIXTURE to verified dpkg 1.22.22")
        expected = EXPECTED_DPKG_SHA256.get(platform.machine())
        if expected is None:
            raise RuntimeError("no native pinned dpkg trigger fixture for this architecture")
        if hashlib.sha256(PINNED_DPKG.read_bytes()).hexdigest() != expected:
            raise ValueError("pinned dpkg fixture SHA256 differs")
        result = subprocess.run(
            [str(PINNED_DPKG), "--version"], capture_output=True, text=True,
            check=True, timeout=10,
        )
        if "version 1.22.22" not in result.stdout:
            raise ValueError("unexpected pinned dpkg version")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="debz-trigger-proof-")
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.root = self.workspace / "root"
        (self.root / "var/lib/dpkg/info").mkdir(parents=True)
        (self.root / "var/lib/dpkg/updates").mkdir()
        (self.root / "var/lib/dpkg/triggers").mkdir()
        (self.root / "var/lib/dpkg/status").write_text("")
        self.admindir = self.root / "var/lib/dpkg"
        self.log = self.workspace / "scripts.log"

    def dpkg(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(PINNED_DPKG), f"--root={self.root}", "--force-not-root",
             "--force-bad-path", "--force-confold", "--force-script-chrootless",
             f"--log={self.workspace / 'dpkg.log'}",
             *arguments],
            capture_output=True, text=True, timeout=20,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                 "DEBIAN_FRONTEND": "noninteractive"},
        )
        if check and result.returncode:
            self.fail(f"pinned dpkg returned {result.returncode}: {result.stderr}")
        return result

    def package(
        self, name: str, *, cascade: bool = False, nested: bool = False,
        direct: bool = False,
    ) -> Path:
        source = self.workspace / name
        control = source / "DEBIAN"
        control.mkdir(parents=True)
        control.chmod(0o755)
        (control / "control").write_text(
            f"Package: {name}\nVersion: 1\nArchitecture: all\n"
            "Maintainer: Proof <nobody@example.invalid>\n"
            "Description: disposable unprivileged trigger fixture\n"
        )
        (control / "triggers").write_text(f"interest-noawait named-{name}\n")
        postinst = control / "postinst"
        postinst.write_text(
            "#!/bin/sh\n"
            f"[ \"$DPKG_ADMINDIR\" = '{self.admindir}' ] || exit 77\n"
            f"printf '%s\\t%s\\n' '{name}' \"$1\" >> '{self.log}'\n"
            + (f"if [ \"$1\" = triggered ]; then "
               f"dpkg-trigger --admindir='{self.admindir}' --no-await named-listener-b; fi\n"
               if cascade else "")
            + (f"if [ \"$1\" = triggered ]; then "
               f"'{PINNED_DPKG}' --root='{self.root}' --force-not-root "
               f"--force-bad-path --force-confold --force-script-chrootless "
               f"--log='{self.workspace / 'nested.log'}' "
               f"--no-triggers --triggers-only listener-b; fi\n"
               if nested else "")
            + (f"if [ \"$1\" = triggered ]; then "
               f"'{self.admindir / 'info/listener-b.postinst'}' triggered named-listener-b; fi\n"
               if direct else "")
        )
        postinst.chmod(0o755)
        (source / "usr/share").mkdir(parents=True)
        (source / "usr/share" / name).write_text(name)
        archive = self.workspace / f"{name}.deb"
        built = subprocess.run(
            ["dpkg-deb", "--build", str(source), str(archive)],
            capture_output=True, text=True, timeout=20,
        )
        if built.returncode:
            self.fail(f"dpkg-deb fixture build failed: {built.stderr}")
        return archive

    def two_pending(
        self, *, cascade: bool = False, nested: bool = False, direct: bool = False,
    ) -> None:
        for name in ("listener-a", "listener-b"):
            archive = self.package(
                name, cascade=cascade and name == "listener-a",
                nested=nested and name == "listener-a",
                direct=direct and name == "listener-a",
            )
            self.dpkg("--no-triggers", "--unpack", str(archive))
            self.dpkg("--no-triggers", "--configure", name)
        self.log.write_text("")
        for name in ("listener-a", "listener-b"):
            subprocess.run(
                ["dpkg-trigger", f"--admindir={self.admindir}",
                 "--no-await", f"named-{name}"],
                check=True, capture_output=True, timeout=10,
            )
        self.dpkg("--no-triggers", "--unpack", str(self.package("seed")))

    def test_explicit_selector_does_not_run_other_pending_script(self) -> None:
        self.two_pending()
        status = (self.admindir / "status").read_text()
        self.assertIn("Triggers-Pending: named-listener-a", status)
        self.assertIn("Triggers-Pending: named-listener-b", status)
        result = self.dpkg("--no-triggers", "--triggers-only", "listener-a", check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text(), "listener-a\ttriggered\n")
        self.assertIn("Triggers-Pending: named-listener-b", (self.admindir / "status").read_text())

    def test_named_trigger_only_does_not_drain_other_pending_listener(self) -> None:
        self.two_pending(cascade=True)
        result = self.dpkg("--triggers-only", "listener-a")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.log.read_text(), "listener-a\ttriggered\n")
        self.assertIn("Triggers-Pending: named-listener-b", (self.admindir / "status").read_text())

    def test_recursive_dpkg_cannot_process_other_listener_while_locked(self) -> None:
        self.two_pending(nested=True)
        result = self.dpkg("--no-triggers", "--triggers-only", "listener-a", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("frontend lock was locked", result.stderr)
        self.assertEqual(self.log.read_text(), "listener-a\ttriggered\n")

    def test_selected_script_can_launch_other_postinst_outside_dpkg_scheduler(self) -> None:
        self.two_pending(direct=True)
        self.dpkg("--no-triggers", "--triggers-only", "listener-a")
        self.assertEqual(
            self.log.read_text().splitlines(),
            ["listener-a\ttriggered", "listener-b\ttriggered"],
        )
        self.assertIn("Triggers-Pending: named-listener-b", (self.admindir / "status").read_text())

    def test_configure_requires_no_triggers_to_isolate_other_scripts(self) -> None:
        self.two_pending()
        self.dpkg("--no-triggers", "--configure", "seed")
        self.assertEqual(self.log.read_text(), "seed\tconfigure\n")
        status = (self.admindir / "status").read_text()
        self.assertIn("Triggers-Pending: named-listener-a", status)
        self.assertIn("Triggers-Pending: named-listener-b", status)
        self.assertEqual(self.log.read_text(), "seed\tconfigure\n")

    def test_default_configure_may_process_unselected_trigger_scripts(self) -> None:
        self.two_pending()
        self.dpkg("--configure", "seed")
        self.assertIn("listener-b\ttriggered\n", self.log.read_text())

    def test_configuring_a_pending_selector_runs_its_triggered_script(self) -> None:
        self.two_pending()
        self.dpkg("--no-triggers", "--configure", "listener-a")
        self.assertEqual(self.log.read_text(), "listener-a\ttriggered\n")
        self.assertIn("Triggers-Pending: named-listener-b", (self.admindir / "status").read_text())


if __name__ == "__main__":
    unittest.main()
