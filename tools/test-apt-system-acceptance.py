#!/usr/bin/env python3
"""Exercise both apt facade backends in disposable installed system roots."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time

REPOSITORY = Path(__file__).resolve().parents[1]
RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "debz_apt_disposable_root_runtime", REPOSITORY / "tools/disposable_root_runtime.py",
)
assert RUNTIME_SPEC and RUNTIME_SPEC.loader
runtime = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(runtime)
copy_program = runtime.copy_program


def run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, timeout=120, **kwargs)


def prepare_root(root: Path, executable: Path) -> None:
    architecture = run("dpkg", "--print-architecture", capture_output=True, text=True).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError(f"unsupported fixture architecture: {architecture}")
    for directory in (
        "etc/debz", "etc/apt", "var/lib/dpkg/info", "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers", "var/lib/debz", "var/cache/debz",
        "usr/share/debz", "usr/sbin", "usr/lib", "usr/lib64",
        "proc", "run", "tmp", "dev", "root",
    ):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for source, destination in (
        (executable, "/usr/bin/debz"),
        (Path("/usr/bin/dpkg"), "/usr/bin/dpkg"),
        (Path("/usr/bin/dpkg-deb"), "/usr/bin/dpkg-deb"),
        (Path("/usr/bin/dpkg-split"), "/usr/bin/dpkg-split"),
        (Path("/usr/bin/dpkg-trigger"), "/usr/bin/dpkg-trigger"),
        (Path("/usr/bin/tar"), "/usr/bin/tar"),
        (Path("/bin/sh"), "/bin/sh"),
    ):
        copy_program(root, source, destination)
    for helper in ("ldconfig", "start-stop-daemon", "rm", "diff"):
        source = shutil.which(helper)
        if source is None:
            raise RuntimeError(f"dpkg fixture requires {helper}")
        copy_program(root, Path(source), f"/usr/sbin/{helper}")
    (root / "usr/bin/gtar").symlink_to("tar")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (root / "etc/group").write_text("root:x:0:\n")
    (root / "etc/os-release").write_text('ID=debian\nNAME="debz disposable fixture"\n')
    (root / "var/lib/dpkg/status").write_text("")
    for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
        os.mknod(root / "dev" / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
    run(
        sys.executable, str(REPOSITORY / "tools/generate-integration-repository.py"),
        "--output", str(root / "repository"), "--suite", "debian-stable",
        "--architecture", architecture,
    )
    (root / "etc/debz/fixture.sources").write_text(
        "Types: deb\nURIs: file:///repository\nSuites: debian-stable\n"
        f"Components: main\nArchitectures: {architecture}\n"
        "Signed-By: /repository/fixture-keyring.gpg\n"
    )
    (root / "etc/debz/default.json").write_text(json.dumps({
        "schema": "https://debz.dev/schema/system-profile-v1",
        "version": 1,
        "repositories": [{"source_path": "/etc/debz/fixture.sources"}],
        "keyring_paths": ["/repository/fixture-keyring.gpg"],
        "architecture": architecture,
        "repository_policy": "strict_priority",
        "default_conffile": "keep_existing",
    }))
    (root / "etc/apt/sources.list").write_text("invalid ambient apt source\n")
    (root / "etc/apt/apt.conf").write_text("invalid ambient apt configuration\n")


def inside(root: Path, backend: str) -> None:
    root = root.resolve(strict=True)
    if (
        os.getpid() != 1
        or root.name != "root"
        or root.parent.parent != (REPOSITORY / ".zig-cache").resolve()
        or not root.parent.name.startswith("apt-system-acceptance-")
    ):
        raise RuntimeError("internal acceptance entry requires a disposable root and private PID namespace")
    run("mount", "--bind", str(root), str(root))
    run("mount", "-t", "proc", "proc", str(root / "proc"))
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "APT_CONFIG": "/etc/apt/apt.conf",
        "http_proxy": "http://invalid-ambient-proxy.invalid:9",
        "https_proxy": "http://invalid-ambient-proxy.invalid:9",
    }
    # Start with an existing dpkg installation, not the empty-root bootstrap path.
    essential_packages = list((root / "repository/pool/main").glob("essential-core_*.deb"))
    assert len(essential_packages) == 1, essential_packages
    run(
        "chroot", str(root), "/usr/bin/dpkg", "--install",
        "/" + str(essential_packages[0].relative_to(root)),
        env=environment, capture_output=True,
    )
    if backend == "native":
        for name in ("dpkg", "dpkg-deb", "dpkg-split"):
            program = root / "usr/bin" / name
            program.rename(program.with_suffix(".disabled"))
    helper_path = root / "usr/bin/dpkg-trigger"
    helper_digest = hashlib.sha256(helper_path.read_bytes()).digest()
    status_path = root / "var/lib/dpkg/status"
    state_path = root / "var/lib/debz"
    initial_status = status_path.read_bytes()
    mountinfo = Path("/proc/self/mountinfo").read_bytes()

    def cli(*args: str, expected: int = 0) -> dict:
        result = subprocess.run(
            ["chroot", str(root), "/usr/bin/debz", *args],
            env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False,
        )
        assert Path("/proc/self/mountinfo").read_bytes() == mountinfo, "live-root mount leaked"
        if result.returncode != expected:
            for name in (
                "transaction.journal", "root-operation-v1.json",
                "root-operation-completion-v1.json", "root-operation-completion-v2.json",
                "root-operation-deferred-ack-v1.json",
                "native-transaction-provenance-v1.json", "native-transaction-provenance-v2.json",
                "apt/active-operation-v1.json",
            ):
                evidence_file = state_path / name
                if evidence_file.is_file():
                    with evidence_file.open("rb") as stream:
                        print(name, stream.read(4096), file=sys.stderr)
        assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
        assert not result.stderr, (args, result.stderr)
        assert result.stdout.count(b"\n") == 1, (args, result.stdout)
        document = json.loads(result.stdout)
        if args[0] != "transaction-result":
            assert document["exit_status"] == expected, document
        return document

    def apt(*args: str, expected: int = 0) -> dict:
        profile = ("--profile", "/etc/debz/native-v2.json") if backend == "native" else ()
        return cli("apt", *profile, "--json", *args, expected=expected)

    def confirm_recovery(expected: int) -> None:
        master, slave = pty.openpty()
        output = bytearray()
        confirmed = False
        deadline = time.monotonic() + 60
        try:
            with subprocess.Popen(
                ["chroot", str(root), "/usr/bin/debz", "recover",
                 "--system-profile", "/etc/debz/native-v2.json"],
                env=environment, stdin=slave, stdout=slave, stderr=slave,
            ) as process:
                os.close(slave)
                slave = -1
                try:
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError(f"recovery confirmation timed out: {output!r}")
                        if not select.select([master], [], [], remaining)[0]:
                            continue
                        try:
                            chunk = os.read(master, 4096)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            break
                        if not chunk:
                            break
                        output.extend(chunk)
                        assert len(output) <= 65536, output
                        if not confirmed and b"Proceed with this reviewed recovery action? [y/N]" in output:
                            os.write(master, b"y\n")
                            confirmed = True
                    assert process.wait(timeout=10) == expected, output
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=10)
        finally:
            os.close(master)
            if slave != -1:
                os.close(slave)
        assert confirmed, output
        assert Path("/proc/self/mountinfo").read_bytes() == mountinfo, "live-root mount leaked"

    # Invalid syntax must not even create the profile's state hierarchy.
    for args in (("install", "--unsupported", "base-dep"), ("install", "base-dep", "base-dep")):
        apt(*args, expected=2)
        assert status_path.read_bytes() == initial_status
        assert not list(state_path.iterdir())
        assert not list((root / "var/cache/debz").iterdir())
        assert not (root / "run/debz").exists()

    native_profile = json.loads((root / "etc/debz/default.json").read_text())
    native_profile.update(
        schema="https://debz.dev/schema/system-profile-v2",
        version=2, transaction_backend="native",
    )
    (root / "etc/debz/native-v2.json").write_text(json.dumps(native_profile))
    invalid_profile = {**native_profile, "transaction_backend": "unsupported"}
    (root / "etc/debz/invalid-v2.json").write_text(json.dumps(invalid_profile))
    for args in (
        ("apt", "--profile", "/etc/debz/invalid-v2.json", "--json", "update"),
        ("apt", "--profile", "/etc/debz/invalid-v2.json", "--json", "install", "-y", "base-dep"),
        ("apt", "--profile", "/etc/debz/invalid-v2.json", "--json", "list", "--installed"),
        ("recover", "--system-profile", "/etc/debz/invalid-v2.json", "--json"),
    ):
        rejected = cli(*args, expected=8 if args[0] == "recover" else 3)
        assert rejected["changed"] is False
        if args[0] == "recover":
            assert rejected["mutation_status"] == "unknown"
            assert rejected["diagnostics"][0]["id"] == "recovery_required"
        assert status_path.read_bytes() == initial_status
        assert not list(state_path.iterdir())
        assert not list((root / "var/cache/debz").iterdir())
        assert not (root / "run/debz").exists()

    apt("update")
    reviewed = apt("install", "base-dep", "alt-a", expected=2)
    assert reviewed["diagnostics"][0]["id"] == "confirmation_required"
    closure = {"base-dep", "alt-a", "essential-core"}
    assert {item["package"] for item in reviewed["items"]} == {"base-dep", "alt-a"}, reviewed
    assert status_path.read_bytes() == initial_status
    operations_path = state_path / "apt/operations"
    previous_results = set(operations_path.glob("*/transaction-result.json"))
    result = apt("install", "-y", "base-dep", "alt-a")
    assert result["changed"] is True
    assert result["outcome"] == "success"
    evidence = result["evidence"]
    assert evidence["exact_lock"]["digest_sha256"] == reviewed["evidence"]["exact_lock"]["digest_sha256"]
    assert len(set(operations_path.glob("*/transaction-result.json")) - previous_results) == 1
    lock_path = root / evidence["exact_lock"]["path"].lstrip("/")
    lock = json.loads(lock_path.read_bytes())
    assert lock["version"] == (3 if backend == "native" else 1), lock
    if backend == "native":
        assert lock["schema"] == "https://debz.dev/schema/exact-closure-lock-v3"
        assert all("index_identity" in repository for repository in lock["repositories"])
        assert all("archive_identity" in package for package in lock["packages"])
    assert {item["name"] for item in lock["packages"]} == closure, lock
    requested = {item["name"] for item in lock["packages"] if item["retention"] == "requested"}
    assert requested == {"base-dep", "alt-a"}
    for key in ("exact_lock", "transaction_result", "root_operation_completion"):
        binding = evidence[key]
        if key == "root_operation_completion":
            binding = binding["document"]
        assert binding and (root / binding["path"].lstrip("/")).is_file(), (key, binding)
    completion_path = root / evidence["root_operation_completion"]["document"]["path"].lstrip("/")
    completion = json.loads(completion_path.read_bytes())
    assert completion["exact_lock"] == evidence["exact_lock"]
    assert completion["transaction_result"] == evidence["transaction_result"]
    assert completion["request_sha256"] == result["request_sha256"]
    if backend == "native":
        receipt = json.loads((root / evidence["transaction_result"]["path"].lstrip("/")).read_bytes())
        assert receipt["schema"] == "https://debz.dev/schema/native-transaction-provenance-v2", receipt
        assert receipt["outcome"] == "succeeded", receipt
        assert receipt["exact_lock_sha256"] == evidence["exact_lock"]["digest_sha256"]
        assert receipt["digest_sha256"] == evidence["transaction_result"]["digest_sha256"]
    else:
        verification = cli(
            "transaction-result", "verify", "--state-path",
            str(Path(evidence["transaction_result"]["path"]).parent),
            "--lock-input", evidence["exact_lock"]["path"],
            "--architecture", lock["target_architecture"], "--json",
        )
        assert verification["lock_sha256"] == evidence["exact_lock"]["digest_sha256"]
        assert verification["transaction_digest_sha256"] == evidence["transaction_result"]["digest_sha256"]
        assert verification["package_count"] == len(closure)
    for package in ("base-dep", "alt-a"):
        assert (root / "usr/share/debz-fixtures" / package).is_file()
    installed = apt("list", "--installed")
    assert installed["version"] == 2
    assert {item["package"] for item in installed["items"]} == closure, installed
    legacy_profile = {**native_profile, "transaction_backend": "legacy_dpkg"}
    (root / "etc/debz/legacy-v2.json").write_text(json.dumps(legacy_profile))
    explicit_legacy = cli(
        "apt", "--profile", "/etc/debz/legacy-v2.json", "--json", "list", "--installed",
    )
    assert explicit_legacy["items"] == installed["items"]
    assert explicit_legacy["profile"]["sha256"] != installed["profile"]["sha256"]

    apt("install", "-y", "fixture-upgrade=1.0-1")
    upgraded = apt("upgrade", "-y")
    assert upgraded["changed"] is True
    assert (root / "usr/share/debz-fixtures/fixture-upgrade").read_text().startswith("fixture-upgrade=2.0-1:")
    if backend == "native":
        lower_completion = json.loads((state_path / "root-operation-completion-v2.json").read_bytes())
        assert lower_completion["operation"] == "upgrade_all", lower_completion
        assert lower_completion["discharge"]["operation"] == "upgrade_all", lower_completion
        assert lower_completion["discharge"]["request_sha256"] == lower_completion["request_sha256"]
        before_unchanged = status_path.read_bytes()
        receipts_before_unchanged = set(operations_path.glob("*/transaction-result.json"))
        unchanged = apt("upgrade", "-y")
        assert unchanged["version"] == 3, unchanged
        assert unchanged["changed"] is False, unchanged
        assert unchanged["evidence"]["transaction_result"] is None, unchanged
        assert unchanged["evidence"]["root_operation_completion"] is None, unchanged
        active_path = state_path / "apt/active-operation-v1.json"
        assert not active_path.exists()
        unchanged_path = root / unchanged["evidence"]["active_operation_state"].lstrip("/")
        unchanged_bytes = unchanged_path.read_bytes()
        unchanged_state = json.loads(unchanged_bytes)
        assert unchanged_state["outcome"] == "unchanged", unchanged_state
        assert unchanged_state["mutation_started"] is False, unchanged_state
        active_path.write_bytes(unchanged_bytes)
        review = cli("recover", "--system-profile", "/etc/debz/native-v2.json", "--json", expected=2)
        assert review["changed"] is False, review
        assert active_path.read_bytes() == unchanged_bytes
        confirm_recovery(expected=0)
        assert not active_path.exists()
        assert unchanged_path.read_bytes() == unchanged_bytes
        assert status_path.read_bytes() == before_unchanged
        assert set(operations_path.glob("*/transaction-result.json")) == receipts_before_unchanged
    reinstalled = apt("install", "-y", "fixture-upgrade=2.0-1")
    assert reinstalled["changed"] is True, reinstalled
    assert reinstalled["evidence"]["transaction_result"] is not None, reinstalled
    assert reinstalled["evidence"]["root_operation_completion"] is not None, reinstalled
    assert not (state_path / "apt/active-operation-v1.json").exists()
    removed = apt("remove", "-y", "base-dep", "alt-a", "fixture-upgrade")
    assert removed["changed"] is True
    assert {item["package"] for item in apt("list", "--installed")["items"]} == {"essential-core"}
    for package in ("base-dep", "alt-a", "fixture-upgrade"):
        assert not (root / "usr/share/debz-fixtures" / package).exists()
    before_rejection = status_path.read_bytes()
    rejected = apt("install", "-y", "base-dep", "nonexistent-fixture-package", expected=5)
    assert rejected["changed"] is False
    assert status_path.read_bytes() == before_rejection
    assert not (root / "usr/share/debz-fixtures/base-dep").exists()
    if backend == "native":
        failure = apt("install", "-y", "fail-script", expected=7)
        assert failure["changed"] is True
        assert failure["diagnostics"][0]["id"] == "transaction_failed", failure
        assert failure["evidence"]["root_operation_completion"] is None
        receipt_path = root / failure["evidence"]["transaction_result"]["path"].lstrip("/")
        receipt = json.loads(receipt_path.read_bytes())
        assert receipt["outcome"] == "failed", receipt
        active_path = state_path / "apt/active-operation-v1.json"
        assert not active_path.exists()
        # Restore the exact durable final state to model interrupted outer clearing.
        final_path = receipt_path.parent / "state-v1.json"
        final_bytes = final_path.read_bytes()
        active_path.write_bytes(final_bytes)
        recovery = cli("recover", "--system-profile", "/etc/debz/native-v2.json", "--json", expected=2)
        assert recovery["changed"] is True, recovery
        assert active_path.read_bytes() == final_bytes
        confirm_recovery(expected=7)
        assert not active_path.exists()
        assert final_path.read_bytes() == final_bytes
        assert hashlib.sha256(helper_path.read_bytes()).digest() == helper_digest
    print(f"apt-system acceptance ({backend}): multi-package install/remove, exact-lock evidence, "
          "confirmation, update, upgrade, list, atomic rejection, ambient isolation and mount cleanup passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("debz", nargs="?", type=Path)
    parser.add_argument("--inside", type=Path)
    parser.add_argument("--transaction-backend", choices=("legacy_dpkg", "native"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("required apt-system acceptance needs root and Linux mount/PID/network namespaces")
    if args.inside:
        if args.transaction_backend is None:
            parser.error("internal acceptance entry requires a transaction backend")
        inside(args.inside, args.transaction_backend)
        return
    if args.debz is None:
        parser.error("debz executable required")
    cache = REPOSITORY / ".zig-cache"
    cache.mkdir(exist_ok=True)
    host_status = Path("/var/lib/dpkg/status")
    before = hashlib.sha256(host_status.read_bytes()).digest() if host_status.exists() else None
    try:
        for backend in (args.transaction_backend,) if args.transaction_backend else ("legacy_dpkg", "native"):
            with tempfile.TemporaryDirectory(prefix="apt-system-acceptance-", dir=cache) as workspace:
                root = Path(workspace) / "root"
                root.mkdir()
                prepare_root(root, args.debz.resolve(strict=True))
                run(
                    "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=SIGKILL",
                    "--propagation", "private", sys.executable, str(Path(__file__).resolve()),
                    "--inside", str(root), "--transaction-backend", backend,
                )
    finally:
        after = hashlib.sha256(host_status.read_bytes()).digest() if host_status.exists() else None
        assert before == after, "host dpkg status changed"


if __name__ == "__main__":
    main()
