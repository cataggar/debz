#!/usr/bin/env python3
"""Exercise the installed apt facade with real dpkg in a disposable system root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[1]


def run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, timeout=120, **kwargs)


def copy_program(root: Path, source: Path, destination: str) -> None:
    target = root / destination.lstrip("/")
    if target.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    with source.open("rb") as executable:
        header = executable.read(256)
    if header.startswith(b"#!"):
        interpreter = shlex.split(header.split(b"\n", 1)[0][2:].decode())[0]
        if not interpreter.startswith("/"):
            raise RuntimeError(f"non-absolute fixture interpreter: {source}")
        copy_program(root, Path(interpreter), interpreter)
        return
    linked = subprocess.run(
        ["ldd", str(source)], capture_output=True, text=True, timeout=10, check=False,
    )
    dependencies = linked.stdout + linked.stderr
    static = any(message in dependencies for message in ("not a dynamic executable", "statically linked"))
    if linked.returncode and not static:
        raise RuntimeError(f"cannot inspect fixture libraries: {source}: {dependencies}")
    if "=> not found" in dependencies:
        raise RuntimeError(f"missing fixture library: {source}: {dependencies}")
    for name in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", dependencies, re.MULTILINE):
        library = root / name.lstrip("/")
        library.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(name, library)


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


def inside(root: Path) -> None:
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
            for name in ("transaction.journal", "root-operation-v1.json"):
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
        return cli("apt", "--json", *args, expected=expected)

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
    for args in (
        ("apt", "--profile", "/etc/debz/native-v2.json", "--json", "update"),
        ("apt", "--profile", "/etc/debz/native-v2.json", "--json", "install", "-y", "base-dep"),
        ("apt", "--profile", "/etc/debz/native-v2.json", "--json", "list", "--installed"),
        ("recover", "--system-profile", "/etc/debz/native-v2.json", "--json"),
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
    print("apt-system acceptance: multi-package install/remove, exact-lock evidence, "
          "confirmation, update, upgrade, list, atomic rejection, ambient isolation and mount cleanup passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("debz", nargs="?", type=Path)
    parser.add_argument("--inside", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("required apt-system acceptance needs root and Linux mount/PID/network namespaces")
    if args.inside:
        inside(args.inside)
        return
    if args.debz is None:
        parser.error("debz executable required")
    cache = REPOSITORY / ".zig-cache"
    cache.mkdir(exist_ok=True)
    host_status = Path("/var/lib/dpkg/status")
    before = hashlib.sha256(host_status.read_bytes()).digest() if host_status.exists() else None
    try:
        with tempfile.TemporaryDirectory(prefix="apt-system-acceptance-", dir=cache) as workspace:
            root = Path(workspace) / "root"
            root.mkdir()
            prepare_root(root, args.debz.resolve(strict=True))
            run(
                "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=SIGKILL",
                "--propagation", "private", sys.executable, str(Path(__file__).resolve()),
                "--inside", str(root),
            )
    finally:
        after = hashlib.sha256(host_status.read_bytes()).digest() if host_status.exists() else None
        assert before == after, "host dpkg status changed"


if __name__ == "__main__":
    main()
