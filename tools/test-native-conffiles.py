#!/usr/bin/env python3
"""Compare native conffile, configure, remove, and purge phases with real dpkg."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "debz_materialization", ROOT / "tools/test-native-materialization.py",
)
assert SPEC and SPEC.loader
materialization = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materialization)

CONFIG = Path("etc/debz-native.conf")
OLD_CONFIG = b"configuration version one\n"
NEW_CONFIG = b"configuration version two\n"
LOCAL_CONFIG = b"administrator configuration\n"
POLICIES = ("keep_existing", "use_package_version")


def local_file(path: Path, content: bytes) -> None:
    materialization.write(path, content, 0o600)
    os.utime(path, (materialization.EPOCH + 60, materialization.EPOCH + 60))


def reference_phase(
    root: Path,
    archive: Path | None,
    operation: str,
    policy: str,
    environment: dict[str, str],
    destination: Path,
    *,
    packages: list[dict[str, str]] | None = None,
) -> None:
    command = materialization.reference_command(root)
    command.append("--force-confold" if policy == "keep_existing" else "--force-confnew")
    if operation in ("install", "upgrade", "downgrade", "reinstall"):
        if archive is None:
            raise ValueError("unpack requires an archive")
        command += ["--unpack", str(archive)]
    elif operation in ("configure", "remove", "purge"):
        identities = [
            f"{package['name']}:{package['architecture']}" for package in packages
        ] if packages is not None else [materialization.PACKAGE]
        command += [f"--{operation}", *identities]
    else:
        raise ValueError(f"unsupported reference operation: {operation}")
    materialization.run(command, environment, destination / "reference.log")


class Scenario:
    def __init__(
        self,
        workspace: Path,
        name: str,
        executable: Path | None,
        architecture: str,
        environment: dict[str, str],
    ) -> None:
        self.directory = workspace / name
        self.expected = self.directory / "reference"
        self.candidate = self.directory / "native"
        self.executable = executable
        self.architecture = architecture
        self.environment = environment
        self.index = 0
        for root in self.roots:
            materialization.make_root(root, architecture)

    @property
    def roots(self) -> tuple[Path, Path]:
        return self.expected, self.candidate

    def seed(self, archive: Path, *, configure: bool = True) -> None:
        for root in self.roots:
            materialization.reference(
                root, archive, self.environment,
                self.directory / f"{root.name}-seed-{self.index}.log",
                configure=configure,
            )
        self.index += 1

    def edit(self, state: str) -> None:
        for root in self.roots:
            if state == "edited":
                local_file(root / CONFIG, LOCAL_CONFIG)
            elif state == "missing":
                (root / CONFIG).unlink()
            elif state == "packaged":
                local_file(root / CONFIG, NEW_CONFIG)
            elif state != "unmodified":
                raise ValueError(f"unknown local conffile state: {state}")

    def phase(
        self,
        operation: str,
        archive: Path | None = None,
        policy: str = "keep_existing",
        *,
        packages: list[dict[str, str]] | None = None,
    ) -> None:
        destination = self.directory / f"{self.index}-{operation}"
        destination.mkdir()
        self.index += 1
        reference_phase(
            self.expected, archive, operation, policy,
            self.environment, destination,
            packages=packages,
        )
        if self.executable:
            report = materialization.native(
                self.executable, self.candidate, archive, self.architecture,
                operation, self.environment, destination,
                conffiles=True, policy=policy,
                packages=packages if packages is not None else [{
                    "name": materialization.PACKAGE,
                    "architecture": self.architecture,
                }] if operation in ("remove", "purge") else None,
            )
            if report["outcome"] != "applied":
                raise AssertionError(
                    f"{self.directory.name}/{operation}: native did not apply: {report}"
                )
            for name in ("root-operation-v1.json", "root-mutation-v1.json"):
                if (self.candidate / "var/lib/debz" / name).exists():
                    raise AssertionError(f"{operation} stranded active evidence: {name}")
        else:
            oracle_destination = destination / "oracle"
            oracle_destination.mkdir()
            reference_phase(
                self.candidate, archive, operation, policy,
                self.environment, oracle_destination,
                packages=packages,
            )
        if operation in ("remove", "purge"):
            materialization.compare_roots(self.expected, self.candidate, destination)
        else:
            materialization.assert_parity(self.expected, self.candidate, destination)

    def complete(self) -> None:
        label = "native/dpkg parity" if self.executable else "oracle fixture"
        print(f"{self.directory.name}: {label} passed", flush=True)


def exercise(
    executable: Path | None,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
) -> None:
    def package(name: str, version: str, feature: str, content: bytes = OLD_CONFIG) -> Path:
        return materialization.make_package(
            workspace / "packages" / name, environment, architecture, version,
            feature, conffile_content=content,
        )

    first = package("first", "1", "conffile")
    changed = package("changed", "2", "conffile", NEW_CONFIG)
    unchanged = package("unchanged", "2", "conffile")
    obsolete = package("obsolete", "2", "obsolete-conffile")
    removed = package("removed", "2", "remove-on-upgrade")
    plain = package("plain", "1", "data")
    other = materialization.make_package(
        workspace / "packages" / "other", environment, architecture, "1",
        package="debz-native-other",
    )

    def scenario(name: str) -> Scenario:
        return Scenario(workspace, name, executable, architecture, environment)

    for policy in POLICIES:
        case = scenario(f"fresh-{policy}")
        case.phase("install", first, policy)
        case.phase("configure", first, policy)
        case.complete()

        for state, incoming, suffix in (
            ("unmodified", changed, "changed"),
            ("edited", changed, "changed"),
            ("missing", changed, "changed"),
            ("packaged", changed, "changed"),
            ("unmodified", unchanged, "unchanged"),
            ("edited", unchanged, "unchanged"),
            ("missing", unchanged, "unchanged"),
        ):
            case = scenario(f"{state}-{suffix}-{policy}")
            case.seed(first)
            case.edit(state)
            case.phase("upgrade", incoming, policy)
            case.phase("configure", incoming, policy)
            case.complete()

        for state in ("unmodified", "edited", "missing"):
            for feature, incoming in (("obsolete", obsolete), ("remove-on-upgrade", removed)):
                case = scenario(f"{feature}-{state}-{policy}")
                case.seed(first)
                case.edit(state)
                case.phase("upgrade", incoming, policy)
                case.phase("configure", incoming, policy)
                case.phase("purge", policy=policy)
                case.complete()

        case = scenario(f"fresh-remove-on-upgrade-{policy}")
        case.phase("install", removed, policy)
        case.phase("configure", removed, policy)
        case.complete()

    case = scenario("repeated-unconfigured-conffiles")
    case.phase("install", first)
    case.phase("upgrade", changed)
    case.phase("configure", changed)
    case.phase("downgrade", first)
    case.phase("configure", first)
    case.phase("reinstall", first)
    case.phase("configure", first)
    case.complete()

    for archive, feature in ((plain, "plain"), (first, "conffile")):
        for configured in (False, True):
            for operation in ("remove", "purge"):
                state = "installed" if configured else "unpacked"
                case = scenario(f"{feature}-{state}-{operation}")
                case.seed(archive, configure=configured)
                case.phase(operation)
                case.phase(operation)
                if operation == "remove":
                    case.phase("purge")
                case.complete()

    for state in ("edited", "missing"):
        case = scenario(f"remove-{state}-conffile")
        case.seed(first)
        case.edit(state)
        case.phase("remove")
        case.phase("purge")
        case.complete()

    case = scenario("purge-retains-local-and-coowned-directories")
    case.seed(first)
    case.seed(other)
    for root in case.roots:
        local_file(root / materialization.PAYLOAD / "administrator-file", b"retain me\n")
        local_file(root / "etc/administrator-file", b"retain me too\n")
        for suffix in (".dpkg-old", ".dpkg-dist", ".dpkg-new"):
            local_file(root / (str(CONFIG) + suffix), b"old configuration artifact\n")
    case.phase("purge")
    case.complete()

    case = scenario("batch-purge-shared-directories")
    case.seed(plain)
    case.seed(other)
    case.phase("purge", packages=[
        {"name": materialization.PACKAGE, "architecture": architecture},
        {"name": "debz-native-other", "architecture": architecture},
    ])
    case.complete()

    if executable:
        for feature in (
            "script", "unregistered-local", "symlink-conffile",
            "generated-stage-collision", "foreign-owned-artifact",
        ):
            case = scenario(f"handoff-{feature}")
            archive = first
            operation = "install"
            if feature == "script":
                archive = package("script", "1", "script")
            elif feature == "unregistered-local":
                local_file(case.candidate / CONFIG, LOCAL_CONFIG)
            elif feature == "symlink-conffile":
                case.seed(first)
                (case.candidate / CONFIG).unlink()
                local_file(case.candidate / "etc/local-target", LOCAL_CONFIG)
                (case.candidate / CONFIG).symlink_to("local-target")
                archive = changed
                operation = "upgrade"
            elif feature == "generated-stage-collision":
                archive = materialization.make_package(
                    workspace / "packages/collision", environment, architecture,
                    "1", "conffile", conffile_content=OLD_CONFIG,
                    extra_files={str(CONFIG) + ".dpkg-new": b"ordinary owned payload\n"},
                )
            else:
                case.seed(first)
                foreign = materialization.make_package(
                    workspace / "packages/foreign-artifact", environment,
                    architecture, "1", package="debz-native-other",
                    extra_files={str(CONFIG) + ".dpkg-dist": b"foreign owned payload\n"},
                )
                case.seed(foreign)
                archive = None
                operation = "purge"
            before = materialization.snapshot(case.candidate)
            destination = case.directory / "refusal"
            destination.mkdir()
            report = materialization.native(
                executable, case.candidate, archive, architecture, operation,
                environment, destination, conffiles=True,
                packages=[{
                    "name": materialization.PACKAGE,
                    "architecture": architecture,
                }] if operation == "purge" else None,
            )
            if report["outcome"] not in ("handoff", "refused"):
                raise AssertionError(f"{feature} did not refuse before mutation: {report}")
            differences = materialization.oracle.differences(
                before, materialization.snapshot(case.candidate), maximum=30,
            )
            if differences:
                raise AssertionError(f"{feature} refusal changed state:\n" + "\n".join(differences))
            for name in ("root-operation-v1.json", "root-mutation-v1.json"):
                if (case.candidate / "var/lib/debz" / name).exists():
                    raise AssertionError(f"{feature} refusal stranded {name}")
            print(f"{feature}: pre-mutation handoff passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_test", nargs="?", type=Path)
    parser.add_argument(
        "--oracle-only", action="store_true",
        help="check reference fixture consistency only; not native parity",
    )
    arguments = parser.parse_args()
    if arguments.oracle_only == bool(arguments.native_test):
        parser.error("provide a native test executable or --oracle-only, not both")
    for command in ("dpkg", "dpkg-deb"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required reference tool is missing: {command}")
    executable = arguments.native_test.resolve(strict=True) if arguments.native_test else None
    architecture = subprocess.run(
        ["dpkg", "--print-architecture"], check=True, capture_output=True,
        text=True, timeout=10,
    ).stdout.strip()
    if architecture not in ("amd64", "arm64"):
        raise RuntimeError(f"unsupported acceptance architecture: {architecture}")
    host_status = Path("/var/lib/dpkg/status").read_bytes()
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="native-conffiles-", dir=temporary_root) as temporary:
        workspace = Path(temporary)
        environment = materialization.fixture_environment(workspace)
        exercise(executable, workspace, environment, architecture)
    if Path("/var/lib/dpkg/status").read_bytes() != host_status:
        raise AssertionError("host dpkg status changed during conffile acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
