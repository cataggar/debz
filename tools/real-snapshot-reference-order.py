#!/usr/bin/env python3
"""Install a verified closure with dpkg without bypassing Pre-Depends."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

MAXIMUM_PACKAGES = 2000
MAXIMUM_PROBES = 10000
MAXIMUM_PROBE_OUTPUT = 65536
MAXIMUM_LOG_BYTES = 16 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*\Z")
DIGEST = re.compile(r"[a-f0-9]{128}\Z")


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    architecture: str
    digest: str
    size: int
    archive: Path

    @property
    def selector(self) -> str:
        return self.name if self.architecture == "all" else f"{self.name}:{self.architecture}"


def packages_from_manifest(path: Path, cache: Path) -> list[Package]:
    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for line in path.read_text().splitlines():
        columns = line.split("\t")
        if len(columns) != 5:
            raise ValueError("invalid reference archive manifest")
        name, version, architecture, digest, declared_size = columns
        if (
            not NAME.fullmatch(name)
            or not version
            or not NAME.fullmatch(architecture)
            or not DIGEST.fullmatch(digest)
            or not declared_size.isascii()
            or not declared_size.isdecimal()
        ):
            raise ValueError("invalid reference package identity")
        key = name, architecture
        if key in seen:
            raise ValueError(f"duplicate reference package: {name}:{architecture}")
        seen.add(key)
        size = int(declared_size)
        if not 0 < size <= MAXIMUM_ARCHIVE_BYTES:
            raise ValueError(f"invalid reference archive size: {name}")
        packages.append(Package(
            name, version, architecture, digest, size,
            cache / "packages-v2/objects" / f"sha512-{digest}",
        ))
        if len(packages) > MAXIMUM_PACKAGES:
            raise ValueError("reference closure exceeds package limit")
    if not packages:
        raise ValueError("empty reference closure")
    return packages


def verify_archive(package: Package) -> None:
    if package.archive.is_symlink() or not package.archive.is_file():
        raise ValueError(f"missing verified reference archive: {package.name}")
    if package.archive.stat().st_size != package.size:
        raise ValueError(f"reference archive size changed: {package.name}")
    digest = hashlib.sha512()
    with package.archive.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != package.digest:
        raise ValueError(f"reference archive digest changed: {package.name}")


def dpkg_command(dpkg: Path, root: Path, *operation: str) -> list[str]:
    return [
        str(dpkg), f"--root={root}", "--force-not-root", "--force-bad-path",
        "--force-confold", *operation,
    ]


def oracle_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/",
        "LC_ALL": "C",
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBCONF_NONINTERACTIVE_SEEN": "true",
        "DPKG_COLORS": "never",
    }


def probe(command: list[str], environment: dict[str, str]) -> tuple[int, bytes]:
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
        if output.tell() > MAXIMUM_PROBE_OUTPUT:
            raise ValueError("reference dpkg dry-run output exceeds limit")
        output.seek(0)
        return result.returncode, output.read()


def apply(
    command: list[str],
    environment: dict[str, str],
    stdout: Path,
    stderr: Path,
) -> None:
    with stdout.open("ab") as output, stderr.open("ab") as errors:
        subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            check=True,
            timeout=120,
        )
    if stdout.stat().st_size > MAXIMUM_LOG_BYTES or stderr.stat().st_size > MAXIMUM_LOG_BYTES:
        raise ValueError("reference dpkg output exceeds limit")


def configured_packages(root: Path, environment: dict[str, str]) -> set[tuple[str, str]]:
    result = subprocess.run(
        [
            "dpkg-query", f"--admindir={root / 'var/lib/dpkg'}", "-W",
            "-f=${Package}\t${Architecture}\t${Status}\n",
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=60,
    )
    if len(result.stdout) > 1024 * 1024 or result.stderr:
        raise ValueError("invalid reference database query")
    configured: set[tuple[str, str]] = set()
    for line in result.stdout.decode("utf-8").splitlines():
        name, architecture, status = line.split("\t")
        if status in ("install ok installed", "install ok triggers-pending"):
            configured.add((name, architecture))
        elif status != "install ok unpacked":
            raise RuntimeError(f"unhealthy reference package state: {name}:{architecture} {status}")
    return configured


def configure_batch(
    dpkg: Path,
    root: Path,
    environment: dict[str, str],
    stdout: Path,
    stderr: Path,
    selectors: tuple[str, ...] = (),
) -> None:
    operation = selectors or ("--pending",)
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(
            dpkg_command(dpkg, root, "--no-triggers", "--configure", *operation),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            check=False,
            timeout=120,
        )
        if output.tell() > MAXIMUM_LOG_BYTES or errors.tell() > MAXIMUM_LOG_BYTES:
            raise ValueError("reference dpkg batch output exceeds limit")
        output.seek(0)
        errors.seek(0)
        observed_output, observed_errors = output.read(), errors.read()
    with stdout.open("ab") as out, stderr.open("ab") as err:
        out.write(observed_output)
        err.write(observed_errors)
    if stdout.stat().st_size > MAXIMUM_LOG_BYTES or stderr.stat().st_size > MAXIMUM_LOG_BYTES:
        raise ValueError("reference dpkg output exceeds limit")
    if result.returncode:
        reasons = re.findall(
            rb"dpkg: error processing package [^\n]+\n ([^\n]+)", observed_errors
        )
        other_errors = [
            line for line in observed_errors.splitlines()
            if line.startswith(b"dpkg: error")
            and not line.startswith(b"dpkg: error processing package ")
        ]
        if (
            not reasons
            or any(reason != b"dependency problems - leaving unconfigured" for reason in reasons)
            or observed_errors.count(b"dpkg: error processing package ") != len(reasons)
            or other_errors
        ):
            raise RuntimeError(f"reference dpkg configuration failed: {observed_errors[:4096]!r}")


@dataclass(frozen=True)
class Prestate:
    selector: str
    status: str
    destination: Path


PRESTATE = re.compile(
    r"(?P<selector>[a-z0-9][a-z0-9+.-]*:[a-z0-9][a-z0-9-]*)="
    r"(?P<status>half-configured|unpacked):(?P<destination>/.+)\Z"
)


def parse_prestate(value: str) -> Prestate:
    match = PRESTATE.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError(f"invalid prestate: {value}")
    return Prestate(
        match["selector"], match["status"], Path(match["destination"]),
    )


def package_status(root: Path, selector: str, environment: dict[str, str]) -> str:
    result = subprocess.run(
        [
            "dpkg-query", f"--admindir={root / 'var/lib/dpkg'}", "-W",
            "-f=${Version} ${Status}", selector,
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=60,
    )
    if len(result.stdout) > 4096 or result.stderr:
        raise ValueError(f"invalid reference status query: {selector}")
    return result.stdout.decode("utf-8")


def interrupt_postinst(
    dpkg: Path,
    root: Path,
    package: Package,
    environment: dict[str, str],
    stdout: Path,
    stderr: Path,
) -> None:
    """Let dpkg start configuring, but deny execution of the installed postinst.

    A private read-only, noexec bind of the unchanged script onto itself makes
    dpkg's own chrooted exec fail with EACCES after it recorded half-configured
    and installed conffiles, so no maintainer-script code runs.
    """
    script = root / "var/lib/dpkg/info" / f"{package.name}.postinst"
    if script.is_symlink() or not script.is_file():
        raise ValueError(f"prestate postinst is not a regular file: {package.selector}")
    before = hashlib.sha256(script.read_bytes()).hexdigest()
    subprocess.run(["mount", "--bind", "--", str(script), str(script)], check=True, timeout=30)
    try:
        subprocess.run(
            ["mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", str(script)],
            check=True, timeout=30,
        )
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run(
                dpkg_command(dpkg, root, "--no-triggers", "--configure", package.selector),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                check=False,
                timeout=120,
            )
            if output.tell() > MAXIMUM_PROBE_OUTPUT or errors.tell() > MAXIMUM_PROBE_OUTPUT:
                raise ValueError("interrupted configure output exceeds limit")
            output.seek(0)
            errors.seek(0)
            observed_output, observed_errors = output.read(), errors.read()
    finally:
        subprocess.run(["umount", "--", str(script)], check=True, timeout=30)
    with stdout.open("ab") as out, stderr.open("ab") as err:
        out.write(observed_output)
        err.write(observed_errors)
    if (
        result.returncode == 0
        or b"post-installation script" not in observed_errors
        or b"Permission denied" not in observed_errors
    ):
        raise RuntimeError(
            f"prestate postinst was not denied before execution: {observed_errors[:4096]!r}"
        )
    if hashlib.sha256(script.read_bytes()).hexdigest() != before:
        raise RuntimeError(f"prestate postinst changed: {package.selector}")


def capture_prestate(
    dpkg: Path,
    root: Path,
    package: Package,
    prestate: Prestate,
    environment: dict[str, str],
    stdout: Path,
    stderr: Path,
) -> None:
    destination = prestate.destination
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError(f"prestate destination must be new: {destination}")
    if prestate.status == "half-configured":
        interrupt_postinst(dpkg, root, package, environment, stdout, stderr)
    expected = f"{package.version} install ok {prestate.status}"
    if package_status(root, package.selector, environment) != expected:
        raise RuntimeError(f"unexpected prestate status for {package.selector}")
    proc = root / "proc"
    mounted = proc.is_mount()
    if mounted:
        subprocess.run(["umount", "--", str(proc)], check=True, timeout=30)
    try:
        if proc.is_mount() or any(proc.iterdir()):
            raise RuntimeError("prestate proc mountpoint is not empty")
        subprocess.run(
            ["cp", "-a", "--one-file-system", "--", str(root), str(destination)],
            check=True, timeout=600,
        )
        # Signed replay fixtures are pinned as root-owned mode-0700 roots.
        destination.chmod(0o700)
    finally:
        if mounted:
            subprocess.run(
                ["mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", str(proc)],
                check=True, timeout=30,
            )
    with (destination.parent / "prestates.tsv").open("a") as record:
        record.write(f"{package.selector}\t{expected}\t{destination}\n")


def install(
    dpkg: Path,
    root: Path,
    cache: Path,
    evidence: Path,
    prestates: tuple[Prestate, ...] = (),
) -> None:
    packages = packages_from_manifest(evidence / "reference-archives.tsv", cache)
    targets = {prestate.selector: prestate for prestate in prestates}
    if len(targets) != len(prestates):
        raise ValueError("duplicate prestate selector")
    destinations = {prestate.destination for prestate in prestates}
    if len(destinations) != len(prestates):
        raise ValueError("duplicate prestate destination")
    selectors = {package.selector for package in packages}
    if any(selector not in selectors for selector in targets):
        raise ValueError("prestate package is not in the verified closure")
    pending = packages[:]
    unpacked: list[Package] = []
    configured: set[tuple[str, str]] = set()
    environment = oracle_environment()
    stdout = evidence / "reference-install.stdout"
    stderr = evidence / "reference-install.stderr"
    probes = 0
    while pending or unpacked:
        progressed = False
        deferred: list[str] = []
        for package in pending[:]:
            command = dpkg_command(dpkg, root, "--no-triggers", "--no-act", "--unpack", str(package.archive))
            probes += 1
            if probes > MAXIMUM_PROBES:
                raise ValueError("reference dpkg dependency probe limit exceeded")
            status, output = probe(command, environment)
            if status:
                if b"pre-dependency problem" not in output:
                    raise RuntimeError(f"reference dpkg unpack refused {package.selector}: {output[:4096]!r}")
                deferred.append(package.selector)
                continue
            verify_archive(package)
            apply(
                dpkg_command(dpkg, root, "--no-triggers", "--unpack", str(package.archive)),
                environment, stdout, stderr,
            )
            pending.remove(package)
            unpacked.append(package)
            progressed = True
        for package in unpacked[:]:
            command = dpkg_command(dpkg, root, "--no-triggers", "--no-act", "--configure", package.selector)
            probes += 1
            if probes > MAXIMUM_PROBES:
                raise ValueError("reference dpkg dependency probe limit exceeded")
            status, output = probe(command, environment)
            if status:
                if b"dependency problems" not in output:
                    raise RuntimeError(f"reference dpkg configure refused {package.selector}: {output[:4096]!r}")
                deferred.append(package.selector)
                continue
            prestate = targets.pop(package.selector, None)
            if prestate is not None:
                capture_prestate(dpkg, root, package, prestate, environment, stdout, stderr)
                if not targets:
                    return
            apply(
                dpkg_command(dpkg, root, "--no-triggers", "--configure", package.selector),
                environment, stdout, stderr,
            )
            unpacked.remove(package)
            configured.add((package.name, package.architecture))
            progressed = True
        if not progressed:
            if unpacked:
                before = set(configured)
                if targets:
                    # Break ordinary dependency cycles without configuring a
                    # package whose exact prestate has not been copied yet.
                    selectors = tuple(
                        package.selector for package in unpacked
                        if package.selector not in targets
                    )
                    if not selectors:
                        raise RuntimeError("prestate packages form an unordered dependency cycle")
                    configure_batch(dpkg, root, environment, stdout, stderr, selectors)
                else:
                    configure_batch(dpkg, root, environment, stdout, stderr)
                observed = configured_packages(root, environment)
                for package in unpacked[:]:
                    if (package.name, package.architecture) in observed:
                        unpacked.remove(package)
                        configured.add((package.name, package.architecture))
                progressed = configured != before
        if not progressed:
            raise RuntimeError(
                "reference dependency ordering stalled: " + ", ".join(deferred[:20])
            )
    if targets:
        raise RuntimeError("prestate package was never configured")
    if len(configured) != len(packages):
        raise ValueError("reference closure not fully configured")
    apply(
        dpkg_command(dpkg, root, "--triggers-only", "--pending"),
        environment, stdout, stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dpkg", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--prestate", type=parse_prestate, action="append", default=[],
        metavar="PACKAGE:ARCH=STATUS:DESTINATION",
        help="copy the root just before configuring PACKAGE, then stop after the last copy",
    )
    args = parser.parse_args()
    if not args.dpkg.is_absolute() or not args.root.is_absolute() or not args.cache.is_absolute():
        raise ValueError("reference inputs must be absolute paths")
    install(args.dpkg, args.root, args.cache, args.evidence, tuple(args.prestate))


if __name__ == "__main__":
    main()
