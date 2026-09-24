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
) -> None:
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(
            dpkg_command(dpkg, root, "--no-triggers", "--configure", "--pending"),
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


def install(dpkg: Path, root: Path, cache: Path, evidence: Path) -> None:
    packages = packages_from_manifest(evidence / "reference-archives.tsv", cache)
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
    args = parser.parse_args()
    if not args.dpkg.is_absolute() or not args.root.is_absolute() or not args.cache.is_absolute():
        raise ValueError("reference inputs must be absolute paths")
    install(args.dpkg, args.root, args.cache, args.evidence)


if __name__ == "__main__":
    main()
