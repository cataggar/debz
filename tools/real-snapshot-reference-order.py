#!/usr/bin/env python3
"""Install a verified closure with dpkg without bypassing Pre-Depends."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import os
import subprocess
import tempfile

from real_snapshot_reference_paths import open_absolute, protected, read_root_file

MAXIMUM_PACKAGES = 2000
MAXIMUM_PROBES = 10000
MAXIMUM_PROBE_OUTPUT = 65536
MAXIMUM_LOG_BYTES = 16 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*\Z")
DIGEST = re.compile(r"[a-f0-9]{128}\Z")
PROFILE_VERSIONS = {
    "systemd": "259.5-0ubuntu3.4",
    "udev": "259.5-0ubuntu3.4",
    "sudo": "1.9.17p2-1ubuntu3.1",
}


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
    before = protected(package.archive)
    if before.st_size != package.size:
        raise ValueError(f"reference archive size changed: {package.name}")
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )
    digest = hashlib.sha512()
    fd = open_absolute(package.archive)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError(f"reference archive identity changed: {package.name}")
        with os.fdopen(fd, "rb", closefd=False) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError(f"reference archive changed: {package.name}")
    finally:
        os.close(fd)
    if digest.hexdigest() != package.digest:
        raise ValueError(f"reference archive digest changed: {package.name}")


def dpkg_command(
    launcher: Path, dpkg: Path, root: Path, architecture: str, profile: str,
    verb: str, package: Package | None = None,
) -> list[str]:
    if verb not in ("probe_unpack", "unpack", "probe_configure", "configure"):
        raise ValueError(f"reference dpkg operation has no single-script binding: {verb}")
    if package is None:
        raise ValueError("reference dpkg operation requires one signed package")
    if profile != "none":
        if (verb != "configure" or architecture != "amd64"
            or profile not in PROFILE_VERSIONS
            or package.name != profile or package.architecture != architecture
            or package.version != PROFILE_VERSIONS[profile]):
            raise ValueError(f"unauthorized reference script profile: {profile}")
    elif verb == "configure" and package.name in PROFILE_VERSIONS:
        raise ValueError(f"missing exact configure profile: {package.selector}")
    command = [str(launcher), str(root), str(dpkg), architecture, profile, verb]
    command.append(package.selector)
    if verb in ("unpack", "probe_unpack"):
        command.extend((str(package.archive), package.digest, str(package.size)))
    return command


def oracle_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/",
        "LC_ALL": "C",
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBCONF_NONINTERACTIVE_SEEN": "true",
        "DPKG_COLORS": "never",
    }


def probe(
    command: list[str], environment: dict[str, str], evidence: Path,
) -> tuple[int, bytes]:
    with tempfile.TemporaryDirectory(prefix="reference-probe-", dir=evidence) as temporary:
        output_path = Path(temporary) / "output"
        with output_path.open("x+b") as output, output_path.open("ab") as writer:
            result = subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=writer,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=60,
            )
            writer.flush()
            if output_path.stat().st_size > MAXIMUM_PROBE_OUTPUT:
                raise ValueError("reference dpkg dry-run output exceeds limit")
            return result.returncode, output.read(MAXIMUM_PROBE_OUTPUT + 1)


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


def database_packages(root: Path) -> dict[tuple[str, str], tuple[str, str]]:
    records: dict[tuple[str, str], tuple[str, str]] = {}
    data = read_root_file(root, "var/lib/dpkg/status", 4 * 1024 * 1024)
    for stanza in data.decode("utf-8").strip().split("\n\n"):
        if not stanza:
            continue
        fields: dict[str, str] = {}
        previous: str | None = None
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                if previous is None or previous in ("package", "architecture", "version", "status"):
                    raise ValueError("invalid continuation in reference database identity")
                continue
            key, separator, value = line.partition(": ")
            if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key):
                raise ValueError("malformed reference database field")
            previous = key.lower()
            if previous in fields:
                raise ValueError(f"duplicate reference database field: {key}")
            fields[previous] = value
        name = fields["package"]
        architecture = fields["architecture"]
        version = fields["version"]
        status = fields["status"]
        if not NAME.fullmatch(name) or not NAME.fullmatch(architecture) or not version:
            raise ValueError("invalid reference database package")
        key = name, architecture
        if key in records:
            raise ValueError(f"duplicate reference database package: {key}")
        records[key] = (status, version)
    return records


def install(
    launcher: Path, dpkg: Path, root: Path, cache: Path, evidence: Path,
    architecture: str,
) -> None:
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
            command = dpkg_command(launcher, dpkg, root, architecture, "none", "probe_unpack", package)
            probes += 1
            if probes > MAXIMUM_PROBES:
                raise ValueError("reference dpkg dependency probe limit exceeded")
            status, output = probe(command, environment, evidence)
            if status:
                if b"pre-dependency problem" not in output:
                    raise RuntimeError(f"reference dpkg unpack refused {package.selector}: {output[:4096]!r}")
                deferred.append(package.selector)
                continue
            verify_archive(package)
            apply(
                dpkg_command(launcher, dpkg, root, architecture, "none", "unpack", package),
                environment, stdout, stderr,
            )
            pending.remove(package)
            unpacked.append(package)
            progressed = True
        for package in unpacked[:]:
            command = dpkg_command(launcher, dpkg, root, architecture, "none", "probe_configure", package)
            probes += 1
            if probes > MAXIMUM_PROBES:
                raise ValueError("reference dpkg dependency probe limit exceeded")
            status, output = probe(command, environment, evidence)
            if status:
                if b"dependency problems" not in output:
                    raise RuntimeError(f"reference dpkg configure refused {package.selector}: {output[:4096]!r}")
                deferred.append(package.selector)
                continue
            current = database_packages(root).get((package.name, package.architecture))
            if current != ("install ok unpacked", package.version):
                raise ValueError(f"reference package state/version changed: {package.selector}")
            profile = package.name if package.name in PROFILE_VERSIONS else "none"
            if profile != "none" and package.version != PROFILE_VERSIONS[profile]:
                raise ValueError(f"unauthorized reference script version: {package.selector}")
            apply(dpkg_command(
                launcher, dpkg, root, architecture, profile, "configure", package,
            ), environment, stdout, stderr)
            unpacked.remove(package)
            configured.add((package.name, package.architecture))
            progressed = True
        if not progressed:
            raise RuntimeError(
                "reference dependency ordering stalled; ambiguous --configure --pending "
                "is not authorized: " + ", ".join(deferred[:20])
            )
    if len(configured) != len(packages):
        raise ValueError("reference closure not fully configured")
    raise RuntimeError(
        "reference trigger closure refused: the launcher has no exact triggered "
        "postinst identity/profile or single-package trigger operation; --pending "
        "and multi-package ordering are not authorized"
    )


def report(root: Path, cache: Path, evidence: Path) -> None:
    packages = packages_from_manifest(evidence / "reference-archives.tsv", cache)
    records = database_packages(root)
    if len(records) != len(packages):
        raise ValueError("reference database differs from signed package closure")
    lines: list[str] = []
    for package in packages:
        key = package.name, package.architecture
        if records.get(key) != ("install ok installed", package.version):
            raise ValueError(f"reference package not installed at signed version: {key}")
        lines.append(f"ii  {package.selector} {package.version}\n")
    (evidence / "reference-installed.txt").write_text("".join(lines))
    info_fd = open_absolute(root / "var/lib/dpkg/info", directory=True)
    try:
        entries = os.listdir(info_fd)
        if len(entries) > MAXIMUM_PACKAGES * 12:
            raise ValueError("reference database info directory exceeds bound")
        for entry in entries:
            if entry.endswith(".list"):
                data = read_root_file(root, f"var/lib/dpkg/info/{entry}", 8 * 1024 * 1024)
                if b"/dev/null" in data.splitlines():
                    raise ValueError("reference package claims excluded chroot device")
    finally:
        os.close(info_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dpkg", type=Path)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--launcher", type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    if not args.root.is_absolute() or not args.cache.is_absolute() or not args.evidence.is_absolute():
        raise ValueError("reference inputs must be absolute paths")
    if args.report_only:
        report(args.root, args.cache, args.evidence)
        return
    if args.dpkg is None or args.launcher is None or not args.dpkg.is_absolute():
        raise ValueError("reference launcher and pinned dpkg are required")
    protected(args.launcher)
    protected(args.dpkg)
    protected(args.cache, directory=True)
    protected(args.evidence, directory=True)
    install(args.launcher, args.dpkg, args.root, args.cache, args.evidence, args.architecture)


if __name__ == "__main__":
    main()
