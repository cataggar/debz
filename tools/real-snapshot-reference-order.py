#!/usr/bin/env python3
"""Install a verified closure with dpkg without bypassing Pre-Depends."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import os
import shutil
import subprocess
import tempfile
import tarfile

from real_snapshot_reference_paths import open_absolute, protected, read_root_file

MAXIMUM_PACKAGES = 2000
MAXIMUM_PROBES = 10000
MAXIMUM_PROBE_OUTPUT = 65536
MAXIMUM_CONTROL_BYTES = 1024 * 1024
MAXIMUM_LOG_BYTES = 16 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*\Z")
DIGEST = re.compile(r"[a-f0-9]{128}\Z")
PROFILE_VERSIONS = {
    "systemd": "259.5-0ubuntu3.4",
    "udev": "259.5-0ubuntu3.4",
    "sudo": "1.9.17p2-1ubuntu3.1",
}
BASE_CYCLE = (
    ("libc6", "2.43-2ubuntu2.4", 2104056,
     "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696",
     "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)"),
    ("libgcc-s1", "16-20260322-1ubuntu1", 80312,
     "a34e93f253ca90bd331c5eee563be6ebcc14dbf08147e82b9479f972fe566c83263b644e348757af1853f8663cb8ca2349e2c013e4a0ca0e3ea3d631297576b2",
     "gcc-16-base (= 16-20260322-1ubuntu1), libc6 (>= 2.35)"),
    ("gcc-16-base", "16-20260322-1ubuntu1", 38296,
     "0767f731e71e709736596d52dbe181245a8ca181cdadbac6226aad5aa7151d8ce5149ad28625facc61d8882e76fc387af5336dc289126a0bf830b9e599b3922c", ""),
    ("libc-gconv-modules-extra", "2.43-2ubuntu2.4", 1362202,
     "c385f1ca4f8054e59f977a38819e31d6f2429909ce0a88c734c874ce163851dfa7e565dded6c65c3feb3bc8cf074498b45a4c2226bb8e17a2bc8b95027a29692", ""),
)
BASE_CYCLE_PROFILE = "libgcc_cycle"
OPENSSL_CYCLE = (
    ("libssl3t64", "3.5.5-1ubuntu3.6", 2364586,
     "10df2f82619faff2ed4b890812313c35cd58abbfce858caf3403e1b654fac857bd7bc28e7a528a79a18ebfbfbdca5cffb3c2dd5b340c729fb7eb2470b76d528d",
     "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy"),
    ("openssl-provider-legacy", "3.5.5-1ubuntu3.6", 39690,
     "cbb4f55a609576d99a1b52952a674e78b2cbb7026e54c765cfd964812b65bdcdea4f5ea67961159b737fcba3093b3b15de8b7a6aff3bbf08a85805a09290c470",
     "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)"),
    BASE_CYCLE[0],
    ("libzstd1", "1.5.7+dfsg-3", 308174,
     "284a44950a9caae10a6b7a06baead5db2d6dd2989fc01107c78c76ef5468cb489fc1a8e92d6cb84d44b5a371f8b1156bd2f5c232e79f1631dcf000a601e52183",
     "libc6 (>= 2.34)"),
    ("zlib1g", "1:1.3.dfsg+really1.3.1-1ubuntu3.1", 61612,
     "a0ad94daadd3099ee40766a62a42d3fa7f431c6d805e9108d1dde07d64bfe3e7da66a41a2294598917e5ef5435df7a239d011711dd6d18037bc9b61b530ed3d4",
     "libc6 (>= 2.14)"),
)
OPENSSL_CYCLE_PROFILE = "openssl_cycle"
SUDO_PRESTATE_COMPANION = ("sudo-rs", "0.2.13-0ubuntu1.2", "amd64")
MAINTAINER_SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config")
LIBGCC_TRIGGERS = b"# Triggers added by dh_makeshlibs/13.31ubuntu1\nactivate-noawait ldconfig\n"


class CycleRefusal(RuntimeError):
    """No authority to break a dependency cycle."""


@dataclass(frozen=True)
class Launcher:
    path: Path
    runtime: Path


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
    launcher: Launcher, dpkg: Path, root: Path, architecture: str, profile: str,
    verb: str, package: Package | None = None, cycle: tuple[Package, ...] = (),
) -> list[str]:
    if verb == "configure_openssl_cycle":
        if (architecture != "amd64" or profile != OPENSSL_CYCLE_PROFILE
            or len(cycle) != len(OPENSSL_CYCLE) or package != cycle[0]
            or any((p.name, p.version, p.architecture, p.size, p.digest) !=
                   (name, version, "amd64", size, digest)
                   for p, (name, version, size, digest, _) in zip(cycle, OPENSSL_CYCLE))):
            raise CycleRefusal("CycleIdentityChanged: unauthorized OpenSSL cycle operation")
        return [str(launcher.path), str(root), str(dpkg), architecture, profile, verb,
                package.selector, str(launcher.runtime), *(str(p.archive) for p in cycle)]
    if verb == "break_base_cycle":
        if (architecture != "amd64" or profile != BASE_CYCLE_PROFILE
            or len(cycle) != len(BASE_CYCLE) or package != cycle[1]
            or any((p.name, p.version, p.architecture, p.size, p.digest) !=
                   (name, version, "amd64", size, digest)
                   for p, (name, version, size, digest, _) in zip(cycle, BASE_CYCLE))):
            raise CycleRefusal("CycleIdentityChanged: unauthorized cycle operation")
        return [str(launcher.path), str(root), str(dpkg), architecture, profile, verb,
                package.selector, str(launcher.runtime), *(str(p.archive) for p in cycle)]
    if cycle:
        raise CycleRefusal("CycleIdentityChanged: archives on a normal operation")
    if verb not in ("probe_unpack", "unpack", "probe_configure", "configure", "continue_prestate"):
        raise ValueError(f"reference dpkg operation has no single-script binding: {verb}")
    if package is None:
        raise ValueError("reference dpkg operation requires one signed package")
    if verb == "continue_prestate" and profile not in ("systemd", "udev"):
        raise ValueError("unauthorized half-configured prestate continuation")
    if profile != "none":
        if (verb not in ("configure", "continue_prestate") or architecture != "amd64"
            or profile not in PROFILE_VERSIONS
            or package.name != profile or package.architecture != architecture
            or package.version != PROFILE_VERSIONS[profile]):
            raise ValueError(f"unauthorized reference script profile: {profile}")
    elif verb == "configure" and package.name in PROFILE_VERSIONS:
        raise ValueError(f"missing exact configure profile: {package.selector}")
    command = [str(launcher.path), str(root), str(dpkg), architecture, profile, verb,
               package.selector, str(launcher.runtime)]
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


@contextlib.contextmanager
def launcher_stdin():
    """The launcher refuses a writable stdin, and subprocess.DEVNULL opens
    /dev/null with O_RDWR."""
    descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def probe(
    command: list[str], environment: dict[str, str], evidence: Path,
) -> tuple[int, bytes]:
    with tempfile.TemporaryDirectory(prefix="reference-probe-", dir=evidence) as temporary:
        output_path = Path(temporary) / "output"
        with output_path.open("x+b") as output, output_path.open("ab") as writer:
            with launcher_stdin() as null:
                result = subprocess.run(
                    command,
                    env=environment,
                    stdin=null,
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
        with launcher_stdin() as null:
            subprocess.run(
                command,
                env=environment,
                stdin=null,
                stdout=output,
                stderr=errors,
                check=True,
                timeout=120,
            )
    if stdout.stat().st_size > MAXIMUM_LOG_BYTES or stderr.stat().st_size > MAXIMUM_LOG_BYTES:
        raise ValueError("reference dpkg output exceeds limit")


def control_fields(data: bytes) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for stanza in data.decode("utf-8").strip().split("\n\n"):
        if not stanza:
            continue
        fields: dict[str, str] = {}
        previous: str | None = None
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                if previous is None or previous in ("package", "architecture", "version", "status"):
                    raise ValueError("invalid continuation in reference database identity")
                fields[previous] += "\n" + line
                continue
            key, separator, value = line.partition(":")
            if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key):
                raise ValueError("malformed reference database field")
            if value and not value.startswith(" "):
                raise ValueError("malformed reference database field")
            value = value[1:]
            previous = key.lower()
            if previous in fields:
                raise ValueError(f"duplicate reference database field: {key}")
            fields[previous] = value
        records.append(fields)
    return records


def database_fields(root: Path) -> dict[tuple[str, str], dict[str, str]]:
    records: dict[tuple[str, str], dict[str, str]] = {}
    data = read_root_file(root, "var/lib/dpkg/status", 4 * 1024 * 1024)
    for fields in control_fields(data):
        name = fields["package"]
        architecture = fields["architecture"]
        version = fields["version"]
        status = fields["status"]
        if not NAME.fullmatch(name) or not NAME.fullmatch(architecture) or not version:
            raise ValueError("invalid reference database package")
        key = name, architecture
        if key in records:
            raise ValueError(f"duplicate reference database package: {key}")
        records[key] = fields
    return records


def database_packages(root: Path) -> dict[tuple[str, str], tuple[str, str]]:
    return {key: (fields["status"], fields["version"])
            for key, fields in database_fields(root).items()}


def base_cycle_packages(packages: list[Package], architecture: str) -> tuple[Package, ...]:
    if architecture != "amd64":
        raise CycleRefusal("UnknownCycle: no reviewed base cycle for this architecture")
    cycle: list[Package] = []
    for name, version, size, digest, _ in BASE_CYCLE:
        matches = [p for p in packages if p.name == name]
        if (len(matches) != 1 or
            (matches[0].version, matches[0].architecture, matches[0].size, matches[0].digest)
                != (version, "amd64", size, digest)):
            raise CycleRefusal(f"CycleIdentityChanged: {name}")
        cycle.append(matches[0])
    return tuple(cycle)


def trigger_database(root: Path) -> dict[str, dict]:
    updates = open_absolute(root / "var/lib/dpkg/updates", directory=True)
    try:
        if os.listdir(updates):
            raise CycleRefusal("CycleStateChanged: pending database updates")
    finally:
        os.close(updates)
    directory = open_absolute(root / "var/lib/dpkg/triggers", directory=True)
    try:
        names = os.listdir(directory)
        if len(names) > MAXIMUM_PACKAGES:
            raise CycleRefusal("CycleCallbackChanged: trigger database exceeds bound")
        result = {}
        for name in sorted(names):
            data = read_root_file(root, f"var/lib/dpkg/triggers/{name}", MAXIMUM_CONTROL_BYTES)
            if name == "Unincorp" and data:
                raise CycleRefusal("CycleCallbackChanged: unincorporated trigger activations")
            result[name] = {"size": len(data), "sha512": hashlib.sha512(data).hexdigest()}
        return result
    finally:
        os.close(directory)


def verify_base_cycle(root: Path, cycle: tuple[Package, ...]) -> dict:
    records = database_fields(root)
    triggers_before = trigger_database(root)
    graph: dict[str, dict] = {}
    for index, (package, binding) in enumerate(zip(cycle, BASE_CYCLE)):
        try:
            verify_archive(package)
        except (ValueError, OSError) as error:
            raise CycleRefusal(f"CycleIdentityChanged: {package.name}: {error}") from error
        result = subprocess.run(
            ["dpkg-deb", "--ctrl-tarfile", str(package.archive)],
            env=oracle_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            check=True, timeout=30,
        )
        if len(result.stdout) > MAXIMUM_CONTROL_BYTES or result.stderr:
            raise CycleRefusal("CycleControlChanged: oversized control archive")
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            members = archive.getmembers()
            control = archive.extractfile("./control")
            if control is None:
                raise CycleRefusal("CycleControlChanged: missing control")
            fields, = control_fields(control.read(MAXIMUM_PROBE_OUTPUT + 1))
            if index == 1 and {m.name for m in members} != {
                ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers",
            }:
                raise CycleRefusal("CycleCallbackChanged: libgcc-s1 must have no scripts")
            if index == 1:
                triggers = archive.extractfile("./triggers")
                if triggers is None or triggers.read() != LIBGCC_TRIGGERS:
                    raise CycleRefusal("CycleCallbackChanged: signed trigger activation changed")
        if (fields.get("package") != package.name or fields.get("version") != package.version
            or fields.get("architecture") != "amd64" or fields.get("depends", "") != binding[4]
            or fields.get("pre-depends", "")):
            raise CycleRefusal(f"CycleControlChanged: signed dependency graph: {package.name}")
        installed = records.get((package.name, "amd64"))
        expected = "install ok unpacked" if index < 2 else "install ok installed"
        if installed is None or installed.get("version") != package.version:
            raise CycleRefusal(f"CycleStateChanged: {package.name}")
        if installed.get("status") != expected:
            reason = "CycleStateChanged" if index < 2 else "CycleOutsideDependency"
            raise CycleRefusal(f"{reason}: {package.name}")
        for field in ("depends", "pre-depends", "provides", "conflicts", "breaks", "replaces",
                      "multi-arch", "protected", "essential"):
            if installed.get(field, "") != fields.get(field, ""):
                raise CycleRefusal(f"CycleControlChanged: installed {package.name} {field}")
        if any(installed.get(field) for field in ("triggers-pending", "triggers-awaited", "config-version")):
            raise CycleRefusal(f"CycleCallbackChanged: {package.name} trigger state")
        graph[package.name] = {"version": package.version, "archive_sha512": package.digest,
                               "depends": binding[4], "pre_depends": "", "status": expected}
    info = root / "var/lib/dpkg/info"
    try:
        installed_triggers = read_root_file(root, "var/lib/dpkg/info/libgcc-s1:amd64.triggers", 1024)
    except (ValueError, OSError) as error:
        raise CycleRefusal("CycleCallbackChanged: installed trigger activation missing") from error
    if installed_triggers != LIBGCC_TRIGGERS:
        raise CycleRefusal("CycleCallbackChanged: installed trigger activation changed")
    if (info / "libgcc-s1.triggers").exists() or (info / "libgcc-s1.triggers").is_symlink():
        raise CycleRefusal("CycleCallbackChanged: ambiguous installed trigger activation")
    for script in MAINTAINER_SCRIPTS:
        for name in ("libgcc-s1", "libgcc-s1:amd64"):
            path = info / f"{name}.{script}"
            if path.exists() or path.is_symlink():
                raise CycleRefusal(f"CycleCallbackChanged: unexpected {path.name}")
    return {"graph": graph, "records": records, "callbacks": [],
            "trigger_database": triggers_before,
            "status_sha512": hashlib.sha512(read_root_file(
                root, "var/lib/dpkg/status", 4 * 1024 * 1024,
            )).hexdigest(),
            "profile": BASE_CYCLE_PROFILE, "force": ["--force-depends"]}


def break_base_cycle(
    launcher: Launcher, dpkg: Path, root: Path, evidence: Path, architecture: str,
    packages: list[Package], environment: dict[str, str], stdout: Path, stderr: Path,
) -> Package:
    cycle = base_cycle_packages(packages, architecture)
    before = verify_base_cycle(root, cycle)
    command = dpkg_command(launcher, dpkg, root, architecture, BASE_CYCLE_PROFILE,
                           "break_base_cycle", cycle[1], cycle)
    (evidence / "base-cycle-before.json").write_text(json.dumps(
        {**before, "records": list(before["records"].values())}, sort_keys=True,
    ) + "\n")
    apply(command, environment, stdout, stderr)
    after = database_fields(root)
    triggers_after = trigger_database(root)
    expected = {key: dict(value) for key, value in before["records"].items()}
    expected[("libgcc-s1", "amd64")]["status"] = "install ok installed"
    if after != expected or triggers_after != before["trigger_database"]:
        raise CycleRefusal("CycleNoProgress: database changed beyond the one reviewed transition")
    (evidence / "base-cycle-after.json").write_text(json.dumps({
        "operation": command[3:], "callbacks": [], "status": "install ok installed",
        "trigger_database": triggers_after,
        "status_sha512": hashlib.sha512(read_root_file(
            root, "var/lib/dpkg/status", 4 * 1024 * 1024,
        )).hexdigest(),
        "records": list(after.values()),
    }, sort_keys=True) + "\n")
    return cycle[1]


def openssl_cycle_packages(packages: list[Package], architecture: str) -> tuple[Package, ...]:
    if architecture != "amd64":
        raise CycleRefusal("UnknownCycle: no reviewed OpenSSL cycle for this architecture")
    cycle = []
    for name, version, size, digest, _ in OPENSSL_CYCLE:
        matches = [p for p in packages if p.name == name]
        if (len(matches) != 1 or
            (matches[0].version, matches[0].architecture, matches[0].size, matches[0].digest)
                != (version, "amd64", size, digest)):
            raise CycleRefusal(f"CycleIdentityChanged: {name}")
        cycle.append(matches[0])
    return tuple(cycle)


def verify_openssl_cycle(root: Path, cycle: tuple[Package, ...]) -> dict:
    records = database_fields(root)
    triggers_before = trigger_database(root)
    graph = {}
    for index, (package, binding) in enumerate(zip(cycle, OPENSSL_CYCLE)):
        try:
            verify_archive(package)
        except (ValueError, OSError) as error:
            raise CycleRefusal(f"CycleIdentityChanged: {package.name}: {error}") from error
        result = subprocess.run(
            ["dpkg-deb", "--ctrl-tarfile", str(package.archive)],
            env=oracle_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            check=True, timeout=30,
        )
        if len(result.stdout) > MAXIMUM_CONTROL_BYTES or result.stderr:
            raise CycleRefusal("CycleControlChanged: oversized OpenSSL control archive")
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            control = archive.extractfile("./control")
            if control is None:
                raise CycleRefusal("CycleControlChanged: missing OpenSSL control")
            fields, = control_fields(control.read(MAXIMUM_PROBE_OUTPUT + 1))
            if index < 2:
                expected_members = {".", "./control", "./md5sums"}
                if index == 0:
                    expected_members.update(("./shlibs", "./symbols", "./triggers"))
                if {m.name for m in archive.getmembers()} != expected_members:
                    raise CycleRefusal("CycleCallbackChanged: OpenSSL pair must have no scripts")
                if index == 0 and archive.extractfile("./triggers").read() != LIBGCC_TRIGGERS:
                    raise CycleRefusal("CycleCallbackChanged: OpenSSL trigger activation changed")
        if (fields.get("package") != package.name or fields.get("version") != package.version
            or fields.get("architecture") != "amd64" or fields.get("depends", "") != binding[4]
            or fields.get("pre-depends", "")):
            raise CycleRefusal(f"CycleControlChanged: signed OpenSSL graph: {package.name}")
        installed = records.get((package.name, "amd64"))
        expected = "install ok unpacked" if index < 2 else "install ok installed"
        if installed is None or installed.get("version") != package.version:
            raise CycleRefusal(f"CycleStateChanged: {package.name}")
        if installed.get("status") != expected:
            reason = "CycleStateChanged" if index < 2 else "CycleOutsideDependency"
            raise CycleRefusal(f"{reason}: {package.name}")
        for field in ("depends", "pre-depends", "provides", "conflicts", "breaks", "replaces",
                      "multi-arch", "protected", "essential"):
            if installed.get(field, "") != fields.get(field, ""):
                raise CycleRefusal(f"CycleControlChanged: installed {package.name} {field}")
        if any(installed.get(field) for field in ("triggers-pending", "triggers-awaited", "config-version")):
            raise CycleRefusal(f"CycleCallbackChanged: {package.name} trigger state")
        graph[package.name] = {"version": package.version, "archive_sha512": package.digest,
                               "depends": binding[4], "pre_depends": "", "status": expected,
                               "multi_arch": fields.get("multi-arch", "")}
    installed_triggers = read_root_file(root, "var/lib/dpkg/info/libssl3t64:amd64.triggers", 1024)
    if installed_triggers != LIBGCC_TRIGGERS:
        raise CycleRefusal("CycleCallbackChanged: installed OpenSSL trigger activation changed")
    info = root / "var/lib/dpkg/info"
    forbidden = ["libssl3t64.triggers", "openssl-provider-legacy.triggers",
                 "openssl-provider-legacy:amd64.triggers"]
    forbidden.extend(f"{name}.{script}" for name in (
        "libssl3t64", "libssl3t64:amd64", "openssl-provider-legacy", "openssl-provider-legacy:amd64",
    ) for script in MAINTAINER_SCRIPTS)
    for name in forbidden:
        path = info / name
        if path.exists() or path.is_symlink():
            raise CycleRefusal(f"CycleCallbackChanged: unexpected {name}")
    return {"graph": graph, "records": records, "callbacks": [],
            "trigger_database": triggers_before, "profile": OPENSSL_CYCLE_PROFILE, "force": []}


def configure_openssl_cycle(
    launcher: Launcher, dpkg: Path, root: Path, evidence: Path, architecture: str,
    packages: list[Package], environment: dict[str, str], stdout: Path, stderr: Path,
) -> tuple[Package, ...]:
    cycle = openssl_cycle_packages(packages, architecture)
    before = verify_openssl_cycle(root, cycle)
    refusals = []
    for package, peer in ((cycle[0], cycle[1]), (cycle[1], cycle[0])):
        command = dpkg_command(launcher, dpkg, root, architecture, "none", "probe_configure", package)
        status, output = probe(command, environment, evidence)
        refusals.append({"argv": command[3:], "exit_status": status,
                         "output": output.decode("utf-8", errors="replace")})
        (evidence / "openssl-cycle-refusals.json").write_text(json.dumps(refusals, sort_keys=True) + "\n")
        peer_name = (
            peer.name if peer.architecture == architecture
            and before["graph"][peer.name]["multi_arch"] != "same" else peer.selector
        )
        if (not status or b"dependency problems" not in output
            or f"Package {peer_name} is not configured yet.".encode() not in output):
            raise CycleRefusal(f"CycleProbeChanged: {package.selector} did not refuse its exact peer")
    (evidence / "openssl-cycle-before.json").write_text(json.dumps(
        {**before, "records": list(before["records"].values())}, sort_keys=True,
    ) + "\n")
    command = dpkg_command(launcher, dpkg, root, architecture, OPENSSL_CYCLE_PROFILE,
                           "configure_openssl_cycle", cycle[0], cycle)
    apply(command, environment, stdout, stderr)
    after = database_fields(root)
    triggers_after = trigger_database(root)
    expected = {key: dict(value) for key, value in before["records"].items()}
    for package in cycle[:2]:
        expected[(package.name, "amd64")]["status"] = "install ok installed"
    if after != expected or triggers_after != before["trigger_database"]:
        raise CycleRefusal("CycleNoProgress: database changed beyond the two reviewed OpenSSL transitions")
    (evidence / "openssl-cycle-after.json").write_text(json.dumps({
        "operation": command[3:], "callbacks": [], "force": [],
        "trigger_database": triggers_after, "records": list(after.values()),
    }, sort_keys=True) + "\n")
    return cycle[:2]


def stage_pending_runtime(baseline: Path, setpriv: Path) -> dict:
    """Stage setpriv's signed library only in the unregistered pending oracle."""
    source = setpriv.with_name("libcap-ng.so.0.0.0")
    try:
        meta = protected(source)
        if meta.st_size != 26928 or meta.st_mode & 0o7777 != 0o644:
            raise ValueError("signed library metadata")
        data = read_root_file(source.parent, source.name, 26928)
        digest = hashlib.sha256(data).hexdigest()
        if digest != "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f":
            raise ValueError("signed library bytes")
        relative = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0"
        target = baseline / relative
        protected(target.parent, directory=True)
        with target.open("xb") as output:
            output.write(data)
        target.chmod(0o644)
    except (OSError, ValueError) as error:
        raise CycleRefusal(f"CycleProofRuntimeChanged: setpriv libcap-ng: {error}") from error
    return {"source": str(source), "target": relative, "sha256": digest,
            "size": len(data), "mode": "0644"}


def record_pending_result(proof: Path, command: list[str], result: subprocess.CompletedProcess,
                          runtime: dict) -> None:
    # Refused loader/setup/callback attempts must retain their own bounded evidence.
    (proof / "pending.stdout").write_bytes(result.stdout[:MAXIMUM_PROBE_OUTPUT])
    (proof / "pending.stderr").write_bytes(result.stderr[:MAXIMUM_PROBE_OUTPUT])
    (proof / "pending-result.json").write_text(json.dumps({
        "schema": "io.github.cataggar.debz.base-cycle-pending-result.v1",
        "argv": command, "returncode": result.returncode, "setpriv_runtime": runtime,
        "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
        "output_truncated": (len(result.stdout) > MAXIMUM_PROBE_OUTPUT
                             or len(result.stderr) > MAXIMUM_PROBE_OUTPUT),
    }, sort_keys=True) + "\n")


def prove_base_cycle(
    launcher: Launcher, dpkg: Path, root: Path, cache: Path, evidence: Path, setpriv: Path,
) -> None:
    """A four-package pending oracle, never a pending operation on the full closure."""
    if os.uname().machine != "x86_64" or database_packages(root):
        raise CycleRefusal("CycleProofPrestate: requires a fresh empty amd64 database")
    protected(root, directory=True)
    protected(setpriv)
    if hashlib.sha256(setpriv.read_bytes()).hexdigest() != (
        "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993"
    ):
        raise CycleRefusal("CycleProofRuntimeChanged: signed setpriv")
    cycle = base_cycle_packages(packages_from_manifest(evidence / "reference-archives.tsv", cache), "amd64")
    proof = evidence / "base-cycle-proof"
    proof.mkdir(mode=0o700)
    environment = oracle_environment()
    seed = proof / "seed"
    subprocess.run(["cp", "-a", "--one-file-system", "--", str(root), str(seed)],
                   check=True, timeout=60)
    stdout, stderr = proof / "unpack.stdout", proof / "unpack.stderr"
    for package in (cycle[2], cycle[3], cycle[0], cycle[1]):
        verify_archive(package)
        apply(dpkg_command(launcher, dpkg, seed, "amd64", "none", "unpack", package),
              environment, stdout, stderr)
    for package in cycle[2:]:
        apply(dpkg_command(launcher, dpkg, seed, "amd64", "none", "configure", package),
              environment, stdout, stderr)
    verify_base_cycle(seed, cycle)
    for package in cycle[:2]:
        status, output = probe(dpkg_command(launcher, dpkg, seed, "amd64", "none",
                                           "probe_configure", package), environment, proof)
        if status == 0 or b"dependency problems" not in output:
            raise CycleRefusal("CycleProofMissingStall: single configure did not refuse")
    candidate, baseline = proof / "candidate", proof / "pending"
    for destination in (candidate, baseline):
        subprocess.run(["cp", "-a", "--one-file-system", "--", str(seed), str(destination)],
                       check=True, timeout=60)
    refused_command = dpkg_command(launcher, dpkg, candidate, "amd64", BASE_CYCLE_PROFILE,
                                   "break_base_cycle", cycle[1], cycle)
    before_refusal = database_fields(candidate)
    before_triggers = trigger_database(candidate)
    injected = candidate / "var/lib/dpkg/info/libgcc-s1:amd64.postinst"
    injected.write_text("#!/bin/sh\necho unbound-cycle-callback-executed\nexit 0\n")
    injected.chmod(0o755)
    try:
        status, output = probe(refused_command, environment, proof)
        if (status == 0 or b"unbound-cycle-callback-executed" in output
            or b"stage 11" not in output or database_fields(candidate) != before_refusal
            or trigger_database(candidate) != before_triggers):
            raise CycleRefusal("CycleProofCallbackChanged: launcher mutation did not refuse before exec")
    finally:
        injected.unlink()
    (proof / "callback-refusal.log").write_bytes(output)
    break_base_cycle(launcher, dpkg, candidate, proof, "amd64", list(cycle),
                     environment, proof / "candidate.stdout", proof / "candidate.stderr")
    if len(database_packages(baseline)) != 4:
        raise CycleRefusal("CycleProofCallbackChanged: oracle pending set is not exactly four")
    verify_base_cycle(baseline, cycle)
    scripts = [baseline / f"var/lib/dpkg/info/{name}.postinst"
               for name in ("libc6", "libc6:amd64")]
    script, = [path for path in scripts if path.exists()]
    signed_control = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(cycle[0].archive)],
                                             env=environment, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(signed_control)) as archive:
        signed_script = archive.extractfile("./postinst")
        signed_bytes = signed_script.read() if signed_script else b""
        if not signed_bytes or read_root_file(
            baseline, str(script.relative_to(baseline)), MAXIMUM_PROBE_OUTPUT,
        ) != signed_bytes:
            raise CycleRefusal("CycleProofCallbackChanged: libc6 postinst")
    # The only pending callback is denied before exec, not merely audited afterwards.
    shutil.copyfile(dpkg, baseline / "usr/bin/dpkg")
    shutil.copyfile(setpriv, baseline / "usr/bin/setpriv")
    (baseline / "usr/bin/setpriv").chmod(0o755)
    runtime = stage_pending_runtime(baseline, setpriv)
    before_pending = list(database_fields(baseline).values())
    subprocess.run(["mount", "--bind", "--", str(script), str(script)], check=True, timeout=30)
    try:
        subprocess.run(["mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", str(script)],
                       check=True, timeout=30)
        command = [
            "unshare", "--mount", "--pid", "--fork", "--kill-child=SIGKILL",
            "--propagation", "private", "--", "chroot", str(baseline),
            "/usr/bin/setpriv",
            "--bounding-set=-all,+chown,+dac_override,+fowner,+fsetid,+setgid,+setuid,+setfcap",
            "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
            "/usr/bin/dpkg", "--root=/", "--force-not-root", "--force-bad-path",
            "--force-confold", "--no-triggers", "--configure", "--pending",
        ]
        result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, check=False, timeout=120)
        record_pending_result(proof, command, result, runtime)
    finally:
        subprocess.run(["umount", "--", str(script)], check=True, timeout=30)
    (proof / "pending-status.json").write_text(json.dumps({
        "before": before_pending, "after": list(database_fields(baseline).values()),
        "trigger_database": trigger_database(baseline),
    }, sort_keys=True) + "\n")
    if (len(result.stdout) > MAXIMUM_PROBE_OUTPUT or len(result.stderr) > MAXIMUM_PROBE_OUTPUT
        or result.returncode == 0 or b"Permission denied" not in result.stderr
        or b"post-installation script" not in result.stderr):
        raise CycleRefusal("CycleProofCallbackChanged: libc6 callback was not denied")
    if read_root_file(baseline, str(script.relative_to(baseline)), MAXIMUM_PROBE_OUTPUT) != signed_bytes:
        raise CycleRefusal("CycleProofCallbackChanged: denied libc6 postinst changed")
    observed = database_packages(baseline)
    wanted = database_packages(candidate)
    expected = dict(wanted)
    expected[("libc6", "amd64")] = ("install ok half-configured", cycle[0].version)
    if observed != expected:
        raise CycleRefusal(f"CycleProofScheduleChanged: {observed!r}")
    (proof / "comparison.json").write_text(json.dumps({
        "schema": "io.github.cataggar.debz.base-cycle-proof.v1",
        "callbacks_executed": [], "callback_denied": "libc6 postinst configure",
        "candidate": list(database_fields(candidate).values()),
        "pending": list(database_fields(baseline).values()),
        "candidate_trigger_database": trigger_database(candidate),
        "pending_trigger_database": trigger_database(baseline),
        "pending_argv": command,
        "pending_setpriv_runtime": runtime,
        "difference": "pending attempts libc6 configure; single breaker leaves libc6 unpacked",
        "parity_claim": False,
    }, sort_keys=True) + "\n")
    for destination in (seed, candidate, baseline):
        subprocess.run(["rm", "-rf", "--one-file-system", "--", str(destination)],
                       check=True, timeout=60)


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
    launcher: Launcher,
    dpkg: Path,
    root: Path,
    architecture: str,
    package: Package,
    environment: dict[str, str],
    stdout: Path,
    stderr: Path,
) -> None:
    """Let dpkg start configuring, but deny execution of the installed postinst."""
    script = root / "var/lib/dpkg/info" / f"{package.name}.postinst"
    if script.is_symlink() or not script.is_file():
        raise ValueError(f"prestate postinst is not a regular file: {package.selector}")
    before = hashlib.sha256(script.read_bytes()).hexdigest()
    profile = package.name if package.name in PROFILE_VERSIONS else "none"
    if profile == "none" or package.version != PROFILE_VERSIONS[profile]:
        raise ValueError(f"unauthorized interrupted prestate package: {package.selector}")
    subprocess.run(["mount", "--bind", "--", str(script), str(script)], check=True, timeout=30)
    try:
        subprocess.run(
            ["mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", str(script)],
            check=True,
            timeout=30,
        )
        with tempfile.TemporaryDirectory(
            prefix="reference-configure-", dir=stdout.parent,
        ) as temporary:
            output_path = Path(temporary) / "stdout"
            errors_path = Path(temporary) / "stderr"
            with output_path.open("x+b") as output, errors_path.open("x+b") as errors, \
                    output_path.open("ab") as out_writer, errors_path.open("ab") as err_writer:
                with launcher_stdin() as null:
                    result = subprocess.run(
                        dpkg_command(launcher, dpkg, root, architecture, profile, "configure", package),
                        env=environment,
                        stdin=null,
                        stdout=out_writer,
                        stderr=err_writer,
                        check=False,
                        timeout=120,
                    )
                out_writer.flush()
                err_writer.flush()
                if (
                    output_path.stat().st_size > MAXIMUM_PROBE_OUTPUT
                    or errors_path.stat().st_size > MAXIMUM_PROBE_OUTPUT
                ):
                    raise ValueError("interrupted configure output exceeds limit")
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
    launcher: Launcher,
    dpkg: Path,
    root: Path,
    architecture: str,
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
        interrupt_postinst(launcher, dpkg, root, architecture, package, environment, stdout, stderr)
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
            check=True,
            timeout=600,
        )
        destination.chmod(0o700)
    finally:
        if mounted:
            subprocess.run(
                ["mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", str(proc)],
                check=True,
                timeout=30,
            )
    with (destination.parent / "prestates.tsv").open("a") as record:
        record.write(f"{package.selector}\t{expected}\t{destination}\n")


def install(
    launcher: Launcher, dpkg: Path, root: Path, cache: Path, evidence: Path,
    architecture: str, prestates: tuple[Prestate, ...] = (),
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
    if "sudo:amd64" in targets:
        name, version, companion_architecture = SUDO_PRESTATE_COMPANION
        companions = [package for package in packages if package.name == name]
        if len(companions) != 1 or (
            companions[0].version, companions[0].architecture,
        ) != (version, companion_architecture):
            raise ValueError("signed sudo prestate requires its exact reviewed sudo-rs companion")
    pending = packages[:]
    unpacked: list[Package] = []
    configured: set[tuple[str, str]] = set()
    environment = oracle_environment()
    stdout = evidence / "reference-install.stdout"
    stderr = evidence / "reference-install.stderr"
    probes = 0
    cycle_broken = False
    openssl_configured = False
    while pending or unpacked:
        progressed = False
        deferred: list[str] = []
        refusals = []
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
                refusals.append({"selector": package.selector, "operation": "probe_unpack",
                                 "exit_status": status, "output_bytes": len(output),
                                 "output_prefix_hex": output[:4096].hex(),
                                 "output_sha512": hashlib.sha512(output).hexdigest()})
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
                refusals.append({"selector": package.selector, "operation": "probe_configure",
                                 "exit_status": status, "output_bytes": len(output),
                                 "output_prefix_hex": output[:4096].hex(),
                                 "output_sha512": hashlib.sha512(output).hexdigest()})
                continue
            current = database_packages(root).get((package.name, package.architecture))
            if current != ("install ok unpacked", package.version):
                raise ValueError(f"reference package state/version changed: {package.selector}")
            profile = package.name if package.name in PROFILE_VERSIONS else "none"
            if profile != "none" and package.version != PROFILE_VERSIONS[profile]:
                raise ValueError(f"unauthorized reference script version: {package.selector}")
            prestate = targets.get(package.selector)
            if prestate is not None and package.selector == "sudo:amd64":
                name, version, companion_architecture = SUDO_PRESTATE_COMPANION
                key = name, companion_architecture
                companion_state = database_packages(root).get(key)
                if companion_state != ("install ok installed", version):
                    if key in configured or (companion_state is not None and companion_state[1] != version):
                        raise ValueError("signed sudo prestate companion state/version changed")
                    deferred.append(package.selector)
                    continue
            targets.pop(package.selector, None)
            operation = "configure"
            if prestate is not None:
                capture_prestate(
                    launcher, dpkg, root, architecture, package, prestate,
                    environment, stdout, stderr,
                )
                if not targets:
                    return
                if prestate.status == "half-configured":
                    if database_packages(root).get((package.name, package.architecture)) != (
                        "install ok half-configured", package.version,
                    ):
                        raise ValueError(f"captured prestate state/version changed: {package.selector}")
                    operation = "continue_prestate"
            apply(dpkg_command(
                launcher, dpkg, root, architecture, profile, operation, package,
            ), environment, stdout, stderr)
            unpacked.remove(package)
            configured.add((package.name, package.architecture))
            progressed = True
        if not progressed:
            (evidence / "reference-no-progress.json").write_text(json.dumps({
                "base_cycle_applied": cycle_broken, "openssl_cycle_applied": openssl_configured,
                "deferred": deferred, "refusals": refusals[:128],
                "refusals_truncated": len(refusals) > 128,
            }, sort_keys=True) + "\n")
            if not cycle_broken:
                if base_cycle_packages(packages, architecture)[1] not in unpacked:
                    raise CycleRefusal("CycleStateChanged: selected member is not unpacked")
                selected = break_base_cycle(
                    launcher, dpkg, root, evidence, architecture, packages,
                    environment, stdout, stderr,
                )
                unpacked.remove(selected)
                configured.add((selected.name, selected.architecture))
                cycle_broken = True
                continue
            if (not openssl_configured and
                {"libssl3t64", "openssl-provider-legacy"} <= {p.name for p in unpacked}):
                probes += 2
                if probes > MAXIMUM_PROBES:
                    raise ValueError("reference dpkg dependency probe limit exceeded")
                selected = configure_openssl_cycle(
                    launcher, dpkg, root, evidence, architecture, packages,
                    environment, stdout, stderr,
                )
                for package in selected:
                    unpacked.remove(package)
                    configured.add((package.name, package.architecture))
                openssl_configured = True
                continue
            raise CycleRefusal(
                "CycleNoProgress: reference dependency ordering stalled; ambiguous --configure --pending "
                "is not authorized: " + ", ".join(deferred[:20])
            )
    if targets:
        raise RuntimeError("prestate package was never configured")
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
    parser.add_argument("--prove-base-cycle", type=Path, metavar="SIGNED_SETPRIV")
    parser.add_argument("--launcher", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument(
        "--prestate", type=parse_prestate, action="append", default=[],
        metavar="PACKAGE:ARCH=STATUS:DESTINATION",
        help="copy the root just before configuring PACKAGE, then stop after the last copy",
    )
    args = parser.parse_args()
    if not args.root.is_absolute() or not args.cache.is_absolute() or not args.evidence.is_absolute():
        raise ValueError("reference inputs must be absolute paths")
    if args.report_only:
        report(args.root, args.cache, args.evidence)
        return
    if args.dpkg is None or args.launcher is None or args.runtime is None or not args.dpkg.is_absolute():
        raise ValueError("reference launcher, authenticated runtime and pinned dpkg are required")
    protected(args.launcher)
    protected(args.dpkg)
    protected(args.runtime, directory=True)
    protected(args.cache, directory=True)
    protected(args.evidence, directory=True)
    if args.prove_base_cycle is not None:
        if args.architecture != "amd64" or args.prestate:
            raise CycleRefusal("CycleProofPrestate: requires amd64 and no capture targets")
        prove_base_cycle(Launcher(args.launcher, args.runtime), args.dpkg, args.root, args.cache, args.evidence,
                         args.prove_base_cycle)
        return
    install(
        Launcher(args.launcher, args.runtime), args.dpkg, args.root, args.cache, args.evidence,
        args.architecture, tuple(args.prestate),
    )


if __name__ == "__main__":
    main()
