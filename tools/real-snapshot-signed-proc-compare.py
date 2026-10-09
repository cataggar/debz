#!/usr/bin/env python3
"""Compare a native signed-script replay root with its pinned-dpkg proof root.

Both roots start as copies of the same generated prestate. Every entry below
each root (excluding the contents of the empty ``proc`` mountpoint) is
compared by type, owner, mode, size, link count, link target, device number
and SHA-256 content. A difference is accepted only when one of the reviewed
rules below explains it exactly; everything else is reported and fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Callable, Optional

MAXIMUM_ENTRIES = 200_000
MAXIMUM_FILE_BYTES = 512 * 1024 * 1024
MAXIMUM_READ_BYTES = 4 * 1024 * 1024
MAXIMUM_REPORTED = 400

PINNED_DPKG_SHA256 = "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5"
SNAPSHOT_DPKG_SHA256 = "972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517"
SETPRIV_SHA256 = "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993"
TARGETS = ("systemd", "udev", "sudo")
ARCHITECTURE = "amd64"

MACHINE_ID = re.compile(rb"[0-9a-f]{32}\n")
ALTERNATIVES_STAMP = re.compile(
    rb"^update-alternatives [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}: ",
    re.MULTILINE,
)
MD5 = re.compile(r"[0-9a-f]{32}")

Entry = Optional[dict]
Reader = Callable[[str], bytes]


def describe(root: Path, relative: str, entry: os.stat_result) -> dict[str, object]:
    mode = entry.st_mode
    record: dict[str, object] = {
        "uid": entry.st_uid,
        "gid": entry.st_gid,
        "mode": oct(stat.S_IMODE(mode)),
    }
    if stat.S_ISDIR(mode):
        record["type"] = "directory"
    elif stat.S_ISLNK(mode):
        record["type"] = "symlink"
        record["target"] = os.readlink(root / relative)
    elif stat.S_ISREG(mode):
        if entry.st_size > MAXIMUM_FILE_BYTES:
            raise ValueError(f"comparison file exceeds limit: {relative}")
        digest = hashlib.sha256()
        descriptor = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            if os.fstat(source.fileno()).st_ino != entry.st_ino:
                raise ValueError(f"comparison file changed: {relative}")
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        record.update(
            type="file", size=entry.st_size, links=entry.st_nlink,
            sha256=digest.hexdigest(),
        )
    elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        record["type"] = "character" if stat.S_ISCHR(mode) else "block"
        record["device"] = f"{os.major(entry.st_rdev)}:{os.minor(entry.st_rdev)}"
    elif stat.S_ISFIFO(mode):
        record["type"] = "fifo"
    elif stat.S_ISSOCK(mode):
        record["type"] = "socket"
    else:
        raise ValueError(f"unsupported comparison entry: {relative}")
    return record


def inventory(root: Path) -> dict[str, dict[str, object]]:
    top = os.lstat(root)
    if not stat.S_ISDIR(top.st_mode) or top.st_uid != 0:
        raise ValueError(f"comparison root is not a root-owned directory: {root}")
    entries: dict[str, dict[str, object]] = {}
    pending = [""]
    while pending:
        directory = pending.pop()
        with os.scandir(root / directory if directory else root) as iterator:
            for child in iterator:
                relative = f"{directory}/{child.name}" if directory else child.name
                entry = os.lstat(root / relative)
                if entry.st_dev != top.st_dev:
                    raise ValueError(f"comparison root crosses a mount: {relative}")
                entries[relative] = describe(root, relative, entry)
                if len(entries) > MAXIMUM_ENTRIES:
                    raise ValueError("comparison root exceeds entry limit")
                if stat.S_ISDIR(entry.st_mode):
                    if relative == "proc":
                        if any(os.scandir(root / relative)):
                            raise ValueError("comparison proc mountpoint is not empty")
                        continue
                    pending.append(relative)
    return entries


def reader(root: Path, entries: dict[str, dict[str, object]]) -> Reader:
    def read(relative: str) -> bytes:
        entry = entries.get(relative)
        if entry is None or entry["type"] != "file" or entry["size"] > MAXIMUM_READ_BYTES:
            raise ValueError(f"comparison content is not a bounded regular file: {relative}")
        descriptor = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            data = source.read(MAXIMUM_READ_BYTES + 1)
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"comparison file changed: {relative}")
        return data
    return read


def root_file(entry: Entry, mode: str, sha256: Optional[str] = None) -> bool:
    return (
        entry is not None and entry["type"] == "file" and entry["uid"] == 0
        and entry["gid"] == 0 and entry["mode"] == mode and entry["links"] == 1
        and (sha256 is None or entry["sha256"] == sha256)
    )


def same_except_content(left: Entry, right: Entry) -> bool:
    if left is None or right is None:
        return False
    return {**left, "sha256": None} == {**right, "sha256": None}


def stanzas(data: bytes) -> dict[str, list[tuple[str, str]]]:
    parsed: dict[str, list[tuple[str, str]]] = {}
    for block in data.decode("utf-8").split("\n\n"):
        if not block.strip():
            continue
        fields: list[tuple[str, str]] = []
        for line in block.split("\n"):
            if line.startswith((" ", "\t")) and fields:
                name, value = fields[-1]
                fields[-1] = (name, f"{value}\n{line}")
            else:
                name, separator, value = line.partition(":")
                if not separator or not name:
                    raise ValueError(f"malformed dpkg status line: {line!r}")
                fields.append((name, value.strip()))
        field = dict(fields)
        key = f"{field.get('Package')}:{field.get('Architecture')}"
        if key in parsed:
            raise ValueError(f"duplicate dpkg status stanza: {key}")
        parsed[key] = fields
    return parsed


def conffiles(value: str) -> list[list[str]]:
    return [line.split() for line in value.split("\n") if line.strip()]


def pending_conffiles(target: str, native_status: bytes) -> list[str]:
    fields = dict(stanzas(native_status).get(f"{target}:{ARCHITECTURE}", []))
    return [
        line[0].lstrip("/") for line in conffiles(fields.get("Conffiles", ""))
        if len(line) == 2 and line[1] == "newconffile"
    ]


def status_transition(target: str, native: bytes, proof: bytes, read_proof: Reader) -> bool:
    """Accept only the proof's configure of the target package."""
    before, after = stanzas(native), stanzas(proof)
    key = f"{target}:{ARCHITECTURE}"
    if before.keys() != after.keys() or key not in before:
        return False
    if any(before[other] != after[other] for other in before if other != key):
        return False
    old, new = before[key], after[key]
    old_fields, new_fields = dict(old), dict(new)
    if old_fields.get("Status") not in ("install ok unpacked", "install ok half-configured"):
        return False
    if new_fields.get("Status") != "install ok installed":
        return False
    version = old_fields.get("Version")
    previous_config, current_config = (
        old_fields.get("Config-Version"), new_fields.get("Config-Version"),
    )
    if current_config not in (None, version) or previous_config not in (None, current_config):
        return False
    old_conffiles = conffiles(old_fields.get("Conffiles", ""))
    new_conffiles = conffiles(new_fields.get("Conffiles", ""))
    if len(old_conffiles) != len(new_conffiles):
        return False
    for previous, current in zip(old_conffiles, new_conffiles):
        if previous == current:
            continue
        if (
            len(previous) != 2 or len(current) != 2 or previous[0] != current[0]
            or previous[1] != "newconffile" or not MD5.fullmatch(current[1])
            or hashlib.md5(
                read_proof(current[0].lstrip("/")), usedforsecurity=False,
            ).hexdigest() != current[1]
        ):
            return False
    ignored = ("Status", "Config-Version", "Conffiles")
    return (
        [field for field in old if field[0] not in ignored]
        == [field for field in new if field[0] not in ignored]
    )


def dpkg_log(target: str, data: bytes, fields: dict[str, str]) -> bool:
    """The proof's own dpkg log records only its configure of the target."""
    version, state = fields.get("Version"), fields.get("Status")
    if not version or state not in ("install ok unpacked", "install ok half-configured"):
        return False
    stamp = r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
    package = f"{target}:{ARCHITECTURE}"
    expected = [
        "startup packages configure",
        f"configure {package} {version} <none>",
    ]
    if state == "install ok unpacked":
        expected.append(f"status unpacked {package} {version}")
    expected.extend((
        f"status half-configured {package} {version}",
        f"status installed {package} {version}",
    ))
    lines = data.decode("utf-8").split("\n")
    return (
        len(lines) == len(expected) + 1 and lines[-1] == ""
        and all(re.fullmatch(rf"{stamp} {re.escape(event)}", line)
                for event, line in zip(expected, lines[:-1]))
    )


def installed_conffile(
    path: str,
    pending: list[str],
    native: dict[str, dict[str, object]],
    proof: dict[str, dict[str, object]],
) -> bool:
    """A pending new conffile is byte-identical to the proof's installed one."""
    for name in pending:
        staged = f"{name}.dpkg-new"
        if path not in (name, staged):
            continue
        entry = native.get(staged)
        return (
            name not in native and staged not in proof and entry is not None
            and entry["type"] == "file" and entry["uid"] == 0 and entry["gid"] == 0
            and entry == proof.get(name)
        )
    return False


def classify(
    target: str,
    path: str,
    native: dict[str, dict[str, object]],
    proof: dict[str, dict[str, object]],
    read_native: Reader,
    read_proof: Reader,
    pending: list[str],
) -> Optional[str]:
    """Return the reviewed reason for one difference, or None."""
    left, right = native.get(path), proof.get(path)
    if path == "usr/bin/setpriv":
        if left is None and root_file(right, "0o755", SETPRIV_SHA256):
            return "proof harness: closure setpriv drops CAP_SYS_ADMIN before pinned dpkg"
    elif path == "usr/local/sbin/dpkg" and target in ("udev", "sudo"):
        if left is None and root_file(right, "0o755", PINNED_DPKG_SHA256):
            return "proof harness: receipt-verified pinned dpkg"
    elif path == "usr/bin/dpkg" and target == "systemd":
        if root_file(left, "0o755", SNAPSHOT_DPKG_SHA256) and root_file(
            right, "0o755", PINNED_DPKG_SHA256,
        ):
            return "proof harness: receipt-verified pinned dpkg replaces the snapshot dpkg"
    elif path == "var/log/dpkg.log":
        if root_file(right, "0o644") and (left is None or root_file(left, "0o644")):
            before = b"" if left is None else read_native(path)
            after = read_proof(path)
            fields = dict(stanzas(read_native("var/lib/dpkg/status")).get(
                f"{target}:{ARCHITECTURE}", [],
            ))
            if (
                (not before or before.endswith(b"\n")) and after.startswith(before)
                and dpkg_log(target, after[len(before):], fields)
            ):
                return "proof harness: unchanged raw history followed only by target configure"
    elif path == "var/lib/dpkg/status":
        if (
            root_file(left, "0o644") and root_file(right, "0o644")
            and status_transition(target, read_native(path), read_proof(path), read_proof)
        ):
            return "dpkg bookkeeping: only the target stanza is configured"
    elif path == "var/lib/dpkg/status-old":
        before = native.get("var/lib/dpkg/status")
        if (
            root_file(left, "0o644") and root_file(right, "0o644")
            and root_file(before, "0o644", str(right["sha256"]))
        ):
            return "dpkg bookkeeping: the proof backs up the unconfigured status"
    elif path == "run/mount":
        if (
            left is None and right == {"type": "directory", "uid": 0, "gid": 0, "mode": "0o700"}
            and not any(other.startswith("run/mount/") for other in proof)
        ):
            return "proof harness: chrooted mount(8) creates libmount's empty utab directory"
    elif path == "etc/machine-id" and target == "systemd":
        if (
            root_file(left, "0o444") and same_except_content(left, right)
            and MACHINE_ID.fullmatch(read_native(path))
            and MACHINE_ID.fullmatch(read_proof(path))
        ):
            return "systemd postinst generates a random machine ID in each copy"
    elif path == "var/log/alternatives.log":
        if (
            root_file(left, "0o644") and same_except_content(left, right)
            and ALTERNATIVES_STAMP.sub(b"", read_native(path))
            == ALTERNATIVES_STAMP.sub(b"", read_proof(path))
        ):
            return "update-alternatives stamps the same log lines with wall-clock time"
    if installed_conffile(path, pending, native, proof):
        return "dpkg configure installs new conffiles before the replayed postinst"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("native", type=Path)
    parser.add_argument("proof", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--report-only", action="store_true",
        help="write and print unexpected differences without failing",
    )
    arguments = parser.parse_args()
    if arguments.report.exists() or arguments.report.is_symlink():
        raise ValueError(f"comparison report must be new: {arguments.report}")
    native = inventory(arguments.native)
    proof = inventory(arguments.proof)
    read_native = reader(arguments.native, native)
    read_proof = reader(arguments.proof, proof)
    pending = pending_conffiles(arguments.target, read_native("var/lib/dpkg/status"))
    differences = []
    for path in sorted(native.keys() | proof.keys()):
        left, right = native.get(path), proof.get(path)
        if left == right:
            continue
        difference = {"path": path, "native": left, "proof": right}
        try:
            difference["reviewed"] = classify(
                arguments.target, path, native, proof, read_native, read_proof, pending,
            )
        except (ValueError, UnicodeDecodeError) as error:
            difference.update(reviewed=None, error=str(error))
        differences.append(difference)
    unexpected = [difference for difference in differences if difference["reviewed"] is None]
    report = {
        "target": arguments.target,
        "native_entries": len(native),
        "proof_entries": len(proof),
        "reviewed_differences": len(differences) - len(unexpected),
        "unexpected_differences": len(unexpected),
        "pending_conffiles": pending,
        "differences": differences,
    }
    with arguments.report.open("x") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        f"{arguments.target}: native_entries={len(native)} proof_entries={len(proof)} "
        f"reviewed_differences={len(differences) - len(unexpected)} "
        f"unexpected_differences={len(unexpected)}"
    )
    for difference in differences:
        if difference["reviewed"] is not None:
            print(f"reviewed {difference['path']}: {difference['reviewed']}")
    for difference in unexpected[:MAXIMUM_REPORTED]:
        print(json.dumps(difference, sort_keys=True))
    if unexpected and not arguments.report_only:
        print(f"{arguments.target}: native replay differs from the pinned dpkg proof", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
