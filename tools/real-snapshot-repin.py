#!/usr/bin/env python3
"""Probe, diff, record and check the reviewed real-snapshot pin manifest.

The tool never authenticates repository metadata itself. ``probe`` drives a
``debz`` binary (``refresh``, ``plan --lock-output`` and ``download
--lock-input``) and binds every Release it fetches to the cleartext digest
that ``debz`` recorded in an exact lock. Package members are read only from
CAS objects that ``debz download`` verified, after re-hashing them against the
lock. ``check`` is offline and is run in CI.
"""

from __future__ import annotations

import argparse
import calendar
import copy
import difflib
import email.utils
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path("tools/fixtures/real-snapshot/pin-v1.json")
MANIFEST_SCHEMA = "io.github.cataggar.debz.real-snapshot-pin.v1"
REPORT_SCHEMA = "io.github.cataggar.debz.real-snapshot-repin-report.v1"
SETTLE_SECONDS = 24 * 60 * 60
WITNESS_WINDOW_SECONDS = 48 * 60 * 60
MAXIMUM_RELEASE_AGE_SECONDS = 31 * 24 * 60 * 60
DEBZ_DEADLINE_MS = "300000"
DEBZ_LOCK_WAIT_MS = "30000"
MAXIMUM_RELEASE_BYTES = 16 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024
MAXIMUM_MEMBER_BYTES = 64 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 120
SHA256_HEX = hashlib.sha256().digest_size * 2
SHA512_HEX = hashlib.sha512().digest_size * 2
DIGEST_ALGORITHMS = {"sha256": SHA256_HEX, "sha512": SHA512_HEX}
TIMESTAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")
REVIEW_REFERENCE = re.compile(r"(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#[1-9][0-9]*")
FINGERPRINT = re.compile(r"[0-9a-f]{40}")
IDENTITY_ID = re.compile(r"[a-z]+:[A-Za-z0-9][A-Za-z0-9+.:/_@-]*")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*")
HEX_LITERAL = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-f]{%d}|[0-9a-f]{%d})(?![0-9A-Za-z])" % (SHA512_HEX, SHA256_HEX))
QUOTED_HEX_LITERAL = re.compile(r'"((?:[0-9a-f]{%d}|[0-9a-f]{%d}))"' % (SHA512_HEX, SHA256_HEX))
KINDS = ("script", "tool_file", "archive", "prestate")
ROLES = ("bounded", "frozen", "witness")
# How each pocket's fetched Release is tied to what debz authenticated, per
# architecture. `exact_lock`: an exact lock names the repository with the same
# cleartext release_sha256. `refresh_only`: debz refresh authenticated the
# pocket, but it contributes no locked package and debz emits no Release digest
# for it, so the fetched bytes are recorded without that cross-check (#344).
BINDINGS = ("exact_lock", "refresh_only")
CONSUMER_FORMS = ("hex", "zig_bytes", "fixture")
STATUSES = ("unchanged", "provenance-only", "changed", "missing")
SNAPSHOT_URI = re.compile(r"snapshot\.ubuntu\.com/ubuntu/([0-9]{8}T[0-9]{6}Z)")
SNAPSHOT_CONSTANT = re.compile(
    r"(?m)^\s*(?:pub\s+)?const\s+(snapshot_[a-z0-9_]*sha256)\b[^=]*=\s*"
)
ZIG_BYTE = re.compile(r"0x([0-9a-fA-F]{2})")
DEBZ_SNAPSHOT_CONSTANT_SOURCES = (
    "src/maintainer_script.zig",
    "src/native_alternatives.zig",
    "src/native_unpack.zig",
)
SNAPSHOT_INPUT_ENTRY = re.compile(
    r'\.path = "(?P<path>[^"]+)",\s*(?:\.mode = 0o(?P<leading_mode>[0-7]+),\s*)?'
    r'\.size = (?P<size>[0-9]+),\s*(?:\.mode = 0o(?P<mode>[0-7]+),\s*)?'
    r'\.sha256 = "(?P<hex>[0-9a-f]+)"'
)
FIXTURE_GLOB = "src/fixtures/ubuntu-*"
PIN_SCRIPT_GLOB = "tools/real-snapshot-*.sh"
PROTECTED_STAGE_SCRIPT = "tools/real-snapshot-reference-protected-stage.sh"
REFERENCE_LAUNCHER = "tools/real-snapshot-reference-launcher.zig"
SCRIPT_BINDING_ENTRY = re.compile(
    r'\.\{\s*\.name\s*=\s*"(?P<name>[a-z0-9+.-]+)",\s*'
    r'\.version\s*=\s*"(?P<version>[^"]+)",\s*'
    r'\.size\s*=\s*(?P<size>[0-9]+),\s*'
    r'\.digest\s*=\s*"(?P<digest>[0-9a-f]{%d})"\s*\}' % SHA256_HEX
)
STAGE_PROFILE_LOOP = re.compile(r"(?m)^\s*for\s+profile\s+in\s+(?P<body>[^;\n]+);\s*do")
STAGE_WITNESS_ARRAY = re.compile(
    r"(?ms)^\s*readonly\s+snapshot_witness_suites=\((?P<body>[^)]*)\)"
)

PROFILES: dict[str, dict] = {
    "ubuntu-stonking": {
        "uri_root": "https://snapshot.ubuntu.com/ubuntu",
        "component": "main",
        "architectures": ["amd64", "arm64"],
        "keyring": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        "signer": "f6ecb3762474eda9d21b7022871920d1991bc93c",
        "request": "ubuntu-minimal",
        "pockets": [{"suite": "stonking", "role": "bounded"}],
    },
    "ubuntu-resolute": {
        "uri_root": "https://snapshot.ubuntu.com/ubuntu",
        "component": "main",
        "architectures": ["amd64", "arm64"],
        "keyring": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        "signer": "f6ecb3762474eda9d21b7022871920d1991bc93c",
        "request": "ubuntu-minimal",
        "pockets": [
            {"suite": "resolute", "role": "frozen"},
            {"suite": "resolute-updates", "role": "witness"},
            {"suite": "resolute-security", "role": "witness"},
        ],
    },
}


class RepinError(Exception):
    """A refusal. The message names the failed check."""


def fail(message: str) -> None:
    raise RepinError(message)


# Time.


def timestamp_seconds(text: str) -> int:
    if not isinstance(text, str) or not TIMESTAMP.fullmatch(text):
        fail(f"snapshot timestamp must be YYYYMMDDTHHMMSSZ: {text!r}")
    try:
        parsed = time.strptime(text, "%Y%m%dT%H%M%SZ")
    except ValueError:
        fail(f"invalid snapshot timestamp: {text!r}")
    return calendar.timegm(parsed)


def format_timestamp(seconds: int) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(seconds))


def default_timestamp(now: int) -> str:
    settled = now - SETTLE_SECONDS
    return format_timestamp(settled - settled % 86400)


def validate_timestamp(text: str, now: int, pinned: str | None) -> int:
    """Checks probe rule 1: T is settled and not older than the current pin."""
    seconds = timestamp_seconds(text)
    if now - seconds < SETTLE_SECONDS:
        fail(
            f"snapshot {text} is less than 24 hours old; snapshot timestamps are "
            "mutable until the service has published every pocket for that time"
        )
    if pinned is not None and seconds < timestamp_seconds(pinned):
        fail(f"snapshot {text} is older than the current pin {pinned}")
    return seconds


def release_time(value: str, field: str) -> int:
    parsed = email.utils.parsedate_tz(value)
    if parsed is None or not re.fullmatch(
        r"[A-Z][a-z]{2}, [0-9]{1,2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} (?:UTC|GMT|\+0000)",
        value,
    ):
        fail(f"Release {field} is not an RFC 2822 UTC time: {value!r}")
    return email.utils.mktime_tz(parsed)


# Digests.


def tagged(algorithm: str, data: bytes) -> str:
    return f"{algorithm}:{hashlib.new(algorithm, data).hexdigest()}"


def parse_tagged(text: object, algorithms: tuple[str, ...] = ("sha256", "sha512")) -> tuple[str, str]:
    if not isinstance(text, str) or ":" not in text:
        fail(f"digest must be algorithm-tagged: {text!r}")
    algorithm, value = text.split(":", 1)
    if algorithm not in algorithms or algorithm not in DIGEST_ALGORITHMS:
        fail(f"unsupported digest algorithm in {text!r}")
    if len(value) != DIGEST_ALGORITHMS[algorithm] or not re.fullmatch(r"[0-9a-f]+", value):
        fail(f"digest must be lowercase hexadecimal of the algorithm's length: {text!r}")
    if set(value) == {"0"}:
        fail(f"digest must not be zero: {text!r}")
    return algorithm, value


def lock_digest(value: str, algorithm: str = "sha256") -> str:
    text = f"{algorithm}:{value}"
    parse_tagged(text, (algorithm,))
    return text


# InRelease.


def in_release_cleartext(data: bytes) -> bytes:
    """Returns the display cleartext, as debz records it in exact locks.

    The result is the text between the armor header block and the signature,
    with dash escapes removed and the original line endings kept.
    """
    lines = data.splitlines(keepends=True)
    if not lines or lines[0].rstrip(b"\r\n") != b"-----BEGIN PGP SIGNED MESSAGE-----":
        fail("InRelease does not start with a cleartext signature header")
    index = 1
    while index < len(lines) and lines[index].rstrip(b"\r\n") != b"":
        index += 1
    if index >= len(lines):
        fail("InRelease has no blank line after its armor headers")
    index += 1
    output = bytearray()
    while index < len(lines):
        line = lines[index]
        text = line.rstrip(b"\r\n")
        if text == b"-----BEGIN PGP SIGNATURE-----":
            return bytes(output)
        if not line.endswith(b"\n"):
            fail("InRelease cleartext is truncated")
        ending = line[len(text):]
        if text.startswith(b"- "):
            text = text[2:]
        elif text.startswith(b"-"):
            fail("InRelease cleartext has an invalid dash escape")
        output += text + ending
        index += 1
    fail("InRelease has no signature block")
    raise AssertionError


def release_fields(cleartext: bytes) -> dict:
    fields: dict[str, str] = {}
    hash_fields: list[str] = []
    current = None
    for raw in cleartext.decode("utf-8").splitlines():
        if not raw:
            break
        if raw[0] in " \t":
            if current is None:
                fail("Release continuation line without a field")
            continue
        if ":" not in raw:
            fail(f"invalid Release line: {raw!r}")
        name, value = raw.split(":", 1)
        if name in fields:
            fail(f"duplicate Release field {name}")
        fields[name] = value.strip()
        current = name
        if name in ("MD5Sum", "SHA1", "SHA256", "SHA512"):
            hash_fields.append(name)
    if "Date" not in fields:
        fail("Release has no Date")
    return {
        "suite": fields.get("Suite"),
        "codename": fields.get("Codename"),
        "date": fields["Date"],
        "date_unix": release_time(fields["Date"], "Date"),
        "valid_until": fields.get("Valid-Until"),
        "valid_until_unix": (
            release_time(fields["Valid-Until"], "Valid-Until") if "Valid-Until" in fields else None
        ),
        "hash_fields": hash_fields,
    }


def pocket_deadline(fields: dict) -> int:
    if fields["valid_until_unix"] is not None:
        return fields["valid_until_unix"]
    return fields["date_unix"] + MAXIMUM_RELEASE_AGE_SECONDS


def check_pocket_dates(pockets: list[dict], snapshot: int) -> int:
    """Checks probe rule 4 and returns the admission deadline."""
    for pocket in pockets:
        if pocket["date_unix"] > snapshot:
            fail(f"{pocket['suite']} Date {pocket['date']} is after the snapshot time")
        if pocket["role"] == "witness" and snapshot - pocket["date_unix"] > WITNESS_WINDOW_SECONDS:
            fail(
                f"witness {pocket['suite']} Date {pocket['date']} is more than 48 hours "
                "before the snapshot time; the snapshot service may be stale"
            )
        if pocket["role"] == "frozen" and pocket["valid_until"] is not None:
            fail(f"frozen pocket {pocket['suite']} carries Valid-Until")
    frozen = [pocket for pocket in pockets if pocket["role"] == "frozen"]
    if frozen:
        witnesses = [pocket for pocket in pockets if pocket["role"] == "witness"]
        if not witnesses:
            fail("a frozen pocket requires at least one witness pocket")
        for pocket in frozen:
            pocket["deadline"] = min(pocket_deadline(witness) for witness in witnesses)
    for pocket in pockets:
        if pocket["role"] != "frozen":
            pocket["deadline"] = pocket_deadline(pocket)
    return min(pocket["deadline"] for pocket in pockets)


# Packages.


def ar_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"!<arch>\n"):
        fail("package is not an ar archive")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            fail("package has a malformed ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip() or "x")
        start = offset + 60
        if start + size > len(data) or name in members:
            fail("package has a truncated or duplicate ar member")
        members[name] = data[start:start + size]
        offset = start + size + (size & 1)
    return members


def decompress(name: str, data: bytes) -> bytes:
    if name.endswith(".tar"):
        return data
    if name.endswith(".tar.gz"):
        return gzip.decompress(data)
    if name.endswith(".tar.xz"):
        return lzma.decompress(data)
    if name.endswith(".tar.zst"):
        try:
            from compression import zstd  # type: ignore[import-not-found]

            return zstd.decompress(data)
        except ImportError:
            pass
        if shutil.which("zstd") is None:
            fail(f"{name} needs Python 3.14 compression.zstd or the zstd program")
        result = subprocess.run(
            ["zstd", "-q", "-d", "-c"], input=data, capture_output=True, check=False
        )
        if result.returncode != 0:
            fail(f"cannot decompress {name}")
        return result.stdout
    fail(f"unsupported package member {name}")
    raise AssertionError


def package_tar(deb: bytes, prefix: str) -> tarfile.TarFile:
    members = ar_members(deb)
    names = [name for name in members if name == prefix or name.startswith(prefix + ".")]
    if len(names) != 1:
        fail(f"package must contain exactly one {prefix} member")
    payload = decompress(names[0], members[names[0]])
    return tarfile.open(fileobj=io.BytesIO(payload), mode="r:")


def tar_member(deb: bytes, prefix: str, path: str) -> tuple[bytes, int]:
    wanted = {path, "./" + path}
    with package_tar(deb, prefix) as archive:
        for member in archive.getmembers():
            if member.name not in wanted:
                continue
            if not (member.isreg() or member.islnk()):
                fail(f"{prefix} member {path} is not a regular file")
            stream = archive.extractfile(member)
            if stream is None:
                fail(f"cannot read {prefix} member {path}")
            data = stream.read(MAXIMUM_MEMBER_BYTES + 1)
            if len(data) > MAXIMUM_MEMBER_BYTES:
                fail(f"{prefix} member {path} is too large")
            return data, member.mode & 0o7777
    fail(f"{prefix} has no member {path}")
    raise AssertionError


def tar_member_dpkg_list_path(name: str) -> str:
    if name in ("", "."):
        return "/."
    if name.startswith("./"):
        name = name[2:]
    if not name.startswith("/"):
        name = "/" + name
    return name.rstrip("/") or "/."


def dpkg_ownership_list(deb: bytes) -> bytes:
    lines = []
    with package_tar(deb, "data.tar") as archive:
        for member in archive:
            lines.append(tar_member_dpkg_list_path(member.name))
    return ("\n".join(lines) + "\n").encode()


# Manifest.


def load_json(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            document = json.load(stream)
    except (OSError, ValueError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(document, dict):
        fail(f"{path} is not a JSON object")
    return document


def canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(canonical_json(document), encoding="ascii")
    os.replace(temporary, path)


def exact_keys(value: object, required: set[str], optional: set[str], where: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        fail(f"{where} has missing {sorted(missing)} or unknown {sorted(unknown)} fields")
    return value


def validate_profile(profile: object, where: str = "series") -> dict:
    exact_keys(
        profile,
        {"name", "uri_root", "component", "architectures", "keyring", "signer", "request", "pockets"},
        set(),
        where,
    )
    assert isinstance(profile, dict)
    if not isinstance(profile["name"], str) or not re.fullmatch(r"[a-z0-9-]+", profile["name"]):
        fail(f"{where}.name is invalid")
    uri = urllib.parse.urlsplit(profile["uri_root"]) if isinstance(profile["uri_root"], str) else None
    if uri is None or uri.scheme not in ("https", "file") or uri.query or uri.fragment or profile["uri_root"].endswith("/"):
        fail(f"{where}.uri_root must be an https or file URI without a trailing slash")
    architectures = profile["architectures"]
    if (
        not isinstance(architectures, list)
        or not architectures
        or len(set(architectures)) != len(architectures)
        or any(arch not in ("amd64", "arm64") for arch in architectures)
    ):
        fail(f"{where}.architectures must list distinct amd64/arm64 values")
    if not isinstance(profile["keyring"], str) or not profile["keyring"].startswith("/"):
        fail(f"{where}.keyring must be absolute")
    if not isinstance(profile["signer"], str) or not FINGERPRINT.fullmatch(profile["signer"]):
        fail(f"{where}.signer must be a lowercase v4 fingerprint")
    for field in ("component", "request"):
        if not isinstance(profile[field], str) or not PACKAGE_NAME.fullmatch(profile[field]):
            fail(f"{where}.{field} is invalid")
    pockets = profile["pockets"]
    if not isinstance(pockets, list) or not pockets:
        fail(f"{where}.pockets must be a non-empty list")
    suites = set()
    for index, pocket in enumerate(pockets):
        exact_keys(pocket, {"suite", "role"}, set(), f"{where}.pockets[{index}]")
        if not isinstance(pocket["suite"], str) or not PACKAGE_NAME.fullmatch(pocket["suite"]):
            fail(f"{where}.pockets[{index}].suite is invalid")
        if pocket["role"] not in ROLES or pocket["suite"] in suites:
            fail(f"{where}.pockets[{index}] has an invalid role or duplicate suite")
        suites.add(pocket["suite"])
    roles = [pocket["role"] for pocket in pockets]
    if roles.count("frozen") > 1 or ("frozen" in roles) != ("witness" in roles):
        fail(f"{where} must pair exactly one frozen pocket with witness pockets")
    return profile


def resolve_profile(name: str, profile_path: Path | None) -> dict:
    if profile_path is not None:
        profile = validate_profile(load_json(profile_path), "profile")
        if profile["name"] != name:
            fail(f"profile {profile_path} is for {profile['name']}, not {name}")
        if name in PROFILES:
            fail(f"{name} is a built-in profile; it cannot be replaced")
        return profile
    if name not in PROFILES:
        fail(f"unknown series {name}")
    return {"name": name, **copy.deepcopy(PROFILES[name])}


def validate_consumer(consumer: object, where: str) -> dict:
    exact_keys(consumer, {"path", "form"}, {"name"}, where)
    assert isinstance(consumer, dict)
    path = consumer["path"]
    if not isinstance(path, str) or path.startswith("/") or ".." in Path(path).parts or not path:
        fail(f"{where}.path must be repository-relative")
    if consumer["form"] not in CONSUMER_FORMS:
        fail(f"{where}.form is invalid")
    if (consumer["form"] == "zig_bytes") != ("name" in consumer):
        fail(f"{where}: only zig_bytes consumers name a constant")
    return consumer


def validate_identity(identity: object, index: int) -> dict:
    where = f"identities[{index}]"
    exact_keys(
        identity,
        {"id", "kind", "package", "architectures", "path", "digest", "size", "mode",
         "version_bound", "provenance", "consumers", "review"},
        {"derived_from"},
        where,
    )
    assert isinstance(identity, dict)
    if not isinstance(identity["id"], str) or not IDENTITY_ID.fullmatch(identity["id"]):
        fail(f"{where}.id is invalid")
    if identity["kind"] not in KINDS:
        fail(f"{where}.kind is invalid")
    if not isinstance(identity["package"], str) or not PACKAGE_NAME.fullmatch(identity["package"]):
        fail(f"{where}.package is invalid")
    architectures = identity["architectures"]
    if (
        not isinstance(architectures, list)
        or not architectures
        or len(set(architectures)) != len(architectures)
        or any(arch not in ("amd64", "arm64") for arch in architectures)
    ):
        fail(f"{where}.architectures is invalid")
    algorithm, _ = parse_tagged(identity["digest"])
    if (identity["kind"] == "archive") != (algorithm == "sha512"):
        fail(f"{where}: archives bind SHA-512 and members bind SHA-256")
    if identity["kind"] == "archive":
        if identity["path"] is not None or identity["mode"] is not None:
            fail(f"{where}: an archive identity has no path or mode")
    else:
        path = identity["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/"):
            fail(f"{where}.path is invalid")
        mode = identity["mode"]
        if mode is None and identity["kind"] == "prestate":
            pass
        elif not isinstance(mode, str) or not re.fullmatch(r"0[0-7]{3,4}", mode):
            fail(f"{where}.mode must be an octal string")
    if not isinstance(identity["size"], int) or isinstance(identity["size"], bool) or identity["size"] < 0:
        fail(f"{where}.size is invalid")
    if not isinstance(identity["version_bound"], bool):
        fail(f"{where}.version_bound must be a boolean")
    derived = identity.get("derived_from")
    if (identity["kind"] == "prestate") != (derived is not None):
        fail(f"{where}: exactly the prestate identities list derived_from")
    if derived is not None:
        if not isinstance(derived, list):
            fail(f"{where}.derived_from must be a list")
        for item_index, item in enumerate(derived):
            exact_keys(item, {"package", "version"}, set(), f"{where}.derived_from[{item_index}]")
            if not PACKAGE_NAME.fullmatch(str(item["package"])) or not isinstance(item["version"], str):
                fail(f"{where}.derived_from[{item_index}] is invalid")
    validate_provenance(identity["provenance"], architectures, where)
    if identity["version_bound"] and identity["provenance"] == "pending":
        fail(f"{where}.version_bound requires recorded provenance")
    consumers = identity["consumers"]
    if not isinstance(consumers, list) or not consumers:
        fail(f"{where} has no consumer")
    for consumer_index, consumer in enumerate(consumers):
        validate_consumer(consumer, f"{where}.consumers[{consumer_index}]")
    if not isinstance(identity["review"], str) or not REVIEW_REFERENCE.fullmatch(identity["review"]):
        fail(f"{where}.review must be a PR or issue reference")
    return identity


def validate_provenance(provenance: object, architectures: list[str], where: str) -> None:
    if provenance == "pending":
        return
    exact_keys(provenance, {"version", "archives"}, set(), f"{where}.provenance")
    assert isinstance(provenance, dict)
    if not isinstance(provenance["version"], str) or not provenance["version"]:
        fail(f"{where}.provenance.version is invalid")
    archives = provenance["archives"]
    if not isinstance(archives, dict) or sorted(archives) != sorted(architectures):
        fail(f"{where}.provenance.archives must cover the identity architectures")
    for value in archives.values():
        parse_tagged(value, ("sha512",))


def validate_snapshot(snapshot: object, profile: dict) -> dict:
    exact_keys(snapshot, {"timestamp", "status"}, {"pockets", "admission_deadline", "closures"}, "snapshot")
    assert isinstance(snapshot, dict)
    timestamp_seconds(snapshot["timestamp"])
    if snapshot["status"] == "pending":
        if set(snapshot) != {"timestamp", "status"}:
            fail("a pending snapshot records only its timestamp")
        return snapshot
    if snapshot["status"] != "probed":
        fail("snapshot.status must be pending or probed")
    exact_keys(snapshot, {"timestamp", "status", "pockets", "admission_deadline", "closures"}, set(), "snapshot")
    pockets = snapshot["pockets"]
    if not isinstance(pockets, list) or [p.get("suite") for p in pockets] != [p["suite"] for p in profile["pockets"]]:
        fail("snapshot.pockets must follow the series pockets")
    for index, pocket in enumerate(pockets):
        exact_keys(
            pocket,
            {"suite", "role", "date", "valid_until", "release_sha256", "in_release_sha256",
             "in_release_sha512", "hash_fields", "signers", "deadline", "binding"},
            {"review"},
            f"snapshot.pockets[{index}]",
        )
        binding = pocket["binding"]
        if (
            not isinstance(binding, dict)
            or sorted(binding) != sorted(profile["architectures"])
            or any(value not in BINDINGS for value in binding.values())
        ):
            fail(f"snapshot.pockets[{index}].binding must give every series architecture one of {', '.join(BINDINGS)}")
        parse_tagged(pocket["release_sha256"], ("sha256",))
        parse_tagged(pocket["in_release_sha256"], ("sha256",))
        parse_tagged(pocket["in_release_sha512"], ("sha512",))
        if pocket["role"] != profile["pockets"][index]["role"]:
            fail(f"snapshot.pockets[{index}].role differs from the series")
        if pocket["signers"] != [profile["signer"]]:
            fail(f"snapshot.pockets[{index}] has an unreviewed signer")
        if pocket["role"] == "frozen":
            if not REVIEW_REFERENCE.fullmatch(str(pocket.get("review", ""))):
                fail("the frozen pocket must carry the review that accepted its Release")
        elif "review" in pocket:
            fail("only the frozen pocket carries a release review")
    if not isinstance(snapshot["admission_deadline"], int):
        fail("snapshot.admission_deadline must be an integer")
    closures = snapshot["closures"]
    if not isinstance(closures, dict) or sorted(closures) != sorted(profile["architectures"]):
        fail("snapshot.closures must cover the series architectures")
    for arch, closure in closures.items():
        exact_keys(closure, {"digest", "package_count", "packages", "pockets"}, set(), f"snapshot.closures.{arch}")
        parse_tagged(closure["digest"], ("sha256",))
        if not isinstance(closure["packages"], dict) or closure["package_count"] != len(closure["packages"]):
            fail(f"snapshot.closures.{arch}.packages does not match package_count")
    return snapshot


def validate_manifest(manifest: dict) -> dict:
    exact_keys(manifest, {"schema", "series", "snapshot", "uri_consumers", "identities", "excluded"}, set(), "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        fail("unsupported manifest schema")
    profile = validate_profile(manifest["series"])
    validate_snapshot(manifest["snapshot"], profile)
    uri_consumers = manifest["uri_consumers"]
    if not isinstance(uri_consumers, list) or any(not isinstance(path, str) for path in uri_consumers):
        fail("uri_consumers must be a list of paths")
    identities = manifest["identities"]
    if not isinstance(identities, list):
        fail("identities must be a list")
    seen = set()
    for index, identity in enumerate(identities):
        validate_identity(identity, index)
        if identity["id"] in seen:
            fail(f"duplicate identity {identity['id']}")
        seen.add(identity["id"])
    excluded = manifest["excluded"]
    if not isinstance(excluded, list):
        fail("excluded must be a list")
    for index, item in enumerate(excluded):
        exact_keys(item, {"digest", "reason"}, set(), f"excluded[{index}]")
        parse_tagged(item["digest"])
        if not isinstance(item["reason"], str) or len(item["reason"]) < 16:
            fail(f"excluded[{index}] needs a reason")
    return manifest


def pinned_timestamp(manifest: dict | None, series: str) -> str | None:
    if manifest is None or manifest["series"]["name"] != series:
        return None
    return manifest["snapshot"]["timestamp"]


def frozen_pocket(document: dict) -> dict | None:
    pockets = document.get("pockets") or []
    for pocket in pockets:
        if pocket["role"] == "frozen":
            return pocket
    return None


# Probe.


class Debz:
    def __init__(self, executable: Path, workspace: Path, arch: str, configs: list[Path], keyring: str):
        self.executable = executable
        self.arch = arch
        self.base = workspace / arch
        for name in ("root", "cache", "state"):
            (self.base / name).mkdir(parents=True)
        self.common = [
            "--install-root", str(self.base / "root"),
            "--cache-path", str(self.base / "cache"),
            "--state-path", str(self.base / "state"),
            "--architecture", arch,
        ]
        for config in configs:
            self.common += ["--config", str(config)]
        self.common += [
            "--keyring", keyring,
            "--deadline-ms", DEBZ_DEADLINE_MS,
            "--lock-wait-ms", DEBZ_LOCK_WAIT_MS,
            "--json",
        ]
        self.log = workspace / f"debz-{arch}.jsonl"

    def run(self, operation: str, extra: list[str]) -> dict:
        argv = [str(self.executable), operation, *self.common, *extra]
        result = subprocess.run(argv, capture_output=True, check=False, timeout=900)
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"argv": argv[1:2] + extra, "exit": result.returncode}) + "\n")
        try:
            document = json.loads(result.stdout)
        except ValueError:
            document = None
        if result.returncode != 0 or not isinstance(document, dict) or document.get("exit_status") != 0:
            detail = result.stdout.decode("utf-8", "replace").strip() or result.stderr.decode("utf-8", "replace").strip()
            fail(f"debz {operation} failed for {self.arch} (exit {result.returncode}): {detail[:2000]}")
        return document

    def refresh(self, suites: set[str]) -> dict[str, str]:
        """Refreshes every pocket and returns suite -> repository id."""
        document = self.run("refresh", ["--assume-yes"])
        repository_ids: dict[str, str] = {}
        for item in document["items"]:
            if item["version"] in suites:
                detail = item.get("detail") or ""
                if not detail.startswith("authenticated") or "stale" in detail:
                    fail(f"{self.arch} refresh did not freshly authenticate {item['version']}: {detail}")
                repository_ids[item["version"]] = item["package"]
        if sorted(repository_ids) != sorted(suites):
            fail(f"{self.arch} refresh did not authenticate every pocket")
        return repository_ids

    def plan(self, package: str, lock: Path) -> dict:
        self.run("plan", ["--transaction-backend", "native", "--lock-output", str(lock), package])
        return load_json(lock)

    def download(self, package: str, lock: Path) -> None:
        self.run("download", ["--transaction-backend", "native", "--lock-input", str(lock), package])

    def archive(self, package: dict) -> bytes:
        identity = package["archive_identity"]
        if identity.get("primary") != "sha512":
            fail(f"{package['name']} {package['version']} has no SHA-512 archive identity")
        expected = [d["digest"] for d in identity["digests"] if d["algorithm"] == "sha512"]
        if len(expected) != 1:
            fail(f"{package['name']} has an ambiguous SHA-512 archive identity")
        path = self.base / "cache" / "packages-v2" / "objects" / f"sha512-{expected[0]}"
        with path.open("rb") as stream:
            data = stream.read(MAXIMUM_ARCHIVE_BYTES + 1)
        if len(data) != package["declared_size"] or hashlib.sha512(data).hexdigest() != expected[0]:
            fail(f"verified CAS object for {package['name']} no longer matches its lock")
        return data


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "debz-real-snapshot-repin"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            data = response.read(MAXIMUM_RELEASE_BYTES + 1)
    except OSError as error:
        fail(f"cannot fetch {url}: {error}")
    if len(data) > MAXIMUM_RELEASE_BYTES:
        fail(f"{url} is too large")
    return data


def snapshot_uri(profile: dict, timestamp: str) -> str:
    return f"{profile['uri_root']}/{timestamp}"


def write_configs(directory: Path, profile: dict, timestamp: str, arch: str, frozen_digest: str | None) -> list[Path]:
    directory.mkdir(parents=True)
    witnesses = [pocket["suite"] for pocket in profile["pockets"] if pocket["role"] == "witness"]
    configs = []
    for pocket in profile["pockets"]:
        source = directory / f"{pocket['suite']}.sources"
        source.write_text(
            "Types: deb\n"
            f"URIs: {snapshot_uri(profile, timestamp)}\n"
            f"Suites: {pocket['suite']}\n"
            f"Components: {profile['component']}\n"
            f"Architectures: {arch}\n"
            f"Signed-By: {profile['keyring']}\n",
            encoding="utf-8",
        )
        if pocket["role"] == "frozen":
            freshness = {
                "mode": "frozen_release_with_witnesses",
                "frozen_release_digest": frozen_digest,
                "witness_suites": witnesses,
            }
        else:
            freshness = {
                "mode": "allow_missing_valid_until_with_max_age_seconds",
                "maximum_release_age_seconds": MAXIMUM_RELEASE_AGE_SECONDS,
            }
        config = directory / f"{pocket['suite']}.json"
        config.write_text(
            json.dumps({
                "source_path": str(source),
                "priority": 500,
                "immutable": True,
                "freshness": freshness,
            }) + "\n",
            encoding="utf-8",
        )
        configs.append(config)
    return configs


def closure_digest(packages: dict[str, dict]) -> str:
    lines = "".join(
        f"{name}\0{entry['version']}\0{entry['architecture']}\0{entry['archive']}\n"
        for name, entry in sorted(packages.items())
    )
    return tagged("sha256", lines.encode("utf-8"))


def lock_packages(lock: dict, repositories: dict[str, str]) -> dict[str, dict]:
    packages: dict[str, dict] = {}
    for package in lock["packages"]:
        identity = package["archive_identity"]
        sha512 = [d["digest"] for d in identity["digests"] if d["algorithm"] == "sha512"]
        origin = package["origin"].get("repository_id")
        if package["name"] in packages:
            fail(f"lock lists {package['name']} twice")
        packages[package["name"]] = {
            "version": package["version"],
            "architecture": package["architecture"],
            "archive": f"sha512:{sha512[0]}" if identity.get("primary") == "sha512" and len(sha512) == 1 else None,
            "pocket": repositories.get(origin),
            "size": package["declared_size"],
        }
    return packages


def require_sha512(packages: dict[str, dict], arch: str) -> None:
    """Checks probe rule 6."""
    missing = sorted(f"{name} {entry['version']}" for name, entry in packages.items() if entry["archive"] is None)
    if missing:
        fail(f"{arch} closure packages without a signed SHA-512 archive identity: {', '.join(missing)}")


def bind_pockets(
    pockets: dict[str, dict], locks: list[dict], refresh_ids: dict[str, str], signer: str, arch: str
) -> set[str]:
    """Binds fetched Release bytes to the cleartext digests debz locked; returns the bound suites."""
    by_id = {repository_id: suite for suite, repository_id in refresh_ids.items()}
    bound: set[str] = set()
    for lock in locks:
        for repository in lock["repositories"]:
            suite = by_id.get(repository["id"])
            if suite is None:
                fail(f"{arch} lock names a repository that refresh did not report")
            if repository["signer_fingerprints"] != [signer]:
                fail(f"{suite} is signed by {repository['signer_fingerprints']}, not the reviewed signer")
            if lock_digest(repository["release_sha256"]) != pockets[suite]["release_sha256"]:
                fail(f"{suite} Release fetched by the probe differs from the Release debz authenticated")
            bound.add(suite)
    return bound


def observe_identity(identity: dict, arch: str, packages: dict[str, dict], debz: Debz, members: Path) -> dict | None:
    entry = packages.get(identity["package"])
    if entry is None:
        return None
    observed = {
        "version": entry["version"],
        "archive": entry["archive"],
        "derived_versions": {},
    }
    if identity["kind"] == "archive":
        observed.update(digest=entry["archive"], size=entry["size"], mode=None)
        return observed
    if identity["kind"] == "prestate":
        for item in identity["derived_from"]:
            derived = packages.get(item["package"])
            observed["derived_versions"][item["package"]] = None if derived is None else derived["version"]
        if identity["path"] == f"var/lib/dpkg/info/{identity['package']}.list":
            data = dpkg_ownership_list(debz.archive(entry["lock_package"]))
            observed.update(
                digest=tagged("sha256", data),
                size=len(data),
                mode="0644",
            )
            return observed
        trigger_paths = {
            f"var/lib/dpkg/info/{identity['package']}.triggers",
            f"var/lib/dpkg/info/{identity['package']}:{entry['architecture']}.triggers",
        }
        if identity["path"] in trigger_paths:
            data, mode = tar_member(debz.archive(entry["lock_package"]), "control.tar", "triggers")
            observed.update(
                digest=tagged("sha256", data),
                size=len(data),
                mode=f"0{mode:03o}",
            )
            return observed
        observed.update(digest=None, size=None, mode=None)
        return observed
    deb = debz.archive(entry["lock_package"])
    prefix = "control.tar" if identity["kind"] == "script" else "data.tar"
    data, mode = tar_member(deb, prefix, identity["path"])
    name = re.sub(r"[^A-Za-z0-9+.-]", "_", identity["id"]) + f"@{arch}"
    (members / name).write_bytes(data)
    observed.update(
        digest=tagged("sha256", data),
        size=len(data),
        mode=f"0{mode:o}" if mode >= 0o1000 else f"0{mode:03o}",
        member_file=f"members/{name}",
    )
    return observed


def probe(args: argparse.Namespace, now: int | None = None) -> int:
    now = int(time.time()) if now is None else now
    manifest = validate_manifest(load_json(args.manifest)) if args.manifest.exists() else None
    profile = resolve_profile(args.series, args.profile)
    timestamp = args.timestamp or default_timestamp(now)
    snapshot_seconds = validate_timestamp(timestamp, now, pinned_timestamp(manifest, profile["name"]))
    debz_path = Path(args.debz).resolve()
    if not debz_path.is_file() or not os.access(debz_path, os.X_OK):
        fail(f"--debz {args.debz} is not an executable file")
    workspace = (args.workspace or ROOT / ".tmp" / "real-snapshot-repin" / timestamp).resolve()
    if workspace.exists():
        fail(f"workspace {workspace} already exists; probes start from a fresh workspace")
    uri = snapshot_uri(profile, timestamp)

    first: dict[str, bytes] = {}
    pockets: dict[str, dict] = {}
    for pocket in profile["pockets"]:
        data = fetch(f"{uri}/dists/{pocket['suite']}/InRelease")
        first[pocket["suite"]] = data
        cleartext = in_release_cleartext(data)
        fields = release_fields(cleartext)
        if pocket["suite"] not in (fields["suite"], fields["codename"]):
            fail(f"{pocket['suite']} Release names suite {fields['suite']}")
        pockets[pocket["suite"]] = {
            "suite": pocket["suite"],
            "role": pocket["role"],
            "date": fields["date"],
            "date_unix": fields["date_unix"],
            "valid_until": fields["valid_until"],
            "valid_until_unix": fields["valid_until_unix"],
            "hash_fields": fields["hash_fields"],
            "in_release_sha256": tagged("sha256", data),
            "in_release_sha512": tagged("sha512", data),
            "release_sha256": tagged("sha256", cleartext),
            "signers": [profile["signer"]],
            "binding": {},
        }
    frozen = next((p for p in pockets.values() if p["role"] == "frozen"), None)
    frozen_change = False
    if frozen is not None:
        pinned = frozen_pocket(manifest["snapshot"]) if manifest and manifest["series"]["name"] == profile["name"] else None
        if pinned is None or pinned["release_sha256"] != frozen["release_sha256"]:
            frozen_change = True
            if not args.accept_frozen_release:
                fail(
                    f"frozen pocket {frozen['suite']} Release {frozen['release_sha256']} differs from the "
                    "reviewed manifest value; review the Release delta and pass --accept-frozen-release"
                )

    workspace.mkdir(parents=True)
    members = workspace / "members"
    members.mkdir()
    locks_directory = workspace / "locks"
    locks_directory.mkdir()
    closures: dict[str, dict] = {}
    identities: dict[str, dict] = {}
    repository_ids: dict[str, dict[str, str]] = {}
    unavailable: dict[str, dict[str, str]] = {}
    manifest_identities = manifest["identities"] if manifest else []
    for arch in profile["architectures"]:
        configs = write_configs(workspace / "config" / arch, profile, timestamp, arch,
                                frozen["release_sha256"] if frozen else None)
        debz = Debz(debz_path, workspace, arch, configs, profile["keyring"])
        refresh_ids = debz.refresh(set(pockets))
        repository_ids[arch] = refresh_ids
        closure_lock_path = locks_directory / f"{arch}.lock.json"
        closure_lock = debz.plan(profile["request"], closure_lock_path)
        debz.download(profile["request"], closure_lock_path)
        locks = [closure_lock]
        by_id = {repository_id: suite for suite, repository_id in refresh_ids.items()}
        packages = lock_packages(closure_lock, by_id)
        lock_entries = {package["name"]: package for package in closure_lock["packages"]}
        require_sha512(packages, arch)
        closure_packages = dict(packages)
        for identity in manifest_identities:
            if arch not in identity["architectures"]:
                continue
            names = [identity["package"]] + [item["package"] for item in identity.get("derived_from", [])]
            for name in names:
                if name in packages:
                    continue
                lock_path = locks_directory / f"{arch}-{name}.lock.json"
                try:
                    extra = debz.plan(name, lock_path)
                except RepinError as error:
                    unavailable.setdefault(arch, {})[name] = str(error)[:500]
                    continue
                debz.download(name, lock_path)
                locks.append(extra)
                extra_packages = lock_packages(extra, by_id)
                require_sha512(extra_packages, arch)
                for package in extra["packages"]:
                    lock_entries.setdefault(package["name"], package)
                for package_name, entry in extra_packages.items():
                    packages.setdefault(package_name, entry)
        bound = bind_pockets(pockets, locks, refresh_ids, profile["signer"], arch)
        for suite, pocket in pockets.items():
            pocket["binding"][arch] = "exact_lock" if suite in bound else "refresh_only"
        for name, entry in packages.items():
            entry["lock_package"] = lock_entries[name]
        for identity in manifest_identities:
            if arch in identity["architectures"]:
                identities.setdefault(identity["id"], {})[arch] = observe_identity(
                    identity, arch, packages, debz, members
                )
        counts: dict[str, int] = {}
        for entry in closure_packages.values():
            counts[entry["pocket"]] = counts.get(entry["pocket"], 0) + 1
        closures[arch] = {
            "lock": f"locks/{arch}.lock.json",
            "lock_sha256": tagged("sha256", closure_lock_path.read_bytes()),
            "digest": closure_digest(closure_packages),
            "package_count": len(closure_packages),
            "pockets": dict(sorted(counts.items())),
            "packages": {
                name: {k: entry[k] for k in ("version", "architecture", "archive", "pocket")}
                for name, entry in sorted(closure_packages.items())
            },
        }

    for suite, data in first.items():
        if fetch(f"{uri}/dists/{suite}/InRelease") != data:
            fail(f"{suite} InRelease changed between the first and second fetch; the snapshot is not settled")
    ordered = [pockets[pocket["suite"]] for pocket in profile["pockets"]]
    deadline = check_pocket_dates(ordered, snapshot_seconds)
    report = {
        "schema": REPORT_SCHEMA,
        "series": profile,
        "timestamp": timestamp,
        "uri": uri,
        "probed_at": now,
        "debz_sha256": tagged("sha256", debz_path.read_bytes()),
        "frozen_release_change": frozen_change,
        "pockets": ordered,
        "repository_ids": repository_ids,
        "admission_deadline": deadline,
        "closures": closures,
        "unavailable": unavailable,
        "identities": identities,
    }
    write_json(workspace / "report.json", report)
    (workspace / "summary.md").write_text(report_summary(report), encoding="utf-8")
    print(f"probe passed: {workspace / 'report.json'}")
    return 0


def unbound_pockets(pockets: list[dict]) -> list[str]:
    lines = []
    for pocket in pockets:
        architectures = [arch for arch, binding in pocket["binding"].items() if binding == "refresh_only"]
        if architectures:
            role = "witness of the frozen pocket" if pocket["role"] == "witness" else f"{pocket['role']} pocket"
            lines.append(f"- `{pocket['suite']}` ({role}) on {', '.join(architectures)}")
    return lines


def report_summary(report: dict) -> str:
    lines = [
        f"## Real-snapshot probe: `{report['series']['name']}` at `{report['timestamp']}`",
        "",
        f"- URI: `{report['uri']}`",
        f"- Admission deadline: {report['admission_deadline']} "
        f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(report['admission_deadline']))})",
        f"- debz: `{report['debz_sha256']}`",
        "",
        "| Pocket | Role | Date | Valid-Until | Hash fields | Release (cleartext) | Deadline | Binding |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for pocket in report["pockets"]:
        binding = ", ".join(f"{arch}: {value}" for arch, value in pocket["binding"].items())
        lines.append(
            f"| `{pocket['suite']}` | {pocket['role']} | {pocket['date']} | {pocket['valid_until'] or 'none'} "
            f"| {', '.join(pocket['hash_fields'])} | `{pocket['release_sha256']}` | {pocket['deadline']} "
            f"| {binding} |"
        )
    lines += ["", "| Architecture | Packages | Pockets | Closure digest |", "|---|---|---|---|"]
    for arch, closure in report["closures"].items():
        pockets = ", ".join(f"{suite}: {count}" for suite, count in closure["pockets"].items())
        lines.append(f"| {arch} | {closure['package_count']} | {pockets} | `{closure['digest']}` |")
    unbound = unbound_pockets(report["pockets"])
    if unbound:
        lines += [
            "",
            "Pockets that contribute no locked package. `debz refresh` authenticated them, but debz emits "
            "no Release digest for a repository outside an exact lock, so their fetched Release is recorded "
            "without that cross-check:",
            "",
            *unbound,
        ]
    return "\n".join(lines) + "\n"


# Diff.


def load_report(path: Path) -> dict:
    report = load_json(path)
    if report.get("schema") != REPORT_SCHEMA:
        fail(f"{path} is not a repin probe report")
    validate_profile(report["series"], "report.series")
    return report


def identity_status(identity: dict, observed: dict[str, dict | None]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    status = "unchanged"
    for arch in identity["architectures"]:
        value = observed.get(arch)
        if value is None:
            return "missing", [f"{identity['package']} is not in the {arch} snapshot"]
        if identity["kind"] == "prestate":
            stale = [
                f"{item['package']} {item['version']} -> {value['derived_versions'].get(item['package'])}"
                for item in identity["derived_from"]
                if value["derived_versions"].get(item["package"]) != item["version"]
            ]
            if stale:
                return "changed", [f"{arch}: derived state depends on changed packages: {', '.join(stale)}"]
            if value.get("digest") is not None and (
                value["digest"] != identity["digest"]
                or value["size"] != identity["size"]
                or value["mode"] != identity["mode"]
            ):
                return "changed", [f"{arch}: derived prestate changed: {identity['digest']} -> {value['digest']}"]
        elif value["digest"] != identity["digest"] or value["size"] != identity["size"] or value["mode"] != identity["mode"]:
            return "changed", [f"{arch}: bound bytes changed: {identity['digest']} -> {value['digest']}"]
        provenance = identity["provenance"]
        if identity["version_bound"] and provenance != "pending" and value["version"] != provenance["version"]:
            return "changed", [
                f"{arch}: version-bound identity moved from {provenance['version']} to {value['version']}"
            ]
        if provenance == "pending":
            reasons.append(f"{arch}: records first provenance")
            status = "provenance-only"
        elif provenance["archives"].get(arch) != value["archive"] or provenance["version"] != value["version"]:
            reasons.append(f"{arch}: archive {provenance['archives'].get(arch)} -> {value['archive']}")
            status = "provenance-only"
    return status, reasons


def advisory(old: bytes | None, new: bytes | None) -> str:
    if old is None or new is None:
        return "no in-tree bytes to compare; review the new member"

    def code(data: bytes) -> list[str]:
        result = []
        for line in data.decode("utf-8", "replace").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                result.append(" ".join(stripped.split()))
        return result

    if code(old) == code(new):
        return "comments or whitespace only"
    return "behavioral change; review every hunk"


def fixture_bytes(identity: dict, root: Path) -> bytes | None:
    for consumer in identity["consumers"]:
        if consumer["form"] == "fixture":
            path = root / consumer["path"]
            return path.read_bytes() if path.is_file() else None
    return None


def compute_diff(manifest: dict, report: dict, report_directory: Path, root: Path, allow_series_migration: bool = False) -> dict:
    if manifest["series"] != report["series"] and not allow_series_migration:
        fail("the report and manifest describe different series profiles")
    comparison_manifest = manifest
    if manifest["series"] != report["series"]:
        comparison_manifest = copy.deepcopy(manifest)
        comparison_manifest["series"] = copy.deepcopy(report["series"])
        comparison_manifest["snapshot"] = {
            "timestamp": report["timestamp"],
            "status": "pending",
        }
    statuses = []
    reported = report["identities"]
    for identity in comparison_manifest["identities"]:
        observed = reported.get(identity["id"], {})
        status, reasons = identity_status(identity, observed)
        entry = {"id": identity["id"], "status": status, "reasons": reasons}
        if status == "changed" and identity["kind"] in ("script", "tool_file"):
            arch = identity["architectures"][0]
            value = observed.get(arch)
            new = (report_directory / value["member_file"]).read_bytes() if value and value.get("member_file") else None
            old = fixture_bytes(identity, root)
            entry["advisory"] = advisory(old, new)
            if old is not None and new is not None and identity["kind"] == "script":
                entry["unified_diff"] = "".join(difflib.unified_diff(
                    old.decode("utf-8", "replace").splitlines(keepends=True),
                    new.decode("utf-8", "replace").splitlines(keepends=True),
                    fromfile=f"pinned/{identity['id']}",
                    tofile=f"{report['timestamp']}/{identity['id']}",
                ))
        statuses.append(entry)
    closures = {}
    old_closures = comparison_manifest["snapshot"].get("closures", {})
    for arch, closure in report["closures"].items():
        old = old_closures.get(arch, {}).get("packages", {})
        new = {name: entry["version"] for name, entry in closure["packages"].items()}
        closures[arch] = {
            "added": sorted(f"{name} {new[name]}" for name in set(new) - set(old)),
            "removed": sorted(f"{name} {old[name]}" for name in set(old) - set(new)),
            "changed": sorted(
                f"{name} {old[name]} -> {new[name]}" for name in set(old) & set(new) if old[name] != new[name]
            ),
        }
    pinned_frozen = frozen_pocket(comparison_manifest["snapshot"])
    reported_frozen = frozen_pocket(report)
    return {
        "series": report["series"]["name"],
        "from": manifest["snapshot"]["timestamp"],
        "to": report["timestamp"],
        "series_migration": manifest["series"]["name"] if manifest["series"] != report["series"] else None,
        "frozen_release": None if reported_frozen is None else {
            "pinned": None if pinned_frozen is None else pinned_frozen["release_sha256"],
            "probed": reported_frozen["release_sha256"],
        },
        "closures": closures,
        "identities": statuses,
    }


def pinned_strings(manifest: dict) -> dict[str, str]:
    strings = {snapshot_uri(manifest["series"], manifest["snapshot"]["timestamp"]): "uri"}
    strings[manifest["snapshot"]["timestamp"]] = "timestamp"
    snapshot = manifest["snapshot"]
    for pocket in snapshot.get("pockets", []):
        strings[pocket["release_sha256"].split(":", 1)[1]] = f"release:{pocket['suite']}"
        strings[pocket["in_release_sha256"].split(":", 1)[1]] = f"in-release:{pocket['suite']}"
    for arch, closure in snapshot.get("closures", {}).items():
        strings[closure["digest"].split(":", 1)[1]] = f"closure:{arch}"
    for identity in manifest["identities"]:
        strings[identity["digest"].split(":", 1)[1]] = f"identity:{identity['id']}"
        if identity["provenance"] != "pending":
            for arch, archive in identity["provenance"]["archives"].items():
                strings[archive.split(":", 1)[1]] = f"archive:{identity['id']}@{arch}"
    return strings


def scan_pr_diff(text: str, manifest: dict, changed: set[str]) -> list[dict]:
    """Lists added PR lines that pin an identity this repin changes."""
    strings = pinned_strings(manifest)
    findings = []
    path = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for value, label in strings.items():
            if value in line:
                findings.append({"path": path, "pin": label, "stale": label in changed, "line": line[1:].strip()[:200]})
    return findings


def changed_labels(diff: dict, manifest: dict, report: dict) -> set[str]:
    labels = set()
    if manifest["snapshot"]["timestamp"] != report["timestamp"]:
        labels.update({"uri", "timestamp"})
    for pocket in manifest["snapshot"].get("pockets", []):
        new = next((p for p in report["pockets"] if p["suite"] == pocket["suite"]), None)
        if new is None or new["release_sha256"] != pocket["release_sha256"]:
            labels.add(f"release:{pocket['suite']}")
        if new is None or new["in_release_sha256"] != pocket["in_release_sha256"]:
            labels.add(f"in-release:{pocket['suite']}")
    for arch, closure in manifest["snapshot"].get("closures", {}).items():
        if report["closures"].get(arch, {}).get("digest") != closure["digest"]:
            labels.add(f"closure:{arch}")
    for entry in diff["identities"]:
        if entry["status"] in ("changed", "missing"):
            labels.add(f"identity:{entry['id']}")
        if entry["status"] != "unchanged":
            for arch in ("amd64", "arm64"):
                labels.add(f"archive:{entry['id']}@{arch}")
    return labels


def diff_summary(diff: dict, findings: list[dict]) -> str:
    lines = [f"## Real-snapshot diff: `{diff['series']}` `{diff['from']}` -> `{diff['to']}`", ""]
    frozen = diff["frozen_release"]
    if frozen is not None:
        state = "unchanged" if frozen["pinned"] == frozen["probed"] else "CHANGED (needs --accept-frozen-release)"
        lines.append(f"- Frozen release: {state}: `{frozen['probed']}`")
    for arch, closure in diff["closures"].items():
        lines.append(
            f"- {arch}: {len(closure['changed'])} changed, {len(closure['added'])} added, "
            f"{len(closure['removed'])} removed closure packages"
        )
        for key in ("changed", "added", "removed"):
            for item in closure[key]:
                lines.append(f"  - {key}: {item}")
    lines += ["", "| Identity | Status | Detail |", "|---|---|---|"]
    for entry in diff["identities"]:
        detail = "; ".join(entry["reasons"])
        if "advisory" in entry:
            detail += f" ({entry['advisory']})"
        lines.append(f"| `{entry['id']}` | {entry['status']} | {detail} |")
    if findings:
        lines += ["", "| PR file | Pin | Stale |", "|---|---|---|"]
        for finding in findings:
            lines.append(f"| `{finding['path']}` | `{finding['pin']}` | {'yes' if finding['stale'] else 'no'} |")
    return "\n".join(lines) + "\n"


def diff_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    report = load_report(args.report)
    diff = compute_diff(manifest, report, args.report.parent, args.root.resolve(), args.allow_series_migration)
    findings = []
    texts = []
    for number in args.pr or []:
        result = subprocess.run(["gh", "pr", "diff", str(number)], capture_output=True, check=False, timeout=300)
        if result.returncode != 0:
            fail(f"gh pr diff {number} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
        texts.append((f"#{number}", result.stdout.decode("utf-8", "replace")))
    for path in args.pr_diff_file or []:
        texts.append((str(path), path.read_text(encoding="utf-8")))
    labels = changed_labels(diff, manifest, report)
    for source, text in texts:
        for finding in scan_pr_diff(text, manifest, labels):
            finding["pr"] = source
            findings.append(finding)
    diff["pr_findings"] = findings
    write_json(args.report.parent / "diff.json", diff)
    summary = diff_summary(diff, findings)
    (args.report.parent / "diff.md").write_text(summary, encoding="utf-8")
    sys.stdout.write(summary)
    return 0


# Record.


def parse_reviews(values: list[str]) -> dict[str, str]:
    reviews: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            fail(f"--reviewed must be IDENTITY=REFERENCE: {value!r}")
        identity, reference = value.split("=", 1)
        if not REVIEW_REFERENCE.fullmatch(reference):
            fail(f"--reviewed {identity} needs a PR or issue reference such as #330")
        if identity in reviews:
            fail(f"--reviewed {identity} is repeated")
        reviews[identity] = reference
    return reviews


def migrated_fixture_path(identity: dict, series_name: str) -> str:
    member = str(identity["path"] or "").replace("/", "-")
    if not member:
        fail(f"{identity['id']} fixture consumer cannot be renamed without a member path")
    return f"src/fixtures/{series_name}-{identity['package']}.{member}"


def refresh_exclusion_reasons(manifest: dict) -> None:
    reasons = {
        "sha256:0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5":
            "pinned dpkg 1.22.22 private Debian reference prepared by tools/prepare-native-dpkg.py; external oracle, not the resolute snapshot dpkg pin",
        "sha256:b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13":
            "update-alternatives from the pinned dpkg 1.22.22 private Debian reference (amd64); external oracle, not the resolute snapshot dpkg pin",
        "sha256:35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5":
            "update-alternatives from the pinned dpkg 1.22.22 private Debian reference (arm64); external oracle, not the resolute snapshot dpkg pin",
    }
    for item in manifest.get("excluded", []):
        reason = reasons.get(item.get("digest"))
        if reason is not None:
            item["reason"] = reason


def record_manifest(
    manifest: dict,
    report: dict,
    diff: dict,
    reviews: dict[str, str],
    accept_frozen: str | None,
    allow_series_migration: bool = False,
) -> dict:
    series_migration = report["series"]["name"] != manifest["series"]["name"]
    if series_migration and not allow_series_migration:
        fail("the report is for a different series")
    if timestamp_seconds(report["timestamp"]) < timestamp_seconds(manifest["snapshot"]["timestamp"]):
        fail(f"the report snapshot {report['timestamp']} is older than the current pin")
    required = {entry["id"] for entry in diff["identities"] if entry["status"] in ("changed", "missing")}
    unreviewed = sorted(required - set(reviews))
    if unreviewed:
        fail("reviewed identities changed without re-review: " + ", ".join(unreviewed) +
             "; pass --reviewed ID=#PR for each after reviewing it")
    unexpected = sorted(set(reviews) - required)
    if unexpected:
        fail("--reviewed names identities that did not change: " + ", ".join(unexpected))
    frozen = diff["frozen_release"]
    frozen_changed = frozen is not None and frozen["pinned"] != frozen["probed"]
    if frozen_changed and accept_frozen is None:
        fail("the frozen release changed; review the Release delta and pass --accept-frozen-release #PR")
    if accept_frozen is not None and not frozen_changed:
        fail("--accept-frozen-release was passed but the frozen release did not change")
    if accept_frozen is not None and not REVIEW_REFERENCE.fullmatch(accept_frozen):
        fail("--accept-frozen-release needs a PR or issue reference")

    updated = copy.deepcopy(manifest)
    if series_migration:
        updated["series"] = copy.deepcopy(report["series"])
    previous_frozen = frozen_pocket(manifest["snapshot"])
    pockets = []
    for pocket in report["pockets"]:
        entry = {key: pocket[key] for key in (
            "suite", "role", "date", "valid_until", "release_sha256", "in_release_sha256",
            "in_release_sha512", "hash_fields", "signers", "deadline", "binding")}
        if pocket["role"] == "frozen":
            entry["review"] = accept_frozen if frozen_changed else previous_frozen["review"]
        pockets.append(entry)
    updated["snapshot"] = {
        "timestamp": report["timestamp"],
        "status": "probed",
        "pockets": pockets,
        "admission_deadline": report["admission_deadline"],
        "closures": {
            arch: {
                "digest": closure["digest"],
                "package_count": closure["package_count"],
                "pockets": closure["pockets"],
                "packages": {name: entry["version"] for name, entry in closure["packages"].items()},
            }
            for arch, closure in report["closures"].items()
        },
    }
    identities = []
    for identity, entry in zip(manifest["identities"], diff["identities"]):
        if entry["status"] == "missing":
            continue
        observed = report["identities"][identity["id"]]
        first = observed[identity["architectures"][0]]
        new = copy.deepcopy(identity)
        if identity["kind"] != "prestate" or first.get("digest") is not None:
            new.update(digest=first["digest"], size=first["size"], mode=first["mode"])
        if series_migration:
            for consumer in new["consumers"]:
                if consumer["form"] == "fixture" and consumer["path"].startswith("src/fixtures/ubuntu-"):
                    consumer["path"] = migrated_fixture_path(identity, report["series"]["name"])
        if identity["version_bound"] and identity["provenance"] != "pending":
            old_name = identity["provenance"]["version"].split(":", 1)[-1]
            new_name = first["version"].split(":", 1)[-1]
            for consumer in new["consumers"]:
                if consumer["form"] == "fixture" and old_name != new_name:
                    consumer["path"] = consumer["path"].replace(old_name, new_name)
        new["provenance"] = {
            "version": first["version"],
            "archives": {arch: observed[arch]["archive"] for arch in identity["architectures"]},
        }
        if identity["kind"] == "prestate":
            new["derived_from"] = [
                {"package": item["package"], "version": first["derived_versions"][item["package"]]}
                for item in identity["derived_from"]
            ]
        if entry["status"] == "changed":
            new["review"] = reviews[identity["id"]]
        identities.append(new)
    updated["identities"] = identities
    refresh_exclusion_reasons(updated)
    return validate_manifest(updated)


def record_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    report = load_report(args.report)
    diff = compute_diff(manifest, report, args.report.parent, args.root.resolve(), args.allow_series_migration)
    updated = record_manifest(
        manifest,
        report,
        diff,
        parse_reviews(args.reviewed or []),
        args.accept_frozen_release,
        args.allow_series_migration,
    )
    write_json(args.manifest, updated)
    counts = {status: sum(1 for entry in diff["identities"] if entry["status"] == status) for status in STATUSES}
    print(f"recorded {report['timestamp']}: " + ", ".join(f"{count} {status}" for status, count in counts.items()))
    return 0


# Check.


def zig_bytes_constant(text: str, name: str) -> str | None:
    match = re.search(r"\bconst\s+" + re.escape(name) + r"\b[^=]*=\s*(?:\[32\]u8)?\s*\.?\{(?P<body>[^}]*)\}", text)
    if match is None:
        return None
    values = ZIG_BYTE.findall(match.group("body"))
    if len(values) != hashlib.sha256().digest_size:
        return None
    return "".join(value.lower() for value in values)


def consumer_failures(identity: dict, root: Path) -> list[str]:
    failures = []
    hexadecimal = identity["digest"].split(":", 1)[1]
    version = None
    if identity["version_bound"] and identity["provenance"] != "pending":
        version = identity["provenance"]["version"].split(":", 1)[-1]
    version_seen = version is None
    for consumer in identity["consumers"]:
        path = root / consumer["path"]
        where = f"{identity['id']} consumer {consumer['path']}"
        if not path.is_file() or path.is_symlink():
            failures.append(f"{where} does not exist")
            continue
        data = path.read_bytes()
        if consumer["form"] == "fixture":
            if tagged("sha256", data) != identity["digest"] or len(data) != identity["size"]:
                failures.append(f"{where} bytes do not match {identity['digest']} ({identity['size']} bytes)")
            if version is not None and version not in consumer["path"]:
                failures.append(f"{where} name does not carry version {identity['provenance']['version']}")
            version_seen = True
            continue
        text = data.decode("utf-8", "replace")
        if version is not None and version in text:
            version_seen = True
        if consumer["form"] == "hex":
            if hexadecimal not in text:
                failures.append(f"{where} does not pin {identity['digest']}")
        elif zig_bytes_constant(text, consumer["name"]) != hexadecimal:
            failures.append(f"{where} constant {consumer['name']} is not {identity['digest']}")
    if not version_seen:
        failures.append(f"{identity['id']} is version-bound but no consumer names {identity['provenance']['version']}")
    return failures


def in_tree_pins(root: Path) -> list[tuple[str, str, dict]]:
    """Returns (location, hex, detail) for every snapshot pin found in the tree.

    Every digest literal in the admission sources and reference scripts counts:
    each must be a manifest identity or an explained exclusion.
    """
    pins: list[tuple[str, str, dict]] = []
    for path in sorted(root.glob(FIXTURE_GLOB)):
        data = path.read_bytes()
        pins.append((str(path.relative_to(root)), hashlib.sha256(data).hexdigest(), {"fixture": True, "size": len(data)}))
    for relative in DEBZ_SNAPSHOT_CONSTANT_SOURCES:
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in SNAPSHOT_CONSTANT.finditer(text):
            name = match.group(1)
            value = zig_bytes_constant(text, name)
            if value is not None:
                pins.append((f"{relative}:{name}", value, {}))
            elif QUOTED_HEX_LITERAL.match(text, match.end()) is None and not re.match(
                r'\s*digestLiteral\(\s*"', text[match.end():match.end() + 64]
            ):
                pins.append((f"{relative}:{name}", "", {"unparsed": True}))
        for match in SNAPSHOT_INPUT_ENTRY.finditer(text):
            mode = match.group("mode") or match.group("leading_mode")
            detail = {"path": match.group("path"), "size": int(match.group("size"))}
            if mode is not None:
                detail["mode"] = "0" + mode
            pins.append((f"{relative}:{match.group('path')}", match.group("hex"), detail))
        for match in QUOTED_HEX_LITERAL.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            pins.append((f"{relative}:{line}", match.group(1), {}))
    for path in sorted(root.glob(PIN_SCRIPT_GLOB)):
        text = path.read_text(encoding="utf-8")
        for match in HEX_LITERAL.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            pins.append((f"{path.relative_to(root)}:{line}", match.group(0), {}))
    return pins


def bound_paths(identity: dict) -> set[str]:
    """Paths under which in-tree admissions may name the identity's bytes."""
    if identity["path"] is None:
        return set()
    if identity["kind"] == "script":
        return {identity["path"], f"var/lib/dpkg/info/{identity['package']}.{identity['path']}"}
    return {identity["path"]}


def shell_readonly_scalars(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        match = re.match(r"^\s*readonly\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if match is None:
            continue
        raw = match.group(2).strip()
        if raw.startswith("("):
            continue
        try:
            words = shlex.split(raw, comments=True, posix=True)
        except ValueError:
            continue
        if len(words) == 1:
            values[match.group(1)] = words[0]
    return values


def shell_readonly_array(text: str, pattern: re.Pattern[str]) -> list[str] | None:
    match = pattern.search(text)
    if match is None:
        return None
    try:
        return shlex.split(match.group("body"), comments=True, posix=True)
    except ValueError:
        return None


def protected_stage_profile_coupling_failures(manifest: dict, root: Path) -> list[str]:
    """Check the protected stage, launcher profile pins and manifest agree.

    The amd64 protected stage extracts postinsts from the configured snapshot
    repositories, while the launcher independently pins those same postinsts by
    version, byte size and SHA-256. This local check makes that cross-file
    contract explicit so a suite revert cannot silently strand profile pins on
    another series until the protected CI proof runs.
    """
    stage_path = root / PROTECTED_STAGE_SCRIPT
    launcher_path = root / REFERENCE_LAUNCHER
    if not stage_path.exists() and not launcher_path.exists():
        return []
    failures = []
    if not stage_path.is_file() or stage_path.is_symlink():
        return [f"protected profile coupling: {PROTECTED_STAGE_SCRIPT} does not exist"]
    if not launcher_path.is_file() or launcher_path.is_symlink():
        return [f"protected profile coupling: {REFERENCE_LAUNCHER} does not exist"]
    stage = stage_path.read_text(encoding="utf-8")
    launcher = launcher_path.read_text(encoding="utf-8")

    frozen_pockets = [pocket for pocket in manifest["series"]["pockets"] if pocket["role"] == "frozen"]
    if frozen_pockets:
        if len(frozen_pockets) != 1:
            failures.append("protected stage profile coupling: series must have exactly one frozen pocket")
        else:
            frozen_suite = frozen_pockets[0]["suite"]
            witness_suites = [
                pocket["suite"] for pocket in manifest["series"]["pockets"] if pocket["role"] == "witness"
            ]
            scalars = shell_readonly_scalars(stage)
            if scalars.get("snapshot_uri") != snapshot_uri(manifest["series"], manifest["snapshot"]["timestamp"]):
                failures.append(
                    f"protected stage profile coupling: {PROTECTED_STAGE_SCRIPT} does not pin "
                    f"{snapshot_uri(manifest['series'], manifest['snapshot']['timestamp'])}"
                )
            if scalars.get("snapshot_suite") != frozen_suite:
                failures.append(
                    f"protected stage profile coupling: snapshot_suite={scalars.get('snapshot_suite')!r}, "
                    f"expected frozen suite {frozen_suite!r}"
                )
            stage_witnesses = shell_readonly_array(stage, STAGE_WITNESS_ARRAY)
            if stage_witnesses != witness_suites:
                failures.append(
                    f"protected stage profile coupling: snapshot_witness_suites={stage_witnesses!r}, "
                    f"expected {witness_suites!r}"
                )
            frozen_records = [
                pocket for pocket in manifest["snapshot"].get("pockets", [])
                if pocket["suite"] == frozen_suite and pocket["role"] == "frozen"
            ]
            if frozen_records:
                expected_digest = frozen_records[0]["release_sha256"].split(":", 1)[1]
                if scalars.get("frozen_release_sha256") != expected_digest:
                    failures.append(
                        f"protected stage profile coupling: frozen_release_sha256="
                        f"{scalars.get('frozen_release_sha256')!r}, expected {expected_digest!r}"
                    )

    bindings = [match.groupdict() for match in SCRIPT_BINDING_ENTRY.finditer(launcher)]
    if not bindings:
        failures.append(f"protected stage profile coupling: {REFERENCE_LAUNCHER} has no script_bindings")
        return failures
    profile_match = STAGE_PROFILE_LOOP.search(stage)
    if profile_match is None:
        failures.append(f"protected stage profile coupling: {PROTECTED_STAGE_SCRIPT} has no profile staging loop")
    else:
        try:
            staged_profiles = shlex.split(profile_match.group("body"), comments=True, posix=True)
        except ValueError:
            staged_profiles = []
        binding_names = [binding["name"] for binding in bindings]
        if staged_profiles != binding_names:
            failures.append(
                f"protected stage profile coupling: staged profiles {staged_profiles!r} "
                f"do not match launcher bindings {binding_names!r}"
            )

    identities = {identity["id"]: identity for identity in manifest["identities"]}
    for binding in bindings:
        identity_id = f"script:{binding['name']}/postinst"
        identity = identities.get(identity_id)
        if identity is None:
            failures.append(f"protected stage profile coupling: {identity_id} is not a manifest identity")
            continue
        expected_digest = "sha256:" + binding["digest"]
        if identity["digest"] != expected_digest:
            failures.append(
                f"protected stage profile coupling: {REFERENCE_LAUNCHER} {binding['name']} digest "
                f"{expected_digest} disagrees with {identity_id} {identity['digest']}"
            )
        if identity["size"] != int(binding["size"]):
            failures.append(
                f"protected stage profile coupling: {REFERENCE_LAUNCHER} {binding['name']} size "
                f"{binding['size']} disagrees with {identity_id} {identity['size']}"
            )
        provenance = identity["provenance"]
        version = provenance.get("version") if isinstance(provenance, dict) else None
        if version != binding["version"]:
            failures.append(
                f"protected stage profile coupling: {REFERENCE_LAUNCHER} {binding['name']} version "
                f"{binding['version']!r} disagrees with {identity_id} provenance {version!r}"
            )
        if identity["architectures"] != ["amd64"]:
            failures.append(f"protected stage profile coupling: {identity_id} must be amd64-only")
        if not any(
            consumer["form"] == "hex" and consumer["path"] == REFERENCE_LAUNCHER
            for consumer in identity["consumers"]
        ):
            failures.append(
                f"protected stage profile coupling: {identity_id} does not register "
                f"{REFERENCE_LAUNCHER} as a hex consumer"
            )
    return failures


def check_manifest(manifest: dict, root: Path, profile: dict | None = None) -> list[str]:
    failures: list[str] = []
    series = manifest["series"]
    expected = profile
    if expected is None and series["name"] in PROFILES:
        expected = {"name": series["name"], **PROFILES[series["name"]]}
    if expected is None:
        failures.append(f"series {series['name']} is not a built-in profile; pass --profile")
    elif expected != series:
        failures.append(f"series {series['name']} differs from its reviewed profile")
    uri = snapshot_uri(series, manifest["snapshot"]["timestamp"])
    for relative in manifest["uri_consumers"]:
        path = root / relative
        if not path.is_file():
            failures.append(f"URI consumer {relative} does not exist")
            continue
        text = path.read_text(encoding="utf-8")
        if uri not in text:
            failures.append(f"URI consumer {relative} does not pin {uri}")
        others = {match.group(1) for match in SNAPSHOT_URI.finditer(text)} - {manifest["snapshot"]["timestamp"]}
        for other in sorted(others):
            failures.append(f"URI consumer {relative} pins another snapshot {other}")
    digests: dict[str, dict] = {}
    for pocket in manifest["snapshot"].get("pockets", []):
        digests[pocket["release_sha256"].split(":", 1)[1]] = {"id": f"release:{pocket['suite']}", "path": None, "size": None}
        digests[pocket["in_release_sha256"].split(":", 1)[1]] = {"id": f"in-release:{pocket['suite']}", "path": None, "size": None}
    for arch, closure in manifest["snapshot"].get("closures", {}).items():
        digests[closure["digest"].split(":", 1)[1]] = {"id": f"closure:{arch}", "path": None, "size": None}
    for identity in manifest["identities"]:
        failures += consumer_failures(identity, root)
        digests.setdefault(identity["digest"].split(":", 1)[1], identity)
    failures += protected_stage_profile_coupling_failures(manifest, root)
    excluded = {item["digest"].split(":", 1)[1] for item in manifest["excluded"]}
    fixture_consumers = {
        consumer["path"]
        for identity in manifest["identities"]
        for consumer in identity["consumers"]
        if consumer["form"] == "fixture"
    }
    for location, value, detail in in_tree_pins(root):
        if detail.get("unparsed"):
            failures.append(f"cannot parse the snapshot pin {location}")
            continue
        if detail.get("fixture") and location not in fixture_consumers:
            failures.append(f"fixture {location} is not a manifest identity consumer")
            continue
        if value in excluded:
            continue
        identity = digests.get(value)
        if identity is None:
            failures.append(f"in-tree pin {location} {value[:16]}... is absent from the manifest")
            continue
        if "path" in detail and (
            detail["path"] not in bound_paths(identity)
            or identity["size"] != detail["size"]
            or ("mode" in detail and identity["mode"] not in (None, detail["mode"]))
        ):
            failures.append(f"in-tree pin {location} disagrees with {identity['id']} on path, size or mode")
    return failures


def check_command(args: argparse.Namespace) -> int:
    manifest = validate_manifest(load_json(args.manifest))
    profile = None
    if args.profile is not None:
        profile = validate_profile(load_json(args.profile), "profile")
    failures = check_manifest(manifest, args.root.resolve(), profile)
    if failures:
        for failure in failures:
            print(f"check: {failure}", file=sys.stderr)
        return 1
    status = manifest["snapshot"]["status"]
    print(
        f"check passed: {len(manifest['identities'])} identities for {manifest['series']['name']} "
        f"{manifest['snapshot']['timestamp']} ({status})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    probe_parser = commands.add_parser("probe", help="authenticate and record one settled snapshot")
    probe_parser.add_argument("--series", required=True)
    probe_parser.add_argument("--timestamp")
    probe_parser.add_argument("--debz", required=True)
    probe_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    probe_parser.add_argument("--profile", type=Path)
    probe_parser.add_argument("--workspace", type=Path)
    probe_parser.add_argument("--accept-frozen-release", action="store_true")

    diff_parser = commands.add_parser("diff", help="compare a probe report with the manifest")
    diff_parser.add_argument("--report", type=Path, required=True)
    diff_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    diff_parser.add_argument("--pr", type=int, action="append")
    diff_parser.add_argument("--pr-diff-file", type=Path, action="append")
    diff_parser.add_argument("--root", type=Path, default=ROOT)
    diff_parser.add_argument("--allow-series-migration", action="store_true")

    record_parser = commands.add_parser("record", help="rewrite the manifest from a probe report")
    record_parser.add_argument("--report", type=Path, required=True)
    record_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    record_parser.add_argument("--reviewed", action="append", metavar="ID=REF")
    record_parser.add_argument("--accept-frozen-release", metavar="REF")
    record_parser.add_argument("--root", type=Path, default=ROOT)
    record_parser.add_argument("--allow-series-migration", action="store_true")

    check_parser = commands.add_parser("check", help="offline: verify in-tree pins against the manifest")
    check_parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    check_parser.add_argument("--root", type=Path, default=ROOT)
    check_parser.add_argument("--profile", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            return probe(args)
        if args.command == "diff":
            return diff_command(args)
        if args.command == "record":
            return record_command(args)
        return check_command(args)
    except RepinError as error:
        print(f"real-snapshot-repin: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
