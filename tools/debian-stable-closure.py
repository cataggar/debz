#!/usr/bin/env python3
"""Reproducible, authenticated Debian stable closure locks and pre-mutation inventory (#261).

`run` resolves the pinned trixie snapshot for one architecture in a new
workspace, publishes bound exact-lock v3 documents, downloads every archive into
a fresh package cache, independently rechecks the signed Release, index, and
every cached archive, and runs the native pre-mutation inventory. `compare`
proves two clean runs are byte-identical. `record` writes the committed
evidence. Nothing is installed or executed; cross-architecture runs are
therefore permitted.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import lzma
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("debian_stable_readiness", ROOT / "tools/debian-stable-readiness.py")
readiness = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(readiness)

PIN_PATH = ROOT / "tools/fixtures/debian-stable-readiness-v1.json"
EVIDENCE_DIR = ROOT / "tools/fixtures/debian-stable-closure-v1"
EVIDENCE_SCHEMA = "https://debz.dev/test/debian-stable-closure-evidence-v1"
MANIFEST_SCHEMA = "https://debz.dev/test/debian-closure-manifest-v1"
INVENTORY_SCHEMA = "https://debz.dev/test/debian-closure-inventory-v1"
LOCK_SCHEMA = "https://debz.dev/schema/exact-closure-lock-v3"
ARCHITECTURES = ("amd64", "arm64")
# `apt` resolves Debian's minbase (Essential plus apt); `systemd-sysv` adds
# Debian's default init. A lock request names at most one package.
REQUESTS = ("apt", "systemd-sysv")
# Debian's own Signed-By path. The repository identity hashes it, so a canonical
# path is what makes locks byte-identical on other machines.
KEYRING = pathlib.Path("/usr/share/keyrings/debian-archive-trixie-stable.pgp")
ARCHIVE_BINDING = "signed_sha256_derived_sha512"
DERIVED_PROVENANCE = "derived_from_signed_sha256"
MAX_PACKAGES_PER_LOCK = 128
MAX_BYTES_PER_LOCK = 64 * 1024 * 1024
DEADLINE_MS = 300000
# Distinct from verification failures (2): the reviewed pin is intact but stale.
PIN_EXPIRED_EXIT = 75
RETRY_LINE = re.compile(
    r"^debz acquisition retry failed_attempt=[1-6]/6 delay_ms=[1-9][0-9]{0,5} "
    r"(?:http_status=(?:429|500|502|503|504)|error=[A-Z][A-Za-z]{0,63})$"
)
HEX = re.compile(r"[0-9a-f]+")
CATEGORY_STATUS = {
    "native_archive_rejected": "native archive admission refuses the archive before mutation",
    "alternatives_script_authority": "native lifecycle refuses the script before launch; only exact Ubuntu script and dpkg tool digests carry update-alternatives authority",
    "debconf_frontend": "no Debian debconf database/frontend authority; only exact Ubuntu staged-script allowances exist",
    "kernel_filesystem": "runner provides no /proc or /sys; only exact Ubuntu proc views exist",
    "device_node": "runner creates no device nodes and the archive profile rejects them",
    "accounts": "script mutates account databases outside the dpkg database; no Debian execution evidence",
    "service_manager": "service enablement/invocation in a chroot without a running manager; no Debian execution evidence",
    "system_registry": "script updates a system registry outside the dpkg database; no Debian execution evidence",
    "capabilities": "file capabilities are not modeled by the native archive profile",
    "environment_probe": "script probes the runtime environment; the native runner result is unobserved for Debian",
    "dpkg_database_helper": "modeled natively (diversions, statoverrides, triggers, maintscript helpers) but without Debian parity evidence",
    "conffile_helper": "ucf-managed configuration is outside dpkg conffile tracking",
    "ldconfig": "modeled as an ordinary in-root command; no Debian parity evidence",
    "trigger_declaration": "declared trigger interests/activations are modeled; Debian processing parity is unobserved",
    "remove_on_upgrade_conffile": "modeled declaration; Debian upgrade parity is unobserved",
    "ownership_and_mode": "supported metadata recorded for review against statoverrides",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def is_hex(value, algorithm):
    return (
        isinstance(value, str)
        and HEX.fullmatch(value) is not None
        and len(value) == 2 * hashlib.new(algorithm).digest_size
    )


def canonical(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def load_pin():
    return json.loads(PIN_PATH.read_text())


def release_expiry(pin):
    date = datetime.datetime.strptime(pin["release"]["date"], "%a, %d %b %Y %H:%M:%S %Z").replace(
        tzinfo=datetime.timezone.utc
    )
    if pin["release"]["valid_until"] is not None:
        raise ValueError("pinned Release unexpectedly declares Valid-Until")
    return date + datetime.timedelta(seconds=pin["release"]["maximum_release_age_seconds"])


def verify_keyring(path, key):
    """The Signed-By file must be exactly the reviewed key and not writable by others."""
    path = pathlib.Path(path)
    if not path.is_absolute():
        raise ValueError("Signed-By keyring must be absolute")
    current = pathlib.Path(path.anchor)
    for part in ("", *path.parts[1:]):
        current = current / part
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"Signed-By path component is a symlink: {current}")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"Signed-By path component must be root-owned and not group/other writable: {current}")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise ValueError("Signed-By keyring is not a regular file")
    if path.read_bytes() != key:
        raise ValueError("Signed-By keyring differs from the reviewed official key")


def review_lock(lock, pin, architecture, request):
    """Fail-closed review of one bound Debian lock; returns its package count and bytes."""
    if lock.get("schema") != LOCK_SCHEMA or lock.get("version") != 3:
        raise ValueError("lock is not exact-closure-lock v3")
    if lock.get("target_architecture") != architecture:
        raise ValueError("lock target architecture differs")
    if lock.get("local_artifacts") != []:
        raise ValueError("Debian input lock must not contain local artifacts")
    repositories = lock.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise ValueError("lock must bind exactly one repository")
    repository = repositories[0]
    if repository.get("signer_fingerprints") != [pin["signer"]["primary_fingerprint"]]:
        raise ValueError("lock repository is not signed by the reviewed Debian key")
    if repository.get("archive_binding") != ARCHIVE_BINDING:
        raise ValueError("lock repository does not record the signed SHA256 archive binding")
    index = pin["architectures"][architecture]["index_sha256"]
    if repository.get("index_identity") != {"primary": "sha256", "digests": [{"algorithm": "sha256", "digest": index}]}:
        raise ValueError("lock index identity differs from the signed Debian index")
    for field in ("id", "snapshot_sha256", "release_sha256"):
        if not is_hex(repository.get(field), "sha256"):
            raise ValueError(f"lock repository {field} is malformed")
    packages = lock.get("packages")
    if not isinstance(packages, list) or not 0 < len(packages) <= MAX_PACKAGES_PER_LOCK:
        raise ValueError("lock package count is outside the reviewed bound")
    names = [package.get("name") for package in packages]
    if names != sorted(set(names)):
        raise ValueError("lock packages are not unique and canonically ordered")
    requested = [package["name"] for package in packages if package.get("retention") == "requested"]
    if requested != [request]:
        raise ValueError("lock does not retain exactly the reviewed request")
    total = 0
    for package in packages:
        if package.get("architecture") not in (architecture, "all"):
            raise ValueError(f"{package.get('name')}: foreign package architecture")
        if package.get("origin") != {
            "type": "authenticated_repository",
            "repository_id": repository["id"],
            "repository_snapshot_sha256": repository["snapshot_sha256"],
        }:
            raise ValueError(f"{package.get('name')}: origin is not the bound Debian repository")
        identity = package.get("archive_identity")
        if (
            not isinstance(identity, dict)
            or identity.get("primary") != "sha256"
            or len(identity.get("digests", [])) != 1
            or identity["digests"][0].get("algorithm") != "sha256"
            or not is_hex(identity["digests"][0].get("digest"), "sha256")
        ):
            raise ValueError(f"{package.get('name')}: archive identity is not the signed SHA256 alone")
        derived = package.get("derived_archive_identity")
        if (
            not isinstance(derived, dict)
            or derived.get("provenance") != DERIVED_PROVENANCE
            or derived.get("algorithm") != "sha512"
            or not is_hex(derived.get("digest"), "sha512")
        ):
            raise ValueError(f"{package.get('name')}: derived SHA512 provenance is missing or forged")
        size = package.get("declared_size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"{package.get('name')}: declared size is malformed")
        total += size
    if total > MAX_BYTES_PER_LOCK:
        raise ValueError("lock archive bytes exceed the reviewed bound")
    return len(packages), total


def signed_records(compressed, index):
    """Maps (package, version, architecture) to its signed Filename, Size, and SHA256."""
    readiness.index_counts(compressed, index)
    text = lzma.decompress(compressed).decode("utf-8")
    records = {}
    for paragraph in text.split("\n\n"):
        if not paragraph.startswith("Package: "):
            continue
        fields = {}
        for line in paragraph.split("\n"):
            if line and not line[0].isspace() and ": " in line:
                name, value = line.split(": ", 1)
                fields[name] = value
        key = (fields["Package"], fields["Version"], fields["Architecture"])
        if key in records:
            raise ValueError(f"signed index repeats {key}")
        records[key] = {"filename": fields["Filename"], "size": int(fields["Size"]), "sha256": fields["SHA256"]}
    return records


def match_signed(lock, records):
    """Every lock identity must be exactly the signed Debian record for that package."""
    matched = []
    for package in lock["packages"]:
        key = (package["name"], package["version"], package["architecture"])
        record = records.get(key)
        if record is None:
            raise ValueError(f"{key}: package is absent from the signed Debian index")
        if record["sha256"] != package["archive_identity"]["digests"][0]["digest"] or record["size"] != package["declared_size"]:
            raise ValueError(f"{key}: lock identity differs from the signed Debian record")
        if not record["filename"].startswith("pool/"):
            raise ValueError(f"{key}: signed Filename is outside the Debian pool")
        matched.append(record["filename"])
    return matched


def locate_objects(cache, packages):
    """Rehash every cached archive for the given lock packages."""
    rows = []
    directories = set()
    for package in packages:
        primary = package["archive_identity"]["primary"]
        digest = package["archive_identity"]["digests"][0]["digest"]
        found = [path for path in cache.rglob(f"{primary}-{digest}") if not path.is_symlink()]
        if len(found) != 1 or not found[0].is_file():
            raise ValueError(f"{package['name']}: cached archive is missing or ambiguous")
        path = found[0]
        directories.add(path.parent)
        data = path.read_bytes()
        info = os.lstat(path)
        row = {
            "package": package["name"],
            "version": package["version"],
            "architecture": package["architecture"],
            "object": path.relative_to(cache).as_posix(),
            "mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "size": len(data),
            "sha256": sha256(data),
            "derived_sha512": hashlib.sha512(data).hexdigest(),
        }
        if (
            row["size"] != package["declared_size"]
            or row["sha256"] != digest
            or row["derived_sha512"] != package["derived_archive_identity"]["digest"]
        ):
            raise ValueError(f"{package['name']}: cached archive differs from its bound identity")
        rows.append(row)
    if len(directories) != 1:
        raise ValueError("cached archives are not in one package object directory")
    return rows, directories.pop()


def source_bytes(pin, architecture):
    """The exact deb822 source; only Architectures differs between runs."""
    return (
        f"Types: deb\nURIs: {pin['snapshot_uri']}\nSuites: {pin['suite']}\n"
        f"Components: {pin['component']}\nArchitectures: {architecture}\nSigned-By: {KEYRING}\n"
    ).encode()


def run_debz(argv, evidence, name):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=1800, check=False)
    (evidence / f"{name}.json").write_text(result.stdout)
    (evidence / f"{name}.stderr").write_text(result.stderr)
    unexpected = [line for line in result.stderr.splitlines() if not RETRY_LINE.fullmatch(line)]
    if result.returncode != 0 or unexpected or json.loads(result.stdout).get("exit_status") != 0:
        raise ValueError(f"debz {name} refused (exit {result.returncode}): {result.stdout[:400]} {result.stderr[:400]}")


def template(argv, replacements):
    out = []
    for item in argv:
        if out and out[-1] == "--architecture":
            item = "$ARCHITECTURE"
        for value, placeholder in replacements:
            item = item.replace(value, placeholder)
        out.append(item)
    return out


def new_workspace(path):
    workspace = pathlib.Path(path).absolute()
    scratch = ROOT / ".tmp"
    if scratch.is_symlink() or workspace.parent.resolve() != scratch.resolve() or workspace.exists() or workspace.is_symlink():
        raise ValueError("workspace must be a new direct child of this checkout's .tmp directory")
    workspace.mkdir(mode=0o700)
    for name in ("root", "cache", "state", "evidence"):
        (workspace / name).mkdir(mode=0o700)
    return workspace


class PinExpired(ValueError):
    """Live re-resolution refused: the pin's bounded missing-Valid-Until freshness lapsed.

    Debian stable's Release has no Valid-Until and is re-signed only at point
    releases, so this awaits the next point release or the #330 policy. The
    committed evidence stays valid; `check` never reads the clock.
    """


def require_fresh(pin, now):
    """Refuses before any network access once the reviewed pin's bounded freshness has lapsed."""
    expiry = release_expiry(pin)
    if now > expiry:
        raise PinExpired(
            f"pin_expired: pinned Release expired at {expiry.isoformat()}; awaiting the next Debian "
            "point release or the #330 frozen-pocket freshness policy, then review a newer snapshot pin"
        )
    return expiry


def run(args, now):
    pin = load_pin()
    architecture = args.architecture
    require_fresh(pin, now)
    debz = args.debz.resolve(strict=True)
    inventory_tool = args.inventory.resolve(strict=True)
    if not debz.is_file() or not inventory_tool.is_file():
        raise ValueError("debz and inventory executables must be regular files")
    key = readiness.decode_key(readiness.fetch(pin["signer"]["url"], readiness.MAX_KEY_BYTES), pin["signer"])
    verify_keyring(KEYRING, key)
    workspace = new_workspace(args.workspace)
    evidence = workspace / "evidence"
    source = workspace / "debian.sources"
    source.write_bytes(source_bytes(pin, architecture))
    config = workspace / "debian.json"
    config.write_text(json.dumps({
        "source_path": str(source),
        "priority": 500,
        "default_release": pin["suite"],
        "immutable": True,
        "freshness": {
            "mode": pin["release"]["freshness_mode"],
            "maximum_release_age_seconds": pin["release"]["maximum_release_age_seconds"],
        },
        "archive_binding": ARCHIVE_BINDING,
    }, separators=(",", ":")) + "\n")
    common = [
        "--install-root", str(workspace / "root"),
        "--cache-path", str(workspace / "cache"),
        "--state-path", str(workspace / "state"),
        "--architecture", architecture,
        "--config", str(config),
        "--keyring", str(KEYRING),
        "--deadline-ms", str(DEADLINE_MS),
        "--lock-wait-ms", "30000",
        "--json",
    ]
    native = [*common, "--transaction-backend", "native"]
    commands = [[str(debz), "refresh", *common, "--assume-yes"]]
    for request in REQUESTS:
        lock = str(evidence / f"{request}.lock.json")
        commands.append([str(debz), "plan", *native, "--lock-output", lock, request])
        commands.append([str(debz), "plan", *native, "--lock-input", lock,
                         "--lock-output", str(evidence / f"{request}.reproduced.lock.json"), request])
        commands.append([str(debz), "download", *native, "--lock-input", lock, request])
    names = ["refresh"] + [f"{step}-{request}" for request in REQUESTS for step in ("plan", "reproduce", "download")]
    for name, argv in zip(names, commands):
        run_debz(argv, evidence, name)

    if any((workspace / "root").iterdir()):
        raise ValueError("lock resolution or download mutated the empty root")
    base = f"{pin['snapshot_uri']}/dists/{pin['suite']}/"
    armored = readiness.fetch(base + "InRelease", readiness.MAX_RELEASE_BYTES)
    readiness.release_index(armored, pin, architecture, now)
    index = pin["architectures"][architecture]
    records = signed_records(readiness.fetch(base + index["index_path"], readiness.MAX_INDEX_BYTES), index)

    locks = {}
    union = {}
    repository = None
    for request in REQUESTS:
        path = evidence / f"{request}.lock.json"
        raw = path.read_bytes()
        if (evidence / f"{request}.reproduced.lock.json").read_bytes() != raw:
            raise ValueError(f"{request}: re-planning from the lock did not reproduce identical bytes")
        lock = json.loads(raw)
        count, total = review_lock(lock, pin, architecture, request)
        filenames = match_signed(lock, records)
        rows, _ = locate_objects(workspace / "cache", lock["packages"])
        for package, filename, row in zip(lock["packages"], filenames, rows):
            entry = {**row, "filename": filename}
            if union.setdefault(package["name"], entry) != entry:
                raise ValueError(f"{package['name']}: locks disagree about the archive")
        if request != REQUESTS[0] and lock["repositories"][0] != repository:
            raise ValueError(f"{request}: locks bind different repository evidence")
        repository = lock["repositories"][0]
        locks[request] = {
            "file_sha256": sha256(raw),
            "digest_sha256": lock["digest_sha256"],
            "request_sha256": lock["request_sha256"],
            "policy_sha256": lock["policy_sha256"],
            "packages": count,
            "total_bytes": total,
        }
    cas = [union[name] for name in sorted(union)]
    _, object_directory = locate_objects(
        workspace / "cache",
        [package for request in REQUESTS for package in json.loads((evidence / f"{request}.lock.json").read_text())["packages"]],
    )
    if sorted(path.name for path in object_directory.iterdir()) != sorted(row["object"].rsplit("/", 1)[1] for row in cas):
        raise ValueError("package cache contains objects outside the bound locks")

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "version": 1,
        "architecture": architecture,
        "repository": repository["id"],
        "packages": [
            {
                "name": row["package"],
                "version": row["version"],
                "architecture": row["architecture"],
                "filename": row["filename"],
                "size": row["size"],
                "sha256": row["sha256"],
                "sha512": row["derived_sha512"],
                "object": str(workspace / "cache" / row["object"]),
            }
            for row in cas
        ],
    }
    (evidence / "inventory-manifest.json").write_text(canonical(manifest))
    inventory_path = evidence / "inventory.json"
    result = subprocess.run(
        [str(inventory_tool), "inventory", str(evidence / "inventory-manifest.json"), str(inventory_path)],
        capture_output=True, text=True, timeout=1800, check=False,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError(f"native inventory failed (exit {result.returncode}): {result.stderr[:400]}")
    inventory = json.loads(inventory_path.read_text())
    if inventory["schema"] != INVENTORY_SCHEMA or [p["package"] for p in inventory["packages"]] != sorted(union):
        raise ValueError("native inventory does not cover exactly the bound closure")
    (evidence / "cas.json").write_text(canonical(cas))
    if any((workspace / "root").iterdir()):
        raise ValueError("inventory mutated the empty root")

    replacements = [(str(workspace), "$WORKSPACE"), (str(debz), "$DEBZ")]
    closure = {
        "architecture": architecture,
        "host_machine": platform.machine(),
        "program_sha256": sha256(debz.read_bytes()),
        "keyring": {"path": str(KEYRING), "sha256": sha256(key), "fingerprint": pin["signer"]["primary_fingerprint"]},
        "source_sha256": sha256(source.read_bytes()),
        "repository": {
            "id": repository["id"],
            "snapshot_sha256": repository["snapshot_sha256"],
            "release_sha256": repository["release_sha256"],
            "inrelease_sha256": sha256(armored),
            "index_sha256": index["index_sha256"],
            "archive_binding": ARCHIVE_BINDING,
        },
        "locks": locks,
        "cas_sha256": sha256(canonical(cas).encode()),
        "cas_objects": len(cas),
        "cas_bytes": sum(row["size"] for row in cas),
        "inventory_sha256": sha256(inventory_path.read_bytes()),
        "root_mutated": False,
        "commands": [template(argv, replacements) for argv in commands],
    }
    (evidence / "closure.json").write_text(canonical(closure))
    print(json.dumps({"workspace": str(workspace), **{k: closure[k] for k in ("locks", "cas_sha256", "inventory_sha256")}}, sort_keys=True))
    return 0


def load_run(workspace):
    evidence = pathlib.Path(workspace) / "evidence"
    closure = json.loads((evidence / "closure.json").read_text())
    return evidence, closure


def compare_runs(first, second):
    """Two clean runs must agree byte-for-byte on locks, CAS evidence, and inventory."""
    (left_dir, left), (right_dir, right) = load_run(first), load_run(second)
    if left != right:
        raise ValueError("run evidence differs between clean runs")
    for name in [f"{request}.lock.json" for request in REQUESTS] + ["cas.json", "inventory.json"]:
        if (left_dir / name).read_bytes() != (right_dir / name).read_bytes():
            raise ValueError(f"{name} differs between clean runs")
    return left


def aggregate_gaps(inventories):
    """Prioritized native gap list across architectures, derived only from inventories."""
    entries = {}
    for architecture, inventory in sorted(inventories.items()):
        for package in inventory["packages"]:
            for gap in package["gaps"]:
                entry = entries.setdefault(gap["category"], {
                    "priority": gap["priority"],
                    "category": gap["category"],
                    "native_status": CATEGORY_STATUS[gap["category"]],
                    "packages": {},
                    "evidence": set(),
                })
                if entry["priority"] != gap["priority"]:
                    raise ValueError(f"{gap['category']}: inconsistent priority")
                entry["packages"].setdefault(architecture, []).append(package["package"])
                entry["evidence"].update(f"{package['package']} {item}" for item in gap["evidence"])
    ordered = []
    for entry in sorted(entries.values(), key=lambda item: (item["priority"], item["category"])):
        ordered.append({
            **entry,
            "packages": {arch: sorted(names) for arch, names in sorted(entry["packages"].items())},
            "evidence": sorted(entry["evidence"]),
        })
    return ordered


def record(args):
    pin = load_pin()
    runs = {"amd64": args.amd64, "arm64": args.arm64}
    if EVIDENCE_DIR.exists():
        shutil.rmtree(EVIDENCE_DIR)
    EVIDENCE_DIR.mkdir()
    architectures = {}
    inventories = {}
    program = set()
    commands = None
    for architecture, workspaces in runs.items():
        closure = compare_runs(*workspaces)
        if closure["architecture"] != architecture:
            raise ValueError("run architecture mismatch")
        program.add(closure["program_sha256"])
        evidence = pathlib.Path(workspaces[0]) / "evidence"
        files = {}
        for request in REQUESTS:
            name = f"{architecture}-{request}.lock.json"
            shutil.copyfile(evidence / f"{request}.lock.json", EVIDENCE_DIR / name)
            files[request] = name
        inventory_name = f"{architecture}-inventory.json"
        shutil.copyfile(evidence / "inventory.json", EVIDENCE_DIR / inventory_name)
        inventories[architecture] = json.loads((evidence / "inventory.json").read_text())
        cas = json.loads((evidence / "cas.json").read_text())
        architectures[architecture] = {
            "source_sha256": closure["source_sha256"],
            "repository": closure["repository"],
            "locks": {request: {"path": files[request], **closure["locks"][request]} for request in REQUESTS},
            "runs": [pathlib.Path(workspace).name for workspace in workspaces],
            "cas_sha256": closure["cas_sha256"],
            "cas_objects": closure["cas_objects"],
            "cas_bytes": closure["cas_bytes"],
            "cas": [{key: row[key] for key in ("package", "version", "architecture", "filename", "size", "sha256", "derived_sha512", "mode")} for row in cas],
            "inventory": {"path": inventory_name, "sha256": closure["inventory_sha256"], "summary": inventories[architecture]["summary"]},
        }
        if commands is not None and commands != closure["commands"]:
            raise ValueError("architectures used different command templates")
        commands = closure["commands"]
    if len(program) != 1:
        raise ValueError("runs used different debz executables")
    expiry = release_expiry(pin)
    document = {
        "schema": EVIDENCE_SCHEMA,
        "issue": 261,
        "pin_sha256": sha256(PIN_PATH.read_bytes()),
        "requests": list(REQUESTS),
        "bounds": {"max_packages_per_lock": MAX_PACKAGES_PER_LOCK, "max_bytes_per_lock": MAX_BYTES_PER_LOCK},
        "program": {"sha256": program.pop(), "version": args.program_version, "optimize": "ReleaseSafe", "source_commit": args.source_commit},
        "host_machine": platform.machine(),
        "keyring": {"path": str(KEYRING), "sha256": load_pin()["signer"]["binary_sha256"], "fingerprint": pin["signer"]["primary_fingerprint"]},
        "freshness": {
            "release_date": pin["release"]["date"],
            "valid_until": pin["release"]["valid_until"],
            "mode": pin["release"]["freshness_mode"],
            "maximum_release_age_seconds": pin["release"]["maximum_release_age_seconds"],
            "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "recorded_on": args.recorded_on,
        },
        "commands": commands,
        "architectures": architectures,
        "gaps": aggregate_gaps(inventories),
    }
    (EVIDENCE_DIR / "evidence.json").write_text(canonical(document))
    print(json.dumps({"evidence": str(EVIDENCE_DIR / "evidence.json"), "gaps": len(document["gaps"])}))
    return 0


def check_evidence(directory=EVIDENCE_DIR):
    """Revalidates the committed evidence offline; used by tests."""
    pin = load_pin()
    document = json.loads((directory / "evidence.json").read_text())
    if document["schema"] != EVIDENCE_SCHEMA or document["pin_sha256"] != sha256(PIN_PATH.read_bytes()):
        raise ValueError("closure evidence is not bound to the reviewed pin")
    if document["requests"] != list(REQUESTS) or document["keyring"]["path"] != str(KEYRING):
        raise ValueError("closure evidence request or Signed-By path changed")
    if document["freshness"]["expires_at"] != release_expiry(pin).strftime("%Y-%m-%dT%H:%M:%SZ"):
        raise ValueError("closure evidence freshness expiry differs from the pin")
    inventories = {}
    for architecture in ARCHITECTURES:
        entry = document["architectures"][architecture]
        if entry["source_sha256"] != sha256(source_bytes(pin, architecture)):
            raise ValueError(f"{architecture}: recorded source differs from the reviewed deb822 source")
        if len(entry["runs"]) != 2 or len(set(entry["runs"])) != 2:
            raise ValueError("closure evidence requires two distinct clean runs")
        cas = {row["package"]: row for row in entry["cas"]}
        seen = set()
        for request in REQUESTS:
            item = entry["locks"][request]
            raw = (directory / item["path"]).read_bytes()
            if sha256(raw) != item["file_sha256"]:
                raise ValueError(f"{item['path']}: committed lock bytes changed")
            lock = json.loads(raw)
            if lock["digest_sha256"] != item["digest_sha256"]:
                raise ValueError(f"{item['path']}: lock digest changed")
            if review_lock(lock, pin, architecture, request) != (item["packages"], item["total_bytes"]):
                raise ValueError(f"{item['path']}: lock bounds changed")
            if lock["repositories"][0]["id"] != entry["repository"]["id"]:
                raise ValueError(f"{item['path']}: repository identity changed")
            for package in lock["packages"]:
                row = cas.get(package["name"])
                if (
                    row is None
                    or row["version"] != package["version"]
                    or row["size"] != package["declared_size"]
                    or row["sha256"] != package["archive_identity"]["digests"][0]["digest"]
                    or row["derived_sha512"] != package["derived_archive_identity"]["digest"]
                ):
                    raise ValueError(f"{package['name']}: CAS evidence differs from the lock")
                seen.add(package["name"])
        if seen != set(cas) or entry["cas_objects"] != len(cas) or entry["cas_bytes"] != sum(row["size"] for row in cas.values()):
            raise ValueError(f"{architecture}: CAS evidence is not exactly the lock union")
        raw = (directory / entry["inventory"]["path"]).read_bytes()
        if sha256(raw) != entry["inventory"]["sha256"]:
            raise ValueError(f"{architecture}: committed inventory bytes changed")
        inventory = json.loads(raw)
        if inventory["schema"] != INVENTORY_SCHEMA or [p["package"] for p in inventory["packages"]] != sorted(cas):
            raise ValueError(f"{architecture}: inventory does not cover exactly the CAS closure")
        for package in inventory["packages"]:
            row = cas[package["package"]]
            if (package["sha256"], package["derived_sha512"], package["size"]) != (row["sha256"], row["derived_sha512"], row["size"]):
                raise ValueError(f"{package['package']}: inventory identity differs from CAS evidence")
        if inventory["summary"] != entry["inventory"]["summary"]:
            raise ValueError(f"{architecture}: inventory summary changed")
        inventories[architecture] = inventory
    if aggregate_gaps(inventories) != document["gaps"]:
        raise ValueError("prioritized gap list is not derived from the committed inventories")
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--debz", type=pathlib.Path, required=True)
    run_parser.add_argument("--inventory", type=pathlib.Path, required=True)
    run_parser.add_argument("--architecture", choices=ARCHITECTURES, required=True)
    run_parser.add_argument("--workspace", type=pathlib.Path, required=True)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("first", type=pathlib.Path)
    compare_parser.add_argument("second", type=pathlib.Path)
    record_parser = commands.add_parser("record")
    record_parser.add_argument("--amd64", type=pathlib.Path, nargs=2, required=True)
    record_parser.add_argument("--arm64", type=pathlib.Path, nargs=2, required=True)
    record_parser.add_argument("--program-version", required=True)
    record_parser.add_argument("--source-commit", required=True)
    record_parser.add_argument("--recorded-on", required=True)
    commands.add_parser("check")
    args = parser.parse_args()
    if args.command == "run":
        return run(args, datetime.datetime.now(datetime.timezone.utc))
    if args.command == "compare":
        print(json.dumps(compare_runs(args.first, args.second)["locks"], sort_keys=True))
        return 0
    if args.command == "record":
        return record(args)
    check_evidence()
    print("debian-stable-closure: committed evidence verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PinExpired as error:
        print(f"debian-stable-closure: {error}", file=sys.stderr)
        sys.exit(PIN_EXPIRED_EXIT)
    except (ValueError, KeyError, OSError, UnicodeError, lzma.LZMAError, subprocess.TimeoutExpired) as error:
        print(f"debian-stable-closure: {error}", file=sys.stderr)
        sys.exit(2)
