"""Pinned-dpkg settlement specification and native differential corpus."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import time


PACKAGE = "diversion-lifecycle"
BASE = f"usr/share/{PACKAGE}"
CONFFILE = "etc/debz-native.conf"
LITERAL = "etc/diversion\\literal"
WATCHER = "diversion-watcher"
MEMBERS = {
    "regular": f"{BASE}/mode",
    "symlink": f"{BASE}/current",
    "hardlink-source": f"{BASE}/data",
    "hardlink-member": f"{BASE}/data.link",
    "conffile": CONFFILE,
    "directory": BASE,
    "obsolete": f"{BASE}/obsolete",
    "introduced": f"{BASE}/introduced",
}
CASES = (
    ("atomic", "regular"), ("unchanged", "regular"), ("inplace", "regular"),
    ("create", "regular"), ("empty", "regular"), ("remove", "regular"),
    ("cached-activation", "regular"), ("exempt", "regular"),
    ("atomic", "symlink"), ("atomic", "hardlink-source"),
    ("atomic", "hardlink-member"), ("atomic", "conffile"),
    ("atomic", "directory"), ("unwind-success", "regular"),
    ("rollback", "regular"), ("rollback", "symlink"),
    ("rollback", "hardlink-source"), ("postinst-failure", "regular"),
    ("atomic", "obsolete"), ("rollback", "obsolete"),
    ("atomic", "introduced"), ("rollback", "introduced"),
    ("rollback", "conffile"), ("postinst-failure", "conffile"),
)
SUCCESSFUL_POSTRM_CASES = tuple(
    case for case in CASES
    if case[0] not in ("unwind-success", "rollback", "postinst-failure")
)
SUCCESSFUL_UPGRADE_CASES = tuple(
    case for case in CASES
    if case[0] not in ("rollback", "postinst-failure")
)


def equal(actual, expected, label: str) -> None:
    if actual != expected:
        if isinstance(actual, dict) and isinstance(expected, dict):
            changed = [
                key for key in sorted(actual.keys() | expected.keys())
                if key not in actual or key not in expected or actual[key] != expected[key]
            ]
            details = [(key, expected.get(key), actual.get(key)) for key in changed[:4]]
            raise AssertionError(f"{label}: differing (key, expected, actual): {details!r}")
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def payload(version: str, epoch: int) -> dict[str, dict]:
    common = {"uid": 0, "gid": 0, "xattrs": []}
    files = {}
    for path, content, mode in (
        (f"{BASE}/data", f"data version {version}\n", "0644"),
        (f"{BASE}/data.link", f"data version {version}\n", "0644"),
        (f"{BASE}/mode", "permission-sensitive payload\n", "0600" if version == "1" else "0640"),
        (f"{BASE}/obsolete" if version == "1" else f"{BASE}/introduced", f"only in {version}\n", "0644"),
        (CONFFILE, f"configuration {version}\n", "0644"),
        (LITERAL, f"literal version {version}\n", "0644"),
    ):
        raw = content.encode()
        files[path] = {
            **common, "kind": "regular", "mode": mode, "mtime_ns": epoch * 10**9,
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "hardlink_to": f"{BASE}/data" if path in (f"{BASE}/data", f"{BASE}/data.link") else None,
        }
    files[f"{BASE}/current"] = {
        **common, "kind": "symlink", "mode": "0777",
        "mtime_ns": epoch * 10**9, "target": "data",
    }
    for path, mode in ((BASE, "0755"), (f"{BASE}/empty", "0750")):
        files[path] = {**common, "kind": "directory", "mode": mode}
    return files


def selected_files(snapshot: dict) -> dict[str, dict]:
    return {
        row["path"]: {key: value for key, value in row.items() if key != "path"}
        for row in snapshot["filesystem"]
        if row["path"] == BASE or row["path"].startswith((BASE + "/", BASE + ".", CONFFILE, LITERAL))
    }


def link_group(files: dict[str, dict], *paths: str) -> None:
    first = min(paths)
    for path in paths:
        files[path]["hardlink_to"] = first


def wall_clock(value: int, observation: dict, label: str) -> int:
    if not observation["started_ns"] <= value <= observation["finished_ns"]:
        raise AssertionError(f"{label}: recreated symlink did not use the invocation clock")
    return value


def expected_upgrade(observation: dict, epoch: int) -> dict[str, dict]:
    update, member = observation["case"]
    if (update, member) not in CASES:
        raise ValueError("unknown diversion settlement profile")
    source = MEMBERS[member]
    original = source if update == "create" else source + ".original"
    before, incoming = payload("1", epoch), payload("2", epoch)
    expected = payload("1" if update == "rollback" else "2", epoch)
    if member == "directory":
        expected[original] = copy.deepcopy(before[source])
    else:
        expected.pop(source, None)
        expected[original] = copy.deepcopy(
            before[source] if member in ("obsolete", "conffile") else incoming[source]
        )
    if member == "conffile":
        expected[original + ".dpkg-new"] = copy.deepcopy(incoming[source])
    elif member in ("regular", "symlink", "hardlink-source", "hardlink-member"):
        if update not in ("unchanged", "inplace"):
            expected[original + ".dpkg-tmp"] = copy.deepcopy(before[source])
            if member == "symlink":
                expected[original + ".dpkg-tmp"]["mtime_ns"] = wall_clock(
                    selected_files(observation["after"])[original + ".dpkg-tmp"]["mtime_ns"],
                    observation, "retained symlink backup",
                )
            elif member.startswith("hardlink-"):
                expected[original + ".dpkg-tmp"]["hardlink_to"] = None
        if member == "hardlink-source":
            if update == "rollback":
                expected[original]["hardlink_to"] = None
                link_group(expected, f"{BASE}/data.link", original + ".dpkg-tmp")
            else:
                link_group(expected, f"{BASE}/data.link", original)
        elif member == "hardlink-member":
            link_group(expected, f"{BASE}/data", original)
    if update == "rollback" and member != "symlink":
        path = f"{BASE}/current"
        expected[path]["mtime_ns"] = wall_clock(
            selected_files(observation["after"])[path]["mtime_ns"],
            observation, "restored symlink",
        )
    return expected


def calls(trace: str, architecture: str) -> list[tuple[str, list[str]]]:
    result = []
    for line in trace.splitlines():
        if line.startswith("backup-stat:"):
            continue
        fields = line.split("\t")
        count = int(fields[4])
        identity, package, kind, arch = fields[:4]
        equal(arch, architecture, "script architecture")
        equal(identity.split("@")[0], package, "script package")
        equal(identity.rsplit(":", 1)[1], kind, "script kind")
        equal(len(fields), count + 6, "script trace width")
        arguments = []
        for field in fields[5:5 + count]:
            length, value = field.split(":", 1)
            equal(int(length), len(value), "script argument length")
            arguments.append(value)
        result.append((identity, arguments))
    return result


def expected_calls(update: str, member: str, *, reinstall: bool = False) -> list[tuple[str, list[str]]]:
    source = MEMBERS[member]
    old = "2" if reinstall else "1"
    result = [
        (f"{PACKAGE}@{old}:prerm", ["upgrade", "2"]),
        (f"{PACKAGE}@2:preinst", ["upgrade", old, "2"]),
        (f"{PACKAGE}@{old}:postrm", ["upgrade", "2"]),
    ]
    if not reinstall and update in ("unwind-success", "rollback"):
        result.append((f"{PACKAGE}@2:postrm", ["failed-upgrade", "1", "2"]))
    if not reinstall and update == "rollback":
        result += [
            (f"{PACKAGE}@1:preinst", ["abort-upgrade", "2"]),
            (f"{PACKAGE}@2:postrm", ["abort-upgrade", "1", "2"]),
            (f"{PACKAGE}@1:postinst", ["abort-upgrade", "2"]),
        ]
    else:
        result.append((f"{PACKAGE}@2:postinst", ["configure", old]))
    if member != "obsolete":
        route = current_route(update, source) if reinstall else source if update == "create" else source + ".original"
        names = f"/{source} /{route}" if member == "directory" and not reinstall else f"/{route}"
        result.append((f"{WATCHER}@1:postinst", ["triggered", names]))
    return result


def current_route(update: str, source: str) -> str:
    if update == "unchanged":
        return source + ".original"
    return source if update in ("empty", "remove", "exempt") else source + ".changed"


def route_settlement_profile(update: str, member: str) -> dict:
    if (update, member) not in CASES:
        raise ValueError("unknown diversion settlement profile")
    source = MEMBERS[member]
    payload_route = source if update == "create" else source + ".original"
    post_script_route = (
        source + ".original"
        if update in ("unchanged", "inplace")
        else current_route(update, source)
    )
    changed = payload_route != post_script_route
    if member in ("regular", "symlink", "hardlink-source", "hardlink-member"):
        backup = "retain" if changed else "discard"
    else:
        backup = "none"
    staging = "retain" if member == "conffile" and changed else "absent"
    if member == "obsolete":
        ownership, triggers, removal = "previous", [], "post_script"
    elif member == "introduced":
        ownership, triggers, removal = "resulting", [f"/{payload_route}"], None
    elif member == "directory":
        ownership = "previous_and_resulting"
        triggers, removal = [f"/{source}", f"/{payload_route}"], None
    else:
        ownership = "previous_and_resulting"
        triggers, removal = [f"/{payload_route}"], None
    conffile_version = "1" if member == "conffile" and changed else "2"
    if update == "rollback":
        outcome = "rollback"
    elif update == "unwind-success":
        outcome = "unwind_succeeded"
    elif update == "postinst-failure":
        outcome = "postinst_failed"
    else:
        outcome = "postrm_succeeded"
    if outcome == "rollback":
        if member == "conffile":
            partial = "retain_conffile_staging"
        elif ownership == "previous":
            partial = "restore_previous"
        else:
            partial = "retain_incoming"
    else:
        partial = None
    return {
        "update": update,
        "member": member,
        "payload_route": payload_route,
        "post_script_route": post_script_route,
        "backup": backup,
        "staging": staging,
        "ownership": ownership,
        "trigger_paths": triggers,
        "removal_route": removal,
        "recorded_md5": hashlib.md5(
            f"configuration {conffile_version}\n".encode()
        ).hexdigest(),
        "outcome": outcome,
        "publish_settlement": outcome != "rollback",
        "partial_disposition": partial,
    }


def successful_route_profile(update: str, member: str) -> dict:
    if (update, member) not in SUCCESSFUL_POSTRM_CASES:
        raise ValueError("profile is not a successful old-postrm transition")
    profile = route_settlement_profile(update, member)
    return {
        key: value for key, value in profile.items()
        if key not in ("outcome", "publish_settlement", "partial_disposition")
    }


def diversion_bytes(update: str, source: str) -> str | None:
    if update == "remove":
        return None
    if update == "empty":
        return ""
    destination = source + (".original" if update in ("unchanged", "exempt") else ".changed")
    owner = PACKAGE if update == "exempt" else ":"
    return f"/{source}\n/{destination}\n{owner}\n"


def diversion_state(root: Path) -> dict | None:
    path = root / "var/lib/dpkg/diversions"
    if path.is_symlink():
        raise AssertionError("reference diversion database became a symlink")
    if not path.exists():
        return None
    observed = path.stat()
    return {"device": observed.st_dev, "inode": observed.st_ino, "bytes": path.read_text()}


def assert_diversions(observation: dict, *, reinstall: bool = False) -> None:
    update, member = observation["case"]
    after = observation["diversions"]
    equal(None if after is None else after["bytes"], diversion_bytes(update, MEMBERS[member]), "live diversion bytes")
    if reinstall:
        return
    before = observation["before_diversions"]
    equal(before is None, update == "create", "initial diversion presence")
    if before is not None and after is not None:
        same_inode = (before["device"], before["inode"]) == (after["device"], after["inode"])
        equal(same_inode, update == "inplace", "diversion database identity")


def assert_database(observation: dict, version: str, conffile_version: str, state: str, controls: dict) -> None:
    statuses = [row for row in observation["after"]["dpkg"]["status"] if row["package"] == PACKAGE]
    equal(len(statuses), 1, "package status count")
    status = statuses[0]
    equal(status["version"], version, "package version")
    equal(status["status"], f"install ok {state}", "package status")
    digest = hashlib.md5(f"configuration {conffile_version}\n".encode()).hexdigest()
    equal(status["conffiles"], f"\n/{CONFFILE} {digest}", "recorded conffile digest")
    expected_list = sorted(["/.", "/etc", "/usr", "/usr/share", *("/" + path for path in payload(version, 0))])
    equal(sorted(observation["list"].splitlines()), expected_list, "logical installed file list")
    equal(observation["controls"], controls[version], "installed control bytes")


def assert_backups(observation: dict, epoch: int) -> None:
    update, member = observation["case"]
    source = MEMBERS[member]
    old = payload("1", epoch)
    expected = {
        "/" + (path + ".original" if path == source and update != "create" else path) + ".dpkg-tmp": row
        for path, row in old.items()
        if path in payload("2", epoch) and path != CONFFILE and row["kind"] != "directory"
    }
    lines = observation["trace"].splitlines()
    primary = next(i for i, line in enumerate(lines) if line.startswith(f"{PACKAGE}@1:postrm\t"))
    observed = {}
    for line in lines[primary + 1:]:
        if not line.startswith("backup-stat:"):
            break
        _, path, mode, uid, gid, seconds, inode = line.split(":")
        if path in observed:
            raise AssertionError("duplicate visible backup")
        observed[path] = (mode, int(uid), int(gid), int(seconds), int(inode))
    equal(set(observed), set(expected), "old postrm visible backups")
    for path, row in expected.items():
        mode, uid, gid, seconds, inode = observed[path]
        equal((mode, uid, gid), (row["mode"].lstrip("0"), row["uid"], row["gid"]), "visible backup metadata")
        original_inode = observation["before_inodes"][path[1:].removesuffix(".dpkg-tmp")]
        if row["kind"] == "regular":
            equal(seconds, epoch, "regular backup timestamp")
            equal(inode, original_inode, "regular backup inode")
        else:
            if not observation["started_ns"] // 10**9 <= seconds <= observation["finished_ns"] // 10**9:
                raise AssertionError("visible symlink backup timestamp")
            if inode == original_inode:
                raise AssertionError("symlink backup was not recreated")


def assert_upgrade(observation: dict, epoch: int, architecture: str, controls: dict) -> None:
    update, member = observation["case"]
    equal(observation["exit"], int(update in ("rollback", "postinst-failure")), "upgrade exit")
    equal(selected_files(observation["after"]), expected_upgrade(observation, epoch), "settled filesystem")
    equal(calls(observation["trace"], architecture), expected_calls(update, member), "upgrade script order and trigger routes")
    assert_diversions(observation)
    assert_backups(observation, epoch)
    assert_database(
        observation, "1" if update == "rollback" else "2",
        "1" if update == "rollback" or member == "conffile" else "2",
        "half-configured" if update == "postinst-failure" else "installed", controls,
    )


def assert_reinstall(upgrade: dict, observation: dict, epoch: int, architecture: str, controls: dict) -> None:
    update, member = upgrade["case"]
    if upgrade["exit"] != 0:
        raise ValueError("subsequent invocation requires a successful upgrade")
    expected = expected_upgrade(upgrade, epoch)
    incoming = payload("2", epoch)
    source = MEMBERS[member]
    route = current_route(update, source)
    if member == "conffile":
        incoming[route + ".dpkg-dist"] = incoming.pop(source)
    elif member != "obsolete":
        incoming[route] = copy.deepcopy(incoming[source])
        if member != "directory" and source != route:
            del incoming[source]
    expected.update(incoming)
    for row in expected.values():
        if row["kind"] == "regular":
            row["hardlink_to"] = None
    link_group(
        expected,
        route if member == "hardlink-source" else f"{BASE}/data",
        route if member == "hardlink-member" else f"{BASE}/data.link",
    )
    equal(observation["exit"], 0, "subsequent invocation exit")
    equal(selected_files(observation["after"]), expected, "subsequent invocation filesystem")
    equal(calls(observation["trace"], architecture), expected_calls(update, member, reinstall=True), "subsequent script order and trigger routes")
    assert_diversions(observation, reinstall=True)
    assert_database(observation, "2", "2", "installed", controls)


def exercise(
    lifecycle,
    reference,
    workspace: Path,
    environment: dict[str, str],
    architecture: str,
    *,
    executable: Path | None = None,
    helper: Path | None = None,
    native_runner=None,
) -> None:
    m = lifecycle.m
    differential = executable is not None
    if differential != (helper is not None and native_runner is not None):
        raise ValueError("native settlement execution requires executable, helper, and runner")
    workspace = workspace / (
        "diversion-settlement-differential"
        if differential else "diversion-settlement-reference"
    )
    workspace.mkdir()
    probes = [
        "/" + path + suffix + ".dpkg-tmp"
        for path in (*MEMBERS.values(), LITERAL)
        for suffix in ("", ".original", ".changed")
    ]
    probe = f"""
if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ]; then
    for backup in {" ".join(shlex.quote(path) for path in probes)}; do
        if [ -L "$backup" ] || [ -f "$backup" ] || [ -d "$backup" ]; then
            /diversion-stat --printf='backup-stat:%n:%a:%u:%g:%Y:%i\\n' "$backup" >> /{lifecycle.TRACE} || exit 30
        fi
    done
    if [ -f /diversion-remove-record ]; then
        /diversion-remove -f /var/lib/dpkg/diversions || exit 29
    fi
fi
""".encode()
    archives, controls = {}, {}
    for version in ("1", "2"):
        scripts = lifecycle.diversion_scripts(PACKAGE, version)
        scripts["postrm"] = scripts["postrm"].replace(b'replacement="/diversion-', probe + b'replacement="/diversion-', 1)
        archives[version] = m.make_package(
            workspace / "packages", environment, architecture, version, "conffile",
            package=PACKAGE, scripts=scripts, conffile_content=f"configuration {version}\n".encode(),
            extra_files={LITERAL: f"literal version {version}\n".encode()},
        )
        control = archives[version].with_suffix(".source") / "DEBIAN"
        controls[version] = {
            name: hashlib.sha256((control / name).read_bytes()).hexdigest()
            for name in (*lifecycle.KINDS, "md5sums", "conffiles")
        }
    for update, member in CASES:
        directory = workspace / f"{update}-{member}"
        expected = directory / "reference"
        candidate = directory / "native"
        roots = (expected, candidate) if differential else (expected,)
        source = MEMBERS[member]
        original = lifecycle.diversion_records(source, source + ".original")
        changed = lifecycle.diversion_records(source, source + ".changed")
        receiver = m.make_package(
            directory / "receiver", environment, architecture, "1", package=WATCHER,
            scripts=lifecycle.scripts(WATCHER, "1"),
            triggers="".join(f"interest-noawait /{source}{suffix}\n" for suffix in ("", ".original", ".changed")).encode(),
        )
        failures = []
        if update in ("unwind-success", "rollback"):
            failures.append(f"{PACKAGE}@1:postrm:upgrade")
        if update == "rollback":
            failures.append(f"{PACKAGE}@2:postrm:failed-upgrade")
        if update == "postinst-failure":
            failures.append(f"{PACKAGE}@2:postinst:configure")
        for root in roots:
            m.make_root(root, architecture)
            m.write(root / lifecycle.TRACE, b"")
            for source_executable, destination in (
                ("/bin/sh", "/bin/sh"),
                ("/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger"),
                ("/usr/bin/stat", "/diversion-stat"),
            ):
                lifecycle.runtime.copy_program(
                    root, Path(source_executable), destination,
                )
            if member == "directory":
                (root / BASE).mkdir(parents=True)
                os.utime(root / BASE, (m.EPOCH, m.EPOCH))
            if update != "create":
                lifecycle.seed_diversions(root, original)
            seed = directory / f"seed-{root.name}"
            seed.mkdir()
            equal(
                reference(
                    root, "install", [receiver, archives["1"]], [],
                    environment, seed,
                ),
                0,
                f"{root.name} seed",
            )
            m.write(root / lifecycle.TRACE, b"")
            if update == "inplace":
                lifecycle.seed_diversion_inplace(root, "postrm", changed)
            elif update == "remove":
                lifecycle.runtime.copy_program(
                    root, Path("/usr/bin/rm"), "/diversion-remove",
                )
                m.write(root / "diversion-remove-record", b"")
            else:
                replacement = original if update == "unchanged" else changed
                if update == "cached-activation":
                    lifecycle.seed_diversion_inplace(root, "preinst", changed)
                elif update == "empty":
                    replacement = b""
                elif update == "exempt":
                    replacement = lifecycle.diversion_records(
                        source, source + ".original", PACKAGE,
                    )
                lifecycle.seed_diversion_replacement(
                    root, "postrm", replacement,
                )
            if failures:
                m.write(
                    root / lifecycle.FAILURE,
                    ("\n".join(failures) + "\n").encode(),
                )
        if differential:
            (candidate / "usr/bin/dpkg-trigger").write_bytes(helper.read_bytes())
            (candidate / "usr/bin/dpkg-trigger").chmod(0o755)

        def observe(root: Path, result: int, before: dict, before_inodes: dict, before_diversions: dict | None, started: int, finished: int) -> dict:
            return {
                "case": [update, member], "exit": result, "before": before,
                "before_inodes": before_inodes, "after": m.snapshot(root),
                "before_diversions": before_diversions,
                "diversions": diversion_state(root),
                "started_ns": started, "finished_ns": finished,
                "trace": (root / lifecycle.TRACE).read_text(),
                "list": (root / f"var/lib/dpkg/info/{PACKAGE}.list").read_text(),
                "controls": {
                    name: hashlib.sha256(
                        (root / f"var/lib/dpkg/info/{PACKAGE}.{name}").read_bytes()
                    ).hexdigest()
                    for name in controls["1"]
                },
            }

        def comparison_snapshot(root: Path) -> dict:
            snapshot = m.oracle.capture(
                root,
                excludes=(
                    *m.oracle.DEFAULT_EXCLUDES,
                    m.GUARD,
                    "usr/bin/dpkg-trigger",
                    lifecycle.TRACE,
                ),
            )
            snapshot.pop("trace", None)
            for entry in snapshot["filesystem"]:
                if entry["path"] in (
                    "diversion-remove-record",
                    lifecycle.FAILURE,
                ):
                    entry["mtime_ns"] = "fixture-clock"
                if (
                    entry["kind"] == "symlink"
                    and entry.get("mtime_ns") != m.EPOCH * 10**9
                ):
                    entry["mtime_ns"] = "invocation-clock"
            return snapshot

        upgrade = None
        candidate_upgrade = None
        for operation in ("upgrade", "reinstall"):
            destination = directory / operation
            destination.mkdir()
            expected_before = m.snapshot(expected)
            expected_inodes = {
                path: os.lstat(expected / path).st_ino
                for path in selected_files(expected_before)
            }
            expected_diversions = diversion_state(expected)
            started = time.time_ns()
            reference_result = reference(
                expected, operation, [archives["2"]], [], environment,
                destination, policy="keep_existing",
            )
            finished = time.time_ns()
            observation = observe(
                expected, reference_result, expected_before, expected_inodes,
                expected_diversions, started, finished,
            )
            m.write(
                destination / "reference.observations.json",
                json.dumps(observation, indent=2).encode(),
            )
            if operation == "upgrade":
                assert_upgrade(observation, m.EPOCH, architecture, controls)
                upgrade = observation
            else:
                assert_reinstall(upgrade, observation, m.EPOCH, architecture, controls)
            if differential:
                candidate_before = m.snapshot(candidate)
                candidate_inodes = {
                    path: os.lstat(candidate / path).st_ino
                    for path in selected_files(candidate_before)
                }
                candidate_diversions = diversion_state(candidate)
                native_started = time.time_ns()
                report = native_runner(
                    executable, candidate, architecture, operation,
                    [archives["2"]], [], environment, destination,
                    policy="keep_existing", recovery=True,
                )
                native_finished = time.time_ns()
                expected_outcomes = (
                    ("script_failed",)
                    if reference_result else
                    ("applied",)
                )
                if report["outcome"] not in expected_outcomes:
                    raise AssertionError(
                        f"{update}-{member}/{operation}: unexpected native result: {report}"
                    )
                candidate_observation = observe(
                    candidate,
                    0 if report["outcome"] == "applied" else 1,
                    candidate_before,
                    candidate_inodes,
                    candidate_diversions,
                    native_started,
                    native_finished,
                )
                m.write(
                    destination / "native.observations.json",
                    json.dumps(candidate_observation, indent=2).encode(),
                )
                if operation == "upgrade":
                    assert_upgrade(
                        candidate_observation, m.EPOCH, architecture, controls,
                    )
                    candidate_upgrade = candidate_observation
                else:
                    assert_reinstall(
                        candidate_upgrade, candidate_observation, m.EPOCH,
                        architecture, controls,
                    )
                equal(
                    calls(candidate_observation["trace"], architecture),
                    calls(observation["trace"], architecture),
                    f"{update}-{member}/{operation} native/reference script and trigger trace",
                )
                equal(
                    sorted(candidate_observation["list"].splitlines()),
                    sorted(observation["list"].splitlines()),
                    f"{update}-{member}/{operation} native/reference file list",
                )
                equal(
                    candidate_observation["controls"],
                    observation["controls"],
                    f"{update}-{member}/{operation} native/reference controls",
                )
                mismatches = m.oracle.differences(
                    comparison_snapshot(expected),
                    comparison_snapshot(candidate),
                    maximum=30,
                )
                if mismatches:
                    raise AssertionError(
                        "native/dpkg diversion settlement mismatch:\n"
                        + "\n".join(mismatches)
                    )
                print(
                    f"native/dpkg diversion settlement {update}-{member}/{operation}: exact outcome passed",
                    flush=True,
                )
            else:
                print(
                    f"reference-only diversion settlement {update}-{member}/{operation}: exact outcome passed",
                    flush=True,
                )
            if reference_result:
                break
            for root in roots:
                m.write(root / lifecycle.TRACE, b"")
