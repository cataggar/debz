"""Unit coverage for the pure logic of tools/real-snapshot-repin.py.

These tests use synthetic fixtures only and never touch the network. The
end-to-end probe through a real debz binary is in test/real-snapshot-repin.zig.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("debz_real_snapshot_repin", ROOT / "tools/real-snapshot-repin.py")
assert SPEC and SPEC.loader
repin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repin)

DAY = 86400
T0 = "20260920T000000Z"
T1 = "20260927T000000Z"
SIGNER = "0123456789abcdef0123456789abcdef01234567"
SCRIPT = b"#!/bin/sh\nset -e\n# configure\ntrue\n"
TOOL = b"\x7fELF synthetic tool\n"


def sha256(data: bytes) -> str:
    return repin.tagged("sha256", data)


def sha512(data: bytes) -> str:
    return repin.tagged("sha512", data)


def profile(pockets=None) -> dict:
    return {
        "name": "synthetic",
        "uri_root": "file:///synthetic/snapshot",
        "component": "main",
        "architectures": ["amd64"],
        "keyring": "/synthetic/keyring.gpg",
        "signer": SIGNER,
        "request": "synthetic-minimal",
        "pockets": pockets or [{"suite": "stable", "role": "bounded"}],
    }


def identity(**overrides) -> dict:
    value = {
        "id": "script:alpha/postinst",
        "kind": "script",
        "package": "alpha",
        "architectures": ["amd64"],
        "path": "postinst",
        "digest": sha256(SCRIPT),
        "size": len(SCRIPT),
        "mode": "0755",
        "version_bound": "1.0",
        "provenance": "pending",
        "consumers": [{"path": "pins.txt", "form": "hex"}],
        "review": "#1",
    }
    value.update(overrides)
    return value


def manifest(identities=None, pockets=None, snapshot=None) -> dict:
    return {
        "schema": repin.MANIFEST_SCHEMA,
        "series": profile(pockets),
        "snapshot": snapshot or {"timestamp": T0, "status": "pending"},
        "uri_consumers": [],
        "identities": [identity()] if identities is None else identities,
        "excluded": [],
    }


def observed(digest=None, size=None, mode="0755", version="1.0", archive=None, derived=None, member=None) -> dict:
    value = {
        "version": version,
        "archive": archive or sha512(version.encode()),
        "derived_versions": derived or {},
        "digest": sha256(SCRIPT) if digest is None else digest,
        "size": len(SCRIPT) if size is None else size,
        "mode": mode,
    }
    if member is not None:
        value["member_file"] = member
    return value


def pocket(suite="stable", role="bounded", release=b"release", binding="exact_lock") -> dict:
    return {
        "binding": {"amd64": binding},
        "suite": suite,
        "role": role,
        "date": "Sun, 26 Sep 2026 23:00:00 UTC",
        "date_unix": repin.timestamp_seconds(T1) - 3600,
        "valid_until": None,
        "valid_until_unix": None,
        "hash_fields": ["SHA256", "SHA512"],
        "in_release_sha256": sha256(b"in" + release),
        "in_release_sha512": sha512(b"in" + release),
        "release_sha256": sha256(release),
        "signers": [SIGNER],
        "deadline": repin.timestamp_seconds(T1) + 30 * DAY,
    }


def report(identities: dict, pockets=None, timestamp=T1, closure=None) -> dict:
    packages = closure or {"alpha": {"version": "1.0", "architecture": "amd64", "archive": sha512(b"1.0"), "pocket": "stable"}}
    return {
        "schema": repin.REPORT_SCHEMA,
        "series": profile([{"suite": p["suite"], "role": p["role"]} for p in pockets] if pockets else None),
        "timestamp": timestamp,
        "pockets": pockets or [pocket()],
        "admission_deadline": repin.timestamp_seconds(timestamp) + 30 * DAY,
        "closures": {
            "amd64": {
                "digest": repin.closure_digest(packages),
                "package_count": len(packages),
                "pockets": {"stable": len(packages)},
                "packages": packages,
            }
        },
        "identities": identities,
    }


def deb(control: dict[str, tuple[bytes, int]], data: dict[str, tuple[bytes, int]], compress=True) -> bytes:
    def tar(members: dict[str, tuple[bytes, int]]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, (content, mode) in members.items():
                info = tarfile.TarInfo("./" + name)
                info.size = len(content)
                info.mode = mode
                archive.addfile(info, io.BytesIO(content))
        return stream.getvalue()

    def member(name: str, content: bytes) -> bytes:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(content):<10}".encode() + b"`\n"
        return header + content + (b"\n" if len(content) % 2 else b"")

    control_tar, data_tar = tar(control), tar(data)
    suffix = ".gz" if compress else ""
    if compress:
        control_tar, data_tar = gzip.compress(control_tar), gzip.compress(data_tar)
    return (
        b"!<arch>\n"
        + member("debian-binary", b"2.0\n")
        + member("control.tar" + suffix, control_tar)
        + member("data.tar" + suffix, data_tar)
    )


class TimeTests(unittest.TestCase):
    def test_recent_snapshot_is_refused(self) -> None:
        now = repin.timestamp_seconds(T1) + DAY - 1
        with self.assertRaisesRegex(repin.RepinError, "less than 24 hours old"):
            repin.validate_timestamp(T1, now, None)
        self.assertEqual(repin.validate_timestamp(T1, now + 1, None), repin.timestamp_seconds(T1))

    def test_snapshot_older_than_the_pin_is_refused(self) -> None:
        now = repin.timestamp_seconds(T1) + 10 * DAY
        with self.assertRaisesRegex(repin.RepinError, "older than the current pin"):
            repin.validate_timestamp(T0, now, T1)
        repin.validate_timestamp(T1, now, T1)

    def test_malformed_timestamps_are_refused(self) -> None:
        for text in ("20260927", "20260927T000000", "20261332T000000Z", "2026-09-27T00:00:00Z"):
            with self.assertRaises(repin.RepinError):
                repin.timestamp_seconds(text)

    def test_default_timestamp_is_the_newest_settled_day(self) -> None:
        now = repin.timestamp_seconds("20260928T153000Z")
        self.assertEqual(repin.default_timestamp(now), T1)
        repin.validate_timestamp(repin.default_timestamp(now), now, None)


class ReleaseTests(unittest.TestCase):
    def test_cleartext_removes_dash_escapes_and_keeps_line_endings(self) -> None:
        data = (
            b"-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA512\r\n\r\n"
            b"Suite: stable\r\n- -escaped\r\nDate: x\r\n"
            b"-----BEGIN PGP SIGNATURE-----\r\n\r\nwgA=\r\n-----END PGP SIGNATURE-----\r\n"
        )
        self.assertEqual(repin.in_release_cleartext(data), b"Suite: stable\r\n-escaped\r\nDate: x\r\n")

    def test_malformed_cleartext_is_refused(self) -> None:
        header = b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        for data, message in (
            (b"Suite: stable\n", "cleartext signature header"),
            (header + b"Suite: stable\n", "no signature block"),
            (header + b"-bad\n-----BEGIN PGP SIGNATURE-----\n", "invalid dash escape"),
            (b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n", "no blank line"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(repin.RepinError, message):
                repin.in_release_cleartext(data)

    def test_release_fields_parse_dates_and_hash_fields(self) -> None:
        fields = repin.release_fields(
            b"Origin: Ubuntu\nSuite: stable\nCodename: stable\nDate: Sun, 26 Sep 2026 23:00:00 UTC\n"
            b"Valid-Until: Sun, 03 Oct 2026 23:00:00 UTC\nSHA256:\n abc 1 main/Packages\n"
        )
        self.assertEqual(fields["date_unix"], repin.timestamp_seconds(T1) - 3600)
        self.assertEqual(fields["valid_until_unix"], repin.timestamp_seconds(T1) - 3600 + 7 * DAY)
        self.assertEqual(fields["hash_fields"], ["SHA256"])
        with self.assertRaisesRegex(repin.RepinError, "RFC 2822 UTC"):
            repin.release_fields(b"Suite: stable\nDate: Sun, 26 Sep 2026 23:00:00 +0200\n")
        with self.assertRaisesRegex(repin.RepinError, "no Date"):
            repin.release_fields(b"Suite: stable\n")
        with self.assertRaisesRegex(repin.RepinError, "duplicate"):
            repin.release_fields(b"Date: Sun, 26 Sep 2026 23:00:00 UTC\nDate: Sun, 26 Sep 2026 23:00:00 UTC\n")


class DateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = repin.timestamp_seconds(T1)

    def pockets(self) -> list[dict]:
        frozen = {"suite": "r", "role": "frozen", "date": "f", "date_unix": self.snapshot - 180 * DAY,
                  "valid_until": None, "valid_until_unix": None}
        updates = {"suite": "r-updates", "role": "witness", "date": "u", "date_unix": self.snapshot - 3600,
                   "valid_until": None, "valid_until_unix": None}
        security = {"suite": "r-security", "role": "witness", "date": "s", "date_unix": self.snapshot - 7200,
                    "valid_until": "v", "valid_until_unix": self.snapshot + 5 * DAY}
        return [frozen, updates, security]

    def test_frozen_deadline_is_the_earliest_witness_deadline(self) -> None:
        pockets = self.pockets()
        deadline = repin.check_pocket_dates(pockets, self.snapshot)
        self.assertEqual(pockets[0]["deadline"], self.snapshot + 5 * DAY)
        self.assertEqual(pockets[1]["deadline"], self.snapshot - 3600 + repin.MAXIMUM_RELEASE_AGE_SECONDS)
        self.assertEqual(deadline, self.snapshot + 5 * DAY)

    def test_date_after_the_snapshot_is_refused(self) -> None:
        pockets = self.pockets()
        pockets[1]["date_unix"] = self.snapshot + 1
        with self.assertRaisesRegex(repin.RepinError, "after the snapshot time"):
            repin.check_pocket_dates(pockets, self.snapshot)

    def test_stale_witness_is_refused(self) -> None:
        pockets = self.pockets()
        pockets[2]["date_unix"] = self.snapshot - repin.WITNESS_WINDOW_SECONDS - 1
        with self.assertRaisesRegex(repin.RepinError, "more than 48 hours"):
            repin.check_pocket_dates(pockets, self.snapshot)

    def test_frozen_pocket_with_valid_until_is_refused(self) -> None:
        pockets = self.pockets()
        pockets[0]["valid_until"] = "x"
        with self.assertRaisesRegex(repin.RepinError, "frozen pocket r carries Valid-Until"):
            repin.check_pocket_dates(pockets, self.snapshot)

    def test_frozen_pocket_without_witness_is_refused(self) -> None:
        with self.assertRaisesRegex(repin.RepinError, "requires at least one witness"):
            repin.check_pocket_dates(self.pockets()[:1], self.snapshot)


class ManifestTests(unittest.TestCase):
    def test_strict_fields_and_tagged_digests(self) -> None:
        repin.validate_manifest(manifest())
        for mutate, message in (
            (lambda m: m.update(extra=1), "unknown"),
            (lambda m: m["identities"][0].update(digest=SCRIPT.hex()), "algorithm-tagged"),
            (lambda m: m["identities"][0].update(digest=sha512(SCRIPT)), "members bind SHA-256"),
            (lambda m: m["identities"][0].update(consumers=[]), "no consumer"),
            (lambda m: m["identities"][0].update(review="PR 1"), "review"),
            (lambda m: m["identities"].append(copy.deepcopy(m["identities"][0])), "duplicate identity"),
            (lambda m: m["identities"][0].update(derived_from=[]), "prestate"),
            (lambda m: m["snapshot"].update(pockets=[]), "pending snapshot records only"),
            (lambda m: m["series"]["pockets"].append({"suite": "x", "role": "frozen"}), "frozen pocket with witness"),
        ):
            value = manifest()
            mutate(value)
            with self.subTest(message=message), self.assertRaisesRegex(repin.RepinError, message):
                repin.validate_manifest(value)

    def test_built_in_profiles_cannot_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            replacement = profile()
            replacement["name"] = "ubuntu-stonking"
            path.write_text(json.dumps(replacement), encoding="utf-8")
            with self.assertRaisesRegex(repin.RepinError, "cannot be replaced"):
                repin.resolve_profile("ubuntu-stonking", path)
        self.assertEqual(repin.resolve_profile("ubuntu-resolute", None)["pockets"][0]["role"], "frozen")

    def test_committed_manifest_checks_against_the_tree(self) -> None:
        committed = repin.validate_manifest(repin.load_json(ROOT / repin.DEFAULT_MANIFEST))
        self.assertEqual(repin.check_manifest(committed, ROOT), [])


class StatusTests(unittest.TestCase):
    def test_statuses(self) -> None:
        base = identity()
        self.assertEqual(repin.identity_status(base, {"amd64": observed()})[0], "provenance-only")
        recorded = dict(base, provenance={"version": "1.0", "archives": {"amd64": sha512(b"1.0")}})
        self.assertEqual(repin.identity_status(recorded, {"amd64": observed()})[0], "unchanged")
        rebuilt = observed(archive=sha512(b"rebuild"))
        self.assertEqual(repin.identity_status(recorded, {"amd64": rebuilt})[0], "provenance-only")
        self.assertEqual(repin.identity_status(recorded, {"amd64": observed(digest=sha256(b"x"))})[0], "changed")
        self.assertEqual(repin.identity_status(recorded, {"amd64": observed(mode="0644")})[0], "changed")
        self.assertEqual(repin.identity_status(recorded, {"amd64": observed(version="1.1")})[0], "changed")
        self.assertEqual(repin.identity_status(recorded, {"amd64": None})[0], "missing")
        self.assertEqual(repin.identity_status(recorded, {})[0], "missing")

    def test_unbound_version_change_with_same_bytes_is_provenance_only(self) -> None:
        unbound = identity(version_bound=None, provenance={"version": "1.0", "archives": {"amd64": sha512(b"1.0")}})
        status, reasons = repin.identity_status(unbound, {"amd64": observed(version="1.1")})
        self.assertEqual(status, "provenance-only")
        self.assertIn("archive", reasons[0])

    def test_prestate_changes_with_any_source_version(self) -> None:
        prestate = identity(
            id="prestate:alpha/var/lib/dpkg/info/alpha.list", kind="prestate",
            path="var/lib/dpkg/info/alpha.list", mode=None,
            derived_from=[{"package": "alpha", "version": "1.0"}, {"package": "beta", "version": "2.0"}],
        )
        same = observed(derived={"alpha": "1.0", "beta": "2.0"})
        self.assertEqual(repin.identity_status(prestate, {"amd64": same})[0], "provenance-only")
        moved = observed(derived={"alpha": "1.0", "beta": "2.1"})
        status, reasons = repin.identity_status(prestate, {"amd64": moved})
        self.assertEqual(status, "changed")
        self.assertIn("beta 2.0 -> 2.1", reasons[0])

    def test_advisory_separates_comment_changes(self) -> None:
        self.assertEqual(repin.advisory(SCRIPT, SCRIPT.replace(b"# configure", b"# configured  ")), "comments or whitespace only")
        self.assertEqual(repin.advisory(SCRIPT, SCRIPT.replace(b"true", b"false")), "behavioral change; review every hunk")


class LockPackageTests(unittest.TestCase):
    def test_missing_signed_sha512_archive_identity_is_refused(self) -> None:
        sha512_digest = "a" * repin.SHA512_HEX
        lock = {
            "packages": [
                {
                    "name": "alpha",
                    "version": "1.0",
                    "architecture": "amd64",
                    "declared_size": 1,
                    "origin": {"repository_id": "repo"},
                    "archive_identity": {
                        "primary": "sha512",
                        "digests": [{"algorithm": "sha512", "digest": sha512_digest}],
                    },
                },
                {
                    "name": "beta",
                    "version": "1.0",
                    "architecture": "amd64",
                    "declared_size": 1,
                    "origin": {"repository_id": "repo"},
                    "archive_identity": {
                        "primary": "sha256",
                        "digests": [{"algorithm": "sha256", "digest": "b" * repin.SHA256_HEX}],
                    },
                },
            ]
        }
        packages = repin.lock_packages(lock, {"repo": "stable"})
        self.assertEqual(packages["alpha"]["archive"], f"sha512:{sha512_digest}")
        self.assertIsNone(packages["beta"]["archive"])
        with self.assertRaisesRegex(
            repin.RepinError,
            "amd64 closure packages without a signed SHA-512 archive identity: beta 1.0",
        ):
            repin.require_sha512(packages, "amd64")


class RecordTests(unittest.TestCase):
    def diff(self, value: dict, probe: dict, directory: Path = ROOT) -> dict:
        return repin.compute_diff(value, probe, directory, directory)

    def test_first_record_applies_provenance_without_review(self) -> None:
        value = manifest()
        probe = report({"script:alpha/postinst": {"amd64": observed()}})
        updated = repin.record_manifest(value, probe, self.diff(value, probe), {}, None)
        self.assertEqual(updated["snapshot"]["status"], "probed")
        self.assertEqual(updated["snapshot"]["closures"]["amd64"]["packages"], {"alpha": "1.0"})
        self.assertEqual(updated["identities"][0]["provenance"], {"version": "1.0", "archives": {"amd64": sha512(b"1.0")}})
        self.assertEqual(updated["identities"][0]["review"], "#1")

    def test_changed_identity_requires_exactly_its_review(self) -> None:
        value = manifest()
        changed = b"#!/bin/sh\nexit 1\n"
        probe = report({"script:alpha/postinst": {"amd64": observed(digest=sha256(changed), size=len(changed))}})
        diff = self.diff(value, probe)
        with self.assertRaisesRegex(repin.RepinError, "changed without re-review: script:alpha/postinst"):
            repin.record_manifest(value, probe, diff, {}, None)
        with self.assertRaisesRegex(repin.RepinError, "did not change: script:other"):
            repin.record_manifest(value, probe, diff, {"script:alpha/postinst": "#2", "script:other": "#2"}, None)
        updated = repin.record_manifest(value, probe, diff, {"script:alpha/postinst": "cataggar/debz#2"}, None)
        self.assertEqual(updated["identities"][0]["digest"], sha256(changed))
        self.assertEqual(updated["identities"][0]["review"], "cataggar/debz#2")

    def test_version_change_renames_versioned_fixture_consumers(self) -> None:
        consumers = [
            {"path": "src/fixtures/ubuntu-alpha-1.0-postinst", "form": "fixture"},
            {"path": "pins-1.0.txt", "form": "hex"},
        ]
        value = manifest([identity(version_bound="1:1.0", consumers=consumers)])
        probe = report({"script:alpha/postinst": {"amd64": observed(version="1:1.1")}})
        updated = repin.record_manifest(value, probe, self.diff(value, probe), {"script:alpha/postinst": "#3"}, None)
        self.assertEqual(updated["identities"][0]["version_bound"], "1:1.1")
        self.assertEqual(
            [consumer["path"] for consumer in updated["identities"][0]["consumers"]],
            ["src/fixtures/ubuntu-alpha-1.1-postinst", "pins-1.0.txt"],
        )

    def test_review_for_unchanged_identity_is_refused(self) -> None:
        value = manifest()
        probe = report({"script:alpha/postinst": {"amd64": observed()}})
        with self.assertRaisesRegex(repin.RepinError, "did not change"):
            repin.record_manifest(value, probe, self.diff(value, probe), {"script:alpha/postinst": "#2"}, None)

    def test_missing_identity_requires_review_and_is_dropped(self) -> None:
        value = manifest()
        probe = report({"script:alpha/postinst": {"amd64": None}})
        diff = self.diff(value, probe)
        with self.assertRaisesRegex(repin.RepinError, "without re-review"):
            repin.record_manifest(value, probe, diff, {}, None)
        updated = repin.record_manifest(value, probe, diff, {"script:alpha/postinst": "#3"}, None)
        self.assertEqual(updated["identities"], [])

    def test_older_report_and_other_series_are_refused(self) -> None:
        value = manifest(snapshot={"timestamp": T1, "status": "pending"})
        probe = report({"script:alpha/postinst": {"amd64": observed()}}, timestamp=T0)
        with self.assertRaisesRegex(repin.RepinError, "older than the current pin"):
            repin.record_manifest(value, probe, self.diff(value, probe), {}, None)
        other = report({"script:alpha/postinst": {"amd64": observed()}})
        other["series"] = dict(other["series"], name="other")
        with self.assertRaisesRegex(repin.RepinError, "different series"):
            self.diff(value, other)

    def test_frozen_release_change_requires_acceptance(self) -> None:
        roles = [{"suite": "r", "role": "frozen"}, {"suite": "r-updates", "role": "witness"}]
        value = manifest(pockets=roles)
        probe = report(
            {"script:alpha/postinst": {"amd64": observed()}},
            pockets=[pocket("r", "frozen", b"frozen-1"), pocket("r-updates", "witness", b"updates")],
        )
        diff = self.diff(value, probe)
        with self.assertRaisesRegex(repin.RepinError, "frozen release changed"):
            repin.record_manifest(value, probe, diff, {}, None)
        first = repin.record_manifest(value, probe, diff, {}, "#330")
        self.assertEqual(first["snapshot"]["pockets"][0]["review"], "#330")

        same = copy.deepcopy(probe)
        same["pockets"][1] = pocket("r-updates", "witness", b"updates-2")
        diff = self.diff(first, same)
        with self.assertRaisesRegex(repin.RepinError, "did not change"):
            repin.record_manifest(first, same, diff, {}, "#331")
        second = repin.record_manifest(first, same, diff, {}, None)
        self.assertEqual(second["snapshot"]["pockets"][0]["review"], "#330")

        point_release = copy.deepcopy(probe)
        point_release["pockets"][0] = pocket("r", "frozen", b"frozen-2")
        diff = self.diff(second, point_release)
        self.assertNotEqual(diff["frozen_release"]["pinned"], diff["frozen_release"]["probed"])
        with self.assertRaisesRegex(repin.RepinError, "frozen release changed"):
            repin.record_manifest(second, point_release, diff, {}, None)
        third = repin.record_manifest(second, point_release, diff, {}, "#332")
        self.assertEqual(third["snapshot"]["pockets"][0]["review"], "#332")

    def test_quiet_witness_is_recorded_as_refresh_only_and_bindings_are_validated(self) -> None:
        roles = [{"suite": "r", "role": "frozen"}, {"suite": "r-security", "role": "witness"}]
        value = manifest(pockets=roles)
        probe = report(
            {"script:alpha/postinst": {"amd64": observed()}},
            pockets=[pocket("r", "frozen", b"frozen"), pocket("r-security", "witness", b"security", "refresh_only")],
        )
        recorded = repin.record_manifest(value, probe, self.diff(value, probe), {}, "#330")
        self.assertEqual(recorded["snapshot"]["pockets"][1]["binding"], {"amd64": "refresh_only"})
        self.assertEqual(
            repin.unbound_pockets(probe["pockets"]), ["- `r-security` (witness of the frozen pocket) on amd64"]
        )
        for binding in ({}, {"amd64": "default_release"}, {"amd64": "exact_lock", "arm64": "exact_lock"}, None):
            mutated = copy.deepcopy(recorded)
            mutated["snapshot"]["pockets"][1]["binding"] = binding
            with self.subTest(binding=binding), self.assertRaisesRegex(repin.RepinError, "binding must give"):
                repin.validate_manifest(mutated)

    def test_closure_diff_and_pr_scan(self) -> None:
        value = manifest()
        probe = report({"script:alpha/postinst": {"amd64": observed()}})
        recorded = repin.record_manifest(value, probe, self.diff(value, probe), {}, None)
        changed = b"#!/bin/sh\nexit 2\n"
        later = report(
            {"script:alpha/postinst": {"amd64": observed(digest=sha256(changed), size=len(changed), version="1.1")}},
            timestamp="20261004T000000Z",
            closure={
                "alpha": {"version": "1.1", "architecture": "amd64", "archive": sha512(b"1.1"), "pocket": "stable"},
                "gamma": {"version": "3", "architecture": "amd64", "archive": sha512(b"3"), "pocket": "stable"},
            },
        )
        diff = self.diff(recorded, later)
        self.assertEqual(diff["closures"]["amd64"], {"added": ["gamma 3"], "removed": [], "changed": ["alpha 1.0 -> 1.1"]})
        self.assertEqual([entry["status"] for entry in diff["identities"]], ["changed"])
        labels = repin.changed_labels(diff, recorded, later)
        pr = (
            "diff --git a/src/x.zig b/src/x.zig\n+++ b/src/x.zig\n"
            f"+const pin = \"{sha256(SCRIPT).split(':')[1]}\";\n"
            f"+// {repin.snapshot_uri(recorded['series'], T1)}\n"
            " unchanged context " + sha256(SCRIPT).split(":")[1] + "\n"
        )
        findings = repin.scan_pr_diff(pr, recorded, labels)
        self.assertEqual(
            sorted((finding["path"], finding["pin"], finding["stale"]) for finding in findings),
            [("src/x.zig", "identity:script:alpha/postinst", True), ("src/x.zig", "timestamp", True), ("src/x.zig", "uri", True)],
        )


class CheckTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="real-snapshot-repin-unit-", dir=ROOT / ".tmp")
        self.root = Path(self.temporary.name)
        (self.root / "src/fixtures").mkdir(parents=True)
        (self.root / "tools").mkdir()
        (self.root / "src/fixtures/ubuntu-synthetic-alpha-1.0.postinst").write_bytes(SCRIPT)
        digest = hashlib.sha256(SCRIPT).digest()
        zig_bytes = ", ".join(f"0x{byte:02x}" for byte in digest)
        tool_hex = hashlib.sha256(TOOL).hexdigest()
        (self.root / "src/maintainer_script.zig").write_text(
            f"const snapshot_alpha_sha256 = [32]u8{{ {zig_bytes} }};\n"
            f'const inputs = .{{ .{{ .path = "usr/bin/beta", .size = {len(TOOL)}, .mode = 0o755, .sha256 = "{tool_hex}" }} }};\n'
            "// alpha 1.0\n",
            encoding="utf-8",
        )
        (self.root / "tools/real-snapshot-synthetic.sh").write_text(
            f"uri=file:///synthetic/snapshot/{T0}\nalpha={hashlib.sha256(SCRIPT).hexdigest()}\n", encoding="utf-8"
        )
        self.manifest = manifest(identities=[
            identity(consumers=[
                {"path": "src/fixtures/ubuntu-synthetic-alpha-1.0.postinst", "form": "fixture"},
                {"path": "src/maintainer_script.zig", "form": "zig_bytes", "name": "snapshot_alpha_sha256"},
                {"path": "tools/real-snapshot-synthetic.sh", "form": "hex"},
            ]),
            identity(
                id="file:beta/usr/bin/beta", kind="tool_file", package="beta", path="usr/bin/beta",
                digest=sha256(TOOL), size=len(TOOL), version_bound=None,
                consumers=[{"path": "src/maintainer_script.zig", "form": "hex"}],
            ),
        ])
        self.manifest["uri_consumers"] = ["tools/real-snapshot-synthetic.sh"]
        repin.validate_manifest(self.manifest)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def failures(self, value=None) -> list[str]:
        value = self.manifest if value is None else value
        return repin.check_manifest(value, self.root, value["series"])

    def test_consistent_tree_passes(self) -> None:
        self.assertEqual(self.failures(), [])
        self.assertEqual(
            repin.zig_bytes_constant((self.root / "src/maintainer_script.zig").read_text(), "snapshot_alpha_sha256"),
            hashlib.sha256(SCRIPT).hexdigest(),
        )

    def test_mutated_fixture_fails(self) -> None:
        (self.root / "src/fixtures/ubuntu-synthetic-alpha-1.0.postinst").write_bytes(SCRIPT + b"\n")
        self.assertTrue(any("bytes do not match" in failure for failure in self.failures()))

    def test_unlisted_pin_fails_until_excluded(self) -> None:
        stray = hashlib.sha256(b"stray").hexdigest()
        with (self.root / "tools/real-snapshot-synthetic.sh").open("a", encoding="utf-8") as stream:
            stream.write(f"stray={stray}\n")
        self.assertTrue(any("absent from the manifest" in failure for failure in self.failures()))
        excluded = copy.deepcopy(self.manifest)
        excluded["excluded"].append({"digest": f"sha256:{stray}", "reason": "synthetic stray digest for the test"})
        self.assertEqual(self.failures(excluded), [])

    def test_unlisted_fixture_fails(self) -> None:
        (self.root / "src/fixtures/ubuntu-synthetic-gamma-3.postinst").write_bytes(b"#!/bin/sh\n")
        self.assertTrue(any("is not a manifest identity consumer" in failure for failure in self.failures()))

    def test_stale_constant_and_input_entry_fail(self) -> None:
        source = self.root / "src/maintainer_script.zig"
        source.write_text(source.read_text().replace("0x", "0X", 1).replace(".size = ", ".size = 1", 1))
        failures = self.failures()
        self.assertTrue(any("constant snapshot_alpha_sha256" in failure for failure in failures))
        self.assertTrue(any("disagrees with file:beta/usr/bin/beta" in failure for failure in failures))

    def test_uri_and_version_consumers_are_enforced(self) -> None:
        script = self.root / "tools/real-snapshot-synthetic.sh"
        script.write_text(script.read_text() + f"old=file:///x/{'snapshot.ubuntu.com/ubuntu/20260101T000000Z'}\n")
        self.assertTrue(any("pins another snapshot" in failure for failure in self.failures()))
        moved = copy.deepcopy(self.manifest)
        moved["snapshot"]["timestamp"] = T1
        self.assertTrue(any("does not pin file:///synthetic/snapshot/" + T1 in failure for failure in self.failures(moved)))
        renamed = copy.deepcopy(self.manifest)
        renamed["identities"][0]["version_bound"] = "1.1"
        self.assertTrue(any("does not carry version 1.1" in failure for failure in self.failures(renamed)))

    def test_series_must_match_its_reviewed_profile(self) -> None:
        self.assertTrue(any("not a built-in profile" in failure for failure in repin.check_manifest(self.manifest, self.root)))
        changed = dict(self.manifest["series"], signer="f" * 40)
        self.assertTrue(any("differs from its reviewed profile" in failure for failure in repin.check_manifest(self.manifest, self.root, changed)))


class PackageTests(unittest.TestCase):
    def test_bind_pockets_returns_only_pockets_a_lock_names(self) -> None:
        pockets = {
            "r": pocket("r", "frozen", b"frozen"),
            "r-updates": pocket("r-updates", "witness", b"updates"),
            "r-security": pocket("r-security", "witness", b"security"),
        }
        ids = {"r": "1" * 64, "r-updates": "2" * 64, "r-security": "3" * 64}

        def repository(suite: str, release: bytes, signer: str = SIGNER) -> dict:
            return {
                "id": ids[suite],
                "release_sha256": hashlib.sha256(release).hexdigest(),
                "signer_fingerprints": [signer],
            }

        closure = {"repositories": [repository("r", b"frozen"), repository("r-updates", b"updates")]}
        self.assertEqual(repin.bind_pockets(pockets, [closure], ids, SIGNER, "amd64"), {"r", "r-updates"})
        bind = {"repositories": [repository("r-security", b"security")]}
        self.assertEqual(
            repin.bind_pockets(pockets, [closure, bind], ids, SIGNER, "amd64"), {"r", "r-updates", "r-security"}
        )
        for lock, message in (
            ({"repositories": [repository("r-security", b"other")]}, "r-security Release fetched by the probe differs"),
            ({"repositories": [repository("r-security", b"security", "0" * 40)]}, "not the reviewed signer"),
            ({"repositories": [dict(repository("r", b"frozen"), id="4" * 64)]}, "refresh did not report"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(repin.RepinError, message):
                repin.bind_pockets(pockets, [lock], ids, SIGNER, "amd64")

    def test_members_are_read_from_compressed_and_plain_tars(self) -> None:
        for compress in (True, False):
            data = deb({"postinst": (SCRIPT, 0o755)}, {"usr/bin/beta": (TOOL, 0o4755)}, compress)
            self.assertEqual(repin.tar_member(data, "control.tar", "postinst"), (SCRIPT, 0o755))
            self.assertEqual(repin.tar_member(data, "data.tar", "usr/bin/beta"), (TOOL, 0o4755))
            with self.assertRaisesRegex(repin.RepinError, "has no member"):
                repin.tar_member(data, "data.tar", "usr/bin/gamma")

    def test_malformed_packages_are_refused(self) -> None:
        with self.assertRaisesRegex(repin.RepinError, "not an ar archive"):
            repin.ar_members(b"not a deb")
        data = deb({"postinst": (SCRIPT, 0o755)}, {})
        with self.assertRaisesRegex(repin.RepinError, "truncated or duplicate"):
            repin.ar_members(data[:-40])


if __name__ == "__main__":
    unittest.main()
