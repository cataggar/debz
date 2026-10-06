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
from unittest.mock import patch
import zipfile


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
        "version_bound": False,
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
            (lambda m: m["identities"][0].update(version_bound="1.0"), "version_bound must be a boolean"),
            (lambda m: m["identities"][0].update(version_bound=True), "version_bound requires recorded provenance"),
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
        (ROOT / ".tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="real-snapshot-repin-profile-", dir=ROOT / ".tmp") as directory:
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
        self.assertEqual(repin.identity_status(recorded, {"amd64": observed(version="1.1")})[0], "provenance-only")
        version_bound = dict(recorded, version_bound=True)
        status, reasons = repin.identity_status(version_bound, {"amd64": observed(version="1.1")})
        self.assertEqual(status, "changed")
        self.assertIn("version-bound identity moved", reasons[0])
        self.assertEqual(repin.identity_status(recorded, {"amd64": None})[0], "missing")
        self.assertEqual(repin.identity_status(recorded, {})[0], "missing")

    def test_exact_byte_identity_version_change_with_same_bytes_is_provenance_only(self) -> None:
        exact = identity(provenance={"version": "1.0", "archives": {"amd64": sha512(b"1.0")}})
        status, reasons = repin.identity_status(exact, {"amd64": observed(version="1.1")})
        self.assertEqual(status, "provenance-only")
        self.assertIn("archive", reasons[0])

    def test_prestate_changes_with_any_source_version(self) -> None:
        prestate = identity(
            id="prestate:alpha/var/lib/dpkg/info/alpha.list", kind="prestate",
            path="var/lib/dpkg/info/alpha.list", mode=None,
            derived_from=[{"package": "alpha", "version": "1.0"}, {"package": "beta", "version": "2.0"}],
        )
        same = observed(derived={"alpha": "1.0", "beta": "2.0"})
        same.update(digest=None, size=None, mode=None)
        self.assertEqual(repin.identity_status(prestate, {"amd64": same})[0], "provenance-only")
        moved = observed(derived={"alpha": "1.0", "beta": "2.1"})
        moved.update(digest=None, size=None, mode=None)
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

    def test_exact_byte_version_change_keeps_fixture_consumers(self) -> None:
        consumers = [
            {"path": "src/fixtures/ubuntu-alpha-1.0-postinst", "form": "fixture"},
            {"path": "pins-1.0.txt", "form": "hex"},
        ]
        value = manifest([identity(consumers=consumers, provenance={"version": "1:1.0", "archives": {"amd64": sha512(b"1.0")}})])
        probe = report({"script:alpha/postinst": {"amd64": observed(version="1:1.1")}})
        updated = repin.record_manifest(value, probe, self.diff(value, probe), {}, None)
        self.assertEqual(updated["identities"][0]["version_bound"], False)
        self.assertEqual(updated["identities"][0]["provenance"]["version"], "1:1.1")
        self.assertEqual(
            [consumer["path"] for consumer in updated["identities"][0]["consumers"]],
            ["src/fixtures/ubuntu-alpha-1.0-postinst", "pins-1.0.txt"],
        )

    def test_explicit_version_bound_identity_requires_review_and_renames_fixture(self) -> None:
        consumers = [
            {"path": "src/fixtures/ubuntu-alpha-1.0-postinst", "form": "fixture"},
            {"path": "pins-1.0.txt", "form": "hex"},
        ]
        value = manifest([identity(
            version_bound=True,
            consumers=consumers,
            provenance={"version": "1:1.0", "archives": {"amd64": sha512(b"1.0")}},
        )])
        probe = report({"script:alpha/postinst": {"amd64": observed(version="1:1.1")}})
        diff = self.diff(value, probe)
        with self.assertRaisesRegex(repin.RepinError, "changed without re-review: script:alpha/postinst"):
            repin.record_manifest(value, probe, diff, {}, None)
        updated = repin.record_manifest(value, probe, diff, {"script:alpha/postinst": "#3"}, None)
        self.assertEqual(updated["identities"][0]["version_bound"], True)
        self.assertEqual(updated["identities"][0]["provenance"]["version"], "1:1.1")
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

    def test_series_migration_records_profile_and_fixture_paths_when_allowed(self) -> None:
        consumers = [
            {"path": "src/fixtures/ubuntu-old-alpha-1.0.postinst", "form": "fixture"},
            {"path": "pins.txt", "form": "hex"},
        ]
        value = manifest([identity(consumers=consumers)])
        probe = report({"script:alpha/postinst": {"amd64": observed(version="1.1")}})
        probe["series"] = dict(probe["series"], name="ubuntu-new")
        with self.assertRaisesRegex(repin.RepinError, "different series"):
            repin.record_manifest(value, probe, self.diff(value, probe, ROOT), {}, None)
        diff = repin.compute_diff(value, probe, ROOT, ROOT, allow_series_migration=True)
        updated = repin.record_manifest(value, probe, diff, {}, None, allow_series_migration=True)
        self.assertEqual(updated["series"]["name"], "ubuntu-new")
        self.assertEqual(
            [consumer["path"] for consumer in updated["identities"][0]["consumers"]],
            ["src/fixtures/ubuntu-new-alpha.postinst", "pins.txt"],
        )

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
                digest=sha256(TOOL), size=len(TOOL), version_bound=False,
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

    def test_archive_record_size_version_and_architecture_cannot_hide_behind_digest(self) -> None:
        archive = identity(id="archive:gamma", kind="archive", package="gamma", path=None, mode=None,
                           digest=sha512(b"gamma"), size=5,
                           provenance={"version": "1.0", "archives": {"amd64": sha512(b"gamma")}},
                           consumers=[{"path": "src/native_unpack.zig", "form": "hex"}])
        value = copy.deepcopy(self.manifest)
        value["identities"].append(archive)
        source = ('.{ .package = .{ .name = "gamma", .version = "1.0", .architecture = "amd64" },\n'
                  f'.size = 5, .sha512 = "{archive["digest"].split(":")[1]}" }},\n')
        target = self.root / "src/native_unpack.zig"
        target.write_text(source)
        self.assertEqual(self.failures(value), [])
        for old, new in ((".size = 5", ".size = 6"), ('"1.0"', '"0.9"'), ('"amd64"', '"arm64"')):
            target.write_text(source.replace(old, new))
            self.assertTrue(any("archive version, size or architecture" in f for f in self.failures(value)))

    def test_protected_stage_profiles_must_match_manifest_and_launcher(self) -> None:
        frozen = pocket("stable", "frozen", b"frozen")
        value = copy.deepcopy(self.manifest)
        value["series"]["pockets"] = [
            {"suite": "stable", "role": "frozen"},
            {"suite": "stable-updates", "role": "witness"},
            {"suite": "stable-security", "role": "witness"},
        ]
        value["snapshot"] = {"timestamp": T0, "status": "probed", "pockets": [frozen]}
        value["identities"][0]["provenance"] = {"version": "1.0", "archives": {"amd64": sha512(b"1.0")}}
        value["identities"][0]["consumers"].append({"path": repin.REFERENCE_LAUNCHER, "form": "hex"})
        (self.root / repin.REFERENCE_LAUNCHER).write_text(
            'const script_bindings = [_]ScriptBinding{\n'
            f'    .{{ .name = "alpha", .version = "1.0", .size = {len(SCRIPT)}, '
            f'.digest = "{sha256(SCRIPT).split(":", 1)[1]}" }},\n'
            '};\n',
            encoding="utf-8",
        )
        stage = self.root / repin.PROTECTED_STAGE_SCRIPT
        stage.write_text(
            f"readonly snapshot_uri={repin.snapshot_uri(value['series'], T0)}\n"
            "readonly snapshot_suite=stable\n"
            "readonly snapshot_witness_suites=(stable-updates stable-security)\n"
            f"readonly frozen_release_sha256={frozen['release_sha256'].split(':', 1)[1]}\n"
            "for profile in alpha; do\n  :\ndone\n",
            encoding="utf-8",
        )
        self.assertEqual(repin.check_manifest(value, self.root, value["series"]), [])

        stage.write_text(stage.read_text().replace("snapshot_suite=stable", "snapshot_suite=devel"),
                         encoding="utf-8")
        self.assertTrue(any("snapshot_suite" in failure for failure in
                            repin.check_manifest(value, self.root, value["series"])))
        stage.write_text(stage.read_text().replace("snapshot_suite=devel", "snapshot_suite=stable"),
                         encoding="utf-8")
        launcher = self.root / repin.REFERENCE_LAUNCHER
        launcher.write_text(launcher.read_text().replace(f".size = {len(SCRIPT)}", ".size = 1"),
                            encoding="utf-8")
        self.assertTrue(any("alpha size" in failure for failure in
                            repin.check_manifest(value, self.root, value["series"])))

    def test_uri_consumers_are_enforced_and_default_admissions_ignore_versions(self) -> None:
        script = self.root / "tools/real-snapshot-synthetic.sh"
        script.write_text(script.read_text() + f"old=file:///x/{'snapshot.ubuntu.com/ubuntu/20260101T000000Z'}\n")
        self.assertTrue(any("pins another snapshot" in failure for failure in self.failures()))
        moved = copy.deepcopy(self.manifest)
        moved["snapshot"]["timestamp"] = T1
        self.assertTrue(any("does not pin file:///synthetic/snapshot/" + T1 in failure for failure in self.failures(moved)))
        renamed = copy.deepcopy(self.manifest)
        renamed["identities"][0]["provenance"] = {"version": "1.1", "archives": {"amd64": sha512(b"1.1")}}
        self.assertFalse(any("version" in failure for failure in self.failures(renamed)))

    def test_explicit_version_bound_consumers_are_enforced(self) -> None:
        renamed = copy.deepcopy(self.manifest)
        renamed["identities"][0]["version_bound"] = True
        renamed["identities"][0]["provenance"] = {"version": "1.1", "archives": {"amd64": sha512(b"1.1")}}
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

    def test_dpkg_ownership_list_uses_data_tar_order(self) -> None:
        data = deb(
            {},
            {
                ".": (b"", 0o755),
                "usr": (b"", 0o755),
                "usr/bin/tool": (TOOL, 0o755),
                "usr/share/doc/beta/": (b"", 0o755),
            },
        )
        self.assertEqual(
            repin.dpkg_ownership_list(data),
            b"/.\n/usr\n/usr/bin/tool\n/usr/share/doc/beta\n",
        )

    def test_malformed_packages_are_refused(self) -> None:
        with self.assertRaisesRegex(repin.RepinError, "not an ar archive"):
            repin.ar_members(b"not a deb")
        data = deb({"postinst": (SCRIPT, 0o755)}, {})
        with self.assertRaisesRegex(repin.RepinError, "truncated or duplicate"):
            repin.ar_members(data[:-40])


class CoordinateTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="repin-coordinates-", dir=ROOT / ".tmp")
        self.root = Path(self.temporary.name)
        self.value = identity(provenance={"version": "1.0", "archives": {"amd64": sha512(b"archive")}},
                              consumers=[{"path": "pins.sh", "form": "shell", "bindings": {
                                  "digest": "member_digest", "size": "member_size", "version": "package_version",
                                  "member": "member_path"}}])
        self.text = (
            f"readonly member_digest={sha256(SCRIPT).split(':')[1]}\n"
            f"readonly member_size={len(SCRIPT)}\n"
            "readonly package_version=1.0\nreadonly member_path=./postinst\n"
        )
        (self.root / "pins.sh").write_text(self.text)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_named_coordinates_reject_stale_literals_even_when_comments_are_correct(self) -> None:
        repin.validate_identity(self.value, 0)
        self.assertEqual(repin.consumer_failures(self.value, self.root), [])
        for old, new, coordinate in (
            (f"member_size={len(SCRIPT)}", "member_size=1", "size"),
            ("package_version=1.0", "package_version=0.9", "version"),
            ("member_path=./postinst", "member_path=./preinst", "member"),
            ("member_digest=" + sha256(SCRIPT).split(":")[1], "member_digest=" + "0" * 64, "digest"),
        ):
            with self.subTest(coordinate=coordinate):
                (self.root / "pins.sh").write_text(self.text.replace(old, new) + "\n# " + self.text.replace("\n", " "))
                self.assertTrue(any(f" {coordinate} (" in failure for failure in repin.consumer_failures(self.value, self.root)))

    def test_keyring_url_deb_size_and_member_size_are_typed_consumers(self) -> None:
        committed = repin.load_json(ROOT / repin.DEFAULT_MANIFEST)
        archive = next(i for i in committed["identities"] if i["id"] == "archive:ubuntu-keyring")
        member = next(i for i in committed["identities"] if i["package"] == "ubuntu-keyring" and i["kind"] == "tool_file")
        relative = next(c["path"] for c in archive["consumers"] if c["form"] == "shell")
        target = self.root / relative
        target.parent.mkdir(parents=True)
        source = (ROOT / relative).read_text()
        for old, new, coordinate, bound in (
            ("ubuntu-keyring_2023.11.28.1build1_all.deb", "ubuntu-keyring_2026.08.18_all.deb", "url", archive),
            ("archive_keyring_deb_size=11228", "archive_keyring_deb_size=12718", "size", archive),
            ("archive_keyring_size=3607", "archive_keyring_size=2334", "size", member),
            ("archive_keyring_member=./usr/share/keyrings", "archive_keyring_member=./etc/keyrings", "member", member),
        ):
            with self.subTest(coordinate=coordinate, old=old):
                target.write_text(source.replace(old, new))
                failures = repin.consumer_failures(bound, self.root, committed)
                self.assertTrue(any(f" {coordinate} (" in failure for failure in failures), failures)
        target.write_text(source)
        self.assertEqual(repin.consumer_failures(archive, self.root, committed), [])
        moved = copy.deepcopy(archive)
        moved["provenance"]["version"] = "2026.08.18"
        with self.assertRaisesRegex(repin.RepinError, "version"):
            repin.validate_identity(moved, 0)

    def test_duplicate_or_dynamic_assignment_is_not_a_literal_binding(self) -> None:
        for addition in ("\nreadonly member_size=1\n", "\nreadonly member_size=$(wc -c <postinst)\n"):
            (self.root / "pins.sh").write_text(self.text + addition)
            self.assertTrue(any(" size (" in failure for failure in repin.consumer_failures(self.value, self.root)))

    def test_digest_size_tuple_and_explicit_version_binding(self) -> None:
        self.value["consumers"][0]["bindings"] = {"digest_size": "member", "version": "version"}
        text = f"readonly member='{sha256(SCRIPT).split(':')[1]} {len(SCRIPT)}'\nreadonly version=1.0\n"
        (self.root / "pins.sh").write_text(text)
        self.assertEqual(repin.consumer_failures(self.value, self.root), [])
        (self.root / "pins.sh").write_text(text.replace(f" {len(SCRIPT)}'", " 1'"))
        self.assertTrue(any("digest_size" in f for f in repin.consumer_failures(self.value, self.root)))

    def test_generic_snapshot_suite_witness_uri_and_release_bindings(self) -> None:
        frozen = pocket("stable", "frozen", b"frozen")
        value = manifest(pockets=[{"suite": "stable", "role": "frozen"}, {"suite": "stable-updates", "role": "witness"}])
        value["snapshot"]["pockets"] = [frozen]
        value["coordinate_consumers"] = [{"path": "pins.sh", "bindings": {
            "suite": "suite", "uri": "uri", "witness_suites": "witnesses", "release_sha256": "release"}}]
        text = ("readonly suite=stable\nreadonly witnesses=(stable-updates)\n"
                f"readonly uri={repin.snapshot_uri(value['series'], T0)}\n"
                f"readonly release={frozen['release_sha256'].split(':')[1]}\n")
        (self.root / "pins.sh").write_text(text)
        self.assertEqual(repin.snapshot_coordinate_failures(value, self.root), [])
        for old, new, coordinate in (
            ("suite=stable", "suite=wrong", "suite"),
            ("witnesses=(stable-updates)", "witnesses=(stable-security)", "witness_suites"),
            (T0, T1, "uri"),
            (frozen["release_sha256"].split(":")[1], "0" * 64, "release_sha256"),
        ):
            with self.subTest(coordinate=coordinate):
                (self.root / "pins.sh").write_text(text.replace(old, new))
                self.assertTrue(any(f" {coordinate} (" in f for f in repin.snapshot_coordinate_failures(value, self.root)))

    def test_coordinate_schema_is_strict(self) -> None:
        for bindings in ({"digest": "x", "unknown": "y"}, {"digest": "x", "size": "x"}, {"digest": "$(true)"}, {"size": "x"}):
            value = copy.deepcopy(self.value)
            value["consumers"][0]["bindings"] = bindings
            with self.subTest(bindings=bindings), self.assertRaises(repin.RepinError):
                repin.validate_identity(value, 0)


class SourceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="repin-evidence-", dir=ROOT / ".tmp")
        self.root = Path(self.temporary.name)
        self.directory = self.root / "probe"
        self.directory.mkdir()
        (self.directory / "locks").mkdir()
        control = b"Package: alpha\nVersion: 1.0\nArchitecture: all\nDescription: synthetic\n"
        self.archive = deb({"control": (control, 0o644), "triggers": (b"interest /usr/share/alpha\n", 0o644)},
                           {"usr/share/alpha": (b"alpha\n", 0o644)})
        self.member = repin.dpkg_ownership_list(self.archive)
        self.value = manifest([identity(
            id="prestate:alpha/var/lib/dpkg/info/alpha.list", kind="prestate", path="var/lib/dpkg/info/alpha.list",
            digest=sha256(self.member), size=len(self.member), mode="0644",
            derived_from=[{"package": "alpha", "version": "1.0"}],
            provenance={"version": "1.0", "archives": {"amd64": sha512(self.archive)}},
        )])
        self.report = report({}, timestamp=T0)
        self.report["repository_ids"] = {"amd64": {"stable": "1" * 64}}
        index = (
            f"Package: alpha\nVersion: 1.0\nArchitecture: all\nSize: {len(self.archive)}\n"
            f"SHA512: {sha512(self.archive).split(':')[1]}\nFilename: pool/alpha_1.0_all.deb\n\n"
        ).encode()
        cleartext = (f"Suite: stable\nDate: Sun, 26 Sep 2026 23:00:00 UTC\nSHA256:\n"
                     f" {sha256(index).split(':')[1]} {len(index)} main/binary-amd64/Packages\n").encode()
        release = (b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + cleartext +
                   b"-----BEGIN PGP SIGNATURE-----\nsynthetic unit fixture\n")
        self.report["pockets"][0].update(release_sha256=sha256(cleartext), in_release_sha256=sha256(release),
                                          in_release_sha512=sha512(release))
        metadata = {"index_file": "indexes/amd64-stable-Packages", "index_path": "main/binary-amd64/Packages",
                    "release_file": "releases/stable.InRelease"}
        self.report["artifact_sources"] = {"amd64": {"alpha": metadata}}
        for relative, content in ((metadata["index_file"], index), (metadata["release_file"], release)):
            target = self.directory / relative
            target.parent.mkdir(parents=True)
            target.write_bytes(content)
        self.value["snapshot"] = {
            "timestamp": T0, "status": "probed", "pockets": self.report["pockets"],
            "admission_deadline": self.report["admission_deadline"], "closures": {},
        }
        entry = {
            "name": "alpha", "version": "1.0", "architecture": "all", "declared_size": len(self.archive),
            "origin": {"type": "authenticated_repository", "repository_id": "1" * 64, "repository_snapshot_sha256": "2" * 64},
            "archive_identity": {"primary": "sha512", "digests": [{"algorithm": "sha512", "digest": sha512(self.archive).split(":")[1]}]},
        }
        self.lock = {"packages": [entry], "repositories": [{
            "id": "1" * 64, "snapshot_sha256": "2" * 64,
            "release_sha256": self.report["pockets"][0]["release_sha256"].split(":")[1], "signer_fingerprints": [SIGNER],
            "index_identity": {"primary": "sha256", "digests": [{"algorithm": "sha256", "digest": sha256(index).split(":")[1]}]},
        }]}
        repin.write_json(self.directory / "report.json", self.report)
        repin.write_json(self.directory / "locks/amd64.lock.json", self.lock)
        cas = self.directory / "amd64/cache/packages-v2/objects"
        cas.mkdir(parents=True)
        (cas / sha512(self.archive).replace(":", "-")).write_bytes(self.archive)
        self.value["prestate_evidence"] = "evidence.zip"
        repin.export_prestate_evidence(self.value, self.report, self.directory, self.root)
        (self.root / "pins.txt").write_text(sha256(self.member).split(":")[1])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_retained_bytes_are_rederived_without_network_or_cached_verdict(self) -> None:
        with patch.object(repin, "fetch", side_effect=AssertionError("offline")), patch.object(repin.Debz, "run", side_effect=AssertionError("offline")):
            self.assertEqual(repin.check_manifest(self.value, self.root, self.value["series"]), [])
        # Even a mutually consistent consumer and manifest cannot replace the retained source bytes.
        changed = copy.deepcopy(self.value)
        changed["identities"][0]["digest"] = sha256(b"historical stale list\n")
        (self.root / "pins.txt").write_text(changed["identities"][0]["digest"].split(":")[1])
        self.assertEqual(repin.consumer_failures(changed["identities"][0], self.root), [])
        self.assertTrue(any("derived bytes disagree" in f for f in repin.check_manifest(changed, self.root, changed["series"])))

    def test_derived_digest_size_mode_version_and_archive_mutations_fail(self) -> None:
        for key, wrong in (("digest", sha256(b"stale")), ("size", 1), ("mode", "0755")):
            changed = copy.deepcopy(self.value)
            changed["identities"][0][key] = wrong
            self.assertTrue(any("derived bytes disagree" in f for f in repin.prestate_evidence_failures(changed, self.root)))
        for mutate in (
            lambda i: i["provenance"].update(version="0.9"),
            lambda i: i["provenance"]["archives"].update(amd64=sha512(b"stale")),
            lambda i: i["derived_from"][0].update(version="0.9"),
        ):
            changed = copy.deepcopy(self.value)
            mutate(changed["identities"][0])
            self.assertTrue(repin.prestate_evidence_failures(changed, self.root))

    def test_trigger_derivation_reuses_control_member_and_missing_evidence_refuses(self) -> None:
        changed = copy.deepcopy(self.value)
        item = changed["identities"][0]
        member = b"interest /usr/share/alpha\n"
        item.update(id="prestate:alpha/var/lib/dpkg/info/alpha.triggers", path="var/lib/dpkg/info/alpha.triggers",
                    digest=sha256(member), size=len(member))
        self.assertEqual(repin.prestate_evidence_failures(changed, self.root), [])
        del changed["prestate_evidence"]
        self.assertTrue(any("no retained" in f for f in repin.prestate_evidence_failures(changed, self.root)))

    def test_artifact_filename_is_grounded_in_original_signed_packages_bytes(self) -> None:
        changed = copy.deepcopy(self.value)
        changed["identities"][0]["artifact"] = {"filename": "pool/alpha_1.0_all.deb", "architecture": "all"}
        changed["identities"][0]["consumers"] = [{"path": "pins.txt", "form": "shell", "bindings": {
            "digest": "digest", "url": "url", "size": "size", "member": "member"}}]
        repin.validate_identity(changed["identities"][0], 0)
        self.assertEqual(repin.prestate_evidence_failures(changed, self.root), [])
        changed["identities"][0]["artifact"]["filename"] = "wrong-pool/alpha_1.0_all.deb"
        repin.validate_identity(changed["identities"][0], 0)
        self.assertTrue(any("artifact filename" in f for f in repin.prestate_evidence_failures(changed, self.root)))

    def test_retained_release_index_and_lock_tampering_or_zip_traversal_refuses(self) -> None:
        original = (self.root / "evidence.zip").read_bytes()
        for prefix in ("releases/", "indexes/", "locks/", "../escape"):
            output = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(original)) as old, zipfile.ZipFile(output, "w") as new:
                for entry in old.infolist():
                    content = old.read(entry.filename)
                    if entry.filename.startswith(prefix):
                        content += b"x"
                    new.writestr(entry, content)
                if prefix == "../escape":
                    new.writestr(prefix, b"bad")
            (self.root / "evidence.zip").write_bytes(output.getvalue())
            with self.subTest(prefix=prefix):
                self.assertTrue(repin.prestate_evidence_failures(self.value, self.root))
        (self.root / "evidence.zip").write_bytes(original)

    def test_source_bundle_symlink_is_not_an_offline_checkout_source(self) -> None:
        path = self.root / "evidence.zip"
        path.rename(self.root / "original.zip")
        path.symlink_to(self.root / "original.zip")
        self.assertTrue(any("unsafe" in f for f in repin.prestate_evidence_failures(self.value, self.root)))
        with self.assertRaisesRegex(repin.RepinError, "symlink"):
            repin.export_prestate_evidence(self.value, self.report, self.directory, self.root)

    def test_report_without_retained_signed_metadata_cannot_record_a_cached_success(self) -> None:
        report = copy.deepcopy(self.report)
        del report["artifact_sources"]
        with self.assertRaisesRegex(repin.RepinError, "run a new probe"):
            repin.export_prestate_evidence(self.value, report, self.directory, self.root)

    def test_source_report_reads_and_lock_directory_are_bounded_before_parsing(self) -> None:
        with patch.object(repin, "MAXIMUM_RELEASE_BYTES", 32):
            with self.assertRaisesRegex(repin.RepinError, "JSON document is too large"):
                repin.load_json(self.directory / "report.json")
            with self.assertRaisesRegex(repin.RepinError, "report.json is too large"):
                repin.export_prestate_evidence(self.value, self.report, self.directory, self.root)
        (self.directory / "locks/extra.lock.json").write_bytes(b"must not be parsed")
        with patch.object(repin, "MAXIMUM_EVIDENCE_FILES", 1):
            with self.assertRaisesRegex(repin.RepinError, "entry bound"):
                repin.export_prestate_evidence(self.value, self.report, self.directory, self.root)

    def test_source_reader_refuses_oversize_and_symlink_metadata(self) -> None:
        path = self.directory / "oversize"
        path.write_bytes(b"x" * 33)
        with self.assertRaisesRegex(repin.RepinError, "too large"):
            repin.read_source_file(path, self.directory, 32, "retained source")
        link = self.directory / "linked"
        link.symlink_to(path)
        with self.assertRaisesRegex(repin.RepinError, "unsafe"):
            repin.read_source_file(link, self.directory, 64, "retained source")

    def test_offline_source_metadata_reads_are_bounded_before_parsing(self) -> None:
        repin.export_prestate_evidence(self.value, self.report, self.directory, self.root)
        with patch.object(repin, "MAXIMUM_RELEASE_BYTES", 32):
            failures = repin.prestate_evidence_failures(self.value, self.root)
            self.assertIn("source evidence member evidence.json is too large", "\n".join(failures))

    def test_aggregate_evidence_budget_caps_the_archive_read(self) -> None:
        lock = next((self.directory / "locks").glob("*.lock.json"))
        limit = (self.directory / "report.json").stat().st_size + lock.stat().st_size + len(self.archive) - 1
        with patch.object(repin, "MAXIMUM_EVIDENCE_BYTES", limit):
            with self.assertRaisesRegex(repin.RepinError, "source archive .* is too large"):
                repin.export_prestate_evidence(self.value, self.report, self.directory, self.root)

    def test_source_control_coordinates_and_authenticated_provenance_are_not_manifest_copies(self) -> None:
        entry = copy.deepcopy(self.lock["packages"][0])
        entry["version"] = "0.9"
        with self.assertRaisesRegex(repin.RepinError, "control coordinates"):
            repin.verify_source_archive(self.archive, entry)
        for mutate in (
            lambda lock: lock["packages"][0]["origin"].update(type="local_artifact"),
            lambda lock: lock["repositories"][0].update(signer_fingerprints=["0" * 40]),
            lambda lock: lock["repositories"][0].update(release_sha256="0" * 64),
        ):
            lock = copy.deepcopy(self.lock)
            mutate(lock)
            with self.assertRaises(repin.RepinError):
                repin.authenticated_source_package(self.report, lock, "alpha", "amd64")

    def test_archive_and_evidence_bounds_and_unsafe_members_fail_closed(self) -> None:
        data = (self.root / "evidence.zip").read_bytes()
        with patch.object(repin, "MAXIMUM_EVIDENCE_BYTES", 64):
            self.assertTrue(any("too large" in f for f in repin.prestate_evidence_failures(self.value, self.root)))
        with patch.object(repin, "MAXIMUM_TAR_BYTES", 64):
            with self.assertRaisesRegex(repin.RepinError, "too large"):
                repin.dpkg_ownership_list(self.archive)
        for path in ("../escape", "/absolute", "usr/../escape", "usr/bad\nname"):
            with self.subTest(path=path), self.assertRaises(repin.RepinError):
                repin.dpkg_ownership_list(deb({}, {path: (b"bad", 0o644)}))
        source = io.BytesIO(data)
        output = io.BytesIO()
        with zipfile.ZipFile(source) as old, zipfile.ZipFile(output, "w") as new:
            for entry in old.infolist():
                content = old.read(entry.filename)
                if entry.filename.startswith("archives/"):
                    content = content[:-1] + b"!"
                new.writestr(entry, content)
        (self.root / "evidence.zip").write_bytes(output.getvalue())
        self.assertTrue(any("archive" in f for f in repin.prestate_evidence_failures(self.value, self.root)))

    def test_each_real_archive_derived_prestate_mutation_fails_independently(self) -> None:
        committed = repin.load_json(ROOT / repin.DEFAULT_MANIFEST)
        covered = [i for i in committed["identities"] if repin.prestate_derivation(i, "amd64")]
        for item in covered:
            changed = copy.deepcopy(committed)
            target = next(i for i in changed["identities"] if i["id"] == item["id"])
            target["digest"] = sha256(b"stale historical prestate")
            with self.subTest(identity=item["id"]):
                failures = repin.prestate_evidence_failures(changed, ROOT)
                self.assertTrue(any(item["id"] in f and "derived bytes disagree" in f for f in failures), failures)


if __name__ == "__main__":
    unittest.main()
