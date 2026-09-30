"""Offline refusal tests for the #261 Debian stable closure locks and inventory evidence."""

import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import lzma
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("debian_stable_closure", ROOT / "tools/debian-stable-closure.py")
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)
PIN = closure.load_pin()
UBUNTU_SIGNER = "f6ecb3762474eda9d21b7022871920d1991bc93c"
UTC = datetime.timezone.utc


def committed_lock(architecture="amd64", request="apt"):
    return json.loads((closure.EVIDENCE_DIR / f"{architecture}-{request}.lock.json").read_text())


def signed_records_for(lock):
    return {
        (package["name"], package["version"], package["architecture"]): {
            "filename": f"pool/main/{package['name'][0]}/{package['name']}/{package['name']}_{package['version']}_{package['architecture']}.deb",
            "size": package["declared_size"],
            "sha256": package["archive_identity"]["digests"][0]["digest"],
        }
        for package in lock["packages"]
    }


class CommittedEvidenceTests(unittest.TestCase):
    def test_committed_evidence_revalidates_offline(self):
        document = closure.check_evidence()
        self.assertEqual(document["issue"], 261)
        self.assertEqual(document["freshness"]["expires_at"], "2026-10-13T07:55:41Z")
        self.assertEqual(document["program"]["optimize"], "ReleaseSafe")
        self.assertEqual(document["keyring"]["sha256"], PIN["signer"]["binary_sha256"])
        for architecture in closure.ARCHITECTURES:
            entry = document["architectures"][architecture]
            self.assertEqual(len(set(entry["runs"])), 2)
            self.assertEqual(entry["repository"]["archive_binding"], closure.ARCHIVE_BINDING)
            self.assertEqual(entry["repository"]["index_sha256"], PIN["architectures"][architecture]["index_sha256"])
            self.assertEqual(entry["repository"]["inrelease_sha256"], PIN["release"]["inrelease_sha256"])
            summary = entry["inventory"]["summary"]
            self.assertEqual((summary["admitted"], summary["rejected"]), (summary["packages"], 0))
            for row in entry["cas"]:
                self.assertTrue(row["filename"].startswith("pool/main/"))
                self.assertTrue(closure.is_hex(row["derived_sha512"], "sha512"))
        priorities = [gap["priority"] for gap in document["gaps"]]
        self.assertEqual(priorities, sorted(priorities))
        # The two architectures resolve different archives, never the same bytes.
        amd64 = {row["sha256"] for row in document["architectures"]["amd64"]["cas"] if row["architecture"] != "all"}
        arm64 = {row["sha256"] for row in document["architectures"]["arm64"]["cas"] if row["architecture"] != "all"}
        self.assertFalse(amd64 & arm64)

    def test_tampered_committed_evidence_is_refused(self):
        def mutated(change):
            directory = pathlib.Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, directory)
            target = directory / "evidence"
            shutil.copytree(closure.EVIDENCE_DIR, target)
            change(target)
            return target

        def edit_evidence(edit):
            def change(target):
                document = json.loads((target / "evidence.json").read_text())
                edit(document)
                (target / "evidence.json").write_text(closure.canonical(document))
            return change

        def flip_lock(target):
            path = target / "amd64-apt.lock.json"
            raw = path.read_bytes()
            path.write_bytes(raw.replace(b'"requested"', b'"retained"', 1))

        def flip_inventory(target):
            path = target / "arm64-inventory.json"
            path.write_bytes(path.read_bytes().replace(b'"admitted": true', b'"admitted": false', 1))

        def ubuntu_substituted_row(document):
            row = document["architectures"]["amd64"]["cas"][0]
            row["sha256"] = hashlib.sha256(b"ubuntu").hexdigest()

        cases = [
            (flip_lock, "committed lock bytes changed"),
            (flip_inventory, "committed inventory bytes changed"),
            (edit_evidence(lambda d: d["architectures"]["amd64"].update(runs=["one", "one"])), "two distinct clean runs"),
            (edit_evidence(lambda d: d["architectures"]["arm64"]["cas"].pop()), "CAS evidence"),
            (edit_evidence(ubuntu_substituted_row), "CAS evidence differs"),
            (edit_evidence(lambda d: d["architectures"]["arm64"]["cas"][0].update(derived_sha512="0" * 128)), "CAS evidence differs"),
            (edit_evidence(lambda d: d["gaps"].pop()), "not derived from the committed inventories"),
            (edit_evidence(lambda d: d["gaps"][0].update(priority="P4")), "not derived from the committed inventories"),
            (edit_evidence(lambda d: d["freshness"].update(expires_at="2027-01-01T00:00:00Z")), "freshness expiry"),
            (edit_evidence(lambda d: d.update(pin_sha256="0" * 64)), "reviewed pin"),
            (edit_evidence(lambda d: d["keyring"].update(path="/tmp/debian.pgp")), "Signed-By path"),
            (edit_evidence(lambda d: d["architectures"]["arm64"].update(
                source_sha256=d["architectures"]["amd64"]["source_sha256"])), "reviewed deb822 source"),
        ]
        for change, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                closure.check_evidence(mutated(change))


class LockReviewTests(unittest.TestCase):
    def test_committed_locks_pass_review_and_match_signed_records(self):
        for architecture in closure.ARCHITECTURES:
            for request in closure.REQUESTS:
                lock = committed_lock(architecture, request)
                count, total = closure.review_lock(lock, PIN, architecture, request)
                self.assertEqual(count, len(lock["packages"]))
                self.assertLessEqual(total, closure.MAX_BYTES_PER_LOCK)
                self.assertEqual(len(closure.match_signed(lock, signed_records_for(lock))), count)

    def test_review_refuses_substituted_or_unbound_locks(self):
        def lock_with(edit):
            lock = committed_lock()
            edit(lock)
            return lock

        def first(lock):
            return lock["packages"][0]

        cases = [
            (lambda l: l["repositories"][0].update(signer_fingerprints=[UBUNTU_SIGNER]), "reviewed Debian key"),
            (lambda l: l["repositories"][0].update(
                signer_fingerprints=[PIN["signer"]["primary_fingerprint"], UBUNTU_SIGNER]), "reviewed Debian key"),
            (lambda l: l["repositories"][0].pop("archive_binding"), "signed SHA256 archive binding"),
            (lambda l: l["repositories"][0].update(archive_binding="published_digests"), "signed SHA256 archive binding"),
            (lambda l: l["repositories"][0]["index_identity"]["digests"][0].update(digest="0" * 64), "signed Debian index"),
            (lambda l: l.update(target_architecture="arm64"), "target architecture"),
            (lambda l: l.update(local_artifacts=[{"name": "relabelled"}]), "local artifacts"),
            (lambda l: l["repositories"].append(copy.deepcopy(l["repositories"][0])), "exactly one repository"),
            (lambda l: first(l).pop("derived_archive_identity"), "derived SHA512 provenance"),
            (lambda l: first(l)["derived_archive_identity"].update(provenance="signed_sha512"), "derived SHA512 provenance"),
            (lambda l: first(l)["derived_archive_identity"].update(algorithm="sha256"), "derived SHA512 provenance"),
            (lambda l: first(l)["derived_archive_identity"].update(digest="0" * 64), "derived SHA512 provenance"),
            (lambda l: first(l)["archive_identity"].update(
                primary="sha512",
                digests=[{"algorithm": "sha512", "digest": first(l)["derived_archive_identity"]["digest"]}],
            ), "signed SHA256 alone"),
            (lambda l: first(l)["archive_identity"]["digests"].append(
                {"algorithm": "sha512", "digest": first(l)["derived_archive_identity"]["digest"]}), "signed SHA256 alone"),
            (lambda l: first(l)["origin"].update(repository_id="0" * 64), "bound Debian repository"),
            (lambda l: first(l)["origin"].update(type="local_artifact"), "bound Debian repository"),
            (lambda l: first(l).update(architecture="i386"), "foreign package architecture"),
            (lambda l: first(l).update(declared_size=0), "declared size"),
            (lambda l: first(l).update(declared_size=closure.MAX_BYTES_PER_LOCK), "exceed the reviewed bound"),
            (lambda l: l["packages"].reverse(), "canonically ordered"),
            (lambda l: l["packages"].append(copy.deepcopy(l["packages"][-1])), "canonically ordered"),
            (lambda l: [p.update(retention="dependency") for p in l["packages"]], "exactly the reviewed request"),
            (lambda l: l.update(packages=[]), "outside the reviewed bound"),
            (lambda l: l.update(version=2), "exact-closure-lock v3"),
        ]
        for edit, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                closure.review_lock(lock_with(edit), PIN, "amd64", "apt")
        with self.assertRaisesRegex(ValueError, "exactly the reviewed request"):
            closure.review_lock(committed_lock(), PIN, "amd64", "systemd-sysv")
        many = committed_lock()
        many["packages"] = [
            {**many["packages"][0], "name": f"p{index:04d}", "retention": "requested" if index == 0 else "dependency"}
            for index in range(closure.MAX_PACKAGES_PER_LOCK + 1)
        ]
        with self.assertRaisesRegex(ValueError, "outside the reviewed bound"):
            closure.review_lock(many, PIN, "amd64", "p0000")

    def test_ubuntu_or_mismatched_archives_never_match_the_signed_debian_index(self):
        lock = committed_lock()
        records = signed_records_for(lock)
        key = next(iter(records))
        cases = [
            ({**records, key: {**records[key], "sha256": hashlib.sha256(b"ubuntu").hexdigest()}}, "differs from the signed Debian record"),
            ({**records, key: {**records[key], "size": records[key]["size"] + 1}}, "differs from the signed Debian record"),
            ({**records, key: {**records[key], "filename": "../ubuntu/pool/main/a/apt.deb"}}, "outside the Debian pool"),
            ({name: record for name, record in records.items() if name != key}, "absent from the signed Debian index"),
        ]
        for substituted, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                closure.match_signed(lock, substituted)
        ubuntu = copy.deepcopy(lock)
        ubuntu["packages"][0]["version"] += "ubuntu1"
        with self.assertRaisesRegex(ValueError, "absent from the signed Debian index"):
            closure.match_signed(ubuntu, records)

    def test_signed_records_bind_filename_size_and_sha256_and_refuse_repeats(self):
        paragraphs = (
            b"Package: apt\nVersion: 3\nArchitecture: amd64\nFilename: pool/main/a/apt/apt_3_amd64.deb\n"
            b"Size: 10\nSHA256: " + b"0" * 64 + b"\n\n"
        )
        compressed = lzma.compress(paragraphs)
        index = {"index_size": len(compressed), "index_sha256": closure.sha256(compressed), "package_records": 1}
        self.assertEqual(
            closure.signed_records(compressed, index),
            {("apt", "3", "amd64"): {"filename": "pool/main/a/apt/apt_3_amd64.deb", "size": 10, "sha256": "0" * 64}},
        )
        repeated = lzma.compress(paragraphs * 2)
        with self.assertRaisesRegex(ValueError, "repeats"):
            closure.signed_records(repeated, {
                "index_size": len(repeated), "index_sha256": closure.sha256(repeated), "package_records": 2,
            })
        with self.assertRaisesRegex(ValueError, "signed Release identity"):
            closure.signed_records(lzma.compress(paragraphs.replace(b"Size: 10", b"Size: 11")), index)


class FreshnessAndHostTests(unittest.TestCase):
    def test_expired_release_refuses_before_any_network_or_workspace(self):
        expiry = datetime.datetime(2026, 10, 13, 7, 55, 41, tzinfo=UTC)
        self.assertEqual(closure.release_expiry(PIN), expiry)
        self.assertEqual(closure.require_fresh(PIN, expiry), expiry)
        workspace = ROOT / ".tmp" / "debian-261-closure-expired-test"
        args = argparse.Namespace(
            debz=ROOT / "missing-debz", inventory=ROOT / "missing-inventory",
            architecture="amd64", workspace=workspace,
        )
        with mock.patch.object(closure.readiness, "fetch", side_effect=AssertionError("network used")):
            with self.assertRaisesRegex(ValueError, "expired at 2026-10-13T07:55:41"):
                closure.run(args, expiry + datetime.timedelta(seconds=1))
        self.assertFalse(workspace.exists())
        pinned = copy.deepcopy(PIN)
        pinned["release"]["valid_until"] = "Sat, 12 Dec 2026 07:55:41 UTC"
        with self.assertRaisesRegex(ValueError, "Valid-Until"):
            closure.release_expiry(pinned)

    def test_keyring_must_be_exact_root_owned_regular_file_without_links(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            closure.verify_keyring("keyring.pgp", b"key")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "debian.pgp"
            path.write_bytes(b"key")
            with self.assertRaisesRegex(ValueError, "root-owned"):
                closure.verify_keyring(path, b"key")
        if os.path.islink("/proc/self") and os.lstat("/").st_uid == os.lstat("/proc").st_uid == 0 \
                and not os.lstat("/").st_mode & 0o022:
            with self.assertRaisesRegex(ValueError, "symlink"):
                closure.verify_keyring("/proc/self/exe", b"key")
        passwd = pathlib.Path("/etc/passwd")
        if passwd.is_file() and all(os.lstat(part).st_uid == 0 and not os.lstat(part).st_mode & 0o022
                                    for part in ("/", "/etc", passwd)):
            with self.assertRaisesRegex(ValueError, "differs from the reviewed official key"):
                closure.verify_keyring(passwd, b"not the Debian key")
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                closure.verify_keyring("/etc", b"key")

    def test_retry_lines_are_the_only_permitted_stderr(self):
        for line in (
            "debz acquisition retry failed_attempt=1/6 delay_ms=2000 error=NameServerFailure",
            "debz acquisition retry failed_attempt=6/6 delay_ms=64000 http_status=503",
        ):
            self.assertIsNotNone(closure.RETRY_LINE.fullmatch(line))
        for line in (
            "debz acquisition retry failed_attempt=1/6 delay_ms=2000 http_status=404",
            "debz acquisition retry failed_attempt=7/6 delay_ms=2000 error=Timeout",
            "debz acquisition retry failed_attempt=1/6 delay_ms=0 error=Timeout",
            "warning: using unsigned index",
            "debz acquisition retry failed_attempt=1/6 delay_ms=2000 error=x y",
        ):
            self.assertIsNone(closure.RETRY_LINE.fullmatch(line))

    def test_workspace_must_be_new_child_of_checkout_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "new direct child"):
                closure.new_workspace(pathlib.Path(directory) / "run")
        with self.assertRaisesRegex(ValueError, "new direct child"):
            closure.new_workspace(ROOT / ".tmp" / "nested" / "run")


class ComparisonAndGapTests(unittest.TestCase):
    def workspace(self, closure_document, files):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        evidence = directory / "evidence"
        evidence.mkdir()
        (evidence / "closure.json").write_text(closure.canonical(closure_document))
        for name, data in files.items():
            (evidence / name).write_bytes(data)
        return directory

    def test_clean_runs_must_agree_byte_for_byte(self):
        files = {f"{request}.lock.json": request.encode() for request in closure.REQUESTS}
        files.update({"cas.json": b"[]\n", "inventory.json": b"{}\n"})
        document = {"architecture": "amd64", "locks": {}}
        first = self.workspace(document, files)
        self.assertEqual(closure.compare_runs(first, self.workspace(document, files)), document)
        with self.assertRaisesRegex(ValueError, "run evidence differs"):
            closure.compare_runs(first, self.workspace({**document, "cas_sha256": "0"}, files))
        for name in files:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, f"{name} differs"):
                closure.compare_runs(first, self.workspace(document, {**files, name: b"changed"}))

    def test_gap_list_is_prioritized_and_consistent(self):
        def inventory(*gaps):
            return {"packages": [{"package": name, "gaps": [
                {"priority": priority, "category": category, "evidence": [f"postinst:{category}"]}
            ]} for name, priority, category in gaps]}

        gaps = closure.aggregate_gaps({
            "arm64": inventory(("libc6", "P3", "ldconfig"), ("bash", "P1", "alternatives_script_authority")),
            "amd64": inventory(("tar", "P1", "alternatives_script_authority"), ("base-files", "P4", "ownership_and_mode")),
        })
        self.assertEqual(
            [(gap["priority"], gap["category"]) for gap in gaps],
            [("P1", "alternatives_script_authority"), ("P3", "ldconfig"), ("P4", "ownership_and_mode")],
        )
        self.assertEqual(gaps[0]["packages"], {"amd64": ["tar"], "arm64": ["bash"]})
        self.assertEqual(gaps[0]["native_status"], closure.CATEGORY_STATUS["alternatives_script_authority"])
        with self.assertRaisesRegex(ValueError, "inconsistent priority"):
            closure.aggregate_gaps({
                "amd64": inventory(("tar", "P1", "ldconfig")),
                "arm64": inventory(("tar", "P3", "ldconfig")),
            })
        with self.assertRaises(KeyError):
            closure.aggregate_gaps({"amd64": inventory(("tar", "P1", "unreviewed_category"))})


if __name__ == "__main__":
    unittest.main()
