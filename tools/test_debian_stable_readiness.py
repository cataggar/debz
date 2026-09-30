"""Offline refusal tests for the Debian stable signed-input preflight."""

import base64
import copy
import datetime
import hashlib
import importlib.util
import json
import lzma
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "debian_stable_readiness", ROOT / "tools/debian-stable-readiness.py"
)
readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)
PIN = json.loads((ROOT / "tools/fixtures/debian-stable-readiness-v1.json").read_text())


class ReadinessTests(unittest.TestCase):
    def test_pre_decision_run_evidence_never_claims_acceptance(self):
        # Recorded before the #261 signed-SHA256 binding decision, when a
        # missing published SHA512 still exited 3.
        evidence = json.loads(
            (ROOT / "tools/fixtures/debian-stable-readiness-arm64-evidence-v1.json").read_text()
        )
        self.assertEqual(evidence["inrelease_sha256"], PIN["release"]["inrelease_sha256"])
        self.assertEqual(evidence["index_sha256"], PIN["architectures"]["arm64"]["index_sha256"])
        self.assertEqual(evidence["package_records"], PIN["architectures"]["arm64"]["package_records"])
        self.assertEqual(evidence["signed_by_sha256"], PIN["signer"]["binary_sha256"])
        self.assertEqual(evidence["sha512_package_records"], 0)
        self.assertFalse(evidence["index_published_sha512"])
        self.assertFalse(evidence["exact_lock_published"])
        self.assertTrue(evidence["install_root_empty"])
        self.assertEqual(evidence["cas_archive_count"], 0)
        self.assertEqual(len(evidence["runs"]), 2)
        self.assertEqual(len({row["refresh_repository_identity"] for row in evidence["runs"]}), 1)
        for run in evidence["runs"]:
            self.assertEqual((run["refresh_exit_status"], run["preflight_exit_status"]), (0, 3))

    def test_signed_sha256_binding_run_evidence_publishes_no_lock_or_cas(self):
        evidence = json.loads(
            (ROOT / "tools/fixtures/debian-stable-readiness-arm64-evidence-v2.json").read_text()
        )
        index = PIN["architectures"]["arm64"]
        self.assertEqual(evidence["inrelease_sha256"], PIN["release"]["inrelease_sha256"])
        self.assertEqual(evidence["index_sha256"], index["index_sha256"])
        self.assertEqual(evidence["signed_by_sha256"], PIN["signer"]["binary_sha256"])
        self.assertEqual(evidence["package_records"], index["package_records"])
        self.assertEqual(evidence["sha256_package_records"], index["package_records"])
        self.assertEqual(
            (evidence["status"], evidence["archive_binding"]),
            readiness.archive_binding(
                evidence["index_published_sha512"],
                evidence["package_records"],
                evidence["sha512_package_records"],
            ),
        )
        self.assertEqual(evidence["archive_binding"], "signed_sha256_derived_sha512")
        self.assertFalse(evidence["exact_lock_published"])
        self.assertTrue(evidence["install_root_empty"])
        self.assertEqual(evidence["cas_archive_count"], 0)
        self.assertEqual(len(evidence["runs"]), 2)
        self.assertEqual(len({row["refresh_repository_identity"] for row in evidence["runs"]}), 1)
        for run in evidence["runs"]:
            self.assertEqual((run["refresh_exit_status"], run["preflight_exit_status"]), (0, 0))

    def test_official_key_pin_never_trusts_modified_armor_or_fingerprint(self):
        body = b"\x04" + b"\x00" * 5 + b"\x01"
        binary = b"\x98" + bytes([len(body)]) + body
        armor = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
            + base64.b64encode(binary)
            + b"\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        pin = {
            "armor_sha256": readiness.sha256(armor),
            "binary_sha256": readiness.sha256(binary),
            "primary_fingerprint": hashlib.sha1(
                b"\x99" + len(body).to_bytes(2, "big") + body
            ).hexdigest(),
        }
        self.assertEqual(readiness.decode_key(armor, pin), binary)
        with self.assertRaisesRegex(ValueError, "armor digest"):
            readiness.decode_key(armor.replace(b"PUBLIC KEY", b"SECRET KEY"), pin)
        with self.assertRaisesRegex(ValueError, "fingerprint changed"):
            readiness.decode_key(armor, {**pin, "primary_fingerprint": "0" * 40})

    def test_release_pin_requires_fresh_exact_debian_suite_and_index_digest(self):
        pin = copy.deepcopy(PIN)
        index = pin["architectures"]["arm64"]
        armor = (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            "Origin: Debian\nSuite: stable\nCodename: trixie\n"
            "Date: Sat, 12 Sep 2026 07:55:41 UTC\nComponents: main\n"
            f"SHA256:\n {index['index_sha256']} {index['index_size']} {index['index_path']}\n"
            "-----BEGIN PGP SIGNATURE-----\n"
        ).encode()
        pin["release"]["inrelease_sha256"] = readiness.sha256(armor)
        now = datetime.datetime(2026, 9, 28, tzinfo=datetime.timezone.utc)
        self.assertEqual(readiness.release_index(armor, pin, "arm64", now)["SHA256"][0], index["index_sha256"])
        with self.assertRaisesRegex(ValueError, "not fresh"):
            readiness.release_index(armor, pin, "arm64", datetime.datetime(2026, 10, 15, tzinfo=datetime.timezone.utc))
        with self.assertRaisesRegex(ValueError, "InRelease digest changed"):
            readiness.release_index(armor + b"tampered", pin, "arm64", now)
        bad = copy.deepcopy(pin)
        bad["architectures"]["arm64"]["index_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "signed index SHA256"):
            readiness.release_index(armor, bad, "arm64", now)

    def test_index_counts_require_every_published_digest_and_refuse_tampering(self):
        paragraphs = (
            b"Package: example\nVersion: 1\nArchitecture: arm64\n"
            b"SHA256: " + b"0" * 64 + b"\n\n"
            b"Package: second\nVersion: 2\nArchitecture: arm64\n"
            b"SHA256: " + b"1" * 64 + b"\n\n"
        )
        compressed = lzma.compress(paragraphs)
        index = {"index_size": len(compressed), "index_sha256": readiness.sha256(compressed), "package_records": 2}
        self.assertEqual(readiness.index_counts(compressed, index), (2, 2, 0))
        self.assertEqual(
            readiness.index_counts(compressed, index, hashlib.sha512(compressed).hexdigest()),
            (2, 2, 0),
        )
        with self.assertRaisesRegex(ValueError, "signed Release SHA512"):
            readiness.index_counts(compressed, index, "0" * 128)
        with self.assertRaisesRegex(ValueError, "signed Release identity"):
            readiness.index_counts(compressed + b"tampered", index)
        with self.assertRaisesRegex(ValueError, "published SHA256"):
            readiness.index_counts(compressed, {**index, "package_records": 3})
        truncated = lzma.compress(paragraphs[:-69])
        with self.assertRaisesRegex(ValueError, "published SHA256"):
            readiness.index_counts(truncated, {**index, "index_size": len(truncated), "index_sha256": readiness.sha256(truncated)})

    def test_record_sha256_is_bound_by_the_signed_index_and_must_be_well_formed(self):
        def paragraphs(first):
            return (
                b"Package: example\nVersion: 1\nArchitecture: arm64\n"
                b"SHA256: " + first + b"\n\n"
                b"Package: second\nVersion: 2\nArchitecture: arm64\n"
                b"SHA256: " + b"1" * 64 + b"\n\n"
            )

        signed = lzma.compress(paragraphs(b"0" * 64))
        index = {"index_size": len(signed), "index_sha256": readiness.sha256(signed), "package_records": 2}
        self.assertEqual(readiness.index_counts(signed, index), (2, 2, 0))
        # A substituted archive SHA256 is not covered by the signed index identity.
        substituted = lzma.compress(paragraphs(b"2" * 64))
        with self.assertRaisesRegex(ValueError, "signed Release identity"):
            readiness.index_counts(substituted, index)
        for malformed in (b"0" * 63, b"0" * 65, b"A" * 64, b"g" * 64):
            compressed = lzma.compress(paragraphs(malformed))
            reindexed = {**index, "index_size": len(compressed), "index_sha256": readiness.sha256(compressed)}
            with self.assertRaisesRegex(ValueError, "malformed published SHA256"):
                readiness.index_counts(compressed, reindexed)

    def test_archive_binding_records_derived_sha512_only_for_sha256_signed_repositories(self):
        self.assertEqual(
            readiness.archive_binding(True, 2, 2),
            ("eligible_signed_sha512", "published_digests"),
        )
        for index_publishes_sha512 in (False, True):
            self.assertEqual(
                readiness.archive_binding(index_publishes_sha512, 2, 0),
                ("eligible_signed_sha256_derived_sha512", "signed_sha256_derived_sha512"),
            )
        for index_publishes_sha512, sha512_count in ((True, 1), (False, 1), (False, 2)):
            self.assertEqual(
                readiness.archive_binding(index_publishes_sha512, 2, sha512_count),
                ("refused_partial_published_sha512", None),
            )


if __name__ == "__main__":
    unittest.main()
