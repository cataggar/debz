#!/usr/bin/env python3
"""Synthetic tests for bounded pre-cleanup vendor-state capture."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import pathlib
import posixpath
import re
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from unittest import mock

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/capture-vendor-state.py"
REFERENCE_TOOL = ROOT / "tools/derive-vendor-state-reference.py"
REFERENCE_DIRECTORY = ROOT / "tools/fixtures/vendor-state"
REFERENCE_INDEX = REFERENCE_DIRECTORY / "index-v1.json"
REFERENCE_DOCUMENT = REFERENCE_DIRECTORY / "reference-v1.json"
REFERENCE_INDEX_SHA256 = (
    "682bff167a4bc2386ceb78fb554be0adbe6fbfab16f4eab77aff3b63af04dd34"
)
REFERENCE_DOCUMENT_SHA256 = (
    "73228f959a335956c58d48712c891ccc372082dfc4f78f4405c18a37f98efe08"
)
SPEC = importlib.util.spec_from_file_location("vendor_state_capture", TOOL)
assert SPEC and SPEC.loader
vendor_state_capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vendor_state_capture
SPEC.loader.exec_module(vendor_state_capture)
REFERENCE_SPEC = importlib.util.spec_from_file_location(
    "vendor_state_reference", REFERENCE_TOOL
)
assert REFERENCE_SPEC and REFERENCE_SPEC.loader
vendor_state_reference = importlib.util.module_from_spec(REFERENCE_SPEC)
sys.modules[REFERENCE_SPEC.name] = vendor_state_reference
REFERENCE_SPEC.loader.exec_module(vendor_state_reference)


class VendorStateCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vendor-state-capture-", dir=temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.workspace = pathlib.Path(self.temporary.name)

    def minimal_root(self, name: str) -> pathlib.Path:
        root = self.workspace / name
        (root / "var/lib/dpkg/info").mkdir(parents=True)
        return root

    def fixture_root(self, name: str, reverse: bool = False) -> pathlib.Path:
        root = self.minimal_root(name)
        info = root / "var/lib/dpkg/info"
        alternatives = root / "var/lib/dpkg/alternatives"
        etc_alternatives = root / "etc/alternatives"
        binaries = root / "usr/bin"
        manuals = root / "usr/share/man/man1"
        for directory in (alternatives, etc_alternatives, binaries, manuals):
            directory.mkdir(parents=True, exist_ok=True)

        members = [
            ("format", b"1\n", 0o644),
            ("demo.control", b"Package: demo\n", 0o644),
            ("demo.list", b"/usr/bin/editor\n", 0o644),
            ("demo.md5sums", b"0" * 32 + b"  usr/bin/editor\n", 0o644),
            ("demo.conffiles", b"/etc/demo.conf\n", 0o644),
            ("demo.triggers", b"interest /usr/share/demo\n", 0o644),
            ("demo.preinst", b"#!/bin/sh\nexit 0\n", 0o755),
            ("demo.config", b"#!/bin/sh\nexit 0\n", 0o755),
            (
                "demo.alternatives",
                (
                    b"Name: editor\n"
                    b"Link: /usr/bin/editor\n"
                    b"Alternative: /usr/bin/editor.real\n"
                ),
                0o644,
            ),
            ("demo.templates", b"Template: demo/question\n", 0o644),
            ("demo.vendor-state", b"\x00opaque vendor metadata\n", 0o640),
        ]
        for filename, contents, mode in reversed(members) if reverse else members:
            path = info / filename
            path.write_bytes(contents)
            path.chmod(mode)

        (alternatives / "editor").write_text(
            "auto\n"
            "/usr/bin/editor\n"
            "editor.1.gz\n"
            "/usr/share/man/man1/editor.1.gz\n"
            "\n"
            "/usr/bin/editor.real\n"
            "50\n"
            "/usr/share/man/man1/editor.real.1.gz\n"
        )
        editor = binaries / "editor.real"
        editor.write_bytes(b"fixture editor\n")
        editor.chmod(0o755)
        manual = manuals / "editor.real.1.gz"
        manual.write_bytes(b"fixture manual\n")
        (binaries / "editor").symlink_to("/etc/alternatives/editor")
        (manuals / "editor.1.gz").symlink_to(
            "/etc/alternatives/editor.1.gz"
        )
        (etc_alternatives / "editor").symlink_to("/usr/bin/editor.real")
        (etc_alternatives / "editor.1.gz").symlink_to(
            "/usr/share/man/man1/editor.real.1.gz"
        )
        return root

    def capture(self, root: pathlib.Path, architecture: str = "amd64", **limits: int) -> dict:
        return vendor_state_capture.capture(
            root, architecture, vendor_state_capture.Limits(**limits)
        )

    def test_capture_is_deterministic_architecture_tagged_and_complete(self) -> None:
        first = self.capture(self.fixture_root("first"))
        second = self.capture(self.fixture_root("second", reverse=True))
        self.assertEqual(
            vendor_state_capture.canonical_json(first),
            vendor_state_capture.canonical_json(second),
        )
        self.assertEqual(first["schema"], vendor_state_capture.SCHEMA)
        self.assertEqual(first["architecture"], "amd64")
        self.assertEqual(first["version"], 1)
        members = first["control_members"]["entries"]
        paths = [entry["path"] for entry in members]
        self.assertEqual(paths, sorted(paths, key=lambda value: value.encode()))
        classifications = {
            pathlib.PurePosixPath(entry["path"]).name: entry["classification"]
            for entry in members
        }
        self.assertEqual(classifications["demo.config"], "debconf-config")
        self.assertEqual(
            classifications["demo.alternatives"], "package-alternatives"
        )
        self.assertEqual(classifications["demo.vendor-state"], "unclassified")
        self.assertEqual(
            set(classifications.values()),
            set(vendor_state_capture.CLASSIFICATIONS),
        )
        counts = first["control_members"]["classification_counts"]
        self.assertEqual(sum(counts.values()), len(members))
        self.assertEqual(set(counts), set(vendor_state_capture.CLASSIFICATIONS))
        linked = {
            entry["path"]: entry for entry in first["linked_filesystem"]["entries"]
        }
        self.assertEqual(
            linked["usr/bin/editor"]["target"], "/etc/alternatives/editor"
        )
        self.assertEqual(
            linked["etc/alternatives/editor"]["target"], "/usr/bin/editor.real"
        )
        self.assertEqual(linked["usr/bin/editor.real"]["kind"], "regular")
        self.assertEqual(
            linked["usr/bin/editor.real"]["sha256"],
            hashlib.sha256(b"fixture editor\n").hexdigest(),
        )
        serialized = json.dumps(first)
        self.assertNotIn(str(self.workspace), serialized)
        self.assertNotIn("fixture editor", serialized)
        self.assertNotIn("opaque vendor metadata", serialized)
        schema = json.loads(
            (ROOT / "schema/vendor-state-inventory-v1.json").read_text()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(first)
        malformed = json.loads(json.dumps(first))
        malformed["linked_filesystem"]["entries"].append(
            {
                "path": "usr/bin/missing",
                "kind": "absent",
                "sha256": "0" * 64,
            }
        )
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate(malformed)

        arm64 = self.capture(self.fixture_root("arm64"), "arm64")
        self.assertEqual(arm64["architecture"], "arm64")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "unsupported architecture"
        ):
            self.capture(self.fixture_root("bad-architecture"), "s390x")
        for architecture in ("amd64\narm64", ["amd64"]):
            with self.subTest(architecture=architecture), self.assertRaisesRegex(
                vendor_state_capture.CaptureError, "unsupported architecture"
            ):
                vendor_state_capture.capture(
                    self.fixture_root(f"bad-architecture-{len(str(architecture))}"),
                    architecture,  # type: ignore[arg-type]
                )

    def test_pinned_vendor_state_references_are_canonical_bounded_and_private(
        self,
    ) -> None:
        raw_index = REFERENCE_INDEX.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw_index).hexdigest(), REFERENCE_INDEX_SHA256
        )
        index = json.loads(raw_index)
        self.assertEqual(
            raw_index, vendor_state_capture.canonical_json(index)
        )
        self.assertEqual(
            set(index),
            {"capture_schema", "index_version", "manifests", "source"},
        )
        self.assertEqual(index["index_version"], 1)
        self.assertEqual(
            index["capture_schema"],
            {"id": vendor_state_capture.SCHEMA, "version": 1},
        )
        self.assertEqual(
            index["source"],
            {
                "commit": "193887f0e45dc35a25768f8e58daa98318daddc9",
                "repository": "cataggar/debz",
                "snapshot_suite": "resolute",
                "snapshot_uri": (
                    "https://snapshot.ubuntu.com/ubuntu/20260816T000000Z"
                ),
                "workflow": "CI",
                "workflow_path": ".github/workflows/ci.yml",
                "workflow_run_attempt": 1,
                "workflow_run_id": 35500920816,
                "workflow_run_url": (
                    "https://github.com/cataggar/debz/actions/runs/35500920816"
                ),
            },
        )
        schema = json.loads(
            (ROOT / "schema/vendor-state-inventory-v1.json").read_text()
        )
        validator = jsonschema.Draft202012Validator(schema)
        digest = re.compile(r"^[0-9a-f]{64}$")
        credential_patterns = (
            re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----"),
            re.compile(
                rb"(?i)authorization\s*:\s*bearer\s+"
                rb"[A-Za-z0-9._~+/=-]{12,}"
            ),
            re.compile(rb"AKIA[0-9A-Z]{16}"),
            re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
        )
        ambient_needles = (
            b"/home/",
            b"/root/",
            b"/run/",
            b"/tmp/",
            b"/var/tmp/",
            b"/var/log/",
            b"/var/lib/cloud/",
            b"/var/lib/private/",
            b"/d/",
            b"GITHUB_",
            b"RUNNER_",
            b"runner-host",
            b"workspace",
            b"etc/apt/auth.conf",
            b"etc/gshadow",
            b"etc/hostname",
            b"etc/hosts",
            b"etc/machine-id",
            b"etc/resolv.conf",
            b"etc/shadow",
            b"etc/ssh/",
            b"etc/ssl/private/",
        )
        manifests: dict[str, dict] = {}
        expected_provenance = {
            "amd64": {
                "artifact_id": 10602721005,
                "artifact_sha256": (
                    "0cc352e4f75e129ebc713d28724133150ff064eaf1a5387460de951a205c52db"
                ),
                "artifact_size_bytes": 262687,
                "job_id": 106052418669,
                "manifest_path": (
                    "ubuntu-resolute-20260816T000000Z-amd64-v1.json"
                ),
                "manifest_sha256": (
                    "9ae81ea204a2cf608860451a41d477068a11ab77e8762e61e53d95bc0a70570b"
                ),
                "manifest_size_bytes": 320842,
            },
            "arm64": {
                "artifact_id": 10602163417,
                "artifact_sha256": (
                    "22c543d5191a9761b2ed4791ce67902fb6106abfaf1228a47d50c82c0dc803c6"
                ),
                "artifact_size_bytes": 262743,
                "job_id": 106052418730,
                "manifest_path": (
                    "ubuntu-resolute-20260816T000000Z-arm64-v1.json"
                ),
                "manifest_sha256": (
                    "90698d5a1eae643dfc68a0acbb38cca48b98b297453fdc5d1a10509c792fa16c"
                ),
                "manifest_size_bytes": 320842,
            },
        }
        expected_classification_counts = {
            "checksums": 177,
            "conffiles": 39,
            "control": 0,
            "debconf-config": 7,
            "format": 1,
            "maintainer-script": 186,
            "ownership-list": 177,
            "package-alternatives": 0,
            "retained-metadata": 158,
            "triggers": 84,
            "unclassified": 0,
        }
        self.assertEqual(
            [item["architecture"] for item in index["manifests"]],
            ["amd64", "arm64"],
        )
        for reference in index["manifests"]:
            architecture = reference["architecture"]
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    reference["artifact_name"],
                    f"ubuntu-real-snapshot-{architecture}",
                )
                self.assertEqual(
                    reference["artifact_member"],
                    "vendor-state-inventory-v1.json",
                )
                self.assertEqual(
                    {
                        key: reference[key]
                        for key in expected_provenance[architecture]
                    },
                    expected_provenance[architecture],
                )
                self.assertEqual(
                    set(reference),
                    {
                        "architecture",
                        "artifact_id",
                        "artifact_member",
                        "artifact_name",
                        "artifact_sha256",
                        "artifact_size_bytes",
                        "inventory",
                        "job_id",
                        "manifest_path",
                        "manifest_sha256",
                        "manifest_size_bytes",
                    },
                )
                self.assertGreater(reference["artifact_id"], 0)
                self.assertGreater(reference["job_id"], 0)
                self.assertGreater(reference["artifact_size_bytes"], 0)
                self.assertLessEqual(
                    reference["artifact_size_bytes"], 1024 * 1024
                )
                self.assertRegex(reference["artifact_sha256"], digest)
                manifest_name = pathlib.PurePosixPath(
                    reference["manifest_path"]
                )
                self.assertEqual(len(manifest_name.parts), 1)
                raw = (REFERENCE_DIRECTORY / manifest_name).read_bytes()
                self.assertEqual(len(raw), reference["manifest_size_bytes"])
                self.assertLessEqual(len(raw), 1024 * 1024)
                self.assertEqual(
                    hashlib.sha256(raw).hexdigest(),
                    reference["manifest_sha256"],
                )
                self.assertFalse(
                    any(pattern.search(raw) for pattern in credential_patterns)
                )
                self.assertFalse(
                    any(needle in raw for needle in ambient_needles)
                )
                document = json.loads(raw)
                manifests[architecture] = document
                validator.validate(document)
                self.assertEqual(document["schema"], vendor_state_capture.SCHEMA)
                self.assertEqual(document["version"], 1)
                self.assertEqual(document["architecture"], architecture)
                self.assertEqual(
                    raw, vendor_state_capture.canonical_json(document)
                )

                limits = document["limits"]
                controls = document["control_members"]["entries"]
                alternatives = document["alternatives_database"]
                requested = document["linked_filesystem"]["requested_paths"]
                linked = document["linked_filesystem"]["entries"]

                def assert_sorted_unique(values: list[str]) -> None:
                    self.assertEqual(
                        values,
                        sorted(values, key=lambda value: value.encode("utf-8")),
                    )
                    self.assertEqual(len(values), len(set(values)))

                assert_sorted_unique([item["path"] for item in controls])
                assert_sorted_unique([item["path"] for item in alternatives])
                assert_sorted_unique(requested)
                assert_sorted_unique([item["path"] for item in linked])

                counts = {
                    classification: 0
                    for classification in vendor_state_capture.CLASSIFICATIONS
                }
                control_bytes = 0
                category_paths = {
                    classification: []
                    for classification in vendor_state_capture.CLASSIFICATIONS
                }
                for item in controls:
                    path = item["path"]
                    self.assertTrue(path.startswith("var/lib/dpkg/info/"))
                    classification = vendor_state_capture._classification(
                        pathlib.PurePosixPath(path).name
                    )
                    self.assertEqual(item["classification"], classification)
                    counts[classification] += 1
                    category_paths[classification].append(path)
                    self.assertLessEqual(
                        item["size"], limits["max_metadata_file_bytes"]
                    )
                    self.assertRegex(item["sha256"], digest)
                    assert_sorted_unique(item["referenced_paths"])
                    control_bytes += item["size"]
                self.assertEqual(
                    counts,
                    document["control_members"]["classification_counts"],
                )
                self.assertEqual(counts, expected_classification_counts)
                self.assertLessEqual(
                    len(controls), limits["max_control_members"]
                )
                self.assertEqual(len(controls), 829)
                self.assertEqual(
                    [
                        pathlib.PurePosixPath(path).name
                        for path in category_paths["debconf-config"]
                    ],
                    [
                        "chrony.config",
                        "console-setup.config",
                        "debconf.config",
                        "iproute2.config",
                        "keyboard-configuration.config",
                        "locales.config",
                        "tzdata.config",
                    ],
                )
                self.assertEqual(category_paths["package-alternatives"], [])
                self.assertEqual(category_paths["unclassified"], [])

                alternatives_bytes = 0
                for item in alternatives:
                    self.assertTrue(
                        item["path"].startswith(
                            "var/lib/dpkg/alternatives/"
                        )
                    )
                    self.assertLessEqual(
                        item["size"], limits["max_metadata_file_bytes"]
                    )
                    self.assertRegex(item["sha256"], digest)
                    assert_sorted_unique(item["referenced_paths"])
                    alternatives_bytes += item["size"]
                self.assertLessEqual(
                    len(alternatives), limits["max_alternatives_records"]
                )
                self.assertEqual(len(alternatives), 14)
                self.assertLessEqual(
                    control_bytes + alternatives_bytes,
                    limits["max_total_metadata_bytes"],
                )
                self.assertLessEqual(
                    len(requested), limits["max_referenced_paths"]
                )
                self.assertEqual(len(requested), 189)

                linked_bytes = 0
                linked_kinds: dict[str, int] = {}
                for path in requested:
                    self.assertFalse(path.startswith("/"))
                    self.assertLessEqual(
                        len(path.encode("utf-8")),
                        vendor_state_capture.MAX_DOCUMENT_PATH_BYTES,
                    )
                    self.assertFalse(
                        any(
                            path == denied
                            or path.startswith(denied + "/")
                            for denied in vendor_state_capture.SENSITIVE_PATHS
                        )
                    )
                for item in linked:
                    path = item["path"]
                    self.assertFalse(path.startswith("/"))
                    self.assertFalse(
                        any(
                            path == denied
                            or path.startswith(denied + "/")
                            for denied in vendor_state_capture.SENSITIVE_PATHS
                        )
                    )
                    linked_kinds[item["kind"]] = (
                        linked_kinds.get(item["kind"], 0) + 1
                    )
                    if item["kind"] == "regular":
                        self.assertLessEqual(
                            item["size"], limits["max_linked_file_bytes"]
                        )
                        self.assertRegex(item["sha256"], digest)
                        linked_bytes += item["size"]
                    elif item["kind"] == "symlink":
                        self.assertLessEqual(
                            len(item["target"].encode("utf-8")),
                            limits["max_link_target_bytes"],
                        )
                self.assertLessEqual(
                    len(linked), limits["max_linked_entries"]
                )
                self.assertEqual(len(linked), 190)
                self.assertLessEqual(
                    linked_bytes, limits["max_total_linked_bytes"]
                )
                self.assertEqual(
                    reference["inventory"],
                    {
                        "alternatives_record_bytes": alternatives_bytes,
                        "alternatives_record_count": len(alternatives),
                        "classification_counts": counts,
                        "control_member_bytes": control_bytes,
                        "control_member_count": len(controls),
                        "linked_entry_count": len(linked),
                        "linked_entry_kind_counts": linked_kinds,
                        "linked_regular_bytes": linked_bytes,
                        "requested_path_count": len(requested),
                    },
                )

                linked_by_path = {item["path"]: item for item in linked}
                reached_entries: set[str] = set()

                def resolve_recorded_path(start: str) -> str:
                    current = start
                    seen: set[str] = set()
                    hops = 0
                    while current not in seen:
                        seen.add(current)
                        parts = current.split("/")
                        for length in range(1, len(parts) + 1):
                            prefix = "/".join(parts[:length])
                            entry = linked_by_path.get(prefix)
                            if entry is None:
                                continue
                            reached_entries.add(prefix)
                            if entry["kind"] != "symlink":
                                self.assertEqual(length, len(parts))
                                return entry["kind"]
                            target = entry["target"]
                            if target.startswith("/"):
                                resolved = posixpath.normpath(target)[1:]
                            else:
                                resolved = posixpath.normpath(
                                    posixpath.join(
                                        posixpath.dirname(prefix), target
                                    )
                                )
                            remaining = parts[length:]
                            current = (
                                posixpath.normpath(
                                    posixpath.join(resolved, *remaining)
                                )
                                if remaining
                                else resolved
                            )
                            self.assertNotIn(current, {"", "."})
                            self.assertFalse(current.startswith("/"))
                            self.assertFalse(current.startswith("../"))
                            self.assertFalse(
                                any(
                                    current == denied
                                    or current.startswith(denied + "/")
                                    for denied in vendor_state_capture.SENSITIVE_PATHS
                                )
                            )
                            hops += 1
                            self.assertLessEqual(
                                hops, limits["max_link_hops"]
                            )
                            break
                        else:
                            self.fail(
                                f"linked path has no recorded terminal: {start}"
                            )
                    self.fail(f"linked path contains a cycle: {start}")

                self.assertEqual(
                    {
                        resolve_recorded_path(path)
                        for path in requested
                    },
                    {"regular"},
                )
                self.assertEqual(reached_entries, set(linked_by_path))
                declared_paths = {
                    path
                    for item in alternatives
                    for path in item["referenced_paths"]
                }
                selector_paths = {
                    path
                    for path in requested
                    if path.startswith("etc/alternatives/")
                }
                self.assertTrue(declared_paths.isdisjoint(selector_paths))
                self.assertEqual(
                    set(requested), declared_paths | selector_paths
                )

        amd64 = manifests["amd64"]
        arm64 = manifests["arm64"]
        self.assertEqual(
            amd64["alternatives_database"],
            arm64["alternatives_database"],
        )
        self.assertEqual(
            amd64["linked_filesystem"]["requested_paths"],
            arm64["linked_filesystem"]["requested_paths"],
        )
        self.assertEqual(
            [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"size", "sha256"}
                }
                for item in amd64["linked_filesystem"]["entries"]
            ],
            [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"size", "sha256"}
                }
                for item in arm64["linked_filesystem"]["entries"]
            ],
        )

        def normalize(path: str) -> str:
            return path.replace(":amd64", ":ARCH").replace(
                ":arm64", ":ARCH"
            )

        expected_control_differences = {
            "checksums": 140,
            "conffiles": 1,
            "control": 0,
            "debconf-config": 0,
            "format": 0,
            "maintainer-script": 28,
            "ownership-list": 94,
            "package-alternatives": 0,
            "retained-metadata": 9,
            "triggers": 3,
            "unclassified": 0,
        }
        control_maps = {}
        for architecture, document in manifests.items():
            control_maps[architecture] = {
                normalize(item["path"]): {
                    **item,
                    "path": normalize(item["path"]),
                }
                for item in document["control_members"]["entries"]
            }
        self.assertEqual(
            set(control_maps["amd64"]), set(control_maps["arm64"])
        )
        observed_control_differences = {
            classification: 0
            for classification in vendor_state_capture.CLASSIFICATIONS
        }
        for path in sorted(control_maps["amd64"]):
            amd64_member = control_maps["amd64"][path]
            arm64_member = control_maps["arm64"][path]
            self.assertEqual(
                amd64_member["classification"],
                arm64_member["classification"],
            )
            changed_fields = {
                key
                for key in amd64_member
                if amd64_member[key] != arm64_member[key]
            }
            if changed_fields:
                self.assertIn(
                    changed_fields, ({"sha256"}, {"sha256", "size"})
                )
                observed_control_differences[
                    amd64_member["classification"]
                ] += 1
        self.assertEqual(
            observed_control_differences, expected_control_differences
        )

        linked_maps = {
            architecture: {
                item["path"]: item
                for item in document["linked_filesystem"]["entries"]
            }
            for architecture, document in manifests.items()
        }
        expected_linked_differences = {
            "usr/bin/less",
            "usr/bin/mawk",
            "usr/bin/more",
            "usr/bin/nc.openbsd",
            "usr/bin/sudo.ws",
            "usr/bin/vim.tiny",
            "usr/lib/cargo/bin/sudo",
            "usr/lib/cargo/bin/visudo",
            "usr/sbin/rmt-tar",
            "usr/sbin/visudo.ws",
        }
        observed_linked_differences = set()
        for path in sorted(linked_maps["amd64"]):
            amd64_entry = linked_maps["amd64"][path]
            arm64_entry = linked_maps["arm64"][path]
            changed_fields = {
                key
                for key in amd64_entry
                if amd64_entry[key] != arm64_entry[key]
            }
            if changed_fields:
                self.assertEqual(changed_fields, {"sha256", "size"})
                self.assertEqual(amd64_entry["kind"], "regular")
                observed_linked_differences.add(path)
        self.assertEqual(
            observed_linked_differences, expected_linked_differences
        )

    def test_bounds_fail_closed(self) -> None:
        root = self.fixture_root("bounds")
        (root / "var/lib/dpkg/alternatives/second").write_text(
            "/usr/bin/editor.real\n"
        )
        cases = (
            (
                {"max_control_members": 1},
                "control-member count limit exceeded",
            ),
            (
                {"max_metadata_file_bytes": 1},
                "regular file exceeds limit",
            ),
            (
                {"max_alternatives_records": 1},
                "alternatives-record count limit exceeded",
            ),
            (
                {"max_total_metadata_bytes": 1},
                "aggregate regular-file limit exceeded",
            ),
            (
                {"max_referenced_paths": 1},
                "alternative reference count limit exceeded",
            ),
            (
                {"max_link_target_bytes": 5},
                "malformed absolute alternative path",
            ),
            (
                {"max_linked_entries": 1},
                "linked-filesystem entry count limit exceeded",
            ),
            (
                {"max_linked_file_bytes": 1},
                "regular file exceeds limit",
            ),
            (
                {"max_total_linked_bytes": 1},
                "aggregate regular-file limit exceeded",
            ),
            (
                {"max_link_hops": 1},
                "symlink hop limit exceeded",
            ),
        )
        defaults = vendor_state_capture.Limits()
        for override, message in cases:
            values = {
                field.name: getattr(defaults, field.name)
                for field in vendor_state_capture.dataclasses.fields(defaults)
            }
            values.update(override)
            with self.subTest(override=override), self.assertRaisesRegex(
                vendor_state_capture.CaptureError, message
            ):
                vendor_state_capture.capture(
                    root, "amd64", vendor_state_capture.Limits(**values)
                )

    def test_invalid_integer_limits_and_oversized_paths_fail_closed(self) -> None:
        root = self.minimal_root("invalid-limits")
        defaults = vendor_state_capture.Limits()
        for value in (
            0,
            -1,
            True,
            1.5,
            vendor_state_capture.MAX_JSON_INTEGER + 1,
        ):
            values = {
                field.name: getattr(defaults, field.name)
                for field in vendor_state_capture.dataclasses.fields(defaults)
            }
            values["max_control_members"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                vendor_state_capture.CaptureError,
                "positive schema-safe integer",
            ):
                vendor_state_capture.capture(
                    root,
                    "amd64",
                    vendor_state_capture.Limits(**values),
                )

        path_root = self.minimal_root("oversized-path")
        (path_root / "var/lib/dpkg/info/demo.alternatives").write_bytes(
            b"Link: /usr/" + b"a" * vendor_state_capture.MAX_DOCUMENT_PATH_BYTES
        )
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError,
            "malformed absolute alternative path",
        ):
            self.capture(path_root)

    def test_malformed_traversal_and_credential_references_are_rejected(self) -> None:
        cases = (
            (b"\xff\n", "not UTF-8"),
            (b"Link: /usr/../etc/shadow\n", "unsafe path component"),
            (b"Link: /etc/shadow\n", "excluded state"),
            (b"Link: /home/runner/.ssh/id_ed25519\n", "excluded state"),
            (b"Link: /run/secrets/token\n", "excluded state"),
            (b"Link: /var/lib/private/token\n", "excluded state"),
            (b"Link: /d/runner/work/repository\n", "excluded state"),
            (b"Link: /usr//bin/editor\n", "malformed absolute"),
            (b"Link: /usr/bin/editor\x01\n", "control bytes"),
        )
        for index, (contents, message) in enumerate(cases):
            root = self.minimal_root(f"malformed-{index}")
            path = root / "var/lib/dpkg/info/demo.alternatives"
            path.write_bytes(contents)
            with self.subTest(contents=contents), self.assertRaisesRegex(
                vendor_state_capture.CaptureError, message
            ):
                self.capture(root)

    def test_non_sensitive_etc_alternative_is_captured(self) -> None:
        root = self.minimal_root("etc-alternative")
        root.joinpath("var/lib/dpkg/info/libnewt0.52.list").write_text(
            "/etc/newt/palette.original\n"
            "/etc/newt/palette.ubuntu\n"
        )
        records = root / "var/lib/dpkg/alternatives"
        records.mkdir()
        records.joinpath("newt-palette").write_text(
            "auto\n"
            "/etc/newt/palette\n"
            "\n"
            "/etc/newt/palette.ubuntu\n"
            "50\n"
            "/etc/newt/palette.original\n"
            "20\n"
        )
        package_link = root / "etc/newt/palette"
        package_link.parent.mkdir(parents=True)
        package_link.symlink_to("/etc/alternatives/newt-palette")
        selected_link = root / "etc/alternatives/newt-palette"
        selected_link.parent.mkdir(parents=True)
        selected_link.symlink_to("/etc/newt/palette.ubuntu")
        selected = root / "etc/newt/palette.ubuntu"
        selected.write_text("root=white,black\n")
        original = root / "etc/newt/palette.original"
        original.write_text("root=white,blue\n")

        document = self.capture(root)
        linked = {
            entry["path"]: entry
            for entry in document["linked_filesystem"]["entries"]
        }
        self.assertEqual(
            document["linked_filesystem"]["requested_paths"],
            [
                "etc/alternatives/newt-palette",
                "etc/newt/palette",
                "etc/newt/palette.original",
                "etc/newt/palette.ubuntu",
            ],
        )
        self.assertEqual(
            linked["etc/newt/palette"]["target"],
            "/etc/alternatives/newt-palette",
        )
        self.assertEqual(
            linked["etc/alternatives/newt-palette"]["target"],
            "/etc/newt/palette.ubuntu",
        )
        self.assertEqual(
            linked["etc/newt/palette.ubuntu"]["kind"], "regular"
        )
        self.assertEqual(
            linked["etc/newt/palette.ubuntu"]["sha256"],
            hashlib.sha256(b"root=white,black\n").hexdigest(),
        )
        self.assertEqual(
            linked["etc/newt/palette.original"]["kind"], "regular"
        )
        arm64 = self.capture(root, "arm64")
        self.assertEqual(
            {**document, "architecture": "arm64"},
            arm64,
        )

    def test_etc_alternatives_do_not_admit_ambient_state(self) -> None:
        ambient_root = self.minimal_root("etc-ambient")
        ambient_records = ambient_root / "var/lib/dpkg/alternatives"
        ambient_records.mkdir()
        ambient_records.joinpath("ambient").write_text("/etc/hostname\n")
        ambient = ambient_root / "etc/hostname"
        ambient.parent.mkdir()
        ambient.write_text("runner-host\n")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "unowned etc state"
        ):
            self.capture(ambient_root)

        credential_root = self.minimal_root("etc-credential")
        credential_root.joinpath(
            "var/lib/dpkg/info/credential.list"
        ).write_text("/etc/apt/auth.conf\n")
        credential_records = credential_root / "var/lib/dpkg/alternatives"
        credential_records.mkdir()
        credential_records.joinpath("credential").write_text(
            "/etc/apt/auth.conf\n"
        )
        credential = credential_root / "etc/apt/auth.conf"
        credential.parent.mkdir(parents=True)
        credential.write_text("machine example.invalid login secret\n")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "excluded state"
        ):
            self.capture(credential_root)

        wrong_link_root = self.minimal_root("etc-wrong-link")
        wrong_link_records = wrong_link_root / "var/lib/dpkg/alternatives"
        wrong_link_records.mkdir()
        wrong_link_records.joinpath("newt-palette").write_text(
            "/etc/newt/palette\n"
        )
        wrong_link = wrong_link_root / "etc/newt/palette"
        wrong_link.parent.mkdir(parents=True)
        wrong_link.symlink_to("/usr/share/newt/palette")
        wrong_target = wrong_link_root / "usr/share/newt/palette"
        wrong_target.parent.mkdir(parents=True)
        wrong_target.write_text("ambient\n")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError,
            "does not target etc/alternatives",
        ):
            self.capture(wrong_link_root)

        undeclared_root = self.minimal_root("etc-undeclared-target")
        undeclared_root.joinpath(
            "var/lib/dpkg/info/libnewt0.52.list"
        ).write_text("/etc/newt/palette.ubuntu\n")
        undeclared_records = undeclared_root / "var/lib/dpkg/alternatives"
        undeclared_records.mkdir()
        undeclared_records.joinpath("newt-palette").write_text(
            "/etc/newt/palette\n"
        )
        undeclared_link = undeclared_root / "etc/newt/palette"
        undeclared_link.parent.mkdir(parents=True)
        undeclared_link.symlink_to("/etc/alternatives/newt-palette")
        undeclared_selector = (
            undeclared_root / "etc/alternatives/newt-palette"
        )
        undeclared_selector.parent.mkdir(parents=True)
        undeclared_selector.symlink_to("/etc/newt/palette.ubuntu")
        undeclared_target = undeclared_root / "etc/newt/palette.ubuntu"
        undeclared_target.write_text("ambient\n")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "excluded state"
        ):
            self.capture(undeclared_root)

    def test_etc_alternative_hard_links_special_files_cycles_and_races_fail_closed(
        self,
    ) -> None:
        hardlink_root = self.minimal_root("etc-hardlink")
        hardlink_root.joinpath("var/lib/dpkg/info/newt.list").write_text(
            "/etc/newt/palette.ubuntu\n"
        )
        hardlink_records = hardlink_root / "var/lib/dpkg/alternatives"
        hardlink_records.mkdir()
        hardlink_records.joinpath("newt-palette").write_text(
            "/etc/newt/palette.ubuntu\n"
        )
        hardlink_target = hardlink_root / "etc/newt/palette.ubuntu"
        hardlink_target.parent.mkdir(parents=True)
        outside = self.workspace / "outside-palette"
        outside.write_text("ambient\n")
        os.link(outside, hardlink_target)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "hard-linked regular file"
        ):
            self.capture(hardlink_root)

        special_root = self.minimal_root("etc-special")
        special_root.joinpath("var/lib/dpkg/info/newt.list").write_text(
            "/etc/newt/palette.ubuntu\n"
        )
        special_records = special_root / "var/lib/dpkg/alternatives"
        special_records.mkdir()
        special_records.joinpath("newt-palette").write_text(
            "/etc/newt/palette.ubuntu\n"
        )
        special = special_root / "etc/newt/palette.ubuntu"
        special.parent.mkdir(parents=True)
        os.mkfifo(special)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError,
            "linked path is a special file",
        ):
            self.capture(special_root)

        cycle_root = self.minimal_root("etc-cycle")
        cycle_records = cycle_root / "var/lib/dpkg/alternatives"
        cycle_records.mkdir()
        cycle_records.joinpath("newt-palette").write_text(
            "/etc/newt/palette\n"
        )
        cycle_link = cycle_root / "etc/newt/palette"
        cycle_link.parent.mkdir(parents=True)
        cycle_link.symlink_to("/etc/alternatives/newt-palette")
        cycle_selector = cycle_root / "etc/alternatives/newt-palette"
        cycle_selector.parent.mkdir(parents=True)
        cycle_selector.symlink_to("/etc/newt/palette")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "symlink cycle"
        ):
            self.capture(cycle_root)

        disappearing_root = self.minimal_root("etc-disappearing")
        disappearing_root.joinpath(
            "var/lib/dpkg/info/newt.list"
        ).write_text("/etc/newt/palette.ubuntu\n")
        disappearing_records = (
            disappearing_root / "var/lib/dpkg/alternatives"
        )
        disappearing_records.mkdir()
        disappearing_records.joinpath("newt-palette").write_text(
            "/etc/newt/palette.ubuntu\n"
        )
        disappearing = disappearing_root / "etc/newt/palette.ubuntu"
        disappearing.parent.mkdir(parents=True)
        disappearing.write_text("palette\n")
        real_open = vendor_state_capture.os.open
        removed = False

        def remove_linked_before_open(
            path, flags, mode=0o777, *, dir_fd=None
        ):
            nonlocal removed
            if (
                path == "palette.ubuntu"
                and dir_fd is not None
                and not removed
            ):
                removed = True
                disappearing.unlink()
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(
            vendor_state_capture.os,
            "open",
            side_effect=remove_linked_before_open,
        ), self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "cannot open regular file"
        ):
            self.capture(disappearing_root)

    def test_hard_links_cycles_permissions_and_races_fail_closed(self) -> None:
        hardlink_root = self.minimal_root("metadata-hardlink")
        member = hardlink_root / "var/lib/dpkg/info/demo.config"
        member.write_text("public metadata\n")
        os.link(member, hardlink_root / "var/lib/dpkg/info/demo.config-copy")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "hard-linked regular file"
        ):
            self.capture(hardlink_root)

        linked_hardlink_root = self.minimal_root("linked-hardlink")
        records = linked_hardlink_root / "var/lib/dpkg/alternatives"
        records.mkdir()
        records.joinpath("editor").write_text("/usr/bin/editor\n")
        linked = linked_hardlink_root / "usr/bin/editor"
        linked.parent.mkdir(parents=True)
        outside = self.workspace / "outside-hardlink"
        outside.write_text("ambient host content")
        os.link(outside, linked)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "hard-linked regular file"
        ):
            self.capture(linked_hardlink_root)

        cycle_root = self.minimal_root("cycle")
        cycle_records = cycle_root / "var/lib/dpkg/alternatives"
        cycle_records.mkdir()
        cycle_records.joinpath("editor").write_text("/usr/bin/a\n")
        cycle_bin = cycle_root / "usr/bin"
        cycle_bin.mkdir(parents=True)
        cycle_bin.joinpath("a").symlink_to("b")
        cycle_bin.joinpath("b").symlink_to("a")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "symlink cycle"
        ):
            self.capture(cycle_root)

        denied_root = self.minimal_root("permission")
        denied = denied_root / "var/lib/dpkg/info/demo.config"
        denied.write_text("metadata\n")
        real_open = vendor_state_capture.os.open

        def deny_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == "demo.config" and dir_fd is not None:
                raise PermissionError("synthetic permission denial")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(
            vendor_state_capture.os, "open", side_effect=deny_open
        ), self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "cannot open regular file"
        ):
            self.capture(denied_root)

        race_root = self.minimal_root("race")
        raced = race_root / "var/lib/dpkg/info/demo.config"
        raced.write_text("first contents\n")
        replaced = False

        def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal replaced
            if path == "demo.config" and dir_fd is not None and not replaced:
                replaced = True
                raced.unlink()
                raced.write_text("other contents\n")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(
            vendor_state_capture.os,
            "open",
            side_effect=replace_before_open,
        ), self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "changed before hashing"
        ):
            self.capture(race_root)

        disappearing_root = self.minimal_root("disappearing")
        disappearing = (
            disappearing_root / "var/lib/dpkg/info/demo.config"
        )
        disappearing.write_text("metadata\n")
        removed = False

        def remove_before_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal removed
            if path == "demo.config" and dir_fd is not None and not removed:
                removed = True
                disappearing.unlink()
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(
            vendor_state_capture.os,
            "open",
            side_effect=remove_before_open,
        ), self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "cannot open regular file"
        ):
            self.capture(disappearing_root)

    def test_symlinks_special_files_and_ambiguous_roots_fail_closed(self) -> None:
        outside = self.workspace / "outside"
        outside.write_text("must not be read")

        info_link_root = self.minimal_root("info-link")
        (info_link_root / "var/lib/dpkg/info/demo.config").symlink_to(outside)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "not a regular file"
        ):
            self.capture(info_link_root)

        record_link_root = self.minimal_root("record-link")
        records = record_link_root / "var/lib/dpkg/alternatives"
        records.mkdir()
        (records / "editor").symlink_to(outside)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "not a regular file"
        ):
            self.capture(record_link_root)

        unsafe_link_root = self.minimal_root("unsafe-link")
        etc_alternatives = unsafe_link_root / "etc/alternatives"
        etc_alternatives.mkdir(parents=True)
        (etc_alternatives / "editor").symlink_to("../../../outside")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "escapes reference root"
        ):
            self.capture(unsafe_link_root)

        fifo_root = self.minimal_root("fifo")
        os.mkfifo(fifo_root / "var/lib/dpkg/info/demo.config")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "not a regular file"
        ):
            self.capture(fifo_root)

        linked_fifo_root = self.minimal_root("linked-fifo")
        linked_records = linked_fifo_root / "var/lib/dpkg/alternatives"
        linked_records.mkdir()
        (linked_records / "editor").write_text("/usr/bin/editor\n")
        (linked_fifo_root / "usr/bin").mkdir(parents=True)
        os.mkfifo(linked_fifo_root / "usr/bin/editor")
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "linked path is a special file"
        ):
            self.capture(linked_fifo_root)

        root_link = self.workspace / "root-link"
        root_link.symlink_to(self.minimal_root("linked-root"), target_is_directory=True)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "must be a real directory"
        ):
            self.capture(root_link)
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "ambiguous component"
        ):
            self.capture(self.workspace / "linked-root/../linked-root")

        ambient_link_root = self.minimal_root("ambient-link")
        ambient_alternatives = ambient_link_root / "etc/alternatives"
        ambient_alternatives.mkdir(parents=True)
        ambient_alternatives.joinpath("editor").symlink_to(str(outside))
        with self.assertRaisesRegex(
            vendor_state_capture.CaptureError, "excluded state"
        ):
            self.capture(ambient_link_root)

    def test_cli_requires_explicit_root_and_writes_one_new_external_artifact(self) -> None:
        root = self.fixture_root("cli")
        output = self.workspace / "vendor-state.json"
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())["architecture"], "amd64")
        repeated = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn("cannot create output", repeated.stderr)
        inside = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(root / "capture.json"),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(inside.returncode, 0)
        self.assertIn("outside the reference root", inside.stderr)
        output_parent = self.workspace / "output-parent"
        output_parent.mkdir()
        output_link = self.workspace / "output-link"
        output_link.symlink_to(output_parent, target_is_directory=True)
        linked_parent = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--reference-root",
                str(root),
                "--architecture",
                "amd64",
                "--output",
                str(output_link / "capture.json"),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(linked_parent.returncode, 0)
        self.assertIn("must be a real directory", linked_parent.stderr)
        missing_root = subprocess.run(
            [sys.executable, str(TOOL)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(missing_root.returncode, 0)

    def test_schema_identity_and_workflow_capture_order_are_pinned(self) -> None:
        schema = json.loads(
            (ROOT / "schema/vendor-state-inventory-v1.json").read_text()
        )
        self.assertEqual(schema["$id"], vendor_state_capture.SCHEMA)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow[workflow.index("  ubuntu-real-snapshot:") :]
        capture = job.index("python3 tools/capture-vendor-state.py")
        manifest_chown = job.index('sudo chown "$USER:$USER" "$manifest"')
        cleanup = job.index(
            'sudo rm -rf "$work/root" "$work/cache" || cleanup_status=$?'
        )
        ownership = job.index(
            'sudo chown -R "$USER:$USER" .real-snapshot || ownership_status=$?'
        )
        upload = job.index("      - name: Upload real acceptance evidence")
        self.assertIn("      - name: Collect diagnostics and clean staged payloads\n"
                      "        if: always()", job)
        self.assertLess(capture, cleanup)
        self.assertLess(capture, manifest_chown)
        self.assertLess(manifest_chown, cleanup)
        self.assertLess(cleanup, ownership)
        self.assertLess(cleanup, upload)
        self.assertIn('if [ "$capture_status" -ne 0 ]; then', job)
        self.assertIn('if [ "$cleanup_status" -ne 0 ]; then', job)
        self.assertIn('exit "$ownership_status"', job)
        self.assertIn(
            "      - name: Upload real acceptance evidence\n"
            "        if: always()",
            job,
        )
        self.assertIn(
            "path: .real-snapshot/${{ matrix.architecture }}/evidence/", job
        )
        self.assertIn(
            'sudo tee "$work/evidence/disk-usage-final.txt" >/dev/null', job
        )
        build = (ROOT / "build.zig").read_text()
        self.assertIn('"vendor-state-inventory-v1.json",', build)
        self.assertIn('"vendor-state-reference-v1.json",', build)


class VendorStateReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vendor-state-reference-", dir=temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.workspace = pathlib.Path(self.temporary.name)

    def mutated_index(
        self,
        name: str,
        mutate: Callable[[dict], None],
        architecture: str | None = "amd64",
    ) -> pathlib.Path:
        directory = self.workspace / name
        directory.mkdir()
        index = json.loads(REFERENCE_INDEX.read_text())
        for reference in index["manifests"]:
            source = REFERENCE_DIRECTORY / reference["manifest_path"]
            destination = directory / reference["manifest_path"]
            destination.write_bytes(source.read_bytes())
        selected_references = [
            item
            for item in index["manifests"]
            if architecture is None or item["architecture"] == architecture
        ]
        for selected in selected_references:
            manifest_path = directory / selected["manifest_path"]
            document = json.loads(manifest_path.read_text())
            mutate(document)
            raw = vendor_state_reference.canonical_json(document)
            manifest_path.write_bytes(raw)
            selected["manifest_size_bytes"] = len(raw)
            selected["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        index_path = directory / "index-v1.json"
        index_path.write_bytes(vendor_state_reference.canonical_json(index))
        return index_path

    def mutated_source_index(
        self,
        name: str,
        mutate: Callable[[dict], None],
    ) -> pathlib.Path:
        directory = self.workspace / name
        directory.mkdir()
        index = json.loads(REFERENCE_INDEX.read_text())
        for reference in index["manifests"]:
            source = REFERENCE_DIRECTORY / reference["manifest_path"]
            destination = directory / reference["manifest_path"]
            destination.write_bytes(source.read_bytes())
        mutate(index)
        index_path = directory / "index-v1.json"
        index_path.write_bytes(vendor_state_reference.canonical_json(index))
        return index_path

    def test_reference_is_deterministic_complete_digest_bound_and_typed(
        self,
    ) -> None:
        raw = REFERENCE_DOCUMENT.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(), REFERENCE_DOCUMENT_SHA256
        )
        document = json.loads(raw)
        self.assertEqual(
            raw, vendor_state_reference.canonical_json(document)
        )
        self.assertEqual(
            raw,
            vendor_state_reference.canonical_json(
                vendor_state_reference.derive(REFERENCE_INDEX)
            ),
        )
        checked = subprocess.run(
            [
                sys.executable,
                str(REFERENCE_TOOL),
                "--index",
                str(REFERENCE_INDEX),
                "--check",
                str(REFERENCE_DOCUMENT),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

        schema = json.loads(
            (ROOT / "schema/vendor-state-reference-v1.json").read_text()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(document)
        self.assertEqual(document["schema"], vendor_state_reference.SCHEMA)
        self.assertEqual(document["version"], 1)
        self.assertEqual(
            document["source"]["index"],
            {
                "path": "index-v1.json",
                "size": REFERENCE_INDEX.stat().st_size,
                "sha256": REFERENCE_INDEX_SHA256,
            },
        )
        self.assertEqual(
            document["source"]["capture_limits"],
            vendor_state_reference.EXPECTED_LIMITS,
        )
        indexed = {
            item["architecture"]: item
            for item in json.loads(REFERENCE_INDEX.read_text())["manifests"]
        }
        self.assertEqual(
            [
                source["architecture"]
                for source in document["source"]["manifests"]
            ],
            ["amd64", "arm64"],
        )
        for source in document["source"]["manifests"]:
            architecture = source["architecture"]
            self.assertEqual(
                source["sha256"], indexed[architecture]["manifest_sha256"]
            )
            self.assertEqual(
                source["size"], indexed[architecture]["manifest_size_bytes"]
            )
            self.assertEqual(
                source["artifact"],
                {
                    "id": indexed[architecture]["artifact_id"],
                    "name": indexed[architecture]["artifact_name"],
                    "member": indexed[architecture]["artifact_member"],
                    "size": indexed[architecture]["artifact_size_bytes"],
                    "sha256": indexed[architecture]["artifact_sha256"],
                    "job_id": indexed[architecture]["job_id"],
                },
            )

        boundary = document["boundary"]
        self.assertEqual(boundary["architectures"], ["amd64", "arm64"])
        self.assertEqual(boundary["paired_control_member_count"], 829)
        self.assertEqual(boundary["alternatives_group_count"], 14)
        self.assertEqual(boundary["requested_path_count"], 189)
        self.assertEqual(boundary["linked_entry_count"], 190)
        for architecture in ("amd64", "arm64"):
            inventory = boundary["per_architecture"][architecture]
            self.assertEqual(inventory["control_member_count"], 829)
            self.assertEqual(inventory["alternatives_record_count"], 14)
            self.assertEqual(inventory["requested_path_count"], 189)
            self.assertEqual(inventory["linked_entry_count"], 190)
            self.assertEqual(inventory["config_member_count"], 7)
            self.assertEqual(
                inventory["package_alternatives_member_count"], 0
            )
            self.assertEqual(
                inventory["unclassified_control_member_count"], 0
            )
            self.assertEqual(
                inventory["control_handling_counts"],
                {
                    "bounded-inert-retained-metadata": 158,
                    "reference-execution-required": 7,
                    "supported-typed-state": 664,
                },
            )

        controls = document["control_members"]
        identities = [item["identity"] for item in controls]
        self.assertEqual(
            identities,
            sorted(identities, key=lambda value: value.encode("utf-8")),
        )
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(len(controls), 829)
        configs = [
            item
            for item in controls
            if item["classification"] == "debconf-config"
        ]
        self.assertEqual(
            [item["identity"] for item in configs],
            [
                "chrony.config",
                "console-setup.config",
                "debconf.config",
                "iproute2.config",
                "keyboard-configuration.config",
                "locales.config",
                "tzdata.config",
            ],
        )
        for item in configs:
            self.assertEqual(item["owner"]["kind"], "package")
            self.assertEqual(
                item["handling"], "reference-execution-required"
            )
            self.assertNotEqual(
                item["reference_execution_requirement"], "none"
            )
            for architecture in ("amd64", "arm64"):
                fact = item["architectures"][architecture]
                self.assertTrue(fact["path"].endswith(".config"))
                self.assertEqual(fact["mode"], "0755")
        for item in controls:
            if item["classification"] == "debconf-config":
                continue
            self.assertIn(
                item["handling"],
                {
                    "supported-typed-state",
                    "bounded-inert-retained-metadata",
                },
            )
            self.assertEqual(item["reference_execution_requirement"], "none")
            self.assertNotEqual(item["classification"], "unclassified")

        alternatives = document["alternatives"]
        groups = alternatives["groups"]
        group_names = [item["name"] for item in groups]
        self.assertEqual(
            group_names,
            [
                "awk",
                "builtins.7.gz",
                "editor",
                "ex",
                "nc",
                "newt-palette",
                "pager",
                "rmt",
                "rview",
                "sudo",
                "vi",
                "view",
                "vtrgb",
                "which",
            ],
        )
        self.assertEqual(len(group_names), len(set(group_names)))
        for group in groups:
            self.assertEqual(
                group["record"]["path"],
                f"var/lib/dpkg/alternatives/{group['name']}",
            )
            self.assertEqual(group["ownership"]["status"], "not-captured")
            self.assertEqual(
                group["selection_mode"]["status"],
                "reference-execution-required",
            )
            self.assertEqual(
                group["priorities"]["status"],
                "reference-execution-required",
            )
            masters = [
                link
                for link in group["links"]
                if link["relationship"] == "master"
            ]
            self.assertEqual(len(masters), 1)
            self.assertEqual(
                [link["link_path"] for link in group["links"]],
                sorted(
                    (link["link_path"] for link in group["links"]),
                    key=lambda value: value.encode("utf-8"),
                ),
            )
            self.assertEqual(
                [item["path"] for item in group["candidate_paths"]],
                sorted(
                    (item["path"] for item in group["candidate_paths"]),
                    key=lambda value: value.encode("utf-8"),
                ),
            )
            self.assertEqual(
                len({link["selector_path"] for link in group["links"]}),
                len(group["links"]),
            )
            self.assertEqual(
                masters[0]["selector_path"],
                f"etc/alternatives/{group['name']}",
            )
            classified_paths = {
                item["link_path"] for item in group["links"]
            } | {item["path"] for item in group["candidate_paths"]}
            self.assertEqual(
                classified_paths, set(group["record"]["referenced_paths"])
            )
            self.assertEqual(
                len(group["record"]["referenced_paths"]),
                len(classified_paths),
            )
            for link in group["links"]:
                self.assertEqual(
                    link["ownership"]["status"], "not-captured"
                )

        requested = alternatives["requested_paths"]
        requested_names = [item["path"] for item in requested]
        self.assertEqual(len(requested), 189)
        self.assertEqual(len(requested_names), len(set(requested_names)))
        self.assertEqual(
            requested_names,
            sorted(requested_names, key=lambda value: value.encode("utf-8")),
        )
        for item in requested:
            self.assertEqual(item["chain"][-1], item["terminal_path"])
        reached = {
            path for item in requested for path in item["chain"]
        }
        linked = alternatives["linked_entries"]
        linked_names = [item["identity"] for item in linked]
        self.assertEqual(len(linked), 190)
        self.assertEqual(len(linked_names), len(set(linked_names)))
        self.assertEqual(
            linked_names,
            sorted(linked_names, key=lambda value: value.encode("utf-8")),
        )
        self.assertEqual(reached, set(linked_names))
        for item in linked:
            self.assertTrue(item["roles"])
            self.assertEqual(item["ownership"]["status"], "not-captured")
            for architecture in ("amd64", "arm64"):
                fact = item["architectures"][architecture]
                if item["kind"] == "regular":
                    self.assertRegex(fact["sha256"], r"^[0-9a-f]{64}$")
                else:
                    self.assertIn("target", fact)
        self.assertEqual(
            alternatives["retained_selector_metadata"],
            [
                {
                    "handling": "bounded-inert-retained-metadata",
                    "path": "etc/alternatives/README",
                    "rationale": (
                        "This regular etc/alternatives entry is not a selector "
                        "or alternatives database record and is retained by identity."
                    ),
                    "terminal_path": "etc/alternatives/README",
                }
            ],
        )

        differences = document["cross_architecture_differences"]
        self.assertEqual(len(differences["path_qualifications"]), 422)
        self.assertEqual(len(differences["control_content"]), 275)
        for field in ("path_qualifications", "control_content", "linked_content"):
            difference_identities = [
                item["identity"] for item in differences[field]
            ]
            self.assertEqual(
                difference_identities,
                sorted(
                    difference_identities,
                    key=lambda value: value.encode("utf-8"),
                ),
            )
        self.assertEqual(
            differences["control_content_counts"],
            {
                "checksums": 140,
                "conffiles": 1,
                "control": 0,
                "debconf-config": 0,
                "format": 0,
                "maintainer-script": 28,
                "ownership-list": 94,
                "package-alternatives": 0,
                "retained-metadata": 9,
                "triggers": 3,
                "unclassified": 0,
            },
        )
        self.assertEqual(
            [item["identity"] for item in differences["linked_content"]],
            [
                "usr/bin/less",
                "usr/bin/mawk",
                "usr/bin/more",
                "usr/bin/nc.openbsd",
                "usr/bin/sudo.ws",
                "usr/bin/vim.tiny",
                "usr/lib/cargo/bin/sudo",
                "usr/lib/cargo/bin/visudo",
                "usr/sbin/rmt-tar",
                "usr/sbin/visudo.ws",
            ],
        )
        controls_by_identity = {
            item["identity"]: item for item in controls
        }
        for difference in differences["control_content"]:
            self.assertNotIn("amd64", difference)
            self.assertNotIn("arm64", difference)
            control = controls_by_identity[difference["identity"]]
            self.assertEqual(
                difference["classification"], control["classification"]
            )
            self.assertEqual(
                difference["changed_fields"],
                [
                    field
                    for field in vendor_state_reference.CONTROL_FACT_FIELDS
                    if control["architectures"]["amd64"][field]
                    != control["architectures"]["arm64"][field]
                ],
            )
        linked_by_identity = {
            item["identity"]: item for item in linked
        }
        for difference in differences["linked_content"]:
            self.assertNotIn("amd64", difference)
            self.assertNotIn("arm64", difference)
            entry = linked_by_identity[difference["identity"]]
            self.assertEqual(difference["kind"], entry["kind"])
            self.assertEqual(
                difference["changed_fields"],
                [
                    field
                    for field in vendor_state_reference.LINKED_FACT_FIELDS
                    if entry["architectures"]["amd64"].get(field)
                    != entry["architectures"]["arm64"].get(field)
                ],
            )
        requirements = {
            item["id"]: item
            for item in document["reference_execution_requirements"]
        }
        self.assertEqual(
            set(requirements),
            {
                "debconf-config-execution",
                "alternatives-record-semantics",
                "alternatives-mutation-behavior",
            },
        )
        native_unpack = (ROOT / "src/native_unpack.zig").read_text()
        self.assertIn(
            'std.mem.endsWith(u8, entry.name, ".alternatives")',
            native_unpack,
        )
        self.assertIn(
            "if (database.model.opaque_info.len != 0)\n"
            '        return .{ .outcome = .handoff, .detail = "package_metadata" };',
            native_unpack,
        )

    def test_reference_derivation_rejects_unclassified_manifest_items(
        self,
    ) -> None:
        def mutate(document: dict) -> None:
            member = next(
                item
                for item in document["control_members"]["entries"]
                if item["classification"] == "retained-metadata"
            )
            old = member["classification"]
            member["path"] = member["path"].rsplit(".", 1)[0] + ".vendor-state"
            member["classification"] = "unclassified"
            counts = document["control_members"]["classification_counts"]
            counts[old] -= 1
            counts["unclassified"] += 1
            document["control_members"]["entries"].sort(
                key=lambda item: item["path"].encode("utf-8")
            )

        index = self.mutated_index("unclassified", mutate)
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError,
            "unclassified control member",
        ):
            vendor_state_reference.derive(index)

    def test_reference_derivation_rejects_malformed_oversized_and_unsafe_state(
        self,
    ) -> None:
        def add_uncaptured_reference(document: dict) -> None:
            references = document["alternatives_database"][0][
                "referenced_paths"
            ]
            references[0] = "usr/bin/not-captured"
            references.sort(key=lambda value: value.encode("utf-8"))

        cases = (
            (
                "malformed",
                lambda document: document["control_members"]["entries"][0].__setitem__(
                    "mode", "9999"
                ),
                "malformed mode",
                "amd64",
            ),
            (
                "oversized",
                lambda document: document["control_members"]["entries"][0].__setitem__(
                    "size",
                    document["limits"]["max_metadata_file_bytes"] + 1,
                ),
                "metadata file byte limit",
                "amd64",
            ),
            (
                "raised-limits",
                lambda document: document["limits"].__setitem__(
                    "max_metadata_file_bytes",
                    document["limits"]["max_metadata_file_bytes"] + 1,
                ),
                "capture limits changed",
                "amd64",
            ),
            (
                "traversal",
                lambda document: document["linked_filesystem"]["entries"][0].__setitem__(
                    "path", "usr/../escape"
                ),
                "unsafe path component",
                "amd64",
            ),
            (
                "escaping-symlink",
                lambda document: next(
                    item
                    for item in document["linked_filesystem"]["entries"]
                    if item["path"] == "etc/alternatives/awk"
                ).__setitem__("target", "../../../outside"),
                "escapes the reference root",
                "amd64",
            ),
            (
                "sensitive-symlink",
                lambda document: next(
                    item
                    for item in document["linked_filesystem"]["entries"]
                    if item["path"] == "etc/alternatives/awk"
                ).__setitem__("target", "/etc/shadow"),
                "excluded sensitive state",
                None,
            ),
            (
                "uncaptured-reference",
                add_uncaptured_reference,
                "references an uncaptured path",
                None,
            ),
            (
                "cycle",
                lambda document: next(
                    item
                    for item in document["linked_filesystem"]["entries"]
                    if item["path"] == "etc/alternatives/awk"
                ).__setitem__("target", "/etc/alternatives/awk"),
                "symlink cycle",
                None,
            ),
            (
                "special-file",
                lambda document: document["linked_filesystem"]["entries"].__setitem__(
                    0,
                    {
                        "path": document["linked_filesystem"]["entries"][0][
                            "path"
                        ],
                        "kind": "fifo",
                    },
                ),
                "unsupported linked entry kind",
                "amd64",
            ),
        )
        for name, mutate, message, architecture in cases:
            with self.subTest(name=name):
                index = self.mutated_index(
                    name, mutate, architecture=architecture
                )
                with self.assertRaisesRegex(
                    vendor_state_reference.DerivationError, message
                ):
                    vendor_state_reference.derive(index)

    def test_reference_derivation_rejects_unsafe_sources_and_input_files(
        self,
    ) -> None:
        private_uri = self.mutated_source_index(
            "private-uri",
            lambda index: index["source"].__setitem__(
                "snapshot_uri",
                "https://snapshot.ubuntu.com/ubuntu/20260816T000000Z?token=secret",
            ),
        )
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError, "public HTTPS URI"
        ):
            vendor_state_reference.derive(private_uri)

        symlink_directory = self.workspace / "symlink-index"
        symlink_directory.mkdir()
        symlink_index = symlink_directory / "index-v1.json"
        symlink_index.symlink_to(REFERENCE_INDEX)
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError, "not a regular file"
        ):
            vendor_state_reference.derive(symlink_index)

        fifo_directory = self.workspace / "fifo-index"
        fifo_directory.mkdir()
        fifo_index = fifo_directory / "index-v1.json"
        os.mkfifo(fifo_index)
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError, "not a regular file"
        ):
            vendor_state_reference.derive(fifo_index)

        oversized_directory = self.workspace / "oversized-index"
        oversized_directory.mkdir()
        oversized_index = oversized_directory / "index-v1.json"
        oversized_index.write_bytes(
            b" " * (vendor_state_reference.MAX_INDEX_BYTES + 1)
        )
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError, "exceeds byte limit"
        ):
            vendor_state_reference.derive(oversized_index)

        nonstandard_directory = self.workspace / "nonstandard-index"
        nonstandard_directory.mkdir()
        nonstandard_index = nonstandard_directory / "index-v1.json"
        nonstandard_index.write_bytes(b'{"source": NaN}\n')
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError,
            "non-standard JSON numeric constant",
        ):
            vendor_state_reference.derive(nonstandard_index)

        manifest_symlink = self.mutated_source_index(
            "manifest-symlink", lambda index: None
        )
        manifest_index = json.loads(manifest_symlink.read_text())
        manifest_path = (
            manifest_symlink.parent
            / manifest_index["manifests"][0]["manifest_path"]
        )
        manifest_path.unlink()
        manifest_path.symlink_to(
            REFERENCE_DIRECTORY
            / manifest_index["manifests"][0]["manifest_path"]
        )
        with self.assertRaisesRegex(
            vendor_state_reference.DerivationError,
            "amd64 manifest is not a regular file",
        ):
            vendor_state_reference.derive(manifest_symlink)


if __name__ == "__main__":
    unittest.main()
