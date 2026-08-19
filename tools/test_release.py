#!/usr/bin/env python3
# Copyright 2026 debz contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for deterministic debz release tooling."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("debz_release", ROOT / "tools/release.py")
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix=".release-test-", dir=ROOT)
        self.root = pathlib.Path(self.temporary.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(
                {
                    "allowed_production_licenses": ["Apache-2.0", "BSD-3-Clause", "0BSD"],
                    "production_dependencies": [
                        {"name": "libsolv", "version": "0.7.39", "license": "BSD-3-Clause", "source": "example"},
                        {"name": "liblzma", "minimum_version": "5.2.6", "license": "0BSD", "source": "example"},
                        {"name": "libzstd", "minimum_version": "1.5.5", "license": "BSD-3-Clause", "source": "example"},
                    ],
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prefix(self, name: str = "prefix", machine: int = 62) -> pathlib.Path:
        prefix = self.root / name
        (prefix / "bin").mkdir(parents=True)
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = machine.to_bytes(2, "little")
        (prefix / "bin/debz").write_bytes(elf)
        (prefix / "share/licenses/debz").mkdir(parents=True)
        (prefix / "share/licenses/debz/LICENSE").write_text("Apache-2.0\n")
        (prefix / "share/licenses/debz/THIRD_PARTY_NOTICES").write_text("libsolv BSD-3-Clause\n")
        return prefix

    def test_strict_tags_and_consistency(self) -> None:
        for tag in ("v0.1.0", "v1.2.3-alpha.1", "v1.2.3-rc.1+build.7"):
            self.assertEqual(release.parse_tag(tag), tag[1:])
        for tag in ("0.1.0", "v01.2.3", "v1.02.3", "v1.2", "v1.2.3-01", "v1.2.3_foo", "v"):
            with self.subTest(tag=tag), self.assertRaises(release.ReleaseError):
                release.parse_tag(tag)
        with self.assertRaises(release.ReleaseError):
            release.command_version(type("Args", (), {"tag": "v0.1.0", "expect": ["build=0.1.1"]})())

    def test_binary_archives_are_deterministic(self) -> None:
        prefix = self.prefix()
        entries, binary = release.binary_entries(prefix, "debz-0.1.0-linux-x64")
        dependencies = release.policy_dependencies(self.policy)
        release.validate_elf_platform(binary, "linux-x64")
        with self.assertRaises(release.ReleaseError):
            release.validate_elf_platform(binary, "linux-arm64")
        self.assertEqual(release.validate_dynamic_dependencies(binary, dependencies), set())
        first = self.root / "first"
        second = self.root / "second"
        release.create_release_files(first, "debz-0.1.0-linux-x64", "0.1.0", entries, 123, dependencies)
        os.utime(prefix / "bin/debz", (9999, 9999))
        release.create_release_files(second, "debz-0.1.0-linux-x64", "0.1.0", entries, 123, dependencies)
        for name in sorted(path.name for path in first.iterdir()):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)
        release.audit_archive(first / "debz-0.1.0-linux-x64.tar.gz", "binary", "0.1.0", "linux-x64")

    def test_source_is_from_commit_not_worktree(self) -> None:
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        for name, data in (
            ("LICENSE", "license"),
            ("THIRD_PARTY_NOTICES", "notices"),
            ("build.zig.zon", "zon"),
            ("source.txt", "committed"),
        ):
            (repo / name).write_text(data)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "fixture"], cwd=repo, check=True, env={**os.environ, "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
        )
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        (repo / "source.txt").write_text("dirty")
        (repo / "untracked-secret").write_text("not archived")
        entries = release.source_entries(repo, commit, "debz-0.1.0-source")
        values = {name: data for name, data, _ in entries}
        self.assertEqual(values["debz-0.1.0-source/source.txt"], b"committed")
        self.assertNotIn("debz-0.1.0-source/untracked-secret", values)
        dependencies = release.policy_dependencies(self.policy)
        first = self.root / "source-first"
        second = self.root / "source-second"
        release.create_release_files(first, "debz-0.1.0-source", "0.1.0", entries, 978307200, dependencies)
        release.create_release_files(second, "debz-0.1.0-source", "0.1.0", entries, 978307200, dependencies)
        for name in sorted(path.name for path in first.iterdir()):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)

    def test_checksum_tampering_is_rejected(self) -> None:
        asset = self.root / "asset"
        asset.write_bytes(b"good")
        sidecar = release.write_checksum(asset)
        release.validate_checksum(sidecar, asset)
        asset.write_bytes(b"bad")
        with self.assertRaises(release.ReleaseError):
            release.validate_checksum(sidecar, asset)

    def test_missing_licenses_are_rejected(self) -> None:
        prefix = self.prefix()
        (prefix / "share/licenses/debz/LICENSE").unlink()
        with self.assertRaises(release.ReleaseError):
            release.binary_entries(prefix, "debz-0.1.0-linux-x64")
        policy = json.loads(self.policy.read_text())
        del policy["production_dependencies"][0]["license"]
        self.policy.write_text(json.dumps(policy))
        with self.assertRaises(release.ReleaseError):
            release.policy_dependencies(self.policy)

    def test_unexpected_dynamic_dependency_is_rejected(self) -> None:
        original = release.elf_needed
        release.elf_needed = lambda _: {"libevil.so.1"}
        try:
            with self.assertRaisesRegex(release.ReleaseError, "libevil"):
                release.validate_dynamic_dependencies(b"ELF", release.policy_dependencies(self.policy))
        finally:
            release.elf_needed = original

    def test_unsafe_duplicate_link_and_modes_are_rejected(self) -> None:
        cases = (
            [self.info("../escape", b"x")],
            [self.info("root/file", b"x"), self.info("root/file", b"x")],
            [self.info("root/link", b"", tarfile.SYMTYPE)],
            [self.info("root/file", b"x", mode=0o777)],
        )
        for index, members in enumerate(cases):
            path = self.root / f"unsafe-{index}.tar"
            with tarfile.open(path, "w") as archive:
                for info, data in members:
                    archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
            with self.subTest(index=index), self.assertRaises(release.ReleaseError):
                release.archive_entries(path)

    def test_unexpected_binary_install_path_is_rejected(self) -> None:
        entries, _ = release.binary_entries(self.prefix(), "debz-0.1.0-linux-x64")
        entries.append(("debz-0.1.0-linux-x64/etc/passwd", b"x", 0o644))
        path = self.root / "unexpected.tar.gz"
        path.write_bytes(release.compress_tar(release.build_tar(entries, 123), "tar.gz"))
        with self.assertRaisesRegex(release.ReleaseError, "unexpected install path"):
            release.audit_archive(path, "binary", "0.1.0", "linux-x64")

    def test_nondeterministic_metadata_and_order_are_rejected(self) -> None:
        path = self.root / "bad-order.tar"
        with tarfile.open(path, "w") as archive:
            for name in ("root/z", "root/a"):
                info, data = self.info(name, b"x")
                archive.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(release.ReleaseError, "not sorted"):
            release.archive_entries(path)

    def test_manifest_and_sbom_are_stable_and_complete(self) -> None:
        first = release.canonical_json(release.manifest_document("v0.1.0"))
        second = release.canonical_json(release.manifest_document("v0.1.0"))
        self.assertEqual(first, second)
        manifest = json.loads(first)
        self.assertEqual(len(manifest["assets"]), 26)
        entries, _ = release.binary_entries(self.prefix(), "debz-0.1.0-linux-x64")
        sbom = release.spdx_document(
            "debz-0.1.0-linux-x64",
            "0.1.0",
            "debz-0.1.0-linux-x64.tar.gz",
            entries,
            release.policy_dependencies(self.policy),
            "0" * 64,
        )
        path = self.root / "test.spdx.json"
        path.write_bytes(release.canonical_json(sbom))
        release.verify_sbom(path, "debz-0.1.0-linux-x64.tar.gz")

    def test_complete_release_verification(self) -> None:
        output = self.root / "dist"
        dependencies = release.policy_dependencies(self.policy)
        for platform, machine in (("linux-x64", 62), ("linux-arm64", 183)):
            base = f"debz-0.1.0-{platform}"
            entries, binary = release.binary_entries(self.prefix(platform, machine), base)
            release.validate_elf_platform(binary, platform)
            release.create_release_files(output, base, "0.1.0", entries, 123, dependencies)
        source_entries = [
            ("debz-0.1.0-source/LICENSE", b"license", 0o644),
            ("debz-0.1.0-source/THIRD_PARTY_NOTICES", b"notices", 0o644),
            ("debz-0.1.0-source/build.zig.zon", b"zon", 0o644),
        ]
        release.create_release_files(
            output, "debz-0.1.0-source", "0.1.0", source_entries, 123, dependencies
        )
        manifest = release.write_manifest("v0.1.0", output)
        release.command_verify(
            type("Args", (), {"manifest": manifest, "assets": output, "smoke": False})()
        )

    @staticmethod
    def info(
        name: str, data: bytes, kind: bytes = tarfile.REGTYPE, mode: int = 0o644
    ) -> tuple[tarfile.TarInfo, bytes]:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.size = len(data) if kind == tarfile.REGTYPE else 0
        info.mode = mode
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        return info, data


if __name__ == "__main__":
    unittest.main()
