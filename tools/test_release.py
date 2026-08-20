#!/usr/bin/env python3
# Copyright 2026 debz contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for deterministic debz release tooling."""

from __future__ import annotations

import importlib.util
import hashlib
import gzip
import io
import json
import lzma
import os
import pathlib
import struct
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
                    "allowed_production_licenses": [
                        "Apache-2.0",
                        "BSD-3-Clause",
                        "0BSD",
                        "MIT",
                    ],
                    "production_dependencies": [
                        {
                            "name": "libsolv",
                            "version": "0.7.39",
                            "license": "BSD-3-Clause",
                            "runtime_linkage": "static_archive_in_debz",
                            "source": "example",
                        },
                        {
                            "name": "liblzma",
                            "version": "5.8.3",
                            "license": "0BSD",
                            "runtime_linkage": "static_archive_in_debz",
                            "source": "example",
                        },
                        {
                            "name": "libzstd",
                            "version": "1.6.0",
                            "license": "BSD-3-Clause",
                            "runtime_linkage": "static_archive_in_debz",
                            "source": "example",
                        },
                        {
                            "name": "musl",
                            "version": "1.2.5+zig.0.16.0.24fdd5b7a4c1",
                            "license": "MIT",
                            "runtime_linkage": "static_libc_in_debz",
                            "source": "example",
                        },
                    ],
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runtime_manifest(self) -> dict[str, object]:
        dependencies = release.policy_dependencies(self.policy)
        return {
            "schema_version": 1,
            "package": "debz",
            "linux_release_runtime": {
                "binary_kind": "fully_static",
                "libc": {
                    "implementation": "musl",
                    "linkage": "static",
                    "expectation": (
                        "musl and all required libraries are statically linked; "
                        "no target-system shared libraries are required."
                    ),
                },
                "system_libraries": [],
                "included_libraries": [
                    {
                        "name": dependency["name"],
                        "version": dependency["version"],
                        "linkage": dependency["runtime_linkage"],
                        "license": dependency["license"],
                    }
                    for dependency in dependencies
                ],
                "fully_static": True,
            },
        }

    @staticmethod
    def elf(
        machine: int = 62,
        *,
        interp: bool = False,
        needed: bool = False,
        needed_mapping_bypass: bool = False,
    ) -> bytes:
        has_dynamic = needed or needed_mapping_bypass
        program_count = 1 + int(interp) + int(has_dynamic)
        cursor = 64 + 56 * program_count
        cursor = (cursor + 7) & ~7
        interpreter = b"/lib/ld-musl-test.so.1\0" if interp else b""
        interpreter_offset = cursor
        cursor += len(interpreter)
        cursor = (cursor + 7) & ~7
        dynamic = (
            struct.pack("<qQqQ", 1, 0, 0, 0)
            if needed
            else struct.pack("<qQqQ", 0, 0, 0, 0)
            if needed_mapping_bypass
            else b""
        )
        dynamic_offset = cursor
        cursor += len(dynamic)
        cursor = (cursor + 7) & ~7
        mapped_dynamic = (
            struct.pack("<qQqQ", 1, 0, 0, 0)
            if needed_mapping_bypass
            else b""
        )
        mapped_dynamic_offset = cursor
        cursor += len(mapped_dynamic)
        binary = bytearray(cursor)
        binary[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            binary,
            16,
            2,
            machine,
            1,
            0x400000,
            64,
            0,
            0,
            64,
            56,
            program_count,
            0,
            0,
            0,
        )
        struct.pack_into(
            "<IIQQQQQQ",
            binary,
            64,
            1,
            5,
            0,
            0x400000,
            0x400000,
            len(binary),
            len(binary),
            0x1000,
        )
        header_offset = 120
        if interp:
            struct.pack_into(
                "<IIQQQQQQ",
                binary,
                header_offset,
                3,
                4,
                interpreter_offset,
                0x400000 + interpreter_offset,
                0x400000 + interpreter_offset,
                len(interpreter),
                len(interpreter),
                1,
            )
            binary[interpreter_offset : interpreter_offset + len(interpreter)] = interpreter
            header_offset += 56
        if has_dynamic:
            struct.pack_into(
                "<IIQQQQQQ",
                binary,
                header_offset,
                2,
                6,
                dynamic_offset,
                0x400000
                + (
                    mapped_dynamic_offset
                    if needed_mapping_bypass
                    else dynamic_offset
                ),
                0x400000
                + (
                    mapped_dynamic_offset
                    if needed_mapping_bypass
                    else dynamic_offset
                ),
                len(dynamic),
                len(dynamic),
                8,
            )
            binary[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
            binary[
                mapped_dynamic_offset : mapped_dynamic_offset + len(mapped_dynamic)
            ] = mapped_dynamic
        return bytes(binary)

    def prefix(
        self,
        name: str = "prefix",
        machine: int = 62,
        *,
        interp: bool = False,
        needed: bool = False,
    ) -> pathlib.Path:
        prefix = self.root / name
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin/debz").write_bytes(
            self.elf(machine, interp=interp, needed=needed)
        )
        (prefix / "share/doc/debz").mkdir(parents=True)
        (prefix / "share/doc/debz/LICENSE").write_text("Apache-2.0\n")
        (prefix / "share/doc/debz/THIRD_PARTY_NOTICES").write_text("libsolv BSD-3-Clause\n")
        (prefix / "share/debz").mkdir(parents=True)
        (prefix / "share/debz/runtime-dependencies.json").write_text(
            json.dumps(self.runtime_manifest())
        )
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
        runtime = next(data for name, data, _ in entries if name.endswith("runtime-dependencies.json"))
        release.validate_runtime_manifest(runtime, dependencies)
        release.validate_static_elf(binary, "linux-x64")
        with self.assertRaises(release.ReleaseError):
            release.validate_static_elf(binary, "linux-arm64")
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
        (prefix / "share/doc/debz/LICENSE").unlink()
        with self.assertRaises(release.ReleaseError):
            release.binary_entries(prefix, "debz-0.1.0-linux-x64")
        policy = json.loads(self.policy.read_text())
        del policy["production_dependencies"][0]["license"]
        self.policy.write_text(json.dumps(policy))
        with self.assertRaises(release.ReleaseError):
            release.policy_dependencies(self.policy)

    def test_static_x64_and_arm64_elfs_are_accepted(self) -> None:
        release.validate_static_elf(self.elf(62), "linux-x64")
        release.validate_static_elf(self.elf(183), "linux-arm64")

    def test_pt_interp_is_rejected(self) -> None:
        with self.assertRaisesRegex(release.ReleaseError, "PT_INTERP"):
            release.validate_static_elf(self.elf(62, interp=True), "linux-x64")

    def test_dt_needed_without_section_headers_is_rejected(self) -> None:
        binary = self.elf(62, needed=True)
        self.assertEqual(struct.unpack_from("<Q", binary, 40)[0], 0)
        with self.assertRaisesRegex(release.ReleaseError, "DT_NEEDED"):
            release.validate_static_elf(binary, "linux-x64")

    def test_pt_dynamic_offset_virtual_mapping_bypass_is_rejected(self) -> None:
        binary = self.elf(62, needed_mapping_bypass=True)
        self.assertEqual(struct.unpack_from("<Q", binary, 40)[0], 0)
        dynamic_offset = struct.unpack_from("<Q", binary, 128)[0]
        dynamic_address = struct.unpack_from("<Q", binary, 136)[0]
        self.assertEqual(struct.unpack_from("<q", binary, dynamic_offset)[0], 0)
        self.assertEqual(
            struct.unpack_from("<q", binary, dynamic_address - 0x400000)[0],
            1,
        )
        with self.assertRaisesRegex(release.ReleaseError, "PT_DYNAMIC"):
            release.validate_static_elf(binary, "linux-x64")

    def test_malformed_elf_is_rejected(self) -> None:
        invalid_encoding = bytearray(self.elf())
        invalid_encoding[5] = 0
        invalid_program_offset = bytearray(self.elf())
        struct.pack_into(
            "<Q", invalid_program_offset, 32, len(invalid_program_offset) + 8
        )
        invalid_dynamic_size = bytearray(self.elf(needed=True))
        struct.pack_into("<Q", invalid_dynamic_size, 152, 17)
        struct.pack_into("<Q", invalid_dynamic_size, 160, 17)
        for name, binary in (
            ("truncated", self.elf()[:63]),
            ("encoding", bytes(invalid_encoding)),
            ("program-offset", bytes(invalid_program_offset)),
            ("dynamic-size", bytes(invalid_dynamic_size)),
        ):
            with self.subTest(name=name), self.assertRaises(release.ReleaseError):
                release.validate_static_elf(binary, "linux-x64")

    def test_previous_dynamic_runtime_manifest_is_rejected(self) -> None:
        previous = self.runtime_manifest()
        linux = previous["linux_release_runtime"]
        assert isinstance(linux, dict)
        linux["binary_kind"] = "dynamically_linked"
        linux["libc"] = {
            "implementation": "glibc",
            "linkage": "dynamic",
            "expectation": "The target glibc ABI must be provided by the destination Linux system.",
        }
        linux["fully_static"] = False
        with self.assertRaisesRegex(release.ReleaseError, "static linkage model"):
            release.validate_runtime_manifest(
                release.canonical_json(previous),
                release.policy_dependencies(self.policy),
            )

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

    def test_archive_audit_accepts_portable_compression_variants(self) -> None:
        entries = [
            ("debz-0.1.0-source/LICENSE", b"license", 0o644),
            ("debz-0.1.0-source/THIRD_PARTY_NOTICES", b"notices", 0o644),
            ("debz-0.1.0-source/build.zig.zon", b"zon", 0o644),
        ]
        tar_data = release.build_tar(entries, 123)
        gzip_bytes = []
        for level in (1, 9):
            output = io.BytesIO()
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=level) as stream:
                stream.write(tar_data)
            gzip_bytes.append(output.getvalue())
        self.assertNotEqual(gzip_bytes[0], gzip_bytes[1])
        for index, data in enumerate(gzip_bytes):
            path = self.root / f"portable-{index}.tar.gz"
            path.write_bytes(data)
            release.audit_archive(path, "source", "0.1.0", None)

        xz_bytes = [lzma.compress(tar_data, format=lzma.FORMAT_XZ, preset=preset) for preset in (0, 9)]
        self.assertNotEqual(xz_bytes[0], xz_bytes[1])
        for index, data in enumerate(xz_bytes):
            path = self.root / f"portable-{index}.tar.xz"
            path.write_bytes(data)
            release.audit_archive(path, "source", "0.1.0", None)

    def test_archive_container_corruption_trailing_and_payload_mismatch_are_rejected(self) -> None:
        entries = [
            ("debz-0.1.0-source/LICENSE", b"license", 0o644),
            ("debz-0.1.0-source/THIRD_PARTY_NOTICES", b"notices", 0o644),
            ("debz-0.1.0-source/build.zig.zon", b"zon", 0o644),
        ]
        tar_data = release.build_tar(entries, 123)
        for archive_format in ("tar.gz", "tar.xz"):
            valid = release.compress_tar(tar_data, archive_format)
            cases = {
                "corrupt": valid[:-1] + bytes([valid[-1] ^ 1]),
                "trailing": valid + b"junk",
                "payload": release.compress_tar(tar_data + b"\0" * 512, archive_format),
            }
            for case, data in cases.items():
                path = self.root / f"{case}.{archive_format}"
                path.write_bytes(data)
                with self.subTest(format=archive_format, case=case), self.assertRaises(release.ReleaseError):
                    release.audit_archive(path, "source", "0.1.0", None)

        wrong_format = self.root / "wrong.tar.xz"
        wrong_format.write_bytes(release.compress_tar(tar_data, "tar.gz"))
        with self.assertRaisesRegex(release.ReleaseError, "not xz"):
            release.audit_archive(wrong_format, "source", "0.1.0", None)

        noncanonical = self.root / "timestamp.tar.gz"
        output = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=123, compresslevel=9) as stream:
            stream.write(tar_data)
        noncanonical.write_bytes(output.getvalue())
        with self.assertRaisesRegex(release.ReleaseError, "timestamp is not canonical"):
            release.audit_archive(noncanonical, "source", "0.1.0", None)

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
        dependencies = release.policy_dependencies(self.policy)
        release.verify_sbom(
            path,
            "debz-0.1.0-linux-x64.tar.gz",
            dependencies,
        )
        packages = {item["name"]: item for item in sbom["packages"]}
        self.assertEqual(
            packages["musl"]["versionInfo"],
            "1.2.5+zig.0.16.0.24fdd5b7a4c1",
        )
        self.assertEqual(packages["musl"]["licenseDeclared"], "MIT")
        sha1_values = sorted(
            checksum["checksumValue"]
            for file_entry in sbom["files"]
            for checksum in file_entry["checksums"]
            if checksum["algorithm"] == "SHA1"
        )
        expected = hashlib.sha1("".join(sha1_values).encode("ascii")).hexdigest()
        self.assertEqual(
            sbom["packages"][0]["packageVerificationCode"]["packageVerificationCodeValue"],
            expected,
        )
        missing_license = json.loads(release.canonical_json(sbom))
        del missing_license["files"][0]["licenseInfoInFiles"]
        path.write_bytes(release.canonical_json(missing_license))
        with self.assertRaisesRegex(release.ReleaseError, "licenseInfoInFiles"):
            release.verify_sbom(
                path,
                "debz-0.1.0-linux-x64.tar.gz",
                dependencies,
            )
        bad_verification = json.loads(release.canonical_json(sbom))
        bad_verification["packages"][0]["packageVerificationCode"]["packageVerificationCodeValue"] = "0" * 40
        path.write_bytes(release.canonical_json(bad_verification))
        with self.assertRaisesRegex(release.ReleaseError, "packageVerificationCode"):
            release.verify_sbom(
                path,
                "debz-0.1.0-linux-x64.tar.gz",
                dependencies,
            )
        wrong_musl = json.loads(release.canonical_json(sbom))
        next(
            package
            for package in wrong_musl["packages"]
            if package["name"] == "musl"
        )["versionInfo"] = "1.2.5"
        path.write_bytes(release.canonical_json(wrong_musl))
        with self.assertRaisesRegex(release.ReleaseError, "reviewed policy for musl"):
            release.verify_sbom(
                path,
                "debz-0.1.0-linux-x64.tar.gz",
                dependencies,
            )

    def test_archived_binary_linkage_is_revalidated(self) -> None:
        dependencies = release.policy_dependencies(self.policy)
        base = "debz-0.1.0-linux-arm64"
        entries, _ = release.binary_entries(self.prefix("wrong-arch", 62), base)
        archive = self.root / f"{base}.tar.gz"
        archive.write_bytes(release.compress_tar(release.build_tar(entries, 123), "tar.gz"))
        audited = release.audit_archive(archive, "binary", "0.1.0", "linux-arm64")
        with self.assertRaisesRegex(release.ReleaseError, "does not match"):
            release.validate_archived_binary(audited, "0.1.0", "linux-arm64", dependencies)

        prefix = self.prefix("bad-runtime", 62)
        (prefix / "share/debz/runtime-dependencies.json").write_text(
            json.dumps(
                {
                    "linux_release_runtime": {
                        "libc": {"implementation": "glibc"},
                        "system_libraries": [{"name": "libevil"}],
                        "included_libraries": [{"name": "libsolv"}],
                    }
                }
            )
        )
        base = "debz-0.1.0-linux-x64"
        entries, _ = release.binary_entries(prefix, base)
        archive = self.root / f"{base}.tar.gz"
        archive.write_bytes(release.compress_tar(release.build_tar(entries, 123), "tar.gz"))
        audited = release.audit_archive(archive, "binary", "0.1.0", "linux-x64")
        with self.assertRaisesRegex(release.ReleaseError, "differs from reviewed policy"):
            release.validate_archived_binary(audited, "0.1.0", "linux-x64", dependencies)

        entries, _ = release.binary_entries(
            self.prefix("bad-needed", 62, needed=True), base
        )
        archive.write_bytes(release.compress_tar(release.build_tar(entries, 123), "tar.gz"))
        audited = release.audit_archive(archive, "binary", "0.1.0", "linux-x64")
        with self.assertRaisesRegex(release.ReleaseError, "DT_NEEDED"):
            release.validate_archived_binary(
                audited, "0.1.0", "linux-x64", dependencies
            )

    def test_complete_release_verification(self) -> None:
        output = self.root / "dist"
        dependencies = release.policy_dependencies(self.policy)
        for platform, machine in (("linux-x64", 62), ("linux-arm64", 183)):
            base = f"debz-0.1.0-{platform}"
            entries, binary = release.binary_entries(self.prefix(platform, machine), base)
            release.validate_static_elf(binary, platform)
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
            type(
                "Args",
                (),
                {"manifest": manifest, "assets": output, "smoke": False, "policy": self.policy},
            )()
        )
        (output / "undeclared.txt").write_text("extra")
        with self.assertRaisesRegex(release.ReleaseError, "undeclared"):
            release.command_verify(
                type(
                    "Args",
                    (),
                    {"manifest": manifest, "assets": output, "smoke": False, "policy": self.policy},
                )()
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
