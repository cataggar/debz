#!/usr/bin/env python3
# Copyright 2026 debz contributors
# SPDX-License-Identifier: Apache-2.0

import copy
import json
import pathlib
import unittest

import jsonschema
try:
    from referencing import Registry, Resource
except ModuleNotFoundError:
    Registry = None
    Resource = None


ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED_SECURITY_TESTS = {
    "src/production_backend.zig": (
        "production workflow required_security.ownership finalization rejects a valid colliding v2 owner",
        "production workflow required_security.restart requires the authenticated exact v2 owner",
    ),
    "src/apt_system_orchestrator.zig": (
        "apt_system_orchestrator.test.required_security.valid v2 prior collision makes concurrent review publication stale",
        "apt_system_orchestrator.test.required_security.restart authenticates durable lower ownership token before review",
        "apt_system_orchestrator.test.required_security.restart cancellation requires fully verified exact owner",
        "apt_system_orchestrator.test.required_security.recovery transport failure preserves lower token for retry without second mutation",
    ),
}


class RequiredSecurityTestManifestTests(unittest.TestCase):
    def test_required_security_tests_are_selected_exactly_once(self) -> None:
        build = (ROOT / "build.zig").read_text()
        self.assertIn(
            '.filters = &.{"production workflow required_security."}',
            build,
        )
        self.assertIn(
            '.filters = &.{"apt_system_orchestrator.test.required_security."}',
            build,
        )
        selected = 0
        for relative_path, names in REQUIRED_SECURITY_TESTS.items():
            source = (ROOT / relative_path).read_text()
            for name in names:
                self.assertEqual(
                    source.count(f'test "{name}"'),
                    1,
                    f"required security test missing or duplicated: {name}",
                )
                selected += 1
        self.assertEqual(selected, 6)


class AptSystemResultSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v1 = json.loads(
            (ROOT / "schema/apt-system-result-v1.json").read_text()
        )
        cls.v2 = json.loads(
            (ROOT / "schema/apt-system-result-v2.json").read_text()
        )
        cls.v3 = json.loads(
            (ROOT / "schema/apt-system-result-v3.json").read_text()
        )
        cls.frozen_v2 = json.loads(
            (
                ROOT
                / "tools/fixtures/apt-system-result-v2-origin-main.schema.json"
            ).read_text()
        )
        cls.frozen_v2_document = json.loads(
            (
                ROOT
                / "tools/fixtures/apt-system-result-v2-origin-main.document.json"
            ).read_text()
        )
        cls.request = json.loads(
            (ROOT / "schema/apt-system-request-v1.json").read_text()
        )
        cls.frozen_request = json.loads(
            (
                ROOT
                / "tools/fixtures/apt-system-request-v1-origin-main.schema.json"
            ).read_text()
        )
        cls.frozen_request_document = json.loads(
            (
                ROOT
                / "tools/fixtures/apt-system-request-v1-origin-main.document.json"
            ).read_text()
        )
        cls.generated_v3_documents = [
            json.loads(
                (
                    ROOT
                    / "tools/fixtures/apt-system-result-v3-confirmation.document.json"
                ).read_text()
            ),
            json.loads(
                (
                    ROOT
                    / "tools/fixtures/apt-system-result-v3-unknown.document.json"
                ).read_text()
            ),
        ]
        if Registry is not None and Resource is not None:
            v1_resource = Resource.from_contents(cls.v1)
            request_resource = Resource.from_contents(cls.request)
            registry = Registry().with_resources(
                [
                    (cls.v1["$id"], v1_resource),
                    (
                        "https://debz.dev/schema/apt-system-result-v1.json",
                        v1_resource,
                    ),
                    (cls.request["$id"], request_resource),
                    (
                        "https://debz.dev/schema/apt-system-request-v1.json",
                        request_resource,
                    ),
                    ("apt-system-request-v1.json", request_resource),
                ]
            )
            cls.v2_validator = jsonschema.Draft202012Validator(
                cls.v2,
                registry=registry,
            )
            cls.v3_validator = jsonschema.Draft202012Validator(
                cls.v3,
                registry=registry,
            )
            cls.frozen_v2_validator = jsonschema.Draft202012Validator(
                cls.frozen_v2,
                registry=registry,
            )
        else:
            store = {
                cls.v1["$id"]: cls.v1,
                "https://debz.dev/schema/apt-system-result-v1.json": cls.v1,
                cls.request["$id"]: cls.request,
                "https://debz.dev/schema/apt-system-request-v1.json": cls.request,
                "apt-system-request-v1.json": cls.request,
            }
            cls.v2_validator = jsonschema.Draft202012Validator(
                cls.v2,
                resolver=jsonschema.RefResolver.from_schema(
                    cls.v2,
                    store=store,
                ),
            )
            cls.v3_validator = jsonschema.Draft202012Validator(
                cls.v3,
                resolver=jsonschema.RefResolver.from_schema(
                    cls.v3,
                    store=store,
                ),
            )
            cls.frozen_v2_validator = jsonschema.Draft202012Validator(
                cls.frozen_v2,
                resolver=jsonschema.RefResolver.from_schema(
                    cls.frozen_v2,
                    store=store,
                ),
            )
        cls.request_validator = jsonschema.Draft202012Validator(cls.request)
        cls.frozen_request_validator = jsonschema.Draft202012Validator(
            cls.frozen_request
        )

    @staticmethod
    def confirmation() -> dict:
        digest = "11" * 32
        return {
            "schema": "https://debz.dev/schema/apt-system-result-v3",
            "version": 3,
            "api_version": 1,
            "operation": "install",
            "request_sha256": digest,
            "profile": {
                "path": "/profile.json",
                "sha256": "22" * 32,
                "reference_evidence_sha256": "33" * 32,
            },
            "outcome": "usage",
            "exit_status": 2,
            "changed": False,
            "mutation_status": "unchanged",
            "recovery_context": None,
            "summary": "confirmation required",
            "items": [
                {
                    "package": "alpha",
                    "version": "1",
                    "architecture": "amd64",
                    "detail": "install",
                }
            ],
            "evidence": {
                "exact_lock": {
                    "path": "/state/exact-lock.json",
                    "schema": "io.github.cataggar.debz.exact-closure-lock.v2",
                    "version": 2,
                    "digest_sha256": "44" * 32,
                },
                "transaction_result": None,
                "root_operation_completion": None,
                "active_operation_state": "/state/apt/active-operation-v1.json",
            },
            "diagnostics": [
                {
                    "id": "confirmation_required",
                    "outcome": "usage",
                    "phase": "confirmation",
                    "message": "confirmation required",
                }
            ],
            "digest_sha256": "55" * 32,
        }

    def validate(self, document: dict) -> None:
        self.v3_validator.validate(document)

    @staticmethod
    def list_result(package: str = "alpha") -> dict:
        return {
            "schema": "https://debz.dev/schema/apt-system-result-v2",
            "version": 2,
            "api_version": 1,
            "operation": "list_installed",
            "request_sha256": "11" * 32,
            "profile": {
                "path": "/profile.json",
                "sha256": "22" * 32,
                "reference_evidence_sha256": "33" * 32,
            },
            "outcome": "success",
            "exit_status": 0,
            "changed": False,
            "summary": "installed packages",
            "items": [
                {
                    "package": package,
                    "version": "1",
                    "architecture": "amd64",
                    "detail": None,
                }
            ],
            "evidence": {
                "exact_lock": None,
                "transaction_result": None,
                "root_operation_completion": None,
                "active_operation_state": None,
            },
            "diagnostics": [],
            "digest_sha256": "44" * 32,
        }

    def test_exactly_one_confirmation_diagnostic_passes(self) -> None:
        self.validate(self.confirmation())
        wrong_phase = self.confirmation()
        wrong_phase["diagnostics"][0]["phase"] = "request"
        with self.assertRaises(jsonschema.ValidationError):
            self.validate(wrong_phase)

    def test_additional_confirmation_diagnostic_fails(self) -> None:
        document = copy.deepcopy(self.confirmation())
        document["diagnostics"].append(
            {
                "id": "invalid_request",
                "outcome": "usage",
                "phase": "request",
                "message": "extra diagnostic",
            }
        )
        with self.assertRaises(jsonschema.ValidationError):
            self.validate(document)
        document["evidence"]["active_operation_state"] = None
        document["diagnostics"].append(copy.deepcopy(document["diagnostics"][0]))
        with self.assertRaises(jsonschema.ValidationError):
            self.validate(document)

    def test_request_and_result_package_grammar_preserve_distinct_contracts(self) -> None:
        punctuation = "+-.:="
        request_only = ["+", ".", ":", "="]
        shared_valid = ["a", "Z", "0"] + [
            f"a{value}" for value in punctuation
        ]
        shared_invalid = ["-", "é", "\x1f", "a/b", "a_", "a" * 256]

        for package in request_only + shared_valid + shared_invalid:
            request = {
                "schema": "https://debz.dev/schema/apt-system-request-v1",
                "version": 1,
                "api_version": 1,
                "operation": "install",
                "profile_path": "/profile.json",
                "packages": [package],
                "assume_yes": False,
            }
            result = self.list_result(package)
            request_valid = self.request_validator.is_valid(request)
            result_valid = self.v2_validator.is_valid(result)
            self.assertEqual(
                package in request_only + shared_valid,
                request_valid,
                package,
            )
            self.assertEqual(package in shared_valid, result_valid, package)

    def test_unknown_mutation_status_is_v3_without_fabricated_evidence(self) -> None:
        document = self.confirmation()
        document.pop("items")
        document["operation"] = "recover"
        document["mutation_status"] = "unknown"
        document["recovery_context"] = {
            "profile_path": "/profile.json",
            "requested_operation": None,
            "action": None,
        }
        document["profile"] = None
        document["outcome"] = "recovery"
        document["exit_status"] = 8
        document["changed"] = False
        document["summary"] = "mutation status unknown; recovery required"
        document["evidence"] = {
            "exact_lock": None,
            "transaction_result": None,
            "root_operation_completion": None,
            "active_operation_state": None,
        }
        document["diagnostics"] = [
            {
                "id": "recovery_required",
                "outcome": "recovery",
                "phase": "recovery",
                "message": "mutation status unknown; recovery required",
            }
        ]
        self.validate(document)
        document["profile"] = {
            "path": "/profile.json",
            "sha256": "22" * 32,
            "reference_evidence_sha256": "33" * 32,
        }
        with self.assertRaises(jsonschema.ValidationError):
            self.validate(document)
        document["profile"] = None
        document["recovery_context"]["action"] = (
            "debz recover --system-profile /profile.json"
        )
        with self.assertRaises(jsonschema.ValidationError):
            self.validate(document)
        document["recovery_context"]["action"] = None
        document["diagnostics"][0]["phase"] = "state"
        with self.assertRaises(jsonschema.ValidationError):
            self.validate(document)

    def test_runtime_generated_v3_documents_validate(self) -> None:
        for document in self.generated_v3_documents:
            self.validate(document)

    def test_v2_is_frozen_and_cross_validates_old_and_new_consumers(self) -> None:
        self.assertEqual(self.frozen_v2, self.v2)
        frozen_document = self.frozen_v2_document
        self.v2_validator.validate(frozen_document)
        self.frozen_v2_validator.validate(frozen_document)

        with_status = copy.deepcopy(frozen_document)
        with_status["mutation_status"] = "unchanged"
        with self.assertRaises(jsonschema.ValidationError):
            self.v2_validator.validate(with_status)
        with self.assertRaises(jsonschema.ValidationError):
            self.frozen_v2_validator.validate(with_status)

    def test_v3_does_not_reinterpret_list_result_v2(self) -> None:
        with self.assertRaises(jsonschema.ValidationError):
            self.v3_validator.validate(self.list_result())

    def test_request_v1_is_frozen_across_old_and_new_consumers(self) -> None:
        self.assertEqual(self.frozen_request, self.request)
        self.request_validator.validate(self.frozen_request_document)
        self.frozen_request_validator.validate(self.frozen_request_document)
        for package in ["+alpha", ".alpha", ":alpha", "=alpha"]:
            document = copy.deepcopy(self.frozen_request_document)
            document["packages"] = [package]
            self.request_validator.validate(document)
            self.frozen_request_validator.validate(document)


if __name__ == "__main__":
    unittest.main()
