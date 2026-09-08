#!/usr/bin/env python3
# Copyright 2026 debz contributors
# SPDX-License-Identifier: Apache-2.0

import copy
import json
import pathlib
import unittest

import jsonschema
from referencing import Registry, Resource


ROOT = pathlib.Path(__file__).resolve().parents[1]


class AptSystemResultSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v1 = json.loads(
            (ROOT / "schema/apt-system-result-v1.json").read_text()
        )
        cls.v2 = json.loads(
            (ROOT / "schema/apt-system-result-v2.json").read_text()
        )
        cls.request = json.loads(
            (ROOT / "schema/apt-system-request-v1.json").read_text()
        )
        v1_resource = Resource.from_contents(cls.v1)
        cls.registry = Registry().with_resources(
            [
                (cls.v1["$id"], v1_resource),
                (
                    "https://debz.dev/schema/apt-system-result-v1.json",
                    v1_resource,
                ),
            ]
        )
        cls.validator = jsonschema.Draft202012Validator(
            cls.v2,
            registry=cls.registry,
        )
        cls.request_validator = jsonschema.Draft202012Validator(cls.request)

    @staticmethod
    def confirmation() -> dict:
        digest = "11" * 32
        return {
            "schema": "https://debz.dev/schema/apt-system-result-v2",
            "version": 2,
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
        self.validator.validate(document)

    def test_exactly_one_confirmation_diagnostic_passes(self) -> None:
        self.validate(self.confirmation())

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

    def test_request_and_result_package_grammar_match_boundaries(self) -> None:
        punctuation = "+-.:="
        valid = ["a", "Z", "0"] + [f"a{value}" for value in punctuation]
        invalid = list(punctuation) + ["é", "\x1f", "a/b", "a_"]
        invalid.append("a" * 256)

        for package in valid + invalid:
            request = {
                "schema": "https://debz.dev/schema/apt-system-request-v1",
                "version": 1,
                "api_version": 1,
                "operation": "install",
                "profile_path": "/profile.json",
                "packages": [package],
                "assume_yes": False,
            }
            result = self.confirmation()
            result["items"][0]["package"] = package
            request_valid = self.request_validator.is_valid(request)
            result_valid = self.validator.is_valid(result)
            self.assertEqual(request_valid, result_valid, package)
            self.assertEqual(package in valid, request_valid, package)

    def test_unknown_mutation_status_is_v2_without_fabricated_evidence(self) -> None:
        document = self.confirmation()
        document.pop("items")
        document["mutation_status"] = "unknown"
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


if __name__ == "__main__":
    unittest.main()
