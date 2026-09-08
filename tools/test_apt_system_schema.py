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


if __name__ == "__main__":
    unittest.main()
