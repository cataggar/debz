#!/usr/bin/env python3
"""Bounded native acceptance outcome evidence, not a root repair or authority."""

from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from real_snapshot_reference_paths import read_root_file

STAGES = {
    "refresh": "refresh",
    "resolve-lock": "plan",
    "download": "download",
    "create": "install",
    "create-summary": "transaction-result verify",
    "reproduce-lock": "plan",
    "resolve-update-lock": "plan",
    "update": "upgrade-all",
    "injected-failure": "plan",
}


def exit_status(value: object) -> bool:
    return type(value) is int and 0 <= value <= 255


def collect_outcome(evidence: Path, workflow_outcome: str) -> tuple[dict, int]:
    stage = None
    command_status = None
    wrapper_status = None
    outcome = {
        "operation": "native",
        "exit_status": 1,
        "changed": None,
        "summary": "native acceptance evidence unavailable",
        "diagnostics": [],
        "stage": None,
        "workflow_step_outcome": workflow_outcome,
        "wrapper_exit_status": None,
        "command_exit_status": None,
        "result_exit_status": None,
        "result_available": False,
        "expected_refusal": False,
    }
    try:
        if workflow_outcome not in ("success", "failure", "cancelled", "skipped", "unavailable"):
            raise ValueError("invalid native workflow step outcome")
        marker = json.loads(read_root_file(evidence, "native-stage-v1.json", 4096))
        if not isinstance(marker, dict) or marker.get("stage") not in STAGES:
            raise ValueError("invalid latest native stage marker")
        stage = marker["stage"]
        outcome.update(stage=stage, operation=STAGES[stage])
        command_status = marker.get("command_exit_status")
        if command_status is not None and not exit_status(command_status):
            raise ValueError("invalid native command exit status")
        outcome["command_exit_status"] = command_status
        try:
            data = read_root_file(evidence, "native-wrapper-exit-status.txt", 32)
        except FileNotFoundError:
            pass  # A killed wrapper may never run its EXIT trap.
        else:
            text = data.decode("ascii").strip()
            if not text.isdecimal() or not exit_status(int(text)):
                raise ValueError("invalid native wrapper exit status")
            wrapper_status = int(text)
            outcome["wrapper_exit_status"] = wrapper_status

        result = json.loads(read_root_file(evidence, f"{stage}.json", 128 * 1024 * 1024))
        if not isinstance(result, dict):
            raise ValueError(f"{stage}.json is not a result object")
        if stage == "create-summary":
            if result.get("backend") != "native" or result.get("outcome") not in ("succeeded", "failed"):
                raise ValueError("invalid native transaction-result verification result")
            outcome.update(
                changed=False,
                summary=f"native transaction-result verification {result['outcome']}",
            )
        else:
            if (not exit_status(result.get("exit_status")) or
                type(result.get("changed")) is not bool or
                result.get("operation") != STAGES[stage] or
                not isinstance(result.get("summary"), str) or
                not isinstance(result.get("diagnostics"), list)):
                raise ValueError(f"invalid native command result: {stage}.json")
            outcome.update({key: result[key] for key in
                            ("operation", "changed", "summary", "diagnostics")})
            outcome["result_exit_status"] = result["exit_status"]
        outcome["result_available"] = True
        if command_status is None:
            raise FileNotFoundError("latest native command did not record its exit status")
        expected_refusal = stage == "injected-failure" and command_status != 0 and outcome["result_exit_status"] == 5
        outcome["expected_refusal"] = expected_refusal
        if workflow_outcome in ("skipped", "unavailable"):
            raise FileNotFoundError(f"native workflow step outcome is {workflow_outcome}")
        if workflow_outcome == "success":
            if wrapper_status != 0 or not expected_refusal:
                raise ValueError("native workflow success lacks completed wrapper/expected refusal evidence")
            outcome["exit_status"] = 0
            outcome["summary"] = "native acceptance completed; injected invalid lock was refused as expected"
        else:
            outcome["exit_status"] = (
                wrapper_status if wrapper_status else
                command_status if command_status and not expected_refusal else 1
            )
            outcome["diagnostics"] = outcome["diagnostics"] + [{
                "id": "native_acceptance_failed",
                "message": f"native workflow step {workflow_outcome}; latest attempted stage {stage}",
            }]
        return outcome, 0
    except (OSError, ValueError, TypeError, RecursionError) as error:
        unavailable = isinstance(error, FileNotFoundError)
        kind = "unavailable" if unavailable else "invalid"
        outcome["exit_status"] = wrapper_status or (command_status if exit_status(command_status) else None) or 1
        outcome["summary"] = f"native acceptance evidence {kind}: {error}"
        outcome["diagnostics"] = outcome["diagnostics"] + [{
            "id": f"native_acceptance_evidence_{kind}",
            "message": str(error),
        }]
        return outcome, 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: real_snapshot_outcome.py EVIDENCE NATIVE_STEP_OUTCOME")
    outcome, status = collect_outcome(Path(sys.argv[1]), sys.argv[2])
    print(json.dumps(outcome, indent=2))
    raise SystemExit(status)
