#!/usr/bin/env python3
"""Derive the bounded vendor-state reference specification from pinned manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
from collections import Counter
from typing import Any, Callable

SCHEMA = "https://debz.dev/schema/vendor-state-reference-v1"
CAPTURE_SCHEMA = "https://debz.dev/schema/vendor-state-inventory-v1"
ARCHITECTURES = ("amd64", "arm64")
MAX_JSON_INTEGER = (1 << 53) - 1
MAX_INDEX_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PATH_BYTES = 4096
EXPECTED_CONTROL_MEMBERS = 829
EXPECTED_ALTERNATIVES_RECORDS = 14
EXPECTED_REQUESTED_PATHS = 189
EXPECTED_LINKED_ENTRIES = 190
EXPECTED_CONFIG_MEMBERS = 7
EXPECTED_CLASSIFICATION_COUNTS = {
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
CLASSIFICATIONS = tuple(EXPECTED_CLASSIFICATION_COUNTS)
MAINTAINER_SCRIPTS = frozenset({"preinst", "postinst", "prerm", "postrm"})
RETAINED_METADATA = frozenset({"templates", "shlibs", "symbols"})
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MODE = re.compile(r"^[0-7]{4}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
ARCHITECTURE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
INDEX_KEYS = frozenset({"capture_schema", "index_version", "manifests", "source"})
INDEX_MANIFEST_KEYS = frozenset(
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
    }
)
SOURCE_KEYS = frozenset(
    {
        "commit",
        "repository",
        "snapshot_suite",
        "snapshot_uri",
        "workflow",
        "workflow_path",
        "workflow_run_attempt",
        "workflow_run_id",
        "workflow_run_url",
    }
)
LIMIT_KEYS = frozenset(
    {
        "max_control_members",
        "max_alternatives_records",
        "max_metadata_file_bytes",
        "max_total_metadata_bytes",
        "max_referenced_paths",
        "max_linked_entries",
        "max_link_hops",
        "max_link_target_bytes",
        "max_linked_file_bytes",
        "max_total_linked_bytes",
    }
)
HANDLING = {
    "format": (
        "supported-typed-state",
        "The package database validates info/format as the typed format-1 marker.",
        "none",
    ),
    "control": (
        "bounded-inert-retained-metadata",
        "Installed *.control bytes are bounded opaque package metadata and are not interpreted.",
        "none",
    ),
    "ownership-list": (
        "supported-typed-state",
        "The package database parses bounded canonical ownership paths and builds the ownership index.",
        "none",
    ),
    "checksums": (
        "supported-typed-state",
        "The package database parses bounded lowercase MD5 records for logical payload paths.",
        "none",
    ),
    "conffiles": (
        "supported-typed-state",
        "The package database and native lifecycle model typed conffile declarations and digests.",
        "none",
    ),
    "triggers": (
        "supported-typed-state",
        "The package database and native lifecycle model the supported trigger declaration grammar.",
        "none",
    ),
    "maintainer-script": (
        "supported-typed-state",
        "Lifecycle scripts are typed by owner, kind, mode, size, and digest before bounded execution.",
        "none",
    ),
    "debconf-config": (
        "reference-execution-required",
        "The config script is bounded and preserved, but this manifest does not prove invocation or effects.",
        "Observe reference frontend invocation, ordering, arguments, environment, outcome, and resulting state.",
    ),
    "package-alternatives": (
        "reference-execution-required",
        "A package alternatives member has active dpkg semantics and may not be treated as inert metadata.",
        "Capture exact package-member bytes and compare reference registration and mutation behavior.",
    ),
    "retained-metadata": (
        "bounded-inert-retained-metadata",
        "templates, shlibs, and symbols are typed by owner and kind and retained byte-for-byte without interpretation.",
        "none",
    ),
}
UNKNOWN_ALTERNATIVES_OWNERSHIP = {
    "status": "not-captured",
    "rationale": (
        "The manifests do not retain package ownership lists or provider "
        "registration records for alternatives paths."
    ),
}
UNKNOWN_SELECTION_MODE = {
    "status": "reference-execution-required",
    "rationale": (
        "The manifest hashes the alternatives record but does not retain the "
        "record bytes needed to distinguish auto from manual mode."
    ),
}
UNKNOWN_PRIORITIES = {
    "status": "reference-execution-required",
    "rationale": (
        "The manifest does not retain candidate priorities or registration rows."
    ),
}
ROLE_ORDER = {
    "path-alias": 0,
    "front-link": 1,
    "selector-link": 2,
    "candidate-target": 3,
    "retained-selector-metadata": 4,
}
CONTROL_FACT_FIELDS = (
    "mode",
    "uid",
    "gid",
    "size",
    "sha256",
    "referenced_paths",
)
LINKED_FACT_FIELDS = ("mode", "uid", "gid", "size", "sha256", "target")


class DerivationError(ValueError):
    """Pinned vendor-state evidence cannot produce the bounded reference."""


def canonical_json(document: Any) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DerivationError(f"duplicate JSON object field: {key}")
        result[key] = value
    return result


def _read_document(
    path: pathlib.Path, maximum: int, label: str
) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise DerivationError(f"cannot read {label}: {path}: {error}") from error
    if len(raw) > maximum:
        raise DerivationError(f"{label} exceeds byte limit: {path}")
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DerivationError(f"{label} is not canonical UTF-8 JSON: {path}") from error
    if not isinstance(document, dict):
        raise DerivationError(f"{label} must be a JSON object: {path}")
    if canonical_json(document) != raw:
        raise DerivationError(f"{label} is not canonical JSON: {path}")
    return raw, document


def _require_keys(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise DerivationError(
            f"{label} fields differ: expected {sorted(expected)}, got {sorted(value)}"
        )


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 1 or value > MAX_JSON_INTEGER:
        raise DerivationError(f"{label} must be a positive schema-safe integer")
    return value


def _count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_JSON_INTEGER:
        raise DerivationError(f"{label} must be a schema-safe count")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DerivationError(f"{label} must be nonempty text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise DerivationError(f"{label} must be UTF-8") from error
    return value


def _digest(value: Any, label: str) -> str:
    text = _text(value, label)
    if DIGEST.fullmatch(text) is None:
        raise DerivationError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _mode(value: Any, label: str) -> str:
    text = _text(value, label)
    if MODE.fullmatch(text) is None:
        raise DerivationError(f"{label} is a malformed mode")
    return text


def _component(value: str, label: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DerivationError(f"{label} contains an unsafe path component")
    return value


def _relative_path(value: Any, label: str) -> str:
    text = _text(value, label)
    encoded = text.encode("utf-8")
    if (
        text.startswith("/")
        or text.endswith("/")
        or "//" in text
        or len(encoded) > MAX_PATH_BYTES
    ):
        if len(encoded) > MAX_PATH_BYTES:
            raise DerivationError(f"{label} exceeds path byte limit")
        raise DerivationError(f"{label} is not a bounded relative path")
    for component in text.split("/"):
        _component(component, label)
    return text


def _target_path(link_path: str, target: Any, label: str) -> str:
    text = _text(target, label)
    encoded = text.encode("utf-8")
    if (
        "\x00" in text
        or "//" in text
        or len(encoded) > MAX_PATH_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise DerivationError(f"{label} is an unsafe symlink target")
    result = [] if text.startswith("/") else link_path.split("/")[:-1]
    for component in text.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            if not result:
                raise DerivationError(f"{label} escapes the reference root")
            result.pop()
            continue
        result.append(_component(component, label))
    if not result:
        raise DerivationError(f"{label} resolves to the reference root")
    return _relative_path("/".join(result), label)


def _sorted_unique(values: Any, validator: Callable[[Any, str], str], label: str) -> list[str]:
    if not isinstance(values, list):
        raise DerivationError(f"{label} must be an array")
    checked = [validator(value, f"{label}[{index}]") for index, value in enumerate(values)]
    if checked != sorted(checked, key=lambda value: value.encode("utf-8")):
        raise DerivationError(f"{label} must be bytewise sorted")
    if len(checked) != len(set(checked)):
        raise DerivationError(f"{label} contains duplicates")
    return checked


def _classification(name: str) -> str:
    if name == "format":
        return "format"
    if "." not in name:
        return "unclassified"
    suffix = name.rsplit(".", 1)[1]
    if suffix == "control":
        return "control"
    if suffix == "list":
        return "ownership-list"
    if suffix == "md5sums":
        return "checksums"
    if suffix == "conffiles":
        return "conffiles"
    if suffix == "triggers":
        return "triggers"
    if suffix in MAINTAINER_SCRIPTS:
        return "maintainer-script"
    if suffix == "config":
        return "debconf-config"
    if suffix == "alternatives":
        return "package-alternatives"
    if suffix in RETAINED_METADATA:
        return "retained-metadata"
    return "unclassified"


def _validate_file_metadata(item: dict[str, Any], label: str) -> None:
    _relative_path(item.get("path"), f"{label}.path")
    _mode(item.get("mode"), f"{label}.mode")
    for field in ("uid", "gid"):
        value = item.get(field)
        if type(value) is not int or value < 0 or value > 4_294_967_295:
            raise DerivationError(f"{label}.{field} is outside the schema")


def _validate_metadata_file(
    item: Any, label: str, limits: dict[str, int], *, control: bool
) -> None:
    if not isinstance(item, dict):
        raise DerivationError(f"{label} must be an object")
    expected = {
        "path",
        "mode",
        "uid",
        "gid",
        "size",
        "sha256",
        "referenced_paths",
    }
    if control:
        expected.add("classification")
    _require_keys(item, frozenset(expected), label)
    _validate_file_metadata(item, label)
    size = _count(item["size"], f"{label}.size")
    if size > limits["max_metadata_file_bytes"]:
        raise DerivationError(f"{label} exceeds metadata file byte limit")
    _digest(item["sha256"], f"{label}.sha256")
    _sorted_unique(
        item["referenced_paths"], _relative_path, f"{label}.referenced_paths"
    )
    if control:
        classification = item["classification"]
        if classification not in CLASSIFICATIONS:
            raise DerivationError(f"{label} has an unknown classification")
        observed = _classification(item["path"].rsplit("/", 1)[1])
        if classification != observed:
            raise DerivationError(
                f"{label} classification mismatch: {classification} != {observed}"
            )


def _validate_linked_entry(
    item: Any, label: str, limits: dict[str, int]
) -> None:
    if not isinstance(item, dict):
        raise DerivationError(f"{label} must be an object")
    path = _relative_path(item.get("path"), f"{label}.path")
    kind = item.get("kind")
    if kind == "regular":
        _require_keys(
            item,
            frozenset({"path", "kind", "mode", "uid", "gid", "size", "sha256"}),
            label,
        )
        _validate_file_metadata(item, label)
        size = _count(item["size"], f"{label}.size")
        if size > limits["max_linked_file_bytes"]:
            raise DerivationError(f"{label} exceeds linked file byte limit")
        _digest(item["sha256"], f"{label}.sha256")
        return
    if kind == "symlink":
        _require_keys(
            item,
            frozenset({"path", "kind", "mode", "uid", "gid", "target"}),
            label,
        )
        _validate_file_metadata(item, label)
        if len(_text(item["target"], f"{label}.target").encode("utf-8")) > limits[
            "max_link_target_bytes"
        ]:
            raise DerivationError(f"{label} symlink target exceeds byte limit")
        _target_path(path, item["target"], f"{label}.target")
        return
    raise DerivationError(f"{label} has unsupported linked entry kind: {kind!r}")


def _inventory(document: dict[str, Any]) -> dict[str, Any]:
    controls = document["control_members"]["entries"]
    alternatives = document["alternatives_database"]
    linked = document["linked_filesystem"]["entries"]
    linked_kinds = Counter(item["kind"] for item in linked)
    return {
        "alternatives_record_bytes": sum(item["size"] for item in alternatives),
        "alternatives_record_count": len(alternatives),
        "classification_counts": document["control_members"][
            "classification_counts"
        ],
        "control_member_bytes": sum(item["size"] for item in controls),
        "control_member_count": len(controls),
        "linked_entry_count": len(linked),
        "linked_entry_kind_counts": dict(sorted(linked_kinds.items())),
        "linked_regular_bytes": sum(
            item["size"] for item in linked if item["kind"] == "regular"
        ),
        "requested_path_count": len(
            document["linked_filesystem"]["requested_paths"]
        ),
    }


def _validate_manifest(document: dict[str, Any], architecture: str) -> None:
    _require_keys(
        document,
        frozenset(
            {
                "schema",
                "version",
                "architecture",
                "limits",
                "control_members",
                "alternatives_database",
                "linked_filesystem",
            }
        ),
        f"{architecture} manifest",
    )
    if document["schema"] != CAPTURE_SCHEMA or document["version"] != 1:
        raise DerivationError(f"{architecture} manifest capture schema mismatch")
    if document["architecture"] != architecture:
        raise DerivationError(f"{architecture} manifest architecture mismatch")
    limits = document["limits"]
    if not isinstance(limits, dict):
        raise DerivationError(f"{architecture} limits must be an object")
    _require_keys(limits, LIMIT_KEYS, f"{architecture} limits")
    validated_limits = {
        key: _positive_integer(value, f"{architecture}.limits.{key}")
        for key, value in limits.items()
    }

    controls_wrapper = document["control_members"]
    if not isinstance(controls_wrapper, dict):
        raise DerivationError(f"{architecture} control_members must be an object")
    _require_keys(
        controls_wrapper,
        frozenset({"classification_counts", "entries"}),
        f"{architecture} control_members",
    )
    declared_counts = controls_wrapper["classification_counts"]
    if not isinstance(declared_counts, dict):
        raise DerivationError(f"{architecture} classification_counts must be an object")
    _require_keys(
        declared_counts,
        frozenset(CLASSIFICATIONS),
        f"{architecture} classification_counts",
    )
    for key, value in declared_counts.items():
        _count(value, f"{architecture}.classification_counts.{key}")

    controls = controls_wrapper["entries"]
    alternatives = document["alternatives_database"]
    linked_wrapper = document["linked_filesystem"]
    if not isinstance(controls, list) or not isinstance(alternatives, list):
        raise DerivationError(f"{architecture} metadata entries must be arrays")
    if not isinstance(linked_wrapper, dict):
        raise DerivationError(f"{architecture} linked_filesystem must be an object")
    _require_keys(
        linked_wrapper,
        frozenset({"requested_paths", "entries"}),
        f"{architecture} linked_filesystem",
    )
    linked = linked_wrapper["entries"]
    if not isinstance(linked, list):
        raise DerivationError(f"{architecture} linked entries must be an array")

    for index, item in enumerate(controls):
        _validate_metadata_file(
            item, f"{architecture}.control[{index}]", validated_limits, control=True
        )
        if not item["path"].startswith("var/lib/dpkg/info/"):
            raise DerivationError(f"{architecture} control path leaves dpkg info")
    for index, item in enumerate(alternatives):
        _validate_metadata_file(
            item,
            f"{architecture}.alternatives[{index}]",
            validated_limits,
            control=False,
        )
        if not item["path"].startswith("var/lib/dpkg/alternatives/"):
            raise DerivationError(
                f"{architecture} alternatives path leaves alternatives database"
            )
    requested = _sorted_unique(
        linked_wrapper["requested_paths"],
        _relative_path,
        f"{architecture}.requested_paths",
    )
    for index, item in enumerate(linked):
        _validate_linked_entry(
            item, f"{architecture}.linked[{index}]", validated_limits
        )

    for label, paths in (
        ("control", [item["path"] for item in controls]),
        ("alternatives", [item["path"] for item in alternatives]),
        ("linked", [item["path"] for item in linked]),
    ):
        if paths != sorted(paths, key=lambda value: value.encode("utf-8")):
            raise DerivationError(f"{architecture} {label} paths are not sorted")
        if len(paths) != len(set(paths)):
            raise DerivationError(f"{architecture} {label} paths contain duplicates")

    observed_counts = Counter(item["classification"] for item in controls)
    normalized_counts = {
        classification: observed_counts.get(classification, 0)
        for classification in CLASSIFICATIONS
    }
    if normalized_counts != declared_counts:
        raise DerivationError(f"{architecture} classification counts do not match entries")
    if normalized_counts["unclassified"] != 0:
        raise DerivationError(f"{architecture} has an unclassified control member")
    if normalized_counts["package-alternatives"] != 0:
        raise DerivationError(
            f"{architecture} package alternatives members require a new reference boundary"
        )
    if normalized_counts != EXPECTED_CLASSIFICATION_COUNTS:
        raise DerivationError(f"{architecture} classification boundary changed")
    if len(controls) != EXPECTED_CONTROL_MEMBERS:
        raise DerivationError(f"{architecture} control-member boundary changed")
    if len(alternatives) != EXPECTED_ALTERNATIVES_RECORDS:
        raise DerivationError(f"{architecture} alternatives-record boundary changed")
    if len(requested) != EXPECTED_REQUESTED_PATHS:
        raise DerivationError(f"{architecture} requested-path boundary changed")
    if len(linked) != EXPECTED_LINKED_ENTRIES:
        raise DerivationError(f"{architecture} linked-entry boundary changed")
    if normalized_counts["debconf-config"] != EXPECTED_CONFIG_MEMBERS:
        raise DerivationError(f"{architecture} config-member boundary changed")
    if len(controls) > validated_limits["max_control_members"]:
        raise DerivationError(f"{architecture} control count exceeds manifest limit")
    if len(alternatives) > validated_limits["max_alternatives_records"]:
        raise DerivationError(f"{architecture} alternatives count exceeds manifest limit")
    if len(requested) > validated_limits["max_referenced_paths"]:
        raise DerivationError(f"{architecture} requested paths exceed manifest limit")
    if len(linked) > validated_limits["max_linked_entries"]:
        raise DerivationError(f"{architecture} linked entries exceed manifest limit")
    metadata_bytes = sum(item["size"] for item in [*controls, *alternatives])
    if metadata_bytes > validated_limits["max_total_metadata_bytes"]:
        raise DerivationError(f"{architecture} metadata bytes exceed manifest limit")
    linked_bytes = sum(
        item["size"] for item in linked if item["kind"] == "regular"
    )
    if linked_bytes > validated_limits["max_total_linked_bytes"]:
        raise DerivationError(f"{architecture} linked bytes exceed manifest limit")


def _control_identity(
    item: dict[str, Any], architecture: str
) -> tuple[str, dict[str, Any]]:
    name = item["path"].rsplit("/", 1)[1]
    if name == "format":
        return "format", {"kind": "database-global"}
    stem, suffix = name.rsplit(".", 1)
    qualifier: str | None = None
    if ":" in stem:
        package, qualifier = stem.rsplit(":", 1)
        if qualifier != architecture or ARCHITECTURE.fullmatch(qualifier) is None:
            raise DerivationError(
                f"{architecture} control member has invalid architecture qualifier: {name}"
            )
    else:
        package = stem
    if PACKAGE.fullmatch(package) is None:
        raise DerivationError(f"{architecture} control member has invalid package: {name}")
    identity = f"{package}:ARCH.{suffix}" if qualifier else f"{package}.{suffix}"
    return identity, {
        "kind": "package",
        "package": package,
        "architecture_qualified": qualifier is not None,
    }


def _control_fact(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": item["path"],
        "mode": item["mode"],
        "uid": item["uid"],
        "gid": item["gid"],
        "size": item["size"],
        "sha256": item["sha256"],
        "referenced_paths": item["referenced_paths"],
    }


def _linked_fact(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key not in {"path", "kind"}}


def _resolve_requested(
    start: str,
    linked: dict[str, dict[str, Any]],
    maximum_hops: int,
) -> dict[str, Any]:
    current = _relative_path(start, "requested path")
    seen = {current}
    chain: list[str] = []
    hops = 0
    while True:
        parts = current.split("/")
        followed = False
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            entry = linked.get(prefix)
            if entry is None:
                continue
            chain.append(prefix)
            kind = entry["kind"]
            if kind == "regular":
                if length != len(parts):
                    raise DerivationError(
                        f"non-directory linked component while resolving {start}: {prefix}"
                    )
                return {
                    "path": start,
                    "chain": chain,
                    "terminal_path": prefix,
                }
            if kind != "symlink":
                raise DerivationError(
                    f"unsupported linked terminal while resolving {start}: {kind}"
                )
            target = _target_path(prefix, entry["target"], f"symlink {prefix}")
            remaining = parts[length:]
            current = (
                _relative_path("/".join([target, *remaining]), "resolved path")
                if remaining
                else target
            )
            hops += 1
            if hops > maximum_hops:
                raise DerivationError(f"symlink hop limit exceeded while resolving {start}")
            if current in seen:
                raise DerivationError(f"symlink cycle while resolving {start}")
            seen.add(current)
            followed = True
            break
        if not followed:
            raise DerivationError(f"linked path has no recorded terminal: {start}")


def _validate_index(index: dict[str, Any]) -> list[dict[str, Any]]:
    _require_keys(index, INDEX_KEYS, "vendor-state index")
    if index["index_version"] != 1:
        raise DerivationError("vendor-state index version mismatch")
    if index["capture_schema"] != {"id": CAPTURE_SCHEMA, "version": 1}:
        raise DerivationError("vendor-state capture schema mismatch")
    if not isinstance(index["source"], dict):
        raise DerivationError("vendor-state source must be an object")
    _require_keys(index["source"], SOURCE_KEYS, "vendor-state source")
    manifests = index["manifests"]
    if not isinstance(manifests, list) or len(manifests) != len(ARCHITECTURES):
        raise DerivationError("vendor-state index must contain two manifests")
    if [item.get("architecture") for item in manifests] != list(ARCHITECTURES):
        raise DerivationError("vendor-state manifests must be ordered amd64 then arm64")
    for architecture, item in zip(ARCHITECTURES, manifests):
        if not isinstance(item, dict):
            raise DerivationError(f"{architecture} index manifest must be an object")
        _require_keys(item, INDEX_MANIFEST_KEYS, f"{architecture} index manifest")
        if item["architecture"] != architecture:
            raise DerivationError(f"{architecture} index architecture mismatch")
        for field in ("artifact_id", "artifact_size_bytes", "job_id", "manifest_size_bytes"):
            _positive_integer(item[field], f"{architecture}.{field}")
        _digest(item["artifact_sha256"], f"{architecture}.artifact_sha256")
        _digest(item["manifest_sha256"], f"{architecture}.manifest_sha256")
        manifest_name = _text(item["manifest_path"], f"{architecture}.manifest_path")
        if (
            pathlib.PurePosixPath(manifest_name).name != manifest_name
            or manifest_name in {".", ".."}
        ):
            raise DerivationError(f"{architecture} manifest path is not a filename")
        _text(item["artifact_name"], f"{architecture}.artifact_name")
        _text(item["artifact_member"], f"{architecture}.artifact_member")
        if not isinstance(item["inventory"], dict):
            raise DerivationError(f"{architecture} inventory must be an object")
    return manifests


def _derive_control_members(
    documents: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, int]]:
    maps: dict[str, dict[str, tuple[dict[str, Any], dict[str, Any]]]] = {}
    for architecture in ARCHITECTURES:
        mapped: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for item in documents[architecture]["control_members"]["entries"]:
            identity, owner = _control_identity(item, architecture)
            if identity in mapped:
                raise DerivationError(
                    f"{architecture} duplicate logical control identity: {identity}"
                )
            mapped[identity] = (item, owner)
        maps[architecture] = mapped
    if set(maps["amd64"]) != set(maps["arm64"]):
        raise DerivationError("control-member logical identities differ by architecture")

    members: list[dict[str, Any]] = []
    path_qualifications: list[dict[str, Any]] = []
    content_differences: list[dict[str, Any]] = []
    handling_counts: Counter[str] = Counter()
    difference_counts = {classification: 0 for classification in CLASSIFICATIONS}
    for identity in sorted(maps["amd64"], key=lambda value: value.encode("utf-8")):
        amd64_item, amd64_owner = maps["amd64"][identity]
        arm64_item, arm64_owner = maps["arm64"][identity]
        if amd64_item["classification"] != arm64_item["classification"]:
            raise DerivationError(f"control classification differs: {identity}")
        if amd64_owner != arm64_owner:
            raise DerivationError(f"control ownership differs: {identity}")
        classification = amd64_item["classification"]
        if classification == "unclassified":
            raise DerivationError(f"unclassified control member: {identity}")
        handling, rationale, requirement = HANDLING[classification]
        handling_counts[handling] += 1
        amd64_fact = _control_fact(amd64_item)
        arm64_fact = _control_fact(arm64_item)
        members.append(
            {
                "identity": identity,
                "classification": classification,
                "owner": amd64_owner,
                "handling": handling,
                "rationale": rationale,
                "reference_execution_requirement": requirement,
                "architectures": {
                    "amd64": amd64_fact,
                    "arm64": arm64_fact,
                },
            }
        )
        if amd64_fact["path"] != arm64_fact["path"]:
            if amd64_owner["kind"] != "package" or not amd64_owner[
                "architecture_qualified"
            ]:
                raise DerivationError(f"unexpected control path difference: {identity}")
            path_qualifications.append(
                {
                    "identity": identity,
                    "amd64_path": amd64_fact["path"],
                    "arm64_path": arm64_fact["path"],
                }
            )
        changed_fields = [
            field
            for field in CONTROL_FACT_FIELDS
            if amd64_fact[field] != arm64_fact[field]
        ]
        if changed_fields:
            if set(changed_fields) not in ({"sha256"}, {"size", "sha256"}):
                raise DerivationError(
                    f"unsupported control difference {identity}: {changed_fields}"
                )
            difference_counts[classification] += 1
            content_differences.append(
                {
                    "identity": identity,
                    "classification": classification,
                    "changed_fields": changed_fields,
                    "amd64": amd64_fact,
                    "arm64": arm64_fact,
                }
            )
    return (
        members,
        {
            "path_qualifications": path_qualifications,
            "control_content": content_differences,
            "control_content_counts": difference_counts,
        },
        dict(sorted(handling_counts.items())),
    )


def _derive_alternatives(
    documents: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    amd64 = documents["amd64"]
    arm64 = documents["arm64"]
    if amd64["alternatives_database"] != arm64["alternatives_database"]:
        raise DerivationError("alternatives records differ by architecture")
    if (
        amd64["linked_filesystem"]["requested_paths"]
        != arm64["linked_filesystem"]["requested_paths"]
    ):
        raise DerivationError("alternatives requested paths differ by architecture")

    linked_maps = {
        architecture: {
            item["path"]: item
            for item in documents[architecture]["linked_filesystem"]["entries"]
        }
        for architecture in ARCHITECTURES
    }
    if set(linked_maps["amd64"]) != set(linked_maps["arm64"]):
        raise DerivationError("linked filesystem paths differ by architecture")
    for path in sorted(linked_maps["amd64"]):
        amd64_item = linked_maps["amd64"][path]
        arm64_item = linked_maps["arm64"][path]
        if amd64_item["kind"] != arm64_item["kind"]:
            raise DerivationError(f"linked entry kind differs: {path}")
        for field in ("mode", "uid", "gid", "target"):
            if amd64_item.get(field) != arm64_item.get(field):
                raise DerivationError(f"linked topology differs at {path}: {field}")

    resolutions_by_architecture: dict[str, dict[str, dict[str, Any]]] = {}
    for architecture in ARCHITECTURES:
        limits = documents[architecture]["limits"]
        resolutions = {
            path: _resolve_requested(
                path, linked_maps[architecture], limits["max_link_hops"]
            )
            for path in documents[architecture]["linked_filesystem"][
                "requested_paths"
            ]
        }
        reached = {
            entry_path
            for resolution in resolutions.values()
            for entry_path in resolution["chain"]
        }
        if reached != set(linked_maps[architecture]):
            missing = sorted(set(linked_maps[architecture]) - reached)
            raise DerivationError(
                f"{architecture} linked entries are not fully reached: {missing}"
            )
        resolutions_by_architecture[architecture] = resolutions
    if resolutions_by_architecture["amd64"] != resolutions_by_architecture["arm64"]:
        raise DerivationError("linked path resolutions differ by architecture")
    resolutions = resolutions_by_architecture["amd64"]

    roles: dict[str, set[str]] = {path: set() for path in linked_maps["amd64"]}
    associated_requested: set[str] = set()
    groups: list[dict[str, Any]] = []
    for record in amd64["alternatives_database"]:
        name = record["path"].rsplit("/", 1)[1]
        links: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        for path in record["referenced_paths"]:
            associated_requested.add(path)
            resolution = resolutions[path]
            selectors = [
                entry_path
                for entry_path in resolution["chain"]
                if entry_path.startswith("etc/alternatives/")
                and linked_maps["amd64"][entry_path]["kind"] == "symlink"
            ]
            if len(selectors) > 1:
                raise DerivationError(
                    f"alternatives path crosses multiple selectors: {path}"
                )
            if not selectors:
                for entry_path in resolution["chain"][:-1]:
                    roles[entry_path].add("path-alias")
                roles[resolution["terminal_path"]].add("candidate-target")
                candidates.append(
                    {
                        "path": path,
                        "terminal_path": resolution["terminal_path"],
                        "selected_by": [],
                    }
                )
                continue
            selector = selectors[0]
            associated_requested.add(selector)
            selector_index = resolution["chain"].index(selector)
            if selector_index == 0:
                raise DerivationError(
                    f"alternatives record directly names selector instead of link: {path}"
                )
            front = resolution["chain"][selector_index - 1]
            for entry_path in resolution["chain"][: selector_index - 1]:
                roles[entry_path].add("path-alias")
            roles[front].add("front-link")
            roles[selector].add("selector-link")
            for entry_path in resolution["chain"][selector_index + 1 : -1]:
                roles[entry_path].add("path-alias")
            roles[resolution["terminal_path"]].add("candidate-target")
            relationship = (
                "master"
                if selector == f"etc/alternatives/{name}"
                else "slave"
            )
            links.append(
                {
                    "relationship": relationship,
                    "link_path": path,
                    "selector_path": selector,
                    "selector_target": linked_maps["amd64"][selector]["target"],
                    "terminal_path": resolution["terminal_path"],
                    "ownership": dict(UNKNOWN_ALTERNATIVES_OWNERSHIP),
                }
            )
        links.sort(key=lambda item: item["link_path"].encode("utf-8"))
        candidates.sort(key=lambda item: item["path"].encode("utf-8"))
        masters = [link for link in links if link["relationship"] == "master"]
        if len(masters) != 1:
            raise DerivationError(
                f"alternatives group {name} does not have exactly one master link"
            )
        selected_terminals: dict[str, list[str]] = {}
        for link in links:
            selected_terminals.setdefault(link["terminal_path"], []).append(
                link["link_path"]
            )
        candidate_terminals = {candidate["terminal_path"] for candidate in candidates}
        if not set(selected_terminals).issubset(candidate_terminals):
            raise DerivationError(
                f"alternatives group {name} selects an undeclared candidate"
            )
        for candidate in candidates:
            candidate["selected_by"] = sorted(
                selected_terminals.get(candidate["terminal_path"], []),
                key=lambda value: value.encode("utf-8"),
            )
        groups.append(
            {
                "name": name,
                "present_in_architectures": list(ARCHITECTURES),
                "record": record,
                "ownership": dict(UNKNOWN_ALTERNATIVES_OWNERSHIP),
                "selection_mode": dict(UNKNOWN_SELECTION_MODE),
                "priorities": dict(UNKNOWN_PRIORITIES),
                "links": links,
                "candidate_paths": candidates,
                "reference_execution_requirement": (
                    "Decode exact record bytes and observe reference "
                    "registration, selection, and mutation behavior."
                ),
            }
        )

    requested_paths = amd64["linked_filesystem"]["requested_paths"]
    unassociated = sorted(
        set(requested_paths) - associated_requested,
        key=lambda value: value.encode("utf-8"),
    )
    retained_requested: list[dict[str, Any]] = []
    for path in unassociated:
        resolution = resolutions[path]
        terminal = linked_maps["amd64"][resolution["terminal_path"]]
        if (
            not path.startswith("etc/alternatives/")
            or terminal["kind"] != "regular"
        ):
            raise DerivationError(f"unclassified alternatives requested path: {path}")
        for entry_path in resolution["chain"][:-1]:
            roles[entry_path].add("path-alias")
        roles[resolution["terminal_path"]].add("retained-selector-metadata")
        retained_requested.append(
            {
                "path": path,
                "terminal_path": resolution["terminal_path"],
                "handling": "bounded-inert-retained-metadata",
                "rationale": (
                    "This regular etc/alternatives entry is not a selector "
                    "or alternatives database record and is retained by identity."
                ),
            }
        )

    linked_entries: list[dict[str, Any]] = []
    linked_differences: list[dict[str, Any]] = []
    for path in sorted(linked_maps["amd64"], key=lambda value: value.encode("utf-8")):
        amd64_item = linked_maps["amd64"][path]
        arm64_item = linked_maps["arm64"][path]
        if not roles[path]:
            raise DerivationError(f"linked entry has no derived role: {path}")
        amd64_fact = _linked_fact(amd64_item)
        arm64_fact = _linked_fact(arm64_item)
        linked_entries.append(
            {
                "identity": path,
                "kind": amd64_item["kind"],
                "roles": sorted(roles[path], key=lambda value: ROLE_ORDER[value]),
                "ownership": dict(UNKNOWN_ALTERNATIVES_OWNERSHIP),
                "architectures": {
                    "amd64": amd64_fact,
                    "arm64": arm64_fact,
                },
            }
        )
        changed_fields = [
            field
            for field in LINKED_FACT_FIELDS
            if amd64_fact.get(field) != arm64_fact.get(field)
        ]
        if changed_fields:
            if (
                amd64_item["kind"] != "regular"
                or set(changed_fields) != {"size", "sha256"}
            ):
                raise DerivationError(
                    f"unsupported linked entry difference {path}: {changed_fields}"
                )
            linked_differences.append(
                {
                    "identity": path,
                    "kind": "regular",
                    "changed_fields": changed_fields,
                    "amd64": amd64_fact,
                    "arm64": arm64_fact,
                }
            )

    requested_output = [resolutions[path] for path in requested_paths]
    return (
        {
            "groups": groups,
            "requested_paths": requested_output,
            "linked_entries": linked_entries,
            "retained_selector_metadata": retained_requested,
        },
        linked_differences,
    )


def derive(index_path: os.PathLike[str] | str) -> dict[str, Any]:
    path = pathlib.Path(index_path)
    raw_index, index = _read_document(path, MAX_INDEX_BYTES, "vendor-state index")
    manifest_references = _validate_index(index)
    documents: dict[str, dict[str, Any]] = {}
    source_manifests: list[dict[str, Any]] = []
    for reference in manifest_references:
        architecture = reference["architecture"]
        manifest_path = path.parent / reference["manifest_path"]
        raw, document = _read_document(
            manifest_path, MAX_MANIFEST_BYTES, f"{architecture} manifest"
        )
        if len(raw) != reference["manifest_size_bytes"]:
            raise DerivationError(f"{architecture} manifest size binding mismatch")
        if hashlib.sha256(raw).hexdigest() != reference["manifest_sha256"]:
            raise DerivationError(f"{architecture} manifest digest binding mismatch")
        _validate_manifest(document, architecture)
        inventory = _inventory(document)
        if inventory != reference["inventory"]:
            raise DerivationError(f"{architecture} index inventory binding mismatch")
        documents[architecture] = document
        source_manifests.append(
            {
                "architecture": architecture,
                "path": reference["manifest_path"],
                "size": reference["manifest_size_bytes"],
                "sha256": reference["manifest_sha256"],
                "artifact": {
                    "id": reference["artifact_id"],
                    "name": reference["artifact_name"],
                    "member": reference["artifact_member"],
                    "size": reference["artifact_size_bytes"],
                    "sha256": reference["artifact_sha256"],
                    "job_id": reference["job_id"],
                },
            }
        )

    control_members, control_differences, handling_counts = _derive_control_members(
        documents
    )
    alternatives, linked_differences = _derive_alternatives(documents)
    config_identities = [
        item["identity"]
        for item in control_members
        if item["classification"] == "debconf-config"
    ]
    group_names = [group["name"] for group in alternatives["groups"]]
    per_architecture = {}
    for reference in manifest_references:
        architecture = reference["architecture"]
        per_architecture[architecture] = {
            **reference["inventory"],
            "config_member_count": EXPECTED_CONFIG_MEMBERS,
            "package_alternatives_member_count": 0,
            "unclassified_control_member_count": 0,
            "control_handling_counts": handling_counts,
        }

    return {
        "schema": SCHEMA,
        "version": 1,
        "source": {
            "capture_schema": index["capture_schema"],
            "index": {
                "path": path.name,
                "size": len(raw_index),
                "sha256": hashlib.sha256(raw_index).hexdigest(),
            },
            "index_source": index["source"],
            "manifests": source_manifests,
        },
        "boundary": {
            "architectures": list(ARCHITECTURES),
            "per_architecture": per_architecture,
            "paired_control_member_count": len(control_members),
            "alternatives_group_count": len(alternatives["groups"]),
            "requested_path_count": len(alternatives["requested_paths"]),
            "linked_entry_count": len(alternatives["linked_entries"]),
        },
        "control_members": control_members,
        "alternatives": alternatives,
        "cross_architecture_differences": {
            **control_differences,
            "linked_content": linked_differences,
            "invariants": [
                "classification-counts",
                "control-logical-identities",
                "alternatives-records",
                "requested-paths",
                "linked-path-kinds-modes-owners-targets",
            ],
        },
        "reference_execution_requirements": [
            {
                "id": "debconf-config-execution",
                "applies_to": {
                    "kind": "control-members",
                    "identities": config_identities,
                },
                "manifest_proves": (
                    "Installed path, owning package name, mode, uid, gid, "
                    "size, and SHA-256 for each config script."
                ),
                "required_reference_execution": (
                    "Observe whether and how the reference frontend invokes "
                    "each config script, including ordering, argv, environment, "
                    "outcome, and resulting state."
                ),
            },
            {
                "id": "alternatives-record-semantics",
                "applies_to": {
                    "kind": "alternatives-groups",
                    "identities": group_names,
                },
                "manifest_proves": (
                    "Record identity and digest, declared paths, current "
                    "master/slave selector topology, selected targets, and "
                    "linked filesystem identities."
                ),
                "required_reference_execution": (
                    "Capture exact record bytes to type auto/manual mode, "
                    "candidate rows, priorities, and provider registration."
                ),
            },
            {
                "id": "alternatives-mutation-behavior",
                "applies_to": {
                    "kind": "alternatives-groups",
                    "identities": group_names,
                },
                "manifest_proves": (
                    "One post-installation state only; no causality or mutation "
                    "sequence is present."
                ),
                "required_reference_execution": (
                    "Run bounded reference install, upgrade, remove, purge, "
                    "failure, and recovery cases and compare exact record and "
                    "link mutations before production support changes."
                ),
            },
        ],
    }


def _write_new(path: pathlib.Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise DerivationError(f"cannot create output {path}: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", required=True, help="Pinned vendor-state index")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", help="Create a new canonical reference file")
    destination.add_argument("--check", help="Require an existing file to match")
    arguments = parser.parse_args()
    try:
        encoded = canonical_json(derive(arguments.index))
        if arguments.check:
            expected = pathlib.Path(arguments.check).read_bytes()
            if expected != encoded:
                raise DerivationError(
                    f"derived reference differs from {arguments.check}"
                )
        else:
            _write_new(pathlib.Path(arguments.output), encoded)
    except (DerivationError, OSError) as error:
        print(f"derive-vendor-state-reference: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
