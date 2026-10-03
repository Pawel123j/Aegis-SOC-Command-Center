"""Reproduce the pinned offline ATT&CK catalogue from a local official STIX bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

SOURCE_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
TAG_OBJECT_SHA = "e400737ebdbfd36b72c63181257de7a2759c5945"
SOURCE_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
LICENSE_SHA256 = "738144f7fb054722a4ef9d3367c51710341dc12fc574c6ac3a41daaaecd8bf5e"
FETCHED_AT = "2026-10-03T14:22:46Z"
CATALOGUE_NAME = "enterprise-attack-19.2.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "backend/app/modules/mitre/data"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def official_reference(obj: dict[str, Any], pattern: str) -> dict[str, Any]:
    references = [
        ref
        for ref in obj.get("external_references", [])
        if ref.get("source_name") == "mitre-attack"
        and re.fullmatch(pattern, ref.get("external_id", ""))
    ]
    require(len(references) == 1, f"Ambiguous ATT&CK reference: {obj['id']}")
    ref = references[0]
    section = "tactics" if pattern == r"TA\d{4}" else "techniques"
    expected_url = (
        "https://attack.mitre.org/"
        + section
        + "/"
        + ref["external_id"].replace(".", "/")
    )
    require(
        ref["url"].rstrip("/") == expected_url,
        f"Unexpected official URL: {obj['id']}",
    )
    return ref


def common_fields(obj: dict[str, Any], pattern: str) -> dict[str, Any]:
    ref = official_reference(obj, pattern)
    return {
        "id": ref["external_id"],
        "stix_id": obj["id"],
        "name": obj["name"],
        "url": ref["url"],
        "version": obj["x_mitre_version"],
        "modified": obj["modified"],
        "revoked": obj.get("revoked", False),
        "deprecated": obj.get("x_mitre_deprecated", False),
    }


def extract(source_bytes: bytes, fetched_at: str) -> dict[str, Any]:
    require(
        hashlib.sha256(source_bytes).hexdigest() == SOURCE_SHA256,
        "Source SHA-256 differs from the pinned official v19.2 bundle",
    )
    require(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", fetched_at)
        is not None,
        "fetched-at must be an explicit UTC timestamp",
    )
    datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
    source = json.loads(source_bytes)
    require(source["type"] == "bundle", "Expected a STIX bundle")
    objects = source["objects"]
    raw_tactics = [obj for obj in objects if obj["type"] == "x-mitre-tactic"]
    raw_techniques = [obj for obj in objects if obj["type"] == "attack-pattern"]
    collections = [obj for obj in objects if obj["type"] == "x-mitre-collection"]
    require(len(collections) == 1, "Expected exactly one ATT&CK collection")
    collection = collections[0]
    require(
        collection["x_mitre_version"] == "19.2" and collection["spec_version"] == "2.1",
        "Expected ATT&CK v19.2 in STIX 2.1",
    )
    technique_ids = {
        obj["id"]: official_reference(obj, r"T\d{4}(?:\.\d{3})?")["external_id"]
        for obj in raw_techniques
    }
    tactic_ids = {
        obj["x_mitre_shortname"]: official_reference(obj, r"TA\d{4}")["external_id"]
        for obj in raw_tactics
    }
    require(
        len(technique_ids) == len(raw_techniques) == 858
        and len(set(technique_ids.values())) == 858
        and len(tactic_ids) == len(raw_tactics) == 15
        and len(set(tactic_ids.values())) == 15
        and len({obj["id"] for obj in raw_tactics}) == 15,
        "Unexpected v19.2 metadata counts or duplicate identifiers",
    )
    parents: dict[str, str] = {}
    for obj in objects:
        if (
            obj["type"] != "relationship"
            or obj.get("relationship_type") != "subtechnique-of"
        ):
            continue
        require(
            obj["source_ref"] in technique_ids and obj["target_ref"] in technique_ids,
            "Subtechnique relationship points outside the catalogue",
        )
        require(obj["source_ref"] not in parents, "Multiple subtechnique parents")
        require(
            not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False),
            "Unexpected inactive parent relationship",
        )
        parents[obj["source_ref"]] = technique_ids[obj["target_ref"]]

    tactics = []
    for obj in raw_tactics:
        tactic = common_fields(obj, r"TA\d{4}")
        tactic["short_name"] = obj["x_mitre_shortname"]
        tactics.append(tactic)

    techniques = []
    for obj in raw_techniques:
        technique = common_fields(obj, r"T\d{4}(?:\.\d{3})?")
        technique.update(
            is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
            parent_id=parents.get(obj["id"]),
            tactic_ids=sorted(
                {
                    tactic_ids[phase["phase_name"]]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase["kill_chain_name"] == "mitre-attack"
                }
            ),
            platforms=sorted(obj.get("x_mitre_platforms", [])),
        )
        if technique["is_subtechnique"] and technique["parent_id"] is None:
            require(
                technique["revoked"] or technique["deprecated"],
                f"Active subtechnique lacks an official parent: {technique['id']}",
            )
        if technique["parent_id"]:
            require(
                technique["is_subtechnique"]
                and technique["parent_id"] == technique["id"].split(".")[0],
                f"Unexpected parent identifier: {technique['id']}",
            )
        techniques.append(technique)

    provenance = {
        "domain": "enterprise-attack",
        "attack_version": "19.2",
        "release_tag": "v19.2",
        "tag_object_sha": TAG_OBJECT_SHA,
        "source_commit": SOURCE_COMMIT,
        "source_url": (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            + SOURCE_COMMIT
            + "/enterprise-attack/enterprise-attack-19.2.json"
        ),
        "source_sha256": SOURCE_SHA256,
        "release_published_at": "2026-08-05T22:58:54Z",
        "collection_id": collection["id"],
        "collection_version": collection["x_mitre_version"],
        "collection_modified": collection["modified"],
        "fetched_at": fetched_at,
    }
    return {
        "schema_version": 1,
        "provenance": provenance,
        "tactics": sorted(tactics, key=lambda item: item["id"]),
        "techniques": sorted(techniques, key=lambda item: item["id"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--license", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fetched-at", default=FETCHED_AT)
    parser.add_argument(
        "--check", action="store_true", help="Verify without writing files"
    )
    args = parser.parse_args()
    try:
        payload = extract(args.source.read_bytes(), args.fetched_at)
        license_bytes = args.license.read_bytes()
        require(
            hashlib.sha256(license_bytes).hexdigest() == LICENSE_SHA256,
            "License SHA-256 differs from the pinned official license",
        )
        catalogue_bytes = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        catalogue_hash = hashlib.sha256(catalogue_bytes).hexdigest()
        files = {
            CATALOGUE_NAME: catalogue_bytes,
            "LICENSE.txt": license_bytes,
            "enterprise-attack-19.2.sha256": (
                catalogue_hash + "  " + CATALOGUE_NAME + "\n"
            ).encode("ascii"),
        }
        if args.check:
            for name, expected in files.items():
                require(
                    (args.output_dir / name).read_bytes() == expected,
                    f"Committed catalogue does not reproduce: {name}",
                )
        else:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            for name, content in files.items():
                (args.output_dir / name).write_bytes(content)
        print(
            json.dumps(
                {
                    "mode": "check" if args.check else "write",
                    "sha256": catalogue_hash,
                    "size_bytes": len(catalogue_bytes),
                    "tactics": len(payload["tactics"]),
                    "techniques": len(payload["techniques"]),
                },
                sort_keys=True,
            )
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        parser.exit(1, f"Catalogue preparation failed: {exc}\n")


if __name__ == "__main__":
    main()
