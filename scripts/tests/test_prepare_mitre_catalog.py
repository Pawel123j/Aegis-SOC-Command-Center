"""Fail closed before replacing pinned ATT&CK artifacts; no network or giant fixture."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts import prepare_mitre_catalog as preparation


class MitrePreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source.json"
        self.license = self.root / "license.txt"
        self.output = self.root / "output"
        self.license.write_bytes(b"incorrect fixture license")

    def run_rejected_cli(self, expected: str) -> None:
        arguments = [
            "prepare_mitre_catalog.py",
            "--source",
            str(self.source),
            "--license",
            str(self.license),
            "--output-dir",
            str(self.output),
        ]
        error = io.StringIO()
        with (
            patch("sys.argv", arguments),
            redirect_stderr(error),
            self.assertRaises(SystemExit) as failure,
        ):
            preparation.main()
        self.assertEqual(failure.exception.code, 1)
        self.assertIn(expected, error.getvalue())

    def test_rejects_corrupt_and_unpinned_source_before_creating_output(self) -> None:
        for content in (b"corrupted non-JSON input", b'{"type":"bundle","objects":[]}'):
            with self.subTest(content=content):
                self.source.write_bytes(content)
                self.run_rejected_cli("Source SHA-256")
                self.assertFalse(self.output.exists())

    def test_rejected_source_preserves_existing_artifacts(self) -> None:
        self.source.write_bytes(b"changed source")
        self.output.mkdir()
        originals = {
            preparation.CATALOGUE_NAME: b"previous catalogue",
            "LICENSE.txt": b"previous license",
            "enterprise-attack-19.2.sha256": b"previous checksum",
        }
        for name, content in originals.items():
            (self.output / name).write_bytes(content)
        self.run_rejected_cli("Source SHA-256")
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.output.iterdir()}, originals
        )

    def test_rejects_license_hash_before_any_output_writes(self) -> None:
        self.source.write_bytes(b"source accepted by isolated extraction phase")
        # Isolate the license boundary without copying the large official STIX bundle.
        with patch.object(
            preparation, "extract", return_value={"tactics": [], "techniques": []}
        ):
            self.run_rejected_cli("License SHA-256")
        self.assertFalse(self.output.exists())

    @staticmethod
    def minimal_bundle() -> dict[str, Any]:
        def reference(identifier: str) -> dict[str, str]:
            section = "tactics" if identifier.startswith("TA") else "techniques"
            return {
                "source_name": "mitre-attack",
                "external_id": identifier,
                "url": f"https://attack.mitre.org/{section}/{identifier}/",
            }

        # Tiny generated objects reach structural guards without a checked-in STIX fixture.
        techniques = [
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{index}",
                "external_references": [reference(f"T{1000 + index}")],
            }
            for index in range(858)
        ]
        tactics = [
            {
                "type": "x-mitre-tactic",
                "id": f"x-mitre-tactic--{index}",
                "x_mitre_shortname": f"tactic-{index}",
                "external_references": [reference(f"TA{index:04d}")],
            }
            for index in range(15)
        ]
        collection = {
            "type": "x-mitre-collection",
            "x_mitre_version": "19.2",
            "spec_version": "2.1",
        }
        return {"type": "bundle", "objects": [collection, *techniques, *tactics]}

    def assert_structural_rejection(self, bundle: dict[str, Any], message: str) -> None:
        content = json.dumps(bundle).encode("utf-8")
        # This controlled pin isolates parser guards. CLI hash tests above use the real pin.
        with (
            patch.object(
                preparation, "SOURCE_SHA256", hashlib.sha256(content).hexdigest()
            ),
            self.assertRaisesRegex(ValueError, message),
        ):
            preparation.extract(content, preparation.FETCHED_AT)

    def test_rejects_duplicate_external_technique_ids(self) -> None:
        bundle = self.minimal_bundle()
        objects = bundle["objects"]
        objects[2]["external_references"] = objects[1]["external_references"]
        self.assert_structural_rejection(bundle, "duplicate identifiers")

    def test_rejects_duplicate_tactic_ids_and_short_names(self) -> None:
        for field in ("external_references", "x_mitre_shortname", "id", "extra_object"):
            with self.subTest(field=field):
                bundle = self.minimal_bundle()
                objects = bundle["objects"]
                if field == "extra_object":
                    objects.append(dict(objects[-1]))
                else:
                    objects[-1][field] = objects[-2][field]
                self.assert_structural_rejection(bundle, "duplicate identifiers")

    def test_rejects_subtechnique_relationship_outside_catalogue(self) -> None:
        bundle = self.minimal_bundle()
        bundle["objects"].append(
            {
                "type": "relationship",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--0",
                "target_ref": "missing-parent",
            }
        )
        self.assert_structural_rejection(bundle, "outside the catalogue")

    def test_rejects_date_only_or_non_utc_fetch_time(self) -> None:
        content = b"{}"
        with patch.object(
            preparation, "SOURCE_SHA256", hashlib.sha256(content).hexdigest()
        ):
            for timestamp in (
                "2026-01-01Z",
                "2026-01-01T00:00:00",
                "2026-01-01T00:00:00+01:00",
            ):
                with (
                    self.subTest(timestamp=timestamp),
                    self.assertRaisesRegex(ValueError, "fetched-at"),
                ):
                    preparation.extract(content, timestamp)

    def test_rejects_ambiguous_official_reference_and_wrong_origin(self) -> None:
        reference = {
            "source_name": "mitre-attack",
            "external_id": "T1059.001",
            "url": "https://attack.mitre.org/techniques/T1059/001/",
        }
        obj = {"id": "test-pattern", "external_references": [reference, reference]}
        with self.assertRaisesRegex(ValueError, "Ambiguous ATT&CK reference"):
            preparation.official_reference(obj, r"T\d{4}(?:\.\d{3})?")
        obj["external_references"] = [
            {**reference, "url": "https://example.test/T1059/001/"}
        ]
        with self.assertRaisesRegex(ValueError, "Unexpected official URL"):
            preparation.official_reference(obj, r"T\d{4}(?:\.\d{3})?")


if __name__ == "__main__":
    unittest.main()
