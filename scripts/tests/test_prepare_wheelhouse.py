"""Verify offline wheel integrity and compatibility without network access."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import prepare_wheelhouse as preparation


class WheelhouseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.content = b"locked wheel contents"
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.packages = {"demo": preparation.LockedPackage("1.0", {self.digest})}

    def wheel(self, filename: str, content: bytes | None = None) -> Path:
        path = self.root / filename
        path.write_bytes(self.content if content is None else content)
        return path

    def test_accepts_locked_linux_wheel(self) -> None:
        path = self.wheel("demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl")
        self.assertEqual(preparation.verify_wheel(path, self.packages), "demo")

    def test_rejects_tampered_wheel(self) -> None:
        path = self.wheel("demo-1.0-py3-none-any.whl", b"tampered")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            preparation.verify_wheel(path, self.packages)

    def test_rejects_unpinned_version(self) -> None:
        path = self.wheel("demo-2.0-py3-none-any.whl")
        with self.assertRaisesRegex(ValueError, "not pinned"):
            preparation.verify_wheel(path, self.packages)

    def test_windows_wheel_does_not_satisfy_linux_requirement(self) -> None:
        path = self.wheel("demo-1.0-cp312-cp312-win_amd64.whl")
        self.assertIsNone(preparation.verify_wheel(path, self.packages))

    def test_rejects_lock_without_hashes(self) -> None:
        lock = self.root / "requirements.lock"
        lock.write_text("demo==1.0\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            preparation.read_locks((lock,))

    def test_rejects_conflicting_lock_versions(self) -> None:
        first = self.root / "first.lock"
        second = self.root / "second.lock"
        first.write_text(f"demo==1.0 \\\n    --hash=sha256:{self.digest}\n", encoding="utf-8")
        second.write_text(f"demo==2.0 \\\n    --hash=sha256:{self.digest}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            preparation.read_locks((first, second))

    def test_complete_verified_cache_needs_no_network(self) -> None:
        self.wheel("demo-1.0-py3-none-any.whl")
        lock = self.root / "requirements.lock"
        lock.write_text(f"demo==1.0 \\\n    --hash=sha256:{self.digest}\n", encoding="utf-8")
        with (
            patch.object(preparation, "WHEELHOUSE", self.root),
            patch.object(preparation, "LEGACY_CACHE", self.root / "absent"),
            patch.object(preparation, "LOCKFILES", (lock,)),
            patch.object(preparation, "download_wheels") as download,
        ):
            self.assertEqual(preparation.main(), 0)
            download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
