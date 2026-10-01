"""Configuration upgrades preserve credentials backing existing volumes."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import bootstrap_env


class BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / ".env"

    def run_bootstrap(self, *flags: str) -> str:
        output = io.StringIO()
        with patch("sys.argv", ["bootstrap", "--output", str(self.path), *flags]):
            with contextlib.redirect_stdout(output):
                bootstrap_env.main()
        return output.getvalue()

    def test_new_configuration_has_separate_owner_secret(self) -> None:
        output = self.run_bootstrap()
        values = dict(
            line.split("=", 1) for line in self.path.read_text().splitlines() if "=" in line
        )
        self.assertNotEqual(values["CLICKHOUSE_PASSWORD"], values["CLICKHOUSE_OWNER_PASSWORD"])
        self.assertGreater(len(values["CLICKHOUSE_OWNER_PASSWORD"]), 40)
        self.assertNotIn(values["CLICKHOUSE_PASSWORD"], output)
        self.assertNotIn(values["CLICKHOUSE_OWNER_PASSWORD"], output)

    def test_upgrade_preserves_every_existing_byte_and_is_repeatable(self) -> None:
        self.run_bootstrap()
        original = b"# custom config\r\n" + b"\r\n".join(
            line
            for line in self.path.read_bytes().splitlines()
            if not line.startswith(b"CLICKHOUSE_OWNER_PASSWORD=")
        )
        self.path.write_bytes(original)
        self.run_bootstrap("--upgrade")
        upgraded = self.path.read_bytes()
        self.assertTrue(upgraded.startswith(original + b"\n"))
        self.assertEqual(upgraded.count(b"CLICKHOUSE_OWNER_PASSWORD="), 1)
        self.run_bootstrap("--upgrade")
        self.assertEqual(self.path.read_bytes(), upgraded)

    def test_default_creation_never_overwrites_existing_file(self) -> None:
        self.path.write_bytes(b"custom configuration")
        with self.assertRaises(SystemExit):
            self.run_bootstrap()
        self.assertEqual(self.path.read_bytes(), b"custom configuration")

    def test_incomplete_configuration_is_preserved(self) -> None:
        self.path.write_bytes(b"CLICKHOUSE_PASSWORD=custom")
        with self.assertRaises(SystemExit):
            self.run_bootstrap("--upgrade")
        self.assertEqual(self.path.read_bytes(), b"CLICKHOUSE_PASSWORD=custom")


if __name__ == "__main__":
    unittest.main()
