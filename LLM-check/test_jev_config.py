"""Check credential isolation and preserve fixed-label requests for Jev."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jev_config import NAMES, public_settings, read_settings
from jev_evaluate import jev_payload


class JevConfigTests(unittest.TestCase):
    def test_dotenv_key_is_read_and_not_in_public_settings(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {name: "" for name in NAMES}):
            path = Path(directory) / ".env"
            path.write_text('TYPESAFE_API_KEY="offline-test-token"\n')
            settings = read_settings(path, require_key=True)
            self.assertEqual(settings["api_key"], "offline-test-token")
            public = public_settings(settings)
            self.assertTrue(public["api_key_configured"])
            self.assertNotIn("offline-test-token", json.dumps(public))

    def test_environment_overrides_file_and_missing_key_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {name: "" for name in NAMES}):
            path = Path(directory) / ".env"
            path.write_text("TYPESAFE_API_KEY=\n")
            with self.assertRaises(ValueError):
                read_settings(path, require_key=True)
            with patch.dict(os.environ, {"TYPESAFE_API_KEY": "env-test-token"}):
                self.assertEqual(read_settings(path)["api_key"], "env-test-token")

    def test_jev_wire_body_drops_laya_controls_without_changing_labels(self):
        payload = {"model": "multilingual", "state": "code evidence", "max_len": 8192, "head_max_len": 512,
                   "questions": {"is_entrypoint": {"type": "choice", "instructions": "Is this an entrypoint?",
                                                    "criteria": {"yes": "bound handler", "no": "internal helper", "unknown": "unclear"}}}}
        result = jev_payload(payload, "jev-latest")
        self.assertEqual(set(result), {"model", "state", "questions"})
        self.assertEqual(result["questions"], payload["questions"])
        self.assertEqual(result["state"], payload["state"])
        self.assertEqual(result["model"], "jev-latest")


if __name__ == "__main__":
    unittest.main()
