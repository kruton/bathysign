#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Local verification must reject changed external action contents before import."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dependency", ROOT / "scripts/signer_action.py")
dependency = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dependency)


class DependencyTests(unittest.TestCase):
    def test_tampered_helper_verifier_or_action_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            config.mkdir(parents=True)
            action = root / "actions/bathysign"
            (action / "scripts").mkdir(parents=True)
            files = {"action.yml": b"reviewed action", "scripts/Reference.java": b"reviewed verifier",
                     "scripts/signer-release.py": b"REVIEWED = True\n"}
            pin = {"revision": "a" * 40, "path": "bathysign",
                   "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
            (config / "action-pin.json").write_text(json.dumps(pin))
            for name, data in files.items():
                (action / name).write_bytes(data)
            with mock.patch.object(dependency, "ROOT", root):
                self.assertTrue(dependency.load_release(root / "actions", config / "action-pin.json").REVIEWED)
                for name, data in files.items():
                    with self.subTest(name=name):
                        (action / name).write_bytes(b"unreviewed content")
                        with self.assertRaisesRegex(ValueError, "differs from approved revision"):
                            dependency.load_release(root / "actions", config / "action-pin.json")
                        (action / name).write_bytes(data)


if __name__ == "__main__":
    unittest.main()
