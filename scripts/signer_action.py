#!/usr/bin/env python3
"""Load the same-checkout verifier, or explicitly authenticate an external checkout."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ACTIONS = ROOT


def load_release(actions_directory=DEFAULT_ACTIONS, pin_path=None):
    directory = Path(actions_directory).resolve()
    action = directory / "bathysign"
    if directory != ROOT.resolve():
        if pin_path is None:
            raise ValueError("External verifier requires an explicit action pin")
        pin = json.loads(Path(pin_path).read_bytes())
        action = directory / pin["path"]
        for relative, expected in pin["files"].items():
            path = action / relative
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("Shared signer action differs from approved revision: " + relative)
    spec = importlib.util.spec_from_file_location("signer_release", action / "scripts/signer-release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
