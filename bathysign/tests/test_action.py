#!/usr/bin/env python3
# Copyright 2026 Kenny Root
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("action", ROOT / "scripts/run_action.py")
action = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(action)


class ActionTests(unittest.TestCase):
    def test_every_operation_passes_only_its_declared_inputs(self):
        for command, options in action.OPTIONS.items():
            with self.subTest(command=command):
                env = {"BATHYSIGN_COMMAND": command, "BATHYSIGN_OUT": "/tmp/output"}
                env.update({"BATHYSIGN_" + key.upper().replace("-", "_"): key for key in options})
                env["BATHYSIGN_UNDECLARED"] = "ignored"
                self.assertEqual(action.arguments(env), [command, "--out=/tmp/output", *["--" + key + "=" + key for key in options]])

    def test_untrusted_values_remain_literal_arguments(self):
        value = "--report=/other path; $(touch /tmp/should-not-exist)\nsecond line"
        args = action.arguments({"BATHYSIGN_COMMAND": "build-info", "BATHYSIGN_OUT": value,
            "BATHYSIGN_PROFILE": "oss", "BATHYSIGN_VERSION_CODE_FILE": value})
        self.assertEqual(args, ["build-info", "--out=" + value, "--profile=oss", "--version-code-file=" + value])

    def test_optional_version_name_file_is_forwarded_only_for_build_info(self):
        env = {"BATHYSIGN_COMMAND": "build-info", "BATHYSIGN_OUT": "out", "BATHYSIGN_PROFILE": "google",
               "BATHYSIGN_VERSION_CODE_FILE": "code", "BATHYSIGN_VERSION_NAME_FILE": "name with spaces"}
        self.assertEqual(action.arguments(env)[-1], "--version-name-file=name with spaces")
        env["BATHYSIGN_COMMAND"] = "policy"
        self.assertEqual(action.arguments(env), ["policy", "--out=out"])

    def test_unknown_operation_and_missing_inputs_are_rejected(self):
        for env in ({"BATHYSIGN_COMMAND": "bash"}, {"BATHYSIGN_COMMAND": "prepare", "BATHYSIGN_OUT": "/tmp/output"}):
            with self.assertRaises(ValueError):
                action.arguments(env)


if __name__ == "__main__":
    unittest.main()
