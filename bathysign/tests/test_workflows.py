#!/usr/bin/env python3
# Copyright 2026 Kenny Root
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def test_signer_and_ci_use_the_same_locked_runtime(self):
        runtime = ROOT / "bathysign/runtime"
        config = tomllib.loads((runtime / "mise.toml").read_text())
        lock = tomllib.loads((runtime / "mise.lock").read_text())
        for name, version in config["tools"].items():
            self.assertRegex(version, r"\d+\.\d+\.\d+")
            entry, = lock["tools"][name]
            self.assertEqual(entry["version"], version)
            platform = entry["platforms.linux-x64"]
            self.assertTrue(platform["url"].startswith("https://"))
            self.assertRegex(platform["checksum"], r"^sha256:[0-9a-f]{64}$")
        setup = (runtime / "action.yml").read_text()
        self.assertRegex(setup, r"uses: jdx/mise-action@[0-9a-f]{40}")
        self.assertRegex(setup, r"version: \d{4}\.\d+\.\d+")
        for setting in ("working_directory: ${{ github.action_path }}", "install_args: --locked",
                        "cache: false", "add_shims_to_path: false"):
            self.assertIn(setting, setup)
        action = (ROOT / "bathysign/action.yml").read_text()
        self.assertIn("uses: $/bathysign/runtime", action)
        self.assertIn("uses: $/bathysign/runtime", self.attestor())
        ci = (ROOT / ".github/workflows/bathysign-ci.yml").read_text()
        self.assertIn("uses: ./bathysign/runtime", ci)
        self.assertIn("tools: python java", ci)
        for name in ("bathysign-attest.yml", "bathysign-finalize.yml", "bathysign-publish.yml", "bathysign-ci.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text()
            self.assertEqual(set(re.findall(r"runs-on: (.+)", workflow)), {"ubuntu-24.04"})

    def test_publishers_verify_before_google_authentication_and_route_testing_tracks(self):
        workflow = (ROOT / ".github/workflows/bathysign-publish.yml").read_text()
        self.assertLess(workflow.index("command: verify-play"), workflow.index("google-github-actions/auth@"))
        self.assertIn("project_id: ${{ needs.play-route.outputs.google_project }}", workflow)
        self.assertNotIn("example", workflow)
        self.assertIn("environment: ${{ format('play-{0}', needs.play-route.outputs.track) }}", workflow)
        self.assertIn("vars.PLAY_BETA_ENABLED", workflow)
        self.assertIn("group: bathysign-play-${{ github.repository_id }}\n", workflow)
        self.assertIn("command: play-route", workflow)
        self.assertNotIn("production", workflow)
        self.assertNotIn("credentials_json", workflow)
        self.assertNotIn("attestations: write", workflow)
        self.assertNotIn("id-token: write", workflow.split("  play:")[0])
        self.assertNotIn("actions/checkout@", workflow)

    def attestor(self):
        return (ROOT / ".github/workflows/bathysign-attest.yml").read_text()

    def python_step(self, name):
        step = self.attestor().split("      - name: " + name + "\n", 1)[1]
        code = step.split("<<'PYTHON'\n", 1)[1].split("          PYTHON\n", 1)[0]
        return textwrap.dedent(code)

    def test_attestor_only_accepts_profile_and_uses_platform_run_identity(self):
        workflow = self.attestor()
        interface, job = workflow.split("jobs:\n", 1)
        self.assertEqual(interface.count("        type: string"), 1)
        self.assertIn("      profile:", interface)
        for forbidden in ("actions/checkout@", "gradlew", "setup-java@", "setup-android@",
                          "setup-gradle@", "secrets:", "run-id:", "repository:",
                          "artifact-ids:", "pattern:", "merge-multiple:", "continue-on-error:"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertIn("github.event_name == 'push'", job)
        for artifact in ("unsigned", "release-support", "provenance"):
            self.assertIn("name: " + artifact + "-${{ inputs.profile }}-${{ github.run_attempt }}", job)
        self.assertIn("support/build-info.json", job)
        self.assertLess(job.index("Validate artifact handoff"), job.index("uses: actions/attest@"))
        self.assertFalse((ROOT / ".github/workflows/android-build.yml").exists())

    def test_profile_rejects_paths_globs_and_shell_expressions(self):
        code = self.python_step("Validate artifact profile")
        for profile in ("oss", "google", "another-profile", "../oss", "*", "oss/extra",
                        "$(touch injected)", "oss\nextra", "", "a" * 33):
            with self.subTest(profile=profile):
                result = subprocess.run([sys.executable, "-c", code],
                    env={**os.environ, "PROFILE": profile}, capture_output=True)
                self.assertEqual(result.returncode == 0, profile in ("oss", "google", "another-profile"))

    def test_handoff_rejects_missing_extra_and_symlinked_files(self):
        code = self.python_step("Validate artifact handoff")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory, names in (("unsigned", ("app.apk", "app.aab")),
                                     ("support", ("mapping.txt", "native-debug-symbols.zip", "build-info.json"))):
                (root / directory).mkdir()
                for name in names:
                    (root / directory / name).write_bytes(b"untrusted build output")
            def verify():
                return subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True).returncode
            self.assertEqual(verify(), 0)
            artifact = root / "unsigned/app.apk"
            artifact.unlink()
            self.assertNotEqual(verify(), 0)
            artifact.write_bytes(b"apk")
            extra = root / "support/execute.py"
            extra.write_text("raise SystemExit('must never run')")
            self.assertNotEqual(verify(), 0)
            extra.unlink()
            artifact.unlink()
            artifact.symlink_to(root / "unsigned/app.aab")
            self.assertNotEqual(verify(), 0)


if __name__ == "__main__":
    unittest.main()
