"""A green exporter cannot hide a failed reference test or tool setup."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CoverageCollectionTests(unittest.TestCase):
    def execute(self, failure=''):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root/'bin'
            binary.mkdir()
            source = '''#!/bin/bash
printf '%s %s\\n' "${0##*/}" "$*" >> "$TEST_COMMAND_LOG"
case "${0##*/}:$*" in
  rustup:*) test "$TEST_FAILURE" != setup ;;
  'cargo:llvm-cov clean --workspace') test "$TEST_FAILURE" != clean ;;
  'cargo:llvm-cov show-env --export-prefix') test "$TEST_FAILURE" != env || exit 7; printf 'export INSTRUMENTED=1\\n' ;;
  'cargo:llvm-cov report --include-build-script --lcov --output-path coverage/rust.lcov') test "$TEST_FAILURE" != report ;;
  python3:*) test "$INSTRUMENTED" = 1; test "$TEST_FAILURE" != tests ;;
  *) exit 9 ;;
esac
'''
            for name in ['cargo','rustup','python3']:
                path = binary/name
                path.write_text(source)
                path.chmod(0o755)
            log = root/'commands'
            result = subprocess.run(['bash', str(ROOT/'scripts/collect-rust-coverage.sh'), '/jdk', '/sdk'], cwd=root, env={**os.environ, 'PATH':str(binary)+':/usr/bin:/bin', 'TEST_COMMAND_LOG':str(log), 'TEST_FAILURE':failure}, capture_output=True)
            return result, log.read_text().splitlines()

    def test_success_collects_reference_coverage_and_build_script(self):
        result, commands = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(commands), 5)
        self.assertEqual(commands[3], 'python3 scripts/test-android.py --java-home /jdk --android-sdk /sdk')
        self.assertIn('--include-build-script', commands[4])
        self.assertIn('--output-path coverage/rust.lcov', commands[4])

    def test_setup_environment_reference_and_export_failures_remain_failures(self):
        for failure, expected_calls in [('setup',1),('clean',2),('env',3),('tests',4),('report',5)]:
            with self.subTest(failure=failure):
                result, commands = self.execute(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(commands), expected_calls)
