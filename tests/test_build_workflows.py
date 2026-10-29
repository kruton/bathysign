"""Guard release/PR build parity and the read-only CI trust boundary."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github/workflows'


def workflow(name):
    return (WORKFLOWS / name).read_text()


class BuildWorkflowContracts(unittest.TestCase):
    def test_pr_and_release_use_the_same_targets_builders_and_integration(self):
        checks = workflow('build-checks.yml')
        release = workflow('release.yml')
        targets = r'- target: (\S+)\s+runner: (\S+)'
        self.assertEqual(re.findall(targets, checks), re.findall(targets, release))
        self.assertEqual(len(re.findall(targets, checks)), 3)
        self.assertIn('uses: ./.github/workflows/build.yml', checks)
        self.assertIn('uses: ./.github/workflows/build.yml', workflow('release-build.yml'))
        for caller in (checks, release):
            self.assertIn('uses: ./.github/workflows/build-integration.yml', caller)
        containers = r'- arch: (\S+)\s+target: (\S+)\s+runner: (\S+)'
        self.assertEqual(re.findall(containers, checks), re.findall(containers, workflow('release-container.yml')))
        for caller in (checks, workflow('release-container.yml')):
            self.assertIn('uses: ./.github/workflows/container-build.yml', caller)

    def test_all_workflows_reachable_from_prs_are_read_only_and_linted(self):
        pending, visited = ['build-checks.yml'], set()
        lint = (ROOT / 'scripts/lint-workflows.sh').read_text()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            content = workflow(name)
            self.assertIn('.github/workflows/' + name, lint)
            self.assertNotRegex(content, r': write\b|secrets\.|secrets: inherit|pull_request_target|uses: actions/attest@')
            pending.extend(re.findall(r'uses: \./\.github/workflows/(\S+)', content))
        self.assertEqual(visited, {'build-checks.yml', 'build.yml', 'build-integration.yml', 'container-build.yml'})
        self.assertNotIn('secrets:', workflow('build-checks.yml'))

    def test_common_builder_keeps_isolated_offline_rebuilds_and_packaged_guest_tests(self):
        build = workflow('build.yml')
        self.assertIn('copy: [first, second]', build)
        self.assertIn('fail-fast: false', build)
        self.assertIn('bash scripts/release-build.sh "$TARGET" prepare', build)
        self.assertIn('--network none -e CARGO_NET_OFFLINE=true -e BATHYSIGN_OFFLINE_BUILD=1', build)
        self.assertIn('python3 scripts/release.py compare first second', build)
        integration = workflow('build-integration.yml')
        self.assertIn('python3 scripts/test-android.py', integration)
        self.assertIn('tests/qemu-smoke.py --tcg', integration)
        for binary in ('--loader "$PWD/guest/bin/hermit-loader"', '--image "$PWD/guest/bin/bathysign"',
                       '--admin "$PWD/host/bin/bathysign-admin"', '--collector "$PWD/host/bin/bathysign-collector"'):
            self.assertIn(binary, integration)
        self.assertIn('bash scripts/release-container.sh "$ARCH" downloads/*.tar.gz', workflow('container-build.yml'))

    def test_release_attestations_and_offline_evidence_remain_in_the_release_path(self):
        build = workflow('release-build.yml')
        self.assertIn('offline-bundle: true', build)
        self.assertIn('id-token: write', build)
        self.assertIn('attestations: write', build)
        self.assertIn('first/offline/*', build)
        self.assertIn('sbom-path: first/sbom.spdx.json', build)
        self.assertIn('release: true', workflow('release.yml'))
        self.assertIn('release: true', workflow('release-container.yml'))

    def test_aggregate_gate_fails_when_any_required_job_fails_or_is_skipped(self):
        content = workflow('build-checks.yml')
        self.assertIn('if: always()', content)
        self.assertIn('needs: [build, integration, containers]', content)
        script = content.split("python3 - <<'PYTHON'\n", 1)[1].split('          PYTHON', 1)[0]
        script = textwrap.dedent(script)
        for outcome in ('success', 'failure', 'cancelled', 'skipped'):
            results = {name: {'result': 'success'} for name in ('build', 'integration', 'containers')}
            results['integration']['result'] = outcome
            result = subprocess.run([sys.executable, '-c', script],
                env={**os.environ, 'RESULTS': json.dumps(results)}, capture_output=True)
            self.assertEqual(result.returncode == 0, outcome == 'success', result.stderr)


class CompilerPinContracts(unittest.TestCase):
    def test_builder_and_hermit_standard_library_use_the_same_compiler_pin(self):
        pins = json.loads((ROOT / 'config/toolchain-pins.json').read_text())
        builder = json.loads((ROOT / 'config/release-build.json').read_text())['builder']
        self.assertEqual((ROOT / 'deploy/build/Dockerfile').read_text().splitlines()[0], 'FROM ' + builder)
        self.assertTrue(builder.startswith('rust:' + pins['rust_version'] + '-'))
        self.assertIn('/' + pins['rust_version'] + '/', pins['hermit_std_url'])

    def test_mismatched_compiler_fails_before_git_or_dependency_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'config').mkdir()
            (root / 'config/toolchain-pins.json').write_text('{"rust_version":"1.99.0"}')
            for version, expected in [('1.99.1', 1), ('1.99.0', 71)]:
                for name, script in {'rustc': f'#!/bin/sh\necho "rustc {version} (test compiler)"\n',
                                     'git': '#!/bin/sh\nexit 71\n'}.items():
                    path = root / name
                    path.write_text(script)
                    path.chmod(0o755)
                result = subprocess.run(['bash', str(ROOT / 'scripts/release-build.sh'),
                                         'x86_64-unknown-linux-gnu', 'prepare'], cwd=root,
                    env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH']},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                if version == '1.99.1':
                    self.assertIn('pinned Hermit standard library requires Rust 1.99.0', result.stderr)
