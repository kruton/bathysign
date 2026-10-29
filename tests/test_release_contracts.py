"""Exercise release CLIs with real files and a fake GitHub service boundary."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release', ROOT / 'scripts/release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
TARGETS = ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-hermit']
COMMIT = 'a' * 40
REF = 'refs/tags/v0.1.0'


def cli(name, *args):
    output = io.StringIO()
    with mock.patch.object(sys, 'argv', [name, *map(str, args)]), mock.patch.dict(sys.modules, {'release': release}), contextlib.redirect_stdout(output):
        runpy.run_path(str(ROOT / 'scripts' / name), run_name='__main__')
    return output.getvalue()


class ReleaseContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.downloads = self.root / 'downloads'
        self.downloads.mkdir()
        for target in TARGETS:
            directory = self.downloads / target
            directory.mkdir()
            (directory / 'inputs.json').write_text(json.dumps({'target': target, 'source': COMMIT}))
            (directory / f'bathysign-{target}.tar.gz').write_bytes(b'artifact-' + target.encode())
            original = release.inventory(directory)
            (directory / 'reproducibility.json').write_text(json.dumps({'matched': True, 'sha256': original}))
            (directory / 'sbom.spdx.json').write_text('{}')
            (directory / 'sbom-attestation.json').write_text('{}')
            (directory / 'provenance.json').write_text('{}')
            (directory / 'offline').mkdir()
            (directory / 'offline/inputs.tar.gz.part-00').write_bytes(b'offline')
            (directory / 'offline/builder.tar.part-00').write_bytes(b'builder')
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        (self.evidence / 'evidence-provenance.json').write_text('{}')
        (self.evidence / 'image-provenance.json').write_text('{}')
        arch = self.evidence / 'container-amd64-1'
        arch.mkdir()
        (arch / 'reproducibility.json').write_text('{}')
        (arch / 'sbom.spdx.json').write_text('{}')
        (arch / 'collector.oci.tar').write_bytes(b'container image')

    def verify(self):
        return cli('verify-release.py', self.downloads, '--commit', COMMIT, '--ref', REF)

    def test_verifies_every_artifact_with_exact_builder_and_source_policy(self):
        with mock.patch.object(subprocess, 'run') as gh:
            self.verify()
        self.assertEqual(len(gh.call_args_list), 21)
        for call in gh.call_args_list:
            args = call.args[0]
            self.assertEqual(args[:3], ['gh', 'attestation', 'verify'])
            for flag, value in [('--repo', 'kruton/bathysign'), ('--source-digest', COMMIT), ('--signer-digest', COMMIT), ('--source-ref', REF), ('--signer-workflow', 'kruton/bathysign/.github/workflows/release-build.yml')]:
                self.assertEqual(args[args.index(flag) + 1], value)
            self.assertIn('--deny-self-hosted-runners', args)
            self.assertTrue(call.kwargs['check'])

    def test_attestation_failure_aborts_verification(self):
        with mock.patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')):
            with self.assertRaises(subprocess.CalledProcessError):
                self.verify()

    def test_incomplete_targets_wrong_source_and_duplicate_targets_fail(self):
        for mutation in ['wrong-source', 'unknown-target', 'duplicate-target']:
            with self.subTest(mutation=mutation):
                path = self.downloads / TARGETS[0] / 'inputs.json'
                original = path.read_text()
                value = json.loads(original)
                value['source' if mutation == 'wrong-source' else 'target'] = 'unexpected' if mutation != 'duplicate-target' else TARGETS[1]
                path.write_text(json.dumps(value))
                with mock.patch.object(subprocess, 'run'), self.assertRaisesRegex(SystemExit, 'Unexpected target or source'):
                    self.verify()
                path.write_text(original)
        empty = self.root / 'empty'
        empty.mkdir()
        with self.assertRaisesRegex(SystemExit, 'Incomplete release'):
            cli('verify-release.py', empty, '--commit', COMMIT, '--ref', REF)

    def test_report_digest_and_match_flag_are_enforced(self):
        directory = self.downloads / TARGETS[0]
        report_path = directory / 'reproducibility.json'
        report = json.loads(report_path.read_text())
        for changed in [dict(report, matched=False), dict(report, sha256={})]:
            report_path.write_text(json.dumps(changed))
            with mock.patch.object(subprocess, 'run'), self.assertRaisesRegex(SystemExit, 'Rebuild evidence'):
                self.verify()
        report_path.write_text(json.dumps(report))
        (directory / 'extra-binary').write_bytes(b'unsigned')
        with mock.patch.object(subprocess, 'run'), self.assertRaisesRegex(SystemExit, 'Rebuild evidence'):
            self.verify()

    def test_release_entries_and_nested_artifacts_cannot_be_symlinks(self):
        link = self.downloads / 'link'
        link.symlink_to(self.downloads / TARGETS[0], target_is_directory=True)
        with mock.patch.object(subprocess, 'run'), self.assertRaisesRegex(SystemExit, 'Unexpected release entry'):
            self.verify()
        link.unlink()
        link = self.downloads / TARGETS[0] / 'offline/link'
        link.symlink_to(self.root)
        with mock.patch.object(subprocess, 'run'), self.assertRaisesRegex(SystemExit, 'Unexpected artifact type'):
            self.verify()
        link.unlink()
        (self.downloads / 'not-a-directory').write_text('bad')
        with mock.patch.object(subprocess, 'run'), self.assertRaisesRegex(SystemExit, 'Unexpected release entry'):
            self.verify()

    def publish(self, existing=None, immutable=True, draft=False, release_commit=COMMIT):
        staged = {}
        calls = []

        def gh(args, **kwargs):
            calls.append(args)
            if args[:3] == ['gh', 'release', 'download']:
                destination = Path(args[args.index('--dir') + 1])
                files = existing if existing is not True else {p.name: p.read_bytes() for p in destination.parent.iterdir() if p.is_file()}
                for name, data in files.items():
                    (destination / name).write_bytes(data)
            if args[:3] == ['gh', 'release', 'create']:
                for name in args[args.index('--notes') + 2:]:
                    staged[Path(name).name] = Path(name).read_bytes()
            return subprocess.CompletedProcess(args, 0, stdout='')

        def api(path, *, allow_missing=False):
            if allow_missing and existing is None:
                return None
            if '/releases/tags/' in path:
                return {'tag_name':'v0.1.0', 'draft':draft, 'immutable':immutable}
            return {'ref':'refs/tags/v0.1.0', 'object':{'type':'commit', 'sha':release_commit}}

        with mock.patch.object(subprocess, 'run', side_effect=gh), \
             mock.patch.object(release, 'github_release_api', side_effect=api):
            cli('publish-release.py', self.downloads, REF.removeprefix('refs/tags/'), COMMIT, self.evidence)
        return staged, calls

    def test_publication_has_only_install_archives_checksums_and_verification_bundle(self):
        staged, calls = self.publish()
        self.assertEqual(set(staged), {
            *(f'bathysign-{target}.tar.gz' for target in TARGETS),
            'bathysign-0.1.0-verification.tar.gz', 'SHA256SUMS',
        })
        self.assertIn('SHA256SUMS', staged)
        sums = staged.pop('SHA256SUMS').decode().splitlines()
        expected = {f'{hashlib.sha256(data).hexdigest()}  {name}' for name, data in staged.items()}
        self.assertEqual(set(sums), expected)
        for target in TARGETS:
            self.assertIn(f'bathysign-{target}.tar.gz', staged)
        with tarfile.open(fileobj=io.BytesIO(staged['bathysign-0.1.0-verification.tar.gz'])) as bundle:
            expected = {'VERIFY.md', 'containers/evidence-provenance.json', 'containers/image-provenance.json',
                        'containers/container-amd64-1/reproducibility.json', 'containers/container-amd64-1/sbom.spdx.json'}
            for target in TARGETS:
                for name in ('inputs.json', 'provenance.json', 'reproducibility.json', 'sbom.spdx.json', 'sbom-attestation.json'):
                    expected.add(target + '/' + name)
                    self.assertEqual(bundle.extractfile(target + '/' + name).read(), (self.downloads / target / name).read_bytes())
            self.assertEqual(set(bundle.getnames()), expected)
        create = next(args for args in calls if args[:3] == ['gh', 'release', 'create'])
        self.assertIn('--prerelease', create)
        self.assertIn('--verify-tag', create)
        self.assertEqual(create[create.index('--target') + 1], COMMIT)
        notes = create[create.index('--notes') + 1]
        self.assertIn('Signing appliance', notes)
        self.assertIn('AMD64 Linux', notes)
        self.assertIn('ARM64 Linux', notes)
        self.assertIn('ghcr.io/kruton/bathysign-collector:v0.1.0', notes)
        evidence = [args for args in calls if args[:3] == ['gh', 'attestation', 'verify']]
        self.assertEqual(len(evidence), 4)
        for args in evidence:
            self.assertEqual(args[args.index('--source-digest') + 1], COMMIT)

    def test_identical_existing_release_does_not_upload_or_replace_assets(self):
        staged, calls = self.publish(existing=True)
        self.assertEqual(staged, {})
        self.assertFalse(any(args[:3] == ['gh', 'release', 'create'] for args in calls))

    def test_release_publication_requires_immutability_and_the_expected_commit(self):
        for existing in (None, True):
            with self.subTest(existing=existing):
                with self.assertRaisesRegex(SystemExit, 'immutable'):
                    self.publish(existing=existing, immutable=False)
                with self.assertRaisesRegex(SystemExit, 'source commit differs'):
                    self.publish(existing=existing, release_commit='b' * 40)
        with self.assertRaisesRegex(SystemExit, 'Incomplete release draft'):
            self.publish(existing=True, draft=True)

    def test_publish_rejects_option_injection_before_any_command(self):
        for tag, commit in [('--help', COMMIT), ('v0.2.0', '--hostname=evil.invalid')]:
            with self.subTest(tag=tag, commit=commit), mock.patch.object(subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'Invalid release'):
                    cli('publish-release.py', self.downloads, tag, commit, self.evidence)
                run.assert_not_called()

    def test_release_lookup_failure_never_creates_or_downloads_a_release(self):
        with mock.patch.object(subprocess, 'run') as run, \
             mock.patch.object(release, 'github_release_api', side_effect=SystemExit('HTTP 503')):
            with self.assertRaisesRegex(SystemExit, 'HTTP 503'):
                cli('publish-release.py', self.downloads, 'v0.2.0', COMMIT, self.evidence)
        self.assertFalse(any(call.args[0][:2] == ['gh', 'release'] for call in run.call_args_list))

    def test_conflicting_release_or_failed_container_attestation_aborts(self):
        with self.assertRaisesRegex(SystemExit, 'Existing release conflicts'):
            self.publish(existing={'unrelated': b'wrong'})
        with mock.patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')):
            with self.assertRaises(subprocess.CalledProcessError):
                cli('publish-release.py', self.downloads, 'v0.1.0', COMMIT, self.evidence)


class PackageContracts(unittest.TestCase):
    def test_host_and_hermit_packages_record_inputs_and_executable_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = ['LICENSE', 'Cargo.lock', 'README.md', 'docs/releases.md', 'scripts/run-qemu.py', 'config/toolchain-pins.json', 'config/signer.example.json']
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{}')
            (root / 'Cargo.toml').write_text('[package]\nversion="1.2.3"\n')
            for target in TARGETS:
                binaries = ['bathysign'] if target.endswith('hermit') else ['bathysign-admin', 'bathysign-collector']
                for binary in binaries:
                    path = root / 'target' / target / 'release' / binary
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(binary.encode())
            (root / 'dist').mkdir()
            (root / 'dist/hermit-loader').write_bytes(b'loader')

            def git(*args):
                return COMMIT if args[1] == 'rev-parse' else '123456' if args[1] == 'show' else 'Cargo.toml\nmissing-file'

            for target in TARGETS:
                output = root / target
                with mock.patch.object(release, 'ROOT', root), mock.patch.object(release, 'run', side_effect=git), mock.patch.object(sys, 'argv', ['release.py', 'package', target, '--out', str(output)]):
                    release.main()
                metadata = json.loads((output / 'inputs.json').read_text())
                self.assertEqual(metadata['source'], COMMIT)
                self.assertEqual(metadata['source_files'], {'Cargo.toml': hashlib.sha256((root / 'Cargo.toml').read_bytes()).hexdigest()})
                with tarfile.open(output / f'bathysign-1.2.3-{target}.tar.gz') as tar:
                    self.assertEqual(tar.getmember('LICENSE').mode, 0o644)
                    self.assertEqual(tar.getmember('config/signer.example.json').mtime, 123456)
                    for binary in ['bathysign', 'hermit-loader'] if target.endswith('hermit') else ['bathysign-admin', 'bathysign-collector']:
                        self.assertEqual(tar.getmember('bin/' + binary).mode, 0o755)
                    self.assertEqual('scripts/run-qemu.py' in tar.getnames(), target.endswith('hermit'))


class ContainerContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()

    def image(self, arch, malformed=False, corrupt=False):
        directory = self.inputs / f'container-{arch}-1'
        directory.mkdir()
        data = ('manifest-' + arch).encode()
        digest = hashlib.sha256(data).hexdigest()
        descriptor = {'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': 'sha256:' + digest, 'size': len(data), 'annotations': {'build': 'run-specific'}}
        index = {'schemaVersion': 2, 'manifests': [] if malformed else [descriptor]}
        files = {'index.json': json.dumps(index).encode(), 'blobs/sha256/' + digest: b'corrupt' if corrupt else data}
        with tarfile.open(directory / 'collector.oci.tar', 'w') as tar:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))

    def test_index_rebuilds_identically_and_keeps_both_architectures(self):
        self.image('amd64')
        self.image('arm64')
        first, second = self.root / 'first', self.root / 'second'
        digest = cli('container-index.py', self.inputs, first).strip()
        self.assertEqual(digest, cli('container-index.py', self.inputs, second).strip())
        self.assertEqual(release.inventory(first), release.inventory(second))
        index = json.loads((first / 'blobs/sha256' / digest.removeprefix('sha256:')).read_text())
        self.assertEqual([child['platform']['architecture'] for child in index['manifests']], ['amd64', 'arm64'])
        self.assertTrue(all('annotations' not in child for child in index['manifests']))
        self.assertEqual(json.loads((first / 'oci-layout').read_text())['imageLayoutVersion'], '1.0.0')

    def test_missing_architecture_is_rejected(self):
        self.image('amd64')
        with self.assertRaisesRegex(SystemExit, 'Missing or duplicate architecture'):
            cli('container-index.py', self.inputs, self.root / 'result')

    def test_invalid_manifest_set_is_rejected(self):
        self.image('amd64', malformed=True)
        with self.assertRaisesRegex(SystemExit, 'Unexpected OCI layout'):
            cli('container-index.py', self.inputs, self.root / 'result')

    def test_corrupt_blob_is_rejected(self):
        self.image('amd64', corrupt=True)
        with self.assertRaisesRegex(SystemExit, 'Corrupt OCI blob'):
            cli('container-index.py', self.inputs, self.root / 'result')
