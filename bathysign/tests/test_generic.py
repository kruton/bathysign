"""Bathysign's generic contracts, with network and attestations mocked at their boundaries."""
import base64
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import test_publishing as fixtures

SPEC = importlib.util.spec_from_file_location('bathysign_publish', Path(__file__).resolve().parents[1] / 'scripts/signer-publish.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class GenericTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.HandoffTests('test_complete_handoff')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.policy = copy.deepcopy(self.f.policy)
        self.policy['receipt_namespace'] = 'bathysign'
        self.policy['profiles'] = {'default': {**self.policy['profiles']['oss'], 'package': 'net.example.app'}}
        self.policy['publishing'] = {'version': 1, 'asset_prefix': 'Example', 'primary_profile': 'default', 'play': None}
        self.origin = {'repository': 'example/.github', 'repository_id': 100, 'owner_id': 7, 'ref': 'refs/heads/main',
                       'commit': 'a' * 40, 'path': '.github/bathysign/42.json', 'signing_sha256': 'b' * 64,
                       'publishing_path': '.github/bathysign/42.publishing.json', 'publishing_sha256': 'c' * 64}
        self.manifest = copy.deepcopy(self.f.manifest)
        self.manifest.update(version=2, publishing=self.policy['publishing'], policy_source=self.origin,
                             version_codes={'default': 101})
        self.predicate = copy.deepcopy(self.f.predicate)
        self.predicate['buildDefinition']['externalParameters']['workflow']['path'] = '.github/workflows/bathysign-release.yml'
        self.result = copy.deepcopy(self.f.result)
        self.result['verificationResult']['statement']['predicate'] = self.predicate
        self.env = self.f.env.copy()
        self.populate()

    def populate(self):
        self.f.policy_path.write_bytes(p.json_bytes(self.policy))
        self.origin['sha256'] = p.digest(self.f.policy_path.read_bytes())
        self.predicate['buildDefinition']['resolvedDependencies'] = [
            {'uri': f"git+https://github.com/{self.origin['repository']}@{self.origin['ref']}#{self.origin[path_key]}",
             'digest': {'gitCommit': self.origin['commit'], 'sha256': self.origin[digest_key]}}
            for path_key, digest_key in (('path', 'signing_sha256'), ('publishing_path', 'publishing_sha256'))]
        self.f.policy_path.with_suffix('.source.json').write_bytes(p.json_bytes(self.origin))
        root = self.f.handoff
        for item in root.iterdir():
            item.unlink()
        files = {'predicate.json': p.json_bytes(self.predicate), 'verification.json': b'{}',
                 'bathysign-policy.json': self.f.policy_path.read_bytes(),
                 'version_code.txt': (str(self.manifest['version_codes'][self.policy['publishing']['primary_profile']]) + '\n').encode()}
        for profile in self.policy['profiles']:
            prefix = f"Example-{self.manifest['release']['tag_name']}-{profile}"
            files.update({f'{prefix}.{ext}': b'verified ' + ext.encode() for ext in ('apk', 'aab', 'mapping.txt.zst', 'native-debug-symbols.zip')})
            files[f'provenance-{profile}.json'] = b'{}'
            files.update({f'{profile}-{name}': b'evidence' for name in ('signing-receipt.dsse.json', 'signing-receipt.json',
                          'code_transparency_signed.jwt', 'transparency-certificate.der', 'apk-lineage.bin')})
        for name, data in files.items():
            (root / name).write_bytes(data)
        self.manifest['assets'] = {name: {'sha256': p.digest(data), 'bytes': len(data)} for name, data in files.items()}
        self.refresh()

    def refresh(self):
        data = p.json_bytes(self.manifest)
        (self.f.handoff / 'release-manifest.json').write_bytes(data)
        (self.f.handoff / 'final.sigstore.json').write_bytes(b'mocked signature')
        self.sha = p.digest(data)
        self.result['verificationResult']['statement']['subject'] = [
            {'name': name, 'digest': {'sha256': value['sha256']}} for name, value in self.manifest['assets'].items()]
        self.result['verificationResult']['statement']['subject'].append({'name': 'release-manifest.json', 'digest': {'sha256': self.sha}})

    def verify(self):
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch.object(p.r, 'api', return_value={'id': 42, 'visibility': 'public', 'default_branch': 'main'}), \
             mock.patch.object(p.r, 'verify_workflow_identity'), \
             mock.patch.object(p.r, 'run', return_value=p.json_bytes([self.result])):
            return p.verify_handoff(self.f.handoff, self.sha, self.f.policy_path)

    def test_single_profile_handoff_and_compact_evidence(self):
        self.assertEqual(self.verify(), self.manifest)
        files = {v.name: v.read_bytes() for v in self.f.handoff.iterdir()}
        compact = p.r.compact_publication(files, self.manifest)
        self.assertEqual(len(compact), 4)
        self.assertEqual(p.r.evidence_name(self.manifest), f"Example-{self.manifest['release']['tag_name']}-signing-evidence.zip")
        self.assertEqual(p.play_track(self.manifest), 'none')

    def test_profiles_can_have_distinct_packages_and_version_codes(self):
        self.policy['profiles']['store'] = {**self.policy['profiles']['default'], 'package': 'net.example.store'}
        self.manifest['version_codes']['store'] = 203
        self.populate()
        self.assertEqual(self.verify()['version_codes'], {'default': 101, 'store': 203})

    def test_packaging_multiple_profiles_round_trips_through_handoff_verification(self):
        self.policy['profiles']['store'] = {**self.policy['profiles']['default'], 'package': 'net.example.store'}
        self.manifest['version_codes']['store'] = 203
        self.populate()
        out = self.f.root / 'prepared'
        out.mkdir()
        metadata = {'source_run': 10, 'source_attempt': 2, 'profiles': {name: {} for name in self.policy['profiles']}}
        (out / 'verification.json').write_bytes(p.json_bytes(metadata))
        predicate = copy.deepcopy(self.predicate)
        predicate['buildDefinition']['resolvedDependencies'] = []
        (out / 'predicate.json').write_bytes(p.json_bytes(predicate))
        for profile, code in self.manifest['version_codes'].items():
            directory = out / profile
            directory.mkdir()
            (directory / 'signing-receipt.json').write_bytes(p.json_bytes({'version_code': code, 'provenance': {'aab': {}}}))
            for name in ('app-signed.apk', 'app-signed.aab', 'unsigned-aab.sigstore.json', 'signing-receipt.dsse.json',
                         'code_transparency_signed.jwt', 'transparency-certificate.der', 'apk-lineage.bin'):
                (directory / name).write_bytes(b'verified input')
        source = {'id': 10, 'run_attempt': 2, 'head_sha': self.manifest['source']['commit']}
        def support(policy, source, profile, receipt):
            return ({'mapping.txt': b'mapping', 'native-debug-symbols.zip': b'symbols', 'build-info.json': b'{}'},
                    {'source': self.manifest['source'], 'profile': profile, 'tag': self.manifest['release']['tag_name'],
                     'title': self.manifest['release']['name'], 'version_code': receipt['version_code']},
                    {'id': 11, 'digest': 'sha256:' + 'a'*64})
        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(p.r, 'api', return_value=source), \
             mock.patch.object(p.r, 'validate_transaction'), mock.patch.object(p, 'support_files', side_effect=support), \
             mock.patch.object(p.r, 'verify_provenance'), mock.patch.object(p.r, 'run', return_value=b'compressed mapping'):
            manifest = p.package_release(out, self.f.policy_path)
        self.assertEqual(manifest['version_codes'], {'default': 101, 'store': 203})
        self.assertEqual(manifest['version'], 2)
        self.assertEqual((out / 'publish/version_code.txt').read_bytes(), b'101\n')
        dependencies = p.load((out / 'predicate.json').read_bytes())['buildDefinition']['resolvedDependencies']
        self.assertTrue(any(d['digest'].get('sha256') == self.origin['publishing_sha256'] for d in dependencies))
        self.f.handoff = out / 'publish'
        self.manifest = manifest
        self.predicate = p.load((out / 'predicate.json').read_bytes())
        self.result['verificationResult']['statement']['predicate'] = self.predicate
        self.refresh()
        self.assertEqual(self.verify(), manifest)

    def test_configuration_drift_and_unexpected_profiles_are_rejected(self):
        self.manifest['publishing'] = {**self.policy['publishing'], 'asset_prefix': 'Attacker'}
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'publishing configuration differs'):
            self.verify()
        self.manifest['publishing'] = self.policy['publishing']
        self.manifest['version_codes']['unexpected'] = 101
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'invalid release versions'):
            self.verify()

    def test_unrelated_central_commit_does_not_invalidate_identical_policy_bytes(self):
        current = {**self.origin, 'commit': 'e' * 40}
        self.f.policy_path.with_suffix('.source.json').write_bytes(p.json_bytes(current))
        self.assertEqual(self.verify(), self.manifest)

    def test_source_snapshot_substitution_is_rejected(self):
        self.manifest['policy_source'] = {**self.origin, 'commit': 'f' * 40}
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'central policy source differs'):
            self.verify()

    def test_play_routing_is_opt_in_and_uses_policy_profile(self):
        play = {'profile': 'default', 'project': 'example-project', 'rules': [
            {'ref': 'refs/heads/main', 'track': 'alpha'},
            {'ref': r'refs/tags/v1\.0\.(?P<patch>[0-9]+)', 'track': 'beta',
             'version_code': {'base': 100, 'multiplier': 1, 'group': 'patch', 'min': 0, 'max': 49}}]}
        self.policy['publishing']['play'] = play
        p.settings(self.policy)
        self.assertEqual(p.play_track(self.manifest), 'alpha')
        self.manifest['source']['ref'] = 'refs/tags/v1.0.1'
        self.assertEqual(p.play_track(self.manifest), 'beta')
        self.manifest['version_codes']['default'] = 102
        with self.assertRaisesRegex(ValueError, 'version code differs'):
            p.play_track(self.manifest)
        self.manifest['source']['ref'] = 'refs/heads/main'
        play['rules'].append({'ref': 'refs/heads/.*', 'track': 'beta'})
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            p.play_track(self.manifest)
        with self.assertRaisesRegex(ValueError, 'invalid Play API path'):
            p.Play('token', 'net.example.app').request('GET', 'applications/other.app/edits')

    def test_play_publication_reuses_the_configured_app_bundle_without_uploading(self):
        self.policy['publishing']['play'] = {'profile': 'default', 'project': 'example-project',
            'rules': [{'ref': 'refs/heads/main', 'track': 'alpha'}]}
        self.populate()
        bundle = next(self.f.handoff.glob('Example-*-default.aab')).read_bytes()
        client = mock.Mock(package='net.example.app')
        client.request.side_effect = [
            {'id': 'edit'}, {'bundles': [{'versionCode': 101, 'sha256': p.digest(bundle)}]},
            {'releases': [{'versionCodes': ['101'], 'status': 'completed'}]}, {}]
        result = p.play_release(client, self.f.handoff, self.manifest, 'alpha')
        self.assertEqual(result['package'], 'net.example.app')
        self.assertEqual(result['status'], 'already-published')
        self.assertEqual(client.request.call_args_list[0].args, ('POST', 'applications/net.example.app/edits', {}))
        self.assertFalse(any('uploadType=' in c.args[1] for c in client.request.call_args_list))
        client.package = 'other.app'
        with self.assertRaisesRegex(ValueError, 'Play application differs'):
            p.play_release(client, self.f.handoff, self.manifest, 'alpha')

    def test_policy_source_is_derived_from_platform_identity_and_pinned_once(self):
        raw = {k: v for k, v in self.policy.items() if k != 'publishing'}
        def file(path, value):
            return {'type': 'file', 'encoding': 'base64', 'path': path,
                    'content': base64.b64encode(p.json_bytes(value)).decode()}
        responses = [ {'id': 100, 'full_name': 'example/.github', 'owner': {'id': 7}, 'default_branch': 'policies'},
            {'protected': True, 'commit': {'sha': 'a' * 40}},
            file('.github/bathysign/42.json', raw),
            file('.github/bathysign/42.publishing.json', self.policy['publishing'])]
        env = {**self.env, 'GITHUB_REPOSITORY_ID': '42', 'GITHUB_REPOSITORY_OWNER_ID': '7',
               'BATHYSIGN_POLICY_REPOSITORY': 'attacker/policies'}
        out = self.f.root / 'fetched.json'
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(p, 'policy_api', side_effect=responses) as api, \
             mock.patch.object(p.r, 'api', return_value={'id': 42, 'full_name': 'example/app', 'owner': {'id': 7}}):
            self.assertEqual(p.policy_repository(), 'example/.github')
            p.fetch_policy(out)
            self.assertEqual(api.call_args.args, ('/contents/.github/bathysign/42.publishing.json?ref=' + 'a' * 40,))
            self.assertEqual(p.load(out.read_bytes()), self.policy)
        for owner in (8,):
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(p, 'policy_api') as api, \
                 mock.patch.object(p.r, 'api', return_value={'id': 42, 'full_name': 'example/app', 'owner': {'id': owner}}):
                with self.assertRaisesRegex(ValueError, 'caller repository identity'):
                    p.fetch_policy(out)
                api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
