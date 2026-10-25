"""CLI dispatch must preserve verification inputs and never bypass routing gates."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import test_publishing as fixtures
p = fixtures.p


class PublishingCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out = self.root / 'out'
        self.out.mkdir()
        self.policy = self.root / 'policy.json'
        self.policy.write_text(json.dumps({'profiles':{'oss':{'package':'net.example.app'}}}))
        self.report = self.root / 'report.json'
        self.bundle = self.root / 'bundle.json'
        self.bundle.write_bytes(b'authenticated bundle')
        self.manifest = {'publishing':{'play':{'profile':'oss', 'project':'example-project'}}}
        self.outputs = self.root / 'outputs'
        self.env = {'GITHUB_OUTPUT':str(self.outputs), 'GOOGLE_PLAY_ACCESS_TOKEN':'test-only-token'}

    def execute(self, command, extras=(), with_policy=True, with_report=True):
        args = ['signer-publish', command, '--out', str(self.out)]
        if with_policy: args.extend(['--policy', str(self.policy)])
        if with_report: args.extend(['--report', str(self.report)])
        args.extend(map(str, extras))
        with mock.patch.object(sys, 'argv', args), mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            p.main()

    def test_policy_build_info_and_prepare_dispatch_use_explicit_inputs(self):
        with mock.patch.object(p, 'fetch_policy') as fetch:
            self.execute('policy', with_policy=False)
            fetch.assert_called_once_with(self.out)
        code = self.root/'version-code.txt'
        with mock.patch.object(p, 'build_info') as build:
            self.execute('build-info', ['--profile','oss','--version-code-file',code], with_policy=False)
            build.assert_called_once_with(self.out, 'oss', code, None)
        tools = self.root/'tools'
        with mock.patch.object(p.r, 'prepare') as prepare, mock.patch.object(p, 'package_release') as package:
            self.execute('prepare', ['--source-run','10','--source-attempt','2','--tools',tools])
            prepare.assert_called_once_with(self.policy, 10, 2, self.out, tools)
            package.assert_called_once_with(self.out, self.policy)

    def test_seal_copies_the_bundle_verifies_both_handoffs_and_exports_manifest_digest(self):
        publish = self.out/'publish'
        publish.mkdir()
        manifest = b'{"verified":true}'
        (publish/'release-manifest.json').write_bytes(manifest)
        with mock.patch.object(p, 'verify_handoff') as verify, mock.patch.object(p.r, 'verify_final_bundle') as final:
            self.execute('seal', ['--bundle',self.bundle])
            verify.assert_called_once_with(publish, p.digest(manifest), self.policy)
            final.assert_called_once_with(self.out, self.policy)
        self.assertEqual((publish/'final.sigstore.json').read_bytes(), self.bundle.read_bytes())
        self.assertEqual((self.out/'final.sigstore.json').read_bytes(), self.bundle.read_bytes())
        self.assertIn('manifest_sha256='+p.digest(manifest), self.outputs.read_text())

    def test_github_publication_respects_superseding_tags_and_reports_the_destination(self):
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'superseding_tag', return_value='v2.0.0'), mock.patch.object(p, 'github_release') as publish:
            self.execute('github')
            publish.assert_not_called()
        self.assertEqual(json.loads(self.report.read_text()), {'destination':'github','status':'superseded-by-tag','tag':'v2.0.0'})
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'superseding_tag', return_value=None), mock.patch.object(p, 'github_release', return_value={'status':'published'}) as publish:
            self.execute('github')
            publish.assert_called_once_with(self.out, self.manifest)
        self.assertEqual(json.loads(self.report.read_text()), {'status':'published'})

    def test_play_route_exports_only_an_authorized_destination(self):
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'superseding_tag', return_value=None), mock.patch.object(p, 'play_track', return_value='alpha'):
            self.execute('play-route')
        self.assertEqual(self.outputs.read_text(), 'play_track=alpha\ngoogle_project=example-project\n')
        self.outputs.write_text('')
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'superseding_tag', return_value='v2.0.0'), mock.patch.object(p, 'play_track') as track:
            self.execute('play-route')
            track.assert_not_called()
        self.assertEqual(self.outputs.read_text(), 'play_track=none\n')

    def test_play_uses_validated_track_and_the_policy_package(self):
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'validate_play_track') as validate, mock.patch.object(p, 'superseding_tag', return_value=None), mock.patch.object(p, 'Play') as service, mock.patch.object(p, 'play_release', return_value={'status':'uploaded'}) as publish:
            self.execute('play', ['--play-track','alpha'])
            validate.assert_called_once_with(self.manifest, 'alpha')
            service.assert_called_once_with('test-only-token', 'net.example.app')
            publish.assert_called_once_with(service.return_value, self.out, self.manifest, 'alpha')
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'validate_play_track', side_effect=ValueError('track mismatch')), mock.patch.object(p, 'Play') as service:
            with self.assertRaisesRegex(ValueError, 'track mismatch'):
                self.execute('play', ['--play-track','beta'])
            service.assert_not_called()
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'validate_play_track') as validate:
            self.execute('verify-play', ['--play-track','alpha'])
            validate.assert_called_once_with(self.manifest, 'alpha')

    def test_missing_policy_prepare_inputs_bundle_and_report_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'explicit central policy'):
            self.execute('verify', with_policy=False)
        with self.assertRaisesRegex(ValueError, 'source run/attempt/tools'):
            self.execute('prepare')
        with self.assertRaisesRegex(ValueError, 'attestation bundle required'):
            self.execute('seal')
        with mock.patch.object(p, 'verify_handoff', return_value=self.manifest), mock.patch.object(p, 'superseding_tag', return_value=None), mock.patch.object(p, 'github_release', return_value={'status':'published'}):
            with self.assertRaisesRegex(ValueError, 'report path required'):
                self.execute('github', with_report=False)

    def test_release_support_metadata_is_bound_to_the_attested_source(self):
        policy = {'repository':'example/app','repository_id':42,'refs':['refs/heads/main','refs/tags/v*']}
        source = {'id':10,'run_attempt':2,'head_sha':'a'*40}
        receipt = {'version_code':42,'provenance':{'aab':{'ref':'refs/tags/v1.0.0'}}}
        info = {'version':1,'source':{'repository':'example/app','run_id':10,'attempt':2,'commit':'a'*40,'ref':'refs/tags/v1.0.0'}, 'profile':'oss','tag':'v1.0.0','title':'Release v1.0.0','version_code':42}
        def archive():
            stream = io.BytesIO()
            with zipfile.ZipFile(stream,'w') as output:
                output.writestr('mapping.txt',b'mapping')
                output.writestr('native-debug-symbols.zip',b'symbols')
                output.writestr('build-info.json',p.json_bytes(info))
            return stream.getvalue()
        data = archive()
        artifact = {'id':20,'name':'release-support-oss-2','expired':False,'workflow_run':{'id':10,'head_sha':'a'*40,'repository_id':42}, 'size_in_bytes':len(data),'digest':'sha256:'+p.digest(data)}
        with mock.patch.object(p.r,'rows',return_value=[artifact]), mock.patch.object(p.r,'run',return_value=data):
            files, metadata, actual = p.support_files(policy,source,'oss',receipt)
            self.assertEqual(metadata,info)
            self.assertEqual(actual['id'],20)
            self.assertEqual(files['mapping.txt'],b'mapping')
            artifact['workflow_run']['repository_id']=99
            with self.assertRaisesRegex(ValueError,'another build'):
                p.support_files(policy,source,'oss',receipt)
            artifact['workflow_run']['repository_id']=42
            artifact['digest']='sha256:wrong'
            with self.assertRaisesRegex(ValueError,'archive digest differs'):
                p.support_files(policy,source,'oss',receipt)

    def test_tag_build_metadata_comes_from_the_source_ref(self):
        code = self.root/'version-code.txt'
        code.write_text('42\n')
        environment = {'GITHUB_REPOSITORY':'example/app','GITHUB_SHA':'a'*40,'GITHUB_REF':'refs/tags/v1.0.0','GITHUB_RUN_ID':'10','GITHUB_RUN_ATTEMPT':'2'}
        with mock.patch.dict(os.environ, environment, clear=True):
            p.build_info(self.out,'oss',code)
        info=json.loads((self.out/'build-info.json').read_text())
        self.assertEqual(info['tag'],'v1.0.0')
        self.assertEqual(info['title'],'Release v1.0.0')
