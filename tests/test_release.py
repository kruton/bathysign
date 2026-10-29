import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import json

SPEC = importlib.util.spec_from_file_location('release', pathlib.Path(__file__).resolve().parents[1] / 'scripts/release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_archive_ignores_source_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / 'source'
            source.write_bytes(b'example')
            release.archive(root / 'first', {'bin/tool': source}, 123456)
            source.chmod(0o777)
            release.archive(root / 'second', {'bin/tool': source}, 123456)
            self.assertEqual((root / 'first').read_bytes(), (root / 'second').read_bytes())

    def test_inventory_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                release.inventory(root)

    def test_comparison_rejects_missing_or_changed_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first, second = root / 'first', root / 'second'
            first.mkdir()
            second.mkdir()
            (first / 'binary').write_bytes(b'original')
            (second / 'binary').write_bytes(b'tampered')
            result = subprocess.run([sys.executable, str(release.ROOT / 'scripts/release.py'), 'compare', str(first), str(second), '--report', str(root / 'report')], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'report').exists())

    def test_comparison_records_all_digests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first, second = root / 'first', root / 'second'
            first.mkdir()
            second.mkdir()
            for directory in [first, second]:
                (directory / 'binary').write_bytes(b'identical')
            subprocess.run([sys.executable, str(release.ROOT / 'scripts/release.py'), 'compare', str(first), str(second), '--report', str(root / 'report')], check=True)
            self.assertIn('binary', (root / 'report').read_text())


class ImmutableReleaseTests(unittest.TestCase):
    def test_invalid_release_identity_never_starts_a_subprocess(self):
        for tag in ('--hostname=evil.invalid', '-XPOST', 'v0.2.0?x=1',
                    'v0.2.0/../../issues', 'v0.2.0;id', 'v0.2.0\n',
                    'v01.2.0', 'v0.2.0+metadata', None):
            with self.subTest(tag=tag), mock.patch.object(release.subprocess, 'run') as run, \
                 mock.patch.object(release, 'github_release_api') as api:
                with self.assertRaisesRegex(SystemExit, 'Invalid release tag'):
                    release.verify_published_release(tag, 'c' * 40)
                run.assert_not_called()
                api.assert_not_called()
        for commit in ('--help', 'c' * 39, 'C' * 40, 'c' * 40 + '\n', None):
            with self.subTest(commit=commit), mock.patch.object(release.subprocess, 'run') as run, \
                 mock.patch.object(release, 'github_release_api') as api:
                with self.assertRaisesRegex(SystemExit, 'Invalid release commit'):
                    release.verify_published_release('v0.2.0', commit)
                run.assert_not_called()
                api.assert_not_called()

    def test_verification_uses_only_github_metadata_without_subprocesses(self):
        tag = 'v0.2.0-rc.1'
        responses = [
            {'tag_name': tag, 'draft': False, 'immutable': True},
            {'ref': 'refs/tags/' + tag, 'object': {'type': 'commit', 'sha': 'c' * 40}},
        ]
        with mock.patch.object(release, 'github_release_api', side_effect=responses) as api, \
             mock.patch.object(release.subprocess, 'run') as run:
            release.verify_published_release(tag, 'c' * 40)
        self.assertEqual(api.call_args_list, [
            mock.call('repos/kruton/bathysign/releases/tags/' + tag),
            mock.call('repos/kruton/bathysign/git/ref/tags/' + tag),
        ])
        run.assert_not_called()

    def verify(self, responses):
        with mock.patch.object(release, 'github_release_api', side_effect=responses):
            release.verify_published_release('v0.2.0', 'c'*40)

    def test_annotated_release_tag_resolves_to_the_expected_commit(self):
        self.verify([
            {'tag_name':'v0.2.0','draft':False,'immutable':True},
            {'ref':'refs/tags/v0.2.0','object':{'type':'tag','sha':'a'*40}},
            {'sha':'a'*40,'object':{'type':'commit','sha':'c'*40}},
        ])

    def test_tag_resolution_rejects_cycles_depth_malformed_and_noncommit_objects(self):
        base = [{'tag_name':'v0.2.0','draft':False,'immutable':True}]
        cases = [
            [{'ref':'refs/tags/other','object':{'type':'commit','sha':'c'*40}}],
            [{'ref':'refs/tags/v0.2.0','object':{'type':'tree','sha':'c'*40}}],
            [{'ref':'refs/tags/v0.2.0','object':{'type':'commit','sha':'malformed'}}],
            [{'ref':'refs/tags/v0.2.0','object':{'type':'tag','sha':'a'*40}},
             {'sha':'a'*40,'object':{'type':'tag','sha':'a'*40}}],
            [{'ref':'refs/tags/v0.2.0','object':{'type':'tag','sha':'a'*40}},
             {'sha':'b'*40,'object':{'type':'commit','sha':'c'*40}}],
        ]
        cases.append([{'ref':'refs/tags/v0.2.0','object':{'type':'tag','sha':'0'*40}},
            *({'sha':str(i)*40,'object':{'type':'tag','sha':str(i+1)*40}} for i in range(8))])
        for responses in cases:
            with self.subTest(responses=responses), self.assertRaises(SystemExit):
                self.verify(base + responses)


class GithubReleaseApiTests(unittest.TestCase):
    def request(self, status=200, body=b'{}', env=None, allow_missing=False, failure=None):
        with mock.patch.object(release.http.client, 'HTTPSConnection') as factory, \
             mock.patch.dict(release.os.environ, env or {}, clear=True):
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = status
            response.read.return_value = body
            if failure:
                connection.getresponse.side_effect = failure
            try:
                result = release.github_release_api('repos/kruton/bathysign/releases/tags/v0.2.0',
                                                    allow_missing=allow_missing)
            finally:
                connection.close.assert_called_once()
        return result, factory, connection, response

    def test_requests_use_fixed_https_host_timeout_token_and_bounded_reads(self):
        result, factory, connection, response = self.request(body=b'{"immutable":true}',
            env={'GH_TOKEN':'preferred-token', 'GITHUB_TOKEN':'fallback-token'})
        self.assertEqual(result, {'immutable':True})
        factory.assert_called_once_with('api.github.com', timeout=30)
        self.assertEqual(connection.request.call_args.args,
                         ('GET', '/repos/kruton/bathysign/releases/tags/v0.2.0'))
        headers = connection.request.call_args.kwargs['headers']
        self.assertEqual(headers['Authorization'], 'Bearer preferred-token')
        self.assertEqual(headers['Accept'], 'application/vnd.github+json')
        response.read.assert_called_once_with(8 * 1024 * 1024 + 1)

    def test_public_requests_and_github_token_fallback(self):
        _, _, connection, _ = self.request()
        self.assertNotIn('Authorization', connection.request.call_args.kwargs['headers'])
        _, _, connection, _ = self.request(env={'GH_TOKEN':'', 'GITHUB_TOKEN':'fallback-token'})
        self.assertEqual(connection.request.call_args.kwargs['headers']['Authorization'],
                         'Bearer fallback-token')

    def test_only_an_explicit_allowed_404_means_a_release_is_missing(self):
        self.assertIsNone(self.request(status=404, allow_missing=True)[0])
        for status in (301, 302, 307, 401, 403, 404, 429, 500, 503):
            for allow_missing in (False, True):
                if status == 404 and allow_missing:
                    continue
                with self.subTest(status=status, allow_missing=allow_missing), \
                     self.assertRaisesRegex(SystemExit, f'HTTP {status}'):
                    self.request(status=status, allow_missing=allow_missing)

    def test_oversized_malformed_and_transport_failures_abort_and_close_connection(self):
        with self.assertRaisesRegex(SystemExit, 'size limit'):
            self.request(body=b'x' * (8 * 1024 * 1024 + 1))
        with self.assertRaises(json.JSONDecodeError):
            self.request(body=b'not JSON')
        with self.assertRaises(TimeoutError):
            self.request(failure=TimeoutError('timed out'))
