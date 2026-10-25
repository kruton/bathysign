"""Drive the manifest flow without creating Apps or contacting GitHub."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('registration', ROOT / 'scripts/register-github-app.py')
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'app'
        self.app = {'id': 123, 'slug': 'bathysign-test', 'html_url': 'https://github.com/apps/bathysign-test',
                    'owner': {'login': 'EXAMPLE'}, 'permissions': {'actions': 'read', 'attestations': 'read', 'contents': 'write', 'metadata': 'read'},
                    'events': ['workflow_run'], 'pem': 'PRIVATE-KEY-CONTENTS', 'webhook_secret': 'WEBHOOK-SECRET-CONTENTS'}

    def execute(self, requests, app=None, arguments=(), api_error=None, existing_credential=False):
        responses = []
        clock = [0]
        app = self.app if app is None else app
        output = io.StringIO()
        test = self

        class Server:
            def __init__(self, address, handler):
                test.assertEqual(address, ('127.0.0.1', 18765))
                self.handler = handler
                self.remaining = list(requests)
                self.closed = False

            def handle_request(self):
                path, host = self.remaining.pop(0)
                if not self.remaining:
                    clock[0] = 4000
                handler = self.handler.__new__(self.handler)
                handler.headers = {'Host': host}
                handler.path = path
                handler.requestline = 'GET ' + path + ' HTTP/1.1'
                handler.request_version = 'HTTP/1.1'
                handler.wfile = io.BytesIO()
                if existing_credential:
                    (test.output / 'github-app.pem').write_text('existing')
                handler.do_GET()
                responses.append(handler.wfile.getvalue().decode())

            def server_close(self):
                self.closed = True

        def open_api(request, timeout):
            self.assertEqual(request.full_url, 'https://api.github.com/app-manifests/code123/conversions')
            self.assertEqual(request.method, 'POST')
            self.assertEqual(timeout, 30)
            if api_error:
                raise api_error
            return io.BytesIO(app if isinstance(app, bytes) else json.dumps(app).encode())

        argv = ['register', '--organization', 'example', '--repository', 'app', '--webhook', 'https://signer.example/webhooks/github', '--out', str(self.output), *arguments]
        old_umask = os.umask(0o077)
        try:
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(registration, 'HTTPServer', Server), mock.patch.object(registration.secrets, 'token_urlsafe', return_value='state123'), mock.patch.object(registration.time, 'monotonic', side_effect=lambda: clock[0]), mock.patch.object(registration, 'urlopen', side_effect=open_api), contextlib.redirect_stdout(output):
                try:
                    registration.main()
                except SystemExit as error:
                    return error, responses, output.getvalue()
        finally:
            os.umask(old_umask)
        return None, responses, output.getvalue()

    def test_manifest_registration_and_credentials_stay_local(self):
        error, replies, output = self.execute([('/register?state=state123', '127.0.0.1:18765'), ('/callback?state=state123&code=code123', '127.0.0.1:18765')])
        self.assertIsNone(error)
        self.assertIn('200 OK', replies[0])
        self.assertIn('form-action https://github.com', replies[0])
        self.assertIn('Cache-Control: no-store', replies[0])
        self.assertIn('Referrer-Policy: no-referrer', replies[0])
        self.assertIn('App registered', replies[1])
        public = json.loads((self.output / 'registration.json').read_text())
        self.assertNotIn('pem', public)
        self.assertNotIn('webhook_secret', public)
        self.assertEqual((self.output / 'github-app.pem').read_text(), self.app['pem'])
        self.assertEqual((self.output / 'webhook-secret').read_text(), self.app['webhook_secret'])
        for file in self.output.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('PRIVATE-KEY-CONTENTS', output + ''.join(replies))
        self.assertNotIn('WEBHOOK-SECRET-CONTENTS', output + ''.join(replies))
        self.assertNotIn('code123', output)
        manifest = json.loads((self.output / 'manifest.json').read_text())
        self.assertEqual(manifest['default_events'], ['workflow_run'])
        self.assertEqual(manifest['redirect_url'], 'http://127.0.0.1:18765/callback')
        self.assertFalse(manifest['public'])
        self.assertFalse(manifest['request_oauth_on_install'])

    def test_invalid_hosts_states_routes_and_codes_do_not_register(self):
        requests = [('/register?state=state123', 'evil.example'), ('/register', '127.0.0.1:18765'),
                    ('/register?state=wrong', '127.0.0.1:18765'), ('/register?state=state123&state=state123', '127.0.0.1:18765'),
                    ('/unknown?state=state123', '127.0.0.1:18765'), ('/callback?state=state123', '127.0.0.1:18765'),
                    ('/callback?state=state123&code=bad%2Fcode', '127.0.0.1:18765')]
        error, replies, _ = self.execute(requests)
        self.assertIn('expired', str(error))
        self.assertEqual([reply.splitlines()[0].split()[1] for reply in replies], ['403', '403', '403', '403', '404', '400', '400'])
        self.assertEqual([p.name for p in self.output.iterdir()], ['manifest.json'])

    def test_wrong_owner_permissions_events_and_oversized_payload_fail(self):
        for name, value in [('owner', {'login': 'attacker'}), ('permissions', {'contents': 'admin'}), ('events', ['push'])]:
            with self.subTest(name=name):
                self.output = self.root / name
                app = copy.deepcopy(self.app)
                app[name] = value
                error, replies, output = self.execute([('/callback?state=state123&code=code123', '127.0.0.1:18765')], app)
                self.assertIsNotNone(error)
                self.assertIn('502', replies[0])
                self.assertIn('Registration failed', output)
                self.assertFalse((self.output / 'github-app.pem').exists())
        self.output = self.root / 'oversized'
        error, replies, _ = self.execute([('/callback?state=state123&code=code123', '127.0.0.1:18765')], b'x' * (1024 * 1024 + 1))
        self.assertIn('502', replies[0])
        self.assertIsNotNone(error)

    def test_service_errors_and_preexisting_credentials_are_not_overwritten(self):
        error, replies, output = self.execute([('/callback?state=state123&code=code123', '127.0.0.1:18765')], api_error=OSError('sensitive diagnostic'))
        self.assertIsNotNone(error)
        self.assertIn('502', replies[0])
        self.assertNotIn('sensitive diagnostic', output)
        self.output = self.root / 'existing'
        error, replies, _ = self.execute([('/callback?state=state123&code=code123', '127.0.0.1:18765')], existing_credential=True)
        self.assertIsNotNone(error)
        self.assertEqual((self.output / 'github-app.pem').read_text(), 'existing')

    def test_rejects_invalid_registration_arguments(self):
        for arguments in [('--organization', 'bad/owner'), ('--webhook', 'http://unsafe.example')]:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                error, _, _ = self.execute([], arguments=arguments)
                self.assertEqual(error.code, 2)
        self.assertFalse(self.output.exists())
