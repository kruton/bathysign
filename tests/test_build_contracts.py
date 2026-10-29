"""Check build input integrity and guest launch policy without compiling a kernel."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class BuildContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.target = self.root / 'target'
        self.image = self.target / 'x86_64-unknown-hermit/release/bathysign'
        self.image.parent.mkdir(parents=True)
        self.image.write_bytes(b'Bathysign: strict entropy profile v1\nSecure entropy unavailable: RDSEED is required')
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            data = b'#!/bin/sh\n'
            info = tarfile.TarInfo('rust/rust-install.sh')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        self.downloads = {'https://inputs/std': archive.getvalue(), 'https://inputs/loader': b'loader'}
        self.pins = {'hermit_std_url': 'https://inputs/std', 'hermit_std_sha256': hashlib.sha256(archive.getvalue()).hexdigest(), 'loader_url': 'https://inputs/loader', 'loader_sha256': hashlib.sha256(b'loader').hexdigest(), 'hermit_kernel_toolchain': 'nightly-2026-02-01'}
        self.calls = []

    def run_build(self, offline=False, validation_errors=()):
        original_read = Path.read_text
        helper = SimpleNamespace(verify_kernel_source=mock.Mock(side_effect=[ValueError(message) for message in validation_errors] + [None]))

        def read(path, *args, **kwargs):
            return json.dumps(self.pins) if path == ROOT / 'config/toolchain-pins.json' else original_read(path, *args, **kwargs)

        def run(args, **kwargs):
            self.calls.append((args, kwargs))
            if args[0] == 'bash':
                (self.cache / 'sysroot/lib/rustlib/x86_64-unknown-hermit/lib').mkdir(parents=True)
            return SimpleNamespace(stdout='{"reason":"build-script-executed"}\n\n')

        def download(url, timeout):
            self.assertEqual(timeout, 120)
            return io.BytesIO(self.downloads[url])

        environment = {'CARGO_TARGET_DIR': str(self.target), 'RUSTFLAGS': '--remap-path-prefix=/tmp=/src'}
        if offline:
            environment['BATHYSIGN_OFFLINE_BUILD'] = '1'
        with mock.patch.object(sys, 'argv', ['build-hermit.py', '--cache', str(self.cache)]), mock.patch.dict(sys.modules, {'hermit_build': helper}), mock.patch.dict(os.environ, environment), mock.patch.object(Path, 'read_text', read), mock.patch('urllib.request.urlopen', side_effect=download), mock.patch.object(subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            runpy.run_path(str(ROOT / 'scripts/build-hermit.py'), run_name='__main__')
        return helper

    def test_verified_downloads_sysroot_and_reproducible_compiler_flags(self):
        helper = self.run_build()
        helper.verify_kernel_source.assert_called_once_with([{'reason': 'build-script-executed'}], self.cache / 'kernel')
        build, kwargs = next(call for call in self.calls if call[0][:2] == ['cargo', 'build'])
        flags = json.loads(build[-1].split('=', 1)[1])
        self.assertIn('--remap-path-prefix=/tmp=/src', flags)
        self.assertIn('--sysroot=' + str(self.cache / 'sysroot'), flags)
        self.assertNotIn('RUSTFLAGS', kwargs['env'])
        self.assertEqual(kwargs['env']['HERMIT_MANIFEST_DIR'], str(self.cache / 'kernel'))
        self.assertTrue(any(args[0] == 'rustup' for args, _ in self.calls))
        self.assertEqual((self.cache / 'hermit-loader').read_bytes(), b'loader')
        self.calls.clear()
        self.run_build(offline=True)
        self.assertFalse(any(args[0] in ['rustup', 'bash'] for args, _ in self.calls))

    def test_cached_input_corruption_fails_before_running_tools(self):
        (self.cache / 'hermit-std.tar.gz').write_bytes(b'tampered')
        with self.assertRaisesRegex(SystemExit, 'Hash mismatch'):
            self.run_build()
        self.assertEqual(self.calls, [])

    def test_stale_kernel_is_cleaned_once_and_retry_is_bounded(self):
        helper = self.run_build(validation_errors=['stale source'])
        self.assertEqual(helper.verify_kernel_source.call_count, 2)
        cleans = [args for args, _ in self.calls if args[:2] == ['cargo', 'clean']]
        self.assertEqual(cleans, [['cargo', 'clean', '--release', '--package', 'hermit', '--target', 'x86_64-unknown-hermit']])
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'still stale'):
            self.run_build(validation_errors=['stale', 'still stale'])
        self.assertEqual(sum(args[:2] == ['cargo', 'clean'] for args, _ in self.calls), 1)

    def test_missing_entropy_guards_or_fallback_code_never_produce_an_image(self):
        for data in [b'old image', self.image.read_bytes() + b'Fallback to a naive implementation']:
            self.image.write_bytes(data)
            with self.assertRaisesRegex(SystemExit, 'stale/unpatched'):
                self.run_build()


class KernelPreparationContracts(unittest.TestCase):
    def test_hashes_and_exact_patch_counts_protect_the_cargo_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'checkout/kernel'
            source.mkdir(parents=True)
            (source / 'entropy.rs').write_text('old implementation')
            manifest = root / 'checkout/hermit/Cargo.toml'
            pins = {'entropy.rs': hashlib.sha256(b'old implementation').hexdigest()}
            replacements = [{'file': 'entropy.rs', 'before': 'old implementation', 'after': 'strict entropy'}]
            original_read = Path.read_text

            def read(path, *args, **kwargs):
                if path == ROOT / 'kernel-patches/upstream-sha256.json':
                    return json.dumps(pins)
                if path == ROOT / 'kernel-patches/replacements.json':
                    return json.dumps(replacements)
                return original_read(path, *args, **kwargs)

            def execute(output):
                with mock.patch.dict(sys.modules, {'hermit_build': SimpleNamespace(verify_network_sources=mock.Mock())}), mock.patch.object(sys, 'argv', ['prepare-kernel', '--out', str(output)]), mock.patch.object(Path, 'read_text', read), mock.patch.object(subprocess, 'check_output', return_value=json.dumps({'packages': [{'name': 'hermit', 'manifest_path': str(manifest)}]}).encode()), contextlib.redirect_stdout(io.StringIO()):
                    runpy.run_path(str(ROOT / 'scripts/prepare-kernel.py'), run_name='__main__')

            destination = root / 'output'
            execute(destination)
            self.assertEqual((destination / 'entropy.rs').read_text(), 'strict entropy')
            self.assertEqual((source / 'entropy.rs').read_text(), 'old implementation')
            replacements[0]['expected_count'] = 2
            with self.assertRaisesRegex(SystemExit, 'does not apply exactly'):
                execute(root / 'bad-count')
            (source / 'entropy.rs').write_text('untrusted source')
            with self.assertRaisesRegex(SystemExit, 'Upstream kernel differs'):
                execute(root / 'bad-source')
            self.assertFalse((root / 'bad-source').exists())


class GuestLaunchContracts(unittest.TestCase):
    def launch(self, root, arguments=(), daemon_ready=True, daemon_status=None, wait_timeout=False, daemon_help='--readonly --sandbox --socket-path --shared-dir'):
        secret = root / 'secrets'
        secret.mkdir(exist_ok=True)
        (secret / 'config.json').write_text('{}')
        daemon = mock.Mock()
        daemon.poll.return_value = daemon_status
        daemon.wait.side_effect = [subprocess.TimeoutExpired('virtiofsd', 5), None] if wait_timeout else None
        observed = []

        def start(command):
            observed.append(command)
            if daemon_ready:
                socket = next(value.split('=', 1)[1] for value in command if value.startswith('--socket-path='))
                Path(socket).touch()
            return daemon

        with mock.patch.object(sys, 'argv', ['run-qemu', '--secrets', str(secret), *arguments]), mock.patch.object(subprocess, 'check_output', return_value=daemon_help), mock.patch.object(subprocess, 'Popen', side_effect=start), mock.patch.object(subprocess, 'call', return_value=0) as guest, mock.patch('time.sleep'), contextlib.redirect_stderr(io.StringIO()):
            try:
                runpy.run_path(str(ROOT / 'scripts/run-qemu.py'), run_name='__main__')
            except SystemExit as error:
                return error, observed, guest, daemon
        raise AssertionError('guest launcher must return a process status')

    def test_launch_keeps_secrets_readonly_and_cleans_up_the_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            error, observed, guest, daemon = self.launch(Path(temporary), ['--tcg', '--gdb-port', '1234', '--memory', '2G', '--test-unsandboxed-fs'])
            self.assertEqual(error.code, 0)
            self.assertIn('--readonly', observed[0])
            self.assertIn('--sandbox=none', observed[0])
            args = guest.call_args.args[0]
            self.assertEqual(args[args.index('-accel') + 1], 'tcg')
            self.assertEqual(args[args.index('-cpu') + 1], 'max')
            self.assertIn('tcp:127.0.0.1:1234', args)
            self.assertNotIn('-drive', args)
            daemon.terminate.assert_called_once()
            daemon.wait.assert_called_once_with(timeout=5)

    def test_default_kvm_profile_uses_namespace_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            error, observed, guest, daemon = self.launch(Path(temporary), wait_timeout=True)
            self.assertEqual(error.code, 0)
            self.assertIn('--sandbox=namespace', observed[0])
            self.assertEqual(guest.call_args.args[0][guest.call_args.args[0].index('-cpu') + 1], 'host')
            daemon.kill.assert_called_once()

    def test_dead_daemon_and_missing_socket_stop_guest_boot(self):
        with tempfile.TemporaryDirectory() as temporary:
            for status, message in [(1, 'virtiofsd failed'), (None, 'socket unavailable')]:
                error, _, guest, daemon = self.launch(Path(temporary), daemon_ready=False, daemon_status=status)
                self.assertIn(message, str(error))
                guest.assert_not_called()
                daemon.terminate.assert_called_once()

    def test_daemon_without_readonly_support_cannot_export_secrets_or_boot_guest(self):
        with tempfile.TemporaryDirectory() as temporary:
            error, observed, guest, daemon = self.launch(Path(temporary), daemon_help='--sandbox --socket-path --shared-dir')
            self.assertEqual(error.code, 2)
            self.assertEqual(observed, [])
            guest.assert_not_called()
            daemon.terminate.assert_not_called()

    def test_missing_configuration_never_starts_a_daemon(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(sys, 'argv', ['run-qemu', '--secrets', temporary]), mock.patch.object(subprocess, 'Popen') as daemon, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    runpy.run_path(str(ROOT / 'scripts/run-qemu.py'), run_name='__main__')
                self.assertEqual(error.exception.code, 2)
                daemon.assert_not_called()
