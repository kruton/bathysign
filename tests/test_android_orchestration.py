"""External Android tools are simulated; command policy and artifacts are real."""
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
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class DeviceRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'output'
        self.device = module('test-rotation-devices')
        self.commands = []
        self.instances = []
        self.ports_in_use = False
        self.boot_error_once = False
        self.never_boot = False
        self.emulator_exits = False
        self.bad_install = False
        self.cleanup_error = False
        self.clock = 0
        self.installed = {}
        self.markers = set()

    def command(self, *values, **kwargs):
        args = [str(value) for value in values]
        self.commands.append(args)
        if args[0].endswith('aapt2'):
            Path(args[args.index('-o') + 1]).write_bytes(b'unsigned fixture')
            return b''
        if args[0] == 'cargo':
            for version in (1, 2, 3):
                (self.output / f'signed-{version}.apk').write_bytes(b'signed fixture')
            self.assertEqual(kwargs['env']['BATHYSIGN_ROTATION_FIXTURES'], str(self.output))
            return b'Android reference tests passed\n'
        if args[0].endswith('avdmanager'):
            path = Path(args[args.index('--path') + 1])
            path.mkdir()
            (path / 'config.ini').write_text('disk.dataPartition.size=100\nhw.cpu.arch=x86\n')
            return b''
        if args[-1] == 'devices':
            return b'emulator-5580\tdevice\n' if self.ports_in_use else b'List of devices attached\n'
        self.assertTrue(args[0].endswith('/adb'))
        serial, command = args[2], args[3:]
        if command == ['shell', 'getprop', 'sys.boot_completed']:
            if self.boot_error_once:
                self.boot_error_once = False
                raise subprocess.CalledProcessError(1, 'adb')
            return b'0' if self.never_boot else b'1'
        if command == ['shell', 'getprop', 'ro.build.version.sdk']:
            return b'24' if serial.endswith('5580') else b'28'
        if command[:2] == ['install', '-r']:
            version = Path(command[2]).stem.removeprefix('signed-')
            self.installed[serial] = version
            return b'Failure' if self.bad_install else b'Success'
        if command[:4] == ['shell', 'run-as', self.device.PACKAGE, 'sh']:
            self.markers.add(serial)
            return b''
        if command[:4] == ['shell', 'run-as', self.device.PACKAGE, 'cat']:
            return b'retained' if serial in self.markers else b''
        if command[:3] == ['shell', 'dumpsys', 'package']:
            return ('versionCode=' + self.installed[serial]).encode()
        if command == ['uninstall', self.device.PACKAGE]:
            self.markers.discard(serial)
            return b'Success'
        if command == ['emu', 'kill']:
            if self.cleanup_error:
                raise subprocess.CalledProcessError(1, 'adb')
            return b''
        raise AssertionError('Unexpected adb command: ' + repr(command))

    def execute(self):
        argv = ['test-rotation-devices', '--sdk', str(self.root / 'sdk'), '--java-home', str(self.root / 'java'), '--reference-tools', str(self.root / 'reference'), '--out', str(self.output)]

        def start(args, **kwargs):
            self.assertIn('-no-snapshot', args)
            self.assertIn('-no-window', args)
            process = mock.Mock()
            process.poll.return_value = 1 if self.emulator_exits else None
            process.wait.side_effect = [subprocess.TimeoutExpired('emulator', 20), None] if self.cleanup_error else None
            self.instances.append(process)
            return process

        def sleep(seconds):
            self.clock += seconds

        with mock.patch.object(sys, 'argv', argv), mock.patch.object(self.device, 'run', side_effect=self.command), mock.patch.object(self.device.subprocess, 'Popen', side_effect=start), mock.patch.object(self.device.time, 'monotonic', side_effect=lambda: self.clock), mock.patch.object(self.device.time, 'sleep', side_effect=sleep), contextlib.redirect_stdout(io.StringIO()):
            self.device.main()

    def test_both_emulators_preserve_data_across_incremental_and_skipped_upgrades(self):
        self.boot_error_once = True
        self.execute()
        report = json.loads((self.output / 'report.json').read_text())
        self.assertEqual(report['status'], 'passed')
        self.assertEqual([row['api'] for row in report['checks']], [24, 24, 28, 28])
        self.assertTrue(all(row['data_retained'] for row in report['checks']))
        self.assertEqual([row['versions'] for row in report['checks']], [[1,2,3], [1,3], [1,2,3], [1,3]])
        self.assertEqual(len(self.instances), 2)
        self.assertFalse(any((self.output / 'avds').glob('*.avd')))
        for process in self.instances:
            process.wait.assert_called_once_with(timeout=20)

    def test_ports_in_use_are_never_reused(self):
        self.ports_in_use = True
        with self.assertRaisesRegex(RuntimeError, 'ports already in use'):
            self.execute()
        self.assertEqual(self.instances, [])

    def test_failed_install_records_failure_and_cleans_up(self):
        self.bad_install = True
        self.cleanup_error = True
        with self.assertRaises(AssertionError):
            self.execute()
        self.assertEqual(json.loads((self.output / 'report.json').read_text())['status'], 'failed')
        self.instances[0].terminate.assert_called_once()
        self.instances[0].kill.assert_called_once()
        self.assertFalse(any((self.output / 'avds').glob('*.avd')))

    def test_exited_emulator_is_reported_and_cleaned_up(self):
        self.emulator_exits = True
        with self.assertRaisesRegex(RuntimeError, 'emulator stopped'):
            self.execute()
        self.instances[0].wait.assert_called_once_with(timeout=20)

    def test_boot_deadline_is_bounded(self):
        self.never_boot = True
        with self.assertRaisesRegex(RuntimeError, 'did not boot'):
            self.execute()
        self.assertGreaterEqual(self.clock, 300)


class AndroidReferencePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.commands = []
        zipdata = io.BytesIO()
        with zipfile.ZipFile(zipdata, 'w') as original:
            original.writestr('classes.dex', b'disposable dex')
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode='w:gz') as tar:
            for name, data in {'src/test/resources/com/android/apksig/golden-aligned-in.apk':zipdata.getvalue(), 'src/main/java/Core.java':b'class Core {}', 'src/main/java/kms/aws/Optional.java':b'ignore this'}.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        self.downloads = {'https://inputs/source':source.getvalue(), 'https://inputs/legacy':b'legacy jar', 'https://inputs/bundletool':b'bundletool jar'}
        helper = module('signer_action').load_release()
        self.reference = helper
        self.pins = {'apksig_source_url':'https://inputs/source', 'apksig_source_tree_sha256':helper.source_tree_digest(source.getvalue()), 'apksig_legacy_url':'https://inputs/legacy', 'apksig_legacy_sha256':hashlib.sha256(b'legacy jar').hexdigest(), 'bundletool_url':'https://inputs/bundletool', 'bundletool_sha256':hashlib.sha256(b'bundletool jar').hexdigest()}

    def command(self, args, **kwargs):
        self.commands.append((args, kwargs))
        executable = Path(args[0]).name
        if executable == 'aapt2':
            path = Path(args[args.index('-o') + 1])
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('AndroidManifest.xml', b'compiled manifest')
        elif executable == 'java':
            module = self.cache / 'module.zip'
            with zipfile.ZipFile(module) as archive:
                self.assertEqual(archive.read('dex/classes.dex'), b'disposable dex')
                self.assertEqual(archive.read('manifest/AndroidManifest.xml'), b'compiled manifest')
            (self.cache / 'unsigned.aab').write_bytes(b'reference bundle')
        elif executable == 'cargo':
            self.assertEqual(args, ['cargo', 'test', '--locked', '--all-features'])
            self.assertEqual(kwargs['env']['BATHYSIGN_REFERENCE_APK'], str(self.cache / 'unsigned.apk'))
            self.assertEqual(kwargs['env']['BATHYSIGN_REFERENCE_AAB'], str(self.cache / 'unsigned.aab'))
        else:
            self.assertEqual(executable, 'javac')
        return subprocess.CompletedProcess(args, 0)

    def execute(self):
        original_read = Path.read_text
        helper = module('signer_action')

        def read(path, *args, **kwargs):
            return json.dumps(self.pins) if path == ROOT / 'config/toolchain-pins.json' else original_read(path, *args, **kwargs)

        with mock.patch.object(sys, 'argv', ['test-android', '--cache', str(self.cache), '--java-home', str(self.root / 'java'), '--android-sdk', str(self.root / 'sdk')]), mock.patch.dict(sys.modules, {'signer_action':helper}), mock.patch.object(Path, 'read_text', read), mock.patch('urllib.request.urlopen', side_effect=lambda url, timeout: io.BytesIO(self.downloads[url])), mock.patch.object(subprocess, 'run', side_effect=self.command):
            runpy.run_path(str(ROOT / 'scripts/test-android.py'), run_name='__main__')

    def test_pinned_tools_compile_core_and_pass_real_artifact_paths_to_tests(self):
        self.execute()
        arguments = (self.cache / 'sources.txt').read_text()
        self.assertIn('Core.java', arguments)
        self.assertNotIn('Optional.java', arguments)
        with zipfile.ZipFile(self.cache / 'unsigned.apk') as archive:
            self.assertEqual(archive.read('classes.dex'), b'disposable dex')
        config = json.loads((self.cache / 'bundle-config.json').read_text())
        self.assertFalse(config['optimizations']['storeArchive']['enabled'])
        self.assertEqual([Path(args[0]).name for args, _ in self.commands], ['javac', 'javac', 'aapt2', 'aapt2', 'java', 'cargo'])
        self.execute()  # Cached inputs are checked again, not downloaded unverified.

    def test_corrupt_pinned_tool_is_rejected_before_compilation(self):
        (self.cache / 'apksig-legacy.jar').write_bytes(b'tampered')
        with self.assertRaisesRegex(SystemExit, 'Hash mismatch'):
            self.execute()
        self.assertEqual(self.commands, [])
