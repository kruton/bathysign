"""Kernel preparation must verify pins and never overlay stale source."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/prepare-kernel.py'
UPSTREAM_URL = 'https://example.invalid/kernel.tar.gz'
SOURCE = b'original'


def archive_bytes(member='upstream/source.rs'):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as tar:
        info = tarfile.TarInfo(member)
        info.size = len(SOURCE)
        tar.addfile(info, io.BytesIO(SOURCE))
    return data.getvalue()


class KernelArchiveTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = root / 'work/kernel'
        self.archive = self.output.parent / 'kernel-revision.tar.gz'
        self.archive_data = archive_bytes()
        self.pins = {
            'hermit_kernel_revision': 'revision',
            'hermit_kernel_url': UPSTREAM_URL,
            'hermit_kernel_sha256': hashlib.sha256(self.archive_data).hexdigest(),
        }
        self.pin_files = {
            ROOT / 'config/toolchain-pins.json': self.pins,
            ROOT / 'kernel-patches/upstream-sha256.json': {
                'source.rs': hashlib.sha256(SOURCE).hexdigest(),
            },
            ROOT / 'kernel-patches/replacements.json': [
                {'file': 'source.rs', 'before': 'original', 'after': 'patched'},
            ],
        }
        self.enterContext(mock.patch.object(sys, 'path', [str(ROOT / 'scripts'), *sys.path]))
        self.enterContext(mock.patch('subprocess.check_output', return_value=b'{}'))
        self.verify_network_sources = self.enterContext(mock.patch('hermit_build.verify_network_sources'))
        self.download = self.enterContext(mock.patch('urllib.request.urlopen'))
        read_text = Path.read_text

        def read(path, *args, **kwargs):
            if path in self.pin_files:
                return json.dumps(self.pin_files[path])
            return read_text(path, *args, **kwargs)

        self.enterContext(mock.patch.object(Path, 'read_text', read))

    def prepare(self, *, offline=False):
        with (
            mock.patch.object(sys, 'argv', [str(SCRIPT), '--out', str(self.output)]),
            mock.patch.dict(os.environ, BATHYSIGN_OFFLINE_BUILD='1' if offline else ''),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runpy.run_path(str(SCRIPT), run_name='__main__')

    def existing_output(self):
        self.output.mkdir(parents=True)
        saved = self.output / 'previous.rs'
        saved.write_bytes(b'previous')
        return saved

    def test_verified_offline_source_replaces_stale_output(self):
        self.archive.parent.mkdir()
        self.archive.write_bytes(self.archive_data)
        self.prepare(offline=True)
        stale = self.output / 'stale.rs'
        stale.write_bytes(b'stale')
        self.prepare(offline=True)
        self.assertEqual((self.output / 'source.rs').read_bytes(), b'patched')
        self.assertFalse(stale.exists())
        self.download.assert_not_called()

    def test_invalid_or_missing_offline_archive_preserves_output(self):
        saved = self.existing_output()
        self.archive.write_bytes(b'corrupt')
        with self.assertRaisesRegex(SystemExit, 'hash mismatch'):
            self.prepare(offline=True)
        self.archive.unlink()
        with self.assertRaisesRegex(SystemExit, 'unavailable offline'):
            self.prepare(offline=True)
        self.assertEqual(saved.read_bytes(), b'previous')
        self.download.assert_not_called()

    def test_downloads_verifies_and_caches_the_pinned_archive(self):
        self.download.return_value = io.BytesIO(self.archive_data)
        self.prepare()
        self.download.assert_called_once_with(UPSTREAM_URL, timeout=120)
        self.assertEqual(self.archive.read_bytes(), self.archive_data)
        self.assertEqual((self.output / 'source.rs').read_bytes(), b'patched')

    def test_hash_mismatch_does_not_cache_download_or_replace_output(self):
        saved = self.existing_output()
        self.download.return_value = io.BytesIO(b'corrupt')
        with self.assertRaisesRegex(SystemExit, 'hash mismatch'):
            self.prepare()
        self.assertFalse(self.archive.exists())
        self.assertEqual(saved.read_bytes(), b'previous')

    def test_rejects_kernel_archive_without_a_top_level_directory(self):
        saved = self.existing_output()
        data = archive_bytes(member='source.rs')
        self.pins['hermit_kernel_sha256'] = hashlib.sha256(data).hexdigest()
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(SystemExit, 'Invalid kernel archive layout'):
            self.prepare(offline=True)
        self.assertEqual(saved.read_bytes(), b'previous')

    def test_rejects_unexpected_cargo_sources_before_download(self):
        saved = self.existing_output()
        self.verify_network_sources.side_effect = ValueError('unapproved Cargo source')
        with self.assertRaisesRegex(SystemExit, 'unapproved Cargo source'):
            self.prepare()
        self.download.assert_not_called()
        self.assertEqual(saved.read_bytes(), b'previous')
