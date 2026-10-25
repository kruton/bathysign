import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

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
