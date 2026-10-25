"""Preparation must reject configuration drift before touching keys or outputs."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("rotation", ROOT / "scripts/prepare-key-rotation.py")
rotation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rotation)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = json.loads((ROOT / "tests/fixtures/rotation-policy.json").read_bytes())
        self.args = SimpleNamespace(config=self.root / "offline.json", deployment_config=self.root / "deployment.json",
                                    signer_revision="a" * 40, key_id="new-app", out=self.root / "candidate",
                                    guest_directory=Path("/root/rotation"), rotation_min_sdk=33,
                                    revision=None, repository=self.config["repositories"][0]["name"])
        self.args.config.write_text(json.dumps(self.config))
        self.args.deployment_config.write_text(json.dumps(self.config))

    def rejected_without_side_effects(self, message):
        with mock.patch.object(rotation, "run") as command:
            with self.assertRaisesRegex(ValueError, message):
                rotation.prepare(self.args)
            command.assert_not_called()
        self.assertFalse(self.args.out.exists())
        self.assertEqual(json.loads(self.args.config.read_bytes()), self.config)

    def test_stale_or_different_deployment_rejected(self):
        for mutate in (
            lambda c: c["repositories"][0].update(revision=99),
            lambda c: c["repositories"][0]["profiles"]["oss"]["signing"].update(upload_key="other"),
            lambda c: c["repositories"][0].update(refs=["refs/heads/untrusted"]),
        ):
            changed = copy.deepcopy(self.config)
            mutate(changed)
            self.args.deployment_config.write_text(json.dumps(changed))
            self.rejected_without_side_effects("differ beyond paths")

    def test_existing_key_role_cannot_be_replaced(self):
        self.args.key_id = next(iter(self.config["keys"]))
        self.rejected_without_side_effects("role already exists")

    def test_invalid_revision_or_guest_directory_rejected(self):
        self.args.signer_revision = "main"
        self.rejected_without_side_effects("full deployed signer")
        self.args.signer_revision = "a" * 40
        self.args.guest_directory = Path("relative")
        self.rejected_without_side_effects("absolute guest")

    def test_invalid_rotation_sdk_or_reused_revision_rejected(self):
        self.args.rotation_min_sdk = 32
        self.rejected_without_side_effects("rotation SDK")
        self.args.rotation_min_sdk = 33
        self.args.revision = self.config["repositories"][0]["revision"]
        self.rejected_without_side_effects("exceed the active revision")


class RotationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = json.loads((ROOT / 'tests/fixtures/rotation-policy.json').read_bytes())
        self.lineage = self.root / 'old-lineage.bin'
        self.lineage.write_bytes(b'old-lineage')
        for profile in self.config['repositories'][0]['profiles'].values():
            profile['signing'].update(lineage=str(self.lineage), lineage_sha256=rotation.digest(b'old-lineage'))
        self.args = SimpleNamespace(config=self.root / 'offline.json', deployment_config=self.root / 'deployment.json',
                                    signer_revision='a' * 40, key_id='new-app', out=self.root / 'candidate',
                                    guest_directory=Path('/root/rotation'), rotation_min_sdk=33, revision=None,
                                    repository='example/app', key=self.root / 'new.pk8', certificate=self.root / 'new.pem', admin=self.root / 'admin')
        self.args.key.write_bytes(b'private key must not be copied')
        self.args.certificate.write_bytes(b'public certificate')
        self.openssl_description = b'Public-Key: (4096 bit)\nExponent: 65537 (0x10001)'
        self.public_der = b'public key'
        self.matching_key = b'public key'
        self.native_hash_matches = True
        self.commands = []

    def save_configs(self):
        self.args.config.write_text(json.dumps(self.config))
        deployed = copy.deepcopy(self.config)
        # A deployment may use different mount paths while preserving all policy.
        for profile in deployed['repositories'][0]['profiles'].values():
            profile['signing']['lineage'] = '/root/input-lineage.bin'
        self.args.deployment_config.write_text(json.dumps(deployed))

    def command(self, *args):
        args = [str(value) for value in args]
        self.commands.append(args)
        if args[0] == 'openssl':
            if args[1] == 'x509':
                if '-pubkey' in args:
                    return b'public key PEM'
                return b'certificate DER' if args[-1] == 'DER' else b'certificate PEM'
            return self.matching_key
        self.assertEqual(args[0], str(self.args.admin))
        output = Path(args[args.index('--out') + 1])
        if args[1] == 'append':
            output.write_bytes(b'new authenticated lineage')
            return b''
        self.assertEqual(args[1], 'export-release-policy')
        candidate = json.loads(Path(args[args.index('--config') + 1]).read_text())
        policy = {'policy_hash': rotation.policy_hash(candidate, 'example/app') if self.native_hash_matches else 'wrong-native-hash'}
        output.write_text(json.dumps(policy))
        return b''

    def openssl(self, args, **kwargs):
        self.assertEqual(args[:3], ['openssl', 'pkey', '-pubin'])
        return SimpleNamespace(returncode=0, stdout=self.openssl_description if '-text' in args else self.public_der)

    def prepare(self):
        import contextlib
        import io
        self.save_configs()
        with mock.patch.object(rotation, 'run', side_effect=self.command), mock.patch.object(rotation.subprocess, 'run', side_effect=self.openssl), contextlib.redirect_stdout(io.StringIO()):
            rotation.prepare(self.args)

    def test_preparation_deduplicates_proofs_preserves_active_stores_and_publishes_no_keys(self):
        self.prepare()
        offline = json.loads((self.args.out / 'config.offline.json').read_text())
        deployed = json.loads((self.args.out / 'config.deployment.json').read_text())
        self.assertEqual(json.loads(self.args.config.read_bytes()), self.config)
        self.assertEqual(self.lineage.read_bytes(), b'old-lineage')
        self.assertEqual(len([args for args in self.commands if args[1] == 'append']), 1)
        self.assertEqual(offline['repositories'][0]['revision'], 2)
        for name, profile in offline['repositories'][0]['profiles'].items():
            signing = profile['signing']
            self.assertEqual(signing['current_key'], 'new-app')
            self.assertEqual(signing['original_key'], 'apk-a')
            self.assertEqual(signing['lineage_sha256'], rotation.digest(b'new authenticated lineage'))
            self.assertEqual(deployed['repositories'][0]['profiles'][name]['signing']['lineage'], '/root/rotation/apk-lineage-0.bin')
        self.assertEqual(offline['keys']['new-app']['private_key'], str(self.args.key))
        self.assertEqual(deployed['keys']['new-app']['private_key'], '/root/rotation/new.pk8')
        public = json.loads((self.args.out / 'public-policy.json').read_text())
        self.assertEqual(public['policy_hash'], rotation.policy_hash(deployed, 'example/app'))
        report = json.loads((self.args.out / 'preparation.json').read_text())
        self.assertEqual(report['status'], 'prepared-not-activated')
        self.assertTrue(report['original_keys_retained'])
        self.assertFalse(any(b'private key must not be copied' in path.read_bytes() for path in self.args.out.iterdir()))

    def test_explicit_revision_rollback_and_legacy_capabilities_are_preserved(self):
        self.args.revision = 5
        self.args.rotation_min_sdk = 28
        signing = self.config['repositories'][0]['profiles']['oss']['signing']
        signing.update(allow_rollback=True, allow_legacy_rsa_1024=True)
        self.prepare()
        calls = [args for args in self.commands if args[1] == 'append']
        self.assertEqual(len(calls), 2)
        self.assertTrue(any('--allow-rollback' in args and '--legacy-old-rsa-1024' in args for args in calls))
        prepared = json.loads((self.args.out / 'preparation.json').read_text())
        self.assertEqual(prepared['revision'], 5)
        self.assertEqual(prepared['rotation_min_sdk'], 28)

    def test_bad_key_parameters_and_mismatched_key_are_rejected_before_writes(self):
        for description, key in [(b'Public-Key: (2048 bit)\nExponent: 65537 ', b'public key'), (b'Public-Key: (4096 bit)\nExponent: 3 ', b'public key'), (self.openssl_description, b'another key')]:
            with self.subTest(description=description, key=key):
                self.openssl_description = description
                self.matching_key = key
                with self.assertRaisesRegex(ValueError, 'RSA-4096|key and certificate differ'):
                    self.prepare()
                self.assertFalse(self.args.out.exists())

    def test_existing_identity_and_untrusted_lineage_are_rejected(self):
        self.config['keys']['apk-a']['fingerprint'] = rotation.digest(b'certificate DER')
        with self.assertRaisesRegex(ValueError, 'certificate already configured'):
            self.prepare()
        self.assertFalse(self.args.out.exists())
        self.config['keys']['apk-a']['fingerprint'] = 'old-certificate'
        self.lineage.write_bytes(b'tampered-lineage')
        with self.assertRaisesRegex(ValueError, 'input lineage hash differs'):
            self.prepare()
        self.assertFalse(any(args[1] == 'append' for args in self.commands))

    def test_native_policy_disagreement_aborts_before_deployment_policy_is_written(self):
        self.native_hash_matches = False
        with self.assertRaisesRegex(ValueError, 'native policy hash disagrees'):
            self.prepare()
        self.assertFalse((self.args.out / 'public-policy.json').exists())
        self.assertFalse((self.args.out / 'preparation.json').exists())

    def test_hybrid_profiles_and_duplicate_preparations_are_rejected(self):
        self.config['repositories'][0]['profiles']['oss']['signing']['hybrid'] = {'unexpected': True}
        with self.assertRaisesRegex(ValueError, 'active hybrid'):
            self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_policy_supports_dynamic_trust_and_rejects_ambiguous_repositories(self):
        self.config['trust_authority'] = {'authority': 'public'}
        first = rotation.policy_hash(self.config, 'example/app')
        self.config['trust_authority']['authority'] = 'replacement'
        self.assertNotEqual(first, rotation.policy_hash(self.config, 'example/app'))
        self.config['repositories'].append(copy.deepcopy(self.config['repositories'][0]))
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            rotation.repository(self.config, 'example/app')

    def test_subprocess_errors_are_sanitized_and_output_files_are_exclusive(self):
        with mock.patch.object(rotation.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'sensitive key')):
            with self.assertRaisesRegex(ValueError, '^openssl failed$'):
                rotation.run('openssl', 'pkey', '-in', 'secret-key')
        with mock.patch.object(rotation.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'public')):
            self.assertEqual(rotation.run('openssl', 'x509'), b'public')
        path = self.root / 'policy.json'
        rotation.save(path, {'verified': True})
        with self.assertRaises(FileExistsError):
            rotation.save(path, {'verified': False})


    def test_cli_parses_explicit_paths_revision_and_sdk(self):
        import os
        import sys
        arguments = ['prepare-key-rotation', '--config', str(self.args.config), '--deployment-config', str(self.args.deployment_config), '--key', str(self.args.key), '--certificate', str(self.args.certificate), '--admin', str(self.args.admin), '--out', str(self.args.out), '--guest-directory', '/root/rotation', '--repository', 'example/app', '--signer-revision', 'a' * 40, '--revision', '7', '--rotation-min-sdk', '28']
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(os, 'umask') as permissions, mock.patch.object(rotation, 'prepare') as prepare:
            rotation.main()
        permissions.assert_called_once_with(0o077)
        parsed = prepare.call_args.args[0]
        self.assertEqual(parsed.config, self.args.config)
        self.assertEqual(parsed.revision, 7)
        self.assertEqual(parsed.rotation_min_sdk, 28)
        self.assertEqual(parsed.key_id, 'apk-rsa4096')


if __name__ == '__main__':
    unittest.main()
