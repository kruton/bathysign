#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Public packaging, bounded archive recovery and transaction-scoped cleanup."""
import io
import zipfile
import unittest
from unittest import mock
import test_publishing as fixtures

p = fixtures.p


class CompactReleaseTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.HandoffTests(methodName='test_complete_handoff')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def files(self):
        return {path.name: path.read_bytes() for path in self.f.handoff.iterdir()}

    def test_public_downloads_preserve_versioned_names_and_all_authenticated_bytes(self):
        files = self.files()
        compact = p.r.compact_publication(files, self.f.manifest)
        self.assertEqual(len(compact), 6)
        for profile in ('oss', 'google'):
            for kind in ('apk', 'aab'):
                name = f"Example-{self.f.manifest['release']['tag_name']}-{profile}.{kind}"
                self.assertEqual(compact[name], files[name])
        archive = p.r.evidence_files(compact[p.r.evidence_name(self.f.manifest)])
        self.assertEqual({**archive, **{name: compact[name] for name in p.r.public_names(self.f.manifest)}}, files)
        self.assertEqual(p.r.compact_publication(files, self.f.manifest), compact)

    def test_unsafe_duplicate_and_oversized_evidence_archives_are_rejected(self):
        for names in (('../outside',), ('a', 'a')):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                for name in names:
                    archive.writestr(name, b'data')
            with self.assertRaises(ValueError):
                p.r.evidence_files(buffer.getvalue())
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('large.json', b'x' * 2048)
        with mock.patch.object(p.r, 'MAX_BYTES', 1024), self.assertRaisesRegex(ValueError, 'expanded evidence'):
            p.r.evidence_files(buffer.getvalue())

    def test_compact_existing_publication_keeps_original_evidence_on_retry(self):
        files = self.files()
        compact = p.r.compact_publication(files, self.f.manifest)
        existing = [{'name': name, 'state': 'uploaded', 'digest': 'sha256:' + p.digest(data), 'size': len(data)} for name, data in compact.items()]
        with mock.patch.object(p.r, 'download_asset', side_effect=lambda repo, asset: compact[asset['name']]):
            self.assertEqual(p.verify_existing_publication(self.f.handoff, self.f.manifest, existing), files)
            changed = dict(compact)
            evidence = p.r.evidence_files(changed[p.r.evidence_name(self.f.manifest)])
            evidence['google-signing-receipt.json'] += b'changed'
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                for name, data in evidence.items():
                    archive.writestr(name, data)
            compact[p.r.evidence_name(self.f.manifest)] = buffer.getvalue()
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                p.verify_existing_publication(self.f.handoff, self.f.manifest, existing)

    def test_published_flat_evidence_recovery_verifies_archive_before_removing_files(self):
        files = self.files()
        assets = [{'id': index, 'name': name, 'state': 'uploaded', 'digest': 'sha256:' + p.digest(data), 'size': len(data)} for index, (name, data) in enumerate(files.items(), 1)]
        marker = 'Verified Android signing; source run 10/2; commit ' + 'f' * 40 + '; policy ' + 'b' * 64
        target = {**self.f.manifest['release'], 'id': 99, 'draft': False, 'body': marker, 'html_url': 'https://example/release'}
        uploaded, deleted = {}, []
        def rows(path):
            return [target] if path.endswith('/releases') else assets
        def upload(repo, release_id, name, data):
            uploaded[name] = data
            assets.append({'id': 1000, 'name': name, 'state': 'uploaded', 'digest': 'sha256:' + p.digest(data), 'size': len(data)})
        def delete(*args):
            self.assertEqual(set(uploaded), {p.r.evidence_name(self.f.manifest)})
            self.assertEqual(p.r.evidence_files(next(iter(uploaded.values()))), {n: d for n, d in files.items() if n not in p.r.public_names(self.f.manifest)})
            asset_id = int(args[-1].rsplit('/', 1)[1])
            name = next(asset['name'] for asset in assets if asset['id'] == asset_id)
            self.assertNotIn(name, p.r.public_names(self.f.manifest))
            deleted.append(name)
            assets[:] = [asset for asset in assets if asset['id'] != asset_id]
            return b''
        with mock.patch.object(p, 'ensure_release_tag'), mock.patch.object(p.r, 'rows', side_effect=rows), \
             mock.patch.object(p.r, 'upload', side_effect=upload), mock.patch.object(p.r, 'run', side_effect=delete), \
             mock.patch.object(p.r, 'download_asset', side_effect=lambda repo, asset: files.get(asset['name'], uploaded.get(asset['name']))):
            result = p.github_release(self.f.handoff, self.f.manifest)
        self.assertEqual(len(assets), 6)
        self.assertEqual(set(deleted), set(files) - p.r.public_names(self.f.manifest))
        self.assertEqual(len(result['public_assets']), 6)

    def test_incomplete_archive_recovery_retains_all_original_evidence(self):
        files = self.files()
        existing = [{'name': name, 'state': 'uploaded', 'digest': 'sha256:' + p.digest(data), 'size': len(data)} for name, data in files.items()]
        existing.append({'name': p.r.evidence_name(self.f.manifest), 'state': 'starter', 'size': 0})
        with mock.patch.object(p.r, 'download_asset', side_effect=lambda repo, asset: files[asset['name']]):
            recovered = p.verify_existing_publication(self.f.handoff, self.f.manifest, existing)
        self.assertEqual(recovered, files)

    def test_failed_archive_upload_never_removes_loose_evidence_or_staging(self):
        files = self.files()
        assets = [{'id': i, 'name': name, 'state': 'uploaded', 'digest': 'sha256:' + p.digest(data), 'size': len(data)} for i, (name, data) in enumerate(files.items())]
        marker = 'Verified Android signing; source run 10/2; commit ' + 'f' * 40 + '; policy ' + 'b' * 64
        target = {**self.f.manifest['release'], 'id': 99, 'draft': False, 'body': marker, 'html_url': 'https://example/release'}
        def upload(repo, release_id, name, data):
            assets.append({'id': 1000, 'name': name, 'state': 'uploaded', 'digest': 'sha256:wrong', 'size': len(data)})
        with mock.patch.object(p, 'ensure_release_tag'), mock.patch.object(p.r, 'rows', side_effect=lambda path: [target] if path.endswith('/releases') else assets), \
             mock.patch.object(p.r, 'upload', side_effect=upload), mock.patch.object(p.r, 'run') as changes:
            with self.assertRaisesRegex(ValueError, 'publication asset digest differs'):
                p.github_release(self.f.handoff, self.f.manifest)
            changes.assert_not_called()
        self.assertTrue(set(files) <= {asset['name'] for asset in assets})

    def staging(self):
        manifest, files = self.f.manifest, self.files()
        source = manifest['source']
        releases, receipts = [], {}
        for index, profile in enumerate(('oss', 'google'), 1):
            job = f"v2-42-10-2-{profile}-{manifest['policy_hash']}"
            releases.append({'id': index, 'tag_name': 'bathysign/' + job, 'draft': True, 'target_commitish': source['commit'], 'body': f"Bathysign job {job}; commit {source['commit']}"})
            receipts[index] = {'signing-receipt.dsse.json': files[f'{profile}-signing-receipt.dsse.json']}
        releases.append({'id': 3, 'tag_name': f"verified/10-2-{manifest['policy_hash'][:16]}", 'draft': True, 'target_commitish': source['commit'], 'body': 'Verified Android signing; source run 10/2'})
        receipts[3] = {f'{profile}-signing-receipt.dsse.json': files[f'{profile}-signing-receipt.dsse.json'] for profile in ('oss', 'google')}
        releases.append({'id': 4, 'tag_name': 'somebody-elses-draft', 'draft': True})
        def rows(path):
            if path.endswith('/releases'):
                return releases
            release_id = int(path.split('/')[-2])
            return [{'name': name, 'data': data} for name, data in receipts[release_id].items()]
        return files, releases, receipts, rows

    def test_cleanup_deletes_only_matching_receipt_bound_staging_drafts(self):
        files, releases, receipts, rows = self.staging()
        with mock.patch.object(p.r, 'rows', side_effect=rows), mock.patch.object(p.r, 'download_asset', side_effect=lambda repo, asset: asset['data']), mock.patch.object(p.r, 'run') as run:
            self.assertEqual(p.cleanup_staging(self.f.manifest, files), [1, 2, 3])
            self.assertEqual([call.args[-1].rsplit('/', 1)[1] for call in run.call_args_list], ['1', '2', '3'])

    def test_cleanup_refuses_published_unmanaged_or_conflicting_receipt(self):
        for kind in ('published', 'unmanaged', 'receipt'):
            files, releases, receipts, rows = self.staging()
            if kind == 'published':
                releases[0]['draft'] = False
            elif kind == 'unmanaged':
                releases[0]['body'] = 'another owner'
            else:
                receipts[1]['signing-receipt.dsse.json'] = b'other transaction'
            with mock.patch.object(p.r, 'rows', side_effect=rows), mock.patch.object(p.r, 'download_asset', side_effect=lambda repo, asset: asset['data']), mock.patch.object(p.r, 'run') as run:
                with self.assertRaises(ValueError):
                    p.cleanup_staging(self.f.manifest, files)
                run.assert_not_called()

    def test_published_recovery_reverifies_receipts_and_exact_signed_output_digests(self):
        receipts = {}
        for profile in ('oss', 'google'):
            files = self.files()
            prefix = f"Example-{self.f.manifest['release']['tag_name']}-{profile}"
            output_data = {'app-signed.apk': files[prefix + '.apk'], 'app-signed.aab': files[prefix + '.aab'],
                'unsigned-apk.sigstore.json': files[f'provenance-{profile}.json'], 'unsigned-aab.sigstore.json': files[f'provenance-{profile}.json'],
                **{name: files[f'{profile}-{name}'] for name in ('apk-lineage.bin', 'code_transparency_signed.jwt', 'transparency-certificate.der')}}
            receipt = {'outputs': [{'name': name, 'sha256': p.digest(data), 'bytes': len(data)} for name, data in output_data.items()]}
            envelope = (profile + '-signed').encode()
            receipts[envelope] = receipt
            for name, data in ((f'{profile}-signing-receipt.json', p.json_bytes(receipt)), (f'{profile}-signing-receipt.dsse.json', envelope)):
                (self.f.handoff / name).write_bytes(data)
                self.f.manifest['assets'][name] = {'sha256': p.digest(data), 'bytes': len(data)}
        self.f.refresh()
        compact = p.r.compact_publication(self.files(), self.f.manifest)
        source = {'id': 10, 'run_attempt': 2, 'head_sha': 'f' * 40}
        release = {'id': 99, 'draft': False, 'tag_name': self.f.manifest['release']['tag_name'], 'target_commitish': 'f' * 40,
            'body': 'Verified Android signing; source run 10/2; commit ' + 'f' * 40 + '; policy ' + 'b' * 64}
        assets = [{'name': name} for name in compact]
        with mock.patch.object(p.r, 'rows', return_value=assets), mock.patch.object(p.r, 'download_asset', side_effect=lambda repo, asset: compact[asset['name']]), \
             mock.patch.object(p.r, 'verify_receipt', side_effect=lambda envelope, policy: receipts[envelope]) as verify, mock.patch.object(p.r, 'validate_transaction') as transaction:
            self.assertEqual(set(p.r.recover_published(self.f.policy, source, [release])), {'oss', 'google'})
            self.assertEqual(verify.call_count, 2)
            self.assertEqual(transaction.call_count, 2)
            compact[f"Example-{release['tag_name']}-google.apk"] += b'tampered'
            with self.assertRaisesRegex(ValueError, 'output differs'):
                p.r.recover_published(self.f.policy, source, [release])


if __name__ == '__main__':
    unittest.main()
