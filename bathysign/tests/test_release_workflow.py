#!/usr/bin/env python3
"""Adversarial finalizer tests; no network or deployment credentials."""
import base64
import copy
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest import mock

from test_publishing import identity
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release", ROOT / "scripts/signer-release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_final_predicate_binds_control_plane_inputs_and_workflow(self):
        policy = self.policy()
        event = Path(self.tmp.name) / "dispatch.json"
        inputs = {"source_run": "42", "source_attempt": "2"}
        event.write_text(release.json.dumps({"inputs": inputs}))
        environment = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_PATH": str(event), "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_WORKFLOW_REF": f"{policy['repository']}/.github/workflows/bathysign-release.yml@refs/heads/main", "GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "1"}
        environment.update(BATHYSIGN_JOB_WORKFLOW_REF="example/workflows/.github/workflows/bathysign-finalize.yml@refs/tags/v0.2.0", BATHYSIGN_JOB_WORKFLOW_SHA="d" * 40)
        with mock.patch.dict(release.os.environ, environment, clear=True), mock.patch.object(release, "verify_workflow_identity"):
            dependency = {"uri": "urn:test:unsigned", "digest": {"sha256": "d" * 64}}
            predicate = release.final_predicate(policy, 42, 2, {"id": policy["repository_id"], "owner": {"id": 7}, "default_branch": "main"}, {}, [dependency])
            self.assertEqual(predicate["buildDefinition"]["externalParameters"]["inputs"], inputs)
            self.assertEqual(predicate["buildDefinition"]["externalParameters"]["workflow"]["path"], ".github/workflows/bathysign-release.yml")
            self.assertEqual(predicate["buildDefinition"]["resolvedDependencies"][0]["digest"], {"gitCommit": "c" * 40})
            self.assertEqual(predicate["buildDefinition"]["resolvedDependencies"][1]["digest"], {"gitCommit": "d" * 40})
            self.assertEqual(predicate["buildDefinition"]["resolvedDependencies"][2], dependency)
            with mock.patch.dict(release.os.environ, {'BATHYSIGN_JOB_WORKFLOW_SHA':'a'*40}):
                with self.assertRaisesRegex(ValueError, 'revision differs from policy pin'):
                    release.final_predicate(policy, 42, 2, {'default_branch':'main'}, {}, [])
            event.write_text(release.json.dumps({"inputs": {**inputs, "source_run": "43"}}))
            with self.assertRaises(ValueError):
                release.final_predicate(policy, 42, 2, {"id": policy["repository_id"], "owner": {"id": 7}, "default_branch": "main"}, {}, [])

    def test_annotated_final_predicate_records_source_commit_and_platform_digest(self):
        policy = self.policy()
        for name in ('builder', 'finalizer'): policy[name]['workflow_digest'] = 'a'*40
        event = Path(self.tmp.name)/'annotated-dispatch.json'
        event.write_text(release.json.dumps({'inputs':{'source_run':'42','source_attempt':'2'}}))
        environment = {'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_PATH':str(event),'RUNNER_ENVIRONMENT':'github-hosted',
            'GITHUB_WORKFLOW_REF':policy['repository']+'/.github/workflows/bathysign-release.yml@refs/heads/main','GITHUB_SHA':'c'*40,'GITHUB_RUN_ID':'99','GITHUB_RUN_ATTEMPT':'1',
            'BATHYSIGN_JOB_WORKFLOW_REF':'example/workflows/.github/workflows/bathysign-finalize.yml@refs/tags/v0.2.0','BATHYSIGN_JOB_WORKFLOW_SHA':'a'*40}
        with mock.patch.dict(release.os.environ, environment, clear=True), mock.patch.object(release, 'verify_workflow_identity'):
            predicate = release.final_predicate(policy,42,2,{'id':policy['repository_id'],'owner':{'id':7},'default_branch':'main'},{},[])
        internal = predicate['buildDefinition']['internalParameters']
        self.assertEqual(internal['finalizerCommit'],policy['finalizer']['commit'])
        self.assertEqual(internal['finalizerWorkflowDigest'],'a'*40)
        self.assertEqual(predicate['buildDefinition']['resolvedDependencies'][1]['digest'],{'gitCommit':policy['finalizer']['commit']})

    def test_finalizer_recovery_requires_default_branch_context(self):
        for event, ref, permitted in [("workflow_run", "refs/heads/main", False), ("workflow_dispatch", "refs/heads/main", True), ("workflow_dispatch", "refs/heads/untrusted", False), ("push", "refs/heads/main", False)]:
            with mock.patch.dict(release.os.environ, {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref}, clear=True):
                if permitted:
                    release.validate_finalizer_context({"default_branch": "main"})
                else:
                    with self.assertRaises(ValueError):
                        release.validate_finalizer_context({"default_branch": "main"})

    def test_incomplete_final_asset_is_cleaned_but_conflicting_completed_asset_is_rejected(self):
        with mock.patch.object(release, "rows", return_value=[{"name": "app.apk", "id": 7, "state": "starter", "digest": None}]), mock.patch.object(release, "run", return_value=b"") as run:
            release.upload("example/repo", 1, "app.apk", b"artifact")
            self.assertEqual(run.call_args_list[0].args, ("gh", "api", "--hostname", "github.com", "--method", "DELETE", "repos/example/repo/releases/assets/7"))
            self.assertEqual(run.call_args_list[1].args[5], "POST")
        with mock.patch.object(release, "rows", return_value=[{"name": "app.apk", "state": "uploaded", "digest": "wrong", "size": 8}]), mock.patch.object(release, "run") as run:
            with self.assertRaises(ValueError):
                release.upload("example/repo", 1, "app.apk", b"artifact")
            run.assert_not_called()

    def test_source_pin_ignores_mtime_but_binds_paths_and_contents(self):
        def archive(name="src/Main.java", content=b"class Main {}", mtime=1, symlink=False):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                member = tarfile.TarInfo(name)
                member.mtime = mtime
                member.size = len(content)
                if symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/tmp/outside"
                tar.addfile(member, io.BytesIO(content))
            return stream.getvalue()
        original = release.source_tree_digest(archive())
        self.assertEqual(original, release.source_tree_digest(archive(mtime=9000)))
        self.assertNotEqual(original, release.source_tree_digest(archive(content=b"class Changed {}")))
        self.assertNotEqual(original, release.source_tree_digest(archive(name="src/Other.java")))
        for data in (archive(name="../Main.java"), archive(symlink=True)):
            with self.assertRaises(ValueError):
                release.source_tree_digest(data)

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.key, cert = root / "key.pem", root / "cert.pem"
        subprocess.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.key), "-out", str(cert), "-days", "2", "-subj", "/CN=Receipt-test"], check=True, capture_output=True)
        cls.der = release.run("openssl", "x509", "-in", cert, "-outform", "DER")
        cls.fingerprint = release.digest(cls.der)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def policy(self):
        return {"version": 3, "receipt_namespace": "bathysign", "callers": [".github/workflows/ci.yml"], "builder": identity(), "finalizer": identity("bathysign-finalize.yml"), "visibility": "public", "repository": "example/app", "repository_id": 42,
            "policy_hash": "a" * 64, "signer_revision": "b" * 40, "revision": 3,
            "receipt_keys": {self.fingerprint: base64.b64encode(self.der).decode()},
            "profiles": {"oss": {"package": "org.example", "keys": {"original": "c" * 64, "classical": "d" * 64, "upload": "e" * 64, "transparency": "f" * 64, "hybrid": None}, "lineage_sha256": "1" * 64, "rotation_min_sdk": 33, "hybrid_min_sdk": None}}}

    def receipt(self):
        policy = self.policy()
        return {"version": 2, "receipt_namespace": "bathysign", "repository": "example/app", "package": "org.example", "job": {
            "version": 2, "profile": "oss", "id": "v2-42-10-2-oss-" + "a" * 64,
            "repository_id": 42, "run_id": 10, "attempt": 2, "commit": "2" * 40,
            "policy_hash": "a" * 64, "revision": 3}, "keys": policy["profiles"]["oss"]["keys"],
            "lineage": {"sha256": "1" * 64}, "rotation_min_sdk": 33, "hybrid_min_sdk": None,
            "signer": {"revision": "b" * 40}, "outputs": [{"name": "app-signed.apk", "sha256": "3" * 64, "bytes": 100}]}

    def envelope(self):
        receipt = self.receipt()
        statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "urn:bathysign:receipt:v2", "predicate": receipt, "subject": [{"name": o["name"], "digest": {"sha256": o["sha256"]}} for o in receipt["outputs"]]}
        payload = release.json_bytes(statement)
        kind = release.PAYLOAD_TYPE
        pae = f"DSSEv1 {len(kind)} {kind} {len(payload)} ".encode() + payload
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key)], input=pae, stdout=subprocess.PIPE, check=True).stdout
        return {"payloadType": kind, "payload": base64.b64encode(payload).decode(), "signatures": [{"keyid": self.fingerprint, "sig": base64.b64encode(sig).decode()}]}

    def test_receipt_signature_and_tampering(self):
        envelope = self.envelope()
        self.assertEqual(release.verify_receipt(release.json_bytes(envelope), self.policy()), self.receipt())
        bad = copy.deepcopy(envelope)
        bad["payload"] = base64.b64encode(b"{}").decode()
        with self.assertRaises(subprocess.CalledProcessError):
            release.verify_receipt(release.json_bytes(bad), self.policy())
        for field, value in [("payloadType", "application/json"), ("signatures", envelope["signatures"] * 2)]:
            bad = copy.deepcopy(envelope)
            bad[field] = value
            with self.assertRaises(ValueError):
                release.verify_receipt(release.json_bytes(bad), self.policy())

    def test_transaction_substitution(self):
        receipt, policy = self.receipt(), self.policy()
        source = {"id": 10, "run_attempt": 2, "head_sha": "2" * 40}
        release.validate_transaction(receipt, policy, source, "oss")
        for section, key, value in [("job", "attempt", 1), ("job", "profile", "google"), ("job", "policy_hash", "0" * 64), ("job", "commit", "0" * 40), ("keys", "upload", "0" * 64), ("lineage", "sha256", "0" * 64), ("signer", "revision", "0" * 40)]:
            bad = copy.deepcopy(receipt)
            bad[section][key] = value
            with self.assertRaises(ValueError, msg=f"accepted {section}.{key}"):
                release.validate_transaction(bad, policy, source, "oss")

    def test_policy_and_duplicate_json(self):
        release.validate_policy(self.policy())
        bad = self.policy()
        bad["policy_hash"] = "REPLACE"
        with self.assertRaises(ValueError):
            release.validate_policy(bad)
        bad = self.policy()
        bad["receipt_keys"] = {"0" * 64: base64.b64encode(self.der).decode()}
        with self.assertRaises(ValueError):
            release.validate_policy(bad)
        with self.assertRaises(ValueError):
            release.load('{"job":1,"job":2}')
        self.assertTrue(release.allowed_ref(["refs/tags/v*"], "refs/tags/v1.2.3"))
        self.assertFalse(release.allowed_ref(["refs/heads/main"], "refs/heads/main-attacker"))

    def test_archive_traversal_duplicates_and_nested_paths(self):
        for names in [["../app.apk"], ["app.apk", "app.apk"], ["a/app.apk"]]:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for name in names:
                    archive.writestr(name, b"artifact")
            with self.assertRaises(ValueError):
                release.unpack(stream.getvalue())

    def transaction_fixture(self):
        policy, receipt = self.policy(), self.receipt()
        policy['refs'] = ['refs/heads/main']
        policy['publishing'] = {'asset_prefix': 'example'}
        source = {'id':10, 'run_attempt':2, 'head_sha':'2' * 40, 'status':'completed', 'conclusion':'success', 'event':'push', 'head_repository':{'id':42}, 'path':'.github/workflows/ci.yml'}
        def packed(entries):
            result = io.BytesIO()
            with zipfile.ZipFile(result, 'w') as archive:
                for name, data in entries.items(): archive.writestr(name, data)
            return result.getvalue()
        inputs = {'apk':packed({'classes.dex':b'dex', 'AndroidManifest.xml':b'manifest'}), 'aab':packed({'base/dex/classes.dex':b'dex', 'base/manifest/AndroidManifest.xml':b'manifest'})}
        jwt = b'authenticated-transparency-jwt'
        files = {
            'app-signed.apk':packed({'classes.dex':b'dex', 'AndroidManifest.xml':b'manifest', 'META-INF/code_transparency_signed.jwt':jwt}),
            'app-signed.aab':packed({'base/dex/classes.dex':b'dex', 'base/manifest/AndroidManifest.xml':b'manifest', 'BUNDLE-METADATA/com.android.tools.build.bundletool/code_transparency_signed.jwt':jwt}),
            'apk-lineage.bin':b'authenticated-lineage', 'code_transparency_signed.jwt':jwt,
            'transparency-certificate.der':b'transparency-certificate', 'unsigned-apk.sigstore.json':b'{"apk":true}', 'unsigned-aab.sigstore.json':b'{"aab":true}'}
        policy['profiles']['oss']['lineage_sha256'] = release.digest(files['apk-lineage.bin'])
        policy['profiles']['oss']['keys']['transparency'] = release.digest(files['transparency-certificate.der'])
        receipt['keys'] = copy.deepcopy(policy['profiles']['oss']['keys'])
        receipt['lineage'] = {'sha256':policy['profiles']['oss']['lineage_sha256'], 'certificates':['c'*64, 'd'*64]}
        receipt['outputs'] = [{'name':name, 'sha256':release.digest(data), 'bytes':len(data)} for name,data in files.items()]
        receipt['inputs'] = {kind:release.digest(data) for kind,data in inputs.items()}
        receipt['artifacts'], archives = {}, {}
        for kind, identity in [('apk',44), ('aab',45)]:
            archive = packed({'app.'+kind:inputs[kind]})
            archives[identity] = archive
            receipt['artifacts'][kind] = {'id':identity, 'name':'unsigned-oss-2', 'digest':'sha256:'+release.digest(archive), 'workflow_run':{'id':10, 'head_sha':source['head_sha'], 'repository_id':42}}
        builder = policy['builder']
        builder_uri = f"https://github.com/{builder['repository']}/{builder['workflow']}@{builder['refs'][0]}"
        receipt['provenance'] = {kind:{'builder':builder_uri, 'builder_commit':'d'*40, 'ref':'refs/heads/main', 'bundle_sha256':release.digest(files['unsigned-'+kind+'.sigstore.json'])} for kind in inputs}
        with mock.patch.object(self, 'receipt', return_value=receipt):
            files['signing-receipt.dsse.json'] = release.json_bytes(self.envelope())
        files['signing-receipt.json'] = release.json_bytes(receipt)
        return policy, source, receipt, files, inputs, archives

    def test_staging_downloads_and_recovery_authenticate_real_receipts_and_every_output(self):
        policy, source, receipt, files, _, _ = self.transaction_fixture()
        job = receipt['job']['id']
        staging = {'id':19, 'tag_name':'bathysign/'+job, 'draft':True, 'target_commitish':source['head_sha'], 'body':f"Bathysign job {job}; commit {source['head_sha']}"}
        assets = [{'id':index, 'name':name, 'size':len(data), 'digest':'sha256:'+release.digest(data)} for index,(name,data) in enumerate(files.items(),1)]
        by_id = {asset['id']:files[asset['name']] for asset in assets}
        original = release.run
        def command(*args):
            if args[0] == 'gh':
                return by_id[int(args[-1].rsplit('/',1)[1])]
            return original(*args)
        def rows(path, field=None):
            return [staging] if path.endswith('/releases') else assets
        with mock.patch.object(release, 'rows', side_effect=rows), mock.patch.object(release, 'run', side_effect=command):
            found = release.wait_staging(policy, source, 1)
        self.assertEqual(found, {'oss':(receipt, files)})
        published = {'tag_name':'v1.0.0'}
        evidence = {'oss-'+name:data for name,data in files.items() if not name.startswith('app-signed.')}
        # Compact publication can carry one shared provenance bundle for both inputs.
        common = b'one common bundle'
        receipt['outputs'] = [dict(output, sha256=release.digest(common), bytes=len(common)) if output['name'].startswith('unsigned-') else output for output in receipt['outputs']]
        with mock.patch.object(self, 'receipt', return_value=receipt):
            evidence['oss-signing-receipt.dsse.json'] = release.json_bytes(self.envelope())
        evidence['oss-signing-receipt.json'] = release.json_bytes(receipt)
        for kind in ['apk','aab']: evidence.pop('oss-unsigned-'+kind+'.sigstore.json')
        evidence['provenance-oss.json'] = common
        published_assets = {'example-v1.0.0-oss.'+kind:{'id':kind} for kind in ['apk','aab']}
        with mock.patch.object(release, 'download_asset', side_effect=lambda repo, asset:files['app-signed.'+asset['id']]):
            recovered = release.recover_published(policy, source, [], (published, {}, evidence, published_assets))
        self.assertEqual(recovered['oss'][0], receipt)
        self.assertEqual(recovered['oss'][1]['unsigned-apk.sigstore.json'], common)
        evidence['oss-signing-receipt.json'] = b'{}'
        with self.assertRaisesRegex(ValueError, 'plain receipt differs'):
            release.recover_published(policy, source, [], (published, {}, evidence, published_assets))

    def test_staging_never_accepts_ambiguous_or_unmanaged_releases_and_waits_are_bounded(self):
        policy, source, receipt, files, _, _ = self.transaction_fixture()
        job = receipt['job']['id']
        staging = {'id':19, 'tag_name':'bathysign/'+job, 'draft':True, 'target_commitish':source['head_sha'], 'body':f"Bathysign job {job}; commit {source['head_sha']}"}
        for rows, expected in [([staging, staging], 'ambiguous staging'), ([dict(staging, draft=False)], 'unmanaged staging')]:
            with mock.patch.object(release, 'rows', return_value=rows), self.assertRaisesRegex(ValueError, expected):
                release.wait_staging(policy, source, 1)
        # A missing transaction can recover from published evidence, but cannot wait forever.
        with mock.patch.object(release, 'rows', return_value=[]), mock.patch.object(release, 'recover_published', return_value={}), mock.patch.object(release.time, 'monotonic', side_effect=[0,0,0,2]), mock.patch.object(release.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'timed out'):
                release.wait_staging(policy, source, 1)
            sleep.assert_called_once()
        with mock.patch.object(release, 'rows', return_value=[]), mock.patch.object(release, 'recover_published', return_value={'oss':(receipt,files)}):
            self.assertEqual(release.wait_staging(policy, source, 1)['oss'][0], receipt)

    def test_unsigned_artifacts_bind_archive_metadata_size_and_original_file_digest(self):
        policy, source, receipt, _, inputs, archives = self.transaction_fixture()
        metadata = {value['id']:{**value, 'expired':False, 'size_in_bytes':len(archives[value['id']])} for value in receipt['artifacts'].values()}
        with mock.patch.object(release, 'api', side_effect=lambda path:metadata[int(path.rsplit('/',1)[1])]), mock.patch.object(release, 'run', side_effect=lambda *args:archives[int(args[-1].split('/')[-2])]):
            self.assertEqual(release.unsigned_files(policy, source, receipt), inputs)
            metadata[44]['expired'] = True
            with self.assertRaisesRegex(ValueError, 'metadata changed'):
                release.unsigned_files(policy, source, receipt)
            metadata[44]['expired'] = False
            receipt['inputs']['apk'] = '0'*64
            with self.assertRaisesRegex(ValueError, 'unsigned input digest differs'):
                release.unsigned_files(policy, source, receipt)

    def test_android_verification_selects_rotated_keys_and_checks_all_tool_results(self):
        _, _, receipt, files, _, _ = self.transaction_fixture()
        root = Path(self.tmp.name) / self._testMethodName
        root.mkdir()
        commands = []
        def command(*args):
            commands.append(args)
            if args[:2] == ('keytool','-printcert'):
                return b'PEM certificate' if '-rfc' in args else receipt['keys']['upload'].encode()
            return b''
        with mock.patch.object(release, 'run', side_effect=command):
            release.android_verify(root, files, receipt, root/'tools')
        apks = [args for args in commands if 'Reference' in args and 'apk' in args]
        self.assertEqual([args[-2] for args in apks], ['24','28','32','33','36','37'])
        self.assertEqual([args[-1] for args in apks], [receipt['keys']['original']]*3+[receipt['keys']['classical']]*3)
        self.assertTrue(any(args[:3] == ('jarsigner','-verify','-strict') for args in commands))
        self.assertEqual(sum('check-transparency' in args for args in commands), 2)
        self.assertFalse((root/'transparency-apks.zip').exists())
        receipt['keys']['hybrid'] = {'rsa':'9'*64}
        with mock.patch.object(release, 'run', side_effect=command):
            release.android_verify(root, files, receipt, root/'tools')
        self.assertEqual([args for args in commands if 'Reference' in args and 'apk' in args][-1][-1], '9'*64)
        with mock.patch.object(release, 'run', return_value=b'wrong certificate'):
            with self.assertRaisesRegex(ValueError, 'upload certificate differs'):
                release.android_verify(root, files, receipt, root/'tools')

    def test_verified_provenance_checks_certificate_claims_and_exact_build_invocation(self):
        policy, source, receipt, files, inputs, _ = self.transaction_fixture()
        summary = receipt['provenance']['apk']
        root = Path(self.tmp.name) / self._testMethodName
        root.mkdir()
        artifact, bundle = root/'app.apk', root/'bundle.json'
        artifact.write_bytes(inputs['apk'])
        bundle.write_bytes(files['unsigned-apk.sigstore.json'])
        uri = 'https://github.com/'+policy['repository']
        workflow = {'repository':uri, 'path':policy['callers'][0], 'ref':'refs/heads/main'}
        invocation = uri+'/actions/runs/10/attempts/2'
        certificate = {'issuer':'https://token.actions.githubusercontent.com', 'sourceRepositoryURI':uri, 'sourceRepositoryIdentifier':'42', 'sourceRepositoryDigest':source['head_sha'], 'sourceRepositoryRef':workflow['ref'], 'buildConfigURI':uri+'/'+workflow['path']+'@'+workflow['ref'], 'buildConfigDigest':source['head_sha'], 'buildSignerURI':summary['builder'], 'buildSignerDigest':summary['builder_commit'], 'runInvocationURI':invocation, 'runnerEnvironment':'github-hosted', 'buildTrigger':'push', 'sourceRepositoryVisibilityAtSigning':'public', 'subjectAlternativeName':summary['builder']}
        predicate = {'buildDefinition':{'buildType':release.BUILD_TYPE, 'externalParameters':{'workflow':workflow}, 'resolvedDependencies':[{'uri':'git+'+uri+'@refs/heads/main', 'digest':{'gitCommit':source['head_sha']}}]}, 'runDetails':{'builder':{'id':summary['builder']}, 'metadata':{'invocationId':invocation}}}
        verified = [{'verificationResult':{'signature':{'certificate':certificate}, 'statement':{'predicate':predicate, 'subject':[{'digest':{'sha256':release.digest(inputs['apk'])}}]}, 'verifiedTimestamps':[{'time':'trusted'}]}}]
        with mock.patch.object(release, 'run', side_effect=lambda *args:release.json_bytes(verified)), mock.patch.object(release, 'verify_workflow_identity'):
            release.verify_provenance(artifact, bundle, policy, source, summary)
            with self.assertRaisesRegex(ValueError, 'builder commit differs from policy pin'):
                release.verify_provenance(artifact, bundle, policy, source, {**summary, 'builder_commit':'a'*40})
            for name in ('builder', 'finalizer'): policy[name]['workflow_digest'] = 'a'*40
            annotated = {**summary, 'builder_workflow_digest':'a'*40}
            certificate['buildSignerDigest'] = 'a'*40
            release.verify_provenance(artifact, bundle, policy, source, annotated)
            with self.assertRaisesRegex(ValueError, 'workflow digest differs'):
                release.verify_provenance(artifact, bundle, policy, source, {**annotated, 'builder_workflow_digest':'b'*40})
            for name in ('builder', 'finalizer'): policy[name].pop('workflow_digest')
            certificate['buildSignerDigest'] = summary['builder_commit']
            certificate['runInvocationURI'] = uri+'/actions/runs/10/attempts/1'
            with self.assertRaisesRegex(ValueError, 'certificate claims differ'):
                release.verify_provenance(artifact, bundle, policy, source, summary)
            certificate['runInvocationURI'] = invocation
            predicate['runDetails']['metadata']['invocationId'] = 'unrelated'
            with self.assertRaisesRegex(ValueError, 'predicate invocation differs'):
                release.verify_provenance(artifact, bundle, policy, source, summary)
            bundle.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'upstream bundle differs'):
                release.verify_provenance(artifact, bundle, policy, source, summary)


    def test_prepare_emits_complete_dependencies_and_verifies_the_final_bundle_identity(self):
        policy, source, receipt, files, inputs, archives = self.transaction_fixture()
        root = Path(self.tmp.name) / self._testMethodName
        root.mkdir()
        policy_path, event = root/'policy.json', root/'event.json'
        policy_path.write_bytes(release.json_bytes(policy))
        event.write_text(release.json.dumps({'inputs':{'source_run':'10', 'source_attempt':'2'}}))
        finalizer = policy['finalizer']
        environment = {'GITHUB_REPOSITORY':policy['repository'], 'GITHUB_EVENT_NAME':'workflow_dispatch', 'GITHUB_REF':'refs/heads/main', 'GITHUB_EVENT_PATH':str(event), 'RUNNER_ENVIRONMENT':'github-hosted', 'GITHUB_WORKFLOW_REF':policy['repository']+'/.github/workflows/bathysign-release.yml@refs/heads/main', 'GITHUB_SHA':'c'*40, 'GITHUB_RUN_ID':'99', 'GITHUB_RUN_ATTEMPT':'1', 'BATHYSIGN_JOB_WORKFLOW_REF':finalizer['repository']+'/'+finalizer['workflow']+'@'+finalizer['refs'][0], 'BATHYSIGN_JOB_WORKFLOW_SHA':'d'*40}
        source_metadata = {'id':42, 'visibility':'public', 'default_branch':'main', 'owner':{'id':7}}
        def api(path):
            if '/actions/runs/' in path: return source
            if '/actions/artifacts/' in path:
                identifier = int(path.rsplit('/',1)[1])
                artifact = next(value for value in receipt['artifacts'].values() if value['id'] == identifier)
                return {**artifact, 'expired':False, 'size_in_bytes':len(archives[identifier])}
            if '/releases/tags/' in path: return {'tag_name':'v0.2.0','draft':False,'immutable':True}
            if '/git/ref/tags/' in path: return {'ref':'refs/tags/v0.2.0','object':{'type':'commit','sha':'d'*40}}
            if path == 'repos/'+policy['repository']: return source_metadata
            return {'id':finalizer['repository_id'], 'visibility':'public'}
        certificate = {'buildSignerURI':'https://github.com/'+environment['BATHYSIGN_JOB_WORKFLOW_REF'], 'buildSignerDigest':'d'*40}
        def command(*args):
            if args[0] == 'gh':
                if args[1] == 'attestation': return release.json_bytes([{'verificationResult':{'signature':{'certificate':certificate}}}])
                return archives[int(args[-1].split('/')[-2])]
            if args[:2] == ('keytool','-printcert'): return b'PEM' if '-rfc' in args else receipt['keys']['upload'].encode()
            return b''
        out = root/'verified'
        with mock.patch.dict(release.os.environ, environment, clear=True), mock.patch.object(release, 'api', side_effect=api), mock.patch.object(release, 'run', side_effect=command), mock.patch.object(release, 'prepare_tools') as tools, mock.patch.object(release, 'wait_staging', return_value={'oss':(receipt,files)}), mock.patch.object(release, 'verify_provenance') as verify:
            release.prepare(policy_path, 10, 2, out, root/'tools')
            tools.assert_called_once_with(root/'tools')
            self.assertEqual(verify.call_count, 2)
            for call in verify.call_args_list:
                self.assertTrue(call.args[0].is_file())
                self.assertTrue(call.args[1].is_file())
            predicate = release.load((out/'predicate.json').read_bytes())
            dependencies = {row['uri']:row['digest'] for row in predicate['buildDefinition']['resolvedDependencies']}
            self.assertEqual(dependencies['urn:bathysign:policy'], {'sha256':policy['policy_hash']})
            self.assertEqual(dependencies['urn:bathysign:receipt:oss'], {'sha256':release.digest(files['signing-receipt.dsse.json'])})
            self.assertEqual(dependencies['urn:bathysign:unsigned:oss:apk'], {'sha256':release.digest(inputs['apk'])})
            self.assertEqual(predicate['buildDefinition']['internalParameters']['finalizerCommit'], 'd'*40)
            verification = release.load((out/'verification.json').read_bytes())
            self.assertEqual(verification['source_commit'], source['head_sha'])
            self.assertEqual(set(verification['profiles']), {'oss'})
            release.verify_final_bundle(out, policy_path)
            verification['profiles'] = {}
            (out/'verification.json').write_bytes(release.json_bytes(verification))
            with self.assertRaisesRegex(ValueError, 'profile set differs'):
                release.verify_final_bundle(out, policy_path)
            source['conclusion'] = 'failure'
            with self.assertRaisesRegex(ValueError, 'unsuccessful source run'):
                release.prepare(policy_path, 10, 2, root/'rejected', root/'tools')
            self.assertFalse((root/'rejected').exists())

    def test_api_pagination_and_tool_downloads_are_bounded_and_hash_pinned(self):
        with mock.patch.object(release, 'api', side_effect=[{'items':[1]*100}, {'items':[2]}]):
            self.assertEqual(release.rows('repos/example/app/items', 'items'), [1]*100+[2])
        with mock.patch.object(release, 'api', return_value={}):
            with self.assertRaisesRegex(ValueError, 'invalid API list'):
                release.rows('repos/example/app/items')
        with mock.patch.object(release, 'api', return_value=[1]*100):
            with self.assertRaisesRegex(ValueError, 'pagination limit'):
                release.rows('repos/example/app/items')
        root = Path(self.tmp.name)/self._testMethodName
        root.mkdir()
        tool = root/'tool.jar'
        data = b'pinned tool'
        with mock.patch.object(release.urllib.request, 'urlopen', return_value=io.BytesIO(data)) as fetch:
            release.download_pinned('https://tools.example/tool', release.digest(data), tool)
            release.download_pinned('https://tools.example/tool', release.digest(data), tool)
            fetch.assert_called_once()
        tool.write_bytes(b'tampered cached tool')
        with self.assertRaisesRegex(ValueError, 'cached tool differs'):
            release.download_pinned('https://tools.example/tool', release.digest(data), tool)
        with self.assertRaisesRegex(ValueError, 'invalid tool pin'):
            release.download_pinned('http://tools.example/tool', release.digest(data), tool)
        with mock.patch.object(release.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong')):
            with self.assertRaisesRegex(ValueError, 'tool download differs'):
                release.download_pinned('https://tools.example/tool', release.digest(data), root/'missing.jar')


    def test_reference_tool_preparation_checks_pins_and_compiles_only_supported_sources(self):
        root = Path(self.tmp.name)/self._testMethodName
        root.mkdir()
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode='w:gz') as archive:
            for name in ['src/main/java/Core.java', 'src/main/java/kms/aws/Optional.java']:
                info = tarfile.TarInfo(name)
                info.size = 0
                archive.addfile(info, io.BytesIO())
        downloads = {'https://tools/source':source.getvalue(), 'https://tools/legacy':b'legacy jar', 'https://tools/bundletool':b'bundletool jar'}
        pins = {'apksig_source_url':'https://tools/source', 'apksig_source_tree_sha256':release.source_tree_digest(source.getvalue()), 'apksig_legacy_url':'https://tools/legacy', 'apksig_legacy_sha256':release.digest(b'legacy jar'), 'bundletool_url':'https://tools/bundletool', 'bundletool_sha256':release.digest(b'bundletool jar')}
        original = Path.read_bytes
        def read(path):
            return release.json_bytes(pins) if path.name == 'signer-toolchain-pins.json' else original(path)
        with mock.patch.object(Path, 'read_bytes', read), mock.patch.object(release.urllib.request, 'urlopen', side_effect=lambda url, timeout:io.BytesIO(downloads[url])), mock.patch.object(release, 'run', return_value=b'') as command:
            release.prepare_tools(root/'tools')
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args_list[0].args[0], 'javac')
        sources = (root/'tools/sources.txt').read_text()
        self.assertIn('Core.java', sources)
        self.assertNotIn('Optional.java', sources)
        self.assertIn('Reference.java', sources)

    def test_finalizer_cli_preserves_explicit_policy_and_source_inputs(self):
        import sys
        root = Path(self.tmp.name)/self._testMethodName
        root.mkdir()
        policy, out, tools = root/'policy.json', root/'out', root/'tools'
        args = ['signer-release', 'prepare', '--policy',str(policy), '--source-run','10', '--source-attempt','2', '--out',str(out), '--tools',str(tools)]
        with mock.patch.object(sys, 'argv', args), mock.patch.object(release, 'prepare') as prepare:
            release.main()
            prepare.assert_called_once_with(policy, 10, 2, out, tools)
        with mock.patch.object(sys, 'argv', ['signer-release','verify-bundle','--policy',str(policy),'--out',str(out)]), mock.patch.object(release, 'verify_final_bundle') as verify:
            release.main()
            verify.assert_called_once_with(out, policy)
        with mock.patch.object(sys, 'argv', ['signer-release','verify-bundle','--out',str(out)]), self.assertRaisesRegex(ValueError,'central policy snapshot required'):
            release.main()



if __name__ == "__main__":
    unittest.main()
