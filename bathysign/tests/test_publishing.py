#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Adversarial publishing tests. All credentials and network APIs are mocked."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish", ROOT / "scripts/signer-publish.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


def identity(workflow="bathysign-attest.yml"):
    return {"repository": "example/workflows", "repository_id": 1001,
        "workflow": ".github/workflows/" + workflow, "refs": ["refs/tags/v0.2.0"], "commit": "d" * 40}


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        cert = b"public test certificate"
        keys = {k: "a" * 64 for k in ("original", "classical", "upload", "transparency")}
        self.policy = {"receipt_namespace": "bathysign", "version": 3, "repository": "example/app", "repository_id": 42, "visibility": "public", "revision": 1,
            "policy_hash": "b" * 64, "signer_revision": "c" * 40, "refs": ["refs/heads/main", "refs/tags/v*"],
            "callers": [".github/workflows/ci.yml"], "builder": identity(), "finalizer": identity("bathysign-finalize.yml"),
            "receipt_keys": {p.digest(cert): base64.b64encode(cert).decode()},
            "profiles": {name: {"package": "net.example.app", "keys": {**keys, "hybrid": None}, "lineage_sha256": "d" * 64, "rotation_min_sdk": 33} for name in ("oss", "google")}}
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_bytes(p.json_bytes(self.policy))
        self.policy['publishing'] = {'version': 1, 'asset_prefix': 'Example', 'primary_profile': 'oss', 'play': None}
        self.origin = {'repository': 'example/.github', 'repository_id': 100, 'owner_id': 7, 'ref': 'refs/heads/main',
            'commit': 'a' * 40, 'path': '.github/bathysign/42.json', 'signing_sha256': 'b' * 64,
            'publishing_path': '.github/bathysign/42.publishing.json', 'publishing_sha256': 'c' * 64}
        self.handoff = self.root / "handoff"
        self.handoff.mkdir()
        self.event = self.root / "event.json"
        self.event.write_text(json.dumps({"inputs": {"source_run": "10", "source_attempt": "2"}}))
        self.env = {"GITHUB_REPOSITORY": "example/app", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "e" * 40, "GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_PATH": str(self.event), "RUNNER_ENVIRONMENT": "github-hosted"}
        self.manifest = {"version": 2, "publishing": self.policy["publishing"], "policy_source": self.origin, "repository": "example/app", "repository_id": 42, "policy_hash": self.policy["policy_hash"],
            "source": {"repository": "example/app", "run_id": 10, "attempt": 2, "commit": "f" * 40, "ref": "refs/heads/main"},
            "finalizer": {"repository": "example/app", "run_id": 99, "attempt": 1, "commit": "e" * 40, "ref": "refs/heads/main"},
            "release": {"tag_name": "git-v1.0.0-1-gfffffff", "name": "Test build", "target_commitish": "f" * 40, "prerelease": True},
            "version_codes": {"oss": 101, "google": 101}, "assets": {}}
        self.predicate = {"buildDefinition": {"buildType": p.r.BUILD_TYPE, "externalParameters": {"workflow": {
            "repository": "https://github.com/example/app", "ref": "refs/heads/main", "path": ".github/workflows/bathysign-release.yml"},
            "inputs": {"source_run": "10", "source_attempt": "2"}}}}
        signer = "https://github.com/example/workflows/.github/workflows/bathysign-finalize.yml@refs/tags/v0.2.0"
        self.predicate["runDetails"] = {"builder": {"id": signer}}
        self.predicate["buildDefinition"]["internalParameters"] = {"finalizerCommit": "d" * 40}
        self.result = {"verificationResult": {"statement": {"predicateType": p.r.SLSA, "predicate": self.predicate, "subject": []},
            "signature": {"certificate": {"runInvocationURI": "https://github.com/example/app/actions/runs/99/attempts/1", "sourceRepositoryIdentifier": "42", "buildSignerURI": signer, "buildSignerDigest": "d" * 40}}}}
        self.populate()

    def test_bundle_verification_uses_policy_identity_without_creating_drafts(self):
        out = self.root / "verified-draft"
        out.mkdir()
        metadata = {"source_run": 10, "source_attempt": 2, "profiles": {"oss": {}, "google": {}}}
        release = {"tag_name": "verified/10-2-policy", "target_commitish": "f" * 40}
        (out / "verification.json").write_bytes(p.json_bytes(metadata))
        (out / "release.json").write_bytes(p.json_bytes(release))
        for profile in metadata["profiles"]:
            (out / profile).mkdir()
        target = {**release, "id": 7, "draft": True, "body": "Verified Android signing; source run 10/2"}
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch.object(p.r, "verify_workflow_identity"), \
             mock.patch.object(p.r, "rows", return_value=[target]) as rows, \
             mock.patch.object(p.r, "upload"), \
             mock.patch.object(p.r, "run", return_value=p.json_bytes([self.result])) as run:
            for name in ("final.sigstore.json", "predicate.json"):
                (out / name).write_bytes(b"fixture")
            p.r.verify_final_bundle(out, self.policy_path)
            self.assertEqual(run.call_count, 4)
            for call in run.call_args_list:
                args = call.args
                self.assertEqual(args[args.index("--signer-workflow") + 1],
                    "example/workflows/.github/workflows/bathysign-finalize.yml")
                self.assertEqual(args[args.index("--source-digest") + 1], self.env["GITHUB_SHA"])
                self.assertEqual(args[args.index("--source-ref") + 1], self.env["GITHUB_REF"])
                self.assertIn("--deny-self-hosted-runners", args)
            for signer in ("example/app/.github/workflows/release-attest.yml@refs/heads/main",
                           "example/workflows/.github/workflows/bathysign-finalize.yml@refs/heads/main"):
                bad = copy.deepcopy(self.result)
                bad["verificationResult"]["signature"]["certificate"]["buildSignerURI"] = "https://github.com/" + signer
                run.return_value = p.json_bytes([bad])
                rows.reset_mock()
                with self.assertRaisesRegex(ValueError, "builder differs"):
                    p.r.verify_final_bundle(out, self.policy_path)
                rows.assert_not_called()

    def populate(self):
        self.policy_path.write_bytes(p.json_bytes(self.policy))
        self.origin['sha256'] = p.digest(self.policy_path.read_bytes())
        self.policy_path.with_suffix('.source.json').write_bytes(p.json_bytes(self.origin))
        self.predicate['buildDefinition']['resolvedDependencies'] = [
            {'uri': f"git+https://github.com/{self.origin['repository']}@{self.origin['ref']}#{self.origin[path_key]}",
             'digest': {'gitCommit': self.origin['commit'], 'sha256': self.origin[digest_key]}}
            for path_key, digest_key in (('path', 'signing_sha256'), ('publishing_path', 'publishing_sha256'))]
        files = {"predicate.json": p.json_bytes(self.predicate), "verification.json": b"{}", "bathysign-policy.json": self.policy_path.read_bytes(), "version_code.txt": b"101\n"}
        for profile in ("oss", "google"):
            prefix = f"Example-{self.manifest['release']['tag_name']}-{profile}"
            files.update({f"{prefix}.{ext}": b"verified " + ext.encode() for ext in ("apk", "aab", "mapping.txt.zst", "native-debug-symbols.zip")})
            files[f"provenance-{profile}.json"] = b"{}"
            files.update({f"{profile}-{name}": b"public evidence" for name in ("signing-receipt.dsse.json", "signing-receipt.json", "code_transparency_signed.jwt", "transparency-certificate.der", "apk-lineage.bin")})
        if not self.manifest["release"]["prerelease"]:
            files["version-info.txt"] = b"VERSION_NAME=1.0.0\nVERSION_CODE=101\n"
        for file in self.handoff.iterdir():
            file.unlink()
        for name, data in files.items():
            (self.handoff / name).write_bytes(data)
        self.manifest["assets"] = {name: {"sha256": p.digest(data), "bytes": len(data)} for name, data in files.items()}
        self.refresh()

    def refresh(self):
        data = p.json_bytes(self.manifest)
        (self.handoff / "release-manifest.json").write_bytes(data)
        (self.handoff / "final.sigstore.json").write_bytes(b"mock Sigstore bundle")
        self.result["verificationResult"]["statement"]["subject"] = [{"name": name, "digest": {"sha256": asset["sha256"]}} for name, asset in self.manifest["assets"].items()]
        self.result["verificationResult"]["statement"]["subject"].append({"name": "release-manifest.json", "digest": {"sha256": p.digest(data)}})
        self.sha = p.digest(data)

    def verify(self, env=None):
        with mock.patch.dict(os.environ, self.env if env is None else env, clear=True), \
             mock.patch.object(p.r, "api", return_value={"id": 42, "visibility": "public", "default_branch": "main"}), \
             mock.patch.object(p.r, "verify_workflow_identity"), \
             mock.patch.object(p.r, "run", return_value=p.json_bytes([self.result])) as run:
            result = p.verify_handoff(self.handoff, self.sha, self.policy_path)
            args = run.call_args.args
            self.assertNotIn("--signer-digest", args)
            self.assertIn("--source-digest", args)
            self.assertIn("--deny-self-hosted-runners", args)
            return result

    def test_complete_handoff(self):
        self.assertEqual(self.verify(), self.manifest)

    def test_retry_failed_publisher_accepts_same_run_prior_producer_attempt(self):
        self.verify({**self.env, "GITHUB_RUN_ATTEMPT": "2"})
        with self.assertRaisesRegex(ValueError, "identity"):
            self.verify({**self.env, "GITHUB_RUN_ID": "100"})

    def test_tampered_asset_and_missing_asset_rejected(self):
        file = self.handoff / "version_code.txt"
        file.write_bytes(b"102\n")
        with self.assertRaisesRegex(ValueError, "asset differs"):
            self.verify()
        file.unlink()
        with self.assertRaisesRegex(ValueError, "unexpected handoff"):
            self.verify()

    def test_manifest_hash_and_duplicate_keys_rejected(self):
        (self.handoff / "release-manifest.json").write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "manifest differs"):
            self.verify()
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            p.load(b'{"version":1,"version":2}')

    def test_unattested_asset_and_wrong_invocation_rejected(self):
        self.result["verificationResult"]["statement"]["subject"] = []
        with self.assertRaisesRegex(ValueError, "absent from final attestation"):
            self.verify()
        self.refresh()
        self.result["verificationResult"]["signature"]["certificate"]["runInvocationURI"] += "9"
        with self.assertRaisesRegex(ValueError, "invocation differs"):
            self.verify()

    def test_wrong_dispatch_policy_and_source_rejected(self):
        self.event.write_text(json.dumps({"inputs": {"source_run": "11", "source_attempt": "2"}}))
        with self.assertRaisesRegex(ValueError, "dispatch inputs"):
            self.verify()
        self.event.write_text(json.dumps({"inputs": {"source_run": "10", "source_attempt": "2"}}))
        self.manifest["policy_hash"] = "1" * 64
        self.refresh()
        with self.assertRaisesRegex(ValueError, "identity differs"):
            self.verify()

    def test_main_cannot_claim_stable_release(self):
        self.manifest["release"]["prerelease"] = False
        self.refresh()
        with self.assertRaisesRegex(ValueError, "classification differs"):
            self.verify()

    def test_stable_tag_and_fdroid_metadata(self):
        self.manifest["source"]["ref"] = "refs/tags/v1.0.0"
        self.manifest["release"].update(tag_name="v1.0.0", prerelease=False)
        self.populate()
        self.verify()
        (self.handoff / "version-info.txt").write_bytes(b"wrong")
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlink_traversal_extra_files_and_missing_required_asset(self):
        (self.handoff / "extra").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected handoff"):
            self.verify()
        (self.handoff / "extra").unlink()
        file = self.handoff / "version_code.txt"
        file.unlink()
        file.symlink_to(self.policy_path)
        with self.assertRaisesRegex(ValueError, "asset differs"):
            self.verify()
        file.unlink()
        self.manifest["assets"].pop("version_code.txt")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "asset set differs"):
            self.verify()

    def test_wrong_auxiliary_attempt_and_altered_archive_rejected(self):
        artifact = {"name": "release-support-oss-2", "expired": False, "id": 7, "size_in_bytes": 1,
                    "workflow_run": {"id": 10, "head_sha": "f" * 40, "repository_id": 42}, "digest": "sha256:wrong"}
        with mock.patch.object(p.r, "rows", return_value=[artifact]), mock.patch.object(p.r, "run", return_value=b"bad archive"):
            with self.assertRaisesRegex(ValueError, "archive digest differs"):
                p.support_files(self.policy, {"id": 10, "run_attempt": 2, "head_sha": "f" * 40}, "oss", {})
            artifact["name"] = "release-support-oss-1"
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                p.support_files(self.policy, {"id": 10, "run_attempt": 2, "head_sha": "f" * 40}, "oss", {})

    def test_package_covers_both_profiles_and_original_support_dependencies(self):
        out = self.root / "verified"
        out.mkdir()
        verification = {"source_run": 10, "source_attempt": 2, "profiles": {"oss": {}, "google": {}}}
        (out / "verification.json").write_bytes(p.json_bytes(verification))
        (out / "predicate.json").write_bytes(p.json_bytes({**self.predicate, "buildDefinition": {
            **self.predicate["buildDefinition"], "resolvedDependencies": [{"uri": "urn:original", "digest": {"sha256": "a" * 64}}]}}))
        for profile in ("oss", "google"):
            root = out / profile
            root.mkdir()
            receipt = {"version_code": 101, "provenance": {"aab": {"ref": "refs/heads/main"}}}
            (root / "signing-receipt.json").write_bytes(p.json_bytes(receipt))
            for name in ("app-signed.apk", "app-signed.aab", "signing-receipt.dsse.json", "code_transparency_signed.jwt", "transparency-certificate.der", "apk-lineage.bin", "unsigned-aab.sigstore.json"):
                (root / name).write_bytes(b"verified fixture")
        info = {"version": 1, "profile": "oss", "source": self.manifest["source"], "tag": self.manifest["release"]["tag_name"], "title": "Test build", "version_code": 101}
        files = {"mapping.txt": b"mapping", "native-debug-symbols.zip": b"symbols", "build-info.json": p.json_bytes(info)}
        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(p.r, "api", return_value={"id": 10, "run_attempt": 2, "head_sha": "f" * 40}), \
             mock.patch.object(p.r, "validate_transaction"), mock.patch.object(p, "support_files", return_value=(files, info, {"id": 7, "digest": "sha256:" + "a" * 64})), \
             mock.patch.object(p.r, "verify_provenance") as verify:
            manifest = p.package_release(out, self.policy_path)
        self.assertEqual(verify.call_count, 6)
        self.assertEqual(manifest["version_codes"], {"oss": 101, "google": 101})
        self.assertIn("Example-git-v1.0.0-1-gfffffff-google.mapping.txt.zst", manifest["assets"])
        self.assertNotIn("version-info.txt", manifest["assets"])
        self.assertNotIn("mapping.txt", manifest["assets"])
        predicate = p.load((out / "predicate.json").read_bytes())
        self.assertEqual(predicate["buildDefinition"]["resolvedDependencies"][0]["uri"], "urn:original")
        self.assertEqual(sum(d["uri"].startswith("urn:bathysign:release-support:") for d in predicate["buildDefinition"]["resolvedDependencies"]), 6)

    def test_build_metadata_uses_source_context_without_shell_interpolation(self):
        code = self.root / "code.txt"
        code.write_text("101\n")
        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(p.r, "run", side_effect=[b"v1.0.0-1-geeeeeee\n", b"Subject with $(literal) and `literal`\n"]):
            p.build_info(self.root / "support", "google", code)
        info = p.load((self.root / "support/build-info.json").read_bytes())
        self.assertEqual(info["tag"], "git-v1.0.0-1-geeeeeee")
        self.assertEqual(info["version_code"], 101)
        self.assertIn("$(literal)", info["title"])
        self.assertEqual(info["source"]["commit"], self.env["GITHUB_SHA"])

    def test_build_metadata_uses_gradle_anchor_instead_of_nearer_maintenance_tag(self):
        code, name = self.root / "code.txt", self.root / "name.txt"
        code.write_text("11150003\n")
        for version in ("git-v1.12.0-alpha-3-gabcdef0", "v1.12.0-alpha"):
            name.write_text(version + "\n")
            with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(p.r, "run", return_value=b"Forward port patch") as run:
                p.build_info(self.root / "support", "google", code, name)
            run.assert_called_once_with("git", "log", "-1", "--format=%s", self.env["GITHUB_SHA"])
            info = p.load((self.root / "support/build-info.json").read_bytes())
            self.assertEqual(info["tag"], version if version.startswith("git-") else "git-" + version)

    def test_github_publishes_only_complete_matching_draft_and_is_idempotent(self):
        marker = "Verified Android signing; source run 10/2; commit " + "f" * 40 + "; policy " + "b" * 64
        target = {"id": 7, "tag_name": self.manifest["release"]["tag_name"], "body": marker + "\n\nNotes", "draft": True,
                  "target_commitish": "f" * 40, "prerelease": True, "name": "Test build", "html_url": "https://example/release"}
        assets, uploaded = [], {}
        def rows(path):
            return [target] if path.endswith("/releases") else assets
        def upload(repo, release_id, name, data):
            uploaded[name] = data
            assets.append({"name": name, "state": "uploaded", "digest": f"sha256:{p.digest(data)}", "size": len(data)})
        def patch(method, path, body):
            self.assertEqual((method, body), ("PATCH", {"draft": False, "make_latest": "false"}))
            target["draft"] = False
            return target
        with mock.patch.object(p.r, "rows", side_effect=rows), mock.patch.object(p.r, "upload", side_effect=upload) as uploads, mock.patch.object(p, "gh_json", side_effect=patch) as changes, \
             mock.patch.object(p.r, "api", return_value={"object": {"type": "commit", "sha": "f" * 40}}), \
             mock.patch.object(p.r, "download_asset", side_effect=lambda repo, asset: uploaded[asset["name"]]):
            self.assertEqual(p.github_release(self.handoff, self.manifest)["status"], "published")
            self.assertEqual(len(assets), len(p.r.public_names(self.manifest)) + 1)
            uploads.reset_mock()
            p.github_release(self.handoff, self.manifest)
            uploads.assert_not_called()
            self.assertEqual(changes.call_count, 1)
            assets[0]["digest"] = "sha256:wrong"
            with self.assertRaisesRegex(ValueError, "published release bytes differ"):
                p.github_release(self.handoff, self.manifest)

    def test_github_conflicting_release_never_modified(self):
        target = {"tag_name": self.manifest["release"]["tag_name"], "target_commitish": "0" * 40}
        with mock.patch.object(p.r, "rows", return_value=[target]), mock.patch.object(p, "gh_json") as changes:
            with self.assertRaisesRegex(ValueError, "conflicting publication"):
                p.github_release(self.handoff, self.manifest)
            changes.assert_not_called()

    def test_release_tag_must_resolve_to_verified_source(self):
        with mock.patch.object(p.r, "api", side_effect=[{"object": {"type": "tag", "sha": "a" * 40}}, {"object": {"type": "commit", "sha": "f" * 40}}]), mock.patch.object(p, "gh_json") as changes:
            p.ensure_release_tag("example/app", "v1.0.0", "f" * 40)
            changes.assert_not_called()
        with mock.patch.object(p.r, "api", return_value={"object": {"type": "commit", "sha": "a" * 40}}), mock.patch.object(p, "gh_json") as changes:
            with self.assertRaisesRegex(ValueError, "another commit"):
                p.ensure_release_tag("example/app", "v1.0.0", "f" * 40)
            changes.assert_not_called()
        with mock.patch.object(p.r, "api", side_effect=p.subprocess.CalledProcessError(1, ["gh"])), mock.patch.object(p.r, "rows", return_value=[]), \
             mock.patch.object(p, "gh_json", return_value={"object": {"type": "commit", "sha": "f" * 40}}) as changes:
            p.ensure_release_tag("example/app", "git-v1.0.0-1-gfffffff", "f" * 40)
            self.assertEqual(changes.call_args.args, ("POST", "repos/example/app/git/refs", {"ref": "refs/tags/git-v1.0.0-1-gfffffff", "sha": "f" * 40}))

    def test_new_stable_release_is_created_as_draft_then_published(self):
        self.manifest["source"]["ref"] = "refs/tags/v1.0.0"
        self.manifest["release"].update(tag_name="v1.0.0", prerelease=False)
        self.populate()
        assets, requests = [], []
        target = {"id": 7, "draft": True, "html_url": "https://example/release"}
        def call(method, path, body):
            requests.append((method, path, body))
            if path.endswith("generate-notes"):
                return {"body": "Generated notes"}
            if method == "POST":
                self.assertTrue(body["draft"])
                self.assertFalse(body["prerelease"])
                self.assertEqual(body["target_commitish"], "f" * 40)
            if method == "PATCH":
                self.assertEqual(body, {"draft": False, "make_latest": "legacy"})
                self.assertEqual(len(assets), len(p.r.public_names(self.manifest)) + 1)
                target["draft"] = False
            return target
        def upload(repo, release_id, name, data):
            assets.append({"name": name, "state": "uploaded", "digest": f"sha256:{p.digest(data)}", "size": len(data)})
        with mock.patch.object(p, "ensure_release_tag"), mock.patch.object(p.r, "rows", side_effect=lambda path: [] if path.endswith("/releases") else assets), \
             mock.patch.object(p, "gh_json", side_effect=call), mock.patch.object(p.r, "upload", side_effect=upload):
            self.assertEqual(p.github_release(self.handoff, self.manifest)["status"], "published")
        self.assertEqual([q[0] for q in requests], ["POST", "POST", "PATCH"])

    def test_published_evidence_is_retained_on_full_finalizer_rerun(self):
        files = {path.name: path.read_bytes() for path in self.handoff.iterdir()}
        existing = [{"name": name, "state": "uploaded", "digest": f"sha256:{p.digest(data)}", "size": len(data)} for name, data in files.items()]
        self.manifest["finalizer"]["attempt"] = 2
        changed = p.json_bytes({**self.predicate, "new_attempt": 2})
        (self.handoff / "predicate.json").write_bytes(changed)
        self.manifest["assets"]["predicate.json"] = {"sha256": p.digest(changed), "bytes": len(changed)}
        (self.handoff / "release-manifest.json").write_bytes(p.json_bytes(self.manifest))
        with mock.patch.object(p.r, "verify_workflow_identity"), \
             mock.patch.object(p.r, "download_asset", side_effect=lambda repo, asset: files[asset["name"]]), \
             mock.patch.object(p.r, "run", return_value=p.json_bytes([self.result])):
            p.verify_existing_publication(self.handoff, self.manifest, existing)
            self.manifest["assets"]["version_code.txt"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                p.verify_existing_publication(self.handoff, self.manifest, existing)


class FakePlay:
    package = "net.example.app"

    def __init__(self):
        self.bundles, self.tracks, self.edits, self.calls = [], {"alpha": {"releases": []}, "beta": {"releases": []}}, {}, []
        self.version_code = 101
        self.lost_upload = self.lost_commit = self.review = False
        self.next_id = 0

    def request(self, method, path, body=None, media=None):
        self.calls.append((method, path, body))
        base = "applications/net.example.app/edits"
        if path == base and method == "POST":
            self.next_id += 1
            edit = str(self.next_id)
            self.edits[edit] = [copy.deepcopy(self.bundles), copy.deepcopy(self.tracks)]
            return {"id": edit}
        edit, _, suffix = path[len(base) + 1:].partition("/")
        if ":commit" in edit:
            edit = edit.partition(":")[0]
            if self.review:
                raise p.PlayError(400)
            self.bundles, self.tracks = copy.deepcopy(self.edits[edit])
            if self.lost_commit:
                self.lost_commit = False
                raise p.PlayError(0)
            return {"id": edit}
        if method == "DELETE":
            self.edits.pop(edit, None)
            return {}
        bundles, tracks = self.edits[edit]
        if suffix == "bundles" and method == "GET":
            return {"bundles": bundles}
        if suffix in ("tracks/alpha", "tracks/beta"):
            name = suffix.split("/")[1]
            if method == "PUT":
                tracks[name] = copy.deepcopy(body)
                return body
            return tracks[name]
        if suffix.startswith("bundles?"):
            bundle = {"versionCode": self.version_code, "sha256": p.digest(media)}
            bundles.append(bundle)
            if self.lost_upload:
                self.lost_upload = False
                raise p.PlayError(503)
            return bundle
        if "deobfuscationFiles" in suffix:
            return {"deobfuscationFile": {}}
        raise AssertionError((method, path))


class PlayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = {"repository": "example/release-app", "repository_id": 1003,
                         "source": {"ref": "refs/tags/v1.0.0", "commit": "f" * 40},
                         "version_codes": {"google": 101}, "release": {"tag_name": "v1.0.0", "prerelease": False}}
        self.aab = b"upload-key-signed AAB"
        prefix = "Example-v1.0.0-google"
        for name, data in ((f"{prefix}.aab", self.aab), (f"{prefix}.native-debug-symbols.zip", b"symbols"), (f"{prefix}.mapping.txt.zst", b"compressed mapping")):
            (self.root / name).write_bytes(data)
        self.manifest['publishing'] = {'version': 1, 'asset_prefix': 'Example', 'primary_profile': 'google',
            'play': {'profile': 'google', 'project': 'example-project', 'rules': [
                {'ref': r'refs/tags/v1\.0\.0', 'track': 'alpha'},
                {'ref': r'refs/tags/v1\.11\.(?P<patch>[0-9]+)', 'track': 'beta',
                 'version_code': {'base': 11100000, 'multiplier': 1000, 'group': 'patch', 'min': 0, 'max': 49}}]}}
        (self.root / "bathysign-policy.json").write_text(json.dumps({'publishing': self.manifest['publishing'], 'profiles': {'google': {'package': 'net.example.app'}}}))
        self.client = FakePlay()

    def publish(self):
        with mock.patch.object(p.r, "run", return_value=b"verified mapping"):
            return p.play_release(self.client, self.root, self.manifest, p.play_track(self.manifest))

    def test_upload_mapping_symbols_completed_alpha_and_retry(self):
        self.assertEqual(self.publish()["status"], "published")
        self.assertEqual(self.client.tracks["alpha"]["releases"], [{"name": "Version v1.0.0", "versionCodes": ["101"], "status": "completed"}])
        paths = [path for method, path, body in self.client.calls]
        self.assertTrue(any("/apks/101/deobfuscationFiles/proguard" in path for path in paths))
        self.assertTrue(any("/apks/101/deobfuscationFiles/nativeCode" in path for path in paths))
        self.assertTrue(any(":commit?changesInReviewBehavior=ERROR_IF_IN_REVIEW" in path for path in paths))
        count = len(self.client.calls)
        self.assertEqual(self.publish()["status"], "already-published")
        self.assertFalse(any(method in ("PUT",) or "deobfuscationFiles" in path or ":commit" in path for method, path, _ in self.client.calls[count:]))

    def maintenance(self):
        self.manifest["source"]["ref"] = "refs/tags/v1.11.2"
        self.manifest["release"]["tag_name"] = "v1.11.2"
        self.manifest["version_codes"]["google"] = self.client.version_code = 11102000
        for path in list(self.root.glob("Example-v1.0.0-*")):
            path.rename(path.with_name(path.name.replace("v1.0.0", "v1.11.2")))

    def test_maintenance_uploads_to_beta_below_newer_alpha(self):
        self.maintenance()
        alpha = {"releases": [{"versionCodes": ["11150025"], "status": "completed"}]}
        self.client.tracks["alpha"] = copy.deepcopy(alpha)
        result = self.publish()
        self.assertEqual((result["track"], result["status"]), ("beta", "published"))
        self.assertEqual(self.client.tracks["alpha"], alpha)
        self.assertEqual(self.client.tracks["beta"]["releases"][0]["versionCodes"], ["11102000"])
        self.assertEqual(self.publish()["status"], "already-published")
        self.assertFalse(any("tracks/alpha" in path for _, path, _ in self.client.calls))

    def test_maintenance_checks_beta_for_superseded_builds(self):
        self.maintenance()
        self.client.tracks["beta"] = {"releases": [{"versionCodes": ["11103000"], "status": "completed"}]}
        self.assertEqual(self.publish()["status"], "superseded")
        self.assertFalse(any(method == "PUT" or "bundles?" in path for method, path, _ in self.client.calls))

    def test_beta_lost_responses_are_reconciled_on_beta(self):
        self.maintenance()
        self.client.lost_upload = self.client.lost_commit = True
        self.assertEqual(self.publish()["status"], "published")
        self.assertEqual(self.publish()["status"], "already-published")
        self.assertFalse(any("tracks/alpha" in path for _, path, _ in self.client.calls))

    def test_wrong_track_and_maintenance_codes_fail_before_network(self):
        with self.assertRaisesRegex(ValueError, "track differs"):
            p.play_release(self.client, self.root, self.manifest, "beta")
        self.maintenance()
        for track in ("alpha", "production", "../beta", None):
            with self.subTest(track=track), self.assertRaisesRegex(ValueError, "track differs"):
                p.play_release(self.client, self.root, self.manifest, track)
        self.manifest["version_codes"]["google"] = 11150000
        with self.assertRaisesRegex(ValueError, "version code differs"):
            self.publish()
        self.assertFalse(self.client.calls)

    def test_routing_requires_one_configured_source_rule(self):
        self.manifest["source"]["ref"] = "refs/heads/unconfigured"
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            p.play_track(self.manifest)
        self.manifest["source"]["ref"] = "refs/tags/v1.0.0"
        self.manifest['publishing']['play']['rules'].append({'ref': 'refs/tags/.*', 'track': 'beta'})
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            p.play_track(self.manifest)

    def test_exact_tag_suppresses_main_publication_only(self):
        self.manifest["source"]["ref"] = "refs/heads/main"
        refs = [{"ref": "refs/tags/v1.12.0-alpha", "object": {"type": "tag", "sha": "a" * 40}}]
        with mock.patch.object(p.r, "rows", return_value=refs), mock.patch.object(p.r, "api", return_value={
            "object": {"type": "commit", "sha": "f" * 40}}):
            self.assertEqual(p.superseding_tag(self.manifest), "v1.12.0-alpha")
            self.manifest["source"]["commit"] = "e" * 40
            self.assertIsNone(p.superseding_tag(self.manifest))
            self.manifest["source"]["ref"] = "refs/tags/v1.12.0-alpha"
            self.manifest["source"]["commit"] = "f" * 40
            self.assertIsNone(p.superseding_tag(self.manifest))

    def test_route_and_verify_play_cli_require_verified_source(self):
        self.maintenance()
        output = self.root / "outputs"
        args = ["publisher", "play-route", "--out=" + str(self.root), "--policy=policy", "--manifest-sha256=hash"]
        with mock.patch("sys.argv", args), mock.patch.object(p, "verify_handoff", return_value=self.manifest) as verify, \
             mock.patch.object(p, "superseding_tag", return_value=None), mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            p.main()
            verify.assert_called_once()
        self.assertEqual(output.read_text(), "play_track=beta\ngoogle_project=example-project\n")
        args[1] = "verify-play"
        args.append("--play-track=alpha")
        with mock.patch("sys.argv", args), mock.patch.object(p, "verify_handoff", return_value=self.manifest), \
             mock.patch.object(p, "Play") as client:
            with self.assertRaisesRegex(ValueError, "track differs"):
                p.main()
            client.assert_not_called()

    def test_conflicting_bundle_hash_rejected_without_track_update(self):
        self.client.bundles = [{"versionCode": 101, "sha256": "0" * 64}]
        with self.assertRaisesRegex(ValueError, "bundle hash conflicts"):
            self.publish()
        self.assertFalse(any(method == "PUT" for method, _, _ in self.client.calls))

    def test_older_build_cannot_downgrade_alpha(self):
        self.client.tracks["alpha"] = {"releases": [{"versionCodes": ["102"], "status": "completed"}]}
        self.assertEqual(self.publish()["status"], "superseded")
        self.assertFalse(any(method == "PUT" or "bundles?" in path for method, path, _ in self.client.calls))

    def test_lost_upload_and_commit_responses_are_reconciled(self):
        self.client.lost_upload = self.client.lost_commit = True
        self.assertEqual(self.publish()["status"], "published")
        self.assertEqual(len(self.client.bundles), 1)
        self.assertEqual(sum(":commit" in path for _, path, _ in self.client.calls), 1)

    def test_review_failure_never_retried_with_changed_review_parameters(self):
        self.client.review = True
        with self.assertRaises(p.PlayError):
            self.publish()
        self.assertFalse(self.client.bundles)
        self.assertEqual(sum(":commit" in path for _, path, _ in self.client.calls), 1)

    def test_unconfirmed_commit_failure_is_not_reported_as_success(self):
        request = self.client.request
        def failed_commit(method, path, body=None, media=None):
            if ":commit" in path:
                raise p.PlayError(503)
            return request(method, path, body, media)
        with mock.patch.object(self.client, "request", side_effect=failed_commit):
            with self.assertRaisesRegex(ValueError, "uncertain Play commit"):
                self.publish()
        self.assertFalse(self.client.bundles)

    def test_play_client_cannot_publish_to_another_application(self):
        self.client.package = "other.example.app"
        with self.assertRaisesRegex(ValueError, "application differs"):
            self.publish()
        self.assertFalse(self.client.calls)

    def test_token_redirect_and_api_path_restrictions(self):
        with self.assertRaises(ValueError):
            p.Play("token\nunsafe", "net.example.app")
        client = p.Play("test-only-not-a-credential", "net.example.app")
        with self.assertRaisesRegex(ValueError, "invalid Play API path"):
            client.request("POST", "https://example.org/token-leak")
        self.assertIsNone(p.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.org"))

    def test_http_error_preserves_google_message_and_redacts_credentials(self):
        client = p.Play("test-only-not-a-credential", "net.example.app")
        path = "applications/net.example.app/edits/1:commit?changesInReviewBehavior=ERROR_IF_IN_REVIEW"
        message = "The caller does not have permission.\n" + client.token
        body = json.dumps({"error": {"code": 403, "message": message}}).encode()
        error = p.urllib.error.HTTPError("https://androidpublisher.googleapis.com/", 403, "Forbidden", {}, io.BytesIO(body))
        with mock.patch.object(client.opener, "open", side_effect=error) as request:
            with self.assertRaises(p.PlayError) as raised:
                client.request("POST", path)
        self.assertEqual(raised.exception.status, 403)
        self.assertIn("The caller does not have permission.", str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))
        self.assertNotIn(client.token, str(raised.exception))
        self.assertNotIn("\n", str(raised.exception))
        self.assertFalse(p.retryable(raised.exception))
        request.assert_called_once()

    def test_unusable_http_error_bodies_preserve_original_status(self):
        client = p.Play("test-only-not-a-credential", "net.example.app")
        for body in (b"not JSON", b"\xff", b"[]", b'{"error": null}',
                     b'{"error": {"message": 42}}', b"x" * (16 * 1024 + 1)):
            with self.subTest(body=body[:50]):
                error = p.urllib.error.HTTPError("https://androidpublisher.googleapis.com/", 503, "Unavailable", {}, io.BytesIO(body))
                with mock.patch.object(client.opener, "open", side_effect=error):
                    with self.assertRaises(p.PlayError) as raised:
                        client.request("GET", "applications/net.example.app/edits/1/bundles")
                self.assertEqual(raised.exception.status, 503)
                self.assertTrue(p.retryable(raised.exception))
                self.assertNotIn("Google response:", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
