#!/usr/bin/env python3
# Copyright 2026 Kenny Root
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_publishing as fixtures
p = fixtures.p


identity = fixtures.identity

class PolicyTests(unittest.TestCase):
    setUp = fixtures.HandoffTests.setUp
    populate = fixtures.HandoffTests.populate
    refresh = fixtures.HandoffTests.refresh

    def test_policy_requires_the_bathysign_receipt_namespace(self):
        for namespace in (None, "android-signer", "attacker"):
            policy = {**self.policy, "receipt_namespace": namespace}
            if namespace is None:
                policy.pop("receipt_namespace")
            with self.subTest(namespace=namespace), self.assertRaisesRegex(ValueError, "receipt namespace"):
                p.r.validate_policy(policy)

    def test_policy_api_authenticates_public_reads_without_following_redirects(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "job-token", "GITHUB_REPOSITORY": "example/app"}, clear=True), \
             mock.patch.object(p.urllib.request, "build_opener") as build_opener:
            opener = build_opener.return_value
            opener.open.return_value.__enter__.return_value.read.return_value = b'{"id": 42}'
            self.assertEqual(p.policy_api("/branches/main"), {"id": 42})
        self.assertIsInstance(build_opener.call_args.args[0], p.NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/example/.github/branches/main")
        self.assertEqual(request.get_header("Authorization"), "Bearer job-token")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})

    def test_policy_api_rejects_missing_or_empty_token_before_network_access(self):
        for env in ({}, {"GH_TOKEN": ""}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(p.urllib.request, "build_opener") as build_opener:
                with self.assertRaisesRegex(ValueError, "GH_TOKEN is required"):
                    p.policy_api("")
                build_opener.assert_not_called()

    def responses(self, policy=None):
        raw = {k: v for k, v in (policy or self.policy).items() if k != 'publishing'}
        def file(path, value):
            return {"path": path, "type": "file", "encoding": "base64", "content": base64.b64encode(p.json_bytes(value)).decode()}
        return [{"id": 100, "full_name": "example/.github", "owner": {"id": 7}, "default_branch": "main"},
            {"protected": True, "commit": {"sha": "a" * 40}},
            file('.github/bathysign/42.json', raw), file('.github/bathysign/42.publishing.json', self.policy['publishing'])]

    def fetch(self, responses):
        out = self.root / "loaded-policy.json"
        with mock.patch.dict(os.environ, {**self.env, "GITHUB_REPOSITORY_ID": "42", "GITHUB_REPOSITORY_OWNER_ID": "7"}, clear=True), \
             mock.patch.object(p, "policy_api", side_effect=responses) as api, \
             mock.patch.object(p.r, 'api', return_value={'id': 42, 'full_name': 'example/app', 'owner': {'id': 7}}):
            p.fetch_policy(out)
        return out, api

    def test_central_policy_uses_platform_repository_id_and_immutable_commit(self):
        out, api = self.fetch(self.responses())
        self.assertEqual(p.load(out.read_bytes()), self.policy)
        self.assertEqual(api.call_args.args, ("/contents/.github/bathysign/42.publishing.json?ref=" + "a" * 40,))
        source = p.load(out.with_suffix(".source.json").read_bytes())
        self.assertEqual(source["commit"], "a" * 40)
        self.assertEqual(source["sha256"], p.digest(out.read_bytes()))

    def test_changed_policy_repository_or_unprotected_branch_is_rejected(self):
        for index, replacement in [(0, {"id": 100, "full_name": "attacker/.github", "owner": {"id": 7}, "default_branch": "main"}), (1, {"protected": False, "commit": {"sha": "a" * 40}})]:
            responses = self.responses()
            responses[index] = replacement
            with self.assertRaises(ValueError):
                self.fetch(responses)
            self.assertFalse((self.root / "loaded-policy.json").exists())

    def test_another_source_repository_policy_is_rejected(self):
        policy = {**self.policy, "repository_id": 43}
        with self.assertRaisesRegex(ValueError, "another repository"):
            self.fetch(self.responses(policy))

    def test_trusted_builder_identity_requires_repository_id_and_branch_protection(self):
        for responses in ([{"id": 99, "visibility": "public"}],
                          [{"id": 1001, "visibility": "public"}, {"protected": False}]):
            with mock.patch.object(p.r, "api", side_effect=responses), self.assertRaises(ValueError):
                p.r.verify_workflow_identity(identity())

    def test_removed_authorization_modes_and_missing_finalizer_are_rejected(self):
        for field, value in (("authorization", "content-pins"), ("authorization", "workflow-identity"),
                             ("sha256", []), ("helpers", {})):
            policy = {**self.policy, "builder": {**self.policy["builder"], field: value}}
            with self.assertRaisesRegex(ValueError, "unsupported workflow policy"):
                p.r.validate_policy(policy)
        old = {**self.policy, "version": 2}
        with self.assertRaisesRegex(ValueError, "version 3"):
            p.r.validate_policy(old)
        missing = {k: v for k, v in self.policy.items() if k != "finalizer"}
        with self.assertRaisesRegex(ValueError, "required policy identities"):
            p.r.validate_policy(missing)
        with self.assertRaises(ValueError):
            p.r.validate_policy({**self.policy, "callers": {".github/workflows/ci.yml": []}})

    def test_shared_finalizer_certificate_and_predicate_must_agree(self):
        trusted = identity("bathysign-finalize.yml")
        self.policy["finalizer"] = trusted
        self.policy_path.write_bytes(p.json_bytes(self.policy))
        signer = "https://github.com/example/workflows/.github/workflows/bathysign-finalize.yml@refs/heads/bathysign-v1"
        certificate = self.result["verificationResult"]["signature"]["certificate"]
        certificate.update(buildSignerURI=signer, buildSignerDigest="1" * 40)
        self.predicate.update(runDetails={"builder": {"id": signer}})
        self.predicate["buildDefinition"]["internalParameters"] = {"finalizerCommit": "1" * 40}
        self.populate()
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch.object(p.r, "api", return_value={"id": 42, "visibility": "public", "default_branch": "main"}), \
             mock.patch.object(p.r, "verify_workflow_identity"), \
             mock.patch.object(p.r, "run", return_value=p.json_bytes([self.result])) as run:
            self.assertEqual(p.verify_handoff(self.handoff, self.sha, self.policy_path), self.manifest)
            self.assertNotIn("--signer-digest", run.call_args.args)
            certificate["buildSignerURI"] = signer.replace("bathysign-finalize.yml", "attacker.yml")
            run.return_value = p.json_bytes([self.result])
            with self.assertRaisesRegex(ValueError, "builder differs"):
                p.verify_handoff(self.handoff, self.sha, self.policy_path)


if __name__ == "__main__":
    unittest.main()
