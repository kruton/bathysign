# Bathysign workflows and trust

Bathysign separates application builds, hosted provenance/finalization jobs, and a self-hosted signing appliance. Android private keys stay in the appliance. The external collector retains policy history, durable jobs, audit chains and authenticated TUF checkpoints.

## Trusted reusable workflows

Application CI uploads `unsigned-PROFILE-ATTEMPT` containing `app.apk` and `app.aab`, and `release-support-PROFILE-ATTEMPT` containing `mapping.txt`, `native-debug-symbols.zip`, and `build-info.json`. Call `kruton/bathysign/.github/workflows/bathysign-attest.yml@vVERSION` for each profile after its build succeeds. Replace `vVERSION` in the templates with a release containing identity authorization. The attestor takes only the profile and binds provenance to its own GitHub run/attempt.

The appliance authorizes repository IDs, caller workflow paths, a separate trusted builder repository/workflow, allowed source and builder refs, event types, and runner class. It verifies original-file attestations before signing. Forks and mismatched run attempts fail verification.

The default-branch `bathysign-release.yml` caller dispatches `bathysign-finalize.yml`, then passes its immutable artifact ID and manifest hash to `bathysign-publish.yml`. The templates are in `config/`. Finalization verifies every policy-defined profile and attests all verified Android outputs and publishing files. Helpers use `$/bathysign` so they execute from the reusable workflow's actual revision.

A workflow identity contains `repository`, `repository_id`, `workflow`, and `refs`. For example:

```json
{
  "repository": "kruton/bathysign",
  "repository_id": 1436515323,
  "workflow": ".github/workflows/bathysign-attest.yml",
  "refs": ["refs/tags/v0.*"]
}
```

Use a different workflow path for the finalizer. Each role may select its own allowed refs; both must be separate from the application repository. Refs accept exact branches or tags, or a single trailing wildcard in a tag family. `refs/heads/main` authorizes changes reviewed into that branch; `refs/tags/v0.*` delegates release selection to the repository's release maintainers. Protect those branches, workflow files and tag creation accordingly. Identity authorization does not establish that every revision is safe. Narrow the allowed refs or change the trusted identity when revoking a release channel.

The appliance and hosted verifiers check the public repository ID, attested workflow path and allowed ref. They authenticate the certificate's actual workflow digest and record it as evidence. For annotated tags that digest is the outer tag object; the verifiers resolve the authenticated object by SHA to record its source commit. They never resolve evidence using today's mutable tag head. API errors fail closed. Branch execution digests are source commits. Final provenance records `finalizerCommit` and `finalizerWorkflowDigest`; receipt provenance records `builder_commit` and `builder_workflow_digest`.

Existing policies may retain `commit` and optional `workflow_digest` as stricter legacy pins. A pinned identity still requires one exact semantic-version release tag, a published immutable release, the pinned reference object, and a tag chain ending at the pinned commit. Omitting `workflow_digest` defaults to `commit` for lightweight tags. A digest pin without a commit pin is rejected. Builder and finalizer pins need not match each other.

## Migrate to identity authorization

1. Publish a release containing the identity-aware appliance, administration tool and hosted verifiers. Existing pinned policies remain readable, so prepare and verify these artifacts before changing authorization.
2. In the appliance configuration, remove `commit` and `workflow_digest` from both workflow identities. Choose stable allowed refs such as `refs/tags/v0.*` or an explicitly protected branch. Keep repository IDs, workflow paths, source restrictions, package names, keys and lineage pins. Increment the repository policy `revision` once; this authorization change produces a new policy hash.
3. Export the public signing policy without `--signer-revision`. Prepare the matching owner `.github` policy PR and deploy the matching appliance configuration during a signing maintenance window. Pause new signing while the two configurations differ; pending jobs tied to the previous policy hash must finish before migration or be recreated afterward. Merge the policy PR and verify that both policy hashes agree. Keep signing paused through the remaining steps.
4. Update application workflow references to the identity-aware release. The old hosted verifier cannot read an unpinned policy, so this first migration requires coordinated workflow changes. Keep production paused while preparing a disposable end-to-end validation.
5. If Google federation currently compares `job_workflow_sha` to an exact release digest, replace that version constraint with the approved publisher workflow identity and allowed ref/channel. Preserve caller repository/owner identity, source-ref restrictions, audience and service-account scope. Cloud authorization is managed separately from the signing policy; inspect the deployed provider mapping and condition before changing it.
6. Verify that the appliance and owner policy hashes agree, all workflow references resolve to identity-aware verifiers, and cloud authorization accepts the chosen publisher identity. Test a disposable repository through signing, finalization and publishing, then resume production.

Configuration versions 3/4, collector API and receipt formats remain unchanged. These protocol versions are separate from Bathysign product versions. Future incompatible protocol changes still need an explicit migration.

## Ordinary upgrades

After migration, authenticate the desired release and pin binaries/container digests in the deployment configuration. Update reusable-workflow references to the chosen release within the already authorized family, and deploy compatible appliance, collector and helper versions in either order. A compatible upgrade needs no owner-policy edit, policy hash change or collector policy revision. No floating tag is required. Change owner policies only when changing authorization, keys, destinations or protocol requirements.

The deployment operator authenticates which software runs. Receipts report the appliance's implementation revision; hosted verifiers validate its format and preserve the actual value per signing profile in final provenance. They do not compare it to a policy-approved product revision. The receipt signature proves possession of an authorized receipt key, not measurement of the running appliance. A compromised appliance can report a false revision. Independent checks of original provenance, source run/attempt, payload preservation, Android signatures, signing keys and lineage remain required.

Commit-status reporting uses a separate installation token. Grant `statuses: write` for rejection notices; lack of that optional permission does not prevent obtaining the core signing token. New GitHub App registrations request the permission up front; existing installations must approve it if notices are desired.

## Caller-owner policy authority

The workflow derives `OWNER/.github` from GitHub's caller repository identity. It verifies caller repository and owner IDs against GitHub metadata and verifies the policy repository belongs to that same owner. This supports organization and personal-account owners. No workflow input or environment override changes the policy authority.

The policy repository's default branch must be protected. Bathysign resolves it to one commit and reads both:

- `.github/bathysign/REPOSITORY_ID.json`: exported signing policy.
- `.github/bathysign/REPOSITORY_ID.publishing.json`: publishing settings.

Missing, inaccessible, invalid, or unprotected policy sources stop the job. The source application cannot replace the policy with a file from its checkout. The workflow token must be able to read the policy repository; use a public policy repository with the supported public-workflow integration.

Export policy using `bathysign-admin export-release-policy --config /secure/config.json --repository example/app --out 42.json`. The deprecated `--signer-revision` argument remains optional metadata for older tooling; it does not authorize the running implementation. Exported policies contain public certificates and authorization constraints; never publish the appliance config or private keys.

Policy fetching produces a local `bathysign-policy.json` snapshot containing both configurations and an adjacent `.source.json` recording repository/owner IDs, branch, immutable commit, source paths and digests. The final predicate binds both original configuration files; the signed publishing manifest binds the combined snapshot and origin. Publishers reject configuration drift instead of silently changing an already-attested release. An unrelated commit in the central repository is allowed when both configuration files are identical; provenance continues to bind the original immutable commit.

## Receipt and evidence formats

Repository policies set `receipt_namespace` to `bathysign`. It participates in the signing policy hash. Receipt predicate URIs are `urn:bathysign:receipt:v2` for static trust and `urn:bathysign:receipt:v3` for dynamic trust. Verifiers check receipt subjects, DSSE signatures, key pins, original bytes and full transaction identity. Receipts must use the Bathysign namespace.

The publisher emits release-manifest version 2. Use service configuration version 3 for static trust roots or version 4 for authenticated dynamic trust. The collector serves ledger API `/v1/` with version-2 jobs and per-profile policy histories.

## Local development

The Rust crate, signer binary and Python interoperability tools use this checkout. There is no sibling action checkout dependency. Passing an external checkout to local verification tools requires an explicit digest pin. Historical public Sigstore fixtures are regression evidence, not provisioning material.

The workflow lint wrapper uses pinned actionlint 1.7.12 with two narrow parser exclusions for the platform's same-revision `$/bathysign` references and `job.workflow_ref`/`job.workflow_sha` fields. Workflow contract tests validate those expressions separately. All other actionlint checks remain enabled.

The v0.2.0 annotated release predates workflow-digest support. Its genuine GitHub attestation remains a regression fixture for keeping the tag object and source commit distinct. Keep historical immutable releases unchanged.
