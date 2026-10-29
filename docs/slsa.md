# Bathysign workflows and trust

Bathysign separates application builds, hosted provenance/finalization jobs, and a self-hosted signing appliance. Android private keys stay in the appliance. The external collector retains policy history, durable jobs, audit chains and authenticated TUF checkpoints.

## Trusted reusable workflows

Application CI uploads `unsigned-PROFILE-ATTEMPT` containing `app.apk` and `app.aab`, and `release-support-PROFILE-ATTEMPT` containing `mapping.txt`, `native-debug-symbols.zip`, and `build-info.json`. Call `kruton/bathysign/.github/workflows/bathysign-attest.yml@v0.2.1` for each profile after its build succeeds. The attestor takes only the profile and binds provenance to its own GitHub run/attempt.

The appliance authorizes immutable repository IDs, approved caller workflows, a separate trusted builder repository/workflow/exact release tag and commit, source refs, event types, and runner class. It verifies original-file attestations before signing. Forks and mismatched run attempts fail verification.

The default-branch `bathysign-release.yml` caller dispatches `bathysign-finalize.yml`, then passes its immutable artifact ID and manifest hash to `bathysign-publish.yml`. The templates are in `config/`. Finalization verifies every policy-defined profile and attests all verified Android outputs and publishing files. Helpers use `$/bathysign` so they execute from the reusable workflow's exact revision.

Trusted workflows must come from a published immutable GitHub release. Each builder/finalizer identity has exactly one `refs` entry (for example `refs/tags/v0.2.1`) and a required `commit` containing the reviewed 40-character lowercase Git commit SHA. Both identities must use the same repository ID, tag and commit, with different workflow paths. Branches, wildcard workflow tags and unpinned identities are rejected. Application source `refs` are a separate allowlist and may still include branches and tag patterns.

The appliance and hosted verifiers check the public repository ID, the release's `immutable: true` and `draft: false` fields, the tag's resolved commit, and the attested workflow identity/digest.

Lightweight tags use the source `commit` as their workflow digest. For an annotated tag, also set `workflow_digest` on both identities to the outer tag object SHA returned by GitHub's git-ref API. GitHub puts that object SHA in `job_workflow_sha` and the certificate's build-signer digest. The verifiers require the reference object to match `workflow_digest`, peel the complete tag chain to the pinned source `commit`, and independently bind the certificate to the workflow digest.

Both pins must agree between builder and finalizer; omitting `workflow_digest` defaults to `commit` for existing lightweight-tag policies. Google federation's `assertion.job_workflow_sha` constraint must use the workflow digest, rather than the resolved source commit. An explicitly approved immutable prerelease is allowed. These public checks require no administrative permission; API failures fail closed. Enabling repository immutability alone does not make an older release acceptable.

Before deploying, obtain the real `kruton/bathysign` repository ID and the selected release's commit, configure both workflow identities, and export the matching public policy. The example's repeated `c` commit and repository IDs are placeholders, not deployment authorization.

### Migrate from branch policies

1. Publish a new immutable release containing the tag-aware verifier. Do not move or reuse an existing tag. `v0.1.0` predates this migration and is not an immutable release.
2. Review the release and resolve its tag to a commit (`git rev-parse 'v0.2.1^{commit}'` after fetching it). Use that exact tag in the application's action, attestor, finalizer and publisher references.
3. Replace the builder/finalizer branch refs with the same exact release ref and add the same source `commit` pin to both identities. For annotated tags, obtain the outer object SHA with `gh api repos/kruton/bathysign/git/ref/tags/v0.2.1 --jq .object.sha` and add it as `workflow_digest` to both. Increment the repository policy `revision`.
4. Deploy the new signer and updated configuration, then export its matching public policy with the measured deployed signer SHA. Update the caller-owner policy repository through its reviewed change process. The trusted workflow commit and deployed signer revision are separate pins, even when they happen to be equal.
5. Exercise the full workflow with disposable keys. Confirm the receipt and final publishing handoff identify the approved workflow release and commit before using production keys.

Configuration versions 3/4 and receipt formats remain unchanged. The optional `workflow_digest` field preserves existing lightweight-tag policies; annotated tags require its explicit value. The required workflow `commit` field is a deliberate compatibility break: old branch policies must be migrated; there is no branch fallback. Coordinate deployment, policy export and consumer changes during a signing maintenance window. Each later workflow upgrade repeats the tag/pin/policy-revision update; no floating major ref is maintained.

## Caller-owner policy authority

The workflow derives `OWNER/.github` from GitHub's caller repository identity. It verifies caller repository and owner IDs against GitHub metadata and verifies the policy repository belongs to that same owner. This supports organization and personal-account owners. No workflow input or environment override changes the policy authority.

The policy repository's default branch must be protected. Bathysign resolves it to one commit and reads both:

- `.github/bathysign/REPOSITORY_ID.json`: exported signing policy.
- `.github/bathysign/REPOSITORY_ID.publishing.json`: publishing settings.

Missing, inaccessible, invalid, or unprotected policy sources stop the job. The source application cannot replace the policy with a file from its checkout. The workflow token must be able to read the policy repository; use a public policy repository with the supported public-workflow integration.

Export policy using `bathysign-admin export-release-policy --config /secure/config.json --repository example/app --signer-revision FULL_SHA --out 42.json`. The signer revision is the measured image source revision. Exported policies contain public certificates and authorization constraints; never publish the appliance config or private keys.

Policy fetching produces a local `bathysign-policy.json` snapshot containing both configurations and an adjacent `.source.json` recording repository/owner IDs, branch, immutable commit, source paths and digests. The final predicate binds both original configuration files; the signed publishing manifest binds the combined snapshot and origin. Publishers reject configuration drift instead of silently changing an already-attested release. An unrelated commit in the central repository is allowed when both configuration files are identical; provenance continues to bind the original immutable commit.

## Receipt and evidence formats

Repository policies set `receipt_namespace` to `bathysign`. It participates in the signing policy hash. Receipt predicate URIs are `urn:bathysign:receipt:v2` for static trust and `urn:bathysign:receipt:v3` for dynamic trust. Verifiers check receipt subjects, DSSE signatures, key pins, original bytes and full transaction identity. Receipts must use the Bathysign namespace.

The publisher emits release-manifest version 2. Use service configuration version 3 for static trust roots or version 4 for authenticated dynamic trust. The collector serves ledger API `/v1/` with version-2 jobs and per-profile policy histories.

## Local development

The Rust crate, signer binary and Python interoperability tools use this checkout. There is no sibling action checkout dependency. Passing an external checkout to local verification tools requires an explicit digest pin. Historical public Sigstore fixtures are regression evidence, not provisioning material.

The workflow lint wrapper uses pinned actionlint 1.7.12 with two narrow parser exclusions for the platform's same-revision `$/bathysign` references and `job.workflow_ref`/`job.workflow_sha` fields. Workflow contract tests validate those expressions separately. All other actionlint checks remain enabled.

The v0.2.0 annotated release predates workflow-digest support. Its genuine GitHub attestation uses the tag object SHA while its verifier expects the source commit, so the disposable signing trial correctly rejected it before signing. Keep that immutable release unchanged and use v0.2.1 or later with both pins. Final provenance records the source revision as `finalizerCommit` and the platform claim separately as `finalizerWorkflowDigest`; receipt provenance uses `builder_commit` and `builder_workflow_digest` for the same distinction.
