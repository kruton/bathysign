# Bathysign workflows and trust

Bathysign separates application builds, hosted provenance/finalization jobs, and a self-hosted signing appliance. Android private keys stay in the appliance. The external collector retains policy history, durable jobs, audit chains and authenticated TUF checkpoints.

## Trusted reusable workflows

Application CI uploads `unsigned-PROFILE-ATTEMPT` containing `app.apk` and `app.aab`, and `release-support-PROFILE-ATTEMPT` containing `mapping.txt`, `native-debug-symbols.zip`, and `build-info.json`. Call `kruton/bathysign/.github/workflows/bathysign-attest.yml@bathysign-v1` for each profile after its build succeeds. The attestor takes only the profile and binds provenance to its own GitHub run/attempt.

The appliance authorizes immutable repository IDs, approved caller workflows, a separate trusted builder repository/workflow/protected branch, source refs, event types, and runner class. It verifies original-file attestations before signing. Forks and mismatched run attempts fail verification.

The default-branch `bathysign-release.yml` caller dispatches `bathysign-finalize.yml`, then passes its immutable artifact ID and manifest hash to `bathysign-publish.yml`. The templates are in `config/`. Finalization verifies every policy-defined profile and attests all verified Android outputs and publishing files. Helpers use `$/bathysign` so they execute from the reusable workflow's exact revision.

Protect the `bathysign-v1` branch with reviewed changes and passing tests. Before deploying, obtain the real `kruton/bathysign` repository ID, configure it in the appliance's builder/finalizer identities, and export the matching public policy. Repository IDs in examples are placeholders.

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
