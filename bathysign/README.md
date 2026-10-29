# Bathysign GitHub action

The composite action and reusable workflows verify and publish results from the Bathysign appliance. See [workflow trust](../docs/slsa.md) and [publishing configuration](../docs/publishing.md).

Use `kruton/bathysign/bathysign@v0.2.0` for the composite action. Trusted reusable workflows are `.github/workflows/bathysign-attest.yml`, `bathysign-finalize.yml`, and `bathysign-publish.yml`. They use same-revision `$/bathysign` references. Application code executes only in the application's build jobs.

Imported Apache-2.0 sources and their originating revision are recorded in `UPSTREAM.json`.

Use exact tags from published immutable releases, with matching tag and commit pins in the signing policy. There is no floating major branch or tag. See the [policy migration guide](../docs/slsa.md#migrate-from-branch-policies) before upgrading an existing deployment.
