# Bathysign GitHub action

The composite action and reusable workflows verify and publish results from the Bathysign appliance. See [workflow trust](../docs/slsa.md) and [publishing configuration](../docs/publishing.md).

Use `kruton/bathysign/bathysign@bathysign-v1` for the composite action. Trusted reusable workflows are `.github/workflows/bathysign-attest.yml`, `bathysign-finalize.yml`, and `bathysign-publish.yml`. They use same-revision `$/bathysign` references. Application code executes only in the application's build jobs.

Imported Apache-2.0 sources and their originating revision are recorded in `UPSTREAM.json`.
