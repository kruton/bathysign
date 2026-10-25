# Verify Bathysign releases

Version tags matching Cargo metadata and belonging to main trigger prereleases. Protect `v*` tags and require review of release workflows before using this distribution channel. Stable promotion must reuse verified bytes. No `latest` container tag is maintained.

Downloads include the x86_64 Hermit appliance/loader and AMD64/ARM64 Linux host tools. Host binaries target Debian 13 or compatible glibc environments. The collector container is published at `ghcr.io/kruton/bathysign-collector:vVERSION`; deploy by digest. Mount configuration, TLS credentials and persistent SQLite storage as described in `deploy/collector/README.md`.

## Authenticate a download

Obtain the expected source commit and version through a trusted channel. Use a recent GitHub CLI supporting source and signer digest checks:

```sh
gh attestation verify bathysign-VERSION-x86_64-unknown-linux-gnu.tar.gz \
  --repo kruton/bathysign \
  --signer-workflow kruton/bathysign/.github/workflows/release-build.yml \
  --signer-digest SOURCE_COMMIT --source-digest SOURCE_COMMIT \
  --source-ref refs/tags/vVERSION --deny-self-hosted-runners
```

For offline verification add `--bundle x86_64-unknown-linux-gnu-provenance.json` and `--custom-trusted-root` pointing to trust roots obtained independently. Checksums alone do not authenticate a download. `scripts/verify-release.py` checks the complete three-target artifact set and its attested comparison reports; it expects the per-target directory layout produced by Actions downloads.

## Authenticate a container

```sh
gh attestation verify oci://ghcr.io/kruton/bathysign-collector@sha256:DIGEST \
  --repo kruton/bathysign \
  --signer-workflow kruton/bathysign/.github/workflows/release-container.yml \
  --signer-digest SOURCE_COMMIT --source-digest SOURCE_COMMIT \
  --source-ref refs/tags/vVERSION --deny-self-hosted-runners
```

Each architecture is built twice with isolated BuildKit instances. Comparisons include compressed layers, configurations and manifests. Run-specific attestations are attached separately from runnable image content.

## Rebuild and compare

Check out the authenticated source commit. Build `deploy/build/Dockerfile`, then invoke `scripts/release-build.sh TARGET prepare` in that container with `/src` containing the checkout and persistent Cargo/rustup volumes. This fetches inputs, warms nested build dependencies, and removes compiled outputs. Invoke the same script with `TARGET` on the same mounts with `--network none`, `CARGO_NET_OFFLINE=true` and `BATHYSIGN_OFFLINE_BUILD=1`. CI records these exact commands in `release-build.yml`.

Repeat on a clean machine. Compare the resulting directories with:

```sh
python3 scripts/release.py compare first second --report comparison.json
```

To reproduce container content, run `scripts/release-container.sh ARCH ARCHIVE` against the verified host archive. Its comparison report inventories all OCI objects. The published multi-platform index combines the verified architecture manifests.

## Assurance and current limits

The intended architecture follows GitHub's reusable-workflow guidance for SLSA Build L3. Provenance establishes the build identity; matching rebuilds provide separate evidence about reproducibility. Neither is an independent security audit. Both CI rebuilds use GitHub infrastructure; container builds use separate builders on the same architecture runner.

The source-built loader is pinned to upstream v0.5.7's immutable commit. Compiler binaries, the prebuilt Hermit standard library, builder OS packages and runtime base image remain upstream trust inputs. Rebuilding these inputs from source is outside the release claim.

This pipeline requires a successful real tagged run before being considered operational. Offline builder and fetched-input archives are split into parts below GitHub’s asset size limit and attested with the other downloads. Verify each part before concatenation. Reconstruct the per-target offline directory and run `scripts/rebuild-offline.sh BUNDLE_DIRECTORY EMPTY_WORK_DIRECTORY TARGET`. The multi-platform index is assembled twice from verified OCI blobs and checked against the published registry digest. SPDX documents are included as provenance-authenticated release assets and separately attested against the binary archives and container index. Public GHCR package visibility must be configured in GitHub. First publication must be checked through public downloads and registry access.

## Sonar release gate

The `Coverage inputs` workflow (`coverage.yml`) produces Rust LCOV (including Android reference checks and `build.rs`) and Python branch coverage for main pushes and PR head commits. It has no Sonar credentials. The default-branch `sonar.yml` consumer calls the pinned `connectbot/actions` isolated SonarCloud workflow, which validates the producer run and reports, independently fetches source, and waits for the configured quality gate. Rust's automatic Clippy execution is disabled in the credential-bearing scanner; Clippy runs separately in the producer.

Set the SonarCloud organization and project key in `.github/sonar.json` (initially `kruton` / `kruton_bathysign`, matching this repository's GitHub owner), and add the Actions secret `SONAR_TOKEN`. Tokens must never be committed. Bind the project to the SonarQube Cloud GitHub App, disable automatic analysis in favor of CI analysis, and assign a custom gate with coverage >=90% on overall and new code. Require the App's **SonarCloud Code Analysis** check and the **coverage** producer job in main branch rules; the consumer workflow's check does not replace the App's PR-head check. Trusted configuration changes take effect after merging to the default branch. This shared workflow currently supports SonarCloud's `sonarcloud.io` region, not self-hosted SonarQube.

Before building or publishing release artifacts, the release coordinator independently requires **overall Sonar coverage >=90%** and a passing quality gate from the published `main` analysis of the exact release SHA. Missing configuration, executable lines, unsuccessful analysis, low coverage, stale revisions, or concurrent replacement of the measured analysis fail closed. Tag only after that commit's main analysis succeeds. If analysis is still pending when a tag is pushed, let it finish and rerun the release workflow. A newer main analysis does not authorize a release of an older commit.

The Rust and Python reports are retained as Actions artifacts even when coverage is below the threshold. Sources include all first-party Rust and Python tooling; tests and vendor dependencies are not included in the source denominator. Host Rust instrumentation does not exercise Hermit-only kernel code. QEMU boot checks remain a separate required gate and do not substitute for instrumented coverage. A passing test count alone does not establish coverage.

Local coverage baseline (2026-10-28 UTC): SonarQube Community Build 26.10.0.133078, using the shared action's pinned SonarScanner 8.1.0.6389 and the same source/test scope, reports **90.0% overall coverage** and passes an overall coverage >=90% gate. The raw counters are 7,068/7,836 covered lines and 442/506 covered conditions (7,510/8,342 combined, or 90.026%). This includes the Java reference helper's 43 uncovered lines; no coverage exclusions were added. Rust LCOV reports 90.39% line coverage, and coverage.py reports 90.72% combined Python line/branch coverage. The local worktree evidence, including server analysis identity, per-file metrics, and source/report hashes, is retained in `coverage/sonarqube-assessment.json` (ignored generated output). This measurement does not establish a SonarCloud analysis or PR check; hosted activation still requires the project, token, and branch rules above.

The Rust-capable shared action is pinned to the `connectbot/actions` main-branch commit that merged [PR #62](https://github.com/connectbot/actions/pull/62). Earlier shared action revisions reject Rust LCOV input. Use the merge commit when updating a consumer after a squash merge, so its pin remains reachable after the review branch is deleted. After landing Bathysign's configuration on main, verify a fork PR receives the App check for its head SHA and a below-threshold PR is blocked.
