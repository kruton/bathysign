# Verify Bathysign releases

Version tags matching Cargo metadata and belonging to main trigger prereleases. Restrict creation of `v*` tags, block their updates/deletion, enable GitHub release immutability, and require review of release workflows before using this distribution channel. The publisher checks that the published release is immutable and its tag resolves to the expected source commit. Stable promotion must reuse verified bytes. No `latest` container tag is maintained.

Downloads include the x86_64 Hermit appliance/loader and AMD64/ARM64 Linux host tools. Host binaries target Debian 13 or compatible glibc environments. The collector container is published at `ghcr.io/kruton/bathysign-collector:vVERSION`; deploy by digest. Mount configuration, TLS credentials and persistent SQLite storage as described in `deploy/collector/README.md`.

## Choose a download

For a typical installation, download the appliance and one host-tools archive:

| Filename suffix | Contents |
| --- | --- |
| `x86_64-unknown-hermit.tar.gz` | Signing appliance and Hermit boot loader for an x86_64 VM. |
| `x86_64-unknown-linux-gnu.tar.gz` | AMD64 Linux administration tool and collector. |
| `aarch64-unknown-linux-gnu.tar.gz` | ARM64 Linux administration tool and collector. |

The release also provides `SHA256SUMS` and an optional `bathysign-VERSION-verification.tar.gz` with per-target provenance, SBOM attestations, SPDX documents, input metadata and reproducibility reports, plus container verification evidence. Extract this bundle to use the paths below. Its bundled attestations authenticate the original subjects; authenticate archives against the expected source and builder identities rather than trusting checksums or the bundle's filename. Container images are distributed through GHCR. Builder images, dependency caches and raw OCI archives remain Actions artifacts and are unnecessary for installation.

## Authenticate a download

Obtain the expected source commit and version through a trusted channel. Use a recent GitHub CLI supporting source and signer digest checks:

```sh
gh attestation verify bathysign-VERSION-x86_64-unknown-linux-gnu.tar.gz \
  --repo kruton/bathysign \
  --signer-workflow kruton/bathysign/.github/workflows/release-build.yml \
  --signer-digest SOURCE_COMMIT --source-digest SOURCE_COMMIT \
  --source-ref refs/tags/vVERSION --deny-self-hosted-runners
```

For offline verification add `--bundle x86_64-unknown-linux-gnu/provenance.json` from the extracted verification bundle and `--custom-trusted-root` pointing to trust roots obtained independently. Checksums alone do not authenticate a download. `scripts/verify-release.py` checks the complete three-target artifact set and its attested comparison reports; it expects the per-target directory layout produced by Actions downloads. To use it with release downloads, extract the verification bundle and place each binary archive inside its matching target directory; pass a directory containing only those three target directories.

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

The builder links `/root/.cargo` and `/root/.rustup` to `/usr/local/cargo` and `/usr/local/rustup`, respectively. Hermit's nested kernel build clears the home override variables, so these aliases keep its toolchain and dependency lookups on the same persistent caches in both phases and in exported offline bundles.

Repeat on a clean machine. Compare the resulting directories with:

```sh
python3 scripts/release.py compare first second --report comparison.json
```

To reproduce container content, run `scripts/release-container.sh ARCH ARCHIVE` against the verified host archive. Its comparison report inventories all OCI objects. The published multi-platform index combines the verified architecture manifests.

## Assurance and current limits

The intended architecture follows GitHub's reusable-workflow guidance for SLSA Build L3. Provenance establishes the build identity; matching rebuilds provide separate evidence about reproducibility. Neither is an independent security audit. Both CI rebuilds use GitHub infrastructure; container builds use separate builders on the same architecture runner.

The source-built loader is pinned to upstream v0.5.7's immutable commit. Compiler binaries, the prebuilt Hermit standard library, builder OS packages and runtime base image remain upstream trust inputs. Rebuilding these inputs from source is outside the release claim.

Offline builder and fetched-input archives are kept in the release run's `offline-TARGET-ATTEMPT` and `verified-TARGET-ATTEMPT` Actions artifacts, subject to repository artifact retention. They are not GitHub Release downloads. Save these artifacts separately if you need long-term offline rebuilding; after expiry, rebuild using the authenticated source and pinned upstream inputs as described above. The offline archives are split into parts and attested. Obtain the target's `provenance.json` from the verification bundle or verified artifact, and verify every part with the same source/builder constraints before concatenation. Reconstruct the per-target offline directory and run `scripts/rebuild-offline.sh BUNDLE_DIRECTORY EMPTY_WORK_DIRECTORY TARGET`. The multi-platform index is assembled twice from verified OCI blobs and checked against the published registry digest. SPDX documents are included in the verification bundle and separately attested against the binary archives and container index. Public GHCR package visibility must be configured in GitHub. First publication must be checked through public downloads and registry access.

## Build checks before tagging

The **Release build checks** workflow runs on pull requests targeting main and pushes to main. It builds the same AMD64 Linux tools, ARM64 Linux tools and x86_64 Hermit appliance as the tag pipeline. Each target is built twice on separate GitHub-hosted jobs using the shared `build.yml` workflow and `scripts/release-build.sh`: prepare online, discard compiled outputs, then compile offline in the pinned Docker environment and compare the packaged archives byte for byte. The matrices do not cancel other targets when one fails, so a Hermit failure does not hide host build failures.

Both branch and tag workflows call the same integration workflow to run Android reference checks and boot the packaged appliance/loader against the packaged administration tool and collector in QEMU. They also call the same container build workflow to build and compare AMD64/ARM64 collector containers. Branch checks consume their own run's `compared-*` artifacts with read-only repository permissions. Tag jobs add authenticated `verified-*` artifacts, binary SBOMs, attestations, offline rebuild exports, GHCR publication and GitHub release publication. These publication credentials and write permissions are not granted to branch build checks.

Require **Release build checks passed** in main branch rules alongside the existing coverage and SonarCloud checks. This aggregate check fails when a target, integration job or container check fails, is cancelled, or is skipped. The full hosted matrix must pass before treating a commit as ready to tag; the fast contract-test and host coverage jobs alone do not establish release buildability.

The builder's Rust version must exactly match `config/toolchain-pins.json` and the prebuilt Hermit standard library, including the patch version. `config/release-build.json` records the matching builder image, and a contract test requires the Dockerfile to use that same image. The release build script checks the running compiler before fetching/building dependencies. Update these pins together when upgrading Rust; a host-only compiler upgrade can otherwise pass ordinary tests and fail the Hermit release build.

## Sonar release gate

The `Coverage inputs` workflow (`coverage.yml`) produces Rust LCOV (including Android reference checks and `build.rs`) and Python branch coverage for main pushes and PR head commits. It has no Sonar credentials. The default-branch `sonar.yml` consumer calls the pinned `connectbot/actions` isolated SonarCloud workflow, which validates the producer run and reports, independently fetches source, and waits for the configured quality gate. Rust's automatic Clippy execution is disabled in the credential-bearing scanner; Clippy runs separately in the producer.

Set the SonarCloud organization and project key in `.github/sonar.json` (initially `kruton` / `kruton_bathysign`, matching this repository's GitHub owner), and add the Actions secret `SONAR_TOKEN`. Tokens must never be committed. Bind the project to the SonarQube Cloud GitHub App, disable automatic analysis in favor of CI analysis, and assign a custom gate with coverage >=90% on overall and new code. Require the App's **SonarCloud Code Analysis** check and the **coverage** producer job in main branch rules; the consumer workflow's check does not replace the App's PR-head check. Trusted configuration changes take effect after merging to the default branch. This shared workflow currently supports SonarCloud's `sonarcloud.io` region, not self-hosted SonarQube.

Before building or publishing release artifacts, the release coordinator independently requires **overall Sonar coverage >=90%** and a passing quality gate from the published `main` analysis of the exact release SHA. Missing configuration, executable lines, unsuccessful analysis, low coverage, stale revisions, or concurrent replacement of the measured analysis fail closed. Tag only after that commit's main analysis succeeds. If analysis is still pending when a tag is pushed, let it finish and rerun the release workflow. A newer main analysis does not authorize a release of an older commit.

The Rust and Python reports are retained as Actions artifacts even when coverage is below the threshold. Sources include all first-party Rust and Python tooling; tests and vendor dependencies are not included in the source denominator. Host Rust instrumentation does not exercise Hermit-only kernel code. QEMU boot checks remain a separate required gate and do not substitute for instrumented coverage. A passing test count alone does not establish coverage.

Local coverage baseline (2026-10-28 UTC): SonarQube Community Build 26.10.0.133078, using the shared action's pinned SonarScanner 8.1.0.6389 and the same source/test scope, reports **90.0% overall coverage** and passes an overall coverage >=90% gate. The raw counters are 7,068/7,836 covered lines and 442/506 covered conditions (7,510/8,342 combined, or 90.026%). This includes the Java reference helper's 43 uncovered lines; no coverage exclusions were added. Rust LCOV reports 90.39% line coverage, and coverage.py reports 90.72% combined Python line/branch coverage. The local worktree evidence, including server analysis identity, per-file metrics, and source/report hashes, is retained in `coverage/sonarqube-assessment.json` (ignored generated output). This measurement does not establish a SonarCloud analysis or PR check; hosted activation still requires the project, token, and branch rules above.

The Rust-capable shared action is pinned to the `connectbot/actions` main-branch commit that merged [PR #62](https://github.com/connectbot/actions/pull/62). Earlier shared action revisions reject Rust LCOV input. Use the merge commit when updating a consumer after a squash merge, so its pin remains reachable after the review branch is deleted. After landing Bathysign's configuration on main, verify a fork PR receives the App check for its head SHA and a below-threshold PR is blocked.

## Branching and version tags

Develop on `main` through short-lived reviewed PR branches. Release the appliance, collector, host tools, action and reusable workflows together under one `vX.Y.Z` tag matching `Cargo.toml` and `Cargo.lock`. Do not maintain a workflow compatibility branch or floating major tag. Introduce maintenance branches only when supporting multiple released product lines; the current release gate authorizes main ancestry only.

During `0.x`, patches preserve compatibility and minor versions may introduce documented breaking changes. Version `0.2.0` introduces exact workflow release tags and commit pins. Configuration and protocol format numbers remain independent of the product version. Merge version bumps and migration notes before tagging, and wait for the exact commit's required checks and published main Sonar analysis to pass.

The GitHub CLI creates a draft, uploads the complete verified asset set, then publishes the prerelease. Immutability takes effect on publication. Promote the same release by changing its prerelease status after deployment validation; never replace its tag or rebuild its bytes for promotion. A separately tagged release candidate is a distinct release. Existing published releases are reused only if their immutable state, resolved commit and complete asset inventory match. Incomplete drafts cause an error: inspect and finish the verified draft, or remove it and retry publication after confirming it was never published. The publisher never overwrites conflicting assets.

Public consumers can inspect `immutable` on the release-by-tag API without administrative credentials:

```sh
gh api repos/kruton/bathysign/releases/tags/v0.2.0 \
  --jq '{tag_name, immutable, draft, prerelease}'
```

Repository-wide immutability settings require administrative read access and are not used as evidence by the signer. Enabling the setting does not retrofit an existing mutable release. Leave `v0.1.0` untouched and publish a fresh version for this architecture. Follow the [workflow policy migration](slsa.md#migrate-from-branch-policies) when updating consumers.

## Annotated workflow release identities

Version 0.2.1 adds an optional `workflow_digest` pin for annotated workflow tags.
Keep the source commit and tag object as separate pins in builder/finalizer
policies. GitHub certificates and job workflow metadata identify an annotated
tag object, while code and provenance dependencies identify its resolved source
commit. Both are verified; neither substitutes for the other. Lightweight tags
retain the existing commit-only policy. See [workflow migration](slsa.md).

The immutable v0.2.0 release exposed this mismatch during a genuine disposable
signing trial. Do not move or replace its tag. Publish the corrected release,
regenerate policies and increment their revisions, then run fresh source builds
with the new workflow tag before the production cutover.

## Timestamp-only trust refreshes

Version 0.2.2 fixes offline verification of trust checkpoints that end with a
timestamp refresh authorizing the existing snapshot. The verifier authenticates
the cached snapshot against the new timestamp before retaining its targets.
The disposable ConnectBot trial provides the regression fixture.
