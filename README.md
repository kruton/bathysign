# Bathysign

Bathysign signs Android APKs and App Bundles produced by GitHub Actions. It runs as a separate signing appliance, verifies the provenance of each unsigned file, and uploads signed outputs and receipts to a draft GitHub release for you to review and publish. Your Android signing keys stay on infrastructure you control instead of being placed on CI runners.

[ConnectBot](https://connectbot.org) uses Bathysign to sign the [ConnectBot app](https://github.com/connectbot/connectbot).

The appliance is a Rust HTTPS service built with the Hermit unikernel. A separate collector maintains its durable queue and audit ledger. Bathysign also provides GitHub Actions workflows for integrating builds and releases.

**Before using production keys:** Bathysign is a new signing-format implementation and has not been independently audited. Test with a disposable repository, application, and keys, including Play Console acceptance, device upgrades, and a live GitHub workflow. The local tests alone do not establish those behaviors.

## Getting started

1. **Build the appliance and collector.** Follow [Build and test](#build-and-test) to produce the bootable image, loader, and collector binary. Review the pinned inputs and deployment artifacts.
2. **Create and install a GitHub App in your organization.** Give it repository Actions and artifact attestations read access, Contents read/write access, and metadata access. Subscribe to `workflow_run` and configure its webhook to point to `https://YOUR-SIGNER:8443/webhooks/github`. Install it only on the repositories you intend to sign for. Provision the App private key and a shared webhook secret to the signer. See [Configure the service](#configure-the-service) for the complete policy and secret requirements.
3. **Configure your Android build.** Adapt [the example workflow](config/android-build.example.yml) to build matching unsigned APK and AAB files, attest each file, and upload them as artifacts. Authorize the repository, workflow, refs, and artifacts in the signer policy. Protect the approved workflows and branches from untrusted edits. See [SLSA integration](docs/slsa.md) for workflow identities and release integration.
4. **Deploy the collector and signer.** Run the collector on durable infrastructure and boot the signer on a dedicated, isolated host or VM with access to its protected key directory. Configure networking so GitHub can reach the webhook and the signer can reach GitHub and the collector. See [Where to run Bathysign](#where-to-run-bathysign) and [External durable collector](#external-durable-collector).
5. **Exercise the complete release path with test keys.** Check the collector ledger and signed receipt, independently verify the outputs, and test installation and upgrades before publishing the draft release. Bathysign does not publish releases itself.

## Where to run Bathysign

Run the signing appliance on infrastructure separate from your GitHub Actions runners, with access limited to trusted operators. The tested deployment is a dedicated single-vCPU QEMU VM with 2 GiB fixed memory, host CPU with RDSEED, VirtIO networking, and a read-only host export containing configuration and secrets. The guest boots directly from the loader and image; it does not need a Linux disk or SSH server. QEMU and Proxmox instructions are below; a [Proxmox provisioning guide](deploy/proxmox/README.md) covers the host setup.

Run the collector as a separate host process with durable storage and TLS. The signer must be able to reach it whenever it signs. Protect and back up its database: restoring an older snapshot can undo replay and rotation protections. The host and its administrators can access the exported keys, so host isolation, access controls, and backups remain part of your security boundary.

## Security model and principles

- **Keep keys away from CI.** The appliance loads keys from a protected host export; keys are not compiled into its image. CI supplies unsigned artifacts and provenance, not signing credentials.
- **Authorize the build, then verify its artifacts.** Repository IDs, workflow identities, refs, runs, and other claims are checked against policy. Each original APK and AAB needs its own verified attestation. The caller and reusable builder are authorized separately.
- **Minimize the signing environment.** Signing uses Rust implementations of Android formats in a Hermit image, without Linux, a JVM, a shell, `bundletool`, `apksigner`, or `jarsigner` in the guest. Independent Android tools are used for host-side checks.
- **Record decisions durably and fail closed.** The collector records signing intent and verified results before upload, enforces policy and replay protections, and stops new signing when unavailable. Its hash-linked records need independently retained anchors to detect tampering relative to those anchors.
- **Leave publication to an operator.** Outputs go to a draft release with a receipt and transparency material. Review and independently verify them before publication. Android code transparency covers DEX and native code, not every app component, and Android does not enforce it at installation.

These controls do not protect keys from a compromised signing host or its privileged operators. See [Implementation boundaries](#implementation-boundaries) for validation limits and the pinned kernel adaptations.

## Configure the service

Copy [signer.example.json](config/signer.example.json) into a protected host directory as `config.json`. Replace the deployment placeholders: repository numeric ID and full name, package, GitHub App ID, workflow, exact refs, artifact names/files, key fingerprints, lineage hashes, and trust material. The example pins the trusted workflow repository `kruton/bathysign` to its numeric ID, `1436515323`. Example expiry `0` deliberately fails startup. Set `receipt_namespace: "bathysign"` in every repository policy.

The default artifact limit is 64 MiB and applies to downloads, original files, and aggregate ZIP expansion, including the nested APK/AAB. The configured limit is capped at 128 MiB. Large AABs can expand to roughly 100 MiB. Use 2 GiB fixed guest memory and one signing worker. Inputs are released after verification, each expanded input map is released before its output is reopened for verification, and uploads consume their buffers. ZIP generation is bounded while writing, allowing up to 16 MiB above the input limit for signing metadata and alignment. Measure peak usage before changing this resource profile; compressed file size alone does not describe memory use.

Provision the following into that directory:

- Signing keys as unencrypted PKCS#8 PEM/DER, and corresponding X.509 certificates as PEM/DER. Classical APK, AAB upload, and transparency keys are RSA, at least 2048 bits. An existing RSA-1024 APK identity requires the explicit profile setting `allow_legacy_rsa_1024`; it cannot be used for upload, receipt, transparency, or a different rotated APK identity. Keep the transparency key separate from every current/historical APK and upload key.
- GitHub App RSA private key, a webhook secret of at least 32 bytes, and a separate audit bearer token of at least 32 printable bytes. Share only the audit token with the collector.
- TLS server certificate/key, the collector CA certificate, public Sigstore and/or GitHub private trusted-root JSON, and the authorized APK lineage files.

A certificate fingerprint is SHA-256 of its **DER certificate**, not PEM text or the SPKI. File pins are SHA-256 of the exact bytes. Generate certificate fingerprints with:

```sh
openssl x509 -in apk-a.pem -outform DER -out apk-a.der
sha256sum apk-a.der apk-lineage.bin sigstore-public.json
```

Public Sigstore trust can instead use configuration v4 with an image-embedded TUF bootstrap, RAM-only signer state, and durable auditor checkpoints; see [dynamic trust](docs/dynamic-trust.md) for initialization and the required shared-action upgrade.

For configuration v3, fetch fresh trusted roots through Sigstore's authenticated trust distribution outside the guest. Pin their bytes and choose an operator-reviewed `valid_until` for this deployment. Replace them before expiry, increment the affected repository policy revisions, and reboot the appliance. The fixtures under `tests/fixtures` are historical interoperability data, not production trust provisioning. Private attestations require a verified RFC3161 timestamp against the private trusted root; they do not bypass certificate, DSSE, timestamp, identity, or CI claim checks.

For the webhook secret, use a printable value and write exactly those bytes to the file, without a trailing newline; enter the same value in GitHub's webhook settings.

Install the GitHub App on only the selected repositories. Grant repository **Actions: read**, **Artifact attestations: read**, **Contents: read/write**, and metadata access. Subscribe it to `workflow_run`; configure its webhook at `https://signer.example.net:8443/webhooks/github` with the provisioned secret. Protect the approved workflow and branches against untrusted edits. The signer checks workflow identity, ref, repository immutable ID, commit, run/attempt, event, runner class, and repository visibility. Caller and reusable-builder identities are authorized separately, including independently pinned workflow/helper contents. Authenticated completions from other workflows in configured repositories return HTTP 200 with `{"ignored":true}`; they do not enqueue jobs or count as dispatch failures. See [SLSA integration](docs/slsa.md).

Use [android-build.example.yml](config/android-build.example.yml) as a producer template. It attests **each APK/AAB file**, then uploads unsigned artifacts. An attestation for only the GitHub ZIP or source commit is insufficient. The APK and AAB must have matching package/version, minSdk at least 24, and matching DEX/native code. Do not pre-sign or pre-add transparency. Do not post-process code after the attested build. The template's project setup/output paths need adapting; it is not installed into any repository automatically.

Code transparency follows Android's JWT format and covers DEX/native libraries, not resources/assets/manifests. Android itself does not enforce transparency at installation. `sharedUserId` is rejected. Archive generation must either be explicitly disabled in BundleConfig, or have `archive_resource` provisioned with the exact bundletool version, resource path, source file, and hash that bundletool expects. APKs with code transformed from the AAB are rejected rather than given an unrelated transparency statement. Publish the transparency certificate fingerprint through a trusted channel independently of downloaded artifacts. See [Android's code transparency guide](https://developer.android.com/guide/app-bundle/code-transparency).

## External durable collector

Run the `bathysign-collector` host binary with `BATHYSIGN_COLLECTOR_CONFIG` pointing to a completed [collector.example.json](config/collector.example.json). Create its database directory with owner-only permissions. Terminate TLS in the collector itself; issue a server certificate matching the signer's configured audit hostname. The signer verifies that certificate and authenticates every ledger operation with its bearer token.

The collector uses SQLite WAL and `synchronous=FULL`. Back up the database through SQLite's backup mechanism, including its committed state; do not copy an active DB without considering WAL. Keep ledger state across guest reboots, policy updates, and key rotations. Restoring an older ledger snapshot can undo its replay/rotation protections.

Routes: authenticated `GET /v1/health`, `POST /v1/policies`, `POST /v1/jobs`, `POST /v1/claim`, `POST /v1/jobs/{id}/events`, `POST /v1/jobs/{id}/finish`, and `GET /v1/jobs/{id}`. The last route returns job state and the ordered hash-linked audit events. Collector JSON requests are limited to 4 MiB to accommodate long certificate histories; the public webhook remains limited to 256 KiB. Deploy one logical signer configuration containing all repositories served by a collector; claims are global, not partitioned by appliance identity.

A version 2 job is deduplicated by repository/run/attempt/profile/full policy hash. Leases expire after five minutes and are renewed every 30 seconds. Recovery records interrupted signing as uncertain; it may deterministically re-sign the same bytes. The collector bounds retries to six attempts, checks active policy on mutations, and prevents policy revision/lineage regression. It acknowledges a signing intent before the corresponding key operation and acknowledges verified results before upload. During collector outages, new signing cannot proceed. Hash links help detect edits relative to a trusted retained anchor; they do not make a compromised collector independently tamper-proof. Retain/replicate audit anchors according to your audit requirements.

A draft release has a job-specific tag/marker and the attested commit as its target. Repeated uploads accept only assets with matching name, size, and GitHub SHA-256; conflicting assets fail. Outputs include `app-signed.apk`, `app-signed.aab`, the transparency JWT/certificate, APK lineage files, and authenticated `signing-receipt.dsse.json` plus its readable `signing-receipt.json`. Inspect the ledger/receipt and independently verify outputs before publishing a release. The service never publishes one.

## QEMU and Proxmox

The tested QEMU profile is `pc`/i440fx, one vCPU, modern VirtIO PCI networking and read-only VirtIO FS, and direct loader/image boot:

```sh
python3 scripts/run-qemu.py --secrets /protected/bathysign --memory 2G
```

The helper uses KVM and `-cpu host`; `--tcg` is for local testing. **RDSEED must be exposed.** The checked kernel removes insecure entropy fallback; the application also rejects CPUs without RDSEED and tests OS entropy before loading keys. A VirtIO RNG device alone does not fix entropy for this pinned kernel. The guest's clock must be valid for TLS/provenance/trust expiry. Use a correct host RTC and keep the host synchronized.

Keep the secret directory private to the host/service identity and export it with `virtiofsd --readonly` and namespace isolation. The mount tag `root` becomes `/root` in Hermit. The helper forwards only localhost TCP8443; production networking/ingress must expose the HTTPS webhook endpoint deliberately. `/healthz` checks the process; `/readyz` also checks trust expiry and the ledger connection. Allow outbound HTTPS to GitHub API/upload hosts, GitHub artifact storage, and the collector, plus required DNS.

For Proxmox, use a **new dedicated VM** with one core, `cpu: host`, 2 GiB fixed memory, ballooning disabled, SeaBIOS, an i440fx machine, VirtIO networking, and serial diagnostics. Host-side `args` must direct-boot the loader with `-kernel` and the signer with `-initrd`, and attach the read-only filesystem socket with shared memory. An example fragment is in [proxmox.example.conf](config/proxmox.example.conf); prepare the host filesystem service before starting the VM and inspect `qm showcmd` for the actual QEMU arguments. This fragment has not been deployed or validated on your Proxmox cluster. No guest Linux disk, cloud-init, SSH server, or guest agent is needed. Keys live in a host-managed export, so VM backups are not a key-backup plan. Disable migration/snapshots of this signing VM unless your key-handling and external-ledger recovery processes explicitly support them.

`-machine microvm` is not supported by the tested image: the loader reaches Hermit, then APIC initialization panics. It would need an MMIO kernel/device profile and separate validation; do not substitute it in the launch helper yet. See [QEMU microvm documentation](https://www.qemu.org/docs/master/system/i386/microvm.html) and [Proxmox VM options](https://github.com/proxmox/pve-docs/blob/master/generated/qm.1-synopsis.adoc).

## Key rotation and long histories

The host-only `bathysign-admin` CLI uses clap and does not require a serial port. The guest starts automatically using `/root/config.json`; `BATHYSIGN_CONFIG` can select another startup path where boot environment support is configured. Serial is for kernel/application diagnostics.

Initialize A, append A→B, then B→C offline:

```sh
target/debug/bathysign-admin init --key apk-a.pk8 --cert apk-a.pem --out lineage-a.bin
target/debug/bathysign-admin append --input lineage-a.bin \
  --old-key apk-a.pk8 --old-cert apk-a.pem \
  --new-key apk-b.pk8 --new-cert apk-b.pem --out lineage-ab.bin
target/debug/bathysign-admin append --input lineage-ab.bin \
  --old-key apk-b.pk8 --old-cert apk-b.pem \
  --new-key apk-c.pk8 --new-cert apk-c.pem --out lineage-abc.bin
target/debug/bathysign-admin inspect --input lineage-abc.bin
```

Preserve the full chain. There is no three-key/count cap; the default byte guard is 1 MiB, configurable up to 16 MiB. Tests exercise 64 certificates. The CLI refuses to overwrite output files. `import --input ... --expected-root <DER-certificate-sha256> --out ...` validates an apksigner lineage against an independently authorized root. Default capabilities include installed data, shared UID, permission, and authentication; rollback is disabled and requires explicit authorization in both the CLI and service policy.

Set `original_key` to A, `current_key` to the latest classical head, and update the pinned lineage/hash. Increment that repository's policy `revision` on every signing-policy change. The policy digest includes the resolved key certificate fingerprints, trust-root pin/expiry, and artifact/lineage limits as well as repository rules. Replacing key material under the same role name therefore requires a new revision too. Keep A available for the API24 v2 signer; older classical private keys other than that required original and the current head can be removed from the online appliance once the next proofs are prepared. Historical certificates/proofs remain in the lineage. Upload-key and transparency-key rotation are separate operational processes, not APK proof-of-rotation.

Default `rotation_min_sdk: 33` preserves the original v3 signer for API28–32 and uses the rotated signer in v3.1 for API33+. Set 28 only for an existing deployment whose classical rotation intentionally starts at API28. There is no APK v1 signing.

For Android 17/API37 hybrid signing, provision fresh RSA-4096 and ML-DSA-65 PKCS#8 keys/certificates, then:

```sh
target/debug/bathysign-admin hybrid --input lineage-abc.bin \
  --old-key apk-c.pk8 --old-cert apk-c.pem \
  --rsa-key hybrid-rsa-b.pk8 --rsa-cert hybrid-rsa-b.pem \
  --pqc-key hybrid-pqc-b.pk8 --pqc-cert hybrid-pqc-b.pem \
  --out-directory hybrid-b
```

This produces two sibling terminal proofs and an independently signed RSA→PQC effective chain. Add those key roles to `keys` and fill [hybrid.example.json](config/hybrid.example.json) into `signing.hybrid`. Classical signing remains available for older Android versions; v3.2 contains both hybrid signers. For a later hybrid generation, use the previous `effective-lineage.bin` as input and its terminal PQC key as `--old-key`, with fresh RSA/PQC keys. Keep complete ancestry and increment policy revision. The previous effective chain can also authorize additional classical fallback transitions; all configured histories must remain compatible.

## Build and test

Use Rust 1.99.0, Python 3.12+, and the pinned inputs in [toolchain-pins.json](config/toolchain-pins.json). From this directory:

```sh
python3 scripts/build-hermit.py
cargo build --locked --features admin,collector --bin bathysign-admin --bin bathysign-collector
cargo test --locked --all-features
python3 -m unittest discover -s tests
# Use the locked Python runtime and hash-pinned dependencies for workflow tests:
bash bathysign/scripts/install-trust.sh /tmp/bathysign-trust-venv
/tmp/bathysign-trust-venv/bin/python -m unittest discover -s bathysign/tests
cargo clippy --all-features --all-targets -- -D warnings
```

The build helper verifies downloaded hashes, installs Hermit std into an isolated sysroot, and prepares a checked local kernel copy. It never patches the shared Cargo checkout. The image is `target/x86_64-unknown-hermit/release/bathysign`; its loader is `dist/hermit-loader`. Both are public deployment artifacts. The helper installs the kernel's pinned nightly toolchain through rustup. Ordinary host tests require OpenSSL with ML-DSA-65 support and `jarsigner` on PATH.

Independent Android checks require JDK 25 and Android SDK platform/build-tools 36:

```sh
python3 scripts/test-android.py \
  --java-home /path/to/jdk-25 \
  --android-sdk /path/to/android-sdk
python3 tests/qemu-smoke.py --loader dist/hermit-loader --tcg
```

The reference helper compiles pinned Android 17 apksig source, uses the pinned older verifier for pre-37 platforms, creates matching real AAPT2 manifests, and verifies signatures, lineages, transparency, and bundle structure. Without the helper's environment, the optional external Android checks return early; ordinary `cargo test` is not evidence that those reference checks ran. The QEMU smoke test creates disposable keys, uses a temporary read-only filesystem export, and tests TLS, collector activation/readiness, and webhook authentication. It never contacts GitHub. Its unsandboxed virtiofsd option is limited to these disposable local fixtures.

The apksig source URL uses an immutable commit. Its pin covers every source path and file digest; Gitiles tar timestamps vary between downloads. The JAR and loader pins cover the exact downloaded bytes.

## Implementation boundaries

This is a new signing-format implementation. Android reference verification and local guest smoke tests do not establish Play Console acceptance, on-device upgrade/downgrade behavior, or live GitHub end-to-end behavior. Validate those with a disposable repository/application and test keys before provisioning production keys. The external tools and kernel fixes are pinned for review, but RustCrypto's TLS provider is an alpha release and the application is not independently audited.

The checked kernel patches halt on entropy failures, bound kernel TCP connects to 15 seconds, prevent nonblocking socket destruction from waiting on a peer, and convert executor Unix-epoch deadlines into the relative futex durations the kernel expects. A companion scheduler patch ignores a second wake notification for a task that its timer already woke, preventing a futex timeout race from panicking. Nonblocking drop aborts the socket; interrupted clients may need to retry. Queue IDs and matching asset checks support safe retry. The vendored hyper-util patch uses a blocking task for Hermit's synchronous connect and registers the successfully connected stream without the unsupported SO_ERROR query. The vendored socket2 fork also returns unrecognized OS errors rather than panicking. These adaptations are specific to the pinned Hermit kernel and should be re-evaluated on upgrades.

The patch set also backports the [TCP_NODELAY correction](https://github.com/hermit-os/kernel/pull/2732) and [Virtqueue memory barriers](https://github.com/hermit-os/kernel/pull/2669). The blocked-task queue preserves the earliest existing, newly added, or network deadline when arming its one-shot timer, addressing the second timer defect in [issue 2639](https://github.com/hermit-os/kernel/issues/2639). This does not establish the cause of intermittent artifact-download stalls or address the separate multicore wakeup report.

Run the scheduler regression against the prepared kernel with `python3 tests/kernel-timers.py --kernel <prepared-kernel-directory>`. It executes the actual queue-insertion methods with a recorded hardware timer, with and without networking. The unchanged code reproduces a 5-second waiter postponing an existing 200 ms deadline; the corrected code preserves the earlier deadline.

## SLSA release integration

See [the workflow and policy guide](docs/slsa.md) for caller-owner policy discovery, trusted reusable workflows, profiles, receipts and provenance. [Publishing](docs/publishing.md) documents generic release naming and optional Google Play publication.

The [monitoring guide](deploy/monitoring/README.md) describes metrics and alert templates. Application-specific configuration and deployment records belong in a separate operator repository; they are not needed to build or test Bathysign.

## License

Bathysign is licensed under [Apache-2.0](LICENSE). Vendored third-party code retains its own licenses and copyright notices in `vendor/`.
