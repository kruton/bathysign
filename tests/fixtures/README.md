# Public interoperability data

Copied from [sigstore/sigstore-rust at f950b1b683560aadf7737539f8d7eaa656a9f0c0](https://github.com/sigstore/sigstore-rust/tree/f950b1b683560aadf7737539f8d7eaa656a9f0c0): its `sigstore-verify` test bundles and `sigstore-trust-root` embedded roots.

`github-public.sigstore.json` is the upstream conda attestation signed by a GitHub Actions workflow under public Sigstore trust. `github-private.sigstore.json` is an upstream GitHub private-trust timestamped attestation whose certificate identifies `dotcom.releases.github.com`; it is not a GitHub Actions workflow identity.

These bundles exercise the RustCrypto provider, certificate chains, DSSE binding, public transparency-log evidence, private timestamp verification, and rejection of wrong digests/identities. They do not demonstrate acceptance by this application's stricter SLSA/workflow/run policy. No private signing keys are included. The historical roots are test fixtures, not production trust provisioning.

`rotation-policy.json` is a synthetic application policy used to test offline rotation preconditions.

`github-annotated.sigstore.json` is genuine GitHub provenance from the disposable
`connectbot/test-signer-1` run [40820440798](https://github.com/connectbot/test-signer-1/actions/runs/40820440798),
attested by Bathysign v0.2.0. Its certificate's build-signer digest is annotated
tag object `afba3630da667063a728b5a7f59ba5a174bb9e94`, resolving to source
commit `2103fdfc57058d232be05e2a16697a8e90e6b85f`. The accompanying
`github-annotated-trusted-root.json` was authenticated through the isolated
test collector's Sigstore TUF checkpoint on 2026-10-29. These public files
reproduce the annotated-tag interoperability failure without network access or
private keys; they are historical test fixtures, not production trust roots.
