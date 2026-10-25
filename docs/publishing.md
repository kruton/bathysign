# Generic release publishing

Each policy-defined profile supplies an APK, AAB, ProGuard mapping, native-symbol archive and build metadata through the handoff described in [SLSA](slsa.md). Profile names match `[a-z][a-z0-9-]{0,31}`. Profiles may have different packages and version codes; their source, release tag and title must agree.

Store a publishing configuration next to the exported signing policy in the caller owner's `.github` repository. `config/publishing.example.json` shows its complete version-1 shape:

```json
{"version":1,"asset_prefix":"Example","primary_profile":"default","play":null}
```

The prefix is a safe filename component, at most 64 characters. Downloads use `PREFIX-TAG-PROFILE.apk` and `.aab`. The evidence ZIP preserves mappings, native symbols, receipts, provenance, lineage and the signed handoff. `version_code.txt` and stable-release `version-info.txt` use `primary_profile`, which must exist in the signing policy.

Source tags `vX.Y.Z` become stable releases; branch builds use attested `git-*` names and become prereleases. Applications supply version metadata during their build. Finalizers and publishers run no application code or Gradle. Missing/extra files, altered digests, unapproved profiles and inconsistent source identities are rejected.

## Optional Google Play

Set `play` to an object with `profile`, `project`, and `rules` to enable Play routing. The selected profile's package comes from the signing policy. A rule contains a full-match source-ref regular expression and track `alpha` or `beta`; exactly one rule must match. `play: null` disables publication regardless of repository variables.

```json
{"profile":"store","project":"example-project","rules":[
  {"ref":"refs/heads/main","track":"alpha"},
  {"ref":"refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+","track":"beta"}
]}
```

A rule may also contain `version_code: {"base":100000,"multiplier":1000,"group":"patch","min":0,"max":49}`. Its ref pattern must contain a named decimal `patch` capture; the bundle's code must equal `base + patch * multiplier` within the specified bounds. This expresses application version allocations as trusted data.

Set repository variables `PLAY_ALPHA_ENABLED` and/or `PLAY_BETA_ENABLED` to `true` only for configured testing tracks. Configure `GOOGLE_WORKLOAD_IDENTITY_PROVIDER`, `GOOGLE_PLAY_SERVICE_ACCOUNT`, and protected `play-alpha`/`play-beta` environments. The Google project is taken from verified configuration. Scope federation to the source repository/owner IDs, approved caller and reusable workflow identities, event, branch, hosted runner and environment. Give the service account access only to the configured Play application and testing tracks.

Publication verifies the handoff before requesting Google credentials. The helper scopes API requests to the selected package, checks bundle hashes/version codes, reconciles lost upload/commit responses, refuses downgrades and reports pending reviews. GitHub publishing and Play jobs recover independently. Re-running failed publisher jobs reuses the attested artifact; rebuilding is unnecessary.
