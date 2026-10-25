# Public Sigstore trust with a read-only signer

Configuration version 4 enables public Sigstore TUF trust. It does not authenticate
private keys, configuration, webhook secrets, or private GitHub trust profiles.
Those remain part of the reviewed read-only image/configuration deployment.

The image embeds `src/trust/sigstore-root.json`, copied from the pinned
sigstore-rust dependency. The authority, public mirror and `trusted_root.json`
target are fixed in code. A configuration pins this bootstrap digest and a
reviewed 32-byte initialization epoch (64 lowercase hex characters):

```json
"version": 4,
"trust_roots": {},
"trust_authority": {
  "authority": "sigstore-public",
  "bootstrap_sha256": "<sha256 of src/trust/sigstore-root.json>",
  "epoch": "<reviewed initialization epoch>",
  "target": "trusted_root.json"
}
```

Version 3 configuration retains the existing static trust checks and exact policy
hash format. Version 4 cannot fall back to static files. Its public policy is
version 4 and its receipt is version 3. Both policy and receipt bind the authority;
the receipt additionally binds the exact checkpoint, target hash, generation and
earliest signed metadata expiry. `trust-evidence.json` is a receipt-covered output.
Publication must authenticate that evidence without contacting the private auditor.
The separately maintained shared action must be upgraded before activating v4.

The guest writes no trust files. Metadata and downloaded targets use a bounded
RAM store. Accepted signed transitions are retained in order, including partial
refreshes, so a later error cannot erase rollback floors. The collector persists
immutable checkpoints in SQLite with FULL synchronization and an atomic head
compare-and-swap. A checkpoint must extend its predecessor's history and epoch.
A lost POST response is resolved by reading the exact immutable digest. A state
becomes usable only after persistence is acknowledged.

On startup the signer requires an existing auditor head, replays signatures,
versions and delegation authorization from the embedded root, then refreshes.
Missing/corrupt state fails closed; HTTPS cannot create an initial head. A network
outage permits the previous checkpoint only if no accepted transitions changed
and the entire authorization remains unexpired. Signature, version, integrity and
persistence failures pause admission. Each job pins one state and rechecks signed
expiry before provenance verification and signing operations.

Refresh runs hourly or at half the remaining metadata lifetime, whichever is
earlier. Requests have a 30-second timeout and the whole refresh a five-minute
limit. Existing bounded GET retry handling applies; failed update cycles back off
from 30 seconds to 15 minutes. Health and metrics remain available during trust
initialization; readiness and job admission require usable trust.

## Explicit initialization

Deploy compatible collectors and offline publication helpers first. Prepare a
checkpoint on a native operator machine, never by adding guest writable storage:

```sh
cargo run --features admin --bin bathysign-admin -- prepare-trust \
  --epoch "$REVIEWED_EPOCH" --out checkpoint.json
AUDIT_CONFIG=collector.json bathysign-collector initialize-trust checkpoint.json
```

The collector command uses its configured local database and requires a complete,
currently valid checkpoint. It refuses to replace an existing head. Review the exported v4
policy, epoch, embedded root digest and helper revision through the existing
policy approval workflow before activating the signer. Test in a disposable
read-only guest before production. Do not overwrite an existing database to seed
trust or treat a service restart as a new expiry deadline.

For offline review, save the policy's `trust_authority` object as authority.json:

```sh
bathysign-admin verify-trust-evidence --input trust-evidence.json --authority authority.json
```

This verifies authorization at the recorded acceptance time for historical release
verification. Runtime additionally requires expiry later than the trusted host
clock. An expired embedded root can authenticate sequential root rotations to a
fresh root, but cannot authorize targets itself.

## Storage recovery and limits

The auditor is durable version history, not an additional trust authority.
Signatures originate at the embedded root. Restoring an older entire auditor
backup cannot be independently detected by a signer without another durable
anchor. Signed absolute expiry bounds usable replay, assuming the host clock is
correct. Review backup age, policy epoch, latest known generation and published
receipt bindings before restoring. Epoch changes require a separately reviewed
initialization procedure; restarting does not reset trust age.

History is bounded to a 16 MiB budget for decoded metadata and entry overhead, and 16,384 observations, with a
24 MiB API envelope and 1 MiB target. Exhaustion fails closed. Plan a reviewed
image/bootstrap and epoch migration before reaching the bound; history is never
automatically truncated. Monitor readiness, expiry, refresh age and persistence
failures using the rules in `deploy/monitoring/prometheusrule.yaml`.

The QEMU smoke test accepts `--trust-checkpoint checkpoint.json`. It boots with
no trust head, checks that health stays available while readiness fails, seeds
the temporary collector explicitly, verifies trust readiness and metrics, then
checks fail-closed behavior during collector outage. The guest has no disks and
its virtiofs export is read-only; the test also checks exported files are unchanged.
