# Prometheus monitoring

Both operational signer and collector export Prometheus text at `GET /metrics`
on their existing HTTPS listener. Provisioning mode has no metrics endpoint.
Signer metrics contain no credentials or job identifiers; restrict access to the
internal network. Collector scrapes require its existing `Authorization: Bearer`
token. Use Prometheus `authorization.credentials` from a Kubernetes Secret through
a ServiceMonitor; never put tokens in Git. Keep TLS CA and server-name verification
on. No new listener or configuration fields are needed.

For each collector, configure a private HTTPS scrape of `/metrics` using its bearer-token Secret and TLS CA/server name. Scrape the signer's private HTTPS metrics endpoint with its CA and server name. Match selectors and target names to your own installation. Expose only the webhook publicly. Add the supplied PrometheusRule template and independent `up == 0` alerts for the actual scrape jobs.

Metrics:

- `bathysign_operations_total{operation,outcome}`: process-local successes
  and failures. Operations include webhook authentication/dispatch, ledger
  activation/enqueue/claim/event/finish, verify_inputs/sign_outputs/publish_outputs,
  job (whole pipeline), job_complete/job_transient/job_rejected, job_retry,
  network_request/network_body/network_timeout/network_retry. Series appear on
  first observation; counters reset on restart. Alert rules handle newly appearing
  series as well as increases, so the first failure can alert. `network_retry` counts
  actual additional GET attempts; `job_retry` counts claimed attempts after the first.
  The generic task alert excludes raw `network_request` failures because expected
  HTTP misses, such as probing for the next TUF root, are normal. Higher-level
  operation failures and separate timeout/retry alerts remain monitored.
- `bathysign_operation_duration_seconds{operation,outcome}`: histogram with
  1/5/30/60/300/600/1800 second buckets. `job` includes network waits and publishing,
  excluding queue time and durable finalization; failed attempts are included.
  `_duration_seconds_total` also exports cumulative duration.
- `bathysign_operation_last_success_timestamp_seconds{operation}`: Unix
  timestamp of latest successful operation. Claim success includes idle polls;
  event success includes lease renewals. Do not alert on missing job successes
  without also checking unfinished work: the signer may legitimately be idle.
- `bathysign_job_active`, `bathysign_job_elapsed_seconds`: active worker
  state and current attempt runtime; zero while idle.
- `bathysign_trust_root_expiry_timestamp_seconds`: earliest configured expiry
  for legacy static trust.
- Dynamic trust exports `bathysign_trust_ready`,
  `bathysign_trust_valid_until_timestamp_seconds`,
  `bathysign_trust_last_online_refresh_timestamp_seconds`,
  `bathysign_trust_checkpoint_generation`, `bathysign_trust_metadata_version`
  and `bathysign_trust_cache_fallbacks_total`, labeled by authority (and role
  for metadata versions). Alerts cover readiness, refresh age, expiry and durable
  commit failures. See [dynamic trust](../../docs/dynamic-trust.md).
- Collector `bathysign_ledger_jobs{status}`: durable pending/running/complete/
  rejected gauges. `ledger_expired_leases` and `ledger_oldest_unfinished_seconds`
  detect stalled work. `ledger_events_total{kind}` persists task milestones,
  failures and interruptions across process restarts. Restoring an older database
  can reset those counters. Scrapes return 503 on database failure, not zeroes.
  Snapshots query the ledger; monitor scrape duration as history grows.

Network behavior: GitHub requests retain the 300 second total request deadline;
ledger requests retain 30 seconds. Safe GET requests retry up to twice on
connection failures, timeouts, or HTTP 408/429/500/502/503/504, with 1/2 second
backoff (numeric Retry-After honored within 1–30 seconds). HTTP writes are not
replayed blindly: the existing durable job protocol retries transient job
failures, up to six attempts, with 30 seconds times attempt backoff. Body-read
failures/timeouts count separately and recover through that job retry mechanism.
The lease renews every 30 seconds while requests wait. There is no new overall
job cancellation deadline: interrupted signing outcomes require the existing
lease/audit recovery protocol. Alert on active runtime and queue age instead.

Useful PromQL:

```promql
# 95th percentile attempt runtime
histogram_quantile(0.95, sum by (le) (rate(bathysign_operation_duration_seconds_bucket{operation="job"}[1h])))
# Network retries and timeouts
sum by (operation) (increase(bathysign_operations_total{operation=~"network_retry|network_timeout|job_retry"}[1h]))
```
