//! Durable, authenticated external ledger. Compiled only for the host collector.
use crate::ledger::{Activation, Claimed, Job};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct Store {
    db: Arc<Mutex<Connection>>,
    token_hash: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub listen: String,
    pub tls_certificate: std::path::PathBuf,
    pub tls_private_key: std::path::PathBuf,
    pub token_file: std::path::PathBuf,
    pub database: std::path::PathBuf,
}
fn rejected(_: anyhow::Error) -> (StatusCode, &'static str) {
    (StatusCode::CONFLICT, "ledger operation rejected")
}
impl Store {
    pub fn open(path: &std::path::Path, token: &[u8]) -> Result<Self> {
        use sha2::{Digest, Sha256};
        ensure!(token.len() >= 32, "audit token too short");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?;
        }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS policies(repo INTEGER PRIMARY KEY, revision INTEGER NOT NULL, hash TEXT NOT NULL, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, repo INTEGER NOT NULL, policy TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', lease TEXT, lease_until INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, retry_after INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events(job TEXT NOT NULL REFERENCES jobs(id), seq INTEGER NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(job,seq));
        CREATE INDEX IF NOT EXISTS events_kind ON events(kind);
        CREATE TABLE IF NOT EXISTS trust_checkpoints(digest TEXT PRIMARY KEY, authority TEXT NOT NULL, body BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS trust_heads(authority TEXT PRIMARY KEY, digest TEXT NOT NULL REFERENCES trust_checkpoints(digest));")?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            token_hash: Sha256::digest(token).into(),
        })
    }
    pub fn trust_checkpoint(
        &self,
        authority: &str,
        digest: Option<&str>,
    ) -> Result<crate::trust::Checkpoint> {
        let db = self.db.lock().unwrap();
        let (digest, body): (String, Vec<u8>) = match digest {
            Some(d) => db.query_row("SELECT digest,body FROM trust_checkpoints WHERE digest=?1 AND authority=?2", params![d,authority], |r| Ok((r.get(0)?,r.get(1)?)))?,
            None => db.query_row("SELECT digest,body FROM trust_checkpoints JOIN trust_heads USING(digest) WHERE trust_heads.authority=?1", [authority], |r| Ok((r.get(0)?,r.get(1)?)))?,
        };
        ensure!(
            crate::sha256(&body) == digest,
            "stored checkpoint digest differs"
        );
        Ok(serde_json::from_slice(&body)?)
    }
    /// Host-only explicit initialization; the HTTPS API cannot create a head.
    pub fn trust_initialize(&self, checkpoint: &crate::trust::Checkpoint) -> Result<String> {
        ensure!(
            checkpoint.generation == 1 && checkpoint.previous.is_none(),
            "initial checkpoint required"
        );
        checkpoint.verify()?.active()?;
        self.trust_write(checkpoint, true)
    }
    pub fn trust_commit(&self, checkpoint: &crate::trust::Checkpoint) -> Result<String> {
        checkpoint.verify()?;
        self.trust_write(checkpoint, false)
    }
    fn trust_write(
        &self,
        checkpoint: &crate::trust::Checkpoint,
        initialize: bool,
    ) -> Result<String> {
        let digest = checkpoint.digest()?;
        let body = serde_json::to_vec(checkpoint)?;
        ensure!(
            body.len() <= crate::trust::MAX_WIRE,
            "trust checkpoint too large"
        );
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let head: Option<String> = tx
            .query_row(
                "SELECT digest FROM trust_heads WHERE authority=?1",
                [&checkpoint.authority.authority],
                |r| r.get(0),
            )
            .optional()?;
        if head.as_ref() == Some(&digest) {
            return Ok(digest);
        }
        if initialize {
            ensure!(head.is_none(), "trust already initialized");
        } else {
            let head =
                head.ok_or_else(|| anyhow::anyhow!("trust requires explicit initialization"))?;
            let previous: Vec<u8> = tx.query_row(
                "SELECT body FROM trust_checkpoints WHERE digest=?1",
                [&head],
                |r| r.get(0),
            )?;
            ensure!(
                crate::sha256(&previous) == head,
                "stored predecessor digest differs"
            );
            checkpoint.follows(&serde_json::from_slice(&previous)?)?;
        }
        tx.execute(
            "INSERT INTO trust_checkpoints(digest,authority,body) VALUES(?1,?2,?3)",
            params![digest, checkpoint.authority.authority, body],
        )?;
        tx.execute("INSERT INTO trust_heads(authority,digest) VALUES(?1,?2) ON CONFLICT(authority) DO UPDATE SET digest=excluded.digest", params![checkpoint.authority.authority,digest])?;
        tx.commit()?;
        Ok(digest)
    }
    fn auth(&self, headers: &HeaderMap) -> Result<()> {
        use sha2::{Digest, Sha256};
        let value = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        ensure!(bool::from(actual.ct_eq(&self.token_hash)), "unauthorized");
        Ok(())
    }
    pub fn activate(&self, a: &Activation) -> Result<()> {
        ensure!(
            a.repository_id > 0 && a.revision > 0 && valid_hash(&a.policy_hash),
            "invalid activation"
        );
        ensure!(
            a.version == 2
                && !a.profiles.is_empty()
                && a.profiles
                    .iter()
                    .all(|(name, h)| crate::config::valid_profile(name)
                        && !h.classical_history.is_empty()
                        && h.classical_history
                            .iter()
                            .chain(&h.hybrid_history)
                            .all(|p| valid_hash(p))),
            "invalid version/profile history"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT body FROM policies WHERE repo=?1",
                [a.repository_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            let prior: Activation = serde_json::from_str(&prior)?;
            ensure!(prior.version == 2, "unsupported policy version");
            let (revision, hash, histories) = (prior.revision, prior.policy_hash, prior.profiles);
            ensure!(a.revision >= revision, "stale policy revision");
            if a.revision == revision {
                ensure!(a.policy_hash == hash, "policy revision reused");
                return Ok(());
            }
            for (name, old) in histories {
                let new = a
                    .profiles
                    .get(&name)
                    .ok_or_else(|| anyhow::anyhow!("profile history cannot be removed"))?;
                ensure!(
                    new.classical_history.starts_with(&old.classical_history)
                        && new.hybrid_history.starts_with(&old.hybrid_history),
                    "lineage regression or fork"
                );
            }
            let stale = {
                let mut q = tx.prepare("SELECT id FROM jobs WHERE repo=?1 AND policy != ?2 AND status IN ('pending','running')")?;
                q.query_map(params![a.repository_id, a.policy_hash], |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            };
            for id in stale {
                append(
                    &tx,
                    &id,
                    "job.finished",
                    json!({"status":"rejected","reason":"policy-superseded"}),
                )?;
                tx.execute(
                    "UPDATE jobs SET status='rejected',lease=NULL,lease_until=0 WHERE id=?1",
                    [id],
                )?;
            }
        }
        tx.execute("INSERT INTO policies(repo,revision,hash,body) VALUES(?1,?2,?3,?4) ON CONFLICT(repo) DO UPDATE SET revision=excluded.revision,hash=excluded.hash,body=excluded.body",params![a.repository_id,a.revision,a.policy_hash,serde_json::to_string(a)?])?;
        tx.commit()?;
        Ok(())
    }
    pub fn enqueue(&self, job: &Job) -> Result<()> {
        ensure!(
            job.version == 2
                && crate::config::valid_profile(&job.profile)
                && valid_hash(&job.policy_hash)
                && job.repository_id > 0
                && job.run_id > 0
                && job.attempt > 0
                && job.commit.len() == 40
                && job.commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid job"
        );
        ensure!(
            job.id
                == crate::ledger::profile_job_id(
                    job.repository_id,
                    job.run_id,
                    job.attempt,
                    &job.profile,
                    &job.policy_hash
                ),
            "job identifier differs"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        let active: (u64, String) = tx.query_row(
            "SELECT revision,hash FROM policies WHERE repo=?1",
            [job.repository_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            active == (job.revision, job.policy_hash.clone()),
            "job uses inactive policy"
        );
        let policy_body: String = tx.query_row(
            "SELECT body FROM policies WHERE repo=?1",
            [job.repository_id],
            |r| r.get(0),
        )?;
        let policy: Activation = serde_json::from_str(&policy_body)?;
        ensure!(
            policy.profiles.contains_key(&job.profile),
            "profile is not active"
        );
        let existing: Option<String> = tx
            .query_row("SELECT body FROM jobs WHERE id=?1", [&job.id], |r| r.get(0))
            .optional()?;
        if let Some(existing) = existing {
            ensure!(
                serde_json::from_str::<Job>(&existing)? == *job,
                "conflicting job"
            );
            return Ok(());
        }
        tx.execute(
            "INSERT INTO jobs(id,repo,policy,body) VALUES(?1,?2,?3,?4)",
            params![
                job.id,
                job.repository_id,
                job.policy_hash,
                serde_json::to_string(job)?
            ],
        )?;
        append(&tx, &job.id, "job.accepted", json!({"job":job}))?;
        tx.commit()?;
        Ok(())
    }
    pub fn claim(&self) -> Result<Option<Claimed>> {
        use rand::RngCore;
        let now = crate::config::now()?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        let exhausted = {
            let mut q = tx.prepare(
                "SELECT id FROM jobs WHERE status='running' AND lease_until < ?1 AND attempts >= 6",
            )?;
            q.query_map([now], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in exhausted {
            append(
                &tx,
                &id,
                "job.interrupted",
                json!({"signing_outcome":"uncertain; retry limit exhausted"}),
            )?;
            append(
                &tx,
                &id,
                "job.finished",
                json!({"status":"rejected","reason":"retry-limit"}),
            )?;
            tx.execute(
                "UPDATE jobs SET status='rejected',lease=NULL,lease_until=0 WHERE id=?1",
                [id],
            )?;
        }
        let row:Option<(String,String,u64,String)>=tx.query_row("SELECT j.id,j.body,j.attempts,j.status FROM jobs j JOIN policies p ON p.repo=j.repo AND p.hash=j.policy WHERE j.status IN ('pending','running') AND j.lease_until < ?1 AND j.retry_after <= ?1 AND j.attempts < 6 ORDER BY j.rowid LIMIT 1",[now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((id, body, attempt, status)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let mut bytes = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut bytes)?;
        let lease = hex::encode(bytes);
        tx.execute("UPDATE jobs SET status='running',lease=?1,lease_until=?2,attempts=attempts+1 WHERE id=?3",params![lease,now+300,id])?;
        if status == "running" {
            append(
                &tx,
                &id,
                "job.interrupted",
                json!({"previous_attempt":attempt,"signing_outcome":"uncertain; inspect prior intent/result events"}),
            )?;
        }
        append(&tx, &id, "job.claimed", json!({"attempt":attempt+1}))?;
        tx.commit()?;
        Ok(Some(Claimed {
            job: serde_json::from_str(&body)?,
            lease,
            attempt: attempt + 1,
        }))
    }
    pub fn event(&self, id: &str, lease: &str, kind: &str, data: Value) -> Result<()> {
        ensure!(kind.len() <= 100 && !kind.is_empty(), "invalid event kind");
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        check_lease(&tx, id, lease)?;
        append(&tx, id, kind, data)?;
        tx.execute(
            "UPDATE jobs SET lease_until=?1 WHERE id=?2",
            params![crate::config::now()? + 300, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn finish(&self, id: &str, lease: &str, status: &str) -> Result<()> {
        ensure!(
            ["complete", "rejected", "retry"].contains(&status),
            "invalid job outcome"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        check_lease(&tx, id, lease)?;
        let attempts: u64 =
            tx.query_row("SELECT attempts FROM jobs WHERE id=?1", [id], |r| r.get(0))?;
        let state = if status == "retry" && attempts < 6 {
            "pending"
        } else if status == "retry" {
            "rejected"
        } else {
            status
        };
        append(
            &tx,
            id,
            "job.finished",
            json!({"status":state,"requested":status}),
        )?;
        tx.execute(
            "UPDATE jobs SET status=?1,lease=NULL,lease_until=0,retry_after=?2 WHERE id=?3",
            params![state, crate::config::now()? + 30 * attempts, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Snapshot durable state; fail the scrape rather than report healthy zeroes.
    pub fn metrics(&self) -> Result<String> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let now = crate::config::now()?;
        let mut out = crate::metrics::render();
        out.push_str("# HELP bathysign_ledger_jobs Current durable job states.\n# TYPE bathysign_ledger_jobs gauge\n");
        for status in ["pending", "running", "complete", "rejected"] {
            let count: u64 =
                db.query_row("SELECT count(*) FROM jobs WHERE status=?1", [status], |r| {
                    r.get(0)
                })?;
            out.push_str(&format!(
                "bathysign_ledger_jobs{{status=\"{status}\"}} {count}\n"
            ));
        }
        let expired: u64 = db.query_row(
            "SELECT count(*) FROM jobs WHERE status='running' AND lease_until < ?1",
            [now],
            |r| r.get(0),
        )?;
        out.push_str(&format!("# HELP bathysign_ledger_expired_leases Running jobs with expired leases.\n# TYPE bathysign_ledger_expired_leases gauge\nbathysign_ledger_expired_leases {expired}\n"));
        // Event timestamps are immutable, including across lease renewal/retries.
        let oldest: Option<u64> = db.query_row("SELECT min(CAST(json_extract(e.body,'$.time') AS INTEGER)) FROM events e JOIN jobs j ON j.id=e.job WHERE e.kind='job.accepted' AND j.status IN ('pending','running')", [], |r| r.get(0))?;
        let age = oldest.map(|t| now.saturating_sub(t)).unwrap_or(0);
        out.push_str(&format!("# HELP bathysign_ledger_oldest_unfinished_seconds Age of oldest unfinished job, zero when empty.\n# TYPE bathysign_ledger_oldest_unfinished_seconds gauge\nbathysign_ledger_oldest_unfinished_seconds {age}\n"));
        out.push_str("# HELP bathysign_ledger_events_total Durable task milestones and failures.\n# TYPE bathysign_ledger_events_total counter\n");
        for kind in [
            "job.accepted",
            "job.claimed",
            "job.failed",
            "job.interrupted",
            "job.finished",
            "inputs.verified",
            "sign.intent",
            "sign.result",
            "outputs.verified",
            "upload.receipt",
        ] {
            let count: u64 =
                db.query_row("SELECT count(*) FROM events WHERE kind=?1", [kind], |r| {
                    r.get(0)
                })?;
            out.push_str(&format!(
                "bathysign_ledger_events_total{{kind=\"{kind}\"}} {count}\n"
            ));
        }
        Ok(out)
    }
    pub fn inspect(&self, id: &str) -> Result<Value> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let (body, status): (String, String) =
            db.query_row("SELECT body,status FROM jobs WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        let mut q =
            db.prepare("SELECT seq,kind,body,previous,hash FROM events WHERE job=?1 ORDER BY seq")?;
        let events=q.query_map([id],|r|Ok(json!({"sequence":r.get::<_,u64>(0)?,"kind":r.get::<_,String>(1)?,"body":serde_json::from_str::<Value>(&r.get::<_,String>(2)?).unwrap_or(Value::Null),"previous":r.get::<_,String>(3)?,"hash":r.get::<_,String>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!({"job":serde_json::from_str::<Value>(&body)?,"status":status,"events":events}))
    }
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn check_lease(tx: &rusqlite::Transaction<'_>, id: &str, lease: &str) -> Result<()> {
    let (actual,until,status,policy,active):(Option<String>,u64,String,String,String)=tx.query_row("SELECT j.lease,j.lease_until,j.status,j.policy,p.hash FROM jobs j JOIN policies p ON p.repo=j.repo WHERE j.id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    ensure!(
        actual.as_deref() == Some(lease)
            && until >= crate::config::now()?
            && status == "running"
            && policy == active,
        "expired lease or inactive policy"
    );
    Ok(())
}
fn append(tx: &rusqlite::Transaction<'_>, job: &str, kind: &str, data: Value) -> Result<()> {
    let prior: Option<(u64, String)> = tx
        .query_row(
            "SELECT seq,hash FROM events WHERE job=?1 ORDER BY seq DESC LIMIT 1",
            [job],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (seq, previous) = prior.map(|(s, h)| (s + 1, h)).unwrap_or((1, String::new()));
    let body = serde_json::to_string(&json!({"time":crate::config::now()?,"data":data}))?;
    let hash = crate::sha256(&serde_json::to_vec(&json!([
        job, seq, kind, &body, &previous
    ]))?);
    tx.execute(
        "INSERT INTO events(job,seq,kind,body,previous,hash) VALUES(?1,?2,?3,?4,?5,?6)",
        params![job, seq, kind, body, previous, hash],
    )?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    lease: String,
    kind: String,
    data: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    lease: String,
    status: String,
}
fn authorize(
    store: &Store,
    headers: &HeaderMap,
) -> std::result::Result<(), (StatusCode, &'static str)> {
    store
        .auth(headers)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized"))
}
pub fn router(store: Store) -> Router {
    Router::new()
        .route("/v1/trust/{authority}/head", get(|State(s): State<Store>, h: HeaderMap, Path(a): Path<String>| async move {
            authorize(&s,&h)?;
            s.trust_checkpoint(&a,None).map(Json).map_err(rejected)
        }))
        .route("/v1/trust/{authority}/checkpoints/{digest}", get(|State(s): State<Store>, h: HeaderMap, Path((a,d)): Path<(String,String)>| async move {
            authorize(&s,&h)?;
            s.trust_checkpoint(&a,Some(&d)).map(Json).map_err(rejected)
        }))
        .route("/v1/trust/{authority}/checkpoints", post(|State(s): State<Store>, h: HeaderMap, Path(a): Path<String>, body: axum::body::Bytes| async move {
            authorize(&s,&h)?;
            let checkpoint: crate::trust::Checkpoint = serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST,"invalid checkpoint"))?;
            if checkpoint.authority.authority != a { return Err((StatusCode::CONFLICT,"authority differs")); }
            s.trust_commit(&checkpoint).map(|d| Json(json!({"digest":d}))).map_err(rejected)
        }).layer(axum::extract::DefaultBodyLimit::max(crate::trust::MAX_WIRE)))
        .route(
            "/metrics",
            get(|State(s): State<Store>, h: HeaderMap| async move {
                authorize(&s, &h)?;
                s.metrics()
                    .map(crate::metrics::response)
                    .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable"))
            }),
        )
        .route(
            "/v1/health",
            get(|State(s): State<Store>, h: HeaderMap| async move {
                authorize(&s, &h)?;
                Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
            }),
        )
        .route(
            "/v1/policies",
            post(
                |State(s): State<Store>, h: HeaderMap, Json(a): Json<Activation>| async move {
                    authorize(&s, &h)?;
                    s.activate(&a).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/jobs",
            post(
                |State(s): State<Store>, h: HeaderMap, Json(j): Json<Job>| async move {
                    authorize(&s, &h)?;
                    s.enqueue(&j).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/claim",
            post(|State(s): State<Store>, h: HeaderMap| async move {
                authorize(&s, &h)?;
                let j = s.claim().map_err(rejected)?;
                Ok::<_, (StatusCode, &'static str)>(Json(
                    serde_json::to_value(j)
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "encoding error"))?,
                ))
            }),
        )
        .route(
            "/v1/jobs/{id}/events",
            post(
                |State(s): State<Store>,
                 h: HeaderMap,
                 Path(id): Path<String>,
                 Json(e): Json<Event>| async move {
                    authorize(&s, &h)?;
                    s.event(&id, &e.lease, &e.kind, e.data).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/jobs/{id}/finish",
            post(
                |State(s): State<Store>,
                 h: HeaderMap,
                 Path(id): Path<String>,
                 Json(f): Json<Finish>| async move {
                    authorize(&s, &h)?;
                    s.finish(&id, &f.lease, &f.status).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/jobs/{id}",
            get(
                |State(s): State<Store>, h: HeaderMap, Path(id): Path<String>| async move {
                    authorize(&s, &h)?;
                    s.inspect(&id).map(Json).map_err(rejected)
                },
            ),
        )
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(store)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_history_is_preserved_and_stale_jobs_are_rejected() {
        use crate::ledger::{History, profile_job_id};
        use std::collections::BTreeMap;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            &dir.path().join("audit.sqlite"),
            b"01234567890123456789012345678901",
        )
        .unwrap();
        let mut activation = Activation {
            version: 2,
            repository_id: 1,
            revision: 2,
            policy_hash: "c".repeat(64),
            profiles: BTreeMap::from([
                (
                    "oss".into(),
                    History {
                        classical_history: vec!["b".repeat(64)],
                        hybrid_history: vec![],
                    },
                ),
                (
                    "google".into(),
                    History {
                        classical_history: vec!["d".repeat(64)],
                        hybrid_history: vec![],
                    },
                ),
            ]),
        };
        store.activate(&activation).unwrap();
        let make = |profile: &str| Job {
            version: 2,
            profile: profile.into(),
            id: profile_job_id(1, 2, 1, profile, &activation.policy_hash),
            repository_id: 1,
            run_id: 2,
            attempt: 1,
            commit: "e".repeat(40),
            policy_hash: activation.policy_hash.clone(),
            revision: 2,
        };
        let oss = make("oss");
        let google = make("google");
        store.enqueue(&oss).unwrap();
        store.enqueue(&google).unwrap();
        store.enqueue(&oss).unwrap();
        assert_ne!(oss.id, google.id);
        let claimed = store.claim().unwrap().unwrap();
        activation.revision = 3;
        activation.policy_hash = "f".repeat(64);
        let mut removed = activation.clone();
        removed.profiles.remove("google");
        assert!(store.activate(&removed).is_err());
        let mut reset = activation.clone();
        reset.profiles.get_mut("google").unwrap().classical_history = vec!["f".repeat(64)];
        assert!(store.activate(&reset).is_err());
        store.activate(&activation).unwrap();
        assert!(
            store
                .event(&claimed.job.id, &claimed.lease, "sign.intent", json!({}))
                .is_err()
        );
        assert!(store.enqueue(&oss).is_err());
        assert!(store.claim().unwrap().is_none());
        assert_eq!(store.inspect(&oss.id).unwrap()["status"], "rejected");
        assert_eq!(store.inspect(&google.id).unwrap()["status"], "rejected");
    }
    #[test]
    fn expired_leases_recover_and_stop_at_retry_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            &dir.path().join("ledger.sqlite"),
            b"01234567890123456789012345678901",
        )
        .unwrap();
        let hash = "a".repeat(64);
        store
            .activate(&Activation {
                repository_id: 1,
                revision: 1,
                policy_hash: hash.clone(),
                version: 2,
                profiles: std::collections::BTreeMap::from([(
                    "default".into(),
                    crate::ledger::History {
                        classical_history: vec!["b".repeat(64)],
                        hybrid_history: vec![],
                    },
                )]),
            })
            .unwrap();
        let job = Job {
            version: 2,
            profile: "default".into(),
            id: crate::ledger::profile_job_id(1, 2, 1, "default", &hash),
            repository_id: 1,
            run_id: 2,
            attempt: 1,
            commit: "c".repeat(40),
            policy_hash: hash,
            revision: 1,
        };
        store.enqueue(&job).unwrap();
        let first = store.claim().unwrap().unwrap();
        store
            .db
            .lock()
            .unwrap()
            .execute("UPDATE jobs SET lease_until=0", [])
            .unwrap();
        assert!(
            store
                .metrics()
                .unwrap()
                .contains("bathysign_ledger_expired_leases 1")
        );
        let second = store.claim().unwrap().unwrap();
        assert!(
            store
                .metrics()
                .unwrap()
                .contains("bathysign_ledger_expired_leases 0")
        );
        assert_ne!(first.lease, second.lease);
        assert!(
            store
                .event(&job.id, &first.lease, "sign.intent", json!({}))
                .is_err()
        );
        assert!(
            store.inspect(&job.id).unwrap()["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "job.interrupted")
        );
        store
            .db
            .lock()
            .unwrap()
            .execute("UPDATE jobs SET lease_until=0, attempts=6", [])
            .unwrap();
        assert!(store.claim().unwrap().is_none());
        assert_eq!(store.inspect(&job.id).unwrap()["status"], "rejected");
        let mut h = HeaderMap::new();
        assert!(store.auth(&h).is_err());
        h.insert(
            "authorization",
            "Bearer 01234567890123456789012345678901".parse().unwrap(),
        );
        store.auth(&h).unwrap();
    }
    #[test]
    fn durable_dedup_claim_and_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.sqlite");
        let token = b"01234567890123456789012345678901";
        let s = Store::open(&path, token).unwrap();
        let hash = "a".repeat(64);
        let a = Activation {
            repository_id: 1,
            revision: 1,
            policy_hash: hash.clone(),
            version: 2,
            profiles: std::collections::BTreeMap::from([(
                "default".into(),
                crate::ledger::History {
                    classical_history: vec!["b".repeat(64)],
                    hybrid_history: vec![],
                },
            )]),
        };
        s.activate(&a).unwrap();
        let job = Job {
            version: 2,
            profile: "default".into(),
            id: crate::ledger::profile_job_id(1, 2, 1, "default", &hash),
            repository_id: 1,
            run_id: 2,
            attempt: 1,
            commit: "c".repeat(40),
            policy_hash: hash,
            revision: 1,
        };
        s.enqueue(&job).unwrap();
        s.enqueue(&job).unwrap();
        let claimed = s.claim().unwrap().unwrap();
        assert!(s.claim().unwrap().is_none());
        assert!(s.event(&job.id, "invalid", "test", json!({})).is_err());
        s.event(&job.id, &claimed.lease, "sign.intent", json!({"key":"A"}))
            .unwrap();
        s.finish(&job.id, &claimed.lease, "complete").unwrap();
        drop(s);
        let s = Store::open(&path, token).unwrap();
        let metrics = s.metrics().unwrap();
        assert!(metrics.contains("bathysign_ledger_jobs{status=\"complete\"} 1"));
        assert!(metrics.contains("bathysign_ledger_events_total{kind=\"job.accepted\"} 1"));
        assert!(metrics.contains("bathysign_ledger_oldest_unfinished_seconds 0"));
        assert!(!metrics.contains(&job.id));
        assert!(!metrics.contains(std::str::from_utf8(token).unwrap()));
        assert!(s.claim().unwrap().is_none());
        assert_eq!(s.inspect(&job.id).unwrap()["status"], "complete");
        let mut newer = a.clone();
        newer.revision = 2;
        newer.policy_hash = "d".repeat(64);
        newer
            .profiles
            .get_mut("default")
            .unwrap()
            .classical_history
            .push("e".repeat(64));
        s.activate(&newer).unwrap();
        assert!(s.activate(&a).is_err());
        newer.revision = 3;
        newer
            .profiles
            .get_mut("default")
            .unwrap()
            .classical_history
            .remove(0);
        assert!(s.activate(&newer).is_err());
    }
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    use crate::trust::{AUTHORITY, Authority, BOOTSTRAP, Checkpoint, TARGET};
    #[test]
    fn checkpoint_cas_is_durable_idempotent_and_runtime_cannot_initialize() {
        crate::initialize_test_crypto();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.sqlite");
        let store = Store::open(&path, &[9; 32]).unwrap();
        let initial = Checkpoint {
            version: 1,
            authority: Authority {
                authority: AUTHORITY.into(),
                bootstrap_sha256: crate::sha256(BOOTSTRAP),
                epoch: "a".repeat(64),
                target: TARGET.into(),
            },
            generation: 1,
            previous: None,
            verified_at: crate::config::now().unwrap(),
            observations: vec![],
            target: None,
            usable: false,
        };
        assert!(store.trust_commit(&initial).is_err());
        assert!(
            store.trust_initialize(&initial).is_err(),
            "partial checkpoints cannot seed trust"
        );
        // Seed a partial head directly to exercise persistence without a live repository.
        store.trust_write(&initial, true).unwrap();
        let mut next = initial.clone();
        next.generation = 2;
        next.previous = Some(initial.digest().unwrap());
        let digest = store.trust_commit(&next).unwrap();
        assert_eq!(store.trust_commit(&next).unwrap(), digest);
        let mut fork = next.clone();
        fork.verified_at += 1;
        assert!(store.trust_commit(&fork).is_err());
        drop(store);
        let restored = Store::open(&path, &[9; 32]).unwrap();
        assert_eq!(restored.trust_checkpoint(AUTHORITY, None).unwrap(), next);
        assert_eq!(
            restored
                .trust_checkpoint(AUTHORITY, Some(&initial.digest().unwrap()))
                .unwrap(),
            initial
        );
        restored
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE trust_checkpoints SET body=?1 WHERE digest=?2",
                params![b"corrupt".as_slice(), digest],
            )
            .unwrap();
        assert!(restored.trust_checkpoint(AUTHORITY, None).is_err());
    }
}
