//! Image-anchored TUF verification. The guest uses RAM and the audit API only.
use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sigstore_tuf::{MetadataStore, Repository, TrustedMetadataSet, Updater};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Instant,
};

pub const AUTHORITY: &str = "sigstore-public";
pub const TARGET: &str = "trusted_root.json";
pub const MIRROR: &str = "https://tuf-repo-cdn.sigstore.dev/";
pub const BOOTSTRAP: &[u8] = include_bytes!("trust/sigstore-root.json");
pub const MAX_STATE: usize = 16 * 1024 * 1024;
pub const MAX_WIRE: usize = 24 * 1024 * 1024;
const MAX_TARGET: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub authority: String,
    pub bootstrap_sha256: String,
    pub epoch: String,
    pub target: String,
}
impl Authority {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.authority == AUTHORITY && self.target == TARGET,
            "unsupported trust authority/target"
        );
        ensure!(
            self.bootstrap_sha256 == crate::sha256(BOOTSTRAP),
            "bootstrap differs from image"
        );
        ensure!(
            crate::config::valid_hash(&self.epoch),
            "invalid trust initialization epoch"
        );
        Ok(())
    }
}

/// Ordered accepted metadata transitions, not a directory that can omit floors.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub name: String,
    pub bytes: String,
    pub verified_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub authority: Authority,
    pub generation: u64,
    pub previous: Option<String>,
    pub verified_at: u64,
    pub observations: Vec<Observation>,
    pub target: Option<String>,
    pub usable: bool,
}
impl Checkpoint {
    pub fn digest(&self) -> Result<String> {
        Ok(crate::sha256(&serde_json::to_vec(self)?))
    }
    pub fn follows(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.authority == previous.authority,
            "trust authority/epoch changed"
        );
        ensure!(
            self.generation
                == previous
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("trust generation exhausted"))?
                && self.previous.as_deref() == Some(previous.digest()?.as_str()),
            "trust predecessor differs"
        );
        ensure!(
            self.verified_at >= previous.verified_at
                && self.observations.starts_with(&previous.observations),
            "trust history regressed"
        );
        Ok(())
    }
    pub fn verify(&self) -> Result<Verified> {
        self.authority.validate()?;
        self.verify_with_anchor(BOOTSTRAP)
    }
    fn verify_with_anchor(&self, anchor: &[u8]) -> Result<Verified> {
        ensure!(
            self.version == 1 && self.generation > 0,
            "unsupported trust checkpoint"
        );
        ensure!(
            (self.generation == 1) == self.previous.is_none(),
            "invalid trust checkpoint ancestry"
        );
        ensure!(
            self.observations.len() <= 16384,
            "trust history entry limit exceeded"
        );
        let mut trusted = TrustedMetadataSet::from_root(anchor)?;
        let mut files = BTreeMap::new();
        let mut roles = BTreeSet::from(["targets".to_string()]);
        let mut total = 0usize;
        let mut last = 0;
        for observation in &self.observations {
            ensure!(
                observation.verified_at >= last && observation.verified_at <= self.verified_at,
                "trust observation time regressed"
            );
            last = observation.verified_at;
            let bytes = STANDARD.decode(&observation.bytes)?;
            total = total
                .checked_add(
                    bytes
                        .len()
                        .saturating_add(observation.name.len())
                        .saturating_add(128),
                )
                .ok_or_else(|| anyhow::anyhow!("trust state too large"))?;
            ensure!(
                total <= MAX_STATE && bytes.len() <= 5_000_000,
                "trust state too large"
            );
            let at = time(observation.verified_at)?;
            let name = &observation.name;
            if let Some(version) = name
                .strip_prefix("root_history/")
                .and_then(|n| n.strip_suffix(".root.json"))
            {
                let version: u64 = version.parse()?;
                if version == trusted.root().version {
                    ensure!(
                        bytes == trusted.root_bytes(),
                        "conflicting root at the same version"
                    );
                } else {
                    trusted.update_root(&bytes)?;
                    ensure!(
                        version == trusted.root().version,
                        "root filename/version differs"
                    );
                    roles.clear();
                    roles.insert("targets".into());
                }
            } else {
                trusted.check_root_expired(at)?;
                match name.as_str() {
                    "timestamp.json" => trusted.update_timestamp(&bytes, at)?,
                    "snapshot.json" => {
                        trusted.update_snapshot(&bytes, at)?;
                        roles.clear();
                        roles.insert("targets".into());
                    }
                    "targets.json" => {
                        trusted.update_targets(&bytes, at)?;
                    }
                    _ => {
                        let role = decode_role(name)?;
                        let parents: Vec<_> = roles
                            .iter()
                            .filter(|parent| {
                                trusted
                                    .targets_role(parent)
                                    .and_then(|t| t.delegations.as_ref())
                                    .is_some_and(|d| d.roles.iter().any(|r| r.name == role))
                            })
                            .cloned()
                            .collect();
                        let mut accepted = false;
                        for parent in parents {
                            if trusted
                                .update_delegated_targets(&bytes, &role, &parent, at)
                                .is_ok()
                            {
                                accepted = true;
                                break;
                            }
                        }
                        ensure!(accepted, "unauthorized delegated metadata");
                        roles.insert(role);
                    }
                }
            }
            files.insert(name.clone(), bytes);
        }
        files.insert("root.json".into(), trusted.root_bytes().to_vec());
        let mut expiry = 0;
        let mut target = None;
        if self.usable {
            let at = time(self.verified_at)?;
            trusted.check_root_expired(at)?;
            trusted.check_timestamp_expired(at)?;
            trusted.check_snapshot_expired(at)?;
            let timestamp = trusted
                .timestamp()
                .ok_or_else(|| anyhow::anyhow!("timestamp missing"))?;
            let snapshot = trusted
                .snapshot()
                .ok_or_else(|| anyhow::anyhow!("snapshot missing"))?;
            let targets = trusted
                .targets_role("targets")
                .ok_or_else(|| anyhow::anyhow!("targets missing"))?;
            ensure!(
                timestamp.snapshot_meta().map(|p| p.version) == Some(snapshot.version)
                    && snapshot.meta.get("targets.json").map(|p| p.version)
                        == Some(targets.version),
                "incomplete target authorization"
            );
            let (info, role_expiry) = resolve_target(&trusted, at)?;
            let bytes = STANDARD.decode(
                self.target
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("trust target missing"))?,
            )?;
            ensure!(
                bytes.len() <= MAX_TARGET && bytes.len() as u64 == info.length,
                "trust target length differs"
            );
            ensure!(
                info.hashes.get("sha256") == Some(&crate::sha256(&bytes)),
                "trust target digest differs"
            );
            sigstore_trust_root::TrustedRoot::from_json(std::str::from_utf8(&bytes)?)?;
            expiry = [
                trusted.root().expires.as_second(),
                trusted.timestamp().unwrap().expires.as_second(),
                trusted.snapshot().unwrap().expires.as_second(),
                role_expiry,
            ]
            .into_iter()
            .min()
            .unwrap()
            .try_into()?;
            ensure!(expiry > self.verified_at, "trust expired");
            files.insert(format!("targets/{TARGET}"), bytes.clone());
            target = Some(bytes);
        } else {
            ensure!(
                self.target.is_none(),
                "partial checkpoint cannot supply a target"
            );
        }
        Ok(Verified {
            checkpoint: self.clone(),
            files,
            target,
            expiry,
            versions: [
                trusted.root().version,
                trusted.timestamp().map_or(0, |t| t.version),
                trusted.snapshot().map_or(0, |s| s.version),
                trusted.targets_role("targets").map_or(0, |t| t.version),
            ],
        })
    }
}

fn time(seconds: u64) -> Result<jiff::Timestamp> {
    Ok(jiff::Timestamp::from_second(seconds.try_into()?)?)
}
fn decode_role(name: &str) -> Result<String> {
    let name = name
        .strip_suffix(".json")
        .ok_or_else(|| anyhow::anyhow!("invalid metadata filename"))?;
    let mut decoded = Vec::new();
    let mut iter = name.bytes();
    while let Some(b) = iter.next() {
        if b == b'%' {
            let h = iter
                .next()
                .ok_or_else(|| anyhow::anyhow!("invalid role encoding"))?;
            let l = iter
                .next()
                .ok_or_else(|| anyhow::anyhow!("invalid role encoding"))?;
            decoded.push(u8::from_str_radix(std::str::from_utf8(&[h, l])?, 16)?);
        } else {
            decoded.push(b);
        }
    }
    Ok(String::from_utf8(decoded)?)
}
fn resolve_target(
    trusted: &TrustedMetadataSet,
    at: jiff::Timestamp,
) -> Result<(sigstore_tuf::TargetFile, i64)> {
    let mut queue = vec![("targets".to_string(), "root".to_string())];
    let mut seen = BTreeSet::new();
    let mut expiry = trusted.root().expires.as_second();
    while !queue.is_empty() {
        let (role, parent) = queue.remove(0);
        if !seen.insert(role.clone()) {
            continue;
        }
        ensure!(seen.len() <= 32, "delegation limit exceeded");
        let metadata = trusted
            .targets_role(&role)
            .ok_or_else(|| anyhow::anyhow!("required delegated metadata missing"))?;
        if role != "targets" {
            trusted.verify_delegated_targets(&role, &parent, at)?;
        }
        ensure!(metadata.expires > at, "delegated trust expired");
        expiry = expiry.min(metadata.expires.as_second());
        if let Some(target) = metadata.target(TARGET) {
            return Ok((target.clone(), expiry));
        }
        let mut children = Vec::new();
        if let Some(delegations) = &metadata.delegations {
            for child in &delegations.roles {
                if child.matches_path(TARGET)? {
                    children.push((child.name.clone(), role.clone()));
                    if child.terminating {
                        queue.clear();
                        break;
                    }
                }
            }
        }
        children.extend(queue);
        queue = children;
    }
    bail!("trust target is not authorized")
}

/// Constructible only by authenticating a checkpoint, including its history.
pub struct Verified {
    pub checkpoint: Checkpoint,
    files: BTreeMap<String, Vec<u8>>,
    target: Option<Vec<u8>>,
    pub expiry: u64,
    pub versions: [u64; 4],
}
impl Verified {
    pub fn binding(&self) -> Result<serde_json::Value> {
        let target = self
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("trust refresh is incomplete"))?;
        Ok(
            serde_json::json!({"authority":self.checkpoint.authority,"generation":self.checkpoint.generation,
            "checkpoint_sha256":self.checkpoint.digest()?,"target_sha256":crate::sha256(target),"valid_until":self.expiry}),
        )
    }
    pub fn active(self) -> Result<Active> {
        let target = self
            .target
            .ok_or_else(|| anyhow::anyhow!("trust refresh is incomplete"))?;
        ensure!(self.expiry > crate::config::now()?, "trust expired");
        Ok(Active {
            checkpoint: self.checkpoint,
            target,
            expiry: self.expiry,
            versions: self.versions,
        })
    }
}
pub struct Active {
    pub checkpoint: Checkpoint,
    pub target: Vec<u8>,
    pub expiry: u64,
    pub versions: [u64; 4],
}
impl Active {
    pub fn check(&self) -> Result<()> {
        ensure!(self.expiry > crate::config::now()?, "trust expired");
        Ok(())
    }
    pub fn binding(&self) -> Result<serde_json::Value> {
        Ok(
            serde_json::json!({"authority":self.checkpoint.authority,"generation":self.checkpoint.generation,
            "checkpoint_sha256":self.checkpoint.digest()?,"target_sha256":crate::sha256(&self.target),"valid_until":self.expiry}),
        )
    }
}

#[derive(Clone)]
struct RecordingStore(Arc<Mutex<Recording>>);
struct Recording {
    files: BTreeMap<String, Vec<u8>>,
    observations: Vec<Observation>,
    now: u64,
    error: bool,
}
impl MetadataStore for RecordingStore {
    fn load(&self, name: &str) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().files.get(name).cloned())
    }
    fn store(&self, name: &str, bytes: &[u8]) -> sigstore_tuf::Result<()> {
        let mut s = self.0.lock().unwrap();
        if name != "root.json"
            && !name
                .strip_suffix(".snapshot.json")
                .is_some_and(|v| v.parse::<u64>().is_ok())
            && !name.starts_with("targets/")
            && s.files.get(name).is_none_or(|old| old != bytes)
        {
            let observation = Observation {
                name: name.into(),
                bytes: STANDARD.encode(bytes),
                verified_at: s.now,
            };
            s.observations.push(observation);
        }
        s.files.insert(name.into(), bytes.to_vec());
        if s.files.values().map(Vec::len).sum::<usize>() > MAX_STATE * 2 + MAX_TARGET {
            s.error = true;
            return Err(sigstore_tuf::Error::transport("trust cache limit exceeded"));
        }
        Ok(())
    }
}

struct HttpRepository {
    client: reqwest::Client,
    recording: RecordingStore,
    mirror: String,
}
impl HttpRepository {
    fn new(recording: RecordingStore) -> Result<Self> {
        Ok(Self {
            recording,
            mirror: MIRROR.into(),
            client: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()?,
        })
    }
    async fn fetch(&self, relative: &str, max: u64) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        let operation = async {
            ensure!(
                relative.len() <= 1024
                    && !relative.starts_with('/')
                    && !relative.split('/').any(|p| p == "..")
                    && !relative.contains(['?', '#', '\\']),
                "invalid TUF path"
            );
            use crate::network::SendMonitored;
            let response = self
                .client
                .get(format!("{}{relative}", self.mirror))
                .send_monitored()
                .await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let bytes = crate::github::bounded(response, usize::try_from(max)?).await?;
            if !relative.starts_with("targets/") {
                let staged = self.recording.0.lock().unwrap();
                let history_size: usize = staged
                    .observations
                    .iter()
                    .map(|o| o.bytes.len() / 4 * 3 + o.name.len() + 128)
                    .sum();
                ensure!(
                    staged.files.get(relative).is_some_and(|old| old == &bytes)
                        || history_size
                            .saturating_add(bytes.len())
                            .saturating_add(1024)
                            .saturating_add(128)
                            <= MAX_STATE,
                    "trust history capacity exhausted before accepting metadata"
                );
            }
            Ok::<_, anyhow::Error>(Some(bytes))
        }
        .await;
        operation
            .map_err(|e| sigstore_tuf::Error::transport_with_source("trust transport failed", e))
    }
}
impl Repository for HttpRepository {
    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
        max: u64,
    ) -> sigstore_tuf::transport::FetchFuture<'a> {
        Box::pin(self.fetch(name, max))
    }
    fn fetch_target<'a>(
        &'a self,
        path: &'a str,
        max: u64,
    ) -> sigstore_tuf::transport::FetchFuture<'a> {
        Box::pin(async move { self.fetch(&format!("targets/{path}"), max).await })
    }
}

pub struct Refresh {
    pub checkpoint: Checkpoint,
    pub network_failed: bool,
    pub complete: bool,
}
/// The updater's best-effort store only stages bytes in RAM. The caller must
/// commit the resulting checkpoint before publishing an Active state.
pub async fn refresh(previous: Option<&Checkpoint>, authority: &Authority) -> Result<Refresh> {
    refresh_from(previous, authority, BOOTSTRAP, HttpRepository::new).await
}

// The public entry point fixes both the image anchor and HTTPS mirror. This
// boundary separates authenticated refresh decisions from transport setup.
async fn refresh_from<R: Repository + 'static>(
    previous: Option<&Checkpoint>,
    authority: &Authority,
    anchor: &[u8],
    repository: impl FnOnce(RecordingStore) -> Result<R>,
) -> Result<Refresh> {
    authority.validate()?;
    let verified = previous
        .map(|p| {
            p.authority.validate()?;
            p.verify_with_anchor(anchor)
        })
        .transpose()?;
    let files = verified
        .as_ref()
        .map(|v| v.files.clone())
        .unwrap_or_default();
    let root = files.get("root.json").map(Vec::as_slice).unwrap_or(anchor);
    let now = crate::config::now()?;
    ensure!(
        previous.is_none_or(|p| p.verified_at <= now),
        "clock precedes accepted trust state"
    );
    let recording = RecordingStore(Arc::new(Mutex::new(Recording {
        files: files.clone(),
        observations: previous.map(|p| p.observations.clone()).unwrap_or_default(),
        now,
        error: false,
    })));
    let mut config = sigstore_tuf::UpdaterConfig::default();
    config.target_max_length = MAX_TARGET as u64;
    let mut updater = Updater::new(repository(recording.clone())?, root)?
        .with_config(config)
        .with_store(recording.clone());
    let started = Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        updater.refresh(time(now)?).await?;
        Ok::<_, anyhow::Error>(updater.get_target(TARGET, time(now)?).await?)
    })
    .await;
    crate::metrics::observe("trust_refresh", matches!(&result, Ok(Ok(_))), started);
    let (target, network_failed) = match result {
        Ok(Ok(bytes)) => (Some(STANDARD.encode(bytes)), false),
        Ok(Err(e)) => {
            let network = e.chain().any(|e| {
                e.is::<reqwest::Error>()
                    || e.downcast_ref::<crate::github::HttpFailure>()
                        .is_some_and(|h| h.retryable())
            });
            (None, network)
        }
        Err(_) => (None, true),
    };
    let recording = recording.0.lock().unwrap();
    ensure!(!recording.error, "trust RAM store failed");
    let changed = previous.is_none_or(|p| p.observations != recording.observations);
    if target.is_none()
        && !changed
        && network_failed
        && let Some(previous) = previous
    {
        previous.verify_with_anchor(anchor)?.active()?;
        return Ok(Refresh {
            checkpoint: previous.clone(),
            network_failed: true,
            complete: true,
        });
    }
    let complete = target.is_some();
    let checkpoint = Checkpoint {
        version: 1,
        authority: authority.clone(),
        generation: previous.map_or(1, |p| p.generation + 1),
        previous: previous.map(Checkpoint::digest).transpose()?,
        verified_at: now,
        observations: recording.observations.clone(),
        target,
        usable: complete,
    };
    checkpoint.verify_with_anchor(anchor)?;
    Ok(Refresh {
        checkpoint,
        network_failed,
        complete,
    })
}

#[derive(Clone, Default)]
pub struct Manager {
    inner: Arc<Mutex<Runtime>>,
}
#[derive(Default)]
struct Runtime {
    active: Option<Arc<Active>>,
    generation: u64,
    last_online: u64,
    cache_fallbacks: u64,
}
impl Manager {
    pub fn active(&self) -> Result<Arc<Active>> {
        let state = self
            .inner
            .lock()
            .unwrap()
            .active
            .clone()
            .ok_or_else(|| anyhow::anyhow!("trust is not ready"))?;
        state.check()?;
        Ok(state)
    }
    pub fn metrics(&self) -> String {
        let state = self.inner.lock().unwrap();
        let expiry = state.active.as_ref().map_or(0, |s| s.expiry);
        let ready = expiry > crate::config::now().unwrap_or(u64::MAX);
        let mut out = String::new();
        for (name, help, kind, value) in [
            (
                "ready",
                "Whether authenticated trust permits signing.",
                "gauge",
                u64::from(ready),
            ),
            (
                "valid_until_timestamp_seconds",
                "Earliest effective TUF metadata expiry.",
                "gauge",
                expiry,
            ),
            (
                "last_online_refresh_timestamp_seconds",
                "Last complete online trust refresh.",
                "gauge",
                state.last_online,
            ),
            (
                "checkpoint_generation",
                "Latest durably accepted trust checkpoint.",
                "gauge",
                state.generation,
            ),
            (
                "cache_fallbacks_total",
                "Network refresh failures using valid saved trust.",
                "counter",
                state.cache_fallbacks,
            ),
        ] {
            out.push_str(&format!("# HELP bathysign_trust_{name} {help}\n# TYPE bathysign_trust_{name} {kind}\nbathysign_trust_{name}{{authority=\"{AUTHORITY}\"}} {value}\n"));
        }
        out.push_str("# HELP bathysign_trust_metadata_version Accepted TUF role version.\n# TYPE bathysign_trust_metadata_version gauge\n");
        for (index, role) in ["root", "timestamp", "snapshot", "targets"]
            .iter()
            .enumerate()
        {
            let value = state.active.as_ref().map_or(0, |s| s.versions[index]);
            out.push_str(&format!("bathysign_trust_metadata_version{{authority=\"{AUTHORITY}\",role=\"{role}\"}} {value}\n"));
        }
        out
    }
    pub async fn update(
        &self,
        ledger: &crate::ledger::Ledger,
        authority: &Authority,
    ) -> Result<()> {
        let start = Instant::now();
        let restored = ledger.trust_head(authority).await.and_then(|previous| {
            ensure!(
                previous.authority == *authority,
                "saved trust authority differs"
            );
            previous.verify()?;
            Ok(previous)
        });
        crate::metrics::observe("trust_restore", restored.is_ok(), start);
        let previous = restored?;
        ensure!(
            previous.authority == *authority,
            "saved trust authority differs"
        );
        previous.verify()?;

        let refreshed = refresh(Some(&previous), authority).await?;
        if refreshed.checkpoint != previous {
            let start = Instant::now();
            let committed = ledger.trust_commit(&refreshed.checkpoint).await;
            crate::metrics::observe("trust_commit", committed.is_ok(), start);
            committed?;
        }
        let active = if refreshed.complete {
            Some(Arc::new(refreshed.checkpoint.verify()?.active()?))
        } else {
            None
        };
        let mut runtime = self.inner.lock().unwrap();
        runtime.generation = refreshed.checkpoint.generation;
        if refreshed.network_failed && active.is_some() {
            runtime.cache_fallbacks += 1;
        } else if active.is_some() {
            runtime.last_online = crate::config::now()?;
        }
        runtime.active = active;
        ensure!(runtime.active.is_some(), "trust refresh did not complete");
        Ok(())
    }
    pub async fn run(self, ledger: crate::ledger::Ledger, authority: Authority) {
        let mut retry = 30;
        loop {
            let started = Instant::now();
            let result = self.update(&ledger, &authority).await;
            crate::metrics::observe("trust_update", result.is_ok(), started);
            let delay = if result.is_ok() {
                retry = 30;
                self.active()
                    .map(|s| {
                        ((s.expiry
                            .saturating_sub(crate::config::now().unwrap_or(u64::MAX)))
                            / 2)
                        .clamp(1, 3600)
                    })
                    .unwrap_or(30)
            } else {
                // Failure of validation or persistence must not retain an old admission state.
                self.inner.lock().unwrap().active = None;
                tracing::warn!("trust update unavailable; signing admission paused");
                let delay = retry;
                retry = (retry * 2).min(900);
                delay
            };
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use serde_json::{Value, json};

    pub(super) fn signed(value: Value, key: &SigningKey, id: &str) -> Vec<u8> {
        let canonical = sigstore_tuf::canonical_json::to_canonical_bytes(&value).unwrap();
        let signature: Signature = key.sign(&canonical);
        serde_json::to_vec(&json!({"signed":value,"signatures":[{"keyid":id,"sig":hex::encode(signature.to_der().as_bytes())}]})).unwrap()
    }
    pub(super) fn fixture() -> (Vec<u8>, Checkpoint) {
        crate::initialize_test_crypto();
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let public = {
            use p256::pkcs8::EncodePublicKey;
            key.verifying_key()
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
        };
        let key_json =
            json!({"keytype":"ecdsa","scheme":"ecdsa-sha2-nistp256","keyval":{"public":public}});
        let parsed: sigstore_tuf::Key = serde_json::from_value(key_json.clone()).unwrap();
        let id = parsed.key_id().unwrap();
        let roles: BTreeMap<_, _> = ["root", "timestamp", "snapshot", "targets"]
            .into_iter()
            .map(|r| (r, json!({"keyids":[id],"threshold":1})))
            .collect();
        let root = signed(
            json!({"_type":"root","spec_version":"1.0.0","version":1,"expires":"2999-01-01T00:00:00Z","consistent_snapshot":false,"keys":{id.clone():key_json},"roles":roles}),
            &key,
            &id,
        );
        let target = include_bytes!("../tests/fixtures/public-trusted-root.json");
        let targets = signed(
            json!({"_type":"targets","spec_version":"1.0.0","version":1,"expires":"2999-01-01T00:00:00Z","targets":{TARGET:{"length":target.len(),"hashes":{"sha256":crate::sha256(target)}}}}),
            &key,
            &id,
        );
        let snapshot = signed(
            json!({"_type":"snapshot","spec_version":"1.0.0","version":1,"expires":"2999-01-01T00:00:00Z","meta":{"targets.json":{"version":1,"length":targets.len(),"hashes":{"sha256":crate::sha256(&targets)}}}}),
            &key,
            &id,
        );
        let timestamp = signed(
            json!({"_type":"timestamp","spec_version":"1.0.0","version":1,"expires":"2999-01-01T00:00:00Z","meta":{"snapshot.json":{"version":1,"length":snapshot.len(),"hashes":{"sha256":crate::sha256(&snapshot)}}}}),
            &key,
            &id,
        );
        let now = crate::config::now().unwrap();
        let observations = [
            ("timestamp.json", timestamp),
            ("snapshot.json", snapshot),
            ("targets.json", targets),
        ]
        .into_iter()
        .map(|(name, bytes)| Observation {
            name: name.into(),
            bytes: STANDARD.encode(bytes),
            verified_at: now,
        })
        .collect();
        (
            root,
            Checkpoint {
                version: 1,
                authority: Authority {
                    authority: AUTHORITY.into(),
                    bootstrap_sha256: crate::sha256(BOOTSTRAP),
                    epoch: "a".repeat(64),
                    target: TARGET.into(),
                },
                generation: 1,
                previous: None,
                verified_at: now,
                observations,
                target: Some(STANDARD.encode(target)),
                usable: true,
            },
        )
    }
    #[test]
    fn authenticates_history_and_rejects_corruption_and_partial_authorization() {
        let (root, checkpoint) = fixture();
        assert!(
            checkpoint
                .verify_with_anchor(&root)
                .unwrap()
                .active()
                .is_ok()
        );
        let mut bad = checkpoint.clone();
        bad.target = Some(STANDARD.encode(b"corrupt"));
        assert!(bad.verify_with_anchor(&root).is_err());
        let mut bad = checkpoint.clone();
        bad.observations.remove(1);
        assert!(bad.verify_with_anchor(&root).is_err());
        let mut bad = checkpoint.clone();
        bad.observations[0].bytes = STANDARD.encode(b"corrupt");
        assert!(bad.verify_with_anchor(&root).is_err());
        let mut partial = checkpoint.clone();
        partial.usable = false;
        partial.target = None;
        assert!(partial.verify_with_anchor(&root).unwrap().active().is_err());
        let mut expired = checkpoint.clone();
        expired.verified_at = 32503680000;
        assert!(expired.verify_with_anchor(&root).is_err());
        assert!(
            checkpoint.verify().is_err(),
            "foreign bootstrap must be rejected"
        );
    }
    #[test]
    fn expired_bootstrap_can_rotate_to_a_fresh_root_but_cannot_authorize() {
        let (root, mut checkpoint) = fixture();
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let mut value: Value = serde_json::from_slice(&root).unwrap();
        let id = value["signatures"][0]["keyid"]
            .as_str()
            .unwrap()
            .to_string();
        value["signed"]["expires"] = json!("2020-01-01T00:00:00Z");
        let expired = signed(value["signed"].clone(), &key, &id);
        assert!(checkpoint.verify_with_anchor(&expired).is_err());
        value["signed"]["version"] = json!(2);
        value["signed"]["expires"] = json!("2999-01-01T00:00:00Z");
        let fresh = signed(value["signed"].clone(), &key, &id);
        checkpoint.observations.insert(
            0,
            Observation {
                name: "root_history/2.root.json".into(),
                bytes: STANDARD.encode(fresh),
                verified_at: checkpoint.verified_at,
            },
        );
        assert!(
            checkpoint
                .verify_with_anchor(&expired)
                .unwrap()
                .active()
                .is_ok()
        );
        let mut rollback: Value =
            serde_json::from_slice(&STANDARD.decode(&checkpoint.observations[1].bytes).unwrap())
                .unwrap();
        rollback["signed"]["version"] = json!(0);
        checkpoint.observations.push(Observation {
            name: "timestamp.json".into(),
            bytes: STANDARD.encode(signed(rollback["signed"].clone(), &key, &id)),
            verified_at: checkpoint.verified_at,
        });
        assert!(checkpoint.verify_with_anchor(&expired).is_err());
    }
    #[test]
    fn checkpoints_cannot_rewrite_history_or_change_epoch() {
        let (_, previous) = fixture();
        let mut next = previous.clone();
        next.generation = 2;
        next.previous = Some(previous.digest().unwrap());
        assert!(next.follows(&previous).is_ok());
        next.observations.remove(0);
        assert!(next.follows(&previous).is_err());
        next = previous.clone();
        next.generation = 2;
        next.previous = Some(previous.digest().unwrap());
        next.authority.epoch = "b".repeat(64);
        assert!(next.follows(&previous).is_err());
    }
    #[test]
    fn delegated_target_requires_its_authorized_parent_and_complete_path() {
        let (root, mut checkpoint) = fixture();
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let root_value: Value = serde_json::from_slice(&root).unwrap();
        let id = root_value["signatures"][0]["keyid"].as_str().unwrap();
        let decode = |o: &Observation| -> Value {
            serde_json::from_slice(&STANDARD.decode(&o.bytes).unwrap()).unwrap()
        };
        let mut top = decode(&checkpoint.observations[2]);
        let delegated = signed(top["signed"].clone(), &key, id);
        top["signed"]["targets"] = json!({});
        top["signed"]["delegations"] = json!({"keys":root_value["signed"]["keys"],"roles":[{"name":"public","keyids":[id],"threshold":1,"paths":[TARGET],"terminating":true}]});
        let top = signed(top["signed"].clone(), &key, id);
        let mut snapshot = decode(&checkpoint.observations[1]);
        snapshot["signed"]["meta"]["targets.json"] =
            json!({"version":1,"length":top.len(),"hashes":{"sha256":crate::sha256(&top)}});
        snapshot["signed"]["meta"]["public.json"] = json!({"version":1,"length":delegated.len(),"hashes":{"sha256":crate::sha256(&delegated)}});
        let snapshot = signed(snapshot["signed"].clone(), &key, id);
        let mut timestamp = decode(&checkpoint.observations[0]);
        timestamp["signed"]["meta"]["snapshot.json"] = json!({"version":1,"length":snapshot.len(),"hashes":{"sha256":crate::sha256(&snapshot)}});
        let timestamp = signed(timestamp["signed"].clone(), &key, id);
        checkpoint.observations[0].bytes = STANDARD.encode(timestamp);
        checkpoint.observations[1].bytes = STANDARD.encode(snapshot);
        checkpoint.observations[2].bytes = STANDARD.encode(top);
        checkpoint.observations.push(Observation {
            name: "public.json".into(),
            bytes: STANDARD.encode(delegated),
            verified_at: checkpoint.verified_at,
        });
        assert!(
            checkpoint
                .verify_with_anchor(&root)
                .unwrap()
                .active()
                .is_ok()
        );
        checkpoint.observations.pop();
        assert!(checkpoint.verify_with_anchor(&root).is_err());
    }
    #[test]
    fn in_flight_job_keeps_its_checkpoint_and_expiry_is_still_enforced() {
        let (root, checkpoint) = fixture();
        let manager = Manager::default();
        manager.inner.lock().unwrap().active = Some(Arc::new(
            checkpoint
                .verify_with_anchor(&root)
                .unwrap()
                .active()
                .unwrap(),
        ));
        let mut pinned = manager.active().unwrap();
        manager.inner.lock().unwrap().active = None;
        assert!(manager.active().is_err());
        assert!(pinned.check().is_ok());
        Arc::get_mut(&mut pinned).unwrap().expiry = 0;
        assert!(pinned.check().is_err());
    }
    #[test]
    fn first_scrape_includes_zero_counters() {
        let metrics = crate::metrics::render();
        assert!(metrics.contains("operation=\"trust_commit\",outcome=\"failure\""));
        assert!(
            Manager::default()
                .metrics()
                .contains("bathysign_trust_ready{authority=\"sigstore-public\"} 0")
        );
    }
}

#[cfg(test)]
#[path = "../tests/unit/trust.rs"]
mod refresh_tests;
