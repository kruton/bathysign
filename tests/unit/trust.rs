//! Real TUF refresh verification with a deterministic local repository.
use super::*;
use serde_json::{Value, json};

struct MemoryRepository {
    metadata: BTreeMap<String, Vec<u8>>,
    target: Vec<u8>,
    offline: bool,
    corrupt_target: bool,
}
impl MemoryRepository {
    fn fixture(checkpoint: &Checkpoint) -> Self {
        Self {
            metadata: checkpoint
                .observations
                .iter()
                .map(|o| (o.name.clone(), STANDARD.decode(&o.bytes).unwrap()))
                .collect(),
            target: STANDARD
                .decode(checkpoint.target.as_ref().unwrap())
                .unwrap(),
            offline: false,
            corrupt_target: false,
        }
    }
}
impl Repository for MemoryRepository {
    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
        max: u64,
    ) -> sigstore_tuf::transport::FetchFuture<'a> {
        Box::pin(async move {
            if self.offline {
                return Err(sigstore_tuf::Error::transport_with_source(
                    "mirror unavailable",
                    crate::github::HttpFailure(503),
                ));
            }
            let bytes = self.metadata.get(name).cloned();
            assert!(bytes.as_ref().is_none_or(|b| b.len() as u64 <= max));
            Ok(bytes)
        })
    }
    fn fetch_target<'a>(
        &'a self,
        path: &'a str,
        max: u64,
    ) -> sigstore_tuf::transport::FetchFuture<'a> {
        Box::pin(async move {
            assert_eq!(path, TARGET);
            assert!(self.target.len() as u64 <= max);
            Ok(Some(if self.corrupt_target {
                b"untrusted target".to_vec()
            } else {
                self.target.clone()
            }))
        })
    }
}

#[tokio::test]
async fn fresh_refresh_authenticates_metadata_and_records_a_complete_checkpoint() {
    let (anchor, expected) = super::tests::fixture();
    let repository = MemoryRepository::fixture(&expected);
    let result = refresh_from(None, &expected.authority, &anchor, |_| Ok(repository))
        .await
        .unwrap();
    assert!(result.complete);
    assert!(!result.network_failed);
    assert_eq!(result.checkpoint.generation, 1);
    assert!(result.checkpoint.previous.is_none());
    let verified = result.checkpoint.verify_with_anchor(&anchor).unwrap();
    assert_eq!(verified.versions, [1, 1, 1, 1]);
    assert_eq!(
        verified.binding().unwrap()["target_sha256"],
        crate::sha256(&STANDARD.decode(expected.target.unwrap()).unwrap())
    );
    assert!(verified.active().unwrap().check().is_ok());
}

#[tokio::test]
async fn unchanged_valid_cache_can_cover_a_transient_mirror_failure() {
    let (anchor, seed) = super::tests::fixture();
    let fresh = MemoryRepository::fixture(&seed);
    let previous = refresh_from(None, &seed.authority, &anchor, |_| Ok(fresh))
        .await
        .unwrap()
        .checkpoint;
    let mut repository = MemoryRepository::fixture(&previous);
    repository.offline = true;
    let result = refresh_from(Some(&previous), &previous.authority, &anchor, |_| {
        Ok(repository)
    })
    .await
    .unwrap();
    assert!(result.complete);
    assert!(result.network_failed);
    assert_eq!(result.checkpoint, previous);
}

#[tokio::test]
async fn newly_observed_metadata_cannot_fall_back_to_an_older_target_on_failure() {
    let (anchor, previous) = super::tests::fixture();
    let mut repository = MemoryRepository::fixture(&previous);
    let mut timestamp: Value =
        serde_json::from_slice(&repository.metadata["timestamp.json"]).unwrap();
    timestamp["signed"]["version"] = json!(2);
    timestamp["signed"]["meta"]["snapshot.json"]["version"] = json!(2);
    let root: Value = serde_json::from_slice(&anchor).unwrap();
    let id = root["signed"]["keys"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap();
    let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    repository.metadata.insert(
        "timestamp.json".into(),
        super::tests::signed(timestamp["signed"].clone(), &key, id),
    );
    repository.metadata.remove("snapshot.json");
    let result = refresh_from(Some(&previous), &previous.authority, &anchor, |_| {
        Ok(repository)
    })
    .await
    .unwrap();
    assert!(!result.complete);
    assert!(!result.checkpoint.usable);
    assert!(result.checkpoint.target.is_none());
    assert_eq!(result.checkpoint.generation, 2);
    assert_eq!(result.checkpoint.previous, Some(previous.digest().unwrap()));
    assert!(
        result
            .checkpoint
            .observations
            .starts_with(&previous.observations)
    );
    assert!(
        result
            .checkpoint
            .verify_with_anchor(&anchor)
            .unwrap()
            .active()
            .is_err()
    );
}

#[tokio::test]
async fn corrupt_target_or_bad_signatures_never_become_active_trust() {
    let (anchor, previous) = super::tests::fixture();
    let mut repository = MemoryRepository::fixture(&previous);
    repository.corrupt_target = true;
    let result = refresh_from(None, &previous.authority, &anchor, |_| Ok(repository))
        .await
        .unwrap();
    assert!(!result.complete);
    assert!(
        result
            .checkpoint
            .verify_with_anchor(&anchor)
            .unwrap()
            .active()
            .is_err()
    );
    let mut repository = MemoryRepository::fixture(&previous);
    repository.metadata.insert(
        "timestamp.json".into(),
        br#"{"signed":{},"signatures":[]}"#.to_vec(),
    );
    let result = refresh_from(None, &previous.authority, &anchor, |_| Ok(repository))
        .await
        .unwrap();
    assert!(!result.complete);
    assert!(!result.network_failed);
}

#[tokio::test]
async fn clock_rollback_and_unapproved_image_authorities_fail_before_fetching() {
    let (anchor, mut previous) = super::tests::fixture();
    previous.verified_at = crate::config::now().unwrap() + 3600;
    assert!(
        refresh_from(
            Some(&previous),
            &previous.authority,
            &anchor,
            |_| -> Result<MemoryRepository> { panic!("clock rollback must stop transport setup") }
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("clock precedes")
    );
    let mut invalid_previous = previous.clone();
    invalid_previous.authority.epoch = "not-an-epoch-hash".into();
    assert!(
        refresh_from(
            Some(&invalid_previous),
            &previous.authority,
            &anchor,
            |_| -> Result<MemoryRepository> {
                panic!("invalid restored authority must stop transport setup")
            }
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("invalid trust initialization epoch")
    );
    let mut authority = previous.authority.clone();
    authority.bootstrap_sha256 = "0".repeat(64);
    assert!(
        refresh(None, &authority)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("bootstrap differs from image")
    );
}

#[test]
fn recorded_metadata_preserves_history_without_duplicating_caches_or_unchanged_files() {
    let store = RecordingStore(Arc::new(Mutex::new(Recording {
        files: BTreeMap::new(),
        observations: vec![],
        now: 1234,
        error: false,
    })));
    for name in [
        "root.json",
        "1.snapshot.json",
        "targets/trusted_root.json",
        "timestamp.json",
    ] {
        store.store(name, b"accepted").unwrap();
    }
    store.store("timestamp.json", b"accepted").unwrap();
    assert_eq!(
        store.load("timestamp.json").unwrap(),
        Some(b"accepted".to_vec())
    );
    assert_eq!(store.load("missing.json").unwrap(), None);
    let saved = store.0.lock().unwrap();
    assert_eq!(saved.observations.len(), 1);
    assert_eq!(saved.observations[0].name, "timestamp.json");
    assert_eq!(saved.observations[0].verified_at, 1234);
}

#[test]
fn metadata_role_names_require_valid_encoding_and_decodable_utf8() {
    assert_eq!(
        decode_role("delegated%2Fstable.json").unwrap(),
        "delegated/stable"
    );
    for name in [
        "missing-suffix",
        "%2.json",
        "%GG.json",
        "%ff.json",
        "%.json",
    ] {
        assert!(decode_role(name).is_err());
    }
    assert!(time(u64::MAX).is_err());
}

#[tokio::test]
async fn http_transport_enforces_relative_paths_body_limits_and_history_capacity() {
    use axum::{Router, routing::get};
    crate::initialize_test_crypto();
    let store = RecordingStore(Arc::new(Mutex::new(Recording {
        files: BTreeMap::new(),
        observations: vec![],
        now: 1234,
        error: false,
    })));
    let fixed = HttpRepository::new(store.clone()).unwrap();
    assert_eq!(fixed.mirror, MIRROR);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mirror = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/timestamp.json", get(|| async { "metadata" }))
        .route("/targets/trusted_root.json", get(|| async { "target" }))
        .route(
            "/denied.json",
            get(|| async { (axum::http::StatusCode::FORBIDDEN, "denied") }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let repository = HttpRepository {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        recording: store.clone(),
        mirror,
    };
    assert_eq!(
        repository
            .fetch_metadata("timestamp.json", 100)
            .await
            .unwrap(),
        Some(b"metadata".to_vec())
    );
    assert_eq!(
        repository.fetch_target(TARGET, 100).await.unwrap(),
        Some(b"target".to_vec())
    );
    assert_eq!(
        repository
            .fetch_metadata("missing.json", 100)
            .await
            .unwrap(),
        None
    );
    assert!(repository.fetch_metadata("denied.json", 100).await.is_err());
    assert!(
        repository
            .fetch_metadata("timestamp.json", 1)
            .await
            .is_err()
    );
    for path in [
        "../timestamp.json",
        "/timestamp.json",
        "timestamp.json?x=1",
        "timestamp.json#x",
        "bad\\path",
    ] {
        assert!(repository.fetch_metadata(path, 100).await.is_err());
    }
    assert!(
        repository
            .fetch_metadata(&"x".repeat(1025), 100)
            .await
            .is_err()
    );
    // A retained history at capacity cannot accept another metadata version.
    store.0.lock().unwrap().observations.push(Observation {
        name: "x".repeat(MAX_STATE),
        bytes: String::new(),
        verified_at: 1234,
    });
    assert!(
        repository
            .fetch_metadata("timestamp.json", 100)
            .await
            .is_err()
    );
    // Identical cached bytes are safe even when no new history can fit.
    store
        .0
        .lock()
        .unwrap()
        .files
        .insert("timestamp.json".into(), b"metadata".to_vec());
    assert_eq!(
        repository
            .fetch_metadata("timestamp.json", 100)
            .await
            .unwrap(),
        Some(b"metadata".to_vec())
    );
    server.abort();
}

#[tokio::test]
async fn failed_ram_persistence_prevents_admitting_an_otherwise_valid_refresh() {
    let (anchor, expected) = super::tests::fixture();
    let repository = MemoryRepository::fixture(&expected);
    let result = refresh_from(None, &expected.authority, &anchor, |recording| {
        recording.0.lock().unwrap().error = true;
        Ok(repository)
    })
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("trust RAM store failed")
    );
}

#[test]
fn recording_store_capacity_failures_are_latched_for_the_refresh_gate() {
    let store = RecordingStore(Arc::new(Mutex::new(Recording {
        files: BTreeMap::new(),
        observations: vec![],
        now: 1234,
        error: false,
    })));
    assert!(
        store
            .store(
                "targets/oversized",
                &vec![0; MAX_STATE * 2 + MAX_TARGET + 1]
            )
            .is_err()
    );
    assert!(store.0.lock().unwrap().error);
}
