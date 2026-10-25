#![cfg(feature = "collector")]
//! Public collector routes against a real durable SQLite ledger.
use bathysign::{
    collector::{Store, router},
    ledger::{Activation, Claimed, History, Job, profile_job_id},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Once};

const TOKEN: &str = "01234567890123456789012345678901";
struct Server {
    _directory: tempfile::TempDir,
    store: Store,
    client: reqwest::Client,
    origin: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start() -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(|| bathysign::initialize_crypto().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(&directory.path().join("audit.sqlite"), TOKEN.as_bytes()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let routes = router(store.clone());
        let task = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        Self {
            _directory: directory,
            store,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            origin,
            task,
        }
    }
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}{path}", self.origin))
            .bearer_auth(TOKEN)
    }
    fn post(&self, path: &str, body: Value) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}{path}", self.origin))
            .bearer_auth(TOKEN)
            .json(&body)
    }
}
fn activation() -> Activation {
    Activation {
        version: 2,
        repository_id: 42,
        revision: 1,
        policy_hash: "a".repeat(64),
        profiles: BTreeMap::from([(
            "default".into(),
            History {
                classical_history: vec!["b".repeat(64)],
                hybrid_history: vec![],
            },
        )]),
    }
}
fn job() -> Job {
    Job {
        version: 2,
        repository_id: 42,
        revision: 1,
        policy_hash: "a".repeat(64),
        id: profile_job_id(42, 123, 2, "default", &"a".repeat(64)),
        profile: "default".into(),
        run_id: 123,
        attempt: 2,
        commit: "c".repeat(40),
    }
}

#[test]
fn collector_cli_validates_configuration_and_checkpoint_before_serving() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let database = directory.path().join("audit.sqlite");
    let config = directory.path().join("collector.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "listen": "127.0.0.1:0",
            "tls_certificate": directory.path().join("missing-cert.pem"),
            "tls_private_key": directory.path().join("missing-key.pem"),
            "token_file": token,
            "database": database,
        }))
        .unwrap(),
    )
    .unwrap();
    let invoke = |args: &[&std::ffi::OsStr]| {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_bathysign-collector"))
            .env("BATHYSIGN_COLLECTOR_CONFIG", &config)
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        let diagnostic = String::from_utf8(result.stderr).unwrap();
        assert!(!diagnostic.contains(TOKEN));
        diagnostic
    };
    assert!(invoke(&[std::ffi::OsStr::new("unknown")]).contains("usage: collector"));
    let mut checkpoint: Value = serde_json::from_slice(include_bytes!(
        "../bathysign/tests/fixtures/trust-checkpoint.json"
    ))
    .unwrap();
    checkpoint["generation"] = json!(2);
    let path = directory.path().join("checkpoint.json");
    std::fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(
        invoke(&[std::ffi::OsStr::new("initialize-trust"), path.as_os_str()])
            .contains("initial checkpoint required")
    );
    let store = Store::open(&database, TOKEN.as_bytes()).unwrap();
    assert!(store.trust_checkpoint("sigstore-public", None).is_err());
    // Normal startup creates the runtime, then fails closed on missing TLS material.
    assert!(invoke(&[]).contains("No such file"));
    std::fs::write(&config, b"{}").unwrap();
    assert!(invoke(&[]).contains("missing field"));
}

#[tokio::test]
async fn complete_authenticated_job_lifecycle_is_durable_and_inspectable() {
    let server = Server::start().await;
    assert_eq!(
        server
            .client
            .get(format!("{}/v1/health", server.origin))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        server
            .get("/v1/health")
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!({"ok":true})
    );
    assert_eq!(
        server
            .post("/v1/policies", serde_json::to_value(activation()).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let job = job();
    for _ in 0..2 {
        assert_eq!(
            server
                .post("/v1/jobs", serde_json::to_value(&job).unwrap())
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let claim: Claimed = server
        .post("/v1/claim", json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(claim.job, job);
    assert_eq!(claim.attempt, 1);
    assert_eq!(claim.lease.len(), 64);
    assert!(
        server
            .post("/v1/claim", json!({}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
            .is_null()
    );
    let event = format!("/v1/jobs/{}/events", job.id);
    assert_eq!(
        server
            .post(
                &event,
                json!({"lease":claim.lease,"kind":"sign.intent","data":{"operation":"apk"}})
            )
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let inspect = server
        .get(&format!("/v1/jobs/{}", job.id))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(inspect["status"], "running");
    assert!(inspect.to_string().contains("sign.intent"));
    let finish = format!("/v1/jobs/{}/finish", job.id);
    assert_eq!(
        server
            .post(&finish, json!({"lease":claim.lease,"status":"complete"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(server.store.inspect(&job.id).unwrap()["status"], "complete");
    assert_eq!(
        server
            .post(
                &event,
                json!({"lease":claim.lease,"kind":"sign.intent","data":{}})
            )
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let metrics = server
        .get("/metrics")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("bathysign_ledger_jobs{status=\"complete\"} 1"));
    assert!(metrics.contains("bathysign_ledger_events_total{kind=\"sign.intent\"} 1"));
}

#[tokio::test]
async fn authentication_stale_leases_and_invalid_jobs_never_mutate_the_ledger() {
    let server = Server::start().await;
    server.store.activate(&activation()).unwrap();
    let job = job();
    server.store.enqueue(&job).unwrap();
    let claim = server.store.claim().unwrap().unwrap();
    for path in [
        "/v1/health",
        "/metrics",
        "/v1/jobs/anything",
        "/v1/trust/sigstore-public/head",
        "/v1/trust/sigstore-public/checkpoints/digest",
    ] {
        assert_eq!(
            server
                .client
                .get(format!("{}{path}", server.origin))
                .bearer_auth("wrong-token")
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    for (path, body) in [
        (
            "/v1/policies".into(),
            serde_json::to_value(activation()).unwrap(),
        ),
        ("/v1/jobs".into(), serde_json::to_value(&job).unwrap()),
        ("/v1/claim".into(), json!({})),
        (
            format!("/v1/jobs/{}/events", job.id),
            json!({"lease":claim.lease,"kind":"event","data":{}}),
        ),
        (
            format!("/v1/jobs/{}/finish", job.id),
            json!({"lease":claim.lease,"status":"complete"}),
        ),
    ] {
        assert_eq!(
            server
                .client
                .post(format!("{}{path}", server.origin))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    assert_eq!(
        server
            .post(
                &format!("/v1/jobs/{}/events", job.id),
                json!({"lease":"wrong","kind":"sign.intent","data":{}})
            )
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        server
            .post(
                &format!("/v1/jobs/{}/finish", job.id),
                json!({"lease":claim.lease,"status":"published"})
            )
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let mut stale = job.clone();
    stale.revision = 2;
    assert_eq!(
        server
            .post("/v1/jobs", serde_json::to_value(stale).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(server.store.inspect(&job.id).unwrap()["status"], "running");
    let response = server.get("/v1/jobs/not-present").send().await.unwrap();
    assert_eq!(response.status(), 409);
    assert_eq!(response.text().await.unwrap(), "ledger operation rejected");
}

#[tokio::test]
async fn trust_routes_validate_input_and_cannot_initialize_an_empty_auditor() {
    let server = Server::start().await;
    let raw = include_bytes!("../bathysign/tests/fixtures/trust-checkpoint.json");
    let checkpoint: bathysign::trust::Checkpoint = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        server
            .get("/v1/trust/sigstore-public/head")
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        server
            .get("/v1/trust/sigstore-public/checkpoints/missing")
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        server
            .post("/v1/trust/sigstore-public/checkpoints", json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        server
            .post(
                "/v1/trust/another-authority/checkpoints",
                serde_json::to_value(&checkpoint).unwrap()
            )
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        server
            .post(
                "/v1/trust/sigstore-public/checkpoints",
                serde_json::to_value(&checkpoint).unwrap()
            )
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert!(
        server
            .store
            .trust_checkpoint("sigstore-public", None)
            .is_err()
    );
    let oversized = server
        .client
        .post(format!("{}/v1/jobs", server.origin))
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .body(vec![b' '; 4 * 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
}
