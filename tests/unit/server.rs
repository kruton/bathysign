//! Exercise HTTP routes and durable job outcomes without real GitHub traffic.
use super::*;
use axum::{body::Body, extract::State as ExtractState, http::Request, response::Response};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct Collector {
    requests: Mutex<Vec<(String, Value)>>,
    unavailable: AtomicBool,
}
async fn collector(
    ExtractState(state): ExtractState<Arc<Collector>>,
    request: Request<Body>,
) -> Response {
    assert_eq!(request.headers()["authorization"], "Bearer test-token");
    let path = request.uri().path().to_string();
    let bytes = axum::body::to_bytes(request.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    state.requests.lock().unwrap().push((path, body));
    Response::builder()
        .status(if state.unavailable.load(Ordering::Relaxed) {
            503
        } else {
            200
        })
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap()
}
async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (origin, task)
}
async fn fixture() -> (App, Arc<Collector>, tokio::task::JoinHandle<()>) {
    crate::initialize_test_crypto();
    let collector_state = Arc::new(Collector::default());
    let (origin, task) = serve(
        Router::new()
            .fallback(collector)
            .with_state(collector_state.clone()),
    )
    .await;
    let mut config: crate::config::Config =
        serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap();
    for root in config.trust_roots.values_mut() {
        root.valid_until = crate::config::now().unwrap() + 3600;
    }
    (
        App {
            loaded: Arc::new(Loaded {
                config,
                keys: Default::default(),
                lineages: Default::default(),
            }),
            ledger: Ledger::local_test_client(&origin),
            webhook: Arc::new(zeroize::Zeroizing::new(vec![7; 32])),
            trust: None,
            policy_ready: Arc::new(AtomicBool::new(true)),
        },
        collector_state,
        task,
    )
}
fn signed_headers(body: &[u8], secret: &[u8], event: &str) -> HeaderMap {
    use hmac::{Hmac, KeyInit, Mac};
    let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
    hmac.update(body);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-hub-signature-256",
        format!("sha256={}", hex::encode(hmac.finalize().into_bytes()))
            .parse()
            .unwrap(),
    );
    headers.insert("x-github-event", event.parse().unwrap());
    headers
}
fn event(app: &App) -> Value {
    let repo = &app.loaded.config.repositories[0];
    json!({"action":"completed","repository":{"id":repo.id,"full_name":repo.name},"workflow":{"path":repo.callers[0]},"workflow_run":{"id":123,"run_attempt":2,"head_sha":"a".repeat(40),"conclusion":"success"}})
}
async fn deliver(
    app: &App,
    value: &Value,
) -> std::result::Result<(StatusCode, Json<Value>), (StatusCode, &'static str)> {
    let body = serde_json::to_vec(value).unwrap();
    webhook(
        State(app.clone()),
        signed_headers(&body, &app.webhook, "workflow_run"),
        Bytes::from(body),
    )
    .await
}

#[tokio::test]
async fn approved_completion_enqueues_one_immutable_job_per_profile() {
    let (app, ledger, task) = fixture().await;
    let (status, Json(response)) = deliver(&app, &event(&app)).await.unwrap();
    assert_eq!(status, StatusCode::ACCEPTED);
    let repo = &app.loaded.config.repositories[0];
    let policy = app.loaded.policy_hash(repo).unwrap();
    let requests = ledger.requests.lock().unwrap();
    assert_eq!(requests.len(), repo.profiles.len());
    for ((path, job), profile) in requests.iter().zip(repo.profiles.keys()) {
        assert_eq!(path, "/v1/jobs");
        assert_eq!(job["profile"], profile.as_str());
        assert_eq!(job["commit"], "a".repeat(40));
        assert_eq!(job["run_id"], 123);
        assert_eq!(job["attempt"], 2);
        assert_eq!(job["policy_hash"], policy);
        assert!(response["job_ids"].as_array().unwrap().contains(&job["id"]));
    }
    task.abort();
}

#[tokio::test]
async fn authenticated_webhooks_validate_required_fields_and_collector_readiness() {
    let (app, ledger, task) = fixture().await;
    let eligible = event(&app);
    for (pointer, expected) in [
        ("/repository/id", "repository ID missing"),
        ("/workflow_run/id", "run ID missing"),
        ("/workflow_run/run_attempt", "run attempt missing"),
        ("/workflow_run/head_sha", "commit missing"),
    ] {
        let mut bad = eligible.clone();
        *bad.pointer_mut(pointer).unwrap() = Value::Null;
        assert_eq!(
            deliver(&app, &bad).await.unwrap_err(),
            (StatusCode::BAD_REQUEST, expected)
        );
    }
    let mut bad = eligible.clone();
    bad["workflow"]["path"] = Value::Null;
    assert_eq!(
        deliver(&app, &bad).await.unwrap_err().0,
        StatusCode::FORBIDDEN
    );
    assert!(ledger.requests.lock().unwrap().is_empty());
    ledger.unavailable.store(true, Ordering::Relaxed);
    assert_eq!(
        deliver(&app, &eligible).await.unwrap_err().0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    task.abort();
}

#[tokio::test]
async fn webhook_authentication_precedes_json_parsing_and_event_dispatch() {
    let (app, ledger, task) = fixture().await;
    for value in [
        None,
        Some("sha1=00"),
        Some("sha256=not-hex"),
        Some("sha256=0000"),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert("x-hub-signature-256", value.parse().unwrap());
        }
        assert_eq!(
            webhook(
                State(app.clone()),
                headers,
                Bytes::from_static(b"invalid JSON")
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let body = b"not JSON";
    assert_eq!(
        webhook(
            State(app.clone()),
            signed_headers(body, &app.webhook, "workflow_run"),
            Bytes::from_static(body)
        )
        .await
        .unwrap_err()
        .0,
        StatusCode::BAD_REQUEST
    );
    for (event, expected) in [
        ("ping", json!({"ok":true})),
        ("push", json!({"ignored":true})),
    ] {
        assert_eq!(
            webhook(
                State(app.clone()),
                signed_headers(body, &app.webhook, event),
                Bytes::from_static(body)
            )
            .await
            .unwrap()
            .1
            .0,
            expected
        );
    }
    for (pointer, value) in [
        ("/action", json!("requested")),
        ("/workflow_run/conclusion", json!("failure")),
    ] {
        let mut ignored = event(&app);
        *ignored.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            deliver(&app, &ignored).await.unwrap().1.0,
            json!({"ignored":true})
        );
    }
    assert!(ledger.requests.lock().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn operational_routes_expose_readiness_and_trust_without_accepting_oversized_webhooks() {
    let (app, collector, task) = fixture().await;
    let (origin, server) = serve(app_router(app.clone())).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(
        client
            .get(format!("{origin}/healthz"))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!({"ok":true})
    );
    assert_eq!(
        client
            .get(format!("{origin}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(
        collector
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path == "/v1/health")
    );
    let metrics = client
        .get(format!("{origin}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("bathysign_trust_root_expiry_timestamp_seconds"));
    app.policy_ready.store(false, Ordering::Release);
    assert_eq!(
        client
            .get(format!("{origin}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    app.policy_ready.store(true, Ordering::Release);
    collector.unavailable.store(true, Ordering::Relaxed);
    assert_eq!(
        client
            .get(format!("{origin}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let oversized = client
        .post(format!("{origin}/webhooks/github"))
        .body(vec![0; 256 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    server.abort();
    task.abort();
    collector.unavailable.store(false, Ordering::Relaxed);
    collector.requests.lock().unwrap().clear();
    let mut config = app.loaded.config.clone();
    for root in config.trust_roots.values_mut() {
        root.valid_until = 0;
    }
    let expired = App {
        loaded: Arc::new(Loaded {
            config,
            keys: Default::default(),
            lineages: Default::default(),
        }),
        ..app.clone()
    };
    let (origin, server) = serve(app_router(expired)).await;
    assert_eq!(
        client
            .get(format!("{origin}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(collector.requests.lock().unwrap().is_empty());
    server.abort();
    let dynamic = App {
        trust: Some(crate::trust::Manager::default()),
        ..app
    };
    let (origin, server) = serve(app_router(dynamic)).await;
    assert_eq!(
        client
            .get(format!("{origin}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let metrics = client
        .get(format!("{origin}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!metrics.contains("bathysign_trust_root_expiry_timestamp_seconds"));
    server.abort();
}

fn claim() -> crate::ledger::Claimed {
    crate::ledger::Claimed {
        job: Job {
            version: 2,
            profile: "default".into(),
            id: "test-job".into(),
            repository_id: 42,
            run_id: 123,
            attempt: 2,
            commit: "a".repeat(40),
            policy_hash: "b".repeat(64),
            revision: 1,
        },
        lease: "lease-123".into(),
        attempt: 1,
    }
}

#[tokio::test]
async fn job_outcomes_distinguish_retryable_errors_and_log_only_safe_diagnostics() {
    let (app, collector, task) = fixture().await;
    report_job(&app, claim(), Ok(()), std::time::Instant::now()).await;
    {
        let records = collector.requests.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "/v1/jobs/test-job/finish");
        assert_eq!(records[0].1["status"], "complete");
    }
    let request_error = reqwest::Client::new()
        .get("https://example.invalid/SENSITIVE_URL")
        .header("bad\nheader", "SENSITIVE_TOKEN")
        .build()
        .unwrap_err();
    for (error, retry) in [
        (anyhow::Error::new(crate::github::HttpFailure(503)), true),
        (anyhow::Error::new(crate::github::HttpFailure(401)), true),
        (anyhow::Error::new(crate::github::HttpFailure(404)), false),
        (anyhow::anyhow!("policy SENSITIVE_TOKEN"), false),
        (
            anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "SENSITIVE_URL",
            )),
            true,
        ),
        (anyhow::Error::new(request_error), true),
    ] {
        collector.requests.lock().unwrap().clear();
        report_job(
            &app,
            claim(),
            Err(error.context("SENSITIVE_CONTEXT")),
            std::time::Instant::now(),
        )
        .await;
        let requests = collector.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].1["kind"], "job.failed");
        assert_eq!(
            requests[0].1["data"]["kind"],
            if retry {
                "transient"
            } else {
                "policy-or-verification"
            }
        );
        assert_eq!(
            requests[1].1["status"],
            if retry { "retry" } else { "rejected" }
        );
        assert!(
            !serde_json::to_string(&*requests)
                .unwrap()
                .contains("SENSITIVE")
        );
    }
    collector.requests.lock().unwrap().clear();
    collector.unavailable.store(true, Ordering::Relaxed);
    report_job(
        &app,
        claim(),
        Err(anyhow::anyhow!("invalid artifact")),
        std::time::Instant::now(),
    )
    .await;
    let requests = collector.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "finish must not bypass a failed durable audit event"
    );
    assert_eq!(requests[0].0, "/v1/jobs/test-job/events");
    task.abort();
}

#[tokio::test]
async fn provisioning_exposes_no_operational_signing_routes() {
    crate::initialize_test_crypto();
    let directory = tempfile::tempdir().unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&certificate, identity.cert.pem()).unwrap();
    std::fs::write(&key, identity.signing_key.serialize_pem()).unwrap();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let path = directory.path().join("provisioning.json");
    std::fs::write(&path, serde_json::to_vec(&json!({"listen":address.to_string(),"tls_certificate":certificate,"tls_private_key":key})).unwrap()).unwrap();
    let config_path = path.clone();
    let server = tokio::spawn(async move { provisioning(&config_path).await.unwrap() });
    let client = crate::network::client_builder()
        .unwrap()
        .no_proxy()
        .add_root_certificate(
            reqwest::Certificate::from_pem(identity.cert.pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap();
    let origin = format!("https://localhost:{}", address.port());
    let mut ready = None;
    for _ in 0..40 {
        match client.get(format!("{origin}/healthz")).send().await {
            Ok(response) => {
                ready = Some(response);
                break;
            }
            Err(error) if error.is_connect() => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await
            }
            Err(error) => panic!("provisioning TLS failure: {error}"),
        }
    }
    assert!(
        crate::network::client_builder()
            .unwrap()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("{origin}/healthz"))
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        ready
            .expect("provisioning server did not start")
            .json::<Value>()
            .await
            .unwrap(),
        json!({"ok":true,"mode":"provisioning","signing_enabled":false})
    );
    assert_eq!(
        client
            .get(format!("{origin}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        client
            .post(format!("{origin}/webhooks/github"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["keys"] = json!({});
    std::fs::write(&path, config.to_string()).unwrap();
    assert!(
        provisioning(&path).await.is_err(),
        "operational fields cannot be silently accepted in provisioning mode"
    );
    std::fs::write(&key, b"no private key").unwrap();
    assert!(
        serve_tls(Router::new(), &address.to_string(), &certificate, &key)
            .await
            .unwrap_err()
            .to_string()
            .contains("TLS key missing")
    );
}
