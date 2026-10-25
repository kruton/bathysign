use crate::{
    config::Loaded,
    ledger::{Job, Ledger, profile_job_id},
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
#[derive(Clone)]
struct App {
    loaded: Arc<Loaded>,
    ledger: Ledger,
    webhook: Arc<zeroize::Zeroizing<Vec<u8>>>,
    trust: Option<crate::trust::Manager>,
    policy_ready: Arc<std::sync::atomic::AtomicBool>,
}

fn failure_diagnostic(error: &anyhow::Error) -> Value {
    // Only typed metadata is safe here: error messages and contexts can contain
    // signed artifact URLs, authorization headers, or credential paths.
    let transport = error
        .chain()
        .find_map(|e| e.downcast_ref::<reqwest::Error>());
    let io = error
        .chain()
        .find_map(|e| e.downcast_ref::<std::io::Error>());
    let status = error
        .chain()
        .find_map(|e| e.downcast_ref::<crate::github::HttpFailure>().map(|e| e.0))
        .or_else(|| transport.and_then(|e| e.status()).map(|s| s.as_u16()));
    json!({
        "http_status": status,
        "timeout": transport.is_some_and(|e| e.is_timeout()),
        "connect": transport.is_some_and(|e| e.is_connect()),
        "request": transport.is_some_and(|e| e.is_request()),
        "body": transport.is_some_and(|e| e.is_body()),
        "io_kind": io.map(|e| format!("{:?}", e.kind())),
    })
}

async fn webhook(
    State(app): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<(StatusCode, Json<Value>), (StatusCode, &'static str)> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut observation = crate::metrics::Stage::new("webhook");
    let supplied = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("sha256="))
        .and_then(|v| hex::decode(v).ok())
        .ok_or((StatusCode::UNAUTHORIZED, "webhook authentication failed"))?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&app.webhook).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authentication unavailable",
        )
    })?;
    hmac.update(&body);
    hmac.verify_slice(&supplied)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "webhook authentication failed"))?;
    observation.next("webhook_dispatch");
    if headers.get("x-github-event").and_then(|h| h.to_str().ok()) == Some("ping") {
        observation.complete();
        return Ok((StatusCode::OK, Json(json!({"ok":true}))));
    }
    if headers.get("x-github-event").and_then(|h| h.to_str().ok()) != Some("workflow_run") {
        observation.complete();
        return Ok((StatusCode::OK, Json(json!({"ignored":true}))));
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid JSON"))?;
    if value["action"] != "completed" || value["workflow_run"]["conclusion"] != "success" {
        observation.complete();
        return Ok((StatusCode::OK, Json(json!({"ignored":true}))));
    }
    let repo_id = value["repository"]["id"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "repository ID missing"))?;
    let repo = app
        .loaded
        .config
        .repositories
        .iter()
        .find(|r| r.id == repo_id)
        .ok_or((StatusCode::FORBIDDEN, "repository not eligible"))?;
    if value["repository"]["full_name"] != repo.name {
        return Err((StatusCode::FORBIDDEN, "workflow not eligible"));
    }
    let workflow_path = value["workflow"]["path"]
        .as_str()
        .ok_or((StatusCode::FORBIDDEN, "workflow not eligible"))?;
    // GitHub sends every workflow completion to the App. Finalizers and
    // unrelated CI workflows are expected events, not failed signing requests.
    if !repo.allows_caller(workflow_path) {
        observation.complete();
        return Ok((StatusCode::OK, Json(json!({"ignored":true}))));
    }
    if !app.policy_ready.load(std::sync::atomic::Ordering::Acquire)
        || app.trust.as_ref().is_some_and(|m| m.active().is_err())
    {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "trust is not ready"));
    }
    let run = &value["workflow_run"];
    let run_id = run["id"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "run ID missing"))?;
    let attempt = run["run_attempt"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "run attempt missing"))?;
    let commit = run["head_sha"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "commit missing"))?
        .to_string();
    let policy = app
        .loaded
        .policy_hash(repo)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "policy unavailable"))?;
    let mut jobs = vec![];
    for profile in repo.profiles.keys() {
        let job = Job {
            version: 2,
            profile: profile.clone(),
            id: profile_job_id(repo.id, run_id, attempt, profile, &policy),
            repository_id: repo.id,
            run_id,
            attempt,
            commit: commit.clone(),
            policy_hash: policy.clone(),
            revision: repo.revision,
        };
        app.ledger.enqueue(&job).await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "durable ledger unavailable",
            )
        })?;
        jobs.push(job.id);
    }
    observation.complete();
    Ok((StatusCode::ACCEPTED, Json(json!({"job_ids":jobs}))))
}
pub async fn serve_tls(
    router: Router,
    listen: &str,
    certificate: &Path,
    private_key: &Path,
) -> Result<()> {
    let certificate_pem = tokio::fs::read(certificate).await?;
    let certs = rustls_pemfile::certs(&mut certificate_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let private_key_pem = zeroize::Zeroizing::new(tokio::fs::read(private_key).await?);
    let key = rustls_pemfile::private_key(&mut private_key_pem.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("TLS key missing"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let limit = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(tls)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream))
                    .await
            {
                let service = hyper_util::service::TowerToHyperService::new(router);
                let mut http = hyper::server::conn::http1::Builder::new();
                http.timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(std::time::Duration::from_secs(10));
                // Bound incomplete request bodies and idle keep-alive connections too.
                let connection = http.serve_connection(hyper_util::rt::TokioIo::new(tls), service);
                if let Ok(Ok(parts)) = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    connection.without_shutdown(),
                )
                .await
                {
                    // Hermit's nonblocking socket Drop aborts pending TCP writes.
                    // Keep the stream alive through TLS close_notify and the peer's
                    // EOF so multi-record responses reach connection-closing clients.
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut tls = parts.io.into_inner();
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                        tls.shutdown().await?;
                        let mut discard = [0; 1024];
                        while tls.read(&mut discard).await? != 0 {}
                        Ok::<_, std::io::Error>(())
                    })
                    .await;
                }
            }
        });
    }
}
pub async fn run(loaded: Loaded) -> Result<()> {
    use rand::RngCore;
    let mut entropy = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut entropy)?;
    ensure!(entropy.iter().any(|b| *b != 0), "entropy unavailable");
    let ledger = Ledger::new(&loaded.config)?;
    let dynamic = loaded.config.trust_authority.is_some();
    if !dynamic {
        crate::pipeline::activate(&loaded, &ledger).await?;
    }
    let policy_ready = Arc::new(std::sync::atomic::AtomicBool::new(!dynamic));
    let webhook_secret = Arc::new(crate::config::read_secret(&loaded.config.webhook_secret)?);
    let loaded = Arc::new(loaded);
    let trust = loaded.config.trust_authority.as_ref().map(|authority| {
        let manager = crate::trust::Manager::default();
        tokio::spawn(manager.clone().run(ledger.clone(), authority.clone()));
        manager
    });
    let state = App {
        loaded: loaded.clone(),
        ledger: ledger.clone(),
        webhook: webhook_secret,
        trust,
        policy_ready,
    };
    let worker = state.clone();
    tokio::spawn(async move {
        loop {
            if !worker
                .policy_ready
                .load(std::sync::atomic::Ordering::Acquire)
            {
                if crate::pipeline::activate(&worker.loaded, &worker.ledger)
                    .await
                    .is_ok()
                {
                    worker
                        .policy_ready
                        .store(true, std::sync::atomic::Ordering::Release);
                } else {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
            let active = match &worker.trust {
                Some(manager) => match manager.active() {
                    Ok(active) => Some(active),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                },
                None => None,
            };
            match worker.ledger.claim().await {
                Ok(Some(claim)) => {
                    let _active = crate::metrics::ActiveJob::start();
                    if claim.attempt > 1 {
                        crate::metrics::observe("job_retry", true, std::time::Instant::now());
                    }
                    let heartbeat_ledger = worker.ledger.clone();
                    let heartbeat_claim = claim.clone();
                    let heartbeat = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            if heartbeat_ledger
                                .event(&heartbeat_claim, "lease.renewed", json!({}))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    let started = std::time::Instant::now();
                    let result = crate::pipeline::process_with_trust(
                        &worker.loaded,
                        &worker.ledger,
                        &claim,
                        active.as_deref(),
                    )
                    .await;
                    heartbeat.abort();
                    report_job(&worker, claim, result, started).await;
                }
                Ok(None) => {}
                Err(_) => tracing::warn!("audit collector unavailable; signing paused"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    let router = app_router(state);
    serve_tls(
        router,
        &loaded.config.listen,
        &loaded.config.tls_certificate,
        &loaded.config.tls_private_key,
    )
    .await
}

async fn report_job(
    worker: &App,
    claim: crate::ledger::Claimed,
    result: Result<()>,
    started: std::time::Instant,
) {
    crate::metrics::observe(
        match &result {
            Ok(()) => "job_complete",
            Err(error)
                if error.chain().any(|e| {
                    e.is::<reqwest::Error>()
                        || e.is::<std::io::Error>()
                        || e.downcast_ref::<crate::github::HttpFailure>()
                            .is_some_and(|h| h.retryable())
                }) =>
            {
                "job_transient"
            }
            Err(_) => "job_rejected",
        },
        result.is_ok(),
        started,
    );
    crate::metrics::observe("job", result.is_ok(), started);
    match result {
        Ok(()) => {
            let _ = worker.ledger.finish(&claim, "complete").await;
        }
        Err(error) => {
            // Signed download URLs and API credentials never enter logs or audit errors.
            let retry = error.chain().any(|e| {
                e.is::<reqwest::Error>()
                    || e.is::<std::io::Error>()
                    || e.downcast_ref::<crate::github::HttpFailure>()
                        .is_some_and(|h| h.retryable())
            });
            let kind = if retry {
                "transient"
            } else {
                "policy-or-verification"
            };
            let diagnostic = failure_diagnostic(&error);
            tracing::warn!(job=%claim.job.id,kind,diagnostic=%diagnostic,"job did not complete");
            if worker
                .ledger
                .event(
                    &claim,
                    "job.failed",
                    json!({"kind":kind,"diagnostic":diagnostic}),
                )
                .await
                .is_ok()
            {
                let _ = worker
                    .ledger
                    .finish(&claim, if retry { "retry" } else { "rejected" })
                    .await;
            }
        }
    }
}

fn app_router(state: App) -> Router {
    Router::new()
        .route("/webhooks/github", post(webhook))
        .route("/metrics", get(|State(app): State<App>| async move {
            let mut body = crate::metrics::render();
            if let Some(trust) = &app.trust { body.push_str(&trust.metrics()); }
            if app.trust.is_none() {
            let expiry = app.loaded.config.trust_roots.values().map(|t| t.valid_until).min().unwrap_or(0);
            body.push_str(&format!("# HELP bathysign_trust_root_expiry_timestamp_seconds Earliest trust root expiry.\n# TYPE bathysign_trust_root_expiry_timestamp_seconds gauge\nbathysign_trust_root_expiry_timestamp_seconds {expiry}\n"));
            }
            crate::metrics::response(body)
        }))
        .route("/healthz", get(|| async { Json(json!({"ok":true})) }))
        .route(
            "/readyz",
            get(|State(app): State<App>| async move {
                if !app.policy_ready.load(std::sync::atomic::Ordering::Acquire) || app.trust.as_ref().is_some_and(|m| m.active().is_err()) { return StatusCode::SERVICE_UNAVAILABLE; }
                if app.loaded.config.trust_roots.values().any(|t| {
                    crate::config::now().is_err()
                        || t.valid_until <= crate::config::now().unwrap_or(u64::MAX)
                }) {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
                if app.ledger.ping().await.is_ok() {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        )
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

/// Explicit provisioning export: no signing policy, keys, queue or GitHub client.
/// Invalid operational configuration never falls back to this mode.
pub async fn provisioning(path: &Path) -> Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bootstrap {
        listen: String,
        tls_certificate: std::path::PathBuf,
        tls_private_key: std::path::PathBuf,
    }
    let bootstrap: Bootstrap = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    tracing::warn!(
        "Provisioning only: signing disabled; configure GitHub App and durable collector"
    );
    let router = Router::new()
        .route(
            "/healthz",
            get(|| async {
                Json(json!({"ok":true,"mode":"provisioning","signing_enabled":false}))
            }),
        )
        .route("/readyz", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        .route(
            "/webhooks/github",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        )
        .layer(DefaultBodyLimit::max(256 * 1024));
    serve_tls(
        router,
        &bootstrap.listen,
        &bootstrap.tls_certificate,
        &bootstrap.tls_private_key,
    )
    .await
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn diagnostics_preserve_status_and_io_kind_without_sensitive_context() {
        let http = anyhow::Error::new(crate::github::HttpFailure(502))
            .context("https://example.invalid/private?signature=DO_NOT_LOG");
        let diagnostic = failure_diagnostic(&http);
        assert_eq!(diagnostic["http_status"], 502);
        assert!(!diagnostic.to_string().contains("DO_NOT_LOG"));

        let io = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "credential file /private/DO_NOT_LOG",
        ));
        let diagnostic = failure_diagnostic(&io);
        assert_eq!(diagnostic["io_kind"], "BrokenPipe");
        assert!(!diagnostic.to_string().contains("DO_NOT_LOG"));

        crate::initialize_test_crypto();
        let transport = reqwest::Client::new()
            .get("https://example.invalid/private?signature=DO_NOT_LOG")
            .header("invalid\nheader", "DO_NOT_LOG")
            .build()
            .unwrap_err();
        let diagnostic = failure_diagnostic(&transport.into());
        assert!(!diagnostic.to_string().contains("DO_NOT_LOG"));
        assert!(!diagnostic.to_string().contains("example.invalid"));
    }
}

#[cfg(test)]
mod webhook_tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn headers(body: &[u8], secret: &[u8]) -> HeaderMap {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let mut headers = HeaderMap::new();
        headers.insert("x-github-event", "workflow_run".parse().unwrap());
        headers.insert(
            "x-hub-signature-256",
            format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
                .parse()
                .unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn unrelated_completions_are_successful_ignores_without_bypassing_policy() {
        crate::initialize_test_crypto();
        let directory = tempfile::tempdir().unwrap();
        let mut config: crate::config::Config =
            serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        config.audit_ca_certificate = directory.path().join("ca.pem");
        config.audit_token = directory.path().join("token");
        std::fs::write(&config.audit_ca_certificate, certificate.cert.pem()).unwrap();
        std::fs::write(
            &config.audit_token,
            "test-token-012345678901234567890123456789",
        )
        .unwrap();
        let repo = &config.repositories[0];
        let repo_id = repo.id;
        let repo_name = repo.name.clone();
        let approved_workflow = repo.callers[0].clone();
        let unrelated_workflow = ".github/workflows/signed-release.yml";
        assert!(!repo.allows_caller(unrelated_workflow));
        let ledger = Ledger::new(&config).unwrap();
        let app = App {
            loaded: Arc::new(Loaded {
                config,
                keys: Default::default(),
                lineages: Default::default(),
            }),
            ledger,
            webhook: Arc::new(zeroize::Zeroizing::new(vec![7; 32])),
            trust: Some(crate::trust::Manager::default()),
            policy_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let event = json!({"action":"completed","repository":{"id":repo_id,"full_name":repo_name},"workflow":{"path":unrelated_workflow},"workflow_run":{"conclusion":"success"}});
        let body = serde_json::to_vec(&event).unwrap();
        let dispatch_failures = || {
            crate::metrics::render().lines().find(|line| line.starts_with("bathysign_operations_total{operation=\"webhook_dispatch\",outcome=\"failure\"}")).map(str::to_owned)
        };
        let before = dispatch_failures();
        let (status, Json(response)) = webhook(
            State(app.clone()),
            headers(&body, &app.webhook),
            Bytes::from(body.clone()),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response, json!({"ignored":true}));
        assert_eq!(
            dispatch_failures(),
            before,
            "ignored deliveries must not increment failure metrics"
        );

        let error = webhook(
            State(app.clone()),
            headers(&body, b"incorrect-secret"),
            Bytes::from(body),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        for (field, value) in [
            ("id", json!(repo_id + 1)),
            ("full_name", json!("other/repository")),
        ] {
            let mut bad = event.clone();
            bad["repository"][field] = value;
            let body = serde_json::to_vec(&bad).unwrap();
            assert_eq!(
                webhook(
                    State(app.clone()),
                    headers(&body, &app.webhook),
                    Bytes::from(body)
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::FORBIDDEN
            );
        }
        let mut missing_path = event.clone();
        missing_path["workflow"] = json!({});
        let body = serde_json::to_vec(&missing_path).unwrap();
        assert_eq!(
            webhook(
                State(app.clone()),
                headers(&body, &app.webhook),
                Bytes::from(body)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );

        let mut eligible = event;
        eligible["workflow"]["path"] = json!(approved_workflow);
        let body = serde_json::to_vec(&eligible).unwrap();
        for policy_ready in [false, true] {
            app.policy_ready
                .store(policy_ready, std::sync::atomic::Ordering::Release);
            assert_eq!(
                webhook(
                    State(app.clone()),
                    headers(&body, &app.webhook),
                    Bytes::from(body.clone())
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::SERVICE_UNAVAILABLE,
                "approved workflows must still require ready policy and trust"
            );
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/server.rs"]
mod service_tests;
