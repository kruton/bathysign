//! Signing transaction tests use real disposable keys and actual reference APKs.
use super::*;
use axum::{body::Body, extract::State, http::Request, response::Response};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Service {
    events: Vec<Value>,
    uploads: BTreeMap<String, Vec<u8>>,
    fail_intent: bool,
    artifacts: Vec<Value>,
    artifact_zip: Vec<u8>,
    artifact_downloads: usize,
    attestations: Vec<Value>,
    api: BTreeMap<String, Value>,
}
async fn endpoint(State(state): State<Arc<Mutex<Service>>>, request: Request<Body>) -> Response {
    if request.uri().path().starts_with("/repos/trusted/builders") {
        assert!(!request.headers().contains_key("authorization"));
    } else {
        assert_eq!(request.headers()["authorization"], "Bearer test-token");
    }
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let body = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let mut state = state.lock().unwrap();
    let result = if let Some(value) = state.api.get(&path) {
        value.clone()
    } else if path.ends_with("/artifacts") {
        json!({"artifacts":state.artifacts})
    } else if path.ends_with("/zip") {
        state.artifact_downloads += 1;
        return Response::builder()
            .body(Body::from(state.artifact_zip.clone()))
            .unwrap();
    } else if path.contains("/attestations/sha256:") {
        json!({"attestations":state.attestations})
    } else if path.ends_with("/events") {
        let event: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(event["lease"], "test-lease");
        let fail = state.fail_intent && event["kind"] == "sign.intent";
        state.events.push(event);
        if fail {
            return Response::builder()
                .status(503)
                .body(Body::from("collector unavailable"))
                .unwrap();
        }
        json!({})
    } else if path.ends_with("/releases") && method == reqwest::Method::GET {
        json!([])
    } else if path.ends_with("/releases") {
        let release: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(release["draft"], true);
        json!({"id": 10})
    } else if path.ends_with("/assets") && method == reqwest::Method::GET {
        json!([])
    } else if path.ends_with("/assets") {
        let name = reqwest::Url::parse(&format!("http://localhost/?{query}"))
            .unwrap()
            .query_pairs()
            .find(|(name, _)| name == "name")
            .unwrap()
            .1
            .to_string();
        let digest = crate::sha256(&body);
        let length = body.len();
        assert!(state.uploads.insert(name.clone(), body.to_vec()).is_none());
        json!({"id":state.uploads.len(),"name":name,"digest":format!("sha256:{digest}"),"size":length})
    } else {
        panic!("unexpected signing service endpoint: {path}")
    };
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(result.to_string()))
        .unwrap()
}

fn loaded_fixture() -> (tempfile::TempDir, Loaded, Claimed, VerifiedArtifacts) {
    crate::initialize_test_crypto();
    let directory = tempfile::tempdir().unwrap();
    let mut config: crate::config::Config =
        serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap();
    let mut keys = BTreeMap::new();
    for (role, spec) in &mut config.keys {
        let key = directory.path().join(format!("{role}.key"));
        let certificate = directory.path().join(format!("{role}.pem"));
        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            std::process::Command::new("openssl")
                .args(["req", "-new", "-x509", "-key"])
                .arg(&key)
                .args(["-out"])
                .arg(&certificate)
                .args(["-days", "2", "-subj", "/CN=Disposable-pipeline-test"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let signing = crate::crypto::SigningKey::load(&key, &certificate).unwrap();
        spec.private_key = key;
        spec.certificate = certificate;
        spec.fingerprint = signing.fingerprint();
        keys.insert(role.clone(), signing);
    }
    let apk_bytes = std::fs::read(
        std::env::var_os("BATHYSIGN_REFERENCE_APK")
            .expect("reference APK is required for this test"),
    )
    .unwrap();
    let aab_bytes = std::fs::read(
        std::env::var_os("BATHYSIGN_REFERENCE_AAB")
            .expect("reference AAB is required for this test"),
    )
    .unwrap();
    let entries = archive::read(&apk_bytes).unwrap();
    let identity = manifest::identity(&entries["AndroidManifest.xml"].bytes, false).unwrap();
    let repo = &mut config.repositories[0];
    let mut profile = repo.profiles.values().next().unwrap().clone();
    profile.package = identity.package;
    profile.archive_resource = None;
    let lineage = crate::lineage::Lineage::root(&keys[&profile.signing.original_key]);
    profile.signing.lineage_sha256 = lineage.digest().unwrap();
    repo.profiles = BTreeMap::from([("default".into(), profile)]);
    let repository_id = repo.id;
    let loaded = Loaded {
        config,
        keys,
        lineages: BTreeMap::from([((repository_id, "default".into()), (lineage, None))]),
    };
    let repo = &loaded.config.repositories[0];
    let claim = Claimed {
        job: crate::ledger::Job {
            version: 2,
            id: "test-job".into(),
            repository_id,
            profile: "default".into(),
            run_id: 7,
            attempt: 1,
            commit: "a".repeat(40),
            policy_hash: loaded.policy_hash(repo).unwrap(),
            revision: repo.revision,
        },
        lease: "test-lease".into(),
        attempt: 1,
    };
    let inputs = VerifiedArtifacts {
        apk_bytes,
        aab_bytes,
        apk_meta: json!({"id":11}),
        aab_meta: json!({"id":12}),
        apk_provenance: json!({"verified":true}),
        aab_provenance: json!({"verified":true}),
        apk_bundle: b"verified APK bundle".to_vec(),
        aab_bundle: b"verified AAB bundle".to_vec(),
    };
    (directory, loaded, claim, inputs)
}

// The ordinary unit-test command does not provision Android's reference tools.
// Coverage CI explicitly provisions these inputs before running the test suite.
fn reference_inputs_available() -> bool {
    std::env::var_os("BATHYSIGN_REFERENCE_APK").is_some()
        && std::env::var_os("BATHYSIGN_REFERENCE_AAB").is_some()
}

#[tokio::test]
async fn signing_outputs_are_verified_audited_and_uploaded_to_a_draft() {
    if !reference_inputs_available() {
        eprintln!("reference APK/AAB required: run scripts/test-android.py");
        return;
    }
    let (_directory, loaded, claim, inputs) = loaded_fixture();
    let state = Arc::new(Mutex::new(Service::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(endpoint)
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let github = Github::local_test_client(&origin);
    let ledger = Ledger::local_test_client(&origin);
    let repo = &loaded.config.repositories[0];
    OutputJob {
        loaded: &loaded,
        ledger: &ledger,
        claim: &claim,
        active: None,
        github: &github,
        repo,
        artifact_profile: &repo.profiles["default"],
    }
    .finish(inputs, crate::metrics::Stage::new("verify_inputs"))
    .await
    .unwrap();
    let saved = state.lock().unwrap().clone();
    assert_eq!(saved.uploads.len(), 9);
    let receipt_key = &loaded.keys[&repo.receipt_key];
    let receipt = crate::receipt::verify(
        &saved.uploads["signing-receipt.dsse.json"],
        &receipt_key.certificate,
        &receipt_key.fingerprint(),
    )
    .unwrap();
    assert_eq!(receipt["job"]["id"], claim.job.id);
    assert_eq!(receipt["job"]["policy_hash"], claim.job.policy_hash);
    for output in receipt["outputs"].as_array().unwrap() {
        assert_eq!(
            output["sha256"],
            crate::sha256(&saved.uploads[output["name"].as_str().unwrap()])
        );
    }
    if let Some(classpath) = std::env::var_os("BATHYSIGN_LEGACY_CLASSES") {
        let output = _directory.path().join("pipeline-signed.apk");
        let apk = saved.uploads["app-signed.apk"].clone();
        tokio::task::spawn_blocking(move || {
            std::fs::write(&output, apk).unwrap();
            let java = std::env::var_os("BATHYSIGN_JAVA").unwrap_or_else(|| "java".into());
            for sdk in [24, 33] {
                let verified = std::process::Command::new(&java)
                    .arg("-cp")
                    .arg(&classpath)
                    .args(["Reference", "apk"])
                    .arg(&output)
                    .arg(sdk.to_string())
                    .output()
                    .unwrap();
                assert!(
                    verified.status.success(),
                    "Android rejected the pipeline output: {}",
                    String::from_utf8_lossy(&verified.stderr)
                );
            }
        })
        .await
        .unwrap();
    }
    assert_eq!(saved.events[0]["kind"], "inputs.verified");
    let intents: Vec<_> = saved
        .events
        .iter()
        .filter(|event| event["kind"] == "sign.intent")
        .collect();
    assert!(
        intents
            .iter()
            .any(|event| event["data"]["operation"] == "code-transparency")
    );
    assert!(
        intents
            .iter()
            .any(|event| event["data"]["operation"] == "receipt-dsse")
    );
    assert_eq!(
        saved
            .events
            .iter()
            .filter(|event| event["kind"] == "upload.receipt")
            .count(),
        9
    );
    let verified = saved
        .events
        .iter()
        .position(|event| event["kind"] == "outputs.verified")
        .unwrap();
    let uploaded = saved
        .events
        .iter()
        .position(|event| event["kind"] == "upload.receipt")
        .unwrap();
    assert!(verified < uploaded);
    server.abort();
}

#[tokio::test]
async fn unavailable_audit_collector_prevents_signing_and_uploads() {
    if !reference_inputs_available() {
        return;
    }
    let (_directory, loaded, claim, inputs) = loaded_fixture();
    let state = Arc::new(Mutex::new(Service {
        fail_intent: true,
        ..Service::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(endpoint)
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let github = Github::local_test_client(&origin);
    let ledger = Ledger::local_test_client(&origin);
    let repo = &loaded.config.repositories[0];
    assert!(
        OutputJob {
            loaded: &loaded,
            ledger: &ledger,
            claim: &claim,
            active: None,
            github: &github,
            repo,
            artifact_profile: &repo.profiles["default"]
        }
        .finish(inputs, crate::metrics::Stage::new("verify_inputs"))
        .await
        .is_err()
    );
    let saved = state.lock().unwrap();
    assert!(saved.uploads.is_empty());
    assert_eq!(saved.events.len(), 2);
    assert_eq!(saved.events[1]["kind"], "sign.intent");
    assert!(
        !saved
            .events
            .iter()
            .any(|event| event["kind"] == "sign.result")
    );
    server.abort();
}

fn policy_fixture() -> Loaded {
    Loaded {
        config: serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap(),
        keys: BTreeMap::new(),
        lineages: BTreeMap::new(),
    }
}

#[tokio::test]
async fn ineligible_jobs_stop_before_contacting_github_or_loading_keys() {
    crate::initialize_test_crypto();
    let mut loaded = policy_fixture();
    let repo = &loaded.config.repositories[0];
    let mut claim = Claimed {
        job: crate::ledger::Job {
            version: 2,
            id: "test-job".into(),
            repository_id: repo.id,
            profile: repo.profiles.keys().next().unwrap().clone(),
            run_id: 7,
            attempt: 1,
            commit: "a".repeat(40),
            policy_hash: loaded.policy_hash(repo).unwrap(),
            revision: repo.revision,
        },
        lease: "lease".into(),
        attempt: 1,
    };
    let ledger = Ledger::local_test_client("http://127.0.0.1:1");
    let original = claim.clone();
    for (field, message) in [
        ("repo", "repository is not allowed"),
        ("version", "unsupported job version"),
        ("profile", "profile is not allowed"),
        ("policy", "stale signing policy"),
        ("revision", "stale signing policy"),
    ] {
        claim = original.clone();
        match field {
            "repo" => claim.job.repository_id = 0,
            "version" => claim.job.version = 1,
            "profile" => claim.job.profile = "unconfigured".into(),
            "policy" => claim.job.policy_hash = "stale".into(),
            "revision" => claim.job.revision += 1,
            _ => unreachable!(),
        }
        assert!(
            process(&loaded, &ledger, &claim)
                .await
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
    loaded.config.trust_authority = Some(crate::trust::Authority {
        authority: "unexpected".into(),
        bootstrap_sha256: "a".repeat(64),
        epoch: "epoch".into(),
        target: "root.json".into(),
    });
    assert!(
        process(&loaded, &ledger, &original)
            .await
            .unwrap_err()
            .to_string()
            .contains("job trust mode differs")
    );
}

#[tokio::test]
async fn artifact_cache_binds_run_repository_archive_digest_and_each_consumed_file() {
    crate::initialize_test_crypto();
    let loaded = policy_fixture();
    let repo = &loaded.config.repositories[0];
    let entries = BTreeMap::from([
        (
            "app.apk".into(),
            archive::Entry {
                bytes: b"APK".to_vec(),
                stored: true,
            },
        ),
        (
            "app.aab".into(),
            archive::Entry {
                bytes: b"AAB".to_vec(),
                stored: true,
            },
        ),
    ]);
    let zip = archive::write(&entries, false).unwrap();
    let metadata = json!({"id":44,"name":"unsigned-1","expired":false,"workflow_run":{"id":7,"head_sha":"commit","repository_id":repo.id},"digest":format!("sha256:{}",crate::sha256(&zip))});
    let state = Arc::new(Mutex::new(Service {
        artifacts: vec![metadata.clone()],
        artifact_zip: zip,
        ..Service::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(endpoint)
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let github = Github::local_test_client(&origin);
    let run = json!({"id":7,"run_attempt":1,"head_sha":"commit"});
    let mut cache = BTreeMap::new();
    assert_eq!(
        artifact(
            &github,
            repo,
            &run,
            "unsigned-{attempt}",
            "app.apk",
            &mut cache
        )
        .await
        .unwrap()
        .0,
        b"APK"
    );
    assert_eq!(
        artifact(
            &github,
            repo,
            &run,
            "unsigned-{attempt}",
            "app.aab",
            &mut cache
        )
        .await
        .unwrap()
        .0,
        b"AAB"
    );
    assert_eq!(state.lock().unwrap().artifact_downloads, 1);
    assert!(cache["unsigned-1"].is_empty());
    assert!(
        artifact(
            &github,
            repo,
            &run,
            "unsigned-{attempt}",
            "app.apk",
            &mut cache
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("configured artifact file missing")
    );
    for (pointer, value, expected) in [
        ("/expired", json!(true), "missing, expired or ambiguous"),
        ("/workflow_run/id", json!(8), "another build"),
        ("/workflow_run/repository_id", json!(0), "another build"),
        (
            "/workflow_run/head_sha",
            json!("another commit"),
            "another build",
        ),
        ("/digest", json!("sha256:wrong"), "archive digest differs"),
        ("/id", json!("invalid"), "artifact ID missing"),
    ] {
        let mut row = metadata.clone();
        *row.pointer_mut(pointer).unwrap() = value;
        state.lock().unwrap().artifacts = vec![row];
        assert!(
            artifact(
                &github,
                repo,
                &run,
                "unsigned-{attempt}",
                "app.apk",
                &mut BTreeMap::new()
            )
            .await
            .unwrap_err()
            .to_string()
            .contains(expected),
            "{pointer}"
        );
    }
    state.lock().unwrap().artifacts = vec![metadata.clone(), metadata];
    assert!(
        artifact(
            &github,
            repo,
            &run,
            "unsigned-{attempt}",
            "app.apk",
            &mut BTreeMap::new()
        )
        .await
        .is_err()
    );
    assert!(
        artifact(
            &github,
            repo,
            &json!({}),
            "unsigned-{attempt}",
            "app.apk",
            &mut BTreeMap::new()
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("run ID missing")
    );
    server.abort();
}

#[tokio::test]
async fn provenance_requires_a_policy_valid_attestation_not_just_an_api_row() {
    crate::initialize_test_crypto();
    let loaded = policy_fixture();
    let repo = &loaded.config.repositories[0];
    let state = Arc::new(Mutex::new(Service::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(endpoint)
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let github = Github::local_test_client(&origin);
    let claim = Claimed {
        job: crate::ledger::Job {
            version: 2,
            id: "test-job".into(),
            repository_id: repo.id,
            profile: "default".into(),
            run_id: 7,
            attempt: 1,
            commit: "a".repeat(40),
            policy_hash: "b".repeat(64),
            revision: 1,
        },
        lease: "lease".into(),
        attempt: 1,
    };
    assert!(
        provenance(&github, &loaded, repo, &claim, b"artifact", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("no valid attestation")
    );
    state.lock().unwrap().attestations = vec![json!({"repository_id":repo.id,"bundle":{}})];
    assert!(
        provenance(&github, &loaded, repo, &claim, b"artifact", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("no valid attestation")
    );
    state.lock().unwrap().attestations = vec![json!({"repository_id":0,"bundle":{}})];
    assert!(
        provenance(&github, &loaded, repo, &claim, b"artifact", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("attestation repository differs")
    );
    server.abort();
}

#[tokio::test]
async fn signed_inputs_missing_manifests_and_different_code_fail_before_signing() {
    if !reference_inputs_available() {
        return;
    }
    let (_directory, loaded, claim, original) = loaded_fixture();
    let github = Github::local_test_client("http://127.0.0.1:1");
    let ledger = Ledger::local_test_client("http://127.0.0.1:1");
    let repo = &loaded.config.repositories[0];
    let apk = archive::read(&original.apk_bytes).unwrap();
    let aab = archive::read(&original.aab_bytes).unwrap();
    for (case, expected) in [
        ("signed", "JAR signature"),
        ("manifest", "bundle manifest missing"),
        ("dex", "APK DEX does not match AAB"),
        ("package", "package or version differs"),
    ] {
        let mut apk = apk.clone();
        let mut aab = aab.clone();
        let mut profile = repo.profiles["default"].clone();
        match case {
            "signed" => {
                archive::add(&mut apk, "META-INF/ATTACKER.SF", b"untrusted".to_vec()).unwrap();
            }
            "manifest" => {
                aab.remove("base/manifest/AndroidManifest.xml");
            }
            "dex" => {
                apk.get_mut("classes.dex").unwrap().bytes = b"different program".to_vec();
            }
            "package" => {
                profile.package = "another.application".into();
            }
            _ => unreachable!(),
        }
        let inputs = VerifiedArtifacts {
            apk_bytes: archive::write(&apk, false).unwrap(),
            aab_bytes: archive::write(&aab, false).unwrap(),
            apk_meta: original.apk_meta.clone(),
            aab_meta: original.aab_meta.clone(),
            apk_provenance: original.apk_provenance.clone(),
            aab_provenance: original.aab_provenance.clone(),
            apk_bundle: original.apk_bundle.clone(),
            aab_bundle: original.aab_bundle.clone(),
        };
        let error = OutputJob {
            loaded: &loaded,
            ledger: &ledger,
            claim: &claim,
            active: None,
            github: &github,
            repo,
            artifact_profile: &profile,
        }
        .finish(inputs, crate::metrics::Stage::new("verify_inputs"))
        .await
        .unwrap_err();
        assert!(error.to_string().contains(expected), "{case}: {error}");
    }
}

#[tokio::test]
async fn signing_admission_binds_repository_builder_run_attempt_event_and_caller() {
    crate::initialize_test_crypto();
    let mut loaded = policy_fixture();
    let repo = &mut loaded.config.repositories[0];
    repo.id = 42;
    repo.name = "owner/app".into();
    repo.visibility = "public".into();
    repo.callers = vec![".github/workflows/release.yml".into()];
    repo.events = vec!["push".into()];
    repo.builder.repository = "trusted/builders".into();
    repo.builder.repository_id = 1001;
    repo.builder.refs = vec!["refs/tags/v0.2.0".into()];
    let mut profile = repo.profiles.values().next().unwrap().clone();
    profile.apk_artifact = "unsigned-{attempt}".into();
    profile.aab_artifact = "unsigned-{attempt}".into();
    profile.apk_file = "app.apk".into();
    profile.aab_file = "app.aab".into();
    repo.profiles = BTreeMap::from([("default".into(), profile)]);
    let repo = &loaded.config.repositories[0];
    let claim = Claimed {
        job: crate::ledger::Job {
            version: 2,
            id: "test-job".into(),
            repository_id: 42,
            run_id: 123,
            attempt: 2,
            commit: "a".repeat(40),
            profile: "default".into(),
            revision: repo.revision,
            policy_hash: loaded.policy_hash(repo).unwrap(),
        },
        lease: "test-lease".into(),
        attempt: 1,
    };
    let entries = BTreeMap::from([
        (
            "app.apk".into(),
            archive::Entry {
                bytes: b"unverified APK".to_vec(),
                stored: true,
            },
        ),
        (
            "app.aab".into(),
            archive::Entry {
                bytes: b"unverified AAB".to_vec(),
                stored: true,
            },
        ),
    ]);
    let zip = archive::write(&entries, false).unwrap();
    let metadata = json!({"id":44,"name":"unsigned-2","expired":false,"workflow_run":{"id":123,"head_sha":claim.job.commit,"repository_id":42},"digest":format!("sha256:{}",crate::sha256(&zip))});
    let api = BTreeMap::from([
        (
            "/repos/trusted/builders".into(),
            json!({"id":1001,"visibility":"public"}),
        ),
        (
            "/repos/trusted/builders/releases/tags/v0.2.0".into(),
            json!({"tag_name":"v0.2.0","draft":false,"immutable":true}),
        ),
        (
            "/repos/trusted/builders/git/ref/tags/v0.2.0".into(),
            json!({"ref":"refs/tags/v0.2.0","object":{"type":"commit","sha":repo.builder.commit}}),
        ),
        (
            "/repos/owner/app".into(),
            json!({"id":42,"visibility":"public"}),
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2".into(),
            json!({"id":123,"run_attempt":2,"status":"completed","conclusion":"success","head_sha":claim.job.commit,"head_repository":{"id":42},"event":"push","workflow_id":9}),
        ),
        (
            "/repos/owner/app/actions/workflows/9".into(),
            json!({"path":repo.callers[0]}),
        ),
    ]);
    let state = Arc::new(Mutex::new(Service {
        api: api.clone(),
        artifacts: vec![metadata],
        artifact_zip: zip,
        ..Service::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(endpoint)
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let github = Github::local_test_client(&origin);
    let ledger = Ledger::local_test_client(&origin);
    // An eligible run can reach provenance verification, but no attestation
    // means no signing intents and no outputs, even with correct API metadata.
    let result = OutputJob {
        loaded: &loaded,
        ledger: &ledger,
        claim: &claim,
        active: None,
        github: &github,
        repo,
        artifact_profile: &repo.profiles["default"],
    }
    .verify_and_finish(crate::metrics::Stage::new("verify_inputs"))
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("no valid attestation")
    );
    for (endpoint, pointer, value, expected) in [
        (
            "/repos/trusted/builders",
            "/id",
            json!(99),
            "trusted builder repository differs",
        ),
        (
            "/repos/trusted/builders/releases/tags/v0.2.0",
            "/immutable",
            json!(false),
            "not published and immutable",
        ),
        (
            "/repos/owner/app",
            "/id",
            json!(99),
            "repository ID changed",
        ),
        (
            "/repos/owner/app",
            "/visibility",
            json!("private"),
            "repository visibility changed",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/id",
            json!(124),
            "eligible successful build",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/run_attempt",
            json!(1),
            "eligible successful build",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/status",
            json!("in_progress"),
            "eligible successful build",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/conclusion",
            json!("failure"),
            "eligible successful build",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/head_sha",
            json!("b".repeat(40)),
            "eligible successful build",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/head_repository/id",
            json!(99),
            "fork builds are forbidden",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/event",
            json!("pull_request"),
            "event is not eligible",
        ),
        (
            "/repos/owner/app/actions/runs/123/attempts/2",
            "/workflow_id",
            json!(null),
            "workflow missing",
        ),
        (
            "/repos/owner/app/actions/workflows/9",
            "/path",
            json!(".github/workflows/attacker.yml"),
            "workflow differs from policy",
        ),
    ] {
        let mut changed = api.clone();
        *changed
            .get_mut(endpoint)
            .unwrap()
            .pointer_mut(pointer)
            .unwrap() = value;
        state.lock().unwrap().api = changed;
        let error = OutputJob {
            loaded: &loaded,
            ledger: &ledger,
            claim: &claim,
            active: None,
            github: &github,
            repo,
            artifact_profile: &repo.profiles["default"],
        }
        .verify_and_finish(crate::metrics::Stage::new("verify_inputs"))
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{endpoint}{pointer}: {error}"
        );
    }
    assert!(state.lock().unwrap().events.is_empty());
    assert!(state.lock().unwrap().uploads.is_empty());
    server.abort();
}
