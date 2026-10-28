//! Real HTTP contract tests. Production origins remain fixed and private.
use super::*;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

struct Exchange {
    method: &'static str,
    path: String,
    token: Option<&'static str>,
    payload: Option<Value>,
    response: String,
}
impl Exchange {
    fn json(method: &'static str, path: &str, value: Value) -> Self {
        let body = value.to_string();
        Self {
            method,
            path: path.into(),
            token: Some("test-token"),
            payload: None,
            response: format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        }
    }
    fn public(mut self) -> Self {
        self.token = None;
        self
    }
    fn body(mut self, value: Value) -> Self {
        self.payload = Some(value);
        self
    }
}

fn fixture(exchanges: Vec<Exchange>) -> (Github, std::thread::JoinHandle<()>) {
    crate::initialize_test_crypto();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        for exchange in exchanges {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("expected {} {}: {error}", exchange.method, exchange.path),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut received = Vec::new();
            let (header, body) = loop {
                let mut buffer = [0; 4096];
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0, "client closed early");
                received.extend_from_slice(&buffer[..count]);
                if let Some(end) = received.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8(received[..end].to_vec()).unwrap();
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|n| n.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if received.len() >= end + 4 + length {
                        break (header, received[end + 4..end + 4 + length].to_vec());
                    }
                }
            };
            assert_eq!(
                header.lines().next().unwrap(),
                format!("{} {} HTTP/1.1", exchange.method, exchange.path)
            );
            let headers = header.to_ascii_lowercase();
            match exchange.token {
                Some(token) => assert!(headers.contains(&format!("authorization: bearer {token}"))),
                None => assert!(!headers.contains("authorization:")),
            }
            if let Some(payload) = exchange.payload {
                assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), payload);
            }
            stream.write_all(exchange.response.as_bytes()).unwrap();
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    (
        Github {
            client,
            token: "test-token".into(),
            max_bytes: 1024,
            api_origin: origin.clone(),
            uploads_origin: origin,
        },
        task,
    )
}
fn repository() -> Repository {
    let config: Config =
        serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap();
    config.repositories[0].clone()
}

#[test]
fn requests_keep_credentials_scoped_and_validate_paths() {
    let (mut github, task) = fixture(vec![]);
    for path in ["relative", "/repos/x?token=y", "/repos/x#fragment"] {
        assert!(github.request(reqwest::Method::GET, path).is_err());
    }
    let request = github
        .request(reqwest::Method::GET, "/repos/owner/app")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(request.headers()["authorization"], "Bearer test-token");
    assert_eq!(request.headers()["x-github-api-version"], "2026-03-10");
    github.token.clear();
    assert!(
        !github
            .request(reqwest::Method::GET, "/repos/owner/app")
            .unwrap()
            .build()
            .unwrap()
            .headers()
            .contains_key("authorization")
    );
    task.join().unwrap();
    for status in [401, 403, 408, 429, 500, 503] {
        assert!(HttpFailure(status).retryable());
    }
    for status in [200, 400, 404, 409, 422] {
        assert!(!HttpFailure(status).retryable());
    }
    assert_eq!(HttpFailure(403).to_string(), "HTTP request rejected (403)");
}

#[tokio::test]
async fn pagination_combines_pages_and_rejects_invalid_shapes() {
    let rows = vec![json!({"id": 1}); 100];
    let (github, task) = fixture(vec![
        Exchange::json("GET", "/rows?per_page=100&page=1", json!({"items":rows})),
        Exchange::json(
            "GET",
            "/rows?per_page=100&page=2",
            json!({"items":[{"id":2}]}),
        ),
        Exchange::json(
            "GET",
            "/invalid?per_page=100&page=1",
            json!({"not":"an array"}),
        ),
    ]);
    let result = github.list("/rows", Some("items")).await.unwrap();
    assert_eq!(result.len(), 101);
    assert_eq!(result[100]["id"], 2);
    assert!(
        github
            .list("/invalid", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid GitHub list")
    );
    task.join().unwrap();
}

#[tokio::test]
async fn pagination_is_bounded() {
    let rows = vec![json!(1); 100];
    let exchanges = (1..=100)
        .map(|page| {
            Exchange::json(
                "GET",
                &format!("/rows?per_page=100&page={page}"),
                json!(rows),
            )
        })
        .collect();
    let (github, task) = fixture(exchanges);
    assert!(
        github
            .list("/rows", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("pagination limit")
    );
    task.join().unwrap();
}

#[tokio::test]
async fn installation_tokens_are_repository_scoped_and_least_privileged() {
    let repo = repository();
    for write in [false, true] {
        let permissions = if write {
            json!({"actions":"read","attestations":"read","contents":"write"})
        } else {
            json!({"contents":"read"})
        };
        let (github, task) = fixture(vec![
            Exchange::json(
                "GET",
                &format!("/repos/{}/installation", repo.name),
                json!({"id": 71}),
            ),
            Exchange::json(
                "POST",
                "/app/installations/71/access_tokens",
                json!({"token":"installation-token"}),
            )
            .body(json!({"repository_ids":[repo.id],"permissions":permissions})),
        ]);
        let connected = if write {
            github.installation(&repo).await
        } else {
            github.installation_for(&repo.name, repo.id, false).await
        }
        .unwrap();
        assert_eq!(connected.token, "installation-token");
        task.join().unwrap();
    }
    for (info, token) in [(json!({}), None), (json!({"id":71}), Some(json!({})))] {
        let mut exchanges = vec![Exchange::json("GET", "/repos/owner/app/installation", info)];
        if let Some(token) = token {
            exchanges.push(Exchange::json(
                "POST",
                "/app/installations/71/access_tokens",
                token,
            ));
        }
        let (github, task) = fixture(exchanges);
        assert!(
            github
                .installation_for("owner/app", 42, false)
                .await
                .is_err()
        );
        task.join().unwrap();
    }
}

#[tokio::test]
async fn builder_identity_is_checked_publicly_without_installation_credentials() {
    let builder = crate::config::Builder {
        repository: "trusted/builders".into(),
        repository_id: 7,
        workflow: ".github/workflows/build.yml".into(),
        refs: vec!["refs/heads/main".into()],
    };
    for protected in [true, false] {
        let (github, task) = fixture(vec![
            Exchange::json(
                "GET",
                "/repos/trusted/builders",
                json!({"id":7,"visibility":"public"}),
            )
            .public(),
            Exchange::json(
                "GET",
                "/repos/trusted/builders/branches/main",
                json!({"protected":protected}),
            )
            .public(),
        ]);
        assert_eq!(
            github.verify_builder_identity(&builder).await.is_ok(),
            protected
        );
        task.join().unwrap();
    }
    for metadata in [
        json!({"id":8,"visibility":"public"}),
        json!({"id":7,"visibility":"private"}),
    ] {
        let (github, task) = fixture(vec![
            Exchange::json("GET", "/repos/trusted/builders", metadata).public(),
        ]);
        assert!(github.verify_builder_identity(&builder).await.is_err());
        task.join().unwrap();
    }
    let mut tag = builder.clone();
    tag.refs = vec!["refs/tags/v1".into()];
    let (github, task) = fixture(vec![
        Exchange::json(
            "GET",
            "/repos/trusted/builders",
            json!({"id":7,"visibility":"public"}),
        )
        .public(),
    ]);
    assert!(github.verify_builder_identity(&tag).await.is_err());
    task.join().unwrap();
}

#[tokio::test]
async fn managed_drafts_are_created_or_reused_but_never_published_or_overwritten() {
    let repo = repository();
    let path = format!("/repos/{}/releases", repo.name);
    let list = format!("{path}?per_page=100&page=1");
    let expected = json!({"tag_name":"bathysign/job1","target_commitish":"commit1","name":"Signed build job1","body":"Bathysign job job1; commit commit1","draft":true});
    let (github, task) = fixture(vec![
        Exchange::json("GET", &list, json!([])),
        Exchange::json("POST", &path, json!({"id":19})).body(expected.clone()),
    ]);
    assert_eq!(
        github.release(&repo, "job1", "commit1").await.unwrap()["id"],
        19
    );
    task.join().unwrap();
    for change in [
        None,
        Some(("draft", json!(false))),
        Some(("body", json!("unmanaged"))),
        Some(("target_commitish", json!("other"))),
    ] {
        let mut release = expected.clone();
        let succeeds = change.is_none();
        if let Some((key, value)) = change {
            release[key] = value;
        }
        let (github, task) = fixture(vec![Exchange::json("GET", &list, json!([release]))]);
        assert_eq!(
            github.release(&repo, "job1", "commit1").await.is_ok(),
            succeeds
        );
        task.join().unwrap();
    }
}

#[tokio::test]
async fn uploads_are_idempotent_and_recover_only_incomplete_assets() {
    let repo = repository();
    let asset_path = format!("/repos/{}/releases/19/assets", repo.name);
    let list = format!("{asset_path}?per_page=100&page=1");
    let digest = format!("sha256:{}", crate::sha256(b"payload"));
    let asset = json!({"name":"app signed.apk","state":"uploaded","digest":digest,"size":7});
    let (github, task) = fixture(vec![Exchange::json("GET", &list, json!([asset.clone()]))]);
    assert_eq!(
        github
            .upload(&repo, 19, "app signed.apk", b"payload".to_vec())
            .await
            .unwrap(),
        asset
    );
    task.join().unwrap();
    let starter = json!({"name":"app signed.apk","id":24,"state":"starter","digest":null});
    let (github, task) = fixture(vec![
        Exchange::json("GET", &list, json!([starter.clone()])),
        Exchange::json(
            "DELETE",
            &format!("/repos/{}/releases/assets/24", repo.name),
            json!(null),
        ),
        Exchange::json(
            "POST",
            &format!("{asset_path}?name=app+signed.apk"),
            asset.clone(),
        ),
    ]);
    assert_eq!(
        github
            .upload(&repo, 19, "app signed.apk", b"payload".to_vec())
            .await
            .unwrap(),
        asset
    );
    task.join().unwrap();
    for assets in [
        json!([asset.clone(), asset]),
        json!([{"name":"app signed.apk","state":"uploaded","digest":"bad","size":7}]),
        json!([{"name":"app signed.apk","state":"starter","digest":null}]),
    ] {
        let (github, task) = fixture(vec![Exchange::json("GET", &list, assets)]);
        assert!(
            github
                .upload(&repo, 19, "app signed.apk", b"payload".to_vec())
                .await
                .is_err()
        );
        task.join().unwrap();
    }
    let (github, task) = fixture(vec![
        Exchange::json("GET", &list, json!([])),
        Exchange::json(
            "POST",
            &format!("{asset_path}?name=app+signed.apk"),
            json!({"digest":"wrong"}),
        ),
    ]);
    assert!(
        github
            .upload(&repo, 19, "app signed.apk", b"payload".to_vec())
            .await
            .unwrap_err()
            .to_string()
            .contains("uploaded asset digest differs")
    );
    task.join().unwrap();
}

#[tokio::test]
async fn download_limits_and_untrusted_redirects_fail_closed() {
    let repo = repository();
    let path = format!("/repos/{}/actions/artifacts/19/zip", repo.name);
    let mut redirection = Exchange::json("GET", &path, json!({}));
    redirection.response = "HTTP/1.1 302 Found\r\nLocation: https://evil.example/file\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into();
    let mut missing_location = Exchange::json("GET", &path, json!({}));
    missing_location.response =
        "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into();
    let (github, task) = fixture(vec![
        Exchange::json("GET", &path, json!([1, 2, 3])),
        redirection,
        missing_location,
    ]);
    assert_eq!(github.download(&repo, 19).await.unwrap(), b"[1,2,3]");
    assert!(github.download(&repo, 19).await.is_err());
    assert!(github.download(&repo, 19).await.is_err());
    task.join().unwrap();
    for response in [
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n123456\r\n6\r\n789012\r\n0\r\n\r\n",
    ] {
        let mut exchange = Exchange::json("GET", &path, json!({}));
        exchange.response = response.into();
        let (mut github, task) = fixture(vec![exchange]);
        github.max_bytes = 10;
        assert!(github.download(&repo, 19).await.is_err());
        task.join().unwrap();
    }
}

#[tokio::test]
async fn embedded_bundles_require_repository_identity_and_valid_bundle_shape() {
    let (github, task) = fixture(vec![]);
    assert_eq!(
        github
            .attestation_bundle(
                42,
                &json!({"repository_id":42,"bundle":{"dsseEnvelope":{}}})
            )
            .await
            .unwrap(),
        json!({"dsseEnvelope":{}})
    );
    for row in [
        json!({"repository_id":43,"bundle":{}}),
        json!({"repository_id":42,"bundle":"invalid"}),
        json!({"repository_id":42,"bundle_url":"https://evil.example/bundle"}),
    ] {
        assert!(github.attestation_bundle(42, &row).await.is_err());
    }
    task.join().unwrap();
}

#[tokio::test]
async fn app_jwt_is_signed_with_the_configured_identity_and_short_expiry() {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::signature::Verifier;
    crate::initialize_test_crypto();
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("app.pem");
    std::fs::write(
        &path,
        key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut config: Config =
        serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap();
    config.github_app_private_key = path;
    config.github_app_id = 1234;
    let before = now().unwrap();
    let github = Github::connect(&config).await.unwrap();
    assert_eq!(github.api_origin, "https://api.github.com");
    assert_eq!(github.uploads_origin, "https://uploads.github.com");
    assert_eq!(github.max_bytes, config.max_artifact_bytes);
    let parts: Vec<_> = github.token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header, json!({"alg":"RS256","typ":"JWT"}));
    assert_eq!(payload["iss"], 1234);
    let issued = payload["iat"].as_u64().unwrap();
    assert!((before - 30..=now().unwrap() - 30).contains(&issued));
    assert_eq!(payload["exp"].as_u64().unwrap() - issued, 570);
    let signature =
        rsa::pkcs1v15::Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice())
            .unwrap();
    rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key.to_public_key())
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
    std::fs::write(&config.github_app_private_key, b"not a key").unwrap();
    assert!(Github::connect(&config).await.is_err());
}

#[tokio::test]
async fn chunked_downloads_can_grow_without_content_length() {
    let repo = repository();
    let path = format!("/repos/{}/actions/artifacts/19/zip", repo.name);
    let mut response = Exchange::json("GET", &path, json!({}));
    response.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n123456\r\n6\r\n789012\r\n0\r\n\r\n".into();
    let (github, task) = fixture(vec![response]);
    assert_eq!(github.download(&repo, 19).await.unwrap(), b"123456789012");
    task.join().unwrap();
}
