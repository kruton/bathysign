//! Connection-closing scrapers must receive responses spanning TLS records.
#[tokio::test]
async fn closing_metrics_client_receives_complete_multi_record_response() {
    bathysign::initialize_crypto().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = directory.path().join("certificate.pem");
    let private_key = directory.path().join("key.pem");
    std::fs::write(&certificate, identity.cert.pem()).unwrap();
    std::fs::write(&private_key, identity.key_pair.serialize_pem()).unwrap();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let expected = "metric_sample 1\n".repeat(8192);
    let response = expected.clone();
    let router = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let response = response.clone();
            async move { response }
        }),
    );
    let server = tokio::spawn(async move {
        bathysign::server::serve_tls(router, &address.to_string(), &certificate, &private_key)
            .await
            .unwrap();
    });
    let client = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(identity.cert.pem().as_bytes()).unwrap(),
        )
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/metrics", address.port());
    let mut result = None;
    for _ in 0..40 {
        match client.get(&url).header("Connection", "close").send().await {
            Ok(response) => {
                result = Some(response);
                break;
            }
            Err(error) if error.is_connect() => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await
            }
            Err(error) => panic!("TLS request failed: {error}"),
        }
    }
    let response = result.expect("TLS server never became ready");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        expected.as_bytes()
    );
    server.abort();
}
