//! Retry safe reads only. Writes recover through the durable job retry protocol.
use std::time::{Duration, Instant};
pub trait SendMonitored {
    async fn send_monitored(self) -> Result<reqwest::Response, reqwest::Error>;
}
impl SendMonitored for reqwest::RequestBuilder {
    async fn send_monitored(self) -> Result<reqwest::Response, reqwest::Error> {
        let template = self.try_clone();
        let safe = template
            .as_ref()
            .and_then(|r| r.try_clone())
            .and_then(|r| r.build().ok())
            .is_some_and(|r| r.method() == reqwest::Method::GET);
        let mut request = self;
        for attempt in 0..3 {
            let started = Instant::now();
            let result = request.send().await;
            let retry = match &result {
                Ok(r) => matches!(r.status().as_u16(), 408 | 429 | 500 | 502 | 503 | 504),
                Err(e) => e.is_timeout() || e.is_connect() || e.is_body(),
            };
            crate::metrics::observe(
                "network_request",
                result
                    .as_ref()
                    .is_ok_and(|r| r.status().is_success() || r.status().is_redirection()),
                started,
            );
            if result.as_ref().is_err_and(|e| e.is_timeout()) {
                crate::metrics::observe("network_timeout", false, started);
            }
            if !safe || !retry || attempt == 2 {
                return result;
            }
            let Some(next) = template.as_ref().and_then(|r| r.try_clone()) else {
                return result;
            };
            // Bound rate-limit waits; longer GitHub cooldowns use durable job backoff.
            let delay = result
                .as_ref()
                .ok()
                .and_then(|r| r.headers().get("retry-after"))
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.clamp(1, 30))
                .unwrap_or(1 << attempt);
            drop(result);
            tokio::time::sleep(Duration::from_secs(delay)).await;
            crate::metrics::observe("network_retry", true, Instant::now());
            request = next;
        }
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test]
    async fn retries_get_on_server_error_but_does_not_replay_post() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for (method, status) in [
                ("GET", "503 Unavailable"),
                ("GET", "200 OK"),
                ("POST", "503 Unavailable"),
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut buf = [0; 4096];
                let n = socket.read(&mut buf).unwrap();
                assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with(method));
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls_rustcrypto::provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .no_proxy()
            .build()
            .unwrap();
        assert_eq!(
            client.get(&url).send_monitored().await.unwrap().status(),
            200
        );
        assert_eq!(
            client.post(&url).send_monitored().await.unwrap().status(),
            503
        );
        server.join().unwrap();
    }
}
