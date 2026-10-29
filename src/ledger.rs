use crate::network::SendMonitored;
use crate::{
    config::{Config, read_secret},
    github::bounded,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub version: u32,
    pub profile: String,
    pub id: String,
    pub repository_id: u64,
    pub run_id: u64,
    pub attempt: u64,
    pub commit: String,
    pub policy_hash: String,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub repository_id: u64,
    pub revision: u64,
    pub policy_hash: String,
    pub version: u32,
    pub profiles: std::collections::BTreeMap<String, History>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claimed {
    pub job: Job,
    pub lease: String,
    pub attempt: u64,
}
#[derive(Clone)]
pub struct Ledger {
    client: reqwest::Client,
    base: String,
    token: String,
}
impl Ledger {
    #[cfg(test)]
    pub(crate) fn local_test_client(origin: &str) -> Self {
        Self {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            base: origin.into(),
            token: "test-token".into(),
        }
    }

    pub fn new(config: &Config) -> Result<Self> {
        let ca = reqwest::Certificate::from_pem(&std::fs::read(&config.audit_ca_certificate)?)?;
        let client = crate::network::client_builder()?
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(ca)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let token = read_secret(&config.audit_token)?;
        let token = std::str::from_utf8(&token)?.trim().to_string();
        ensure!(token.len() >= 32, "audit token too short");
        Ok(Self {
            client,
            base: config.audit_url.clone(),
            token,
        })
    }
    async fn post(&self, path: &str, body: &impl Serialize) -> Result<Value> {
        let operation = match path {
            "/v1/policies" => "ledger_activate",
            "/v1/jobs" => "ledger_enqueue",
            "/v1/claim" => "ledger_claim",
            _ if path.ends_with("/finish") => "ledger_finish",
            _ => "ledger_event",
        };
        let start = std::time::Instant::now();
        let result = self.post_inner(path, body).await;
        crate::metrics::observe(operation, result.is_ok(), start);
        result
    }
    async fn post_inner(&self, path: &str, body: &impl Serialize) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(body)
            .send_monitored()
            .await?;
        Ok(serde_json::from_slice(
            &bounded(response, 8 * 1024 * 1024).await?,
        )?)
    }
    pub async fn trust_head(
        &self,
        authority: &crate::trust::Authority,
    ) -> Result<crate::trust::Checkpoint> {
        authority.validate()?;
        let response = self
            .client
            .get(format!(
                "{}/v1/trust/{}/head",
                self.base, authority.authority
            ))
            .bearer_auth(&self.token)
            .send_monitored()
            .await?;
        let checkpoint: crate::trust::Checkpoint =
            serde_json::from_slice(&bounded(response, crate::trust::MAX_WIRE).await?)?;
        ensure!(
            checkpoint.authority == *authority,
            "saved trust authority differs"
        );
        Ok(checkpoint)
    }
    pub async fn trust_commit(&self, checkpoint: &crate::trust::Checkpoint) -> Result<()> {
        let digest = checkpoint.digest()?;
        let result = self
            .client
            .post(format!(
                "{}/v1/trust/{}/checkpoints",
                self.base, checkpoint.authority.authority
            ))
            .bearer_auth(&self.token)
            .json(checkpoint)
            .send_monitored()
            .await;
        if let Ok(response) = result
            && response.status().is_success()
        {
            let ack: Value = serde_json::from_slice(&bounded(response, 1024).await?)?;
            ensure!(
                ack["digest"] == digest,
                "trust persistence acknowledgment differs"
            );
            return Ok(());
        }
        // A response can be lost after SQLite commits. Resolve ambiguity by
        // reading the exact immutable checkpoint, never by blindly advancing.
        let response = self
            .client
            .get(format!(
                "{}/v1/trust/{}/checkpoints/{digest}",
                self.base, checkpoint.authority.authority
            ))
            .bearer_auth(&self.token)
            .send_monitored()
            .await?;
        let saved: crate::trust::Checkpoint =
            serde_json::from_slice(&bounded(response, crate::trust::MAX_WIRE).await?)?;
        ensure!(saved == *checkpoint, "trust commit was not confirmed");
        Ok(())
    }
    pub async fn activate(&self, activation: &Activation) -> Result<()> {
        self.post("/v1/policies", activation).await?;
        Ok(())
    }
    pub async fn enqueue(&self, job: &Job) -> Result<()> {
        self.post("/v1/jobs", job).await?;
        Ok(())
    }
    pub async fn claim(&self) -> Result<Option<Claimed>> {
        let value = self.post("/v1/claim", &serde_json::json!({})).await?;
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_value(value)?))
        }
    }
    pub async fn event(&self, claimed: &Claimed, kind: &str, data: Value) -> Result<()> {
        self.post(
            &format!("/v1/jobs/{}/events", claimed.job.id),
            &serde_json::json!({"lease":claimed.lease,"kind":kind,"data":data}),
        )
        .await?;
        Ok(())
    }
    pub async fn finish(&self, claimed: &Claimed, status: &str) -> Result<()> {
        self.post(
            &format!("/v1/jobs/{}/finish", claimed.job.id),
            &serde_json::json!({"lease":claimed.lease,"status":status}),
        )
        .await?;
        Ok(())
    }
    pub async fn ping(&self) -> Result<()> {
        let response = self
            .client
            .get(format!("{}/v1/health", self.base))
            .bearer_auth(&self.token)
            .send_monitored()
            .await?;
        bounded(response, 1024).await?;
        Ok(())
    }
}
pub fn job_id(repository: u64, run: u64, attempt: u64, policy: &str) -> String {
    format!("{repository}-{run}-{attempt}-{policy}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub classical_history: Vec<String>,
    pub hybrid_history: Vec<String>,
}
pub fn profile_job_id(
    repository: u64,
    run: u64,
    attempt: u64,
    profile: &str,
    policy: &str,
) -> String {
    format!("v2-{repository}-{run}-{attempt}-{profile}-{policy}")
}

#[cfg(test)]
mod trust_commit_tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn jobs_require_explicit_version_and_profile() {
        let job = serde_json::json!({"version":2,"profile":"default","id":"job", "repository_id":1,"run_id":2,"attempt":1,"commit":"a".repeat(40),"policy_hash":"b".repeat(64),"revision":1});
        assert!(serde_json::from_value::<Job>(job.clone()).is_ok());
        for field in ["version", "profile"] {
            let mut incomplete = job.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Job>(incomplete).is_err());
        }
    }
    #[tokio::test]
    async fn lost_commit_response_is_resolved_by_exact_digest_without_replaying_post() {
        let checkpoint = crate::trust::Checkpoint {
            version: 1,
            authority: crate::trust::Authority {
                authority: crate::trust::AUTHORITY.into(),
                bootstrap_sha256: crate::sha256(crate::trust::BOOTSTRAP),
                epoch: "a".repeat(64),
                target: crate::trust::TARGET.into(),
            },
            generation: 1,
            previous: None,
            verified_at: 1,
            observations: vec![],
            target: None,
            usable: false,
        };
        let body = serde_json::to_vec(&checkpoint).unwrap();
        let expected_digest = checkpoint.digest().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 4096];
                let header_end = loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                    if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
                if index == 0 {
                    assert!(headers.starts_with("POST /v1/trust/sigstore-public/checkpoints "));
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|s| s.trim().parse().unwrap())
                        })
                        .unwrap();
                    while request.len() < header_end + length {
                        let n = stream.read(&mut chunk).unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&chunk[..n]);
                    }
                    assert_eq!(&request[header_end..], body.as_slice());
                    // The durable write happened; its acknowledgment is lost.
                } else {
                    assert!(headers.starts_with(&format!(
                        "GET /v1/trust/sigstore-public/checkpoints/{expected_digest} "
                    )));
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
        });
        let ledger = Ledger {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
            base: format!("http://{address}"),
            token: "test-only".into(),
        };
        ledger.trust_commit(&checkpoint).await.unwrap();
        server.join().unwrap();
    }
}
