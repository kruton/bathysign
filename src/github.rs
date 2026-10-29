use crate::config::{Config, Repository, now};
use crate::network::SendMonitored;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use serde_json::{Value, json};

#[derive(Clone)]
pub struct Github {
    client: reqwest::Client,
    token: String,
    pub max_bytes: usize,
    // Fixed service origins in production; private so callers cannot redirect credentials.
    api_origin: String,
    uploads_origin: String,
}
#[derive(Debug)]
pub struct HttpFailure(pub u16);
impl std::fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP request rejected ({})", self.0)
    }
}
impl std::error::Error for HttpFailure {}
impl HttpFailure {
    pub fn retryable(&self) -> bool {
        [401, 403, 408, 429].contains(&self.0) || self.0 >= 500
    }
}
pub async fn bounded(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let started = std::time::Instant::now();
    let result = bounded_inner(response, limit).await;
    if result.as_ref().is_err_and(|e| {
        e.downcast_ref::<reqwest::Error>()
            .is_some_and(|e| e.is_timeout())
    }) {
        crate::metrics::observe("network_timeout", false, started);
    }
    crate::metrics::observe("network_body", result.is_ok(), started);
    result
}
async fn bounded_inner(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(HttpFailure(response.status().as_u16()).into());
    }
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "HTTP response too large"
    );
    let mut out = Vec::new();
    if let Some(length) = response.content_length() {
        out.try_reserve_exact(usize::try_from(length)?)?;
    }
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit.saturating_sub(out.len()),
            "HTTP response too large"
        );
        let needed = out.len() + chunk.len();
        if needed > out.capacity() {
            let capacity = needed.max(out.capacity().saturating_mul(2).min(limit));
            out.try_reserve_exact(capacity - out.len())?;
        }
        out.extend(chunk);
    }
    Ok(out)
}
impl Github {
    #[cfg(test)]
    pub(crate) fn local_test_client(origin: &str) -> Self {
        Self {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            token: "test-token".into(),
            max_bytes: 16 * 1024 * 1024,
            api_origin: origin.into(),
            uploads_origin: origin.into(),
        }
    }

    pub async fn attestation_bundle(&self, repository_id: u64, row: &Value) -> Result<Value> {
        ensure!(
            row["repository_id"].as_u64() == Some(repository_id),
            "attestation repository differs"
        );
        // Older API versions embed the bundle; 2026-03-10 returns a signed URL.
        if let Some(bundle) = row.get("bundle").filter(|v| v.is_object()) {
            return Ok(bundle.clone());
        }
        let location = row["bundle_url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("attestation bundle URL missing"))?;
        let url = storage_url(location)?;
        // The client has no default authorization and does not follow redirects.
        // Signed storage URLs must never receive the GitHub installation token.
        let response = self.client.get(url).send_monitored().await?;
        let compressed = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/x-snappy");
        decode_bundle(&bounded(response, BUNDLE_LIMIT).await?, compressed)
    }
    pub async fn connect(config: &Config) -> Result<Self> {
        let client = crate::network::client_builder()?
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(300))
            .user_agent("hermit-bathysign/0.1")
            .build()?;
        let key = crate::crypto::github_app_key(&config.github_app_private_key)?;
        let issued = now()?;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"iat":issued-30,"exp":issued+540,"iss":config.github_app_id}),
        )?);
        let input = format!("{header}.{payload}");
        let sig = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key)
            .try_sign_with_rng(&mut rsa::rand_core::OsRng, input.as_bytes())?;
        Ok(Self {
            client,
            token: format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_vec())),
            max_bytes: config.max_artifact_bytes,
            api_origin: "https://api.github.com".into(),
            uploads_origin: "https://uploads.github.com".into(),
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        ensure!(
            path.starts_with('/') && !path.contains(['?', '#']),
            "invalid GitHub API path"
        );
        let request = self
            .client
            .request(method, format!("{}{path}", self.api_origin))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2026-03-10");
        Ok(if self.token.is_empty() {
            request
        } else {
            request.bearer_auth(&self.token)
        })
    }
    pub async fn verify_builder_identity(&self, builder: &crate::config::Builder) -> Result<()> {
        // Public trust repositories do not need installation-token access. Never send
        // source-repository credentials while resolving their identity/protection.
        let mut public = self.clone();
        public.token.clear();
        let metadata = public
            .get(&format!("/repos/{}", builder.repository))
            .await?;
        ensure!(
            metadata["id"].as_u64() == Some(builder.repository_id)
                && metadata["visibility"] == "public",
            "trusted builder repository differs"
        );
        ensure!(
            builder.refs.len() == 1
                && crate::config::release_ref(&builder.refs[0])
                && crate::config::valid_commit(&builder.commit),
            "exact trusted release tag and commit required"
        );
        let tag = builder.refs[0].strip_prefix("refs/tags/").unwrap();
        let release = public
            .get(&format!(
                "/repos/{}/releases/tags/{tag}",
                builder.repository
            ))
            .await?;
        ensure!(
            release["tag_name"] == tag && release["draft"] == false && release["immutable"] == true,
            "trusted workflow release is not published and immutable"
        );
        let reference = public
            .get(&format!("/repos/{}/git/ref/tags/{tag}", builder.repository))
            .await?;
        ensure!(
            reference["ref"] == builder.refs[0],
            "trusted release tag differs"
        );
        ensure!(
            reference["object"]["sha"] == builder.workflow_digest(),
            "trusted workflow digest differs from policy pin"
        );
        let mut object = reference["object"].clone();
        let mut seen = std::collections::BTreeSet::new();
        for depth in 0..=8 {
            let sha = object["sha"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("tag object SHA missing"))?;
            ensure!(
                crate::config::valid_commit(sha) && seen.insert(sha.to_owned()),
                "invalid or cyclic tag object"
            );
            match object["type"].as_str() {
                Some("commit") => {
                    ensure!(
                        sha == builder.commit,
                        "trusted release commit differs from policy pin"
                    );
                    return Ok(());
                }
                Some("tag") if depth < 8 => {
                    let annotated = public
                        .get(&format!("/repos/{}/git/tags/{sha}", builder.repository))
                        .await?;
                    ensure!(annotated["sha"] == sha, "annotated tag object differs");
                    object = annotated["object"].clone();
                }
                _ => anyhow::bail!("unsupported tag object or annotation depth exceeded"),
            }
        }
        anyhow::bail!("tag annotation depth exceeded")
    }
    pub async fn get(&self, path: &str) -> Result<Value> {
        let response = self
            .request(reqwest::Method::GET, path)?
            .send_monitored()
            .await?;
        Ok(serde_json::from_slice(
            &bounded(response, 8 * 1024 * 1024).await?,
        )?)
    }
    pub async fn installation(self, repo: &Repository) -> Result<Self> {
        self.installation_for(&repo.name, repo.id, true).await
    }
    pub async fn installation_for(
        mut self,
        repository: &str,
        repository_id: u64,
        write_outputs: bool,
    ) -> Result<Self> {
        let info = self
            .get(&format!("/repos/{}/installation", repository))
            .await?;
        let id = info["id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("installation missing"))?;
        let permissions = if write_outputs {
            json!({"actions":"read","attestations":"read","contents":"write"})
        } else {
            json!({"contents":"read"})
        };
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/app/installations/{id}/access_tokens"),
            )?
            .json(&json!({"repository_ids":[repository_id],"permissions":permissions}))
            .send_monitored()
            .await?;
        let body: Value = serde_json::from_slice(&bounded(response, 1024 * 1024).await?)?;
        self.token = body["token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("installation token missing"))?
            .to_string();
        Ok(self)
    }
    pub async fn list(&self, path: &str, field: Option<&str>) -> Result<Vec<Value>> {
        let mut all = vec![];
        for page in 1..=100 {
            let response = self
                .request(reqwest::Method::GET, path)?
                .query(&[("per_page", 100), ("page", page)])
                .send_monitored()
                .await?;
            let body: Value = serde_json::from_slice(&bounded(response, 8 * 1024 * 1024).await?)?;
            let rows = field
                .map(|f| &body[f])
                .unwrap_or(&body)
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid GitHub list"))?;
            all.extend(rows.iter().cloned());
            if rows.len() < 100 {
                return Ok(all);
            }
        }
        anyhow::bail!("GitHub pagination limit exceeded")
    }
    pub async fn download(&self, repo: &Repository, id: u64) -> Result<Vec<u8>> {
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/repos/{}/actions/artifacts/{id}/zip", repo.name),
            )?
            .send_monitored()
            .await?;
        if response.status() == reqwest::StatusCode::FOUND {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or_else(|| anyhow::anyhow!("artifact redirect missing"))?
                .to_str()?;
            let url = storage_url(location)?;
            // Never forward GitHub authorization to artifact storage.
            bounded(self.client.get(url).send_monitored().await?, self.max_bytes).await
        } else {
            bounded(response, self.max_bytes).await
        }
    }
    pub async fn release(&self, repo: &Repository, job: &str, commit: &str) -> Result<Value> {
        let tag = format!("bathysign/{job}");
        let marker = format!("Bathysign job {job}; commit {commit}");
        let existing = self
            .list(&format!("/repos/{}/releases", repo.name), None)
            .await?
            .into_iter()
            .find(|r| r["tag_name"] == tag);
        if let Some(r) = existing {
            ensure!(
                r["draft"] == true && r["body"] == marker && r["target_commitish"] == commit,
                "release is published, conflicting, or unmanaged"
            );
            return Ok(r);
        }
        let response=self.request(reqwest::Method::POST,&format!("/repos/{}/releases",repo.name))?.json(&json!({"tag_name":tag,"target_commitish":commit,"name":format!("Signed build {job}"),"body":marker,"draft":true})).send_monitored().await?;
        Ok(serde_json::from_slice(
            &bounded(response, 1024 * 1024).await?,
        )?)
    }
    pub async fn upload(
        &self,
        repo: &Repository,
        release: u64,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<Value> {
        let digest = format!("sha256:{}", crate::sha256(&bytes));
        let assets = self
            .list(
                &format!("/repos/{}/releases/{release}/assets", repo.name),
                None,
            )
            .await?;
        let mut existing = assets.iter().filter(|a| a["name"] == name);
        if let Some(asset) = existing.next() {
            ensure!(existing.next().is_none(), "duplicate release asset");
            if reusable_asset(asset, &digest, bytes.len())? {
                return Ok(asset.clone());
            }
            // GitHub documents starter assets as leftovers from failed uploads.
            // release() has already authenticated this job's managed draft.
            let id = asset["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .ok_or_else(|| anyhow::anyhow!("incomplete asset ID missing"))?;
            let response = self
                .request(
                    reqwest::Method::DELETE,
                    &format!("/repos/{}/releases/assets/{id}", repo.name),
                )?
                .send_monitored()
                .await?;
            bounded(response, 1024).await?;
        }
        let mut url = reqwest::Url::parse(&format!(
            "{}/repos/{}/releases/{release}/assets",
            self.uploads_origin, repo.name
        ))?;
        url.query_pairs_mut().append_pair("name", name);
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .header("X-GitHub-Api-Version", "2026-03-10")
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send_monitored()
            .await?;
        let asset: Value = serde_json::from_slice(&bounded(response, 1024 * 1024).await?)?;
        ensure!(
            asset["digest"] == digest,
            "GitHub uploaded asset digest differs"
        );
        Ok(asset)
    }
}

fn reusable_asset(asset: &Value, digest: &str, size: usize) -> Result<bool> {
    if asset["state"] == "starter" && asset["digest"].is_null() {
        return Ok(false);
    }
    ensure!(
        asset["state"] == "uploaded"
            && asset["digest"] == digest
            && asset["size"].as_u64() == Some(size as u64),
        "conflicting release asset"
    );
    Ok(true)
}

fn storage_url(location: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(location)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443),
        "unsafe storage URL"
    );
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("storage host missing"))?;
    ensure!(
        host.ends_with(".blob.core.windows.net") || host.ends_with(".githubusercontent.com"),
        "unexpected storage host"
    );
    Ok(url)
}

const BUNDLE_LIMIT: usize = 8 * 1024 * 1024;

fn decode_bundle(bytes: &[u8], compressed: bool) -> Result<Value> {
    ensure!(bytes.len() <= BUNDLE_LIMIT, "attestation bundle too large");
    if compressed {
        // Snappy includes the decoded length. Check it before allocating, so a
        // small compressed response cannot exhaust the key-holding VM's memory.
        ensure!(
            snap::raw::decompress_len(bytes)? <= BUNDLE_LIMIT,
            "decoded attestation bundle too large"
        );
        Ok(serde_json::from_slice(
            &snap::raw::Decoder::new().decompress_vec(bytes)?,
        )?)
    } else {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_recovery_replaces_only_incomplete_assets() {
        let digest = "sha256:expected";
        assert!(
            !reusable_asset(
                &json!({"state":"starter","digest":null,"size":100}),
                digest,
                100
            )
            .unwrap()
        );
        assert!(
            reusable_asset(
                &json!({"state":"uploaded","digest":digest,"size":100}),
                digest,
                100
            )
            .unwrap()
        );
        for value in [
            json!({"state":"uploaded","digest":"wrong","size":100}),
            json!({"state":"uploaded","digest":digest,"size":0}),
            json!({"state":"starter","digest":digest,"size":100}),
        ] {
            assert!(reusable_asset(&value, digest, 100).is_err());
        }
    }

    #[test]
    fn attestation_storage_supports_json_and_bounded_raw_snappy() {
        let json = br#"{"mediaType":"test","dsseEnvelope":{}}"#;
        let compressed = snap::raw::Encoder::new().compress_vec(json).unwrap();
        assert_eq!(
            decode_bundle(json, false).unwrap(),
            decode_bundle(&compressed, true).unwrap()
        );
        // Raw Snappy varint declaring 8 MiB + 1 bytes, without allocating it.
        assert!(
            decode_bundle(&[0x81, 0x80, 0x80, 0x04], true)
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
        assert!(decode_bundle(b"invalid", true).is_err());
    }

    #[test]
    fn signed_storage_urls_cannot_redirect_credentials_or_target_other_hosts() {
        assert!(storage_url("https://example.blob.core.windows.net/bundle.json?sig=test").is_ok());
        for url in [
            "http://example.blob.core.windows.net/bundle.json",
            "https://example.blob.core.windows.net:8443/bundle.json",
            "https://user@example.blob.core.windows.net/bundle.json",
            "https://example.blob.core.windows.net/bundle.json#fragment",
            "https://example.blob.core.windows.net.evil.example/bundle.json",
            "https://blob.core.windows.net/bundle.json",
            "https://127.0.0.1/bundle.json",
        ] {
            assert!(storage_url(url).is_err());
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/github.rs"]
mod transport_tests;
