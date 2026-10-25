use crate::{
    crypto::{PrivateKey, SigningKey},
    lineage::{DEFAULT_LIMIT, Lineage, validate_hybrid},
    transparency::ArchiveResource,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub listen: String,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub github_app_id: u64,
    pub github_app_private_key: PathBuf,
    pub webhook_secret: PathBuf,
    pub audit_url: String,
    pub audit_token: PathBuf,
    pub audit_ca_certificate: PathBuf,
    pub keys: BTreeMap<String, KeySpec>,
    #[serde(default)]
    pub trust_roots: BTreeMap<String, TrustRoot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_authority: Option<crate::trust::Authority>,
    pub repositories: Vec<Repository>,
    #[serde(default = "default_limit")]
    pub max_artifact_bytes: usize,
    #[serde(default = "lineage_limit")]
    pub max_lineage_bytes: usize,
}
fn default_limit() -> usize {
    64 * 1024 * 1024
}
fn lineage_limit() -> usize {
    DEFAULT_LIMIT
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    pub file: PathBuf,
    pub sha256: String,
    pub valid_until: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub receipt_namespace: String,
    pub id: u64,
    pub name: String,
    pub callers: Vec<String>,
    pub builder: Builder,
    pub finalizer: Builder,
    pub receipt_key: String,
    pub refs: Vec<String>,
    pub events: Vec<String>,
    pub runners: Vec<String>,
    pub visibility: String,
    pub revision: u64,
    pub profiles: BTreeMap<String, ArtifactProfile>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Builder {
    pub repository: String,
    pub repository_id: u64,
    pub workflow: String,
    pub refs: Vec<String>,
}
impl Repository {
    pub fn allows_caller(&self, path: &str) -> bool {
        self.callers.iter().any(|allowed| allowed == path)
    }
    pub fn validate_workflow_authorization(&self) -> Result<()> {
        ensure!(
            self.receipt_namespace == "bathysign",
            "unsupported receipt namespace"
        );
        ensure!(
            !self.callers.is_empty()
                && self.callers.iter().all(|path| workflow_path(path))
                && self.callers.iter().collect::<BTreeSet<_>>().len() == self.callers.len(),
            "unique caller workflow paths required"
        );
        ensure!(
            self.builder.repository_id != self.id
                && self.builder.repository != self.name
                && self.builder.refs.len() == 1
                && self.builder.refs[0]
                    .strip_prefix("refs/heads/")
                    .is_some_and(safe_path),
            "a separate trusted builder and one protected branch are required"
        );
        ensure!(
            self.finalizer.repository == self.builder.repository
                && self.finalizer.repository_id == self.builder.repository_id
                && workflow_path(&self.finalizer.workflow)
                && self.finalizer.workflow != self.builder.workflow
                && self.finalizer.refs == self.builder.refs,
            "a separate finalizer workflow in the same trusted repository and branch is required"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProfile {
    pub package: String,
    pub apk_artifact: String,
    pub aab_artifact: String,
    pub apk_file: String,
    pub aab_file: String,
    pub signing: Signing,
    pub archive_resource: Option<ArchiveResource>,
}
impl Repository {
    pub fn allows_ref(&self, value: &str) -> bool {
        ref_allowed(&self.refs, value)
    }
}
pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_profile(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn ref_allowed(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| {
        p == value
            || (p.starts_with("refs/tags/")
                && p.ends_with('*')
                && !p[..p.len() - 1].contains('*')
                && value.starts_with(&p[..p.len() - 1]))
    })
}
fn workflow_path(value: &str) -> bool {
    value.starts_with(".github/workflows/") && safe_path(value)
}
pub fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    pub original_key: String,
    pub current_key: String,
    pub upload_key: String,
    pub transparency_key: String,
    /// Explicit compatibility for an already deployed APK certificate only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_legacy_rsa_1024: bool,
    pub lineage: PathBuf,
    pub lineage_sha256: String,
    #[serde(default = "rotation_sdk")]
    pub rotation_min_sdk: u32,
    #[serde(default)]
    pub allow_rollback: bool,
    pub hybrid: Option<HybridConfig>,
}
fn is_false(value: &bool) -> bool {
    !value
}
fn rotation_sdk() -> u32 {
    33
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridConfig {
    pub classical_key: String,
    pub pqc_key: String,
    pub classical_lineage: PathBuf,
    pub classical_lineage_sha256: String,
    pub pqc_lineage: PathBuf,
    pub pqc_lineage_sha256: String,
    pub effective_lineage: PathBuf,
    pub effective_lineage_sha256: String,
}

pub type RepositoryLineages = (Lineage, Option<(Lineage, Lineage, Lineage)>);
pub struct Loaded {
    pub config: Config,
    pub keys: BTreeMap<String, SigningKey>,
    pub lineages: BTreeMap<(u64, String), RepositoryLineages>,
}
pub fn now() -> Result<u64> {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    ensure!(n >= 1_700_000_000, "guest clock is invalid");
    Ok(n)
}
pub fn read_secret(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let meta = std::fs::metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= 1024 * 1024,
        "invalid secret file"
    );
    Ok(zeroize::Zeroizing::new(std::fs::read(path)?))
}
fn read_lineage(path: &Path, hash: &str, limit: usize) -> Result<Lineage> {
    ensure!(
        std::fs::metadata(path)?.len() <= limit as u64,
        "lineage too large"
    );
    let b = std::fs::read(path)?;
    ensure!(crate::sha256(&b) == hash, "lineage hash differs");
    Lineage::read(&b, limit)
}
impl Loaded {
    pub fn read(path: &Path) -> Result<Self> {
        let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            matches!(config.version, 3 | 4),
            "configuration version 3 or 4 with trusted workflow identities required"
        );
        if config.version == 4 {
            config
                .trust_authority
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("trust authority missing"))?
                .validate()?;
            ensure!(
                config.trust_roots.is_empty(),
                "dynamic trust cannot fall back to static roots"
            );
        } else {
            ensure!(
                config.trust_authority.is_none(),
                "static-trust configuration cannot enable dynamic trust"
            );
        }
        ensure!(
            !config.repositories.is_empty(),
            "no repositories configured"
        );
        ensure!(
            config.audit_url.starts_with("https://") && !config.audit_url.ends_with('/'),
            "audit URL must be HTTPS without trailing slash"
        );
        ensure!(
            config.max_artifact_bytes > 0 && config.max_artifact_bytes <= 128 * 1024 * 1024,
            "artifact size limit must be at most 128 MiB for the v1 memory budget"
        );
        ensure!(
            config.max_lineage_bytes >= 1024 && config.max_lineage_bytes <= 16 * 1024 * 1024,
            "invalid lineage size limit"
        );
        let mut keys = BTreeMap::new();
        let legacy_apk_keys: std::collections::BTreeSet<_> = config
            .repositories
            .iter()
            .flat_map(|r| r.profiles.values())
            .filter(|p| p.signing.allow_legacy_rsa_1024)
            .map(|p| &p.signing.original_key)
            .collect();
        for (id, spec) in &config.keys {
            let k = if legacy_apk_keys.contains(id) {
                SigningKey::load_legacy_apk(&spec.private_key, &spec.certificate)?
            } else {
                SigningKey::load(&spec.private_key, &spec.certificate)?
            };
            ensure!(
                k.fingerprint() == spec.fingerprint,
                "key fingerprint differs: {id}"
            );
            keys.insert(id.clone(), k);
        }
        for t in config.trust_roots.values() {
            ensure!(t.valid_until > now()?, "trust material expired");
            ensure!(
                crate::sha256(&std::fs::read(&t.file)?) == t.sha256,
                "trust-root hash differs"
            );
        }
        use rsa::pkcs8::EncodePublicKey;
        let app_spki = crate::crypto::github_app_key(&config.github_app_private_key)?
            .to_public_key()
            .to_public_key_der()?;
        let mut lineages = BTreeMap::new();
        let mut names = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for repo in &config.repositories {
            ensure!(
                repo.id > 0
                    && repo.revision > 0
                    && names.insert(repo.name.clone())
                    && ids.insert(repo.id),
                "invalid repository identity/revision"
            );
            let parts: Vec<_> = repo.name.split('/').collect();
            ensure!(
                parts.len() == 2
                    && parts.iter().all(|p| !p.is_empty()
                        && p.chars()
                            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))),
                "invalid repository name"
            );
            repo.validate_workflow_authorization()?;
            ensure!(
                repo.builder.repository_id > 0
                    && safe_path(&repo.builder.repository)
                    && repo.builder.repository.split('/').count() == 2
                    && workflow_path(&repo.builder.workflow)
                    && !repo.builder.refs.is_empty(),
                "invalid builder policy"
            );
            let receipt = keys
                .get(&repo.receipt_key)
                .ok_or_else(|| anyhow::anyhow!("receipt key missing"))?;
            ensure!(
                receipt.spki()?.as_slice() != app_spki.as_bytes(),
                "receipt key shares GitHub App key material"
            );
            ensure!(
                receipt.rsa_bits().is_some_and(|n| n >= 2048),
                "receipt key must be RSA with at least 2048 bits"
            );
            ensure!(
                !repo.refs.is_empty()
                    && repo
                        .refs
                        .iter()
                        .all(|r| r.starts_with("refs/heads/") || r.starts_with("refs/tags/")),
                "explicit refs required"
            );
            ensure!(
                !repo.events.is_empty()
                    && !repo.runners.is_empty()
                    && repo.runners.iter().all(|r| r == "github-hosted"),
                "explicit build event/runner policy required"
            );
            ensure!(
                ["public", "private"].contains(&repo.visibility.as_str())
                    && (if config.version == 4 {
                        repo.visibility == "public"
                    } else {
                        config.trust_roots.contains_key(&repo.visibility)
                    }),
                "trust profile missing"
            );
            ensure!(!repo.profiles.is_empty(), "signing profiles missing");
            for (profile_id, profile) in &repo.profiles {
                ensure!(valid_profile(profile_id), "invalid profile ID");
                ensure!(
                    [&profile.apk_artifact, &profile.aab_artifact]
                        .iter()
                        .all(|s| !s.is_empty()
                            && s.len() <= 200
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_{}.".contains(&b)))
                        && safe_path(&profile.apk_file)
                        && safe_path(&profile.aab_file),
                    "invalid artifact selector"
                );
                let s = &profile.signing;
                ensure!(
                    [28, 33].contains(&s.rotation_min_sdk),
                    "rotation SDK must be 28 or 33"
                );
                let key = |id: &str| {
                    keys.get(id)
                        .ok_or_else(|| anyhow::anyhow!("key reference missing: {id}"))
                };
                let original = key(&s.original_key)?;
                let current = key(&s.current_key)?;
                let upload = key(&s.upload_key)?;
                let transparency = key(&s.transparency_key)?;
                validate_rsa_roles(s, original, current, upload, transparency)?;
                ensure!(
                    [original, current, upload, transparency]
                        .iter()
                        .all(|k| k.algorithm() == crate::crypto::RSA_SHA256),
                    "classical, upload and transparency keys must be RSA"
                );
                let receipt_spki = receipt.spki()?;
                ensure!(
                    [original, current, upload, transparency]
                        .iter()
                        .all(|k| k.spki().is_ok_and(|s| s != receipt_spki)),
                    "receipt key shares Android signing material"
                );
                let lineage =
                    read_lineage(&s.lineage, &s.lineage_sha256, config.max_lineage_bytes)?;
                lineage.validate(s.allow_rollback)?;
                ensure!(
                    lineage.nodes[0].certificate == original.certificate
                        && lineage.last()?.certificate == current.certificate,
                    "lineage key roles differ"
                );
                let hybrid = if let Some(h) = &s.hybrid {
                    let c = key(&h.classical_key)?;
                    let p = key(&h.pqc_key)?;
                    let PrivateKey::Rsa(rsa) = &c.private else {
                        anyhow::bail!("hybrid classical signer must be RSA")
                    };
                    use rsa::traits::PublicKeyParts;
                    ensure!(
                        rsa.n().bits() == 4096 && p.algorithm() == crate::crypto::ML_DSA,
                        "hybrid requires RSA-4096 and ML-DSA-65"
                    );
                    let cl = read_lineage(
                        &h.classical_lineage,
                        &h.classical_lineage_sha256,
                        config.max_lineage_bytes,
                    )?;
                    let pl = read_lineage(
                        &h.pqc_lineage,
                        &h.pqc_lineage_sha256,
                        config.max_lineage_bytes,
                    )?;
                    let effective = read_lineage(
                        &h.effective_lineage,
                        &h.effective_lineage_sha256,
                        config.max_lineage_bytes,
                    )?;
                    validate_hybrid(&cl, &pl, s.allow_rollback)?;
                    effective.validate(s.allow_rollback)?;
                    ensure!(
                        cl.last()?.certificate == c.certificate
                            && pl.last()?.certificate == p.certificate,
                        "hybrid key mismatch"
                    );
                    let mut ancestry = cl.nodes[..cl.nodes.len() - 1].iter();
                    ensure!(
                        lineage
                            .nodes
                            .iter()
                            .all(|n| ancestry.by_ref().any(|a| a.certificate == n.certificate)),
                        "hybrid history lacks ordered classical fallback ancestry"
                    );
                    ensure!(
                        effective.extends(&cl)
                            && effective.nodes.len() == cl.nodes.len() + 1
                            && effective.last()?.certificate == p.certificate,
                        "hybrid effective lineage mismatch"
                    );
                    ensure!(
                        c.spki()? != current.spki()? && c.spki()? != original.spki()?,
                        "hybrid key material reused"
                    );
                    for old in &cl.nodes[..cl.nodes.len() - 1] {
                        use der::{Decode, Encode};
                        let old = x509_cert::Certificate::from_der(&old.certificate)?
                            .tbs_certificate
                            .subject_public_key_info
                            .to_der()?;
                        ensure!(
                            old != c.spki()? && old != p.spki()?,
                            "hybrid key material reused from signing history"
                        );
                    }
                    Some((cl, pl, effective))
                } else {
                    None
                };
                let transparency_spki = transparency.spki()?;
                for node in lineage.nodes.iter().chain(
                    hybrid
                        .iter()
                        .flat_map(|(c, p, _)| c.nodes.iter().chain(&p.nodes)),
                ) {
                    use der::{Decode, Encode};
                    let cert = x509_cert::Certificate::from_der(&node.certificate)?;
                    let history_spki = cert.tbs_certificate.subject_public_key_info.to_der()?;
                    ensure!(
                        receipt_spki != history_spki,
                        "receipt key shares Android signing history"
                    );
                    ensure!(
                        transparency_spki != history_spki,
                        "transparency key shares APK key material"
                    );
                }
                ensure!(
                    transparency_spki != upload.spki()?,
                    "transparency key shares upload key material"
                );
                ensure!(
                    lineages
                        .insert((repo.id, profile_id.clone()), (lineage, hybrid))
                        .is_none(),
                    "duplicate signing profile"
                );
            }
        }
        ensure!(
            read_secret(&config.webhook_secret)?.len() >= 32,
            "webhook secret must be at least 32 bytes"
        );
        Ok(Self {
            config,
            keys,
            lineages,
        })
    }
    pub fn release_policy(
        &self,
        repo: &Repository,
        signer_revision: &str,
    ) -> Result<serde_json::Value> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        ensure!(
            signer_revision.len() == 40 && signer_revision.bytes().all(|b| b.is_ascii_hexdigit()),
            "full deployed signer commit required"
        );
        let receipt = &self.keys[&repo.receipt_key];
        let profiles = repo.profiles.iter().map(|(name,p)| {
            let s = &p.signing;
            let (lineage, _) = &self.lineages[&(repo.id, name.clone())];
            Ok((name.clone(), serde_json::json!({"package":p.package,"lineage_sha256":lineage.digest()?,"rotation_min_sdk":s.rotation_min_sdk,"hybrid_min_sdk":s.hybrid.as_ref().map(|_|37),"keys":{"original":self.keys[&s.original_key].fingerprint(),"classical":self.keys[&s.current_key].fingerprint(),"upload":self.keys[&s.upload_key].fingerprint(),"transparency":self.keys[&s.transparency_key].fingerprint(),"hybrid":s.hybrid.as_ref().map(|h|serde_json::json!({"rsa":self.keys[&h.classical_key].fingerprint(),"pqc":self.keys[&h.pqc_key].fingerprint()}))}})))
        }).collect::<Result<BTreeMap<_,_>>>()?;
        let mut policy = serde_json::json!({"version":self.config.version,"repository":repo.name,"repository_id":repo.id,"visibility":repo.visibility,"policy_hash":self.policy_hash(repo)?,"revision":repo.revision,"refs":repo.refs,"callers":repo.callers,"builder":repo.builder,"finalizer":repo.finalizer,"receipt_keys":{receipt.fingerprint():STANDARD.encode(&receipt.certificate)},"profiles":profiles,"signer_revision":signer_revision});
        policy["receipt_namespace"] = serde_json::json!(repo.receipt_namespace);
        if let Some(authority) = &self.config.trust_authority {
            policy["trust_authority"] = serde_json::to_value(authority)?;
        }
        Ok(policy)
    }
    pub fn policy_hash(&self, repo: &Repository) -> Result<String> {
        let mut roles = vec![&repo.receipt_key];
        for p in repo.profiles.values() {
            let signing = &p.signing;
            roles.extend([
                &signing.original_key,
                &signing.current_key,
                &signing.upload_key,
                &signing.transparency_key,
            ]);
            if let Some(hybrid) = &signing.hybrid {
                roles.extend([&hybrid.classical_key, &hybrid.pqc_key]);
            }
        }
        let pins = roles
            .into_iter()
            .map(|id| {
                let key = self
                    .config
                    .keys
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("policy key missing"))?;
                Ok((id, &key.fingerprint))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        if let Some(authority) = &self.config.trust_authority {
            return Ok(crate::sha256(&serde_json::to_vec(&serde_json::json!({
                "version":4,"repository":repo,"key_certificate_pins":pins,"trust_authority":authority,
                "max_artifact_bytes":self.config.max_artifact_bytes,"max_lineage_bytes":self.config.max_lineage_bytes,
            }))?));
        }
        let trust = self
            .config
            .trust_roots
            .get(&repo.visibility)
            .ok_or_else(|| anyhow::anyhow!("policy trust missing"))?;
        Ok(crate::sha256(&serde_json::to_vec(&serde_json::json!({
            "version": 3, "repository": repo, "key_certificate_pins": pins,
            "trust_root": trust, "max_artifact_bytes": self.config.max_artifact_bytes,
            "max_lineage_bytes": self.config.max_lineage_bytes,
        }))?))
    }
}

fn validate_rsa_roles(
    signing: &Signing,
    original: &SigningKey,
    current: &SigningKey,
    upload: &SigningKey,
    transparency: &SigningKey,
) -> Result<()> {
    let original_min = if signing.allow_legacy_rsa_1024 {
        1024
    } else {
        2048
    };
    ensure!(
        original.rsa_bits().is_some_and(|n| n >= original_min),
        "original APK key is too small; legacy RSA-1024 requires an explicit profile opt-in"
    );
    let current_min =
        if signing.allow_legacy_rsa_1024 && original.fingerprint() == current.fingerprint() {
            1024
        } else {
            2048
        };
    ensure!(
        current.rsa_bits().is_some_and(|n| n >= current_min),
        "rotated APK key must be RSA with at least 2048 bits"
    );
    ensure!(
        [upload, transparency]
            .iter()
            .all(|k| k.rsa_bits().is_some_and(|n| n >= 2048)),
        "upload and transparency keys must be RSA with at least 2048 bits"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repository_requires_the_bathysign_receipt_namespace() {
        let config: Config =
            serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
        let mut repository = serde_json::to_value(&config.repositories[0]).unwrap();
        repository
            .as_object_mut()
            .unwrap()
            .remove("receipt_namespace");
        assert!(serde_json::from_value::<Repository>(repository.clone()).is_err());
        for namespace in ["android-signer", "attacker"] {
            repository["receipt_namespace"] = serde_json::json!(namespace);
            let decoded: Repository = serde_json::from_value(repository.clone()).unwrap();
            assert!(decoded.validate_workflow_authorization().is_err());
        }
        assert!(
            config.repositories[0]
                .validate_workflow_authorization()
                .is_ok()
        );
    }

    #[test]
    fn only_trusted_workflow_identities_are_supported() {
        let config: Config =
            serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
        let valid = config.repositories[0].clone();
        valid.validate_workflow_authorization().unwrap();
        let mut repo = valid.clone();
        repo.builder.repository_id = repo.id;
        assert!(repo.validate_workflow_authorization().is_err());
        repo = valid.clone();
        repo.builder.refs = vec!["refs/tags/v*".into()];
        assert!(repo.validate_workflow_authorization().is_err());
        repo = valid.clone();
        repo.finalizer.repository = "attacker/builders".into();
        assert!(repo.validate_workflow_authorization().is_err());
        repo = valid.clone();
        repo.finalizer.workflow = repo.builder.workflow.clone();
        assert!(repo.validate_workflow_authorization().is_err());
        repo = valid.clone();
        repo.callers.push(repo.callers[0].clone());
        assert!(repo.validate_workflow_authorization().is_err());
        for field in ["authorization", "sha256", "helpers"] {
            let mut serialized = serde_json::to_value(&valid).unwrap();
            serialized["builder"][field] = serde_json::json!([]);
            assert!(serde_json::from_value::<Repository>(serialized).is_err());
        }
        let mut serialized = serde_json::to_value(&valid).unwrap();
        serialized.as_object_mut().unwrap().remove("finalizer");
        assert!(serde_json::from_value::<Repository>(serialized).is_err());
    }
    #[test]
    fn legacy_exception_is_limited_to_the_existing_apk_identity() {
        let mut signing: Signing = serde_json::from_value(serde_json::json!({
            "original_key":"old", "current_key":"old", "upload_key":"upload",
            "transparency_key":"transparency", "lineage":"lineage.bin",
            "lineage_sha256":"0".repeat(64), "hybrid":null
        }))
        .unwrap();
        assert!(!signing.allow_legacy_rsa_1024);
        assert!(
            serde_json::to_value(&signing)
                .unwrap()
                .get("allow_legacy_rsa_1024")
                .is_none()
        );
        let make_key = |bits, label| SigningKey {
            private: PrivateKey::Rsa(Box::new(
                rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).unwrap(),
            )),
            certificate: vec![label],
        };
        let old = make_key(1024, 1);
        let strong = make_key(2048, 2);
        let other_weak = make_key(1024, 3);
        assert!(validate_rsa_roles(&signing, &old, &old, &strong, &strong).is_err());
        signing.allow_legacy_rsa_1024 = true;
        assert!(validate_rsa_roles(&signing, &old, &old, &strong, &strong).is_ok());
        assert!(validate_rsa_roles(&signing, &old, &strong, &strong, &strong).is_ok());
        assert!(validate_rsa_roles(&signing, &old, &other_weak, &strong, &strong).is_err());
        assert!(validate_rsa_roles(&signing, &old, &old, &old, &strong).is_err());
        assert!(validate_rsa_roles(&signing, &old, &old, &strong, &old).is_err());
    }
    #[test]
    fn replacing_role_key_or_trust_pin_requires_new_policy_revision() {
        let mut config: Config =
            serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
        for (name, key) in &mut config.keys {
            key.fingerprint = crate::sha256(name.as_bytes());
        }
        let mut loaded = Loaded {
            config,
            keys: BTreeMap::new(),
            lineages: BTreeMap::new(),
        };
        let original = loaded.policy_hash(&loaded.config.repositories[0]).unwrap();
        loaded.config.repositories[0]
            .profiles
            .values_mut()
            .next()
            .unwrap()
            .signing
            .allow_legacy_rsa_1024 = true;
        assert_ne!(
            original,
            loaded.policy_hash(&loaded.config.repositories[0]).unwrap()
        );
        loaded.config.repositories[0]
            .profiles
            .values_mut()
            .next()
            .unwrap()
            .signing
            .allow_legacy_rsa_1024 = false;
        assert_eq!(
            original,
            loaded.policy_hash(&loaded.config.repositories[0]).unwrap()
        );
        loaded
            .config
            .keys
            .get_mut("transparency")
            .unwrap()
            .fingerprint = "e".repeat(64);
        let changed_key = loaded.policy_hash(&loaded.config.repositories[0]).unwrap();
        assert_ne!(original, changed_key);
        loaded.config.trust_roots.get_mut("public").unwrap().sha256 = "f".repeat(64);
        let changed_trust = loaded.policy_hash(&loaded.config.repositories[0]).unwrap();
        assert_ne!(changed_key, changed_trust);
        #[cfg(feature = "collector")]
        {
            let temporary = tempfile::tempdir().unwrap();
            let store = crate::collector::Store::open(
                &temporary.path().join("audit.sqlite"),
                b"01234567890123456789012345678901",
            )
            .unwrap();
            let mut activation = crate::ledger::Activation {
                repository_id: 1,
                revision: 1,
                policy_hash: original,
                version: 2,
                profiles: std::collections::BTreeMap::from([(
                    "default".into(),
                    crate::ledger::History {
                        classical_history: vec!["a".repeat(64)],
                        hybrid_history: vec![],
                    },
                )]),
            };
            store.activate(&activation).unwrap();
            activation.policy_hash = changed_trust;
            assert!(store.activate(&activation).is_err());
            activation.revision = 2;
            store.activate(&activation).unwrap();
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/config.rs"]
mod loading_tests;
