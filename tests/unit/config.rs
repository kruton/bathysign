//! Configuration integration tests use real, disposable signing identities.
use super::*;
use serde_json::{Value, json};
use std::sync::LazyLock;

struct Fixture {
    _directory: tempfile::TempDir,
    config: Config,
    hybrid: Config,
    legacy: Config,
}
fn identity(directory: &Path, name: &str, algorithm: &str, bits: &str) -> KeySpec {
    let pem = directory.join(format!("{name}.key.pem"));
    let cert = directory.join(format!("{name}.pem"));
    let mut command = std::process::Command::new("openssl");
    command
        .args(["genpkey", "-algorithm", algorithm, "-out"])
        .arg(&pem);
    if algorithm == "RSA" {
        command.args(["-pkeyopt", &format!("rsa_keygen_bits:{bits}")]);
    }
    assert!(command.output().unwrap().status.success());
    assert!(
        std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&pem)
            .args(["-out"])
            .arg(&cert)
            .args(["-days", "2", "-subj", "/CN=Disposable-config-fixture"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let key = if algorithm == "RSA" {
        pem
    } else {
        let der = directory.join(format!("{name}.pk8"));
        assert!(
            std::process::Command::new("openssl")
                .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
                .arg(pem)
                .args(["-outform", "DER", "-out"])
                .arg(&der)
                .output()
                .unwrap()
                .status
                .success()
        );
        der
    };
    let loaded = if bits == "1024" {
        SigningKey::load_legacy_apk(&key, &cert)
    } else {
        SigningKey::load(&key, &cert)
    }
    .unwrap();
    KeySpec {
        private_key: key,
        certificate: cert,
        fingerprint: loaded.fingerprint(),
    }
}
fn store_lineage(directory: &Path, name: &str, lineage: &Lineage) -> (PathBuf, String) {
    let path = directory.join(name);
    std::fs::write(&path, lineage.file().unwrap()).unwrap();
    (path, lineage.digest().unwrap())
}
static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    crate::initialize_test_crypto();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut config: Config =
        serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap();
    for (name, spec) in &mut config.keys {
        *spec = identity(root, name, "RSA", "2048");
    }
    config.github_app_private_key = identity(root, "app", "RSA", "2048").private_key;
    config.webhook_secret = root.join("webhook-secret");
    std::fs::write(&config.webhook_secret, b"01234567890123456789012345678901").unwrap();
    let trust_path = root.join("trusted-root.json");
    std::fs::write(
        &trust_path,
        include_bytes!("../fixtures/public-trusted-root.json"),
    )
    .unwrap();
    for trust in config.trust_roots.values_mut() {
        trust.file = trust_path.clone();
        trust.sha256 = crate::sha256(&std::fs::read(&trust_path).unwrap());
        trust.valid_until = now().unwrap() + 3600;
    }
    let spec = &config.keys["apk-a"];
    let apk = SigningKey::load(&spec.private_key, &spec.certificate).unwrap();
    let lineage = Lineage::root(&apk);
    let (path, digest) = store_lineage(root, "lineage.bin", &lineage);
    let repo = &mut config.repositories[0];
    let mut profile = repo.profiles.values().next().unwrap().clone();
    profile.signing.lineage = path;
    profile.signing.lineage_sha256 = digest;
    profile.archive_resource = None;
    repo.profiles = BTreeMap::from([("default".into(), profile)]);
    let mut hybrid = config.clone();
    let rsa_spec = identity(root, "hybrid-rsa", "RSA", "4096");
    let pqc_spec = identity(root, "hybrid-pqc", "ML-DSA-65", "");
    let rsa = SigningKey::load(&rsa_spec.private_key, &rsa_spec.certificate).unwrap();
    let pqc = SigningKey::load(&pqc_spec.private_key, &pqc_spec.certificate).unwrap();
    let classical = lineage
        .append(&apk, &rsa, crate::lineage::DEFAULT_FLAGS)
        .unwrap();
    let quantum = lineage
        .append(&apk, &pqc, crate::lineage::DEFAULT_FLAGS)
        .unwrap();
    let effective = classical
        .append(&rsa, &pqc, crate::lineage::DEFAULT_FLAGS)
        .unwrap();
    let (classical_lineage, classical_lineage_sha256) =
        store_lineage(root, "hybrid-classical.bin", &classical);
    let (pqc_lineage, pqc_lineage_sha256) = store_lineage(root, "hybrid-pqc.bin", &quantum);
    let (effective_lineage, effective_lineage_sha256) =
        store_lineage(root, "hybrid-effective.bin", &effective);
    hybrid.keys.insert("hybrid-rsa".into(), rsa_spec);
    hybrid.keys.insert("hybrid-pqc".into(), pqc_spec);
    hybrid.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing
        .hybrid = Some(HybridConfig {
        classical_key: "hybrid-rsa".into(),
        pqc_key: "hybrid-pqc".into(),
        classical_lineage,
        classical_lineage_sha256,
        pqc_lineage,
        pqc_lineage_sha256,
        effective_lineage,
        effective_lineage_sha256,
    });
    let mut legacy = config.clone();
    let legacy_spec = identity(root, "legacy", "RSA", "1024");
    let old =
        SigningKey::load_legacy_apk(&legacy_spec.private_key, &legacy_spec.certificate).unwrap();
    let (path, digest) = store_lineage(root, "legacy-lineage.bin", &Lineage::root(&old));
    legacy.keys.insert("apk-a".into(), legacy_spec);
    let signing = &mut legacy.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing;
    signing.allow_legacy_rsa_1024 = true;
    signing.lineage = path;
    signing.lineage_sha256 = digest;
    Fixture {
        _directory: directory,
        config,
        hybrid,
        legacy,
    }
});

fn load(config: &Config) -> Result<Loaded> {
    load_json(&serde_json::to_value(config).unwrap())
}
fn load_json(value: &Value) -> Result<Loaded> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    Loaded::read(&path)
}
fn failure(config: &Config, expected: &str) {
    let error = load(config)
        .err()
        .expect("unsafe configuration was accepted");
    assert!(
        error.to_string().contains(expected),
        "wanted {expected}: {error}"
    );
}
fn authority() -> crate::trust::Authority {
    crate::trust::Authority {
        authority: crate::trust::AUTHORITY.into(),
        target: crate::trust::TARGET.into(),
        bootstrap_sha256: crate::sha256(crate::trust::BOOTSTRAP),
        epoch: "a".repeat(64),
    }
}

#[test]
fn static_dynamic_legacy_and_hybrid_configurations_load_and_export_public_policy() {
    for config in [&FIXTURE.config, &FIXTURE.legacy, &FIXTURE.hybrid] {
        let loaded = load(config).unwrap();
        let repo = &loaded.config.repositories[0];
        let policy = loaded.release_policy(repo, &"a".repeat(40)).unwrap();
        assert_eq!(policy["policy_hash"], loaded.policy_hash(repo).unwrap());
        assert_eq!(policy["receipt_namespace"], "bathysign");
        assert_eq!(
            policy["profiles"]["default"]["lineage_sha256"],
            repo.profiles["default"].signing.lineage_sha256
        );
        assert!(!policy.to_string().contains("PRIVATE KEY"));
        assert_eq!(loaded.lineages.len(), 1);
        if config.repositories[0].profiles["default"]
            .signing
            .hybrid
            .is_some()
        {
            assert_eq!(policy["profiles"]["default"]["hybrid_min_sdk"], 37);
            assert!(loaded.lineages.values().next().unwrap().1.is_some());
        }
        assert!(loaded.release_policy(repo, "main").is_err());
    }
    let mut config = FIXTURE.config.clone();
    config.version = 4;
    config.trust_roots.clear();
    config.trust_authority = Some(authority());
    let loaded = load(&config).unwrap();
    let policy = loaded
        .release_policy(&loaded.config.repositories[0], &"b".repeat(40))
        .unwrap();
    assert_eq!(policy["version"], 4);
    assert_eq!(
        policy["trust_authority"],
        serde_json::to_value(authority()).unwrap()
    );
}

#[test]
fn configuration_versions_limits_and_repository_policies_fail_closed() {
    let base = serde_json::to_value(&FIXTURE.config).unwrap();
    for (pointer, changed, expected) in [
        ("/version", json!(2), "version 3 or 4"),
        ("/repositories", json!([]), "no repositories"),
        ("/audit_url", json!("http://audit.example"), "HTTPS"),
        (
            "/audit_url",
            json!("https://audit.example/"),
            "trailing slash",
        ),
        ("/max_artifact_bytes", json!(0), "artifact size limit"),
        (
            "/max_artifact_bytes",
            json!(134217729),
            "artifact size limit",
        ),
        ("/max_lineage_bytes", json!(16), "lineage size limit"),
        ("/max_lineage_bytes", json!(16777217), "lineage size limit"),
        ("/repositories/0/id", json!(0), "repository identity"),
        ("/repositories/0/revision", json!(0), "repository identity"),
        (
            "/repositories/0/name",
            json!("invalid owner/repo"),
            "repository name",
        ),
        ("/repositories/0/refs", json!([]), "explicit refs"),
        ("/repositories/0/events", json!([]), "explicit build event"),
        (
            "/repositories/0/runners",
            json!(["self-hosted"]),
            "explicit build event",
        ),
        (
            "/repositories/0/visibility",
            json!("internal"),
            "trust profile missing",
        ),
        (
            "/repositories/0/profiles",
            json!({}),
            "signing profiles missing",
        ),
        (
            "/repositories/0/profiles/default/apk_file",
            json!("../outside.apk"),
            "artifact selector",
        ),
        (
            "/repositories/0/profiles/default/apk_artifact",
            json!("bad/name"),
            "artifact selector",
        ),
        (
            "/repositories/0/profiles/default/signing/rotation_min_sdk",
            json!(32),
            "rotation SDK",
        ),
        (
            "/repositories/0/profiles/default/signing/current_key",
            json!("absent"),
            "key reference missing",
        ),
        (
            "/repositories/0/profiles/default/signing/current_key",
            json!("upload"),
            "lineage key roles differ",
        ),
        (
            "/repositories/0/receipt_key",
            json!("absent"),
            "receipt key missing",
        ),
        (
            "/repositories/0/receipt_key",
            json!("apk-a"),
            "shares Android signing material",
        ),
        (
            "/repositories/0/profiles/default/signing/transparency_key",
            json!("apk-a"),
            "shares APK key material",
        ),
        (
            "/repositories/0/profiles/default/signing/transparency_key",
            json!("upload"),
            "shares upload key material",
        ),
    ] {
        let mut value = base.clone();
        *value.pointer_mut(pointer).unwrap() = changed;
        let error = load_json(&value).err().expect("unsafe policy accepted");
        assert!(
            error.to_string().contains(expected),
            "{pointer}: {error}; wanted {expected}"
        );
    }
}

#[test]
fn pins_expiry_secret_sizes_and_key_separation_are_enforced() {
    let mut config = FIXTURE.config.clone();
    config.keys.get_mut("apk-a").unwrap().fingerprint = "0".repeat(64);
    failure(&config, "key fingerprint differs");
    config = FIXTURE.config.clone();
    config.trust_roots.get_mut("public").unwrap().valid_until = 1;
    failure(&config, "trust material expired");
    config = FIXTURE.config.clone();
    config.trust_roots.get_mut("public").unwrap().sha256 = "0".repeat(64);
    failure(&config, "trust-root hash differs");
    config = FIXTURE.config.clone();
    config.github_app_private_key = config.keys["receipt"].private_key.clone();
    failure(&config, "receipt key shares GitHub App");
    config = FIXTURE.config.clone();
    config.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing
        .lineage_sha256 = "0".repeat(64);
    failure(&config, "lineage hash differs");
    let directory = tempfile::tempdir().unwrap();
    let large = directory.path().join("large-lineage");
    std::fs::write(&large, vec![0; 2048]).unwrap();
    config = FIXTURE.config.clone();
    config.max_lineage_bytes = 1024;
    config.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing
        .lineage = large;
    failure(&config, "lineage too large");
    let short = directory.path().join("short-secret");
    std::fs::write(&short, b"too-short").unwrap();
    config = FIXTURE.config.clone();
    config.webhook_secret = short;
    failure(&config, "webhook secret must be at least 32 bytes");
    assert!(read_secret(directory.path()).is_err());
    let oversized = directory.path().join("oversized-secret");
    std::fs::write(&oversized, vec![0; 1024 * 1024 + 1]).unwrap();
    assert!(read_secret(&oversized).is_err());
}

#[test]
fn dynamic_trust_cannot_mix_modes_or_use_unapproved_private_trust() {
    let mut config = FIXTURE.config.clone();
    config.version = 4;
    failure(&config, "trust authority missing");
    config.trust_authority = Some(authority());
    failure(&config, "cannot fall back to static roots");
    config.trust_roots.clear();
    config.repositories[0].visibility = "private".into();
    failure(&config, "trust profile missing");
    config.version = 3;
    failure(
        &config,
        "static-trust configuration cannot enable dynamic trust",
    );
}

#[test]
fn profiles_and_repositories_are_unique_and_schema_is_strict() {
    let mut config = FIXTURE.config.clone();
    config.repositories.push(config.repositories[0].clone());
    failure(&config, "repository identity/revision");
    config = FIXTURE.config.clone();
    let profile = config.repositories[0].profiles.remove("default").unwrap();
    config.repositories[0]
        .profiles
        .insert("INVALID".into(), profile);
    failure(&config, "invalid profile ID");
    let mut value = serde_json::to_value(&FIXTURE.config).unwrap();
    value["unexpected_setting"] = json!(true);
    assert!(load_json(&value).is_err());
    value.as_object_mut().unwrap().remove("unexpected_setting");
    value.as_object_mut().unwrap().remove("max_artifact_bytes");
    value.as_object_mut().unwrap().remove("max_lineage_bytes");
    let loaded = load_json(&value).unwrap();
    assert_eq!(loaded.config.max_artifact_bytes, 64 * 1024 * 1024);
    assert_eq!(loaded.config.max_lineage_bytes, DEFAULT_LIMIT);
}

#[test]
fn hybrid_policies_bind_key_algorithms_and_complete_effective_lineages() {
    let mut config = FIXTURE.hybrid.clone();
    config.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing
        .hybrid
        .as_mut()
        .unwrap()
        .classical_key = "hybrid-pqc".into();
    failure(&config, "hybrid classical signer must be RSA");
    config = FIXTURE.hybrid.clone();
    config.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing
        .hybrid
        .as_mut()
        .unwrap()
        .pqc_key = "upload".into();
    failure(&config, "hybrid requires RSA-4096 and ML-DSA-65");
    config = FIXTURE.hybrid.clone();
    let hybrid = config.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing
        .hybrid
        .as_mut()
        .unwrap();
    hybrid.effective_lineage = hybrid.classical_lineage.clone();
    hybrid.effective_lineage_sha256 = hybrid.classical_lineage_sha256.clone();
    failure(&config, "hybrid effective lineage mismatch");
    config = FIXTURE.hybrid.clone();
    let upload = &config.keys["upload"];
    let key = SigningKey::load(&upload.private_key, &upload.certificate).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (path, digest) = store_lineage(directory.path(), "different-history", &Lineage::root(&key));
    let signing = &mut config.repositories[0]
        .profiles
        .get_mut("default")
        .unwrap()
        .signing;
    signing.original_key = "upload".into();
    signing.current_key = "upload".into();
    signing.lineage = path;
    signing.lineage_sha256 = digest;
    failure(
        &config,
        "hybrid history lacks ordered classical fallback ancestry",
    );
}

#[test]
fn workflow_release_pins_are_exported_and_bound_to_policy_hash() {
    let loaded = load(&FIXTURE.config).unwrap();
    let original = &loaded.config.repositories[0];
    let hash = loaded.policy_hash(original).unwrap();
    let mut changed = original.clone();
    changed.builder.commit = "b".repeat(40);
    changed.finalizer.commit = changed.builder.commit.clone();
    assert_ne!(hash, loaded.policy_hash(&changed).unwrap());
    changed = original.clone();
    changed.builder.refs = vec!["refs/tags/v0.2.2".into()];
    changed.finalizer.refs = changed.builder.refs.clone();
    assert_ne!(hash, loaded.policy_hash(&changed).unwrap());
    changed = original.clone();
    changed.builder.workflow_digest = Some("e".repeat(40));
    changed.finalizer.workflow_digest = changed.builder.workflow_digest.clone();
    changed.validate_workflow_authorization().unwrap();
    assert_ne!(hash, loaded.policy_hash(&changed).unwrap());
    let exported = loaded.release_policy(&changed, &"a".repeat(40)).unwrap();
    assert_eq!(exported["builder"]["workflow_digest"], "e".repeat(40));
    changed.finalizer.workflow_digest = Some("f".repeat(40));
    assert!(changed.validate_workflow_authorization().is_err());
    changed = original.clone();
    changed.builder.workflow_digest = Some("E".repeat(40));
    assert!(changed.validate_workflow_authorization().is_err());
    let policy = loaded.release_policy(original, &"a".repeat(40)).unwrap();
    assert_eq!(policy["builder"]["commit"], original.builder.commit);
    assert_eq!(policy["finalizer"]["commit"], original.finalizer.commit);
}
