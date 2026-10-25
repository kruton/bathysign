use bathysign::{
    apk::{self, Hybrid, Profile},
    archive::{self, Entries, Entry},
    crypto::SigningKey,
    jar,
    lineage::{DEFAULT_FLAGS, DEFAULT_LIMIT, Lineage},
    transparency,
};
use std::{process::Command, sync::LazyLock};
struct Fixtures {
    dir: tempfile::TempDir,
}
static FIXTURES: LazyLock<Fixtures> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    for (name, algorithm) in [
        ("a", "RSA"),
        ("b", "RSA"),
        ("c", "RSA"),
        ("hybrid", "RSA"),
        ("pqc", "ML-DSA-65"),
        ("pqc2", "ML-DSA-65"),
        ("hybrid2", "RSA"),
        ("transparency", "RSA"),
        ("legacy", "RSA"),
        ("too-small", "RSA"),
    ] {
        let pem = dir.path().join(format!("{name}.key.pem"));
        let mut command = Command::new("openssl");
        command
            .args(["genpkey", "-algorithm", algorithm, "-out"])
            .arg(&pem);
        if algorithm == "RSA" {
            command.args([
                "-pkeyopt",
                if name.starts_with("hybrid") {
                    "rsa_keygen_bits:4096"
                } else if name == "legacy" {
                    "rsa_keygen_bits:1024"
                } else if name == "too-small" {
                    "rsa_keygen_bits:512"
                } else {
                    "rsa_keygen_bits:2048"
                },
            ]);
        }
        assert!(command.output().unwrap().status.success());
        let der = dir.path().join(format!("{name}.pk8"));
        assert!(
            Command::new("openssl")
                .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
                .arg(&pem)
                .args(["-outform", "DER", "-out"])
                .arg(&der)
                .output()
                .unwrap()
                .status
                .success()
        );
        let cert = dir.path().join(format!("{name}.pem"));
        assert!(
            Command::new("openssl")
                .args(["req", "-new", "-x509", "-key"])
                .arg(&pem)
                .args(["-out"])
                .arg(&cert)
                .args(["-days", "10950", "-subj", &format!("/CN=Test-{name}")])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    Fixtures { dir }
});
fn key(name: &str) -> SigningKey {
    SigningKey::load(
        &FIXTURES.dir.path().join(format!("{name}.pk8")),
        &FIXTURES.dir.path().join(format!("{name}.pem")),
    )
    .unwrap()
}
fn reference(path: &std::path::Path, sdk: u32) {
    reference_expected(path, sdk, None);
}
fn reference_expected(path: &std::path::Path, sdk: u32, expected_signer: Option<&str>) {
    let Some(mut classpath) = std::env::var_os("BATHYSIGN_REFERENCE_CLASSES") else {
        return;
    };
    if sdk < 37
        && let Some(legacy) = std::env::var_os("BATHYSIGN_LEGACY_CLASSES")
    {
        classpath = legacy;
    }
    let java = std::env::var_os("BATHYSIGN_JAVA").unwrap_or_else(|| "java".into());
    let mut command = Command::new(java);
    command
        .arg("-cp")
        .arg(classpath)
        .args(["Reference", "apk"])
        .arg(path)
        .arg(sdk.to_string());
    if let Some(fingerprint) = expected_signer {
        command.arg(fingerprint);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "Android reference rejected API {sdk}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn original() -> Entries {
    if let Some(path) = std::env::var_os("BATHYSIGN_REFERENCE_APK") {
        let mut entries = archive::read(&std::fs::read(path).unwrap()).unwrap();
        entries.retain(|n, _| !n.starts_with("META-INF/"));
        entries
    } else {
        Entries::from([
            (
                "AndroidManifest.xml".into(),
                Entry {
                    bytes: b"manifest-test".to_vec(),
                    stored: false,
                },
            ),
            (
                "classes.dex".into(),
                Entry {
                    bytes: b"dex-test".to_vec(),
                    stored: false,
                },
            ),
        ])
    }
}
#[test]
fn rotation_signatures_match_android() {
    let a = key("a");
    let b = key("b");
    let c = key("c");
    let chain = Lineage::root(&a)
        .append(&a, &b, DEFAULT_FLAGS)
        .unwrap()
        .append(&b, &c, DEFAULT_FLAGS)
        .unwrap();
    let bytes = chain.file().unwrap();
    assert_eq!(Lineage::read(&bytes, DEFAULT_LIMIT).unwrap(), chain);
    let unsigned = archive::write(&original(), true).unwrap();
    for sdk in [28, 33] {
        let profile = Profile {
            original: &a,
            current: &c,
            lineage: &chain,
            rotation_min_sdk: sdk,
            hybrid: None,
        };
        let signed = apk::sign(&unsigned, &profile).unwrap();
        assert_eq!(apk::sign(&unsigned, &profile).unwrap(), signed);
        let path = FIXTURES.dir.path().join(format!("classical-{sdk}.apk"));
        std::fs::write(&path, &signed).unwrap();
        for platform in [24, 28, 32, 33, 36, 37] {
            let expected = if platform >= sdk {
                c.fingerprint()
            } else {
                a.fingerprint()
            };
            reference_expected(&path, platform, Some(&expected));
        }
        let mut corrupted = signed;
        corrupted[30] ^= 1;
        assert!(apk::verify_output(&corrupted, &profile).is_err());
    }
    if let Some(classes) = std::env::var_os("BATHYSIGN_REFERENCE_CLASSES") {
        let path = FIXTURES.dir.path().join("lineage.bin");
        std::fs::write(&path, &bytes).unwrap();
        let java = std::env::var_os("BATHYSIGN_JAVA").unwrap_or_else(|| "java".into());
        let out = Command::new(java)
            .arg("-cp")
            .arg(classes)
            .args(["Reference", "lineage"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn legacy_apk_identity_is_explicit_and_can_rotate_to_a_stronger_key() {
    let dir = FIXTURES.dir.path();
    assert!(SigningKey::load(&dir.join("legacy.pk8"), &dir.join("legacy.pem")).is_err());
    assert!(
        SigningKey::load_legacy_apk(&dir.join("too-small.pk8"), &dir.join("too-small.pem"))
            .is_err()
    );
    let old =
        SigningKey::load_legacy_apk(&dir.join("legacy.pk8"), &dir.join("legacy.pem")).unwrap();
    assert_eq!(old.rsa_bits(), Some(1024));
    let new = key("hybrid"); // The key rotation is RSA-1024 -> RSA-4096.
    for rotation_sdk in [28, 33] {
        for rotate in [false, true] {
            let chain = if rotate {
                Lineage::root(&old)
                    .append(&old, &new, DEFAULT_FLAGS)
                    .unwrap()
            } else {
                Lineage::root(&old)
            };
            let current = if rotate { &new } else { &old };
            let profile = Profile {
                original: &old,
                current,
                lineage: &chain,
                rotation_min_sdk: rotation_sdk,
                hybrid: None,
            };
            let mut entries = original();
            jar::sign(&mut entries, &old).unwrap();
            jar::verify_output(&entries, &old).unwrap();
            let signed = apk::sign(&archive::write(&entries, true).unwrap(), &profile).unwrap();
            apk::verify_output(&signed, &profile).unwrap();
            let path = dir.join(format!("legacy-{rotation_sdk}-{rotate}.apk"));
            std::fs::write(&path, signed).unwrap();
            for sdk in [24, 27, 28, 32, 33, 36, 37] {
                let expected = if rotate && sdk >= rotation_sdk {
                    new.fingerprint()
                } else {
                    old.fingerprint()
                };
                reference_expected(&path, sdk, Some(&expected));
            }
        }
    }
}

#[test]
fn certificate_only_rotation_preserves_authorization() {
    let old = key("a");
    let new = key("hybrid");
    let root = Lineage::root(&old);
    let chain = root
        .append_certificate(&old, &new.certificate, DEFAULT_FLAGS)
        .unwrap();
    assert_eq!(chain, root.append(&old, &new, DEFAULT_FLAGS).unwrap());
    assert!(
        root.append_certificate(&new, &old.certificate, DEFAULT_FLAGS)
            .is_err()
    );
    assert!(
        root.append_certificate(&old, b"invalid DER", DEFAULT_FLAGS)
            .is_err()
    );
    assert!(
        root.append_certificate(&old, &old.certificate, DEFAULT_FLAGS)
            .is_err()
    );
    let legacy = SigningKey::load_legacy_apk(
        &FIXTURES.dir.path().join("legacy.pk8"),
        &FIXTURES.dir.path().join("legacy.pem"),
    )
    .unwrap();
    assert!(
        root.append_certificate(&old, &legacy.certificate, DEFAULT_FLAGS)
            .is_err()
    );
    let pqc = key("pqc");
    let pqc_chain = root
        .append_certificate(&old, &pqc.certificate, DEFAULT_FLAGS)
        .unwrap();
    assert_eq!(pqc_chain, root.append(&old, &pqc, DEFAULT_FLAGS).unwrap());
    pqc_chain
        .append(&pqc, &new, DEFAULT_FLAGS)
        .unwrap()
        .validate(false)
        .unwrap();
}

#[test]
#[cfg(feature = "admin")]
fn admin_authorizes_a_public_certificate_without_the_successor_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let old = key("a");
    let new = key("hybrid");
    let input = dir.path().join("root.bin");
    let output = dir.path().join("rotated.bin");
    std::fs::write(&input, Lineage::root(&old).file().unwrap()).unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_bathysign-admin"))
            .arg("append")
            .arg("--input")
            .arg(&input)
            .arg("--old-key")
            .arg(FIXTURES.dir.path().join("a.pk8"))
            .arg("--old-cert")
            .arg(FIXTURES.dir.path().join("a.pem"))
            .arg("--new-cert")
            .arg(FIXTURES.dir.path().join("hybrid.pem"))
            .arg("--out")
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = invoke();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(
        Lineage::read(&bytes, DEFAULT_LIMIT).unwrap(),
        Lineage::root(&old)
            .append(&old, &new, DEFAULT_FLAGS)
            .unwrap()
    );
    assert!(
        !invoke().status.success(),
        "existing authorization must not be overwritten"
    );
    assert_eq!(std::fs::read(output).unwrap(), bytes);
}

/// Used by test-rotation-devices.py with disposable, debuggable AAPT2 APKs.
#[test]
fn export_rotation_device_fixtures() {
    let Some(directory) = std::env::var_os("BATHYSIGN_ROTATION_FIXTURES") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    let old = SigningKey::load_legacy_apk(
        &FIXTURES.dir.path().join("legacy.pk8"),
        &FIXTURES.dir.path().join("legacy.pem"),
    )
    .unwrap();
    let new = key("hybrid");
    let root = Lineage::root(&old);
    let rotated = root
        .append_certificate(&old, &new.certificate, DEFAULT_FLAGS)
        .unwrap();
    for version in 1..=3 {
        let bytes = std::fs::read(directory.join(format!("unsigned-{version}.apk"))).unwrap();
        let profile = Profile {
            original: &old,
            current: if version == 1 { &old } else { &new },
            lineage: if version == 1 { &root } else { &rotated },
            rotation_min_sdk: 28,
            hybrid: None,
        };
        let signed = apk::sign(&bytes, &profile).unwrap();
        let path = directory.join(format!("signed-{version}.apk"));
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap()
            .write_all(&signed)
            .unwrap();
        for sdk in [24, 27, 28, 32, 33, 36, 37] {
            let expected = if version == 1 || sdk < 28 {
                old.fingerprint()
            } else {
                new.fingerprint()
            };
            reference_expected(&path, sdk, Some(&expected));
        }
    }
}
#[test]
fn hybrid_and_repeated_rotation_match_android() {
    let a = key("a");
    let c = key("c");
    let r = key("hybrid");
    let p = key("pqc");
    let history = Lineage::root(&a).append(&a, &c, DEFAULT_FLAGS).unwrap();
    let rsa_history = history.append(&c, &r, DEFAULT_FLAGS).unwrap();
    let pqc_history = history.append(&c, &p, DEFAULT_FLAGS).unwrap();
    let unsigned = archive::write(&original(), true).unwrap();
    let profile = Profile {
        original: &a,
        current: &c,
        lineage: &history,
        rotation_min_sdk: 33,
        hybrid: Some(Hybrid {
            classical: &r,
            pqc: &p,
            classical_lineage: &rsa_history,
            pqc_lineage: &pqc_history,
        }),
    };
    let signed = apk::sign(&unsigned, &profile).unwrap();
    let path = FIXTURES.dir.path().join("hybrid.apk");
    std::fs::write(&path, &signed).unwrap();
    for sdk in [24, 28, 32, 33, 36, 37] {
        reference(&path, sdk);
    }
    assert_eq!(apk::sign(&unsigned, &profile).unwrap(), signed);
    let effective = rsa_history.append(&r, &p, DEFAULT_FLAGS).unwrap();
    let r2 = key("hybrid2");
    let p2 = key("pqc2");
    let rh = effective.append(&p, &r2, DEFAULT_FLAGS).unwrap();
    let ph = effective.append(&p, &p2, DEFAULT_FLAGS).unwrap();
    let profile2 = Profile {
        original: &a,
        current: &c,
        lineage: &history,
        rotation_min_sdk: 33,
        hybrid: Some(Hybrid {
            classical: &r2,
            pqc: &p2,
            classical_lineage: &rh,
            pqc_lineage: &ph,
        }),
    };
    let signed2 = apk::sign(&unsigned, &profile2).unwrap();
    let path2 = FIXTURES.dir.path().join("hybrid2.apk");
    std::fs::write(&path2, &signed2).unwrap();
    reference(&path2, 37);
    let mut bad = ph.clone();
    bad.nodes[0].flags ^= 4;
    let broken = Profile {
        original: &a,
        current: &c,
        lineage: &history,
        rotation_min_sdk: 33,
        hybrid: Some(Hybrid {
            classical: &r2,
            pqc: &p2,
            classical_lineage: &rh,
            pqc_lineage: &bad,
        }),
    };
    assert!(apk::sign(&unsigned, &broken).is_err());
}
#[test]
fn jar_transparency_and_tamper_detection() {
    let upload = key("a");
    let transparency_key = key("transparency");
    let mut entries = Entries::from([(
        "base/dex/classes.dex".into(),
        Entry {
            bytes: b"dex-test".to_vec(),
            stored: false,
        },
    )]);
    let statement = transparency::Statement {
        version: 1,
        code_related_file: vec![transparency::CodeFile {
            path: Some("base/dex/classes.dex".into()),
            bundletool_repo_path: None,
            kind: "DEX".into(),
            apk_path: None,
            sha256: bathysign::sha256(b"dex-test"),
        }],
    };
    let jwt = transparency::sign(&statement, &transparency_key).unwrap();
    transparency::verify(&jwt, &statement, &transparency_key.certificate).unwrap();
    archive::add(&mut entries, transparency::BUNDLE_PATH, jwt).unwrap();
    jar::sign(&mut entries, &upload).unwrap();
    jar::verify_output(&entries, &upload).unwrap();
    let path = FIXTURES.dir.path().join("signed.aab");
    std::fs::write(&path, archive::write(&entries, false).unwrap()).unwrap();
    let truststore = FIXTURES.dir.path().join("upload-truststore.p12");
    let trust = Command::new("keytool")
        .args(["-importcert", "-noprompt", "-alias", "test-upload", "-file"])
        .arg(FIXTURES.dir.path().join("a.pem"))
        .arg("-keystore")
        .arg(&truststore)
        .args(["-storepass", "test-only-password"])
        .output()
        .unwrap();
    assert!(
        trust.status.success(),
        "{}",
        String::from_utf8_lossy(&trust.stderr)
    );
    let out = Command::new("jarsigner")
        .args(["-verify", "-strict", "-keystore"])
        .arg(&truststore)
        .args(["-storepass", "test-only-password"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("jar verified"),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    entries
        .get_mut("base/dex/classes.dex")
        .unwrap()
        .bytes
        .push(1);
    assert!(jar::verify_output(&entries, &upload).is_err());
    let tampered = FIXTURES.dir.path().join("tampered.aab");
    std::fs::write(&tampered, archive::write(&entries, false).unwrap()).unwrap();
    let rejected = Command::new("jarsigner")
        .args(["-verify", "-strict", "-keystore"])
        .arg(&truststore)
        .args(["-storepass", "test-only-password"])
        .arg(tampered)
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "jarsigner accepted modified signed content"
    );
}
#[test]
fn archive_and_lineage_reject_unsafe_inputs() {
    let a = key("a");
    let b = key("b");
    let chain = Lineage::root(&a).append(&a, &b, DEFAULT_FLAGS).unwrap();
    let mut corrupted = chain.file().unwrap();
    let end = corrupted.len() - 1;
    corrupted[end] ^= 1;
    assert!(Lineage::read(&corrupted, DEFAULT_LIMIT).is_err());
    assert!(Lineage::read(&chain.file().unwrap(), 1).is_err());
    assert!(chain.append(&b, &a, DEFAULT_FLAGS).is_err());
    let rollback = Lineage::root(&a).append(&a, &b, DEFAULT_FLAGS | 8).unwrap();
    assert!(rollback.validate(false).is_err());
    let entries = Entries::from([(
        "../key".into(),
        Entry {
            bytes: vec![1],
            stored: true,
        },
    )]);
    let zip = archive::write(&entries, false).unwrap();
    assert!(archive::read(&zip).is_err());
    let compressed = archive::write(
        &Entries::from([(
            "large".into(),
            Entry {
                bytes: vec![0; 4096],
                stored: false,
            },
        )]),
        false,
    )
    .unwrap();
    assert!(archive::read_limited(&compressed, 4095).is_err());
    assert_eq!(
        archive::read_limited(&compressed, 4096).unwrap()["large"]
            .bytes
            .len(),
        4096
    );
}
#[test]
fn sixty_four_certificate_history() {
    // Distinct certificates exercise Android's identity history independently of
    // expensive key generation; production rotation uses provisioned new keys.
    let mut previous = key("a");
    let mut chain = Lineage::root(&previous);
    for i in 1..64 {
        let source = if i % 2 == 0 { "a" } else { "b" };
        let cert = FIXTURES.dir.path().join(format!("chain-{i}.pem"));
        assert!(
            Command::new("openssl")
                .args(["req", "-new", "-x509", "-key"])
                .arg(FIXTURES.dir.path().join(format!("{source}.key.pem")))
                .args(["-out"])
                .arg(&cert)
                .args(["-days", "10950", "-subj", &format!("/CN=Chain-{i}")])
                .output()
                .unwrap()
                .status
                .success()
        );
        let next =
            SigningKey::load(&FIXTURES.dir.path().join(format!("{source}.pk8")), &cert).unwrap();
        chain = chain.append(&previous, &next, DEFAULT_FLAGS).unwrap();
        previous = next;
        if [3, 10, 64].contains(&chain.nodes.len()) {
            let bytes = chain.file().unwrap();
            assert_eq!(Lineage::read(&bytes, DEFAULT_LIMIT).unwrap(), chain);
        }
    }
    assert_eq!(chain.nodes.len(), 64);
}

#[test]
fn bundletool_verifies_native_transparency_and_bundle_signature() {
    let Some(fixture) = std::env::var_os("BATHYSIGN_REFERENCE_AAB") else {
        return;
    };
    let tool =
        std::env::var_os("BATHYSIGN_BUNDLETOOL").expect("bundletool is required with AAB fixture");
    let java = std::env::var_os("BATHYSIGN_JAVA").unwrap_or_else(|| "java".into());
    let upload = key("a");
    let transparency_key = key("transparency");
    let mut entries = archive::read(&std::fs::read(fixture).unwrap()).unwrap();
    let identity =
        bathysign::manifest::identity(&entries["base/manifest/AndroidManifest.xml"].bytes, true)
            .unwrap();
    assert_eq!(identity.package, "test.example");
    assert_eq!(identity.min_sdk, 24);
    let statement = transparency::statement(&entries, None).unwrap();
    let jwt = transparency::sign(&statement, &transparency_key).unwrap();
    archive::add(&mut entries, transparency::BUNDLE_PATH, jwt.clone()).unwrap();
    jar::sign(&mut entries, &upload).unwrap();
    let aab = FIXTURES.dir.path().join("bundletool-signed.aab");
    std::fs::write(&aab, archive::write(&entries, false).unwrap()).unwrap();
    for command in ["validate", "check-transparency"] {
        let mut run = Command::new(&java);
        run.args(["-jar"])
            .arg(&tool)
            .arg(command)
            .arg(format!("--bundle={}", aab.display()));
        if command == "check-transparency" {
            run.arg("--mode=bundle").arg(format!(
                "--transparency-key-certificate={}",
                FIXTURES.dir.path().join("transparency.pem").display()
            ));
        }
        let output = run.output().unwrap();
        assert!(
            output.status.success(),
            "bundletool {command}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut apk_entries = original();
    transparency::check_apk(&statement, &apk_entries).unwrap();
    archive::add(&mut apk_entries, transparency::APK_PATH, jwt).unwrap();
    let lineage = Lineage::root(&upload);
    let profile = Profile {
        original: &upload,
        current: &upload,
        lineage: &lineage,
        rotation_min_sdk: 33,
        hybrid: None,
    };
    let signed = apk::sign(&archive::write(&apk_entries, true).unwrap(), &profile).unwrap();
    let apk_zip = FIXTURES.dir.path().join("transparency-apks.zip");
    let zip_entries = Entries::from([(
        "base.apk".into(),
        Entry {
            bytes: signed,
            stored: true,
        },
    )]);
    std::fs::write(&apk_zip, archive::write(&zip_entries, false).unwrap()).unwrap();
    let out = Command::new(java)
        .arg("-jar")
        .arg(tool)
        .args(["check-transparency", "--mode=apk"])
        .arg(format!("--apk-zip={}", apk_zip.display()))
        .arg(format!(
            "--transparency-key-certificate={}",
            FIXTURES.dir.path().join("transparency.pem").display()
        ))
        .arg(format!(
            "--apk-signing-key-certificate={}",
            FIXTURES.dir.path().join("a.pem").display()
        ))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "bundletool APK check: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn receipt_dsse_is_authenticated_and_domain_separated() {
    let key = key("a");
    let receipt = serde_json::json!({"version":2,"receipt_namespace":"bathysign","job":{"profile":"oss","run_id":42},"inputs":{"apk":"a".repeat(64)},"outputs":[{"name":"app-signed.apk","sha256":"b".repeat(64),"bytes":123}]});
    let envelope = bathysign::receipt::sign(&receipt, &key).unwrap();
    assert_eq!(
        bathysign::receipt::verify(&envelope, &key.certificate, &key.fingerprint()).unwrap(),
        receipt
    );
    let other = self::key("b");
    assert!(
        bathysign::receipt::verify(&envelope, &other.certificate, &other.fingerprint()).is_err()
    );
    let mut altered: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    altered["payloadType"] = serde_json::json!("application/json");
    assert!(
        bathysign::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
    use base64::Engine;
    let mut altered: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    altered["payload"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b"{}"));
    assert!(
        bathysign::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
    altered["signatures"][0]["keyid"] = serde_json::json!(other.fingerprint());
    assert!(
        bathysign::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
    // Ordinary RSA signatures over JSON cannot be substituted for DSSE PAE.
    let mut altered: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    let payload = base64::engine::general_purpose::STANDARD
        .decode(altered["payload"].as_str().unwrap())
        .unwrap();
    altered["signatures"][0]["sig"] = serde_json::json!(
        base64::engine::general_purpose::STANDARD
            .encode(key.sign(bathysign::crypto::RSA_SHA256, &payload).unwrap())
    );
    assert!(
        bathysign::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
}

#[test]
fn bathysign_receipts_require_and_bind_the_namespace() {
    use base64::Engine;
    let key = key("a");
    for version in [2, 3] {
        let receipt = serde_json::json!({"version":version,"receipt_namespace":"bathysign","outputs":[{"name":"app-signed.apk","sha256":"a".repeat(64),"bytes":1}]});
        let envelope = bathysign::receipt::sign(&receipt, &key).unwrap();
        assert_eq!(
            bathysign::receipt::verify(&envelope, &key.certificate, &key.fingerprint()).unwrap(),
            receipt
        );
        let value: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(value["payload"].as_str().unwrap())
            .unwrap();
        let statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            statement["predicateType"],
            format!("urn:bathysign:receipt:v{version}")
        );
        for namespace in [
            serde_json::Value::Null,
            serde_json::json!("android-signer"),
            serde_json::json!("attacker"),
        ] {
            let mut invalid = receipt.clone();
            invalid["receipt_namespace"] = namespace;
            assert!(bathysign::receipt::sign(&invalid, &key).is_err());
            // Even a valid signature cannot authorize a different namespace.
            let forged = serde_json::json!({"_type":"https://in-toto.io/Statement/v1", "predicateType":format!("urn:bathysign:receipt:v{version}"), "subject":statement["subject"], "predicate":invalid});
            let payload = serde_json::to_vec(&forged).unwrap();
            let mut envelope = value.clone();
            envelope["payload"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&payload));
            envelope["signatures"][0]["sig"] = serde_json::json!(
                base64::engine::general_purpose::STANDARD.encode(
                    key.sign(
                        bathysign::crypto::RSA_SHA256,
                        &bathysign::receipt::pae(&payload)
                    )
                    .unwrap()
                )
            );
            assert!(
                bathysign::receipt::verify(
                    &serde_json::to_vec(&envelope).unwrap(),
                    &key.certificate,
                    &key.fingerprint()
                )
                .is_err()
            );
        }
    }
}

#[cfg(feature = "admin")]
fn admin_command(
    command: &str,
    paths: &[(&str, &std::path::Path)],
    flags: &[&str],
) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_bathysign-admin"));
    process.arg(command);
    for (flag, path) in paths {
        process.arg(flag).arg(path);
    }
    process.args(flags).output().unwrap()
}

#[test]
#[cfg(feature = "admin")]
fn administration_cli_round_trips_lineages_and_hybrid_proofs_without_overwriting_files() {
    let directory = tempfile::tempdir().unwrap();
    let source = FIXTURES.dir.path();
    let root = directory.path().join("root.bin");
    let result = admin_command(
        "init",
        &[
            ("--key", &source.join("a.pk8")),
            ("--cert", &source.join("a.pem")),
            ("--out", &root),
        ],
        &[],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original = std::fs::read(&root).unwrap();
    assert_eq!(
        Lineage::read(&original, DEFAULT_LIMIT).unwrap(),
        Lineage::root(&key("a"))
    );
    let inspected = admin_command("inspect", &[("--input", &root)], &[]);
    assert!(inspected.status.success());
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(report["sha256"], bathysign::sha256(&original));
    assert_eq!(report["certificates"].as_array().unwrap().len(), 1);
    assert!(
        !admin_command("inspect", &[("--input", &root)], &["--max-bytes", "1"])
            .status
            .success()
    );
    let imported = directory.path().join("imported.bin");
    assert!(
        !admin_command(
            "import",
            &[("--input", &root), ("--out", &imported)],
            &["--expected-root", &"0".repeat(64)]
        )
        .status
        .success()
    );
    assert!(!imported.exists());
    assert!(
        admin_command(
            "import",
            &[("--input", &root), ("--out", &imported)],
            &["--expected-root", &key("a").fingerprint()]
        )
        .status
        .success()
    );
    assert_eq!(std::fs::read(&imported).unwrap(), original);
    assert!(
        !admin_command(
            "import",
            &[("--input", &root), ("--out", &imported)],
            &["--expected-root", &key("a").fingerprint()]
        )
        .status
        .success()
    );
    let appended = directory.path().join("appended.bin");
    assert!(
        admin_command(
            "append",
            &[
                ("--input", &root),
                ("--old-key", &source.join("a.pk8")),
                ("--old-cert", &source.join("a.pem")),
                ("--new-key", &source.join("b.pk8")),
                ("--new-cert", &source.join("b.pem")),
                ("--out", &appended)
            ],
            &[]
        )
        .status
        .success()
    );
    assert_eq!(
        Lineage::read(&std::fs::read(&appended).unwrap(), DEFAULT_LIMIT).unwrap(),
        Lineage::root(&key("a"))
            .append(&key("a"), &key("b"), DEFAULT_FLAGS)
            .unwrap()
    );
    let hybrid = directory.path().join("hybrid");
    let result = admin_command(
        "hybrid",
        &[
            ("--input", &root),
            ("--old-key", &source.join("a.pk8")),
            ("--old-cert", &source.join("a.pem")),
            ("--rsa-key", &source.join("hybrid.pk8")),
            ("--rsa-cert", &source.join("hybrid.pem")),
            ("--pqc-key", &source.join("pqc.pk8")),
            ("--pqc-cert", &source.join("pqc.pem")),
            ("--out-directory", &hybrid),
        ],
        &[],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let classical = Lineage::read(
        &std::fs::read(hybrid.join("rsa-lineage.bin")).unwrap(),
        DEFAULT_LIMIT,
    )
    .unwrap();
    let quantum = Lineage::read(
        &std::fs::read(hybrid.join("pqc-lineage.bin")).unwrap(),
        DEFAULT_LIMIT,
    )
    .unwrap();
    let effective = Lineage::read(
        &std::fs::read(hybrid.join("effective-lineage.bin")).unwrap(),
        DEFAULT_LIMIT,
    )
    .unwrap();
    bathysign::lineage::validate_hybrid(&classical, &quantum, false).unwrap();
    effective.validate(false).unwrap();
    assert!(effective.extends(&classical));
    assert_eq!(
        effective.last().unwrap().certificate,
        key("pqc").certificate
    );
    assert_eq!(std::fs::read(root).unwrap(), original);
    let legacy = directory.path().join("legacy.bin");
    let arguments = [
        ("--key", &*source.join("legacy.pk8")),
        ("--cert", &*source.join("legacy.pem")),
        ("--out", &*legacy),
    ];
    assert!(!admin_command("init", &arguments, &[]).status.success());
    assert!(
        admin_command("init", &arguments, &["--legacy-rsa-1024"])
            .status
            .success()
    );
}

#[test]
#[cfg(feature = "admin")]
fn administration_cli_authenticates_receipts_and_historical_trust_evidence_offline() {
    let directory = tempfile::tempdir().unwrap();
    let signer = key("a");
    let receipt = serde_json::json!({"version":2,"receipt_namespace":"bathysign","outputs":[{"name":"app.apk","sha256":"a".repeat(64),"bytes":123}]});
    let envelope = directory.path().join("receipt.json");
    let cert = directory.path().join("cert.der");
    std::fs::write(
        &envelope,
        bathysign::receipt::sign(&receipt, &signer).unwrap(),
    )
    .unwrap();
    std::fs::write(&cert, &signer.certificate).unwrap();
    let verified = admin_command(
        "verify-receipt",
        &[("--input", &envelope), ("--certificate-der", &cert)],
        &["--fingerprint", &signer.fingerprint()],
    );
    assert!(verified.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap(),
        receipt
    );
    assert!(
        !admin_command(
            "verify-receipt",
            &[("--input", &envelope), ("--certificate-der", &cert)],
            &["--fingerprint", &key("b").fingerprint()]
        )
        .status
        .success()
    );
    std::fs::File::create(&cert)
        .unwrap()
        .set_len(65537)
        .unwrap();
    assert!(
        !admin_command(
            "verify-receipt",
            &[("--input", &envelope), ("--certificate-der", &cert)],
            &["--fingerprint", &signer.fingerprint()]
        )
        .status
        .success()
    );
    let checkpoint = directory.path().join("checkpoint.json");
    let authority = directory.path().join("authority.json");
    let raw = include_bytes!("../bathysign/tests/fixtures/trust-checkpoint.json");
    let value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    std::fs::write(&checkpoint, raw).unwrap();
    std::fs::write(&authority, serde_json::to_vec(&value["authority"]).unwrap()).unwrap();
    let verified = admin_command(
        "verify-trust-evidence",
        &[("--input", &checkpoint), ("--authority", &authority)],
        &[],
    );
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let expected: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../bathysign/tests/fixtures/trust-binding.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap(),
        expected
    );
    let mut wrong = value["authority"].clone();
    wrong["epoch"] = serde_json::json!("0".repeat(64));
    std::fs::write(&authority, wrong.to_string()).unwrap();
    assert!(
        !admin_command(
            "verify-trust-evidence",
            &[("--input", &checkpoint), ("--authority", &authority)],
            &[]
        )
        .status
        .success()
    );
    let output = directory.path().join("new-checkpoint.json");
    assert!(
        !admin_command(
            "prepare-trust",
            &[("--out", &output)],
            &["--epoch", "invalid"]
        )
        .status
        .success()
    );
    assert!(!output.exists());
}

#[test]
#[cfg(feature = "admin")]
fn administration_cli_exports_only_the_loaded_public_policy_for_the_requested_repository() {
    let directory = tempfile::tempdir().unwrap();
    let mut config: bathysign::config::Config =
        serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
    for (role, fixture) in [
        ("apk-a", "a"),
        ("upload", "b"),
        ("transparency", "transparency"),
        ("receipt", "c"),
    ] {
        let spec = config.keys.get_mut(role).unwrap();
        spec.private_key = FIXTURES.dir.path().join(format!("{fixture}.pk8"));
        spec.certificate = FIXTURES.dir.path().join(format!("{fixture}.pem"));
        spec.fingerprint = key(fixture).fingerprint();
    }
    config.github_app_private_key = FIXTURES.dir.path().join("hybrid.key.pem");
    config.webhook_secret = directory.path().join("webhook-secret");
    std::fs::write(&config.webhook_secret, b"01234567890123456789012345678901").unwrap();
    let lineage = Lineage::root(&key("a"));
    let lineage_file = directory.path().join("lineage.bin");
    std::fs::write(&lineage_file, lineage.file().unwrap()).unwrap();
    for profile in config.repositories[0].profiles.values_mut() {
        profile.signing.lineage = lineage_file.clone();
        profile.signing.lineage_sha256 = lineage.digest().unwrap();
    }
    for trust in config.trust_roots.values_mut() {
        trust.file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/public-trusted-root.json");
        trust.sha256 = bathysign::sha256(&std::fs::read(&trust.file).unwrap());
        trust.valid_until = bathysign::config::now().unwrap() + 3600;
    }
    let path = directory.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let output = directory.path().join("public-policy.json");
    let repository = config.repositories[0].name.as_str();
    let revision = "a".repeat(40);
    let invoke = |repository: &str, out: &std::path::Path| {
        admin_command(
            "export-release-policy",
            &[("--config", &path), ("--out", out)],
            &["--repository", repository, "--signer-revision", &revision],
        )
    };
    let result = invoke(repository, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let loaded = bathysign::config::Loaded::read(&path).unwrap();
    let expected = loaded
        .release_policy(&loaded.config.repositories[0], &revision)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&output).unwrap()).unwrap(),
        expected
    );
    assert!(!invoke(repository, &output).status.success());
    assert!(
        !invoke(
            "unconfigured/repository",
            &directory.path().join("wrong.json")
        )
        .status
        .success()
    );
    assert!(!directory.path().join("wrong.json").exists());
}
