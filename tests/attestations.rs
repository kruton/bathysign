static INIT: std::sync::Once = std::sync::Once::new();
fn initialize() {
    INIT.call_once(|| bathysign::initialize_crypto().unwrap());
}
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};

#[test]
fn genuine_public_and_private_bundles_with_rustcrypto() {
    initialize();
    let cases = [
        (
            include_str!("fixtures/public-trusted-root.json"),
            include_str!("fixtures/github-public.sigstore.json"),
            "54303491a8418fbed24344b513546182c29b43bf282ceb433af65e2299f9271f",
            false,
        ),
        (
            include_str!("fixtures/github-trusted-root.json"),
            include_str!("fixtures/github-private.sigstore.json"),
            "76f1fe8593bf227cca2c089e3c16dc95014a8d3e89c5dd220530469ca043c428",
            true,
        ),
    ];
    for (root, bundle, digest, private) in cases {
        let root = TrustedRoot::from_json(root).unwrap();
        let bundle = Bundle::from_json(bundle).unwrap();
        // Fixture identity is not used to authorize a production signing request.
        // The pipeline separately enforces its configured workflow and CI claims.
        let mut policy = if private {
            VerificationPolicy::any_identity()
                .require_identity("https://dotcom.releases.github.com")
        } else {
            VerificationPolicy::new(
                "https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main",
                "https://token.actions.githubusercontent.com",
            )
        };
        if private {
            policy = policy.skip_tlog_unsafe().skip_sct();
        }
        let verifier = Verifier::new(&root).unwrap();
        let verified = verifier
            .verify(Sha256Hash::from_hex(digest).unwrap(), &bundle, &policy)
            .unwrap();
        assert!(verified.certificate_verified());
        assert!(!verified.verified_timestamps().is_empty());
        assert!(
            verifier
                .verify(Sha256Hash::new([0; 32]), &bundle, &policy)
                .is_err()
        );
        let wrong_identity = policy.require_identity(
            "https://github.com/untrusted/repo/.github/workflows/build.yml@refs/heads/main",
        );
        assert!(
            verifier
                .verify(
                    Sha256Hash::from_hex(digest).unwrap(),
                    &bundle,
                    &wrong_identity
                )
                .is_err()
        );
    }
}

// Cryptographic bundle interoperability is tested above; these adversarial
// claim tests exercise the application's authorization after that verification.
#[test]
fn reusable_builder_and_caller_are_authorized_independently() {
    use serde_json::{Value, json};
    let config: bathysign::config::Config =
        serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
    let mut repo = config.repositories[0].clone();
    repo.name = "owner/app".into();
    repo.id = 42;
    repo.callers = vec![".github/workflows/release.yml".into()];
    repo.builder.repository = "trusted/builders".into();
    repo.builder.workflow = ".github/workflows/android.yml".into();
    repo.builder.refs = vec!["refs/tags/v0.2.0".into()];
    repo.refs = vec!["refs/heads/main".into(), "refs/tags/v*".into()];
    repo.events = vec!["push".into()];
    let sha = "b".repeat(40);
    let builder_sha = "c".repeat(40);
    let caller = "https://github.com/owner/app/.github/workflows/release.yml@refs/heads/main";
    let builder =
        "https://github.com/trusted/builders/.github/workflows/android.yml@refs/tags/v0.2.0";
    let invocation = "https://github.com/owner/app/actions/runs/100/attempts/2";
    let mut claims = sigstore_crypto::FulcioCiClaims::default();
    claims.source_repository_uri = Some("https://github.com/owner/app".into());
    claims.source_repository_identifier = Some("42".into());
    claims.source_repository_digest = Some(sha.clone());
    claims.source_repository_ref = Some("refs/heads/main".into());
    claims.build_config_uri = Some(caller.into());
    claims.build_config_digest = Some(sha.clone());
    claims.build_signer_uri = Some(builder.into());
    claims.build_signer_digest = Some(builder_sha);
    claims.run_invocation_uri = Some(invocation.into());
    claims.runner_environment = Some("github-hosted".into());
    claims.build_trigger = Some("push".into());
    claims.source_repository_visibility_at_signing = Some("public".into());
    let statement = json!({"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"path":".github/workflows/release.yml","repository":"https://github.com/owner/app","ref":"refs/heads/main"}},"internalParameters":{"github":{"repository_id":"42","runner_environment":"github-hosted","event_name":"push"}},"resolvedDependencies":[{"uri":"git+https://github.com/owner/app@refs/heads/main","digest":{"gitCommit":sha}}]},"runDetails":{"builder":{"id":builder},"metadata":{"invocationId":invocation}}}});
    let verify = |s: &Value, c: &sigstore_crypto::FulcioCiClaims| {
        bathysign::attestation::validate_claims(s, c, &repo, &sha, 100, 2)
    };
    verify(&statement, &claims).unwrap();
    for pointer in [
        "/predicate/buildDefinition/externalParameters/workflow/path",
        "/predicate/buildDefinition/externalParameters/workflow/ref",
        "/predicate/runDetails/builder/id",
        "/predicate/runDetails/metadata/invocationId",
        "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit",
        "/predicate/buildDefinition/internalParameters/github/repository_id",
        "/predicate/buildDefinition/buildType",
    ] {
        let mut bad = statement.clone();
        *bad.pointer_mut(pointer).unwrap() = json!("attacker");
        assert!(verify(&bad, &claims).is_err(), "accepted {pointer}");
    }
    let mut bad = statement.clone();
    bad["predicate"]["buildDefinition"]["externalParameters"]["script"] = json!("arbitrary");
    assert!(verify(&bad, &claims).is_err());
    let mut bad = claims.clone();
    bad.build_signer_uri = Some(caller.into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.build_config_uri = Some(builder.into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.run_invocation_uri = Some(invocation.replace("attempts/2", "attempts/1"));
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.source_repository_identifier = Some("43".into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.runner_environment = Some("self-hosted".into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.build_signer_digest = Some("d".repeat(40));
    assert!(verify(&statement, &bad).is_err());
    bad.build_signer_digest = None;
    assert!(verify(&statement, &bad).is_err());
    assert!(bathysign::config::ref_allowed(
        &repo.refs,
        "refs/tags/v1.2.3"
    ));
    assert!(!bathysign::config::ref_allowed(
        &repo.refs,
        "refs/heads/attacker"
    ));
}

#[path = "support/attestation_fixture.rs"]
mod local_attestation;

#[test]
fn complete_slsa_attestation_binds_signed_certificate_claims_and_timestamp() {
    initialize();
    let fixture = local_attestation::Fixture::new();
    let bundle = fixture.bundle(&fixture.statement, &fixture.claims);
    let expiry = bathysign::config::now().unwrap() + 3600;
    let verified = bathysign::attestation::verify_digest_with_root(
        &fixture.digest,
        &bundle,
        &fixture.repository,
        &fixture.root,
        expiry,
        &fixture.commit,
        123,
        2,
    )
    .unwrap();
    assert_eq!(verified["subject_sha256"], fixture.digest);
    assert_eq!(verified["commit"], fixture.commit);
    assert_eq!(verified["builder_commit"], "b".repeat(40));
    assert_eq!(
        verified["trust_root_sha256"],
        bathysign::sha256(&fixture.root)
    );
    let trust = bathysign::config::TrustRoot {
        file: fixture.root_path(),
        sha256: bathysign::sha256(&fixture.root),
        valid_until: expiry,
    };
    assert_eq!(
        bathysign::attestation::verify(
            b"disposable unsigned artifact",
            &bundle,
            &fixture.repository,
            &trust,
            &fixture.commit,
            123,
            2
        )
        .unwrap(),
        verified
    );
}

#[test]
fn authenticated_slsa_certificates_cannot_substitute_repository_invocation_or_runner_claims() {
    initialize();
    let fixture = local_attestation::Fixture::new();
    let expiry = bathysign::config::now().unwrap() + 3600;
    for (claim, replacement) in [
        (15, Some("99")),
        (12, Some("https://github.com/attacker/app")),
        (13, Some("cccccccccccccccccccccccccccccccccccccccc")),
        (14, Some("refs/heads/attacker")),
        (
            21,
            Some("https://github.com/owner/app/actions/runs/123/attempts/1"),
        ),
        (11, Some("self-hosted")),
        (11, None),
        (20, Some("pull_request")),
        (20, None),
        (22, Some("public")),
        (
            18,
            Some("https://github.com/owner/app/.github/workflows/attacker.yml@refs/heads/main"),
        ),
        (19, Some("cccccccccccccccccccccccccccccccccccccccc")),
        (10, Some("main")),
    ] {
        let mut claims = fixture.claims.clone();
        match replacement {
            Some(value) => {
                claims.insert(claim, value.into());
            }
            None => {
                claims.remove(&claim);
            }
        }
        // Each negative case has a valid CA chain, DSSE signature, and RFC3161
        // timestamp; only its authenticated authorization claim differs.
        let bundle = fixture.bundle(&fixture.statement, &claims);
        let error = bathysign::attestation::verify_digest_with_root(
            &fixture.digest,
            &bundle,
            &fixture.repository,
            &fixture.root,
            expiry,
            &fixture.commit,
            123,
            2,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("claim")
                || error.to_string().contains("eligible")
                || error.to_string().contains("builder commit"),
            "claim {claim}: {error}"
        );
    }
}

#[test]
fn provenance_statement_shape_and_workflow_policy_fail_before_untrusted_data_is_used() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    initialize();
    let fixture = local_attestation::Fixture::new();
    let bundle = fixture.bundle(&fixture.statement, &fixture.claims);
    let expiry = bathysign::config::now().unwrap() + 3600;
    for (pointer, value, expected) in [
        (
            "/_type",
            json!("invalid"),
            "unsupported provenance statement",
        ),
        (
            "/predicateType",
            json!("invalid"),
            "unsupported provenance statement",
        ),
        ("/subject", json!([]), "subject digest differs"),
        (
            "/predicate/buildDefinition/buildType",
            json!("invalid"),
            "unsupported build type",
        ),
        (
            "/predicate/buildDefinition/externalParameters/workflow/ref",
            json!(null),
            "workflow ref missing",
        ),
        (
            "/predicate/buildDefinition/externalParameters/workflow/ref",
            json!("refs/heads/attacker"),
            "build ref is not allowed",
        ),
        (
            "/predicate/buildDefinition/externalParameters/workflow/path",
            json!(null),
            "caller path missing",
        ),
        (
            "/predicate/buildDefinition/externalParameters/workflow/path",
            json!(".github/workflows/attacker.yml"),
            "caller workflow differs",
        ),
        (
            "/predicate/runDetails/builder/id",
            json!(null),
            "builder identity missing",
        ),
        (
            "/predicate/runDetails/builder/id",
            json!(
                "https://github.com/attacker/builders/.github/workflows/build.yml@refs/heads/main"
            ),
            "builder identity differs",
        ),
        (
            "/predicate/runDetails/builder/id",
            json!(
                "https://github.com/trusted/builders/.github/workflows/build.yml@refs/heads/attacker"
            ),
            "builder ref is not allowed",
        ),
    ] {
        let mut statement = fixture.statement.clone();
        *statement.pointer_mut(pointer).unwrap() = value;
        let mut changed = bundle.clone();
        changed["dsseEnvelope"]["payload"] =
            json!(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
        let error = bathysign::attestation::verify_digest_with_root(
            &fixture.digest,
            &changed,
            &fixture.repository,
            &fixture.root,
            expiry,
            &fixture.commit,
            123,
            2,
        )
        .unwrap_err();
        assert!(error.to_string().contains(expected), "{pointer}: {error}");
    }
    let mut message = bundle.clone();
    message.as_object_mut().unwrap().remove("dsseEnvelope");
    message["messageSignature"] = json!({"messageDigest":{"algorithm":"SHA2_256","digest":STANDARD.encode([0;32])},"signature":STANDARD.encode([1;256])});
    let error = bathysign::attestation::verify_digest_with_root(
        &fixture.digest,
        &message,
        &fixture.repository,
        &fixture.root,
        expiry,
        &fixture.commit,
        123,
        2,
    )
    .unwrap_err();
    assert!(error.to_string().contains("requires DSSE"), "{error}");
}

#[test]
fn trusted_root_pins_expiry_and_timestamp_evidence_are_mandatory() {
    use serde_json::json;
    initialize();
    let fixture = local_attestation::Fixture::new();
    let bundle = fixture.bundle(&fixture.statement, &fixture.claims);
    let expiry = bathysign::config::now().unwrap() + 3600;
    let mut trust = bathysign::config::TrustRoot {
        file: fixture.root_path(),
        sha256: bathysign::sha256(&fixture.root),
        valid_until: expiry,
    };
    assert!(
        bathysign::attestation::verify_digest(
            "not-a-digest",
            &bundle,
            &fixture.repository,
            &trust,
            &fixture.commit,
            123,
            2
        )
        .unwrap_err()
        .to_string()
        .contains("invalid subject digest")
    );
    trust.valid_until = 0;
    assert!(
        bathysign::attestation::verify_digest(
            &fixture.digest,
            &bundle,
            &fixture.repository,
            &trust,
            &fixture.commit,
            123,
            2
        )
        .unwrap_err()
        .to_string()
        .contains("trust material expired")
    );
    trust.valid_until = expiry;
    trust.sha256 = "0".repeat(64);
    assert!(
        bathysign::attestation::verify_digest(
            &fixture.digest,
            &bundle,
            &fixture.repository,
            &trust,
            &fixture.commit,
            123,
            2
        )
        .unwrap_err()
        .to_string()
        .contains("trust-root hash differs")
    );
    assert!(
        bathysign::attestation::verify_digest_with_root(
            &fixture.digest,
            &bundle,
            &fixture.repository,
            &fixture.root,
            0,
            &fixture.commit,
            123,
            2
        )
        .is_err()
    );
    assert!(
        bathysign::attestation::verify_digest_with_root(
            "invalid",
            &bundle,
            &fixture.repository,
            &fixture.root,
            expiry,
            &fixture.commit,
            123,
            2
        )
        .is_err()
    );
    let mut missing = bundle.clone();
    missing["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"] = json!([]);
    assert!(
        bathysign::attestation::verify_digest_with_root(
            &fixture.digest,
            &missing,
            &fixture.repository,
            &fixture.root,
            expiry,
            &fixture.commit,
            123,
            2
        )
        .unwrap_err()
        .to_string()
        .contains("requires trusted timestamp")
    );
    let mut corrupt = bundle.clone();
    corrupt["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"] =
        json!("dGFtcGVyZWQ=");
    assert!(
        bathysign::attestation::verify_digest_with_root(
            &fixture.digest,
            &corrupt,
            &fixture.repository,
            &fixture.root,
            expiry,
            &fixture.commit,
            123,
            2
        )
        .is_err()
    );
    assert!(
        bathysign::attestation::verify_digest_with_root(
            &fixture.digest,
            &bundle,
            &fixture.repository,
            b"\xff",
            expiry,
            &fixture.commit,
            123,
            2
        )
        .is_err()
    );
}
