//! Entirely disposable Fulcio-style CA, TSA, certificate claims, and DSSE evidence.
use base64::{Engine, engine::general_purpose::STANDARD};
use bathysign::config::{Config, Repository};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

pub struct Fixture {
    directory: tempfile::TempDir,
    pub repository: Repository,
    pub statement: Value,
    pub claims: BTreeMap<u32, String>,
    pub digest: String,
    pub commit: String,
    pub root: Vec<u8>,
}
fn openssl(directory: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("openssl")
        .current_dir(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
impl Fixture {
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        openssl(
            path,
            &[
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "root.key",
                "-out",
                "root.pem",
                "-days",
                "2",
                "-subj",
                "/CN=Disposable attestation test root",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        for name in ["leaf", "tsa"] {
            let algorithm = if name == "tsa" { "ec" } else { "rsa:2048" };
            let mut arguments = vec!["req", "-new", "-newkey", algorithm];
            if name == "tsa" {
                arguments.extend(["-pkeyopt", "ec_paramgen_curve:P-256"]);
            }
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let subject = format!("/CN=Disposable {name}");
            arguments.extend(["-nodes", "-keyout", &key, "-out", &csr, "-subj", &subject]);
            openssl(path, &arguments);
        }
        std::fs::write(path.join("tsa.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n").unwrap();
        openssl(
            path,
            &[
                "x509",
                "-req",
                "-in",
                "tsa.csr",
                "-CA",
                "root.pem",
                "-CAkey",
                "root.key",
                "-CAcreateserial",
                "-out",
                "tsa.pem",
                "-days",
                "2",
                "-extfile",
                "tsa.ext",
            ],
        );
        std::fs::write(path.join("tsa.serial"), "01\n").unwrap();
        let config = format!(
            "[tsa]\ndefault_tsa=local\n[local]\nserial={0}/tsa.serial\nsigner_cert={0}/tsa.pem\ncerts={0}/root.pem\nsigner_key={0}/tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n",
            path.display()
        );
        std::fs::write(path.join("tsa.conf"), config).unwrap();
        let root_der = openssl(path, &["x509", "-in", "root.pem", "-outform", "DER"]);
        let authority = json!({"subject":{"organization":"Bathysign tests","commonName":"Disposable attestation test root"},"uri":"https://test.invalid","certChain":{"certificates":[{"rawBytes":STANDARD.encode(root_der)}]},"validFor":{"start":"2000-01-01T00:00:00Z","end":"2099-01-01T00:00:00Z"}});
        let mut timestamp_authority = authority.clone();
        let tsa_der = openssl(path, &["x509", "-in", "tsa.pem", "-outform", "DER"]);
        timestamp_authority["certChain"]["certificates"]
            .as_array_mut()
            .unwrap()
            .insert(0, json!({"rawBytes":STANDARD.encode(tsa_der)}));
        let root = serde_json::to_vec(&json!({"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","certificateAuthorities":[authority],"timestampAuthorities":[timestamp_authority]})).unwrap();
        let config: Config =
            serde_json::from_str(include_str!("../../config/signer.example.json")).unwrap();
        let mut repository = config.repositories[0].clone();
        repository.id = 42;
        repository.name = "owner/app".into();
        repository.visibility = "private".into();
        repository.callers = vec![".github/workflows/release.yml".into()];
        repository.refs = vec!["refs/heads/main".into()];
        repository.events = vec!["push".into()];
        repository.runners = vec!["github-hosted".into()];
        repository.builder.repository = "trusted/builders".into();
        repository.builder.workflow = ".github/workflows/build.yml".into();
        repository.builder.refs = vec!["refs/tags/v0.2.0".into()];
        repository.builder.commit = "b".repeat(40);
        let commit = "a".repeat(40);
        let digest = bathysign::sha256(b"disposable unsigned artifact");
        let source = "https://github.com/owner/app";
        let caller = format!("{source}/.github/workflows/release.yml@refs/heads/main");
        let builder =
            "https://github.com/trusted/builders/.github/workflows/build.yml@refs/tags/v0.2.0";
        let invocation = format!("{source}/actions/runs/123/attempts/2");
        let claims = BTreeMap::from([
            (8, "https://token.actions.githubusercontent.com".into()),
            (9, builder.into()),
            (10, "b".repeat(40)),
            (11, "github-hosted".into()),
            (12, source.into()),
            (13, commit.clone()),
            (14, "refs/heads/main".into()),
            (15, "42".into()),
            (18, caller),
            (19, commit.clone()),
            (20, "push".into()),
            (21, invocation.clone()),
            (22, "private".into()),
        ]);
        let statement = json!({"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"app.apk","digest":{"sha256":digest}}],"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"repository":source,"path":".github/workflows/release.yml","ref":"refs/heads/main"}},"internalParameters":{"github":{"repository_id":"42","runner_environment":"github-hosted","event_name":"push"}},"resolvedDependencies":[{"uri":format!("git+{source}@refs/heads/main"),"digest":{"gitCommit":commit}}]},"runDetails":{"builder":{"id":builder},"metadata":{"invocationId":invocation}}}});
        Self {
            directory,
            repository,
            statement,
            claims,
            digest,
            commit,
            root,
        }
    }
    pub fn bundle(&self, statement: &Value, claims: &BTreeMap<u32, String>) -> Value {
        let path = self.directory.path();
        let mut extensions = format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectAltName=URI:{}\n",
            claims[&9]
        );
        for (id, value) in claims {
            assert!(!value.contains(['\n', '\r']));
            extensions.push_str(&format!(
                "1.3.6.1.4.1.57264.1.{id}=ASN1:UTF8String:{value}\n"
            ));
        }
        std::fs::write(path.join("leaf.ext"), extensions).unwrap();
        openssl(
            path,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "root.pem",
                "-CAkey",
                "root.key",
                "-CAcreateserial",
                "-out",
                "leaf.pem",
                "-days",
                "2",
                "-extfile",
                "leaf.ext",
            ],
        );
        let certificate = openssl(path, &["x509", "-in", "leaf.pem", "-outform", "DER"]);
        let payload = serde_json::to_vec(statement).unwrap();
        let kind = "application/vnd.in-toto+json";
        let mut pae = format!("DSSEv1 {} {kind} {} ", kind.len(), payload.len()).into_bytes();
        pae.extend_from_slice(&payload);
        std::fs::write(path.join("pae.bin"), pae).unwrap();
        openssl(
            path,
            &[
                "dgst",
                "-sha256",
                "-sign",
                "leaf.key",
                "-out",
                "signature.bin",
                "pae.bin",
            ],
        );
        openssl(
            path,
            &[
                "ts",
                "-query",
                "-data",
                "signature.bin",
                "-sha256",
                "-cert",
                "-out",
                "query.tsq",
            ],
        );
        openssl(
            path,
            &[
                "ts",
                "-reply",
                "-config",
                "tsa.conf",
                "-queryfile",
                "query.tsq",
                "-out",
                "response.tsr",
            ],
        );
        json!({"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":STANDARD.encode(certificate)},"timestampVerificationData":{"rfc3161Timestamps":[{"signedTimestamp":STANDARD.encode(std::fs::read(path.join("response.tsr")).unwrap())}]}},"dsseEnvelope":{"payload":STANDARD.encode(payload),"payloadType":kind,"signatures":[{"sig":STANDARD.encode(std::fs::read(path.join("signature.bin")).unwrap()),"keyid":""}]}})
    }
    pub fn root_path(&self) -> PathBuf {
        let path = self.directory.path().join("trusted-root.json");
        std::fs::write(&path, &self.root).unwrap();
        path
    }
}
