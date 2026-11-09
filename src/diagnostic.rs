//! Audit diagnostics are closed vocabularies, never formatted error messages.
use anyhow::Result;
use serde::Serialize;

macro_rules! diagnostic {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
        #[serde(rename_all = "snake_case")]
        pub(crate) enum $name { $($variant),+ }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for $name {}

        impl $name {
            pub(crate) fn attach<T>(self, result: Result<T>) -> Result<T> {
                result.map_err(|error| {
                    // Keep the most specific boundary when calls are nested.
                    if error.downcast_ref::<Self>().is_some() {
                        error
                    } else {
                        error.context(self)
                    }
                })
            }
        }
    };
}

diagnostic!(FailurePoint {
    Trust,
    JobPolicy,
    GithubInstallation,
    BuilderIdentity,
    RepositoryIdentity,
    SourceRun,
    CallerWorkflow,
    ApkDownload,
    AabDownload,
    ApkProvenance,
    AabProvenance,
    ApkUnsigned,
    ApkArchive,
    AabArchive,
    ApkManifest,
    AabManifest,
    PackageVersion,
    AndroidSdk,
    TransparencyStatement,
    TransparencyApk,
    SigningKeys,
    InputsAudit,
    SignTransparency,
    SignAab,
    SignApk,
    Receipt,
    PublishOutputs,
});

diagnostic!(AttestationCheck {
    SubjectDigest,
    TrustMaterial,
    BundleFormat,
    StatementType,
    BuildType,
    SourceRef,
    CallerWorkflow,
    BuilderIdentity,
    TimestampEvidence,
    Signature,
    CertificateTime,
    RepositoryClaims,
    InvocationClaims,
    RunnerClaim,
    EventClaim,
    VisibilityClaim,
    ProvenanceClaims,
    NoMatchingAttestation,
});
