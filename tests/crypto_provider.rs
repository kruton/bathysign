use bathysign::crypto::RustCryptoProvider;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sigstore_crypto::{CryptoProvider, SigningScheme};
use sigstore_types::HashAlgorithm;

const MESSAGE: &[u8] = b"Sigstore crypto provider interoperability";

fn verify_signature(scheme: SigningScheme, key: &[u8], signature: &[u8]) {
    let digest = match scheme.hash_algorithm().unwrap() {
        HashAlgorithm::Sha2256 => Sha256::digest(MESSAGE).to_vec(),
        HashAlgorithm::Sha2384 => Sha384::digest(MESSAGE).to_vec(),
        HashAlgorithm::Sha2512 => Sha512::digest(MESSAGE).to_vec(),
        _ => unreachable!(),
    };
    let provider = RustCryptoProvider;
    provider
        .verify_raw(scheme, key, MESSAGE, signature)
        .unwrap();
    provider
        .verify_prehashed(scheme, key, &digest, signature)
        .unwrap();
    assert!(
        provider
            .verify_raw(scheme, key, b"tampered", signature)
            .is_err()
    );
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(
        provider
            .verify_prehashed(scheme, key, &wrong_digest, signature)
            .is_err()
    );
}

#[test]
fn ecdsa_signatures_accept_both_supported_hashes_and_reject_tampering() {
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    let p256 = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let p384 = p384::ecdsa::SigningKey::from_slice(&[1; 48]).unwrap();
    for (p256_scheme, p384_scheme, digest) in [
        (
            SigningScheme::EcdsaP256Sha256,
            SigningScheme::EcdsaP384Sha256,
            Sha256::digest(MESSAGE).to_vec(),
        ),
        (
            SigningScheme::EcdsaP256Sha384,
            SigningScheme::EcdsaP384Sha384,
            Sha384::digest(MESSAGE).to_vec(),
        ),
    ] {
        let signature: p256::ecdsa::Signature = p256.sign_prehash(&digest).unwrap();
        verify_signature(
            p256_scheme,
            p256.verifying_key().to_sec1_point(false).as_bytes(),
            signature.to_der().as_bytes(),
        );
        let signature: p384::ecdsa::Signature = p384.sign_prehash(&digest).unwrap();
        verify_signature(
            p384_scheme,
            p384.verifying_key().to_sec1_point(false).as_bytes(),
            signature.to_der().as_bytes(),
        );
    }
}

#[test]
fn rsa_signatures_bridge_digest_versions_and_reject_tampering() {
    use rsa::{
        pkcs1::EncodeRsaPublicKey,
        signature::{RandomizedSigner, SignatureEncoding},
    };

    let mut rng = rsa::rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public = key.to_public_key().to_pkcs1_der().unwrap();
    macro_rules! check {
        ($padding:ident, $hash:ident, $scheme:ident) => {
            let signer = rsa::$padding::SigningKey::<rsa::sha2::$hash>::new(key.clone());
            let signature = signer.try_sign_with_rng(&mut rng, MESSAGE).unwrap();
            verify_signature(
                SigningScheme::$scheme,
                public.as_bytes(),
                &signature.to_vec(),
            );
        };
    }
    check!(pkcs1v15, Sha256, RsaPkcs1Sha256);
    check!(pkcs1v15, Sha384, RsaPkcs1Sha384);
    check!(pkcs1v15, Sha512, RsaPkcs1Sha512);
    check!(pss, Sha256, RsaPssSha256);
    check!(pss, Sha384, RsaPssSha384);
    check!(pss, Sha512, RsaPssSha512);
}
