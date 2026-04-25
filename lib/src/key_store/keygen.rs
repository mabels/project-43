//! OpenPGP key generation using rPGP.
//!
//! Replaces the old `sequoia_openpgp::cert::prelude::CertBuilder` approach.
//! rPGP key generation is done through `SecretKeyParamsBuilder`.

use anyhow::{bail, Context, Result};
use pgp::composed::{
    EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::thread_rng;
use smallvec::smallvec;

/// Generate a new OpenPGP key with sign + encrypt + auth subkeys.
///
/// `algo`: `"ed25519"` | `"rsa4096"` | `"rsa3072"`
///
/// `passphrase`: if `Some`, secret key material is encrypted at generation
/// time.
pub fn generate(uid: &str, algo: &str, passphrase: Option<&str>) -> Result<SignedSecretKey> {
    let mut rng = thread_rng();

    let (primary_type, enc_type, auth_type) = match algo {
        "ed25519" => (
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519),
            KeyType::Ed25519Legacy,
        ),
        "rsa4096" => (KeyType::Rsa(4096), KeyType::Rsa(4096), KeyType::Rsa(4096)),
        "rsa3072" => (KeyType::Rsa(3072), KeyType::Rsa(3072), KeyType::Rsa(3072)),
        other => bail!(
            "Unknown algorithm '{}'. Supported: ed25519, rsa4096, rsa3072",
            other
        ),
    };

    let key_params = SecretKeyParamsBuilder::default()
        .key_type(primary_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(uid.to_owned())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256, HashAlgorithm::Sha512])
        .passphrase(passphrase.filter(|p| !p.is_empty()).map(str::to_owned))
        .subkeys(vec![
            // Encryption subkey
            SubkeyParamsBuilder::default()
                .key_type(enc_type)
                .can_encrypt(EncryptionCaps::All)
                .build()
                .context("Failed to build encryption subkey params")?,
            // Authentication subkey
            SubkeyParamsBuilder::default()
                .key_type(auth_type)
                .can_authenticate(true)
                .build()
                .context("Failed to build authentication subkey params")?,
        ])
        .build()
        .context("Failed to build key params")?;

    key_params
        .generate(&mut rng)
        .context("Key generation failed")
}
