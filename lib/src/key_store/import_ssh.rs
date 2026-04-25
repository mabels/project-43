//! Import OpenSSH and OpenPGP private keys into the p43 key store (rPGP version).
//!
//! ## Ed25519
//! The 32-byte private seed is extracted from the SSH keypair and wrapped in a
//! v4 OpenPGP `EdDSALegacy` primary key.  A self-certification (CertPositive)
//! over the UID is produced using the key itself.
//!
//! ## RSA
//! The public modulus/exponent and private `d`, `p`, `q` are assembled into an
//! `rsa::RsaPrivateKey` then wrapped in a v4 OpenPGP RSA primary key.
//!
//! ## Passphrase
//! If `openpgp_passphrase` is supplied the secret scalar is CFB-encrypted with
//! AES-256 + iterated S2K before being written to disk.

use anyhow::{Context, Result};
use pgp::composed::{Deserializable, SignedKeyDetails, SignedSecretKey};
use pgp::crypto::ed25519::Mode as Ed25519Mode;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{PubKeyInner, PublicKey as PgpPublicKey, SecretKey as PgpSecretKey, UserId};
use pgp::types::KeyDetails as _;
use pgp::types::{
    EddsaLegacyPublicParams, KeyVersion, PacketHeaderVersion, Password, PlainSecretParams,
    PublicParams, RsaPublicParams, S2kParams, SecretParams, SignedUser, Tag, Timestamp,
};
use rand::thread_rng;
use rsa::BigUint;
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use std::io;

use crate::key_store::store::KeyStore;

/// Import an OpenSSH private key (OpenSSH PEM format) into the p43 key store
/// as an OpenPGP cert.
///
/// The SSH key material (Ed25519 or RSA) becomes the primary OpenPGP key with
/// CERTIFY + SIGN + AUTH flags.  A self-signed UID binding is created using the
/// key itself.
///
/// - `pem_bytes`: raw contents of the SSH private key file (OpenSSH format).
/// - `uid_override`: if non-empty, used as the cert UID; otherwise the SSH key
///   comment is used.  Returns an error if neither is set.
/// - `ssh_passphrase`: used to decrypt the SSH key if it is encrypted.
/// - `openpgp_passphrase`: if Some, the stored secret key will be encrypted
///   with this passphrase (you will need it every time you sign).
///
/// Returns the hex fingerprint of the imported cert.
pub fn import_ssh_private_key(
    ks: &KeyStore,
    pem_bytes: &[u8],
    uid_override: Option<&str>,
    ssh_passphrase: Option<&str>,
    openpgp_passphrase: Option<&str>,
) -> Result<String> {
    // ── 1. Parse ──────────────────────────────────────────────────────────────
    let ssh_key = PrivateKey::from_openssh(pem_bytes)
        .context("Failed to parse SSH private key — expected OpenSSH format")?;

    // ── 2. Decrypt if needed ──────────────────────────────────────────────────
    let ssh_key = if ssh_key.is_encrypted() {
        let pw = ssh_passphrase
            .ok_or_else(|| anyhow::anyhow!("SSH key is encrypted; provide the SSH passphrase"))?;
        ssh_key
            .decrypt(pw.as_bytes())
            .context("Failed to decrypt SSH private key (wrong passphrase?)")?
    } else {
        ssh_key
    };

    // ── 3. Resolve UID ────────────────────────────────────────────────────────
    let uid_str: String = match uid_override {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            let comment = ssh_key.comment();
            anyhow::ensure!(
                !comment.is_empty(),
                "SSH key has no comment field; enter a UID in the import dialog"
            );
            comment.to_owned()
        }
    };

    let algo_name = ssh_key.algorithm().to_string();
    let created_at = Timestamp::now();

    // ── 4. Build OpenPGP key material from SSH key data ───────────────────────
    let (plain_params, pub_params, pgp_algorithm) = match ssh_key.key_data() {
        KeypairData::Ed25519(kp) => {
            let seed: [u8; 32] = kp.private.to_bytes();
            let secret =
                pgp::crypto::ed25519::SecretKey::try_from_bytes(seed, Ed25519Mode::EdDSALegacy)
                    .context("Failed to build Ed25519 secret key from SSH seed")?;
            let pub_p = PublicParams::EdDSALegacy(EddsaLegacyPublicParams::from(&secret));
            let plain = PlainSecretParams::Ed25519Legacy(secret);
            (plain, pub_p, PublicKeyAlgorithm::EdDSALegacy)
        }
        KeypairData::Rsa(rsa) => {
            let n = ssh_mpint_to_biguint(&rsa.public.n).context("RSA modulus n")?;
            let e = ssh_mpint_to_biguint(&rsa.public.e).context("RSA public exponent e")?;
            let d = ssh_mpint_to_biguint(&rsa.private.d).context("RSA private exponent d")?;
            let p = ssh_mpint_to_biguint(&rsa.private.p).context("RSA prime p")?;
            let q = ssh_mpint_to_biguint(&rsa.private.q).context("RSA prime q")?;

            let rsa_priv = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
                .context("Failed to reconstruct RSA private key from SSH components")?;
            let pub_p = PublicParams::RSA(RsaPublicParams::from(rsa_priv.to_public_key()));
            let plain = PlainSecretParams::RSA(pgp::crypto::rsa::SecretKey::from(rsa_priv));
            (plain, pub_p, PublicKeyAlgorithm::RSA)
        }
        other => anyhow::bail!("Unsupported SSH key type for import: {:?}", other),
    };

    // ── 5. Build the OpenPGP public key packet ────────────────────────────────
    let inner = PubKeyInner::new(KeyVersion::V4, pgp_algorithm, created_at, None, pub_params)
        .context("Failed to build PubKeyInner")?;
    let pub_key = PgpPublicKey::from_inner(inner).context("Failed to build PublicKey packet")?;

    // ── 6. Self-certify the UID (sign with a plain copy of the key) ───────────
    //
    // The UID certification covers only the public key + UID hash, so it stays
    // valid regardless of whether we later encrypt the secret scalar.
    let signing_sec_key =
        PgpSecretKey::new(pub_key.clone(), SecretParams::Plain(plain_params.clone()))
            .context("Failed to build signing SecretKey")?;

    let uid = UserId::from_str(PacketHeaderVersion::New, &uid_str)
        .context("Failed to build UserId packet")?;

    let mut rng = thread_rng();
    let signed_user: SignedUser = uid
        .sign(
            &mut rng,
            &signing_sec_key,
            signing_sec_key.public_key(),
            &Password::empty(),
        )
        .context("Failed to create UID self-certification")?;

    // ── 7. Optionally encrypt secret material ─────────────────────────────────
    let final_secret_params = match openpgp_passphrase.filter(|p| !p.is_empty()) {
        Some(pw) => {
            let s2k = S2kParams::new_default(&mut rng, KeyVersion::V4);
            let enc = plain_params
                .encrypt(pw.as_bytes(), s2k, &pub_key, Some(Tag::SecretKey))
                .context("Failed to encrypt key material with passphrase")?;
            SecretParams::Encrypted(enc)
        }
        None => SecretParams::Plain(plain_params),
    };

    // ── 8. Assemble and save ──────────────────────────────────────────────────
    let final_sec_key = PgpSecretKey::new(pub_key, final_secret_params)
        .context("Failed to build final SecretKey")?;

    let details = SignedKeyDetails::new(vec![], vec![], vec![signed_user], vec![]);
    let key = SignedSecretKey::new(final_sec_key, details, vec![], vec![]);

    let fp = hex::encode(key.to_public_key().fingerprint().as_bytes()).to_uppercase();
    ks.save_secret(&key)
        .context("Failed to save imported cert")?;

    println!("Imported SSH key {} as {}", algo_name, fp);
    println!("  UID: {}", uid_str);

    Ok(fp)
}

/// Import an armored OpenPGP private key (TSK — Transferable Secret Key) into
/// the key store.
///
/// The armored text is parsed and saved as-is.  The passphrase (if any) is not
/// required at import time; it will be prompted when signing.
///
/// Returns the hex fingerprint of the imported cert.
pub fn import_openpgp_private_key(ks: &KeyStore, armored: &[u8]) -> Result<String> {
    let (key, _) = SignedSecretKey::from_armor_single(io::Cursor::new(armored))
        .context("Failed to parse OpenPGP key — expected armored TSK")?;
    let fp = hex::encode(key.to_public_key().fingerprint().as_bytes()).to_uppercase();
    ks.save_secret(&key).context("Failed to save OpenPGP key")?;
    Ok(fp)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Convert an [`ssh_key::Mpint`] (positive big-endian integer) to [`rsa::BigUint`].
fn ssh_mpint_to_biguint(m: &ssh_key::Mpint) -> Result<BigUint> {
    let bytes = m
        .as_positive_bytes()
        .ok_or_else(|| anyhow::anyhow!("RSA key component is not a positive integer"))?;
    Ok(BigUint::from_bytes_be(bytes))
}
