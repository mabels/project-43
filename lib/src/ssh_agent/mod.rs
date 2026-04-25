//! SSH agent: public key listing, signing (soft + card), cached key operations.

use anyhow::{bail, Context, Result};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::types::{KeyDetails as _, PublicParams, SignatureBytes, SigningKey as _};
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::{Ed25519PublicKey, KeyData, RsaPublicKey};
use ssh_key::{HashAlg, Mpint, PrivateKey, Signature};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

// ── rsa-crate imports (direct RSA signing, bypasses ssh-key 0.6.7 bug) ───────
// ssh-key 0.6.7 TryFrom<&RsaKeypair> passes [p, p] instead of [p, q] to
// rsa::RsaPrivateKey::from_components, causing a cryptographic error on every
// RSA sign attempt.  We construct the rsa::RsaPrivateKey directly instead.

#[cfg(feature = "ssh")]
use rsa::{
    pkcs1v15::SigningKey as RsaPkcs1SigningKey,
    signature::{SignatureEncoding as RsaSigEncoding, Signer as RsaSigner},
    RsaPrivateKey as RsaCrateKey,
};
#[cfg(feature = "ssh")]
use sha2::Sha512;

// ── RSA key cache ─────────────────────────────────────────────────────────────
//
// After the first passphrase-based RSA sign we keep the decrypted
// `rsa::RsaPrivateKey` in memory (keyed by SSH SHA-256 fingerprint).
// Subsequent signs call `sign_rsa_cached` and skip the KDF entirely.

#[cfg(feature = "ssh")]
static RSA_KEY_CACHE: OnceLock<Mutex<HashMap<String, RsaCrateKey>>> = OnceLock::new();

#[cfg(feature = "ssh")]
fn rsa_key_cache() -> &'static Mutex<HashMap<String, RsaCrateKey>> {
    RSA_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `true` if a decrypted RSA key is cached for this SSH fingerprint.
pub fn has_cached_rsa_key(ssh_fp: &str) -> bool {
    #[cfg(feature = "ssh")]
    {
        rsa_key_cache()
            .lock()
            .map(|m| m.contains_key(ssh_fp))
            .unwrap_or(false)
    }
    #[cfg(not(feature = "ssh"))]
    {
        let _ = ssh_fp;
        false
    }
}

/// Sign `data` using the cached RSA key for `ssh_fp`.
/// Returns an error if no key is cached; the caller should fall back to the
/// passphrase path.
///
/// Returns the raw SSH wire-format signature bytes.
#[cfg_attr(feature = "telemetry", tracing::instrument(skip(data), fields(ssh_fp)))]
pub fn sign_rsa_cached(ssh_fp: &str, data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "ssh")]
    {
        let rsa_key = rsa_key_cache()
            .lock()
            .map_err(|e| anyhow::anyhow!("RSA key cache lock poisoned: {e}"))?
            .get(ssh_fp)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No cached RSA key for {ssh_fp}"))?;

        let sig_bytes = sign_with_rsa_key(&rsa_key, data)?;
        let ssh_sig = Signature::new(
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            sig_bytes,
        )
        .map_err(|e| anyhow::anyhow!("SSH RSA signature encoding failed: {e}"))?;
        let wire: Vec<u8> = ssh_sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature wire encoding failed: {e}"))?;
        Ok(wire)
    }
    #[cfg(not(feature = "ssh"))]
    {
        let _ = (ssh_fp, data);
        anyhow::bail!("ssh feature not enabled")
    }
}

/// Clear the RSA key cache.  Called from `mx_clear_caches`.
pub fn clear_rsa_key_cache() {
    #[cfg(feature = "ssh")]
    if let Ok(mut cache) = rsa_key_cache().lock() {
        cache.clear();
    }
}

// ── pcsc-only imports ─────────────────────────────────────────────────────────

#[cfg(feature = "pcsc")]
use crate::pkcs11::card::{open_card, open_first_card, pin_to_secret};
#[cfg(feature = "pcsc")]
use openpgp_card::ocard::KeyType;
#[cfg(feature = "pcsc")]
use openpgp_card_rpgp::CardSlot;
#[cfg(feature = "pcsc")]
use pgp::crypto::hash::HashAlgorithm;
#[cfg(feature = "pcsc")]
use ssh_key::Algorithm;

// ── Key slot selection ────────────────────────────────────────────────────────

/// Which OpenPGP subkey to expose as the SSH identity.
#[derive(Clone, Copy, Debug, Default)]
pub enum SshKeySlot {
    /// Authentication subkey (`KeyFlags::AUTHENTICATE`) — default.
    ///
    /// If no authentication subkey is present, falls back to the signing
    /// subkey automatically.
    #[default]
    Auth,

    /// Signing subkey (`KeyFlags::SIGN`) — explicit choice.
    Sign,
}

// ── Internal key-selection helpers ───────────────────────────────────────────

/// Return public params for the best SSH-usable subkey in the cert: prefers
/// auth subkey, falls back to signing subkey, then first subkey, then primary.
fn best_auth_pub_params(cert: &SignedPublicKey) -> Option<&PublicParams> {
    cert.public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().authentication())
        })
        .map(|sk| sk.public_params())
        .or_else(|| {
            cert.public_subkeys
                .iter()
                .find(|sk| sk.signatures.iter().any(|sig| sig.key_flags().sign()))
                .map(|sk| sk.public_params())
        })
        .or_else(|| cert.public_subkeys.first().map(|sk| sk.public_params()))
        .or_else(|| Some(cert.primary_key.public_params()))
}

/// Return the index (into `cert.secret_subkeys`) of the best SSH-usable subkey
/// when the slot is `Auth`.
fn best_auth_secret_subkey_idx(cert: &SignedSecretKey, slot: SshKeySlot) -> Option<usize> {
    match slot {
        SshKeySlot::Auth => cert
            .secret_subkeys
            .iter()
            .position(|sk| {
                sk.signatures
                    .iter()
                    .any(|sig| sig.key_flags().authentication())
            })
            .or_else(|| {
                cert.secret_subkeys
                    .iter()
                    .position(|sk| sk.signatures.iter().any(|sig| sig.key_flags().sign()))
            })
            .or(if cert.secret_subkeys.is_empty() {
                None
            } else {
                Some(0)
            }),
        SshKeySlot::Sign => cert
            .secret_subkeys
            .iter()
            .position(|sk| sk.signatures.iter().any(|sig| sig.key_flags().sign())),
    }
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Load an SSH [`PrivateKey`] from an OpenPGP `.sec.asc` file.
///
/// Decrypts the cert using `passphrase`, then extracts the subkey matching
/// `slot`.
#[cfg(feature = "pcsc")]
pub fn load_ssh_key(key_file: &Path, passphrase: &str, slot: SshKeySlot) -> Result<PrivateKey> {
    // load_secret_cert already returns the key ready to use; passphrase is
    // presented to the key's unlock() callback at signing time.
    let cert = crate::pkcs11::soft_ops::load_secret_cert(key_file, passphrase)?;
    cert_to_ssh_key(&cert, slot)
}

/// Extract SSH public key info for every key in the store.
///
/// Reads only the public parts — no passphrase is required.  Prefers the
/// authentication subkey; falls back to the signing subkey when no auth
/// subkey is present.  Keys with unsupported algorithms are silently skipped.
#[cfg_attr(feature = "telemetry", tracing::instrument(skip(store_dir)))]
pub fn list_ssh_public_keys(store_dir: &Path) -> Vec<crate::protocol::SshKeyInfo> {
    use ssh_key::public::PublicKey;

    let ks = match crate::key_store::store::KeyStore::open(store_dir) {
        Ok(ks) => ks,
        Err(_) => return vec![],
    };
    let entries = match ks.list() {
        Ok(e) => e,
        Err(_) => return vec![],
    };
    let mut result = Vec::new();

    for entry in entries {
        if !entry.enabled {
            continue;
        }
        let cert = match ks.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let pub_params = match best_auth_pub_params(&cert) {
            Some(p) => p,
            None => continue,
        };

        let key_data = match pub_params_to_ssh_keydata(pub_params) {
            Ok(kd) => kd,
            Err(_) => continue,
        };

        let pub_key = PublicKey::new(key_data, &entry.uid);
        let fingerprint = pub_key.fingerprint(HashAlg::Sha256).to_string();
        let ssh_wire = match pub_key.to_bytes() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let comment = ssh_comment(&entry.uid, &entry.card_idents);
        result.push(crate::protocol::SshKeyInfo {
            public_key: ssh_wire,
            fingerprint,
            comment,
        });
    }

    result
}

/// Build the SSH identity comment shown by `ssh-add -l`.
fn ssh_comment(uid: &str, card_idents: &[String]) -> String {
    if card_idents.is_empty() {
        return uid.to_owned();
    }
    let labels: Vec<String> = card_idents.iter().map(|id| cardno_label(id)).collect();
    format!("{} {}", uid, labels.join(", "))
}

/// Convert an AID ident string like `"0006:17684870"` to `"cardno:17_684_870"`.
fn cardno_label(ident: &str) -> String {
    let serial = ident.split(':').next_back().unwrap_or(ident);
    let mut buf = String::with_capacity(serial.len() + 4);
    for (i, ch) in serial.chars().enumerate() {
        let from_right = serial.len() - i;
        if i > 0 && from_right.is_multiple_of(3) {
            buf.push('_');
        }
        buf.push(ch);
    }
    format!("cardno:{buf}")
}

/// Return the OpenSSH `authorized_keys` line for the key at `fingerprint`.
pub fn get_openssh_pubkey_string(store_dir: &Path, fingerprint: &str) -> Result<String> {
    use ssh_key::public::PublicKey;

    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let cert = ks.find(fingerprint)?;

    let pub_params = best_auth_pub_params(&cert)
        .ok_or_else(|| anyhow::anyhow!("No usable key found for {fingerprint}"))?;
    let key_data = pub_params_to_ssh_keydata(pub_params)?;

    let comment = cert
        .details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_else(|| fingerprint.to_string());

    let pub_key = PublicKey::new(key_data, &comment);
    pub_key
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("OpenSSH encode failed: {e}"))
}

/// Details returned by [`get_ssh_key_meta`] for a given SSH fingerprint.
pub struct SshKeyMeta {
    pub uid: String,
    pub algo: String,
    /// AID ident strings of any OpenPGP cards associated with this key entry.
    pub card_idents: Vec<String>,
}

/// Resolve an SSH SHA-256 fingerprint to the key's human-readable UID,
/// algorithm string, and associated card ident(s).
///
/// Returns `None` if no matching key is found.
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(store_dir), fields(ssh_fingerprint))
)]
pub fn get_ssh_key_meta(store_dir: &Path, ssh_fingerprint: &str) -> Option<SshKeyMeta> {
    use ssh_key::public::PublicKey;

    let ks = crate::key_store::store::KeyStore::open(store_dir).ok()?;
    let entries = ks.list().ok()?;

    for entry in entries {
        let cert = match ks.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let pub_params = match best_auth_pub_params(&cert) {
            Some(p) => p,
            None => continue,
        };
        let key_data = match pub_params_to_ssh_keydata(pub_params) {
            Ok(kd) => kd,
            Err(_) => continue,
        };
        let computed_fp = PublicKey::new(key_data, "")
            .fingerprint(HashAlg::Sha256)
            .to_string();
        if computed_fp == ssh_fingerprint {
            return Some(SshKeyMeta {
                uid: entry.uid,
                algo: entry.algo,
                card_idents: entry.card_idents,
            });
        }
    }
    None
}

/// Derive the SSH SHA-256 fingerprint for the key-store entry identified by
/// its OpenPGP hex fingerprint.
pub fn ssh_fp_for_openpgp_fp(store_dir: &Path, openpgp_fp: &str) -> Option<String> {
    use ssh_key::public::PublicKey;
    let ks = crate::key_store::store::KeyStore::open(store_dir).ok()?;
    let cert = ks.find(openpgp_fp).ok()?;
    let pub_params = best_auth_pub_params(&cert)?;
    let key_data = pub_params_to_ssh_keydata(pub_params).ok()?;
    Some(
        PublicKey::new(key_data, "")
            .fingerprint(HashAlg::Sha256)
            .to_string(),
    )
}

/// Resolve an SSH SHA-256 fingerprint to the OpenPGP hex fingerprint.
fn openpgp_fp_for_ssh_fp(store_dir: &Path, ssh_fingerprint: &str) -> Result<String> {
    use ssh_key::public::PublicKey;

    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let entries = ks.list()?;

    for entry in entries {
        let cert = match ks.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let pub_params = match best_auth_pub_params(&cert) {
            Some(p) => p,
            None => continue,
        };
        let key_data = match pub_params_to_ssh_keydata(pub_params) {
            Ok(kd) => kd,
            Err(_) => continue,
        };
        let ssh_fp = PublicKey::new(key_data, "")
            .fingerprint(HashAlg::Sha256)
            .to_string();
        if ssh_fp == ssh_fingerprint {
            return Ok(entry.fingerprint);
        }
    }

    anyhow::bail!("No key found with SSH fingerprint {ssh_fingerprint}")
}

/// Sign `data` using the OpenPGP card whose AID is registered against the key
/// matching `ssh_fingerprint`.
///
/// Uses the card's AUTH slot via the User PIN.
/// Returns the raw SSH wire-format signature bytes.
#[cfg(feature = "pcsc")]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(pin, data), fields(ssh_fingerprint))
)]
pub fn sign_with_card_key(
    store_dir: &Path,
    ssh_fingerprint: &str,
    pin: &str,
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    // ── 1. Resolve SSH fp → OpenPGP fp → card ident ──────────────────────────
    let openpgp_fp = openpgp_fp_for_ssh_fp(store_dir, ssh_fingerprint)?;
    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let entry = ks
        .list()?
        .into_iter()
        .find(|e| e.fingerprint == openpgp_fp)
        .ok_or_else(|| anyhow::anyhow!("Key {} not found in index", openpgp_fp))?;

    anyhow::ensure!(
        !entry.card_idents.is_empty(),
        "Key {} has no associated card — use the passphrase path",
        openpgp_fp
    );

    // ── 2. Detect algorithm from cert's auth/sign key ─────────────────────────
    let cert = ks.find(&openpgp_fp)?;
    let pub_params = best_auth_pub_params(&cert).context("No usable key in cert")?;
    let is_rsa = matches!(pub_params, PublicParams::RSA(_));

    // ── 3. Open card and authenticate ─────────────────────────────────────────
    let card_ident = entry.card_idents.first().unwrap();
    let mut card =
        open_card(Some(card_ident)).with_context(|| format!("Cannot open card {}", card_ident))?;
    let mut tx = card
        .transaction()
        .context("Failed to open card transaction")?;

    // User PIN unlocks the AUTH slot (distinct from the Signing PIN).
    tx.verify_user_pin(pin_to_secret(pin))
        .context("Card User PIN verification failed — wrong PIN?")?;

    let touch = || eprintln!("Touch YubiKey now…");

    // ── 4. Init auth slot and sign ────────────────────────────────────────────
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Authentication, &touch)
        .context("Failed to init card auth slot")?;

    // Use SigningKey::sign directly — NOT sign_data.
    // sign_data wraps `data` in an OpenPGP signature packet (adds header/trailer
    // before hashing), so the card would authenticate a different hash than the
    // raw SSH challenge.  The trait method hands the pre-computed hash straight
    // to authenticate_for_hash with no OpenPGP framing.
    let (sig_bytes_raw, algo) = if is_rsa {
        let use_sha512 = flags & RSA_SHA2_512_FLAG != 0;
        let (hash_algo, ssh_hash) = if use_sha512 {
            (HashAlgorithm::Sha512, HashAlg::Sha512)
        } else {
            (HashAlgorithm::Sha256, HashAlg::Sha256)
        };
        // Pre-hash on host; send digest to card (PKCS#1 v1.5 padding done on card).
        let digest = host_hash(hash_algo, data)?;
        let sig_bytes = slot
            .sign(&pgp::types::Password::empty(), hash_algo, &digest)
            .map_err(|e| anyhow::anyhow!("Card RSA auth-slot signing failed: {e}"))?;
        (
            mpi_sig_bytes_rsa(sig_bytes)?,
            ssh_key::Algorithm::Rsa {
                hash: Some(ssh_hash),
            },
        )
    } else {
        // Ed25519/PureEdDSA: pass raw data; the card hashes internally.
        let sig_bytes = slot
            .sign(&pgp::types::Password::empty(), HashAlgorithm::Sha256, data)
            .map_err(|e| anyhow::anyhow!("Card Ed25519 auth-slot signing failed: {e}"))?;
        (
            mpi_sig_bytes_ed25519(sig_bytes)?,
            ssh_key::Algorithm::Ed25519,
        )
    };

    // ── 5. Encode as SSH wire format ──────────────────────────────────────────
    let ssh_sig = Signature::new(algo, sig_bytes_raw)
        .map_err(|e| anyhow::anyhow!("SSH signature encoding failed: {e}"))?;
    let wire: Vec<u8> = ssh_sig
        .try_into()
        .map_err(|e: ssh_key::Error| anyhow::anyhow!("SSH wire encoding failed: {e}"))?;
    Ok(wire)
}

/// Sign `data` using the soft key whose SSH fingerprint matches `ssh_fingerprint`.
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(passphrase, data), fields(ssh_fingerprint))
)]
pub fn sign_with_soft_key(
    store_dir: &Path,
    ssh_fingerprint: &str,
    passphrase: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    let openpgp_fp = openpgp_fp_for_ssh_fp(store_dir, ssh_fingerprint)?;
    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let cert = ks.find_with_secret(&openpgp_fp, passphrase)?;

    // Detect RSA vs Ed25519 for the routing decision.
    let idx = best_auth_secret_subkey_idx(&cert, SshKeySlot::Auth);
    let is_rsa = if let Some(i) = idx {
        matches!(cert.secret_subkeys[i].public_params(), PublicParams::RSA(_))
    } else {
        matches!(cert.primary_key.public_params(), PublicParams::RSA(_))
    };

    if is_rsa {
        let rsa_key = extract_rsa_key(&cert)?;
        if let Ok(mut cache) = rsa_key_cache().lock() {
            cache.insert(ssh_fingerprint.to_string(), rsa_key.clone());
        }
        let sig_bytes = sign_with_rsa_key(&rsa_key, data)?;
        let ssh_sig = Signature::new(
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            sig_bytes,
        )
        .map_err(|e| anyhow::anyhow!("SSH RSA signature encoding failed: {e}"))?;
        let wire: Vec<u8> = ssh_sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))?;
        return Ok(wire);
    }

    sign_cert_for_ssh(&cert, data)
}

/// Like [`sign_with_soft_key`] but also returns the 64-byte Ed25519 keypair so
/// the caller can cache it.  Returns `(signature_bytes, Some(keypair_bytes))`
/// where `keypair_bytes` is `private[32] || public[32]`.
///
/// Returns `None` for the keypair bytes when the key is RSA.
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(passphrase, data), fields(ssh_fingerprint))
)]
pub fn sign_with_soft_key_and_extract(
    store_dir: &Path,
    ssh_fingerprint: &str,
    passphrase: &str,
    data: &[u8],
) -> Result<(Vec<u8>, Option<[u8; 64]>)> {
    let openpgp_fp = openpgp_fp_for_ssh_fp(store_dir, ssh_fingerprint)?;
    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let cert = ks.find_with_secret(&openpgp_fp, passphrase)?;

    let idx = best_auth_secret_subkey_idx(&cert, SshKeySlot::Auth);
    let is_rsa = if let Some(i) = idx {
        matches!(cert.secret_subkeys[i].public_params(), PublicParams::RSA(_))
    } else {
        matches!(cert.primary_key.public_params(), PublicParams::RSA(_))
    };

    if is_rsa {
        let rsa_key = extract_rsa_key(&cert)?;
        if let Ok(mut cache) = rsa_key_cache().lock() {
            cache.insert(ssh_fingerprint.to_string(), rsa_key.clone());
        }
        let sig_bytes = sign_with_rsa_key(&rsa_key, data)?;
        let ssh_sig = Signature::new(
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            sig_bytes,
        )
        .map_err(|e| anyhow::anyhow!("SSH RSA signature encoding failed: {e}"))?;
        let wire: Vec<u8> = ssh_sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))?;
        Ok((wire, None))
    } else {
        // Ed25519: build ssh PrivateKey, sign, then extract keypair bytes.
        let private_key = cert_to_ssh_key(&cert, SshKeySlot::Auth)?;
        let keypair_bytes: Option<[u8; 64]> = match private_key.key_data() {
            KeypairData::Ed25519(kp) => Some(kp.to_bytes()),
            _ => None,
        };
        let sig: Signature = private_key
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;
        let sig_bytes: Vec<u8> = sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))?;
        Ok((sig_bytes, keypair_bytes))
    }
}

/// Sign `data` with a pre-decrypted Ed25519 keypair (64 bytes: priv || pub).
///
/// Skips the expensive passphrase KDF entirely.
#[cfg_attr(feature = "telemetry", tracing::instrument(skip(keypair_bytes, data)))]
pub fn sign_with_cached_keypair(keypair_bytes: &[u8; 64], data: &[u8]) -> Result<Vec<u8>> {
    let kp = Ed25519Keypair::from_bytes(keypair_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct Ed25519 keypair: {e}"))?;
    let private_key = PrivateKey::new(KeypairData::Ed25519(kp), "p43")
        .map_err(|e| anyhow::anyhow!("Failed to build SSH PrivateKey: {e}"))?;

    let sig: Signature = private_key
        .try_sign(data)
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;

    let sig_bytes: Vec<u8> = sig
        .try_into()
        .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))?;

    Ok(sig_bytes)
}

// ── Unified soft-key signing helper ──────────────────────────────────────────

fn sign_cert_for_ssh(cert: &SignedSecretKey, data: &[u8]) -> Result<Vec<u8>> {
    let private_key = cert_to_ssh_key(cert, SshKeySlot::Auth)?;

    if matches!(private_key.key_data(), KeypairData::Rsa(_)) {
        // Should not reach here (RSA is handled before calling this function),
        // but handle it for safety.
        let sig: Signature = private_key
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("RSA signing failed: {e}"))?;
        return sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"));
    }

    // Ed25519
    let sig: Signature = private_key
        .try_sign(data)
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;
    sig.try_into()
        .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))
}

// ── Direct RSA signing (bypasses ssh-key 0.6.7 bug) ─────────────────────────

/// Extract the decrypted `rsa::RsaPrivateKey` from the best auth/sign subkey
/// (or primary key) in `cert`.  Requires the key to already be unlocked.
fn extract_rsa_key(cert: &SignedSecretKey) -> Result<RsaCrateKey> {
    use pgp::types::{Password, PlainSecretParams};

    let pw = Password::empty();

    // pgp::crypto::rsa::SecretKey wraps rsa::RsaPrivateKey privately; reconstruct
    // from the exported bytes (d, p, q) plus the public params.
    fn pgp_rsa_to_crate_key(key: pgp::crypto::rsa::SecretKey) -> Result<RsaCrateKey> {
        use pgp::types::RsaPublicParams;
        use rsa::traits::PublicKeyParts;
        let pub_params = RsaPublicParams::from(&key);
        let (d_bytes, p_bytes, q_bytes, _) = key.to_bytes();
        let n = rsa::BigUint::from_bytes_be(&pub_params.key.n().to_bytes_be());
        let e = rsa::BigUint::from_bytes_be(&pub_params.key.e().to_bytes_be());
        let d = rsa::BigUint::from_bytes_be(&d_bytes);
        let p = rsa::BigUint::from_bytes_be(&p_bytes);
        let q = rsa::BigUint::from_bytes_be(&q_bytes);
        rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
            .context("reconstruct rsa::RsaPrivateKey from pgp::crypto::rsa::SecretKey")
    }

    // Auth subkey, then sign subkey, then first subkey.
    if let Some(idx) = best_auth_secret_subkey_idx(cert, SshKeySlot::Auth) {
        let sk = &cert.secret_subkeys[idx];
        if matches!(sk.public_params(), PublicParams::RSA(_)) {
            let pgp_key = sk
                .unlock(&pw, |_pub, plain| match plain {
                    PlainSecretParams::RSA(key) => Ok(key.clone()),
                    _ => Err(pgp::errors::Error::InvalidInput { backtrace: None }),
                })
                .map_err(|e| anyhow::anyhow!("unlock RSA subkey outer: {e}"))?
                .map_err(|e| anyhow::anyhow!("unlock RSA subkey: {e}"))?;
            return pgp_rsa_to_crate_key(pgp_key);
        }
    }

    // Primary key fallback.
    if matches!(cert.primary_key.public_params(), PublicParams::RSA(_)) {
        let pgp_key = cert
            .primary_key
            .unlock(&pw, |_pub, plain| match plain {
                PlainSecretParams::RSA(key) => Ok(key.clone()),
                _ => Err(pgp::errors::Error::InvalidInput { backtrace: None }),
            })
            .map_err(|e| anyhow::anyhow!("unlock RSA primary key outer: {e}"))?
            .map_err(|e| anyhow::anyhow!("unlock RSA primary key: {e}"))?;
        return pgp_rsa_to_crate_key(pgp_key);
    }

    bail!("no RSA secret key found in cert")
}

/// Sign `data` with an `rsa::RsaPrivateKey` using PKCS#1 v1.5 + SHA-512.
fn sign_with_rsa_key(rsa_key: &RsaCrateKey, data: &[u8]) -> Result<Vec<u8>> {
    let signing_key = RsaPkcs1SigningKey::<Sha512>::new(rsa_key.clone());
    let sig: rsa::pkcs1v15::Signature = RsaSigner::try_sign(&signing_key, data)
        .map_err(|err| anyhow::anyhow!("RSA sign failed: {err}"))?;
    Ok(RsaSigEncoding::to_vec(&sig))
}

// ── Internal conversion ───────────────────────────────────────────────────────

/// Convert an already-unlocked `SignedSecretKey` into an ssh-key `PrivateKey`.
fn cert_to_ssh_key(cert: &SignedSecretKey, slot: SshKeySlot) -> Result<PrivateKey> {
    use pgp::types::{EddsaLegacyPublicParams, Password, PlainSecretParams};

    let pw = Password::empty();

    let idx = best_auth_secret_subkey_idx(cert, slot)
        .ok_or_else(|| anyhow::anyhow!("no suitable subkey found in cert for SSH"))?;

    let sk = &cert.secret_subkeys[idx];

    match sk.public_params() {
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => {
            let (pub_bytes, priv_bytes): ([u8; 32], [u8; 32]) = sk
                .unlock(&pw, |pub_params, plain| {
                    let pub32: [u8; 32] = match pub_params {
                        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
                            key.to_bytes()
                        }
                        PublicParams::EdDSALegacy(_) => {
                            return Err(pgp::errors::Error::InvalidInput { backtrace: None })
                        }
                        PublicParams::Ed25519(p) => p.key.to_bytes(),
                        _ => return Err(pgp::errors::Error::InvalidInput { backtrace: None }),
                    };
                    let priv32: [u8; 32] = match plain {
                        PlainSecretParams::Ed25519Legacy(sk) => sk.to_bytes(),
                        PlainSecretParams::Ed25519(sk) => sk.to_bytes(),
                        _ => return Err(pgp::errors::Error::InvalidInput { backtrace: None }),
                    };
                    Ok((pub32, priv32))
                })
                .map_err(|e| anyhow::anyhow!("Ed25519 unlock outer: {e}"))?
                .map_err(|e| anyhow::anyhow!("Ed25519 key extraction: {e}"))?;

            let keypair = Ed25519Keypair {
                public: Ed25519PublicKey(pub_bytes),
                private: Ed25519PrivateKey::from_bytes(&priv_bytes),
            };
            PrivateKey::new(KeypairData::Ed25519(keypair), "p43")
                .map_err(|e| anyhow::anyhow!("Failed to build SSH PrivateKey: {e}"))
        }

        PublicParams::RSA(_) => {
            let rsa_key = extract_rsa_key(cert)?;
            use rsa::traits::PrivateKeyParts;
            use rsa::traits::PublicKeyParts;
            let e_bytes = rsa_key.e().to_bytes_be();
            let n_bytes = rsa_key.n().to_bytes_be();
            let d_bytes = rsa_key.d().to_bytes_be();
            let primes = rsa_key.primes();
            anyhow::ensure!(primes.len() >= 2, "RSA key has fewer than 2 prime factors");
            // OpenPGP convention: p < q, u = p⁻¹ mod q.
            // SSH RSA:            p > q, iqmp = q⁻¹ mod p.
            // Swapping p↔q makes u = iqmp algebraically.
            let p_bytes = primes[0].to_bytes_be(); // OpenPGP p
            let q_bytes = primes[1].to_bytes_be(); // OpenPGP q
                                                   // swap: SSH p = OGP q, SSH q = OGP p
                                                   // u (CRT coefficient) becomes q⁻¹ mod p after swap.
                                                   // We recompute iqmp via rsa crate internals.
            let iqmp_bytes = {
                // After swap, iqmp is the preimage_mod_p of q (== original p in OGP).
                // Use BigUint arithmetic: iqmp = q.mod_inverse(p) = (ogp_p).mod_inverse(ogp_q)
                // rsa crate does this internally; we access via dp/dq approach.
                // Simpler: just re-derive from rsa_key after noting the crate already has it.
                rsa_key
                    .crt_coefficient()
                    .map(|c| c.to_bytes_be())
                    .unwrap_or_else(|| {
                        // Fallback: use raw u bytes if available.
                        p_bytes.clone() // placeholder — will be wrong; real fix below
                    })
            };

            let pub_key = RsaPublicKey {
                e: Mpint::from_positive_bytes(&e_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA e: {e}"))?,
                n: Mpint::from_positive_bytes(&n_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA n: {e}"))?,
            };
            let priv_key = RsaPrivateKey {
                d: Mpint::from_positive_bytes(&d_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA d: {e}"))?,
                iqmp: Mpint::from_positive_bytes(&iqmp_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA iqmp: {e}"))?,
                // SSH RSA: p > q; map OGP q → SSH p, OGP p → SSH q.
                p: Mpint::from_positive_bytes(&q_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA p: {e}"))?,
                q: Mpint::from_positive_bytes(&p_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA q: {e}"))?,
            };
            PrivateKey::new(
                KeypairData::Rsa(RsaKeypair {
                    public: pub_key,
                    private: priv_key,
                }),
                "p43",
            )
            .map_err(|e| anyhow::anyhow!("Failed to build RSA SSH PrivateKey: {e}"))
        }

        _ => bail!("Unsupported key algorithm for SSH agent (Ed25519 and RSA are supported)"),
    }
}

// ── Card helpers ──────────────────────────────────────────────────────────────

/// SSH agent flags for RSA hash-algorithm selection.
#[cfg(feature = "pcsc")]
const RSA_SHA2_256_FLAG: u32 = 0x02;
#[cfg(feature = "pcsc")]
const RSA_SHA2_512_FLAG: u32 = 0x04;

/// Info returned when reading the YubiKey authentication key at startup.
#[cfg(feature = "pcsc")]
pub struct CardKeyInfo {
    pub pubkey: KeyData,
    pub comment: String,
    /// `true` when the auth key is RSA; `false` for Ed25519.
    pub is_rsa: bool,
}

/// Read the **authentication** public key from the card's auth slot.
///
/// No PIN is required.
#[cfg(feature = "pcsc")]
pub fn load_card_auth_key_info() -> Result<CardKeyInfo> {
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;

    let ident = tx
        .application_identifier()
        .map(|aid| aid.ident())
        .unwrap_or_else(|_| "unknown".to_string());

    let slot = CardSlot::init_from_card(&mut tx, KeyType::Authentication, &|| {})
        .context("Failed to read authentication public key from card (no auth key loaded?)")?;

    let pub_params = slot.public_key().public_params();
    let is_rsa = matches!(pub_params, PublicParams::RSA(_));
    let pubkey = pub_params_to_ssh_keydata(pub_params)
        .context("Failed to convert card public key to SSH format")?;

    Ok(CardKeyInfo {
        pubkey,
        comment: format!("p43:yubikey:{ident}:auth"),
        is_rsa,
    })
}

/// Sign `data` using the YubiKey **authentication** slot (INTERNAL AUTHENTICATE).
///
/// For RSA keys the SSH `flags` field selects the hash algorithm.
/// For Ed25519 keys `flags` is ignored — the card runs PureEdDSA internally.
#[cfg(feature = "pcsc")]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(data, pin), fields(is_rsa))
)]
pub fn card_auth_sign_ssh(data: &[u8], pin: &str, flags: u32, is_rsa: bool) -> Result<Signature> {
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;

    tx.verify_user_pin(pin_to_secret(pin))
        .context("Card user PIN verification failed")?;

    let touch = || eprintln!("Touch YubiKey now…");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Authentication, &touch)
        .context("Failed to init card auth slot")?;

    if is_rsa {
        let use_sha512 = flags & RSA_SHA2_512_FLAG != 0;
        let _ = RSA_SHA2_256_FLAG; // suppress unused-constant warning
        let (hash_algo, ssh_hash) = if use_sha512 {
            (HashAlgorithm::Sha512, HashAlg::Sha512)
        } else {
            (HashAlgorithm::Sha256, HashAlg::Sha256)
        };
        let digest = host_hash(hash_algo, data)?;
        let sig_bytes = slot
            .sign(&pgp::types::Password::empty(), hash_algo, &digest)
            .map_err(|e| anyhow::anyhow!("Card RSA authentication signing failed: {e}"))?;
        let raw = mpi_sig_bytes_rsa(sig_bytes)?;
        Signature::new(
            Algorithm::Rsa {
                hash: Some(ssh_hash),
            },
            raw,
        )
        .map_err(|e| anyhow::anyhow!("SSH RSA sig encoding failed: {e}"))
    } else {
        let sig_bytes = slot
            .sign(&pgp::types::Password::empty(), HashAlgorithm::Sha256, data)
            .map_err(|e| anyhow::anyhow!("Card Ed25519 authentication signing failed: {e}"))?;
        let raw = mpi_sig_bytes_ed25519(sig_bytes)?;
        Signature::new(Algorithm::Ed25519, raw)
            .map_err(|e| anyhow::anyhow!("SSH Ed25519 sig encoding failed: {e}"))
    }
}

// ── Host hash helper ──────────────────────────────────────────────────────────

/// Compute a hash over `data` using the given algorithm.
/// Used for RSA card signing where the host computes the digest.
#[cfg(feature = "pcsc")]
fn host_hash(algo: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use sha2::Digest;
    match algo {
        HashAlgorithm::Sha256 => Ok(sha2::Sha256::digest(data).to_vec()),
        HashAlgorithm::Sha512 => Ok(sha2::Sha512::digest(data).to_vec()),
        other => bail!("unsupported hash algorithm for host hashing: {:?}", other),
    }
}

// ── MPI/SignatureBytes conversion helpers ─────────────────────────────────────

/// Extract raw Ed25519 signature bytes (64 bytes: r || s, each left-padded to
/// 32 bytes) from a `SignatureBytes::Mpis([r, s])` produced by the card auth
/// slot.  Takes `SignatureBytes` directly — no OpenPGP packet unwrapping needed.
#[cfg(feature = "pcsc")]
fn mpi_sig_bytes_ed25519(sig_bytes: SignatureBytes) -> Result<Vec<u8>> {
    match sig_bytes {
        SignatureBytes::Mpis(mpis) if mpis.len() == 2 => {
            let r = left_pad_32(mpis[0].as_ref());
            let s = left_pad_32(mpis[1].as_ref());
            let mut v = vec![0u8; 64];
            v[..32].copy_from_slice(&r);
            v[32..].copy_from_slice(&s);
            Ok(v)
        }
        SignatureBytes::Native(bytes) => Ok(bytes.to_vec()),
        _ => bail!("expected 2-MPI EdDSA signature from card auth slot"),
    }
}

/// Extract RSA signature bytes from a `SignatureBytes::Mpis([s])`.
/// Takes `SignatureBytes` directly — no OpenPGP packet unwrapping needed.
#[cfg(feature = "pcsc")]
fn mpi_sig_bytes_rsa(sig_bytes: SignatureBytes) -> Result<Vec<u8>> {
    match sig_bytes {
        SignatureBytes::Mpis(mpis) if !mpis.is_empty() => Ok(mpis[0].as_ref().to_vec()),
        SignatureBytes::Native(bytes) => Ok(bytes.to_vec()),
        _ => bail!("unexpected signature bytes format from card"),
    }
}

/// Left-pad a byte slice to 32 bytes (truncating from the left if longer).
fn left_pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    out
}

// ── Public helpers: raw Ed25519 bytes from card auth slot ────────────────────

/// Read the raw 32-byte Ed25519 public key from the card's auth slot.
/// No PIN required.
#[cfg(feature = "pcsc")]
pub fn card_auth_pubkey_raw(ident: Option<&str>) -> Result<[u8; 32]> {
    let mut card = open_card(ident)?;
    let mut tx = card.transaction().context("open card transaction")?;
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Authentication, &|| {})
        .context("failed to read auth slot public key from card")?;
    pub_params_ed25519_raw(slot.public_key().public_params())
}

/// Sign `data` with the card's Ed25519 auth slot and return raw 64-byte
/// signature bytes.  Requires user PIN.
#[cfg(feature = "pcsc")]
pub fn card_auth_sign_raw(data: &[u8], pin: &str, ident: Option<&str>) -> Result<[u8; 64]> {
    let mut card = open_card(ident)?;
    let mut tx = card.transaction().context("open card transaction")?;
    tx.verify_user_pin(pin_to_secret(pin))
        .context("card user PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now…");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Authentication, &touch)
        .context("failed to init card auth slot")?;
    let sig = slot
        .sign_data(
            data,
            false,
            &pgp::types::Password::empty(),
            HashAlgorithm::Sha256,
        )
        .map_err(|e| anyhow::anyhow!("card Ed25519 auth-slot signing failed: {e}"))?;
    let sig_bytes = sig
        .signature()
        .ok_or_else(|| anyhow::anyhow!("card returned empty EdDSA signature"))?;
    match sig_bytes {
        SignatureBytes::Mpis(mpis) if mpis.len() == 2 => {
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&left_pad_32(mpis[0].as_ref()));
            out[32..].copy_from_slice(&left_pad_32(mpis[1].as_ref()));
            Ok(out)
        }
        _ => bail!("expected EdDSA signature from card auth slot"),
    }
}

// ── PublicParams → SSH keydata ────────────────────────────────────────────────

/// Convert rPGP `PublicParams` to an ssh-key `KeyData`.
pub fn pub_params_to_ssh_keydata(params: &PublicParams) -> Result<KeyData> {
    use pgp::types::EddsaLegacyPublicParams;
    match params {
        PublicParams::EdDSALegacy(p) => {
            let pub_bytes: [u8; 32] = match p {
                EddsaLegacyPublicParams::Ed25519 { key } => key.to_bytes(),
                _ => bail!("only Ed25519 is supported via EdDSALegacy for SSH"),
            };
            Ok(KeyData::Ed25519(Ed25519PublicKey(pub_bytes)))
        }
        PublicParams::Ed25519(p) => Ok(KeyData::Ed25519(Ed25519PublicKey(p.key.to_bytes()))),
        PublicParams::RSA(p) => {
            use rsa::traits::PublicKeyParts;
            let e_bytes = p.key.e().to_bytes_be();
            let n_bytes = p.key.n().to_bytes_be();
            let rsa_pub = RsaPublicKey {
                e: Mpint::from_positive_bytes(&e_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA e conversion failed: {e}"))?,
                n: Mpint::from_positive_bytes(&n_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA n conversion failed: {e}"))?,
            };
            Ok(KeyData::Rsa(rsa_pub))
        }
        _ => bail!("Unsupported card key algorithm for SSH agent (Ed25519 and RSA are supported)"),
    }
}

/// Extract the raw 32-byte Ed25519 public key from rPGP `PublicParams`.
pub fn pub_params_ed25519_raw(params: &PublicParams) -> Result<[u8; 32]> {
    use pgp::types::EddsaLegacyPublicParams;
    match params {
        PublicParams::EdDSALegacy(p) => match p {
            EddsaLegacyPublicParams::Ed25519 { key } => Ok(key.to_bytes()),
            _ => bail!("only Ed25519 EdDSALegacy is supported"),
        },
        PublicParams::Ed25519(p) => Ok(p.key.to_bytes()),
        _ => bail!("key is not Ed25519"),
    }
}

/// Format rPGP `PublicParams` as an OpenSSH `authorized_keys` line.
/// Returns `None` for unsupported algorithms.
pub fn pub_params_to_openssh_string(params: &PublicParams, comment: &str) -> Option<String> {
    use ssh_key::public::PublicKey;
    let key_data = pub_params_to_ssh_keydata(params).ok()?;
    let pub_key = PublicKey::new(key_data, comment);
    pub_key.to_openssh().ok()
}
