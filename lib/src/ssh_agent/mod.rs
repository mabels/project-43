use anyhow::{bail, Context, Result};
use openpgp::crypto::mpi;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::policy::StandardPolicy;
use openpgp::types::Curve;
use sequoia_openpgp as openpgp;
use signature::Signer as _; // Ed25519 PrivateKey::try_sign
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::{Ed25519PublicKey, KeyData, RsaPublicKey};
use ssh_key::{HashAlg, Mpint, PrivateKey, Signature};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

// ── rsa-crate imports (direct RSA signing, bypasses ssh-key 0.6.7 bug) ───────
// ssh-key 0.6.7 TryFrom<&RsaKeypair> passes [p, p] instead of [p, q] to
// rsa::RsaPrivateKey::from_components, causing a cryptographic error on every
// RSA sign attempt.  We construct the rsa::RsaPrivateKey directly instead.

#[cfg(feature = "ssh")]
use rsa::{
    pkcs1v15::SigningKey as RsaPkcs1SigningKey,
    signature::{SignatureEncoding as RsaSigEncoding, Signer as RsaSigner},
    BigUint, RsaPrivateKey as RsaCrateKey,
};
#[cfg(feature = "ssh")]
use sha2::Sha512;

// ── RSA key cache ─────────────────────────────────────────────────────────────
//
// After the first passphrase-based RSA sign we keep the decrypted
// `rsa::RsaPrivateKey` in memory (keyed by SSH SHA-256 fingerprint).
// Subsequent signs call `sign_rsa_cached` and skip the KDF entirely —
// the same behaviour as the Ed25519 keypair cache but for variable-length RSA.

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
/// Returns the base64-encoded SSH wire signature (same format as
/// `sign_with_soft_key` / `sign_with_soft_key_and_extract`).
pub fn sign_rsa_cached(ssh_fp: &str, data: &[u8]) -> Result<String> {
    #[cfg(feature = "ssh")]
    {
        let rsa_key = rsa_key_cache()
            .lock()
            .map_err(|e| anyhow::anyhow!("RSA key cache lock poisoned: {e}"))?
            .get(ssh_fp)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No cached RSA key for {ssh_fp}"))?;

        let sig_bytes = sign_with_rsa_key(&rsa_key, data)?;
        // Wrap in SSH wire format (algorithm name + raw bytes) before encoding.
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
        Ok(B64.encode(wire))
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
use crate::pkcs11::card::open_first_card;
#[cfg(feature = "pcsc")]
use crate::pkcs11::soft_ops::load_secret_cert;
#[cfg(feature = "pcsc")]
use openpgp::crypto::Signer as _OgpSigner;
#[cfg(feature = "pcsc")]
use openpgp::types::HashAlgorithm;
#[cfg(feature = "pcsc")]
use openpgp_card_sequoia::types::KeyType;
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

// ── Public helpers ────────────────────────────────────────────────────────────

/// Load an SSH [`PrivateKey`] from an OpenPGP `.sec.asc` file.
///
/// Decrypts the cert using `passphrase`, then extracts the subkey matching
/// `slot`.  When `slot` is [`SshKeySlot::Auth`] and no authentication subkey
/// exists, the signing subkey is used as a fallback.
///
/// Only Ed25519 keys are currently supported.
#[cfg(feature = "pcsc")]
pub fn load_ssh_key(key_file: &Path, passphrase: &str, slot: SshKeySlot) -> Result<PrivateKey> {
    let cert = load_secret_cert(key_file, passphrase)?;
    cert_to_ssh_key(&cert, slot)
}

/// Extract SSH public key info for every key in the store.
///
/// Reads only the public parts — no passphrase is required.  Prefers the
/// authentication subkey; falls back to the signing subkey when no auth
/// subkey is present.  Keys with unsupported algorithms are silently skipped.
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
    let policy = StandardPolicy::new();
    let mut result = Vec::new();

    for entry in entries {
        if !entry.enabled {
            continue;
        }
        let cert = match ks.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Prefer auth subkey; fall back to signing subkey; then primary key
        // (card-imported certs may have only a primary key with CERTIFY flags).
        let ka_opt = cert
            .keys()
            .with_policy(&policy, None)
            .for_authentication()
            .next()
            .or_else(|| cert.keys().with_policy(&policy, None).for_signing().next())
            .or_else(|| cert.keys().with_policy(&policy, None).next());

        let ka = match ka_opt {
            Some(ka) => ka,
            None => continue,
        };

        let key_data = match mpi_pubkey_to_ssh_keydata(ka.key().mpis()) {
            Ok(kd) => kd,
            Err(_) => continue,
        };

        let pub_key = PublicKey::new(key_data, &entry.uid);
        let fingerprint = pub_key.fingerprint(HashAlg::Sha256).to_string();
        let ssh_wire = match pub_key.to_bytes() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let public_key_b64 = B64.encode(&ssh_wire);

        let comment = ssh_comment(&entry.uid, &entry.card_idents);
        result.push(crate::protocol::SshKeyInfo {
            public_key: public_key_b64,
            fingerprint,
            comment,
        });
    }

    result
}

/// Build the SSH identity comment shown by `ssh-add -l`.
///
/// For soft keys this is just the UID.  For card-backed keys each AID ident
/// (format `"XXXX:YYYYYYYY"` from openpgp-card-sequoia) is formatted as
/// `cardno:Y_YYY_YYY` and appended, e.g.:
///
/// ```text
/// Abels<<Meno cardno:17_684_870
/// ```
fn ssh_comment(uid: &str, card_idents: &[String]) -> String {
    if card_idents.is_empty() {
        return uid.to_owned();
    }
    let labels: Vec<String> = card_idents.iter().map(|id| cardno_label(id)).collect();
    format!("{} {}", uid, labels.join(", "))
}

/// Convert an AID ident string like `"0006:17684870"` to `"cardno:17_684_870"`.
///
/// Strips the manufacturer prefix before the colon, then groups the remaining
/// digits in threes from the right with underscores.
fn cardno_label(ident: &str) -> String {
    let serial = ident.split(':').last().unwrap_or(ident);
    let mut buf = String::with_capacity(serial.len() + 4);
    for (i, ch) in serial.chars().enumerate() {
        let from_right = serial.len() - i;
        if i > 0 && from_right % 3 == 0 {
            buf.push('_');
        }
        buf.push(ch);
    }
    format!("cardno:{buf}")
}

/// Return the OpenSSH `authorized_keys` line for the key at `fingerprint`.
///
/// Prefers the authentication subkey; falls back to the signing subkey.
/// Returns an error if the key has no supported SSH subkey.
pub fn get_openssh_pubkey_string(store_dir: &Path, fingerprint: &str) -> Result<String> {
    use ssh_key::public::PublicKey;

    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let cert = ks.find(fingerprint)?;
    let policy = StandardPolicy::new();

    let ka = cert
        .keys()
        .with_policy(&policy, None)
        .for_authentication()
        .next()
        .or_else(|| cert.keys().with_policy(&policy, None).for_signing().next())
        // Card-imported certs may have only a primary key with CERTIFY flags
        // (old import path). Fall back to the primary key so we can still
        // display the SSH public key representation.
        .or_else(|| cert.keys().with_policy(&policy, None).next())
        .ok_or_else(|| anyhow::anyhow!("No usable key found for {fingerprint}"))?;

    let key_data = mpi_pubkey_to_ssh_keydata(ka.key().mpis())?;

    // Use the first UID as the comment.
    let comment = cert
        .userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
        .unwrap_or_else(|| fingerprint.to_string());

    let pub_key = PublicKey::new(key_data, &comment);
    pub_key
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("OpenSSH encode failed: {e}"))
}

/// Details returned by [`get_ssh_key_details`] for a given SSH fingerprint.
pub struct SshKeyMeta {
    pub uid: String,
    pub algo: String,
    /// AID ident strings of any OpenPGP cards associated with this key entry.
    pub card_idents: Vec<String>,
}

/// Resolve an SSH SHA-256 fingerprint to the key's human-readable UID,
/// algorithm string, and associated card ident(s).
///
/// Returns `None` if no matching key is found.  Used by the UI to display key
/// information in sign-request tiles and the passphrase dialog.
pub fn get_ssh_key_meta(store_dir: &Path, ssh_fingerprint: &str) -> Option<SshKeyMeta> {
    use ssh_key::public::PublicKey;

    let ks = crate::key_store::store::KeyStore::open(store_dir).ok()?;
    let entries = ks.list().ok()?;
    let policy = StandardPolicy::new();

    for entry in entries {
        let cert = match ks.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let ka = cert
            .keys()
            .with_policy(&policy, None)
            .for_authentication()
            .next()
            .or_else(|| cert.keys().with_policy(&policy, None).for_signing().next())
            .or_else(|| cert.keys().with_policy(&policy, None).next());
        let ka = match ka {
            Some(ka) => ka,
            None => continue,
        };
        let key_data = match mpi_pubkey_to_ssh_keydata(ka.key().mpis()) {
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

/// Resolve an SSH SHA-256 fingerprint (e.g. `SHA256:AbCd…`) to the OpenPGP
/// hex fingerprint used as the key-store lookup query.
///
/// Iterates every cert in the store, derives its SSH public key, and compares
/// the SSH fingerprint.  Returns an error if no matching key is found.
fn openpgp_fp_for_ssh_fp(store_dir: &Path, ssh_fingerprint: &str) -> Result<String> {
    use ssh_key::public::PublicKey;

    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let entries = ks.list()?;
    let policy = StandardPolicy::new();

    for entry in entries {
        let cert = match ks.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let ka_opt = cert
            .keys()
            .with_policy(&policy, None)
            .for_authentication()
            .next()
            .or_else(|| cert.keys().with_policy(&policy, None).for_signing().next())
            .or_else(|| cert.keys().with_policy(&policy, None).next());
        let ka = match ka_opt {
            Some(ka) => ka,
            None => continue,
        };
        let key_data = match mpi_pubkey_to_ssh_keydata(ka.key().mpis()) {
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
/// Uses the card's AUTH slot via the User PIN (not the Signing PIN).
/// Ed25519 cards perform PureEdDSA internally; RSA cards hash on-host and
/// respect `flags` (SSH agent sign flags: 0x02 = SHA-256, 0x04 = SHA-512;
/// anything else defaults to SHA-256).
///
/// Returns the SSH wire-encoded signature as base64.
#[cfg(feature = "pcsc")]
pub fn sign_with_card_key(
    store_dir: &Path,
    ssh_fingerprint: &str,
    pin: &str,
    data: &[u8],
    flags: u32,
) -> Result<String> {
    use crate::pkcs11::card::open_card;
    use openpgp_card_sequoia::types::KeyType;

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
    let policy = StandardPolicy::new();
    let cert = ks.find(&openpgp_fp)?;
    let ka = cert
        .keys()
        .with_policy(&policy, None)
        .for_authentication()
        .next()
        .or_else(|| cert.keys().with_policy(&policy, None).for_signing().next())
        .or_else(|| cert.keys().with_policy(&policy, None).next())
        .context("No usable key in cert")?;
    let is_rsa = matches!(ka.key().mpis(), mpi::PublicKey::RSA { .. });

    // ── 3. Open card and authenticate ─────────────────────────────────────────
    let card_ident = entry.card_idents.first().unwrap();
    let mut card =
        open_card(Some(card_ident)).with_context(|| format!("Cannot open card {}", card_ident))?;
    let mut tx = card
        .transaction()
        .context("Failed to open card transaction")?;

    // Check that the auth slot is populated — surface a useful error if not.
    let auth_present = tx
        .public_key(KeyType::Authentication)
        .ok()
        .flatten()
        .is_some();
    anyhow::ensure!(
        auth_present,
        "Card {} has no key in the AUTH slot; import the card again",
        card_ident
    );

    // User PIN unlocks the AUTH slot (distinct from the Signing PIN).
    tx.verify_user_pin(pin)
        .context("Card User PIN verification failed — wrong PIN?")?;

    let mut user_card = tx
        .to_user_card(None)
        .context("Failed to enter user-card mode")?;

    let mut auth = user_card
        .authenticator(&|| eprintln!("Touch YubiKey now…"))
        .context("Failed to acquire card authenticator")?;

    // ── 4. Sign ───────────────────────────────────────────────────────────────
    let (sig_bytes, algo) = if is_rsa {
        // RSA: hash data on host, send digest to card.
        // Mirror card_auth_sign_ssh: 0x04 → SHA-512, everything else → SHA-256.
        let use_sha512 = flags & RSA_SHA2_512_FLAG != 0;
        let (openpgp_hash, ssh_hash, digest_len) = if use_sha512 {
            (
                openpgp::types::HashAlgorithm::SHA512,
                HashAlg::Sha512,
                64usize,
            )
        } else {
            (
                openpgp::types::HashAlgorithm::SHA256,
                HashAlg::Sha256,
                32usize,
            )
        };
        let mut ctx = openpgp_hash.context().context("Hash context unavailable")?;
        ctx.update(data);
        let mut digest = vec![0u8; digest_len];
        ctx.digest(&mut digest)
            .context("Failed to compute digest")?;

        let sig_mpi = auth
            .sign(openpgp_hash, &digest)
            .context("Card RSA auth-slot signing failed")?;

        let bytes = match &sig_mpi {
            mpi::Signature::RSA { s } => s.value().to_vec(),
            other => anyhow::bail!("Expected RSA signature from card, got {:?}", other),
        };
        (
            bytes,
            ssh_key::Algorithm::Rsa {
                hash: Some(ssh_hash),
            },
        )
    } else {
        // Ed25519: PureEdDSA — card hashes internally; pass raw data.
        let sig_mpi = auth
            .sign(openpgp::types::HashAlgorithm::SHA512, data)
            .context("Card Ed25519 auth-slot signing failed")?;

        let bytes = match &sig_mpi {
            mpi::Signature::EdDSA { r, s } => {
                let mut v = Vec::with_capacity(64);
                v.extend_from_slice(&r.value_padded(32).context("EdDSA r padding failed")?);
                v.extend_from_slice(&s.value_padded(32).context("EdDSA s padding failed")?);
                v
            }
            other => anyhow::bail!("Expected EdDSA signature from card, got {:?}", other),
        };
        (bytes, ssh_key::Algorithm::Ed25519)
    };

    // ── 5. Encode as SSH wire format ──────────────────────────────────────────
    let ssh_sig = Signature::new(algo.clone(), sig_bytes)
        .map_err(|e| anyhow::anyhow!("SSH signature encoding failed: {e}"))?;
    let wire: Vec<u8> = ssh_sig
        .try_into()
        .map_err(|e: ssh_key::Error| anyhow::anyhow!("SSH wire encoding failed: {e}"))?;
    Ok(B64.encode(wire))
}

/// Sign `data` using the soft key whose SSH fingerprint matches `ssh_fingerprint`.
///
/// The sign request from the CLI carries the SSH SHA-256 fingerprint, which
/// differs from the OpenPGP hex fingerprint used in the key store.  This
/// function resolves the mapping automatically.
///
/// Decrypts the `.sec.asc` file using `passphrase`, then signs `data` with
/// the auth subkey (falling back to the sign subkey).  Returns the SSH
/// wire-encoded signature as a base64 string (the format expected by
/// `SshSignResponse.signature`).
pub fn sign_with_soft_key(
    store_dir: &Path,
    ssh_fingerprint: &str,
    passphrase: &str,
    data: &[u8],
) -> Result<String> {
    let openpgp_fp = openpgp_fp_for_ssh_fp(store_dir, ssh_fingerprint)?;
    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let cert = ks.find_with_secret(&openpgp_fp, passphrase)?;

    // For RSA keys: extract the decrypted key and cache it so subsequent
    // signs skip the expensive S2K KDF entirely (same behaviour as the
    // Ed25519 keypair cache but for variable-length RSA keys).
    let policy = StandardPolicy::new();
    let ka = cert
        .keys()
        .with_policy(&policy, None)
        .for_authentication()
        .secret()
        .next()
        .or_else(|| {
            cert.keys()
                .with_policy(&policy, None)
                .for_signing()
                .secret()
                .next()
        })
        .or_else(|| cert.keys().with_policy(&policy, None).secret().next())
        .context("No usable secret key found")?;

    if matches!(ka.key().mpis(), mpi::PublicKey::RSA { .. }) {
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
        return Ok(B64.encode(wire));
    }

    sign_cert_for_ssh(&cert, data)
}

/// Unified signing function: routes Ed25519 through ssh-key and RSA through
/// the rsa crate directly (working around the ssh-key 0.6.7 RSA bug).
fn sign_cert_for_ssh(cert: &openpgp::Cert, data: &[u8]) -> Result<String> {
    let policy = StandardPolicy::new();

    // Peek at the algorithm to decide which code path to take.
    let ka = cert
        .keys()
        .with_policy(&policy, None)
        .for_authentication()
        .secret()
        .next()
        .or_else(|| {
            cert.keys()
                .with_policy(&policy, None)
                .for_signing()
                .secret()
                .next()
        })
        .or_else(|| cert.keys().with_policy(&policy, None).secret().next())
        .context("No usable secret key found")?;

    let is_rsa = matches!(ka.key().mpis(), mpi::PublicKey::RSA { .. });

    if is_rsa {
        let sig = sign_rsa_direct(cert, data)?;
        let sig_bytes: Vec<u8> = sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))?;
        Ok(B64.encode(sig_bytes))
    } else {
        let private_key = cert_to_ssh_key(cert, SshKeySlot::Auth)?;
        let sig: Signature = private_key
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;
        let sig_bytes: Vec<u8> = sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature encoding failed: {e}"))?;
        Ok(B64.encode(sig_bytes))
    }
}

/// Like [`sign_with_soft_key`] but also returns the 64-byte Ed25519 keypair so
/// the caller can cache it.  Returns `(signature_b64, Some(keypair_bytes))`
/// where `keypair_bytes` is `private[32] || public[32]` (the SSH wire layout).
///
/// Returns `None` for the keypair bytes when the key is RSA (RSA keys are too
/// large to cache in a fixed 64-byte slot; the passphrase cache is used instead).
///
/// Pass the returned bytes to [`sign_with_cached_keypair`] for zero-KDF
/// subsequent signs.
pub fn sign_with_soft_key_and_extract(
    store_dir: &Path,
    ssh_fingerprint: &str,
    passphrase: &str,
    data: &[u8],
) -> Result<(String, Option<[u8; 64]>)> {
    let openpgp_fp = openpgp_fp_for_ssh_fp(store_dir, ssh_fingerprint)?;
    let ks = crate::key_store::store::KeyStore::open(store_dir)?;
    let cert = ks.find_with_secret(&openpgp_fp, passphrase)?;

    let policy = StandardPolicy::new();
    let ka = cert
        .keys()
        .with_policy(&policy, None)
        .for_authentication()
        .secret()
        .next()
        .or_else(|| {
            cert.keys()
                .with_policy(&policy, None)
                .for_signing()
                .secret()
                .next()
        })
        .or_else(|| cert.keys().with_policy(&policy, None).secret().next())
        .context("No usable secret key found")?;

    let is_rsa = matches!(ka.key().mpis(), mpi::PublicKey::RSA { .. });

    if is_rsa {
        // RSA: extract key, cache it for zero-KDF subsequent signs, then sign.
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
        Ok((B64.encode(wire), None))
    } else {
        // Ed25519: use ssh-key, extract keypair bytes for the hot-path cache.
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
        Ok((B64.encode(sig_bytes), keypair_bytes))
    }
}

/// Sign `data` with a pre-decrypted Ed25519 keypair (64 bytes: priv || pub).
///
/// Skips the expensive passphrase KDF entirely — typically completes in
/// microseconds.  Call this on the hot path after caching the bytes from a
/// first successful [`sign_with_soft_key_and_extract`].
pub fn sign_with_cached_keypair(keypair_bytes: &[u8; 64], data: &[u8]) -> Result<String> {
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

    Ok(B64.encode(sig_bytes))
}

// ── Direct RSA signing (bypasses ssh-key 0.6.7 bug) ─────────────────────────

/// Extract the decrypted `rsa::RsaPrivateKey` from a cert that has been loaded
/// with its secret material already decrypted (via `find_with_secret`).
///
/// Sequoia convention: p < q, u = p⁻¹ mod q.
/// The rsa crate accepts primes in any order and recomputes CRT parameters.
fn extract_rsa_key(cert: &openpgp::Cert) -> Result<RsaCrateKey> {
    let policy = StandardPolicy::new();

    let ka = cert
        .keys()
        .with_policy(&policy, None)
        .for_authentication()
        .secret()
        .next()
        .or_else(|| {
            cert.keys()
                .with_policy(&policy, None)
                .for_signing()
                .secret()
                .next()
        })
        .or_else(|| cert.keys().with_policy(&policy, None).secret().next())
        .context("No usable RSA secret key found")?;

    let key = ka.key();

    let (e_val, n_val) = match key.mpis() {
        mpi::PublicKey::RSA { e, n } => (e.value().to_vec(), n.value().to_vec()),
        _ => bail!("extract_rsa_key called on non-RSA key"),
    };

    match key.optional_secret().context("No RSA secret material")? {
        SecretKeyMaterial::Unencrypted(unenc) => unenc.map(|sec| match sec {
            mpi::SecretKeyMaterial::RSA { d, p, q, .. } => RsaCrateKey::from_components(
                BigUint::from_bytes_be(&n_val),
                BigUint::from_bytes_be(&e_val),
                BigUint::from_bytes_be(d.value()),
                vec![
                    BigUint::from_bytes_be(p.value()),
                    BigUint::from_bytes_be(q.value()),
                ],
            )
            .map_err(|err| anyhow::anyhow!("RSA key construction: {err}")),
            _ => bail!("Expected RSA secret key material"),
        }),
        SecretKeyMaterial::Encrypted(_) => bail!("Key is still encrypted — wrong passphrase?"),
    }
}

/// Sign `data` with an `rsa::RsaPrivateKey` using PKCS#1 v1.5 + SHA-512.
/// Returns the raw SSH wire bytes (not base64-encoded).
fn sign_with_rsa_key(rsa_key: &RsaCrateKey, data: &[u8]) -> Result<Vec<u8>> {
    let signing_key = RsaPkcs1SigningKey::<Sha512>::new(rsa_key.clone());
    let sig: rsa::pkcs1v15::Signature = RsaSigner::try_sign(&signing_key, data)
        .map_err(|err| anyhow::anyhow!("RSA sign failed: {err}"))?;
    Ok(RsaSigEncoding::to_vec(&sig))
}

/// Sign `data` with the RSA secret key held in `cert` and cache the key for
/// subsequent zero-KDF signs.  Uses the `rsa` crate directly (ssh-key 0.6.7
/// bug: passes `[p, p]` instead of `[p, q]` in `from_components`).
fn sign_rsa_direct(cert: &openpgp::Cert, data: &[u8]) -> Result<Signature> {
    let rsa_key = extract_rsa_key(cert)?;
    let sig_bytes = sign_with_rsa_key(&rsa_key, data)?;
    Signature::new(
        ssh_key::Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        sig_bytes,
    )
    .map_err(|err| anyhow::anyhow!("SSH RSA signature encoding failed: {err}"))
}

// ── Internal conversion ───────────────────────────────────────────────────────

fn cert_to_ssh_key(cert: &openpgp::Cert, slot: SshKeySlot) -> Result<PrivateKey> {
    let policy = StandardPolicy::new();

    // Locate the requested subkey; Auth slot falls back to Sign.
    let ka = match slot {
        SshKeySlot::Auth => cert
            .keys()
            .with_policy(&policy, None)
            .for_authentication()
            .secret()
            .next()
            .or_else(|| {
                cert.keys()
                    .with_policy(&policy, None)
                    .for_signing()
                    .secret()
                    .next()
            }),
        SshKeySlot::Sign => cert
            .keys()
            .with_policy(&policy, None)
            .for_signing()
            .secret()
            .next(),
    }
    .context(
        "No suitable subkey found in cert \
         (need an authentication or signing subkey with secret material)",
    )?;

    let key = ka.key();

    match key.mpis() {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let q_bytes = q.value();
            anyhow::ensure!(
                q_bytes.len() == 33 && q_bytes[0] == 0x40,
                "Unexpected EdDSA public key encoding (expected 0x40 prefix)"
            );
            let pub_bytes: [u8; 32] = q_bytes[1..33]
                .try_into()
                .context("EdDSA public key point is not 32 bytes")?;

            let priv_bytes: [u8; 32] =
                match key.optional_secret().context("No secret material in key")? {
                    SecretKeyMaterial::Unencrypted(u) => u.map(|mpi_secret| match mpi_secret {
                        mpi::SecretKeyMaterial::EdDSA { scalar } => {
                            let raw = scalar.value_padded(32);
                            raw.as_ref()
                                .try_into()
                                .context("EdDSA scalar is not 32 bytes")
                        }
                        _ => bail!("Expected EdDSA secret key material, got a different type"),
                    }),
                    SecretKeyMaterial::Encrypted(_) => {
                        bail!("Key is still encrypted — wrong passphrase?")
                    }
                }?;

            let keypair = Ed25519Keypair {
                public: Ed25519PublicKey(pub_bytes),
                private: Ed25519PrivateKey::from_bytes(&priv_bytes),
            };

            PrivateKey::new(KeypairData::Ed25519(keypair), "p43")
                .map_err(|e| anyhow::anyhow!("Failed to build SSH PrivateKey: {e}"))
        }
        mpi::PublicKey::RSA { e, n } => {
            // OpenPGP RSA secret: p < q, u = p⁻¹ mod q.
            // SSH RSA secret:     p > q, iqmp = q⁻¹ mod p.
            // Swapping p↔q makes u equal iqmp algebraically — no big-int
            // modular inverse needed.
            match key
                .optional_secret()
                .context("No secret material in key (RSA)")?
            {
                SecretKeyMaterial::Unencrypted(unenc) => {
                    unenc.map(|sec| match sec {
                        mpi::SecretKeyMaterial::RSA { d, p, q, u } => {
                            let pub_key = RsaPublicKey {
                                e: Mpint::from_positive_bytes(e.value())
                                    .map_err(|err| anyhow::anyhow!("RSA e: {err}"))?,
                                n: Mpint::from_positive_bytes(n.value())
                                    .map_err(|err| anyhow::anyhow!("RSA n: {err}"))?,
                            };
                            let priv_key = RsaPrivateKey {
                                d: Mpint::from_positive_bytes(d.value())
                                    .map_err(|err| anyhow::anyhow!("RSA d: {err}"))?,
                                // Swapped p↔q → u is now q⁻¹ mod p = iqmp.
                                iqmp: Mpint::from_positive_bytes(u.value())
                                    .map_err(|err| anyhow::anyhow!("RSA iqmp: {err}"))?,
                                p: Mpint::from_positive_bytes(q.value())
                                    .map_err(|err| anyhow::anyhow!("RSA p: {err}"))?,
                                q: Mpint::from_positive_bytes(p.value())
                                    .map_err(|err| anyhow::anyhow!("RSA q: {err}"))?,
                            };
                            PrivateKey::new(
                                KeypairData::Rsa(RsaKeypair {
                                    public: pub_key,
                                    private: priv_key,
                                }),
                                "p43",
                            )
                            .map_err(|err| {
                                anyhow::anyhow!("Failed to build RSA SSH PrivateKey: {err}")
                            })
                        }
                        _ => bail!("Expected RSA secret key material"),
                    })
                }
                SecretKeyMaterial::Encrypted(_) => {
                    bail!("Key is still encrypted — wrong passphrase?")
                }
            }
        }
        _ => bail!("Unsupported key algorithm for SSH agent (Ed25519 and RSA are supported)"),
    }
}

// ── Card helpers ──────────────────────────────────────────────────────────────

/// SSH agent flags for RSA hash-algorithm selection
/// (OpenSSH `SSH_AGENT_RSA_SHA2_*` constants).
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
/// No PIN is required — the card serves the public key in its base
/// (transaction) state via a plain GET DATA command.
#[cfg(feature = "pcsc")]
pub fn load_card_auth_key_info() -> Result<CardKeyInfo> {
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;

    let ident = tx
        .application_identifier()
        .map(|aid| aid.ident())
        .unwrap_or_else(|_| "unknown".to_string());

    let pub_key = tx
        .public_key(KeyType::Authentication)
        .context("Failed to read authentication public key from card")?
        .context("No authentication key is loaded on this card")?;

    let is_rsa = matches!(pub_key.mpis(), mpi::PublicKey::RSA { .. });
    let pubkey = mpi_pubkey_to_ssh_keydata(pub_key.mpis())
        .context("Failed to convert card public key to SSH format")?;

    Ok(CardKeyInfo {
        pubkey,
        comment: format!("p43:yubikey:{ident}:auth"),
        is_rsa,
    })
}

/// Sign `data` using the YubiKey **authentication** slot (INTERNAL AUTHENTICATE).
///
/// For RSA keys the SSH `flags` field selects the hash algorithm:
/// `0x04` → SHA-512 (`rsa-sha2-512`), otherwise SHA-256 (`rsa-sha2-256`).
/// For Ed25519 keys `flags` is ignored — the card runs PureEdDSA internally.
#[cfg(feature = "pcsc")]
pub fn card_auth_sign_ssh(data: &[u8], pin: &str, flags: u32, is_rsa: bool) -> Result<Signature> {
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;

    // User PIN (not the signing PIN) is required for INTERNAL AUTHENTICATE.
    tx.verify_user_pin(pin)
        .context("Card user PIN verification failed")?;

    let mut user_card = tx
        .to_user_card(None)
        .context("Failed to enter user card state")?;

    let mut auth = user_card
        .authenticator(&|| eprintln!("Touch YubiKey now…"))
        .context("Failed to obtain card authenticator")?;

    if is_rsa {
        let use_sha512 = flags & RSA_SHA2_512_FLAG != 0;
        let _ = RSA_SHA2_256_FLAG; // suppress unused-constant warning
        let (openpgp_hash, ssh_hash) = if use_sha512 {
            (HashAlgorithm::SHA512, HashAlg::Sha512)
        } else {
            (HashAlgorithm::SHA256, HashAlg::Sha256)
        };
        let digest = hash_data(openpgp_hash, data)?;
        let mpi_sig = auth
            .sign(openpgp_hash, &digest)
            .context("Card RSA authentication signing failed")?;
        rsa_mpi_to_ssh_sig(mpi_sig, ssh_hash)
    } else {
        let mpi_sig = auth
            .sign(HashAlgorithm::SHA512, data)
            .context("Card Ed25519 authentication signing failed")?;
        ed25519_mpi_to_ssh_sig(mpi_sig)
    }
}

// ── Hash helper ───────────────────────────────────────────────────────────────

#[cfg(feature = "pcsc")]
fn hash_data(algo: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use openpgp::crypto::hash::Digest;
    let mut ctx = algo
        .context()
        .map_err(|e| anyhow::anyhow!("Hash context creation failed: {e}"))?;
    ctx.update(data);
    ctx.into_digest()
        .map_err(|e| anyhow::anyhow!("Hash finalization failed: {e}"))
}

// ── MPI ↔ SSH conversion helpers ─────────────────────────────────────────────

/// Convert an OpenPGP public-key MPI blob to an OpenSSH `authorized_keys`
/// line.  Returns `None` for algorithms that have no SSH equivalent
/// (e.g. ECDH encryption keys).  Used by the key-store to populate
/// per-subkey SSH representations without duplicating the conversion logic.
pub fn mpi_to_openssh_string(mpis: &mpi::PublicKey, comment: &str) -> Option<String> {
    use ssh_key::public::PublicKey;
    let key_data = mpi_pubkey_to_ssh_keydata(mpis).ok()?;
    let pub_key = PublicKey::new(key_data, comment);
    pub_key.to_openssh().ok()
}

fn mpi_pubkey_to_ssh_keydata(mpis: &mpi::PublicKey) -> Result<KeyData> {
    match mpis {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let q_bytes = q.value();
            anyhow::ensure!(
                q_bytes.len() == 33 && q_bytes[0] == 0x40,
                "Unexpected EdDSA public-key encoding (expected 0x40 prefix, got {:02x})",
                q_bytes[0]
            );
            let pub_bytes: [u8; 32] = q_bytes[1..33]
                .try_into()
                .context("EdDSA public key is not 32 bytes")?;
            Ok(KeyData::Ed25519(Ed25519PublicKey(pub_bytes)))
        }
        mpi::PublicKey::RSA { e, n } => {
            use ssh_key::public::RsaPublicKey;
            let rsa_pub = RsaPublicKey {
                e: Mpint::from_positive_bytes(e.value())
                    .map_err(|err| anyhow::anyhow!("RSA exponent conversion failed: {err}"))?,
                n: Mpint::from_positive_bytes(n.value())
                    .map_err(|err| anyhow::anyhow!("RSA modulus conversion failed: {err}"))?,
            };
            Ok(KeyData::Rsa(rsa_pub))
        }
        _ => bail!(
            "Unsupported card key algorithm for SSH agent \
             (Ed25519 and RSA are supported)"
        ),
    }
}

#[cfg(feature = "pcsc")]
fn ed25519_mpi_to_ssh_sig(sig: mpi::Signature) -> Result<Signature> {
    match sig {
        mpi::Signature::EdDSA { r, s } => {
            let r_bytes = r
                .value_padded(32)
                .context("EdDSA r scalar padding failed")?;
            let s_bytes = s
                .value_padded(32)
                .context("EdDSA s scalar padding failed")?;
            let mut raw = [0u8; 64];
            raw[..32].copy_from_slice(&r_bytes);
            raw[32..].copy_from_slice(&s_bytes);
            Signature::new(Algorithm::Ed25519, raw.to_vec())
                .map_err(|e| anyhow::anyhow!("Failed to build SSH Ed25519 signature: {e}"))
        }
        _ => bail!("Expected EdDSA signature from card for Ed25519 auth key"),
    }
}

#[cfg(feature = "pcsc")]
fn rsa_mpi_to_ssh_sig(sig: mpi::Signature, hash: HashAlg) -> Result<Signature> {
    match sig {
        mpi::Signature::RSA { s } => {
            Signature::new(Algorithm::Rsa { hash: Some(hash) }, s.value().to_vec())
                .map_err(|e| anyhow::anyhow!("Failed to build SSH RSA signature: {e}"))
        }
        _ => bail!("Expected RSA signature from card for RSA auth key"),
    }
}
