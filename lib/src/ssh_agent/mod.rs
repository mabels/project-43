use anyhow::{bail, Context, Result};
use openpgp::crypto::mpi;
use openpgp::crypto::Signer as _;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::policy::StandardPolicy;
use openpgp::types::{Curve, HashAlgorithm};
use openpgp_card_sequoia::types::KeyType;
use sequoia_openpgp as openpgp;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, HashAlg, Mpint, PrivateKey, Signature};
use std::path::Path;

use crate::pkcs11::card::open_first_card;
use crate::pkcs11::soft_ops::load_secret_cert;

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
pub fn load_ssh_key(key_file: &Path, passphrase: &str, slot: SshKeySlot) -> Result<PrivateKey> {
    let cert = load_secret_cert(key_file, passphrase)?;
    cert_to_ssh_key(&cert, slot)
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
        _ => bail!(
            "Unsupported key algorithm for SSH agent \
             (only Ed25519 is currently supported; RSA support is planned)"
        ),
    }
}

// ── Card helpers ──────────────────────────────────────────────────────────────

/// SSH agent flags for RSA hash-algorithm selection
/// (OpenSSH `SSH_AGENT_RSA_SHA2_*` constants).
const RSA_SHA2_256_FLAG: u32 = 0x02;
const RSA_SHA2_512_FLAG: u32 = 0x04;

/// Info returned when reading the YubiKey authentication key at startup.
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
        // RSA: pre-hash the SSH data on the host; the card receives a
        // DigestInfo blob and returns the raw PKCS#1 v1.5 signature.
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
        // Ed25519: pass the raw SSH blob; the card hashes internally.
        let mpi_sig = auth
            .sign(HashAlgorithm::SHA512, data)
            .context("Card Ed25519 authentication signing failed")?;
        ed25519_mpi_to_ssh_sig(mpi_sig)
    }
}

// ── Hash helper ───────────────────────────────────────────────────────────────

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
            // `from_positive_bytes` strips leading zeros and adds a leading
            // 0x00 when the MSB is set, matching the SSH Mpint wire format.
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

fn rsa_mpi_to_ssh_sig(sig: mpi::Signature, hash: HashAlg) -> Result<Signature> {
    match sig {
        mpi::Signature::RSA { s } => {
            Signature::new(Algorithm::Rsa { hash: Some(hash) }, s.value().to_vec())
                .map_err(|e| anyhow::anyhow!("Failed to build SSH RSA signature: {e}"))
        }
        _ => bail!("Expected RSA signature from card for RSA auth key"),
    }
}
