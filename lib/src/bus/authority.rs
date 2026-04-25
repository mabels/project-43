//! Bus authority key: generate, seal, unseal.
//!
//! The authority holds an **Ed25519** keypair (for cert signing + message
//! signing) and an **X25519** keypair (for ECDH decryption of bus messages
//! sent to the phone/UI).  Both private scalars are stored together in a
//! single OpenPGP-encrypted CBOR blob so there is exactly **one** secret to
//! protect.
//!
//! The encrypted blob can be sealed to **multiple** OpenPGP recipients so
//! that e.g. a work YubiKey and a backup YubiKey can both unlock it.
//!
//! ## Files on disk
//!
//! | File                    | Content                                         |
//! |-------------------------|-------------------------------------------------|
//! | `authority.pub.cbor`    | CBOR [`AuthorityPub`] — Ed25519 + X25519 pubkeys|
//! | `authority.key.enc`     | OpenPGP-encrypted CBOR [`AuthoritySecret`]      |
//! | `authority.cert.cbor`   | Self-issued [`DeviceCert`] for the authority    |
//!
//! **Format note:** `authority.key.enc` is now an armored PGP message
//! (ASCII-armored, `-----BEGIN PGP MESSAGE-----`).  Files created with the
//! old sequoia-based `p43` are in raw binary format and must be re-sealed.

use anyhow::{Context, Result};
use pgp::composed::{ArmorOptions, Deserializable, MessageBuilder, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::io::{self, BufReader};
use std::path::Path;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

// ── Public key bundle (distribute freely) ─────────────────────────────────────

/// The authority's two public keys.  Stored as `authority.pub.cbor`.
/// Distributed to devices so they can verify certs and encrypt to the phone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityPub {
    pub version: u8,
    /// 32-byte Ed25519 public key — verifies device certs and signed messages.
    pub ed25519_pub: Vec<u8>,
    /// 32-byte X25519 public key — ECDH target for messages sent to the phone.
    pub x25519_pub: Vec<u8>,
}

impl AuthorityPub {
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).context("CBOR encode AuthorityPub")?;
        std::fs::write(path, &buf)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let buf = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_cbor_bytes(&buf)
    }

    /// Decode from raw CBOR bytes (e.g. received over the bus in a `BusCertResponse`).
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let pub_key: Self = ciborium::from_reader(bytes).context("CBOR decode AuthorityPub")?;
        Ok(pub_key)
    }

    /// Encode to raw CBOR bytes (e.g. for embedding in a `BusCertResponse`).
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).context("CBOR encode AuthorityPub")?;
        Ok(buf)
    }

    /// Ed25519 pubkey as a fixed-size array.
    pub fn ed25519_pub_array(&self) -> Result<[u8; 32]> {
        self.ed25519_pub[..]
            .try_into()
            .context("authority ed25519_pub must be 32 bytes")
    }

    /// X25519 pubkey as a fixed-size array.
    pub fn x25519_pub_array(&self) -> Result<[u8; 32]> {
        self.x25519_pub[..]
            .try_into()
            .context("authority x25519_pub must be 32 bytes")
    }

    /// First 8 bytes of the Ed25519 pubkey — stable authority fingerprint.
    pub fn fingerprint(&self) -> [u8; 8] {
        self.ed25519_pub[..8].try_into().unwrap()
    }
}

// ── Unlocked authority (both private scalars in memory) ───────────────────────

/// The authority's private keys, held in memory after unlocking.
/// Never written to disk in plaintext.
pub struct AuthorityKey {
    pub signing: ed25519_dalek::SigningKey,
    pub ecdh: StaticSecret,
}

impl AuthorityKey {
    /// Public key bundle derived from this key (no secrets).
    pub fn authority_pub(&self) -> AuthorityPub {
        AuthorityPub {
            version: 1,
            ed25519_pub: self.signing.verifying_key().to_bytes().to_vec(),
            x25519_pub: X25519Public::from(&self.ecdh).to_bytes().to_vec(),
        }
    }

    /// X25519 Diffie-Hellman with a peer's ephemeral public key.
    pub fn ecdh_exchange(&self, peer_pub: &[u8; 32]) -> [u8; 32] {
        let peer = X25519Public::from(*peer_pub);
        self.ecdh.diffie_hellman(&peer).to_bytes()
    }
}

// ── Wire format for the encrypted blob ───────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct AuthoritySecret {
    version: u8,
    ed25519_scalar: Vec<u8>,
    x25519_scalar: Vec<u8>,
}

// ── Generate ──────────────────────────────────────────────────────────────────

/// Generate a fresh authority keypair and encrypt both private scalars to one
/// or more OpenPGP recipient certs.
///
/// Returns `(AuthorityKey, AuthorityPub, encrypted_blob)`.
pub fn generate_and_encrypt(
    recipient_paths: &[&Path],
) -> Result<(AuthorityKey, AuthorityPub, Vec<u8>)> {
    use rand::rngs::OsRng;
    let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let ecdh = StaticSecret::random_from_rng(OsRng);

    let secret = AuthoritySecret {
        version: 1,
        ed25519_scalar: signing.to_bytes().to_vec(),
        x25519_scalar: ecdh.to_bytes().to_vec(),
    };
    let mut plain = Vec::new();
    ciborium::into_writer(&secret, &mut plain).context("CBOR encode authority secret")?;

    let encrypted = seal_to_certs(&plain, recipient_paths)?;
    let key = AuthorityKey { signing, ecdh };
    let pub_key = key.authority_pub();
    Ok((key, pub_key, encrypted))
}

/// Re-seal an existing authority key to a new set of recipients.
pub fn reseal(unlocked: &AuthorityKey, recipient_paths: &[&Path]) -> Result<Vec<u8>> {
    let secret = AuthoritySecret {
        version: 1,
        ed25519_scalar: unlocked.signing.to_bytes().to_vec(),
        x25519_scalar: unlocked.ecdh.to_bytes().to_vec(),
    };
    let mut plain = Vec::new();
    ciborium::into_writer(&secret, &mut plain).context("CBOR encode authority secret")?;
    seal_to_certs(&plain, recipient_paths)
}

// ── Unlock ────────────────────────────────────────────────────────────────────

/// Decrypt an authority key blob using a **soft** OpenPGP key.
pub fn unlock_soft(encrypted: &[u8], key_file: &Path, passphrase: &str) -> Result<AuthorityKey> {
    let plain = crate::pkcs11::soft_ops::decrypt(encrypted, key_file, passphrase)
        .context("decrypt authority key blob with soft key")?;
    parse_secret(plain)
}

/// Decrypt an authority key blob using a connected **OpenPGP card**.
#[cfg(feature = "pcsc")]
pub fn unlock_card(encrypted: &[u8], pin: &str, ident: Option<&str>) -> Result<AuthorityKey> {
    let plain = crate::pkcs11::ops::decrypt_with_card(encrypted, pin, ident)
        .context("decrypt authority key blob with card")?;
    parse_secret(plain)
}

// ── Import validation helpers ─────────────────────────────────────────────────

/// Check which keys in `store` can decrypt `key_enc`.
///
/// Parses the PKESK headers from the encrypted blob and checks each key entry
/// in the store.  Returns the UIDs of all matching keys.
pub fn check_importable(
    key_enc: &[u8],
    store: &crate::key_store::store::KeyStore,
) -> Result<Vec<String>> {
    use pgp::composed::{Esk, Message};

    let msg = parse_pgp_message(key_enc).context("parse OpenPGP message from key_enc")?;

    // Collect PKESK packets.
    let pkesk_list: Vec<_> = match &msg {
        Message::Encrypted { esk, .. } => esk
            .iter()
            .filter_map(|e| {
                if let Esk::PublicKeyEncryptedSessionKey(p) = e {
                    Some(p)
                } else {
                    None
                }
            })
            .collect(),
        _ => vec![],
    };

    anyhow::ensure!(
        !pkesk_list.is_empty(),
        "no PKESK packets found — this does not look like an encrypted authority bundle"
    );

    let entries = store.list()?;
    let mut matching = Vec::new();

    for entry in &entries {
        let cert = match store.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Check if any encryption subkey in this cert matches a PKESK recipient.
        let is_match = cert
            .public_subkeys
            .iter()
            .filter(|sk| {
                sk.signatures
                    .iter()
                    .any(|sig| sig.key_flags().encrypt_comms())
            })
            .any(|sk| pkesk_list.iter().any(|pkesk| pkesk.match_identity(sk)));
        if is_match {
            matching.push(entry.uid.clone());
        }
    }

    anyhow::ensure!(
        !matching.is_empty(),
        "none of your imported keys can unlock this bundle — \
         import the correct key first, or use a different device"
    );

    Ok(matching)
}

/// One key's sealing status — returned by [`key_seal_status`].
pub struct KeySealStatus {
    pub fingerprint: String,
    pub uid: String,
    pub is_sealed: bool,
    /// `true` when this key lives on an OpenPGP card (needs a PIN to unlock),
    /// `false` for soft keys (needs a passphrase).
    pub has_card: bool,
}

/// Return the sealing status of every keystore key against `authority.key.enc`
/// at `enc_path`.
///
/// Returns an empty `Vec` when no authority exists yet.
pub fn key_seal_status(
    enc_path: &std::path::Path,
    store: &crate::key_store::store::KeyStore,
) -> Result<Vec<KeySealStatus>> {
    use pgp::composed::{Esk, Message};

    if !enc_path.exists() {
        return Ok(vec![]);
    }

    let key_enc = std::fs::read(enc_path).context("read authority.key.enc")?;

    let msg = parse_pgp_message(&key_enc).context("parse authority.key.enc")?;

    let pkesk_list: Vec<_> = match &msg {
        Message::Encrypted { esk, .. } => esk
            .iter()
            .filter_map(|e| {
                if let Esk::PublicKeyEncryptedSessionKey(p) = e {
                    Some(p)
                } else {
                    None
                }
            })
            .collect(),
        _ => vec![],
    };

    let entries = store.list()?;
    let mut result = Vec::new();

    for entry in &entries {
        let cert = match store.find(&entry.fingerprint) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let is_sealed = cert
            .public_subkeys
            .iter()
            .filter(|sk| {
                sk.signatures
                    .iter()
                    .any(|sig| sig.key_flags().encrypt_comms())
            })
            .any(|sk| pkesk_list.iter().any(|pkesk| pkesk.match_identity(sk)));
        result.push(KeySealStatus {
            fingerprint: entry.fingerprint.clone(),
            uid: entry.uid.clone(),
            is_sealed,
            has_card: !entry.card_idents.is_empty(),
        });
    }

    Ok(result)
}

// ── Internals ─────────────────────────────────────────────────────────────────

/// Parse an OpenPGP `Message` from `bytes`, accepting both ASCII-armored
/// (new rPGP format) and raw binary (old sequoia format) encodings.
fn parse_pgp_message(bytes: &[u8]) -> Result<pgp::composed::Message<'_>> {
    use pgp::composed::Message;

    // Try ASCII armor first (new format written by rPGP).
    if let Ok((msg, _)) = Message::from_armor(BufReader::new(io::Cursor::new(bytes))) {
        return Ok(msg);
    }

    // Fall back to raw binary (OpenPGP packet stream written by sequoia).
    Message::from_bytes(bytes).context(
        "authority.key.enc is neither valid ASCII-armored PGP nor a raw binary PGP message; \
         the file may be corrupted — run `p43 authority reseal` to recreate it",
    )
}

fn parse_secret(plain: Vec<u8>) -> Result<AuthorityKey> {
    // Support both the old format (raw 32-byte Ed25519 scalar) and the new
    // CBOR format so existing `authority.key.enc` files keep working.
    if plain.len() == 32 {
        let arr: [u8; 32] = plain.try_into().unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&arr);
        let ecdh = StaticSecret::from(signing.to_bytes());
        return Ok(AuthorityKey { signing, ecdh });
    }

    let secret: AuthoritySecret =
        ciborium::from_reader(plain.as_slice()).context("CBOR decode authority secret")?;
    anyhow::ensure!(
        secret.version == 1,
        "unsupported authority secret version {}",
        secret.version
    );

    let ed_arr: [u8; 32] = secret.ed25519_scalar[..]
        .try_into()
        .context("ed25519_scalar must be 32 bytes")?;
    let x_arr: [u8; 32] = secret.x25519_scalar[..]
        .try_into()
        .context("x25519_scalar must be 32 bytes")?;

    Ok(AuthorityKey {
        signing: ed25519_dalek::SigningKey::from_bytes(&ed_arr),
        ecdh: StaticSecret::from(x_arr),
    })
}

/// OpenPGP-encrypt `plaintext` to the encryption subkeys of all certs at
/// `cert_paths`.  Produces an ASCII-armored PGP message.
fn seal_to_certs(plaintext: &[u8], cert_paths: &[&Path]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !cert_paths.is_empty(),
        "at least one recipient cert required"
    );

    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);

    for path in cert_paths {
        let f = std::fs::File::open(path)
            .with_context(|| format!("load recipient cert from {}", path.display()))?;
        let (cert, _) = SignedPublicKey::from_armor_single(BufReader::new(f))
            .with_context(|| format!("parse cert from {}", path.display()))?;

        let enc_subkey = cert
            .public_subkeys
            .iter()
            .find(|sk| {
                sk.signatures
                    .iter()
                    .any(|sig| sig.key_flags().encrypt_comms())
            })
            .with_context(|| format!("no encryption subkey found in cert at {}", path.display()))?;

        builder
            .encrypt_to_key(thread_rng(), enc_subkey)
            .map_err(|e| anyhow::anyhow!("Encryption failed for {}: {e}", path.display()))?;
    }

    // Produce ASCII-armored output.  Both soft_ops::decrypt and
    // ops::decrypt_with_card use Message::from_armor to parse the blob.
    let armored = builder
        .to_armored_string(thread_rng(), ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Failed to build encrypted message: {e}"))?;
    Ok(armored.into_bytes())
}
