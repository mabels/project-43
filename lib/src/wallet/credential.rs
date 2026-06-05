//! Credential traits — uniform interfaces over soft keys and YubiKey cards.
//!
//! - [`KeyCredential`]: SSH agent operations (auth slot sign, pubkey).
//! - [`PgpCredential`]: OpenPGP operations (sign, decrypt, sign-encrypt).
//!
//! [`YubikeyRef`] implements both — the same card_id + PIN covers all slots.

use anyhow::{bail, Context, Result};

use super::entry::{FilePgpKey, KeySlot, SshKey, YubikeyRef};

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Uniform interface over [`YubikeyRef`] (card-backed) and [`SshKey`] (soft).
///
/// Both `pubkey_bytes` and `pubkey_openssh_string` return **SSH wire-format**
/// data for the Auth slot so callers can treat the two key types uniformly.
pub trait KeyCredential {
    /// SSH wire-format public key bytes for the Auth slot.
    ///
    /// For `SshKey`  : derived from the stored private key.
    /// For `YubikeyRef`: read live from the connected card (Auth slot only;
    ///   non-Auth slots bail — they are OpenPGP-specific).
    fn pubkey_bytes(&self, slot: KeySlot) -> Result<Vec<u8>>;

    /// OpenSSH `authorized_keys` line — derived from `pubkey_bytes`.
    ///
    /// Default implementation: deserialise the SSH wire bytes and call
    /// `PublicKey::to_openssh()`.  Overriding is only needed if the wire
    /// bytes are not straightforwardly parseable.
    fn pubkey_openssh_string(&self, slot: KeySlot) -> Result<String> {
        let raw = self.pubkey_bytes(slot)?;
        let pk = ssh_key::PublicKey::from_bytes(&raw).context("deserialize SSH public key")?;
        pk.to_openssh()
            .map_err(|e| anyhow::anyhow!("OpenSSH encode: {e}"))
    }

    /// Comment for `ssh-add -l` listings.
    fn comment(&self) -> &str;

    /// Sign `data` using the Auth slot and return SSH agent wire-format bytes.
    ///
    /// For `SshKey`   : in-memory sign using the stored private key.
    /// For `YubikeyRef`: opens the card, verifies the stored PIN, and signs
    ///   via the authentication slot.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Same as `sign` but carries the SSH agent `flags` field so RSA key
    /// variants (SHA-256 vs SHA-512) can be selected.  For Ed25519 keys
    /// (the common case) flags are ignored.
    ///
    /// Default: ignores flags and calls `sign`.
    fn sign_with_flags(&self, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        self.sign(data)
    }
}

// ── SshKey impl ───────────────────────────────────────────────────────────────

impl KeyCredential for SshKey {
    fn pubkey_bytes(&self, slot: KeySlot) -> Result<Vec<u8>> {
        match slot {
            KeySlot::Auth => {
                let sk = ssh_key::PrivateKey::from_openssh(&self.private_key)
                    .context("parse SSH private key")?;
                sk.public_key()
                    .to_bytes()
                    .context("serialize SSH public key")
            }
            KeySlot::Sign | KeySlot::Enc => {
                bail!("SshKey has no {:?} slot — only Auth is available", slot)
            }
        }
    }

    fn comment(&self) -> &str {
        &self.comment
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer as _;
        use ssh_key::Signature;

        let sk = ssh_key::PrivateKey::from_openssh(&self.private_key)
            .context("parse SSH private key for signing")?;

        let sig: Signature = sk
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("SSH sign failed: {e}"))?;

        let wire: Vec<u8> = sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature wire encoding failed: {e}"))?;
        Ok(wire)
    }
}

// ── YubikeyRef impl ───────────────────────────────────────────────────────────
//
// Requires the `pcsc` feature — card operations via PC/SC.

#[cfg(feature = "pcsc")]
impl KeyCredential for YubikeyRef {
    fn pubkey_bytes(&self, slot: KeySlot) -> Result<Vec<u8>> {
        use openpgp_card::ocard::KeyType;
        use openpgp_card_rpgp::CardSlot;
        use pgp::types::KeyDetails as _;

        // Only the Auth slot makes sense in SSH wire format.
        anyhow::ensure!(
            slot == KeySlot::Auth,
            "YubikeyRef::pubkey_bytes only supports the Auth slot for SSH; \
             use a PGP path for Sign/Enc"
        );

        let mut card = crate::pkcs11::card::open_card(Some(&self.card_fingerprint))?;
        let mut tx = card.transaction().context("card transaction")?;
        let no_touch: &(dyn Fn() + Send + Sync) = &|| {};

        let card_slot = CardSlot::init_from_card(&mut tx, KeyType::Authentication, no_touch)
            .with_context(|| format!("read Auth slot from card {}", self.card_fingerprint))?;

        // Convert card public params → SSH wire bytes (consistent with SshKey).
        let pub_params = card_slot.public_key().public_params();
        let key_data = crate::ssh_agent::pub_params_to_ssh_keydata(pub_params)?;
        ssh_key::PublicKey::new(key_data, &self.label)
            .to_bytes()
            .context("serialize card auth-slot public key as SSH wire bytes")
    }

    fn comment(&self) -> &str {
        &self.label
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_with_flags(data, 0)
    }

    fn sign_with_flags(&self, data: &[u8], flags: u32) -> Result<Vec<u8>> {
        crate::ssh_agent::sign_with_card_ident(&self.card_fingerprint, &self.pin, data, flags)
    }
}

// ── PgpCredential trait ───────────────────────────────────────────────────────

/// Uniform OpenPGP interface over [`FilePgpKey`] (soft) and [`YubikeyRef`] (card).
///
/// Both use the same call surface; the impl picks the right underlying path.
/// Recipients / signers are passed as armored public-key bytes so callers
/// never touch the filesystem.
pub trait PgpCredential {
    /// Armored OpenPGP public key — distribute to senders / recipients.
    fn pgp_pubkey_armored(&self) -> Result<String>;

    /// Create an armored detached signature over `data` (sign slot).
    fn pgp_sign(&self, data: &[u8]) -> Result<String>;

    /// Decrypt an armored OpenPGP message (enc slot).
    fn pgp_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Sign-then-encrypt `data` for a recipient given their armored public key.
    fn pgp_sign_encrypt(&self, data: &[u8], recipient_armored: &[u8]) -> Result<String>;

    /// Decrypt a signed+encrypted message and verify the embedded signature.
    fn pgp_decrypt_verify(&self, ciphertext: &[u8], signer_armored: &[u8]) -> Result<Vec<u8>>;
}

// ── FilePgpKey impl ───────────────────────────────────────────────────────────

impl PgpCredential for FilePgpKey {
    fn pgp_pubkey_armored(&self) -> Result<String> {
        let key = crate::pgp_ops::load_secret_cert_from_bytes(&self.key_bytes)?;
        crate::pgp_ops::pubkey_armored(&key)
    }

    fn pgp_sign(&self, data: &[u8]) -> Result<String> {
        let key = crate::pgp_ops::load_secret_cert_from_bytes(&self.key_bytes)?;
        crate::pgp_ops::sign_with_key(&key, &self.passphrase, data)
    }

    fn pgp_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = crate::pgp_ops::load_secret_cert_from_bytes(&self.key_bytes)?;
        crate::pgp_ops::decrypt_with_key(&key, &self.passphrase, ciphertext)
    }

    fn pgp_sign_encrypt(&self, data: &[u8], recipient_armored: &[u8]) -> Result<String> {
        let key = crate::pgp_ops::load_secret_cert_from_bytes(&self.key_bytes)?;
        crate::pgp_ops::sign_encrypt_with_key(&key, &self.passphrase, data, recipient_armored)
    }

    fn pgp_decrypt_verify(&self, ciphertext: &[u8], signer_armored: &[u8]) -> Result<Vec<u8>> {
        let key = crate::pgp_ops::load_secret_cert_from_bytes(&self.key_bytes)?;
        crate::pgp_ops::decrypt_verify_with_key(&key, &self.passphrase, ciphertext, signer_armored)
    }
}

// ── YubikeyRef PgpCredential impl ─────────────────────────────────────────────
//
// Requires the `pcsc` feature.

#[cfg(feature = "pcsc")]
impl PgpCredential for YubikeyRef {
    fn pgp_pubkey_armored(&self) -> Result<String> {
        // Read the sign-slot public key from the card and export it as a
        // minimal armored public cert.
        use openpgp_card::ocard::KeyType;
        use openpgp_card_rpgp::CardSlot;
        use pgp::types::KeyDetails as _;

        let mut card = crate::pkcs11::card::open_card(Some(&self.card_fingerprint))?;
        let mut tx = card.transaction().context("card transaction")?;
        let no_touch: &(dyn Fn() + Send + Sync) = &|| {};
        let slot = CardSlot::init_from_card(&mut tx, KeyType::Signing, no_touch)
            .context("init signing slot for pubkey")?;
        let pub_params = slot.public_key().public_params();
        // Convert to an armored SSH-style pubkey string as a best-effort
        // representation; full OpenPGP armoring requires the whole cert.
        crate::ssh_agent::pub_params_to_openssh_string(pub_params, &self.label)
            .ok_or_else(|| anyhow::anyhow!("unsupported key algorithm for OpenPGP pubkey export"))
    }

    fn pgp_sign(&self, data: &[u8]) -> Result<String> {
        crate::pkcs11::ops::sign_with_ident(data, &self.pin, Some(&self.card_fingerprint))
    }

    fn pgp_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        crate::pkcs11::ops::decrypt_with_card(ciphertext, &self.pin, Some(&self.card_fingerprint))
    }

    fn pgp_sign_encrypt(&self, data: &[u8], recipient_armored: &[u8]) -> Result<String> {
        crate::pkcs11::ops::sign_encrypt_with_recipient_bytes(
            data,
            recipient_armored,
            &self.pin,
            Some(&self.card_fingerprint),
        )
    }

    fn pgp_decrypt_verify(&self, ciphertext: &[u8], signer_armored: &[u8]) -> Result<Vec<u8>> {
        crate::pkcs11::ops::decrypt_verify_with_signer_bytes(
            ciphertext,
            signer_armored,
            &self.pin,
            Some(&self.card_fingerprint),
        )
    }
}
