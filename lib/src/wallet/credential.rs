//! `KeyCredential` trait — uniform interface for YubiKey card keys and
//! software SSH keys, covering the operations the SSH agent needs.

use anyhow::{bail, Context, Result};

use super::entry::{KeySlot, SshKey, YubikeyRef};

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Uniform interface over [`YubikeyRef`] (card-backed) and [`SshKey`] (soft).
pub trait KeyCredential {
    /// Public key bytes for the requested slot.
    ///
    /// For `YubikeyRef`: opens the card and reads the slot.
    /// For `SshKey`: derives the public key from the stored private key;
    /// only [`KeySlot::Auth`] is meaningful.
    fn pubkey_bytes(&self, slot: KeySlot) -> Result<Vec<u8>>;

    /// Comment for `ssh-add -l` listings.
    fn comment(&self) -> &str;

    /// Sign `data` using the Auth slot.
    ///
    /// For `YubikeyRef`: opens the card, uses the stored PIN, signs via the
    /// authentication slot.
    /// For `SshKey`: in-memory sign using the stored private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
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

        // Convert to SSH agent wire format: [len][algorithm][len][sig_bytes]
        let wire: Vec<u8> = sig
            .try_into()
            .map_err(|e: ssh_key::Error| anyhow::anyhow!("Signature wire encoding failed: {e}"))?;

        Ok(wire)
    }
}

// ── YubikeyRef impl ───────────────────────────────────────────────────────────
//
// Requires the `pcsc` feature — card operations via PC/SC.
// TODO: implement once the correct rPGP + openpgp-card-rpgp serialization
// API is confirmed. The card path needs:
//   - CardSlot::init_from_card(...).public_key() → correct serialization to bytes
//   - The existing ops.rs sign path adapted for the auth slot

#[cfg(feature = "pcsc")]
impl KeyCredential for YubikeyRef {
    fn pubkey_bytes(&self, slot: KeySlot) -> Result<Vec<u8>> {
        use openpgp_card::ocard::KeyType;
        use openpgp_card_rpgp::CardSlot;

        let mut card = crate::pkcs11::card::open_card(Some(&self.card_fingerprint))?;
        let mut tx = card.transaction().context("card transaction")?;
        let no_touch: &(dyn Fn() + Send + Sync) = &|| {};

        let key_type = match slot {
            KeySlot::Auth => KeyType::Authentication,
            KeySlot::Sign => KeyType::Signing,
            KeySlot::Enc => KeyType::Decryption,
        };

        let card_slot = CardSlot::init_from_card(&mut tx, key_type, no_touch)
            .with_context(|| format!("read {:?} slot from card {}", slot, self.card_fingerprint))?;

        // Serialize the rPGP PublicKey to OpenPGP packet bytes.
        use pgp::ser::Serialize as PgpSerialize;
        let mut buf = Vec::new();
        card_slot
            .public_key()
            .to_writer(&mut buf)
            .context("serialize public key")?;
        Ok(buf)
    }

    fn comment(&self) -> &str {
        &self.label
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // TODO: use existing auth slot sign path from ops.rs, adapted for wallet.
        let _ = data;
        bail!("YubikeyRef::sign not yet implemented")
    }
}
