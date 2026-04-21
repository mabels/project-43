use anyhow::{Context, Result};
use openpgp::crypto::Password;
use openpgp::packet::{
    key::{Key4, PrimaryRole, SecretParts},
    signature::SignatureBuilder,
    UserID,
};
use openpgp::types::{HashAlgorithm, KeyFlags, SignatureType};
use openpgp::Packet;
use sequoia_openpgp as openpgp;
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use std::time::SystemTime;

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

    let creation_time = SystemTime::now();

    // ── 4. Build primary key from SSH key material ────────────────────────────

    let primary_unenc: openpgp::packet::Key<SecretParts, PrimaryRole> = match ssh_key.key_data() {
        KeypairData::Ed25519(kp) => {
            // to_bytes() = secret_seed[32] || public[32].  Sequoia only
            // needs the 32-byte seed.
            let bytes = kp.to_bytes();
            Key4::import_secret_ed25519(&bytes[..32], Some(creation_time))
                .context("Failed to import Ed25519 key material")?
                .into()
        }
        KeypairData::Rsa(rsa) => {
            // sequoia's import_secret_rsa(d, p, q, t) derives n = p·q
            // and u = p⁻¹ mod q internally — no need to pass e, n, or u.
            Key4::import_secret_rsa(
                rsa.private.d.as_bytes(),
                rsa.private.p.as_bytes(),
                rsa.private.q.as_bytes(),
                Some(creation_time),
            )
            .context("Failed to import RSA key material")?
            .into()
        }
        other => anyhow::bail!("Unsupported SSH key type for import: {:?}", other),
    };

    // ── 5. Self-sign the UID ──────────────────────────────────────────────────

    // Build bare cert from the public part so uid.bind() can reference it.
    let bare = openpgp::Cert::from_packets(std::iter::once(Packet::from(
        primary_unenc.clone().parts_into_public(),
    )))
    .context("Failed to create bare cert")?;

    let uid = UserID::from(uid_str.as_bytes());

    let mut pair = primary_unenc
        .clone()
        .into_keypair()
        .context("Failed to create keypair from imported key")?;

    let sig_builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_signing()
                .set_authentication(),
        )
        .context("set_key_flags failed")?
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
        .context("set_preferred_hash_algorithms failed")?;

    let binding_sig = uid
        .bind(&mut pair, &bare, sig_builder)
        .context("Failed to create UID binding signature")?;

    // ── 6. Optionally encrypt secret material ────────────────────────────────

    let primary_final: openpgp::packet::Key<SecretParts, PrimaryRole> =
        if let Some(pw) = openpgp_passphrase {
            primary_unenc
                .encrypt_secret(&Password::from(pw))
                .context("Failed to encrypt key with passphrase")?
        } else {
            primary_unenc
        };

    // ── 7. Assemble and save ──────────────────────────────────────────────────

    let cert = openpgp::Cert::from_packets(
        [
            Packet::from(primary_final),
            Packet::from(uid),
            Packet::from(binding_sig),
        ]
        .into_iter(),
    )
    .context("Failed to assemble cert")?;

    let fp = cert.fingerprint().to_hex();
    ks.save(&cert, None)
        .context("Failed to save imported cert")?;

    println!("Imported SSH key {} as {}", ssh_key.algorithm(), fp);
    println!("  UID: {}", uid_str);

    Ok(fp)
}

/// Import an armored OpenPGP private key (TSK — Transferable Secret Key) into
/// the key store.
///
/// The armored text is saved as-is.  The passphrase (if any) is not required
/// at import time; it will be prompted when signing.
///
/// Returns the hex fingerprint of the imported cert.
pub fn import_openpgp_private_key(ks: &KeyStore, armored: &[u8]) -> Result<String> {
    let cert = ks
        .import(armored)
        .context("Failed to parse or save OpenPGP key")?;
    Ok(cert.fingerprint().to_hex())
}
