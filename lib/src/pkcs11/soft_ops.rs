use anyhow::{Context, Result};
use openpgp::armor::{Kind as ArmorKind, Writer as ArmorWriter};
use openpgp::crypto::{Password, SessionKey};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{
    packet::{PKESK, SKESK},
    Cert, Fingerprint, KeyHandle,
};
use sequoia_openpgp as openpgp;
use std::io::{self, Write};
use std::path::Path;

use crate::pkcs11::ops::load_cert;

fn decrypt_all_secrets(cert: Cert, passphrase: &str) -> Result<Cert> {
    let pw: Password = passphrase.into();
    let mut packets: Vec<openpgp::Packet> = Vec::new();
    let primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .context("Primary key has no secret material")?;
    packets.push(
        primary
            .decrypt_secret(&pw)
            .context("Failed to decrypt primary key")?
            .into(),
    );
    for ka in cert.keys().subkeys().secret() {
        let key = ka
            .key()
            .clone()
            .parts_into_secret()
            .context("Subkey has no secret material")?;
        packets.push(
            key.decrypt_secret(&pw)
                .context("Failed to decrypt subkey")?
                .into(),
        );
    }
    cert.insert_packets(packets)
        .context("Failed to rebuild cert with decrypted secrets")
}

pub fn load_secret_cert(key_file: &Path, passphrase: &str) -> Result<Cert> {
    let cert = load_cert(key_file)?;
    if passphrase.is_empty() {
        Ok(cert)
    } else {
        decrypt_all_secrets(cert, passphrase)
    }
}

// ── SoftDecryptHelper ─────────────────────────────────────────────────────────

struct SoftDecryptHelper {
    cert: Cert,
}

impl VerificationHelper for SoftDecryptHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![])
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for SoftDecryptHelper {
    fn decrypt<F>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt_fn: F,
    ) -> openpgp::Result<Option<Fingerprint>>
    where
        F: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let policy = &StandardPolicy::new();
        for pkesk in pkesks {
            for ka in self
                .cert
                .keys()
                .with_policy(policy, None)
                .for_transport_encryption()
                .secret()
            {
                let mut keypair = ka.key().clone().into_keypair()?;
                if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt_fn(algo, &sk) {
                        return Ok(Some(ka.fingerprint()));
                    }
                }
            }
        }
        Err(anyhow::anyhow!("No key could decrypt the session key"))
    }
}

// ── VerifyDecryptHelper ───────────────────────────────────────────────────────

struct VerifyDecryptHelper {
    decrypt_cert: Cert,
    verify_cert: Cert,
}

impl VerificationHelper for VerifyDecryptHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.verify_cert.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    if result.is_ok() {
                        return Ok(());
                    }
                }
                return Err(anyhow::anyhow!("No valid signature found"));
            }
        }
        Err(anyhow::anyhow!("No signature layer in message"))
    }
}

impl DecryptionHelper for VerifyDecryptHelper {
    fn decrypt<F>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt_fn: F,
    ) -> openpgp::Result<Option<Fingerprint>>
    where
        F: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let policy = &StandardPolicy::new();
        for pkesk in pkesks {
            for ka in self
                .decrypt_cert
                .keys()
                .with_policy(policy, None)
                .for_transport_encryption()
                .secret()
            {
                let mut keypair = ka.key().clone().into_keypair()?;
                if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt_fn(algo, &sk) {
                        return Ok(Some(ka.fingerprint()));
                    }
                }
            }
        }
        Err(anyhow::anyhow!("No key could decrypt the session key"))
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn sign(data: &[u8], key_file: &Path, passphrase: &str) -> Result<String> {
    let policy = &StandardPolicy::new();
    let cert = load_secret_cert(key_file, passphrase)?;
    let keypair = cert
        .keys()
        .with_policy(policy, None)
        .for_signing()
        .secret()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing subkey found in cert"))?
        .key()
        .clone()
        .into_keypair()?;
    let mut output = Vec::new();
    {
        let mut armor = ArmorWriter::new(&mut output, ArmorKind::Signature)?;
        let message = Message::new(&mut armor);
        let mut signer = Signer::new(message, keypair)
            .detached()
            .build()
            .context("Failed to build signer")?;
        signer.write_all(data)?;
        signer.finalize()?;
        armor.finalize()?;
    }
    Ok(String::from_utf8(output)?)
}

pub fn decrypt(data: &[u8], key_file: &Path, passphrase: &str) -> Result<Vec<u8>> {
    let policy = &StandardPolicy::new();
    let helper = SoftDecryptHelper {
        cert: load_secret_cert(key_file, passphrase)?,
    };
    let mut output = Vec::new();
    let mut decryptor = DecryptorBuilder::from_reader(io::BufReader::new(data))?
        .with_policy(policy, None, helper)
        .context("Decryption failed")?;
    io::copy(&mut decryptor, &mut output)?;
    Ok(output)
}

pub fn sign_encrypt(
    data: &[u8],
    key_file: &Path,
    recipient_path: &Path,
    passphrase: &str,
) -> Result<String> {
    let policy = &StandardPolicy::new();
    let cert = load_secret_cert(key_file, passphrase)?;
    let recipient_cert = load_cert(recipient_path)?;
    let recipient_keys: Vec<_> = recipient_cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();
    anyhow::ensure!(
        !recipient_keys.is_empty(),
        "No valid encryption key found in recipient cert"
    );
    let keypair = cert
        .keys()
        .with_policy(policy, None)
        .for_signing()
        .secret()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing subkey found in cert"))?
        .key()
        .clone()
        .into_keypair()?;
    let mut output = Vec::new();
    {
        let mut armor = ArmorWriter::new(&mut output, ArmorKind::Message)?;
        let message = Message::new(&mut armor);
        let message = Encryptor2::for_recipients(message, recipient_keys)
            .build()
            .context("Failed to build encryptor")?;
        let signed = Signer::new(message, keypair)
            .build()
            .context("Failed to build signer")?;
        let mut literal = LiteralWriter::new(signed).build()?;
        literal.write_all(data)?;
        literal.finalize()?;
        armor.finalize()?;
    }
    Ok(String::from_utf8(output)?)
}

pub fn decrypt_verify(
    data: &[u8],
    key_file: &Path,
    signer_path: &Path,
    passphrase: &str,
) -> Result<Vec<u8>> {
    let policy = &StandardPolicy::new();
    let helper = VerifyDecryptHelper {
        decrypt_cert: load_secret_cert(key_file, passphrase)?,
        verify_cert: load_cert(signer_path)?,
    };
    let mut output = Vec::new();
    let mut decryptor = DecryptorBuilder::from_reader(io::BufReader::new(data))?
        .with_policy(policy, None, helper)
        .context("Decryption/verification failed")?;
    io::copy(&mut decryptor, &mut output)?;
    Ok(output)
}
