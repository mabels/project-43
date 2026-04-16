use anyhow::{Context, Result};
use sequoia_openpgp as openpgp;
use openpgp::armor::{Writer as ArmorWriter, Kind as ArmorKind};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder,
    MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::types::SymmetricAlgorithm;
use openpgp::crypto::SessionKey;
use openpgp::{Cert, Fingerprint, KeyHandle, packet::{PKESK, SKESK}};
use openpgp_card_sequoia::sq_util;
use std::io::{self, Write};
use std::path::Path;

use crate::pkcs11::card::open_first_card;

pub(crate) fn load_cert(path: &Path) -> Result<Cert> {
    Cert::from_file(path)
        .with_context(|| format!("Failed to load public key from {:?}", path))
}

fn touch_prompt() { eprintln!("Touch YubiKey now..."); }

struct VerifyHelper { cert: Cert }

impl VerificationHelper for VerifyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> { Ok(vec![self.cert.clone()]) }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results { if result.is_ok() { return Ok(()); } }
                anyhow::bail!("No valid signature found");
            }
        }
        anyhow::bail!("No signature layer in message")
    }
}

struct VerifyDecryptHelper<D> { inner: D, cert: Cert }

impl<D: DecryptionHelper + VerificationHelper> VerificationHelper for VerifyDecryptHelper<D> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> { Ok(vec![self.cert.clone()]) }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results { if result.is_ok() { return Ok(()); } }
                anyhow::bail!("No valid signature found");
            }
        }
        anyhow::bail!("No signature layer in message")
    }
}

impl<D: DecryptionHelper + VerificationHelper> DecryptionHelper for VerifyDecryptHelper<D> {
    fn decrypt<F>(&mut self, pkesks: &[PKESK], skesks: &[SKESK], sym_algo: Option<SymmetricAlgorithm>, dec_fn: F) -> openpgp::Result<Option<Fingerprint>>
    where F: FnMut(SymmetricAlgorithm, &SessionKey) -> bool {
        self.inner.decrypt(pkesks, skesks, sym_algo, dec_fn)
    }
}

pub fn sign(data: &[u8], pin: &str) -> Result<String> {
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;
    tx.verify_user_signing_pin(pin).context("PIN verification failed")?;
    let mut sign_card = tx.to_signing_card(None)?;
    let signer = sign_card.signer(&touch_prompt).context("Failed to get signer from card")?;
    sq_util::sign(signer, &mut io::Cursor::new(data))
}

pub fn verify(data: &[u8], sig: &[u8], signer_path: &Path) -> Result<()> {
    let policy = &StandardPolicy::new();
    let helper = VerifyHelper { cert: load_cert(signer_path)? };
    let mut verifier = DetachedVerifierBuilder::from_bytes(sig)?
        .with_policy(policy, None, helper).context("Signature verification failed")?;
    verifier.verify_bytes(data).context("Signature verification failed")
}

pub fn encrypt(data: &[u8], recipient_path: &Path) -> Result<String> {
    let policy = &StandardPolicy::new();
    let recipient_cert = load_cert(recipient_path)?;
    let recipient_keys: Vec<_> = recipient_cert.keys().with_policy(policy, None)
        .supported().alive().revoked(false).for_transport_encryption().collect();
    anyhow::ensure!(!recipient_keys.is_empty(), "No valid encryption key found in recipient cert");
    let mut output = Vec::new();
    {
        let mut armor = ArmorWriter::new(&mut output, ArmorKind::Message)?;
        let message = Message::new(&mut armor);
        let message = Encryptor2::for_recipients(message, recipient_keys).build().context("Failed to build encryptor")?;
        let mut literal = LiteralWriter::new(message).build()?;
        literal.write_all(data)?;
        literal.finalize()?;
        armor.finalize()?;
    }
    Ok(String::from_utf8(output)?)
}

pub fn decrypt(data: &[u8], pin: &str) -> Result<Vec<u8>> {
    let policy = &StandardPolicy::new();
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;
    tx.verify_user_pin(pin).context("PIN verification failed")?;
    let mut user_card = tx.to_user_card(None)?;
    let decryptor = user_card.decryptor(&touch_prompt).context("Failed to get decryptor from card")?;
    sq_util::decrypt(decryptor, data.to_vec(), policy)
}

pub fn sign_encrypt(data: &[u8], recipient_path: &Path, pin: &str) -> Result<String> {
    let policy = &StandardPolicy::new();
    let recipient_cert = load_cert(recipient_path)?;
    let recipient_keys: Vec<_> = recipient_cert.keys().with_policy(policy, None)
        .supported().alive().revoked(false).for_transport_encryption().collect();
    anyhow::ensure!(!recipient_keys.is_empty(), "No valid encryption key found in recipient cert");
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;
    tx.verify_user_signing_pin(pin).context("PIN verification failed")?;
    let mut sign_card = tx.to_signing_card(None)?;
    let signer = sign_card.signer(&touch_prompt).context("Failed to get signer from card")?;
    let mut output = Vec::new();
    {
        let mut armor = ArmorWriter::new(&mut output, ArmorKind::Message)?;
        let message = Message::new(&mut armor);
        let message = Encryptor2::for_recipients(message, recipient_keys).build().context("Failed to build encryptor")?;
        let signed = Signer::new(message, signer).build().context("Failed to build signer")?;
        let mut literal = LiteralWriter::new(signed).build()?;
        literal.write_all(data)?;
        literal.finalize()?;
        armor.finalize()?;
    }
    Ok(String::from_utf8(output)?)
}

pub fn decrypt_verify(data: &[u8], signer_path: &Path, pin: &str) -> Result<Vec<u8>> {
    let policy = &StandardPolicy::new();
    let cert = load_cert(signer_path)?;
    let mut card = open_first_card()?;
    let mut tx = card.transaction()?;
    tx.verify_user_pin(pin).context("PIN verification failed")?;
    let mut user_card = tx.to_user_card(None)?;
    let decryptor = user_card.decryptor(&touch_prompt).context("Failed to get decryptor from card")?;
    let helper = VerifyDecryptHelper { inner: decryptor, cert };
    let mut output = Vec::new();
    let reader = io::BufReader::new(data);
    let mut decryptor = DecryptorBuilder::from_reader(reader)?
        .with_policy(policy, None, helper).context("Decryption/verification failed")?;
    io::copy(&mut decryptor, &mut output)?;
    Ok(output)
}
