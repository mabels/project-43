use anyhow::Result;
use p43::key_store::store::{self, KeyStore};
use std::path::Path;

pub fn run_list(ks: &KeyStore) -> Result<()> {
    let keys = ks.list()?;
    if keys.is_empty() {
        println!("No keys in store.");
    } else {
        println!(
            "{:<36} {:<16} {:<42} Cards",
            "UID", "Algorithm", "Fingerprint"
        );
        println!("{}", "-".repeat(120));
        for e in keys {
            let cards = if e.card_idents.is_empty() {
                "-".to_owned()
            } else {
                e.card_idents.join(", ")
            };
            println!(
                "{:<36} {:<16} {:<42} {}",
                e.uid, e.algo, e.fingerprint, cards
            );
        }
    }
    Ok(())
}

pub fn run_export_pub(ks: &KeyStore, key: &str) -> Result<()> {
    print!("{}", store::export_pub(&ks.find(key)?)?);
    Ok(())
}

pub fn run_export_priv(ks: &KeyStore, key: &str) -> Result<()> {
    let pw = rpassword::prompt_password("Passphrase: ")?;
    print!("{}", store::export_priv(&ks.find_with_secret(key, &pw)?)?);
    Ok(())
}

pub fn run_import(ks: &KeyStore, file: &Path) -> Result<()> {
    let cert = ks.import(&std::fs::read(file)?)?;
    println!("Imported: {}", cert.fingerprint());
    for uid in cert.userids() {
        println!("  UID: {}", uid.userid());
    }
    Ok(())
}

pub fn run_delete(ks: &KeyStore, key: &str) -> Result<()> {
    println!("Deleted key: {}", ks.delete(key)?);
    Ok(())
}

pub fn run_register_card(ks: &KeyStore, key: &str, ident: &str) -> Result<()> {
    ks.register_card(key, ident)?;
    println!("Registered card ident '{}' with key '{}'", ident, key);
    Ok(())
}

pub fn run_import_card(
    ks: &KeyStore,
    card_ident: Option<&str>,
    uid_override: Option<&str>,
) -> Result<()> {
    let pin = rpassword::prompt_password("Card User Signing PIN: ")?;
    p43::pkcs11::import_card::import_card_cert(ks, card_ident, uid_override, &pin)
}

pub fn run_list_cards() -> Result<()> {
    let cards = p43::pkcs11::card::list_connected_cards()?;
    if cards.is_empty() {
        println!("No OpenPGP cards connected.");
        return Ok(());
    }
    for (i, c) in cards.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("Card {}", i + 1);
        println!("  Ident:  {}", c.ident);
        if !c.cardholder_name.is_empty() {
            println!("  Name:   {}", c.cardholder_name);
        }
        match &c.sig_fingerprint {
            Some(fp) => println!("  Sig FP: {}", fp),
            None => println!("  Sig FP: (none)"),
        }
        match &c.auth_fingerprint {
            Some(fp) => println!("  Auth FP: {}", fp),
            None => println!("  Auth FP: (none)"),
        }
    }
    Ok(())
}
