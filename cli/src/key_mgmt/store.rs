use anyhow::Result;
use p43::key_store::store::{self, KeyStore};
use std::path::Path;

pub fn run_list(ks: &KeyStore) -> Result<()> {
    let keys = ks.list()?;
    if keys.is_empty() {
        println!("No keys in store.");
    } else {
        println!("{:<36} {:<16} {}", "UID", "Algorithm", "Fingerprint");
        println!("{}", "-".repeat(90));
        for e in keys {
            println!("{:<36} {:<16} {}", e.uid, e.algo, e.fingerprint);
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
