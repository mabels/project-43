use flutter_rust_bridge::frb;
use p43::key_store::{keygen, store::KeyStore};
use std::path::PathBuf;

/// A key entry returned to Flutter — mirrors p43::key_store::store::KeyEntry.
pub struct KeyInfo {
    pub fingerprint: String,
    pub uid: String,
    pub algo: String,
    pub has_secret: bool,
}

fn default_store_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot find home dir")
        .join(".config")
        .join("project-43")
        .join("keys")
}

fn open_store() -> anyhow::Result<KeyStore> {
    KeyStore::open(&default_store_dir())
}

/// Returns all keys in the local store.
#[frb]
pub fn list_keys() -> anyhow::Result<Vec<KeyInfo>> {
    let entries = open_store()?.list()?;
    Ok(entries
        .into_iter()
        .map(|e| KeyInfo {
            fingerprint: e.fingerprint,
            uid: e.uid,
            algo: e.algo,
            has_secret: e.has_secret,
        })
        .collect())
}

/// Generates a new soft key, saves it to the store, and returns the updated list.
/// Pass `passphrase: None` to skip encryption (not recommended).
#[frb]
pub fn generate_key(
    uid: String,
    algo: String,
    passphrase: Option<String>,
) -> anyhow::Result<Vec<KeyInfo>> {
    let ks = open_store()?;
    let cert = keygen::generate(&uid, &algo, passphrase.as_deref())?;
    ks.save(&cert, None)?;
    let entries = ks.list()?;
    Ok(entries
        .into_iter()
        .map(|e| KeyInfo {
            fingerprint: e.fingerprint,
            uid: e.uid,
            algo: e.algo,
            has_secret: e.has_secret,
        })
        .collect())
}
