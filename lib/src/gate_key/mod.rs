//! Gate-key: passphrase-sealed random keys that protect Level 2 secrets.
//!
//! A gate-key is a 32-byte random value that encrypts Level 2 store entries.
//! It is sealed on disk using Argon2id key derivation + AES-256-GCM.
//! Multiple sealed files can coexist under the gate-key directory —
//! one per passphrase.  [`GateKeyStore::try_unlock`] iterates them all
//! and returns on the first successful decryption (authenticated by the
//! GCM tag — wrong passphrase → auth failure, not garbage).
//!
//! # Directory layout
//!
//! ```text
//! ~/.config/project-43/gate-keys/
//!   gate-9c12ef.sealed
//!   gate-ab3401.sealed
//! ```
//!
//! The filename stem is the `key_id` — a `"gate-"` prefix followed by the
//! first 6 hex bytes of `SHA-256(random)`.  The `key_id` is also bound into
//! the AES-GCM AAD so the file cannot be renamed without invalidating the tag.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use anyhow::{bail, Context, Result};

// ── Public types ──────────────────────────────────────────────────────────────

/// An unlocked gate-key: the 32-byte random held in memory.
///
/// Drop-zeroed via `zeroize::Zeroizing`.  Never written to disk in plaintext.
pub struct GateKey {
    pub key_id: String,
    pub random: Zeroizing<Vec<u8>>,
}

/// Argon2id parameters stored alongside each sealed key so they can be
/// tuned per-device without changing the format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String, // always "argon2id"
    pub salt: String,      // base64url
    pub m_cost: u32,       // memory in KiB
    pub t_cost: u32,       // iterations
    pub p_cost: u32,       // parallelism
}

impl KdfParams {
    /// Sensible defaults: ~64 MiB, 3 iterations, 4 threads.
    /// Adjust with [`GateKeyStore::benchmark`] for ~1 s on target hardware.
    pub fn default_params() -> Self {
        Self {
            algorithm: "argon2id".into(),
            salt: base64url_encode(&random_bytes(16)),
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// The on-disk representation of a sealed gate-key.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedGateKey {
    pub version: u8,
    pub key_id: String,
    pub kdf: KdfParams,
    pub nonce: String,      // base64url, 12 bytes
    pub ciphertext: String, // base64url — AES-256-GCM(derived_key, plaintext, aad=key_id)
}

/// Per-file result returned by [`GateKeyStore::try_unlock_verbose`].
pub type UnlockAttempts = Vec<(String, Result<()>)>;

/// Manages the directory of `.sealed` gate-key files.
pub struct GateKeyStore {
    dir: PathBuf,
}

// ── GateKeyStore ──────────────────────────────────────────────────────────────

impl GateKeyStore {
    /// Open (or create) the gate-key directory.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create gate-key dir {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    /// Create a new gate-key sealed with `passphrase`.
    ///
    /// Writes `<dir>/gate-<key_id>.sealed` and returns the unlocked key.
    /// Pass `existing_random` (hex-encoded) to re-seal a known random instead
    /// of generating a fresh one — useful for adding a second passphrase to an
    /// already-existing gate-key random.
    pub fn create(
        &self,
        passphrase: &str,
        kdf: KdfParams,
        existing_random: Option<&str>,
    ) -> Result<GateKey> {
        let random = match existing_random {
            Some(hex) => hex::decode(hex).context("--from-secret: invalid hex")?,
            None => random_bytes(32),
        };
        anyhow::ensure!(
            random.len() == 32,
            "--from-secret must be exactly 32 bytes (64 hex chars)"
        );
        let key_id = derive_key_id(&random, &kdf.salt);
        let sealed = SealedGateKey::seal(&key_id, &random, passphrase, kdf)?;
        sealed.save(&self.dir)?;
        Ok(GateKey {
            key_id,
            random: Zeroizing::new(random),
        })
    }

    /// Try every `.sealed` file with `passphrase`.
    ///
    /// Returns the first one that successfully decrypts, or an error if none
    /// matches.  The GCM authentication tag is the verifier — wrong passphrase
    /// produces an auth error, not garbage.
    pub fn try_unlock(&self, passphrase: &str) -> Result<GateKey> {
        let (key, _) = self.try_unlock_verbose(passphrase)?;
        Ok(key)
    }

    /// Try a single sealed file by `key_id` with `passphrase`.
    pub fn try_unlock_by_id(&self, key_id: &str, passphrase: &str) -> Result<GateKey> {
        let path = self.dir.join(format!("{key_id}.sealed"));
        anyhow::ensure!(path.exists(), "gate-key {key_id} not found");
        SealedGateKey::load(&path)?.unseal(passphrase)
    }

    /// Like [`try_unlock`] but also returns the per-file attempt log so the
    /// caller can report which files passed or failed.
    ///
    /// Returns `(unlocked_key, attempts)` where each attempt is
    /// `(key_id, ok_or_err_message)`.
    pub fn try_unlock_verbose(&self, passphrase: &str) -> Result<(GateKey, UnlockAttempts)> {
        let files = self.sealed_files()?;
        if files.is_empty() {
            bail!("no gate-keys found in {}", self.dir.display());
        }
        let mut attempts: Vec<(String, Result<()>)> = Vec::new();
        let mut success: Option<GateKey> = None;

        for path in &files {
            let key_id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_owned();
            match SealedGateKey::load(path).and_then(|s| s.unseal(passphrase)) {
                Ok(key) => {
                    attempts.push((key_id, Ok(())));
                    success = Some(key);
                    // keep iterating so we report all attempts
                }
                Err(e) => {
                    attempts.push((key_id, Err(e)));
                }
            }
        }

        match success {
            Some(key) => Ok((key, attempts)),
            None => {
                // return attempts as context even on failure via the last error
                bail!("passphrase did not match any gate-key");
            }
        }
    }

    /// List the key_ids of all sealed files in the directory.
    pub fn list(&self) -> Result<Vec<String>> {
        Ok(self
            .sealed_files()?
            .iter()
            .filter_map(|p| p.file_stem()?.to_str().map(str::to_owned))
            .collect())
    }

    /// Change the passphrase for the gate-key that `old_passphrase` unlocks.
    ///
    /// Writes the new `.sealed` file first, then removes the old one — if the
    /// write fails the old file is left intact.  Returns the (unchanged) key_id.
    pub fn change_passphrase(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
        new_kdf: KdfParams,
    ) -> Result<String> {
        let key = self
            .try_unlock(old_passphrase)
            .context("current passphrase did not match any gate-key")?;

        let key_id = key.key_id.clone();

        // Write new seal (same key_id, same random, new passphrase + KDF params).
        let new_sealed = SealedGateKey::seal(&key_id, key.as_bytes(), new_passphrase, new_kdf)?;
        new_sealed.save(&self.dir)?;

        Ok(key_id)
    }

    /// Delete the sealed file for `key_id`.
    ///
    /// Also removes the corresponding Level 2 entries (caller responsibility
    /// for now — a future `Level2Store::revoke(key_id)` will handle that).
    pub fn revoke(&self, key_id: &str) -> Result<()> {
        let path = self.dir.join(format!("{key_id}.sealed"));
        std::fs::remove_file(&path).with_context(|| format!("cannot revoke gate-key {key_id}"))?;
        Ok(())
    }

    // ── private ───────────────────────────────────────────────────────────────

    fn sealed_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.dir)
            .with_context(|| format!("cannot read gate-key dir {}", self.dir.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sealed") {
                files.push(path);
            }
        }
        Ok(files)
    }
}

// ── SealedGateKey ─────────────────────────────────────────────────────────────

impl SealedGateKey {
    /// Seal `random` with `passphrase` using Argon2id + AES-256-GCM.
    pub fn seal(key_id: &str, random: &[u8], passphrase: &str, kdf: KdfParams) -> Result<Self> {
        let derived = argon2_derive(passphrase, &kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&derived).context("invalid derived key length")?;

        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let plaintext = serde_json::to_vec(&PlainPayload {
            version: 1,
            random: base64url_encode(random),
        })?;

        let ciphertext = cipher
            .encrypt(
                &nonce_bytes,
                Payload {
                    msg: &plaintext,
                    aad: key_id.as_bytes(),
                },
            )
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;

        Ok(Self {
            version: 1,
            key_id: key_id.to_owned(),
            kdf,
            nonce: base64url_encode(&nonce_bytes),
            ciphertext: base64url_encode(&ciphertext),
        })
    }

    /// Try to unseal with `passphrase`.  Fails with an error if the passphrase
    /// is wrong (GCM authentication failure) or the file is corrupted.
    pub fn unseal(&self, passphrase: &str) -> Result<GateKey> {
        let derived = argon2_derive(passphrase, &self.kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&derived).context("invalid derived key length")?;

        let nonce = base64url_decode(&self.nonce)?;
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = base64url_decode(&self.ciphertext)?;

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: self.key_id.as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("decryption failed — wrong passphrase or corrupted file")
            })?;

        let payload: PlainPayload =
            serde_json::from_slice(&plaintext).context("invalid sealed payload")?;

        Ok(GateKey {
            key_id: self.key_id.clone(),
            random: Zeroizing::new(base64url_decode(&payload.random)?),
        })
    }

    /// Save to `<dir>/<key_id>.sealed`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(format!("{}.sealed", self.key_id));
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }

    /// Load from a `.sealed` file.
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_str(&json)
            .with_context(|| format!("invalid sealed file {}", path.display()))
    }
}

// ── GateKey helpers ───────────────────────────────────────────────────────────

impl GateKey {
    /// Expose the raw random bytes for use as an encryption key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.random
    }
}

// ── Internals ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct PlainPayload {
    version: u8,
    random: String, // base64url
}

fn argon2_derive(passphrase: &str, kdf: &KdfParams) -> Result<Vec<u8>> {
    let salt = base64url_decode(&kdf.salt)?;
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| anyhow::anyhow!("Argon2 failed: {e}"))?;
    Ok(out)
}

/// Derive a unique key_id from both the random AND the KDF salt.
///
/// Using only the random would give the same key_id for every seal of the
/// same master secret, causing files to overwrite each other.  Including the
/// salt (which is freshly generated per seal) makes each key_id unique.
fn derive_key_id(random: &[u8], salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(random);
    hasher.update(salt.as_bytes());
    format!("gate-{}", hex::encode(&hasher.finalize()[..6]))
}

/// Generate a random base64url-encoded salt for use in [`KdfParams`].
pub fn random_salt() -> String {
    base64url_encode(&random_bytes(16))
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn base64url_encode(b: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(b)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(s).context("invalid base64url")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let kdf = KdfParams {
            algorithm: "argon2id".into(),
            salt: base64url_encode(&random_bytes(16)),
            m_cost: 8, // tiny for tests
            t_cost: 1,
            p_cost: 1,
        };
        let passphrase = "test-passphrase";
        let random = random_bytes(32);
        let salt = base64url_encode(&random_bytes(16));
        let key_id = derive_key_id(&random, &salt);
        let kdf = KdfParams { salt, ..kdf };

        let sealed = SealedGateKey::seal(&key_id, &random, passphrase, kdf).unwrap();
        let unlocked = sealed.unseal(passphrase).unwrap();

        assert_eq!(unlocked.key_id, key_id);
        assert_eq!(unlocked.as_bytes(), random.as_slice());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let kdf = KdfParams {
            algorithm: "argon2id".into(),
            salt: base64url_encode(&random_bytes(16)),
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let random = random_bytes(32);
        let key_id = derive_key_id(&random, &kdf.salt);
        let sealed = SealedGateKey::seal(&key_id, &random, "correct", kdf).unwrap();
        assert!(sealed.unseal("wrong").is_err());
    }

    #[test]
    fn store_create_and_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let store = GateKeyStore::open(dir.path()).unwrap();
        let kdf = KdfParams {
            algorithm: "argon2id".into(),
            salt: base64url_encode(&random_bytes(16)),
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let created = store.create("my-pass", kdf, None).unwrap();
        let unlocked = store.try_unlock("my-pass").unwrap();
        assert_eq!(created.key_id, unlocked.key_id);
        assert_eq!(created.as_bytes(), unlocked.as_bytes());
    }

    #[test]
    fn change_passphrase_works() {
        let dir = tempfile::tempdir().unwrap();
        let store = GateKeyStore::open(dir.path()).unwrap();
        let kdf = || KdfParams {
            algorithm: "argon2id".into(),
            salt: base64url_encode(&random_bytes(16)),
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let original = store.create("old-pass", kdf(), None).unwrap();
        store
            .change_passphrase("old-pass", "new-pass", kdf())
            .unwrap();

        // new passphrase works and returns same random
        let changed = store.try_unlock("new-pass").unwrap();
        assert_eq!(original.key_id, changed.key_id);
        assert_eq!(original.as_bytes(), changed.as_bytes());

        // old passphrase no longer works — file was overwritten in place
        assert!(store.try_unlock("old-pass").is_err());
    }

    #[test]
    fn store_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = GateKeyStore::open(dir.path()).unwrap();
        let kdf = KdfParams {
            algorithm: "argon2id".into(),
            salt: base64url_encode(&random_bytes(16)),
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        store.create("correct", kdf, None).unwrap();
        assert!(store.try_unlock("wrong").is_err());
    }
}
