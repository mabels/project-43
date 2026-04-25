//! Key store: on-disk persistence for OpenPGP certs (rPGP version).
//!
//! File layout under the store directory:
//!   `<FP>.pub.asc`    — armored public key (always present)
//!   `<FP>.sec.asc`    — armored secret key (present for soft keys)
//!   `<FP>.card.json`  — list of card AIDs associated with this key (optional)
//!   `index.json`      — list of [`KeyEntry`] metadata

use anyhow::{Context, Result};
use pgp::composed::{ArmorOptions, Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::KeyDetails;
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Role + algorithm summary for one key component inside an OpenPGP cert.
pub struct SubkeyMeta {
    /// Comma-separated role labels: any combination of `"certify"`, `"sign"`,
    /// `"auth"`, `"encrypt"`.  Never empty — falls back to `"unknown"`.
    pub role: String,
    /// Algorithm name, e.g. `"RSA4096"`, `"Ed25519"`.
    pub algo: String,
    /// OpenSSH `authorized_keys` line for this key component, or `None` when the
    /// algorithm has no SSH equivalent (e.g. ECDH encryption subkeys).
    pub openssh_key: Option<String>,
}

#[derive(Debug, SerdeSerialize, Deserialize)]
pub struct KeyEntry {
    pub fingerprint: String,
    pub uid: String,
    pub algo: String,
    pub has_secret: bool,
    /// Whether this key is active in the SSH agent.  Defaults to `true` for
    /// backward compatibility with existing index files.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Application Identifier strings of OpenPGP cards that carry this key.
    /// Populated at read-time from the companion `.card.json` file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub card_idents: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// On-disk format for `<fingerprint>.card.json`.
#[derive(Debug, SerdeSerialize, Deserialize)]
struct CardInfo {
    version: u32,
    idents: Vec<String>,
}

pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("Cannot create key store at {:?}", dir))?;
        set_dir_private(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    // ── write ─────────────────────────────────────────────────────────────────

    /// Save a public cert (from a card import or exported key).
    pub fn save_public(&self, cert: &SignedPublicKey) -> Result<()> {
        let fp = fp_hex(cert);
        let pub_path = self.pub_path(&fp);
        let armored = cert
            .to_armored_bytes(ArmorOptions::default())
            .context("Failed to armor public key")?;
        fs::write(&pub_path, &armored)
            .with_context(|| format!("Cannot write public key to {:?}", pub_path))?;
        set_file_private(&pub_path)?;
        self.update_index_pub(cert)?;
        Ok(())
    }

    /// Save a secret key (generated or imported soft key).
    pub fn save_secret(&self, key: &SignedSecretKey) -> Result<()> {
        // Always write the public side too.
        let pub_cert = key.to_public_key();
        self.save_public(&pub_cert)?;

        let fp = fp_hex(&pub_cert);
        let sec_path = self.sec_path(&fp);
        let armored = key
            .to_armored_bytes(ArmorOptions::default())
            .context("Failed to armor secret key")?;
        fs::write(&sec_path, &armored)
            .with_context(|| format!("Cannot write secret key to {:?}", sec_path))?;
        set_file_private(&sec_path)?;

        // Mark as having a secret key in the index.
        let mut entries = self.list().unwrap_or_default();
        if let Some(e) = entries.iter_mut().find(|e| e.fingerprint == fp) {
            e.has_secret = true;
        }
        fs::write(self.index_path(), serde_json::to_string_pretty(&entries)?)
            .context("Failed to write key store index")?;

        Ok(())
    }

    // ── read ──────────────────────────────────────────────────────────────────

    pub fn list(&self) -> Result<Vec<KeyEntry>> {
        let index_path = self.index_path();
        if !index_path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read_to_string(&index_path)?;
        let mut entries: Vec<KeyEntry> =
            serde_json::from_str(&data).context("Failed to parse key store index")?;
        for entry in &mut entries {
            let card_path = self.card_path(&entry.fingerprint);
            if card_path.exists() {
                if let Ok(raw) = fs::read_to_string(&card_path) {
                    if let Ok(info) = serde_json::from_str::<CardInfo>(&raw) {
                        entry.card_idents = info.idents;
                    }
                }
            }
        }
        Ok(entries)
    }

    /// Load a public cert by fingerprint or UID substring.
    pub fn find(&self, query: &str) -> Result<SignedPublicKey> {
        let entry = self.find_entry(query)?;
        let path = self.pub_path(&entry.fingerprint);
        let f = fs::File::open(&path)
            .with_context(|| format!("Cannot open public key at {:?}", path))?;
        let (key, _) = SignedPublicKey::from_armor_single(io::BufReader::new(f))
            .with_context(|| format!("Failed to parse public key for '{}'", query))?;
        Ok(key)
    }

    /// Load a secret key.  The passphrase (if any) is presented at signing
    /// time via `SecretKey::unlock`; we do not decrypt in-place here.
    pub fn find_with_secret(&self, query: &str, _passphrase: &str) -> Result<SignedSecretKey> {
        let entry = self.find_entry(query)?;
        anyhow::ensure!(entry.has_secret, "No secret key found for '{}'", query);
        let path = self.sec_path(&entry.fingerprint);
        let f = fs::File::open(&path)
            .with_context(|| format!("Cannot open secret key at {:?}", path))?;
        let (key, _) = SignedSecretKey::from_armor_single(io::BufReader::new(f))
            .with_context(|| format!("Failed to parse secret key for '{}'", query))?;
        Ok(key)
    }

    /// Import a raw armored public key blob and save it to the store.
    pub fn import(&self, data: &[u8]) -> Result<SignedPublicKey> {
        let (cert, _) = SignedPublicKey::from_armor_single(io::Cursor::new(data))
            .context("Failed to parse key — expected armored OpenPGP public key")?;
        self.save_public(&cert)?;
        Ok(cert)
    }

    pub fn delete(&self, query: &str) -> Result<String> {
        let entry = self.find_entry(query)?;
        let fp = &entry.fingerprint;
        for path in [self.pub_path(fp), self.sec_path(fp), self.card_path(fp)] {
            if path.exists() {
                fs::remove_file(&path)?;
            }
        }
        let mut entries = self.list()?;
        entries.retain(|e| &e.fingerprint != fp);
        fs::write(self.index_path(), serde_json::to_string_pretty(&entries)?)?;
        Ok(fp.clone())
    }

    // ── path helpers ──────────────────────────────────────────────────────────

    pub fn pub_file_path(&self, fingerprint: &str) -> PathBuf {
        self.pub_path(fingerprint)
    }
    pub fn sec_file_path(&self, fingerprint: &str) -> PathBuf {
        self.sec_path(fingerprint)
    }

    fn pub_path(&self, fp: &str) -> PathBuf {
        self.dir.join(format!("{fp}.pub.asc"))
    }
    fn sec_path(&self, fp: &str) -> PathBuf {
        self.dir.join(format!("{fp}.sec.asc"))
    }
    fn card_path(&self, fp: &str) -> PathBuf {
        self.dir.join(format!("{fp}.card.json"))
    }
    fn index_path(&self) -> PathBuf {
        self.dir.join("index.json")
    }

    // ── card registration ─────────────────────────────────────────────────────

    /// Associate a card AID with a key entry.
    pub fn register_card(&self, fingerprint: &str, card_ident: &str) -> Result<()> {
        let fp = self.find_entry(fingerprint)?.fingerprint;
        let card_path = self.card_path(&fp);
        let mut info = if card_path.exists() {
            let raw = fs::read_to_string(&card_path)
                .with_context(|| format!("Cannot read {:?}", card_path))?;
            serde_json::from_str::<CardInfo>(&raw).context("Failed to parse card info")?
        } else {
            CardInfo {
                version: 1,
                idents: Vec::new(),
            }
        };
        if !info.idents.iter().any(|id| id == card_ident) {
            info.idents.push(card_ident.to_owned());
            fs::write(&card_path, serde_json::to_string_pretty(&info)?)
                .with_context(|| format!("Cannot write {:?}", card_path))?;
        }
        Ok(())
    }

    // ── agent enable/disable ──────────────────────────────────────────────────

    pub fn set_key_enabled(&self, query: &str, enabled: bool) -> Result<()> {
        let fp = self.find_entry(query)?.fingerprint;
        let mut entries = self.list()?;
        let found = entries.iter_mut().find(|e| e.fingerprint == fp);
        anyhow::ensure!(found.is_some(), "Key '{}' not found in index", query);
        found.unwrap().enabled = enabled;
        fs::write(self.index_path(), serde_json::to_string_pretty(&entries)?)
            .context("Failed to write key store index")?;
        Ok(())
    }

    // ── subkey info ───────────────────────────────────────────────────────────

    /// Return role+algorithm info for each key component in the cert.
    pub fn list_subkeys(&self, query: &str) -> Vec<SubkeyMeta> {
        let cert = match self.find(query) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let mut out = Vec::new();

        // Primary key — flags live in the first user-id self-signature.
        {
            let kf = cert
                .details
                .users
                .first()
                .and_then(|u| u.signatures.first())
                .map(|sig| sig.key_flags())
                .unwrap_or_default();
            let mut roles: Vec<&str> = Vec::new();
            if kf.certify() {
                roles.push("certify");
            }
            if kf.sign() {
                roles.push("sign");
            }
            let role = if roles.is_empty() {
                "unknown".to_string()
            } else {
                roles.join("+")
            };
            let uid_comment = cert
                .details
                .users
                .first()
                .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
                .unwrap_or_default();
            let openssh_key = crate::ssh_agent::pub_params_to_openssh_string(
                cert.primary_key.public_params(),
                &uid_comment,
            );
            out.push(SubkeyMeta {
                role,
                algo: format!("{:?}", cert.primary_key.algorithm()),
                openssh_key,
            });
        }

        // Subkeys — flags live in the subkey binding signature.
        for sk in &cert.public_subkeys {
            let kf = sk
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();
            let mut roles: Vec<&str> = Vec::new();
            if kf.sign() {
                roles.push("sign");
            }
            if kf.authentication() {
                roles.push("auth");
            }
            if kf.encrypt_comms() {
                roles.push("encrypt");
            }
            let role = if roles.is_empty() {
                "unknown".to_string()
            } else {
                roles.join("+")
            };
            let openssh_key =
                crate::ssh_agent::pub_params_to_openssh_string(sk.public_params(), "");
            out.push(SubkeyMeta {
                role,
                algo: format!("{:?}", sk.algorithm()),
                openssh_key,
            });
        }

        out
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn find_entry(&self, query: &str) -> Result<KeyEntry> {
        let q = query.to_lowercase();
        let matches: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|e| {
                e.fingerprint.to_lowercase().contains(&q) || e.uid.to_lowercase().contains(&q)
            })
            .collect();
        match matches.len() {
            0 => anyhow::bail!("No key found matching '{}'", query),
            1 => Ok(matches.into_iter().next().unwrap()),
            n => anyhow::bail!("Ambiguous query '{}' matched {} keys", query, n),
        }
    }

    fn update_index_pub(&self, cert: &SignedPublicKey) -> Result<()> {
        let fp = fp_hex(cert);
        let uid = cert
            .details
            .users
            .first()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .unwrap_or_default();
        let algo = format!("{:?}", cert.primary_key.algorithm());

        let mut entries = self.list().unwrap_or_default();
        let was_enabled = entries
            .iter()
            .find(|e| e.fingerprint == fp)
            .map(|e| e.enabled)
            .unwrap_or(true);
        let had_secret = entries
            .iter()
            .find(|e| e.fingerprint == fp)
            .map(|e| e.has_secret)
            .unwrap_or(false);
        entries.retain(|e| e.fingerprint != fp);
        entries.push(KeyEntry {
            fingerprint: fp,
            uid,
            algo,
            has_secret: had_secret,
            enabled: was_enabled,
            card_idents: Vec::new(),
        });
        fs::write(self.index_path(), serde_json::to_string_pretty(&entries)?)
            .context("Failed to write key store index")?;
        Ok(())
    }
}

// ── export helpers ────────────────────────────────────────────────────────────

pub fn export_pub(cert: &SignedPublicKey) -> Result<String> {
    cert.to_armored_string(ArmorOptions::default())
        .context("Failed to armor public key")
}

pub fn export_priv(key: &SignedSecretKey) -> Result<String> {
    key.to_armored_string(ArmorOptions::default())
        .context("Failed to armor secret key")
}

// ── internal utilities ────────────────────────────────────────────────────────

fn fp_hex(cert: &SignedPublicKey) -> String {
    hex::encode(cert.fingerprint().as_bytes()).to_uppercase()
}

// ── file-permission helpers ───────────────────────────────────────────────────

fn set_file_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Cannot set 0o600 on {:?}", path))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn set_dir_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Cannot set 0o700 on {:?}", path))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
