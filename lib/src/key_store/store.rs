use anyhow::{Context, Result};
use openpgp::armor::{Kind as ArmorKind, Writer as ArmorWriter};
use openpgp::crypto::Password;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Role + algorithm summary for one key (primary or subkey) inside an OpenPGP
/// cert.  Returned by [`KeyStore::list_subkeys`].
pub struct SubkeyMeta {
    /// Comma-separated role labels: any combination of `"certify"`, `"sign"`,
    /// `"auth"`, `"encrypt"`.  Never empty — falls back to `"unknown"`.
    pub role: String,
    /// Algorithm name as reported by sequoia, e.g. `"RSA4096"`, `"EdDSA"`.
    pub algo: String,
    /// OpenSSH `authorized_keys` line for this subkey, or `None` when the
    /// algorithm has no SSH equivalent (e.g. ECDH encryption keys).
    pub openssh_key: Option<String>,
}

#[derive(Debug, SerdeSerialize, Deserialize)]
pub struct KeyEntry {
    pub fingerprint: String,
    pub uid: String,
    pub algo: String,
    pub has_secret: bool,
    /// Whether this key is active in the SSH agent.  Disabled keys are not
    /// advertised by `ssh-add -l` and cannot be used for signing.
    /// Defaults to `true` for backward compatibility with existing index files.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Application Identifier strings of YubiKeys (or other OpenPGP cards)
    /// that carry the secret key for this entry.  Empty for soft keys.
    /// Populated at read-time from the companion `<fp>.card.json` file;
    /// not stored in `index.json`.
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

    pub fn save(&self, cert: &Cert, _passphrase: Option<&str>) -> Result<()> {
        let fp = cert.fingerprint().to_hex();

        let pub_path = self.pub_path(&fp);
        let mut pub_file = fs::File::create(&pub_path)
            .with_context(|| format!("Cannot write public key to {:?}", pub_path))?;
        let mut armor = ArmorWriter::new(&mut pub_file, ArmorKind::PublicKey)?;
        cert.export(&mut armor)?;
        armor.finalize()?;
        set_file_private(&pub_path)?;

        if cert.is_tsk() {
            let sec_path = self.sec_path(&fp);
            let mut sec_file = fs::File::create(&sec_path)
                .with_context(|| format!("Cannot write secret key to {:?}", sec_path))?;
            let mut armor = ArmorWriter::new(&mut sec_file, ArmorKind::SecretKey)?;
            cert.as_tsk().serialize(&mut armor)?;
            armor.finalize()?;
            set_file_private(&sec_path)?;
        }

        self.update_index(cert)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<KeyEntry>> {
        let index_path = self.index_path();
        if !index_path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read_to_string(&index_path)?;
        let mut entries: Vec<KeyEntry> =
            serde_json::from_str(&data).context("Failed to parse key store index")?;
        // Populate card_idents from companion .card.json files (best-effort).
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

    pub fn find(&self, query: &str) -> Result<Cert> {
        let entry = self.find_entry(query)?;
        Cert::from_file(self.pub_path(&entry.fingerprint))
            .with_context(|| format!("Cannot load public key for '{}'", query))
    }

    pub fn find_with_secret(&self, query: &str, passphrase: &str) -> Result<Cert> {
        let entry = self.find_entry(query)?;
        anyhow::ensure!(entry.has_secret, "No secret key found for '{}'", query);
        let cert = Cert::from_file(self.sec_path(&entry.fingerprint))
            .with_context(|| format!("Cannot load secret key for '{}'", query))?;
        decrypt_all_secrets(cert, passphrase)
            .context("Failed to decrypt secret keys — wrong passphrase?")
    }

    pub fn import(&self, data: &[u8]) -> Result<Cert> {
        let cert = Cert::from_bytes(data)
            .context("Failed to parse key — expected armored OpenPGP cert")?;
        self.save(&cert, None)?;
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

    pub fn pub_file_path(&self, fingerprint: &str) -> PathBuf {
        self.pub_path(fingerprint)
    }
    pub fn sec_file_path(&self, fingerprint: &str) -> PathBuf {
        self.sec_path(fingerprint)
    }

    /// Register a YubiKey (or other OpenPGP card) AID with a key entry.
    ///
    /// Creates or updates `<fingerprint>.card.json` alongside the public-key
    /// file.  The same `fingerprint` can accumulate multiple `card_ident`
    /// strings — useful when the user has two identical-content YubiKeys.
    ///
    /// `card_ident` should be the string returned by
    /// `tx.application_identifier()?.ident()` from `openpgp-card-sequoia`.
    pub fn register_card(&self, fingerprint: &str, card_ident: &str) -> Result<()> {
        // Ensure the key is known before creating any file.
        let fp = &self.find_entry(fingerprint)?.fingerprint;
        let card_path = self.card_path(fp);
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

    fn pub_path(&self, fp: &str) -> PathBuf {
        self.dir.join(format!("{}.pub.asc", fp))
    }
    fn sec_path(&self, fp: &str) -> PathBuf {
        self.dir.join(format!("{}.sec.asc", fp))
    }
    fn card_path(&self, fp: &str) -> PathBuf {
        self.dir.join(format!("{}.card.json", fp))
    }
    fn index_path(&self) -> PathBuf {
        self.dir.join("index.json")
    }

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

    /// Enable or disable a key in the agent.
    ///
    /// Disabled keys are not advertised by `ssh-add -l` and cannot be used for
    /// signing until re-enabled.  The key files are not modified.
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

    /// Return role+algorithm info for every key component (primary + subkeys)
    /// in the cert identified by `query`.  Returns an empty `Vec` (not an
    /// error) when the cert cannot be read, so callers can degrade gracefully.
    pub fn list_subkeys(&self, query: &str) -> Vec<SubkeyMeta> {
        let cert = match self.find(query) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let policy = StandardPolicy::new();
        // Derive comment once from first UID.
        let comment = cert
            .userids()
            .next()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .unwrap_or_default();

        cert.keys()
            .with_policy(&policy, None)
            .map(|ka| {
                let mut roles: Vec<&str> = Vec::new();
                if ka.for_certification() {
                    roles.push("certify");
                }
                if ka.for_signing() {
                    roles.push("sign");
                }
                if ka.for_authentication() {
                    roles.push("auth");
                }
                if ka.for_storage_encryption() || ka.for_transport_encryption() {
                    roles.push("encrypt");
                }
                let role = if roles.is_empty() {
                    "unknown".to_string()
                } else {
                    roles.join("+")
                };
                let openssh_key =
                    crate::ssh_agent::mpi_to_openssh_string(ka.key().mpis(), &comment);
                SubkeyMeta {
                    role,
                    algo: ka.key().pk_algo().to_string(),
                    openssh_key,
                }
            })
            .collect()
    }

    fn update_index(&self, cert: &Cert) -> Result<()> {
        let fp = cert.fingerprint().to_hex();
        let uid = cert
            .userids()
            .next()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .unwrap_or_default();
        let algo = cert.primary_key().key().pk_algo().to_string();
        let mut entries = self.list().unwrap_or_default();
        // Preserve `enabled` if the key already exists.
        let was_enabled = entries
            .iter()
            .find(|e| e.fingerprint == fp)
            .map(|e| e.enabled)
            .unwrap_or(true);
        entries.retain(|e| e.fingerprint != fp);
        entries.push(KeyEntry {
            fingerprint: fp,
            uid,
            algo,
            has_secret: cert.is_tsk(),
            enabled: was_enabled,
            card_idents: Vec::new(),
        });
        fs::write(self.index_path(), serde_json::to_string_pretty(&entries)?)?;
        Ok(())
    }
}

fn decrypt_all_secrets(cert: Cert, passphrase: &str) -> Result<Cert> {
    let pw: Password = passphrase.into();
    let mut packets: Vec<openpgp::Packet> = Vec::new();
    let primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .context("Primary key has no secret material")?;
    packets.push(if primary.secret().is_encrypted() {
        primary
            .decrypt_secret(&pw)
            .context("Failed to decrypt primary key — wrong passphrase?")?
            .into()
    } else {
        primary.into()
    });
    for ka in cert.keys().subkeys().secret() {
        let key = ka
            .key()
            .clone()
            .parts_into_secret()
            .context("Subkey has no secret material")?;
        packets.push(if key.secret().is_encrypted() {
            key.decrypt_secret(&pw)
                .context("Failed to decrypt subkey — wrong passphrase?")?
                .into()
        } else {
            key.into()
        });
    }
    cert.insert_packets(packets)
        .context("Failed to rebuild cert with decrypted secrets")
}

// ── File-permission helpers ───────────────────────────────────────────────────

/// Set a key file to owner-read/write only (0o600).  No-op on non-Unix.
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

/// Set the key store directory to owner-only access (0o700).  No-op on non-Unix.
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

pub fn export_pub(cert: &Cert) -> Result<String> {
    let mut out = Vec::new();
    let mut armor = ArmorWriter::new(&mut out, ArmorKind::PublicKey)?;
    cert.export(&mut armor)?;
    armor.finalize()?;
    Ok(String::from_utf8(out)?)
}

pub fn export_priv(cert: &Cert) -> Result<String> {
    anyhow::ensure!(cert.is_tsk(), "No secret key material available");
    let mut out = Vec::new();
    let mut armor = ArmorWriter::new(&mut out, ArmorKind::SecretKey)?;
    cert.as_tsk().serialize(&mut armor)?;
    armor.finalize()?;
    Ok(String::from_utf8(out)?)
}
