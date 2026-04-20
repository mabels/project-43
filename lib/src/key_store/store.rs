use anyhow::{Context, Result};
use openpgp::armor::{Kind as ArmorKind, Writer as ArmorWriter};
use openpgp::crypto::Password;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, SerdeSerialize, Deserialize)]
pub struct KeyEntry {
    pub fingerprint: String,
    pub uid: String,
    pub algo: String,
    pub has_secret: bool,
    /// Application Identifier strings of YubiKeys (or other OpenPGP cards)
    /// that carry the secret key for this entry.  Empty for soft keys.
    /// Populated at read-time from the companion `<fp>.card.json` file;
    /// not stored in `index.json`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub card_idents: Vec<String>,
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

        if cert.is_tsk() {
            let sec_path = self.sec_path(&fp);
            let mut sec_file = fs::File::create(&sec_path)
                .with_context(|| format!("Cannot write secret key to {:?}", sec_path))?;
            let mut armor = ArmorWriter::new(&mut sec_file, ArmorKind::SecretKey)?;
            cert.as_tsk().serialize(&mut armor)?;
            armor.finalize()?;
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

    fn update_index(&self, cert: &Cert) -> Result<()> {
        let fp = cert.fingerprint().to_hex();
        let uid = cert
            .userids()
            .next()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .unwrap_or_default();
        let algo = cert.primary_key().key().pk_algo().to_string();
        let mut entries = self.list().unwrap_or_default();
        entries.retain(|e| e.fingerprint != fp);
        entries.push(KeyEntry {
            fingerprint: fp,
            uid,
            algo,
            has_secret: cert.is_tsk(),
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
