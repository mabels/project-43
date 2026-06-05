pub mod subcmd;

use anyhow::{Context, Result};
#[cfg(feature = "pcsc")]
use p43::wallet::YubikeyRef;
use p43::wallet::{FilePgpKey, PgpCredential, WalletPayload};
use std::io::{self, Write};
use std::path::PathBuf;
use subcmd::PgpCmd;

pub fn run(cmd: PgpCmd, store_dir: &std::path::Path, passphrase: Option<String>) -> Result<()> {
    match cmd {
        PgpCmd::Sign { message, file } => {
            let data = read_input(message, file)?;
            let cred = load_pgp_cred(store_dir, passphrase.as_deref())?;
            let sig = dispatch_sign(&cred, &data)?;
            print!("{sig}");
        }

        PgpCmd::Pubkey => {
            let cred = load_pgp_cred(store_dir, passphrase.as_deref())?;
            let armor = dispatch_pubkey(&cred)?;
            print!("{armor}");
        }

        PgpCmd::Encrypt {
            message,
            file,
            recipient,
        } => {
            let data = read_input(message, file)?;
            // Encrypt only (no signing key needed) — use rPGP directly.
            let cipher = p43::pkcs11::ops::encrypt(&data, &recipient)?;
            print!("{cipher}");
        }

        PgpCmd::Decrypt { file } => {
            let data = read_input(None, file)?;
            let cred = load_pgp_cred(store_dir, passphrase.as_deref())?;
            let plain = dispatch_decrypt(&cred, &data)?;
            io::stdout().write_all(&plain)?;
        }

        PgpCmd::SignEncrypt {
            message,
            file,
            recipient,
        } => {
            let data = read_input(message, file)?;
            let recipient_armor = std::fs::read(&recipient)
                .with_context(|| format!("read recipient {}", recipient.display()))?;
            let cred = load_pgp_cred(store_dir, passphrase.as_deref())?;
            let cipher = dispatch_sign_encrypt(&cred, &data, &recipient_armor)?;
            print!("{cipher}");
        }

        PgpCmd::Verify { file, sig, signer } => {
            let data = read_input(None, file)?;
            let sig_data = std::fs::read(&sig)?;
            // Verification is pure-public — no wallet key needed.
            match p43::pkcs11::ops::verify(&data, &sig_data, &signer) {
                Ok(()) => eprintln!("✓ Signature valid"),
                Err(e) => {
                    eprintln!("✗ Signature invalid: {e}");
                    std::process::exit(1);
                }
            }
        }

        PgpCmd::DecryptVerify { file, signer } => {
            let data = read_input(None, file)?;
            let signer_armor = std::fs::read(&signer)
                .with_context(|| format!("read signer {}", signer.display()))?;
            let cred = load_pgp_cred(store_dir, passphrase.as_deref())?;
            match dispatch_decrypt_verify(&cred, &data, &signer_armor) {
                Ok(plain) => {
                    io::stdout().write_all(&plain)?;
                    eprintln!("\n✓ Signature valid");
                }
                Err(e) => {
                    eprintln!("✗ Decrypt/verify failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

// ── Wallet credential loading ─────────────────────────────────────────────────

/// A resolved PGP credential — either a file key or a YubiKey ref.
enum PgpCred {
    File(FilePgpKey),
    #[cfg(feature = "pcsc")]
    Card(YubikeyRef),
}

fn load_pgp_cred(store_dir: &std::path::Path, passphrase: Option<&str>) -> Result<PgpCred> {
    let wallet = p43::wallet::Wallet::open(store_dir)?;
    let master = unlock_wallet(store_dir, passphrase)?;

    for (cn, _) in wallet.list_with_ids(&master)? {
        let Some(payload) = wallet.get(&cn.fingerprint, &cn.kind, &master)? else {
            continue;
        };
        match payload {
            WalletPayload::PgpKey(k) => return Ok(PgpCred::File(k)),
            WalletPayload::YubikeyRef(r) => {
                #[cfg(feature = "pcsc")]
                return Ok(PgpCred::Card(r));
                #[cfg(not(feature = "pcsc"))]
                {
                    let _ = r;
                }
            }
            _ => continue,
        }
    }
    anyhow::bail!(
        "No PGP credential found in wallet.\n\
         Import one with: p43 wallet add-pgp-key --key-file <key.asc>"
    )
}

fn unlock_wallet(store_dir: &std::path::Path, passphrase: Option<&str>) -> Result<Vec<u8>> {
    let store = p43::gate_key::GateKeyStore::open(store_dir)?;
    anyhow::ensure!(
        !store.list()?.is_empty(),
        "No gate-key configured — run `p43 gate-key create` first"
    );
    let pw = match passphrase {
        Some(p) => p.to_string(),
        None => rpassword::prompt_password("Wallet passphrase: ")?,
    };
    let gate_key = store.try_unlock(&pw)?;
    Ok(gate_key.random.to_vec())
}

// ── Dispatch — routes to FilePgpKey or YubikeyRef impl ───────────────────────

fn dispatch_sign(cred: &PgpCred, data: &[u8]) -> Result<String> {
    match cred {
        PgpCred::File(k) => k.pgp_sign(data),
        #[cfg(feature = "pcsc")]
        PgpCred::Card(r) => r.pgp_sign(data),
    }
}

fn dispatch_pubkey(cred: &PgpCred) -> Result<String> {
    match cred {
        PgpCred::File(k) => k.pgp_pubkey_armored(),
        #[cfg(feature = "pcsc")]
        PgpCred::Card(r) => r.pgp_pubkey_armored(),
    }
}

fn dispatch_decrypt(cred: &PgpCred, data: &[u8]) -> Result<Vec<u8>> {
    match cred {
        PgpCred::File(k) => k.pgp_decrypt(data),
        #[cfg(feature = "pcsc")]
        PgpCred::Card(r) => r.pgp_decrypt(data),
    }
}

fn dispatch_sign_encrypt(cred: &PgpCred, data: &[u8], recipient: &[u8]) -> Result<String> {
    match cred {
        PgpCred::File(k) => k.pgp_sign_encrypt(data, recipient),
        #[cfg(feature = "pcsc")]
        PgpCred::Card(r) => r.pgp_sign_encrypt(data, recipient),
    }
}

fn dispatch_decrypt_verify(cred: &PgpCred, data: &[u8], signer: &[u8]) -> Result<Vec<u8>> {
    match cred {
        PgpCred::File(k) => k.pgp_decrypt_verify(data, signer),
        #[cfg(feature = "pcsc")]
        PgpCred::Card(r) => r.pgp_decrypt_verify(data, signer),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn read_input(message: Option<String>, file: Option<PathBuf>) -> Result<Vec<u8>> {
    use std::io::Read;
    if let Some(msg) = message {
        return Ok(msg.into_bytes());
    }
    if let Some(path) = file {
        return Ok(std::fs::read(path)?);
    }
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}
