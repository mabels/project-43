pub mod subcmd;

use anyhow::Result;
use p43::pkcs11::{card, ops, soft_ops};
use std::io::{self, Write};
use std::path::PathBuf;
use subcmd::PgpCmd;

pub fn run(
    cmd: PgpCmd,
    soft_key: Option<PathBuf>,
    passphrase: Option<String>,
    pin: Option<String>,
) -> Result<()> {
    match cmd {
        PgpCmd::List => {
            anyhow::ensure!(
                soft_key.is_none(),
                "'pgp list' shows card info — omit --key-file"
            );
            card::list_card()?;
        }

        PgpCmd::Sign { message, file } => {
            let data = read_input(message, file)?;
            let sig = if let Some(kf) = soft_key {
                soft_ops::sign(&data, &kf, &resolve_passphrase(passphrase)?)?
            } else {
                ops::sign(&data, &resolve_pin(pin)?)?
            };
            print!("{}", sig);
        }

        PgpCmd::Encrypt {
            message,
            file,
            recipient,
        } => {
            let data = read_input(message, file)?;
            print!("{}", ops::encrypt(&data, &recipient)?);
        }

        PgpCmd::Decrypt { file } => {
            let data = read_input(None, file)?;
            let plain = if let Some(kf) = soft_key {
                soft_ops::decrypt(&data, &kf, &resolve_passphrase(passphrase)?)?
            } else {
                ops::decrypt(&data, &resolve_pin(pin)?)?
            };
            io::stdout().write_all(&plain)?;
        }

        PgpCmd::SignEncrypt {
            message,
            file,
            recipient,
        } => {
            let data = read_input(message, file)?;
            let cipher = if let Some(kf) = soft_key {
                soft_ops::sign_encrypt(&data, &kf, &recipient, &resolve_passphrase(passphrase)?)?
            } else {
                ops::sign_encrypt(&data, &recipient, &resolve_pin(pin)?)?
            };
            print!("{}", cipher);
        }

        PgpCmd::Verify { file, sig, signer } => {
            let data = read_input(None, file)?;
            let sig_data = std::fs::read(&sig)?;
            match ops::verify(&data, &sig_data, &signer) {
                Ok(()) => eprintln!("✓ Signature valid"),
                Err(e) => {
                    eprintln!("✗ Signature invalid: {e}");
                    std::process::exit(1);
                }
            }
        }

        PgpCmd::DecryptVerify { file, signer } => {
            let data = read_input(None, file)?;
            let result = if let Some(kf) = soft_key {
                soft_ops::decrypt_verify(&data, &kf, &signer, &resolve_passphrase(passphrase)?)
            } else {
                ops::decrypt_verify(&data, &signer, &resolve_pin(pin)?)
            };
            match result {
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

fn resolve_pin(provided: Option<String>) -> Result<String> {
    if let Some(v) = provided {
        return Ok(v);
    }
    if let Ok(v) = std::env::var("YK_PIN") {
        return Ok(v);
    }
    Ok(rpassword::prompt_password("Card PIN: ")?)
}

fn resolve_passphrase(provided: Option<String>) -> Result<String> {
    if let Some(v) = provided {
        return Ok(v);
    }
    if let Ok(v) = std::env::var("YK_PASSPHRASE") {
        return Ok(v);
    }
    Ok(rpassword::prompt_password("Key passphrase: ")?)
}
