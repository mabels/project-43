pub mod subcmd;

use anyhow::Result;
use p43::gate_key::{GateKeyStore, KdfParams};
use p43::util::resolve_secret;
use std::path::Path;
use subcmd::GateKeyCmd;

pub fn run(cmd: GateKeyCmd, store_dir: &Path) -> Result<()> {
    let gate_dir = store_dir.join("gate-keys");
    let store = GateKeyStore::open(&gate_dir)?;

    match cmd {
        // ── Create (first-time setup) ─────────────────────────────────────────
        GateKeyCmd::Create {
            passphrase,
            m_cost,
            t_cost,
            p_cost,
        } => {
            anyhow::ensure!(
                store.list()?.is_empty(),
                "gate-keys already exist — use `add-passphrase` to add more"
            );
            let pw = resolve_secret(passphrase, "P43_GATE_PASSPHRASE", "Master passphrase: ")?;
            let kdf = kdf(m_cost, t_cost, p_cost);
            let key = store.create(&pw, kdf, None)?;
            println!("Created gate-key: {}", key.key_id);
            eprintln!("(add biometric lock: `gate-key verify --show-secret` then store the hex in your OS secure enclave)");
        }

        // ── Add another passphrase seal ───────────────────────────────────────
        GateKeyCmd::AddPassphrase {
            passphrase,
            new_passphrase,
            m_cost,
            t_cost,
            p_cost,
        } => {
            let pw = resolve_secret(
                passphrase,
                "P43_GATE_PASSPHRASE",
                "Existing passphrase (proves ownership): ",
            )?;
            let master_key = store.try_unlock(&pw).map_err(|_| {
                anyhow::anyhow!("existing passphrase is wrong — cannot add new seal")
            })?;
            let new_pw = resolve_secret(new_passphrase, "", "New passphrase: ")?;
            let master_hex = hex::encode(master_key.as_bytes());
            let kdf = kdf(m_cost, t_cost, p_cost);
            let new_key = store.create(&new_pw, kdf, Some(&master_hex))?;
            println!("Added seal: {}", new_key.key_id);
        }

        // ── List ──────────────────────────────────────────────────────────────
        GateKeyCmd::List => {
            let ids = store.list()?;
            if ids.is_empty() {
                eprintln!("no gate-keys found");
            } else {
                for id in &ids {
                    println!("{id}");
                }
                eprintln!("\n{} seal(s)", ids.len());
            }
        }

        // ── Verify ────────────────────────────────────────────────────────────
        GateKeyCmd::Verify {
            passphrase,
            key_id,
            show_secret,
            format,
        } => {
            let pw = resolve_secret(passphrase, "P43_GATE_PASSPHRASE", "Gate-key passphrase: ")?;
            let json_out = format.eq_ignore_ascii_case("json");

            let attempts: Vec<(String, Result<p43::gate_key::GateKey>)> = if let Some(id) = key_id {
                vec![(id.clone(), store.try_unlock_by_id(&id, &pw))]
            } else {
                match store.try_unlock_verbose(&pw) {
                    Ok((_, attempts_ok)) => attempts_ok
                        .into_iter()
                        .map(|(id, r)| {
                            let key_result = match r {
                                Ok(()) => store.try_unlock_by_id(&id, &pw),
                                Err(e) => Err(e),
                            };
                            (id, key_result)
                        })
                        .collect(),
                    Err(_) => store
                        .list()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|id| (id.clone(), store.try_unlock_by_id(&id, &pw)))
                        .collect(),
                }
            };

            if json_out {
                let entries: Vec<serde_json::Value> = attempts
                    .iter()
                    .map(|(id, r)| match r {
                        Ok(key) => {
                            let mut obj = serde_json::json!({ "key_id": id, "ok": true });
                            if show_secret {
                                obj["secret"] =
                                    serde_json::Value::String(hex::encode(key.as_bytes()));
                            }
                            obj
                        }
                        Err(e) => {
                            serde_json::json!({ "key_id": id, "ok": false, "error": e.to_string() })
                        }
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut any_ok = false;
                for (id, r) in &attempts {
                    match r {
                        Ok(key) => {
                            any_ok = true;
                            eprintln!("  ✓ {id}");
                            if show_secret {
                                println!("Secret: {}", hex::encode(key.as_bytes()));
                                eprintln!(
                                    "(store this in your OS secure enclave for biometric unlock)"
                                );
                            }
                        }
                        Err(e) => eprintln!("  ✗ {id}  ({e})"),
                    }
                }
                if !any_ok {
                    anyhow::bail!("passphrase did not match any gate-key");
                }
            }
        }

        // ── Revoke ────────────────────────────────────────────────────────────
        GateKeyCmd::Revoke { key_id, passphrase } => {
            let all = store.list()?;
            anyhow::ensure!(
                all.len() >= 2,
                "cannot revoke — only one seal remains (revoking it would lock you out)"
            );
            anyhow::ensure!(all.contains(&key_id), "key-id {key_id} not found");

            // Prove ownership with a DIFFERENT working key.
            let pw = resolve_secret(
                passphrase,
                "P43_GATE_PASSPHRASE",
                "Passphrase (must be for a different seal): ",
            )?;
            let unlocked = store
                .try_unlock(&pw)
                .map_err(|_| anyhow::anyhow!("passphrase is wrong"))?;

            // The unlocked key_id must differ from the target.
            anyhow::ensure!(
                unlocked.key_id != key_id,
                "cannot use the same seal you are revoking — unlock with a different seal first"
            );

            store.revoke(&key_id)?;
            println!("Revoked {key_id}");
        }
    }
    Ok(())
}

fn kdf(m_cost: u32, t_cost: u32, p_cost: u32) -> KdfParams {
    KdfParams {
        algorithm: "argon2id".into(),
        salt: p43::gate_key::random_salt(),
        m_cost,
        t_cost,
        p_cost,
    }
}
