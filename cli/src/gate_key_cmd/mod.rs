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
        GateKeyCmd::Create {
            passphrase,
            from_secret,
            m_cost,
            t_cost,
            p_cost,
        } => {
            let pw = resolve_secret(passphrase, "P43_GATE_PASSPHRASE", "Gate-key passphrase: ")?;
            let kdf = KdfParams {
                algorithm: "argon2id".into(),
                salt: p43::gate_key::random_salt(),
                m_cost,
                t_cost,
                p_cost,
            };
            let key = store.create(&pw, kdf, from_secret.as_deref())?;
            if from_secret.is_some() {
                println!("Re-sealed as gate-key: {}", key.key_id);
            } else {
                println!("Created gate-key: {}", key.key_id);
            }
        }

        GateKeyCmd::List => {
            let ids = store.list()?;
            if ids.is_empty() {
                eprintln!("no gate-keys found");
            } else {
                for id in &ids {
                    println!("{id}");
                }
                eprintln!("\n{} gate-key(s)", ids.len());
            }
        }

        GateKeyCmd::Verify {
            passphrase,
            key_id,
            show_secret,
            format,
        } => {
            let pw = resolve_secret(passphrase, "P43_GATE_PASSPHRASE", "Gate-key passphrase: ")?;
            let json_out = format.eq_ignore_ascii_case("json");

            // Build attempt list: either a single key-id or all files.
            let attempts: Vec<(String, Result<p43::gate_key::GateKey>)> = if let Some(id) = key_id {
                vec![(id.clone(), store.try_unlock_by_id(&id, &pw))]
            } else {
                match store.try_unlock_verbose(&pw) {
                    Ok((_, attempts_ok)) => {
                        // try_unlock_verbose returns Result<()> per attempt — re-run
                        // individually to get the GateKey out for show-secret
                        attempts_ok
                            .into_iter()
                            .map(|(id, r)| {
                                let key_result = match r {
                                    Ok(()) => store.try_unlock_by_id(&id, &pw),
                                    Err(e) => Err(e),
                                };
                                (id, key_result)
                            })
                            .collect()
                    }
                    Err(_) => store
                        .list()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|id| {
                            let r = store.try_unlock_by_id(&id, &pw);
                            (id, r)
                        })
                        .collect(),
                }
            };

            let raw_out = format.eq_ignore_ascii_case("raw");

            if raw_out {
                let mut any_ok = false;
                for (_, r) in &attempts {
                    if let Ok(key) = r {
                        any_ok = true;
                        println!("{}", hex::encode(key.as_bytes()));
                    }
                }
                if !any_ok {
                    anyhow::bail!("passphrase did not match any gate-key");
                }
            } else if json_out {
                let entries: Vec<serde_json::Value> = attempts
                    .iter()
                    .map(|(id, r)| match r {
                        Ok(key) => {
                            let mut obj = serde_json::json!({
                                "key_id": id,
                                "ok": true,
                            });
                            if show_secret {
                                obj["secret"] =
                                    serde_json::Value::String(hex::encode(key.as_bytes()));
                            }
                            obj
                        }
                        Err(e) => serde_json::json!({
                            "key_id": id,
                            "ok": false,
                            "error": e.to_string(),
                        }),
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
                                println!("Secret:   {}", hex::encode(key.as_bytes()));
                                eprintln!(
                                    "(pass to `gate-key create --from-secret <hex>` to re-seal)"
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

        GateKeyCmd::ChangePassphrase {
            passphrase,
            new_passphrase,
            m_cost,
            t_cost,
            p_cost,
        } => {
            let old_pw = resolve_secret(passphrase, "P43_GATE_PASSPHRASE", "Current passphrase: ")?;
            let new_pw = resolve_secret(new_passphrase, "", "New passphrase: ")?;
            let new_kdf = KdfParams {
                algorithm: "argon2id".into(),
                salt: p43::gate_key::random_salt(),
                m_cost,
                t_cost,
                p_cost,
            };
            let key_id = store.change_passphrase(&old_pw, &new_pw, new_kdf)?;
            println!("Passphrase changed for gate-key: {key_id}");
        }

        GateKeyCmd::Revoke { key_id, yes } => {
            if !yes {
                eprint!("Revoke gate-key {key_id}? This cannot be undone. [y/N] ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("Aborted.");
                    return Ok(());
                }
            }
            store.revoke(&key_id)?;
            println!("Revoked {key_id}");
        }
    }
    Ok(())
}
