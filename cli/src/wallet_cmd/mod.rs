pub mod subcmd;

use anyhow::Result;
use p43::gate_key::GateKeyStore;
use p43::sync_store::KeyRef;
use p43::util::resolve_secret;
use p43::wallet::KeyCredential;
use p43::wallet::{SshKey, Wallet, WalletPayload, YubikeyRef};
use serde_bytes::ByteBuf;
use std::path::Path;
use subcmd::WalletCmd;

pub fn run(cmd: WalletCmd, store_dir: &Path) -> Result<()> {
    let wallet = Wallet::open(store_dir)?;

    match cmd {
        WalletCmd::List {
            passphrase,
            full,
            full_private,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            let entries_with_ids = wallet.list_with_ids(&root_key)?;
            if entries_with_ids.is_empty() {
                eprintln!("(wallet is empty)");
                return Ok(());
            }

            if full || full_private {
                let show_secrets = full_private;
                let mut items = Vec::new();
                for (e, chain_id) in entries_with_ids.iter() {
                    match wallet.get(&e.fingerprint, &e.kind, &root_key)? {
                        None => {}
                        Some(payload) => {
                            let mut obj = payload_to_json(&payload, show_secrets);
                            obj["chain_id"] = serde_json::Value::String(chain_id.clone());
                            obj["chain_name"] =
                                serde_json::Value::String(format!("{}-{}", e.fingerprint, e.kind));
                            items.push(obj);
                        }
                    }
                }
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                for (i, (e, chain_id)) in entries_with_ids.iter().enumerate() {
                    let chain_name = format!("{}-{}", e.fingerprint, e.kind);
                    println!("{:>3}  {}  {}", i + 1, &chain_id[..12], chain_name);
                }
                eprintln!("\n{} entry/entries", entries_with_ids.len());
            }
        }

        WalletCmd::Get {
            fingerprint,
            kind,
            passphrase,
            show_secrets,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            // Three forms accepted:
            //   "2"                          → index from `wallet list`
            //   "0006_17684870-yubikey-ref"  → full chain name (fingerprint-kind)
            //   "0006_17684870" yubikey-ref  → fingerprint + kind as separate args
            let (resolved_fp, resolved_kind) = if let Ok(idx) = fingerprint.parse::<usize>() {
                let entries = wallet.list_with_ids(&root_key)?;
                let (e, _) = entries
                    .get(idx.saturating_sub(1))
                    .ok_or_else(|| anyhow::anyhow!("index {idx} out of range"))?;
                (
                    e.fingerprint.clone(),
                    kind.unwrap_or_else(|| e.kind.clone()),
                )
            } else if kind.is_none() {
                // Try splitting "fingerprint-kind" on the last known kind suffix.
                use p43::wallet::ChainName;
                let cn = ChainName::from_chain_name(&fingerprint).ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot parse '{}' as a chain name — expected 'fingerprint-kind'",
                        fingerprint
                    )
                })?;
                (cn.fingerprint, cn.kind)
            } else {
                // kind is Some here — is_none() branch handled above
                #[allow(clippy::unnecessary_unwrap)]
                (fingerprint, kind.unwrap())
            };
            match wallet.get(&resolved_fp, &resolved_kind, &root_key)? {
                None => eprintln!("not found: {resolved_fp} / {resolved_kind}"),
                Some(payload) => print_payload(&payload, show_secrets),
            }
        }

        WalletCmd::AddYubikeyRef {
            label,
            card,
            pin,
            passphrase,
            creator_id,
        } => {
            let selected = select_card(card)?;
            let resolved_label = label.unwrap_or_else(|| {
                if selected.cardholder_name.is_empty() {
                    selected.ident.clone()
                } else {
                    selected.cardholder_name.clone()
                }
            });
            let root_key = unlock(passphrase, store_dir)?;
            let pin_val = resolve_secret(pin, "P43_CARD_PIN", "Card PIN: ")?;
            let fingerprint = &selected.ident;
            let payload = WalletPayload::YubikeyRef(YubikeyRef {
                version: 1,
                card_fingerprint: fingerprint.clone(),
                label: resolved_label,
                pin: pin_val,
            });
            wallet.put(
                fingerprint,
                "yubikey-ref",
                &payload,
                &root_key,
                direct_key_ref(store_dir)?,
                &creator_id,
            )?;
            println!("stored yubikey-ref for {fingerprint}");
        }

        WalletCmd::AddSshKey {
            private_key,
            comment,
            passphrase,
            creator_id,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            let priv_bytes = std::fs::read(&private_key)?;
            let mut sk = ssh_key::PrivateKey::from_openssh(&priv_bytes)
                .map_err(|e| anyhow::anyhow!("cannot parse SSH private key: {e}"))?;

            // If key is passphrase-protected, decrypt it so it can be
            // stored plaintext inside the wallet's AES-GCM envelope.
            if sk.is_encrypted() {
                let ssh_pass = rpassword::prompt_password("SSH key passphrase: ")?;
                sk = sk
                    .decrypt(ssh_pass.as_bytes())
                    .map_err(|e| anyhow::anyhow!("SSH key decryption failed: {e}"))?;
            }

            let fingerprint = sk.public_key().fingerprint(Default::default()).to_string();
            let resolved_comment = comment.unwrap_or_else(|| sk.comment().to_owned());

            // Store the decrypted key — the wallet's AES-GCM is the outer protection.
            let decrypted_bytes = sk
                .to_openssh(ssh_key::LineEnding::LF)
                .map_err(|e| anyhow::anyhow!("re-encode key: {e}"))?;

            let payload = WalletPayload::SshKey(SshKey {
                version: 1,
                private_key: ByteBuf::from(decrypted_bytes.as_bytes()),
                comment: resolved_comment,
            });
            wallet.put(
                &fingerprint,
                "ssh-key",
                &payload,
                &root_key,
                direct_key_ref(store_dir)?,
                &creator_id,
            )?;
            println!("stored ssh-key  {fingerprint}");
        }

        WalletCmd::Delete {
            fingerprint,
            kind,
            passphrase,
            creator_id,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            wallet.delete(
                &fingerprint,
                &kind,
                &root_key,
                direct_key_ref(store_dir)?,
                &creator_id,
            )?;
            println!("deleted {fingerprint} / {kind}");
        }
    }
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// List connected cards and return the one to use.
/// If `preferred_ident` is set, selects by AID.
/// If exactly one card is connected, auto-selects it.
/// Otherwise prompts the user to choose.
fn select_card(preferred_ident: Option<String>) -> Result<p43::pkcs11::card::ConnectedCard> {
    let cards = p43::pkcs11::card::list_connected_cards()?;
    anyhow::ensure!(!cards.is_empty(), "no OpenPGP cards connected");

    if let Some(ident) = preferred_ident {
        return cards
            .into_iter()
            .find(|c| c.ident == ident)
            .ok_or_else(|| anyhow::anyhow!("card {ident} not found"));
    }

    if cards.len() == 1 {
        let card = &cards[0];
        eprintln!("Using card: {} ({})", card.ident, card.cardholder_name);
        return Ok(cards.into_iter().next().unwrap());
    }

    // Multiple cards — prompt.
    eprintln!("Connected cards:");
    for (i, c) in cards.iter().enumerate() {
        eprintln!("  {}. {}  {}", i + 1, c.ident, c.cardholder_name);
    }
    eprint!("Select card [1]: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let idx: usize = input.trim().parse().unwrap_or(1);
    anyhow::ensure!(idx >= 1 && idx <= cards.len(), "invalid selection");
    Ok(cards.into_iter().nth(idx - 1).unwrap())
}

fn unlock(passphrase: Option<String>, store_dir: &Path) -> Result<Vec<u8>> {
    let pw = resolve_secret(passphrase, "P43_GATE_PASSPHRASE", "Gate-key passphrase: ")?;
    let gate_store = GateKeyStore::open(&store_dir.join("gate-keys"))?;
    let gate_key = gate_store.try_unlock(&pw)?;
    Ok(gate_key.as_bytes().to_vec())
}

fn direct_key_ref(store_dir: &Path) -> Result<KeyRef> {
    let gate_store = GateKeyStore::open(&store_dir.join("gate-keys"))?;
    let ids = gate_store.list()?;
    anyhow::ensure!(
        !ids.is_empty(),
        "no gate-keys found — run `p43 gate-key create` first"
    );
    let id_bytes = hex::decode(ids[0].trim_start_matches("gate-"))?;
    Ok(KeyRef::Direct {
        gate_key_id: ByteBuf::from(id_bytes),
    })
}

fn payload_to_json(payload: &WalletPayload, show_secrets: bool) -> serde_json::Value {
    match payload {
        WalletPayload::YubikeyRef(r) => serde_json::json!({
            "kind":             "yubikey-ref",
            "card_fingerprint": r.card_fingerprint,
            "label":            r.label,
            "pin":              if show_secrets { r.pin.clone() } else { "****".into() },
        }),
        WalletPayload::SshKey(k) => {
            let pubkey_hex = k
                .pubkey_bytes(p43::wallet::KeySlot::Auth)
                .map(|b| hex::encode(&b))
                .unwrap_or_else(|e| format!("(error: {e})"));
            let mut obj = serde_json::json!({
                "kind":       "ssh-key",
                "comment":    k.comment,
                "public_key": pubkey_hex,
            });
            if show_secrets {
                obj["private_key"] = serde_json::Value::String(hex::encode(&*k.private_key));
            }
            obj
        }
    }
}

fn print_payload(payload: &WalletPayload, show_secrets: bool) {
    match payload {
        WalletPayload::YubikeyRef(r) => {
            println!("kind:              yubikey-ref");
            println!("card_fingerprint:  {}", r.card_fingerprint);
            println!("label:             {}", r.label);
            println!(
                "pin:               {}",
                if show_secrets { &r.pin } else { "****" }
            );
        }
        WalletPayload::SshKey(k) => {
            println!("kind:              ssh-key");
            println!("comment:           {}", k.comment);
            match k.pubkey_bytes(p43::wallet::KeySlot::Auth) {
                Ok(pub_bytes) => println!("public_key:        {}", hex::encode(&pub_bytes)),
                Err(e) => println!("public_key:        (derive failed: {e})"),
            }
            if show_secrets {
                println!("private_key:       {}", hex::encode(&*k.private_key));
            } else {
                println!(
                    "private_key:       ({} bytes, use --show-secrets)",
                    k.private_key.len()
                );
            }
        }
    }
}
