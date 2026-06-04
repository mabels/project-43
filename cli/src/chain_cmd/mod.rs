pub mod subcmd;

use crate::util::hexdump;
use anyhow::Result;
use p43::gate_key::GateKeyStore;
use p43::level2::store::{ChainRef, ChainStore, FileObjectStore, KeyRef};
use p43::util::resolve_secret;
use serde_bytes::ByteBuf;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use subcmd::ChainCmd;

pub fn run(cmd: ChainCmd, store_dir: &Path) -> Result<()> {
    let obj_store = Arc::new(FileObjectStore::open(store_dir.join("level2"))?);
    let chains = ChainStore::new(obj_store);

    match cmd {
        ChainCmd::List => {
            let list = chains.list_chains()?;
            if list.is_empty() {
                eprintln!("(no chains)");
                return Ok(());
            }
            for c in &list {
                println!("{}", c.name);
            }
            eprintln!("\n{} chain(s)", list.len());
        }

        ChainCmd::Show {
            name,
            passphrase,
            full,
        } => {
            let chain = ChainRef::new(&name);
            let root_key = unlock(passphrase, store_dir)?;

            if full {
                let history = chains.history(&chain)?;
                if history.is_empty() {
                    eprintln!("chain {name} not found");
                    return Ok(());
                }
                for (i, item) in history.iter().enumerate() {
                    let marker = if i == 0 { "tip" } else { "   " };
                    println!("{marker} id      : {}", item.id.as_hex());
                    println!("    version  : {}", item.version);
                    println!(
                        "    prev     : {}",
                        item.prev.as_ref().map_or("none".into(), |p| p.as_hex())
                    );
                    println!("    next     : {}", item.next.as_hex());
                    println!("    deleted  : {}", item.deleted);
                    println!("    creator  : {}", item.creator_id);
                    println!("    cid      : {}", hex::encode(&*item.cid));
                    if item.deleted {
                        println!("    payload  : (tombstone)");
                    } else {
                        match item.decrypt(&root_key) {
                            Ok(payload) => {
                                println!("    payload  : {} bytes", payload.len());
                                hexdump(&payload);
                            }
                            Err(e) => println!("    payload  : (decrypt failed: {e})"),
                        }
                    }
                    if i + 1 < history.len() {
                        println!();
                    }
                }
            } else {
                match chains.read(&chain, &root_key)? {
                    None => eprintln!("chain {name} not found or deleted"),
                    Some(payload) => hexdump(&payload),
                }
            }
        }

        ChainCmd::History { name, passphrase } => {
            let chain = ChainRef::new(&name);
            let root_key = unlock(passphrase, store_dir)?;
            let history = chains.history(&chain)?;
            if history.is_empty() {
                eprintln!("(no history)");
                return Ok(());
            }
            for (i, item) in history.iter().enumerate() {
                let label = if i == 0 { "tip " } else { "    " };
                let payload_hex = if item.deleted {
                    "(deleted)".to_owned()
                } else {
                    match item.decrypt(&root_key) {
                        Ok(b) => hex::encode(&b),
                        Err(_) => "(decrypt failed)".to_owned(),
                    }
                };
                println!(
                    "{label} id={}  prev={}  creator={}  payload={}",
                    &item.id.as_hex()[..12],
                    item.prev
                        .as_ref()
                        .map_or("none".into(), |p| p.as_hex()[..12].to_owned()),
                    item.creator_id,
                    payload_hex,
                );
            }
        }

        ChainCmd::Append {
            name,
            payload,
            passphrase,
            creator_id,
        } => {
            let chain = ChainRef::new(&name);
            let root_key = unlock(passphrase, store_dir)?;
            let payload_bytes = read_payload(&payload)?;
            let key_ref = direct_key_ref(store_dir)?;
            let item_id = chains.append(&chain, &root_key, key_ref, &creator_id, &payload_bytes)?;
            println!("appended {}", item_id.as_hex());
        }

        ChainCmd::Delete {
            name,
            passphrase,
            creator_id,
        } => {
            let chain = ChainRef::new(&name);
            let root_key = unlock(passphrase, store_dir)?;
            let key_ref = direct_key_ref(store_dir)?;
            chains.delete(&chain, &root_key, key_ref, &creator_id)?;
            println!("deleted {name}");
        }

        ChainCmd::Gc => {
            let removed = chains.gc()?;
            eprintln!("{removed} orphaned item(s) found");
        }
    }
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

fn read_payload(input: &str) -> Result<Vec<u8>> {
    if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return Ok(buf);
    }
    hex::decode(input).map_err(|e| anyhow::anyhow!("invalid hex payload: {e}"))
}
