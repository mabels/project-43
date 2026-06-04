pub mod subcmd;

use crate::util::hexdump;
use anyhow::Result;
use p43::gate_key::GateKeyStore;
use p43::sync_store::{ChainRef, ChainStore, ChainValidity, FileObjectStore, KeyRef};
use p43::util::resolve_secret;
use serde_bytes::ByteBuf;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use subcmd::ChainCmd;

pub fn run(cmd: ChainCmd, store_dir: &Path) -> Result<()> {
    let obj_store = Arc::new(FileObjectStore::open(store_dir.join("sync-store"))?);
    let chains = ChainStore::new(obj_store.clone());

    match cmd {
        ChainCmd::List { format } => {
            let list = chains.list_chains()?;
            if list.is_empty() {
                eprintln!("(no chains)");
                return Ok(());
            }
            if format.eq_ignore_ascii_case("json") {
                let items: Vec<serde_json::Value> = list
                    .iter()
                    .map(|(c, meta)| {
                        serde_json::json!({
                            "name":     c.name,
                            "chain_id": meta.chain_id_hex(),
                            "last_id":  hex::encode(&*meta.last_id),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                for (c, meta) in &list {
                    println!(
                        "{}  chain_id={}  last_id={}",
                        c.name,
                        meta.chain_id_hex(),
                        hex::encode(&*meta.last_id)
                    );
                }
                eprintln!("\n{} chain(s)", list.len());
            }
        }

        ChainCmd::Show {
            name,
            passphrase,
            full,
        } => {
            let chain = ChainRef::new(&name);
            let root_key = unlock(passphrase, store_dir)?;

            if full {
                // Show chain_id from meta header first.
                if let Some(meta) = chains.meta(&chain)? {
                    println!("chain_id: {}", meta.chain_id_hex());
                    println!("last_id:  {}", hex::encode(&*meta.last_id));
                    println!();
                }
                // If the named chain doesn't exist as a meta ref, the name
                // may be any item id — walk prev links back to the root and
                // resolve the chain from there.
                let resolved_chain = if chains.meta(&chain)?.is_none() {
                    use p43::sync_store::item::ItemEnvelope;
                    use p43::sync_store::ObjectStore;
                    let mut current_name = name.clone();
                    loop {
                        let key = format!("items/{current_name}");
                        match obj_store.get(&key) {
                            Ok(data) => match ItemEnvelope::from_cbor(&data) {
                                Ok(item) => match &item.prev {
                                    None => {
                                        // Found root — chain_id = root.id
                                        break ChainRef::new(item.id.as_hex());
                                    }
                                    Some(prev) => current_name = prev.as_hex(),
                                },
                                Err(_) => {
                                    eprintln!("cannot parse item {current_name}");
                                    return Ok(());
                                }
                            },
                            Err(_) => {
                                eprintln!("item {current_name} not found");
                                return Ok(());
                            }
                        }
                    }
                } else {
                    chain
                };
                let chain = resolved_chain;
                let items = chains.walk_validated(&chain)?;
                if items.is_empty() {
                    eprintln!("chain {name} not found");
                    return Ok(());
                }
                for (i, chain_item) in items.iter().enumerate() {
                    let item = &chain_item.envelope;
                    let valid_marker = if chain_item.validity == ChainValidity::Ok {
                        "✓".to_owned()
                    } else {
                        format!("✗ {:?}", chain_item.validity)
                    };
                    let marker = if i == 0 { "tip" } else { "   " };
                    println!("{marker} [{valid_marker}]");
                    println!("    id       : {}", item.id.as_hex());
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
                    if i + 1 < items.len() {
                        println!();
                    }
                }
            } else {
                match chains.read(&chain, &root_key)? {
                    Some(payload) => hexdump(&payload),
                    None => {
                        // Meta not found — try loading the item directly by id.
                        use p43::sync_store::item::ItemEnvelope;
                        use p43::sync_store::ObjectStore;
                        let item_key = format!("items/{name}");
                        match obj_store.get(&item_key) {
                            Ok(data) => match ItemEnvelope::from_cbor(&data) {
                                Ok(item) => {
                                    eprintln!(
                                        "item  id={} prev={} next={}",
                                        item.id.as_hex(),
                                        item.prev.as_ref().map_or("none".into(), |p| p.as_hex()),
                                        item.next.as_hex()
                                    );
                                    match item.decrypt(&root_key) {
                                        Ok(payload) => hexdump(&payload),
                                        Err(e) => eprintln!("decrypt failed: {e}"),
                                    }
                                }
                                Err(e) => eprintln!("cannot parse item: {e}"),
                            },
                            Err(_) => eprintln!("not found: {name}"),
                        }
                    }
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
            payload,
            id,
            passphrase,
            creator_id,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            let payload_bytes = read_payload(&payload)?;
            let key_ref = direct_key_ref(store_dir)?;
            match id {
                None => {
                    // New chain: chain_id = root.next (SHA-1 of root item's id).
                    let chain_id =
                        chains.create(&root_key, key_ref, &creator_id, &payload_bytes)?;
                    println!("{}", chain_id.as_hex());
                }
                Some(chain_name) => {
                    let chain = ChainRef::new(&chain_name);
                    chains.append(&chain, &root_key, key_ref, &creator_id, &payload_bytes)?;
                }
            }
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
