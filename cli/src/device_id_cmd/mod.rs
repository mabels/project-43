pub mod subcmd;

use anyhow::{Context, Result};
use base64::Engine as _;
use p43::bus::{DeviceCsr, DeviceKey};
use p43::gate_key::GateKeyStore;
use p43::matrix::{client as mx_client, listen, resolve_room_id, send_message, MatrixConfig};
use p43::protocol::{BusCertResponse, BusCsrRequest, Message};
use p43::sync_store::KeyRef;
use p43::util::resolve_secret;
use p43::wallet::{CertifiedDeviceIdPayload, DeviceIdPayload, Wallet, WalletPayload};
use serde_bytes::ByteBuf;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use subcmd::DeviceIdCmd;

pub fn run(cmd: DeviceIdCmd, store_dir: &Path) -> Result<()> {
    // Async commands need a runtime.
    if let DeviceIdCmd::Register { .. } = &cmd {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return rt.block_on(do_register(cmd, store_dir));
    }

    match cmd {
        // ── Create ────────────────────────────────────────────────────────────
        DeviceIdCmd::Create { label, passphrase } => {
            let root_key = unlock(passphrase, store_dir)?;
            let wallet = Wallet::open(store_dir)?;

            let key = DeviceKey::generate(&label);
            let (ed, x) = key.to_scalars();
            let device_id = key.device_id();

            let payload = WalletPayload::DeviceId(DeviceIdPayload {
                version: 1,
                label: label.clone(),
                ed25519_scalar: ByteBuf::from(ed.to_vec()),
                x25519_scalar: ByteBuf::from(x.to_vec()),
                device_id: device_id.clone(),
            });

            wallet.put(
                &device_id,
                "device-id",
                &payload,
                &root_key,
                direct_key_ref(store_dir)?,
                "cli",
            )?;

            println!("created device-id  {device_id}  ({label})");
            eprintln!("Run `p43 device-id csr` to generate a CSR for the authority.");
        }

        // ── List ──────────────────────────────────────────────────────────────
        DeviceIdCmd::List { passphrase } => {
            let root_key = unlock(passphrase, store_dir)?;
            let wallet = Wallet::open(store_dir)?;
            let entries = wallet.list_with_ids(&root_key)?;
            let device_entries: Vec<_> = entries
                .iter()
                .filter(|(cn, _)| cn.kind == "device-id" || cn.kind == "certified-device-id")
                .collect();

            if device_entries.is_empty() {
                eprintln!("(no device identities — run `p43 device-id create --label <name>`)");
                return Ok(());
            }

            for (cn, _chain_id) in &device_entries {
                let marker = if cn.kind == "certified-device-id" {
                    "✓"
                } else {
                    " "
                };
                let label = wallet
                    .get(&cn.fingerprint, &cn.kind, &root_key)?
                    .and_then(|p| match p {
                        WalletPayload::DeviceId(d) => Some(d.label),
                        WalletPayload::CertifiedDeviceId(d) => Some(d.label),
                        _ => None,
                    })
                    .unwrap_or_default();
                println!("{marker}  {}  {}  [{}]", cn.fingerprint, label, cn.kind);
            }
        }

        // ── CSR ───────────────────────────────────────────────────────────────
        DeviceIdCmd::Csr {
            device_id,
            passphrase,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            let wallet = Wallet::open(store_dir)?;

            let (fp, payload) =
                resolve_device_id(&wallet, &root_key, device_id.as_deref(), "device-id")?;
            let d = match payload {
                WalletPayload::DeviceId(d) => d,
                _ => anyhow::bail!("{fp} is already certified — no CSR needed"),
            };

            let key = DeviceKey::from_scalars(&d.label, &d.ed25519_scalar, &d.x25519_scalar)?;
            let csr = DeviceCsr::generate(&key)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&csr.cose_bytes);
            println!("{b64}");
            eprintln!("(Send this to the authority, then run `p43 device-id certify --device-id {fp} --cert <file>`)");
        }

        // ── Show ──────────────────────────────────────────────────────────────
        DeviceIdCmd::Show {
            device_id,
            passphrase,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            let wallet = Wallet::open(store_dir)?;

            // Accept either device-id or certified-device-id.
            let (fp, payload) = resolve_device_id_any(&wallet, &root_key, device_id.as_deref())?;

            match &payload {
                WalletPayload::DeviceId(d) => {
                    println!("kind:        device-id (pending certification)");
                    println!("device_id:   {}", d.device_id);
                    println!("label:       {}", d.label);
                    let key =
                        DeviceKey::from_scalars(&d.label, &d.ed25519_scalar, &d.x25519_scalar)?;
                    println!("sign_pubkey: {}", hex::encode(key.sign_pubkey()));
                    println!("ecdh_pubkey: {}", hex::encode(key.ecdh_pubkey()));
                }
                WalletPayload::CertifiedDeviceId(d) => {
                    println!("kind:        certified-device-id ✓");
                    println!("device_id:   {}", d.device_id);
                    println!("label:       {}", d.label);
                    let key =
                        DeviceKey::from_scalars(&d.label, &d.ed25519_scalar, &d.x25519_scalar)?;
                    println!("sign_pubkey: {}", hex::encode(key.sign_pubkey()));
                    println!("ecdh_pubkey: {}", hex::encode(key.ecdh_pubkey()));
                    println!("cert_bytes:  {} bytes", d.cert_bytes.len());
                }
                _ => anyhow::bail!("{fp} is not a device identity"),
            }
        }

        // ── Register — handled above as async ─────────────────────────────────
        DeviceIdCmd::Register { .. } => unreachable!(),

        // ── Certify ───────────────────────────────────────────────────────────
        DeviceIdCmd::Certify {
            device_id,
            cert,
            passphrase,
        } => {
            let root_key = unlock(passphrase, store_dir)?;
            let wallet = Wallet::open(store_dir)?;

            let (fp, payload) =
                resolve_device_id(&wallet, &root_key, Some(&device_id), "device-id")?;
            let d = match payload {
                WalletPayload::DeviceId(d) => d,
                _ => anyhow::bail!("{fp} is already certified"),
            };

            // Read and base64-decode the cert.
            let cert_b64 = read_file_or_stdin(&cert)?;
            let cert_bytes = base64::engine::general_purpose::STANDARD
                .decode(cert_b64.trim())
                .context("decode base64 cert")?;

            // Verify the cert belongs to this device (sanity check).
            let key = DeviceKey::from_scalars(&d.label, &d.ed25519_scalar, &d.x25519_scalar)?;
            let sign_pub = key.sign_pubkey();
            // Parse cert and check sign_pubkey matches.
            let cert_parsed = p43::bus::DeviceCert::load_from_bytes(cert_bytes.clone())?;
            anyhow::ensure!(
                cert_parsed.payload.sign_pubkey.as_slice() == sign_pub.as_slice(),
                "cert sign_pubkey does not match this device identity"
            );

            // Tombstone the old device-id chain.
            wallet.delete(
                &fp,
                "device-id",
                &root_key,
                direct_key_ref(store_dir)?,
                "cli",
            )?;

            // Write the certified-device-id chain.
            let new_payload = WalletPayload::CertifiedDeviceId(CertifiedDeviceIdPayload {
                version: 1,
                label: d.label.clone(),
                ed25519_scalar: d.ed25519_scalar.clone(),
                x25519_scalar: d.x25519_scalar.clone(),
                device_id: d.device_id.clone(),
                cert_bytes: ByteBuf::from(cert_bytes),
            });
            wallet.put(
                &fp,
                "certified-device-id",
                &new_payload,
                &root_key,
                direct_key_ref(store_dir)?,
                "cli",
            )?;

            println!("certified  {fp}  ({}) ✓", d.label);
        }
    }
    Ok(())
}

// ── register (async) ─────────────────────────────────────────────────────────

async fn do_register(cmd: DeviceIdCmd, store_dir: &Path) -> Result<()> {
    let DeviceIdCmd::Register {
        room,
        device_id,
        passphrase,
        timeout,
    } = cmd
    else {
        unreachable!()
    };

    let root_key = unlock(passphrase, store_dir)?;
    let wallet = Wallet::open(store_dir)?;

    // Accept both device-id (fresh) and certified-device-id (re-registration).
    let (fp, current_kind, label, device_id_hex, ed_scalar, x_scalar) = {
        let (fp, payload) = resolve_device_id_any(&wallet, &root_key, device_id.as_deref())?;
        match payload {
            WalletPayload::DeviceId(d) => (
                fp,
                "device-id",
                d.label,
                d.device_id,
                d.ed25519_scalar,
                d.x25519_scalar,
            ),
            WalletPayload::CertifiedDeviceId(d) => {
                eprintln!("Re-registering already-certified device {}…", d.device_id);
                (
                    fp,
                    "certified-device-id",
                    d.label,
                    d.device_id,
                    d.ed25519_scalar,
                    d.x25519_scalar,
                )
            }
            _ => anyhow::bail!("{fp} is not a device identity"),
        }
    };

    let key = DeviceKey::from_scalars(&label, &ed_scalar, &x_scalar)?;
    let csr = DeviceCsr::generate(&key)?;
    let request_id = uuid::Uuid::new_v4().to_string();

    let msg = Message::BusCsrRequest(BusCsrRequest {
        request_id: request_id.clone(),
        device_label: label.clone(),
        device_id: device_id_hex.clone(),
        csr_b64: base64::engine::general_purpose::STANDARD.encode(&csr.cose_bytes),
    });

    // Connect to Matrix (must already be logged in).
    let cfg = MatrixConfig::from_store_dir(store_dir);
    let client = mx_client::restore(&cfg)
        .await?
        .context("No Matrix session — run `p43 matrix login` first")?;

    // Resolve room: CLI arg → saved agent room → error.
    let room_str = match room {
        Some(r) => r,
        None => mx_client::load_config(&cfg.config_path)?
            .and_then(|c| c.agent_room)
            .context("No agent room configured. Pass --room or set one in the UI (Agent tab).")?,
    };
    let room_id = resolve_room_id(&client, &room_str).await?;

    // Send the CSR.
    send_message(&client, &room_id, &msg.to_json()?).await?;
    eprintln!("CSR sent for device {} ({}).", device_id_hex, label);
    eprintln!("Waiting for authority response (timeout: {timeout}s)…");

    // Listen for the matching BusCertResponse.
    // Use a oneshot to signal the listener to stop as soon as the cert arrives.
    let (tx, mut rx) = tokio::sync::oneshot::channel::<BusCertResponse>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let req_id = request_id.clone();
    let dev_id = device_id_hex.clone();

    // Sync from "now" so we only see new messages.
    let initial_token = {
        let sync = client
            .sync_once(
                matrix_sdk::config::SyncSettings::default().timeout(std::time::Duration::ZERO),
            )
            .await?;
        Some(sync.next_batch)
    };

    let listen_fut = listen(
        &client,
        &room_id,
        initial_token.as_deref(),
        move |_sender, body, _ts, _event_id| {
            if let Ok(Message::BusCertResponse(resp)) = Message::from_json(&body) {
                if resp.request_id == req_id && resp.device_id == dev_id {
                    if let Ok(mut guard) = tx.lock() {
                        if let Some(sender) = guard.take() {
                            let _ = sender.send(resp);
                        }
                    }
                }
            }
        },
        |_token| {},
    );

    // Race: cert arrives (rx), timeout, or listen error.
    let resp = tokio::select! {
        biased;
        r = &mut rx => {
            r.context("internal channel error")?
        }
        result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout), listen_fut
        ) => {
            match result {
                Err(_) => anyhow::bail!(
                    "Timed out after {timeout}s — authority may not be listening or room is wrong."
                ),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(_)) => anyhow::bail!("Listener exited before receiving a cert response"),
            }
        }
    };

    // Decode and verify the cert.
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(&resp.cert_b64)
        .context("decode cert base64")?;
    let cert = p43::bus::DeviceCert::load_from_bytes(cert_bytes.clone())?;
    let sign_pub = key.sign_pubkey();
    anyhow::ensure!(
        cert.payload.sign_pubkey.as_slice() == sign_pub.as_slice(),
        "cert sign_pubkey does not match this device identity"
    );

    // Tombstone the current chain (device-id or certified-device-id) and
    // write the new certified-device-id.
    wallet.delete(
        &fp,
        current_kind,
        &root_key,
        direct_key_ref(store_dir)?,
        "cli",
    )?;
    let new_payload = WalletPayload::CertifiedDeviceId(CertifiedDeviceIdPayload {
        version: 1,
        label: label.clone(),
        ed25519_scalar: ed_scalar,
        x25519_scalar: x_scalar,
        device_id: device_id_hex.clone(),
        cert_bytes: ByteBuf::from(cert_bytes),
    });
    wallet.put(
        &fp,
        "certified-device-id",
        &new_payload,
        &root_key,
        direct_key_ref(store_dir)?,
        "cli",
    )?;

    println!("✓  Device {} ({}) certified.", device_id_hex, label);
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

/// Resolve a `device-id` or `certified-device-id` entry by hex fingerprint
/// (or auto-select if exactly one of `kind` exists).
fn resolve_device_id(
    wallet: &Wallet,
    root_key: &[u8],
    device_id: Option<&str>,
    kind: &str,
) -> Result<(String, WalletPayload)> {
    let entries = wallet.list_with_ids(root_key)?;
    let matches: Vec<_> = entries.iter().filter(|(cn, _)| cn.kind == kind).collect();

    let fp = if let Some(id) = device_id {
        id.to_string()
    } else if matches.len() == 1 {
        matches[0].0.fingerprint.clone()
    } else {
        anyhow::bail!(
            "multiple {kind} entries — specify --device-id. Run `p43 device-id list` to see them."
        );
    };

    let payload = wallet
        .get(&fp, kind, root_key)?
        .ok_or_else(|| anyhow::anyhow!("no {kind} entry with device_id {fp}"))?;
    Ok((fp, payload))
}

/// Like `resolve_device_id` but accepts either `device-id` or `certified-device-id`.
fn resolve_device_id_any(
    wallet: &Wallet,
    root_key: &[u8],
    device_id: Option<&str>,
) -> Result<(String, WalletPayload)> {
    // Try device-id first, then certified-device-id.
    if let Some(id) = device_id {
        if let Ok(Some(payload)) = wallet.get(id, "device-id", root_key) {
            return Ok((id.to_string(), payload));
        }
        if let Ok(Some(payload)) = wallet.get(id, "certified-device-id", root_key) {
            return Ok((id.to_string(), payload));
        }
        anyhow::bail!("no device identity with device_id {id}");
    }

    let entries = wallet.list_with_ids(root_key)?;
    let device_entries: Vec<_> = entries
        .iter()
        .filter(|(cn, _)| cn.kind == "device-id" || cn.kind == "certified-device-id")
        .collect();

    match device_entries.len() {
        0 => anyhow::bail!("no device identities in wallet"),
        1 => {
            let (cn, _) = device_entries[0];
            let payload = wallet
                .get(&cn.fingerprint, &cn.kind, root_key)?
                .ok_or_else(|| anyhow::anyhow!("wallet entry disappeared"))?;
            Ok((cn.fingerprint.clone(), payload))
        }
        _ => anyhow::bail!("multiple device identities — specify a device_id"),
    }
}

fn read_file_or_stdin(path: &Path) -> Result<String> {
    if path.to_str() == Some("-") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
    }
}
