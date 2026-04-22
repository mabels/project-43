pub mod subcmd;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use p43::bus::{self, AuthorityPub, DeviceCert, DeviceCsr, DeviceKey, MsgPayload};
use std::path::{Path, PathBuf};
use subcmd::BusCmd;
use uuid::Uuid;

pub fn run(
    cmd: BusCmd,
    store_dir: &Path,
    soft_key: Option<PathBuf>,
    passphrase: Option<String>,
    pin: Option<String>,
) -> Result<()> {
    let bus_dir = bus::bus_dir(store_dir);
    std::fs::create_dir_all(&bus_dir)?;

    match cmd {
        BusCmd::Init { recipient, force } => cmd_init(&bus_dir, &recipient, force),
        BusCmd::GenKey { label, force } => cmd_gen_key(&bus_dir, label.as_deref(), force),
        BusCmd::GenCsr { label, out } => cmd_gen_csr(&bus_dir, label.as_deref(), out),
        BusCmd::IssueCert {
            csr,
            label,
            ttl,
            out,
            card,
            ident,
        } => cmd_issue_cert(
            &bus_dir,
            csr.as_deref(),
            label.as_deref(),
            Some(ttl),
            out,
            UnlockOpts {
                use_card: card,
                ident: ident.as_deref(),
                soft_key: soft_key.as_deref(),
                passphrase,
                pin,
            },
        ),
        BusCmd::Show { file } => cmd_show(&file),
        BusCmd::ListKeys => cmd_list_keys(&bus_dir),
        BusCmd::ListPeers => cmd_list_peers(&bus_dir),
        BusCmd::Encrypt {
            to,
            device,
            from_cert,
            msg,
            kind,
            out,
        } => cmd_encrypt(
            &bus_dir,
            &to,
            &msg,
            &kind,
            out,
            SenderOpts {
                device: device.as_deref(),
                from_cert: from_cert.as_deref(),
            },
            UnlockOpts {
                use_card: false,
                ident: None,
                soft_key: soft_key.as_deref(),
                passphrase,
                pin,
            },
        ),

        BusCmd::Decrypt { file, device } => cmd_decrypt(
            &bus_dir,
            &file,
            device.as_deref(),
            soft_key.as_deref(),
            passphrase,
            pin,
        ),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

// ── Authority-unlock option bundle ───────────────────────────────────────────
//
// Groups the five authority-unlock parameters into one struct so callers stay
// under clippy's `too_many_arguments` limit of 7.

struct UnlockOpts<'a> {
    use_card: bool,
    ident: Option<&'a str>,
    soft_key: Option<&'a Path>,
    passphrase: Option<String>,
    pin: Option<String>,
}

/// Sender context for `cmd_encrypt`.
struct SenderOpts<'a> {
    device: Option<&'a str>,
    from_cert: Option<&'a Path>,
}

fn resolve_secret(explicit: Option<String>, env_var: &str, prompt: &str) -> Result<String> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var) {
        return Ok(v);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

/// Resolve a device key from `bus_dir/devices/`.
///
/// - If `label` is `Some`, load `devices/<label>.key.cbor` directly.
/// - If `label` is `None`, scan `devices/` for exactly one `*.key.cbor` file
///   and use that.  Errors if zero or more than one device key is found.
fn resolve_device_key(bus_dir: &Path, label: Option<&str>) -> Result<(String, PathBuf, DeviceKey)> {
    if let Some(lbl) = label {
        let path = bus::device_key_path(bus_dir, lbl);
        let key = DeviceKey::load(&path)
            .with_context(|| format!("load device key from {}", path.display()))?;
        return Ok((lbl.to_string(), path, key));
    }

    // Auto-detect: scan devices/ for *.key.cbor files.
    let devices_dir = bus::devices_dir(bus_dir);
    if !devices_dir.exists() {
        bail!(
            "no devices directory found at {}; run `bus gen-key` first",
            devices_dir.display()
        );
    }

    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&devices_dir)
        .with_context(|| format!("read {}", devices_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("cbor") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.ends_with(".key") {
                    let label = stem.trim_end_matches(".key").to_string();
                    candidates.push((label, path));
                }
            }
        }
    }

    match candidates.len() {
        0 => bail!(
            "no device keys found in {}; run `bus gen-key` first",
            devices_dir.display()
        ),
        1 => {
            let (lbl, path) = candidates.remove(0);
            let key = DeviceKey::load(&path)
                .with_context(|| format!("load device key from {}", path.display()))?;
            Ok((lbl, path, key))
        }
        n => {
            let labels: Vec<_> = candidates.iter().map(|(l, _)| l.as_str()).collect();
            bail!(
                "{} device keys found in {}; specify one with --label (or --device): {}",
                n,
                devices_dir.display(),
                labels.join(", ")
            )
        }
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

fn cmd_init(bus_dir: &Path, recipient: &Path, force: bool) -> Result<()> {
    let pub_path = bus::authority_pub_path(bus_dir);
    let enc_path = bus::authority_enc_path(bus_dir);
    let cert_path = bus::authority_cert_path(bus_dir);

    if pub_path.exists() && !force {
        bail!(
            "authority already initialised at {}; use --force to reinitialise",
            pub_path.display()
        );
    }

    let (authority_key, authority_pub, encrypted) =
        p43::bus::authority::generate_and_encrypt(&[recipient])?;

    std::fs::create_dir_all(bus_dir)?;
    authority_pub.save(&pub_path)?;
    std::fs::write(&enc_path, &encrypted)?;

    // Self-issue an authority cert so the authority can act as a bus sender.
    // Construct a synthetic CsrPayload directly from the authority's public keys
    // (no nonce/self-sig verification needed — authority signs its own cert).
    let authority_csr_payload = p43::bus::CsrPayload {
        version: 1,
        label: "authority".to_string(),
        sign_pubkey: authority_pub.ed25519_pub.clone(),
        ecdh_pubkey: authority_pub.x25519_pub.clone(),
        nonce: vec![0u8; 16],
        timestamp: p43::bus::unix_now()?,
    };
    let authority_cert = DeviceCert::issue(&authority_csr_payload, &authority_key, None)?;
    authority_cert.save(&cert_path)?;

    println!("Authority initialised:");
    println!(
        "  fingerprint: {}",
        hex::encode(authority_pub.fingerprint())
    );
    println!("  ed25519_pub: {}", hex::encode(&authority_pub.ed25519_pub));
    println!("  x25519_pub : {}", hex::encode(&authority_pub.x25519_pub));
    println!("  pub.cbor   : {}", pub_path.display());
    println!("  key.enc    : {}", enc_path.display());
    println!("  cert.cbor  : {}", cert_path.display());
    Ok(())
}

// ── gen-key ───────────────────────────────────────────────────────────────────

fn cmd_gen_key(bus_dir: &Path, label: Option<&str>, force: bool) -> Result<()> {
    // Generate the key first so we have the fingerprint available as fallback label.
    let mut key = DeviceKey::generate(label.unwrap_or(""));

    // If no label was given, fall back to the device_id (fingerprint).
    let effective_label = if label.map(|l| !l.is_empty()).unwrap_or(false) {
        label.unwrap().to_string()
    } else {
        key.device_id()
    };

    // Update the label stored inside the key so it's persisted correctly.
    // (`label` is pub on DeviceKey, so no extra constructor needed.)
    key.label = effective_label.clone();

    let key_path = bus::device_key_path(bus_dir, &effective_label);
    if key_path.exists() && !force {
        bail!(
            "device key already exists at {}; use --force to overwrite",
            key_path.display()
        );
    }

    std::fs::create_dir_all(key_path.parent().unwrap())?;
    key.save(&key_path)?;

    println!("Device key generated:");
    println!("  label      : {}", effective_label);
    println!("  device_id  : {}", key.device_id());
    println!("  sign_pubkey: {}", hex::encode(key.sign_pubkey()));
    println!("  ecdh_pubkey: {}", hex::encode(key.ecdh_pubkey()));
    println!("  key        : {}", key_path.display());
    Ok(())
}

// ── gen-csr ───────────────────────────────────────────────────────────────────

fn cmd_gen_csr(bus_dir: &Path, label: Option<&str>, out: Option<PathBuf>) -> Result<()> {
    let (effective_label, _key_path, key) = resolve_device_key(bus_dir, label)?;

    let csr = DeviceCsr::generate(&key)?;
    let out_path = out.unwrap_or_else(|| bus::device_csr_path(bus_dir, &effective_label));
    std::fs::create_dir_all(out_path.parent().unwrap())?;
    csr.save(&out_path)?;

    println!("CSR generated:");
    println!("  label  : {}", csr.payload.label);
    println!("  device : {}", effective_label);
    println!("  nonce  : {}", hex::encode(&csr.payload.nonce));
    println!("  file   : {}", out_path.display());
    println!("  bytes  : {}", csr.cose_bytes.len());
    Ok(())
}

// ── issue-cert ────────────────────────────────────────────────────────────────

fn cmd_issue_cert(
    bus_dir: &Path,
    csr_file: Option<&Path>,
    label: Option<&str>,
    ttl: Option<i64>,
    out: Option<PathBuf>,
    unlock: UnlockOpts<'_>,
) -> Result<()> {
    // Resolve the CSR path: explicit file takes precedence, then --label, then error.
    let csr_path_buf;
    let csr_path: &Path = match (csr_file, label) {
        (Some(f), None) => f,
        (None, Some(lbl)) => {
            csr_path_buf = bus::device_csr_path(bus_dir, lbl);
            &csr_path_buf
        }
        (Some(_), Some(_)) => bail!("specify either CSR_FILE or --label, not both"),
        (None, None) => bail!("provide either a CSR_FILE argument or --label"),
    };

    let enc_path = bus::authority_enc_path(bus_dir);
    let encrypted = std::fs::read(&enc_path)
        .with_context(|| format!("read authority key blob from {}", enc_path.display()))?;

    let authority_key = if let (false, Some(key)) = (unlock.use_card, unlock.soft_key) {
        let phrase = resolve_secret(unlock.passphrase, "YK_PASSPHRASE", "Key passphrase: ")?;
        p43::bus::authority::unlock_soft(&encrypted, key, &phrase)?
    } else {
        let card_pin = resolve_secret(unlock.pin, "YK_PIN", "YubiKey PIN: ")?;
        p43::bus::authority::unlock_card(&encrypted, &card_pin, unlock.ident)?
    };

    let csr_bytes = DeviceCsr::load_bytes(csr_path)?;
    let csr_payload = DeviceCsr::verify(&csr_bytes)?;
    let cert = DeviceCert::issue(&csr_payload, &authority_key, ttl)?;

    let out_path = out.unwrap_or_else(|| bus::peer_cert_path(bus_dir, &cert.payload.device_id));
    cert.save(&out_path)?;

    // Also write the cert into devices/ so `bus encrypt` can find it without --from-cert.
    //
    // When --label was given we know the path directly.  Fall back to scanning
    // devices/ by device_id when the cert was issued from a raw CSR file.
    let own_cert_path = if let Some(lbl) = label {
        let key_path = bus::device_key_path(bus_dir, lbl);
        if key_path.exists() {
            Some(bus::device_cert_path(bus_dir, lbl))
        } else {
            find_own_cert_path(bus_dir, &cert.payload.device_id)
        }
    } else {
        find_own_cert_path(bus_dir, &cert.payload.device_id)
    };
    if let Some(ref own_path) = own_cert_path {
        cert.save(own_path)?;
    }

    println!("Certificate issued:");
    println!("  device_id  : {}", cert.payload.device_id);
    println!("  label      : {}", cert.payload.label);
    println!("  issuer_fp  : {}", hex::encode(&cert.payload.issuer_fp));
    println!("  iat        : {}", cert.payload.iat);
    match cert.payload.exp {
        Some(exp) => println!("  exp        : {}", exp),
        None => println!("  exp        : (never)"),
    }
    println!("  file       : {}", out_path.display());
    if let Some(own_path) = own_cert_path {
        println!("  own cert   : {}", own_path.display());
    }
    Ok(())
}

/// Scan `devices/` for a key whose device_id matches, and return the path
/// where the corresponding cert should be written.
fn find_own_cert_path(bus_dir: &Path, device_id: &str) -> Option<PathBuf> {
    let devices_dir = bus::devices_dir(bus_dir);
    if !devices_dir.exists() {
        return None;
    }
    let entries = std::fs::read_dir(&devices_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("cbor") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.ends_with(".key") {
                    if let Ok(key) = DeviceKey::load(&path) {
                        if key.device_id() == device_id {
                            let label = stem.trim_end_matches(".key");
                            return Some(bus::device_cert_path(bus_dir, label));
                        }
                    }
                }
            }
        }
    }
    None
}

// ── show ──────────────────────────────────────────────────────────────────────

fn cmd_show(file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;

    if let Ok(cert) = DeviceCert::load(file) {
        println!("Type       : DeviceCert (COSE_Sign1)");
        println!("device_id  : {}", cert.payload.device_id);
        println!("label      : {}", cert.payload.label);
        println!("sign_pubkey: {}", hex::encode(&cert.payload.sign_pubkey));
        println!("ecdh_pubkey: {}", hex::encode(&cert.payload.ecdh_pubkey));
        println!("issuer_fp  : {}", hex::encode(&cert.payload.issuer_fp));
        println!("iat        : {}", cert.payload.iat);
        match cert.payload.exp {
            Some(exp) => println!("exp        : {}", exp),
            None => println!("exp        : (never)"),
        }
        println!("bytes      : {}", bytes.len());
        return Ok(());
    }

    if let Ok(csr_payload) = DeviceCsr::verify(&bytes) {
        println!("Type       : DeviceCsr (COSE_Sign1, self-signed)");
        println!("label      : {}", csr_payload.label);
        println!("sign_pubkey: {}", hex::encode(&csr_payload.sign_pubkey));
        println!("ecdh_pubkey: {}", hex::encode(&csr_payload.ecdh_pubkey));
        println!("nonce      : {}", hex::encode(&csr_payload.nonce));
        println!("timestamp  : {}", csr_payload.timestamp);
        println!("bytes      : {}", bytes.len());
        return Ok(());
    }

    bail!(
        "file {} is not a recognised bus CSR or cert",
        file.display()
    );
}

// ── list-keys ─────────────────────────────────────────────────────────────────

fn cmd_list_keys(bus_dir: &Path) -> Result<()> {
    let devices_dir = bus::devices_dir(bus_dir);
    if !devices_dir.exists() {
        println!(
            "No devices directory found at {}; run `bus gen-key` first",
            devices_dir.display()
        );
        return Ok(());
    }

    let mut rows: Vec<(String, String, bool, bool)> = Vec::new(); // (label, device_id, has_cert, has_csr)

    for entry in std::fs::read_dir(&devices_dir)
        .with_context(|| format!("read {}", devices_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if !stem.ends_with(".key") {
            continue;
        }

        let label = stem.trim_end_matches(".key").to_string();
        let key = match DeviceKey::load(&path) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("warn: could not load {}: {}", path.display(), e);
                continue;
            }
        };
        let device_id = key.device_id();
        let has_cert = bus::device_cert_path(bus_dir, &label).exists();
        let has_csr = bus::device_csr_path(bus_dir, &label).exists();
        rows.push((label, device_id, has_cert, has_csr));
    }

    if rows.is_empty() {
        println!("No device keys found in {}", devices_dir.display());
        return Ok(());
    }

    rows.sort_by(|a, b| a.0.cmp(&b.0));

    println!(
        "{:<24}  {:<16}  {:<4}  {:<3}",
        "label", "device_id", "cert", "csr"
    );
    println!("{}", "-".repeat(56));
    for (label, device_id, has_cert, has_csr) in rows {
        println!(
            "{:<24}  {:<16}  {:<4}  {:<3}",
            label,
            device_id,
            if has_cert { "yes" } else { "no" },
            if has_csr { "yes" } else { "no" },
        );
    }
    Ok(())
}

// ── list-peers ────────────────────────────────────────────────────────────────

fn cmd_list_peers(bus_dir: &Path) -> Result<()> {
    let peers_dir = bus_dir.join("peers");
    if !peers_dir.exists() {
        println!("No peers registered.");
        return Ok(());
    }

    let mut found = false;
    for entry in std::fs::read_dir(&peers_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("cbor") {
            if let Ok(cert) = DeviceCert::load(&path) {
                found = true;
                let exp_str = cert
                    .payload
                    .exp
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "(never)".into());
                println!(
                    "{}  {}  exp={}  {}",
                    cert.payload.device_id,
                    cert.payload.label,
                    exp_str,
                    path.display()
                );
            }
        }
    }
    if !found {
        println!("No peer certs found in {}", peers_dir.display());
    }
    Ok(())
}

// ── recipient resolution ──────────────────────────────────────────────────────

/// Resolve `--to` value to a cert file path.
///
/// Accepts:
///   1. The special token `"authority"` → `authority.cert.cbor`.
///   2. A literal file path that already exists on disk.
///   3. A label / device-id — looked up first in `peers/`, then in `devices/`.
fn resolve_recipient_cert(bus_dir: &Path, to: &str) -> Result<PathBuf> {
    // Special token: encrypt to the authority itself.
    if to == "authority" {
        let auth_cert = bus::authority_cert_path(bus_dir);
        if !auth_cert.exists() {
            bail!(
                "authority cert not found at {}; run `bus init` first",
                auth_cert.display()
            );
        }
        return Ok(auth_cert);
    }

    let as_path = PathBuf::from(to);
    if as_path.exists() {
        return Ok(as_path);
    }

    // Try peers/<label>.cert.cbor
    let peer_path = bus::peer_cert_path(bus_dir, to);
    if peer_path.exists() {
        return Ok(peer_path);
    }

    // Try devices/<label>.cert.cbor
    let dev_path = bus::device_cert_path(bus_dir, to);
    if dev_path.exists() {
        return Ok(dev_path);
    }

    bail!(
        "could not resolve recipient {:?}: not a file path, \
         not found in peers/ or devices/",
        to
    )
}

// ── encrypt ───────────────────────────────────────────────────────────────────

fn cmd_encrypt(
    bus_dir: &Path,
    to: &str,
    msg: &str,
    kind: &str,
    out: Option<PathBuf>,
    sender: SenderOpts<'_>,
    unlock: UnlockOpts<'_>,
) -> Result<()> {
    let payload = MsgPayload {
        msg_id: Uuid::new_v4().to_string(),
        timestamp: p43::bus::unix_now()?,
        kind: kind.to_string(),
        body: msg.as_bytes().to_vec(),
    };

    let to_cert_path = resolve_recipient_cert(bus_dir, to)?;
    let recipient_cert = DeviceCert::load(&to_cert_path)?;

    let envelope = if sender.device == Some("authority") {
        // Sender is the authority — unlock AuthorityKey and use authority.cert.cbor.
        let enc_path = bus::authority_enc_path(bus_dir);
        let encrypted = std::fs::read(&enc_path)
            .with_context(|| format!("read authority key blob from {}", enc_path.display()))?;
        let authority_key = if let Some(key) = unlock.soft_key {
            let phrase = resolve_secret(unlock.passphrase, "YK_PASSPHRASE", "Key passphrase: ")?;
            p43::bus::authority::unlock_soft(&encrypted, key, &phrase)?
        } else {
            let card_pin = resolve_secret(unlock.pin, "YK_PIN", "YubiKey PIN: ")?;
            p43::bus::authority::unlock_card(&encrypted, &card_pin, None)?
        };
        let sender_cert_path = sender
            .from_cert
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| bus::authority_cert_path(bus_dir));
        let sender_cert_bytes = std::fs::read(&sender_cert_path)
            .with_context(|| format!("load authority cert from {}", sender_cert_path.display()))?;
        bus::encrypt(
            &authority_key,
            &sender_cert_bytes,
            &recipient_cert.payload,
            &payload,
        )?
    } else {
        // Sender is a regular device key.
        let (effective_label, _key_path, sender_key) = resolve_device_key(bus_dir, sender.device)?;
        let sender_cert_path = sender
            .from_cert
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| bus::device_cert_path(bus_dir, &effective_label));
        let sender_cert_bytes = std::fs::read(&sender_cert_path)
            .with_context(|| format!("load sender cert from {}", sender_cert_path.display()))?;
        bus::encrypt(
            &sender_key,
            &sender_cert_bytes,
            &recipient_cert.payload,
            &payload,
        )?
    };

    match out {
        Some(path) => {
            std::fs::write(&path, &envelope)?;
            println!("Encrypted envelope written to {}", path.display());
        }
        None => {
            println!(
                "{}",
                base64::engine::general_purpose::STANDARD.encode(&envelope)
            );
        }
    }
    Ok(())
}

// ── decrypt ───────────────────────────────────────────────────────────────────

fn cmd_decrypt(
    bus_dir: &Path,
    file: &Path,
    device: Option<&str>,
    soft_key: Option<&Path>,
    passphrase: Option<String>,
    pin: Option<String>,
) -> Result<()> {
    // Load the authority pubkey for sender cert verification.
    let pub_path = bus::authority_pub_path(bus_dir);
    let authority_pub = AuthorityPub::load(&pub_path)
        .with_context(|| format!("load authority pubkey from {}", pub_path.display()))?;
    let authority_sign_pub = authority_pub.ed25519_pub_array()?;

    // Read the envelope.
    let envelope = if file == Path::new("-") {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin().read_to_string(&mut raw)?;
        base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .context("decode base64 envelope from stdin")?
    } else {
        std::fs::read(file).with_context(|| format!("read {}", file.display()))?
    };

    // Resolve the decryptor: authority key or device key.
    let (payload, sender_cert) = if device == Some("authority") {
        let enc_path = bus::authority_enc_path(bus_dir);
        let encrypted = std::fs::read(&enc_path)
            .with_context(|| format!("read authority key blob from {}", enc_path.display()))?;
        let authority_key = if let Some(key) = soft_key {
            let phrase = resolve_secret(passphrase, "YK_PASSPHRASE", "Key passphrase: ")?;
            p43::bus::authority::unlock_soft(&encrypted, key, &phrase)?
        } else {
            let card_pin = resolve_secret(pin, "YK_PIN", "YubiKey PIN: ")?;
            p43::bus::authority::unlock_card(&encrypted, &card_pin, None)?
        };
        bus::decrypt(&authority_key, &envelope, &authority_sign_pub)?
    } else {
        let (_effective_label, _key_path, recipient_key) = resolve_device_key(bus_dir, device)?;
        bus::decrypt(&recipient_key, &envelope, &authority_sign_pub)?
    };

    println!("Decrypted message:");
    println!("  msg_id   : {}", payload.msg_id);
    println!("  kind     : {}", payload.kind);
    println!("  timestamp: {}", payload.timestamp);
    println!(
        "  sender   : {} ({})",
        sender_cert.label, sender_cert.device_id
    );
    println!("  body     : {}", String::from_utf8_lossy(&payload.body));
    Ok(())
}
