pub mod subcmd;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use p43::bus::{
    self, delete_device_key, list_own_devices, list_peers, resolve_device_key,
    resolve_own_device_label, resolve_recipient_cert, AuthorityPub, DeviceCert, DeviceCsr,
    DeviceKey, MsgPayload,
};
use p43::util::resolve_secret;
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
        BusCmd::DeleteKey { label, id, force } => {
            cmd_delete_key(&bus_dir, label.as_deref(), id.as_deref(), force)
        }
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
    let items = list_own_devices(bus_dir)?;
    if items.is_empty() {
        println!(
            "No device keys found in {}",
            bus::devices_dir(bus_dir).display()
        );
        return Ok(());
    }
    println!(
        "{:<24}  {:<16}  {:<4}  {:<3}",
        "label", "device_id", "cert", "csr"
    );
    println!("{}", "-".repeat(56));
    for d in items {
        println!(
            "{:<24}  {:<16}  {:<4}  {:<3}",
            d.label,
            d.device_id,
            if d.has_cert { "yes" } else { "no" },
            if d.has_csr { "yes" } else { "no" },
        );
    }
    Ok(())
}

// ── delete-key ────────────────────────────────────────────────────────────────

fn cmd_delete_key(
    bus_dir: &Path,
    label: Option<&str>,
    id: Option<&str>,
    force: bool,
) -> Result<()> {
    // Resolve first (read-only) so the user sees what will be deleted before
    // we touch the filesystem.
    let resolved = resolve_own_device_label(bus_dir, label, id)?;

    if !force {
        eprint!(
            "Delete device key {:?} and any associated CSR/cert? [y/N] ",
            resolved
        );
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    delete_device_key(bus_dir, &resolved)?;
    println!("Deleted device key: {resolved}");
    Ok(())
}

// ── list-peers ────────────────────────────────────────────────────────────────

fn cmd_list_peers(bus_dir: &Path) -> Result<()> {
    let items = list_peers(bus_dir)?;
    if items.is_empty() {
        println!("No peer certs found.");
        return Ok(());
    }
    println!(
        "{:<16}  {:<24}  {:<12}  expires_at",
        "device_id", "label", "issued_at"
    );
    println!("{}", "-".repeat(68));
    for p in items {
        let exp = p
            .expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "(never)".into());
        println!(
            "{:<16}  {:<24}  {:<12}  {}",
            p.device_id, p.label, p.issued_at, exp
        );
    }
    Ok(())
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

    let body_display = p43::bus::csr::cbor_to_json_pretty(&payload.body)
        .unwrap_or_else(|_| format!("<{} bytes, not valid CBOR>", payload.body.len()));

    println!("Decrypted message:");
    println!("  msg_id   : {}", payload.msg_id);
    println!("  kind     : {}", payload.kind);
    println!("  timestamp: {}", payload.timestamp);
    println!(
        "  sender   : {} ({})",
        sender_cert.label, sender_cert.device_id
    );
    println!("  body     :\n{}", body_display);
    Ok(())
}
