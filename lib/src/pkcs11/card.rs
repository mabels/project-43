use anyhow::{Context, Result};
use card_backend_pcsc::PcscBackend;
use openpgp_card_sequoia::types::KeyType;
use openpgp_card_sequoia::{state::Open, Card};

/// Summary of a connected OpenPGP card, returned by [`list_connected_cards`].
pub struct ConnectedCard {
    pub ident: String,
    pub cardholder_name: String,
    /// Hex fingerprint of the signing slot key, if one is programmed.
    pub sig_fingerprint: Option<String>,
    /// Hex fingerprint of the authentication slot key, if one is programmed.
    pub auth_fingerprint: Option<String>,
}

pub fn list_card() -> Result<()> {
    let backends =
        PcscBackend::cards(None).context("Failed to list PC/SC cards — is pcscd running?")?;

    let mut found = false;
    for backend in backends {
        found = true;
        let backend = backend.context("Failed to open card backend")?;
        let mut card = Card::<Open>::new(backend).context("Failed to open card")?;
        let mut tx = card.transaction().context("Failed to open transaction")?;

        let aid = tx
            .application_identifier()
            .context("Failed to read application identifier")?;

        println!("=== OpenPGP Card ===");
        println!("  Ident:   {}", aid.ident());

        if let Ok(name) = tx.cardholder_name() {
            if !name.is_empty() {
                println!("  Name:    {}", name);
            }
        }

        if let Ok(fps) = tx.fingerprints() {
            println!("\n  Fingerprints:");
            match fps.signature() {
                Some(fp) => println!("    Signing:    {}", hex::encode(fp.as_bytes())),
                None => println!("    Signing:    (none)"),
            }
            match fps.decryption() {
                Some(fp) => println!("    Decryption: {}", hex::encode(fp.as_bytes())),
                None => println!("    Decryption: (none)"),
            }
            match fps.authentication() {
                Some(fp) => println!("    Auth:       {}", hex::encode(fp.as_bytes())),
                None => println!("    Auth:       (none)"),
            }
        }

        if let Ok(times) = tx.key_generation_times() {
            println!("\n  Key creation times (unix):");
            if let Some(t) = times.signature() {
                println!("    Signing:    {}", t.get());
            }
            if let Some(t) = times.decryption() {
                println!("    Decryption: {}", t.get());
            }
            if let Some(t) = times.authentication() {
                println!("    Auth:       {}", t.get());
            }
        }

        println!("\n  Algorithm attributes:");
        for kt in [
            KeyType::Signing,
            KeyType::Decryption,
            KeyType::Authentication,
        ] {
            if let Ok(algo) = tx.algorithm_attributes(kt) {
                let label = match kt {
                    KeyType::Signing => "Signing",
                    KeyType::Decryption => "Decryption",
                    KeyType::Authentication => "Auth",
                    _ => "Other",
                };
                println!("    {}: {}", label, algo);
            }
        }

        if let Ok(pw) = tx.pw_status_bytes() {
            println!("\n  PIN retries remaining:");
            println!("    User PIN:  {}", pw.err_count_pw1());
            println!("    Admin PIN: {}", pw.err_count_pw3());
        }
        println!();
    }

    if !found {
        println!("No OpenPGP cards found.");
    }
    Ok(())
}

/// Return a summary of every connected OpenPGP card (no PIN required).
pub fn list_connected_cards() -> Result<Vec<ConnectedCard>> {
    let backends =
        PcscBackend::cards(None).context("Failed to list PC/SC cards — is pcscd running?")?;
    let mut out = Vec::new();
    for backend in backends {
        let backend = backend.context("Failed to open card backend")?;
        let mut card = Card::<Open>::new(backend).context("Failed to open card")?;
        let mut tx = card.transaction().context("Failed to open transaction")?;

        let ident = tx
            .application_identifier()
            .context("Failed to read AID")?
            .ident();
        let cardholder_name = tx.cardholder_name().unwrap_or_default();
        let (sig_fingerprint, auth_fingerprint) = tx
            .fingerprints()
            .map(|fps| {
                let sig = fps
                    .signature()
                    .map(|fp| hex::encode(fp.as_bytes()).to_uppercase());
                let auth = fps
                    .authentication()
                    .map(|fp| hex::encode(fp.as_bytes()).to_uppercase());
                (sig, auth)
            })
            .unwrap_or((None, None));

        out.push(ConnectedCard {
            ident,
            cardholder_name,
            sig_fingerprint,
            auth_fingerprint,
        });
    }
    Ok(out)
}

pub fn open_first_card() -> Result<Card<Open>> {
    let mut backends =
        PcscBackend::cards(None).context("Failed to list PC/SC cards — is pcscd running?")?;
    let backend = backends
        .next()
        .context("No OpenPGP cards found")?
        .context("Failed to open card backend")?;
    Card::<Open>::new(backend).context("Failed to open card")
}

/// Open a specific card by its AID ident string, or the first card if `ident`
/// is `None`.
pub fn open_card(ident: Option<&str>) -> Result<Card<Open>> {
    let wanted = match ident {
        None => return open_first_card(),
        Some(s) => s,
    };

    let backends =
        PcscBackend::cards(None).context("Failed to list PC/SC cards — is pcscd running?")?;
    for backend in backends {
        let backend = backend.context("Failed to open card backend")?;
        let mut card = Card::<Open>::new(backend).context("Failed to open card")?;
        {
            let tx = card.transaction().context("Failed to open transaction")?;
            let aid_ident = tx
                .application_identifier()
                .context("Failed to read AID")?
                .ident();
            if aid_ident != wanted {
                continue;
            }
        }
        return Ok(card);
    }
    anyhow::bail!("No connected card with ident '{}'", wanted)
}
