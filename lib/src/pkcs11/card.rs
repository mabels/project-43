use anyhow::{Context, Result};
use card_backend_pcsc::PcscBackend;
use openpgp_card_sequoia::types::KeyType;
use openpgp_card_sequoia::{state::Open, Card};

pub fn list_card() -> Result<()> {
    let backends = PcscBackend::cards(None)
        .context("Failed to list PC/SC cards — is pcscd running?")?;

    let mut found = false;
    for backend in backends {
        found = true;
        let backend = backend.context("Failed to open card backend")?;
        let mut card = Card::<Open>::new(backend).context("Failed to open card")?;
        let mut tx = card.transaction().context("Failed to open transaction")?;

        let aid = tx.application_identifier()
            .context("Failed to read application identifier")?;

        println!("=== OpenPGP Card ===");
        println!("  Ident:   {}", aid.ident());

        if let Ok(name) = tx.cardholder_name() {
            if !name.is_empty() { println!("  Name:    {}", name); }
        }

        if let Ok(fps) = tx.fingerprints() {
            println!("\n  Fingerprints:");
            match fps.signature()  { Some(fp) => println!("    Signing:    {}", hex::encode(fp.as_bytes())), None => println!("    Signing:    (none)") }
            match fps.decryption() { Some(fp) => println!("    Decryption: {}", hex::encode(fp.as_bytes())), None => println!("    Decryption: (none)") }
            match fps.authentication() { Some(fp) => println!("    Auth:       {}", hex::encode(fp.as_bytes())), None => println!("    Auth:       (none)") }
        }

        if let Ok(times) = tx.key_generation_times() {
            println!("\n  Key creation times (unix):");
            if let Some(t) = times.signature()     { println!("    Signing:    {}", t.get()); }
            if let Some(t) = times.decryption()    { println!("    Decryption: {}", t.get()); }
            if let Some(t) = times.authentication(){ println!("    Auth:       {}", t.get()); }
        }

        println!("\n  Algorithm attributes:");
        for kt in [KeyType::Signing, KeyType::Decryption, KeyType::Authentication] {
            if let Ok(algo) = tx.algorithm_attributes(kt) {
                let label = match kt {
                    KeyType::Signing => "Signing", KeyType::Decryption => "Decryption",
                    KeyType::Authentication => "Auth", _ => "Other",
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

    if !found { println!("No OpenPGP cards found."); }
    Ok(())
}

pub fn open_first_card() -> Result<Card<Open>> {
    let mut backends = PcscBackend::cards(None)
        .context("Failed to list PC/SC cards — is pcscd running?")?;
    let backend = backends.next()
        .context("No OpenPGP cards found")?
        .context("Failed to open card backend")?;
    Card::<Open>::new(backend).context("Failed to open card")
}
