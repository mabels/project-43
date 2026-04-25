//! Import an OpenPGP card's public keys into the key store.
//!
//! The old sequoia-based implementation manually assembled raw MPI packets and
//! self-signed them.  With `openpgp-card-rpgp` 0.7 we delegate that entirely
//! to [`openpgp_card_rpgp::bind_into_certificate`], which reads all three slot
//! public keys off the card, issues the self-signatures (signing-slot PIN
//! required), and returns a complete [`pgp::composed::SignedPublicKey`].

use crate::key_store::store::KeyStore;
use crate::pkcs11::card::{open_card, pin_to_secret};
use anyhow::{Context, Result};
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::{bind_into_certificate, CardSlot};

/// Read all three slot public keys off a connected OpenPGP card, bind them
/// into a self-signed OpenPGP certificate (using the card's signing slot to
/// issue the binding signatures), then import the cert into `ks` and write a
/// `<fingerprint>.card.json` recording the card's AID.
///
/// `card_ident`: if `Some`, selects the card by AID ident string; if `None`,
/// uses the first connected card.  Run `p43 key list-cards` to find idents.
///
/// `uid_override`: if `Some`, used as the cert's UID.  Falls back to the
/// cardholder name stored on the card.  Returns an error if neither is set.
///
/// `pin`: the card's User Signing PIN (unlocks the SIG slot).
pub fn import_card_cert(
    ks: &KeyStore,
    card_ident: Option<&str>,
    uid_override: Option<&str>,
    pin: &str,
) -> Result<()> {
    let mut card = open_card(card_ident)?;
    let mut tx = card
        .transaction()
        .context("Failed to open card transaction")?;

    // ── 1. Read card metadata (before any signing PIN verification) ───────────

    let ident = tx
        .application_identifier()
        .context("Failed to read card AID")?
        .ident();

    let cardholder_name: String = tx
        .cardholder_related_data()
        .ok()
        .and_then(|chd| chd.name().map(|b| String::from_utf8_lossy(b).into_owned()))
        .unwrap_or_default();

    let uid_str: String = match uid_override {
        Some(s) => s.to_owned(),
        None => {
            anyhow::ensure!(
                !cardholder_name.is_empty(),
                "No UID available: set a cardholder name on the card or pass --uid"
            );
            cardholder_name
        }
    };

    // ── 2. Read public keys for all three slots (short-lived borrows) ─────────
    //
    // Each `CardSlot` borrow ends when the block ends, freeing `tx` for the
    // next call.

    // touch_prompt is a no-op here: we're only reading public keys, not
    // performing card signing.  The real touch prompt comes from bind_into_certificate.
    let no_touch: &(dyn Fn() + Send + Sync) = &|| {};

    let sig_pk = CardSlot::init_from_card(&mut tx, KeyType::Signing, no_touch)
        .context("Failed to read signing slot public key")?
        .public_key()
        .clone();

    let dec_pk = CardSlot::init_from_card(&mut tx, KeyType::Decryption, no_touch)
        .ok()
        .map(|s| s.public_key().clone());

    let aut_pk = CardSlot::init_from_card(&mut tx, KeyType::Authentication, no_touch)
        .ok()
        .map(|s| s.public_key().clone());

    let has_dec = dec_pk.is_some();
    let has_aut = aut_pk.is_some();

    // ── 3. Bind into a self-signed certificate ────────────────────────────────
    //
    // `bind_into_certificate` verifies the signing PIN, does the card signing
    // operations to issue UID binding and subkey binding signatures, and
    // returns a complete `SignedPublicKey`.

    let touch_prompt: &(dyn Fn() + Send + Sync) = &|| eprintln!("Touch YubiKey now…");

    let cert = bind_into_certificate(
        &mut tx,
        sig_pk,
        dec_pk,
        aut_pk,
        std::slice::from_ref(&uid_str),
        Some(pin_to_secret(pin)),
        &|| {}, // no pinpad
        touch_prompt,
    )
    .map_err(|e| anyhow::anyhow!("bind_into_certificate failed: {e}"))?;

    // ── 4. Save to key store ──────────────────────────────────────────────────

    use pgp::types::KeyDetails as _;
    let fp = hex::encode(cert.fingerprint().as_bytes());

    ks.save_public(&cert)
        .context("Failed to save cert to key store")?;
    ks.register_card(&fp, &ident)
        .context("Failed to register card AID")?;

    println!("Imported key {fp}");
    println!("  UID:   {uid_str}");
    println!("  Card:  {ident}");
    println!(
        "  Slots: SIG{}{}",
        if has_aut { " + AUTH" } else { "" },
        if has_dec { " + DEC" } else { "" },
    );

    Ok(())
}
