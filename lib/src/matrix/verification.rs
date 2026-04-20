use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use matrix_sdk::{
    encryption::verification::{SasState, SasVerification, VerificationRequest},
    ruma::events::key::verification::{
        request::ToDeviceKeyVerificationRequestEvent, VerificationMethod,
    },
    Client,
};
use std::{
    io::{self, Write},
    sync::Arc,
};
use tokio::sync::Mutex;

// ── EmojiItem ─────────────────────────────────────────────────────────────────

/// A single emoji from an SAS verification exchange.
pub struct EmojiItem {
    pub symbol: String,
    pub description: String,
}

// ── verify_own_device ─────────────────────────────────────────────────────────

/// Wait for an incoming SAS emoji verification request from another session
/// (typically Element) and walk through the confirmation loop.
///
/// # Flow (accepting side)
///
/// 1. Register an event handler that captures the first
///    `m.key.verification.request` to-device event sent by our own user.
/// 2. Accept it with SasV1.
/// 3. Wait for `Ready` then start the SAS flow (or handle it if the other side
///    already started it via `Transitioned`).
/// 4. Show the seven verification emojis and ask the user to confirm.
/// 5. Confirm or abort, then wait for `Done`.
///
/// A background sync loop must be running while this is in progress (see the
/// CLI caller which uses `LocalSet` + `spawn_local`).
///
/// # Interactive
///
/// Prints seven verification emojis to stderr and reads one line from stdin.
/// Type `y` to confirm, anything else cancels.
pub async fn verify_own_device(client: &Client) -> Result<()> {
    let own_user_id = client.user_id().context("Not logged in")?.to_owned();

    // ── Capture the incoming request via an event handler ─────────────────
    // The oneshot channel carries the VerificationRequest once it arrives.
    let (tx, rx) = tokio::sync::oneshot::channel::<VerificationRequest>();
    let tx_slot: Arc<Mutex<Option<tokio::sync::oneshot::Sender<VerificationRequest>>>> =
        Arc::new(Mutex::new(Some(tx)));

    client.add_event_handler({
        let tx_slot = tx_slot.clone();
        let own_user = own_user_id.clone();
        move |ev: ToDeviceKeyVerificationRequestEvent, client: Client| {
            let tx_slot = tx_slot.clone();
            let own_user = own_user.clone();
            async move {
                // Only accept self-verification requests.
                if ev.sender != own_user {
                    return;
                }

                let flow_id = ev.content.transaction_id.as_str().to_owned();

                // The SDK's OlmMachine processes the event before event handlers
                // run, so `get_verification_request` should already have it.
                if let Some(request) = client
                    .encryption()
                    .get_verification_request(&ev.sender, &flow_id)
                    .await
                {
                    let mut guard = tx_slot.lock().await;
                    if let Some(sender) = guard.take() {
                        let _ = sender.send(request);
                    }
                }
            }
        }
    });

    eprintln!("Waiting for a verification request (120 s timeout)…");
    eprintln!("In Element: Settings → Security & Privacy → find this device → Verify");

    // ── Wait for the request ───────────────────────────────────────────────
    let request = tokio::time::timeout(tokio::time::Duration::from_secs(120), rx)
        .await
        .context("Timed out after 120 s — no verification request received")?
        .context("Internal channel closed")?;

    eprintln!("Request received — accepting with SAS…");

    // ── Accept ─────────────────────────────────────────────────────────────
    request
        .accept_with_methods(vec![VerificationMethod::SasV1])
        .await
        .context("Failed to accept verification request")?;

    // ── Get the SAS object ─────────────────────────────────────────────────
    // After we accept, either:
    //   (a) the request moves to Ready and we call start_sas(), or
    //   (b) the other side starts SAS first → Transitioned.
    // handle_ready_or_transitioned covers both cases.
    let sas = wait_for_sas(&request).await?;
    eprintln!("SAS started — key exchange in progress…");

    // ── Show emojis and ask the user ───────────────────────────────────────
    let confirmed = run_emoji_confirmation(&sas).await?;

    if confirmed {
        sas.confirm()
            .await
            .context("Failed to send SAS confirmation")?;
        eprintln!("Confirmation sent — waiting for the other side…");
    } else {
        sas.mismatch()
            .await
            .context("Failed to send SAS mismatch signal")?;
        bail!("Verification cancelled: emojis did not match.");
    }

    // ── Wait for Done ──────────────────────────────────────────────────────
    wait_for_done(&sas).await?;
    eprintln!("✓ Verification complete.  Device is now verified.");
    Ok(())
}

// ── State-machine helpers ─────────────────────────────────────────────────────

/// Poll until `Ready`, then call `start_sas()`.
///
/// We avoid relying on `request.changes()` here because the `Ready` state
/// can fire before we subscribe to that hot stream (e.g. if `accept_with_methods`
/// returned and the homeserver round-trip already completed).  Polling
/// `is_ready()` / `is_done()` / `is_cancelled()` is always safe and the
/// `sleep` yields to the background sync task on each iteration.
async fn wait_for_sas(request: &VerificationRequest) -> Result<SasVerification> {
    loop {
        if request.is_done() {
            bail!("Verification request reached Done before SAS started.")
        }
        if request.is_cancelled() {
            let reason = request
                .cancel_info()
                .map(|i| i.reason().to_owned())
                .unwrap_or_else(|| "unknown".into());
            bail!("Verification request cancelled: {reason}")
        }
        if request.is_ready() {
            // Both sides ready — we start SAS.
            return request
                .start_sas()
                .await
                .context("Failed to start SAS after Ready")?
                .context("start_sas() returned None — no shared SAS method?");
        }
        // Yield to let the background sync task run.
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

/// Poll `sas.state()` until `KeysExchanged`, then show emojis.
///
/// Same reasoning as `wait_for_sas`: `changes()` is a hot stream and
/// `KeysExchanged` can fire between `start_sas()` returning and us
/// subscribing.  Polling is reliable; the `sleep` yields to the sync task.
async fn run_emoji_confirmation(sas: &SasVerification) -> Result<bool> {
    loop {
        match sas.state() {
            SasState::KeysExchanged { .. } => return show_emojis_prompt(sas),
            SasState::Done { .. } => bail!("SAS flow finished before we could confirm."),
            SasState::Cancelled(info) => bail!("SAS flow cancelled: {}", info.reason()),
            _ => {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
        }
    }
}

fn show_emojis_prompt(sas: &SasVerification) -> Result<bool> {
    let emojis = sas
        .emoji()
        .context("Other device does not support emoji verification")?;

    print_emojis(&emojis);

    loop {
        eprint!("\n  Do the emojis match? [y/n/?] ");
        io::stderr().flush().ok();

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("Failed to read confirmation from stdin")?;

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" | "" => return Ok(false),
            "?" => print_emojis(&emojis),
            other => eprintln!("  Unknown input '{other}' — type y, n, or ? to re-show emojis."),
        }
    }
}

fn print_emojis(emojis: &[matrix_sdk::encryption::verification::Emoji; 7]) {
    eprintln!("\n  Verification emojis — compare with the other device");
    eprintln!("  ────────────────────────────────────────────────────");
    for (i, e) in emojis.iter().enumerate() {
        eprintln!("  {}. {}  {}", i + 1, e.symbol, e.description);
    }
    eprintln!("  ────────────────────────────────────────────────────");
}

async fn wait_for_done(sas: &SasVerification) -> Result<()> {
    if sas.is_done() {
        return Ok(());
    }

    let mut stream = sas.changes();
    while let Some(state) = stream.next().await {
        match state {
            SasState::Done { .. } => return Ok(()),
            SasState::Cancelled(info) => {
                bail!(
                    "Verification cancelled after confirmation: {}",
                    info.reason()
                )
            }
            _ => {}
        }
    }
    bail!("SAS state stream closed before Done.")
}

// ── verify_non_interactive ────────────────────────────────────────────────────

/// Non-interactive SAS verification — same flow as [`verify_own_device`] but
/// without stdin/stderr interaction.
///
/// - `on_emojis` is called once with the seven emojis when they are ready;
///   the UI should display them and wait for the user's decision.
/// - `confirm_rx` receives `true` (emojis match) or `false` (mismatch) from
///   the UI once the user has decided.
///
/// A background sync loop must be running while this is awaited (see
/// [`crate::matrix::global::start_background_sync`]).
pub async fn verify_non_interactive<F>(
    client: &Client,
    on_emojis: F,
    confirm_rx: tokio::sync::oneshot::Receiver<bool>,
) -> Result<()>
where
    F: FnOnce(Vec<EmojiItem>) + Send + 'static,
{
    let own_user_id = client.user_id().context("Not logged in")?.to_owned();

    let (tx, rx) = tokio::sync::oneshot::channel::<VerificationRequest>();
    let tx_slot: Arc<Mutex<Option<tokio::sync::oneshot::Sender<VerificationRequest>>>> =
        Arc::new(Mutex::new(Some(tx)));

    client.add_event_handler({
        let tx_slot = tx_slot.clone();
        let own_user = own_user_id.clone();
        move |ev: ToDeviceKeyVerificationRequestEvent, client: Client| {
            let tx_slot = tx_slot.clone();
            let own_user = own_user.clone();
            async move {
                if ev.sender != own_user {
                    return;
                }
                let flow_id = ev.content.transaction_id.as_str().to_owned();
                if let Some(request) = client
                    .encryption()
                    .get_verification_request(&ev.sender, &flow_id)
                    .await
                {
                    let mut guard = tx_slot.lock().await;
                    if let Some(sender) = guard.take() {
                        let _ = sender.send(request);
                    }
                }
            }
        }
    });

    let request = tokio::time::timeout(tokio::time::Duration::from_secs(120), rx)
        .await
        .context("Timed out waiting for verification request (120 s)")?
        .context("Internal channel closed")?;

    request
        .accept_with_methods(vec![VerificationMethod::SasV1])
        .await
        .context("Failed to accept verification request")?;

    let sas = wait_for_sas(&request).await?;

    let emojis = wait_for_emojis(&sas).await?;
    on_emojis(emojis);

    let confirmed = confirm_rx
        .await
        .context("Confirmation channel dropped before user responded")?;

    if confirmed {
        sas.confirm()
            .await
            .context("Failed to send SAS confirmation")?;
    } else {
        sas.mismatch()
            .await
            .context("Failed to send SAS mismatch")?;
        bail!("Verification cancelled: emojis did not match.");
    }

    wait_for_done(&sas).await?;
    Ok(())
}

async fn wait_for_emojis(sas: &SasVerification) -> Result<Vec<EmojiItem>> {
    loop {
        match sas.state() {
            SasState::KeysExchanged { .. } => {
                let emojis = sas
                    .emoji()
                    .context("Other device does not support emoji verification")?;
                return Ok(emojis
                    .iter()
                    .map(|e| EmojiItem {
                        symbol: e.symbol.to_owned(),
                        description: e.description.to_owned(),
                    })
                    .collect());
            }
            SasState::Done { .. } => bail!("SAS completed before emoji confirmation"),
            SasState::Cancelled(info) => bail!("SAS cancelled: {}", info.reason()),
            _ => tokio::time::sleep(tokio::time::Duration::from_millis(200)).await,
        }
    }
}
