pub mod subcmd;

use anyhow::{Context, Result};
use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::OwnedDeviceId;
use p43::matrix::{
    client as mx_client, delete_devices, device_id_from_config, join_room, list_devices,
    list_joined_rooms, listen, logout, purge_room_history, resolve_room_id, send_message,
    set_room_alias, verify_own_device, ListenPointer, MatrixConfig, RoomPointerStore,
};
use rpassword::prompt_password;
use std::path::Path;
use subcmd::{
    DeleteDeviceArgs, DevicesArgs, JoinArgs, ListenArgs, LoginArgs, MatrixCmd, PurgeArgs,
    RoomsArgs, SendArgs, SetAliasArgs,
};

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn run(cmd: MatrixCmd, store_dir: &Path, rt: &tokio::runtime::Runtime) -> Result<()> {
    let cfg = MatrixConfig::from_store_dir(store_dir);

    match cmd {
        MatrixCmd::Login(args) => rt.block_on(do_login(args, &cfg)),
        MatrixCmd::Logout => rt.block_on(do_logout(&cfg)),
        MatrixCmd::Devices(args) => rt.block_on(do_devices(args, &cfg)),
        MatrixCmd::DeleteDevice(args) => rt.block_on(do_delete_device(args, &cfg)),
        MatrixCmd::Rooms(args) => rt.block_on(do_rooms(args, &cfg)),
        MatrixCmd::Join(args) => rt.block_on(do_join(args, &cfg)),
        MatrixCmd::SetAlias(args) => rt.block_on(do_set_alias(args, &cfg)),
        MatrixCmd::Send(args) => rt.block_on(do_send(args, &cfg)),
        MatrixCmd::Listen(args) => rt.block_on(do_listen(args, &cfg)),
        MatrixCmd::Verify => rt.block_on(do_verify(&cfg)),
        MatrixCmd::Purge(args) => rt.block_on(do_purge(args, &cfg)),
    }
}

// ── Login ─────────────────────────────────────────────────────────────────────

async fn do_login(args: LoginArgs, cfg: &MatrixConfig) -> Result<()> {
    let password = resolve_password(args.password)?;
    mx_client::login(&args.homeserver, &args.user, &password, cfg).await?;
    eprintln!("Logged in. Config saved to {}.", cfg.config_path.display());
    Ok(())
}

// ── Logout ────────────────────────────────────────────────────────────────────

async fn do_logout(cfg: &MatrixConfig) -> Result<()> {
    logout(cfg).await?;
    eprintln!(
        "Logged out. Session removed from {}.",
        cfg.config_path.display()
    );
    Ok(())
}

// ── Devices ───────────────────────────────────────────────────────────────────

async fn do_devices(_args: DevicesArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;
    let devices = list_devices(&client).await?;

    if devices.is_empty() {
        eprintln!("No devices found.");
        return Ok(());
    }

    println!(
        "{:<25}  {:<30}  {:<15}",
        "DEVICE ID", "DISPLAY NAME", "LAST SEEN IP"
    );
    println!("{}", "-".repeat(80));

    for d in devices {
        let name = d.display_name.as_deref().unwrap_or("-");
        let ip = d.last_seen_ip.as_deref().unwrap_or("-");
        let flag = if d.is_current {
            " ← this session"
        } else {
            ""
        };
        println!("{:<25}  {:<30}  {:<15}  {}", d.device_id, name, ip, flag);
    }

    Ok(())
}

// ── DeleteDevice ──────────────────────────────────────────────────────────────

async fn do_delete_device(args: DeleteDeviceArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;

    // Resolve the list of device IDs to delete.
    let targets: Vec<OwnedDeviceId> = if args.stale {
        // All non-current devices whose display name is "p43".
        let current = client.device_id().map(|d| d.to_string());
        list_devices(&client)
            .await?
            .into_iter()
            .filter(|d| {
                !d.is_current
                    && d.display_name.as_deref() == Some("p43")
                    && current.as_deref() != Some(&d.device_id)
            })
            .map(|d| OwnedDeviceId::from(d.device_id.as_str()))
            .collect()
    } else {
        args.devices
            .iter()
            .map(|s| OwnedDeviceId::from(s.as_str()))
            .collect()
    };

    if targets.is_empty() {
        eprintln!("No devices to delete.");
        return Ok(());
    }

    eprintln!("Deleting {} device(s):", targets.len());
    for id in &targets {
        eprintln!("  {id}");
    }

    let password = resolve_password(args.password)?;
    delete_devices(&client, &targets, &password).await?;

    eprintln!("Done.");
    Ok(())
}

// ── Rooms ─────────────────────────────────────────────────────────────────────

async fn do_rooms(_args: RoomsArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;
    let rooms = list_joined_rooms(&client);

    if rooms.is_empty() {
        eprintln!("No joined rooms found.");
        return Ok(());
    }

    for r in rooms {
        let alias = r.alias.as_deref().unwrap_or("-");
        let name = r.name.as_deref().unwrap_or("-");
        println!("{:<40}  {:<35}  {}", r.room_id, alias, name);
    }
    Ok(())
}

// ── Join ──────────────────────────────────────────────────────────────────────

async fn do_join(args: JoinArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;
    let result = join_room(&client, &args.room).await?;

    eprintln!("Joined  {}", result.room_id);
    if let Some(name) = &result.name {
        eprintln!("  name:      {name}");
    }
    if let Some(alias) = &result.alias {
        eprintln!("  alias:     {alias}");
    }
    eprintln!("  encrypted: {}", result.is_encrypted);

    if !args.skip_session {
        // Persist this room as the default agent room so `p43 ssh-agent`
        // can find it without a --room flag.
        let mut saved = mx_client::load_config(&cfg.config_path)?
            .context("Session config disappeared after join — this should not happen")?;
        saved.agent_room = Some(result.room_id.to_string());
        mx_client::save_config(&saved, &cfg.config_path)
            .context("Joined room but failed to update matrix-config.json")?;
        eprintln!("  agent_room saved to {}", cfg.config_path.display());
    }

    Ok(())
}

// ── SetAlias ──────────────────────────────────────────────────────────────────

async fn do_set_alias(args: SetAliasArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;
    let registered = set_room_alias(&client, &args.room, &args.alias).await?;
    eprintln!("Alias registered: {registered}");
    Ok(())
}

// ── Send ─────────────────────────────────────────────────────────────────────

async fn do_send(args: SendArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;
    let room_id = resolve_room_id(&client, &args.room).await?;
    send_message(&client, &room_id, &args.message).await?;
    eprintln!("Message sent.");
    Ok(())
}

// ── Listen ────────────────────────────────────────────────────────────────────

async fn do_listen(args: ListenArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;
    let room_id = resolve_room_id(&client, &args.room).await?;

    // Per-reader pointer store: app-state/<device_id>/cli.json
    let store_root = cfg
        .config_path
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let device_id = device_id_from_config(&cfg.config_path).unwrap_or_else(|_| "unknown".into());
    let ptr_store = RoomPointerStore::new(store_root, &device_id, "cli");

    let since: Option<String> = match args.since {
        Some(ref explicit) => Some(explicit.clone()),
        None => ptr_store.get(room_id.as_str()),
    };
    match &since {
        Some(token) => eprintln!("Resuming from pointer: {token}"),
        None => eprintln!("No stored pointer — replaying full room history"),
    };

    let ptr_store = std::sync::Arc::new(ptr_store);
    let room_id_str = room_id.to_string();

    let pointer: ListenPointer = listen(
        &client,
        &room_id,
        since.as_deref(),
        |sender, body, _ts_ms, _event_id| println!("[{sender}] {body}"),
        move |token| {
            let _ = ptr_store.set(&room_id_str, &token);
        },
    )
    .await?;

    eprintln!("pointer: {pointer}");
    Ok(())
}

// ── Purge ─────────────────────────────────────────────────────────────────────

async fn do_purge(args: PurgeArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;

    let room_id = match args.room {
        Some(ref r) => resolve_room_id(&client, r).await?,
        None => {
            // Fall back to saved agent room.
            let saved = mx_client::load_config(&cfg.config_path)?
                .context("No saved session — run `p43 matrix login` first")?;
            let room_str = saved
                .agent_room
                .context("No default room set — run `p43 matrix join` or pass --room")?;
            resolve_room_id(&client, &room_str).await?
        }
    };

    let cutoff_ms: u64 = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("System clock is before Unix epoch")?
            .as_millis() as u64;
        now.saturating_sub(args.older_than_hours * 3_600_000)
    };

    eprintln!(
        "Purging messages in {room_id} older than {} h (cutoff: {cutoff_ms} ms)…",
        args.older_than_hours
    );

    let n = purge_room_history(&client, &room_id, cutoff_ms).await?;
    eprintln!("Done — {n} message(s) redacted.");
    Ok(())
}

// ── Verify ────────────────────────────────────────────────────────────────────

async fn do_verify(cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(cfg).await?;

    // `client.sync()` is not `Send` (vendored SDK wraps futures in
    // `Instrumented<T>`), so we cannot use `tokio::spawn`.  A `LocalSet`
    // lets us `spawn_local` non-Send tasks on the current thread instead.
    let local = tokio::task::LocalSet::new();
    let sync_client = client.clone();

    local
        .run_until(async move {
            // Sync loop keeps Matrix events flowing while we interact with the
            // user.  It is cancelled implicitly when the LocalSet is dropped.
            tokio::task::spawn_local(async move {
                let _ = sync_client.sync(SyncSettings::default()).await;
            });

            verify_own_device(&client).await
        })
        .await
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Restore the saved session, or error with instructions to log in first.
async fn require_client(cfg: &MatrixConfig) -> Result<matrix_sdk::Client> {
    mx_client::restore(cfg).await?.context(
        "No saved session found. Run `p43 matrix login --homeserver URL --user USER` first.",
    )
}

/// Return the password from the CLI arg, or prompt interactively.
fn resolve_password(pw: Option<String>) -> Result<String> {
    match pw {
        Some(p) => Ok(p),
        None => prompt_password("Matrix password: ").context("Failed to read password"),
    }
}
