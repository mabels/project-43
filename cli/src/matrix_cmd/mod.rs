pub mod subcmd;

use anyhow::{Context, Result};
use p43::matrix::{client as mx_client, list_joined_rooms, listen, resolve_room_id, send_message, MatrixConfig};
use rpassword::prompt_password;
use std::path::Path;
use subcmd::{ListenArgs, LoginArgs, MatrixCmd, RoomsArgs, SendArgs};

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn run(cmd: MatrixCmd, store_dir: &Path) -> Result<()> {
    let cfg = MatrixConfig::from_store_dir(store_dir);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    match cmd {
        MatrixCmd::Login(args) => rt.block_on(do_login(args, &cfg)),
        MatrixCmd::Rooms(args) => rt.block_on(do_rooms(args, &cfg)),
        MatrixCmd::Send(args) => rt.block_on(do_send(args, &cfg)),
        MatrixCmd::Listen(args) => rt.block_on(do_listen(args, &cfg)),
    }
}

// ── Login ─────────────────────────────────────────────────────────────────────

async fn do_login(args: LoginArgs, cfg: &MatrixConfig) -> Result<()> {
    let password = resolve_password(args.password)?;
    mx_client::login(&args.homeserver, &args.user, &password, &cfg.session_path).await?;
    eprintln!("Logged in. Session saved to {}.", cfg.session_path.display());
    Ok(())
}

// ── Rooms ─────────────────────────────────────────────────────────────────────

async fn do_rooms(args: RoomsArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(&args.homeserver, args.user.as_deref(), args.password, cfg).await?;
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

// ── Send ─────────────────────────────────────────────────────────────────────

async fn do_send(args: SendArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(&args.homeserver, args.user.as_deref(), args.password, cfg).await?;
    let room_id = resolve_room_id(&client, &args.room).await?;
    send_message(&client, &room_id, &args.message).await?;
    eprintln!("Message sent.");
    Ok(())
}

// ── Listen ────────────────────────────────────────────────────────────────────

async fn do_listen(args: ListenArgs, cfg: &MatrixConfig) -> Result<()> {
    let client = require_client(&args.homeserver, args.user.as_deref(), args.password, cfg).await?;
    let room_id = resolve_room_id(&client, &args.room).await?;
    listen(&client, &room_id).await?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Obtain a ready client: restore from disk if possible, otherwise do a full
/// login using the supplied credentials.
async fn require_client(
    homeserver: &str,
    user: Option<&str>,
    password: Option<String>,
    cfg: &MatrixConfig,
) -> Result<matrix_sdk::Client> {
    if let Some(client) = mx_client::restore(homeserver, &cfg.session_path).await? {
        return Ok(client);
    }
    let user = user.context(
        "No saved session found. Pass --user (and optionally --password), \
         or run `p43 matrix login` first.",
    )?;
    let password = resolve_password(password)?;
    mx_client::login(homeserver, user, &password, &cfg.session_path).await
}

/// Return the password from the CLI arg, or prompt interactively.
fn resolve_password(pw: Option<String>) -> Result<String> {
    match pw {
        Some(p) => Ok(p),
        None => prompt_password("Matrix password: ").context("Failed to read password"),
    }
}
