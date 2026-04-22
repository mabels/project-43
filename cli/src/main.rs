mod bus_cmd;
mod key_mgmt;
mod matrix_cmd;
mod pgp;
mod ssh_agent_cmd;

use anyhow::Result;
use bus_cmd::subcmd::BusCmd;
use clap::{Parser, Subcommand};
use key_mgmt::subcmd::KeyCmd;
use matrix_cmd::subcmd::MatrixCmd;
use p43::key_store::store::KeyStore;
use pgp::subcmd::PgpCmd;
use ssh_agent_cmd::subcmd::SshAgentArgs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "p43",
    about = "project-43 — key management and OpenPGP operations"
)]
struct Cli {
    /// Key store directory (default: ~/.config/project-43/keys)
    #[arg(long, global = true)]
    store: Option<PathBuf>,

    /// Card PIN [env: YK_PIN]
    #[arg(long, global = true)]
    pin: Option<String>,

    /// Software key file (.sec.asc) [env: YK_KEY_FILE]
    #[arg(long, global = true, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// Passphrase for software key [env: YK_PASSPHRASE]
    #[arg(long, global = true)]
    passphrase: Option<String>,

    /// OpenTelemetry collector endpoint [env: P43_OTEL_ENDPOINT]
    ///
    /// Empty string (default) enables local fmt mode — spans go to stderr
    /// via RUST_LOG, zero network traffic.  Set to a URL to export spans
    /// via OTLP HTTP (e.g. https://otel.adviser.com).
    #[arg(long, global = true, env = "P43_OTEL_ENDPOINT", default_value = "")]
    otel_endpoint: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bus — device registration, cert issuance, encrypted messaging
    #[command(subcommand)]
    Bus(BusCmd),

    /// Key management — generate, list, export, import, delete
    #[command(subcommand)]
    Key(KeyCmd),

    /// OpenPGP card / software-key operations — sign, encrypt, decrypt, verify
    #[command(subcommand)]
    Pgp(PgpCmd),

    /// SSH agent — expose a key over the OpenSSH agent protocol
    SshAgent(SshAgentArgs),

    /// Matrix — login, send messages, listen for messages
    #[command(subcommand)]
    Matrix(MatrixCmd),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let store_dir = cli.store.unwrap_or_else(|| {
        dirs::home_dir()
            .expect("cannot find home dir")
            .join(".config")
            .join("project-43")
            .join("keys")
    });

    let soft_key = cli
        .key_file
        .or_else(|| std::env::var("YK_KEY_FILE").ok().map(PathBuf::from));

    // Sync commands (key, pgp) don't need a Tokio runtime.
    // Build one only for async subcommands, and use it for telemetry init
    // so the OTLP batch exporter has the runtime context it requires.
    match cli.command {
        Command::Bus(cmd) => {
            let passphrase = cli
                .passphrase
                .or_else(|| std::env::var("YK_PASSPHRASE").ok());
            let pin = cli.pin.or_else(|| std::env::var("YK_PIN").ok());
            bus_cmd::run(cmd, &store_dir, soft_key, passphrase, pin)
        }
        Command::Key(cmd) => {
            // Sync — local fmt tracing only (no runtime needed for OTLP).
            p43::telemetry::init("")?;
            let ks = KeyStore::open(&store_dir)?;
            key_mgmt::run(cmd, &ks)
        }
        Command::Pgp(cmd) => {
            p43::telemetry::init("")?;
            pgp::run(cmd, soft_key, cli.passphrase, cli.pin)
        }
        Command::SshAgent(args) => {
            let passphrase = cli
                .passphrase
                .or_else(|| std::env::var("YK_PASSPHRASE").ok())
                .unwrap_or_default();
            let pin = cli.pin.or_else(|| std::env::var("YK_PIN").ok());
            // Build the runtime first so telemetry::init (OTLP batch exporter)
            // has a live Tokio context when a non-empty endpoint is provided.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async { p43::telemetry::init(&cli.otel_endpoint) })?;
            ssh_agent_cmd::run(args, &store_dir, soft_key, passphrase, pin, &rt)
        }
        Command::Matrix(cmd) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async { p43::telemetry::init(&cli.otel_endpoint) })?;
            matrix_cmd::run(cmd, &store_dir, &rt)
        }
    }
}
