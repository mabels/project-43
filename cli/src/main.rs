mod key_mgmt;
mod pgp;

use anyhow::Result;
use clap::{Parser, Subcommand};
use key_mgmt::subcmd::KeyCmd;
use p43::key_store::store::KeyStore;
use pgp::subcmd::PgpCmd;
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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Key management — generate, list, export, import, delete
    #[command(subcommand)]
    Key(KeyCmd),

    /// OpenPGP card / software-key operations — sign, encrypt, decrypt, verify
    #[command(subcommand)]
    Pgp(PgpCmd),
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

    match cli.command {
        Command::Key(cmd) => {
            let ks = KeyStore::open(&store_dir)?;
            key_mgmt::run(cmd, &ks)
        }
        Command::Pgp(cmd) => pgp::run(cmd, soft_key, cli.passphrase, cli.pin),
    }
}
