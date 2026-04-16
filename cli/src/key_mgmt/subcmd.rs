use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Generate a new key pair
    Generate {
        /// User ID, e.g. "Alice <alice@example.com>"
        #[arg(short, long)]
        uid: String,
        /// Algorithm: ed25519 (default), rsa4096, rsa3072
        #[arg(short, long, default_value = "ed25519")]
        algo: String,
        /// Store without passphrase protection (not recommended)
        #[arg(long)]
        no_encrypt: bool,
    },
    /// List all keys in the store
    List,
    /// Export a public key (armored)
    ExportPub {
        /// Fingerprint or partial UID
        #[arg(short, long)]
        key: String,
    },
    /// Export a private key (armored, passphrase-protected)
    ExportPriv {
        /// Fingerprint or partial UID
        #[arg(short, long)]
        key: String,
    },
    /// Import an existing key (public or private)
    Import {
        /// Path to armored key file
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a key from the store
    Delete {
        /// Fingerprint or partial UID
        #[arg(short, long)]
        key: String,
    },
}
