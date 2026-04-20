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
    /// Associate a YubiKey (or other OpenPGP card) AID with a key entry
    RegisterCard {
        /// Fingerprint or partial UID of the key to associate
        #[arg(short, long)]
        key: String,
        /// Card Application Identifier string (e.g. from `p43 key list --verbose`
        /// or printed by `p43 pgp card-info`)
        #[arg(short, long)]
        ident: String,
    },
    /// Import a key directly from a connected OpenPGP card (YubiKey etc.)
    ///
    /// Reads the signing-slot public key off the card, creates a self-signed
    /// OpenPGP cert (the card signs the UID binding), saves the public cert to
    /// the store, and records the card's AID in a companion .card.json file.
    ImportCard {
        /// Override the UID (default: cardholder name stored on card)
        #[arg(long)]
        uid: Option<String>,
        /// Select card by AID ident string (default: first connected card).
        /// Run `p43 key list-cards` to see available idents.
        #[arg(long)]
        card: Option<String>,
    },
    /// List all connected OpenPGP cards and their slot fingerprints
    ListCards,
}
