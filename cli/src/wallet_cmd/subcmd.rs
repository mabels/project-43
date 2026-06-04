use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum WalletCmd {
    /// List all entries in the wallet
    List {
        /// Gate-key passphrase — required for --full and --full-private
        /// [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Output full entry details as JSON (secrets redacted)
        #[arg(long)]
        full: bool,

        /// Like --full but also includes private material (PIN, private keys).
        /// Implies --full.
        #[arg(long)]
        full_private: bool,
    },

    /// Show a wallet entry (secrets redacted by default).
    /// Pass a list index (from `wallet list`) or a full fingerprint.
    /// KIND is required when using a fingerprint; omit it when using an index.
    Get {
        /// List index (e.g. 2) or card/key fingerprint
        #[arg(value_name = "FINGERPRINT_OR_INDEX")]
        fingerprint: String,

        /// Kind: yubikey-ref, ssh-key (required when using fingerprint)
        #[arg(value_name = "KIND")]
        kind: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Print secret fields in plain text (PIN, private key)
        #[arg(long)]
        show_secrets: bool,
    },

    /// Add a YubiKey reference entry — reads the card fingerprint from the
    /// connected card automatically. PIN only is stored; public keys are
    /// fetched from the card on demand.
    AddYubikeyRef {
        /// Human-readable label (defaults to cardholder name on the card)
        #[arg(long)]
        label: Option<String>,

        /// Select card by AID ident when multiple cards are connected
        /// (use `p43 key list-cards` to see AIDs). If omitted, uses the
        /// only connected card or prompts when multiple are present.
        #[arg(long, value_name = "AID")]
        card: Option<String>,

        /// Card PIN (prompted if omitted) [env: P43_CARD_PIN]
        #[arg(long, env = "P43_CARD_PIN")]
        pin: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Creator id [env: P43_CREATOR_ID]
        #[arg(long, env = "P43_CREATOR_ID", default_value = "cli")]
        creator_id: String,
    },

    /// Add an SSH private key entry.
    /// The fingerprint (chain identifier) is derived from the key automatically.
    AddSshKey {
        /// Private key file path (OpenSSH format)
        #[arg(long, value_name = "FILE")]
        private_key: PathBuf,

        /// Comment e.g. "meno@macbook" (defaults to comment embedded in the key file)
        #[arg(long)]
        comment: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Creator id [env: P43_CREATOR_ID]
        #[arg(long, env = "P43_CREATOR_ID", default_value = "cli")]
        creator_id: String,
    },

    /// Delete (tombstone) a wallet entry
    Delete {
        /// Card or key fingerprint
        #[arg(value_name = "FINGERPRINT")]
        fingerprint: String,

        /// Kind: yubikey-ref, ssh-key
        #[arg(value_name = "KIND")]
        kind: String,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Creator id [env: P43_CREATOR_ID]
        #[arg(long, env = "P43_CREATOR_ID", default_value = "cli")]
        creator_id: String,
    },
}
