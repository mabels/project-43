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

    /// Import an OpenSSH private key into the wallet.
    ///
    /// Reads from FILE if given, otherwise reads from stdin (paste and press
    /// Ctrl-D).  If the key is passphrase-protected you will be prompted.
    /// The key is stored decrypted — the wallet gate-key is the outer protection.
    AddSshKey {
        /// Private key file (OpenSSH format). Omit to read from stdin.
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,

        /// Comment e.g. "meno@macbook" (defaults to the embedded key comment)
        #[arg(long)]
        comment: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Creator id [env: P43_CREATOR_ID]
        #[arg(long, env = "P43_CREATOR_ID", default_value = "cli")]
        creator_id: String,
    },

    /// Import an armored OpenPGP secret key into the wallet.
    ///
    /// Reads from FILE if given, otherwise reads from stdin (paste and press
    /// Ctrl-D).  If the key is passphrase-protected, supply --key-passphrase
    /// or you will be prompted.  Both the key and its passphrase are stored
    /// in the wallet — the gate-key AES-GCM is the outer protection.
    AddPgpKey {
        /// Armored TSK file (.asc). Omit to read from stdin.
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,

        /// Passphrase protecting the key (leave empty or omit if unencrypted).
        /// Prompted interactively if the key is encrypted and this is not set.
        #[arg(long)]
        key_passphrase: Option<String>,

        /// Human-readable label (defaults to the primary UID in the key).
        #[arg(long)]
        label: Option<String>,

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

        /// Kind: yubikey-ref, ssh-key, pgp-key, authority-key
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
