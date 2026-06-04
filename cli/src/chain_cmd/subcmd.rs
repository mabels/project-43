use clap::Subcommand;

#[derive(Subcommand)]
pub enum ChainCmd {
    /// List all chains in the store
    List,

    /// Show the current tip item of a chain (hex-dumps decrypted payload).
    /// With --full, shows every item in history with metadata.
    Show {
        /// Chain name (opaque string, e.g. "0006_17684870-card_pin")
        #[arg(value_name = "NAME")]
        name: String,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Show full history with metadata for every item
        #[arg(long)]
        full: bool,
    },

    /// Walk and display the full history of a chain (newest first)
    History {
        /// Chain name
        #[arg(value_name = "NAME")]
        name: String,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },

    /// Append a new item to a chain (creates the chain if it does not exist)
    Append {
        /// Chain name
        #[arg(value_name = "NAME")]
        name: String,

        /// Payload bytes as hex (pass "-" to read from stdin)
        #[arg(value_name = "HEX_OR_DASH")]
        payload: String,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Creator id written into the item envelope [env: P43_CREATOR_ID]
        #[arg(long, env = "P43_CREATOR_ID", default_value = "cli")]
        creator_id: String,
    },

    /// Tombstone a chain (marks it deleted, does not remove files).
    /// Requires the gate-key passphrase — the tombstone is cryptographically
    /// authenticated, preventing deletion by anyone without the key.
    Delete {
        /// Chain name
        #[arg(value_name = "NAME")]
        name: String,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Creator id written into the tombstone [env: P43_CREATOR_ID]
        #[arg(long, env = "P43_CREATOR_ID", default_value = "cli")]
        creator_id: String,
    },

    /// Remove orphaned item files not reachable from any chain
    Gc,
}
