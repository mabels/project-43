use clap::Subcommand;

#[derive(Subcommand)]
pub enum GateKeyCmd {
    /// Create a new gate-key sealed with a passphrase
    Create {
        /// Passphrase (prompted interactively if omitted) [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Re-seal an existing random instead of generating a new one (hex, 64 chars).
        /// Use `gate-key verify --show-secret` to obtain the value.
        #[arg(long, value_name = "HEX")]
        from_secret: Option<String>,

        /// Argon2 memory cost in KiB (default: 65536 = 64 MiB)
        #[arg(long, default_value_t = 65536)]
        m_cost: u32,

        /// Argon2 iterations (default: 3)
        #[arg(long, default_value_t = 3)]
        t_cost: u32,

        /// Argon2 parallelism threads (default: 4)
        #[arg(long, default_value_t = 4)]
        p_cost: u32,
    },

    /// List all gate-key IDs in the store
    List,

    /// Verify that a passphrase unlocks at least one gate-key.
    /// Reports every file attempted and whether it succeeded or failed.
    Verify {
        /// Passphrase (prompted interactively if omitted) [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Only try this specific key-id instead of all sealed files
        #[arg(long, value_name = "KEY_ID")]
        key_id: Option<String>,

        /// Print the unlocked random as hex so it can be passed to `create --from-secret`
        #[arg(long)]
        show_secret: bool,

        /// Output format: "text" (default) or "json"
        #[arg(long, default_value = "text", value_name = "FORMAT")]
        format: String,
    },

    /// Change the passphrase for a gate-key
    ChangePassphrase {
        /// Current passphrase (prompted if omitted) [env: P43_GATE_PASSPHRASE]
        #[arg(long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// New passphrase (prompted if omitted)
        #[arg(long)]
        new_passphrase: Option<String>,

        /// Argon2 memory cost in KiB for the new seal (default: 65536)
        #[arg(long, default_value_t = 65536)]
        m_cost: u32,

        /// Argon2 iterations for the new seal (default: 3)
        #[arg(long, default_value_t = 3)]
        t_cost: u32,

        /// Argon2 parallelism threads for the new seal (default: 4)
        #[arg(long, default_value_t = 4)]
        p_cost: u32,
    },

    /// Revoke (delete) a gate-key by key-id
    Revoke {
        /// Key ID to revoke (as shown by `gate-key list`)
        #[arg(value_name = "KEY_ID")]
        key_id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}
