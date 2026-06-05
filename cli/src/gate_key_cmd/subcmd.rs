use clap::Subcommand;

#[derive(Subcommand)]
pub enum GateKeyCmd {
    /// First-time setup: generate the master secret and seal it with a passphrase.
    ///
    /// The passphrase is always required for the first seal.  Additional seals
    /// (more passphrases or biometric) can be added with `add-passphrase` after
    /// this step.
    Create {
        /// Master passphrase (prompted if omitted) [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

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

    /// Add a new passphrase seal for the same master secret.
    ///
    /// You must prove ownership by supplying a currently-working passphrase
    /// (--passphrase).  The master secret is then re-sealed with the new
    /// passphrase, creating an additional entry in the gate-keys directory.
    AddPassphrase {
        /// An existing working passphrase (proves ownership) [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// New passphrase for the additional seal (prompted if omitted)
        #[arg(long)]
        new_passphrase: Option<String>,

        /// Argon2 memory cost in KiB (default: 65536)
        #[arg(long, default_value_t = 65536)]
        m_cost: u32,

        /// Argon2 iterations (default: 3)
        #[arg(long, default_value_t = 3)]
        t_cost: u32,

        /// Argon2 parallelism threads (default: 4)
        #[arg(long, default_value_t = 4)]
        p_cost: u32,
    },

    /// List all seal IDs in the store.
    List,

    /// Verify that a passphrase works and optionally print the master secret.
    Verify {
        /// Passphrase (prompted if omitted) [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// Only try this specific key-id instead of all sealed files
        #[arg(long, value_name = "KEY_ID")]
        key_id: Option<String>,

        /// Print the master secret as hex (for adding a biometric lock externally)
        #[arg(long)]
        show_secret: bool,

        /// Output format: "text" (default) or "json"
        #[arg(long, default_value = "text", value_name = "FORMAT")]
        format: String,
    },

    /// Revoke a seal by key-id.
    ///
    /// You must prove ownership with a DIFFERENT working passphrase — you cannot
    /// revoke the only remaining seal (that would lock you out permanently).
    Revoke {
        /// Key ID to revoke (as shown by `gate-key list`)
        #[arg(value_name = "KEY_ID")]
        key_id: String,

        /// A currently-working passphrase (must be for a DIFFERENT seal) [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },
}
