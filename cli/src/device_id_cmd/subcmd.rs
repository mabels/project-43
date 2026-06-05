use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum DeviceIdCmd {
    /// Generate a new device identity and store it in the wallet.
    Create {
        /// Human-readable device name.
        #[arg(long)]
        label: String,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },

    /// List all device identities in the wallet.
    List {
        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },

    /// Print the CSR for a device identity (send this to the authority).
    ///
    /// Outputs base64-encoded COSE_Sign1 bytes to stdout.
    Csr {
        /// Device ID hex (first 8 bytes of signing public key).
        /// Defaults to the only device-id in the wallet if there is exactly one.
        #[arg(long, value_name = "HEX")]
        device_id: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },

    /// Show detail for a device identity.
    Show {
        /// Device ID hex.  Defaults to the only entry if exactly one exists.
        #[arg(value_name = "DEVICE_ID")]
        device_id: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },

    /// Upgrade a `device-id` entry to `certified-device-id` using the cert
    /// returned by the authority.
    ///
    /// Tombstones the old chain and writes a new `certified-device-id` chain.
    Certify {
        /// Device ID hex to upgrade.
        #[arg(long, value_name = "HEX")]
        device_id: String,

        /// Path to a file containing the base64-encoded cert, or `-` for stdin.
        #[arg(long, value_name = "FILE")]
        cert: PathBuf,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,
    },

    /// Send a CSR to the authority over Matrix and wait for the signed cert.
    ///
    /// Sends `bus.csr_request` into the room, then listens for the matching
    /// `bus.cert_response` from the authority.  On receipt the wallet entry is
    /// automatically upgraded from `device-id` to `certified-device-id`.
    Register {
        /// Matrix room ID or alias where the authority is listening.
        /// Defaults to the agent room saved in matrix-config.json.
        #[arg(long, value_name = "ROOM")]
        room: Option<String>,

        /// Device ID hex.  Defaults to the only device-id in the wallet.
        #[arg(long, value_name = "HEX")]
        device_id: Option<String>,

        /// Gate-key passphrase [env: P43_GATE_PASSPHRASE]
        #[arg(short, long, env = "P43_GATE_PASSPHRASE")]
        passphrase: Option<String>,

        /// How long to wait for the authority response (seconds, default 120).
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
}
