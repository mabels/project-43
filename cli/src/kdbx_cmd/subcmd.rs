use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum KdbxCmd {
    /// List all entries in a .kdbx database
    List {
        /// Path to the .kdbx file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Master password [env: P43_KDBX_PASSWORD]
        #[arg(short, long, env = "P43_KDBX_PASSWORD")]
        password: Option<String>,

        /// HMAC-SHA1 secret hex (simulates YubiKey slot 2) [env: P43_KDBX_HMAC]
        #[arg(long, env = "P43_KDBX_HMAC", value_name = "HEX")]
        hmac_secret: Option<String>,
    },

    /// Show a single entry by index (as shown by `kdbx list`)
    Get {
        /// Path to the .kdbx file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Entry index (from `kdbx list`)
        #[arg(value_name = "INDEX")]
        index: usize,

        /// Master password [env: P43_KDBX_PASSWORD]
        #[arg(short, long, env = "P43_KDBX_PASSWORD")]
        password: Option<String>,

        /// HMAC-SHA1 secret hex (simulates YubiKey slot 2) [env: P43_KDBX_HMAC]
        #[arg(long, env = "P43_KDBX_HMAC", value_name = "HEX")]
        hmac_secret: Option<String>,

        /// Print the password field to stdout (default: hidden)
        #[arg(long)]
        show_password: bool,
    },

    /// Search entries by title (case-insensitive substring match)
    Search {
        /// Path to the .kdbx file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Search query
        #[arg(value_name = "QUERY")]
        query: String,

        /// Master password [env: P43_KDBX_PASSWORD]
        #[arg(short, long, env = "P43_KDBX_PASSWORD")]
        password: Option<String>,

        /// HMAC-SHA1 secret hex (simulates YubiKey slot 2) [env: P43_KDBX_HMAC]
        #[arg(long, env = "P43_KDBX_HMAC", value_name = "HEX")]
        hmac_secret: Option<String>,
    },
}
