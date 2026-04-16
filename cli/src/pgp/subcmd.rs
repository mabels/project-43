use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum PgpCmd {
    /// List card content (YubiKey only)
    List,
    /// Sign a message — produces an armored detached signature
    Sign {
        #[arg(short, long)] message: Option<String>,
        #[arg(short, long)] file: Option<PathBuf>,
    },
    /// Encrypt to a recipient's public key
    Encrypt {
        #[arg(short, long)] message: Option<String>,
        #[arg(short, long)] file: Option<PathBuf>,
        /// Recipient public key file (.asc)
        #[arg(short, long)] recipient: PathBuf,
    },
    /// Decrypt an armored message
    Decrypt {
        #[arg(short, long)] file: Option<PathBuf>,
    },
    /// Sign then encrypt
    SignEncrypt {
        #[arg(short, long)] message: Option<String>,
        #[arg(short, long)] file: Option<PathBuf>,
        /// Recipient public key file (.asc)
        #[arg(short, long)] recipient: PathBuf,
    },
    /// Verify a detached signature
    Verify {
        #[arg(short, long)] file: Option<PathBuf>,
        /// Detached signature file (.asc)
        #[arg(short = 'S', long)] sig: PathBuf,
        /// Signer's public key file (.asc)
        #[arg(short, long)] signer: PathBuf,
    },
    /// Decrypt and verify a sign+encrypt message
    DecryptVerify {
        #[arg(short, long)] file: Option<PathBuf>,
        /// Signer's public key file (.asc)
        #[arg(short, long)] signer: PathBuf,
    },
}
