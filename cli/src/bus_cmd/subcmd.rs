use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum BusCmd {
    /// Generate a new Ed25519 authority keypair and protect it with an existing main key.
    ///
    /// The main key can be any format (RSA, ECDSA, Ed25519, …).  Its *public* cert is used
    /// to OpenPGP-encrypt the authority private scalar — no passphrase or PIN required here.
    ///
    /// Two files are written:
    ///   authority.pub.bin  — 32-byte Ed25519 public key (distribute to devices)
    ///   authority.key.enc  — encrypted private scalar (keep alongside main key)
    Init {
        /// Path to the main key's public cert (.asc or .pgp).
        /// For a soft key file, this is typically the same .asc file used with --key-file.
        /// For a card key, export the public cert first: `p43 key export-pub <fp>`.
        #[arg(long, value_name = "CERT_FILE")]
        recipient: PathBuf,
        /// Overwrite existing authority files if present.
        #[arg(long)]
        force: bool,
    },

    /// Generate a device key (run once per device / client).
    ///
    /// Files are stored in <bus_dir>/devices/<label>.key.cbor.
    /// If --label is omitted the device fingerprint is used as both the label
    /// and the filename.
    GenKey {
        /// Human-readable device label, e.g. `"laptop-ssh-agent"`.
        /// Defaults to the hex device-id (first 8 bytes of the signing key).
        #[arg(long)]
        label: Option<String>,
        /// Overwrite existing device key if present.
        #[arg(long)]
        force: bool,
    },

    /// Generate a CSR from a device key in <bus_dir>/devices/.
    GenCsr {
        /// Which device key to use (label or fingerprint used at gen-key time).
        /// Auto-detected when exactly one device key exists.
        #[arg(long)]
        label: Option<String>,
        /// Write CSR to FILE (default: <bus_dir>/devices/<label>.csr.cbor).
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Issue a device certificate from a CSR (authority side).
    ///
    /// Decrypts `authority.key.enc` using the main key, then signs the cert.
    /// Use global --key-file + YK_PASSPHRASE / --passphrase for a soft key.
    /// Use --card (+ YK_PIN / --pin) for a YubiKey / OpenPGP card.
    ///
    /// The CSR can be specified either as a positional file path or via --label,
    /// which resolves to <bus_dir>/devices/<label>.csr.cbor automatically.
    /// Exactly one of CSR_FILE or --label must be provided.
    IssueCert {
        /// CSR file produced by `gen-csr`.  Mutually exclusive with --label.
        #[arg(value_name = "CSR_FILE")]
        csr: Option<PathBuf>,
        /// Device label — resolves to <bus_dir>/devices/<label>.csr.cbor.
        /// Mutually exclusive with CSR_FILE.
        #[arg(long)]
        label: Option<String>,
        /// TTL in seconds (default: 15_897_600 = ~6 months).
        #[arg(long, default_value_t = 15_897_600)]
        ttl: i64,
        /// Write cert to FILE (default: <bus_dir>/peers/<device_id>.cert.cbor).
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Use a connected OpenPGP card to decrypt the authority key.
        #[arg(long)]
        card: bool,
        /// Card AID ident string (default: first connected card).
        #[arg(long)]
        ident: Option<String>,
    },

    /// Display a CSR or cert in human-readable form.
    Show {
        /// CSR or cert file.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// List device keys stored in <bus_dir>/devices/.
    ///
    /// Shows label, device-id (fingerprint), and whether a cert and/or CSR exist
    /// alongside each key.
    ListKeys,

    /// Delete a locally-owned device key (and its CSR/cert if present).
    ///
    /// Provide exactly one of --label or --id.
    /// --id accepts a prefix of the hex device-id (min 4 chars recommended).
    DeleteKey {
        /// Label given at gen-key time.
        #[arg(long)]
        label: Option<String>,
        /// Device-id (or unambiguous prefix) as shown in list-keys.
        #[arg(long)]
        id: Option<String>,
        /// Skip confirmation prompt.
        #[arg(long)]
        force: bool,
    },

    /// List registered peer certs.
    ListPeers,

    /// Encrypt a message to a peer.
    ///
    /// --to accepts either a cert file path or a peer label / device-id.
    /// Label resolution order: peers/<label>.cert.cbor, devices/<label>.cert.cbor.
    Encrypt {
        /// Recipient: a cert file path, or a peer label / device-id (auto-resolved).
        #[arg(long, value_name = "FILE|LABEL")]
        to: String,
        /// Sender device label / fingerprint (auto-detected if only one device exists).
        #[arg(long)]
        device: Option<String>,
        /// Sender cert file (overrides --device; default: <bus_dir>/devices/<device>.cert.cbor).
        #[arg(long, value_name = "FILE")]
        from_cert: Option<PathBuf>,
        /// Plaintext message string.
        #[arg(long)]
        msg: String,
        /// Message kind / type tag (default: "text").
        #[arg(long, default_value = "text")]
        kind: String,
        /// Write envelope to FILE (default: stdout as hex).
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Decrypt a message (using this device's key).
    Decrypt {
        /// Envelope file (or `-` for stdin).
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Device label / fingerprint to decrypt with (auto-detected if only one device exists).
        #[arg(long)]
        device: Option<String>,
    },
}
