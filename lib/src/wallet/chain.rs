//! Chain name convention for the wallet layer.
//!
//! The wallet uses chain names of the form `<fingerprint>-<kind>` where
//! `fingerprint` has `:` replaced with `_` to be filesystem-safe.
//! Only chains whose suffix matches a known kind are recognised as wallet entries.

use crate::sync_store::ChainRef;

/// The known payload kinds the wallet understands.
/// Chains in the store whose name ends with one of these suffixes are wallet entries.
/// All other chains (e.g. raw SHA-1 hex names from `p43 chain`) are skipped.
// NOTE: longer kinds that are suffixes of shorter ones MUST come first so
// `from_chain_name` matches greedily (e.g. "certified-device-id" before
// "device-id", otherwise "…-certified-device-id" is mis-parsed).
pub const KNOWN_KINDS: &[&str] = &[
    "yubikey-ref",
    "ssh-key",
    "pgp-key",
    "authority-key",
    "certified-device-id",
    "device-id",
];

/// Wallet-level chain identifier: a (fingerprint, kind) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainName {
    /// Card AID or soft-key hex fingerprint with `:` replaced by `_`.
    pub fingerprint: String,
    /// Payload kind — always one of [`KNOWN_KINDS`].
    pub kind: String,
}

impl ChainName {
    pub fn new(fingerprint: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            fingerprint: fingerprint.into().replace(':', "_"),
            kind: kind.into(),
        }
    }

    /// Convert to the opaque chain store name.
    pub fn to_chain_ref(&self) -> ChainRef {
        ChainRef::new(format!("{}-{}", self.fingerprint, self.kind))
    }

    /// Parse a raw chain store name back into a `ChainName`.
    ///
    /// Returns `None` if the name does not end with a known kind suffix.
    /// This filters out raw chains (e.g. pure SHA-1 hex names) that are not
    /// wallet entries.
    pub fn from_chain_name(name: &str) -> Option<Self> {
        for kind in KNOWN_KINDS {
            let suffix = format!("-{kind}");
            if let Some(fp) = name.strip_suffix(suffix.as_str()) {
                if !fp.is_empty() {
                    return Some(Self::new(fp, *kind));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_kinds_parse() {
        let c = ChainName::from_chain_name("0006_17684870-yubikey-ref").unwrap();
        assert_eq!(c.fingerprint, "0006_17684870");
        assert_eq!(c.kind, "yubikey-ref");

        let c = ChainName::from_chain_name("SHA256_abc123-ssh-key").unwrap();
        assert_eq!(c.fingerprint, "SHA256_abc123");
        assert_eq!(c.kind, "ssh-key");
    }

    #[test]
    fn raw_hex_chain_returns_none() {
        // Pure SHA-1 hex from `p43 chain append` — not a wallet entry
        assert!(ChainName::from_chain_name("80997125f65cbdc540415482624bd04b00a86250").is_none());
    }

    #[test]
    fn unknown_kind_returns_none() {
        assert!(ChainName::from_chain_name("fp1-unknown-type").is_none());
    }

    #[test]
    fn round_trip() {
        let cn = ChainName::new("0006:17684870", "yubikey-ref");
        let name = cn.to_chain_ref().name;
        let parsed = ChainName::from_chain_name(&name).unwrap();
        assert_eq!(parsed.fingerprint, "0006_17684870");
        assert_eq!(parsed.kind, "yubikey-ref");
    }
}
