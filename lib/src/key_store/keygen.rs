use anyhow::{bail, Result};
use openpgp::cert::prelude::*;
use openpgp::types::KeyFlags;
use sequoia_openpgp as openpgp;

/// Generate a new OpenPGP cert with sign + encrypt + auth subkeys.
/// algo: "ed25519" | "rsa4096" | "rsa3072"
/// passphrase: if Some, secret key material is encrypted at generation time
pub fn generate(uid: &str, algo: &str, passphrase: Option<&str>) -> Result<openpgp::Cert> {
    let suite = match algo {
        "ed25519" => CipherSuite::Cv25519,
        "rsa4096" => CipherSuite::RSA4k,
        "rsa3072" => CipherSuite::RSA3k,
        other => bail!(
            "Unknown algorithm '{}'. Supported: ed25519, rsa4096, rsa3072",
            other
        ),
    };

    let mut builder = CertBuilder::new()
        .add_userid(uid)
        .set_cipher_suite(suite)
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_authentication_subkey();

    if let Some(pw) = passphrase {
        builder = builder.set_password(Some(pw.into()));
    }

    let (cert, _revocation) = builder.generate()?;
    Ok(cert)
}
