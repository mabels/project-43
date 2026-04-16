use anyhow::Result;
use p43::key_store::{keygen, store::KeyStore};

pub fn run(ks: &KeyStore, uid: &str, algo: &str, no_encrypt: bool) -> Result<()> {
    let passphrase = if !no_encrypt {
        let pw  = rpassword::prompt_password("Passphrase for private key: ")?;
        let pw2 = rpassword::prompt_password("Confirm passphrase: ")?;
        anyhow::ensure!(pw == pw2, "Passphrases do not match");
        Some(pw)
    } else {
        None
    };

    let cert = keygen::generate(uid, algo, passphrase.as_deref())?;
    let fp = cert.fingerprint();
    ks.save(&cert, None)?;

    println!("Generated key:");
    println!("  UID:         {}", uid);
    println!("  Algorithm:   {}", algo);
    println!("  Fingerprint: {}", fp);
    Ok(())
}
