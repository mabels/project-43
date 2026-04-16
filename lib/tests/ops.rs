/// Integration tests — full chain:
///   p43::key_store::keygen  →  KeyStore  →  p43::pkcs11::soft_ops
use p43::key_store::{keygen, store};
use p43::pkcs11::{ops, soft_ops};
use tempfile::TempDir;

struct TestKey {
    _dir: TempDir,
    ks:   store::KeyStore,
    fingerprint: String,
}

impl TestKey {
    fn new(uid: &str, passphrase: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ks  = store::KeyStore::open(dir.path()).unwrap();
        let cert = keygen::generate(uid, "ed25519", passphrase).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        ks.save(&cert, None).unwrap();
        TestKey { _dir: dir, ks, fingerprint }
    }
    fn sec(&self) -> std::path::PathBuf { self.ks.sec_file_path(&self.fingerprint) }
    fn pub_(&self) -> std::path::PathBuf { self.ks.pub_file_path(&self.fingerprint) }
}

// ── sign / verify ─────────────────────────────────────────────────────────────

#[test]
fn sign_verify_no_passphrase() {
    let k = TestKey::new("Signer <s@test>", None);
    let sig = soft_ops::sign(b"hello", &k.sec(), "").unwrap();
    ops::verify(b"hello", sig.as_bytes(), &k.pub_()).unwrap();
}

#[test]
fn sign_verify_with_passphrase() {
    let k = TestKey::new("Signer <s@test>", Some("pw"));
    let sig = soft_ops::sign(b"hello", &k.sec(), "pw").unwrap();
    ops::verify(b"hello", sig.as_bytes(), &k.pub_()).unwrap();
}

#[test]
fn sign_wrong_passphrase_fails() {
    let k = TestKey::new("Signer <s@test>", Some("correct"));
    assert!(soft_ops::sign(b"data", &k.sec(), "wrong").is_err());
}

#[test]
fn verify_tampered_data_fails() {
    let k = TestKey::new("Signer <s@test>", None);
    let sig = soft_ops::sign(b"original", &k.sec(), "").unwrap();
    assert!(ops::verify(b"tampered", sig.as_bytes(), &k.pub_()).is_err());
}

// ── encrypt / decrypt ─────────────────────────────────────────────────────────

#[test]
fn encrypt_decrypt_no_passphrase() {
    let k = TestKey::new("Recv <r@test>", None);
    let cipher = ops::encrypt(b"secret", &k.pub_()).unwrap();
    let plain  = soft_ops::decrypt(cipher.as_bytes(), &k.sec(), "").unwrap();
    assert_eq!(plain, b"secret");
}

#[test]
fn encrypt_decrypt_with_passphrase() {
    let k = TestKey::new("Recv <r@test>", Some("recvpw"));
    let cipher = ops::encrypt(b"secret", &k.pub_()).unwrap();
    let plain  = soft_ops::decrypt(cipher.as_bytes(), &k.sec(), "recvpw").unwrap();
    assert_eq!(plain, b"secret");
}

#[test]
fn decrypt_wrong_key_fails() {
    let recv  = TestKey::new("Recv  <r@test>", None);
    let other = TestKey::new("Other <o@test>", None);
    let cipher = ops::encrypt(b"data", &recv.pub_()).unwrap();
    assert!(soft_ops::decrypt(cipher.as_bytes(), &other.sec(), "").is_err());
}

// ── sign+encrypt / decrypt+verify ─────────────────────────────────────────────

#[test]
fn sign_encrypt_decrypt_verify_no_passphrase() {
    let signer = TestKey::new("Signer <s@test>", None);
    let recv   = TestKey::new("Recv   <r@test>", None);
    let cipher = soft_ops::sign_encrypt(b"payload", &signer.sec(), &recv.pub_(), "").unwrap();
    let plain  = soft_ops::decrypt_verify(cipher.as_bytes(), &recv.sec(), &signer.pub_(), "").unwrap();
    assert_eq!(plain, b"payload");
}

#[test]
fn sign_encrypt_decrypt_verify_with_passphrases() {
    let signer = TestKey::new("Signer <s@test>", Some("spw"));
    let recv   = TestKey::new("Recv   <r@test>", Some("rpw"));
    let cipher = soft_ops::sign_encrypt(b"payload", &signer.sec(), &recv.pub_(), "spw").unwrap();
    let plain  = soft_ops::decrypt_verify(cipher.as_bytes(), &recv.sec(), &signer.pub_(), "rpw").unwrap();
    assert_eq!(plain, b"payload");
}

#[test]
fn decrypt_verify_wrong_signer_fails() {
    let signer = TestKey::new("Signer <s@test>", None);
    let other  = TestKey::new("Other  <o@test>", None);
    let recv   = TestKey::new("Recv   <r@test>", None);
    let cipher = soft_ops::sign_encrypt(b"data", &signer.sec(), &recv.pub_(), "").unwrap();
    assert!(soft_ops::decrypt_verify(cipher.as_bytes(), &recv.sec(), &other.pub_(), "").is_err());
}

// ── key_store round-trips ──────────────────────────────────────────────────────

#[test]
fn store_save_list_find_delete() {
    let dir = tempfile::tempdir().unwrap();
    let ks  = store::KeyStore::open(dir.path()).unwrap();
    let cert = keygen::generate("Alice <a@test>", "ed25519", None).unwrap();
    ks.save(&cert, None).unwrap();

    let entries = ks.list().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].uid.contains("a@test"));

    let found = ks.find("alice").unwrap();
    assert_eq!(found.fingerprint(), cert.fingerprint());

    ks.delete("alice").unwrap();
    assert_eq!(ks.list().unwrap().len(), 0);
}

#[test]
fn store_find_with_secret_and_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let ks  = store::KeyStore::open(dir.path()).unwrap();
    let cert = keygen::generate("Bob <b@test>", "ed25519", Some("bpw")).unwrap();
    ks.save(&cert, None).unwrap();

    let decrypted = ks.find_with_secret("bob", "bpw").unwrap();
    let policy = sequoia_openpgp::policy::StandardPolicy::new();
    let kp = decrypted.keys().with_policy(&policy, None).for_signing().secret().next().unwrap()
        .key().clone().into_keypair();
    assert!(kp.is_ok());
}
