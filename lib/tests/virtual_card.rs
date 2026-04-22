/// Integration tests — virtual-card path:
///   keygen  →  KeyStore  →  VirtualCard (CardOps impl via soft_ops)  →  ops::verify / ops::encrypt
///
/// These tests exercise the same operations as a physical YubiKey would, but
/// use an in-process software key so they run without any PC/SC hardware.
use p43::key_store::{keygen, store};
use p43::pkcs11::{
    ops,
    virtual_card::{CardOps, VirtualCard},
};
use tempfile::TempDir;

// ── helpers ───────────────────────────────────────────────────────────────────

struct TestKey {
    _dir: TempDir,
    ks: store::KeyStore,
    fingerprint: String,
}

impl TestKey {
    fn new(uid: &str, passphrase: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ks = store::KeyStore::open(dir.path()).unwrap();
        let cert = keygen::generate(uid, "ed25519", passphrase).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        ks.save(&cert, None).unwrap();
        TestKey {
            _dir: dir,
            ks,
            fingerprint,
        }
    }

    fn sec(&self) -> std::path::PathBuf {
        self.ks.sec_file_path(&self.fingerprint)
    }

    fn pub_(&self) -> std::path::PathBuf {
        self.ks.pub_file_path(&self.fingerprint)
    }

    fn card(&self, passphrase: &str) -> VirtualCard {
        VirtualCard::new(self.sec(), passphrase)
    }
}

// ── sign / verify ─────────────────────────────────────────────────────────────

#[test]
fn virtual_card_sign_verify_no_passphrase() {
    let k = TestKey::new("Signer <s@test>", None);
    let card = k.card("");
    let sig = card.card_sign(b"hello").unwrap();
    ops::verify(b"hello", sig.as_bytes(), &k.pub_()).unwrap();
}

#[test]
fn virtual_card_sign_verify_with_passphrase() {
    let k = TestKey::new("Signer <s@test>", Some("pw"));
    let card = k.card("pw");
    let sig = card.card_sign(b"hello").unwrap();
    ops::verify(b"hello", sig.as_bytes(), &k.pub_()).unwrap();
}

#[test]
fn virtual_card_sign_wrong_passphrase_fails() {
    let k = TestKey::new("Signer <s@test>", Some("correct"));
    let card = k.card("wrong");
    assert!(card.card_sign(b"data").is_err());
}

#[test]
fn virtual_card_verify_tampered_data_fails() {
    let k = TestKey::new("Signer <s@test>", None);
    let card = k.card("");
    let sig = card.card_sign(b"original").unwrap();
    assert!(ops::verify(b"tampered", sig.as_bytes(), &k.pub_()).is_err());
}

// ── encrypt / decrypt ─────────────────────────────────────────────────────────

#[test]
fn virtual_card_encrypt_decrypt_no_passphrase() {
    let k = TestKey::new("Recv <r@test>", None);
    let card = k.card("");
    let cipher = ops::encrypt(b"secret", &k.pub_()).unwrap();
    let plain = card.card_decrypt(cipher.as_bytes()).unwrap();
    assert_eq!(plain, b"secret");
}

#[test]
fn virtual_card_encrypt_decrypt_with_passphrase() {
    let k = TestKey::new("Recv <r@test>", Some("recvpw"));
    let card = k.card("recvpw");
    let cipher = ops::encrypt(b"secret", &k.pub_()).unwrap();
    let plain = card.card_decrypt(cipher.as_bytes()).unwrap();
    assert_eq!(plain, b"secret");
}

#[test]
fn virtual_card_decrypt_wrong_key_fails() {
    let recv = TestKey::new("Recv  <r@test>", None);
    let other = TestKey::new("Other <o@test>", None);
    let cipher = ops::encrypt(b"data", &recv.pub_()).unwrap();
    assert!(other.card("").card_decrypt(cipher.as_bytes()).is_err());
}

// ── cross-card: one VirtualCard signs/encrypts, another decrypts/verifies ────

#[test]
fn virtual_card_sign_encrypt_decrypt_verify_no_passphrase() {
    let signer = TestKey::new("Signer <s@test>", None);
    let recv = TestKey::new("Recv   <r@test>", None);

    let cipher = signer
        .card("")
        .card_sign_encrypt(b"payload", &recv.pub_())
        .unwrap();

    let plain = recv
        .card("")
        .card_decrypt_verify(cipher.as_bytes(), &signer.pub_())
        .unwrap();

    assert_eq!(plain, b"payload");
}

#[test]
fn virtual_card_sign_encrypt_decrypt_verify_with_passphrases() {
    let signer = TestKey::new("Signer <s@test>", Some("spw"));
    let recv = TestKey::new("Recv   <r@test>", Some("rpw"));

    let cipher = signer
        .card("spw")
        .card_sign_encrypt(b"payload", &recv.pub_())
        .unwrap();

    let plain = recv
        .card("rpw")
        .card_decrypt_verify(cipher.as_bytes(), &signer.pub_())
        .unwrap();

    assert_eq!(plain, b"payload");
}

#[test]
fn virtual_card_decrypt_verify_wrong_signer_fails() {
    let signer = TestKey::new("Signer <s@test>", None);
    let other = TestKey::new("Other  <o@test>", None);
    let recv = TestKey::new("Recv   <r@test>", None);

    let cipher = signer
        .card("")
        .card_sign_encrypt(b"data", &recv.pub_())
        .unwrap();

    // Verify against `other`'s public key — must fail
    assert!(recv
        .card("")
        .card_decrypt_verify(cipher.as_bytes(), &other.pub_())
        .is_err());
}

// ── rsa4096 variant ───────────────────────────────────────────────────────────
//
// Key generation for RSA 4096 is slow in pure Rust (~60 s in CI).  Instead of
// generating a fresh key on every run we import a pre-generated fixture.
// The fixture was created once with gpg --batch --gen-key (libgcrypt, fast)
// and committed to lib/tests/fixtures/.  There is no security concern: the
// key is only used for functional correctness checks in a throwaway tempdir.

#[test]
fn virtual_card_rsa4096_sign_verify() {
    let dir = tempfile::tempdir().unwrap();
    let ks = store::KeyStore::open(dir.path()).unwrap();

    let sec_bytes = include_bytes!("fixtures/rsa4096_test.sec.asc");
    let cert = ks.import(sec_bytes).unwrap();
    let fp = cert.fingerprint().to_hex();

    let card = VirtualCard::new(ks.sec_file_path(&fp), "");
    let sig = card.card_sign(b"rsa test").unwrap();
    ops::verify(b"rsa test", sig.as_bytes(), &ks.pub_file_path(&fp)).unwrap();
}
