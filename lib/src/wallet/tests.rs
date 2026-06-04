#[cfg(test)]
mod wallet_tests {
    use crate::sync_store::{object_store::mem::MemObjectStore, ChainStore, KeyRef};
    use crate::wallet::{ChainName, SshKey, Wallet, WalletPayload, YubikeyRef};
    use serde_bytes::ByteBuf;
    use std::sync::Arc;

    fn root_key() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    fn key_ref() -> KeyRef {
        KeyRef::Direct {
            gate_key_id: ByteBuf::from(vec![0u8; 6]),
        }
    }

    fn wallet() -> Wallet {
        let store = ChainStore::new(Arc::new(MemObjectStore::new()));
        Wallet { store }
    }

    fn yubikey_ref(fp: &str) -> WalletPayload {
        WalletPayload::YubikeyRef(YubikeyRef {
            version: 1,
            card_fingerprint: fp.into(),
            label: "test yubikey".into(),
            pin: "123456".into(),
        })
    }

    #[test]
    fn put_and_get_yubikey_ref() {
        let w = wallet();
        let payload = yubikey_ref("0006:17684870");
        w.put(
            "0006:17684870",
            "yubikey-ref",
            &payload,
            &root_key(),
            key_ref(),
            "test",
        )
        .unwrap();
        let result = w
            .get("0006:17684870", "yubikey-ref", &root_key())
            .unwrap()
            .unwrap();
        if let WalletPayload::YubikeyRef(r) = result {
            assert_eq!(r.label, "test yubikey");
            assert_eq!(r.pin, "123456");
        } else {
            panic!("wrong payload kind");
        }
    }

    #[test]
    fn put_and_get_ssh_key() {
        let w = wallet();
        let payload = WalletPayload::SshKey(SshKey {
            version: 1,
            private_key: ByteBuf::from(vec![0xAAu8; 64]),
            comment: "meno@macbook".into(),
        });
        // chain_name_for falls back to comment → sanitised "meno_macbook"
        w.put(
            "meno_macbook",
            "ssh-key",
            &payload,
            &root_key(),
            key_ref(),
            "test",
        )
        .unwrap();
        let result = w
            .get("meno_macbook", "ssh-key", &root_key())
            .unwrap()
            .unwrap();
        if let WalletPayload::SshKey(k) = result {
            assert_eq!(k.comment, "meno@macbook");
        } else {
            panic!("wrong payload kind");
        }
    }

    #[test]
    fn get_missing_returns_none() {
        let w = wallet();
        assert!(w.get("fp1", "yubikey-ref", &root_key()).unwrap().is_none());
    }

    #[test]
    fn delete_makes_get_return_none() {
        let w = wallet();
        w.put(
            "0006:17684870",
            "yubikey-ref",
            &yubikey_ref("0006:17684870"),
            &root_key(),
            key_ref(),
            "test",
        )
        .unwrap();
        w.delete(
            "0006:17684870",
            "yubikey-ref",
            &root_key(),
            key_ref(),
            "test",
        )
        .unwrap();
        assert!(w
            .get("0006:17684870", "yubikey-ref", &root_key())
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_returns_all_entries() {
        let w = wallet();
        w.put(
            "0006:17684870",
            "yubikey-ref",
            &yubikey_ref("0006:17684870"),
            &root_key(),
            key_ref(),
            "t",
        )
        .unwrap();
        // comment="" → fallback uses SHA-256 of key bytes prefix
        w.put(
            "meno_macbook", // unused by new wallet — chain_name_for derives from payload
            "ssh-key",
            &WalletPayload::SshKey(SshKey {
                version: 1,
                private_key: ByteBuf::from(vec![0u8; 32]),
                comment: "meno_macbook".into(),
            }),
            &root_key(),
            key_ref(),
            "t",
        )
        .unwrap();
        let mut list: Vec<String> = w
            .list_with_ids(&root_key())
            .unwrap()
            .iter()
            .map(|(c, _)| format!("{}-{}", c.fingerprint, c.kind))
            .collect();
        list.sort();
        assert_eq!(
            list,
            vec!["0006_17684870-yubikey-ref", "meno_macbook-ssh-key"]
        );
    }

    #[test]
    fn chain_name_normalises_colon() {
        let cn = ChainName::new("0006:17684870", "yubikey-ref");
        assert_eq!(cn.fingerprint, "0006_17684870");
        assert_eq!(cn.to_chain_ref().name, "0006_17684870-yubikey-ref");
    }

    #[test]
    fn payload_cbor_round_trip() {
        let orig = yubikey_ref("fp1");
        let bytes = orig.to_cbor().unwrap();
        let restored = WalletPayload::from_cbor(&bytes).unwrap();
        assert_eq!(restored.kind(), "yubikey-ref");
    }
}
