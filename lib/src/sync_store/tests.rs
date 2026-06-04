//! Storage layer tests.
//!
//! All tests use MemObjectStore — no filesystem I/O.

#[cfg(test)]
mod object_store_tests {
    use crate::sync_store::object_store::{mem::MemObjectStore, ObjectStore};

    fn store() -> MemObjectStore {
        MemObjectStore::new()
    }

    #[test]
    fn put_and_get_round_trip() {
        let s = store();
        s.put("a", b"hello").unwrap();
        assert_eq!(s.get("a").unwrap(), b"hello");
    }

    #[test]
    fn put_fails_on_duplicate() {
        let s = store();
        s.put("a", b"v1").unwrap();
        assert!(s.put("a", b"v2").is_err());
    }

    #[test]
    fn update_overwrites() {
        let s = store();
        s.put("a", b"v1").unwrap();
        s.update("a", b"v2").unwrap();
        assert_eq!(s.get("a").unwrap(), b"v2");
    }

    #[test]
    fn update_creates_if_missing() {
        let s = store();
        s.update("a", b"v1").unwrap();
        assert_eq!(s.get("a").unwrap(), b"v1");
    }

    #[test]
    fn get_fails_on_missing() {
        let s = store();
        assert!(s.get("nope").is_err());
    }

    #[test]
    fn exists_reflects_state() {
        let s = store();
        assert!(!s.exists("a"));
        s.put("a", b"x").unwrap();
        assert!(s.exists("a"));
    }

    #[test]
    fn list_returns_all_ids() {
        let s = store();
        s.put("a", b"1").unwrap();
        s.put("b", b"2").unwrap();
        let mut ids = s.list().unwrap();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }
}

#[cfg(test)]
mod item_id_tests {
    use crate::sync_store::item::ItemId;

    #[test]
    fn from_bytes_is_deterministic() {
        let a = ItemId::from_bytes(b"hello");
        let b = ItemId::from_bytes(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_give_different_ids() {
        let a = ItemId::from_bytes(b"hello");
        let b = ItemId::from_bytes(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn next_is_sha1_of_self() {
        let id = ItemId::from_bytes(b"seed");
        let next = id.next();
        let expected = ItemId::from_bytes(id.as_bytes());
        assert_eq!(next, expected);
    }

    #[test]
    fn chain_is_deterministic() {
        let root = ItemId::from_bytes(b"root");
        let n1 = root.next();
        let n2 = n1.next();
        // Re-derive independently
        let root2 = ItemId::from_bytes(b"root");
        assert_eq!(root2.next().next(), n2);
    }

    #[test]
    fn hex_is_40_chars() {
        let id = ItemId::from_bytes(b"test");
        assert_eq!(id.as_hex().len(), 40);
    }
}

#[cfg(test)]
mod item_envelope_tests {
    use crate::sync_store::item::{ItemEnvelope, ItemId, KeyRef};
    use serde_bytes::ByteBuf;

    fn direct_key_ref() -> KeyRef {
        KeyRef::Direct {
            gate_key_id: ByteBuf::from(vec![0u8; 6]),
        }
    }

    fn root_key() -> Vec<u8> {
        vec![42u8; 32]
    }

    #[test]
    fn root_encrypt_decrypt_round_trip() {
        let payload = b"secret data";
        let item =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", payload).unwrap();
        let decrypted = item.decrypt(&root_key()).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn root_id_is_sha1_of_ciphertext() {
        let item =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"data").unwrap();
        let expected = ItemId::from_bytes(&item.ciphertext);
        assert_eq!(item.id, expected);
    }

    #[test]
    fn root_next_is_sha1_of_root_id() {
        let item =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"data").unwrap();
        assert_eq!(item.next, item.id.next());
    }

    #[test]
    fn root_prev_is_none() {
        let item =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"data").unwrap();
        assert!(item.prev.is_none());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let item =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"data").unwrap();
        let wrong_key = vec![0u8; 32];
        assert!(item.decrypt(&wrong_key).is_err());
    }

    #[test]
    fn successor_links_correctly() {
        let root =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"v1").unwrap();
        let succ =
            ItemEnvelope::new_successor(&root.id, &root_key(), direct_key_ref(), "device-1", b"v2")
                .unwrap();
        assert_eq!(succ.id, root.next);
        assert_eq!(succ.prev.as_ref().unwrap(), &root.id);
    }

    #[test]
    fn successor_decrypt_round_trip() {
        let root =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"v1").unwrap();
        let succ =
            ItemEnvelope::new_successor(&root.id, &root_key(), direct_key_ref(), "device-1", b"v2")
                .unwrap();
        assert_eq!(succ.decrypt(&root_key()).unwrap(), b"v2");
    }

    #[test]
    fn tombstone_decrypt_returns_empty() {
        let root =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"data").unwrap();
        let tomb = ItemEnvelope::new_tombstone(&root.id, &root_key(), direct_key_ref(), "device-1")
            .unwrap();
        assert!(tomb.deleted);
        // Tombstone decrypts to empty payload (zero-length = delete marker).
        assert_eq!(tomb.decrypt(&root_key()).unwrap(), b"");
        // Wrong key fails authentication.
        assert!(tomb.decrypt(&[0u8; 32]).is_err());
    }

    #[test]
    fn cbor_round_trip() {
        let item =
            ItemEnvelope::new_root(&root_key(), direct_key_ref(), "device-1", b"data").unwrap();
        let bytes = item.to_cbor().unwrap();
        let restored = ItemEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(item.id, restored.id);
        assert_eq!(restored.decrypt(&root_key()).unwrap(), b"data");
    }
}

#[cfg(test)]
mod chain_store_tests {
    use crate::sync_store::{
        chain_store::{ChainRef, ChainStore},
        item::KeyRef,
        object_store::mem::MemObjectStore,
    };
    use serde_bytes::ByteBuf;
    use std::sync::Arc;

    fn store() -> ChainStore {
        ChainStore::new(Arc::new(MemObjectStore::new()))
    }

    fn key_ref() -> KeyRef {
        KeyRef::Direct {
            gate_key_id: ByteBuf::from(vec![0u8; 6]),
        }
    }

    fn root_key() -> Vec<u8> {
        vec![7u8; 32]
    }

    fn chain(fp: &str, kind: &str) -> ChainRef {
        ChainRef::new(format!("{fp}-{kind}"))
    }

    #[test]
    fn read_missing_chain_returns_none() {
        let s = store();
        assert!(s
            .read(&chain("fp1", "card_pin"), &root_key())
            .unwrap()
            .is_none());
    }

    #[test]
    fn append_creates_chain_and_read_returns_payload() {
        let s = store();
        let c = chain("fp1", "card_pin");
        s.append(&c, &root_key(), key_ref(), "dev-1", b"1234")
            .unwrap();
        let payload = s.read(&c, &root_key()).unwrap().unwrap();
        assert_eq!(payload, b"1234");
    }

    #[test]
    fn second_append_updates_tip() {
        let s = store();
        let c = chain("fp1", "card_pin");
        s.append(&c, &root_key(), key_ref(), "dev-1", b"old")
            .unwrap();
        s.append(&c, &root_key(), key_ref(), "dev-1", b"new")
            .unwrap();
        let payload = s.read(&c, &root_key()).unwrap().unwrap();
        assert_eq!(payload, b"new");
    }

    #[test]
    fn delete_makes_read_return_none() {
        let s = store();
        let c = chain("fp1", "card_pin");
        s.append(&c, &root_key(), key_ref(), "dev-1", b"1234")
            .unwrap();
        s.delete(&c, &root_key(), key_ref(), "dev-1").unwrap();
        assert!(s.read(&c, &root_key()).unwrap().is_none());
    }

    #[test]
    fn history_returns_items_newest_first() {
        let s = store();
        let c = chain("fp1", "card_pin");
        s.append(&c, &root_key(), key_ref(), "dev-1", b"v1")
            .unwrap();
        s.append(&c, &root_key(), key_ref(), "dev-1", b"v2")
            .unwrap();
        s.append(&c, &root_key(), key_ref(), "dev-1", b"v3")
            .unwrap();
        let hist = s.history(&c).unwrap();
        assert_eq!(hist.len(), 3);
        // newest first: v3, v2, v1
        assert_eq!(hist[0].decrypt(&root_key()).unwrap(), b"v3");
        assert_eq!(hist[2].decrypt(&root_key()).unwrap(), b"v1");
        // root is last and has no prev
        assert!(hist[2].prev.is_none());
    }

    #[test]
    fn list_chains_returns_all_created() {
        let s = store();
        s.append(&chain("fp1", "card_pin"), &root_key(), key_ref(), "d", b"a")
            .unwrap();
        s.append(
            &chain("fp1", "passphrase"),
            &root_key(),
            key_ref(),
            "d",
            b"b",
        )
        .unwrap();
        s.append(&chain("fp2", "card_pin"), &root_key(), key_ref(), "d", b"c")
            .unwrap();
        let mut names: Vec<String> = s
            .list_chains()
            .unwrap()
            .iter()
            .map(|(c, _)| c.name.clone())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["fp1-card_pin", "fp1-passphrase", "fp2-card_pin"]
        );
    }

    #[test]
    fn chain_name_is_opaque() {
        let c = ChainRef::new("any-string:with/special.chars");
        assert_eq!(c.name, "any-string:with/special.chars");
    }

    #[test]
    fn duplicate_append_is_skipped() {
        let s = store();
        let c = chain("fp1", "card_pin");
        let id1 = s
            .append(&c, &root_key(), key_ref(), "dev-1", b"same")
            .unwrap();
        let id2 = s
            .append(&c, &root_key(), key_ref(), "dev-1", b"same")
            .unwrap();
        // Same content → same tip returned, no new item written.
        assert_eq!(id1, id2);
        // History has only one item.
        assert_eq!(s.history(&c).unwrap().len(), 1);
    }

    #[test]
    fn different_content_is_not_deduplicated() {
        let s = store();
        let c = chain("fp1", "card_pin");
        let id1 = s
            .append(&c, &root_key(), key_ref(), "dev-1", b"v1")
            .unwrap();
        let id2 = s
            .append(&c, &root_key(), key_ref(), "dev-1", b"v2")
            .unwrap();
        assert_ne!(id1, id2);
        assert_eq!(s.history(&c).unwrap().len(), 2);
    }

    #[test]
    fn wrong_root_key_fails_read() {
        let s = store();
        let c = chain("fp1", "card_pin");
        s.append(&c, &root_key(), key_ref(), "dev-1", b"secret")
            .unwrap();
        let wrong = vec![0u8; 32];
        assert!(s
            .read(&c, &wrong)
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }
}
