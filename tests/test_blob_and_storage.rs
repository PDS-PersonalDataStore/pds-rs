use pds::{
    BlobId, BlobStore, Change, ChangeId, ChangeMetadata, DiskStorage, EntityId, Operation,
    PropertyValue,
};
use std::fs;

#[test]
fn test_blob_store_deduplication_and_retrieval() {
    let temp_path = std::env::temp_dir().join(format!("pds_test_blob_{}", BlobId::new()));
    let mut store = BlobStore::new(&temp_path).unwrap();

    let data = b"Hello, decentralized world of personal data!";
    let id1 = BlobId::new();
    let desc1 = store
        .put(id1, data, Some("text/plain".to_string()))
        .expect("Put blob 1 failed");

    assert_eq!(desc1.id, id1);
    assert_eq!(desc1.size_bytes, data.len() as u64);
    assert_eq!(desc1.mime_type.as_deref(), Some("text/plain"));

    // Put identical content under different BlobId -> CAS deduplication
    let id2 = BlobId::new();
    let desc2 = store
        .put(id2, data, Some("text/plain".to_string()))
        .expect("Put blob 2 failed");

    assert_eq!(desc2.sha256, desc1.sha256);
    assert_eq!(desc2.id, id2);

    let read_back1 = store.get_data(&id1).expect("Failed to get blob 1");
    let read_back2 = store.get_data(&id2).expect("Failed to get blob 2");
    assert_eq!(read_back1, data);
    assert_eq!(read_back2, data);

    let non_existent = BlobId::new();
    assert!(store.get_data(&non_existent).is_err());

    let _ = fs::remove_dir_all(&temp_path);
}

#[test]
fn test_disk_storage_reopen_and_persistence() {
    let root = std::env::temp_dir().join(format!("pds_test_storage_{}", BlobId::new()));
    let entity_id = EntityId::new();
    let c1_id = ChangeId::new();

    {
        let mut storage = DiskStorage::open(&root).expect("Failed to open storage");
        let change = Change::new(
            c1_id,
            vec![],
            ChangeMetadata::new("device-node-1").with_author("test_author"),
            vec![
                Operation::CreateEntity {
                    entity_id,
                    entity_type: Some("document".to_string()),
                },
                Operation::SetEntityProperty {
                    entity_id,
                    name: "title".into(),
                    value: PropertyValue::Text("My Notes".to_string()),
                },
            ],
        );

        storage
            .append_change(change)
            .expect("Failed to append change");
        assert_eq!(storage.change_count(), 1);

        let blob_id = BlobId::new();
        storage
            .blobs_mut()
            .put(blob_id, b"binary payload", None)
            .expect("Failed to store blob");
    }

    // Reopen from disk
    {
        let storage = DiskStorage::open(&root).expect("Failed to reopen storage");
        assert_eq!(storage.change_count(), 1);
        let restored_change = storage.get_change(&c1_id).expect("Change not found");
        assert_eq!(
            restored_change.metadata.author_id.as_deref(),
            Some("test_author")
        );
        assert_eq!(restored_change.metadata.device_id, "device-node-1");

        let entity = storage
            .state()
            .entities
            .get(&entity_id)
            .expect("Entity not projected");
        assert_eq!(entity.entity_type.as_deref(), Some("document"));
        assert_eq!(
            entity.get_property(&"title".into()),
            Some(&PropertyValue::Text("My Notes".to_string()))
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_encrypted_blob_storage_and_recovery() {
    let root = std::env::temp_dir().join(format!("pds_test_enc_blob_{}", BlobId::new()));
    let blob_id = BlobId::new();
    let secret = b"Decentralized secure patient record biometric image data";
    let mut keystore = pds::KeyStore::new();
    let (key_id, _) = keystore.generate_key();

    {
        let mut storage = DiskStorage::open(&root).expect("Failed to open storage");
        let desc = storage
            .blobs_mut()
            .put_encrypted(blob_id, secret, key_id, &keystore, Some("image/png".into()))
            .expect("Failed to put encrypted blob");
        assert_eq!(desc.id, blob_id);
        assert!(matches!(
            desc.encryption,
            pds::BlobEncryption::Encrypted { .. }
        ));
    }

    // Reopen storage and verify persistence and decryption
    {
        let storage = DiskStorage::open(&root).expect("Failed to reopen storage");
        let desc = storage
            .blobs()
            .get_descriptor(&blob_id)
            .expect("Descriptor not found");
        assert_eq!(desc.id, blob_id);

        let raw = storage
            .blobs()
            .get_raw_data(&blob_id)
            .expect("Failed to read raw");
        assert_ne!(raw, secret);

        let decrypted = storage
            .blobs()
            .get_decrypted_data(&blob_id, &keystore)
            .expect("Failed to decrypt blob");
        assert_eq!(decrypted, secret);
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_sqlite_encrypted_blob_storage_and_recovery() {
    let root = std::env::temp_dir().join(format!("pds_test_sql_enc_blob_{}", BlobId::new()));
    let blob_id = BlobId::new();
    let secret = b"SQLite stored encrypted financial ledger payload";
    let mut keystore = pds::KeyStore::new();
    let (key_id, _) = keystore.generate_key();

    {
        let mut storage = pds::SqliteStorage::open(&root).expect("Failed to open sqlite storage");
        let desc = storage
            .blobs_mut()
            .put_encrypted(
                blob_id,
                secret,
                key_id,
                &keystore,
                Some("application/json".into()),
            )
            .expect("Failed to put encrypted blob");
        assert_eq!(desc.id, blob_id);
    }

    // Reopen sqlite storage and verify persistence and decryption
    {
        let storage = pds::SqliteStorage::open(&root).expect("Failed to reopen sqlite storage");
        let desc = storage
            .blobs()
            .get_descriptor(&blob_id)
            .expect("Descriptor not found");
        assert_eq!(desc.id, blob_id);

        let raw = storage
            .blobs()
            .get_raw_data(&blob_id)
            .expect("Failed to read raw");
        assert_ne!(raw, secret);

        let decrypted = storage
            .blobs()
            .get_decrypted_data(&blob_id, &keystore)
            .expect("Failed to decrypt blob");
        assert_eq!(decrypted, secret);
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fastcdc_chunked_blob_storage_and_recovery() {
    let root = std::env::temp_dir().join(format!("pds_test_chunked_blob_{}", BlobId::new()));
    let blob_id = BlobId::new();
    let mut keystore = pds::KeyStore::new();
    let (key_id, _) = keystore.generate_key();

    // 1.25 MiB payload to exceed CHUNKING_THRESHOLD_BYTES
    let size = 1280 * 1024;
    let mut large_secret = Vec::with_capacity(size);
    for i in 0..size {
        large_secret.push(((i * 7) % 256) as u8);
    }

    {
        let mut storage = pds::SqliteStorage::open(&root).expect("Failed to open sqlite storage");
        let desc = storage
            .blobs_mut()
            .put_encrypted(
                blob_id,
                &large_secret,
                key_id,
                &keystore,
                Some("application/octet-stream".into()),
            )
            .expect("Failed to put chunked encrypted blob");

        assert!(desc.chunks.is_some());
        assert!(desc.chunks.unwrap().len() > 1);
    }

    {
        let storage = pds::SqliteStorage::open(&root).expect("Failed to reopen sqlite storage");
        let desc = storage
            .blobs()
            .get_descriptor(&blob_id)
            .expect("Descriptor not found");

        assert!(desc.chunks.is_some());
        let raw = storage
            .blobs()
            .get_raw_data(&blob_id)
            .expect("Failed to get raw");
        assert_ne!(raw, large_secret);

        let decrypted = storage
            .blobs()
            .get_decrypted_data(&blob_id, &keystore)
            .expect("Failed to decrypt chunked blob");
        assert_eq!(decrypted, large_secret);
    }

    let _ = fs::remove_dir_all(&root);
}
