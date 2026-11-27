//! High-level client API providing secure access to entities, relations, and blobs.

use crate::change::{Change, ChangeMetadata};
use crate::entity::Entity;
use crate::id::{ChangeId, EntityId, RelationId};
use crate::operation::Operation;

use crate::relation::Relation;
use crate::security::{AccessController, Permission, SecurityError};
use crate::storage::{DiskStorage, StorageError};
use crate::value::{PropertyName, PropertyValue};

/// Errors produced during client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Security permission check failed.
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),
    /// Storage operation failed.
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    /// Relation operation failed.
    #[error("Relation error: {0}")]
    Relation(#[from] crate::relation::RelationError),
    /// Blob operation failed.
    #[error("Blob error: {0}")]
    Blob(#[from] crate::blob::BlobError),
    /// Referenced entity was not found.
    #[error("Entity not found: {0}")]
    EntityNotFound(EntityId),
    /// Referenced relation was not found.
    #[error("Relation not found: {0}")]
    RelationNotFound(RelationId),
}

/// Client interface for interacting with a PDS storage backend under permission checks.
pub struct PdsClient<'a> {
    app_id: String,
    device_id: String,
    security: &'a AccessController,
    storage: &'a mut DiskStorage,
}

impl<'a> PdsClient<'a> {
    /// Creates a new PDS client for a specific application and device.
    pub fn new(
        app_id: impl Into<String>,
        device_id: impl Into<String>,
        security: &'a AccessController,
        storage: &'a mut DiskStorage,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            device_id: device_id.into(),
            security,
            storage,
        }
    }

    /// Retrieves an entity by its identifier if present and allowed.
    pub fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::ReadEntities)?;
        Ok(self.storage.state().entities.get(id).cloned())
    }

    /// Retrieves a relation by its identifier if present and allowed.
    pub fn get_relation(&self, id: &RelationId) -> Result<Option<Relation>, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::ReadEntities)?;
        Ok(self.storage.state().relations.get(id).cloned())
    }

    /// Creates a new entity with the specified type and properties.
    pub fn create_entity(
        &mut self,
        entity_type: Option<String>,
        properties: Vec<(PropertyName, PropertyValue)>,
    ) -> Result<EntityId, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::WriteEntities)?;

        let entity_id = EntityId::new();
        let mut ops = vec![Operation::CreateEntity {
            entity_id,
            entity_type,
        }];

        for (name, val) in properties {
            ops.push(Operation::SetEntityProperty {
                entity_id,
                name,
                value: val,
            });
        }

        let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
        let meta = ChangeMetadata::new(&self.device_id).with_author(&self.app_id);
        let change = Change::new(ChangeId::new(), parents, meta, ops);

        self.storage.append_change(change)?;
        Ok(entity_id)
    }

    /// Creates a binary relation between two entities.
    pub fn create_relation(
        &mut self,
        relation_type: impl Into<String>,
        source: EntityId,
        target: EntityId,
    ) -> Result<RelationId, ClientError> {
        let members = vec![
            crate::relation::RelationMember::new(source, "source"),
            crate::relation::RelationMember::new(target, "target"),
        ];
        self.create_multimember_relation(relation_type, members)
    }

    /// Creates a multi-member relation with specified participants and roles.
    pub fn create_multimember_relation(
        &mut self,
        relation_type: impl Into<String>,
        members: Vec<crate::relation::RelationMember>,
    ) -> Result<RelationId, ClientError> {
        if members.is_empty() {
            return Err(crate::relation::RelationError::EmptyMembers.into());
        }

        self.security
            .check_permission(&self.app_id, &Permission::WriteEntities)?;

        let relation_id = RelationId::new();
        let ops = vec![Operation::CreateRelation {
            relation_id,
            relation_type: relation_type.into(),
            members,
        }];

        let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
        let meta = ChangeMetadata::new(&self.device_id).with_author(&self.app_id);
        let change = Change::new(ChangeId::new(), parents, meta, ops);

        self.storage.append_change(change)?;
        Ok(relation_id)
    }

    /// Stores an unencrypted binary blob with optional MIME media type.
    pub fn put_blob(
        &mut self,
        data: &[u8],
        mime_type: Option<String>,
    ) -> Result<crate::blob::BlobDescriptor, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::WriteBlobs)?;
        let blob_id = crate::id::BlobId::new();
        let descriptor = self.storage.blobs_mut().put(blob_id, data, mime_type)?;
        Ok(descriptor)
    }

    /// Encrypts and stores a binary blob using the specified encryption key.
    pub fn put_encrypted_blob(
        &mut self,
        plaintext: &[u8],
        key_id: crate::id::KeyId,
        keystore: &crate::crypto::KeyStore,
        mime_type: Option<String>,
    ) -> Result<crate::blob::BlobDescriptor, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::WriteBlobs)?;
        self.security
            .check_permission(&self.app_id, &Permission::ReadCryptoKeys)?;
        let blob_id = crate::id::BlobId::new();
        let descriptor = self
            .storage
            .blobs_mut()
            .put_encrypted(blob_id, plaintext, key_id, keystore, mime_type)?;
        Ok(descriptor)
    }

    /// Retrieves the metadata descriptor of a binary blob if present.
    pub fn get_blob_descriptor(
        &self,
        id: &crate::id::BlobId,
    ) -> Result<Option<crate::blob::BlobDescriptor>, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::ReadBlobs)?;
        Ok(self.storage.blobs().get_descriptor(id).cloned())
    }

    /// Retrieves the byte content of a binary blob.
    pub fn get_blob(&self, id: &crate::id::BlobId) -> Result<Vec<u8>, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::ReadBlobs)?;
        let data = self.storage.blobs().get_data(id)?;
        Ok(data)
    }

    /// Retrieves raw blob bytes without attempting automatic decryption.
    pub fn get_raw_blob(&self, id: &crate::id::BlobId) -> Result<Vec<u8>, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::ReadBlobs)?;
        let data = self.storage.blobs().get_raw_data(id)?;
        Ok(data)
    }

    /// Retrieves and decrypts a binary blob using the provided key store.
    pub fn get_decrypted_blob(
        &self,
        id: &crate::id::BlobId,
        keystore: &crate::crypto::KeyStore,
    ) -> Result<Vec<u8>, ClientError> {
        self.security
            .check_permission(&self.app_id, &Permission::ReadBlobs)?;
        self.security
            .check_permission(&self.app_id, &Permission::ReadCryptoKeys)?;
        let data = self.storage.blobs().get_decrypted_data(id, keystore)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::AppRegistration;
    use std::fs;

    #[test]
    fn test_client_enforces_permissions() {
        let temp_dir = std::env::temp_dir().join(format!("pds_client_test_{}", EntityId::new()));
        let mut storage = DiskStorage::open(&temp_dir).unwrap();
        let mut security = AccessController::new();

        let mut app = AppRegistration::new("app:reader", "Reader App");
        app.grant(Permission::ReadEntities);
        security.register_app(app);

        // App reader tries to write entity - should fail
        let mut client = PdsClient::new("app:reader", "dev-1", &security, &mut storage);
        let result = client.create_entity(Some("note".into()), vec![]);
        assert!(matches!(result, Err(ClientError::Security(_))));

        // Grant write permission
        let mut app_writer = AppRegistration::new("app:writer", "Writer App");
        app_writer.grant(Permission::ReadEntities);
        app_writer.grant(Permission::WriteEntities);
        security.register_app(app_writer);

        let mut client_writer = PdsClient::new("app:writer", "dev-1", &security, &mut storage);
        let e_id = client_writer
            .create_entity(
                Some("note".into()),
                vec![("title".into(), PropertyValue::from("Witaj PDS"))],
            )
            .unwrap();

        let loaded = client_writer.get_entity(&e_id).unwrap().unwrap();
        assert_eq!(
            loaded.get_property(&"title".into()),
            Some(&PropertyValue::from("Witaj PDS"))
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_client_blob_operations() {
        let temp_dir =
            std::env::temp_dir().join(format!("pds_client_blob_test_{}", EntityId::new()));
        let mut storage = DiskStorage::open(&temp_dir).unwrap();
        let mut security = AccessController::new();

        let mut app = AppRegistration::new("app:blobber", "Blob App");
        app.grant(Permission::ReadBlobs);
        app.grant(Permission::WriteBlobs);
        app.grant(Permission::ReadCryptoKeys);
        security.register_app(app);

        let mut client = PdsClient::new("app:blobber", "dev-1", &security, &mut storage);

        // 1. Plaintext blob
        let data = b"Hello unencrypted world";
        let desc = client.put_blob(data, Some("text/plain".into())).unwrap();
        assert_eq!(desc.size_bytes, data.len() as u64);

        let read_desc = client.get_blob_descriptor(&desc.id).unwrap().unwrap();
        assert_eq!(read_desc.id, desc.id);

        let fetched = client.get_blob(&desc.id).unwrap();
        assert_eq!(fetched, data);

        // 2. Encrypted blob
        let mut keystore = crate::crypto::KeyStore::new();
        let key_id = crate::id::KeyId::new();
        let key_bytes = [7u8; 32];
        keystore.insert_key(key_id, key_bytes);

        let secret = b"Top secret personal payload";
        let enc_desc = client
            .put_encrypted_blob(
                secret,
                key_id,
                &keystore,
                Some("application/octet-stream".into()),
            )
            .unwrap();

        // get_blob should fail because it requires keystore for encrypted blob
        let direct_get = client.get_blob(&enc_desc.id);
        assert!(direct_get.is_err());

        // get_raw_blob should succeed and return ciphertext
        let raw_data = client.get_raw_blob(&enc_desc.id).unwrap();
        assert_ne!(raw_data, secret);

        // get_decrypted_blob with keystore should succeed
        let decrypted = client.get_decrypted_blob(&enc_desc.id, &keystore).unwrap();
        assert_eq!(decrypted, secret);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
