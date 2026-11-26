use crate::id::{ChangeId, KeyId};
use crate::operation::Operation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Encryption mode for change data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EncryptionMode {
    /// Store data without encryption.
    #[default]
    Plaintext,
    /// Encrypt operation payloads while keeping metadata in plaintext.
    EncryptedPayload {
        /// Identifier of the encryption key.
        key_id: KeyId,
        /// Nonce used for symmetric encryption.
        nonce: [u8; 12],
    },
    /// Encrypt both operations and metadata.
    BlindChange {
        /// Identifier of the encryption key.
        key_id: KeyId,
        /// Nonce used for symmetric encryption.
        nonce: [u8; 12],
        /// Authentication tag verifying ciphertext integrity.
        auth_tag: [u8; 16],
    },
}

/// Metadata associated with a change record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeMetadata {
    /// Optional identifier of the author.
    pub author_id: Option<String>,
    /// Identifier of the device that created the change.
    pub device_id: String,
    /// Timestamp when the change occurred.
    pub timestamp: DateTime<Utc>,
    /// Optional descriptive message.
    pub message: Option<String>,
    /// Encryption mode applied to the change.
    #[serde(default)]
    pub encryption_mode: EncryptionMode,
}

impl ChangeMetadata {
    /// Creates a new metadata record with the specified device identifier.
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            author_id: None,
            device_id: device_id.into(),
            timestamp: Utc::now(),
            message: None,
            encryption_mode: EncryptionMode::Plaintext,
        }
    }

    /// Sets the author identifier.
    pub fn with_author(mut self, author_id: impl Into<String>) -> Self {
        self.author_id = Some(author_id.into());
        self
    }

    /// Sets the commit message.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Sets the encryption mode.
    pub fn with_encryption_mode(mut self, mode: EncryptionMode) -> Self {
        self.encryption_mode = mode;
        self
    }
}

/// Record representing an atomic set of operations in the history graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    /// Unique identifier of this change.
    pub id: ChangeId,
    /// Identifiers of parent changes in the history graph.
    pub parents: Vec<ChangeId>,
    /// Metadata describing this change.
    pub metadata: ChangeMetadata,
    /// List of operations included in this change.
    pub operations: Vec<Operation>,
}

impl Change {
    /// Creates a new change record with the provided parameters.
    pub fn new(
        id: ChangeId,
        parents: Vec<ChangeId>,
        metadata: ChangeMetadata,
        operations: Vec<Operation>,
    ) -> Self {
        Self {
            id,
            parents,
            metadata,
            operations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::EntityId;

    #[test]
    fn test_change_serialization() {
        let meta = ChangeMetadata::new("device-laptop")
            .with_author("user-alice")
            .with_message("Add first entity");

        let entity_id = EntityId::new();
        let ops = vec![Operation::CreateEntity {
            entity_id,
            entity_type: Some("note".into()),
        }];

        let change = Change::new(ChangeId::new(), vec![], meta, ops);
        let json = serde_json::to_string(&change).unwrap();
        let deserialized: Change = serde_json::from_str(&json).unwrap();

        assert_eq!(change, deserialized);
    }
}
