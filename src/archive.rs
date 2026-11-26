//! Dataset export and import archive format definitions.

use crate::blob::BlobDescriptor;
use crate::change::Change;
use crate::schema::EntitySchema;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata describing a PDS archive package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PdsArchiveMetadata {
    /// Archive format version number.
    pub format_version: u32,
    /// Timestamp when the archive was generated.
    pub exported_at: DateTime<Utc>,
    /// Semantic version of the PDS software that created the archive.
    pub pds_version: String,
    /// Number of changes contained in the archive.
    pub change_count: usize,
    /// Number of blob descriptors contained in the archive.
    pub blob_count: usize,
}

/// Represents a complete exportable PDS dataset archive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PdsArchive {
    /// Metadata header of the archive.
    pub metadata: PdsArchiveMetadata,
    /// List of historical changes in the dataset.
    pub changes: Vec<Change>,
    /// List of registered entity schemas.
    pub schemas: Vec<EntitySchema>,
    /// Descriptors of all binary blobs referenced by the dataset.
    pub blob_descriptors: Vec<BlobDescriptor>,
}

impl PdsArchive {
    /// Creates a new dataset archive and calculates metadata metrics.
    pub fn new(
        changes: Vec<Change>,
        schemas: Vec<EntitySchema>,
        blob_descriptors: Vec<BlobDescriptor>,
    ) -> Self {
        let metadata = PdsArchiveMetadata {
            format_version: 1,
            exported_at: Utc::now(),
            pds_version: env!("CARGO_PKG_VERSION").to_string(),
            change_count: changes.len(),
            blob_count: blob_descriptors.len(),
        };

        Self {
            metadata,
            changes,
            schemas,
            blob_descriptors,
        }
    }

    /// Serializes the archive into a formatted JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes an archive from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_serde() {
        let archive = PdsArchive::new(vec![], vec![], vec![]);
        let json = archive.to_json().unwrap();
        let restored = PdsArchive::from_json(&json).unwrap();
        assert_eq!(
            archive.metadata.format_version,
            restored.metadata.format_version
        );
        assert_eq!(archive.changes.len(), restored.changes.len());
    }
}
