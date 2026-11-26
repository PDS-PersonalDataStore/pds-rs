//! Binary serialization and deserialization using CBOR and SHA-256 checksums.

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

/// Magic 4-byte header identifying PDS binary payloads.
pub const PDS_MAGIC_HEADER: &[u8; 4] = b"PDS1";

/// Errors produced during binary encoding and decoding.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// Magic header does not match the expected value.
    #[error("Invalid magic header: expected {expected:?}, got {actual:?}")]
    InvalidMagic {
        /// Expected 4-byte header.
        expected: [u8; 4],
        /// Actual 4-byte header found in the payload.
        actual: [u8; 4],
    },
    /// Data buffer is too short to contain the header and checksum.
    #[error("Data too short to contain magic header and checksum")]
    TooShort,
    /// Computed checksum does not match the stored checksum.
    #[error("Checksum mismatch: expected {expected:?}, got {actual:?}")]
    ChecksumMismatch {
        /// Expected SHA-256 checksum.
        expected: [u8; 32],
        /// Actual calculated SHA-256 checksum.
        actual: [u8; 32],
    },
    /// CBOR serialization failure.
    #[error("CBOR serialization error: {0}")]
    CborSer(String),
    /// CBOR deserialization failure.
    #[error("CBOR deserialization error: {0}")]
    CborDe(String),
}

/// Provides binary encoding and decoding routines with checksum verification.
pub struct BinaryCodec;

impl BinaryCodec {
    /// Serializes a value into CBOR bytes prefixed with magic header and SHA-256 checksum.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
        let mut payload = Vec::new();
        ciborium::into_writer(value, &mut payload)
            .map_err(|e| CodecError::CborSer(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let checksum: [u8; 32] = hasher.finalize().into();

        let mut output = Vec::with_capacity(4 + 32 + payload.len());
        output.extend_from_slice(PDS_MAGIC_HEADER);
        output.extend_from_slice(&checksum);
        output.extend_from_slice(&payload);

        Ok(output)
    }

    /// Validates header and checksum, then deserializes a value from CBOR bytes.
    pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
        if bytes.len() < 36 {
            return Err(CodecError::TooShort);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[..4]);
        if magic != *PDS_MAGIC_HEADER {
            return Err(CodecError::InvalidMagic {
                expected: *PDS_MAGIC_HEADER,
                actual: magic,
            });
        }

        let mut expected_checksum = [0u8; 32];
        expected_checksum.copy_from_slice(&bytes[4..36]);

        let payload = &bytes[36..];
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let actual_checksum: [u8; 32] = hasher.finalize().into();

        if expected_checksum != actual_checksum {
            return Err(CodecError::ChecksumMismatch {
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }

        let value: T =
            ciborium::from_reader(payload).map_err(|e| CodecError::CborDe(e.to_string()))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{Change, ChangeMetadata};
    use crate::id::{ChangeId, EntityId};
    use crate::operation::Operation;
    use crate::value::PropertyValue;

    #[test]
    fn test_binary_codec_roundtrip() {
        let entity_id = EntityId::new();
        let change = Change::new(
            ChangeId::new(),
            vec![],
            ChangeMetadata::new("device-binary"),
            vec![
                Operation::CreateEntity {
                    entity_id,
                    entity_type: Some("binary_item".into()),
                },
                Operation::SetEntityProperty {
                    entity_id,
                    name: "weight".into(),
                    value: PropertyValue::from(100),
                },
            ],
        );

        let encoded = BinaryCodec::encode(&change).unwrap();
        assert_eq!(&encoded[..4], PDS_MAGIC_HEADER);

        let decoded: Change = BinaryCodec::decode(&encoded).unwrap();
        assert_eq!(change, decoded);
    }

    #[test]
    fn test_binary_codec_checksum_tampering() {
        let val = vec![1u32, 2, 3, 4, 5];
        let mut encoded = BinaryCodec::encode(&val).unwrap();

        // Tamper with payload byte
        let last_idx = encoded.len() - 1;
        encoded[last_idx] ^= 0xFF;

        let result: Result<Vec<u32>, CodecError> = BinaryCodec::decode(&encoded);
        assert!(matches!(result, Err(CodecError::ChecksumMismatch { .. })));
    }
}
