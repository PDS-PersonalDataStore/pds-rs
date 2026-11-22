use crate::crypto::{CryptoError, KeyStore};
use crate::id::{BlobId, KeyId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Integrity check failed. Expected hash: {expected}, got: {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    #[error("Blob not found: {0}")]
    NotFound(BlobId),
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Blob is encrypted and requires a keystore")]
    EncryptedBlobRequiresKeystore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", content = "details")]
pub enum BlobEncryption {
    #[default]
    Plaintext,
    Encrypted {
        key_id: KeyId,
        nonce: [u8; 12],
        plaintext_size_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub id: BlobId,
    pub sha256: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    #[serde(default)]
    pub encryption: BlobEncryption,
}

#[derive(Debug, Clone)]
pub struct BlobStore {
    root_dir: PathBuf,
    descriptors: BTreeMap<BlobId, BlobDescriptor>,
}

impl BlobStore {
    pub fn new(root_dir: impl AsRef<Path>) -> io::Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;
        let mut store = Self {
            root_dir,
            descriptors: BTreeMap::new(),
        };
        store.load_descriptors()?;
        Ok(store)
    }

    fn meta_dir(&self) -> PathBuf {
        self.root_dir.join("meta")
    }

    fn load_descriptors(&mut self) -> io::Result<()> {
        let meta_dir = self.meta_dir();
        if meta_dir.exists() {
            for entry in fs::read_dir(meta_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json")
                    && let Ok(content) = fs::read_to_string(&path)
                    && let Ok(descriptor) = serde_json::from_str::<BlobDescriptor>(&content)
                {
                    self.descriptors.insert(descriptor.id, descriptor);
                }
            }
        }
        Ok(())
    }

    fn persist_descriptor(&self, descriptor: &BlobDescriptor) -> io::Result<()> {
        let meta_dir = self.meta_dir();
        fs::create_dir_all(&meta_dir)?;
        let desc_path = meta_dir.join(format!("{}.json", descriptor.id));
        let serialized = serde_json::to_string_pretty(descriptor)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(desc_path, serialized)?;
        Ok(())
    }

    pub fn compute_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        let prefix = &sha256[..2];
        let rest = &sha256[2..];
        self.root_dir.join(prefix).join(rest)
    }

    pub fn put(
        &mut self,
        id: BlobId,
        data: &[u8],
        mime_type: Option<String>,
    ) -> Result<BlobDescriptor, BlobError> {
        let sha256 = Self::compute_sha256(data);
        let path = self.blob_path(&sha256);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if !path.exists() {
            fs::write(&path, data)?;
        }

        let descriptor = BlobDescriptor {
            id,
            sha256,
            size_bytes: data.len() as u64,
            mime_type,
            encryption: BlobEncryption::Plaintext,
        };

        self.persist_descriptor(&descriptor)?;
        self.descriptors.insert(id, descriptor.clone());
        Ok(descriptor)
    }

    pub fn put_encrypted(
        &mut self,
        id: BlobId,
        plaintext: &[u8],
        key_id: KeyId,
        keystore: &KeyStore,
        mime_type: Option<String>,
    ) -> Result<BlobDescriptor, BlobError> {
        let encrypted_data = keystore.encrypt(&key_id, plaintext)?;
        let sha256 = Self::compute_sha256(&encrypted_data.ciphertext);
        let path = self.blob_path(&sha256);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if !path.exists() {
            fs::write(&path, &encrypted_data.ciphertext)?;
        }

        let descriptor = BlobDescriptor {
            id,
            sha256,
            size_bytes: encrypted_data.ciphertext.len() as u64,
            mime_type,
            encryption: BlobEncryption::Encrypted {
                key_id,
                nonce: encrypted_data.nonce,
                plaintext_size_bytes: plaintext.len() as u64,
            },
        };

        self.persist_descriptor(&descriptor)?;
        self.descriptors.insert(id, descriptor.clone());
        Ok(descriptor)
    }

    pub fn put_descriptor_and_data(
        &mut self,
        descriptor: BlobDescriptor,
        data: &[u8],
    ) -> Result<(), BlobError> {
        let actual_hash = Self::compute_sha256(data);
        if actual_hash != descriptor.sha256 {
            return Err(BlobError::IntegrityMismatch {
                expected: descriptor.sha256.clone(),
                actual: actual_hash,
            });
        }

        let path = self.blob_path(&descriptor.sha256);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if !path.exists() {
            fs::write(&path, data)?;
        }

        self.persist_descriptor(&descriptor)?;
        self.descriptors.insert(descriptor.id, descriptor);
        Ok(())
    }

    pub fn get_descriptor(&self, id: &BlobId) -> Option<&BlobDescriptor> {
        self.descriptors.get(id)
    }

    pub fn get_raw_data(&self, id: &BlobId) -> Result<Vec<u8>, BlobError> {
        let descriptor = self.descriptors.get(id).ok_or(BlobError::NotFound(*id))?;
        let path = self.blob_path(&descriptor.sha256);
        let data = fs::read(&path)?;

        let actual_hash = Self::compute_sha256(&data);
        if actual_hash != descriptor.sha256 {
            return Err(BlobError::IntegrityMismatch {
                expected: descriptor.sha256.clone(),
                actual: actual_hash,
            });
        }

        Ok(data)
    }

    pub fn get_data(&self, id: &BlobId) -> Result<Vec<u8>, BlobError> {
        let descriptor = self.descriptors.get(id).ok_or(BlobError::NotFound(*id))?;
        match descriptor.encryption {
            BlobEncryption::Plaintext => self.get_raw_data(id),
            BlobEncryption::Encrypted { .. } => Err(BlobError::EncryptedBlobRequiresKeystore),
        }
    }

    pub fn get_decrypted_data(
        &self,
        id: &BlobId,
        keystore: &KeyStore,
    ) -> Result<Vec<u8>, BlobError> {
        let descriptor = self.descriptors.get(id).ok_or(BlobError::NotFound(*id))?;
        let raw_data = self.get_raw_data(id)?;

        match &descriptor.encryption {
            BlobEncryption::Plaintext => Ok(raw_data),
            BlobEncryption::Encrypted { key_id, nonce, .. } => {
                let enc_data = crate::crypto::EncryptedData {
                    key_id: *key_id,
                    nonce: *nonce,
                    ciphertext: raw_data,
                };
                let plaintext = keystore.decrypt(&enc_data)?;
                Ok(plaintext)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_store_cas_and_deduplication() {
        let temp_dir = std::env::temp_dir().join(format!("pds_blob_test_{}", BlobId::new()));
        let mut store = BlobStore::new(&temp_dir).unwrap();

        let data = b"Testowy plik binarny zawartosci PDS";
        let b1 = BlobId::new();
        let b2 = BlobId::new();

        let desc1 = store.put(b1, data, Some("text/plain".into())).unwrap();
        let desc2 = store.put(b2, data, Some("text/plain".into())).unwrap();

        assert_eq!(desc1.sha256, desc2.sha256);
        assert_eq!(desc1.size_bytes, data.len() as u64);

        let retrieved = store.get_data(&b1).unwrap();
        assert_eq!(retrieved, data);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_blob_store_encryption_and_decryption() {
        let temp_dir = std::env::temp_dir().join(format!("pds_blob_enc_test_{}", BlobId::new()));
        let mut store = BlobStore::new(&temp_dir).unwrap();
        let mut keystore = KeyStore::new();
        let (key_id, _) = keystore.generate_key();

        let secret_data = b"Encrypted medical image payload binary";
        let blob_id = BlobId::new();

        let desc = store
            .put_encrypted(
                blob_id,
                secret_data,
                key_id,
                &keystore,
                Some("application/octet-stream".into()),
            )
            .unwrap();

        match &desc.encryption {
            BlobEncryption::Encrypted {
                key_id: k_id,
                plaintext_size_bytes,
                ..
            } => {
                assert_eq!(*k_id, key_id);
                assert_eq!(*plaintext_size_bytes, secret_data.len() as u64);
            }
            _ => panic!("Expected Encrypted blob"),
        }

        // Raw data should be ciphertext (different from plaintext)
        let raw = store.get_raw_data(&blob_id).unwrap();
        assert_ne!(raw, secret_data);

        // Calling get_data without keystore should error
        assert!(matches!(
            store.get_data(&blob_id),
            Err(BlobError::EncryptedBlobRequiresKeystore)
        ));

        // Decryption with keystore should succeed
        let decrypted = store.get_decrypted_data(&blob_id, &keystore).unwrap();
        assert_eq!(decrypted, secret_data);

        // Decryption with empty keystore should fail
        let empty_keystore = KeyStore::new();
        assert!(store.get_decrypted_data(&blob_id, &empty_keystore).is_err());

        // Re-opening BlobStore should reload persisted descriptors
        let reloaded_store = BlobStore::new(&temp_dir).unwrap();
        let reloaded_desc = reloaded_store.get_descriptor(&blob_id).unwrap();
        assert_eq!(reloaded_desc.id, blob_id);
        assert_eq!(reloaded_desc.encryption, desc.encryption);
        let reloaded_decrypted = reloaded_store
            .get_decrypted_data(&blob_id, &keystore)
            .unwrap();
        assert_eq!(reloaded_decrypted, secret_data);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
