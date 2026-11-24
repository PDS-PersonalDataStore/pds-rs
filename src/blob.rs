use crate::crypto::{CryptoError, KeyStore};
use crate::id::{BlobId, KeyId};
use rand::RngExt;
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

pub const FASTCDC_MIN_SIZE: usize = 16 * 1024; // 16 KiB
pub const FASTCDC_AVG_SIZE: usize = 128 * 1024; // 128 KiB
pub const FASTCDC_MAX_SIZE: usize = 1024 * 1024; // 1 MiB
pub const CHUNKING_THRESHOLD_BYTES: usize = 1024 * 1024; // > 1 MiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobChunk {
    pub sha256: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub id: BlobId,
    pub sha256: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    #[serde(default)]
    pub encryption: BlobEncryption,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Vec<BlobChunk>>,
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

    fn write_cas_file(&self, sha256: &str, data: &[u8]) -> io::Result<()> {
        let path = self.blob_path(sha256);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            fs::write(&path, data)?;
        }
        Ok(())
    }

    fn read_cas_file(&self, sha256: &str) -> Result<Vec<u8>, BlobError> {
        let path = self.blob_path(sha256);
        let data = fs::read(&path)?;
        let actual_hash = Self::compute_sha256(&data);
        if actual_hash != sha256 {
            return Err(BlobError::IntegrityMismatch {
                expected: sha256.to_string(),
                actual: actual_hash,
            });
        }
        Ok(data)
    }

    pub fn derive_chunk_nonce(base_nonce: &[u8; 12], chunk_index: u32) -> [u8; 12] {
        let mut chunk_nonce = *base_nonce;
        let index_bytes = chunk_index.to_le_bytes();
        for i in 0..4 {
            chunk_nonce[8 + i] ^= index_bytes[i];
        }
        chunk_nonce
    }

    pub fn put(
        &mut self,
        id: BlobId,
        data: &[u8],
        mime_type: Option<String>,
    ) -> Result<BlobDescriptor, BlobError> {
        let sha256 = Self::compute_sha256(data);

        let chunks = if data.len() > CHUNKING_THRESHOLD_BYTES {
            let chunker = fastcdc::v2020::FastCDC::new(
                data,
                FASTCDC_MIN_SIZE,
                FASTCDC_AVG_SIZE,
                FASTCDC_MAX_SIZE,
            );
            let mut chunk_list = Vec::new();
            for entry in chunker {
                let chunk_slice = &data[entry.offset..entry.offset + entry.length];
                let chunk_sha256 = Self::compute_sha256(chunk_slice);
                self.write_cas_file(&chunk_sha256, chunk_slice)?;
                chunk_list.push(BlobChunk {
                    sha256: chunk_sha256,
                    offset: entry.offset as u64,
                    length: entry.length as u64,
                });
            }
            Some(chunk_list)
        } else {
            self.write_cas_file(&sha256, data)?;
            None
        };

        let descriptor = BlobDescriptor {
            id,
            sha256,
            size_bytes: data.len() as u64,
            mime_type,
            encryption: BlobEncryption::Plaintext,
            chunks,
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
        if plaintext.len() > CHUNKING_THRESHOLD_BYTES {
            let mut base_nonce = [0u8; 12];
            rand::rng().fill(&mut base_nonce);

            let chunker = fastcdc::v2020::FastCDC::new(
                plaintext,
                FASTCDC_MIN_SIZE,
                FASTCDC_AVG_SIZE,
                FASTCDC_MAX_SIZE,
            );

            let mut chunk_list = Vec::new();
            let mut total_cipher_len: u64 = 0;
            let mut whole_hasher = Sha256::new();

            for (chunk_index, entry) in (0_u32..).zip(chunker) {
                let chunk_plain = &plaintext[entry.offset..entry.offset + entry.length];
                let chunk_nonce = Self::derive_chunk_nonce(&base_nonce, chunk_index);
                let enc_chunk = keystore.encrypt_with_nonce(&key_id, &chunk_nonce, chunk_plain)?;
                let chunk_sha256 = Self::compute_sha256(&enc_chunk.ciphertext);
                whole_hasher.update(&enc_chunk.ciphertext);

                self.write_cas_file(&chunk_sha256, &enc_chunk.ciphertext)?;
                let chunk_len = enc_chunk.ciphertext.len() as u64;
                chunk_list.push(BlobChunk {
                    sha256: chunk_sha256,
                    offset: total_cipher_len,
                    length: chunk_len,
                });
                total_cipher_len += chunk_len;
            }

            let sha256 = hex::encode(whole_hasher.finalize());

            let descriptor = BlobDescriptor {
                id,
                sha256,
                size_bytes: total_cipher_len,
                mime_type,
                encryption: BlobEncryption::Encrypted {
                    key_id,
                    nonce: base_nonce,
                    plaintext_size_bytes: plaintext.len() as u64,
                },
                chunks: Some(chunk_list),
            };

            self.persist_descriptor(&descriptor)?;
            self.descriptors.insert(id, descriptor.clone());
            Ok(descriptor)
        } else {
            let encrypted_data = keystore.encrypt(&key_id, plaintext)?;
            let sha256 = Self::compute_sha256(&encrypted_data.ciphertext);
            self.write_cas_file(&sha256, &encrypted_data.ciphertext)?;

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
                chunks: None,
            };

            self.persist_descriptor(&descriptor)?;
            self.descriptors.insert(id, descriptor.clone());
            Ok(descriptor)
        }
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

        self.write_cas_file(&descriptor.sha256, data)?;
        self.persist_descriptor(&descriptor)?;
        self.descriptors.insert(descriptor.id, descriptor);
        Ok(())
    }

    pub fn get_descriptor(&self, id: &BlobId) -> Option<&BlobDescriptor> {
        self.descriptors.get(id)
    }

    pub fn get_raw_data(&self, id: &BlobId) -> Result<Vec<u8>, BlobError> {
        let descriptor = self.descriptors.get(id).ok_or(BlobError::NotFound(*id))?;

        if let Some(chunks) = &descriptor.chunks {
            let mut combined = Vec::with_capacity(descriptor.size_bytes as usize);
            for chunk in chunks {
                let chunk_data = self.read_cas_file(&chunk.sha256)?;
                combined.extend_from_slice(&chunk_data);
            }
            let actual_hash = Self::compute_sha256(&combined);
            if actual_hash != descriptor.sha256 {
                return Err(BlobError::IntegrityMismatch {
                    expected: descriptor.sha256.clone(),
                    actual: actual_hash,
                });
            }
            Ok(combined)
        } else {
            self.read_cas_file(&descriptor.sha256)
        }
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

        match &descriptor.encryption {
            BlobEncryption::Plaintext => self.get_raw_data(id),
            BlobEncryption::Encrypted {
                key_id,
                nonce,
                plaintext_size_bytes,
            } => {
                if let Some(chunks) = &descriptor.chunks {
                    let mut plaintext = Vec::with_capacity(*plaintext_size_bytes as usize);
                    for (index, chunk) in chunks.iter().enumerate() {
                        let chunk_cipher = self.read_cas_file(&chunk.sha256)?;
                        let chunk_nonce = Self::derive_chunk_nonce(nonce, index as u32);
                        let enc_data = crate::crypto::EncryptedData {
                            key_id: *key_id,
                            nonce: chunk_nonce,
                            ciphertext: chunk_cipher,
                        };
                        let chunk_plain = keystore.decrypt(&enc_data)?;
                        plaintext.extend_from_slice(&chunk_plain);
                    }
                    Ok(plaintext)
                } else {
                    let raw_data = self.get_raw_data(id)?;
                    let enc_data = crate::crypto::EncryptedData {
                        key_id: *key_id,
                        nonce: *nonce,
                        ciphertext: raw_data,
                    };
                    let plain = keystore.decrypt(&enc_data)?;
                    Ok(plain)
                }
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

    #[test]
    fn test_blob_store_fastcdc_chunking_plaintext_and_encrypted() {
        let temp_dir = std::env::temp_dir().join(format!("pds_blob_chunk_test_{}", BlobId::new()));
        let mut store = BlobStore::new(&temp_dir).unwrap();
        let mut keystore = KeyStore::new();
        let (key_id, _) = keystore.generate_key();

        // 1. Create large data payload > 1 MiB (e.g. 1.5 MiB with repeating patterned content)
        let total_size = 1536 * 1024; // 1.5 MiB
        let mut large_data = Vec::with_capacity(total_size);
        for i in 0..total_size {
            large_data.push((i % 251) as u8);
        }

        // 2. Put large plaintext blob
        let plain_id = BlobId::new();
        let plain_desc = store
            .put(
                plain_id,
                &large_data,
                Some("application/octet-stream".into()),
            )
            .unwrap();

        assert!(plain_desc.chunks.is_some());
        let chunks = plain_desc.chunks.as_ref().unwrap();
        assert!(chunks.len() > 1, "Must have split into multiple chunks");

        // Verify total length matches sum of chunks
        let total_chunks_len: u64 = chunks.iter().map(|c| c.length).sum();
        assert_eq!(total_chunks_len, large_data.len() as u64);

        // Verify retrieval of chunked plaintext blob
        let retrieved_plain = store.get_data(&plain_id).unwrap();
        assert_eq!(retrieved_plain, large_data);

        // 3. Put large encrypted blob
        let enc_id = BlobId::new();
        let enc_desc = store
            .put_encrypted(
                enc_id,
                &large_data,
                key_id,
                &keystore,
                Some("application/octet-stream".into()),
            )
            .unwrap();

        assert!(enc_desc.chunks.is_some());
        let enc_chunks = enc_desc.chunks.as_ref().unwrap();
        assert!(enc_chunks.len() > 1);

        // Raw data should be combined ciphertexts
        let raw_cipher = store.get_raw_data(&enc_id).unwrap();
        assert_ne!(raw_cipher, large_data);

        // Decryption of chunked encrypted blob must succeed and reconstruct original payload
        let decrypted_large = store.get_decrypted_data(&enc_id, &keystore).unwrap();
        assert_eq!(decrypted_large, large_data);

        // 4. Persistence check: Reload store from disk and verify chunked blob recovery
        let reloaded_store = BlobStore::new(&temp_dir).unwrap();
        let reloaded_plain = reloaded_store.get_data(&plain_id).unwrap();
        assert_eq!(reloaded_plain, large_data);

        let reloaded_enc = reloaded_store
            .get_decrypted_data(&enc_id, &keystore)
            .unwrap();
        assert_eq!(reloaded_enc, large_data);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
