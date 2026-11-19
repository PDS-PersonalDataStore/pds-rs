use crate::auth::ClientId;
use crate::blob::{BlobError, BlobStore};
use crate::change::Change;
use crate::dag::{DagError, HistoryDag};
use crate::id::ChangeId;
use crate::state::DatasetState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("DAG error: {0}")]
    Dag(#[from] DagError),
    #[error("Blob error: {0}")]
    Blob(#[from] BlobError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCursor {
    pub client_id: ClientId,
    pub last_ack_change_id: Option<ChangeId>,
    pub updated_at: DateTime<Utc>,
}

pub struct DiskStorage {
    root_dir: PathBuf,
    dag: HistoryDag,
    state: DatasetState,
    blobs: BlobStore,
    cursors: BTreeMap<ClientId, ClientCursor>,
}

impl DiskStorage {
    pub fn open(root_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;

        let blob_dir = root_dir.join("blobs");
        let blobs = BlobStore::new(blob_dir)?;

        let mut storage = Self {
            root_dir,
            dag: HistoryDag::new(),
            state: DatasetState::new(),
            blobs,
            cursors: BTreeMap::new(),
        };

        storage.load_history()?;
        storage.load_cursors()?;
        Ok(storage)
    }

    fn history_file_path(&self) -> PathBuf {
        self.root_dir.join("history.jsonl")
    }

    fn load_history(&mut self) -> Result<(), StorageError> {
        let path = self.history_file_path();
        if !path.exists() {
            return Ok(());
        }

        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let change: Change = serde_json::from_str(&line)?;
            self.dag.insert(change)?;
        }

        self.state = DatasetState::from_dag(&self.dag);
        Ok(())
    }

    pub fn append_change(&mut self, change: Change) -> Result<(), StorageError> {
        self.dag.insert(change.clone())?;
        self.state.apply_change(&change);

        let path = self.history_file_path();
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;

        let serialized = serde_json::to_string(&change)?;
        writeln!(file, "{}", serialized)?;
        file.flush()?;

        Ok(())
    }

    pub fn dag(&self) -> &HistoryDag {
        &self.dag
    }

    pub fn state(&self) -> &DatasetState {
        &self.state
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    pub fn blobs_mut(&mut self) -> &mut BlobStore {
        &mut self.blobs
    }

    pub fn change_count(&self) -> usize {
        self.dag.len()
    }

    pub fn get_change(&self, id: &ChangeId) -> Option<&Change> {
        self.dag.get(id)
    }

    fn cursors_file_path(&self) -> PathBuf {
        self.root_dir.join("client_cursors.json")
    }

    fn load_cursors(&mut self) -> Result<(), StorageError> {
        let path = self.cursors_file_path();
        if !path.exists() {
            return Ok(());
        }
        let data = fs::read_to_string(path)?;
        if data.trim().is_empty() {
            return Ok(());
        }
        self.cursors = serde_json::from_str(&data)?;
        Ok(())
    }

    fn save_cursors(&self) -> Result<(), StorageError> {
        let path = self.cursors_file_path();
        let serialized = serde_json::to_string_pretty(&self.cursors)?;
        fs::write(path, serialized)?;
        Ok(())
    }

    pub fn get_client_cursor(&self, client_id: &ClientId) -> Option<ChangeId> {
        self.cursors
            .get(client_id)
            .and_then(|c| c.last_ack_change_id)
    }

    pub fn set_client_cursor(
        &mut self,
        client_id: ClientId,
        change_id: Option<ChangeId>,
    ) -> Result<(), StorageError> {
        let cursor = ClientCursor {
            client_id,
            last_ack_change_id: change_id,
            updated_at: Utc::now(),
        };
        self.cursors.insert(client_id, cursor);
        self.save_cursors()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::ChangeMetadata;
    use crate::id::EntityId;
    use crate::operation::Operation;
    use crate::value::PropertyValue;

    #[test]
    fn test_disk_storage_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("pds_disk_test_{}", EntityId::new()));

        let entity_id = EntityId::new();
        let c1_id = ChangeId::new();

        {
            let mut storage = DiskStorage::open(&temp_dir).unwrap();
            let c1 = Change::new(
                c1_id,
                vec![],
                ChangeMetadata::new("laptop-1"),
                vec![
                    Operation::CreateEntity {
                        entity_id,
                        entity_type: Some("doc".into()),
                    },
                    Operation::SetEntityProperty {
                        entity_id,
                        name: "name".into(),
                        value: PropertyValue::from("Specyfikacja"),
                    },
                ],
            );
            storage.append_change(c1).unwrap();
            assert_eq!(storage.change_count(), 1);
        }

        {
            let storage = DiskStorage::open(&temp_dir).unwrap();
            assert_eq!(storage.change_count(), 1);
            let entity = storage.state().entities.get(&entity_id).unwrap();
            assert_eq!(entity.entity_type.as_deref(), Some("doc"));
            assert_eq!(
                entity.get_property(&"name".into()),
                Some(&PropertyValue::from("Specyfikacja"))
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_client_cursor_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("pds_cursor_test_{}", EntityId::new()));
        let client_id = ClientId::new();
        let change_id = ChangeId::new();

        {
            let mut storage = DiskStorage::open(&temp_dir).unwrap();
            assert_eq!(storage.get_client_cursor(&client_id), None);
            storage
                .set_client_cursor(client_id, Some(change_id))
                .unwrap();
            assert_eq!(storage.get_client_cursor(&client_id), Some(change_id));
        }

        {
            let storage = DiskStorage::open(&temp_dir).unwrap();
            assert_eq!(storage.get_client_cursor(&client_id), Some(change_id));
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
