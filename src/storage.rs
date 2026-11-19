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
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
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

pub struct SqliteStorage {
    root_dir: PathBuf,
    conn: rusqlite::Connection,
    dag: HistoryDag,
    state: DatasetState,
    blobs: BlobStore,
}

impl SqliteStorage {
    pub fn open(root_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;

        let blob_dir = root_dir.join("blobs");
        let blobs = BlobStore::new(blob_dir)?;

        let db_path = root_dir.join("pds.db");
        let conn = rusqlite::Connection::open(&db_path)?;

        // WAL mode & normal synchronous for speed + crash consistency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS changes (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS client_cursors (
                client_id TEXT PRIMARY KEY,
                last_ack_change_id TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_changes_created_at ON changes(created_at);
            ",
        )?;

        let mut storage = Self {
            root_dir,
            conn,
            dag: HistoryDag::new(),
            state: DatasetState::new(),
            blobs,
        };

        storage.load_history_from_db()?;
        Ok(storage)
    }

    fn load_history_from_db(&mut self) -> Result<(), StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM changes ORDER BY rowid ASC")?;
        let rows = stmt.query_map([], |row| {
            let data: String = row.get(0)?;
            Ok(data)
        })?;

        for row in rows {
            let json_str = row?;
            let change: Change = serde_json::from_str(&json_str)?;
            self.dag.insert(change)?;
        }

        self.state = DatasetState::from_dag(&self.dag);
        Ok(())
    }

    pub fn append_change(&mut self, change: Change) -> Result<(), StorageError> {
        self.dag.insert(change.clone())?;
        self.state.apply_change(&change);

        let serialized = serde_json::to_string(&change)?;
        let id_str = change.id.to_string();
        let created_at = change.metadata.timestamp.to_rfc3339();

        self.conn.execute(
            "INSERT INTO changes (id, data, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![id_str, serialized, created_at],
        )?;

        Ok(())
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
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

    pub fn get_client_cursor(&self, client_id: &ClientId) -> Option<ChangeId> {
        let client_id_str = client_id.to_string();
        let res: rusqlite::Result<Option<String>> = self.conn.query_row(
            "SELECT last_ack_change_id FROM client_cursors WHERE client_id = ?1",
            rusqlite::params![client_id_str],
            |row| row.get(0),
        );

        match res {
            Ok(Some(id_str)) => id_str.parse::<ChangeId>().ok(),
            _ => None,
        }
    }

    pub fn set_client_cursor(
        &mut self,
        client_id: ClientId,
        change_id: Option<ChangeId>,
    ) -> Result<(), StorageError> {
        let client_id_str = client_id.to_string();
        let change_id_str = change_id.map(|id| id.to_string());
        let updated_at = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO client_cursors (client_id, last_ack_change_id, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(client_id) DO UPDATE SET
                last_ack_change_id = excluded.last_ack_change_id,
                updated_at = excluded.updated_at",
            rusqlite::params![client_id_str, change_id_str, updated_at],
        )?;

        Ok(())
    }

    /// Migrates existing DiskStorage (history.jsonl & client_cursors.json) into this SqliteStorage instance
    pub fn migrate_from_disk_storage(root_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root_dir = root_dir.as_ref();
        let disk = DiskStorage::open(root_dir)?;
        let mut sqlite = Self::open(root_dir)?;

        let tx = sqlite.conn.transaction()?;
        {
            let mut insert_change = tx.prepare(
                "INSERT OR IGNORE INTO changes (id, data, created_at) VALUES (?1, ?2, ?3)",
            )?;
            for change in disk.dag().topological_order() {
                let id_str = change.id.to_string();
                let serialized = serde_json::to_string(change)?;
                let created_at = change.metadata.timestamp.to_rfc3339();
                insert_change.execute(rusqlite::params![id_str, serialized, created_at])?;
            }
        }

        {
            let mut insert_cursor = tx.prepare(
                "INSERT OR REPLACE INTO client_cursors (client_id, last_ack_change_id, updated_at) VALUES (?1, ?2, ?3)"
            )?;
            for cursor in disk.cursors.values() {
                let client_id_str = cursor.client_id.to_string();
                let change_id_str = cursor.last_ack_change_id.map(|id| id.to_string());
                let updated_at = cursor.updated_at.to_rfc3339();
                insert_cursor.execute(rusqlite::params![
                    client_id_str,
                    change_id_str,
                    updated_at
                ])?;
            }
        }
        tx.commit()?;

        sqlite.dag = disk.dag;
        sqlite.state = disk.state;

        Ok(sqlite)
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

    #[test]
    fn test_sqlite_storage_persistence_and_cursor() {
        let temp_dir = std::env::temp_dir().join(format!("pds_sqlite_test_{}", EntityId::new()));
        let entity_id = EntityId::new();
        let c1_id = ChangeId::new();
        let client_id = ClientId::new();

        {
            let mut storage = SqliteStorage::open(&temp_dir).unwrap();
            let c1 = Change::new(
                c1_id,
                vec![],
                ChangeMetadata::new("sqlite-node"),
                vec![
                    Operation::CreateEntity {
                        entity_id,
                        entity_type: Some("note".into()),
                    },
                    Operation::SetEntityProperty {
                        entity_id,
                        name: "body".into(),
                        value: PropertyValue::from("Hello SQLite!"),
                    },
                ],
            );
            storage.append_change(c1).unwrap();
            storage.set_client_cursor(client_id, Some(c1_id)).unwrap();
            assert_eq!(storage.change_count(), 1);
            assert_eq!(storage.get_client_cursor(&client_id), Some(c1_id));
        }

        {
            let storage = SqliteStorage::open(&temp_dir).unwrap();
            assert_eq!(storage.change_count(), 1);
            assert_eq!(storage.get_client_cursor(&client_id), Some(c1_id));
            let ent = storage.state().entities.get(&entity_id).unwrap();
            assert_eq!(ent.entity_type.as_deref(), Some("note"));
            assert_eq!(
                ent.get_property(&"body".into()),
                Some(&PropertyValue::from("Hello SQLite!"))
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sqlite_storage_migration_from_disk() {
        let temp_dir = std::env::temp_dir().join(format!("pds_migrate_test_{}", EntityId::new()));
        let entity_id = EntityId::new();
        let c1_id = ChangeId::new();
        let client_id = ClientId::new();

        // 1. Create legacy DiskStorage with data
        {
            let mut disk = DiskStorage::open(&temp_dir).unwrap();
            let c1 = Change::new(
                c1_id,
                vec![],
                ChangeMetadata::new("legacy-disk"),
                vec![Operation::CreateEntity {
                    entity_id,
                    entity_type: Some("contact".into()),
                }],
            );
            disk.append_change(c1).unwrap();
            disk.set_client_cursor(client_id, Some(c1_id)).unwrap();
        }

        // 2. Migrate into SQLite
        {
            let sqlite = SqliteStorage::migrate_from_disk_storage(&temp_dir).unwrap();
            assert_eq!(sqlite.change_count(), 1);
            assert_eq!(sqlite.get_client_cursor(&client_id), Some(c1_id));
            assert!(sqlite.state().entities.contains_key(&entity_id));
        }

        // 3. Re-open SQLite independently and verify data integrity
        {
            let sqlite = SqliteStorage::open(&temp_dir).unwrap();
            assert_eq!(sqlite.change_count(), 1);
            assert_eq!(sqlite.get_client_cursor(&client_id), Some(c1_id));
            assert_eq!(
                sqlite.get_change(&c1_id).unwrap().metadata.device_id,
                "legacy-disk"
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
