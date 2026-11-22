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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRoutingRecord {
    pub node_id: String,
    pub endpoint_addr_json: String,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSyncRule {
    pub id: String,
    pub app_id: Option<String>,
    pub entity_type: Option<String>,
    pub relation_type: Option<String>,
    pub max_size_bytes: Option<u64>,
    pub created_at: DateTime<Utc>,
}

pub type LoadedTrustedNodes = (
    Vec<crate::trust::TrustedNode>,
    std::collections::BTreeMap<String, [u8; 32]>,
);

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

// rusqlite::Connection is Send but not Sync because it uses RefCell internally.
// SqliteStorage is always guarded by tokio::sync::RwLock or std::sync::RwLock,
// guaranteeing exclusive access during mutations and no concurrent calls into conn.
unsafe impl Send for SqliteStorage {}
unsafe impl Sync for SqliteStorage {}

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
            CREATE TABLE IF NOT EXISTS trusted_nodes (
                node_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                revocation_hash BLOB NOT NULL,
                revocation_secret BLOB,
                is_revoked INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS peer_routing (
                node_id TEXT PRIMARY KEY,
                endpoint_addr_json TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blob_sync_rules (
                id TEXT PRIMARY KEY,
                app_id TEXT,
                entity_type TEXT,
                relation_type TEXT,
                max_size_bytes INTEGER,
                created_at TEXT NOT NULL
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

    pub fn save_trusted_node(
        &mut self,
        node: &crate::trust::TrustedNode,
        revocation_secret: Option<[u8; 32]>,
    ) -> Result<(), StorageError> {
        let is_revoked_int = if node.is_revoked { 1 } else { 0 };
        let created_at_str = node.created_at.to_rfc3339();
        let revoked_at_str = node.revoked_at.map(|t| t.to_rfc3339());
        let sec_blob = revocation_secret.map(|s| s.to_vec());

        self.conn.execute(
            "INSERT INTO trusted_nodes (node_id, name, public_key, revocation_hash, revocation_secret, is_revoked, created_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(node_id) DO UPDATE SET
                name = excluded.name,
                public_key = excluded.public_key,
                revocation_hash = excluded.revocation_hash,
                revocation_secret = coalesce(excluded.revocation_secret, trusted_nodes.revocation_secret),
                is_revoked = excluded.is_revoked,
                revoked_at = excluded.revoked_at",
            rusqlite::params![
                node.node_id,
                node.name,
                node.public_key.to_vec(),
                node.revocation_hash.to_vec(),
                sec_blob,
                is_revoked_int,
                created_at_str,
                revoked_at_str,
            ],
        )?;

        Ok(())
    }

    pub fn load_trusted_nodes(&self) -> Result<LoadedTrustedNodes, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, name, public_key, revocation_hash, revocation_secret, is_revoked, created_at, revoked_at FROM trusted_nodes"
        )?;

        let mut nodes = Vec::new();
        let mut secrets = std::collections::BTreeMap::new();

        let rows = stmt.query_map([], |row| {
            let node_id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let pub_blob: Vec<u8> = row.get(2)?;
            let rev_hash_blob: Vec<u8> = row.get(3)?;
            let sec_blob: Option<Vec<u8>> = row.get(4)?;
            let is_revoked: i64 = row.get(5)?;
            let created_at_str: String = row.get(6)?;
            let revoked_at_str: Option<String> = row.get(7)?;

            Ok((
                node_id,
                name,
                pub_blob,
                rev_hash_blob,
                sec_blob,
                is_revoked != 0,
                created_at_str,
                revoked_at_str,
            ))
        })?;

        for r in rows {
            let (
                node_id,
                name,
                pub_blob,
                rev_hash_blob,
                sec_blob,
                is_revoked,
                created_str,
                revoked_str,
            ) = r?;
            let mut public_key = [0u8; 32];
            if pub_blob.len() == 32 {
                public_key.copy_from_slice(&pub_blob);
            }
            let mut revocation_hash = [0u8; 32];
            if rev_hash_blob.len() == 32 {
                revocation_hash.copy_from_slice(&rev_hash_blob);
            }
            if let Some(sec) = sec_blob
                && sec.len() == 32
            {
                let mut s = [0u8; 32];
                s.copy_from_slice(&sec);
                secrets.insert(node_id.clone(), s);
            }

            let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let revoked_at = revoked_str.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            });

            nodes.push(crate::trust::TrustedNode {
                node_id,
                name,
                public_key,
                revocation_hash,
                is_revoked,
                created_at,
                revoked_at,
            });
        }

        Ok((nodes, secrets))
    }

    pub fn save_peer_routing(
        &self,
        node_id: &str,
        endpoint_addr_json: &str,
        last_seen_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let last_seen_str = last_seen_at.to_rfc3339();
        self.conn.execute(
            "INSERT INTO peer_routing (node_id, endpoint_addr_json, last_seen_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(node_id) DO UPDATE SET
                endpoint_addr_json = excluded.endpoint_addr_json,
                last_seen_at = excluded.last_seen_at",
            rusqlite::params![node_id, endpoint_addr_json, last_seen_str],
        )?;
        Ok(())
    }

    pub fn load_all_peer_routing(&self) -> Result<Vec<PeerRoutingRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT node_id, endpoint_addr_json, last_seen_at FROM peer_routing")?;

        let rows = stmt.query_map([], |row| {
            let node_id: String = row.get(0)?;
            let endpoint_addr_json: String = row.get(1)?;
            let last_seen_str: String = row.get(2)?;
            Ok((node_id, endpoint_addr_json, last_seen_str))
        })?;

        let mut list = Vec::new();
        for r in rows {
            let (node_id, endpoint_addr_json, last_seen_str) = r?;
            let last_seen_at = chrono::DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            list.push(PeerRoutingRecord {
                node_id,
                endpoint_addr_json,
                last_seen_at,
            });
        }
        Ok(list)
    }

    pub fn save_blob_sync_rule(&self, rule: &BlobSyncRule) -> Result<(), StorageError> {
        let created_at_str = rule.created_at.to_rfc3339();
        let max_size_i64 = rule.max_size_bytes.map(|s| s as i64);
        self.conn.execute(
            "INSERT INTO blob_sync_rules (id, app_id, entity_type, relation_type, max_size_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                app_id = excluded.app_id,
                entity_type = excluded.entity_type,
                relation_type = excluded.relation_type,
                max_size_bytes = excluded.max_size_bytes",
            rusqlite::params![
                rule.id,
                rule.app_id,
                rule.entity_type,
                rule.relation_type,
                max_size_i64,
                created_at_str,
            ],
        )?;
        Ok(())
    }

    pub fn load_blob_sync_rules(&self) -> Result<Vec<BlobSyncRule>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, app_id, entity_type, relation_type, max_size_bytes, created_at FROM blob_sync_rules"
        )?;

        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let app_id: Option<String> = row.get(1)?;
            let entity_type: Option<String> = row.get(2)?;
            let relation_type: Option<String> = row.get(3)?;
            let max_size_i64: Option<i64> = row.get(4)?;
            let max_size_bytes = max_size_i64.map(|s| s as u64);
            let created_at_str: String = row.get(5)?;
            Ok((
                id,
                app_id,
                entity_type,
                relation_type,
                max_size_bytes,
                created_at_str,
            ))
        })?;

        let mut list = Vec::new();
        for r in rows {
            let (id, app_id, entity_type, relation_type, max_size_bytes, created_at_str) = r?;
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            list.push(BlobSyncRule {
                id,
                app_id,
                entity_type,
                relation_type,
                max_size_bytes,
                created_at,
            });
        }
        Ok(list)
    }

    pub fn delete_blob_sync_rule(&self, rule_id: &str) -> Result<bool, StorageError> {
        let affected = self.conn.execute(
            "DELETE FROM blob_sync_rules WHERE id = ?1",
            rusqlite::params![rule_id],
        )?;
        Ok(affected > 0)
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
