use crate::auth::ClientId;
use crate::blob::{BlobError, BlobStore};
use crate::change::Change;
use crate::dag::{DagError, HistoryDag};
use crate::id::ChangeId;
use crate::state::DatasetState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Errors occurring in persistent storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Underlying input/output error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// Serialization or deserialization error.
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Directed acyclic graph validation error.
    #[error("DAG error: {0}")]
    Dag(#[from] DagError),
    /// Binary large object storage error.
    #[error("Blob error: {0}")]
    Blob(#[from] BlobError),
    /// SQLite database operation error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Client synchronization cursor record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCursor {
    /// Identifier of the client.
    pub client_id: ClientId,
    /// Optional identifier of the last acknowledged change.
    pub last_ack_change_id: Option<ChangeId>,
    /// Timestamp when the cursor was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Routing record containing network address information for a peer node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRoutingRecord {
    /// Identifier of the peer node.
    pub node_id: String,
    /// Serialized JSON endpoint address of the peer.
    pub endpoint_addr_json: String,
    /// Timestamp when the peer was last observed.
    pub last_seen_at: DateTime<Utc>,
}

/// Rule specifying conditions for synchronizing binary large objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSyncRule {
    /// Unique identifier of the sync rule.
    pub id: String,
    /// Optional application identifier filter.
    pub app_id: Option<String>,
    /// Optional entity type filter.
    pub entity_type: Option<String>,
    /// Optional relation type filter.
    pub relation_type: Option<String>,
    /// Optional maximum blob size limit in bytes.
    pub max_size_bytes: Option<u64>,
    /// Timestamp when the rule was created.
    pub created_at: DateTime<Utc>,
}

/// Tuple containing loaded trusted nodes and their associated revocation secrets.
pub type LoadedTrustedNodes = (
    Vec<crate::trust::TrustedNode>,
    std::collections::BTreeMap<String, [u8; 32]>,
);

/// File-system storage engine using JSON lines for change history.
pub struct DiskStorage {
    root_dir: PathBuf,
    dag: HistoryDag,
    state: DatasetState,
    blobs: BlobStore,
    cursors: BTreeMap<ClientId, ClientCursor>,
}

impl DiskStorage {
    /// Opens or creates disk storage at the specified root directory.
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

    /// Appends a change to the history graph and persists it to disk.
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

    /// Returns a reference to the in-memory history graph.
    pub fn dag(&self) -> &HistoryDag {
        &self.dag
    }

    /// Returns a reference to the materialized dataset state.
    pub fn state(&self) -> &DatasetState {
        &self.state
    }

    /// Returns a reference to the blob store.
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// Returns a mutable reference to the blob store.
    pub fn blobs_mut(&mut self) -> &mut BlobStore {
        &mut self.blobs
    }

    /// Returns the total number of changes stored in the history graph.
    pub fn change_count(&self) -> usize {
        self.dag.len()
    }

    /// Retrieves a change by its identifier.
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

    /// Retrieves the last acknowledged change identifier for a client.
    pub fn get_client_cursor(&self, client_id: &ClientId) -> Option<ChangeId> {
        self.cursors
            .get(client_id)
            .and_then(|c| c.last_ack_change_id)
    }

    /// Updates the last acknowledged change identifier for a client.
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

/// Persistent storage engine backed by SQLite and a content-addressed blob store.
pub struct SqliteStorage {
    root_dir: PathBuf,
    conn: rusqlite::Connection,
    dag: HistoryDag,
    state: DatasetState,
    blobs: BlobStore,
    pending_materialization: VecDeque<Change>,
}

// rusqlite::Connection is Send but not Sync because it uses RefCell internally.
// SqliteStorage is always guarded by tokio::sync::RwLock or std::sync::RwLock,
// guaranteeing exclusive access during mutations and no concurrent calls into conn.
unsafe impl Send for SqliteStorage {}
unsafe impl Sync for SqliteStorage {}

impl SqliteStorage {
    /// Opens or creates SQLite storage at the specified root directory.
    pub fn open(root_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;

        let blob_dir = root_dir.join("blobs");
        let blobs = BlobStore::new(blob_dir)?;

        let db_path = root_dir.join("pds.db");
        let mut conn = rusqlite::Connection::open(&db_path)?;

        // WAL mode & normal synchronous for speed + crash consistency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        Self::apply_migrations(&mut conn)?;

        let mut storage = Self {
            root_dir,
            conn,
            dag: HistoryDag::new(),
            state: DatasetState::new(),
            blobs,
            pending_materialization: VecDeque::new(),
        };

        storage.load_history_from_db()?;
        storage.load_pending_materializations()?;
        Ok(storage)
    }

    fn apply_migrations(conn: &mut rusqlite::Connection) -> Result<(), StorageError> {
        let version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        if version < 1 {
            let tx = conn.transaction()?;
            tx.execute_batch(
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
                PRAGMA user_version = 1;
                ",
            )?;
            tx.commit()?;
        }

        let version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < 2 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS materialization_cursor (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_change_id TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    entity_type TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
                CREATE INDEX IF NOT EXISTS idx_entities_updated_at ON entities(updated_at);

                CREATE TABLE IF NOT EXISTS entity_properties (
                    entity_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    property_type TEXT NOT NULL,
                    value_text TEXT,
                    value_int INTEGER,
                    value_float REAL,
                    value_json TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (entity_id, name),
                    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_ep_name_text ON entity_properties(name, value_text);
                CREATE INDEX IF NOT EXISTS idx_ep_name_int ON entity_properties(name, value_int);
                CREATE INDEX IF NOT EXISTS idx_ep_name_float ON entity_properties(name, value_float);

                CREATE TABLE IF NOT EXISTS relations (
                    id TEXT PRIMARY KEY,
                    relation_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_relations_type ON relations(relation_type);

                CREATE TABLE IF NOT EXISTS relation_members (
                    relation_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    PRIMARY KEY (relation_id, entity_id, role),
                    FOREIGN KEY (relation_id) REFERENCES relations(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_rm_entity ON relation_members(entity_id);
                CREATE INDEX IF NOT EXISTS idx_rm_role ON relation_members(role);

                CREATE TABLE IF NOT EXISTS relation_properties (
                    relation_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    property_type TEXT NOT NULL,
                    value_text TEXT,
                    value_int INTEGER,
                    value_float REAL,
                    value_json TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (relation_id, name),
                    FOREIGN KEY (relation_id) REFERENCES relations(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_rp_name_text ON relation_properties(name, value_text);
                CREATE INDEX IF NOT EXISTS idx_rp_name_int ON relation_properties(name, value_int);
                CREATE INDEX IF NOT EXISTS idx_rp_name_float ON relation_properties(name, value_float);
                PRAGMA user_version = 2;
                ",
            )?;
            tx.commit()?;
        }

        Ok(())
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

    /// Loads unmaterialized changes into the pending materialization queue upon startup.
    fn load_pending_materializations(&mut self) -> Result<(), StorageError> {
        let last_change_id = self.get_materialization_cursor()?;
        let mut unmaterialized = false;
        let mut pending = VecDeque::new();

        // Changes in DAG are in topological order
        for change in self.dag.topological_order() {
            if let Some(ref last_id) = last_change_id {
                if unmaterialized {
                    pending.push_back(change.clone());
                } else if &change.id == last_id {
                    unmaterialized = true;
                }
            } else {
                // No cursor yet recorded, all changes are pending materialization
                pending.push_back(change.clone());
            }
        }

        self.pending_materialization = pending;
        Ok(())
    }

    /// Retrieves the last materialized change identifier from the database.
    pub fn get_materialization_cursor(&self) -> Result<Option<ChangeId>, StorageError> {
        let res: rusqlite::Result<Option<String>> = self.conn.query_row(
            "SELECT last_change_id FROM materialization_cursor WHERE id = 1",
            [],
            |row| row.get(0),
        );

        match res {
            Ok(Some(id_str)) => Ok(id_str.parse::<ChangeId>().ok()),
            Ok(None) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Sqlite(e)),
        }
    }

    /// Appends a change to the database, in-memory history graph, and materialization queue.
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

        self.pending_materialization.push_back(change);
        Ok(())
    }

    /// Returns the number of changes currently pending in the materialization queue.
    pub fn pending_materialization_count(&self) -> usize {
        self.pending_materialization.len()
    }

    /// Returns a slice of changes pending materialization.
    pub fn pending_materialization_changes(&self) -> &VecDeque<Change> {
        &self.pending_materialization
    }

    /// Sets the materialization cursor in the database.
    pub fn set_materialization_cursor(&mut self, change_id: &ChangeId) -> Result<(), StorageError> {
        let change_id_str = change_id.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO materialization_cursor (id, last_change_id, updated_at) VALUES (1, ?1, ?2)",
            rusqlite::params![change_id_str, now],
        )?;
        Ok(())
    }

    /// Materializes up to `max_changes` from the pending queue into the SQLite relational tables.
    pub fn materialize_pending_batch(&mut self, max_changes: usize) -> Result<usize, StorageError> {
        if self.pending_materialization.is_empty() {
            return Ok(0);
        }

        let count = std::cmp::min(max_changes, self.pending_materialization.len());
        let tx = self.conn.transaction()?;

        let mut last_change_id = None;

        for _ in 0..count {
            if let Some(change) = self.pending_materialization.pop_front() {
                let change_time = change.metadata.timestamp.to_rfc3339();

                for op in &change.operations {
                    match op {
                        crate::operation::Operation::CreateEntity {
                            entity_id,
                            entity_type,
                        } => {
                            tx.execute(
                                "INSERT OR REPLACE INTO entities (id, entity_type, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                                rusqlite::params![entity_id.to_string(), entity_type, change_time, change_time],
                            )?;
                        }
                        crate::operation::Operation::SetEntityProperty {
                            entity_id,
                            name,
                            value,
                        } => {
                            let (ptype, text, int_val, float_val, json_val) =
                                Self::decompose_property_value(value);

                            // Ensure entity exists
                            tx.execute(
                                "INSERT OR IGNORE INTO entities (id, entity_type, created_at, updated_at) VALUES (?1, NULL, ?2, ?2)",
                                rusqlite::params![entity_id.to_string(), change_time],
                            )?;
                            tx.execute(
                                "UPDATE entities SET updated_at = ?2 WHERE id = ?1",
                                rusqlite::params![entity_id.to_string(), change_time],
                            )?;

                            tx.execute(
                                "INSERT OR REPLACE INTO entity_properties
                                 (entity_id, name, property_type, value_text, value_int, value_float, value_json, updated_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                                rusqlite::params![
                                    entity_id.to_string(),
                                    name.to_string(),
                                    ptype,
                                    text,
                                    int_val,
                                    float_val,
                                    json_val,
                                    change_time
                                ],
                            )?;
                        }
                        crate::operation::Operation::RemoveEntityProperty { entity_id, name } => {
                            tx.execute(
                                "DELETE FROM entity_properties WHERE entity_id = ?1 AND name = ?2",
                                rusqlite::params![entity_id.to_string(), name.to_string()],
                            )?;
                            tx.execute(
                                "UPDATE entities SET updated_at = ?2 WHERE id = ?1",
                                rusqlite::params![entity_id.to_string(), change_time],
                            )?;
                        }
                        crate::operation::Operation::DeleteEntity { entity_id } => {
                            tx.execute(
                                "DELETE FROM entities WHERE id = ?1",
                                rusqlite::params![entity_id.to_string()],
                            )?;
                        }
                        crate::operation::Operation::CreateRelation {
                            relation_id,
                            relation_type,
                            members,
                        } => {
                            tx.execute(
                                "INSERT OR REPLACE INTO relations (id, relation_type, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                                rusqlite::params![relation_id.to_string(), relation_type, change_time, change_time],
                            )?;
                            for member in members {
                                tx.execute(
                                    "INSERT OR REPLACE INTO relation_members (relation_id, entity_id, role) VALUES (?1, ?2, ?3)",
                                    rusqlite::params![relation_id.to_string(), member.entity_id.to_string(), member.role],
                                )?;
                            }
                        }
                        crate::operation::Operation::SetRelationProperty {
                            relation_id,
                            name,
                            value,
                        } => {
                            let (ptype, text, int_val, float_val, json_val) =
                                Self::decompose_property_value(value);

                            tx.execute(
                                "UPDATE relations SET updated_at = ?2 WHERE id = ?1",
                                rusqlite::params![relation_id.to_string(), change_time],
                            )?;
                            tx.execute(
                                "INSERT OR REPLACE INTO relation_properties
                                 (relation_id, name, property_type, value_text, value_int, value_float, value_json, updated_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                                rusqlite::params![
                                    relation_id.to_string(),
                                    name.to_string(),
                                    ptype,
                                    text,
                                    int_val,
                                    float_val,
                                    json_val,
                                    change_time
                                ],
                            )?;
                        }
                        crate::operation::Operation::RemoveRelationProperty {
                            relation_id,
                            name,
                        } => {
                            tx.execute(
                                "DELETE FROM relation_properties WHERE relation_id = ?1 AND name = ?2",
                                rusqlite::params![relation_id.to_string(), name.to_string()],
                            )?;
                            tx.execute(
                                "UPDATE relations SET updated_at = ?2 WHERE id = ?1",
                                rusqlite::params![relation_id.to_string(), change_time],
                            )?;
                        }
                        crate::operation::Operation::DeleteRelation { relation_id } => {
                            tx.execute(
                                "DELETE FROM relations WHERE id = ?1",
                                rusqlite::params![relation_id.to_string()],
                            )?;
                        }
                        crate::operation::Operation::Unknown { .. } => {}
                    }
                }
                last_change_id = Some(change.id);
            }
        }

        if let Some(ref change_id) = last_change_id {
            let change_id_str = change_id.to_string();
            let now = Utc::now().to_rfc3339();
            tx.execute(
                "INSERT OR REPLACE INTO materialization_cursor (id, last_change_id, updated_at) VALUES (1, ?1, ?2)",
                rusqlite::params![change_id_str, now],
            )?;
        }

        tx.commit()?;
        Ok(count)
    }

    /// Materializes all pending changes in the queue into SQLite relational tables.
    pub fn materialize_all(&mut self) -> Result<usize, StorageError> {
        let total = self.pending_materialization.len();
        if total == 0 {
            return Ok(0);
        }
        self.materialize_pending_batch(total)
    }

    fn decompose_property_value(
        val: &crate::value::PropertyValue,
    ) -> (
        &'static str,
        Option<String>,
        Option<i64>,
        Option<f64>,
        Option<String>,
    ) {
        use crate::value::PropertyValue;
        match val {
            PropertyValue::Null => ("Null", None, None, None, None),
            PropertyValue::Bool(b) => (
                "Bool",
                Some(b.to_string()),
                Some(if *b { 1 } else { 0 }),
                None,
                None,
            ),
            PropertyValue::Int(i) => ("Int", Some(i.to_string()), Some(*i), Some(*i as f64), None),
            PropertyValue::Float(f) => ("Float", Some(f.to_string()), None, Some(*f), None),
            PropertyValue::Text(s) => ("Text", Some(s.clone()), None, None, None),
            PropertyValue::DateTime(dt) => ("DateTime", Some(dt.to_rfc3339()), None, None, None),
            PropertyValue::EntityRef(id) => ("EntityRef", Some(id.to_string()), None, None, None),
            PropertyValue::BlobRef(id) => ("BlobRef", Some(id.to_string()), None, None, None),
            PropertyValue::Encrypted { key_id, ciphertext } => (
                "Encrypted",
                None,
                None,
                None,
                serde_json::to_string(&serde_json::json!({
                    "key_id": key_id.to_string(),
                    "ciphertext": hex::encode(ciphertext),
                }))
                .ok(),
            ),
            PropertyValue::List(items) => {
                ("List", None, None, None, serde_json::to_string(items).ok())
            }
            PropertyValue::Map(map) => ("Map", None, None, None, serde_json::to_string(map).ok()),
        }
    }

    fn reconstruct_property_value(
        ptype: &str,
        text: Option<String>,
        int_val: Option<i64>,
        float_val: Option<f64>,
        json_val: Option<String>,
    ) -> Option<crate::value::PropertyValue> {
        use crate::value::PropertyValue;
        match ptype {
            "Null" => Some(PropertyValue::Null),
            "Bool" => int_val.map(|i| PropertyValue::Bool(i != 0)),
            "Int" => int_val.map(PropertyValue::Int),
            "Float" => float_val.map(PropertyValue::Float),
            "Text" => text.map(PropertyValue::Text),
            "DateTime" => text
                .and_then(|t| t.parse::<DateTime<Utc>>().ok())
                .map(PropertyValue::DateTime),
            "EntityRef" => text
                .and_then(|t| t.parse::<crate::id::EntityId>().ok())
                .map(PropertyValue::EntityRef),
            "BlobRef" => text
                .and_then(|t| t.parse::<crate::id::BlobId>().ok())
                .map(PropertyValue::BlobRef),
            "Encrypted" => json_val.and_then(|j| {
                let v: serde_json::Value = serde_json::from_str(&j).ok()?;
                let key_id: crate::id::KeyId = v.get("key_id")?.as_str()?.parse().ok()?;
                let cipher_hex = v.get("ciphertext")?.as_str()?;
                let ciphertext = hex::decode(cipher_hex).ok()?;
                Some(PropertyValue::Encrypted { key_id, ciphertext })
            }),
            "List" => json_val
                .and_then(|j| serde_json::from_str(&j).ok())
                .map(PropertyValue::List),
            "Map" => json_val
                .and_then(|j| serde_json::from_str(&j).ok())
                .map(PropertyValue::Map),
            _ => None,
        }
    }

    /// Retrieves an entity by querying the SQLite materialized tables and applying any pending changes.
    pub fn get_entity_materialized(
        &self,
        entity_id: &crate::id::EntityId,
    ) -> Result<Option<crate::entity::Entity>, StorageError> {
        let id_str = entity_id.to_string();

        let entity_res: rusqlite::Result<(Option<String>, String, String)> = self.conn.query_row(
            "SELECT entity_type, created_at, updated_at FROM entities WHERE id = ?1",
            rusqlite::params![id_str],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        );

        let mut entity_opt = match entity_res {
            Ok((entity_type, created_at_str, updated_at_str)) => {
                let _created_at = created_at_str
                    .parse::<DateTime<Utc>>()
                    .unwrap_or_else(|_| Utc::now());
                let _updated_at = updated_at_str
                    .parse::<DateTime<Utc>>()
                    .unwrap_or_else(|_| Utc::now());

                let mut props = BTreeMap::new();
                let mut stmt = self.conn.prepare(
                    "SELECT name, property_type, value_text, value_int, value_float, value_json
                     FROM entity_properties WHERE entity_id = ?1",
                )?;

                let rows = stmt.query_map(rusqlite::params![id_str], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<f64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })?;

                for row in rows {
                    let (name, ptype, text, int_val, float_val, json_val) = row?;
                    if let Ok(prop_name) = name.parse::<crate::value::PropertyName>()
                        && let Some(val) = Self::reconstruct_property_value(
                            &ptype, text, int_val, float_val, json_val,
                        )
                    {
                        props.insert(prop_name, val);
                    }
                }

                let mut entity = match entity_type {
                    Some(t) => crate::entity::Entity::with_type(*entity_id, t),
                    None => crate::entity::Entity::new(*entity_id),
                };
                for (k, v) in props {
                    entity.set_property(k, v);
                }

                Some(entity)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(StorageError::Sqlite(e)),
        };

        // Pending queue pass: apply changes in pending_materialization that have not yet been flushed to SQLite
        for change in &self.pending_materialization {
            for op in &change.operations {
                match op {
                    crate::operation::Operation::CreateEntity {
                        entity_id: eid,
                        entity_type,
                    } if eid == entity_id => {
                        let e = match entity_type {
                            Some(t) => crate::entity::Entity::with_type(*entity_id, t),
                            None => crate::entity::Entity::new(*entity_id),
                        };
                        entity_opt = Some(e);
                    }
                    crate::operation::Operation::SetEntityProperty {
                        entity_id: eid,
                        name,
                        value,
                    } if eid == entity_id => {
                        if let Some(ref mut entity) = entity_opt {
                            entity.set_property(name.clone(), value.clone());
                        }
                    }
                    crate::operation::Operation::RemoveEntityProperty {
                        entity_id: eid,
                        name,
                    } if eid == entity_id => {
                        if let Some(ref mut entity) = entity_opt {
                            entity.remove_property(name);
                        }
                    }
                    crate::operation::Operation::DeleteEntity { entity_id: eid }
                        if eid == entity_id =>
                    {
                        entity_opt = None;
                    }
                    _ => {}
                }
            }
        }

        Ok(entity_opt)
    }

    /// Returns the root directory path.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns a reference to the in-memory history graph.
    pub fn dag(&self) -> &HistoryDag {
        &self.dag
    }

    /// Returns a reference to the materialized dataset state.
    pub fn state(&self) -> &DatasetState {
        &self.state
    }

    /// Returns a reference to the blob store.
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// Returns a mutable reference to the blob store.
    pub fn blobs_mut(&mut self) -> &mut BlobStore {
        &mut self.blobs
    }

    /// Returns the total number of changes in the history graph.
    pub fn change_count(&self) -> usize {
        self.dag.len()
    }

    /// Retrieves a change by its identifier.
    pub fn get_change(&self, id: &ChangeId) -> Option<&Change> {
        self.dag.get(id)
    }

    /// Retrieves the last acknowledged change identifier for a client.
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

    /// Updates the last acknowledged change identifier for a client.
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

    /// Saves or updates a trusted node record in the database.
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

    /// Loads all trusted nodes and revocation secrets from the database.
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

    /// Saves or updates peer routing information.
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

    /// Loads all peer routing records from the database.
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

    /// Saves or updates a blob synchronization rule.
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

    /// Loads all blob synchronization rules from the database.
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

    /// Deletes a blob synchronization rule by identifier.
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

    #[test]
    fn test_sqlite_materialization_and_pending_queue_pass() {
        let temp_dir = std::env::temp_dir().join(format!("pds_mat_test_{}", EntityId::new()));
        let entity_id = EntityId::new();
        let c1_id = ChangeId::new();
        let c2_id = ChangeId::new();

        {
            let mut storage = SqliteStorage::open(&temp_dir).unwrap();

            // Append change 1: create entity
            let c1 = Change::new(
                c1_id,
                vec![],
                ChangeMetadata::new("device-1"),
                vec![
                    Operation::CreateEntity {
                        entity_id,
                        entity_type: Some("firefighter".into()),
                    },
                    Operation::SetEntityProperty {
                        entity_id,
                        name: "first_name".into(),
                        value: PropertyValue::from("Jan"),
                    },
                ],
            );
            storage.append_change(c1).unwrap();

            // Change 1 is in pending queue
            assert_eq!(storage.pending_materialization_count(), 1);

            // get_entity_materialized should return entity even before flush (pending queue pass)
            let ent = storage
                .get_entity_materialized(&entity_id)
                .unwrap()
                .expect("entity should exist via pending queue");
            assert_eq!(ent.entity_type.as_deref(), Some("firefighter"));
            assert_eq!(
                ent.get_property(&"first_name".into()),
                Some(&PropertyValue::from("Jan"))
            );

            // Materialize pending changes
            let flushed = storage.materialize_all().unwrap();
            assert_eq!(flushed, 1);
            assert_eq!(storage.pending_materialization_count(), 0);
            assert_eq!(storage.get_materialization_cursor().unwrap(), Some(c1_id));

            // Verify directly from materialized DB
            let ent_db = storage
                .get_entity_materialized(&entity_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                ent_db.get_property(&"first_name".into()),
                Some(&PropertyValue::from("Jan"))
            );

            // Append change 2: update property and add age
            let c2 = Change::new(
                c2_id,
                vec![c1_id],
                ChangeMetadata::new("device-1"),
                vec![
                    Operation::SetEntityProperty {
                        entity_id,
                        name: "first_name".into(),
                        value: PropertyValue::from("Stanisław"),
                    },
                    Operation::SetEntityProperty {
                        entity_id,
                        name: "age".into(),
                        value: PropertyValue::from(42),
                    },
                ],
            );
            storage.append_change(c2).unwrap();
            assert_eq!(storage.pending_materialization_count(), 1);

            // get_entity_materialized merges DB with pending queue
            let ent_merged = storage
                .get_entity_materialized(&entity_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                ent_merged.get_property(&"first_name".into()),
                Some(&PropertyValue::from("Stanisław"))
            );
            assert_eq!(
                ent_merged.get_property(&"age".into()),
                Some(&PropertyValue::from(42))
            );

            // Flush change 2
            storage.materialize_all().unwrap();
            assert_eq!(storage.get_materialization_cursor().unwrap(), Some(c2_id));
        }

        // Reopen storage: should resume cursor and retain unmaterialized queue correctly
        {
            let storage = SqliteStorage::open(&temp_dir).unwrap();
            assert_eq!(storage.get_materialization_cursor().unwrap(), Some(c2_id));
            assert_eq!(storage.pending_materialization_count(), 0);

            let ent = storage
                .get_entity_materialized(&entity_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                ent.get_property(&"first_name".into()),
                Some(&PropertyValue::from("Stanisław"))
            );
            assert_eq!(
                ent.get_property(&"age".into()),
                Some(&PropertyValue::from(42))
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
