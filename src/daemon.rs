use crate::auth::ClientAuthenticator;
use crate::change::Change;
use crate::dag::{DagError, HistoryDag};
use crate::id::{BlobId, ChangeId, EntityId, RelationId};
use crate::ipc::{
    EventTopic, IpcNotification, IpcRequest, IpcResponse, IpcSessionManager, Session,
};
use crate::net::{NetSyncError, PdsNetworkNode};
use crate::operation::Operation;
use crate::security::Permission;
use crate::storage::{SqliteStorage, StorageError};
use crate::value::PropertyValue;
use iroh::{EndpointAddr, EndpointId};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Network sync error: {0}")]
    Net(#[from] NetSyncError),
    #[error("DAG error: {0}")]
    Dag(#[from] DagError),
    #[error("IPC error: {0}")]
    Ipc(String),
}

use crate::blob::BlobStore;
use crate::trust::TrustManager;
use ed25519_dalek::SigningKey;

/// The top-level PDS node daemon unifying persistent SQLite storage,
/// IPC clients authentication, pub/sub notifications, and P2P Iroh synchronization.
#[derive(Clone)]
#[allow(clippy::arc_with_non_send_sync)]
pub struct PdsNodeDaemon {
    storage: Arc<RwLock<SqliteStorage>>,
    sessions: Arc<RwLock<IpcSessionManager>>,
    authenticator: Arc<RwLock<ClientAuthenticator>>,
    trust: Arc<RwLock<TrustManager>>,
    blobs: Arc<RwLock<BlobStore>>,
    signing_key: SigningKey,
    net_node: PdsNetworkNode,
    shared_dag: Arc<RwLock<HistoryDag>>,
}

impl PdsNodeDaemon {
    /// Initializes a new PdsNodeDaemon from a root storage directory and node name.
    /// Loads history and trusted nodes from SQLite and initializes the Iroh QUIC network endpoint.
    #[allow(clippy::arc_with_non_send_sync)]
    pub async fn init(root_dir: impl AsRef<Path>, node_name: &str) -> Result<Self, DaemonError> {
        let storage = SqliteStorage::open(root_dir)?;
        let shared_dag = Arc::new(RwLock::new(storage.dag().clone()));
        let blobs = Arc::new(RwLock::new(storage.blobs().clone()));

        // Generate or load node signing key
        let mut key_bytes = [0u8; 32];
        rand::fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        let mut trust_mgr = TrustManager::new(node_name, signing_key.clone());
        let (saved_nodes, _) = storage.load_trusted_nodes()?;
        for n in saved_nodes {
            trust_mgr.register_trusted_node(n);
        }
        let trust = Arc::new(RwLock::new(trust_mgr));

        let net_node =
            PdsNetworkNode::new(shared_dag.clone(), trust.clone(), blobs.clone()).await?;

        Ok(Self {
            storage: Arc::new(RwLock::new(storage)),
            sessions: Arc::new(RwLock::new(IpcSessionManager::new())),
            authenticator: Arc::new(RwLock::new(ClientAuthenticator::new(node_name))),
            trust,
            blobs,
            signing_key,
            net_node,
            shared_dag,
        })
    }

    /// Returns the Iroh EndpointId of this node.
    pub fn endpoint_id(&self) -> EndpointId {
        self.net_node.endpoint_id()
    }

    /// Returns the Iroh EndpointAddr of this node.
    pub fn addr(&self) -> EndpointAddr {
        self.net_node.addr()
    }

    /// Returns a reference to the underlying PdsNetworkNode.
    pub fn net_node(&self) -> &PdsNetworkNode {
        &self.net_node
    }

    /// Returns a shared reference to the in-memory HistoryDag.
    pub fn dag(&self) -> Arc<RwLock<HistoryDag>> {
        self.shared_dag.clone()
    }

    /// Returns a shared reference to the SqliteStorage.
    pub fn storage(&self) -> Arc<RwLock<SqliteStorage>> {
        self.storage.clone()
    }

    /// Returns a shared reference to the IpcSessionManager.
    pub fn sessions(&self) -> Arc<RwLock<IpcSessionManager>> {
        self.sessions.clone()
    }

    /// Returns a shared reference to the ClientAuthenticator.
    pub fn authenticator(&self) -> Arc<RwLock<ClientAuthenticator>> {
        self.authenticator.clone()
    }

    /// Processes an incoming IPC request.
    /// For mutating requests (Create/Update/Delete Entity or Relation),
    /// the change is persisted to SqliteStorage, reflected in the shared DAG,
    /// and pub/sub notifications are queued.
    pub async fn handle_ipc_request(
        &self,
        request: IpcRequest,
        caller_pid: Option<u32>,
    ) -> Result<IpcResponse, DaemonError> {
        match request {
            IpcRequest::Hello(hello) => {
                let mut auth = self.authenticator.write().await;
                match auth.handle_client_hello(&hello) {
                    Ok(challenge) => Ok(IpcResponse::Challenge(challenge)),
                    Err(e) => Ok(IpcResponse::Error(e.to_string())),
                }
            }
            IpcRequest::Authenticate(auth_req) => {
                let mut auth = self.authenticator.write().await;
                match auth.handle_client_auth(&auth_req) {
                    Ok(success) => {
                        let mut sessions = self.sessions.write().await;
                        sessions.insert_session(Session {
                            session_id: success.session_id.clone(),
                            client_id: success.client_id,
                            permissions: success.permissions.clone(),
                            expires_at: success.expires_at,
                            peer_pid: caller_pid,
                            api_version: success.api_version.clone(),
                            subscriptions: BTreeSet::new(),
                            pending_notifications: Vec::new(),
                        });
                        Ok(IpcResponse::Authenticated(success))
                    }
                    Err(e) => Ok(IpcResponse::Error(e.to_string())),
                }
            }
            IpcRequest::GetEntity {
                session_id,
                entity_id,
            } => {
                let sessions = self.sessions.read().await;
                if let Err(err) = sessions.check_permission(&session_id, &Permission::ReadEntities)
                {
                    return Ok(IpcResponse::Error(err.to_string()));
                }
                let storage = self.storage.read().await;
                let entity = storage.state().entities.get(&entity_id).cloned();
                Ok(IpcResponse::Entity(entity))
            }
            IpcRequest::CreateEntity {
                session_id,
                entity_type,
                properties,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteEntities)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }

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

                let (parents, meta) = {
                    let storage = self.storage.read().await;
                    let heads: Vec<ChangeId> = storage.dag().heads().iter().copied().collect();
                    (heads, crate::change::ChangeMetadata::new("ipc-client"))
                };
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);
                let change_id = change.id;

                self.append_and_sync_change(change.clone()).await?;

                let notif = IpcNotification::ChangeAppended { change_id, change };
                let mut sessions = self.sessions.write().await;
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
                sessions.publish_notification(EventTopic::EntityChanges, notif);

                Ok(IpcResponse::EntityCreated(entity_id))
            }
            IpcRequest::UpdateEntity {
                session_id,
                entity_id,
                set_properties,
                remove_properties,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteEntities)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }

                let (parents, meta) = {
                    let storage = self.storage.read().await;
                    if !storage.state().entities.contains_key(&entity_id) {
                        return Ok(IpcResponse::Error(format!("Entity not found: {entity_id}")));
                    }
                    let heads: Vec<ChangeId> = storage.dag().heads().iter().copied().collect();
                    (heads, crate::change::ChangeMetadata::new("ipc-client"))
                };

                let mut ops = Vec::new();
                for (name, value) in set_properties {
                    ops.push(Operation::SetEntityProperty {
                        entity_id,
                        name,
                        value,
                    });
                }
                for name in remove_properties {
                    ops.push(Operation::RemoveEntityProperty { entity_id, name });
                }

                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);
                let change_id = change.id;

                self.append_and_sync_change(change.clone()).await?;

                let notif = IpcNotification::ChangeAppended { change_id, change };
                let mut sessions = self.sessions.write().await;
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
                sessions.publish_notification(EventTopic::EntityChanges, notif);

                Ok(IpcResponse::EntityUpdated(entity_id))
            }
            IpcRequest::DeleteEntity {
                session_id,
                entity_id,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteEntities)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }

                let (parents, meta) = {
                    let storage = self.storage.read().await;
                    if !storage.state().entities.contains_key(&entity_id) {
                        return Ok(IpcResponse::Error(format!("Entity not found: {entity_id}")));
                    }
                    let heads: Vec<ChangeId> = storage.dag().heads().iter().copied().collect();
                    (heads, crate::change::ChangeMetadata::new("ipc-client"))
                };

                let ops = vec![Operation::DeleteEntity { entity_id }];
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);
                let change_id = change.id;

                self.append_and_sync_change(change.clone()).await?;

                let notif = IpcNotification::ChangeAppended { change_id, change };
                let mut sessions = self.sessions.write().await;
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
                sessions.publish_notification(EventTopic::EntityChanges, notif);

                Ok(IpcResponse::EntityDeleted(entity_id))
            }
            IpcRequest::GetRelation {
                session_id,
                relation_id,
            } => {
                let sessions = self.sessions.read().await;
                if let Err(err) = sessions.check_permission(&session_id, &Permission::ReadEntities)
                {
                    return Ok(IpcResponse::Error(err.to_string()));
                }
                let storage = self.storage.read().await;
                let rel = storage.state().relations.get(&relation_id).cloned();
                Ok(IpcResponse::Relation(rel))
            }
            IpcRequest::CreateRelation {
                session_id,
                relation_type,
                source,
                target,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteEntities)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }

                let (parents, meta) = {
                    let storage = self.storage.read().await;
                    if !storage.state().entities.contains_key(&source) {
                        return Ok(IpcResponse::Error(format!(
                            "Source entity not found: {source}"
                        )));
                    }
                    if !storage.state().entities.contains_key(&target) {
                        return Ok(IpcResponse::Error(format!(
                            "Target entity not found: {target}"
                        )));
                    }
                    let heads: Vec<ChangeId> = storage.dag().heads().iter().copied().collect();
                    (heads, crate::change::ChangeMetadata::new("ipc-client"))
                };

                let relation_id = RelationId::new();
                let ops = vec![Operation::CreateRelation {
                    relation_id,
                    relation_type,
                    source,
                    target,
                }];

                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);
                let change_id = change.id;

                self.append_and_sync_change(change.clone()).await?;

                let notif = IpcNotification::ChangeAppended { change_id, change };
                let mut sessions = self.sessions.write().await;
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
                sessions.publish_notification(EventTopic::RelationChanges, notif);

                Ok(IpcResponse::RelationCreated(relation_id))
            }
            IpcRequest::UpdateRelation {
                session_id,
                relation_id,
                set_properties,
                remove_properties,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteEntities)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }

                let (parents, meta) = {
                    let storage = self.storage.read().await;
                    if !storage.state().relations.contains_key(&relation_id) {
                        return Ok(IpcResponse::Error(format!(
                            "Relation not found: {relation_id}"
                        )));
                    }
                    let heads: Vec<ChangeId> = storage.dag().heads().iter().copied().collect();
                    (heads, crate::change::ChangeMetadata::new("ipc-client"))
                };

                let mut ops = Vec::new();
                for (name, value) in set_properties {
                    ops.push(Operation::SetRelationProperty {
                        relation_id,
                        name,
                        value,
                    });
                }
                for name in remove_properties {
                    ops.push(Operation::RemoveRelationProperty { relation_id, name });
                }

                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);
                let change_id = change.id;

                self.append_and_sync_change(change.clone()).await?;

                let notif = IpcNotification::ChangeAppended { change_id, change };
                let mut sessions = self.sessions.write().await;
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
                sessions.publish_notification(EventTopic::RelationChanges, notif);

                Ok(IpcResponse::RelationUpdated(relation_id))
            }
            IpcRequest::DeleteRelation {
                session_id,
                relation_id,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteEntities)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }

                let (parents, meta) = {
                    let storage = self.storage.read().await;
                    if !storage.state().relations.contains_key(&relation_id) {
                        return Ok(IpcResponse::Error(format!(
                            "Relation not found: {relation_id}"
                        )));
                    }
                    let heads: Vec<ChangeId> = storage.dag().heads().iter().copied().collect();
                    (heads, crate::change::ChangeMetadata::new("ipc-client"))
                };

                let ops = vec![Operation::DeleteRelation { relation_id }];
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);
                let change_id = change.id;

                self.append_and_sync_change(change.clone()).await?;

                let notif = IpcNotification::ChangeAppended { change_id, change };
                let mut sessions = self.sessions.write().await;
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
                sessions.publish_notification(EventTopic::RelationChanges, notif);

                Ok(IpcResponse::RelationDeleted(relation_id))
            }
            IpcRequest::GetBlob {
                session_id,
                blob_id,
            } => {
                let sessions = self.sessions.read().await;
                if let Err(err) = sessions.check_permission(&session_id, &Permission::ReadBlobs) {
                    return Ok(IpcResponse::Error(err.to_string()));
                }
                let storage = self.storage.read().await;
                match storage.blobs().get_data(&blob_id) {
                    Ok(data) => Ok(IpcResponse::Blob(data)),
                    Err(err) => Ok(IpcResponse::Error(err.to_string())),
                }
            }
            IpcRequest::PutBlob {
                session_id,
                data,
                media_type,
            } => {
                {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::WriteBlobs)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                }
                let blob_id = BlobId::new();
                let mut storage = self.storage.write().await;
                match storage.blobs_mut().put(blob_id, &data, media_type) {
                    Ok(descriptor) => {
                        let mut sessions = self.sessions.write().await;
                        sessions.publish_notification(
                            EventTopic::BlobCreated,
                            IpcNotification::BlobAppended {
                                descriptor: descriptor.clone(),
                            },
                        );
                        Ok(IpcResponse::BlobCreated(descriptor))
                    }
                    Err(err) => Ok(IpcResponse::Error(err.to_string())),
                }
            }
            IpcRequest::PollChanges {
                session_id,
                since_change_id,
                limit,
            } => {
                let sessions = self.sessions.read().await;
                if let Err(err) = sessions.check_permission(&session_id, &Permission::ReadHistory) {
                    return Ok(IpcResponse::Error(err.to_string()));
                }
                let storage = self.storage.read().await;
                let topological = storage.dag().topological_order();
                let mut start_collecting = since_change_id.is_none();
                let mut collected = Vec::new();
                let max_limit = limit.unwrap_or(100);

                for change in topological {
                    if start_collecting {
                        collected.push(change.clone());
                        if collected.len() >= max_limit {
                            break;
                        }
                    } else if since_change_id.as_ref() == Some(&change.id) {
                        start_collecting = true;
                    }
                }
                let latest_change_id = collected.last().map(|c| c.id);
                Ok(IpcResponse::Changes {
                    changes: collected,
                    latest_change_id,
                })
            }
            IpcRequest::GetPendingChanges { session_id, limit } => {
                let client_id = {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::ReadHistory)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                    match sessions.get_session(&session_id) {
                        Some(s) => s.client_id,
                        None => return Ok(IpcResponse::Error("Session not found".into())),
                    }
                };

                let storage = self.storage.read().await;
                let since_change_id = storage.get_client_cursor(&client_id);
                let topological = storage.dag().topological_order();
                let mut start_collecting = since_change_id.is_none();
                let mut collected = Vec::new();
                let max_limit = limit.unwrap_or(100);

                for change in topological {
                    if start_collecting {
                        collected.push(change.clone());
                        if collected.len() >= max_limit {
                            break;
                        }
                    } else if since_change_id.as_ref() == Some(&change.id) {
                        start_collecting = true;
                    }
                }
                let latest_change_id = collected.last().map(|c| c.id);
                Ok(IpcResponse::Changes {
                    changes: collected,
                    latest_change_id,
                })
            }
            IpcRequest::AcknowledgeChanges {
                session_id,
                change_id,
            } => {
                let client_id = {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::ReadHistory)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                    match sessions.get_session(&session_id) {
                        Some(s) => s.client_id,
                        None => return Ok(IpcResponse::Error("Session not found".into())),
                    }
                };

                let mut storage = self.storage.write().await;
                if let Err(err) = storage.set_client_cursor(client_id, Some(change_id)) {
                    return Ok(IpcResponse::Error(err.to_string()));
                }
                Ok(IpcResponse::ChangesAcknowledged {
                    last_ack_change_id: change_id,
                })
            }
            IpcRequest::GetClientCursor { session_id } => {
                let client_id = {
                    let sessions = self.sessions.read().await;
                    if let Err(err) =
                        sessions.check_permission(&session_id, &Permission::ReadHistory)
                    {
                        return Ok(IpcResponse::Error(err.to_string()));
                    }
                    match sessions.get_session(&session_id) {
                        Some(s) => s.client_id,
                        None => return Ok(IpcResponse::Error("Session not found".into())),
                    }
                };

                let storage = self.storage.read().await;
                let cursor = storage.get_client_cursor(&client_id);
                Ok(IpcResponse::Cursor(cursor))
            }
            IpcRequest::Subscribe { session_id, topics } => {
                let mut sessions = self.sessions.write().await;
                match sessions.subscribe(&session_id, topics) {
                    Ok(subscribed) => Ok(IpcResponse::Subscribed { topics: subscribed }),
                    Err(err) => Ok(IpcResponse::Error(err.to_string())),
                }
            }
            IpcRequest::Unsubscribe { session_id, topics } => {
                let mut sessions = self.sessions.write().await;
                match sessions.unsubscribe(&session_id, &topics) {
                    Ok(current) => Ok(IpcResponse::Unsubscribed { topics: current }),
                    Err(err) => Ok(IpcResponse::Error(err.to_string())),
                }
            }
            IpcRequest::CloseSession { session_id } => {
                let mut sessions = self.sessions.write().await;
                sessions.remove_session(&session_id);
                Ok(IpcResponse::SessionClosed)
            }
        }
    }

    pub fn trust(&self) -> Arc<RwLock<TrustManager>> {
        self.trust.clone()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Synchronizes history with a remote Iroh peer, persisting newly applied changes
    /// to SQLite storage and broadcasting them to subscribed IPC sessions.
    pub async fn sync_with_peer(
        &self,
        peer_addr: EndpointAddr,
    ) -> Result<([u8; 32], Vec<Change>), DaemonError> {
        let (session_token, applied_changes) = self
            .net_node
            .sync_with_peer(peer_addr.clone(), &self.signing_key)
            .await?;

        if !applied_changes.is_empty() {
            let mut storage = self.storage.write().await;
            let mut sessions = self.sessions.write().await;

            for change in &applied_changes {
                // Persist each change to SQLite
                storage.append_change(change.clone())?;

                // Publish real-time events to IPC subscribers
                let notif = IpcNotification::ChangeAppended {
                    change_id: change.id,
                    change: change.clone(),
                };
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());

                let has_entities = change.operations.iter().any(|op| {
                    matches!(
                        op,
                        Operation::CreateEntity { .. }
                            | Operation::SetEntityProperty { .. }
                            | Operation::RemoveEntityProperty { .. }
                            | Operation::DeleteEntity { .. }
                    )
                });
                if has_entities {
                    sessions.publish_notification(EventTopic::EntityChanges, notif.clone());
                }

                let has_relations = change.operations.iter().any(|op| {
                    matches!(
                        op,
                        Operation::CreateRelation { .. }
                            | Operation::SetRelationProperty { .. }
                            | Operation::RemoveRelationProperty { .. }
                            | Operation::DeleteRelation { .. }
                    )
                });
                if has_relations {
                    sessions.publish_notification(EventTopic::RelationChanges, notif);
                }
            }
            drop(storage);
            drop(sessions);

            // Check and sync blobs according to configured BlobSyncRules
            self.sync_blobs_for_changes(&applied_changes, peer_addr, session_token)
                .await;
        }

        Ok((session_token, applied_changes))
    }

    /// Fetches blobs referenced by applied changes if matching configured BlobSyncRules.
    pub async fn sync_blobs_for_changes(
        &self,
        changes: &[Change],
        peer_addr: EndpointAddr,
        session_token: [u8; 32],
    ) {
        let rules = {
            let storage = self.storage.read().await;
            storage.load_blob_sync_rules().unwrap_or_default()
        };

        if rules.is_empty() {
            return;
        }

        let mut candidate_blobs = BTreeSet::new();
        for change in changes {
            for op in &change.operations {
                match op {
                    Operation::SetEntityProperty { name, value, .. } => {
                        let is_blob_ref = name.name.contains("blob")
                            || name.name.contains("receipt")
                            || name.name.contains("backed_by");
                        if is_blob_ref {
                            match value {
                                PropertyValue::BlobRef(blob_id) => {
                                    candidate_blobs.insert(*blob_id);
                                }
                                PropertyValue::Text(s) => {
                                    if let Ok(blob_id) = s.parse::<BlobId>() {
                                        candidate_blobs.insert(blob_id);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Operation::SetRelationProperty { name, value, .. } => {
                        let is_blob_ref =
                            name.name.contains("blob") || name.name.contains("backed_by");
                        if is_blob_ref {
                            match value {
                                PropertyValue::BlobRef(blob_id) => {
                                    candidate_blobs.insert(*blob_id);
                                }
                                PropertyValue::Text(s) => {
                                    if let Ok(blob_id) = s.parse::<BlobId>() {
                                        candidate_blobs.insert(blob_id);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        for blob_id in candidate_blobs {
            let already_has = {
                let blobs = self.blobs.read().await;
                blobs.get_descriptor(&blob_id).is_some()
            };
            if !already_has
                && let Ok(bytes) = self
                    .net_node
                    .fetch_blob(peer_addr.clone(), session_token, blob_id)
                    .await
            {
                let mut blobs = self.blobs.write().await;
                let _ = blobs.put(blob_id, &bytes, None);
            }
        }
    }

    /// Handles a single incoming Iroh QUIC peer connection, persisting newly applied changes
    /// to SQLite storage and broadcasting them to subscribed IPC sessions.
    pub async fn handle_net_connection(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<Vec<Change>, DaemonError> {
        let applied_changes = PdsNetworkNode::handle_connection(
            conn,
            self.shared_dag.clone(),
            self.trust.clone(),
            self.blobs.clone(),
            self.net_node.active_tokens(),
        )
        .await?;

        if !applied_changes.is_empty() {
            let mut storage = self.storage.write().await;
            let mut sessions = self.sessions.write().await;

            for change in &applied_changes {
                storage.append_change(change.clone())?;

                let notif = IpcNotification::ChangeAppended {
                    change_id: change.id,
                    change: change.clone(),
                };
                sessions.publish_notification(EventTopic::AllChanges, notif.clone());
            }

            // Trigger proactive blob fetch with paired peers in peer_routing
            let routing_records = storage.load_all_peer_routing().unwrap_or_default();
            drop(storage);
            drop(sessions);

            for rec in routing_records {
                if let Ok(addr) = serde_json::from_str::<EndpointAddr>(&rec.endpoint_addr_json) {
                    let d = self.clone();
                    let changes = applied_changes.clone();
                    tokio::spawn(async move {
                        if let Ok((token, _)) = d
                            .net_node
                            .sync_with_peer(addr.clone(), &d.signing_key)
                            .await
                        {
                            d.sync_blobs_for_changes(&changes, addr, token).await;
                        }
                    });
                }
            }
        }

        Ok(applied_changes)
    }

    /// Broadcasts HeadAnnounce to all stored peers in peer_routing.
    pub async fn broadcast_change_to_peers(&self) {
        let routing_records = {
            let storage = self.storage.read().await;
            storage.load_all_peer_routing().unwrap_or_default()
        };

        let local_node_id = {
            let trust = self.trust.read().await;
            trust.local_node_id().to_string()
        };

        for rec in routing_records {
            if let Ok(addr) = serde_json::from_str::<EndpointAddr>(&rec.endpoint_addr_json)
                && let Ok((_remote_heads, needs_sync)) = self
                    .net_node
                    .announce_heads(addr.clone(), local_node_id.clone())
                    .await
                && needs_sync
            {
                let _ = self.sync_with_peer(addr).await;
            }
        }
    }

    /// Internal helper: appends a change to SQLite, keeps shared_dag in sync,
    /// and triggers a reactive HeadAnnounce broadcast to paired peers.
    async fn append_and_sync_change(&self, change: Change) -> Result<(), DaemonError> {
        {
            let mut storage = self.storage.write().await;
            storage.append_change(change.clone())?;
        }
        {
            let mut dag = self.shared_dag.write().await;
            if dag.get(&change.id).is_none() {
                dag.insert(change)?;
            }
        }
        self.broadcast_change_to_peers().await;
        Ok(())
    }

    /// Spawns the background sync and connection acceptance tasks with graceful shutdown via watch receiver.
    /// Runs incoming Iroh connection handler loop and periodic heartbeat sync with exponential backoff.
    pub fn start_background_sync(
        self: Arc<Self>,
        heartbeat_secs: u64,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let srv_endpoint = self.net_node.endpoint().clone();

            // Task 1: accept incoming connections
            let accept_daemon = self.clone();
            let mut accept_shutdown = shutdown_rx.clone();
            let accept_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = accept_shutdown.changed() => {
                            if *accept_shutdown.borrow() {
                                break;
                            }
                        }
                        incoming = srv_endpoint.accept() => {
                            match incoming {
                                Some(inc) => {
                                    if let Ok(conn) = inc.await {
                                        let d = accept_daemon.clone();
                                        tokio::spawn(async move {
                                            let _ = d.handle_net_connection(conn).await;
                                        });
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
            });

            // Task 2: periodic heartbeat sync loop with backoff per peer
            let mut peer_backoff_secs: std::collections::BTreeMap<String, u64> =
                std::collections::BTreeMap::new();
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(heartbeat_secs.max(1)));

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        let routing_records = {
                            let storage = self.storage.read().await;
                            storage.load_all_peer_routing().unwrap_or_default()
                        };

                        let local_node_id = {
                            let trust = self.trust.read().await;
                            trust.local_node_id().to_string()
                        };

                        for rec in routing_records {
                            let backoff = peer_backoff_secs.entry(rec.node_id.clone()).or_insert(5);
                            if let Ok(addr) = serde_json::from_str::<EndpointAddr>(&rec.endpoint_addr_json) {
                                match self.net_node.announce_heads(addr.clone(), local_node_id.clone()).await {
                                    Ok((_heads, needs_sync)) => {
                                        // Reset backoff on success
                                        *backoff = 5;
                                        if needs_sync {
                                            let _ = self.sync_with_peer(addr).await;
                                        }
                                    }
                                    Err(_) => {
                                        // Exponential backoff up to 60s
                                        *backoff = (*backoff * 2).min(60);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let _ = accept_handle.await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::PdsIpcClient;
    use crate::value::{PropertyName, PropertyValue};
    use ed25519_dalek::SigningKey;

    #[tokio::test]
    async fn test_daemon_ipc_and_p2p_sync_lifecycle() {
        let dir1 = std::env::temp_dir().join(format!("pds_daemon_test_{}", EntityId::new()));
        let dir2 = std::env::temp_dir().join(format!("pds_daemon_test_{}", EntityId::new()));

        let daemon1 = PdsNodeDaemon::init(&dir1, "daemon-1").await.unwrap();
        let daemon2 = PdsNodeDaemon::init(&dir2, "daemon-2").await.unwrap();

        // 1. Client creates entity on Daemon 1 via IPC
        let signing_key = SigningKey::from_bytes(&[88u8; 32]);

        // Pre-register and approve client on daemon1
        let client_id = {
            let auth_arc = daemon1.authenticator();
            let mut auth = auth_arc.write().await;
            let id = auth.register_client("DaemonApp", signing_key.verifying_key().to_bytes());
            let mut perms = BTreeSet::new();
            perms.insert(Permission::ReadEntities);
            perms.insert(Permission::WriteEntities);
            perms.insert(Permission::ReadHistory);
            auth.approve_client(&id, perms);
            id
        };

        let mut client = PdsIpcClient::new(client_id, signing_key);

        let hello = client.start_handshake(vec!["1.0.0".into()]);
        let resp = daemon1.handle_ipc_request(hello, None).await.unwrap();
        let challenge = match resp {
            IpcResponse::Challenge(c) => c,
            other => panic!("Expected challenge, got {:?}", other),
        };

        let auth_req = client.handle_challenge(&challenge);
        let resp = daemon1.handle_ipc_request(auth_req, None).await.unwrap();
        match resp {
            IpcResponse::Authenticated(success) => client.handle_auth_success(&success),
            other => panic!("Expected authenticated, got {:?}", other),
        };

        // Create an entity via IPC
        let prop_name = PropertyName::new("title");
        let create_req = client
            .create_entity_request(
                Some("note".into()),
                vec![(prop_name.clone(), PropertyValue::Text("Daemon Note".into()))],
            )
            .unwrap();
        let resp = daemon1.handle_ipc_request(create_req, None).await.unwrap();
        let entity_id = match resp {
            IpcResponse::EntityCreated(id) => id,
            other => panic!("Expected EntityCreated, got {:?}", other),
        };

        // Register mutual trust between Daemon 1 and Daemon 2
        {
            let pin = "654321";
            let pin_hash = TrustManager::compute_pin_hash(
                &daemon2.signing_key().verifying_key().to_bytes(),
                pin,
            );
            let t1_arc = daemon1.trust();
            let mut t1 = t1_arc.write().await;
            let (_trusted_n2, auth_event) = t1
                .complete_pairing(
                    "daemon-2".into(),
                    "Daemon 2".into(),
                    daemon2.signing_key().verifying_key().to_bytes(),
                    pin,
                    pin_hash,
                )
                .unwrap();

            let t2_arc = daemon2.trust();
            let mut t2 = t2_arc.write().await;
            t2.register_trusted_node(t1.get_node("daemon-1").unwrap().clone());
            t2.apply_authorization(auth_event).unwrap();
        }

        // Verify entity persisted in SQLite on Daemon 1
        {
            let st_arc = daemon1.storage();
            let storage1 = st_arc.read().await;
            assert_eq!(storage1.change_count(), 1);
            assert!(storage1.state().entities.contains_key(&entity_id));
        }

        // 2. Daemon 1 runs incoming connection listener in local set
        let srv_endpoint = daemon1.net_node().endpoint().clone();
        let daemon1_shared_dag = daemon1.dag();
        let daemon1_trust = daemon1.trust();
        let daemon1_blobs = daemon1.blobs.clone();
        let daemon1_tokens = daemon1.net_node().active_tokens();
        let daemon1_storage = daemon1.storage();
        let daemon1_addr = daemon1.addr();
        let storage2_arc = daemon2.storage();

        let server_handle = tokio::spawn(async move {
            let incoming = srv_endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let changes = PdsNetworkNode::handle_connection(
                conn,
                daemon1_shared_dag,
                daemon1_trust,
                daemon1_blobs,
                daemon1_tokens,
            )
            .await
            .unwrap();
            let mut st = daemon1_storage.write().await;
            for c in changes {
                st.append_change(c).unwrap();
            }
        });

        // 3. Daemon 2 syncs with Daemon 1
        let (_token, applied) = daemon2.sync_with_peer(daemon1_addr).await.unwrap();
        assert_eq!(
            applied.len(),
            1,
            "Daemon 2 must receive 1 change from Daemon 1"
        );

        server_handle.await.unwrap();

        // Verify Daemon 2 persisted the change from Daemon 1 into SQLite
        {
            let storage2 = storage2_arc.read().await;
            assert_eq!(storage2.change_count(), 1);
            let ent = storage2.state().entities.get(&entity_id).unwrap();
            assert_eq!(
                ent.properties.get(&prop_name),
                Some(&PropertyValue::Text("Daemon Note".into()))
            );
        }

        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[tokio::test]
    async fn test_background_sync_and_blob_rule_replication() {
        tokio::time::timeout(std::time::Duration::from_secs(59), async {
            let dir1 =
                std::env::temp_dir().join(format!("pds_bg_sync_1_{}", ulid::Ulid::generate()));
            let dir2 =
                std::env::temp_dir().join(format!("pds_bg_sync_2_{}", ulid::Ulid::generate()));

            let daemon1 = Arc::new(PdsNodeDaemon::init(&dir1, "daemon-1").await.unwrap());
            let daemon2 = Arc::new(PdsNodeDaemon::init(&dir2, "daemon-2").await.unwrap());

            // Mutual trust pairing
            let pin = "123456";
            let pin_hash = TrustManager::compute_pin_hash(
                &daemon2.signing_key().verifying_key().to_bytes(),
                pin,
            );
            let t1_arc = daemon1.trust();
            let (_trusted_n2, auth_event) = {
                let mut t1 = t1_arc.write().await;
                t1.complete_pairing(
                    "daemon-2".into(),
                    "Daemon 2".into(),
                    daemon2.signing_key().verifying_key().to_bytes(),
                    pin,
                    pin_hash,
                )
                .unwrap()
            };

            {
                let t2_arc = daemon2.trust();
                let mut t2 = t2_arc.write().await;
                let t1 = t1_arc.read().await;
                t2.register_trusted_node(t1.get_node("daemon-1").unwrap().clone());
                t2.apply_authorization(auth_event).unwrap();
            }

            // Configure peer routing on daemon2 pointing to daemon1
            let d1_addr_json = serde_json::to_string(&daemon1.addr()).unwrap();
            {
                let st2 = daemon2.storage();
                let storage2 = st2.read().await;
                storage2
                    .save_peer_routing("daemon-1", &d1_addr_json, chrono::Utc::now())
                    .unwrap();
            }

            // Configure peer routing on daemon1 pointing to daemon2
            let d2_addr_json = serde_json::to_string(&daemon2.addr()).unwrap();
            {
                let st1 = daemon1.storage();
                let storage1 = st1.read().await;
                storage1
                    .save_peer_routing("daemon-2", &d2_addr_json, chrono::Utc::now())
                    .unwrap();
            }

            // Configure BlobSyncRule on daemon2 for receipt backed_by blobs
            {
                let st2 = daemon2.storage();
                let storage2 = st2.read().await;
                let rule = crate::storage::BlobSyncRule {
                    id: "receipt-rule".into(),
                    app_id: Some("accounting".into()),
                    entity_type: Some("receipt".into()),
                    relation_type: Some("backed_by".into()),
                    max_size_bytes: Some(1024 * 1024),
                    created_at: chrono::Utc::now(),
                };
                storage2.save_blob_sync_rule(&rule).unwrap();
            }

            // Store a blob on daemon1
            let blob_payload = b"Sample receipt scan PDF data";
            let blob_id = BlobId::new();
            {
                let mut b1 = daemon1.blobs.write().await;
                b1.put(blob_id, blob_payload, Some("application/pdf".into()))
                    .unwrap();
            }

            // Create an entity change on daemon1 referencing the blob via IPC
            let prop_name = PropertyName::new("receipt_blob");
            let client_key = SigningKey::from_bytes(&[77u8; 32]);
            let client_id = {
                let auth_arc = daemon1.authenticator();
                let mut auth = auth_arc.write().await;
                let id =
                    auth.register_client("AccountingApp", client_key.verifying_key().to_bytes());
                let mut perms = BTreeSet::new();
                perms.insert(Permission::WriteEntities);
                auth.approve_client(&id, perms);
                id
            };

            let mut client = PdsIpcClient::new(client_id, client_key);
            let hello = client.start_handshake(vec!["1.0.0".into()]);
            let resp = daemon1.handle_ipc_request(hello, None).await.unwrap();
            let challenge = match resp {
                IpcResponse::Challenge(c) => c,
                other => panic!("Expected challenge, got {:?}", other),
            };
            let auth_req = client.handle_challenge(&challenge);
            let resp = daemon1.handle_ipc_request(auth_req, None).await.unwrap();
            match resp {
                IpcResponse::Authenticated(success) => client.handle_auth_success(&success),
                other => panic!("Expected authenticated, got {:?}", other),
            };

            // Start background sync on daemon1 with shutdown signal
            let (shutdown_tx1, shutdown_rx1) = tokio::sync::watch::channel(false);
            let bg_handle1 = daemon1.clone().start_background_sync(1, shutdown_rx1);

            // Start background sync on daemon2 with shutdown signal
            let (shutdown_tx2, shutdown_rx2) = tokio::sync::watch::channel(false);
            let bg_handle2 = daemon2.clone().start_background_sync(1, shutdown_rx2);

            let create_req = client
                .create_entity_request(
                    Some("receipt".into()),
                    vec![(prop_name.clone(), PropertyValue::BlobRef(blob_id))],
                )
                .unwrap();
            let resp = daemon1.handle_ipc_request(create_req, None).await.unwrap();
            let entity_id = match resp {
                IpcResponse::EntityCreated(id) => id,
                other => panic!("Expected EntityCreated, got {:?}", other),
            };

            // Wait for background periodic heartbeat & blob sync to propagate
            let mut synced = false;
            for _i in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                let st2 = daemon2.storage();
                let storage2 = st2.read().await;
                let has_entity = storage2.state().entities.contains_key(&entity_id);
                let b2 = daemon2.blobs.read().await;
                let has_blob = b2.get_descriptor(&blob_id).is_some();
                if has_entity && has_blob {
                    synced = true;
                    break;
                }
            }

            assert!(synced, "Daemon 2 must sync change and blob in background");

            // Verify data integrity on daemon2
            {
                let b2 = daemon2.blobs.read().await;
                let data = b2.get_data(&blob_id).unwrap();
                assert_eq!(data, blob_payload);
            }

            // Graceful shutdown
            let _ = shutdown_tx1.send(true);
            let _ = shutdown_tx2.send(true);
            let _ = bg_handle1.await;
            let _ = bg_handle2.await;

            let _ = std::fs::remove_dir_all(&dir1);
            let _ = std::fs::remove_dir_all(&dir2);
        })
        .await
        .expect("test_background_sync_and_blob_rule_replication timed out after 59s");
    }
}
