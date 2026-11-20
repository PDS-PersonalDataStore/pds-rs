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
            .sync_with_peer(peer_addr, &self.signing_key)
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
        }

        Ok((session_token, applied_changes))
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
        }

        Ok(applied_changes)
    }

    /// Internal helper: appends a change to SQLite and keeps shared_dag in sync.
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
        Ok(())
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
        let local = tokio::task::LocalSet::new();
        let srv_endpoint = daemon1.net_node().endpoint().clone();
        let daemon1_shared_dag = daemon1.dag();
        let daemon1_trust = daemon1.trust();
        let daemon1_blobs = daemon1.blobs.clone();
        let daemon1_tokens = daemon1.net_node().active_tokens();
        let daemon1_storage = daemon1.storage();
        let daemon1_addr = daemon1.addr();
        let storage2_arc = daemon2.storage();

        local
            .run_until(async move {
                let server_handle = tokio::task::spawn_local(async move {
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
            })
            .await;

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
}
