use crate::auth::{AuthChallenge, AuthSuccess, ClientAuth, ClientHello};
use crate::blob::BlobDescriptor;
use crate::change::Change;
use crate::entity::Entity;
use crate::id::{BlobId, ChangeId, EntityId, KeyId, RelationId};
use crate::operation::Operation;
use crate::relation::Relation;
use crate::security::Permission;
use crate::storage::DiskStorage;
use crate::value::{PropertyName, PropertyValue};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", content = "payload")]
pub enum IpcRequest {
    Hello(ClientHello),
    Authenticate(ClientAuth),
    GetEntity {
        session_id: String,
        entity_id: EntityId,
    },
    CreateEntity {
        session_id: String,
        entity_type: Option<String>,
        properties: Vec<(PropertyName, PropertyValue)>,
    },
    UpdateEntity {
        session_id: String,
        entity_id: EntityId,
        set_properties: Vec<(PropertyName, PropertyValue)>,
        remove_properties: Vec<PropertyName>,
    },
    DeleteEntity {
        session_id: String,
        entity_id: EntityId,
    },
    GetRelation {
        session_id: String,
        relation_id: RelationId,
    },
    CreateRelation {
        session_id: String,
        relation_type: String,
        source: EntityId,
        target: EntityId,
    },
    UpdateRelation {
        session_id: String,
        relation_id: RelationId,
        set_properties: Vec<(PropertyName, PropertyValue)>,
        remove_properties: Vec<PropertyName>,
    },
    DeleteRelation {
        session_id: String,
        relation_id: RelationId,
    },
    GetBlob {
        session_id: String,
        blob_id: BlobId,
    },
    GetBlobDescriptor {
        session_id: String,
        blob_id: BlobId,
    },
    PutBlob {
        session_id: String,
        data: Vec<u8>,
        media_type: Option<String>,
    },
    PutEncryptedBlob {
        session_id: String,
        plaintext: Vec<u8>,
        key_id: KeyId,
        media_type: Option<String>,
    },
    PollChanges {
        session_id: String,
        since_change_id: Option<ChangeId>,
        limit: Option<usize>,
    },
    GetPendingChanges {
        session_id: String,
        limit: Option<usize>,
    },
    AcknowledgeChanges {
        session_id: String,
        change_id: ChangeId,
    },
    GetClientCursor {
        session_id: String,
    },
    Subscribe {
        session_id: String,
        topics: BTreeSet<EventTopic>,
    },
    Unsubscribe {
        session_id: String,
        topics: BTreeSet<EventTopic>,
    },
    CloseSession {
        session_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventTopic {
    AllChanges,
    EntityChanges,
    RelationChanges,
    BlobCreated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload")]
pub enum IpcNotification {
    ChangeAppended { change_id: ChangeId, change: Change },
    BlobAppended { descriptor: BlobDescriptor },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "payload")]
pub enum IpcResponse {
    Challenge(AuthChallenge),
    Authenticated(AuthSuccess),
    Entity(Option<Entity>),
    EntityCreated(EntityId),
    EntityUpdated(EntityId),
    EntityDeleted(EntityId),
    Relation(Option<Relation>),
    RelationCreated(RelationId),
    RelationUpdated(RelationId),
    RelationDeleted(RelationId),
    Blob(Vec<u8>),
    BlobDescriptor(Option<BlobDescriptor>),
    BlobCreated(BlobDescriptor),
    Changes {
        changes: Vec<Change>,
        latest_change_id: Option<ChangeId>,
    },
    Cursor(Option<ChangeId>),
    ChangesAcknowledged {
        last_ack_change_id: ChangeId,
    },
    Subscribed {
        topics: BTreeSet<EventTopic>,
    },
    Unsubscribed {
        topics: BTreeSet<EventTopic>,
    },
    SessionClosed,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub client_id: crate::auth::ClientId,
    pub permissions: BTreeSet<Permission>,
    pub expires_at: DateTime<Utc>,
    pub peer_pid: Option<u32>,
    pub api_version: String,
    pub subscriptions: BTreeSet<EventTopic>,
    pub pending_notifications: Vec<IpcNotification>,
}

#[derive(Default)]
pub struct IpcSessionManager {
    sessions: BTreeMap<String, Session>,
}

impl IpcSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }

    pub fn insert_session(&mut self, session: Session) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        let session = self.sessions.get(session_id)?;
        if Utc::now() > session.expires_at {
            return None;
        }
        Some(session)
    }

    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut Session> {
        let session = self.sessions.get_mut(session_id)?;
        if Utc::now() > session.expires_at {
            return None;
        }
        Some(session)
    }

    pub fn remove_session(&mut self, session_id: &str) -> Option<Session> {
        self.sessions.remove(session_id)
    }

    pub fn check_permission(
        &self,
        session_id: &str,
        permission: &Permission,
    ) -> Result<(), &'static str> {
        let session = self
            .get_session(session_id)
            .ok_or("Invalid or expired session")?;
        if !session.permissions.contains(permission) {
            return Err("Permission denied");
        }
        Ok(())
    }

    pub fn subscribe(
        &mut self,
        session_id: &str,
        topics: BTreeSet<EventTopic>,
    ) -> Result<BTreeSet<EventTopic>, &'static str> {
        let session = self
            .get_session_mut(session_id)
            .ok_or("Invalid or expired session")?;
        session.subscriptions.extend(topics);
        Ok(session.subscriptions.clone())
    }

    pub fn unsubscribe(
        &mut self,
        session_id: &str,
        topics: &BTreeSet<EventTopic>,
    ) -> Result<BTreeSet<EventTopic>, &'static str> {
        let session = self
            .get_session_mut(session_id)
            .ok_or("Invalid or expired session")?;
        for topic in topics {
            session.subscriptions.remove(topic);
        }
        Ok(session.subscriptions.clone())
    }

    pub fn publish_notification(&mut self, topic: EventTopic, notification: IpcNotification) {
        let now = Utc::now();
        for session in self.sessions.values_mut() {
            if session.expires_at > now {
                let matches = session.subscriptions.contains(&EventTopic::AllChanges)
                    || session.subscriptions.contains(&topic);
                if matches {
                    session.pending_notifications.push(notification.clone());
                }
            }
        }
    }

    pub fn drain_notifications(&mut self, session_id: &str) -> Vec<IpcNotification> {
        if let Some(session) = self.get_session_mut(session_id) {
            std::mem::take(&mut session.pending_notifications)
        } else {
            Vec::new()
        }
    }
}

pub struct IpcServerHandler<'a> {
    pub storage: &'a mut DiskStorage,
    pub sessions: &'a mut IpcSessionManager,
    pub authenticator: &'a mut crate::auth::ClientAuthenticator,
}

impl<'a> IpcServerHandler<'a> {
    pub fn new(
        storage: &'a mut DiskStorage,
        sessions: &'a mut IpcSessionManager,
        authenticator: &'a mut crate::auth::ClientAuthenticator,
    ) -> Self {
        Self {
            storage,
            sessions,
            authenticator,
        }
    }

    pub fn handle_request(&mut self, request: IpcRequest, peer_pid: Option<u32>) -> IpcResponse {
        match request {
            IpcRequest::Hello(hello) => match self.authenticator.handle_client_hello(&hello) {
                Ok(challenge) => IpcResponse::Challenge(challenge),
                Err(err) => IpcResponse::Error(err.to_string()),
            },
            IpcRequest::Authenticate(auth) => match self.authenticator.handle_client_auth(&auth) {
                Ok(success) => {
                    self.sessions.insert_session(Session {
                        session_id: success.session_id.clone(),
                        client_id: success.client_id,
                        permissions: success.permissions.clone(),
                        expires_at: success.expires_at,
                        peer_pid,
                        api_version: success.api_version.clone(),
                        subscriptions: BTreeSet::new(),
                        pending_notifications: Vec::new(),
                    });
                    IpcResponse::Authenticated(success)
                }
                Err(err) => IpcResponse::Error(err.to_string()),
            },
            IpcRequest::GetEntity {
                session_id,
                entity_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let entity = self.storage.state().entities.get(&entity_id).cloned();
                IpcResponse::Entity(entity)
            }
            IpcRequest::CreateEntity {
                session_id,
                entity_type,
                properties,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteEntities)
                {
                    return IpcResponse::Error(err.to_string());
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

                let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("ipc-client");
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);

                let change_id = change.id;
                if let Err(err) = self.storage.append_change(change.clone()) {
                    return IpcResponse::Error(err.to_string());
                }

                let notif = IpcNotification::ChangeAppended { change_id, change };
                self.sessions
                    .publish_notification(EventTopic::AllChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::EntityChanges, notif);

                IpcResponse::EntityCreated(entity_id)
            }
            IpcRequest::UpdateEntity {
                session_id,
                entity_id,
                set_properties,
                remove_properties,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }

                if !self.storage.state().entities.contains_key(&entity_id) {
                    return IpcResponse::Error(format!("Entity not found: {entity_id}"));
                }

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

                let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("ipc-client");
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);

                let change_id = change.id;
                if let Err(err) = self.storage.append_change(change.clone()) {
                    return IpcResponse::Error(err.to_string());
                }

                let notif = IpcNotification::ChangeAppended { change_id, change };
                self.sessions
                    .publish_notification(EventTopic::AllChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::EntityChanges, notif);

                IpcResponse::EntityUpdated(entity_id)
            }
            IpcRequest::DeleteEntity {
                session_id,
                entity_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }

                if !self.storage.state().entities.contains_key(&entity_id) {
                    return IpcResponse::Error(format!("Entity not found: {entity_id}"));
                }

                let ops = vec![Operation::DeleteEntity { entity_id }];
                let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("ipc-client");
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);

                let change_id = change.id;
                if let Err(err) = self.storage.append_change(change.clone()) {
                    return IpcResponse::Error(err.to_string());
                }

                let notif = IpcNotification::ChangeAppended { change_id, change };
                self.sessions
                    .publish_notification(EventTopic::AllChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::EntityChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::RelationChanges, notif);

                IpcResponse::EntityDeleted(entity_id)
            }
            IpcRequest::GetRelation {
                session_id,
                relation_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let rel = self.storage.state().relations.get(&relation_id).cloned();
                IpcResponse::Relation(rel)
            }
            IpcRequest::CreateRelation {
                session_id,
                relation_type,
                source,
                target,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }

                let relation_id = RelationId::new();
                let ops = vec![Operation::CreateRelation {
                    relation_id,
                    relation_type,
                    source,
                    target,
                }];

                let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("ipc-client");
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);

                let change_id = change.id;
                if let Err(err) = self.storage.append_change(change.clone()) {
                    return IpcResponse::Error(err.to_string());
                }

                let notif = IpcNotification::ChangeAppended { change_id, change };
                self.sessions
                    .publish_notification(EventTopic::AllChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::RelationChanges, notif);

                IpcResponse::RelationCreated(relation_id)
            }
            IpcRequest::UpdateRelation {
                session_id,
                relation_id,
                set_properties,
                remove_properties,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }

                if !self.storage.state().relations.contains_key(&relation_id) {
                    return IpcResponse::Error(format!("Relation not found: {relation_id}"));
                }

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

                let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("ipc-client");
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);

                let change_id = change.id;
                if let Err(err) = self.storage.append_change(change.clone()) {
                    return IpcResponse::Error(err.to_string());
                }

                let notif = IpcNotification::ChangeAppended { change_id, change };
                self.sessions
                    .publish_notification(EventTopic::AllChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::RelationChanges, notif);

                IpcResponse::RelationUpdated(relation_id)
            }
            IpcRequest::DeleteRelation {
                session_id,
                relation_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteEntities)
                {
                    return IpcResponse::Error(err.to_string());
                }

                if !self.storage.state().relations.contains_key(&relation_id) {
                    return IpcResponse::Error(format!("Relation not found: {relation_id}"));
                }

                let ops = vec![Operation::DeleteRelation { relation_id }];
                let parents: Vec<ChangeId> = self.storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("ipc-client");
                let change = crate::change::Change::new(ChangeId::new(), parents, meta, ops);

                let change_id = change.id;
                if let Err(err) = self.storage.append_change(change.clone()) {
                    return IpcResponse::Error(err.to_string());
                }

                let notif = IpcNotification::ChangeAppended { change_id, change };
                self.sessions
                    .publish_notification(EventTopic::AllChanges, notif.clone());
                self.sessions
                    .publish_notification(EventTopic::RelationChanges, notif);

                IpcResponse::RelationDeleted(relation_id)
            }
            IpcRequest::GetBlob {
                session_id,
                blob_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadBlobs)
                {
                    return IpcResponse::Error(err.to_string());
                }
                match self.storage.blobs().get_data(&blob_id) {
                    Ok(data) => IpcResponse::Blob(data),
                    Err(err) => IpcResponse::Error(err.to_string()),
                }
            }
            IpcRequest::GetBlobDescriptor {
                session_id,
                blob_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadBlobs)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let desc = self.storage.blobs().get_descriptor(&blob_id).cloned();
                IpcResponse::BlobDescriptor(desc)
            }
            IpcRequest::PutBlob {
                session_id,
                data,
                media_type,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteBlobs)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let blob_id = BlobId::new();
                match self.storage.blobs_mut().put(blob_id, &data, media_type) {
                    Ok(descriptor) => {
                        self.sessions.publish_notification(
                            EventTopic::BlobCreated,
                            IpcNotification::BlobAppended {
                                descriptor: descriptor.clone(),
                            },
                        );
                        IpcResponse::BlobCreated(descriptor)
                    }
                    Err(err) => IpcResponse::Error(err.to_string()),
                }
            }
            IpcRequest::PutEncryptedBlob {
                session_id,
                plaintext: _,
                key_id: _,
                media_type: _,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::WriteBlobs)
                {
                    return IpcResponse::Error(err.to_string());
                }
                IpcResponse::Error(
                    "Encrypted blob storage via standalone handler requires keystore".into(),
                )
            }
            IpcRequest::PollChanges {
                session_id,
                since_change_id,
                limit,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadHistory)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let topological = self.storage.dag().topological_order();
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
                IpcResponse::Changes {
                    changes: collected,
                    latest_change_id,
                }
            }
            IpcRequest::GetPendingChanges { session_id, limit } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadHistory)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let client_id = match self.sessions.get_session(&session_id) {
                    Some(s) => s.client_id,
                    None => return IpcResponse::Error("Session not found".into()),
                };
                let since_change_id = self.storage.get_client_cursor(&client_id);
                let topological = self.storage.dag().topological_order();
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
                IpcResponse::Changes {
                    changes: collected,
                    latest_change_id,
                }
            }
            IpcRequest::AcknowledgeChanges {
                session_id,
                change_id,
            } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadHistory)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let client_id = match self.sessions.get_session(&session_id) {
                    Some(s) => s.client_id,
                    None => return IpcResponse::Error("Session not found".into()),
                };
                if let Err(err) = self.storage.set_client_cursor(client_id, Some(change_id)) {
                    return IpcResponse::Error(err.to_string());
                }
                IpcResponse::ChangesAcknowledged {
                    last_ack_change_id: change_id,
                }
            }
            IpcRequest::GetClientCursor { session_id } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadHistory)
                {
                    return IpcResponse::Error(err.to_string());
                }
                let client_id = match self.sessions.get_session(&session_id) {
                    Some(s) => s.client_id,
                    None => return IpcResponse::Error("Session not found".into()),
                };
                let cursor = self.storage.get_client_cursor(&client_id);
                IpcResponse::Cursor(cursor)
            }
            IpcRequest::Subscribe { session_id, topics } => {
                if let Err(err) = self
                    .sessions
                    .check_permission(&session_id, &Permission::ReadHistory)
                {
                    return IpcResponse::Error(err.to_string());
                }
                match self.sessions.subscribe(&session_id, topics) {
                    Ok(current) => IpcResponse::Subscribed { topics: current },
                    Err(err) => IpcResponse::Error(err.to_string()),
                }
            }
            IpcRequest::Unsubscribe { session_id, topics } => {
                match self.sessions.unsubscribe(&session_id, &topics) {
                    Ok(current) => IpcResponse::Unsubscribed { topics: current },
                    Err(err) => IpcResponse::Error(err.to_string()),
                }
            }
            IpcRequest::CloseSession { session_id } => {
                self.sessions.remove_session(&session_id);
                IpcResponse::SessionClosed
            }
        }
    }

    pub fn append_change_and_notify(
        &mut self,
        change: Change,
    ) -> Result<(), crate::storage::StorageError> {
        let change_id = change.id;
        let is_relation = change.operations.iter().any(|op| {
            matches!(
                op,
                Operation::CreateRelation { .. } | Operation::DeleteRelation { .. }
            )
        });
        let is_entity = change.operations.iter().any(|op| {
            matches!(
                op,
                Operation::CreateEntity { .. }
                    | Operation::SetEntityProperty { .. }
                    | Operation::RemoveEntityProperty { .. }
                    | Operation::DeleteEntity { .. }
            )
        });

        self.storage.append_change(change.clone())?;

        let notif = IpcNotification::ChangeAppended { change_id, change };
        self.sessions
            .publish_notification(EventTopic::AllChanges, notif.clone());
        if is_entity {
            self.sessions
                .publish_notification(EventTopic::EntityChanges, notif.clone());
        }
        if is_relation {
            self.sessions
                .publish_notification(EventTopic::RelationChanges, notif);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IpcClientError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Session not established. Complete handshake first.")]
    NoActiveSession,
    #[error("Server returned error: {0}")]
    ServerError(String),
    #[error("Unexpected server response")]
    UnexpectedResponse,
}

pub struct PdsIpcClient {
    client_id: crate::auth::ClientId,
    signing_key: ed25519_dalek::SigningKey,
    session_id: Option<String>,
    api_version: String,
    negotiated_version: Option<String>,
}

impl PdsIpcClient {
    pub fn new(client_id: crate::auth::ClientId, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            client_id,
            signing_key,
            session_id: None,
            api_version: crate::auth::API_VERSION.to_string(),
            negotiated_version: None,
        }
    }

    pub fn with_api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = version.into();
        self
    }

    pub fn client_id(&self) -> crate::auth::ClientId {
        self.client_id
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn negotiated_version(&self) -> Option<&str> {
        self.negotiated_version.as_deref()
    }

    pub fn start_handshake(&self, capabilities: Vec<String>) -> IpcRequest {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let hello = ClientHello::new(self.client_id, &self.api_version, nonce, capabilities);
        IpcRequest::Hello(hello)
    }

    pub fn handle_challenge(&mut self, challenge: &AuthChallenge) -> IpcRequest {
        let sig = crate::auth::create_client_auth_signature(&self.signing_key, challenge);
        IpcRequest::Authenticate(ClientAuth {
            client_id: self.client_id,
            signature: sig,
        })
    }

    pub fn handle_auth_success(&mut self, success: &AuthSuccess) {
        self.session_id = Some(success.session_id.clone());
        self.negotiated_version = Some(success.api_version.clone());
    }

    pub fn require_session(&self) -> Result<&str, IpcClientError> {
        self.session_id
            .as_deref()
            .ok_or(IpcClientError::NoActiveSession)
    }

    pub fn get_entity_request(&self, entity_id: EntityId) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::GetEntity {
            session_id,
            entity_id,
        })
    }

    pub fn create_entity_request(
        &self,
        entity_type: Option<String>,
        properties: Vec<(PropertyName, PropertyValue)>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::CreateEntity {
            session_id,
            entity_type,
            properties,
        })
    }

    pub fn update_entity_request(
        &self,
        entity_id: EntityId,
        set_properties: Vec<(PropertyName, PropertyValue)>,
        remove_properties: Vec<PropertyName>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::UpdateEntity {
            session_id,
            entity_id,
            set_properties,
            remove_properties,
        })
    }

    pub fn delete_entity_request(&self, entity_id: EntityId) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::DeleteEntity {
            session_id,
            entity_id,
        })
    }

    pub fn get_relation_request(
        &self,
        relation_id: RelationId,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::GetRelation {
            session_id,
            relation_id,
        })
    }

    pub fn create_relation_request(
        &self,
        relation_type: String,
        source: EntityId,
        target: EntityId,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::CreateRelation {
            session_id,
            relation_type,
            source,
            target,
        })
    }

    pub fn update_relation_request(
        &self,
        relation_id: RelationId,
        set_properties: Vec<(PropertyName, PropertyValue)>,
        remove_properties: Vec<PropertyName>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::UpdateRelation {
            session_id,
            relation_id,
            set_properties,
            remove_properties,
        })
    }

    pub fn delete_relation_request(
        &self,
        relation_id: RelationId,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::DeleteRelation {
            session_id,
            relation_id,
        })
    }

    pub fn get_blob_request(&self, blob_id: BlobId) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::GetBlob {
            session_id,
            blob_id,
        })
    }

    pub fn get_blob_descriptor_request(
        &self,
        blob_id: BlobId,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::GetBlobDescriptor {
            session_id,
            blob_id,
        })
    }

    pub fn put_blob_request(
        &self,
        data: Vec<u8>,
        media_type: Option<String>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::PutBlob {
            session_id,
            data,
            media_type,
        })
    }

    pub fn put_encrypted_blob_request(
        &self,
        plaintext: Vec<u8>,
        key_id: KeyId,
        media_type: Option<String>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::PutEncryptedBlob {
            session_id,
            plaintext,
            key_id,
            media_type,
        })
    }

    pub fn poll_changes_request(
        &self,
        since_change_id: Option<ChangeId>,
        limit: Option<usize>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::PollChanges {
            session_id,
            since_change_id,
            limit,
        })
    }

    pub fn get_pending_changes_request(
        &self,
        limit: Option<usize>,
    ) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::GetPendingChanges { session_id, limit })
    }

    pub fn ack_changes_request(&self, change_id: ChangeId) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::AcknowledgeChanges {
            session_id,
            change_id,
        })
    }

    pub fn get_cursor_request(&self) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::GetClientCursor { session_id })
    }

    pub fn subscribe_request<I>(&self, topics: I) -> Result<IpcRequest, IpcClientError>
    where
        I: IntoIterator<Item = EventTopic>,
    {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::Subscribe {
            session_id,
            topics: topics.into_iter().collect(),
        })
    }

    pub fn unsubscribe_request<I>(&self, topics: I) -> Result<IpcRequest, IpcClientError>
    where
        I: IntoIterator<Item = EventTopic>,
    {
        let session_id = self.require_session()?.to_string();
        Ok(IpcRequest::Unsubscribe {
            session_id,
            topics: topics.into_iter().collect(),
        })
    }

    pub fn close_session_request(&mut self) -> Result<IpcRequest, IpcClientError> {
        let session_id = self.require_session()?.to_string();
        self.session_id = None;
        Ok(IpcRequest::CloseSession { session_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{API_VERSION, ClientAuthenticator, create_client_auth_signature};
    use ed25519_dalek::SigningKey;
    use rand::Rng;
    use std::fs;

    #[test]
    fn test_ipc_handler_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("pds_ipc_test_{}", EntityId::new()));
        let mut storage = DiskStorage::open(&temp_dir).unwrap();
        let mut sessions = IpcSessionManager::new();
        let mut authenticator = ClientAuthenticator::new("pds-local-test");

        let mut csprng = rand::rng();
        let mut secret = [0u8; 32];
        csprng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let client_id =
            authenticator.register_client("ShopLedger", signing_key.verifying_key().to_bytes());

        let mut perms = BTreeSet::new();
        perms.insert(Permission::ReadEntities);
        perms.insert(Permission::WriteEntities);
        authenticator.approve_client(&client_id, perms);

        let mut handler = IpcServerHandler::new(&mut storage, &mut sessions, &mut authenticator);

        let mut nonce = [0u8; 32];
        csprng.fill_bytes(&mut nonce);
        let hello = ClientHello::new(client_id, API_VERSION, nonce, vec!["ipc".into()]);

        let resp = handler.handle_request(IpcRequest::Hello(hello), Some(1234));
        let challenge = match resp {
            IpcResponse::Challenge(c) => c,
            other => panic!("Expected challenge, got {:?}", other),
        };

        let sig = create_client_auth_signature(&signing_key, &challenge);
        let auth = ClientAuth {
            client_id,
            signature: sig,
        };

        let auth_resp = handler.handle_request(IpcRequest::Authenticate(auth), Some(1234));
        let session_id = match auth_resp {
            IpcResponse::Authenticated(success) => success.session_id,
            other => panic!("Expected Authenticated, got {:?}", other),
        };

        // Create entity over IPC session
        let create_req = IpcRequest::CreateEntity {
            session_id: session_id.clone(),
            entity_type: Some("invoice".into()),
            properties: vec![("total".into(), PropertyValue::from(1500))],
        };
        let create_resp = handler.handle_request(create_req, Some(1234));
        let created_id = match create_resp {
            IpcResponse::EntityCreated(id) => id,
            other => panic!("Expected EntityCreated, got {:?}", other),
        };

        // Get entity over IPC session
        let get_req = IpcRequest::GetEntity {
            session_id: session_id.clone(),
            entity_id: created_id,
        };
        let get_resp = handler.handle_request(get_req, Some(1234));
        match get_resp {
            IpcResponse::Entity(Some(ent)) => {
                assert_eq!(ent.entity_type.as_deref(), Some("invoice"));
                assert_eq!(
                    ent.get_property(&"total".into()),
                    Some(&PropertyValue::from(1500))
                );
            }
            other => panic!("Expected Entity, got {:?}", other),
        }

        // Close session
        let close_resp = handler.handle_request(
            IpcRequest::CloseSession {
                session_id: session_id.clone(),
            },
            Some(1234),
        );
        assert_eq!(close_resp, IpcResponse::SessionClosed);

        // Next request fails
        let post_close = handler.handle_request(
            IpcRequest::GetEntity {
                session_id,
                entity_id: created_id,
            },
            Some(1234),
        );
        assert!(matches!(post_close, IpcResponse::Error(_)));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pds_ipc_client_full_flow() {
        let temp_dir =
            std::env::temp_dir().join(format!("pds_ipc_client_test_{}", EntityId::new()));
        let mut storage = DiskStorage::open(&temp_dir).unwrap();
        let mut sessions = IpcSessionManager::new();
        let mut authenticator = ClientAuthenticator::new("pds-local-node");

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let client_id = authenticator.register_client("DesktopApp", public_key);

        let mut perms = BTreeSet::new();
        perms.insert(Permission::ReadEntities);
        perms.insert(Permission::WriteEntities);
        perms.insert(Permission::ReadBlobs);
        perms.insert(Permission::WriteBlobs);
        perms.insert(Permission::ReadHistory);
        authenticator.approve_client(&client_id, perms);

        let mut handler = IpcServerHandler::new(&mut storage, &mut sessions, &mut authenticator);
        let mut client = PdsIpcClient::new(client_id, signing_key);

        // 1. Handshake
        let hello_req = client.start_handshake(vec!["entities".into(), "blobs".into()]);
        let challenge = match handler.handle_request(hello_req, Some(5678)) {
            IpcResponse::Challenge(c) => c,
            other => panic!("Expected challenge, got {:?}", other),
        };

        let auth_req = client.handle_challenge(&challenge);
        let success = match handler.handle_request(auth_req, Some(5678)) {
            IpcResponse::Authenticated(s) => s,
            other => panic!("Expected authenticated, got {:?}", other),
        };
        client.handle_auth_success(&success);
        assert!(client.session_id().is_some());

        // 2. Put and Get Blob over IPC
        let blob_data = b"Hello from encrypted personal cloud blob!".to_vec();
        let put_blob_req = client
            .put_blob_request(blob_data.clone(), Some("text/plain".into()))
            .unwrap();
        let desc = match handler.handle_request(put_blob_req, Some(5678)) {
            IpcResponse::BlobCreated(d) => d,
            other => panic!("Expected BlobCreated, got {:?}", other),
        };

        let get_blob_req = client.get_blob_request(desc.id).unwrap();
        match handler.handle_request(get_blob_req, Some(5678)) {
            IpcResponse::Blob(retrieved) => assert_eq!(retrieved, blob_data),
            other => panic!("Expected Blob, got {:?}", other),
        }

        // 3. Create Entity and Poll Changes
        let create_req = client
            .create_entity_request(
                Some("note".into()),
                vec![("title".into(), PropertyValue::Text("My Note".into()))],
            )
            .unwrap();
        let entity_id = match handler.handle_request(create_req, Some(5678)) {
            IpcResponse::EntityCreated(id) => id,
            other => panic!("Expected EntityCreated, got {:?}", other),
        };

        let get_ent_req = client.get_entity_request(entity_id).unwrap();
        match handler.handle_request(get_ent_req, Some(5678)) {
            IpcResponse::Entity(Some(ent)) => {
                assert_eq!(ent.entity_type.as_deref(), Some("note"));
            }
            other => panic!("Expected Entity, got {:?}", other),
        }

        let poll_req = client.poll_changes_request(None, Some(10)).unwrap();
        match handler.handle_request(poll_req, Some(5678)) {
            IpcResponse::Changes {
                changes,
                latest_change_id,
            } => {
                assert!(!changes.is_empty());
                assert!(latest_change_id.is_some());
            }
            other => panic!("Expected Changes, got {:?}", other),
        }

        // 4. Close Session
        let close_req = client.close_session_request().unwrap();
        assert_eq!(
            handler.handle_request(close_req, Some(5678)),
            IpcResponse::SessionClosed
        );
        assert!(client.session_id().is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pds_ipc_offline_client_reconnect_queue() {
        let temp_dir = std::env::temp_dir().join(format!("pds_offline_queue_{}", EntityId::new()));
        let signing_key = SigningKey::from_bytes(&[99u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let client_id;
        let first_change_id;

        // --- Session 1: Client connects, creates 1 entity, ACKs, then disconnects ---
        {
            let mut storage = DiskStorage::open(&temp_dir).unwrap();
            let mut sessions = IpcSessionManager::new();
            let mut authenticator = ClientAuthenticator::new("pds-node-test");

            client_id = authenticator.register_client("MobileSyncApp", public_key);

            let mut perms = BTreeSet::new();
            perms.insert(Permission::ReadEntities);
            perms.insert(Permission::WriteEntities);
            perms.insert(Permission::ReadHistory);
            authenticator.approve_client(&client_id, perms);

            let mut handler =
                IpcServerHandler::new(&mut storage, &mut sessions, &mut authenticator);
            let mut client = PdsIpcClient::new(client_id, signing_key.clone());

            let challenge = match handler
                .handle_request(client.start_handshake(vec!["history".into()]), Some(1))
            {
                IpcResponse::Challenge(c) => c,
                other => panic!("Expected challenge, got {:?}", other),
            };
            let success = match handler.handle_request(client.handle_challenge(&challenge), Some(1))
            {
                IpcResponse::Authenticated(s) => s,
                other => panic!("Expected Authenticated, got {:?}", other),
            };
            client.handle_auth_success(&success);

            // Create entity 1
            let create_req = client
                .create_entity_request(
                    Some("task".into()),
                    vec![("name".into(), PropertyValue::Text("Zadanie 1".into()))],
                )
                .unwrap();
            handler.handle_request(create_req, Some(1));

            // Initial poll: gets change 1
            let poll = match handler
                .handle_request(client.get_pending_changes_request(None).unwrap(), Some(1))
            {
                IpcResponse::Changes {
                    changes,
                    latest_change_id,
                } => {
                    assert_eq!(changes.len(), 1);
                    first_change_id = latest_change_id;
                    latest_change_id.unwrap()
                }
                other => panic!("Expected Changes, got {:?}", other),
            };

            // Client acknowledges change 1
            let ack_req = client.ack_changes_request(poll).unwrap();
            assert!(matches!(
                handler.handle_request(ack_req, Some(1)),
                IpcResponse::ChangesAcknowledged { .. }
            ));

            // Client disconnects and shuts down
            let close = client.close_session_request().unwrap();
            handler.handle_request(close, Some(1));
        }

        // --- Offline period: Changes arrive from network peer while client is disconnected ---
        {
            let mut storage = DiskStorage::open(&temp_dir).unwrap();
            // Simulate 2 changes replicated from remote peer B
            for i in 2..=3 {
                let parents = storage.dag().heads().iter().copied().collect();
                let meta = crate::change::ChangeMetadata::new("peer-node-b")
                    .with_message(format!("Peer change {i}"));
                let ops = vec![Operation::CreateEntity {
                    entity_id: EntityId::new(),
                    entity_type: Some("remote_doc".into()),
                }];
                let c = Change::new(ChangeId::new(), parents, meta, ops);
                storage.append_change(c).unwrap();
            }
            assert_eq!(storage.change_count(), 3);
        }

        // --- Session 2: Demon PDS reboots, Client wakes up after being offline ---
        {
            let mut storage = DiskStorage::open(&temp_dir).unwrap();
            let mut sessions = IpcSessionManager::new();
            let mut authenticator = ClientAuthenticator::new("pds-node-test");

            authenticator.insert_client(client_id, "MobileSyncApp", public_key);
            authenticator.approve_client(&client_id, {
                let mut perms = BTreeSet::new();
                perms.insert(Permission::ReadEntities);
                perms.insert(Permission::WriteEntities);
                perms.insert(Permission::ReadHistory);
                perms
            });

            // Verify cursor was preserved across restarts
            assert_eq!(storage.get_client_cursor(&client_id), first_change_id);

            let mut handler =
                IpcServerHandler::new(&mut storage, &mut sessions, &mut authenticator);
            let mut client = PdsIpcClient::new(client_id, signing_key);

            // Fresh handshake with new session
            let challenge = match handler
                .handle_request(client.start_handshake(vec!["history".into()]), Some(2))
            {
                IpcResponse::Challenge(c) => c,
                other => panic!("Expected challenge, got {:?}", other),
            };
            let success = match handler.handle_request(client.handle_challenge(&challenge), Some(2))
            {
                IpcResponse::Authenticated(s) => s,
                other => panic!("Expected Authenticated, got {:?}", other),
            };
            client.handle_auth_success(&success);

            // Check cursor over IPC
            let cursor_resp = handler.handle_request(client.get_cursor_request().unwrap(), Some(2));
            assert_eq!(cursor_resp, IpcResponse::Cursor(first_change_id));

            // Client pulls pending queue: receives exactly the 2 changes that arrived while offline!
            let pending_resp =
                handler.handle_request(client.get_pending_changes_request(None).unwrap(), Some(2));
            let new_last_id = match pending_resp {
                IpcResponse::Changes {
                    changes,
                    latest_change_id,
                } => {
                    assert_eq!(
                        changes.len(),
                        2,
                        "Must receive exactly the 2 changes from peer while offline"
                    );
                    assert_eq!(changes[0].metadata.device_id, "peer-node-b");
                    assert_eq!(changes[1].metadata.device_id, "peer-node-b");
                    latest_change_id.unwrap()
                }
                other => panic!("Expected Changes, got {:?}", other),
            };

            // Client acknowledges all newly caught up changes
            let ack_resp =
                handler.handle_request(client.ack_changes_request(new_last_id).unwrap(), Some(2));
            assert_eq!(
                ack_resp,
                IpcResponse::ChangesAcknowledged {
                    last_ack_change_id: new_last_id
                }
            );

            // Next pull: queue is empty (all caught up)
            let empty_resp =
                handler.handle_request(client.get_pending_changes_request(None).unwrap(), Some(2));
            match empty_resp {
                IpcResponse::Changes { changes, .. } => {
                    assert!(changes.is_empty(), "Queue must be empty after full catchup")
                }
                other => panic!("Expected Changes, got {:?}", other),
            }
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pds_ipc_pubsub_realtime_and_ack() {
        let temp_dir = std::env::temp_dir().join(format!("pds_pubsub_test_{}", EntityId::new()));
        let mut storage = DiskStorage::open(&temp_dir).unwrap();
        let mut sessions = IpcSessionManager::new();
        let mut authenticator = ClientAuthenticator::new("pds-pubsub-node");

        let signing_key = SigningKey::from_bytes(&[77u8; 32]);
        let client_id =
            authenticator.register_client("RealtimeApp", signing_key.verifying_key().to_bytes());
        authenticator.approve_client(&client_id, {
            let mut perms = BTreeSet::new();
            perms.insert(Permission::ReadEntities);
            perms.insert(Permission::WriteEntities);
            perms.insert(Permission::ReadHistory);
            perms.insert(Permission::WriteBlobs);
            perms
        });

        let mut client = PdsIpcClient::new(client_id, signing_key);
        let mut handler = IpcServerHandler::new(&mut storage, &mut sessions, &mut authenticator);

        // 1. Authenticate
        let challenge = match handler
            .handle_request(client.start_handshake(vec!["realtime".into()]), Some(100))
        {
            IpcResponse::Challenge(c) => c,
            other => panic!("Expected challenge, got {:?}", other),
        };
        let success = match handler.handle_request(client.handle_challenge(&challenge), Some(100)) {
            IpcResponse::Authenticated(s) => s,
            other => panic!("Expected Authenticated, got {:?}", other),
        };
        client.handle_auth_success(&success);
        let session_id = client.session_id().unwrap();

        // 2. Subscribe to EntityChanges and BlobCreated
        let sub_req = client
            .subscribe_request(vec![EventTopic::EntityChanges, EventTopic::BlobCreated])
            .unwrap();
        match handler.handle_request(sub_req, Some(100)) {
            IpcResponse::Subscribed { topics } => {
                assert!(topics.contains(&EventTopic::EntityChanges));
                assert!(topics.contains(&EventTopic::BlobCreated));
            }
            other => panic!("Expected Subscribed, got {:?}", other),
        }

        // 3. Create Entity -> should produce real-time notification
        let create_ent_req = client
            .create_entity_request(
                Some("channel".into()),
                vec![("title".into(), PropertyValue::Text("General".into()))],
            )
            .unwrap();
        handler.handle_request(create_ent_req, Some(100));

        let notifications = handler.sessions.drain_notifications(session_id);
        assert_eq!(
            notifications.len(),
            1,
            "Must receive exactly 1 real-time notification for entity creation"
        );
        let change_id = match &notifications[0] {
            IpcNotification::ChangeAppended { change_id, change } => {
                assert_eq!(change.metadata.device_id, "ipc-client");
                *change_id
            }
            other => panic!("Expected ChangeAppended, got {:?}", other),
        };

        // 4. Client ACKs the change received from realtime stream -> advances cursor!
        let ack_req = client.ack_changes_request(change_id).unwrap();
        assert_eq!(
            handler.handle_request(ack_req, Some(100)),
            IpcResponse::ChangesAcknowledged {
                last_ack_change_id: change_id
            }
        );
        assert_eq!(
            handler.storage.get_client_cursor(&client_id),
            Some(change_id)
        );

        // 5. Incoming peer change replicated via append_change_and_notify
        let peer_change = Change::new(
            ChangeId::new(),
            vec![change_id],
            crate::change::ChangeMetadata::new("peer-node-sync"),
            vec![Operation::CreateEntity {
                entity_id: EntityId::new(),
                entity_type: Some("message".into()),
            }],
        );
        let peer_change_id = peer_change.id;
        handler.append_change_and_notify(peer_change).unwrap();

        // 6. Client receives peer change push notification in realtime
        let peer_notifs = handler.sessions.drain_notifications(session_id);
        assert_eq!(
            peer_notifs.len(),
            1,
            "Client must receive pushed peer change notification in real time"
        );
        match &peer_notifs[0] {
            IpcNotification::ChangeAppended { change_id, change } => {
                assert_eq!(*change_id, peer_change_id);
                assert_eq!(change.metadata.device_id, "peer-node-sync");
            }
            other => panic!("Expected ChangeAppended, got {:?}", other),
        }

        // 7. Client ACKs peer change -> cursor advanced again
        let ack_peer_req = client.ack_changes_request(peer_change_id).unwrap();
        handler.handle_request(ack_peer_req, Some(100));
        assert_eq!(
            handler.storage.get_client_cursor(&client_id),
            Some(peer_change_id)
        );

        // 8. Pending queue is now empty because all real-time events were ACKed
        let pending_resp =
            handler.handle_request(client.get_pending_changes_request(None).unwrap(), Some(100));
        match pending_resp {
            IpcResponse::Changes { changes, .. } => {
                assert!(changes.is_empty(), "All changes were ACKed in real time")
            }
            other => panic!("Expected Changes, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pds_ipc_entity_and_relation_mutations() {
        let temp_dir = std::env::temp_dir().join(format!("pds_mut_test_{}", EntityId::new()));
        let mut storage = DiskStorage::open(&temp_dir).unwrap();
        let mut sessions = IpcSessionManager::new();
        let mut authenticator = ClientAuthenticator::new("pds-mut-node");

        let signing_key = SigningKey::from_bytes(&[88u8; 32]);
        let client_id =
            authenticator.register_client("EditorApp", signing_key.verifying_key().to_bytes());
        authenticator.approve_client(&client_id, {
            let mut perms = BTreeSet::new();
            perms.insert(Permission::ReadEntities);
            perms.insert(Permission::WriteEntities);
            perms.insert(Permission::ReadHistory);
            perms
        });

        let mut client = PdsIpcClient::new(client_id, signing_key);
        let mut handler = IpcServerHandler::new(&mut storage, &mut sessions, &mut authenticator);

        let challenge = match handler
            .handle_request(client.start_handshake(vec!["entities".into()]), Some(1))
        {
            IpcResponse::Challenge(c) => c,
            other => panic!("Expected challenge, got {:?}", other),
        };
        let success = match handler.handle_request(client.handle_challenge(&challenge), Some(1)) {
            IpcResponse::Authenticated(s) => s,
            other => panic!("Expected Authenticated, got {:?}", other),
        };
        client.handle_auth_success(&success);

        // 1. Create two entities
        let e1_req = client
            .create_entity_request(
                Some("doc".into()),
                vec![("title".into(), PropertyValue::Text("Stary tytul".into()))],
            )
            .unwrap();
        let e1_id = match handler.handle_request(e1_req, Some(1)) {
            IpcResponse::EntityCreated(id) => id,
            other => panic!("Expected EntityCreated, got {:?}", other),
        };

        let e2_req = client
            .create_entity_request(
                Some("user".into()),
                vec![("name".into(), PropertyValue::Text("Jan".into()))],
            )
            .unwrap();
        let e2_id = match handler.handle_request(e2_req, Some(1)) {
            IpcResponse::EntityCreated(id) => id,
            other => panic!("Expected EntityCreated, got {:?}", other),
        };

        // 2. Update entity e1
        let update_e1 = client
            .update_entity_request(
                e1_id,
                vec![("title".into(), PropertyValue::Text("Nowy tytul".into()))],
                vec![],
            )
            .unwrap();
        assert_eq!(
            handler.handle_request(update_e1, Some(1)),
            IpcResponse::EntityUpdated(e1_id)
        );

        let ent = handler.storage.state().entities.get(&e1_id).unwrap();
        assert_eq!(
            ent.get_property(&"title".into()),
            Some(&PropertyValue::Text("Nowy tytul".into()))
        );

        // 3. Create relation e1 -> e2
        let rel_req = client
            .create_relation_request("author_of".into(), e2_id, e1_id)
            .unwrap();
        let rel_id = match handler.handle_request(rel_req, Some(1)) {
            IpcResponse::RelationCreated(id) => id,
            other => panic!("Expected RelationCreated, got {:?}", other),
        };
        assert!(handler.storage.state().relations.contains_key(&rel_id));

        // 4. Update relation
        let update_rel = client
            .update_relation_request(
                rel_id,
                vec![("weight".into(), PropertyValue::Int(10))],
                vec![],
            )
            .unwrap();
        assert_eq!(
            handler.handle_request(update_rel, Some(1)),
            IpcResponse::RelationUpdated(rel_id)
        );
        let rel = handler.storage.state().relations.get(&rel_id).unwrap();
        assert_eq!(
            rel.get_property(&"weight".into()),
            Some(&PropertyValue::Int(10))
        );

        // 5. Delete relation
        let del_rel = client.delete_relation_request(rel_id).unwrap();
        assert_eq!(
            handler.handle_request(del_rel, Some(1)),
            IpcResponse::RelationDeleted(rel_id)
        );
        assert!(!handler.storage.state().relations.contains_key(&rel_id));

        // 6. Delete entity e2
        let del_e2 = client.delete_entity_request(e2_id).unwrap();
        assert_eq!(
            handler.handle_request(del_e2, Some(1)),
            IpcResponse::EntityDeleted(e2_id)
        );
        assert!(!handler.storage.state().entities.contains_key(&e2_id));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
