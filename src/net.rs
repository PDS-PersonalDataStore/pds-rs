use crate::blob::{BlobDescriptor, BlobStore};
use crate::change::Change;
use crate::dag::HistoryDag;
use crate::id::BlobId;
use crate::sync::{SyncEngine, SyncError, SyncMessage};
use crate::trust::{TrustError, TrustManager};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iroh::endpoint::{Connection, Endpoint, presets};
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// PDS ALPN protocol identifier for DAG history synchronization
pub const PDS_SYNC_ALPN: &[u8] = b"/pds/sync/1.0";
/// PDS ALPN protocol identifier for CAS blob retrieval
pub const PDS_BLOB_ALPN: &[u8] = b"/pds/blob/1.0";

/// Legacy alias for compatibility
pub const PDS_ALPN: &[u8] = PDS_SYNC_ALPN;

#[derive(Debug, thiserror::Error)]
pub enum NetSyncError {
    #[error("Iroh connection error: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error("Iroh connect error: {0}")]
    Connect(#[from] iroh::endpoint::ConnectError),
    #[error("Iroh bind error: {0}")]
    Bind(#[from] iroh::endpoint::BindError),
    #[error("Iroh read error: {0}")]
    Read(String),
    #[error("Iroh write error: {0}")]
    Write(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Sync engine error: {0}")]
    Sync(#[from] SyncError),
    #[error("Trust error: {0}")]
    Trust(#[from] TrustError),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Authentication handshake message on /pds/sync/1.0
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetAuthMessage {
    AuthHello {
        node_id: String,
        public_key: [u8; 32],
    },
    AuthChallenge {
        challenge: [u8; 32],
    },
    AuthResponse {
        public_key: [u8; 32],
        signature: Vec<u8>,
    },
    AuthSuccess {
        session_token: [u8; 32],
        expires_at: DateTime<Utc>,
    },
    AuthFailed(String),
    HeadAnnounce {
        node_id: String,
        heads: BTreeSet<crate::id::ChangeId>,
    },
    HeadAnnounceReply {
        heads: BTreeSet<crate::id::ChangeId>,
        needs_sync: bool,
    },
}

/// Request/Response message for /pds/blob/1.0
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobNetRequest {
    Get {
        session_token: [u8; 32],
        blob_id: BlobId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobNetResponse {
    Found {
        descriptor: BlobDescriptor,
        data: Vec<u8>,
    },
    NotFound(BlobId),
    Unauthorized,
}

/// A network node transport wrapper using Iroh QUIC with mutual auth & blob transfer
#[derive(Clone)]
pub struct PdsNetworkNode {
    endpoint: Endpoint,
    dag: Arc<RwLock<HistoryDag>>,
    trust: Arc<RwLock<TrustManager>>,
    blobs: Arc<RwLock<BlobStore>>,
    active_tokens: Arc<RwLock<BTreeMap<[u8; 32], DateTime<Utc>>>>,
}

impl PdsNetworkNode {
    pub async fn new(
        dag: Arc<RwLock<HistoryDag>>,
        trust: Arc<RwLock<TrustManager>>,
        blobs: Arc<RwLock<BlobStore>>,
    ) -> Result<Self, NetSyncError> {
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![PDS_SYNC_ALPN.to_vec(), PDS_BLOB_ALPN.to_vec()])
            .bind()
            .await?;

        Ok(Self {
            endpoint,
            dag,
            trust,
            blobs,
            active_tokens: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Returns the active tokens mapping
    pub fn active_tokens(&self) -> Arc<RwLock<BTreeMap<[u8; 32], DateTime<Utc>>>> {
        self.active_tokens.clone()
    }

    /// Returns the blob store
    pub fn blobs(&self) -> Arc<RwLock<BlobStore>> {
        self.blobs.clone()
    }

    /// Handles an incoming connection on either /pds/sync/1.0 or /pds/blob/1.0
    pub async fn handle_connection(
        conn: Connection,
        dag: Arc<RwLock<HistoryDag>>,
        trust: Arc<RwLock<TrustManager>>,
        blobs: Arc<RwLock<BlobStore>>,
        active_tokens: Arc<RwLock<BTreeMap<[u8; 32], DateTime<Utc>>>>,
    ) -> Result<Vec<Change>, NetSyncError> {
        let (mut send, mut recv) = conn.accept_bi().await?;

        // 1. First frame on stream: either NetAuthMessage (for sync) or BlobNetRequest (for blob)
        let first_bytes = recv
            .read_to_end(10 * 1024 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;

        // Try parsing as BlobNetRequest
        if let Ok(blob_req) = serde_json::from_slice::<BlobNetRequest>(&first_bytes) {
            match blob_req {
                BlobNetRequest::Get {
                    session_token,
                    blob_id,
                } => {
                    let is_valid_token = {
                        let tokens = active_tokens.read().await;
                        if let Some(exp) = tokens.get(&session_token) {
                            *exp > Utc::now()
                        } else {
                            false
                        }
                    };

                    if !is_valid_token {
                        let resp = BlobNetResponse::Unauthorized;
                        let bytes = serde_json::to_vec(&resp)?;
                        send.write_all(&bytes)
                            .await
                            .map_err(|e| NetSyncError::Write(e.to_string()))?;
                        let _ = send.finish();
                        return Ok(Vec::new());
                    }

                    let resp = {
                        let b_store = blobs.read().await;
                        match b_store.get_descriptor(&blob_id) {
                            Some(desc) => match b_store.get_data(&blob_id) {
                                Ok(data) => BlobNetResponse::Found {
                                    descriptor: desc.clone(),
                                    data,
                                },
                                Err(_) => BlobNetResponse::NotFound(blob_id),
                            },
                            None => BlobNetResponse::NotFound(blob_id),
                        }
                    };

                    let resp_bytes = serde_json::to_vec(&resp)?;
                    send.write_all(&resp_bytes)
                        .await
                        .map_err(|e| NetSyncError::Write(e.to_string()))?;
                    send.finish()
                        .map_err(|e| NetSyncError::Write(e.to_string()))?;
                    let _ = send.stopped().await;
                    return Ok(Vec::new());
                }
            }
        }

        // Otherwise handle as sync stream: Challenge-Response Authentication
        let auth_msg: NetAuthMessage = serde_json::from_slice(&first_bytes)?;
        let _peer_pub_key = match auth_msg {
            NetAuthMessage::AuthHello { public_key, .. } => {
                // Verify peer is in trust manager
                let is_trusted = {
                    let t = trust.read().await;
                    t.is_trusted(&public_key)
                };
                if !is_trusted {
                    let err_resp =
                        NetAuthMessage::AuthFailed("Peer public key untrusted or revoked".into());
                    let bytes = serde_json::to_vec(&err_resp)?;
                    send.write_all(&bytes)
                        .await
                        .map_err(|e| NetSyncError::Write(e.to_string()))?;
                    let _ = send.finish();
                    return Err(NetSyncError::Unauthorized("Untrusted peer".into()));
                }

                // Send challenge
                let mut challenge = [0u8; 32];
                rand::fill(&mut challenge);
                let chal_msg = NetAuthMessage::AuthChallenge { challenge };
                let bytes = serde_json::to_vec(&chal_msg)?;
                send.write_all(&bytes)
                    .await
                    .map_err(|e| NetSyncError::Write(e.to_string()))?;
                let _ = send.finish();

                // Read AuthResponse on next bidirectional stream or wait for response
                let (mut auth_resp_send, mut auth_resp_recv) = conn.accept_bi().await?;
                let resp_bytes = auth_resp_recv
                    .read_to_end(64 * 1024)
                    .await
                    .map_err(|e| NetSyncError::Read(e.to_string()))?;
                let resp_msg: NetAuthMessage = serde_json::from_slice(&resp_bytes)?;

                match resp_msg {
                    NetAuthMessage::AuthResponse {
                        public_key: resp_pub,
                        signature,
                    } => {
                        if resp_pub != public_key {
                            return Err(NetSyncError::Unauthorized("Public key mismatch".into()));
                        }
                        let verifier = VerifyingKey::from_bytes(&resp_pub)
                            .map_err(|e| NetSyncError::Protocol(e.to_string()))?;
                        let sig = Signature::from_slice(&signature).map_err(|_| {
                            NetSyncError::Unauthorized("Invalid challenge signature".into())
                        })?;
                        verifier.verify(&challenge, &sig).map_err(|_| {
                            NetSyncError::Unauthorized(
                                "Challenge signature verification failed".into(),
                            )
                        })?;

                        // Issue session token valid for 24h
                        let mut token = [0u8; 32];
                        rand::fill(&mut token);
                        let expires_at = Utc::now() + chrono::Duration::hours(24);

                        {
                            let mut tokens = active_tokens.write().await;
                            tokens.insert(token, expires_at);
                        }

                        let success_msg = NetAuthMessage::AuthSuccess {
                            session_token: token,
                            expires_at,
                        };
                        let succ_bytes = serde_json::to_vec(&success_msg)?;
                        auth_resp_send
                            .write_all(&succ_bytes)
                            .await
                            .map_err(|e| NetSyncError::Write(e.to_string()))?;
                        let _ = auth_resp_send.finish();
                        resp_pub
                    }
                    _ => return Err(NetSyncError::Protocol("Expected AuthResponse".into())),
                }
            }
            NetAuthMessage::HeadAnnounce { heads, .. } => {
                let local_heads = {
                    let d = dag.read().await;
                    d.heads().clone()
                };
                let needs_sync = local_heads != heads;
                let reply = NetAuthMessage::HeadAnnounceReply {
                    heads: local_heads,
                    needs_sync,
                };
                let reply_bytes = serde_json::to_vec(&reply)?;
                send.write_all(&reply_bytes)
                    .await
                    .map_err(|e| NetSyncError::Write(e.to_string()))?;
                send.finish()
                    .map_err(|e| NetSyncError::Write(e.to_string()))?;
                let _ = send.stopped().await;
                return Ok(Vec::new());
            }
            _ => {
                return Err(NetSyncError::Protocol(
                    "Expected AuthHello or HeadAnnounce".into(),
                ));
            }
        };

        // 2. Open bidirectional stream for SyncRequest / SyncResponse
        let (mut sync_send, mut sync_recv) = conn.accept_bi().await?;
        let req_bytes = sync_recv
            .read_to_end(10 * 1024 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;
        let request: SyncMessage = serde_json::from_slice(&req_bytes)?;

        let (missing_changes, current_heads) = match request {
            SyncMessage::SyncRequest { known_heads } => {
                let dag_guard = dag.read().await;
                match SyncEngine::handle_request(&dag_guard, &known_heads) {
                    SyncMessage::SyncResponse {
                        missing_changes,
                        current_heads,
                    } => (missing_changes, current_heads),
                    _ => unreachable!(),
                }
            }
            _ => return Err(NetSyncError::Protocol("Expected SyncRequest".into())),
        };

        let response = SyncMessage::SyncResponse {
            missing_changes,
            current_heads,
        };
        let resp_bytes = serde_json::to_vec(&response)?;
        sync_send
            .write_all(&resp_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        sync_send
            .finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        // 3. Client sends its reverse changes
        let mut applied_changes = Vec::new();
        if let Ok((mut client_send, mut client_recv)) = conn.accept_bi().await {
            let client_bytes = client_recv
                .read_to_end(10 * 1024 * 1024)
                .await
                .map_err(|e| NetSyncError::Read(e.to_string()))?;
            if !client_bytes.is_empty() {
                let incoming: SyncMessage = serde_json::from_slice(&client_bytes)?;
                if let SyncMessage::SyncResponse {
                    missing_changes, ..
                } = incoming
                {
                    let to_apply = missing_changes.clone();
                    let mut dag_guard = dag.write().await;
                    SyncEngine::apply_response(&mut dag_guard, to_apply)?;
                    applied_changes = missing_changes;
                }
            }
            let _ = client_send.write_all(b"OK").await;
            let _ = client_send.finish();
        }

        Ok(applied_changes)
    }

    /// Connects to a remote peer via Iroh, completes challenge authentication,
    /// receives a session token, and synchronizes history.
    pub async fn sync_with_peer(
        &self,
        peer_addr: EndpointAddr,
        signing_key: &SigningKey,
    ) -> Result<([u8; 32], Vec<Change>), NetSyncError> {
        let conn = self
            .endpoint
            .connect(peer_addr, PDS_SYNC_ALPN)
            .await
            .map_err(NetSyncError::Connect)?;

        // 1. Send AuthHello on first stream
        let (mut auth_send, mut auth_recv) = conn.open_bi().await?;
        let hello = NetAuthMessage::AuthHello {
            node_id: {
                let t = self.trust.read().await;
                t.local_node_id().to_string()
            },
            public_key: signing_key.verifying_key().to_bytes(),
        };
        let hello_bytes = serde_json::to_vec(&hello)?;
        auth_send
            .write_all(&hello_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        auth_send
            .finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        // Read Challenge
        let chal_bytes = auth_recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;
        let chal_msg: NetAuthMessage = serde_json::from_slice(&chal_bytes)?;
        let challenge = match chal_msg {
            NetAuthMessage::AuthChallenge { challenge } => challenge,
            NetAuthMessage::AuthFailed(err) => return Err(NetSyncError::Unauthorized(err)),
            _ => return Err(NetSyncError::Protocol("Expected AuthChallenge".into())),
        };

        // 2. Respond to Challenge on new bi-stream
        let (mut resp_send, mut resp_recv) = conn.open_bi().await?;
        let sig = signing_key.sign(&challenge).to_bytes().to_vec();
        let auth_resp = NetAuthMessage::AuthResponse {
            public_key: signing_key.verifying_key().to_bytes(),
            signature: sig,
        };
        let resp_bytes = serde_json::to_vec(&auth_resp)?;
        resp_send
            .write_all(&resp_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        resp_send
            .finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        // Read AuthSuccess containing session_token
        let succ_bytes = resp_recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;
        let succ_msg: NetAuthMessage = serde_json::from_slice(&succ_bytes)?;
        let session_token = match succ_msg {
            NetAuthMessage::AuthSuccess { session_token, .. } => session_token,
            NetAuthMessage::AuthFailed(err) => return Err(NetSyncError::Unauthorized(err)),
            _ => return Err(NetSyncError::Protocol("Expected AuthSuccess".into())),
        };

        // 3. Send SyncRequest on next stream
        let (mut send, mut recv) = conn.open_bi().await?;
        let sync_req = {
            let dag_guard = self.dag.read().await;
            SyncEngine::create_request(&dag_guard)
        };
        let req_bytes = serde_json::to_vec(&sync_req)?;
        send.write_all(&req_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        send.finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        // 4. Read peer's SyncResponse
        let resp_bytes = recv
            .read_to_end(10 * 1024 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;
        let response: SyncMessage = serde_json::from_slice(&resp_bytes)?;

        let (peer_changes, peer_heads) = match response {
            SyncMessage::SyncResponse {
                missing_changes,
                current_heads,
            } => (missing_changes, current_heads),
            _ => return Err(NetSyncError::Protocol("Expected SyncResponse".into())),
        };

        // 5. Apply changes from peer to our DAG
        let applied_changes = {
            let to_apply = peer_changes.clone();
            let mut dag_guard = self.dag.write().await;
            SyncEngine::apply_response(&mut dag_guard, to_apply)?;
            peer_changes
        };

        // 6. Send changes that peer is missing in a reverse stream
        let changes_for_peer: Vec<Change> = {
            let dag_guard = self.dag.read().await;
            let resp = SyncEngine::handle_request(&dag_guard, &peer_heads);
            match resp {
                SyncMessage::SyncResponse {
                    missing_changes, ..
                } => missing_changes,
                _ => Vec::new(),
            }
        };

        let (mut rev_send, mut rev_recv) = conn.open_bi().await?;
        let rev_msg = SyncMessage::SyncResponse {
            missing_changes: changes_for_peer,
            current_heads: self.dag.read().await.heads().clone(),
        };
        let rev_bytes = serde_json::to_vec(&rev_msg)?;
        rev_send
            .write_all(&rev_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        rev_send
            .finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        let _ = rev_recv.read_to_end(64).await;

        Ok((session_token, applied_changes))
    }

    /// Fetches a CAS blob from a peer over /pds/blob/1.0 using an agreed session token.
    pub async fn fetch_blob(
        &self,
        peer_addr: EndpointAddr,
        session_token: [u8; 32],
        blob_id: BlobId,
    ) -> Result<Vec<u8>, NetSyncError> {
        let conn = self
            .endpoint
            .connect(peer_addr, PDS_BLOB_ALPN)
            .await
            .map_err(NetSyncError::Connect)?;

        let (mut send, mut recv) = conn.open_bi().await?;
        let req = BlobNetRequest::Get {
            session_token,
            blob_id,
        };
        let req_bytes = serde_json::to_vec(&req)?;
        send.write_all(&req_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        send.finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        let resp_bytes = recv
            .read_to_end(50 * 1024 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;
        let resp: BlobNetResponse = serde_json::from_slice(&resp_bytes)?;

        match resp {
            BlobNetResponse::Found { data, .. } => Ok(data),
            BlobNetResponse::NotFound(id) => {
                Err(NetSyncError::Protocol(format!("Blob not found: {id}")))
            }
            BlobNetResponse::Unauthorized => Err(NetSyncError::Unauthorized(
                "Invalid or expired blob session token".into(),
            )),
        }
    }

    /// Sends a lightweight HeadAnnounce message to a peer over /pds/sync/1.0
    /// and returns the peer's heads and whether the peer needs sync.
    pub async fn announce_heads(
        &self,
        peer_addr: EndpointAddr,
        node_id: String,
    ) -> Result<(BTreeSet<crate::id::ChangeId>, bool), NetSyncError> {
        let conn = self
            .endpoint
            .connect(peer_addr, PDS_SYNC_ALPN)
            .await
            .map_err(NetSyncError::Connect)?;

        let (mut send, mut recv) = conn.open_bi().await?;
        let local_heads = self.dag.read().await.heads().clone();
        let announce = NetAuthMessage::HeadAnnounce {
            node_id,
            heads: local_heads,
        };
        let bytes = serde_json::to_vec(&announce)?;
        send.write_all(&bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        send.finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        let reply_bytes = recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| NetSyncError::Read(e.to_string()))?;
        let reply_msg: NetAuthMessage = serde_json::from_slice(&reply_bytes)?;
        match reply_msg {
            NetAuthMessage::HeadAnnounceReply { heads, needs_sync } => Ok((heads, needs_sync)),
            _ => Err(NetSyncError::Protocol("Expected HeadAnnounceReply".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{Change, ChangeMetadata};
    use crate::id::{ChangeId, EntityId};
    use crate::operation::Operation;
    use crate::value::PropertyValue;

    #[tokio::test]
    async fn test_iroh_network_sync_and_blob_transfer() {
        let dag1 = Arc::new(RwLock::new(HistoryDag::new()));
        let dag2 = Arc::new(RwLock::new(HistoryDag::new()));

        let key1 = SigningKey::from_bytes(&[11u8; 32]);
        let key2 = SigningKey::from_bytes(&[22u8; 32]);

        let mut trust1 = TrustManager::new("node-1", key1.clone());
        let mut trust2 = TrustManager::new("node-2", key2.clone());

        // Mutual trust registration
        let pin = "123456";
        let pin_hash = TrustManager::compute_pin_hash(&key2.verifying_key().to_bytes(), pin);
        let (_, auth_event) = trust1
            .complete_pairing(
                "node-2".into(),
                "Node 2".into(),
                key2.verifying_key().to_bytes(),
                pin,
                pin_hash,
            )
            .unwrap();

        // Node 2 trusts Node 1
        trust2.register_trusted_node(trust1.get_node("node-1").unwrap().clone());
        trust2.apply_authorization(auth_event).unwrap();

        let trust_arc1 = Arc::new(RwLock::new(trust1));
        let trust_arc2 = Arc::new(RwLock::new(trust2));

        let dir1 = std::env::temp_dir().join(format!("pds_net_blob1_{}", EntityId::new()));
        let dir2 = std::env::temp_dir().join(format!("pds_net_blob2_{}", EntityId::new()));
        let blobs1 = Arc::new(RwLock::new(BlobStore::new(&dir1).unwrap()));
        let blobs2 = Arc::new(RwLock::new(BlobStore::new(&dir2).unwrap()));

        // Store a blob on node 1
        let blob_id = BlobId::new();
        let payload = b"Hello P2P Encrypted Blobs via Iroh";
        {
            let mut b1 = blobs1.write().await;
            b1.put(blob_id, payload, Some("text/plain".into())).unwrap();
        }

        // Add 2 changes to node 1
        let c1_id = ChangeId::new();
        let c1 = Change::new(
            c1_id,
            vec![],
            ChangeMetadata::new("node-1"),
            vec![Operation::CreateEntity {
                entity_id: EntityId::new(),
                entity_type: Some("doc".into()),
            }],
        );
        let c2_id = ChangeId::new();
        let c2 = Change::new(
            c2_id,
            vec![c1_id],
            ChangeMetadata::new("node-1"),
            vec![Operation::SetEntityProperty {
                entity_id: EntityId::new(),
                name: "title".into(),
                value: PropertyValue::Text("P2P Iroh Sync".into()),
            }],
        );

        {
            let mut d1 = dag1.write().await;
            d1.insert(c1).unwrap();
            d1.insert(c2).unwrap();
            assert_eq!(d1.len(), 2);
        }

        // Initialize two Iroh nodes
        let node1 = PdsNetworkNode::new(dag1.clone(), trust_arc1.clone(), blobs1.clone())
            .await
            .unwrap();
        let node2 = PdsNetworkNode::new(dag2.clone(), trust_arc2.clone(), blobs2.clone())
            .await
            .unwrap();

        let node1_addr = node1.addr();
        let node1_dag = dag1.clone();
        let node1_trust = trust_arc1.clone();
        let node1_blobs = blobs1.clone();
        let node1_tokens = node1.active_tokens();

        // Spawn node 1 server connection loop for sync connection and blob connection
        let srv_endpoint = node1.endpoint().clone();
        let server_handle = tokio::spawn(async move {
            // First connection: /pds/sync/1.0
            let incoming = srv_endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            PdsNetworkNode::handle_connection(
                conn,
                node1_dag,
                node1_trust,
                node1_blobs.clone(),
                node1_tokens.clone(),
            )
            .await
            .unwrap();

            // Second connection: /pds/blob/1.0
            let incoming2 = srv_endpoint.accept().await.unwrap();
            let conn2 = incoming2.await.unwrap();
            PdsNetworkNode::handle_connection(
                conn2,
                Arc::new(RwLock::new(HistoryDag::new())),
                Arc::new(RwLock::new(TrustManager::new(
                    "mock",
                    SigningKey::from_bytes(&[99u8; 32]),
                ))),
                node1_blobs,
                node1_tokens,
            )
            .await
            .unwrap();
        });

        // Node 2 initiates authenticated sync with Node 1
        let (session_token, applied) = node2
            .sync_with_peer(node1_addr.clone(), &key2)
            .await
            .unwrap();

        assert_eq!(
            applied.len(),
            2,
            "Node 2 must receive and apply 2 changes from Node 1"
        );
        {
            let d2 = dag2.read().await;
            assert_eq!(d2.len(), 2);
            assert!(d2.get(&c1_id).is_some());
            assert!(d2.get(&c2_id).is_some());
        }

        // Node 2 fetches blob using agreed session token
        let fetched_bytes = node2
            .fetch_blob(node1_addr, session_token, blob_id)
            .await
            .unwrap();
        assert_eq!(fetched_bytes, payload);

        server_handle.await.unwrap();

        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
    }
}
