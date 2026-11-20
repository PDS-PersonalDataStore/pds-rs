use crate::change::Change;
use crate::dag::HistoryDag;
use crate::sync::{SyncEngine, SyncError, SyncMessage};
use iroh::endpoint::{Connection, Endpoint, presets};
use iroh::{EndpointAddr, EndpointId};
use std::sync::Arc;
use tokio::sync::RwLock;

/// PDS ALPN protocol identifier for Iroh QUIC connections
pub const PDS_ALPN: &[u8] = b"/pds/sync/1.0";

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
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// A network node transport wrapper using Iroh QUIC
pub struct PdsNetworkNode {
    endpoint: Endpoint,
    dag: Arc<RwLock<HistoryDag>>,
}

impl PdsNetworkNode {
    pub async fn new(dag: Arc<RwLock<HistoryDag>>) -> Result<Self, NetSyncError> {
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![PDS_ALPN.to_vec()])
            .bind()
            .await?;

        Ok(Self { endpoint, dag })
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

    /// Handles a single incoming PDS connection
    pub async fn handle_connection(
        conn: Connection,
        dag: Arc<RwLock<HistoryDag>>,
    ) -> Result<Vec<Change>, NetSyncError> {
        let (mut send, mut recv) = conn.accept_bi().await?;

        // 1. Read SyncRequest
        let req_bytes = recv
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

        // 2. Send SyncResponse back to client
        let response = SyncMessage::SyncResponse {
            missing_changes,
            current_heads,
        };
        let resp_bytes = serde_json::to_vec(&response)?;
        send.write_all(&resp_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        send.finish()
            .map_err(|e| NetSyncError::Write(e.to_string()))?;

        // 3. Client might also send its changes (bidirectional exchange)
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
            let _ = client_send.finish();
        }

        Ok(applied_changes)
    }

    /// Connects to a remote peer via Iroh and synchronizes history
    pub async fn sync_with_peer(
        &self,
        peer_addr: EndpointAddr,
    ) -> Result<Vec<Change>, NetSyncError> {
        let conn = self
            .endpoint
            .connect(peer_addr, PDS_ALPN)
            .await
            .map_err(NetSyncError::Connect)?;

        let (mut send, mut recv) = conn.open_bi().await?;

        // 1. Send our SyncRequest
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

        // 2. Read peer's SyncResponse
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

        // 3. Apply changes from peer to our DAG
        let applied_changes = {
            let to_apply = peer_changes.clone();
            let mut dag_guard = self.dag.write().await;
            SyncEngine::apply_response(&mut dag_guard, to_apply)?;
            peer_changes
        };

        // 4. Send changes that peer is missing in a reverse stream
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

        let (mut rev_send, _rev_recv) = conn.open_bi().await?;
        let rev_msg = SyncMessage::SyncResponse {
            missing_changes: changes_for_peer,
            current_heads: self.dag.read().await.heads().clone(),
        };
        let rev_bytes = serde_json::to_vec(&rev_msg)?;
        rev_send
            .write_all(&rev_bytes)
            .await
            .map_err(|e| NetSyncError::Write(e.to_string()))?;
        let _ = rev_send.finish();

        Ok(applied_changes)
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
    async fn test_iroh_network_sync_two_nodes() {
        let dag1 = Arc::new(RwLock::new(HistoryDag::new()));
        let dag2 = Arc::new(RwLock::new(HistoryDag::new()));

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
        let node1 = PdsNetworkNode::new(dag1.clone()).await.unwrap();
        let node2 = PdsNetworkNode::new(dag2.clone()).await.unwrap();

        let node1_addr = node1.addr();
        let node1_dag = dag1.clone();

        // Spawn node 1 server connection loop for 1 connection
        let srv_endpoint = node1.endpoint().clone();
        let server_handle = tokio::spawn(async move {
            let incoming = srv_endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            PdsNetworkNode::handle_connection(conn, node1_dag)
                .await
                .unwrap();
        });

        // Node 2 initiates sync with Node 1
        let applied = node2.sync_with_peer(node1_addr).await.unwrap();

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

        server_handle.await.unwrap();
    }
}
