//! History DAG synchronization protocol and synchronization engine.

use crate::change::Change;
use crate::dag::{DagError, HistoryDag};
use crate::id::ChangeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Protocol messages exchanged during history DAG synchronization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncMessage {
    /// Request containing the set of known DAG head identifiers.
    SyncRequest {
        /// Set of head change identifiers known to the requester.
        known_heads: BTreeSet<ChangeId>,
    },
    /// Response containing missing changes and current head identifiers.
    SyncResponse {
        /// List of changes missing from the requester.
        missing_changes: Vec<Change>,
        /// Current head change identifiers of the responder.
        current_heads: BTreeSet<ChangeId>,
    },
}

/// Errors produced during history DAG synchronization.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Failure when inserting a change into the DAG.
    #[error("DAG insertion error: {0}")]
    Dag(#[from] DagError),
    /// Missing parent dependencies prevent change application.
    #[error("Missing dependencies during sync: {0:?}")]
    UnresolvedDependencies(Vec<ChangeId>),
}

/// Provides synchronization routines for history DAGs.
pub struct SyncEngine;

impl SyncEngine {
    /// Creates a sync request message with the head identifiers of the given DAG.
    pub fn create_request(dag: &HistoryDag) -> SyncMessage {
        SyncMessage::SyncRequest {
            known_heads: dag.heads().clone(),
        }
    }

    /// Computes missing changes and creates a sync response message.
    pub fn handle_request(dag: &HistoryDag, peer_heads: &BTreeSet<ChangeId>) -> SyncMessage {
        let mut missing_changes = Vec::new();

        for change in dag.topological_order() {
            if !peer_heads.contains(&change.id) {
                missing_changes.push(change.clone());
            }
        }

        SyncMessage::SyncResponse {
            missing_changes,
            current_heads: dag.heads().clone(),
        }
    }

    /// Applies received changes to the DAG in dependency order.
    pub fn apply_response(
        dag: &mut HistoryDag,
        missing_changes: Vec<Change>,
    ) -> Result<usize, SyncError> {
        let mut applied_count = 0;
        let mut pending = missing_changes;

        while !pending.is_empty() {
            let initial_len = pending.len();
            let mut still_pending = Vec::new();

            for change in pending {
                match dag.insert(change.clone()) {
                    Ok(()) => {
                        applied_count += 1;
                    }
                    Err(DagError::AlreadyExists(_)) => {
                        // Already in DAG, safe to ignore
                    }
                    Err(DagError::MissingParent(_)) => {
                        still_pending.push(change);
                    }
                }
            }

            if still_pending.len() == initial_len {
                let unresolved_ids = still_pending.iter().map(|c| c.id).collect();
                return Err(SyncError::UnresolvedDependencies(unresolved_ids));
            }

            pending = still_pending;
        }

        Ok(applied_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::ChangeMetadata;
    use crate::id::EntityId;
    use crate::operation::Operation;

    #[test]
    fn test_sync_between_two_dags() {
        let mut dag_a = HistoryDag::new();
        let mut dag_b = HistoryDag::new();

        let root_id = ChangeId::new();
        let root = Change::new(
            root_id,
            vec![],
            ChangeMetadata::new("device-a"),
            vec![Operation::CreateEntity {
                entity_id: EntityId::new(),
                entity_type: Some("root".into()),
            }],
        );
        dag_a.insert(root.clone()).unwrap();
        dag_b.insert(root).unwrap();

        // Device A creates a change
        let a_change_id = ChangeId::new();
        let change_a = Change::new(
            a_change_id,
            vec![root_id],
            ChangeMetadata::new("device-a"),
            vec![Operation::CreateEntity {
                entity_id: EntityId::new(),
                entity_type: Some("note_a".into()),
            }],
        );
        dag_a.insert(change_a).unwrap();

        // Device B creates a concurrent change offline
        let b_change_id = ChangeId::new();
        let change_b = Change::new(
            b_change_id,
            vec![root_id],
            ChangeMetadata::new("device-b"),
            vec![Operation::CreateEntity {
                entity_id: EntityId::new(),
                entity_type: Some("note_b".into()),
            }],
        );
        dag_b.insert(change_b).unwrap();

        // Sync B -> A
        let req_from_a = SyncEngine::create_request(&dag_a);
        let resp_from_b = match req_from_a {
            SyncMessage::SyncRequest { known_heads } => {
                SyncEngine::handle_request(&dag_b, &known_heads)
            }
            _ => panic!("Expected SyncRequest"),
        };

        match resp_from_b {
            SyncMessage::SyncResponse {
                missing_changes, ..
            } => {
                let applied = SyncEngine::apply_response(&mut dag_a, missing_changes).unwrap();
                assert_eq!(applied, 1);
            }
            _ => panic!("Expected SyncResponse"),
        }

        assert_eq!(dag_a.heads().len(), 2);
        assert!(dag_a.heads().contains(&a_change_id));
        assert!(dag_a.heads().contains(&b_change_id));
    }
}
