use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("Node not found: {0}")]
    NotFound(String),
    #[error("Node is revoked: {0}")]
    Revoked(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid revocation secret: hash mismatch")]
    InvalidRevocationSecret,
    #[error("Invalid PIN: PIN verification failed")]
    InvalidPin,
    #[error("Pairing session expired or not found")]
    SessionExpired,
    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

/// Represents a trusted node in the private PDS device network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedNode {
    pub node_id: String,
    pub name: String,
    pub public_key: [u8; 32],
    /// SHA256(revocation_secret)
    pub revocation_hash: [u8; 32],
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Event exchanged between trusted nodes to propagate trust or revocations outside the DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustEvent {
    NodeAuthorized {
        node: TrustedNode,
        /// The revocation secret is only sent to other authorized nodes (never to the newly paired node itself)
        revocation_secret: Option<[u8; 32]>,
        approved_by_node_id: String,
        signature: Vec<u8>,
    },
    NodeRevoked {
        node_id: String,
        /// Pre-generated one-time revocation secret satisfying SHA256(secret) == revocation_hash
        revocation_secret: [u8; 32],
    },
}

/// Pairing session information created by Node A when scanning Node B's PIN.
#[derive(Debug, Clone)]
pub struct PairingSession {
    pub session_id: String,
    pub peer_public_key: [u8; 32],
    pub expected_pin_hash: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

/// Manages trusted peer nodes and their pre-generated revocation secrets.
pub struct TrustManager {
    local_node_id: String,
    signing_key: SigningKey,
    nodes: BTreeMap<String, TrustedNode>,
    /// Revocation secrets held locally for peer nodes (so we can revoke them if needed)
    revocation_secrets: BTreeMap<String, [u8; 32]>,
    active_pairings: BTreeMap<String, PairingSession>,
}

impl TrustManager {
    pub fn new(local_node_id: impl Into<String>, signing_key: SigningKey) -> Self {
        let local_node_id = local_node_id.into();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let mut mgr = Self {
            local_node_id: local_node_id.clone(),
            signing_key,
            nodes: BTreeMap::new(),
            revocation_secrets: BTreeMap::new(),
            active_pairings: BTreeMap::new(),
        };

        // Local node is self-trusted
        let local_node = TrustedNode {
            node_id: local_node_id,
            name: "Self".into(),
            public_key: pub_bytes,
            revocation_hash: [0u8; 32],
            is_revoked: false,
            created_at: Utc::now(),
            revoked_at: None,
        };
        mgr.nodes.insert(local_node.node_id.clone(), local_node);
        mgr
    }

    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn is_trusted(&self, public_key: &[u8; 32]) -> bool {
        self.nodes
            .values()
            .any(|n| &n.public_key == public_key && !n.is_revoked)
    }

    pub fn get_node(&self, node_id: &str) -> Option<&TrustedNode> {
        self.nodes.get(node_id)
    }

    pub fn nodes(&self) -> &BTreeMap<String, TrustedNode> {
        &self.nodes
    }

    pub fn active_pairings(&self) -> &BTreeMap<String, PairingSession> {
        &self.active_pairings
    }

    pub fn register_trusted_node(&mut self, node: TrustedNode) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Helper to compute PIN hash for SAS verification: SHA256(peer_public_key || PIN)
    pub fn compute_pin_hash(peer_public_key: &[u8; 32], pin: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(peer_public_key);
        hasher.update(pin.as_bytes());
        hasher.finalize().into()
    }

    /// Registers a new node pairing initiated after QR scan and verifies the 6-digit PIN.
    pub fn complete_pairing(
        &mut self,
        node_id: String,
        name: String,
        peer_public_key: [u8; 32],
        pin: &str,
        expected_pin_hash: [u8; 32],
    ) -> Result<(TrustedNode, TrustEvent), TrustError> {
        let computed = Self::compute_pin_hash(&peer_public_key, pin);
        if computed != expected_pin_hash {
            return Err(TrustError::InvalidPin);
        }

        // Generate revocation secret for the new node
        let mut revocation_secret = [0u8; 32];
        rand::fill(&mut revocation_secret);

        let mut hasher = Sha256::new();
        hasher.update(revocation_secret);
        let revocation_hash: [u8; 32] = hasher.finalize().into();

        let trusted_node = TrustedNode {
            node_id: node_id.clone(),
            name,
            public_key: peer_public_key,
            revocation_hash,
            is_revoked: false,
            created_at: Utc::now(),
            revoked_at: None,
        };

        // Sign authorization
        let canonical_bytes = Self::canonical_auth_bytes(&trusted_node);
        let sig = self.signing_key.sign(&canonical_bytes).to_bytes().to_vec();

        self.nodes.insert(node_id.clone(), trusted_node.clone());
        self.revocation_secrets.insert(node_id, revocation_secret);

        let event = TrustEvent::NodeAuthorized {
            node: trusted_node.clone(),
            revocation_secret: Some(revocation_secret),
            approved_by_node_id: self.local_node_id.clone(),
            signature: sig,
        };

        Ok((trusted_node, event))
    }

    /// Emits a revocation event for a compromised or lost node.
    pub fn revoke_node(&mut self, node_id: &str) -> Result<TrustEvent, TrustError> {
        let secret = self
            .revocation_secrets
            .get(node_id)
            .copied()
            .ok_or_else(|| TrustError::NotFound(format!("No revocation secret for {node_id}")))?;

        self.apply_revocation(node_id, secret)?;

        Ok(TrustEvent::NodeRevoked {
            node_id: node_id.to_string(),
            revocation_secret: secret,
        })
    }

    /// Applies an incoming revocation event from the network.
    pub fn apply_revocation(
        &mut self,
        node_id: &str,
        revocation_secret: [u8; 32],
    ) -> Result<(), TrustError> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| TrustError::NotFound(node_id.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(revocation_secret);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        if computed_hash != node.revocation_hash {
            return Err(TrustError::InvalidRevocationSecret);
        }

        node.is_revoked = true;
        node.revoked_at = Some(Utc::now());
        self.revocation_secrets.remove(node_id);
        Ok(())
    }

    /// Applies an incoming node authorization event.
    pub fn apply_authorization(&mut self, event: TrustEvent) -> Result<(), TrustError> {
        match event {
            TrustEvent::NodeAuthorized {
                node,
                revocation_secret,
                approved_by_node_id,
                signature,
            } => {
                let approver = self
                    .nodes
                    .get(&approved_by_node_id)
                    .ok_or_else(|| TrustError::NotFound(approved_by_node_id.clone()))?;

                if approver.is_revoked {
                    return Err(TrustError::Revoked(approved_by_node_id));
                }

                let verifying_key = VerifyingKey::from_bytes(&approver.public_key)
                    .map_err(|e| TrustError::Crypto(e.to_string()))?;

                let canonical_bytes = Self::canonical_auth_bytes(&node);
                let sig =
                    Signature::from_slice(&signature).map_err(|_| TrustError::InvalidSignature)?;

                verifying_key
                    .verify(&canonical_bytes, &sig)
                    .map_err(|_| TrustError::InvalidSignature)?;

                if let Some(secret) = revocation_secret {
                    self.revocation_secrets.insert(node.node_id.clone(), secret);
                }

                self.nodes.insert(node.node_id.clone(), node);
                Ok(())
            }
            TrustEvent::NodeRevoked {
                node_id,
                revocation_secret,
            } => self.apply_revocation(&node_id, revocation_secret),
        }
    }

    fn canonical_auth_bytes(node: &TrustedNode) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PDS-TRUST-AUTH-v1");
        bytes.extend_from_slice(node.node_id.as_bytes());
        bytes.extend_from_slice(&node.public_key);
        bytes.extend_from_slice(&node.revocation_hash);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    #[test]
    fn test_trust_manager_pairing_and_revocation_lifecycle() {
        let mut rng = rand::rng();
        let mut key_a_bytes = [0u8; 32];
        let mut key_b_bytes = [0u8; 32];
        rng.fill(&mut key_a_bytes);
        rng.fill(&mut key_b_bytes);

        let signing_a = SigningKey::from_bytes(&key_a_bytes);
        let signing_b = SigningKey::from_bytes(&key_b_bytes);

        let mut mgr_a = TrustManager::new("node-A", signing_a);
        let pub_b = signing_b.verifying_key().to_bytes();

        let pin = "481516";
        let pin_hash = TrustManager::compute_pin_hash(&pub_b, pin);

        // Node A accepts pairing with Node B via PIN
        let (node_b, auth_event) = mgr_a
            .complete_pairing("node-B".into(), "Phone B".into(), pub_b, pin, pin_hash)
            .unwrap();

        assert_eq!(node_b.node_id, "node-B");
        assert!(mgr_a.is_trusted(&pub_b));

        // Node C receives authorization event
        let mut key_c_bytes = [0u8; 32];
        rng.fill(&mut key_c_bytes);
        let signing_c = SigningKey::from_bytes(&key_c_bytes);
        let mut mgr_c = TrustManager::new("node-C", signing_c);

        // First, C trusts A
        let trusted_a = mgr_a.get_node("node-A").unwrap().clone();
        mgr_c.nodes.insert("node-A".into(), trusted_a);

        // C applies authorization of B issued by A
        mgr_c.apply_authorization(auth_event).unwrap();
        assert!(mgr_c.is_trusted(&pub_b));

        // Now Node A revokes Node B (e.g., lost phone)
        let revoke_event = mgr_a.revoke_node("node-B").unwrap();
        assert!(!mgr_a.is_trusted(&pub_b));

        // Node C applies revocation event
        mgr_c.apply_authorization(revoke_event).unwrap();
        assert!(!mgr_c.is_trusted(&pub_b));
    }
}
