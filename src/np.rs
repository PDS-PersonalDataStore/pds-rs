use crate::codec::BinaryCodec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use ulid::Ulid;

/// Node protocol frame magic bytes ("PDSN").
pub const NP_MAGIC: &[u8; 4] = b"PDSN";
/// Node protocol version string.
pub const NP_VERSION: &str = "1.0.0";
/// Domain separator string for node protocol signature verification.
pub const NP_DOMAIN_SEPARATOR: &str = "PDS-NP-v1";

/// Unique identity identifier derived from a node public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeIdentityId(pub [u8; 32]);

impl NodeIdentityId {
    /// Derives a node identity identifier from an Ed25519 public key.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        Self(hasher.finalize().into())
    }
}

impl std::fmt::Display for NodeIdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Unique identifier for a node protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(pub Ulid);

impl MessageId {
    /// Generates a new random message identifier.
    pub fn new() -> Self {
        Self(Ulid::generate())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Type category of a node protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Client hello handshake initiation.
    HandshakeClientHello,
    /// Server hello handshake response.
    HandshakeServerHello,
    /// Client authentication handshake message.
    HandshakeClientAuth,
    /// Server finished handshake message.
    HandshakeServerFinished,
    /// DAG synchronization request.
    SyncRequest,
    /// DAG synchronization response.
    SyncResponse,
    /// Binary large object retrieval request.
    BlobRequest,
    /// Binary large object retrieval response.
    BlobResponse,
    /// Error response message.
    Error,
}

/// Header metadata for a node protocol frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpFrameHeader {
    /// Protocol magic bytes.
    pub magic: [u8; 4],
    /// Protocol version string.
    pub protocol_version: String,
    /// Message type classification.
    pub message_type: MessageType,
    /// Active session identifier.
    pub session_id: [u8; 32],
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Unique message identifier.
    pub message_id: MessageId,
    /// Identity of the sender node.
    pub sender_id: NodeIdentityId,
    /// Identity of the recipient node.
    pub recipient_id: NodeIdentityId,
    /// SHA-256 hash of the frame payload.
    pub payload_hash: [u8; 32],
}

/// Signed wire frame for node protocol communication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpFrame {
    /// Frame header metadata.
    pub header: NpFrameHeader,
    /// Encoded frame payload bytes.
    pub payload: Vec<u8>,
    /// Ed25519 signature over canonical header bytes.
    pub signature: Vec<u8>,
}

/// Errors occurring in the node protocol.
#[derive(Debug, thiserror::Error)]
pub enum NpError {
    /// Magic header bytes do not match expected value.
    #[error("Invalid magic: expected PDSN")]
    InvalidMagic,
    /// Cryptographic signature verification failed.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Payload hash does not match the header payload hash.
    #[error("Payload hash mismatch")]
    PayloadHashMismatch,
    /// Serialization or decoding error.
    #[error("Codec error: {0}")]
    Codec(String),
    /// Handshake protocol error.
    #[error("Handshake error: {0}")]
    Handshake(String),
    /// Peer node identity is not trusted.
    #[error("Untrusted peer identity: {0}")]
    UntrustedPeer(NodeIdentityId),
}

impl NpFrame {
    /// Creates and signs a new frame containing the serialized payload.
    pub fn create<T: Serialize>(
        signing_key: &SigningKey,
        sender_id: NodeIdentityId,
        recipient_id: NodeIdentityId,
        session_id: [u8; 32],
        sequence: u64,
        message_type: MessageType,
        payload_data: &T,
    ) -> Result<Self, NpError> {
        let serialized_payload =
            BinaryCodec::encode(payload_data).map_err(|e| NpError::Codec(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized_payload);
        let payload_hash: [u8; 32] = hasher.finalize().into();

        let header = NpFrameHeader {
            magic: *NP_MAGIC,
            protocol_version: NP_VERSION.to_string(),
            message_type,
            session_id,
            sequence,
            message_id: MessageId::new(),
            sender_id,
            recipient_id,
            payload_hash,
        };

        let canonical_bytes = Self::canonical_header_bytes(&header);
        let signature = signing_key.sign(&canonical_bytes).to_bytes().to_vec();

        Ok(Self {
            header,
            payload: serialized_payload,
            signature,
        })
    }

    /// Computes the canonical byte representation of a frame header.
    pub fn canonical_header_bytes(header: &NpFrameHeader) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(NP_DOMAIN_SEPARATOR.as_bytes());
        data.extend_from_slice(&header.magic);
        data.extend_from_slice(header.protocol_version.as_bytes());
        data.push(header.message_type as u8);
        data.extend_from_slice(&header.session_id);
        data.extend_from_slice(&header.sequence.to_be_bytes());
        data.extend_from_slice(header.message_id.0.to_bytes().as_ref());
        data.extend_from_slice(&header.sender_id.0);
        data.extend_from_slice(&header.recipient_id.0);
        data.extend_from_slice(&header.payload_hash);
        data
    }

    /// Verifies the signature and payload integrity of the frame.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), NpError> {
        if self.header.magic != *NP_MAGIC {
            return Err(NpError::InvalidMagic);
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.payload);
        let computed_hash: [u8; 32] = hasher.finalize().into();
        if computed_hash != self.header.payload_hash {
            return Err(NpError::PayloadHashMismatch);
        }

        let canonical_bytes = Self::canonical_header_bytes(&self.header);
        let sig = Signature::from_slice(&self.signature).map_err(|_| NpError::InvalidSignature)?;

        verifying_key
            .verify(&canonical_bytes, &sig)
            .map_err(|_| NpError::InvalidSignature)?;

        Ok(())
    }

    /// Decodes the payload into the specified type.
    pub fn decode_payload<T: DeserializeOwned>(&self) -> Result<T, NpError> {
        BinaryCodec::decode(&self.payload).map_err(|e| NpError::Codec(e.to_string()))
    }
}

// Handshake structures
/// Client greeting message in the node protocol handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpClientHello {
    /// Identity identifier of the client node.
    pub identity_id: NodeIdentityId,
    /// Public key bytes of the client node.
    pub public_key: [u8; 32],
    /// Random client nonce.
    pub nonce: [u8; 32],
    /// List of supported protocol versions.
    pub supported_versions: Vec<String>,
    /// List of advertised client capabilities.
    pub capabilities: Vec<String>,
}

/// Server greeting message in the node protocol handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpServerHello {
    /// Identity identifier of the server node.
    pub identity_id: NodeIdentityId,
    /// Public key bytes of the server node.
    pub public_key: [u8; 32],
    /// Random server nonce.
    pub nonce: [u8; 32],
    /// Hash of the client hello message.
    pub client_hello_hash: [u8; 32],
    /// Protocol version chosen by the server.
    pub chosen_version: String,
    /// List of advertised server capabilities.
    pub capabilities: Vec<String>,
}

/// Client authentication message in the node protocol handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpClientAuth {
    /// Identity identifier of the client node.
    pub identity_id: NodeIdentityId,
    /// Cryptographic hash of the handshake transcript.
    pub transcript_hash: [u8; 32],
}

/// Server completion message in the node protocol handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpServerFinished {
    /// Identity identifier of the server node.
    pub identity_id: NodeIdentityId,
    /// Cryptographic hash of the handshake transcript.
    pub transcript_hash: [u8; 32],
}

/// Node instance participating in the node protocol.
pub struct NpNode {
    /// Signing key of the node.
    pub signing_key: SigningKey,
    /// Identity identifier of the node.
    pub identity_id: NodeIdentityId,
    /// Set of trusted peer identity identifiers.
    pub trusted_peers: BTreeSet<NodeIdentityId>,
}

impl NpNode {
    /// Creates a new node instance with a generated key pair.
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key().to_bytes();
        let identity_id = NodeIdentityId::from_public_key(&public_key);

        Self {
            signing_key,
            identity_id,
            trusted_peers: BTreeSet::new(),
        }
    }

    /// Returns the public key bytes of the node.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Adds a peer identity identifier to the trusted set.
    pub fn trust_peer(&mut self, peer_id: NodeIdentityId) {
        self.trusted_peers.insert(peer_id);
    }

    /// Checks if a peer identity identifier is trusted.
    pub fn is_trusted(&self, peer_id: &NodeIdentityId) -> bool {
        self.trusted_peers.contains(peer_id)
    }

    /// Computes a session identifier from a handshake transcript hash.
    pub fn compute_session_id(transcript_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PDS-NP-SESSION");
        hasher.update(transcript_hash);
        hasher.finalize().into()
    }
}

impl Default for NpNode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_np_frame_signing_and_verification() {
        let node_a = NpNode::new();
        let node_b = NpNode::new();

        let payload_msg = vec!["sync".to_string(), "heads".to_string()];
        let session_id = [1u8; 32];

        let frame = NpFrame::create(
            &node_a.signing_key,
            node_a.identity_id,
            node_b.identity_id,
            session_id,
            1,
            MessageType::SyncRequest,
            &payload_msg,
        )
        .unwrap();

        assert!(frame.verify(&node_a.signing_key.verifying_key()).is_ok());

        let decoded: Vec<String> = frame.decode_payload().unwrap();
        assert_eq!(decoded, payload_msg);

        // Verification fails with wrong key
        assert!(frame.verify(&node_b.signing_key.verifying_key()).is_err());
    }

    #[test]
    fn test_np_handshake_session_derivation() {
        let node_a = NpNode::new();
        let mut node_b = NpNode::new();
        node_b.trust_peer(node_a.identity_id);

        let mut nonce_a = [0u8; 32];
        rand::rng().fill(&mut nonce_a);

        let client_hello = NpClientHello {
            identity_id: node_a.identity_id,
            public_key: node_a.public_key(),
            nonce: nonce_a,
            supported_versions: vec![NP_VERSION.to_string()],
            capabilities: vec!["sync".into(), "blobs".into()],
        };

        assert!(node_b.is_trusted(&client_hello.identity_id));

        let mut hasher = Sha256::new();
        hasher.update(node_a.public_key());
        hasher.update(nonce_a);
        let transcript: [u8; 32] = hasher.finalize().into();

        let session_id_a = NpNode::compute_session_id(&transcript);
        let session_id_b = NpNode::compute_session_id(&transcript);

        assert_eq!(session_id_a, session_id_b);
        assert_ne!(session_id_a, [0u8; 32]);
    }
}
