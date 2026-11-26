use crate::security::Permission;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use ulid::Ulid;

/// Current default API version.
pub const API_VERSION: &str = "1.4.0";
/// List of default supported API versions.
pub const DEFAULT_SUPPORTED_API_VERSIONS: &[&str] =
    &["1.0.0", "1.0.1", "1.1.0", "1.2.0", "1.3.0", "1.4.0"];
/// Context separation domain string for authentication signatures.
pub const AUTH_CONTEXT_TAG: &str = "PDS-CLIENT-AUTH-v1";

/// Unique identifier for an authenticated client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientId(pub Ulid);

impl ClientId {
    /// Generates a new random client identifier.
    pub fn new() -> Self {
        Self(Ulid::generate())
    }
}

impl Default for ClientId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle status of an authorized client application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientStatus {
    /// Registration is pending administrative approval.
    Pending,
    /// Client is active and permitted to authenticate.
    Active,
    /// Client access is temporarily suspended.
    Suspended,
    /// Client access has been permanently revoked.
    Revoked,
}

/// Persistent record of a registered client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRecord {
    /// Unique identifier of the client.
    pub client_id: ClientId,
    /// Human-readable application name.
    pub name: String,
    /// Ed25519 public key bytes.
    pub public_key: [u8; 32],
    /// Current status of the client.
    pub status: ClientStatus,
    /// Granted permission set.
    pub permissions: BTreeSet<Permission>,
    /// Timestamp when the client registered.
    pub created_at: DateTime<Utc>,
}

/// Initial handshake message sent by a connecting client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// Identifier of the client.
    pub client_id: ClientId,
    /// Preferred API version.
    pub api_version: String,
    /// Random client nonce for handshake freshness.
    pub client_nonce: [u8; 32],
    /// List of advertised client capabilities.
    pub capabilities: Vec<String>,
    /// List of supported API versions for negotiation.
    #[serde(default)]
    pub supported_versions: Vec<String>,
}

impl ClientHello {
    /// Creates a new hello message with specified parameters.
    pub fn new(
        client_id: ClientId,
        api_version: impl Into<String>,
        client_nonce: [u8; 32],
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            api_version: api_version.into(),
            client_nonce,
            capabilities,
            supported_versions: Vec::new(),
        }
    }

    /// Sets supported API versions for version negotiation.
    pub fn with_supported_versions<I, S>(mut self, versions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.supported_versions = versions.into_iter().map(Into::into).collect();
        self
    }
}

/// Challenge sent by the server in response to a client hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Unique identifier of the server instance.
    pub server_instance_id: String,
    /// Identifier of the target client.
    pub client_id: ClientId,
    /// Echoed client nonce.
    pub client_nonce: [u8; 32],
    /// Random server nonce.
    pub server_nonce: [u8; 32],
    /// Negotiated API version.
    pub api_version: String,
    /// Expiration timestamp of the challenge.
    pub challenge_expires_at: DateTime<Utc>,
}

/// Authentication response containing the challenge signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Identifier of the client.
    pub client_id: ClientId,
    /// Ed25519 signature over the canonical challenge payload.
    pub signature: Vec<u8>,
}

/// Confirmation message returned upon successful authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSuccess {
    /// Unique session identifier token.
    pub session_id: String,
    /// Identifier of the authenticated client.
    pub client_id: ClientId,
    /// Granted permission set.
    pub permissions: BTreeSet<Permission>,
    /// Expiration timestamp of the session.
    pub expires_at: DateTime<Utc>,
    /// Negotiated API version.
    pub api_version: String,
}

/// Errors encountered during client authentication.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// Client identifier was not found.
    #[error("Client not found: {0}")]
    ClientNotFound(ClientId),
    /// Client is not in active status.
    #[error("Client is not active (status: {0:?})")]
    ClientNotActive(ClientStatus),
    /// Challenge timestamp has expired.
    #[error("Challenge expired")]
    ChallengeExpired,
    /// Challenge parameters or nonces are invalid.
    #[error("Invalid challenge nonce or parameters")]
    InvalidChallenge,
    /// Cryptographic signature verification failed.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Client and server could not negotiate a common API version.
    #[error("Unsupported API version: expected {expected}, got {actual}")]
    UnsupportedApiVersion {
        /// Expected or supported versions.
        expected: String,
        /// Version requested by the client.
        actual: String,
    },
}

/// Manages client authentication and challenge-response handshakes.
pub struct ClientAuthenticator {
    server_instance_id: String,
    supported_versions: Vec<String>,
    clients: BTreeMap<ClientId, ClientRecord>,
    active_challenges: BTreeMap<ClientId, AuthChallenge>,
}

impl ClientAuthenticator {
    /// Creates a new client authenticator for a server instance.
    pub fn new(server_instance_id: impl Into<String>) -> Self {
        Self {
            server_instance_id: server_instance_id.into(),
            supported_versions: DEFAULT_SUPPORTED_API_VERSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            clients: BTreeMap::new(),
            active_challenges: BTreeMap::new(),
        }
    }

    /// Sets the supported API versions.
    pub fn with_supported_versions<I, S>(mut self, versions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.supported_versions = versions.into_iter().map(Into::into).collect();
        self
    }

    /// Returns the supported API versions.
    pub fn supported_versions(&self) -> &[String] {
        &self.supported_versions
    }

    /// Registers a new client with pending status.
    pub fn register_client(&mut self, name: impl Into<String>, public_key: [u8; 32]) -> ClientId {
        let client_id = ClientId::new();
        self.insert_client(client_id, name, public_key);
        client_id
    }

    /// Inserts a client record directly.
    pub fn insert_client(
        &mut self,
        client_id: ClientId,
        name: impl Into<String>,
        public_key: [u8; 32],
    ) {
        let record = ClientRecord {
            client_id,
            name: name.into(),
            public_key,
            status: ClientStatus::Pending,
            permissions: BTreeSet::new(),
            created_at: Utc::now(),
        };
        self.clients.insert(client_id, record);
    }

    /// Approves a client and grants permissions.
    pub fn approve_client(&mut self, client_id: &ClientId, permissions: BTreeSet<Permission>) {
        if let Some(client) = self.clients.get_mut(client_id) {
            client.status = ClientStatus::Active;
            client.permissions = permissions;
        }
    }

    /// Retrieves a client record by identifier.
    pub fn get_client(&self, client_id: &ClientId) -> Option<&ClientRecord> {
        self.clients.get(client_id)
    }

    /// Negotiates an API version between client and server.
    pub fn negotiate_version(&self, hello: &ClientHello) -> Result<String, AuthError> {
        let requested_versions: Vec<&str> = if !hello.supported_versions.is_empty() {
            hello
                .supported_versions
                .iter()
                .map(|s| s.as_str())
                .collect()
        } else {
            vec![hello.api_version.as_str()]
        };

        for server_ver in self.supported_versions.iter().rev() {
            if requested_versions.contains(&server_ver.as_str()) {
                return Ok(server_ver.clone());
            }
        }

        Err(AuthError::UnsupportedApiVersion {
            expected: self.supported_versions.join(", "),
            actual: hello.api_version.clone(),
        })
    }

    /// Processes a client hello and generates an authentication challenge.
    pub fn handle_client_hello(&mut self, hello: &ClientHello) -> Result<AuthChallenge, AuthError> {
        let negotiated_version = self.negotiate_version(hello)?;

        let client = self
            .clients
            .get(&hello.client_id)
            .ok_or(AuthError::ClientNotFound(hello.client_id))?;

        if client.status != ClientStatus::Active {
            return Err(AuthError::ClientNotActive(client.status.clone()));
        }

        let mut server_nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut server_nonce);

        let challenge = AuthChallenge {
            server_instance_id: self.server_instance_id.clone(),
            client_id: hello.client_id,
            client_nonce: hello.client_nonce,
            server_nonce,
            api_version: negotiated_version,
            challenge_expires_at: Utc::now() + Duration::seconds(60),
        };

        self.active_challenges
            .insert(hello.client_id, challenge.clone());
        Ok(challenge)
    }

    /// Computes the canonical byte payload for challenge signing.
    pub fn compute_signing_payload(
        server_instance_id: &str,
        client_id: &ClientId,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
        api_version: &str,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(AUTH_CONTEXT_TAG.as_bytes());
        data.extend_from_slice(server_instance_id.as_bytes());
        data.extend_from_slice(client_id.0.to_bytes().as_ref());
        data.extend_from_slice(client_nonce);
        data.extend_from_slice(server_nonce);
        data.extend_from_slice(api_version.as_bytes());
        data
    }

    /// Verifies a client authentication response.
    pub fn handle_client_auth(&mut self, auth: &ClientAuth) -> Result<AuthSuccess, AuthError> {
        let challenge = self
            .active_challenges
            .remove(&auth.client_id)
            .ok_or(AuthError::InvalidChallenge)?;

        if Utc::now() > challenge.challenge_expires_at {
            return Err(AuthError::ChallengeExpired);
        }

        let client = self
            .clients
            .get(&auth.client_id)
            .ok_or(AuthError::ClientNotFound(auth.client_id))?;

        if client.status != ClientStatus::Active {
            return Err(AuthError::ClientNotActive(client.status.clone()));
        }

        let payload = Self::compute_signing_payload(
            &challenge.server_instance_id,
            &challenge.client_id,
            &challenge.client_nonce,
            &challenge.server_nonce,
            &challenge.api_version,
        );

        let verifying_key = VerifyingKey::from_bytes(&client.public_key)
            .map_err(|_| AuthError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&auth.signature).map_err(|_| AuthError::InvalidSignature)?;

        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| AuthError::InvalidSignature)?;

        let mut session_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut session_bytes);
        let session_id = hex::encode(session_bytes);

        Ok(AuthSuccess {
            session_id,
            client_id: auth.client_id,
            permissions: client.permissions.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            api_version: challenge.api_version,
        })
    }
}

/// Generates an authentication signature for a challenge.
pub fn create_client_auth_signature(
    signing_key: &SigningKey,
    challenge: &AuthChallenge,
) -> Vec<u8> {
    let payload = ClientAuthenticator::compute_signing_payload(
        &challenge.server_instance_id,
        &challenge.client_id,
        &challenge.client_nonce,
        &challenge.server_nonce,
        &challenge.api_version,
    );
    let signature = signing_key.sign(&payload);
    signature.to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_challenge_response_handshake() {
        let mut server = ClientAuthenticator::new("pds-local-node-1");

        let mut csprng = rand::rng();
        let mut secret = [0u8; 32];
        csprng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key().to_bytes();

        let client_id = server.register_client("ShopApp", public_key);

        let mut perms = BTreeSet::new();
        perms.insert(Permission::ReadEntities);
        perms.insert(Permission::WriteEntities);
        server.approve_client(&client_id, perms.clone());

        let mut client_nonce = [0u8; 32];
        csprng.fill_bytes(&mut client_nonce);
        let hello = ClientHello::new(client_id, API_VERSION, client_nonce, vec!["ipc".into()]);

        let challenge = server.handle_client_hello(&hello).unwrap();
        assert_eq!(challenge.client_id, client_id);

        let sig_bytes = create_client_auth_signature(&signing_key, &challenge);
        let auth = ClientAuth {
            client_id,
            signature: sig_bytes,
        };

        let success = server.handle_client_auth(&auth).unwrap();
        assert_eq!(success.client_id, client_id);
        assert_eq!(success.permissions, perms);
        assert_eq!(success.session_id.len(), 64);
        assert_eq!(success.api_version, API_VERSION);
    }

    #[test]
    fn test_client_api_version_negotiation_legacy_single_version() {
        let mut server = ClientAuthenticator::new("pds-local-node-1");

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let client_id = server.register_client("LegacyClient", public_key);
        server.approve_client(&client_id, BTreeSet::new());

        let hello = ClientHello {
            client_id,
            api_version: "1.0.0".to_string(),
            client_nonce: [2u8; 32],
            capabilities: vec![],
            supported_versions: vec![],
        };

        let challenge = server.handle_client_hello(&hello).unwrap();
        assert_eq!(challenge.api_version, "1.0.0");

        let sig = create_client_auth_signature(&signing_key, &challenge);
        let auth = ClientAuth {
            client_id,
            signature: sig,
        };
        let success = server.handle_client_auth(&auth).unwrap();
        assert_eq!(success.api_version, "1.0.0");
    }

    #[test]
    fn test_client_api_version_negotiation_multi_versions() {
        let mut server = ClientAuthenticator::new("pds-local-node-1");

        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let client_id = server.register_client("ModernClient", public_key);
        server.approve_client(&client_id, BTreeSet::new());

        // Client supports 1.0.0 and 1.1.0, server supports 1.0.0, 1.0.1, 1.1.0 -> should pick highest (1.1.0)
        let hello = ClientHello {
            client_id,
            api_version: "1.0.0".to_string(),
            client_nonce: [4u8; 32],
            capabilities: vec![],
            supported_versions: vec!["1.0.0".to_string(), "1.1.0".to_string()],
        };

        let challenge = server.handle_client_hello(&hello).unwrap();
        assert_eq!(challenge.api_version, "1.1.0");
    }

    #[test]
    fn test_client_api_version_negotiation_unsupported() {
        let mut server = ClientAuthenticator::new("pds-local-node-1");

        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let client_id = server.register_client("FutureClient", public_key);
        server.approve_client(&client_id, BTreeSet::new());

        let hello = ClientHello {
            client_id,
            api_version: "2.0.0".to_string(),
            client_nonce: [6u8; 32],
            capabilities: vec![],
            supported_versions: vec!["2.0.0".to_string()],
        };

        let err = server.handle_client_hello(&hello).unwrap_err();
        assert!(matches!(err, AuthError::UnsupportedApiVersion { .. }));
    }
}
