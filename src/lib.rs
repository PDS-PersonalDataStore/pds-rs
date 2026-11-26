//! Personal Data Store (PDS) core library.
//!
//! This library provides a local-first data storage and synchronization engine.

/// Archive export and import management.
pub mod archive;
/// Client authentication and authorization.
pub mod auth;
/// Binary large object (BLOB) storage and chunking.
pub mod blob;
/// Change records and encryption metadata.
pub mod change;
/// High-level client interface for PDS.
pub mod client;
/// Binary encoding and decoding primitives.
pub mod codec;
/// Cryptographic keys and encryption utilities.
pub mod crypto;
/// Background service management.
pub mod daemon;
/// Directed acyclic graph (DAG) for history tracking.
pub mod dag;
/// Entity data models and properties.
pub mod entity;
/// Strongly-typed identifiers.
pub mod id;
/// Inter-process communication protocol and server.
pub mod ipc;
/// Structured audit logging system.
pub mod logging;
/// Network transport and synchronization services.
pub mod net;
/// Node protocol implementation.
pub mod np;
/// Atomic dataset operations.
pub mod operation;
/// Data provenance and activity tracking.
pub mod provenance;
/// Entity relationship graphs.
pub mod relation;
/// Schema definitions and validation.
pub mod schema;
/// Access control and permissions.
pub mod security;
/// Materialized dataset state.
pub mod state;
/// Persistent storage backends.
pub mod storage;
/// State synchronization algorithms.
pub mod sync;
/// Device trust and pairing management.
pub mod trust;
/// Property values and dynamic types.
pub mod value;

pub use archive::{PdsArchive, PdsArchiveMetadata};
pub use auth::{
    API_VERSION, AUTH_CONTEXT_TAG, AuthChallenge, AuthError, AuthSuccess, ClientAuth,
    ClientAuthenticator, ClientHello, ClientId, ClientRecord, ClientStatus,
    DEFAULT_SUPPORTED_API_VERSIONS, create_client_auth_signature,
};
pub use blob::{
    BlobChunk, BlobDescriptor, BlobEncryption, BlobError, BlobStore, CHUNKING_THRESHOLD_BYTES,
    FASTCDC_AVG_SIZE, FASTCDC_MAX_SIZE, FASTCDC_MIN_SIZE,
};
pub use change::{Change, ChangeMetadata, EncryptionMode};
pub use client::{ClientError, PdsClient};
pub use codec::{BinaryCodec, CodecError, PDS_MAGIC_HEADER};
pub use crypto::{CryptoError, EncryptedData, KeyStore};
pub use daemon::{DaemonError, PdsNodeDaemon};
pub use dag::{DagError, HistoryDag};
pub use entity::Entity;
pub use id::{BlobId, ChangeId, EntityId, KeyId, RelationId};
pub use ipc::{
    EventTopic, IpcClientError, IpcNotification, IpcRequest, IpcResponse, IpcServerHandler,
    IpcSessionManager, PdsIpcClient, Session,
};
pub use logging::{LoggingError, LoggingManager};
pub use net::{
    BlobNetRequest, BlobNetResponse, NetAuthMessage, NetSyncError, PDS_ALPN, PDS_BLOB_ALPN,
    PDS_SYNC_ALPN, PdsNetworkNode,
};
pub use np::{
    MessageId, MessageType, NP_DOMAIN_SEPARATOR, NP_MAGIC, NP_VERSION, NodeIdentityId,
    NpClientAuth, NpClientHello, NpError, NpFrame, NpFrameHeader, NpNode, NpServerFinished,
    NpServerHello,
};
pub use operation::Operation;
pub use provenance::{Activity, ActivityId, ActivityStatus, ProvenanceTarget};
pub use relation::{Relation, RelationError, RelationMember};
pub use schema::{EntitySchema, PropertyDefinition, PropertyType, SchemaValidationError};
pub use security::{AccessController, AppRegistration, Permission, SecurityError};
pub use state::DatasetState;
pub use storage::{ClientCursor, DiskStorage, SqliteStorage, StorageError};
pub use sync::{SyncEngine, SyncError, SyncMessage};
pub use trust::{PairingSession, TrustError, TrustEvent, TrustManager, TrustedNode};
pub use value::{PropertyName, PropertyValue};
