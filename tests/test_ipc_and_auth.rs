use ed25519_dalek::SigningKey;
use pds::{
    API_VERSION, BlobId, ClientAuth, ClientAuthenticator, ClientHello, DiskStorage, IpcRequest,
    IpcResponse, IpcServerHandler, IpcSessionManager, Permission, PropertyValue,
    create_client_auth_signature,
};
use std::collections::BTreeSet;
use std::fs;

#[test]
fn test_ipc_authentication_and_unauthorized_rejections() {
    let temp_dir = std::env::temp_dir().join(format!("pds_test_ipc_{}", BlobId::new()));
    let mut storage = DiskStorage::open(&temp_dir).unwrap();
    let mut session_manager = IpcSessionManager::new();
    let mut authenticator = ClientAuthenticator::new("server-srv-1");

    // Register legitimate client
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let mut permissions = BTreeSet::new();
    permissions.insert(Permission::ReadEntities);
    permissions.insert(Permission::WriteEntities);

    let client_id =
        authenticator.register_client("trusted_backup_client", verifying_key.to_bytes());
    authenticator.approve_client(&client_id, permissions);

    let mut handler = IpcServerHandler::new(&mut storage, &mut session_manager, &mut authenticator);

    // Step 1: Valid handshake flow
    let hello = ClientHello::new(
        client_id,
        API_VERSION,
        [1u8; 32],
        vec!["entities".to_string()],
    );
    let hello_resp = handler.handle_request(IpcRequest::Hello(hello), Some(9999));
    let challenge = match hello_resp {
        IpcResponse::Challenge(c) => c,
        other => panic!("Expected Challenge response, got {:?}", other),
    };

    let valid_sig = create_client_auth_signature(&signing_key, &challenge);
    let valid_auth = ClientAuth {
        client_id,
        signature: valid_sig,
    };
    let valid_resp = handler.handle_request(IpcRequest::Authenticate(valid_auth), Some(9999));
    let session_id = match valid_resp {
        IpcResponse::Authenticated(success) => {
            assert_eq!(success.api_version, API_VERSION);
            success.session_id
        }
        other => panic!("Expected Authenticated, got {:?}", other),
    };
    assert_eq!(
        handler
            .sessions
            .get_session(&session_id)
            .unwrap()
            .api_version,
        API_VERSION
    );

    // Step 2: Test rejection with forged/wrong key on a fresh challenge
    let hello_forged = ClientHello::new(client_id, API_VERSION, [2u8; 32], vec![]);
    let forged_challenge = match handler.handle_request(IpcRequest::Hello(hello_forged), Some(9999))
    {
        IpcResponse::Challenge(c) => c,
        other => panic!("Expected Challenge response, got {:?}", other),
    };
    let wrong_key = SigningKey::from_bytes(&[8u8; 32]);
    let forged_sig = create_client_auth_signature(&wrong_key, &forged_challenge);
    let forged_auth = ClientAuth {
        client_id,
        signature: forged_sig,
    };
    let forged_resp = handler.handle_request(IpcRequest::Authenticate(forged_auth), Some(9999));
    assert!(matches!(forged_resp, IpcResponse::Error(_)));

    // Step 4: Perform operations with valid session
    let create_req = IpcRequest::CreateEntity {
        session_id: session_id.clone(),
        entity_type: Some("task".to_string()),
        properties: vec![("status".into(), PropertyValue::Text("pending".to_string()))],
    };
    let create_resp = handler.handle_request(create_req, Some(9999));
    let entity_id = match create_resp {
        IpcResponse::EntityCreated(id) => id,
        other => panic!("Expected EntityCreated, got {:?}", other),
    };

    let get_req = IpcRequest::GetEntity {
        session_id: session_id.clone(),
        entity_id,
    };
    let get_resp = handler.handle_request(get_req, Some(9999));
    match get_resp {
        IpcResponse::Entity(Some(entity)) => {
            assert_eq!(entity.entity_type.as_deref(), Some("task"));
        }
        other => panic!("Expected Entity, got {:?}", other),
    }

    // Step 5: Close session
    let close_resp = handler.handle_request(
        IpcRequest::CloseSession {
            session_id: session_id.clone(),
        },
        Some(9999),
    );
    assert_eq!(close_resp, IpcResponse::SessionClosed);

    // Step 6: Rejected after close
    let post_req = IpcRequest::GetEntity {
        session_id,
        entity_id,
    };
    let post_resp = handler.handle_request(post_req, Some(9999));
    assert!(matches!(post_resp, IpcResponse::Error(_)));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multimember_relation_ipc_flow() {
    let temp_dir = std::env::temp_dir().join(format!("pds_test_ipc_rel_{}", pds::BlobId::new()));
    let mut storage = DiskStorage::open(&temp_dir).unwrap();
    let mut session_manager = IpcSessionManager::new();
    let mut authenticator = ClientAuthenticator::new("server-srv-rel");

    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let mut permissions = BTreeSet::new();
    permissions.insert(Permission::ReadEntities);
    permissions.insert(Permission::WriteEntities);

    let client_id =
        authenticator.register_client("rel_client", signing_key.verifying_key().to_bytes());
    authenticator.approve_client(&client_id, permissions);

    let mut handler = IpcServerHandler::new(&mut storage, &mut session_manager, &mut authenticator);
    let mut client = pds::PdsIpcClient::new(client_id, signing_key);

    let hello_req = client.start_handshake(vec!["1.0.0".into()]);
    let challenge = match handler.handle_request(hello_req, Some(101)) {
        IpcResponse::Challenge(c) => c,
        other => panic!("Expected challenge, got {:?}", other),
    };
    let auth_req = client.handle_challenge(&challenge);
    match handler.handle_request(auth_req, Some(101)) {
        IpcResponse::Authenticated(success) => client.handle_auth_success(&success),
        other => panic!("Expected authenticated, got {:?}", other),
    };

    let e1 = pds::EntityId::new();
    let e2 = pds::EntityId::new();
    let e3 = pds::EntityId::new();

    // Multimember relation with 3 members
    let members = vec![
        pds::RelationMember::new(e1, "initiator"),
        pds::RelationMember::new(e2, "participant"),
        pds::RelationMember::new(e3, "observer"),
    ];

    let create_rel_req = client
        .create_multimember_relation_request("meeting".into(), members.clone())
        .unwrap();

    let rel_id = match handler.handle_request(create_rel_req, Some(101)) {
        IpcResponse::RelationCreated(id) => id,
        other => panic!("Expected RelationCreated, got {:?}", other),
    };

    let get_rel_req = client.get_relation_request(rel_id).unwrap();
    match handler.handle_request(get_rel_req, Some(101)) {
        IpcResponse::Relation(Some(rel)) => {
            assert_eq!(rel.id, rel_id);
            assert_eq!(rel.relation_type, "meeting");
            assert_eq!(rel.members.len(), 3);
            assert_eq!(rel.members, members);
        }
        other => panic!("Expected Relation, got {:?}", other),
    }

    // Creating relation with empty members must be rejected
    assert!(
        client
            .create_multimember_relation_request("invalid".into(), vec![])
            .is_err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
