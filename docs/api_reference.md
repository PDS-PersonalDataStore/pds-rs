# PDS API Reference — Podręcznik Implementacji Hosta / Węzła PDS

Dokumentacja referencyjna API biblioteki `pds` (v1.4.0) dla aplikacji implementujących węzeł lub usługę systemową PDS (np. usługa Android `pds-android`, demon linuksowy czy aplikacja desktopowa).

---

## 1. Architektura Roli Hosta

Aplikacja-host jest administratorem lokalnej bazy danych PDS. Odpowiada za:
1. Zarządzanie bazą danych (`SqliteStorage` lub `DiskStorage`).
2. Uwierzytelnianie i autoryzację aplikacji klienckich (`ClientAuthenticator`).
3. Obsługę protokołu IPC i wysyłanie powiadomień Pub/Sub w czasie rzeczywistym (`IpcServerHandler`, `IpcSessionManager`).
4. Wymianę danych i synchronizację P2P z innymi węzłami (`SyncEngine`).

```text
+------------------------------------------------------------------------+
|                      Aplikacja-Host (np. Android Service)              |
|                                                                        |
|  [Warstwa IPC / AIDL / Sockets]                 [Warstwa Sieciowa P2P] |
|               |                                           |            |
|               v                                           v            |
|     +-------------------+                       +------------------+   |
|     | IpcServerHandler  |                       |    SyncEngine    |   |
|     +---------+---------+                       +---------+--------+   |
|               |                                           |            |
|               +--------------------+ +--------------------+            |
|                                    v v                                 |
|                         +------------------------+                     |
|                         |     SqliteStorage      |                     |
|                         | (pds.db WAL, CAS Blobs)|                     |
|                         +-----------+------------+                     |
|                                     v                                  |
|                         +------------------------+                     |
|                         |      DatasetState      |                     |
|                         +------------------------+                     |
+------------------------------------------------------------------------+
```

---

## 2. Moduły i Komponenty Silnika

### 2.1. Warstwa Przechowywania: `SqliteStorage`

Odpowiedzialna za atomowy, transakcyjny zapis w SQLite w trybie WAL.

```rust
use pds::SqliteStorage;
use std::path::Path;

// Inicjalizacja bazy w podanym katalogu (tworzy pds.db oraz podkatalog blobs/)
let mut storage = SqliteStorage::open("/data/pds")?;

// Dostęp do grafu DAG historii
let dag = storage.dag();
let change_count = storage.change_count();

// Dostęp do zmaterializowanego stanu encji i relacji
let state = storage.state();
let entities = &state.entities;
let relations = &state.relations;

// Zapis nowej jednostki zmiany (atomowo aktualizuje DAG oraz stan)
storage.append_change(change)?;

// Zarządzanie trwałym kursorem klienta (client_cursors)
let cursor = storage.get_client_cursor(&client_id);
storage.set_client_cursor(client_id, Some(change_id))?;

// Dostęp do magazynu binarnego CAS (Content-Addressable Storage)
let blob_desc = storage.blobs_mut().put(blob_id, &bytes, Some("image/png".into()))?;
let blob_data = storage.blobs().get_data(&blob_id)?;

// Migracja ze starszego formatu DiskStorage (history.jsonl)
let migrated_storage = SqliteStorage::migrate_from_disk_storage("/data/pds")?;
```

---

### 2.2. Uwierzytelnianie Klientów: `ClientAuthenticator`

Zarządza tożsamościami aplikacji klienckich, ich kluczami publicznymi Ed25519 oraz prawami dostępu.

```rust
use pds::{ClientAuthenticator, Permission};
use std::collections::BTreeSet;

let mut auth = ClientAuthenticator::new("pds-node-instance-01");

// 1. Rejestracja nowego klienta (zwraca ClientId)
let client_id = auth.register_client("NotesApp", public_key_32_bytes);

// 2. Nadanie uprawnień (np. po zatwierdzeniu przez użytkownika w UI hosta)
let mut perms = BTreeSet::new();
perms.insert(Permission::ReadEntities);
perms.insert(Permission::WriteEntities);
perms.insert(Permission::ReadBlobs);
perms.insert(Permission::WriteBlobs);
perms.insert(Permission::ReadHistory);
auth.approve_client(&client_id, perms);

// 3. Obsługa powitania klienta (ClientHello) -> generowanie wyzwania AuthChallenge
let challenge = auth.handle_client_hello(&client_hello)?;

// 4. Weryfikacja podpisu wyzwania (ClientAuth) -> utworzenie sesji AuthSuccess
let success = auth.handle_client_auth(&client_auth)?;
```

---

### 2.3. Obsługa Zapytań IPC i Zdarzeń Pub/Sub: `IpcServerHandler`

Główny punkt wejścia dla komunikatów przychodzących z lokalnych procesów aplikacji klienckich.

```rust
use pds::{
    Change, EventTopic, IpcNotification, IpcRequest, IpcResponse,
    IpcServerHandler, IpcSessionManager, SqliteStorage,
};

let mut sessions = IpcSessionManager::new();
let mut handler = IpcServerHandler::new(&mut storage, &mut sessions, &mut auth);

// 1. Obsługa dowolnego żądania od klienta (przekazując opcjonalnie peer_pid z systemu OS)
let response: IpcResponse = handler.handle_request(request, Some(calling_pid));

// 2. Replikacja zmian przychodzących z sieci (P2P) z automatycznym rozesłaniem Pub/Sub
handler.append_change_and_notify(remote_change_from_peer)?;

// 3. Pobranie i wypchnięcie (push) oczekujących zdarzeń Pub/Sub do konkretnej sesji klienta
let pending_notifs: Vec<IpcNotification> = handler.sessions.drain_notifications(&session_id);
for notif in pending_notifs {
    match notif {
        IpcNotification::ChangeAppended { change_id, change } => {
            // Wypchnij powiadomienie do klienta przez IPC/AIDL
        }
        IpcNotification::BlobAppended { descriptor } => {
            // Wypchnij powiadomienie o nowym pliku CAS
        }
    }
}
```

#### Obsługiwane żądania `IpcRequest`:
- `Hello(ClientHello)`: Rozpoczęcie handshake i negocjacja wersji protokołu.
- `Authenticate(ClientAuth)`: Przesłanie podpisu kryptograficznego i otwarcie sesji.
- `GetEntity { session_id, entity_id }`: Pobranie encji ze stanu.
- `CreateEntity { session_id, entity_type, properties }`: Utworzenie encji w nowym `Change`.
- `UpdateEntity { session_id, entity_id, set_properties, remove_properties }`: Modyfikacja atrybutów encji.
- `DeleteEntity { session_id, entity_id }`: Usunięcie encji (z kaskadowym usunięciem jej relacji).
- `GetRelation { session_id, relation_id }`: Pobranie relacji.
- `CreateRelation { session_id, relation_type, members, source, target }`: Utworzenie relacji wielostronnej z rolami (lub binarnej `source`/`target`).
- `UpdateRelation { session_id, relation_id, set_properties, remove_properties }`: Modyfikacja atrybutów relacji.
- `DeleteRelation { session_id, relation_id }`: Usunięcie relacji.
- `GetBlob { session_id, blob_id }`: Pobranie zawartości binarnej z CAS.
- `PutBlob { session_id, data, media_type }`: Zapis pliku binarnego z deduplikacją SHA-256 (bloby są niemutowalne).
- `PollChanges { session_id, since_change_id, limit }`: Odpytanie o historię zmian.
- `GetPendingChanges { session_id, limit }`: Pobranie zaległych zmian od ostatniego kursora.
- `AcknowledgeChanges { session_id, change_id }`: Potwierdzenie i przesunięcie trwałego kursora.
- `GetClientCursor { session_id }`: Odczyt aktualnego położenia kursora klienta.
- `Subscribe { session_id, topics }`: Rejestracja w Pub/Sub (`AllChanges`, `EntityChanges`, `RelationChanges`, `BlobCreated`).
- `Unsubscribe { session_id, topics }`: Usunięcie tematów z subskrypcji.
- `CloseSession { session_id }`: Zamknięcie sesji klienta.

---

### 2.4. Synchronizacja P2P: `SyncEngine`

Zapewnia bezserwerową wymianę jednostek historii DAG pomiędzy instancjami PDS.

```rust
use pds::{SyncEngine, SyncMessage};

let engine = SyncEngine::new("node-a");

// Krok 1 (Węzeł A): Wygenerowanie żądania synchronizacji z lokalnymi głowami DAG
let sync_req: SyncMessage = SyncEngine::create_sync_request(storage.dag());

// Krok 2 (Węzeł B): Przetworzenie żądania i przygotowanie brakujących zmian
let sync_resp: SyncMessage = engine.handle_sync_request(&sync_req, storage_b.dag())?;

// Krok 3 (Węzeł A): Scalenie odebranych brakujących zmian do lokalnego DAG
let applied_count = engine.handle_sync_response(&sync_resp, storage.dag_mut())?;
```

---

## 3. Przykładowa Integracja w Hoscie (np. Demon / Service)

```rust
use pds::{
    ClientAuthenticator, IpcRequest, IpcResponse, IpcSessionManager,
    PdsNetworkNode, PdsNodeDaemon, SqliteStorage,
};
use iroh::EndpointAddr;

// Inicjalizacja pełnego demona węzła (SQLite + IPC + Iroh P2P)
let daemon = PdsNodeDaemon::init("/var/lib/pds", "node-alpha").await?;

// Obsługa żądania IPC od lokalnej aplikacji klienckiej
let response = daemon.handle_ipc_request(request, caller_pid).await?;

// Synchronizacja historii DAG z innym węzłem PDS przez Iroh QUIC
let applied_changes = daemon.sync_with_peer(peer_addr).await?;
println!("Zastosowano {} nowych zmian od peera.", applied_changes.len());
```

---

## 7. P2P Network Synchronization (`net` module)

Moduł `net` udostępnia transport sieciowy oparty na bibliotece **Iroh (QUIC)** ([`PdsNetworkNode`](file:///home/tau2c/Projects/PDS/src/net.rs)), służący do wzajemnie uwierzytelnionej synchronizacji historii DAG oraz transferu szyfrowanych obiektów CAS ([`BlobStore`](file:///home/tau2c/Projects/PDS/src/blob.rs)) pomiędzy zaufanymi węzłami PDS w architekturze peer-to-peer.

### Protokoły ALPN
- **Synchronizacja historii DAG**: `b"/pds/sync/1.0"` (`PDS_SYNC_ALPN`) – challenge-response Ed25519, weryfikacja zaufania węzła oraz wydanie 24-godzinnego tokenu sesyjnego (`session_token`).
- **Pobieranie blobów CAS**: `b"/pds/blob/1.0"` (`PDS_BLOB_ALPN`) – autoryzowane pobieranie zaszyfrowanych danych obiektów CAS na podstawie uzgodnionego tokenu sesyjnego.

### Typy i interfejsy

- `PdsNetworkNode::new(dag: Arc<RwLock<HistoryDag>>, trust: Arc<RwLock<TrustManager>>, blobs: Arc<RwLock<BlobStore>>) -> Result<Self, NetSyncError>`: tworzy nowy punkt końcowy Iroh z rejestracją obu ALPN.
- `PdsNetworkNode::endpoint_id(&self) -> EndpointId`: zwraca identyfikator klucza punktu końcowego.
- `PdsNetworkNode::addr(&self) -> EndpointAddr`: pobiera adres punktu końcowego (zawierający relay oraz bezpośrednie IP).
- `PdsNetworkNode::active_tokens(&self) -> Arc<RwLock<BTreeMap<[u8; 32], DateTime<Utc>>>>`: zwraca mapę aktywnych tokenów sesyjnych.
- `PdsNetworkNode::handle_connection(conn: Connection, dag: Arc<RwLock<HistoryDag>>, trust: Arc<RwLock<TrustManager>>, blobs: Arc<RwLock<BlobStore>>, active_tokens: Arc<RwLock<BTreeMap<[u8; 32], DateTime<Utc>>>>) -> Result<Vec<Change>, NetSyncError>`: obsługuje przychodzące połączenia na `/pds/sync/1.0` lub `/pds/blob/1.0`.
- `PdsNetworkNode::sync_with_peer(&self, peer_addr: EndpointAddr, signing_key: &SigningKey) -> Result<([u8; 32], Vec<Change>), NetSyncError>`: realizuje handshake uwierzytelniający, pobiera token sesyjny i przeprowadza dwukierunkową synchronizację DAG.
- `PdsNetworkNode::fetch_blob(&self, peer_addr: EndpointAddr, session_token: [u8; 32], blob_id: BlobId) -> Result<Vec<u8>, NetSyncError>`: pobiera zawartość bloba CAS po ALPN `/pds/blob/1.0`.

---

## 8. Node Daemon Service (`daemon` module)

Moduł `daemon` udostępnia strukturę [`PdsNodeDaemon`](file:///home/tau2c/Projects/PDS/src/daemon.rs), integrującą:
- Trwałą bazę danych [`SqliteStorage`](file:///home/tau2c/Projects/PDS/src/storage.rs),
- Uwierzytelnianie i autoryzację klientów [`ClientAuthenticator`](file:///home/tau2c/Projects/PDS/src/auth.rs),
- Zarządzanie sesjami i powiadomieniami Pub/Sub [`IpcSessionManager`](file:///home/tau2c/Projects/PDS/src/ipc.rs),
- Magazyn zaufania urządzeń [`TrustManager`](file:///home/tau2c/Projects/PDS/src/trust.rs),
- Magazyn obiektów binarnych [`BlobStore`](file:///home/tau2c/Projects/PDS/src/blob.rs),
- P2P transport Iroh [`PdsNetworkNode`](file:///home/tau2c/Projects/PDS/src/net.rs).

### 8.1. Zadania w Tle i Replikacja (Background Sync)
- **`start_background_sync(heartbeat_secs, shutdown_rx)`**: Uruchamia asynchroniczną pętlę nasłuchiwania połączeń QUIC oraz cykliczny heartbeat sprawdzający stan historii u znanych peerów (`peer_routing`).
- **`broadcast_change_to_peers()`**: Po zatwierdzeniu nowej zmiany rozsyła ogłoszenie nagłówków (`HeadAnnounce`) do sparowanych peerów w celu natychmiastowej synchronizacji.
- **Replikacja obiektów CAS (`BlobSyncRule`)**: Automatycznie pobiera obiekty binarne referencjonowane przez zsynchronizowane encje i relacje zgodnie z zapisanymi regułami pobierania (np. według typu encji, typu relacji i limitu rozmiaru).

---

## 9. Device Trust & Revocation (`trust` module)

Moduł `trust` odpowiada za zarządzanie tożsamościami i zaufaniem węzłów w sieci PDS:
- **Parowanie urządzeń (QR + PIN)**: Generowanie 6-cyfrowego kodu PIN i weryfikacja SAS hash `SHA256(peer_public_key || PIN)` w celu zapobiegania atakom typu MITM.
- **Pre-generowane jednorazowe sekrety odwołania (`revocation_secret`)**: Podczas parowania węzeł autoryzujący tworzy losowy 32-bajtowy sekret odwołania i publikuje skrót `revocation_hash = SHA256(revocation_secret)`. Sekret jest przechowywany lokalnie i nie jest przekazywany parowanemu urządzeniu.
- **Odwołanie węzła (`revoke_node`)**: Ujawnienie sekretu trwale i nieodwracalnie unieważnia zaufanie do węzła w całej sieci.

---

## 10. Peer Routing & Blob Sync Rules (`storage` module)

Tabela `peer_routing` oraz `blob_sync_rules` w [`SqliteStorage`](file:///home/tau2c/Projects/PDS/src/storage.rs):
- **`save_peer_routing(node_id, endpoint_addr_json, last_seen)`**: Zapisuje lub aktualizuje adres sieciowy punktu końcowego peera dla mechanizmu routingu.
- **`load_all_peer_routing()`**: Zwraca listę wszystkich zarejestrowanych rekordów routingu peerów.
- **`save_blob_sync_rule(rule)`**: Konfiguruje regułę selektywnej replikacji obiektów CAS (`BlobSyncRule`).
- **`load_blob_sync_rules()`**: Wczytuje aktywne reguły pobierania blobów.
- **`delete_blob_sync_rule(rule_id)`**: Usuwa wybraną regułę replikacji blobów.


