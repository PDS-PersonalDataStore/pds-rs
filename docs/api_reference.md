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
- `CreateRelation { session_id, relation_type, source, target }`: Połączenie encji relacją.
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
    ClientAuthenticator, IpcRequest, IpcResponse, IpcServerHandler,
    IpcSessionManager, Permission, SqliteStorage,
};
use std::collections::BTreeSet;

pub struct PdsNodeDaemon {
    storage: SqliteStorage,
    sessions: IpcSessionManager,
    authenticator: ClientAuthenticator,
}

impl PdsNodeDaemon {
    pub fn init(storage_path: &str, node_name: &str) -> anyhow::Result<Self> {
        let storage = SqliteStorage::open(storage_path)?;
        let sessions = IpcSessionManager::new();
        let authenticator = ClientAuthenticator::new(node_name);

        Ok(Self {
            storage,
            sessions,
            authenticator,
        })
    }

    pub fn process_ipc_message(
        &mut self,
        raw_json: &[u8],
        caller_pid: Option<u32>,
    ) -> (IpcResponse, Vec<(String, pds::IpcNotification)>) {
        let req: IpcRequest = match serde_json::from_slice(raw_json) {
            Ok(r) => r,
            Err(e) => return (IpcResponse::Error(e.to_string()), Vec::new()),
        };

        let mut handler = IpcServerHandler::new(
            &mut self.storage,
            &mut self.sessions,
            &mut self.authenticator,
        );

        let resp = handler.handle_request(req, caller_pid);

        // Zbierz powiadomienia czasu rzeczywistego dla wszystkich aktywnych sesji
        let mut outgoing_notifications = Vec::new();
        // Host przesyła powiadomienia do odpowiednich subskrybentów
        (resp, outgoing_notifications)
    }
}
```

---

## 7. P2P Network Synchronization (`net` module)

Moduł `net` udostępnia transport sieciowy oparty na bibliotece **Iroh (QUIC)** (`PdsNetworkNode`), służący do bezpośredniej synchronizacji historii DAG pomiędzy węzłami PDS w architekturze peer-to-peer.

### Protokół ALPN
- Identyfikator protokołu: `b"/pds/sync/1.0"` (`PDS_ALPN`)

### Typy i interfejsy

- `PdsNetworkNode::new(dag: Arc<RwLock<HistoryDag>>) -> Result<Self, NetSyncError>`: tworzy nowy punkt końcowy Iroh z domyślnym presetem n0 (`presets::N0`) i rejestruje ALPN.
- `PdsNetworkNode::endpoint_id(&self) -> EndpointId`: zwraca unikalny identyfikator klucza publicznego węzła.
- `PdsNetworkNode::addr(&self) -> EndpointAddr`: pobiera adres punktu końcowego (zawierający relay oraz bezpośrednie IP).
- `PdsNetworkNode::handle_connection(conn: Connection, dag: Arc<RwLock<HistoryDag>>) -> Result<usize, NetSyncError>`: obsługuje przychodzące połączenie PDS, odpowiada zmianami oraz odbiera zmiany zdalne.
- `PdsNetworkNode::sync_with_peer(&self, peer_addr: EndpointAddr) -> Result<usize, NetSyncError>`: łączy się ze wskazanym węzłem i przeprowadza dwukierunkową synchronizację brakujących zmian historii DAG.

