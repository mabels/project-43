# project-43 — External API Surface Notes

Verified API details for the specific crate versions in use. Check this file before writing code that touches these crates.

---

## openpgp-card-sequoia 0.2

### Card access
```rust
use crate::pkcs11::card::open_first_card;  // returns Result<Card<Open>>
let mut card = open_first_card()?;
let mut tx = card.transaction()?;           // Card<Transaction>
```

### Reading the auth public key (no PIN needed)
```rust
use openpgp_card_sequoia::types::KeyType;
let pub_key = tx.public_key(KeyType::Authentication)
    // returns Result<Option<Box<dyn PublicKeyMaterial>>>
    .context("read failed")?
    .context("no auth key on card")?;
let mpis: &openpgp::crypto::mpi::PublicKey = pub_key.mpis();
```
`KeyType::Authentication` reads the auth slot. `KeyType::Signing` / `KeyType::Decryption` also exist.

### Signing via auth slot (INTERNAL AUTHENTICATE)
```rust
tx.verify_user_pin(pin)?;                    // User PIN, not signing PIN
let mut user_card = tx.to_user_card(None)?;  // None = no touch confirmation callback override
let mut auth = user_card.authenticator(&|| eprintln!("Touch YubiKey now…"))?;
// For RSA: pre-hash data on host, pass digest + algorithm
let sig: openpgp::crypto::mpi::Signature = auth.sign(HashAlgorithm::SHA256, &digest)?;
// For Ed25519: pass raw data; card does PureEdDSA internally
let sig = auth.sign(HashAlgorithm::SHA512, raw_data)?;
```
The `openpgp::crypto::Signer` trait must be in scope: `use openpgp::crypto::Signer as _;`

### MPI variants
```rust
mpi::PublicKey::EdDSA { curve: Curve::Ed25519, q }  // q is 33 bytes: 0x40 prefix + 32 raw bytes
mpi::PublicKey::RSA { e, n }                          // e = exponent, n = modulus
mpi::Signature::EdDSA { r, s }                        // r, s are scalars; use value_padded(32)
mpi::Signature::RSA { s }                             // s.value() is the raw PKCS#1 blob
```

---

## ssh-key 0.6

### Mpint construction from raw positive integer bytes
```rust
// Use from_positive_bytes — handles leading zero stripping and MSB padding automatically.
// Do NOT use from_bytes (that expects SSH wire format already).
Mpint::from_positive_bytes(mpi_value.value())
```

### Building an RSA public key
```rust
use ssh_key::public::RsaPublicKey;
RsaPublicKey { e: Mpint::from_positive_bytes(e.value())?, n: Mpint::from_positive_bytes(n.value())? }
// Wrap: KeyData::Rsa(rsa_pub)
```

### Building signatures
```rust
// Ed25519: concatenate r (32 bytes) + s (32 bytes)
Signature::new(Algorithm::Ed25519, raw_64_bytes.to_vec())?
// RSA:
Signature::new(Algorithm::Rsa { hash: Some(HashAlg::Sha256) }, s_bytes)?
```

### SSH RSA flag constants (from OpenSSH agent protocol)
```rust
const RSA_SHA2_256_FLAG: u32 = 0x02;
const RSA_SHA2_512_FLAG: u32 = 0x04;
// flags come from SignRequest.flags in ssh-agent-lib
```

---

## ssh-agent-lib 0.5

### Implementing a session
```rust
#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for MySession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> { ... }
    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> { ... }
}
// SignRequest fields: request.data (the bytes to sign), request.flags (u32)
// AgentError conversion from anyhow::Error:
.map_err(|e| AgentError::other(std::io::Error::other(e.to_string())))
```

### Listening on a Unix socket
```rust
use tokio::net::UnixListener;
use ssh_agent_lib::agent::listen;
let listener = UnixListener::bind(&socket_path)?;
listen(listener, session).await?;  // blocks until socket closes
```

---

## matrix-sdk 0.16.0

### Important: `MatrixSession` import path
```rust
// NOT matrix_sdk::matrix_auth::MatrixSession — that module doesn't exist at the root
use matrix_sdk::authentication::matrix::MatrixSession;
```

### `MatrixSession` structure
```rust
// Fields (both pub, both #[serde(flatten)]):
MatrixSession {
    meta: SessionMeta {        // from matrix_sdk_base, re-exported as matrix_sdk::SessionMeta
        user_id: OwnedUserId,
        device_id: OwnedDeviceId,
    },
    tokens: SessionTokens {   // matrix_sdk::SessionTokens
        access_token: String,
        refresh_token: Option<String>,
    },
}
// Implements Serialize + Deserialize (serde flatten — session JSON has flat keys)
// From<&login::v3::Response> is implemented — use this instead of constructing manually:
let session = MatrixSession::from(&response);
```

### Login
```rust
let client = Client::builder().homeserver_url(url).build().await?;
let response = client
    .matrix_auth()
    .login_username(username, password)
    .initial_device_display_name("p43")
    .await?;
let session = MatrixSession::from(&response);
```

### Restore session
```rust
use matrix_sdk::store::RoomLoadSettings;
// restore_session takes TWO arguments in 0.16.0:
client.matrix_auth()
    .restore_session(session, RoomLoadSettings::default())
    .await?;
```

### Sync
```rust
use matrix_sdk::config::SyncSettings;
// One-shot sync (populates room state):
client.sync_once(SyncSettings::default()).await?;
// Infinite loop (for listen):
client.sync(SyncSettings::default()).await?;  // returns only on error
```

### Sending a message
```rust
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
let room = client.get_room(&room_id)  // returns Option<Room>
    .context("room not found")?;
room.send(RoomMessageEventContent::text_plain("hello")).await?;
// room.send() returns SendMessageLikeEvent which implements IntoFuture — .await works directly
```

### Receiving messages (event handler)
```rust
use matrix_sdk::ruma::events::room::message::{
    MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent,
};
use matrix_sdk::room::Room;
// add_room_event_handler filters by room_id automatically:
client.add_room_event_handler(&room_id, |event: OriginalSyncRoomMessageEvent, _room: Room| async move {
    let MessageType::Text(text) = &event.content.msgtype else { return; };
    println!("[{}] {}", event.sender, text.body);
});
```

### RoomId parsing
```rust
use matrix_sdk::ruma::{RoomId, OwnedRoomId};
let owned: OwnedRoomId = RoomId::parse("!abc:matrix.org")?;
```

---

## tokio (concurrency patterns used)

### CardQueue pattern
```rust
// Semaphore held for entire duration of blocking call:
let _permit = semaphore.acquire().await?;
tokio::task::spawn_blocking(move || { /* blocking card op */ }).await??
```

### Building a runtime from sync context (CLI)
```rust
tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()?
    .block_on(async move { ... })
```
