//! KeePass / KDBX database access.
//!
//! Read-only for now.  Long-term path:
//!   open → list/get entries → import into p43's own syncable store.

use anyhow::{Context, Result};
use keepass::{
    db::{Entry, Group, Node},
    ChallengeResponseKey, Database, DatabaseKey,
};
use std::path::Path;

// ── public types ─────────────────────────────────────────────────────────────

/// How to authenticate to the KDBX file.
///
/// At least one variant must be supplied; both can be combined.
pub enum KdbxKey<'a> {
    /// Master password only.
    Password(&'a str),
    /// HMAC-SHA1 secret (hex-encoded, 40 chars) — simulates a YubiKey slot.
    HmacSecret(&'a str),
    /// Password + HMAC-SHA1 secret combined (KeePassXC default when both are set).
    PasswordAndHmac {
        password: &'a str,
        hmac_secret: &'a str,
    },
}

/// A flattened, owned view of a single KeePass entry.
///
/// Passwords are returned as plain `String`; callers that need them
/// protected at rest should wrap them in `secrecy::Secret`.
///
/// `index` is the position in the flat walk order produced by [`entries`] —
/// use it as the stable handle for [`entry_by_index`].
#[derive(Debug, Clone)]
pub struct EntryView {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Full group path, e.g. `["Root", "Email"]`
    pub group_path: Vec<String>,
}

// ── public API ────────────────────────────────────────────────────────────────

/// Open a `.kdbx` file.
///
/// Pass the appropriate [`KdbxKey`] variant for your database.  For a
/// YubiKey-protected database (no master password), use
/// `KdbxKey::HmacSecret("deadbeef…")` where the string is the hex-encoded
/// HMAC-SHA1 secret programmed into slot 2.
pub fn open(path: &Path, key: KdbxKey<'_>) -> Result<Database> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;

    let db_key = build_key(key);

    Database::open(&mut file, db_key).with_context(|| format!("cannot unlock {}", path.display()))
}

/// Return every entry in the database as a flat list (walks all groups).
pub fn entries(db: &Database) -> Vec<EntryView> {
    let mut out = Vec::new();
    walk_group(&db.root, &[], &mut out);
    out
}

/// Find a single entry by its flat-walk index (as shown by [`entries`]).
pub fn entry_by_index(db: &Database, index: usize) -> Option<EntryView> {
    entries(db).into_iter().nth(index)
}

/// Find entries whose title contains `query` (case-insensitive).
pub fn search_by_title(db: &Database, query: &str) -> Vec<EntryView> {
    let q = query.to_lowercase();
    entries(db)
        .into_iter()
        .filter(|e| e.title.to_lowercase().contains(&q))
        .collect()
}

// ── internals ─────────────────────────────────────────────────────────────────

fn build_key(key: KdbxKey<'_>) -> DatabaseKey {
    match key {
        KdbxKey::Password(pw) => DatabaseKey::new().with_password(pw),
        KdbxKey::HmacSecret(secret) => DatabaseKey::new()
            .with_challenge_response_key(ChallengeResponseKey::LocalChallenge(secret.to_owned())),
        KdbxKey::PasswordAndHmac {
            password,
            hmac_secret,
        } => DatabaseKey::new()
            .with_password(password)
            .with_challenge_response_key(ChallengeResponseKey::LocalChallenge(
                hmac_secret.to_owned(),
            )),
    }
}

fn walk_group(group: &Group, path: &[String], out: &mut Vec<EntryView>) {
    let mut current_path = path.to_vec();
    current_path.push(group.name.clone());

    for node in &group.children {
        match node {
            Node::Entry(entry) => {
                let index = out.len();
                out.push(entry_view(entry, index, &current_path));
            }
            Node::Group(child) => {
                walk_group(child, &current_path, out);
            }
        }
    }
}

fn entry_view(entry: &Entry, index: usize, group_path: &[String]) -> EntryView {
    EntryView {
        index,
        title: entry.get_title().unwrap_or("").to_owned(),
        username: entry.get_username().unwrap_or("").to_owned(),
        password: entry.get_password().unwrap_or("").to_owned(),
        url: entry.get("URL").unwrap_or("").to_owned(),
        notes: entry.get("Notes").unwrap_or("").to_owned(),
        group_path: group_path.to_vec(),
    }
}
