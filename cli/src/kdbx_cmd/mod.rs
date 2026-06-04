pub mod subcmd;

use anyhow::Result;
use p43::kdbx::{self, KdbxKey};
use subcmd::KdbxCmd;

pub fn run(cmd: KdbxCmd) -> Result<()> {
    match cmd {
        KdbxCmd::List {
            file,
            password,
            hmac_secret,
        } => {
            let key = resolve_key(password.as_deref(), hmac_secret.as_deref())?;
            let db = kdbx::open(&file, key)?;
            let entries = kdbx::entries(&db);

            if entries.is_empty() {
                eprintln!("(no entries)");
                return Ok(());
            }

            for e in &entries {
                println!(
                    "{idx:>4}  {title:<40}  {group}",
                    idx = e.index,
                    title = if e.title.is_empty() {
                        "(no title)"
                    } else {
                        &e.title
                    },
                    group = e.group_path.join(" / "),
                );
            }

            eprintln!("\n{} entries", entries.len());
        }

        KdbxCmd::Get {
            file,
            index,
            password,
            hmac_secret,
            show_password,
        } => {
            let key = resolve_key(password.as_deref(), hmac_secret.as_deref())?;
            let db = kdbx::open(&file, key)?;

            let e = kdbx::entry_by_index(&db, index)
                .ok_or_else(|| anyhow::anyhow!("no entry at index {index}"))?;

            println!("Index:    {}", e.index);
            println!("Title:    {}", e.title);
            println!("Username: {}", e.username);
            println!(
                "Password: {}",
                if show_password { &e.password } else { "****" }
            );
            println!("URL:      {}", e.url);
            println!("Group:    {}", e.group_path.join(" / "));
            if !e.notes.is_empty() {
                println!("Notes:\n{}", e.notes);
            }
        }

        KdbxCmd::Search {
            file,
            query,
            password,
            hmac_secret,
        } => {
            let key = resolve_key(password.as_deref(), hmac_secret.as_deref())?;
            let db = kdbx::open(&file, key)?;
            let results = kdbx::search_by_title(&db, &query);

            if results.is_empty() {
                eprintln!("no entries matching {:?}", query);
                return Ok(());
            }

            for e in &results {
                println!(
                    "{idx:>4}  {title:<40}  {group}",
                    idx = e.index,
                    title = if e.title.is_empty() {
                        "(no title)"
                    } else {
                        &e.title
                    },
                    group = e.group_path.join(" / "),
                );
            }
        }
    }
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn resolve_key<'a>(password: Option<&'a str>, hmac_secret: Option<&'a str>) -> Result<KdbxKey<'a>> {
    match (password, hmac_secret) {
        (Some(pw), Some(hmac)) => Ok(KdbxKey::PasswordAndHmac {
            password: pw,
            hmac_secret: hmac,
        }),
        (Some(pw), None) => Ok(KdbxKey::Password(pw)),
        (None, Some(hmac)) => Ok(KdbxKey::HmacSecret(hmac)),
        (None, None) => {
            // Nothing supplied — prompt for password by default.
            // HMAC secret must be explicit (not prompted, since it's hex, not human text).
            let pw = rpassword::prompt_password("Database password: ")?;
            // Leak into 'a via Box::leak so we can return a &str.
            // This is a CLI process — the memory is freed on exit.
            let pw: &'a str = Box::leak(pw.into_boxed_str());
            Ok(KdbxKey::Password(pw))
        }
    }
}
