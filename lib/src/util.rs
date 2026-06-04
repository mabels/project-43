use anyhow::{Context, Result};

/// Resolve a secret value via three-tier fallback:
///   1. An explicitly-provided value (CLI flag, config field, …)
///   2. An environment variable named `env_var`
///   3. An interactive terminal prompt (via `rpassword`)
///
/// This is the canonical implementation; both the CLI and the bridge crate
/// should call this rather than re-implementing the logic.
/// Convert CBOR bytes to a pretty-printed JSON string for display.
///
/// Byte strings are base64-encoded.  All other CBOR types map to their natural
/// JSON equivalents.  Returns an error if the bytes are not valid CBOR.
pub fn cbor_to_json_pretty(bytes: &[u8]) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let value: ciborium::Value = ciborium::from_reader(bytes).context("CBOR decode for display")?;

    fn convert(v: ciborium::Value) -> serde_json::Value {
        match v {
            ciborium::Value::Bytes(b) => serde_json::Value::String(B64.encode(&b)),
            ciborium::Value::Text(s) => serde_json::Value::String(s),
            ciborium::Value::Bool(b) => serde_json::Value::Bool(b),
            ciborium::Value::Null => serde_json::Value::Null,
            ciborium::Value::Integer(i) => {
                let n: i128 = i.into();
                serde_json::Value::Number(serde_json::Number::from(n as i64))
            }
            ciborium::Value::Float(f) => serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            ciborium::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(convert).collect())
            }
            ciborium::Value::Map(pairs) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in pairs {
                    let key = match k {
                        ciborium::Value::Text(s) => s,
                        ciborium::Value::Integer(i) => {
                            let n: i128 = i.into();
                            n.to_string()
                        }
                        other => format!("{other:?}"),
                    };
                    obj.insert(key, convert(v));
                }
                serde_json::Value::Object(obj)
            }
            ciborium::Value::Tag(_, inner) => convert(*inner),
            _ => serde_json::Value::Null,
        }
    }

    Ok(serde_json::to_string_pretty(&convert(value))?)
}

pub fn resolve_secret(explicit: Option<String>, env_var: &str, prompt: &str) -> Result<String> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var) {
        return Ok(v);
    }
    Ok(rpassword::prompt_password(prompt)?)
}
