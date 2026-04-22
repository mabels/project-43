use anyhow::Result;

/// Resolve a secret value via three-tier fallback:
///   1. An explicitly-provided value (CLI flag, config field, …)
///   2. An environment variable named `env_var`
///   3. An interactive terminal prompt (via `rpassword`)
///
/// This is the canonical implementation; both the CLI and the bridge crate
/// should call this rather than re-implementing the logic.
pub fn resolve_secret(explicit: Option<String>, env_var: &str, prompt: &str) -> Result<String> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var) {
        return Ok(v);
    }
    Ok(rpassword::prompt_password(prompt)?)
}
