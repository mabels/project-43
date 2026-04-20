// matrix-sdk 0.16 + rustc ≥ 1.92 overflows the default limit of 128 during
// Send-bound evaluation for deeply-nested async state machines.
// Mirrors the same fix applied to the vendored matrix-sdk crate.
#![recursion_limit = "256"]

pub mod api;
mod frb_generated;
