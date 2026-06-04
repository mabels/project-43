// matrix-sdk 0.16 async state machines overflow the default recursion limit
// on rustc ≥ 1.92.  Mirrors the fix applied to the vendored matrix-sdk crate.
#![recursion_limit = "256"]

pub mod credential_cache;
pub mod key_store;
pub mod pgp_ops;
pub mod protocol;
pub mod util;

#[cfg(feature = "bus")]
pub mod bus;

#[cfg(feature = "matrix")]
pub mod matrix;

#[cfg(feature = "pcsc")]
pub mod pkcs11;

#[cfg(feature = "ssh")]
pub mod ssh_agent;

#[cfg(feature = "gate_key")]
pub mod gate_key;

#[cfg(feature = "sync_store")]
pub mod sync_store;

#[cfg(feature = "wallet")]
pub mod wallet;

#[cfg(feature = "kdbx")]
pub mod kdbx;

pub mod telemetry;
