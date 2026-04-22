// matrix-sdk 0.16 async state machines overflow the default recursion limit
// on rustc ≥ 1.92.  Mirrors the fix applied to the vendored matrix-sdk crate.
#![recursion_limit = "256"]

pub mod key_store;
pub mod protocol;

#[cfg(feature = "bus")]
pub mod bus;

#[cfg(feature = "matrix")]
pub mod matrix;

#[cfg(feature = "pcsc")]
pub mod pkcs11;

#[cfg(feature = "ssh")]
pub mod ssh_agent;

pub mod telemetry;
