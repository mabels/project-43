//! Re-exports [`crate::pgp_ops`] for code inside the `pcsc` feature boundary.
//!
//! The actual implementation now lives in `pgp_ops` (ungated) so that
//! `bus::authority` and `ssh_agent` can call it on all targets, including
//! Android and iOS where the `pcsc` feature is disabled.

pub use crate::pgp_ops::*;
