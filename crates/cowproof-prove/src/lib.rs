//! Capsule writer/reader and verifier for cowproof.
//!
//! This crate provides:
//! - `Capsule`: structured representation of a lane's proof capsule
//! - `Capsule::write()` and `Capsule::read()`: persistence with hash verification
//! - `verify()`: rebuild and replay a capsule's checks to reproduce the lane's results
//! - `CheckRunner` trait and `ProcessRunner` implementation: execute checks in isolation

pub mod capsule;
pub mod runner;
pub mod verify;

pub use capsule::{Capsule, CapsuleError};
pub use runner::{CheckOutcome, CheckRunner, ProcessRunner};
pub use verify::{Diverged, Reproduced, VerifyError, VerifyReport, verify};

#[cfg(test)]
mod tests;
