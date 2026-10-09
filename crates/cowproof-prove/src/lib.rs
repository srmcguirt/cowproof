//! Capsule writer/reader and verifier for cowproof.
//!
//! This crate provides:
//! - `Capsule`: structured representation of a lane's proof capsule
//! - `Capsule::write()` and `Capsule::read()`: persistence with hash verification
//! - `verify()`: rebuild and replay a capsule's checks to reproduce the lane's results
//! - `CheckRunner` trait and `ProcessRunner` implementation: execute checks in isolation
//! - `run_gates()`: mechanical proof gates that load configuration from the base revision
//! - `flaws`: shared flaw rule types and matching logic for gates and report

pub mod capsule;
pub mod flaws;
pub mod gates;
pub mod runner;
pub mod verify;

pub use capsule::{Capsule, CapsuleError};
pub use flaws::{FlawFinding, FlawRule, PatchDelta, RuleFile};
pub use gates::{GatePacket, GateReport, GateResult, run_gates};
pub use runner::{CheckOutcome, CheckRunner, ProcessRunner, SandboxedRunner, SlotGuard};
pub use verify::{VerifyError, VerifyReport, VerifyResult, verify};

#[cfg(test)]
mod tests;
