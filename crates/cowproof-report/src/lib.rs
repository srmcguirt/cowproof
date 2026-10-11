//! The aggregate reports over many lanes. `cowproof report rollup` is the `cowproof`
//! subcommand that calls into this crate; `main.rs` stays the per-lane handoff report.
#![forbid(unsafe_code)]

pub mod rollup;
