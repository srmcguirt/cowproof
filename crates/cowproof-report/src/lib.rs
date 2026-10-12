//! The aggregate reports over many lanes. `cowproof report rollup` and `cowproof report
//! port-candidates` are the `cowproof` subcommands that call into this crate; `main.rs` stays the per-lane handoff report.
#![forbid(unsafe_code)]

pub mod port_candidates;
pub mod rollup;
