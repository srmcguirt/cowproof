//! The reports over lanes. `cowproof report handback`, `cowproof report rollup` and
//! `cowproof report port-candidates` are the `cowproof` subcommands that call into this
//! crate: `handback` is the per-lane handoff report, the other two aggregate over many
//! lanes.
#![forbid(unsafe_code)]

pub mod handback;
pub mod port_candidates;
pub mod rollup;
pub mod traces;
