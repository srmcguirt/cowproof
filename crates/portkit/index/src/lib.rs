//! Persistent symbol index, and the tools that serve it.
//!
//! Cold load is ~0.5 ms at a few thousand symbols and a warm lookup is ~60 ns,
//! against 190–280 ms for a `grep` that also returns far more. The index wins
//! on latency and on precision — an exact span rather than a blind ±50 lines —
//! rather than on raw bytes.

pub mod extract;
pub mod index;
pub mod tools;

pub use extract::{language_of, Kind, Symbol};
pub use index::Index;
pub use tools::register;
