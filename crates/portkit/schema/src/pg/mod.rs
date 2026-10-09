//! Postgres introspection via `pg_catalog`.
//!
//! # Provenance
//!
//! Vendored from `magna-introspect` (github.com/fellwork/magna), commit
//! `8519d710ee50cfee0ff69fe48b85d6c0297a12ce`, 2026-04-26. Same author, same
//! MIT OR Apache-2.0 terms.
//!
//! Copied rather than depended on because magna is a `publish = false`
//! workspace in another repository: a path dependency would make portkit
//! unbuildable for anyone else. Its declared `magna-types` dependency was
//! unused and has been dropped.
//!
//! Re-sync by diffing against that path in magna and updating the commit above.
//!
//! # Deviations
//!
//! - `queries.rs` `QUERY_TYPES` also matches `pg_catalog`. Built-in types are
//!   defined there, not in the schemas a caller asks about, so without it
//!   every column's `data_type` came back `unknown`. Marked `PORTKIT
//!   DEVIATION` in the source.
//!
pub mod cache;
pub mod introspect;
pub mod queries;
pub mod types;

// Re-export the primary public API.
pub use cache::{IntrospectionCache, RELOAD_CHANNEL};
pub use introspect::introspect;
pub use types::{
    ForeignKeyAction, IntrospectionResult, PgAttribute, PgClass, PgClassKind, PgConstraint,
    PgConstraintKind, PgDescription, PgEnum, PgIndex, PgNamespace, PgProc, PgType, ProcVolatility,
};
