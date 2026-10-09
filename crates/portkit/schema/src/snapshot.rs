//! A materialized, fingerprinted view of a schema, plus where it came from.
//!
//! Agents often cannot reach the live source: no credentials in CI, no
//! touching production, offline work. So introspect once, commit the result,
//! and validate against it — the same bargain the parity harness makes with
//! fixtures. A snapshot diff is a schema change, and should be reviewed as one.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use portkit_core::{Error, Result};

/// Where a snapshot came from, so an answer can be audited rather than trusted.
///
/// Without this a stale snapshot and a live database are indistinguishable,
/// which is the failure mode where a confidently wrong answer beats a missing
/// one to the agent's context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    /// Named source, e.g. `workshop`. Never defaulted — a system with more
    /// than one database must say which one it means.
    pub source: String,
    /// What kind of source of truth this was read from.
    pub kind: SourceKind,
    /// Non-secret locator: host and database, never a connection string.
    pub locator: String,
    pub captured_at: String,
    /// Content fingerprint, for detecting drift without a full re-read.
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Live introspection of `pg_catalog` — the authoritative reading.
    PostgresCatalog,
    /// Parsed from migration files. Records intent, not necessarily reality.
    SqlMigrations,
}

impl SourceKind {
    /// Whether this reflects the database as it actually is.
    ///
    /// Migrations state intent; only the catalog states fact. A checker that
    /// conflates them will confidently approve a column that was dropped.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, SourceKind::PostgresCatalog)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Column {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Table {
    /// Schema-qualified, e.g. `source.tokens`.
    pub name: String,
    pub schema: String,
    pub kind: String,
    pub columns: Vec<Column>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_key: Vec<String>,
}

impl Table {
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// The known facts about one schema source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub provenance: Provenance,
    /// Keyed by schema-qualified name, so lookup is O(log n) and ordering is
    /// stable across captures.
    pub tables: BTreeMap<String, Table>,
    #[serde(default)]
    pub enums: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub functions: Vec<String>,
}

impl Snapshot {
    pub fn table(&self, name: &str) -> Option<&Table> {
        // Accept an unqualified name when it is unambiguous — agents routinely
        // say `tokens` for `source.tokens`, and refusing that is unhelpful
        // when exactly one table can be meant.
        if let Some(t) = self.tables.get(name) {
            return Some(t);
        }
        let mut matches = self
            .tables
            .values()
            .filter(|t| t.name.ends_with(&format!(".{name}")));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    pub fn table_names(&self) -> Vec<&str> {
        self.tables.keys().map(String::as_str).collect()
    }

    pub fn column_count(&self) -> usize {
        self.tables.values().map(|t| t.columns.len()).sum()
    }

    pub fn save(&self, path: &Path) -> Result<u64> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        std::fs::write(path, &json)?;
        Ok(json.len() as u64)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        serde_json::from_slice(&raw).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }

    /// Stable content hash over names and types, ignoring capture time.
    ///
    /// Two captures of an unchanged database must agree, or drift detection
    /// fires on every run and stops being read.
    pub fn compute_fingerprint(&self) -> String {
        let mut h = Fnv::new();
        for (name, t) in &self.tables {
            h.write(name.as_bytes());
            for c in &t.columns {
                h.write(c.name.as_bytes());
                h.write(c.data_type.as_bytes());
                h.write(&[c.nullable as u8]);
            }
        }
        for (name, labels) in &self.enums {
            h.write(name.as_bytes());
            for l in labels {
                h.write(l.as_bytes());
            }
        }
        format!("{:016x}", h.finish())
    }

    pub fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default()
    }
}

struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= *b as u64;
            self.0 = self.0.wrapping_mul(0x1000_0000_01b3);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}
