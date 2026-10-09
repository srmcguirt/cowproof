//! Schema grounding: check names against known facts before an agent acts.
//!
//! Two things an agent gets wrong about a database. It invents a column that
//! never existed, and it reads a migration file that has since been altered.
//! The second is worse, because it looks sourced.
//!
//! fellwork-data makes the point: 143 `CREATE TABLE` and 239 `ALTER TABLE`
//! across 87 files, including 16 `DROP COLUMN`. No single file states the
//! current shape — only the catalog does.
//!
//! So read the catalog, [`Snapshot`] it with [`Provenance`], commit that, and
//! check against it. The same bargain the parity harness makes with fixtures.

#[cfg(feature = "postgres")]
pub mod pg;
pub mod resolve;
pub mod resolver;
pub mod snapshot;
pub mod tools;

pub use resolve::{resolve_column, resolve_table, Resolution, Suggestion};
pub use resolver::SchemaRegistry;
pub use snapshot::{Column, Provenance, Snapshot, SourceKind, Table};
pub use tools::register;

#[cfg(feature = "postgres")]
use std::collections::BTreeMap;

#[cfg(feature = "postgres")]
use portkit_core::Result;

/// Introspect a live database and materialize a fingerprinted snapshot.
///
/// Requires the `postgres` feature. Checking against a committed snapshot does
/// not, which is the common case in CI and for anyone without credentials.
///
/// `locator` is recorded in the provenance and must not be a connection
/// string — provenance travels into agent context and often into commits.
#[cfg(feature = "postgres")]
pub async fn capture(
    pool: &sqlx::PgPool,
    schemas: &[&str],
    source: &str,
    locator: &str,
) -> Result<Snapshot> {
    let result = pg::introspect(pool, schemas)
        .await
        .map_err(|e| portkit_core::Error::Config(format!("introspection failed: {e}")))?;

    let mut snapshot = from_introspection(result, source, locator);
    snapshot.provenance.fingerprint = snapshot.compute_fingerprint();
    Ok(snapshot)
}

#[cfg(feature = "postgres")]
/// Fold pg_catalog rows into the flat shape a checker needs.
///
/// The catalog is normalized by oid; a checker wants names. Most of this is
/// resolving those joins once, at capture time, so every later lookup is a
/// map hit rather than a graph walk.
fn from_introspection(r: pg::IntrospectionResult, source: &str, locator: &str) -> Snapshot {
    let ns: BTreeMap<u32, &str> = r
        .namespaces
        .iter()
        .map(|n| (n.oid, n.name.as_str()))
        .collect();
    let type_names: BTreeMap<u32, &str> =
        r.types.iter().map(|t| (t.oid, t.name.as_str())).collect();

    // COMMENT ON values, keyed by (relation, column number). obj_sub_id 0 is
    // the relation itself; anything higher is a specific column.
    let mut descriptions: BTreeMap<(u32, i32), &str> = BTreeMap::new();
    for d in &r.descriptions {
        descriptions.insert((d.obj_oid, d.obj_sub_id), d.description.as_str());
    }

    // Dropped and system columns are already excluded by the catalog query,
    // so anything arriving here is a column that really exists.
    let mut cols: BTreeMap<u32, Vec<snapshot::Column>> = BTreeMap::new();
    for a in &r.attributes {
        cols.entry(a.class_oid).or_default().push(snapshot::Column {
            name: a.name.clone(),
            data_type: type_names
                .get(&a.type_oid)
                .copied()
                .unwrap_or("unknown")
                .to_string(),
            nullable: !a.is_not_null,
            description: descriptions
                .get(&(a.class_oid, a.num as i32))
                .map(|d| (*d).to_string()),
        });
    }

    let mut tables = BTreeMap::new();
    for c in &r.classes {
        let schema = ns.get(&c.schema_oid).copied().unwrap_or("public");
        let name = format!("{schema}.{}", c.name);
        let mut columns = cols.remove(&c.oid).unwrap_or_default();
        // Sorted so a snapshot diff shows real schema changes, not catalog
        // ordering noise.
        columns.sort_by(|a, b| a.name.cmp(&b.name));

        tables.insert(
            name.clone(),
            snapshot::Table {
                name,
                schema: schema.to_string(),
                kind: format!("{:?}", c.kind).to_lowercase(),
                columns,
                primary_key: Vec::new(),
            },
        );
    }

    // Enum labels in declared order, which is meaningful in Postgres.
    let mut by_type: BTreeMap<u32, Vec<&pg::PgEnum>> = BTreeMap::new();
    for e in &r.enums {
        by_type.entry(e.type_oid).or_default().push(e);
    }
    let mut enums: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (type_oid, mut labels) in by_type {
        labels.sort_by(|a, b| {
            a.sort_order
                .partial_cmp(&b.sort_order)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let name = type_names
            .get(&type_oid)
            .copied()
            .unwrap_or("unknown")
            .to_string();
        enums.insert(name, labels.into_iter().map(|e| e.label.clone()).collect());
    }

    let mut functions: Vec<String> = r.procs.iter().map(|p| p.name.clone()).collect();
    functions.sort();
    functions.dedup();

    Snapshot {
        provenance: Provenance {
            source: source.to_string(),
            kind: SourceKind::PostgresCatalog,
            locator: locator.to_string(),
            captured_at: Snapshot::now_rfc3339(),
            fingerprint: String::new(),
        },
        tables,
        enums,
        functions,
    }
}
