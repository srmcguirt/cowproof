//! Raw SQL queries against pg_catalog for schema introspection.
//!
//! All queries are raw strings executed via `sqlx::query()` (not `sqlx::query!`).
//! pg_catalog's schema is stable across Postgres versions, so compile-time
//! checking is unnecessary and would require a live database connection.
//!
//! Each query accepts a `$1` parameter: an array of schema names to introspect.

/// Fetch namespaces (schemas) by name.
///
/// Returns: oid, nspname
pub const QUERY_NAMESPACES: &str = r#"
SELECT
    n.oid::int4   AS oid,
    n.nspname     AS name
FROM pg_catalog.pg_namespace n
WHERE n.nspname = ANY($1)
ORDER BY n.nspname
"#;

/// Fetch classes (tables, views, materialized views, composite types, foreign tables)
/// in the given namespaces.
///
/// Filters to relkind in ('r', 'v', 'm', 'c', 'f') and excludes TOAST tables.
/// Returns: oid, relname, relnamespace, relkind, relrowsecurity
pub const QUERY_CLASSES: &str = r#"
SELECT
    c.oid::int4          AS oid,
    c.relname            AS name,
    c.relnamespace::int4 AS schema_oid,
    c.relkind::text      AS kind,
    c.relrowsecurity     AS is_rls_enabled
FROM pg_catalog.pg_class c
WHERE c.relnamespace = ANY(
    SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
)
AND c.relkind IN ('r', 'v', 'm', 'c', 'f')
ORDER BY c.relnamespace, c.relname
"#;

/// Fetch attributes (columns) for classes in the given namespaces.
///
/// Excludes dropped columns (attisdropped) and system columns (attnum < 1).
/// Returns: attrelid, attname, atttypid, attnum, attnotnull, atthasdef, attidentity
pub const QUERY_ATTRIBUTES: &str = r#"
SELECT
    a.attrelid::int4  AS class_oid,
    a.attname         AS name,
    a.atttypid::int4  AS type_oid,
    a.attnum          AS num,
    a.attnotnull      AS is_not_null,
    a.atthasdef       AS has_default,
    CASE WHEN a.attidentity IN ('a', 'd') THEN true ELSE false END AS is_identity
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
WHERE c.relnamespace = ANY(
    SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
)
AND c.relkind IN ('r', 'v', 'm', 'c', 'f')
AND a.attnum > 0
AND NOT a.attisdropped
ORDER BY a.attrelid, a.attnum
"#;

/// Fetch constraints (PK, FK, unique, check, exclusion) for classes in the given namespaces.
///
/// Returns: oid, conname, conrelid, contype, conkey, confrelid, confkey, confdeltype, confupdtype
pub const QUERY_CONSTRAINTS: &str = r#"
SELECT
    con.oid::int4           AS oid,
    con.conname             AS name,
    con.conrelid::int4      AS class_oid,
    con.contype::text       AS kind,
    con.conkey              AS key_attrs,
    con.confrelid::int4     AS foreign_class_oid,
    con.confkey             AS foreign_key_attrs,
    con.confdeltype::text   AS on_delete,
    con.confupdtype::text   AS on_update
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
WHERE c.relnamespace = ANY(
    SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
)
ORDER BY con.conrelid, con.conname
"#;

/// Fetch functions/procedures in the given namespaces.
///
/// Excludes aggregate functions (prokind = 'a') and window functions (prokind = 'w').
/// Returns: oid, proname, pronamespace, proargtypes, prorettype, proretset, proisstrict, provolatile, prolang
pub const QUERY_PROCS: &str = r#"
SELECT
    p.oid::int4           AS oid,
    p.proname             AS name,
    p.pronamespace::int4  AS schema_oid,
    COALESCE(ARRAY(SELECT unnest(p.proargtypes)::int4), ARRAY[]::int4[]) AS arg_types,
    p.prorettype::int4    AS return_type,
    p.proretset           AS returns_set,
    p.proisstrict         AS is_strict,
    p.provolatile::text   AS volatility,
    l.lanname             AS language
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_language l ON l.oid = p.prolang
WHERE p.pronamespace = ANY(
    SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
)
AND p.prokind IN ('f', 'p')
ORDER BY p.pronamespace, p.proname
"#;

/// Fetch types in the given namespaces.
///
/// Returns: oid, typname, typnamespace, typcategory, typelem, typbasetype, typrelid, typcategory='E'
pub const QUERY_TYPES: &str = r#"
SELECT
    t.oid::int4            AS oid,
    t.typname              AS name,
    t.typnamespace::int4   AS schema_oid,
    t.typcategory::text    AS category,
    t.typelem::int4        AS array_element_type_oid,
    t.typbasetype::int4    AS base_type_oid,
    t.typrelid::int4       AS class_oid,
    (t.typtype = 'e')      AS is_enum
FROM pg_catalog.pg_type t
WHERE (
    t.typnamespace = ANY(
        SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
    )
    -- PORTKIT DEVIATION from magna-introspect: built-in types (text, int4,
    -- uuid) live in pg_catalog, which is never among the schemas a caller
    -- asks about. Without this every column's type resolves to "unknown".
    OR t.typnamespace = 'pg_catalog'::regnamespace
)
ORDER BY t.typnamespace, t.typname
"#;

/// Fetch enum labels for enum types in the given namespaces.
///
/// Returns: oid, enumtypid, enumsortorder, enumlabel
pub const QUERY_ENUMS: &str = r#"
SELECT
    e.oid::int4         AS oid,
    e.enumtypid::int4   AS type_oid,
    e.enumsortorder     AS sort_order,
    e.enumlabel         AS label
FROM pg_catalog.pg_enum e
JOIN pg_catalog.pg_type t ON t.oid = e.enumtypid
WHERE t.typnamespace = ANY(
    SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
)
ORDER BY e.enumtypid, e.enumsortorder
"#;

/// Fetch indexes for tables in the given namespaces.
///
/// Returns: indexrelid, indrelid, indkey, indisunique, indisprimary
pub const QUERY_INDEXES: &str = r#"
SELECT
    i.indexrelid::int4  AS index_oid,
    i.indrelid::int4    AS class_oid,
    COALESCE(ARRAY(SELECT unnest(i.indkey)::int2), ARRAY[]::int2[]) AS key_attrs,
    i.indisunique       AS is_unique,
    i.indisprimary      AS is_primary
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
WHERE c.relnamespace = ANY(
    SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
)
ORDER BY i.indrelid, i.indexrelid
"#;

/// Fetch descriptions (COMMENT ON) for objects in the given namespaces.
///
/// Joins through pg_class to restrict to the target schemas. Also fetches
/// comments on types, procs, and constraints via their respective catalog OIDs.
/// Returns: objoid, classoid, objsubid, description
pub const QUERY_DESCRIPTIONS: &str = r#"
SELECT
    d.objoid::int4    AS obj_oid,
    d.classoid::int4  AS class_oid,
    d.objsubid        AS obj_sub_id,
    d.description     AS description
FROM pg_catalog.pg_description d
WHERE d.objoid = ANY(
    SELECT c.oid
    FROM pg_catalog.pg_class c
    WHERE c.relnamespace = ANY(
        SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
    )
    UNION
    SELECT p.oid
    FROM pg_catalog.pg_proc p
    WHERE p.pronamespace = ANY(
        SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
    )
    UNION
    SELECT t.oid
    FROM pg_catalog.pg_type t
    WHERE t.typnamespace = ANY(
        SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ANY($1)
    )
)
ORDER BY d.objoid, d.objsubid
"#;
