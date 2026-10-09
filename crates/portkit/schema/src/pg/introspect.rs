//! Main introspection entry point — runs all pg_catalog queries and assembles
//! an [`IntrospectionResult`].

use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::pg::queries;
use crate::pg::types::*;

/// Introspect the given schemas in parallel queries against pg_catalog.
///
/// Each query targets a specific system catalog (pg_class, pg_attribute, etc.)
/// and is filtered to only return objects in the requested schemas.
///
/// # Arguments
///
/// * `pool` - A sqlx Postgres connection pool.
/// * `schemas` - Schema names to introspect (e.g. `["public"]`).
///
/// # Errors
///
/// Returns `sqlx::Error` if any catalog query fails.
pub async fn introspect(
    pool: &PgPool,
    schemas: &[&str],
) -> Result<IntrospectionResult, sqlx::Error> {
    let schema_names: Vec<String> = schemas.iter().map(|s| s.to_string()).collect();

    // Run all queries concurrently for performance.
    let (namespaces, classes, attributes, constraints, procs, types, enums, indexes, descriptions) =
        tokio::try_join!(
            fetch_namespaces(pool, &schema_names),
            fetch_classes(pool, &schema_names),
            fetch_attributes(pool, &schema_names),
            fetch_constraints(pool, &schema_names),
            fetch_procs(pool, &schema_names),
            fetch_types(pool, &schema_names),
            fetch_enums(pool, &schema_names),
            fetch_indexes(pool, &schema_names),
            fetch_descriptions(pool, &schema_names),
        )?;

    Ok(IntrospectionResult {
        namespaces,
        classes,
        attributes,
        constraints,
        procs,
        types,
        enums,
        indexes,
        descriptions,
    })
}

// ---------------------------------------------------------------------------
// Individual fetch functions
// ---------------------------------------------------------------------------

async fn fetch_namespaces(
    pool: &PgPool,
    schemas: &[String],
) -> Result<Vec<PgNamespace>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_NAMESPACES)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| PgNamespace {
            oid: r.get::<i32, _>("oid") as u32,
            name: r.get("name"),
        })
        .collect())
}

async fn fetch_classes(pool: &PgPool, schemas: &[String]) -> Result<Vec<PgClass>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_CLASSES)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let kind_char: &str = r.get("kind");
            PgClass {
                oid: r.get::<i32, _>("oid") as u32,
                name: r.get("name"),
                schema_oid: r.get::<i32, _>("schema_oid") as u32,
                kind: PgClassKind::from_char(kind_char.chars().next().unwrap_or('r'))
                    .unwrap_or(PgClassKind::Table),
                is_rls_enabled: r.get("is_rls_enabled"),
            }
        })
        .collect())
}

async fn fetch_attributes(
    pool: &PgPool,
    schemas: &[String],
) -> Result<Vec<PgAttribute>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_ATTRIBUTES)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| PgAttribute {
            class_oid: r.get::<i32, _>("class_oid") as u32,
            name: r.get("name"),
            type_oid: r.get::<i32, _>("type_oid") as u32,
            num: r.get("num"),
            is_not_null: r.get("is_not_null"),
            has_default: r.get("has_default"),
            is_identity: r.get("is_identity"),
        })
        .collect())
}

async fn fetch_constraints(
    pool: &PgPool,
    schemas: &[String],
) -> Result<Vec<PgConstraint>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_CONSTRAINTS)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let kind_char: &str = r.get("kind");
            let kind = PgConstraintKind::from_char(kind_char.chars().next().unwrap_or('c'))
                .unwrap_or(PgConstraintKind::Check);

            let foreign_class_oid_raw: i32 = r.get("foreign_class_oid");
            let foreign_class_oid = if foreign_class_oid_raw != 0 {
                Some(foreign_class_oid_raw as u32)
            } else {
                None
            };

            let foreign_key_attrs: Option<Vec<i16>> = r.get("foreign_key_attrs");
            let foreign_key_attrs = foreign_key_attrs.filter(|v| !v.is_empty());

            let on_delete_char: &str = r.get("on_delete");
            let on_update_char: &str = r.get("on_update");
            let on_delete = on_delete_char.chars().next().and_then(|c| {
                if c == ' ' {
                    None
                } else {
                    ForeignKeyAction::from_char(c)
                }
            });
            let on_update = on_update_char.chars().next().and_then(|c| {
                if c == ' ' {
                    None
                } else {
                    ForeignKeyAction::from_char(c)
                }
            });

            PgConstraint {
                oid: r.get::<i32, _>("oid") as u32,
                name: r.get("name"),
                class_oid: r.get::<i32, _>("class_oid") as u32,
                kind,
                key_attrs: r.get::<Vec<i16>, _>("key_attrs"),
                foreign_class_oid,
                foreign_key_attrs,
                on_delete,
                on_update,
            }
        })
        .collect())
}

async fn fetch_procs(pool: &PgPool, schemas: &[String]) -> Result<Vec<PgProc>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_PROCS)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let volatility_char: &str = r.get("volatility");
            let arg_types_i32: Vec<i32> = r.get("arg_types");

            PgProc {
                oid: r.get::<i32, _>("oid") as u32,
                name: r.get("name"),
                schema_oid: r.get::<i32, _>("schema_oid") as u32,
                arg_types: arg_types_i32.into_iter().map(|v| v as u32).collect(),
                return_type: r.get::<i32, _>("return_type") as u32,
                returns_set: r.get("returns_set"),
                is_strict: r.get("is_strict"),
                volatility: ProcVolatility::from_char(
                    volatility_char.chars().next().unwrap_or('v'),
                )
                .unwrap_or(ProcVolatility::Volatile),
                language: r.get("language"),
            }
        })
        .collect())
}

async fn fetch_types(pool: &PgPool, schemas: &[String]) -> Result<Vec<PgType>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_TYPES)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let category_str: &str = r.get("category");
            PgType {
                oid: r.get::<i32, _>("oid") as u32,
                name: r.get("name"),
                schema_oid: r.get::<i32, _>("schema_oid") as u32,
                category: category_str.chars().next().unwrap_or('X'),
                array_element_type_oid: r.get::<i32, _>("array_element_type_oid") as u32,
                base_type_oid: r.get::<i32, _>("base_type_oid") as u32,
                class_oid: r.get::<i32, _>("class_oid") as u32,
                is_enum: r.get("is_enum"),
            }
        })
        .collect())
}

async fn fetch_enums(pool: &PgPool, schemas: &[String]) -> Result<Vec<PgEnum>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_ENUMS)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| PgEnum {
            oid: r.get::<i32, _>("oid") as u32,
            type_oid: r.get::<i32, _>("type_oid") as u32,
            sort_order: r.get("sort_order"),
            label: r.get("label"),
        })
        .collect())
}

async fn fetch_indexes(pool: &PgPool, schemas: &[String]) -> Result<Vec<PgIndex>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_INDEXES)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| PgIndex {
            index_oid: r.get::<i32, _>("index_oid") as u32,
            class_oid: r.get::<i32, _>("class_oid") as u32,
            key_attrs: r.get("key_attrs"),
            is_unique: r.get("is_unique"),
            is_primary: r.get("is_primary"),
        })
        .collect())
}

async fn fetch_descriptions(
    pool: &PgPool,
    schemas: &[String],
) -> Result<Vec<PgDescription>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(queries::QUERY_DESCRIPTIONS)
        .bind(schemas)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| PgDescription {
            obj_oid: r.get::<i32, _>("obj_oid") as u32,
            class_oid: r.get::<i32, _>("class_oid") as u32,
            obj_sub_id: r.get("obj_sub_id"),
            description: r.get("description"),
        })
        .collect())
}
