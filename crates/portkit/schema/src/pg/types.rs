//! Introspection result types — Rust representations of pg_catalog rows.
//!
//! These structs mirror the Postgres system catalogs queried during introspection.
//! They are fully owned (no lifetimes) so they can be cached and shared across threads.

use serde::{Deserialize, Serialize};

/// The complete result of introspecting one or more Postgres schemas.
/// Cached by [`super::cache::IntrospectionCache`] and consumed by downstream
/// crates (magna-build) to generate the GraphQL schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResult {
    /// Schemas (pg_namespace rows) that were introspected.
    pub namespaces: Vec<PgNamespace>,
    /// Tables, views, materialized views, and composite types (pg_class).
    pub classes: Vec<PgClass>,
    /// Columns (pg_attribute) for the introspected classes.
    pub attributes: Vec<PgAttribute>,
    /// Primary key, foreign key, unique, and check constraints (pg_constraint).
    pub constraints: Vec<PgConstraint>,
    /// Functions and procedures (pg_proc).
    pub procs: Vec<PgProc>,
    /// Base, domain, enum, composite, and array types (pg_type).
    pub types: Vec<PgType>,
    /// Enum label values (pg_enum).
    pub enums: Vec<PgEnum>,
    /// Indexes (pg_index + pg_class for the index relation).
    pub indexes: Vec<PgIndex>,
    /// COMMENT ON values (pg_description).
    pub descriptions: Vec<PgDescription>,
}

// ---------------------------------------------------------------------------
// pg_namespace
// ---------------------------------------------------------------------------

/// A Postgres schema (namespace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgNamespace {
    pub oid: u32,
    pub name: String,
}

// ---------------------------------------------------------------------------
// pg_class
// ---------------------------------------------------------------------------

/// A Postgres relation — table, view, materialized view, or composite type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgClass {
    pub oid: u32,
    pub name: String,
    pub schema_oid: u32,
    pub kind: PgClassKind,
    /// True when row-level security is enabled on the relation.
    pub is_rls_enabled: bool,
}

/// The `relkind` column from pg_class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PgClassKind {
    /// Ordinary table (`r`).
    Table,
    /// View (`v`).
    View,
    /// Materialized view (`m`).
    MaterializedView,
    /// Composite type (`c`).
    CompositeType,
    /// Foreign table (`f`).
    ForeignTable,
}

impl PgClassKind {
    /// Parse the single-char `relkind` value from pg_class.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'r' => Some(Self::Table),
            'v' => Some(Self::View),
            'm' => Some(Self::MaterializedView),
            'c' => Some(Self::CompositeType),
            'f' => Some(Self::ForeignTable),
            _ => None,
        }
    }

    /// Return the single-char representation used by Postgres.
    pub fn as_char(self) -> char {
        match self {
            Self::Table => 'r',
            Self::View => 'v',
            Self::MaterializedView => 'm',
            Self::CompositeType => 'c',
            Self::ForeignTable => 'f',
        }
    }
}

// ---------------------------------------------------------------------------
// pg_attribute
// ---------------------------------------------------------------------------

/// A column on a relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgAttribute {
    /// OID of the owning relation (pg_class.oid).
    pub class_oid: u32,
    /// Column name.
    pub name: String,
    /// OID of the column's type (pg_type.oid).
    pub type_oid: u32,
    /// Ordinal position (1-based). Corresponds to `attnum`.
    pub num: i16,
    /// True when the column has a NOT NULL constraint.
    pub is_not_null: bool,
    /// True when the column has a DEFAULT expression.
    pub has_default: bool,
    /// True when the column is an identity column (GENERATED ALWAYS / BY DEFAULT).
    pub is_identity: bool,
}

// ---------------------------------------------------------------------------
// pg_constraint
// ---------------------------------------------------------------------------

/// A table constraint — primary key, foreign key, unique, check, or exclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgConstraint {
    pub oid: u32,
    pub name: String,
    /// OID of the table this constraint is on.
    pub class_oid: u32,
    pub kind: PgConstraintKind,
    /// Attribute numbers (1-based) that form this constraint's key.
    pub key_attrs: Vec<i16>,
    /// For FK constraints: OID of the referenced table.
    pub foreign_class_oid: Option<u32>,
    /// For FK constraints: attribute numbers on the referenced table.
    pub foreign_key_attrs: Option<Vec<i16>>,
    /// For FK constraints: action on DELETE of referenced row.
    pub on_delete: Option<ForeignKeyAction>,
    /// For FK constraints: action on UPDATE of referenced row.
    pub on_update: Option<ForeignKeyAction>,
}

/// The `contype` column from pg_constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PgConstraintKind {
    /// Primary key (`p`).
    PrimaryKey,
    /// Foreign key (`f`).
    ForeignKey,
    /// Unique constraint (`u`).
    Unique,
    /// Check constraint (`c`).
    Check,
    /// Exclusion constraint (`x`).
    Exclusion,
}

impl PgConstraintKind {
    /// Parse the single-char `contype` value from pg_constraint.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'p' => Some(Self::PrimaryKey),
            'f' => Some(Self::ForeignKey),
            'u' => Some(Self::Unique),
            'c' => Some(Self::Check),
            'x' => Some(Self::Exclusion),
            _ => None,
        }
    }

    /// Return the single-char representation used by Postgres.
    pub fn as_char(self) -> char {
        match self {
            Self::PrimaryKey => 'p',
            Self::ForeignKey => 'f',
            Self::Unique => 'u',
            Self::Check => 'c',
            Self::Exclusion => 'x',
        }
    }
}

/// Foreign key referential actions (confdeltype / confupdtype).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForeignKeyAction {
    /// No action (`a`).
    NoAction,
    /// Restrict (`r`).
    Restrict,
    /// Cascade (`c`).
    Cascade,
    /// Set null (`n`).
    SetNull,
    /// Set default (`d`).
    SetDefault,
}

impl ForeignKeyAction {
    /// Parse the single-char referential action from pg_constraint.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'a' => Some(Self::NoAction),
            'r' => Some(Self::Restrict),
            'c' => Some(Self::Cascade),
            'n' => Some(Self::SetNull),
            'd' => Some(Self::SetDefault),
            _ => None,
        }
    }

    /// Return the single-char representation used by Postgres.
    pub fn as_char(self) -> char {
        match self {
            Self::NoAction => 'a',
            Self::Restrict => 'r',
            Self::Cascade => 'c',
            Self::SetNull => 'n',
            Self::SetDefault => 'd',
        }
    }
}

// ---------------------------------------------------------------------------
// pg_proc
// ---------------------------------------------------------------------------

/// A Postgres function or procedure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgProc {
    pub oid: u32,
    pub name: String,
    /// OID of the schema containing this function.
    pub schema_oid: u32,
    /// OIDs of the argument types.
    pub arg_types: Vec<u32>,
    /// OID of the return type.
    pub return_type: u32,
    /// True when the function returns SETOF (table-valued).
    pub returns_set: bool,
    /// True when the function is STRICT (returns null on null input).
    pub is_strict: bool,
    /// Volatility classification.
    pub volatility: ProcVolatility,
    /// Implementation language (e.g. "sql", "plpgsql", "c").
    pub language: String,
}

/// Function volatility classification (`provolatile` in pg_proc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcVolatility {
    /// Immutable (`i`) — same inputs always produce the same output.
    Immutable,
    /// Stable (`s`) — result does not change within a single statement.
    Stable,
    /// Volatile (`v`) — result can change at any time (default).
    Volatile,
}

impl ProcVolatility {
    /// Parse the single-char `provolatile` value from pg_proc.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'i' => Some(Self::Immutable),
            's' => Some(Self::Stable),
            'v' => Some(Self::Volatile),
            _ => None,
        }
    }

    /// Return the single-char representation used by Postgres.
    pub fn as_char(self) -> char {
        match self {
            Self::Immutable => 'i',
            Self::Stable => 's',
            Self::Volatile => 'v',
        }
    }
}

// ---------------------------------------------------------------------------
// pg_type
// ---------------------------------------------------------------------------

/// A Postgres type — base, domain, enum, composite, array, or range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgType {
    pub oid: u32,
    pub name: String,
    /// OID of the schema containing this type.
    pub schema_oid: u32,
    /// Type category (e.g. 'S' = string, 'N' = numeric, 'B' = boolean).
    pub category: char,
    /// For array types: the OID of the element type. Zero if not an array.
    pub array_element_type_oid: u32,
    /// For domain types: the OID of the base type. Zero if not a domain.
    pub base_type_oid: u32,
    /// For composite types: the OID of the associated pg_class. Zero otherwise.
    pub class_oid: u32,
    /// For enum types: true. Use this to quickly filter enums.
    pub is_enum: bool,
}

// ---------------------------------------------------------------------------
// pg_enum
// ---------------------------------------------------------------------------

/// A single label value within an enum type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgEnum {
    pub oid: u32,
    /// OID of the parent enum type (pg_type.oid).
    pub type_oid: u32,
    /// Sort position of this label within the enum.
    pub sort_order: f32,
    /// The label string.
    pub label: String,
}

// ---------------------------------------------------------------------------
// pg_index
// ---------------------------------------------------------------------------

/// An index on a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgIndex {
    /// OID of the index relation (pg_class.oid of the index itself).
    pub index_oid: u32,
    /// OID of the table this index is on.
    pub class_oid: u32,
    /// Attribute numbers (1-based) of the indexed columns.
    pub key_attrs: Vec<i16>,
    /// True when this is a unique index.
    pub is_unique: bool,
    /// True when this is the primary key index.
    pub is_primary: bool,
}

// ---------------------------------------------------------------------------
// pg_description
// ---------------------------------------------------------------------------

/// A COMMENT ON value from pg_description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgDescription {
    /// OID of the object being described.
    pub obj_oid: u32,
    /// OID of the catalog table the `obj_oid` refers to (e.g. pg_class OID).
    pub class_oid: u32,
    /// Sub-object ID: 0 for the table itself, N for column N.
    pub obj_sub_id: i32,
    /// The comment text.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_result_construction() {
        let result = IntrospectionResult {
            namespaces: vec![PgNamespace {
                oid: 2200,
                name: "public".to_string(),
            }],
            classes: vec![PgClass {
                oid: 16384,
                name: "users".to_string(),
                schema_oid: 2200,
                kind: PgClassKind::Table,
                is_rls_enabled: true,
            }],
            attributes: vec![PgAttribute {
                class_oid: 16384,
                name: "id".to_string(),
                type_oid: 2950,
                num: 1,
                is_not_null: true,
                has_default: true,
                is_identity: false,
            }],
            constraints: vec![PgConstraint {
                oid: 16400,
                name: "users_pkey".to_string(),
                class_oid: 16384,
                kind: PgConstraintKind::PrimaryKey,
                key_attrs: vec![1],
                foreign_class_oid: None,
                foreign_key_attrs: None,
                on_delete: None,
                on_update: None,
            }],
            procs: vec![],
            types: vec![PgType {
                oid: 2950,
                name: "uuid".to_string(),
                schema_oid: 11,
                category: 'U',
                array_element_type_oid: 0,
                base_type_oid: 0,
                class_oid: 0,
                is_enum: false,
            }],
            enums: vec![],
            indexes: vec![PgIndex {
                index_oid: 16401,
                class_oid: 16384,
                key_attrs: vec![1],
                is_unique: true,
                is_primary: true,
            }],
            descriptions: vec![PgDescription {
                obj_oid: 16384,
                class_oid: 1259,
                obj_sub_id: 0,
                description: "Application users".to_string(),
            }],
        };

        assert_eq!(result.namespaces.len(), 1);
        assert_eq!(result.namespaces[0].name, "public");
        assert_eq!(result.classes.len(), 1);
        assert_eq!(result.classes[0].name, "users");
        assert!(result.classes[0].is_rls_enabled);
        assert_eq!(result.attributes.len(), 1);
        assert_eq!(result.constraints.len(), 1);
        assert_eq!(result.constraints[0].kind, PgConstraintKind::PrimaryKey);
        assert_eq!(result.indexes.len(), 1);
        assert!(result.indexes[0].is_primary);
        assert_eq!(result.descriptions.len(), 1);
    }

    #[test]
    fn pg_class_kind_roundtrip() {
        let kinds = [
            ('r', PgClassKind::Table),
            ('v', PgClassKind::View),
            ('m', PgClassKind::MaterializedView),
            ('c', PgClassKind::CompositeType),
            ('f', PgClassKind::ForeignTable),
        ];
        for (ch, expected) in &kinds {
            let parsed = PgClassKind::from_char(*ch).unwrap();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.as_char(), *ch);
        }
        assert!(PgClassKind::from_char('z').is_none());
    }

    #[test]
    fn pg_constraint_kind_roundtrip() {
        let kinds = [
            ('p', PgConstraintKind::PrimaryKey),
            ('f', PgConstraintKind::ForeignKey),
            ('u', PgConstraintKind::Unique),
            ('c', PgConstraintKind::Check),
            ('x', PgConstraintKind::Exclusion),
        ];
        for (ch, expected) in &kinds {
            let parsed = PgConstraintKind::from_char(*ch).unwrap();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.as_char(), *ch);
        }
        assert!(PgConstraintKind::from_char('z').is_none());
    }

    #[test]
    fn foreign_key_action_roundtrip() {
        let actions = [
            ('a', ForeignKeyAction::NoAction),
            ('r', ForeignKeyAction::Restrict),
            ('c', ForeignKeyAction::Cascade),
            ('n', ForeignKeyAction::SetNull),
            ('d', ForeignKeyAction::SetDefault),
        ];
        for (ch, expected) in &actions {
            let parsed = ForeignKeyAction::from_char(*ch).unwrap();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.as_char(), *ch);
        }
        assert!(ForeignKeyAction::from_char('z').is_none());
    }

    #[test]
    fn proc_volatility_roundtrip() {
        let vols = [
            ('i', ProcVolatility::Immutable),
            ('s', ProcVolatility::Stable),
            ('v', ProcVolatility::Volatile),
        ];
        for (ch, expected) in &vols {
            let parsed = ProcVolatility::from_char(*ch).unwrap();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.as_char(), *ch);
        }
        assert!(ProcVolatility::from_char('z').is_none());
    }

    #[test]
    fn fk_constraint_construction() {
        let fk = PgConstraint {
            oid: 16500,
            name: "posts_author_fk".to_string(),
            class_oid: 16450,
            kind: PgConstraintKind::ForeignKey,
            key_attrs: vec![2],
            foreign_class_oid: Some(16384),
            foreign_key_attrs: Some(vec![1]),
            on_delete: Some(ForeignKeyAction::Cascade),
            on_update: Some(ForeignKeyAction::NoAction),
        };
        assert_eq!(fk.kind, PgConstraintKind::ForeignKey);
        assert_eq!(fk.foreign_class_oid, Some(16384));
        assert_eq!(fk.on_delete, Some(ForeignKeyAction::Cascade));
        assert_eq!(fk.on_update, Some(ForeignKeyAction::NoAction));
    }
}
