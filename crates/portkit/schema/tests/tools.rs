//! The schema capability as registered tools.
//!
//! The logic was already tested; what these check is that it is *reachable* —
//! registered in a `Registry`, so `pk serve` exposes it and it inherits
//! validation, budgets and provenance instead of bypassing them.

use portkit_core::Registry;
use portkit_schema::{register, SchemaRegistry, Snapshot};
use serde_json::json;

fn registry() -> Registry {
    let snap = Snapshot::load(std::path::Path::new("tests/fixtures/fellwork.json"))
        .expect("committed fixture must load");
    let mut r = Registry::new();
    register(&mut r, SchemaRegistry::new().with(snap));
    r
}

#[tokio::test]
async fn the_capability_is_registered_and_discoverable() {
    let r = registry();
    let names = r.names();
    for expected in ["schema_check", "schema_columns", "schema_tables"] {
        assert!(names.contains(&expected), "missing {expected} in {names:?}");
    }
}

#[tokio::test]
async fn columns_come_back_with_their_real_types() {
    // Every column read "unknown" until pg_catalog was included in the type
    // query — the sort of defect that makes a tool worse than no tool.
    let out = registry()
        .call(
            "schema_columns",
            json!({"source": "fellwork", "table": "source.tokens"}),
        )
        .await
        .unwrap();

    let cols = out["columns"].as_array().unwrap();
    assert!(!cols.is_empty());
    assert!(
        cols.iter().all(|c| c["type"] != "unknown"),
        "some columns have no resolved type: {cols:?}"
    );
}

#[tokio::test]
async fn a_hallucinated_column_returns_the_nearest_real_name() {
    let out = registry()
        .call(
            "schema_check",
            json!({"source": "fellwork", "table": "source.tokens", "column": "surface_from"}),
        )
        .await
        .unwrap();

    assert_eq!(out["exists"], false);
    assert_eq!(out["suggestions"][0], "surface_form");
}

#[tokio::test]
async fn every_answer_carries_provenance() {
    // An answer that cannot be audited is only believed.
    for (tool, args) in [
        ("schema_tables", json!({"source": "fellwork"})),
        (
            "schema_columns",
            json!({"source": "fellwork", "table": "source.tokens"}),
        ),
        (
            "schema_check",
            json!({"source": "fellwork", "table": "source.tokens"}),
        ),
    ] {
        let out = registry().call(tool, args).await.unwrap();
        let p = &out["provenance"];
        assert_eq!(p["source"], "fellwork", "{tool}");
        assert!(p["fingerprint"].is_string(), "{tool}");
        assert!(p["captured_at"].is_string(), "{tool}");
    }
}

#[tokio::test]
async fn an_unloaded_source_is_named_rather_than_guessed_at() {
    let err = registry()
        .call(
            "schema_check",
            json!({"source": "nope", "table": "source.tokens"}),
        )
        .await
        .unwrap_err();
    assert!(err.is_caller_fault());
    assert!(
        err.to_string().contains("fellwork"),
        "should list what is loaded: {err}"
    );
}

#[tokio::test]
async fn arguments_are_validated_by_the_registry_not_the_tool() {
    // Registering means inheriting the boundary checks; shelling out to `pks`
    // would bypass them.
    let err = registry()
        .call(
            "schema_check",
            json!({"source": "fellwork", "table": "t", "bogus": 1}),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bogus"), "{err}");
}

#[tokio::test]
async fn registering_also_wires_the_reference_resolver() {
    // The same snapshots that answer schema_* also gate x-schema-ref, so the
    // two can never disagree about what exists.
    use portkit_core::{async_trait, Result, Tool, ToolSpec};
    use serde_json::Value;

    struct Query;

    #[async_trait]
    impl Tool for Query {
        fn spec(&self) -> ToolSpec {
            ToolSpec::new(
                "q",
                "Reads a table.",
                json!({
                    "type": "object",
                    "properties": { "table": { "type": "string", "x-schema-ref": "fellwork#table" } },
                    "required": ["table"]
                }),
            )
        }
        async fn call(&self, _input: Value) -> Result<Value> {
            Ok(json!({"ran": true}))
        }
    }

    let snap = Snapshot::load(std::path::Path::new("tests/fixtures/fellwork.json")).unwrap();
    let mut r = Registry::new();
    r.register(Query);
    register(&mut r, SchemaRegistry::new().with(snap));

    assert!(r.call("q", json!({"table": "source.tokens"})).await.is_ok());
    let err = r
        .call("q", json!({"table": "source.nope"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a known table"), "{err}");
}
