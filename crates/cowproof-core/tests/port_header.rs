//! The `kind: port` packet header (portkit-integration.md, section 6.4): `kind` and the
//! strictly parsed `port` object.

use cowproof_core::{PacketKind, parse_header};
use serde_json::{Value, json};

/// A complete, valid port header, as JSON.
fn full() -> Value {
    json!({
        "id": "port-lanes",
        "kind": "port",
        "class": "rust",
        "owns": ["crates/pk-lanes/**", "ports/lanes/fixtures/**", ".portkit/plugins.toml"],
        "checks": [{"id": "parity", "command": "cowproof pk port replay --fixtures ports/lanes/fixtures"}],
        "port": {
            "lang": "node",
            "adapter": "function",
            "reference": {
                "cmd": "node reference/adapter.mjs",
                "cwd": "reference",
                "env": {"TZ": "UTC", "LANG": "C"},
                "runtime": "node>=22"
            },
            "cases": "ports/lanes/cases.jsonl",
            "fixtures": "ports/lanes/fixtures",
            "tools": ["parse_header", "glob_matches"],
            "parity": {
                "epsilon": 0.0,
                "ignore_paths": ["/meta/generated_at"],
                "unordered_arrays": false,
                "path_roots": ["$ROOT", "$TMP"]
            }
        }
    })
}

fn text(header: &Value) -> String {
    format!("# Port\n\n<!-- lane {header} -->\n\nBody.\n")
}

fn error_of(header: &Value) -> String {
    format!("{:#}", parse_header(&text(header)).expect_err("a refusal"))
}

#[test]
fn a_full_port_header_parses_every_field() {
    let header = parse_header(&text(&full())).expect("a valid port header");
    assert_eq!(header.kind, PacketKind::Port);
    assert_eq!(header.class_name, "rust");
    let port = header.port.expect("the port object");
    assert_eq!(port.lang, "node");
    assert_eq!(port.adapter, "function");
    let reference = port.reference.as_ref().expect("a reference");
    assert_eq!(reference.cmd, "node reference/adapter.mjs");
    assert_eq!(reference.cwd.as_deref(), Some("reference"));
    assert_eq!(reference.env["TZ"], "UTC");
    assert_eq!(reference.runtime.as_deref(), Some("node>=22"));
    assert_eq!(port.cases, "ports/lanes/cases.jsonl");
    assert_eq!(port.fixtures, "ports/lanes/fixtures");
    assert_eq!(port.tools, ["parse_header", "glob_matches"]);
    assert_eq!(port.parity.epsilon, Some(0.0));
    assert_eq!(port.parity.ignore_paths, ["/meta/generated_at"]);
    assert!(!port.parity.unordered_arrays);
    assert_eq!(port.parity.path_roots, ["$ROOT", "$TMP"]);
    // The packet's epsilon wins; with none given the project's default does.
    assert_eq!(port.epsilon(1e-6), 0.0);
}

#[test]
fn a_minimal_process_port_header_needs_no_reference_and_defaults_the_rest() {
    let header = json!({
        "id": "port-min", "kind": "port", "owns": ["x/**"],
        "port": {"lang": "other", "adapter": "process", "cases": "c.jsonl",
                 "fixtures": "f", "tools": ["t"]}
    });
    let parsed = parse_header(&text(&header)).unwrap();
    let port = parsed.port.unwrap();
    assert!(port.reference.is_none());
    assert_eq!(port.parity.epsilon, None);
    assert!(port.parity.ignore_paths.is_empty());
    assert_eq!(port.epsilon(1e-9), 1e-9);
}

#[test]
fn kind_defaults_to_work_and_a_work_packet_has_no_port() {
    let work = parse_header(r#"<!-- lane {"id":"lane-a","owns":["a"]} -->"#).unwrap();
    assert_eq!(work.kind, PacketKind::Work);
    assert!(work.port.is_none());
    let named =
        parse_header(r#"<!-- lane {"id":"lane-a","kind":"work","owns":["a"]} -->"#).unwrap();
    assert_eq!(named.kind, PacketKind::Work);
}

#[test]
fn unknown_keys_are_refused_at_every_level_of_the_port_object() {
    for (path, key) in [
        (&["port"][..], "adaptor"),
        (&["port", "reference"][..], "timeout"),
        (&["port", "parity"][..], "epsilon_rel"),
    ] {
        let mut header = full();
        let mut at = &mut header;
        for step in path {
            at = &mut at[*step];
        }
        at[key] = json!(1);
        let error = error_of(&header);
        assert!(
            error.contains(&format!("unknown field `{key}`")),
            "{path:?} {key}: {error}"
        );
    }
}

#[test]
fn a_port_object_on_a_work_packet_is_an_error() {
    let mut header = full();
    header["kind"] = json!("work");
    let error = error_of(&header);
    assert!(
        error.contains("a \"port\" object belongs to a packet with \"kind\": \"port\""),
        "{error}"
    );
    // No kind at all is a work packet too.
    header.as_object_mut().unwrap().remove("kind");
    assert!(error_of(&header).contains("belongs to a packet"));
}

#[test]
fn a_port_packet_without_a_port_object_and_an_unknown_kind_are_errors() {
    let mut header = full();
    header.as_object_mut().unwrap().remove("port");
    assert!(error_of(&header).contains("kind \"port\" needs a \"port\" object"));
    let mut header = full();
    header["kind"] = json!("prove");
    assert!(error_of(&header).contains("unknown variant `prove`"));
}

#[test]
fn a_bad_lang_and_a_bad_adapter_are_errors_that_list_the_choices() {
    let mut header = full();
    header["port"]["lang"] = json!("cobol");
    let error = error_of(&header);
    assert!(error.contains("port.lang \"cobol\""), "{error}");
    assert!(error.contains("python, node, typescript, shell"), "{error}");

    let mut header = full();
    header["port"]["adapter"] = json!("magic");
    let error = error_of(&header);
    assert!(error.contains("port.adapter \"magic\""), "{error}");
    assert!(error.contains("function, process"), "{error}");
}

#[test]
fn the_function_adapter_requires_a_reference_command() {
    let mut header = full();
    header["port"].as_object_mut().unwrap().remove("reference");
    assert!(error_of(&header).contains("requires port.reference.cmd"));
    let mut header = full();
    header["port"]["reference"]["cmd"] = json!("  ");
    assert!(error_of(&header).contains("port.reference.cmd must not be empty"));
}

#[test]
fn paths_tools_epsilon_env_and_runtime_are_checked() {
    let cases: [(&[&str], Value, &str); 9] = [
        (&["port", "cases"], json!("/etc/cases.jsonl"), "port.cases"),
        (&["port", "fixtures"], json!("../out"), "port.fixtures"),
        (&["port", "tools"], json!([]), "at least one tool"),
        (&["port", "tools"], json!(["a/b"]), "is not a tool name"),
        (&["port", "parity", "epsilon"], json!(-1.0), "at least 0"),
        (
            &["port", "parity", "ignore_paths"],
            json!(["meta"]),
            "is not a JSON Pointer",
        ),
        (
            &["port", "reference", "env"],
            json!({"1BAD": "x"}),
            "not an environment variable name",
        ),
        (
            &["port", "reference", "runtime"],
            json!("node>=x"),
            "port.reference.runtime",
        ),
        (
            &["port", "reference", "cwd"],
            json!("/abs"),
            "port.reference.cwd",
        ),
    ];
    for (path, value, needle) in cases {
        let mut header = full();
        let mut at = &mut header;
        for step in &path[..path.len() - 1] {
            at = &mut at[*step];
        }
        at[path[path.len() - 1]] = value;
        let error = error_of(&header);
        assert!(error.contains(needle), "{path:?}: {error}");
    }
}

#[test]
fn the_class_list_in_the_refusal_is_the_one_the_header_accepts() {
    // `port` is a slot class (the port blocks), not a packet class: the message must not
    // offer it, and `class: "port"` must stay refused.
    let header = json!({"id": "lane-c", "class": "port", "owns": ["a"]});
    let error = error_of(&header);
    assert!(
        error.contains("class must be one of rust, crate, pg, light"),
        "{error}"
    );
    assert!(!error.contains("light, port"), "{error}");
    for class in ["rust", "crate", "pg", "light"] {
        let header = json!({"id": "lane-c", "class": class, "owns": ["a"]});
        assert!(parse_header(&text(&header)).is_ok(), "{class}");
    }
}

#[test]
fn held_out_port_cases_name_a_file_beside_the_held_out_file() {
    use cowproof_core::heldout::load;
    let dir = tempfile::Builder::new()
        .prefix("cp-heldout-port-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let write = |text: &str| {
        let path = dir.path().join("lane.toml");
        std::fs::write(&path, text).unwrap();
        path
    };

    let path = write("[port]\ncases = \"lane.cases.jsonl\"\n");
    let held = load(&path).unwrap();
    assert!(!held.is_empty(), "port cases alone are a held-out file");
    assert!(held.check.is_empty());
    assert_eq!(
        held.port_cases_path(&path).unwrap(),
        dir.path().join("lane.cases.jsonl")
    );

    // Checks and cases may share a file; checks alone have no cases path.
    let both = write("[[check]]\nid = \"a\"\ncommand = \"true\"\n\n[port]\ncases = \"c.jsonl\"\n");
    assert_eq!(load(&both).unwrap().check.len(), 1);
    let checks = write("[[check]]\nid = \"a\"\ncommand = \"true\"\n");
    assert!(load(&checks).unwrap().port_cases_path(&checks).is_none());
    assert!(load(&write("")).unwrap().is_empty());

    // The cases are a plain file name beside the file; anything else, or another key, is refused.
    for bad in [
        "[port]\ncases = \"../c.jsonl\"\n",
        "[port]\ncases = \"sub/c.jsonl\"\n",
        "[port]\ncases = \"\"\n",
        "[port]\ncases = \".hidden\"\n",
        "[port]\ncases = \"c.jsonl\"\nextra = 1\n",
    ] {
        let path = write(bad);
        assert!(load(&path).is_err(), "{bad}");
    }
}
