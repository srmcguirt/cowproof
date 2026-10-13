//! The ten lint rules of `kind: port` packets (portkit-integration.md, section 6.4): for
//! each, a packet that passes and one that fails, on a real directory of files.

use cowproof_lint::{Finding, LintOptions, Severity, lint_packet, lint_packet_with};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const BODY: &str = "\n## Task\n\nPort `word_count` to Rust and register it in `.portkit/plugins.toml`.\n\n## Checks\n\n- `cowproof pk port replay --fixtures ports/wc/fixtures --surface both`\n";

fn repo() -> TempDir {
    let dir = tempfile::Builder::new()
        .prefix("cp-lint-port-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let root = dir.path();
    put(
        root,
        "ports/wc/cases.jsonl",
        "{\"tool\":\"word_count\",\"input\":{}}\n",
    );
    put(
        root,
        "ports/wc/fixtures/word_count/001.json",
        r#"{"tool":"word_count","id":"001","input":{"text":"a b"},"expected":{"words":2}}"#,
    );
    put(root, ".portkit/plugins.toml", "");
    put(root, "reference/wc.mjs", "");
    put(root, "crates/pk-wc/src/lib.rs", "");
    dir
}

fn put(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// A valid port header; `edit` changes it before it is written into a packet.
fn header(edit: impl FnOnce(&mut Value)) -> Value {
    let mut header = json!({
        "id": "port-wc",
        "kind": "port",
        "class": "light",
        "owns": ["crates/pk-wc/**", "ports/wc/fixtures/**", ".portkit/plugins.toml"],
        "allow": ["cowproof pk port *"],
        "checks": [{"id": "parity", "command": "cowproof pk port replay --fixtures ports/wc/fixtures --surface both"}],
        "port": {
            "lang": "node",
            "adapter": "function",
            "reference": {"cmd": "node reference/wc.mjs"},
            "cases": "ports/wc/cases.jsonl",
            "fixtures": "ports/wc/fixtures",
            "tools": ["word_count"]
        }
    });
    edit(&mut header);
    header
}

fn packet(header: &Value, body: &str) -> String {
    format!("# Port\n\n<!-- lane {header} -->\n{body}")
}

fn lint(root: &Path, header: &Value, body: &str) -> Vec<Finding> {
    lint_packet(&packet(header, body), root, &[])
}

fn rules(findings: &[Finding]) -> Vec<&'static str> {
    findings
        .iter()
        .filter(|f| f.rule.starts_with("port-"))
        .map(|f| f.rule)
        .collect()
}

fn errors(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.to_string())
        .collect()
}

#[test]
fn a_clean_port_packet_has_no_port_findings_and_no_errors() {
    let dir = repo();
    let findings = lint(dir.path(), &header(|_| {}), BODY);
    assert_eq!(rules(&findings), Vec::<&str>::new(), "{findings:?}");
    assert_eq!(errors(&findings), Vec::<String>::new());
}

#[test]
fn a_work_packet_is_never_checked_by_the_port_rules() {
    let dir = repo();
    let work = json!({"id": "lane-a", "owns": ["crates/pk-wc/**"]});
    let findings = lint(dir.path(), &work, "");
    assert_eq!(rules(&findings), Vec::<&str>::new());
}

#[test]
fn port_adapter_missing() {
    let dir = repo();
    // The adapter the clean packet runs exists, so there is nothing to report.
    let present = header(|h| h["port"]["reference"]["cmd"] = json!("node reference/wc.mjs --flag"));
    assert_eq!(rules(&lint(dir.path(), &present, BODY)), Vec::<&str>::new());
    // A script the command names that is not a file is reported, with the rule and the path.
    let missing = header(|h| h["port"]["reference"]["cmd"] = json!("node reference/nope.mjs"));
    let findings = lint(dir.path(), &missing, BODY);
    assert_eq!(rules(&findings), ["port-adapter-missing"], "{findings:?}");
    let text = errors(&findings).join("\n");
    assert!(text.contains("port-adapter-missing"), "{text}");
    assert!(text.contains("reference/nope.mjs"), "{text}");
    // A directory is not an adapter file.
    let directory = header(|h| h["port"]["reference"]["cmd"] = json!("python3 reference"));
    assert_eq!(
        rules(&lint(dir.path(), &directory, BODY)),
        ["port-adapter-missing"]
    );
    // Flags, assignments and a leading `env` are read past; a command that is itself a path
    // is the file.
    for (cmd, expected) in [
        ("python3 -u reference/nope.py", "reference/nope.py"),
        (
            "node --import ./hook.mjs reference/nope.mjs",
            "reference/nope.mjs",
        ),
        (
            "TZ=UTC env node 'reference/nope.mjs' x",
            "reference/nope.mjs",
        ),
        ("sh reference/nope.sh", "reference/nope.sh"),
        ("./reference/nope.sh --x", "./reference/nope.sh"),
    ] {
        let h = header(|h| h["port"]["reference"]["cmd"] = json!(cmd));
        let findings = lint(dir.path(), &h, BODY);
        assert_eq!(
            rules(&findings),
            ["port-adapter-missing"],
            "{cmd}: {findings:?}"
        );
        assert!(errors(&findings).join("\n").contains(expected), "{cmd}");
    }
    // The existing adapter, reached through the same shapes, passes.
    for cmd in [
        "node ./reference/wc.mjs",
        "env TZ=UTC node reference/wc.mjs",
        "node -r ./x.cjs reference/wc.mjs arg",
        "./reference/wc.mjs",
    ] {
        let h = header(|h| h["port"]["reference"]["cmd"] = json!(cmd));
        let findings = lint(dir.path(), &h, BODY);
        assert_eq!(rules(&findings), Vec::<&str>::new(), "{cmd}: {findings:?}");
    }
}

#[test]
fn port_adapter_missing_skips_commands_with_no_file_to_name() {
    let dir = repo();
    for cmd in [
        "sh -c 'node nope.mjs'",
        "bash -c \"python3 nope.py\"",
        "node -e 'process.exit(0)'",
        "python3 -m adapter",
        "cargo run --bin adapter",
        "adapter-bin --serve",
        "node $ADAPTER",
        "node reference/*.mjs",
        "node ~/adapter.mjs",
        "node",
    ] {
        let h = header(|h| h["port"]["reference"]["cmd"] = json!(cmd));
        let findings = lint(dir.path(), &h, BODY);
        assert_eq!(rules(&findings), Vec::<&str>::new(), "{cmd}: {findings:?}");
    }
}

#[test]
fn port_adapter_missing_reports_a_path_outside_the_repository() {
    let dir = repo();
    // Even when the file exists (`reference/wc.mjs` does), an absolute or `..` path is not
    // a path inside the repository.
    let absolute = dir.path().join("reference/wc.mjs");
    for cmd in [
        "node ../escape.mjs".to_string(),
        "node reference/../wc.mjs".to_string(),
        "./../escape.mjs".to_string(),
        format!("node {}", absolute.display()),
        format!("{}", absolute.display()),
    ] {
        let h = header(|h| h["port"]["reference"]["cmd"] = json!(cmd));
        let findings = lint(dir.path(), &h, BODY);
        assert_eq!(
            rules(&findings),
            ["port-adapter-missing"],
            "{cmd}: {findings:?}"
        );
        assert!(
            errors(&findings)
                .join("\n")
                .contains("outside the repository"),
            "{cmd}"
        );
    }
}

#[test]
fn port_adapter_missing_reads_the_script_from_the_reference_cwd() {
    let dir = repo();
    put(dir.path(), "tools/ref/adapter.mjs", "");
    let inside = header(|h| {
        h["port"]["reference"] = json!({"cmd": "node adapter.mjs", "cwd": "tools/ref"});
    });
    assert_eq!(rules(&lint(dir.path(), &inside, BODY)), Vec::<&str>::new());
    let missing = header(|h| {
        h["port"]["reference"] = json!({"cmd": "node adapter.mjs", "cwd": "tools/other"});
    });
    let findings = lint(dir.path(), &missing, BODY);
    assert_eq!(rules(&findings), ["port-adapter-missing"], "{findings:?}");
}

#[test]
fn port_cases_missing() {
    let dir = repo();
    let missing = header(|h| h["port"]["cases"] = json!("ports/wc/nope.jsonl"));
    let findings = lint(dir.path(), &missing, BODY);
    assert_eq!(rules(&findings), ["port-cases-missing"], "{findings:?}");
    assert!(errors(&findings)[0].contains("ports/wc/nope.jsonl"));
    // A directory is not a cases file either.
    let directory = header(|h| h["port"]["cases"] = json!("ports/wc"));
    assert_eq!(
        rules(&lint(dir.path(), &directory, BODY)),
        ["port-cases-missing"]
    );
}

#[test]
fn port_fixtures_not_owned() {
    let dir = repo();
    // The builder writes <fixtures>/<tool>/<id>.json: two levels, so `*` is not enough.
    let shallow = header(|h| {
        h["owns"] = json!([
            "crates/pk-wc/**",
            "ports/wc/fixtures/*",
            ".portkit/plugins.toml"
        ])
    });
    let findings = lint(dir.path(), &shallow, BODY);
    assert_eq!(
        rules(&findings),
        ["port-fixtures-not-owned"],
        "{findings:?}"
    );
    assert!(errors(&findings)[0].contains("word_count"));

    let none = header(|h| h["owns"] = json!(["crates/pk-wc/**", ".portkit/plugins.toml"]));
    assert_eq!(
        rules(&lint(dir.path(), &none, BODY)),
        ["port-fixtures-not-owned"]
    );

    // One finding per tool the owns glob does not reach.
    put(
        dir.path(),
        "ports/wc/fixtures/line_count/001.json",
        r#"{"tool":"line_count","id":"001","input":{},"expected":{}}"#,
    );
    let two = header(|h| {
        h["port"]["tools"] = json!(["word_count", "line_count"]);
        h["owns"] = json!([
            "crates/pk-wc/**",
            "ports/wc/fixtures/word_count/**",
            ".portkit/plugins.toml"
        ]);
    });
    let body = BODY.replace("`word_count`", "`word_count` and `line_count`");
    let findings = lint(dir.path(), &two, &body);
    assert_eq!(
        rules(&findings),
        ["port-fixtures-not-owned"],
        "{findings:?}"
    );
    assert!(errors(&findings)[0].contains("line_count"));
}

#[test]
fn port_reference_not_allowed() {
    let dir = repo();
    let runs_reference = |allow: Value, wide: bool| {
        header(|h| {
            h["allow"] = allow;
            h["wide"] = json!(wide);
            h["checks"] = json!([
                {"id": "ref", "command": "node reference/wc.mjs < ports/wc/cases.jsonl"},
                {"id": "parity", "command": "cowproof pk port replay --fixtures ports/wc/fixtures"}
            ]);
        })
    };
    // No allow entry matches the check that runs the reference.
    let findings = lint(
        dir.path(),
        &runs_reference(json!(["cowproof pk port *"]), false),
        BODY,
    );
    assert_eq!(
        rules(&findings),
        ["port-reference-not-allowed"],
        "{findings:?}"
    );
    assert!(errors(&findings)[0].contains("node reference/wc.mjs"));

    // An allow entry for it clears the rule.
    let allowed = runs_reference(json!(["cowproof pk port *", "node reference/*"]), false);
    assert_eq!(rules(&lint(dir.path(), &allowed, BODY)), Vec::<&str>::new());

    // A wide lane has no command allowlist to break.
    let wide = runs_reference(json!([]), true);
    assert_eq!(rules(&lint(dir.path(), &wide, BODY)), Vec::<&str>::new());

    // The `## Checks` section is read as well as the header.
    let in_section = header(|h| h["checks"] = json!([]));
    let body = format!("{BODY}- `node reference/wc.mjs --self-test`\n");
    let findings = lint(dir.path(), &in_section, &body);
    assert_eq!(
        rules(&findings),
        ["port-reference-not-allowed"],
        "{findings:?}"
    );
}

#[test]
fn port_tool_unregistered() {
    let dir = repo();
    // The tool is named and the plugin manifest is named and owned: registered.
    assert_eq!(
        rules(&lint(dir.path(), &header(|_| {}), BODY)),
        Vec::<&str>::new()
    );

    // The tool is not named in the packet text.
    let findings = lint(
        dir.path(),
        &header(|_| {}),
        "\n## Task\n\nPort it. See .portkit/plugins.toml.\n",
    );
    assert_eq!(rules(&findings), ["port-tool-unregistered"], "{findings:?}");
    assert!(errors(&findings)[0].contains("does not name tool \"word_count\""));

    // No registration target is named.
    let findings = lint(
        dir.path(),
        &header(|_| {}),
        "\n## Task\n\nPort `word_count` to Rust.\n",
    );
    assert_eq!(rules(&findings), ["port-tool-unregistered"], "{findings:?}");
    assert!(errors(&findings)[0].contains("no registration target"));

    // The manifest is named but the lane does not own it.
    let unowned = header(|h| h["owns"] = json!(["crates/pk-wc/**", "ports/wc/fixtures/**"]));
    let findings = lint(dir.path(), &unowned, BODY);
    assert_eq!(rules(&findings), ["port-tool-unregistered"], "{findings:?}");
    assert!(errors(&findings)[0].contains("not covered by owns"));

    // The header's own text does not count as the packet text naming the tool.
    put(
        dir.path(),
        "ports/wc/fixtures/only_in_header/001.json",
        r#"{"tool":"only_in_header","id":"001","input":{},"expected":{}}"#,
    );
    let only_header = header(|h| h["port"]["tools"] = json!(["only_in_header"]));
    let findings = lint(dir.path(), &only_header, BODY);
    assert_eq!(rules(&findings), ["port-tool-unregistered"], "{findings:?}");
    assert!(errors(&findings)[0].contains("does not name tool \"only_in_header\""));
}

const ACCEPTED: &str = r#"{"tool":"word_count","id":"002","input":{"text":"a"},"expected":{"words":1},
  "accepted":[{"path":"/words","reason":"REASON"}]}"#;

fn escalation_log(dir: &Path, answer: &str) -> std::path::PathBuf {
    let ruled = json!({
        "event": "ruled", "lane": "port-wc", "id": "esc-1",
        "verdict": {"verdict": "answer", "text": answer}, "at_ms": 1
    });
    // An open escalation and a stop must not count as rulings.
    let stopped = json!({
        "event": "ruled", "lane": "port-wc", "id": "esc-2",
        "verdict": {"verdict": "stop"}, "at_ms": 2
    });
    let path = dir.join("escalations.jsonl");
    fs::write(&path, format!("{ruled}\n{stopped}\n")).unwrap();
    path
}

#[test]
fn port_accepted_unruled() {
    let dir = repo();
    let root = dir.path();
    let h = header(|_| {});
    let text = packet(&h, BODY);

    // A reason that cites no ruling is unruled, with or without a log.
    put(
        root,
        "ports/wc/fixtures/word_count/002.json",
        &ACCEPTED.replace("REASON", "close enough"),
    );
    let findings = lint_packet(&text, root, &[]);
    assert_eq!(rules(&findings), ["port-accepted-unruled"], "{findings:?}");
    assert!(errors(&findings)[0].contains("002.json"));
    assert!(errors(&findings)[0].contains("cites no ruling"));

    // Citing a ruling is enough when there is no log to check it against.
    put(
        root,
        "ports/wc/fixtures/word_count/002.json",
        &ACCEPTED.replace("REASON", "ruling:r42 float order"),
    );
    assert_eq!(rules(&lint_packet(&text, root, &[])), Vec::<&str>::new());

    // With the lane's escalation log, the id must be carried by a director's answer.
    let log = escalation_log(
        root,
        "Accept it: the order is unspecified upstream. ruling:r42",
    );
    let options = LintOptions {
        escalations: Some(&log),
        ..Default::default()
    };
    let findings = lint_packet_with(&text, root, &[], &options);
    assert_eq!(rules(&findings), Vec::<&str>::new(), "{findings:?}");

    // A different id, one that only starts like a real one, and an empty log all fail.
    for answer in ["ruling:r4", "ruling:r420", "nothing cited"] {
        let log = escalation_log(root, answer);
        let options = LintOptions {
            escalations: Some(&log),
            ..Default::default()
        };
        let findings = lint_packet_with(&text, root, &[], &options);
        assert_eq!(
            rules(&findings),
            ["port-accepted-unruled"],
            "{answer}: {findings:?}"
        );
        assert!(errors(&findings)[0].contains("ruling:r42"), "{answer}");
    }
    let missing = root.join("no-such-log.jsonl");
    let options = LintOptions {
        escalations: Some(&missing),
        ..Default::default()
    };
    let findings = lint_packet_with(&text, root, &[], &options);
    assert_eq!(rules(&findings), ["port-accepted-unruled"], "{findings:?}");
}

#[test]
fn port_epsilon_loosened() {
    let dir = repo();
    let root = dir.path();
    // The project default is exact; a packet at the default is fine, above it is not.
    let at_default = header(|h| h["port"]["parity"] = json!({"epsilon": 0.0}));
    assert_eq!(rules(&lint(root, &at_default, BODY)), Vec::<&str>::new());
    let loosened = header(|h| h["port"]["parity"] = json!({"epsilon": 1e-6}));
    let findings = lint(root, &loosened, BODY);
    assert_eq!(rules(&findings), ["port-epsilon-loosened"], "{findings:?}");
    assert!(errors(&findings)[0].contains("project default 0"));

    // A fixture that sets epsilon above the default is the same error.
    put(
        root,
        "ports/wc/fixtures/word_count/003.json",
        r#"{"tool":"word_count","id":"003","input":{},"expected":{"words":0},"epsilon":0.5}"#,
    );
    let findings = lint(root, &header(|_| {}), BODY);
    assert_eq!(rules(&findings), ["port-epsilon-loosened"], "{findings:?}");
    assert!(errors(&findings)[0].contains("003.json"));
    fs::remove_file(root.join("ports/wc/fixtures/word_count/003.json")).unwrap();

    // The default is the project's `[port] epsilon` in cowproof.toml.
    put(root, "cowproof.toml", "[port]\nepsilon = 1e-3\n");
    assert_eq!(rules(&lint(root, &loosened, BODY)), Vec::<&str>::new());
    let beyond = header(|h| h["port"]["parity"] = json!({"epsilon": 0.5}));
    let findings = lint(root, &beyond, BODY);
    assert_eq!(rules(&findings), ["port-epsilon-loosened"], "{findings:?}");
    assert!(errors(&findings)[0].contains("project default 0.001"));
}

/// A `.portkit/plugins.toml` with one `pk port wrap` entry, `args` after `port wrap`.
fn wrap_manifest(args: &str) -> String {
    format!(
        "[[plugin]]\ncommand = \"/usr/bin/cowproof\"\nargs = [\"pk\", \"port\", \"wrap\", {args}]\n"
    )
}

fn with_roots(roots: &[&str]) -> Value {
    header(|h| h["port"]["parity"] = json!({"path_roots": roots}))
}

#[test]
fn port_wrap_roots_mismatch() {
    let dir = repo();
    let root = dir.path();
    let manifest = |args: &str| put(root, ".portkit/plugins.toml", &wrap_manifest(args));

    // The flags name the packet's roots, in another order: nothing to report.
    manifest(
        r#""--tool", "word_count", "--exe", "target/wc", "--path-root", "$HOME", "--path-root", "$ROOT""#,
    );
    let declared = with_roots(&["$ROOT", "$HOME"]);
    assert_eq!(rules(&lint(root, &declared, BODY)), Vec::<&str>::new());
    // The `=` spelling of both flags reads the same.
    manifest(r#""--tool=word_count", "--path-root=$ROOT", "--path-root=$HOME""#);
    assert_eq!(rules(&lint(root, &declared, BODY)), Vec::<&str>::new());
    // A packet with no roots and a wrap with none.
    manifest(r#""--tool", "word_count", "--exe", "target/wc""#);
    assert_eq!(
        rules(&lint(root, &header(|_| {}), BODY)),
        Vec::<&str>::new()
    );

    // A root the manifest leaves out: reported, with the rule and both lists.
    manifest(r#""--tool", "word_count", "--path-root", "$ROOT""#);
    let findings = lint(root, &with_roots(&["$ROOT", "$HOME", "$TMP"]), BODY);
    assert_eq!(
        rules(&findings),
        ["port-wrap-roots-mismatch"],
        "{findings:?}"
    );
    let text = errors(&findings).join("\n");
    assert!(
        text.contains("port-wrap-roots-mismatch")
            && text.contains("--path-root [$ROOT]")
            && text.contains("path_roots is [$HOME, $ROOT, $TMP]")
            && text.contains(".portkit/plugins.toml"),
        "{text}"
    );
    // A root it adds, and roots against none.
    let findings = lint(root, &with_roots(&["$HOME"]), BODY);
    assert_eq!(rules(&findings), ["port-wrap-roots-mismatch"]);
    let findings = lint(root, &header(|_| {}), BODY);
    assert_eq!(rules(&findings), ["port-wrap-roots-mismatch"]);
    assert!(
        errors(&findings)
            .join("\n")
            .contains("path_roots is [none]")
    );

    // The name the manifest gives the plugin is the tool, whatever `--tool` says.
    put(
        root,
        ".portkit/plugins.toml",
        &format!(
            "{}name = \"word_count\"\n",
            wrap_manifest(r#""--tool", "other", "--path-root", "$ROOT""#)
        ),
    );
    assert_eq!(
        rules(&lint(root, &with_roots(&["$HOME"]), BODY)),
        ["port-wrap-roots-mismatch"]
    );
    // An entry for another tool, and a plugin that is not a wrap, are not this packet's.
    manifest(r#""--tool", "other", "--path-root", "$ROOT""#);
    assert_eq!(
        rules(&lint(root, &with_roots(&["$HOME"]), BODY)),
        Vec::<&str>::new()
    );
    put(
        root,
        ".portkit/plugins.toml",
        "[[plugin]]\ncommand = \"/usr/bin/tool\"\nargs = [\"--tool\", \"word_count\", \"--path-root\", \"$ROOT\"]\n",
    );
    assert_eq!(
        rules(&lint(root, &with_roots(&["$HOME"]), BODY)),
        Vec::<&str>::new()
    );

    // No manifest at all is not an error; one that is not TOML is.
    fs::remove_file(root.join(".portkit/plugins.toml")).unwrap();
    assert_eq!(
        rules(&lint(root, &with_roots(&["$HOME"]), BODY)),
        Vec::<&str>::new()
    );
    put(root, ".portkit/plugins.toml", "[[plugin\n");
    assert_eq!(
        rules(&lint(root, &with_roots(&["$HOME"]), BODY)),
        ["port-wrap-roots-mismatch"]
    );
}

#[test]
fn port_nondeterministic_output_is_a_warning_with_declared_exceptions() {
    let dir = repo();
    let root = dir.path();
    let fixture = |expected: &str| {
        format!(r#"{{"tool":"word_count","id":"004","input":{{}},"expected":{expected}}}"#)
    };
    let write = |expected: &str| {
        put(
            root,
            "ports/wc/fixtures/word_count/004.json",
            &fixture(expected),
        )
    };
    let h = header(|_| {});

    // A home path, built here so the file carries no literal home directory.
    let home_path = format!(r#"{{"dir":"/{}/someone/work"}}"#, "Users");
    for (expected, what) in [
        (r#"{"at":"2026-10-12T04:59:45Z"}"#, "a time"),
        (r#"{"dir":"/tmp/run-1/out"}"#, "a temp or home path"),
        (home_path.as_str(), "a temp or home path"),
        (r#"{"host":"buildbox.local"}"#, "a host name"),
    ] {
        write(expected);
        let findings = lint(root, &h, BODY);
        assert_eq!(
            rules(&findings),
            ["port-nondeterministic-output"],
            "{expected}"
        );
        let finding = findings
            .iter()
            .find(|f| f.rule.starts_with("port-"))
            .unwrap();
        assert_eq!(finding.severity, Severity::Warn, "{expected}");
        assert!(finding.message.contains(what), "{}", finding.message);
        assert_eq!(errors(&findings), Vec::<String>::new(), "a warning only");
    }

    // Declared: ignore_paths covers the pointer, path_roots covers the path.
    write(r#"{"at":"2026-10-12T04:59:45Z"}"#);
    let ignored = header(|h| h["port"]["parity"] = json!({"ignore_paths": ["/at"]}));
    assert_eq!(rules(&lint(root, &ignored, BODY)), Vec::<&str>::new());
    write(r#"{"dir":"/tmp/run-1/out"}"#);
    let rooted = header(|h| h["port"]["parity"] = json!({"path_roots": ["$TMP"]}));
    assert_eq!(rules(&lint(root, &rooted, BODY)), Vec::<&str>::new());
    // A root for another kind of path does not cover it.
    let other = header(|h| h["port"]["parity"] = json!({"path_roots": ["$HOME"]}));
    assert_eq!(
        rules(&lint(root, &other, BODY)),
        ["port-nondeterministic-output"]
    );
    // An accepted difference at the pointer declares it too.
    put(
        root,
        "ports/wc/fixtures/word_count/004.json",
        r#"{"tool":"word_count","id":"004","input":{},"expected":{"dir":"/tmp/x"},"accepted":[{"path":"/dir","reason":"ruling:r1 temp dir"}]}"#,
    );
    assert_eq!(rules(&lint(root, &h, BODY)), Vec::<&str>::new());
}

#[test]
fn a_process_capture_with_substituted_roots_is_not_flagged_but_a_raw_path_beside_one_is() {
    // `pk port exec` records a run's directories as `$ROOT`, `$HOME`, `$TMP` and `$SRC`
    // (portkit's `path-roots` v1). The heuristic reads `/home/..` and `/tmp/..` as the start
    // of a path, so `$ROOT/home/a` must not be taken for a home directory.
    let dir = repo();
    let root = dir.path();
    let h = header(|_| {});
    let put_expected = |expected: &str| {
        put(
            root,
            "ports/wc/fixtures/word_count/004.json",
            &format!(
                r#"{{"tool":"word_count","id":"004","input":{{}},"expected":{expected},"normalized":{{"name":"path-roots","version":1,"roots":["$ROOT"]}}}}"#
            ),
        )
    };
    put_expected(
        r#"{"exit":0,"stdout":"wrote $ROOT/home/a and $HOME/b and $ROOT/tmp/c and $TMP/d and $SRC/e\n","files_after":{"out.txt":{"content":"cwd=$ROOT/tmp/x\n"}}}"#,
    );
    assert_eq!(rules(&lint(root, &h, BODY)), Vec::<&str>::new());

    // The same text with a path the substitution missed is still a finding.
    put_expected(r#"{"stdout":"wrote $ROOT/home/a and /tmp/run-1/out\n"}"#);
    let findings = lint(root, &h, BODY);
    assert_eq!(
        rules(&findings),
        ["port-nondeterministic-output"],
        "{findings:?}"
    );
    assert!(
        findings[0].message.contains("/tmp/"),
        "{}",
        findings[0].message
    );
}

/// A held-out file in its own directory, outside the repository, whose port cases name `tools`.
fn held_out_file(tools: &[&str]) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("cp-lint-held-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let cases: Vec<String> = tools
        .iter()
        .map(|t| format!("{{\"tool\":\"{t}\",\"input\":{{}}}}"))
        .collect();
    put(
        dir.path(),
        "heldout.cases.jsonl",
        &format!("# the director's cases\n\n{}\n", cases.join("\n")),
    );
    let toml = dir.path().join("lane.toml");
    fs::write(&toml, "[port]\ncases = \"heldout.cases.jsonl\"\n").unwrap();
    (dir, toml)
}

fn findings_of<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.rule == rule).collect()
}

#[test]
fn port_no_base_fixtures_is_an_error_on_an_empty_base() {
    let dir = repo();
    let root = dir.path();
    // The clean base holds a fixture for the tool: nothing to report.
    assert_eq!(
        rules(&lint(root, &header(|_| {}), BODY)),
        Vec::<&str>::new()
    );

    // A fixtures directory with no file for the tool (an empty directory, a file in the
    // wrong place, a non-JSON file) is an empty base.
    fs::remove_file(root.join("ports/wc/fixtures/word_count/001.json")).unwrap();
    for stray in [
        "ports/wc/fixtures/README.md",
        "ports/wc/fixtures/word_count/notes.txt",
    ] {
        put(root, stray, "x");
    }
    put(root, "ports/wc/fixtures/other_tool/001.json", "{}");
    let findings = lint(root, &header(|_| {}), BODY);
    assert_eq!(rules(&findings), ["port-no-base-fixtures"], "{findings:?}");
    assert_eq!(findings[0].severity, Severity::Error);
    let text = errors(&findings).join("\n");
    assert!(text.contains("word_count"), "{text}");
    assert!(
        text.contains("record the fixtures in the base first"),
        "{text}"
    );

    // A missing fixtures directory is the same.
    fs::remove_dir_all(root.join("ports/wc/fixtures")).unwrap();
    let findings = lint(root, &header(|_| {}), BODY);
    assert_eq!(findings_of(&findings, "port-no-base-fixtures").len(), 1);

    // Only the tool without fixtures is named, when the packet has two.
    put(root, "ports/wc/fixtures/word_count/001.json", "{}");
    let two = header(|h| h["port"]["tools"] = json!(["word_count", "line_count"]));
    let body = format!("{BODY}\nAlso `line_count`.\n");
    let findings = lint(root, &two, &body);
    let found = findings_of(&findings, "port-no-base-fixtures");
    assert_eq!(found.len(), 1, "{findings:?}");
    assert!(found[0].message.contains("line_count") && !found[0].message.contains("word_count"));
}

#[test]
fn port_no_base_fixtures_is_a_warning_only_when_the_held_out_cases_name_the_tool() {
    let dir = repo();
    let root = dir.path();
    fs::remove_file(root.join("ports/wc/fixtures/word_count/001.json")).unwrap();
    // A fixtures directory with a file in it still exists for the `owns` rule.
    put(root, "ports/wc/fixtures/README.md", "fixtures\n");
    let run = |toml: &Path| {
        let options = LintOptions {
            held_out: Some(toml),
            ..Default::default()
        };
        lint_packet_with(&packet(&header(|_| {}), BODY), root, &[], &options)
    };

    // The held-out cases (one JSONL line per case, blank lines and comments skipped) name it.
    let (_keep, toml) = held_out_file(&["word_count"]);
    let findings = run(&toml);
    let found = findings_of(&findings, "port-no-base-fixtures");
    assert_eq!(found.len(), 1, "{findings:?}");
    assert_eq!(found[0].severity, Severity::Warn);
    assert_eq!(errors(&findings), Vec::<String>::new());

    // They name another tool: still an error.
    let (_keep2, other) = held_out_file(&["line_count"]);
    let found = run(&other);
    assert_eq!(found[0].rule, "port-no-base-fixtures");
    assert_eq!(found[0].severity, Severity::Error);

    // A held-out file with no port cases: an error.
    let bare = tempfile::Builder::new().tempdir_in("/var/tmp").unwrap();
    let toml = bare.path().join("lane.toml");
    fs::write(&toml, "[[check]]\nid = \"x\"\ncommand = \"true\"\n").unwrap();
    let found = run(&toml);
    assert_eq!(found[0].severity, Severity::Error);

    // A held-out file that cannot be read: an error that says so.
    let found = run(&bare.path().join("missing.toml"));
    assert_eq!(found[0].severity, Severity::Error);
    assert!(
        found[0].message.contains("could not be read"),
        "{}",
        found[0].message
    );

    // No held-out file at all: an error.
    let found = lint(root, &header(|_| {}), BODY);
    assert_eq!(
        findings_of(&found, "port-no-base-fixtures")[0].severity,
        Severity::Error
    );
}

#[test]
fn port_no_base_fixtures_reads_the_base_commit_not_the_working_tree() {
    let dir = repo();
    let root = dir.path();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .args(["-c", "user.name=t", "-c", "user.email=t@localhost"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
    };
    git(&["init", "-q"]);
    // The base commit has no fixture; the working tree does.
    fs::rename(
        root.join("ports/wc/fixtures"),
        root.join("ports/fixtures-held-back"),
    )
    .unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "base"]);
    fs::rename(
        root.join("ports/fixtures-held-back"),
        root.join("ports/wc/fixtures"),
    )
    .unwrap();
    let findings = lint(root, &header(|_| {}), BODY);
    assert_eq!(rules(&findings), ["port-no-base-fixtures"], "{findings:?}");

    // Committed, it is in the base.
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "fixtures"]);
    let findings = lint(root, &header(|_| {}), BODY);
    assert_eq!(rules(&findings), Vec::<&str>::new(), "{findings:?}");
}
