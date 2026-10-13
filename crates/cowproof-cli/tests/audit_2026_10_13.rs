//! Proof tests for `docs/audit-2026-10-13.md`. Every test is `#[ignore]`d and FAILS today, so
//! the suite stays green; `cargo test -p cowproof --test audit_2026_10_13 -- --ignored` shows
//! them failing. Each names the finding it proves. None needs a sandbox, a network or a tool.

use cowproof_run::bundler::{Host, Plan, parse, plan};
use std::fs;
use std::path::Path;

/// S-1. `bundle install --local` runs the lane's `Gemfile`, and the first line of its output
/// reaches the director's terminal unescaped: `first_error_line` keeps control characters
/// (cowproof verify prints it as `setup: ...`; npm, yarn, pnpm and gem failures take the same
/// path to `infrastructure: ...`). `first_line` of the port judge strips them; this does not.
#[test]
#[ignore = "S-1: open finding"]
fn audit_s1_a_gemfile_error_reaches_the_directors_terminal_with_its_escape_sequences() {
    let output = b"[!] There was an error parsing `Gemfile`: \x1b[2J\x1b[1;1Hverify: reproduced \
                   \x1b]52;c;ZXZpbA==\x07. Bundler cannot continue.\n\n #  from Gemfile:2\n";
    let line = cowproof_run::deps::bundle_failure(output);
    assert!(
        !line.chars().any(char::is_control),
        "control characters survive into the failure line: {line:?}"
    );
}

/// S-3. A lockfile of R `remote:` lines and S specs makes `plan` hold R x S remote strings, and
/// `gem_fetch_script` writes one `--source` per remote per gem. A 1 MB `Gemfile.lock` is about
/// 20 000 remotes and 30 000 specs: 600 million strings in the director's process.
#[test]
#[ignore = "S-3: open finding"]
fn audit_s3_the_bundler_plan_multiplies_remotes_by_specs() {
    const R: usize = 1000;
    const S: usize = 1000;
    let mut lock = String::from("GEM\n");
    for i in 0..R {
        lock.push_str(&format!("  remote: https://h{i}.example/\n"));
    }
    lock.push_str("  specs:\n");
    for i in 0..S {
        lock.push_str(&format!("    g{i} (1.0.0)\n"));
    }
    lock.push_str("\nPLATFORMS\n  ruby\n");
    let input_lines = lock.lines().count();
    let parsed = parse(&lock).expect("the lockfile parses");
    let Plan::Fetch(downloads) = plan("Gemfile.lock", &parsed, &Host::of("x86_64", "linux")) else {
        panic!("the plan fetches");
    };
    let held: usize = downloads.iter().map(|d| d.remotes.len()).sum();
    assert!(
        held <= 4 * input_lines,
        "{input_lines} lines of input make the plan hold {held} remote strings"
    );
}

/// S-4. `ini` (what npm and pnpm read `.npmrc` with) unquotes a quoted key, so
/// `"//host/:_authToken"=...` sets the token; the stripper looks at the text after the last `:`
/// and sees `_authToken"`, so the token is handed to the fetch and lands in the entry's cache.
#[test]
#[ignore = "S-4: open finding"]
fn audit_s4_a_quoted_npmrc_key_keeps_its_token() {
    let text = "registry=https://registry.npmjs.org/\n\
                \"//registry.npmjs.org/:_authToken\"=DOUBLE-QUOTED-SECRET\n\
                '//registry.npmjs.org/:_authToken'=SINGLE-QUOTED-SECRET\n";
    let (out, _) = cowproof_run::deps::strip_npmrc_auth(text);
    assert!(
        !out.contains("SECRET"),
        "a token survived the credential strip:\n{out}"
    );
}

fn lane_with_run_json(root: &Path, id: &str, run: &serde_json::Value) -> std::path::PathBuf {
    let lane = root.join(id);
    fs::create_dir_all(lane.join("control")).unwrap();
    fs::write(lane.join("control/run.json"), run.to_string()).unwrap();
    lane
}

fn trace_line(tool: &str) -> String {
    format!(
        r#"{{"tool":"{tool}","target":"a","surface":"agent","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":90,"delivered_bytes":40}}"#
    )
}

/// S-5. `traceTotals.byTool` is keyed by tool names the builder writes into its own trace, with
/// no limit on their length or number, and the runner copies it into `run.json`. `watch` and
/// the `lanes` tool read `run.json` only up to 4 MiB, so a builder that makes it larger loses the
/// lane its CREDENTIAL (including `in lane`) and CTX-SAVED columns, silently.
#[test]
#[ignore = "S-5: open finding"]
fn audit_s5_a_builder_can_blind_watch_to_the_credential_column_by_growing_run_json() {
    let tmp = tempfile::tempdir_in("/var/tmp").unwrap();
    let make = |name: &str, tool: &str| {
        let root = tmp.path().join(name);
        let lane = root.join("lane-a");
        fs::create_dir_all(lane.join("portkit/traces")).unwrap();
        fs::write(
            lane.join("portkit/traces/2026-10-13.jsonl"),
            trace_line(tool) + "\n",
        )
        .unwrap();
        let totals = cowproof_report::traces::lane_trace_totals(&lane).expect("a traced lane");
        let run = serde_json::json!({
            "status": "finished",
            "authMode": "subscription",
            "credentialKind": "claude-oauth-token",
            "credentialInLane": true,
            "traceTotals": totals,
        });
        lane_with_run_json(&root, "lane-a", &run);
        cowproof_cli::watch::lane_snapshots(&root, 0, 0).unwrap()
    };
    let honest = make("honest", "Read");
    assert!(honest[0].credential.is_some() && honest[0].ctx_saved_bytes.is_some());
    let bloated = make("bloated", &"T".repeat(5 * 1024 * 1024));
    assert!(
        bloated[0].credential.is_some(),
        "the lane held a credential in its sandbox and watch no longer says so"
    );
}

/// S-6. A figure that comes from the builder's own trace is marked builder-written only in
/// `run.json`; the `lanes` tool's JSON (and the `watch` column) carry it with no marker, so an
/// agent director reads `ctx_saved_bytes` as a measurement.
#[test]
#[ignore = "S-6: open finding"]
fn audit_s6_the_lanes_tool_does_not_label_a_builder_reported_figure() {
    let tmp = tempfile::tempdir_in("/var/tmp").unwrap();
    let run = serde_json::json!({
        "status": "finished",
        "traceTotals": { "savedBytes": 123456789u64 },
        "traceBuilderWritten": true,
    });
    lane_with_run_json(tmp.path(), "lane-a", &run);
    let rows = cowproof_cli::watch::lane_snapshots(tmp.path(), 0, 0).unwrap();
    let json = serde_json::to_string(&rows).unwrap();
    assert!(json.contains("ctx_saved_bytes"), "{json}");
    assert!(
        json.to_ascii_lowercase().contains("builder"),
        "the figure has no builder-written marker anywhere in the reply: {json}"
    );
}

/// S-7. Every planner refuses a symlinked lockfile (`is_regular`), but the cache key follows
/// it (`is_file`) and reads the whole target into memory: a lane's `Gemfile.lock -> <any
/// readable file>` changes the key and makes the director read that file.
#[test]
#[ignore = "S-7: open finding"]
fn audit_s7_a_symlinked_lockfile_does_not_belong_in_the_cache_key() {
    let tmp = tempfile::tempdir_in("/var/tmp").unwrap();
    let triple = "x86_64-unknown-linux-gnu";
    let empty = tmp.path().join("empty");
    fs::create_dir_all(&empty).unwrap();
    let linked = tmp.path().join("linked");
    fs::create_dir_all(&linked).unwrap();
    let elsewhere = tmp.path().join("elsewhere.txt");
    fs::write(&elsewhere, "any file the director can read").unwrap();
    std::os::unix::fs::symlink(&elsewhere, linked.join("Gemfile.lock")).unwrap();
    assert_eq!(
        cowproof_run::dependency_cache_key(&empty, triple).unwrap(),
        cowproof_run::dependency_cache_key(&linked, triple).unwrap(),
        "a symlink the planners ignore still changes the key"
    );
}
