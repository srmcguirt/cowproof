//! `cowproof_report::port_candidates`: the fingerprint, the ranking and the walk. Every
//! lanes root here is built by hand under `/var/tmp`, with trace lines written as portkit
//! writes them (`portkit_core::trace::CallRecord` as JSONL: `tool`, `session`, `target`,
//! `surface`, `outcome`, `at`, `duration_ms`, `input_bytes`, `produced_bytes`,
//! `delivered_bytes`); the CLI's own test produces a real trace with `pk hook` so these
//! shapes cannot drift from the writer.

use cowproof_report::port_candidates::{Options, fingerprint, port_candidates};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
}

/// A secret-shaped value: Anthropic prefix and a synthetic lettered tail.
const SECRET_TAIL: &str = "abcdefghij";

fn secret() -> String {
    format!("sk-{}-api03-{}", "ant", SECRET_TAIL.repeat(3))
}

/// One hook-written `Bash` record: the surface is `agent`, `duration_ms` is `0.0`, and
/// `delivered_bytes` equals `produced_bytes`.
fn bash(target: &str, bytes: usize) -> String {
    timed(target, bytes, 0.0)
}

fn timed(target: &str, bytes: usize, ms: f64) -> String {
    let target = serde_json::to_string(target).unwrap();
    format!(
        r#"{{"tool":"Bash","session":"s1","target":{target},"surface":"agent","outcome":"ok","at":"2026-10-11T00:00:00Z","duration_ms":{ms:?},"input_bytes":40,"produced_bytes":{bytes},"delivered_bytes":{bytes}}}"#
    )
}

/// A lane the way the runner leaves it: `<lane>/portkit/traces/<date>-<session>.jsonl`.
fn put(root: &Path, lane: &str, lines: &[String]) -> PathBuf {
    let traces = root.join(lane).join("portkit").join("traces");
    fs::create_dir_all(&traces).unwrap();
    let file = traces.join("2026-10-11-s1.jsonl");
    let mut text = lines.join("\n");
    text.push('\n');
    fs::write(&file, text).unwrap();
    file
}

fn repeat(target: &str, bytes: usize, n: usize) -> Vec<String> {
    (0..n).map(|_| bash(target, bytes)).collect()
}

fn run(roots: &[&Path], options: &Options) -> cowproof_report::port_candidates::PortCandidates {
    let roots: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
    port_candidates(&roots, options).unwrap()
}

fn fp(target: &str) -> String {
    fingerprint(target).unwrap_or_else(|| panic!("no fingerprint for {target:?}"))
}

// ---- the fingerprint ----

#[test]
fn the_same_command_on_different_temp_paths_has_one_fingerprint() {
    let a = fp("cat /tmp/pc-a1b2c3/out.log");
    let b = fp("cat /var/folders/zz/abc123/T/tmp.QwErTy/other.txt");
    let c = fp("cat /private/tmp/claude-501/x/y/z");
    assert_eq!(a, "cat <tmp>");
    assert_eq!(a, b);
    assert_eq!(a, c);
    // And a path that is not under a temp directory is not.
    assert_ne!(a, fp("cat /srv/me/out.log"));
}

#[test]
fn a_script_run_from_two_lane_clones_is_one_command() {
    assert_eq!(
        fp("node /srv/me/cache/cowproof/lanes/lane-a/clone/scripts/gate.mjs"),
        "node gate.mjs"
    );
    assert_eq!(fp("node ./scripts/gate.mjs"), "node gate.mjs");
    assert_eq!(fp("/usr/local/bin/node gate.mjs"), "node gate.mjs");
}

#[test]
fn different_subcommands_have_different_fingerprints() {
    assert_eq!(fp("cargo test"), "cargo test");
    assert_ne!(fp("cargo test"), fp("cargo build"));
    assert_ne!(fp("git status"), fp("git diff"));
    // A flag is part of the command.
    assert_ne!(fp("ls -la"), fp("ls -R"));
}

#[test]
fn ids_and_numbers_are_collapsed_and_environment_assignments_are_dropped() {
    assert_eq!(fp("git show 1a2b3c4d5e"), "git show <id>");
    assert_eq!(fp("git show 9f8e7d6c5b4a"), fp("git show 1a2b3c4d5e"));
    assert_eq!(fp("tail 3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "tail <id>");
    assert_eq!(fp("sleep 4821"), "sleep <n>");
    assert_eq!(fp("sleep 5"), "sleep <n>");
    assert_eq!(fp("cat lane-4821.log"), "cat lane-<n>.log");
    // A word of letters that happens to be hex is not an id.
    assert_eq!(fp("git show deadbeef"), "git show deadbeef");
    // The assignment goes whole, name and value.
    assert_eq!(fp("FOO=bar cargo test"), "cargo test");
    assert_eq!(fp("A=1 B=2 cargo test"), "cargo test");
}

#[test]
fn a_value_after_equals_a_string_or_a_url_is_never_kept() {
    assert_eq!(fp("deploy --token=hunter2hunter2"), "deploy --token=<v>");
    assert_eq!(fp("make KEY=value"), "make <kv>");
    assert_eq!(fp("echo 'hello"), "echo <str>");
    assert_eq!(fp("curl https://user:pw@example.com/x"), "curl <url>");
    assert_eq!(fp("cat .env.local"), "cat <secret-file>");
    assert_eq!(fp("cat ~/.ssh/id_rsa"), "cat <secret-file>");
}

#[test]
fn a_head_with_no_program_has_no_fingerprint() {
    assert_eq!(fingerprint(""), None);
    assert_eq!(fingerprint("   "), None);
    assert_eq!(fingerprint("FOO=bar"), None);
}

// ---- the ranking ----

fn three_commands(root: &Path) {
    // lane-a: cargo test x4 (1000 B), git status x6 (100 B), rg foo x1 (6000 B), ls once.
    let mut a = repeat("cargo test", 1000, 4);
    a.extend(repeat("git status", 100, 6));
    a.push(bash("rg foo", 6000));
    a.push(bash("ls -la", 50));
    put(root, "lane-a", &a);
    // lane-b: cargo test x2, git status x4, rg foo x1.
    let mut b = repeat("cargo test", 1000, 2);
    b.extend(repeat("git status", 100, 4));
    b.push(bash("rg foo", 6000));
    put(root, "lane-b", &b);
}

fn approx(a: f64, b: f64) {
    assert!((a - b).abs() < 1e-12, "{a} != {b}");
}

#[test]
fn candidates_rank_by_calls_times_bytes_when_no_time_is_recorded() {
    let dir = var_tmp("cp-pc-rank-");
    three_commands(dir.path());
    let report = run(&[dir.path()], &Options::default());
    // cargo test: 6 calls, 6000 B; git status: 10 calls, 1000 B; rg foo: 2 calls, 12000 B;
    // ls -la ran once and is no candidate. max calls 10, max bytes 12000, no time.
    assert_eq!(report.candidate_count, 3);
    assert!(!report.time_recorded);
    let names: Vec<_> = report
        .candidates
        .iter()
        .map(|c| c.fingerprint.as_str())
        .collect();
    assert_eq!(names, ["cargo test", "rg foo", "git status"]);
    let [cargo, rg, git] = &report.candidates[..] else {
        panic!("three candidates");
    };
    assert_eq!((cargo.rank, rg.rank, git.rank), (1, 2, 3));
    assert_eq!(
        (cargo.calls, cargo.lanes, cargo.delivered_bytes),
        (6, 2, 6000)
    );
    assert_eq!((rg.calls, rg.lanes, rg.delivered_bytes), (2, 2, 12000));
    assert_eq!((git.calls, git.lanes, git.delivered_bytes), (10, 2, 1000));
    approx(cargo.factors.calls, 0.6);
    approx(cargo.factors.bytes, 0.5);
    approx(cargo.factors.time, 1.0);
    approx(cargo.score, 0.3);
    approx(rg.score, 0.2);
    approx(git.score, 1.0 * (1000.0 / 12000.0));
    assert_eq!((cargo.median_ms, cargo.timed_calls), (None, 0));
}

#[test]
fn measured_time_joins_the_score_and_an_unmeasured_call_counts_one_millisecond() {
    let dir = var_tmp("cp-pc-time-");
    let mut lines = Vec::new();
    // cargo test: 6 calls x 100 ms; rg foo: 2 calls x 500 ms; git status: 10 unmeasured.
    lines.extend((0..6).map(|_| timed("cargo test", 1000, 100.0)));
    lines.extend((0..2).map(|_| timed("rg foo", 6000, 500.0)));
    lines.extend(repeat("git status", 100, 10));
    put(dir.path(), "lane-a", &lines);
    let report = run(&[dir.path()], &Options::default());
    assert!(report.time_recorded);
    // effective ms: cargo 600, rg 1000, git 10 (1 ms each); max 1000.
    let names: Vec<_> = report
        .candidates
        .iter()
        .map(|c| c.fingerprint.as_str())
        .collect();
    assert_eq!(names, ["rg foo", "cargo test", "git status"]);
    let [rg, cargo, git] = &report.candidates[..] else {
        panic!("three candidates");
    };
    // max calls 10, max bytes 12000.
    approx(rg.score, 0.2 * 1.0 * 1.0);
    approx(cargo.score, 0.6 * 0.5 * 0.6);
    approx(git.score, 1.0 * (1000.0 / 12000.0) * 0.01);
    assert_eq!(
        (rg.median_ms, rg.total_ms, rg.timed_calls),
        (Some(500.0), 1000.0, 2)
    );
    assert_eq!((cargo.median_ms, cargo.total_ms), (Some(100.0), 600.0));
    assert_eq!(
        (git.median_ms, git.total_ms, git.timed_calls),
        (None, 0.0, 0)
    );
}

#[test]
fn top_and_min_calls_cut_the_list_but_not_the_normalization() {
    let dir = var_tmp("cp-pc-top-");
    three_commands(dir.path());
    let top = run(
        &[dir.path()],
        &Options {
            top: 1,
            min_calls: 2,
        },
    );
    assert_eq!(top.candidates.len(), 1);
    assert_eq!(top.candidate_count, 3);
    assert_eq!(top.candidates[0].fingerprint, "cargo test");
    approx(top.candidates[0].score, 0.3);
    // With min_calls 1 the single `ls -la` is a candidate and the maxima are the same.
    let all = run(
        &[dir.path()],
        &Options {
            top: 10,
            min_calls: 1,
        },
    );
    assert_eq!(all.candidate_count, 4);
    assert!(all.candidates.iter().any(|c| c.fingerprint == "ls -la"));
}

#[test]
fn calls_across_lanes_and_roots_add_up_per_fingerprint() {
    let one = var_tmp("cp-pc-r1-");
    let two = var_tmp("cp-pc-r2-");
    put(one.path(), "same-name", &repeat("cargo test", 10, 2));
    put(two.path(), "same-name", &repeat("cargo test", 10, 3));
    let report = run(&[one.path(), two.path()], &Options::default());
    assert_eq!(report.roots, 2);
    let c = &report.candidates[0];
    // The same lane name under two roots is two lanes.
    assert_eq!((c.calls, c.lanes, c.delivered_bytes), (5, 2, 50));
}

// ---- secrets ----

fn secret_lanes(root: &Path) {
    let secret = secret();
    let mut lines = Vec::new();
    for _ in 0..3 {
        lines.push(bash(&format!("curl {secret}"), 500));
        lines.push(bash(&format!("deploy --token={secret}"), 500));
        lines.push(bash(&format!("API_KEY={secret} make"), 500));
        lines.push(bash(
            &format!("echo Bearer {SECRET_TAIL}{SECRET_TAIL}"),
            500,
        ));
    }
    put(root, "lane-a", &lines);
}

#[test]
fn a_secret_shaped_argument_never_reaches_the_output_json_or_drafts() {
    let dir = var_tmp("cp-pc-secret-");
    secret_lanes(dir.path());
    let report = run(&[dir.path()], &Options::default());
    assert!(
        !report.candidates.is_empty(),
        "the secret commands are candidates, so the check below looks at real output"
    );
    let mut everything = report.render();
    everything.push_str(&report.to_json().to_string());
    for draft in report.drafts() {
        everything.push_str(&draft.id);
        everything.push_str(&draft.file_name);
        everything.push_str(&draft.text);
    }
    assert!(
        !everything.contains(SECRET_TAIL),
        "a secret reached the output:\n{everything}"
    );
    assert!(!everything.contains("sk-ant"), "{everything}");
    // What the output does say about them is the fingerprint without the value.
    let names: Vec<&str> = report
        .candidates
        .iter()
        .map(|c| c.fingerprint.as_str())
        .collect();
    assert!(names.contains(&"deploy --token=<v>"), "{names:?}");
    assert!(names.contains(&"make"), "{names:?}");
}

#[test]
fn control_characters_in_a_trace_cannot_reach_the_terminal() {
    let dir = var_tmp("cp-pc-ctrl-");
    let lines = repeat("echo \u{1b}[31mred\u{7}", 10, 3);
    put(dir.path(), "lane-a", &lines);
    let report = run(&[dir.path()], &Options::default());
    let out = report.render() + &report.to_json().to_string();
    assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'), "{out:?}");
}

// ---- the walk ----

#[test]
fn a_symlinked_lane_directory_is_skipped_and_counted() {
    let dir = var_tmp("cp-pc-link-lane-");
    let outside = var_tmp("cp-pc-link-out-");
    put(dir.path(), "real", &repeat("cargo test", 10, 2));
    put(outside.path(), "elsewhere", &repeat("cargo test", 10, 7));
    symlink(outside.path().join("elsewhere"), dir.path().join("linked")).unwrap();
    symlink(dir.path().join("real"), dir.path().join("twin")).unwrap();
    let report = run(&[dir.path()], &Options::default());
    assert_eq!(report.counts.symlinked, 2);
    assert_eq!(report.counts.seen, 3);
    assert_eq!(report.counts.lanes_traced, 1);
    assert_eq!(
        report.candidates[0].calls, 2,
        "nothing was read through a link"
    );
}

#[test]
fn a_symlinked_portkit_traces_or_trace_file_is_skipped_and_counted() {
    let dir = var_tmp("cp-pc-link-dirs-");
    let outside = var_tmp("cp-pc-link-out2-");
    // lane-a: `portkit` is a link out of the root.
    put(outside.path(), "state-holder", &repeat("cargo test", 10, 5));
    fs::create_dir_all(dir.path().join("lane-a")).unwrap();
    symlink(
        outside.path().join("state-holder").join("portkit"),
        dir.path().join("lane-a").join("portkit"),
    )
    .unwrap();
    // lane-b: `traces` is a link out of the root.
    fs::create_dir_all(dir.path().join("lane-b").join("portkit")).unwrap();
    symlink(
        outside
            .path()
            .join("state-holder")
            .join("portkit")
            .join("traces"),
        dir.path().join("lane-b").join("portkit").join("traces"),
    )
    .unwrap();
    // lane-c: a real trace file and a link to another one.
    let real = put(dir.path(), "lane-c", &repeat("git status", 10, 3));
    let stray = outside.path().join("stray.jsonl");
    fs::write(&stray, repeat("git status", 10, 9).join("\n")).unwrap();
    symlink(&stray, real.parent().unwrap().join("2026-10-12-s1.jsonl")).unwrap();
    let report = run(&[dir.path()], &Options::default());
    assert_eq!(report.counts.symlinked, 3, "{:?}", report.counts);
    assert_eq!(report.counts.trace_files, 1);
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].fingerprint, "git status");
    assert_eq!(report.candidates[0].calls, 3);
}

#[test]
fn malformed_lines_are_counted_and_the_rest_is_read() {
    let dir = var_tmp("cp-pc-bad-");
    let file = put(dir.path(), "lane-a", &repeat("cargo test", 10, 2));
    let mut text = fs::read(&file).unwrap();
    text.extend_from_slice(b"{ truncated\n\n   \nnot json at all\n");
    // Not UTF-8, and a record with the wrong type for a field.
    text.extend_from_slice(b"\xff\xfe{\"tool\":\n");
    text.extend_from_slice(br#"{"tool":"Bash","surface":"agent","outcome":"ok","at":"x","duration_ms":"slow","input_bytes":1,"produced_bytes":2,"delivered_bytes":2}"#);
    text.push(b'\n');
    text.extend_from_slice(bash("cargo test", 10).as_bytes());
    text.push(b'\n');
    fs::write(&file, text).unwrap();
    let report = run(&[dir.path()], &Options::default());
    assert_eq!(report.counts.malformed_lines, 4, "{:?}", report.counts);
    assert_eq!(report.counts.records, 3);
    assert_eq!(report.candidates[0].calls, 3);
}

#[test]
fn only_hook_bash_calls_are_commands() {
    let dir = var_tmp("cp-pc-kinds-");
    let mut lines = repeat("cargo test", 10, 2);
    // portkit's own tool (surface cli), a Read, and a Bash record with no target.
    for _ in 0..3 {
        lines.push(r#"{"tool":"sym","surface":"cli","outcome":"ok","at":"x","duration_ms":1.0,"input_bytes":1,"produced_bytes":9,"delivered_bytes":9}"#.into());
        lines.push(r#"{"tool":"Read","session":"s1","target":"/a/b.rs","surface":"agent","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":9,"delivered_bytes":9}"#.into());
        lines.push(r#"{"tool":"Bash","session":"s1","surface":"agent","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":9,"delivered_bytes":9}"#.into());
    }
    put(dir.path(), "lane-a", &lines);
    let report = run(&[dir.path()], &Options::default());
    assert_eq!(report.counts.records, 11);
    assert_eq!(report.counts.commands, 2);
    assert_eq!(report.counts.not_commands, 9);
    assert_eq!(report.candidates.len(), 1);
}

#[test]
fn lanes_without_traces_are_counted_and_other_files_are_ignored() {
    let dir = var_tmp("cp-pc-untraced-");
    let file = put(dir.path(), "traced", &repeat("cargo test", 10, 2));
    // portkit's `said` directory and a stray text file next to the trace are not traces.
    fs::create_dir_all(file.parent().unwrap().join("said")).unwrap();
    fs::write(file.parent().unwrap().join("said").join("s1.txt"), "x").unwrap();
    fs::write(file.parent().unwrap().join("notes.txt"), "cargo test").unwrap();
    // A Codex lane: a control directory and no portkit directory at all.
    fs::create_dir_all(dir.path().join("codex-lane").join("control")).unwrap();
    // A lane whose traces directory is empty, and a plain file among the lanes.
    fs::create_dir_all(dir.path().join("empty").join("portkit").join("traces")).unwrap();
    fs::write(dir.path().join("README"), "x").unwrap();
    let report = run(&[dir.path()], &Options::default());
    assert_eq!(report.counts.seen, 3);
    assert_eq!(report.counts.lanes_traced, 1);
    assert_eq!(report.counts.lanes_untraced, 2);
    assert_eq!(report.counts.trace_files, 1);
    assert_eq!(report.candidates.len(), 1);
}

#[test]
fn a_root_that_is_not_a_directory_is_an_error() {
    let dir = var_tmp("cp-pc-root-");
    let file = dir.path().join("file");
    fs::write(&file, "x").unwrap();
    for bad in [file, dir.path().join("missing")] {
        let err = port_candidates(std::slice::from_ref(&bad), &Options::default()).unwrap_err();
        assert!(err.to_string().contains("lanes root"), "{err:#}");
    }
}

// ---- the table ----

#[test]
fn the_table_fits_80_columns_and_clips_a_long_command() {
    let dir = var_tmp("cp-pc-width-");
    let long = format!("{} --{}", "p".repeat(40), "f".repeat(40));
    let mut lines = repeat(&long, 12_345_678, 3);
    lines.extend(repeat("cargo test", 10, 2));
    put(dir.path(), "lane-a", &lines);
    let report = run(&[dir.path()], &Options::default());
    let table = report.render();
    assert!(
        table.contains("Port candidates: 2 of 2 commands run 2+ times"),
        "{table}"
    );
    assert!(table.contains("35.3 MiB"), "{table}");
    for line in table.lines() {
        assert!(line.chars().count() <= 80, "{line:?}");
    }
    assert!(table.contains('~'), "the long command is clipped: {table}");
}

#[test]
fn an_empty_root_says_so() {
    let dir = var_tmp("cp-pc-empty-");
    let report = run(&[dir.path()], &Options::default());
    assert!(report.candidates.is_empty());
    assert!(report.render().contains("no command was run often enough"));
    assert!(report.drafts().is_empty());
}

// ---- the drafts ----

#[test]
fn a_draft_is_marked_draft_and_its_header_parses() {
    let dir = var_tmp("cp-pc-draft-");
    three_commands(dir.path());
    let report = run(&[dir.path()], &Options::default());
    let drafts = report.drafts();
    assert_eq!(drafts.len(), 3);
    let ids: Vec<&str> = drafts.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, ["port-cargo-test", "port-rg-foo", "port-git-status"]);
    for draft in &drafts {
        assert_eq!(draft.file_name, format!("{}.md", draft.id));
        let header = cowproof_core::parse_header(&draft.text)
            .unwrap_or_else(|e| panic!("{}: {e:#}", draft.id));
        assert_eq!(header.id, draft.id);
        assert_eq!(header.class_name, "rust");
        // A valid port header, strictly parsed: `kind: port` with a `port` object and the
        // fixtures and the plugin manifest owned, so the lint rules for ports can pass.
        assert_eq!(header.kind, cowproof_core::PacketKind::Port);
        let port = header.port.as_ref().expect("a port object");
        assert_eq!(port.adapter, "process");
        assert!(port.reference.is_none(), "the director sets the reference");
        assert!(header.owns.iter().any(|o| o.ends_with("/fixtures/**")));
        assert!(header.owns.iter().any(|o| o == ".portkit/plugins.toml"));
        assert!(draft.text.contains("# DRAFT: port"), "{}", draft.text);
        assert!(draft.text.contains("is not dispatched"), "{}", draft.text);
        assert!(
            draft.text.contains("cowproof pk port capture"),
            "{}",
            draft.text
        );
        assert!(draft.text.contains("FILL-"), "{}", draft.text);
    }
    let cargo = &drafts[0].text;
    assert!(cargo.contains("- calls: 6 in 2 lanes"), "{cargo}");
    assert!(
        cargo.contains("- bytes delivered into context: 5.9 KiB (1000 per call)"),
        "{cargo}"
    );
    assert!(cargo.contains("- `cargo test`"), "{cargo}");
    assert!(cargo.contains("rank 1 of 3"), "{cargo}");
}

#[test]
fn drafts_with_one_slug_get_distinct_ids() {
    let dir = var_tmp("cp-pc-slug-");
    let mut lines = repeat("node a.mjs", 10, 2);
    lines.extend(repeat("node a-mjs", 10, 2));
    put(dir.path(), "lane-a", &lines);
    let report = run(&[dir.path()], &Options::default());
    let ids: Vec<String> = report.drafts().into_iter().map(|d| d.id).collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert!(
        ids.iter().all(|id| id.starts_with("port-node-a-mjs")),
        "{ids:?}"
    );
}

#[test]
fn write_drafts_creates_the_files_and_never_overwrites() {
    let dir = var_tmp("cp-pc-write-");
    three_commands(dir.path());
    let out = var_tmp("cp-pc-write-out-");
    let drafts_dir = out.path().join("nested").join("drafts");
    let report = run(&[dir.path()], &Options::default());
    let written = report.write_drafts(&drafts_dir).unwrap();
    assert_eq!(written.len(), 3);
    for path in &written {
        assert!(fs::read_to_string(path).unwrap().contains("# DRAFT: port"));
    }
    // A second run refuses, names the file, and leaves the first untouched.
    fs::write(&written[1], "mine").unwrap();
    let err = report.write_drafts(&drafts_dir).unwrap_err();
    assert!(err.to_string().contains("never overwrite"), "{err:#}");
    assert_eq!(fs::read_to_string(&written[1]).unwrap(), "mine");
    // A link where a draft would go is not followed.
    let target = out.path().join("victim");
    fs::write(&target, "keep").unwrap();
    let other = out.path().join("links");
    fs::create_dir_all(&other).unwrap();
    symlink(&target, other.join("port-cargo-test.md")).unwrap();
    assert!(report.write_drafts(&other).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
}
