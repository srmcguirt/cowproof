//! Whole-process capture (portkit-integration.md, sections 6.1 to 6.3; gaps G2, G3, G4, G13):
//! a POSIX `sh` script as the reference, captured by `pk port exec` in a sandbox with the
//! network denied and a scripted `git` first on `PATH`, and a Rust program as the port,
//! replayed through `pk port wrap` as a plugin. The real `pk`, the real `sh`, a real `rustc`
//! and, for the last tests, a whole `cowproof run` against a FAKE `claude`.
//!
//! The script is written to run under dash and bash alike (the Linux gate's `/bin/sh` is
//! dash). Every test that runs a case needs the sandbox (`sandbox-exec`, or `bwrap` on Linux
//! with `COWPROOF_REQUIRE_SANDBOX=1` demanding it); without one it prints a skip. The tests
//! that read the committed example under `fixtures/port-process/` read above the crate and run
//! in the workspace only (`common/workspace.rs`).

mod common;
#[path = "common/workspace.rs"]
mod workspace;

use common::{Lane, output, run_checks, sandbox_available, text, var_tmp};
use serde_json::{Value, json};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

// ---- the example: a script and its ports ----------------------------------------------------

/// `fixtures/port-process/project/reference/greet.sh` (a test checks the copy).
const GREET_SH: &str = r#"#!/bin/sh
# greet.sh NAMEFILE: say hello to the name in NAMEFILE.
#
# Reads the file, asks git which revision it is run in, writes greeting.txt, removes
# stale.txt, and prints where it wrote. Exits 2 when NAMEFILE does not exist.
set -eu
if [ ! -f "${1:-}" ]; then
  echo "no such file: ${1:-}" >&2
  exit 2
fi
name=$(cat "$1")
rev=$(git rev-parse --short HEAD)
printf 'hello %s\nrev %s\n' "$name" "$rev" > greeting.txt
rm -f stale.txt
echo "wrote $(pwd)/greeting.txt"
"#;

/// The three cases of the example, as the committed `cases.jsonl` has them.
const GREET_CASES: &str = r#"{"tool":"greet","id":"basic","input":{"argv":["name.txt"],"files":{"name.txt":"world\n","stale.txt":"old\n"},"shims":{"git":[{"argv":["rev-parse","--short","HEAD"],"stdout":"abc1234\n"}]}}}
{"tool":"greet","id":"loose","input":{"argv":["name.txt"],"files":{"name.txt":"moon\n"},"shims":{"git":[{"stdout":"def5678\n","repeat":true}]}}}
{"tool":"greet","id":"missing","input":{"argv":["absent.txt"]},"expect_error":true}
"#;

/// The Rust port. `@GREETING@` is the format of the greeting file, `@GIT_ARGS@` the arguments
/// it gives `git`, `@MISSING_EXIT@` its exit status for a missing file. The right values are
/// [`RIGHT`]; each wrong port changes one.
const GREET_RS: &str = r#"use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let file = args.first().cloned().unwrap_or_default();
    if !std::path::Path::new(&file).is_file() {
        eprintln!("no such file: {file}");
        std::process::exit(@MISSING_EXIT@);
    }
    let name = std::fs::read_to_string(&file).unwrap();
    let name = name.trim_end_matches('\n');
    let out = Command::new("git").args([@GIT_ARGS@]).output().expect("git");
    let rev = String::from_utf8_lossy(&out.stdout);
    let rev = rev.trim_end_matches('\n');
    std::fs::write("greeting.txt", format!("@GREETING@")).unwrap();
    let _ = std::fs::remove_file("stale.txt");
    println!("wrote {}/greeting.txt", std::env::current_dir().unwrap().display());
}
"#;

struct Port {
    greeting: &'static str,
    git_args: &'static str,
    missing_exit: &'static str,
}

const RIGHT: Port = Port {
    greeting: r"hello {name}\nrev {rev}\n",
    git_args: r#""rev-parse", "--short", "HEAD""#,
    missing_exit: "2",
};

impl Port {
    fn source(&self) -> String {
        GREET_RS
            .replace("@GREETING@", self.greeting)
            .replace("@GIT_ARGS@", self.git_args)
            .replace("@MISSING_EXIT@", self.missing_exit)
    }
}

/// The roots a process capture declares.
const ROOTS: [&str; 6] = [
    "--path-root",
    "$ROOT",
    "--path-root",
    "$HOME",
    "--path-root",
    "$TMP",
];

fn pk_exe() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_pk")).canonicalize().unwrap()
}

// ---- a project directory, a home of its own, a place for work ------------------------------

struct Project {
    dir: TempDir,
    home: TempDir,
    work: TempDir,
}

impl Project {
    fn new() -> Self {
        Self {
            dir: var_tmp("cp-process-"),
            home: var_tmp("cp-process-home-"),
            work: var_tmp("cp-process-work-"),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, content: &str) -> &Self {
        let path = self.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
        self
    }

    /// `pk` in the project with a `HOME` of its own: its plugin manifest is
    /// `.portkit/plugins.toml` here.
    fn pk(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(pk_exe());
        cmd.args(args)
            .current_dir(self.path())
            .env("HOME", self.home.path())
            .env_remove("PORTKIT_NOW")
            .env_remove("PORTKIT_SEED")
            .env_remove("COWPROOF_SANDBOXED");
        output(&mut cmd)
    }

    /// `pk port exec` of `command` over `cases` (JSONL text), into `fixtures`, with the extra
    /// arguments `extra`.
    fn exec(&self, command: &str, cases: &str, extra: &[&str]) -> Output {
        self.write("cases.jsonl", cases);
        let work = self.work.path().to_string_lossy().into_owned();
        let mut args = vec![
            "port",
            "exec",
            "--cmd",
            command,
            "--cases",
            "cases.jsonl",
            "--out",
            "fixtures",
            "--work-dir",
            &work,
        ];
        args.extend_from_slice(extra);
        self.pk(&args)
    }

    fn fixture(&self, tool: &str, id: &str) -> Value {
        read_json(
            &self
                .path()
                .join("fixtures")
                .join(tool)
                .join(format!("{id}.json")),
        )
    }

    /// Compile `source` as `target/<name>` and register it as the plugin `tool`, wrapped by
    /// `pk port wrap` with the declared roots.
    fn port(&self, name: &str, source: &str, tool: &str) {
        let target = self.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let src = self.path().join(format!("{name}.rs"));
        fs::write(&src, source).unwrap();
        let out = {
            let _g = common::fork_lock();
            Command::new("rustc")
                .args(["--edition", "2021"])
                .arg(&src)
                .arg("-o")
                .arg(target.join(name))
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap()
        };
        assert!(out.status.success(), "rustc: {}", text(&out));
        self.write(
            ".portkit/plugins.toml",
            &format!(
                "[[plugin]]\ncommand = \"{}\"\nargs = [\"port\", \"wrap\", \"--tool\", \"{tool}\", \"--exe\", \"target/{name}\", \"--path-root\", \"$ROOT\", \"--path-root\", \"$HOME\", \"--path-root\", \"$TMP\", \"--work-dir\", \"{}\"]\n",
                pk_exe().display(),
                self.work.path().display(),
            ),
        );
    }

    /// Replay `fixtures` at epsilon 0 on both surfaces; the exit status and the report.
    fn replay(&self) -> (Option<i32>, Value) {
        self.write(
            "pk.toml",
            "[parity]\nepsilon = 0.0\nepsilon_rel = 0.0\nignore_paths = []\nunordered_arrays = false\n",
        );
        let out = self.pk(&[
            "--config",
            "pk.toml",
            "port",
            "replay",
            "--fixtures",
            "fixtures",
            "--surface",
            "both",
            "--epsilon",
            "0",
            "--json",
        ]);
        let report = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("no JSON report ({e}): {}", text(&out)));
        (out.status.code(), report)
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(
        &fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap()
}

/// The paths of the differences the replay found for fixture `id` on `surface`.
fn diff_paths(report: &Value, surface: &str, id: &str) -> Vec<String> {
    report[surface]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["id"] == id)
        .flat_map(|o| o["differences"].as_array().cloned().unwrap_or_default())
        .map(|d| d["path"].as_str().unwrap().to_string())
        .collect()
}

fn status_of(report: &Value, surface: &str, id: &str) -> String {
    report[surface]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == id)
        .unwrap_or_else(|| panic!("no outcome for {id}: {report}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A project that holds the greeting script and has its three cases captured.
fn greet_project() -> Project {
    let project = Project::new();
    project.write("reference/greet.sh", GREET_SH);
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/reference/greet.sh""#,
        GREET_CASES,
        &ROOTS,
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("3 captured, 0 failed"),
        "{}",
        text(&out)
    );
    project
}

// ---- G3: capture ---------------------------------------------------------------------------

#[test]
fn a_script_is_captured_with_its_files_effects_calls_and_a_substituted_path() {
    if !sandbox_available() {
        return;
    }
    let project = greet_project();
    let basic = project.fixture("greet", "basic");

    // The envelope: everything the process did.
    let expected = &basic["expected"];
    assert_eq!(expected["exit"], 0);
    assert_eq!(expected["stderr"], "");
    // It printed the directory it ran in; the fixture holds the declared root, not a temp path.
    assert_eq!(expected["stdout"], "wrote $ROOT/greeting.txt\n");
    let files = &expected["files_after"];
    assert_eq!(
        files["greeting.txt"]["content"],
        "hello world\nrev abc1234\n"
    );
    assert_eq!(files["greeting.txt"]["mode"], 0o644, "umask 022 is pinned");
    assert_eq!(files["greeting.txt"]["size"], 24);
    assert_eq!(
        files["greeting.txt"]["sha256"].as_str().unwrap().len(),
        64,
        "sha256, in hex"
    );
    assert_eq!(files["name.txt"]["content"], "world\n");
    assert!(files.get("stale.txt").is_none());
    assert_eq!(expected["deleted"], json!(["stale.txt"]));
    // The one external program it called, as the shim saw it.
    assert_eq!(
        expected["calls"],
        json!([{"program": "git", "argv": ["rev-parse", "--short", "HEAD"], "env": {}, "stdin": null}])
    );
    // The transform is declared and versioned in the fixture.
    assert_eq!(
        basic["normalized"],
        json!({"name": "path-roots", "version": 1, "roots": ["$HOME", "$ROOT", "$TMP"]})
    );
    assert!(basic["source"].as_str().unwrap().contains("pk port exec"));

    // A case marked `expect_error` records the failure as its fixture (G4).
    let missing = project.fixture("greet", "missing");
    assert_eq!(missing["expect_error"], true);
    assert_eq!(missing["expected"]["exit"], 2);
    assert_eq!(missing["expected"]["stderr"], "no such file: absent.txt\n");
    assert_eq!(missing["expected"]["files_after"], json!({}));
    assert_eq!(missing["expected"]["calls"], json!([]));

    // The same cases captured again give the same fixtures: the roots differ per run, the
    // record does not.
    let again = project.exec(
        r#"sh "$PORTKIT_SRC/reference/greet.sh""#,
        GREET_CASES,
        &[ROOTS.as_slice(), &["--repeat", "3"]].concat(),
    );
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
    assert_eq!(project.fixture("greet", "basic")["expected"], *expected);
}

#[test]
fn a_call_that_reads_stdin_and_the_environment_it_was_given_are_recorded() {
    if !sandbox_available() {
        return;
    }
    let project = Project::new();
    project.write(
        "ref/commit.sh",
        "#!/bin/sh\necho \"msg from stdin\" | git commit -F -\necho \"status=$?\"\n",
    );
    let cases = json!({
        "tool": "commit",
        "id": "one",
        "input": {
            "env": {"GIT_AUTHOR_NAME": "Ada"},
            "record_env": ["GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL"],
            "shims": {"git": [{"argv": ["commit", "-F", "-"], "read_stdin": true, "stdout": "[main 1] ok\n", "exit": 0}]}
        }
    })
    .to_string();
    let out = project.exec(r#"sh "$PORTKIT_SRC/ref/commit.sh""#, &cases, &ROOTS);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let expected = &project.fixture("commit", "one")["expected"];
    assert_eq!(expected["stdout"], "[main 1] ok\nstatus=0\n");
    assert_eq!(
        expected["calls"],
        json!([{
            "program": "git",
            "argv": ["commit", "-F", "-"],
            "env": {"GIT_AUTHOR_NAME": "Ada", "GIT_AUTHOR_EMAIL": null},
            "stdin": "msg from stdin\n"
        }])
    );
}

#[test]
fn the_clock_is_pinned_through_a_date_shim_or_the_capture_refuses() {
    if !sandbox_available() {
        return;
    }
    let project = Project::new();
    project.write("ref/when.sh", "#!/bin/sh\ndate -u +%Y-%m-%dT%H:%M:%S\n");
    // Pinned: the shim answers from PORTKIT_NOW.
    let pinned = json!({"tool": "when", "id": "pinned", "env": {"PORTKIT_NOW": "2026-01-02T03:04:05Z"}, "input": {}}).to_string();
    let out = project.exec(r#"sh "$PORTKIT_SRC/ref/when.sh""#, &pinned, &ROOTS);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let fixture = project.fixture("when", "pinned");
    assert_eq!(fixture["expected"]["stdout"], "2026-01-02T03:04:05\n");
    // The pin is recorded with the fixture, so a recapture does not need the director's shell.
    assert_eq!(
        fixture["env"],
        json!({"PORTKIT_NOW": "2026-01-02T03:04:05Z"})
    );

    // Not pinned: the script read a clock nothing fixed, and recording that would be a flaky
    // fixture. The capture says so and writes nothing.
    let unpinned = json!({"tool": "when", "id": "unpinned", "input": {}}).to_string();
    let out = project.exec(r#"sh "$PORTKIT_SRC/ref/when.sh""#, &unpinned, &ROOTS);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("PORTKIT_NOW is not set"),
        "{}",
        text(&out)
    );
    assert!(!project.path().join("fixtures/when/unpinned.json").exists());
}

#[test]
fn a_capture_that_would_record_a_flaky_fixture_is_refused_loudly() {
    if !sandbox_available() {
        return;
    }
    let project = Project::new();
    let case = |id: &str, input: Value| json!({"tool": "t", "id": id, "input": input}).to_string();

    // The run's directory is printed and no root is declared: the two runs differ.
    project.write("ref/where.sh", "#!/bin/sh\npwd\n");
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/where.sh""#,
        &case("pwd", json!({})),
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("not deterministic"), "{}", text(&out));
    assert!(
        text(&out).contains("/stdout"),
        "the field is named: {}",
        text(&out)
    );
    assert!(!project.path().join("fixtures/t/pwd.json").exists());
    // With the root declared, the same script is a fixture.
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/where.sh""#,
        &case("pwd", json!({})),
        &["--path-root", "$ROOT"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(project.fixture("t", "pwd")["expected"]["stdout"], "$ROOT\n");

    // Random bytes differ per run whatever is declared. (`$$` is no test of this: on Linux each
    // run has its own PID namespace, so it repeats.)
    project.write(
        "ref/random.sh",
        "#!/bin/sh\nhead -c 8 /dev/urandom | od -An -tx1\n",
    );
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/random.sh""#,
        &case("random", json!({})),
        &ROOTS,
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("not deterministic"), "{}", text(&out));

    // A real program, with no network to use: it fails, the same way every time.
    project.write(
        "ref/net.sh",
        "#!/bin/sh\ncurl -s --max-time 5 http://127.0.0.1:9/ || echo failed\n",
    );
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/net.sh""#,
        &case("curl", json!({})),
        &ROOTS,
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        project.fixture("t", "curl")["expected"]["stdout"],
        "failed\n"
    );

    // A program the case declared but did not script for this call.
    project.write("ref/git.sh", "#!/bin/sh\ngit status\n");
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/git.sh""#,
        &case("unscripted", json!({"shims": {"git": [{"argv": ["log"]}]}})),
        &ROOTS,
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("`git status`"), "{}", text(&out));

    // A failure the case did not expect, and a success where one was expected.
    project.write("ref/exit.sh", "#!/bin/sh\nexit \"${1:-0}\"\n");
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/exit.sh""#,
        &case("fails", json!({"argv": ["3"]})),
        &ROOTS,
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("exited 3") && text(&out).contains("expect_error"),
        "{}",
        text(&out)
    );
    let must_fail = json!({"tool": "t", "id": "ok", "input": {}, "expect_error": true}).to_string();
    let out = project.exec(r#"sh "$PORTKIT_SRC/ref/exit.sh""#, &must_fail, &ROOTS);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("expects an error but the reference exited 0"),
        "{}",
        text(&out)
    );

    // A typo in the input is an error, not a case that silently ignores it.
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/exit.sh""#,
        &case("typo", json!({"stdn": "x"})),
        &ROOTS,
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("stdn"), "{}", text(&out));
}

#[test]
fn the_network_is_denied_to_the_reference_and_the_capture_checks_it_first() {
    if !sandbox_available() {
        return;
    }
    // A listener the test holds. A process that could connect to it would be on the host's
    // network; the harness's own probe is the tool the script uses to try.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = listener.local_addr().unwrap().to_string();

    let project = Project::new();
    project.write(
        "ref/net.sh",
        "#!/bin/sh\n\"$PK_BIN\" port net-probe \"$PK_TARGET\" 2>/dev/null\necho \"status=$?\"\n",
    );
    let cases = json!({
        "tool": "net",
        "id": "loopback",
        "env": {"PK_BIN": pk_exe().to_string_lossy(), "PK_TARGET": target},
        "input": {}
    })
    .to_string();
    let out = project.exec(r#"sh "$PORTKIT_SRC/ref/net.sh""#, &cases, &ROOTS);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // The attempt failed the same way twice (the capture runs it twice), and nothing arrived.
    assert_eq!(
        project.fixture("net", "loopback")["expected"]["stdout"],
        "denied\nstatus=0\n"
    );
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("a connection reached the test's listener: {other:?}"),
    }
}

#[test]
fn a_run_that_is_not_inside_a_sandbox_cannot_claim_to_inherit_one() {
    if !sandbox_available() {
        return;
    }
    let project = Project::new();
    project.write("ref/ok.sh", "#!/bin/sh\necho hi\n");
    let case = json!({"tool": "t", "id": "x", "input": {}}).to_string();
    let out = project.exec(
        r#"sh "$PORTKIT_SRC/ref/ok.sh""#,
        &case,
        &["--sandbox", "inherited"],
    );
    let said = text(&out);
    if out.status.code() == Some(0) {
        // Only a host with no network at all passes the probe; say so rather than pass vacuously.
        let interfaces = fs::read_to_string("/proc/net/dev").unwrap_or_default();
        let outside: Vec<_> = interfaces
            .lines()
            .skip(2)
            .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim().to_string()))
            .filter(|n| n != "lo")
            .collect();
        assert!(
            cfg!(target_os = "linux") && outside.is_empty(),
            "`--sandbox inherited` outside a sandbox passed on a host with a network: {said}"
        );
    } else {
        assert_eq!(out.status.code(), Some(1), "{said}");
        assert!(said.contains("NOT denied"), "{said}");
        assert!(!project.path().join("fixtures/t/x.json").exists());
    }
}

// ---- G3: the Rust port side, G4, G13: replay ------------------------------------------------

#[test]
fn a_right_port_passes_and_wrong_ones_are_refuted_naming_the_field() {
    if !sandbox_available() {
        return;
    }
    let project = greet_project();

    // The right port answers every fixture, on both surfaces, at epsilon 0.
    project.port("greet", &RIGHT.source(), "greet");
    let (code, report) = project.replay();
    assert_eq!(code, Some(0), "{report}");
    for surface in ["direct", "mcp"] {
        assert_eq!(report[surface]["passed"], 3, "{surface}: {report}");
        assert_eq!(report[surface]["failed"], 0);
    }

    // A port that writes the wrong content is refuted on the file, and its hash.
    let wrong_content = Port {
        greeting: r"hello {name}!\nrev {rev}\n",
        ..RIGHT
    };
    project.port("greet", &wrong_content.source(), "greet");
    let (code, report) = project.replay();
    assert_eq!(code, Some(1), "{report}");
    let basic = diff_paths(&report, "direct", "basic");
    assert!(
        basic.contains(&"/files_after/greeting.txt/sha256".to_string())
            && basic.contains(&"/files_after/greeting.txt/content".to_string()),
        "{basic:?}"
    );
    assert_eq!(status_of(&report, "direct", "missing"), "pass");
    assert_eq!(status_of(&report, "mcp", "basic"), "fail");

    // A port that calls git with another argv is refuted on `calls`. `loose` is answered
    // whatever it is asked, so nothing else differs there.
    let wrong_argv = Port {
        git_args: r#""rev-parse", "HEAD""#,
        ..RIGHT
    };
    project.port("greet", &wrong_argv.source(), "greet");
    let (code, report) = project.replay();
    assert_eq!(code, Some(1), "{report}");
    let loose = diff_paths(&report, "direct", "loose");
    assert!(!loose.is_empty());
    assert!(
        loose.iter().all(|p| p.starts_with("/calls/0/argv")),
        "only the call differs: {loose:?}"
    );
    assert_eq!(status_of(&report, "direct", "missing"), "pass");

    // A port that exits 1 where the script exits 2 on a must-reject case.
    let wrong_exit = Port {
        missing_exit: "1",
        ..RIGHT
    };
    project.port("greet", &wrong_exit.source(), "greet");
    let (code, report) = project.replay();
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(diff_paths(&report, "direct", "missing"), ["/exit"]);
    assert_eq!(status_of(&report, "direct", "basic"), "pass");
}

#[test]
fn a_fixture_whose_transform_this_build_does_not_know_is_an_error_not_a_pass() {
    if !sandbox_available() {
        return;
    }
    let project = greet_project();
    project.port("greet", &RIGHT.source(), "greet");
    let path = project.path().join("fixtures/greet/basic.json");
    let mut fixture = read_json(&path);
    fixture["normalized"]["version"] = json!(2);
    fs::write(&path, fixture.to_string()).unwrap();
    let (code, report) = project.replay();
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(status_of(&report, "direct", "basic"), "error");
    let error = report["direct"]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == "basic")
        .unwrap()["error"]
        .to_string();
    assert!(
        error.contains("unknown normalizer") && error.contains("v2"),
        "{error}"
    );
    // The other fixtures still replay.
    assert_eq!(status_of(&report, "direct", "loose"), "pass");
}

#[test]
fn a_port_that_leaves_the_declared_roots_out_is_refuted_on_the_path() {
    if !sandbox_available() {
        return;
    }
    let project = greet_project();
    project.port("greet", &RIGHT.source(), "greet");
    // The same plugin without `--path-root`: it prints the run's real directory.
    let manifest = project.path().join(".portkit/plugins.toml");
    let text = fs::read_to_string(&manifest).unwrap();
    let bare = text
        .replace(", \"--path-root\", \"$ROOT\"", "")
        .replace(", \"--path-root\", \"$HOME\"", "")
        .replace(", \"--path-root\", \"$TMP\"", "");
    assert_ne!(bare, text);
    fs::write(&manifest, bare).unwrap();
    let (code, report) = project.replay();
    assert_eq!(code, Some(1), "{report}");
    assert!(diff_paths(&report, "direct", "basic").contains(&"/stdout".to_string()));
    let actual = report["direct"]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == "basic")
        .unwrap()["differences"][0]["actual"]
        .to_string();
    assert!(
        actual.contains("greeting.txt") && !actual.contains("$ROOT"),
        "{actual}"
    );
}

#[test]
fn pk_port_wrap_describes_itself_as_a_plugin() {
    let project = Project::new();
    let out = project.pk(&["port", "wrap", "--tool", "greet", "--portkit-spec"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let spec: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(spec["name"], "greet");
    assert_eq!(spec["input_schema"], json!({"type": "object"}));
    // Asked to run with no port named, it says what it needs.
    let out = project.pk(&["port", "wrap", "--tool", "greet"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("--exe"), "{}", text(&out));
}

// ---- G2 and G4 on the function path --------------------------------------------------------

#[test]
fn pk_port_capture_sets_the_directory_and_environment_and_records_a_must_reject_case() {
    let project = Project::new();
    project.write("work/.keep", "");
    project.write(
        "cases.jsonl",
        &[
            json!({"tool": "t", "id": "plain", "input": {}}),
            json!({"tool": "t", "id": "case", "input": {}, "env": {"A": "from-case"}}),
            json!({"tool": "t", "id": "bad", "input": {}, "expect_error": true, "env": {"FAIL": "1"}}),
        ]
        .map(|c| c.to_string())
        .join("\n"),
    );
    // Prints what it was given, and fails when asked to (the third case sets `FAIL`).
    let script = r#"if [ -n "${FAIL:-}" ]; then echo "refused" >&2; exit 4; fi; printf '{"cwd":"%s","a":"%s","home":"%s"}' "$(pwd -P)" "$A" "${HOME-unset}""#;
    let out = project.pk(&[
        "port",
        "capture",
        "--cmd",
        script,
        "--cases",
        "cases.jsonl",
        "--out",
        "fixtures",
        "--cwd",
        "work",
        "--env",
        "A=from-capture",
        "--clear-env",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let work = project.path().join("work").canonicalize().unwrap();
    let plain = project.fixture("t", "plain");
    assert_eq!(plain["expected"]["cwd"], work.to_string_lossy().as_ref());
    assert_eq!(plain["expected"]["a"], "from-capture");
    assert_eq!(
        plain["expected"]["home"], "unset",
        "--clear-env: nothing inherited"
    );
    let case = project.fixture("t", "case");
    assert_eq!(case["expected"]["a"], "from-case");
    assert_eq!(case["env"], json!({"A": "from-case"}));
    let bad = project.fixture("t", "bad");
    assert_eq!(bad["expect_error"], true);
    assert_eq!(
        bad["expected"],
        json!({"error": {"exit": 4, "message": "refused"}})
    );
}

// ---- the committed example and a whole `cowproof run` --------------------------------------

fn example() -> PathBuf {
    workspace::root().unwrap().join("fixtures/port-process")
}

#[test]
fn the_committed_example_is_what_the_script_does_today() {
    if workspace::skipped("the_committed_example_is_what_the_script_does_today") {
        return;
    }
    // The script and the cases in this file are the committed ones.
    let committed = example().join("project");
    assert_eq!(
        fs::read_to_string(committed.join("reference/greet.sh")).unwrap(),
        GREET_SH
    );
    assert_eq!(
        fs::read_to_string(committed.join("ports/greet/cases.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    if !sandbox_available() {
        return;
    }
    // Recapturing gives the committed fixtures (the machine and the time aside): a drift guard
    // on the harness, the script and the fixtures together, on whatever platform runs it.
    let project = Project::new();
    copy_tree(&committed, project.path());
    let out = project.pk(&[
        "port",
        "exec",
        "--cmd",
        r#"sh "$PORTKIT_SRC/reference/greet.sh""#,
        "--cases",
        "ports/greet/cases.jsonl",
        "--out",
        "fresh",
        "--path-root",
        "$ROOT",
        "--path-root",
        "$HOME",
        "--path-root",
        "$TMP",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    for id in ["basic", "loose", "missing"] {
        let strip = |mut v: Value| {
            let o = v.as_object_mut().unwrap();
            o.remove("captured_at");
            o.remove("source");
            v
        };
        assert_eq!(
            strip(read_json(
                &project
                    .path()
                    .join("fresh/greet")
                    .join(format!("{id}.json"))
            )),
            strip(read_json(
                &committed
                    .join("ports/greet/fixtures/greet")
                    .join(format!("{id}.json"))
            )),
            "{id}"
        );
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            copy_tree(&entry.path(), &dest);
        } else if kind.is_file() {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

const PACKET_ID: &str = "port-1";

fn packet(id: &str) -> String {
    let text = fs::read_to_string(example().join("packet.md")).unwrap();
    assert!(text.contains(&format!("\"id\":\"{PACKET_ID}\"")));
    text.replace(
        &format!("\"id\":\"{PACKET_ID}\""),
        &format!("\"id\":\"{id}\""),
    )
}

/// What the fake builder does: write `source` as the port, register it as a plugin that is
/// the lane's own `cowproof pk port wrap`, and run the build check.
fn builder_body(source: &str) -> String {
    format!(
        "mkdir -p tools target .portkit\ncat > tools/greet.rs <<'RUST'\n{source}RUST\n\
         printf '[[plugin]]\\ncommand = \"%s\"\\nargs = [\"pk\", \"port\", \"wrap\", \"--tool\", \"greet\", \"--exe\", \"target/greet\", \"--path-root\", \"$ROOT\", \"--path-root\", \"$HOME\", \"--path-root\", \"$TMP\"]\\n' \"$cp_bin\" > .portkit/plugins.toml\n{}",
        run_checks(&["build"]),
    )
}

#[test]
fn a_process_port_packet_with_a_shell_reference_is_proved() {
    if workspace::skipped("a_process_port_packet_with_a_shell_reference_is_proved") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let lane = Lane::from_project(
        &builder_body(&RIGHT.source()),
        &example().join("project"),
        &packet,
    );
    let heldout = example().join("heldout/heldout.toml");
    let out = lane.run(&[Path::new("--heldout"), &heldout]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["failedGates"], json!([]), "{verdict}");

    let gates: Value =
        serde_json::from_str(&fs::read_to_string(lane.capsule_dir().join("gates.json")).unwrap())
            .unwrap();
    let port = gates["gates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "port_replay")
        .unwrap();
    assert_eq!(port["passed"], true, "{port}");
    assert!(port["evidence"].to_string().contains("3 fixture"), "{port}");

    // The capsule records the process adapter, the reference and the declared roots.
    let capsule = cowproof_prove::Capsule::read(&lane.capsule_dir()).unwrap();
    let port = capsule.port.expect("a port capsule");
    assert_eq!(
        (port.lang.as_str(), port.adapter.as_str()),
        ("shell", "process")
    );
    assert_eq!(
        port.reference.as_ref().unwrap().cmd,
        r#"sh "$PORTKIT_SRC/reference/greet.sh""#
    );
    assert_eq!(port.path_roots, ["$ROOT", "$HOME", "$TMP"]);
    let result = port.result.expect("the replay is recorded");
    assert!(result.success, "{:?}", result.failures);
    assert_eq!(result.fixture_count, 3);
    assert_eq!(result.surfaces["direct"].passed, 3);
    assert_eq!(result.surfaces["mcp"].passed, 3);
    // The held-out cases were captured from the script in the verifier's sandbox with
    // `pk port exec` (a 3-line script, a git shim, a must-reject case) and the port passed.
    assert_eq!(
        result.held_out.state, "passed",
        "{:?}",
        result.held_out.reason
    );
    assert_eq!(result.held_out.cases, 2);
}

#[test]
fn a_process_port_that_writes_the_wrong_file_is_refuted_by_the_replay_gate() {
    if workspace::skipped("a_process_port_that_writes_the_wrong_file_is_refuted_by_the_replay_gate")
    {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let wrong = Port {
        greeting: r"hello {name}!\nrev {rev}\n",
        ..RIGHT
    };
    let lane = Lane::from_project(
        &builder_body(&wrong.source()),
        &example().join("project"),
        &packet,
    );
    let heldout = example().join("heldout/heldout.toml");
    let out = lane.run(&[Path::new("--heldout"), &heldout]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert!(
        verdict["failedGates"].to_string().contains("port_replay"),
        "{verdict}"
    );
    let capsule = cowproof_prove::Capsule::read(&lane.capsule_dir()).unwrap();
    let result = capsule.port.unwrap().result.unwrap();
    assert!(!result.success);
    let failures = result.failures.join("\n");
    assert!(failures.contains("/files_after/greeting.txt"), "{failures}");
    // The held-out case that reads a file is refuted the same way; the must-reject one passes.
    assert_eq!(result.held_out.state, "failed", "{:?}", result.held_out);
    assert!(
        result
            .held_out
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("greet/ada"),
        "{:?}",
        result.held_out.reason
    );
}
