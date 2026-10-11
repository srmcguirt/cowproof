//! No Rust file in the workspace runs the `kill` program (2026-10-11).
//!
//! Ubuntu 24.04's `/usr/bin/kill` (procps 2:4.0.4-4ubuntu3.3) keeps only the first digit of a
//! negative id that is not preceded by `--`: `kill -KILL -3322` is `kill(-3, SIGKILL)`, and a
//! process group that starts with 1 is `kill(-1, SIGKILL)`, which ends every process of the
//! user. A test did exactly that eight times in a day. Signals go through `kill(2)` in
//! `cowproof_prove::runner` (`signal_pid`, `signal_group`, `pid_exists`, `group_exists`), which
//! refuses the ids that would reach more than the caller meant.
//!
//! This test reads every `.rs` file under `crates/` and fails, naming the file and the line,
//! when a line that is not a comment names the program. The patterns below are built from two
//! halves so that this file does not match itself.

use std::fs;
use std::path::{Path, PathBuf};

/// A needle made of two halves, so the source of this file never holds it whole.
fn needle(a: &str, b: &str) -> String {
    format!("{a}{b}")
}

/// What is forbidden on a line of code: the program started by name or by path, the family of
/// tools that signal by name (`pkill`, `killall`), the program named as an argument to a
/// command runner, and a shell string that runs it with a signal or a negative id.
fn forbidden() -> Vec<(String, String)> {
    let k = "ki";
    let l = "ll";
    vec![
        (
            needle(&format!("Command::new(\"{k}"), &format!("{l}\")")),
            "starts the program".into(),
        ),
        (
            needle(&format!("\"/bin/{k}"), &format!("{l}\"")),
            "names /bin path".into(),
        ),
        (
            needle(&format!("\"/usr/bin/{k}"), &format!("{l}\"")),
            "names /usr/bin path".into(),
        ),
        (
            needle("p", &format!("{k}{l}")),
            "the by-name signaller with a p prefix".into(),
        ),
        (
            needle(&format!("{k}{l}"), "all"),
            "the by-name signaller with an all suffix".into(),
        ),
        (
            needle(&format!("\"{k}"), &format!("{l}\"")),
            "names the program as a string".into(),
        ),
        (
            needle(&format!("{k}{l} -"), ""),
            "a shell string that runs it with a flag or a negative id".into(),
        ),
    ]
}

/// A line that is exempt, by exact file (relative to the workspace root) and the exact text the
/// line has to hold.
///
/// The one entry is the documentation test of the old shell line in `src/host_agent.rs`: it runs
/// `sh -c 'kill -0 -- "$0"'` against the pid of a child it started and reaped, to show that
/// dash answers "Illegal number" and never "No such process". It is signal 0 against a positive
/// pid, so it delivers nothing, and it is the evidence for why `kill(2)` replaced the shell.
const ALLOWED: [(&str, &str); 1] = [(
    "crates/cowproof-cli/src/host_agent.rs",
    r##"-0 -- "$0" 2>&1"#, &pid]"##,
)];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every offence in `text`, as `line number: reason: the line`, comments skipped.
fn offences(rel: &str, text: &str) -> Vec<String> {
    let needles = forbidden();
    let mut found = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for (needle, why) in &needles {
            if line.contains(needle.as_str()) {
                let allowed = ALLOWED
                    .iter()
                    .any(|(path, text)| *path == rel && line.contains(text));
                if !allowed {
                    found.push(format!("{rel}:{}: {why}: {}", i + 1, line.trim()));
                }
                break;
            }
        }
    }
    found
}

#[test]
fn no_rust_file_runs_the_kill_program() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    assert!(files.len() > 50, "found only {} files", files.len());
    let mut found = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy();
        found.extend(offences(&rel, &fs::read_to_string(file).unwrap()));
    }
    assert!(
        found.is_empty(),
        "signal through cowproof_prove::runner (kill(2)), never the kill program:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_scan_catches_each_form_and_skips_comments() {
    let k = "ki";
    let l = "ll";
    for code in [
        format!("let _ = std::process::Command::new(\"{k}{l}\");"),
        format!("Command::new(\"/bin/{k}{l}\")"),
        format!("Command::new(\"/usr/bin/{k}{l}\")"),
        format!("Command::new(\"p{k}{l}\")"),
        format!("runner.output(\"{k}{l}\", &[\"-0\"])"),
        format!("sh.arg(\"{k}{l} -9 -- -12\")"),
    ] {
        assert_eq!(offences("x.rs", &code).len(), 1, "missed: {code}");
    }
    assert!(offences("x.rs", &format!("// run `{k}{l} -0 1` by hand")).is_empty());
    assert!(offences("x.rs", "child.kill().unwrap();").is_empty());
}
