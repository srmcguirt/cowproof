//! `cowproof host setup` (D27): run by the owner of a remote host, it prints the
//! `authorized_keys` line that locks the director's key to `host-agent --forced`, the
//! director-side hosts.json entry and this host's doctor, and writes nothing.
//!
//! The real binary, a `HOME` of its own under `/var/tmp`, and synthetic keys: nothing here is
//! anyone's key, and the "private key" is lettered filler.

#[allow(dead_code)] // this file needs only a few of the shared helpers
mod common;

use common::{fork_lock, output, var_tmp};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// An ed25519 public key blob made up for the tests: the type string, then 32 filler bytes.
const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9g";
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9g director@example.invalid";

struct Setup {
    work: tempfile::TempDir,
    home: tempfile::TempDir,
    /// The binary under test at its canonical path: that is the path `setup` prints.
    cowproof: PathBuf,
}

impl Setup {
    fn new() -> Self {
        Setup {
            work: var_tmp("cp-hostsetup-work-"),
            home: var_tmp("cp-hostsetup-home-"),
            cowproof: fs::canonicalize(env!("CARGO_BIN_EXE_cowproof")).unwrap(),
        }
    }

    fn key_file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.work.path().join(name);
        fs::write(&path, text).unwrap();
        path
    }

    /// `cowproof host setup --key <key> <extra>` with the working directory and HOME of its
    /// own. Without a `--claude` in `extra` it is told a `claude` that does not exist, so the
    /// real one on this machine is never run.
    fn run(&self, key: &Path, extra: &[&str]) -> Output {
        let mut cmd = Command::new(&self.cowproof);
        cmd.args(["host", "setup", "--key"]).arg(key).args(extra);
        if !extra.contains(&"--claude") {
            cmd.arg("--claude")
                .arg(self.work.path().join("no-such-claude"));
        }
        output(
            cmd.current_dir(self.work.path())
                .env("HOME", self.home.path())
                .env_remove("ANTHROPIC_API_KEY"),
        )
    }

    fn home_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.home.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The pretty-printed JSON object in the output: from the first line that is `{` to the next
/// line that is `}`.
fn hosts_entry(text: &str) -> Value {
    let block: Vec<&str> = text
        .lines()
        .skip_while(|l| *l != "{")
        .take_while(|l| *l != "}")
        .chain(std::iter::once("}"))
        .collect();
    serde_json::from_str(&block.join("\n")).unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn write_executable(path: &Path, script: &str) {
    let _g = fork_lock();
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn the_printed_line_is_exact_and_names_this_binary_and_the_directors_key() {
    let s = Setup::new();
    let key = s.key_file("director.pub", &format!("{KEY}\n"));
    let out = s.run(&key, &[]);
    let text = stdout(&out);
    let expected = format!(
        "command=\"{} host-agent --forced\",restrict,port-forwarding,permitopen=\"127.0.0.1:1\",permitlisten=\"127.0.0.1:1\" {KEY}",
        s.cowproof.display()
    );
    // The line, alone on its own line.
    assert!(
        text.lines().any(|l| l == expected),
        "{expected}\n---\n{text}"
    );
    // Where to put it: the authorized_keys of the user who runs it.
    assert!(
        text.contains(&format!("{}/.ssh/authorized_keys", s.home.path().display())),
        "{text}"
    );
    // The key appears once and only in that line: no second, unrestricted copy.
    assert_eq!(text.matches(BLOB).count(), 1, "{text}");
}

#[test]
fn the_hosts_entry_holds_this_machines_absolute_paths() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let claude = s.work.path().join("claude");
    write_executable(
        &claude,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"fake-claude 9.9.9\"; exit 0; fi\nexit 99\n",
    );
    let out = s.run(
        &key,
        &[
            "--claude",
            claude.to_str().unwrap(),
            "--ssh",
            "me@host.example",
            "--alias",
            "box",
        ],
    );
    let text = stdout(&out);
    let entry = hosts_entry(&text);
    assert_eq!(
        entry,
        serde_json::json!({"box": {
            "ssh": "me@host.example",
            "cowproof": s.cowproof,
            "claude": claude,
        }})
    );
    // And this host's doctor, run here: protocol, the sandbox, and the claude it was given.
    assert!(text.contains("protocol: 2"), "{text}");
    assert!(text.contains("claude: ok - fake-claude 9.9.9"), "{text}");
    assert!(text.contains("sandbox: "), "{text}");
    // The same entry the director's own parser would take must at least be valid JSON
    // with absolute paths.
    assert!(Path::new(entry["box"]["cowproof"].as_str().unwrap()).is_absolute());
}

#[test]
fn a_host_without_claude_is_not_ready_and_says_so() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let out = s.run(&key, &[]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("claude: FAILED"), "{text}");
    assert!(text.contains("Not ready"), "{text}");
    // The line is still printed: the owner can fix claude later.
    assert!(text.contains("restrict,port-forwarding"), "{text}");
    assert!(
        text.contains("permitopen=\"127.0.0.1:1\",permitlisten=\"127.0.0.1:1\""),
        "{text}"
    );
}

#[test]
fn setup_writes_nothing() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let before = s.home_entries();
    let _ = s.run(&key, &[]);
    assert_eq!(s.home_entries(), before, "setup wrote into HOME");
    assert!(!s.home.path().join(".ssh").exists());
}

#[test]
fn a_private_key_is_refused_loudly_and_never_printed() {
    let s = Setup::new();
    let filler = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop";
    // (Built from parts: the repository's scrub check looks for the armor line itself.)
    let kind = "OPENSSH";
    let private = s.key_file(
        "id_ed25519",
        &format!("-----BEGIN {kind} PRIVATE KEY-----\n{filler}\n{filler}\n-----END {kind} PRIVATE KEY-----\n"),
    );
    let out = s.run(&private, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    let err = stderr(&out);
    assert!(err.contains("PRIVATE key"), "{err}");
    assert!(
        !err.contains(filler),
        "the error quotes the key file: {err}"
    );
}

#[test]
fn a_file_with_two_keys_or_none_or_options_is_refused() {
    let s = Setup::new();
    let other = KEY.replace("director@example.invalid", "second@example.invalid");
    for (name, text, why) in [
        ("two.pub", format!("{KEY}\n{other}\n"), "2 lines"),
        ("none.pub", "\n\n".to_string(), "empty"),
        (
            "options.pub",
            format!("command=\"/bin/sh\" {KEY}\n"),
            "key type",
        ),
        ("junk.pub", "hello\n".to_string(), "key type"),
    ] {
        let out = s.run(&s.key_file(name, &text), &[]);
        assert_eq!(out.status.code(), Some(1), "{name}");
        assert!(out.stdout.is_empty(), "{name}: {}", stdout(&out));
        assert!(stderr(&out).contains(why), "{name}: {}", stderr(&out));
    }
    let out = s.run(&s.work.path().join("missing.pub"), &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}
