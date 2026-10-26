//! `cowproof host setup` (D27): run by the owner of a remote host, it prints the
//! `authorized_keys` line that locks the director's key to `host-agent --forced`, the
//! director-side hosts.json entry and this host's doctor, and writes nothing.
//!
//! The real binary, a `HOME` of its own under `/var/tmp`, and synthetic keys: nothing here is
//! anyone's key, and the "private key" is lettered filler.

#[allow(dead_code, reason = "this file needs only a few of the shared helpers")]
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
        let mut args = vec!["--key", key.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.run_args(&args, &[])
    }

    /// `cowproof host setup <args>`, with more environment variables, and a `--claude` that
    /// does not exist unless `args` gives one.
    fn run_args(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(&self.cowproof);
        cmd.args(["host", "setup"]).args(args);
        if !args.contains(&"--claude") {
            cmd.arg("--claude")
                .arg(self.work.path().join("no-such-claude"));
        }
        output(
            cmd.current_dir(self.work.path())
                .env("HOME", self.home.path())
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("ANTHROPIC_API_KEY")
                .envs(env.iter().copied()),
        )
    }

    /// An executable `claude` that answers `--version`, at `name` in the work directory.
    fn claude(&self, name: &str) -> PathBuf {
        let path = self.work.path().join(name);
        write_executable(
            &path,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"{name} 9.9.9\"; exit 0; fi\nexit 99\n"
            ),
        );
        path
    }

    /// The config `--write-config` writes, in this home.
    fn config_file(&self) -> PathBuf {
        self.home.path().join(".config/cowproof/host.toml")
    }

    /// `host-agent --forced` asked to run `asked`, in this home.
    fn forced(&self, asked: &str) -> Output {
        output(
            Command::new(&self.cowproof)
                .args(["host-agent", "--forced"])
                .current_dir(self.work.path())
                .env("HOME", self.home.path())
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("ANTHROPIC_API_KEY")
                .env("SSH_ORIGINAL_COMMAND", asked),
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

/// The file's lines that are not comments.
fn settings_of(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn without_write_config_the_config_is_only_shown() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let claude = s.claude("claude");
    let out = s.run(&key, &["--claude", claude.to_str().unwrap()]);
    let text = stdout(&out);
    let root = s.home.path().join(".cache/cowproof/remote-lanes");
    assert!(
        text.contains(&format!("claude = \"{}\"", claude.display())),
        "{text}"
    );
    assert!(
        text.contains(&format!("root = \"{}\"", root.display())),
        "{text}"
    );
    assert!(
        text.contains(&s.config_file().display().to_string()),
        "{text}"
    );
    assert!(text.contains("(not written)"), "{text}");
    assert!(text.contains("host setup --write-config"), "{text}");
    assert!(!s.config_file().exists());
    assert!(
        !s.home.path().join(".config").exists(),
        "setup made a directory"
    );
}

#[test]
fn write_config_writes_exactly_the_resolved_paths_privately() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let claude = s.claude("claude");
    let out = s.run(
        &key,
        &["--claude", claude.to_str().unwrap(), "--write-config"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("(written)"), "{}", stdout(&out));

    let file = s.config_file();
    let written = fs::read_to_string(&file).unwrap();
    let root = s.home.path().join(".cache/cowproof/remote-lanes");
    assert_eq!(
        settings_of(&written),
        [
            format!("claude = \"{}\"", claude.display()),
            format!("root = \"{}\"", root.display()),
        ],
        "{written}"
    );
    // Whatever else is in it is a comment, and the whole is TOML that says the same.
    assert!(
        written
            .lines()
            .all(|l| l.starts_with('#') || l.starts_with("claude = ") || l.starts_with("root = ")),
        "{written}"
    );
    let parsed: toml::Table = written.parse().unwrap();
    assert_eq!(parsed["claude"].as_str(), claude.to_str());
    assert_eq!(parsed["root"].as_str(), root.to_str());
    assert_eq!(parsed.len(), 2);
    // Only the owner can write it, and only the owner can write its directory.
    assert_eq!(mode_of(&file), 0o600);
    assert_eq!(mode_of(file.parent().unwrap()), 0o700);
    // The other printed parts are still there.
    let text = stdout(&out);
    assert!(text.contains("restrict,port-forwarding"), "{text}");
    assert!(text.contains("claude: ok - claude 9.9.9"), "{text}");
}

#[test]
fn write_config_never_overwrites_without_force() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let first = s.claude("first-claude");
    let second = s.claude("second-claude");
    let out = s.run(
        &key,
        &["--claude", first.to_str().unwrap(), "--write-config"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let before = fs::read_to_string(s.config_file()).unwrap();

    // A second run with another claude: refused, with nothing else printed, file untouched.
    let out = s.run(
        &key,
        &["--claude", second.to_str().unwrap(), "--write-config"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    let err = stderr(&out);
    assert!(
        err.contains("--force") && err.contains("left as it was"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(s.config_file()).unwrap(), before);

    // Shown without the flag: the file that is there is named and `--force` is suggested.
    let out = s.run(&key, &["--claude", second.to_str().unwrap()]);
    assert!(
        stdout(&out).contains("--write-config --force"),
        "{}",
        stdout(&out)
    );
    assert_eq!(fs::read_to_string(s.config_file()).unwrap(), before);

    let out = s.run(
        &key,
        &[
            "--claude",
            second.to_str().unwrap(),
            "--write-config",
            "--force",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let after = fs::read_to_string(s.config_file()).unwrap();
    assert!(
        after.contains("second-claude") && !after.contains("first-claude"),
        "{after}"
    );
    assert_eq!(mode_of(&s.config_file()), 0o600);
}

#[test]
fn write_config_honours_xdg_config_home_and_needs_no_key() {
    let s = Setup::new();
    let xdg = var_tmp("cp-hostsetup-xdg-");
    let claude = s.claude("claude");
    let out = s.run_args(
        &["--write-config", "--claude", claude.to_str().unwrap()],
        &[("XDG_CONFIG_HOME", xdg.path())],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let file = xdg.path().join("cowproof/host.toml");
    assert!(file.is_file());
    assert!(!s.config_file().exists(), "HOME's place was used");
    // The file is where `setup` was told, and says that a forced key will not read it there.
    let text = stdout(&out);
    assert!(text.contains("WARNING"), "{text}");
    assert!(
        text.contains(&s.config_file().display().to_string())
            && text.contains("forced key reads only"),
        "{text}"
    );
    // No key: no authorized_keys line and no hosts.json entry, only the config and the check.
    assert!(
        !text.contains("authorized_keys") && !text.contains("command=\""),
        "{text}"
    );
    assert!(text.contains(&file.display().to_string()), "{text}");
    assert!(text.contains("claude: ok"), "{text}");
}

#[test]
fn write_config_without_a_claude_writes_nothing_and_says_why() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    // `run` gives a claude that does not exist.
    let out = s.run(&key, &["--write-config"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    assert!(stderr(&out).contains("--claude"), "{}", stderr(&out));
    assert!(!s.home.path().join(".config").exists());
}

#[test]
fn the_flags_fit_together() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    // `--force` is only for `--write-config`; with neither a key nor `--write-config` there is
    // nothing to do. Both are usage errors, and nothing is written.
    for args in [
        vec!["--key", key.to_str().unwrap(), "--force"],
        vec![],
        vec!["--force"],
    ] {
        let out = s.run_args(&args, &[]);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(out.stdout.is_empty());
    }
    assert!(!s.home.path().join(".config").exists());
}

#[test]
fn what_setup_writes_is_what_a_forced_key_then_trusts_until_someone_else_can_write_it() {
    let s = Setup::new();
    let key = s.key_file("director.pub", KEY);
    let claude = s.claude("claude");
    let out = s.run(
        &key,
        &["--claude", claude.to_str().unwrap(), "--write-config"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

    // Forced doctor, with no arguments: the written claude is the one checked.
    let doctor = s.forced("cowproof host-agent doctor");
    let json: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(json["config"], "ok", "{json}");
    assert!(
        json["claude_detail"]
            .as_str()
            .unwrap()
            .contains("claude 9.9.9"),
        "{json}"
    );

    // Someone else could now write the file (0666): the key refuses to trust it.
    fs::set_permissions(s.config_file(), fs::Permissions::from_mode(0o666)).unwrap();
    let out = s.forced("cowproof host-agent cleanup --lane-id l-1");
    assert_eq!(out.status.code(), Some(77), "{}", stdout(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    let error = json["error"].as_str().unwrap();
    assert!(error.starts_with("refused: "), "{error}");
    assert!(
        error.contains("writable by its group or by others"),
        "{error}"
    );
    assert!(error.contains("mode 0666"), "{error}");
    let doctor = s.forced("cowproof host-agent doctor");
    let json: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(json["config"], "invalid", "{json}");
}

#[test]
fn setup_warns_only_when_the_xdg_place_is_not_the_one_a_forced_key_reads() {
    let s = Setup::new();
    let claude = s.claude("claude");
    let args = ["--write-config", "--claude", claude.to_str().unwrap()];

    // XDG_CONFIG_HOME elsewhere: written there, with a warning naming both files.
    let xdg = var_tmp("cp-hostsetup-xdg-");
    let out = s.run_args(&args, &[("XDG_CONFIG_HOME", xdg.path())]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("WARNING"), "{text}");
    assert!(
        text.contains(&s.config_file().display().to_string()),
        "{text}"
    );
    assert!(xdg.path().join("cowproof/host.toml").is_file());
    // Not written where a forced key looks.
    assert!(!s.config_file().exists());

    // Not set, or set to HOME's own place: no warning.
    let out = s.run_args(&args, &[]);
    assert!(!stdout(&out).contains("WARNING"), "{}", stdout(&out));
    assert!(s.config_file().is_file());
    let own = s.home.path().join(".config");
    let out = s.run_args(
        &[args[0], args[1], args[2], "--force"],
        &[("XDG_CONFIG_HOME", own.as_path())],
    );
    assert!(!stdout(&out).contains("WARNING"), "{}", stdout(&out));
}
