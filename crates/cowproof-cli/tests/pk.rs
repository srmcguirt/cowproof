use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn pk_read_exe() -> PathBuf {
    env!("CARGO_BIN_EXE_pk-read").into()
}

fn cowproof_exe() -> PathBuf {
    env!("CARGO_BIN_EXE_cowproof").into()
}

/// Both entry points to the same command tree: `(label, command)`.
fn entries() -> [(&'static str, Command); 2] {
    let pk = Command::new(env!("CARGO_BIN_EXE_pk"));
    let mut cowproof = Command::new(cowproof_exe());
    cowproof.arg("pk");
    [("pk", pk), ("cowproof pk", cowproof)]
}

/// Run to completion, killing the child if it outlives 60 s. The outputs here
/// are small, so reading the pipes after exit cannot deadlock.
fn output_within_a_minute(cmd: &mut Command) -> std::process::Output {
    output_with_stdin_within_a_minute(cmd, None)
}

/// As above, feeding `stdin` first. The payloads are tiny, so writing them
/// before reading the pipes cannot fill a pipe buffer.
fn output_with_stdin_within_a_minute(
    cmd: &mut Command,
    stdin: Option<&[u8]>,
) -> std::process::Output {
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = cmd
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().expect("stdin pipe");
        pipe.write_all(bytes).expect("write stdin");
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("command still running after 60 s: {cmd:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

fn run_both(extra: &[&str], home: &std::path::Path) -> Vec<(&'static str, std::process::Output)> {
    entries()
        .into_iter()
        .map(|(label, mut cmd)| {
            cmd.args(extra)
                .env("HOME", home)
                .env_remove("PK_LOG_LEVEL")
                .current_dir(home);
            (label, output_within_a_minute(&mut cmd))
        })
        .collect()
}

/// The subcommand names in the `Commands:` section of `--help`.
fn command_names(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|l| l.trim() != "Commands:")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

#[test]
fn pk_and_cowproof_pk_print_the_same_version() {
    let tmp = TempDir::new().expect("temp dir");
    let outs = run_both(&["--version"], tmp.path());
    for (label, out) in &outs {
        assert!(out.status.success(), "{label} --version failed: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("pk "),
            "{label}: {out:?}"
        );
    }
    assert_eq!(outs[0].1.stdout, outs[1].1.stdout);
}

#[test]
fn pk_and_cowproof_pk_list_the_same_subcommands() {
    let tmp = TempDir::new().expect("temp dir");
    let outs = run_both(&["--help"], tmp.path());
    let mut names = Vec::new();
    for (label, out) in &outs {
        assert!(out.status.success(), "{label} --help failed: {out:?}");
        let found = command_names(&String::from_utf8_lossy(&out.stdout));
        assert!(
            found.iter().any(|n| n == "tools") && found.iter().any(|n| n == "run"),
            "{label}: unexpected command list {found:?}"
        );
        names.push(found);
    }
    assert_eq!(names[0], names[1]);
}

#[test]
fn an_unknown_subcommand_exits_the_same_way_through_both() {
    let tmp = TempDir::new().expect("temp dir");
    let outs = run_both(&["no-such-subcommand"], tmp.path());
    let codes: Vec<_> = outs.iter().map(|(_, o)| o.status.code()).collect();
    assert_eq!(codes[0], codes[1], "{codes:?}");
    // Not collapsed to a generic 1: clap's usage error code survives.
    assert_eq!(codes[0], Some(2), "{outs:?}");
    for (label, out) in &outs {
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("no-such-subcommand"), "{label}: {err}");
    }
}

/// A config file, passed on the command line, whose global plugin layer holds a
/// working plugin and whose project layer holds a manifest that is not TOML.
/// Both layers live under /var/tmp, never under the real home.
struct PluginFixture {
    dir: tempfile::TempDir,
    config: PathBuf,
    broken: PathBuf,
}

fn plugin_fixture() -> PluginFixture {
    let dir = tempfile::Builder::new()
        .prefix("cowproof-pk-")
        .tempdir_in("/var/tmp")
        .expect("temp dir under /var/tmp");
    let greet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../portkit/plugin/tests/fixtures/greet.py")
        .canonicalize()
        .expect("greet.py fixture");
    let good = dir.path().join("good-plugins.toml");
    fs::write(
        &good,
        format!(
            "[[plugin]]\ncommand = \"python3\"\nargs = [\"{}\"]\n",
            greet.display()
        ),
    )
    .expect("write good manifest");
    let broken = dir.path().join("broken-plugins.toml");
    fs::write(&broken, "[[plugin\nthis is not toml").expect("write broken manifest");
    let config = dir.path().join("pk.toml");
    fs::write(
        &config,
        format!(
            "[plugins]\nglobal = \"{}\"\nproject = \"{}\"\n",
            good.display(),
            broken.display()
        ),
    )
    .expect("write config");
    PluginFixture {
        dir,
        config,
        broken,
    }
}

#[test]
fn a_config_passed_to_pk_reaches_plugin_discovery_and_a_broken_manifest_only_warns() {
    let fx = plugin_fixture();
    let config = fx.config.to_str().unwrap();
    // HOME holds no plugin manifests, so only `--config` can supply the tools.
    let outs = run_both(&["--config", config, "tools"], fx.dir.path());
    for (label, out) in &outs {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{label}: {out:?}");
        assert!(
            stdout.contains("greet"),
            "{label}: the plugin from --config's layer is missing: {stdout}"
        );
        assert!(stderr.contains("warning"), "{label}: {stderr}");
        assert!(
            stderr.contains("broken-plugins.toml"),
            "{label}: the warning must name the broken manifest: {stderr}"
        );
    }
    assert!(fx.broken.exists());
}

#[test]
fn the_config_flag_is_what_selects_plugins_not_a_pre_parse_default() {
    // Without `--config` the default layers (under the empty HOME and cwd)
    // load nothing: no plugin, no warning.
    let fx = plugin_fixture();
    for (label, out) in run_both(&["tools"], fx.dir.path()) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{label}: {out:?}");
        assert!(!stdout.contains("greet"), "{label}: {stdout}");
        assert!(!stderr.contains("warning"), "{label}: {stderr}");
    }
}

#[test]
fn pk_read_full() {
    let tmp = TempDir::new().expect("temp dir");
    let file = tmp.path().join("test.txt");
    fs::write(&file, "line1\nline2\nline3\n").expect("write file");

    let pk_out = Command::new(pk_read_exe())
        .args(["--full", file.to_str().unwrap()])
        .env("HOME", tmp.path())
        .env("PORTKIT_SESSION", "")
        .output()
        .expect("pk-read --full");

    let cowproof_out = Command::new(cowproof_exe())
        .args(["read", "--full", file.to_str().unwrap()])
        .env("HOME", tmp.path())
        .env("PORTKIT_SESSION", "")
        .output()
        .expect("cowproof read --full");

    assert!(pk_out.status.success(), "pk-read --full failed");
    assert!(cowproof_out.status.success(), "cowproof read --full failed");

    let pk_text = String::from_utf8_lossy(&pk_out.stdout);
    let cowproof_text = String::from_utf8_lossy(&cowproof_out.stdout);

    // Both should contain the file content
    assert!(pk_text.contains("line1"), "pk-read output missing line1");
    assert!(
        cowproof_text.contains("line1"),
        "cowproof read output missing line1"
    );
}

#[test]
fn pk_read_with_state_dir() {
    let tmp = TempDir::new().expect("temp dir");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).expect("create state dir");
    let file = tmp.path().join("test.txt");
    fs::write(&file, "line1\nline2\nline3\n").expect("write file");

    // Run pk-read with explicit state dir
    let pk_out = Command::new(pk_read_exe())
        .args(["--full", file.to_str().unwrap()])
        .env("HOME", tmp.path())
        .env("PORTKIT_STATE_DIR", &state_dir)
        .env("PORTKIT_SESSION", "test")
        .output()
        .expect("pk-read --full with state");

    assert!(pk_out.status.success(), "pk-read with state dir failed");

    // Verify state file was created
    let state_files: Vec<_> = fs::read_dir(&state_dir)
        .expect("read state dir")
        .filter_map(Result::ok)
        .collect();
    assert!(!state_files.is_empty(), "no state file created");
}

#[test]
fn pk_read_ls() {
    let tmp = TempDir::new().expect("temp dir");
    let subdir = tmp.path().join("subdir");
    fs::create_dir(&subdir).expect("create subdir");
    fs::write(tmp.path().join("file.txt"), "content").expect("write file");

    let pk_out = Command::new(pk_read_exe())
        .args(["--ls", tmp.path().to_str().unwrap()])
        .env("HOME", tmp.path())
        .env("PORTKIT_SESSION", "")
        .output()
        .expect("pk-read --ls");

    assert!(pk_out.status.success(), "pk-read --ls failed");

    let text = String::from_utf8_lossy(&pk_out.stdout);
    assert!(text.contains("subdir/"), "listing missing subdir");
    assert!(text.contains("file.txt"), "listing missing file.txt");
}

#[test]
fn a_failing_read_exits_the_same_way_through_both() {
    let tmp = TempDir::new().expect("temp dir");
    let missing = tmp.path().join("missing.txt");
    let run = |cmd: &mut Command| {
        output_within_a_minute(
            cmd.arg("--full")
                .arg(&missing)
                .current_dir(tmp.path())
                .env("HOME", tmp.path())
                .env("PORTKIT_SESSION", ""),
        )
    };
    let direct = run(&mut Command::new(pk_read_exe()));
    let embedded = run(Command::new(cowproof_exe()).arg("read"));
    assert!(!direct.status.success(), "{direct:?}");
    assert_eq!(
        direct.status.code(),
        embedded.status.code(),
        "pk-read: {direct:?}\ncowproof read: {embedded:?}"
    );
}

// ---- G6 and G7: lane-private trace directory and machine-readable doctor ----

/// A scratch directory under /var/tmp, never the real home or the cwd.
fn scratch() -> TempDir {
    TempDir::new_in("/var/tmp").expect("scratch dir")
}

/// A config that turns tracing on and leaves `[trace] dir` at its default.
fn tracing_on(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("pk.toml");
    fs::write(&path, "[trace]\nenabled = true\n").expect("write config");
    path
}

const BASH_EVENT: &[u8] = br#"{"session_id":"sess-1","tool_name":"Bash","tool_input":{"command":"ls -la"},"tool_output":"total 0"}"#;

/// Run one real `pk hook post-tool-use` with `BASH_EVENT` on stdin.
fn hook_event(
    config: &std::path::Path,
    cwd: &std::path::Path,
    home: &std::path::Path,
    state_dir: Option<&std::path::Path>,
    session: Option<&str>,
) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
    cmd.arg("--config")
        .arg(config)
        .args(["hook", "post-tool-use"])
        .env("HOME", home)
        .env_remove("PORTKIT_STATE_DIR")
        .env_remove("PORTKIT_SESSION")
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(cwd);
    if let Some(dir) = state_dir {
        cmd.env("PORTKIT_STATE_DIR", dir);
    }
    if let Some(session) = session {
        cmd.env("PORTKIT_SESSION", session);
    }
    let out = output_with_stdin_within_a_minute(&mut cmd, Some(BASH_EVENT));
    assert!(out.status.success(), "hook must exit 0: {out:?}");
}

/// `pk doctor --json` with an isolated environment; returns (exit code, JSON).
fn doctor_json(
    config: &std::path::Path,
    home: &std::path::Path,
    state_dir: Option<&std::path::Path>,
    extra: &[&std::ffi::OsStr],
    claude_config_dir: Option<&std::path::Path>,
) -> (Option<i32>, serde_json::Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
    cmd.arg("--config")
        .arg(config)
        .args(["doctor", "--json"])
        .args(extra)
        .env("HOME", home)
        .env_remove("PORTKIT_STATE_DIR")
        .env_remove("PORTKIT_SESSION")
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(home);
    if let Some(dir) = state_dir {
        cmd.env("PORTKIT_STATE_DIR", dir);
    }
    if let Some(dir) = claude_config_dir {
        cmd.env("CLAUDE_CONFIG_DIR", dir);
    }
    let out = output_within_a_minute(&mut cmd);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {out:?}"));
    (out.status.code(), json)
}

fn check_status<'a>(report: &'a serde_json::Value, name: &str) -> &'a str {
    report["checks"]
        .as_array()
        .expect("checks is an array")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no check named {name}: {report}"))["status"]
        .as_str()
        .expect("status is a string")
}

fn files_in(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("entry").path())
        .collect();
    v.sort();
    v
}

const HOOK_SETTINGS: &str = r#"{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"pk hook post-tool-use"}]}]}}"#;

#[test]
fn the_hook_traces_into_the_state_dir_and_leaves_the_cwd_alone() {
    let root = scratch();
    let state = root.path().join("state");
    let cwd = root.path().join("clone");
    let home = root.path().join("home");
    for d in [&state, &cwd, &home] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let config = tracing_on(root.path());

    hook_event(&config, &cwd, &home, Some(&state), Some("lane-a"));

    // The default dir resolves to <state>/traces.
    let traces = state.join("traces");
    assert!(traces.is_dir(), "no {} directory", traces.display());
    let files = files_in(&traces);
    assert_eq!(files.len(), 1, "one trace file expected: {files:?}");
    let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.ends_with("-lane-a.jsonl"),
        "file name should carry the session: {name}"
    );

    let text = fs::read_to_string(&files[0]).expect("read trace");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "one record expected: {text}");
    let record: serde_json::Value = serde_json::from_str(lines[0]).expect("record is JSON");
    assert_eq!(record["tool"], "Bash");
    assert_eq!(record["surface"], "agent");
    assert_eq!(record["session"], "sess-1");

    assert!(
        files_in(&cwd).is_empty(),
        "the hook's cwd must stay empty: {:?}",
        files_in(&cwd)
    );
    assert!(
        !state.join(".portkit").exists(),
        "the cwd-style default must not be recreated under the state dir"
    );
}

#[test]
fn a_relative_trace_dir_resolves_against_the_state_dir() {
    let root = scratch();
    let state = root.path().join("state");
    let cwd = root.path().join("clone");
    let home = root.path().join("home");
    for d in [&state, &cwd, &home] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let config = root.path().join("pk.toml");
    fs::write(&config, "[trace]\nenabled = true\ndir = \"mine/t\"\n").expect("write config");

    hook_event(&config, &cwd, &home, Some(&state), None);

    let traces = state.join("mine").join("t");
    assert!(traces.is_dir(), "no {} directory", traces.display());
    let files = files_in(&traces);
    assert_eq!(files.len(), 1, "one trace file expected: {files:?}");
    assert!(
        fs::read_to_string(&files[0]).unwrap().contains("\"Bash\""),
        "the record is in the file"
    );
    assert!(files_in(&cwd).is_empty(), "cwd must stay empty");
}

#[test]
fn without_a_state_dir_the_trace_stays_in_the_cwd() {
    let root = scratch();
    let cwd = root.path().join("clone");
    let home = root.path().join("home");
    for d in [&cwd, &home] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let config = tracing_on(root.path());

    hook_event(&config, &cwd, &home, None, None);

    let traces = cwd.join(".portkit").join("traces");
    assert!(traces.is_dir(), "no {} directory", traces.display());
    let files = files_in(&traces);
    assert_eq!(files.len(), 1, "one trace file expected: {files:?}");
    // No session set, so the name is the bare date: YYYY-MM-DD.jsonl.
    let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
    let stem = name.strip_suffix(".jsonl").expect("a .jsonl file");
    assert_eq!(stem.len(), 10, "bare date expected, got {name}");
    assert!(
        fs::read_to_string(&files[0]).unwrap().contains("\"Bash\""),
        "the record is in the file"
    );
    assert!(
        files_in(&home).is_empty(),
        "nothing may be written into the home"
    );
}

#[test]
fn doctor_reports_traced_only_after_a_hook_event_was_recorded() {
    let root = scratch();
    let state = root.path().join("state");
    let cwd = root.path().join("clone");
    let home = root.path().join("home");
    for d in [&state, &cwd, &home] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let config = tracing_on(root.path());
    let settings = root.path().join("lane-settings.json");
    fs::write(&settings, HOOK_SETTINGS).expect("write settings");
    let settings_arg: &std::ffi::OsStr = settings.as_os_str();
    let args = [std::ffi::OsStr::new("--settings"), settings_arg];

    let (_, before) = doctor_json(&config, &home, Some(&state), &args, None);
    assert_eq!(before["traced"], false, "nothing recorded yet: {before}");
    assert_eq!(check_status(&before, "hooks have fired"), "miss");

    hook_event(&config, &cwd, &home, Some(&state), Some("lane-a"));

    let (code, after) = doctor_json(&config, &home, Some(&state), &args, None);
    assert_eq!(after["traced"], true, "one event was recorded: {after}");
    assert_eq!(check_status(&after, "hooks have fired"), "pass");
    assert_eq!(check_status(&after, "hooks registered"), "pass");
    assert_eq!(check_status(&after, "tracing enabled"), "pass");

    // The exit code follows the checks, as in text mode: zero only when every
    // check passes (`pk on PATH` depends on the machine running this test).
    let all_pass = after["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["status"] == "pass");
    assert_eq!(code == Some(0), all_pass, "exit {code:?} for {after}");
}

#[test]
fn doctor_json_has_the_documented_shape() {
    let root = scratch();
    let home = root.path().join("home");
    fs::create_dir_all(&home).expect("mkdir");
    let config = root.path().join("empty.toml");
    fs::write(&config, "").expect("write config");

    let (code, report) = doctor_json(&config, &home, None, &[], None);

    let obj = report.as_object().expect("top level is an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["checks", "traced"]);
    assert_eq!(report["traced"], false);

    let names: Vec<&str> = report["checks"]
        .as_array()
        .expect("checks is an array")
        .iter()
        .map(|c| {
            let fields = c.as_object().expect("a check is an object");
            let mut f: Vec<&str> = fields.keys().map(String::as_str).collect();
            f.sort_unstable();
            assert_eq!(f, ["detail", "name", "status"], "{c}");
            assert!(c["detail"].is_string());
            assert!(matches!(c["status"].as_str(), Some("pass" | "miss")), "{c}");
            c["name"].as_str().expect("name is a string")
        })
        .collect();
    assert_eq!(
        names,
        [
            "pk on PATH",
            "hooks registered",
            "tracing enabled",
            "hooks have fired"
        ]
    );
    // Tracing is off and nothing fired, so doctor must fail, as it always has.
    assert_eq!(check_status(&report, "tracing enabled"), "miss");
    assert_eq!(code, Some(1));
}

#[test]
fn doctor_text_output_and_exit_code_are_unchanged_without_json() {
    let root = scratch();
    let home = root.path().join("home");
    fs::create_dir_all(&home).expect("mkdir");
    let config = root.path().join("empty.toml");
    fs::write(&config, "").expect("write config");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
    cmd.arg("--config")
        .arg(&config)
        .arg("doctor")
        .env("HOME", &home)
        .env_remove("PORTKIT_STATE_DIR")
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(&home);
    let out = output_within_a_minute(&mut cmd);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!stdout.trim_start().starts_with('{'), "text, not JSON");
    for label in ["hooks registered", "tracing enabled", "hooks have fired"] {
        assert!(
            stdout
                .lines()
                .any(|l| l.trim_start().starts_with("MISS") && l.contains(label)),
            "no MISS line for {label}:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("hooks have fired -> run any tool in a hooked session"),
        "the fix lines are still printed:\n{stdout}"
    );
}

#[test]
fn doctor_settings_flag_replaces_the_default_search() {
    let root = scratch();
    let home = root.path().join("home");
    fs::create_dir_all(home.join(".claude")).expect("mkdir");
    let config = root.path().join("empty.toml");
    fs::write(&config, "").expect("write config");

    // The default location registers the hook; the file named by --settings
    // does not. With the flag, only the named file is read.
    fs::write(home.join(".claude/settings.json"), HOOK_SETTINGS).expect("home settings");
    let (_, default_search) = doctor_json(&config, &home, None, &[], None);
    assert_eq!(check_status(&default_search, "hooks registered"), "pass");

    let empty = root.path().join("empty-settings.json");
    fs::write(&empty, "{}").expect("empty settings");
    let args = [std::ffi::OsStr::new("--settings"), empty.as_os_str()];
    let (_, named_empty) = doctor_json(&config, &home, None, &args, None);
    assert_eq!(check_status(&named_empty, "hooks registered"), "miss");

    // And the named file is read when it does register the hook.
    let lane = root.path().join("lane-settings.json");
    fs::write(&lane, HOOK_SETTINGS).expect("lane settings");
    fs::remove_file(home.join(".claude/settings.json")).expect("remove home settings");
    let args = [std::ffi::OsStr::new("--settings"), lane.as_os_str()];
    let (_, named) = doctor_json(&config, &home, None, &args, None);
    assert_eq!(check_status(&named, "hooks registered"), "pass");
}

#[test]
fn doctor_honours_claude_config_dir() {
    let root = scratch();
    let home = root.path().join("home");
    let claude = root.path().join("claude-config");
    for d in [&home, &claude] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let config = root.path().join("empty.toml");
    fs::write(&config, "").expect("write config");
    fs::write(claude.join("settings.json"), HOOK_SETTINGS).expect("settings");

    let (_, without) = doctor_json(&config, &home, None, &[], None);
    assert_eq!(check_status(&without, "hooks registered"), "miss");

    let (_, with) = doctor_json(&config, &home, None, &[], Some(&claude));
    assert_eq!(check_status(&with, "hooks registered"), "pass");
}

#[test]
fn doctor_recognises_an_absolute_path_to_pk_and_the_cowproof_form() {
    let root = scratch();
    let home = root.path().join("home");
    fs::create_dir_all(&home).expect("mkdir");
    let config = root.path().join("empty.toml");
    fs::write(&config, "").expect("write config");

    let pk = env!("CARGO_BIN_EXE_pk");
    let cowproof = env!("CARGO_BIN_EXE_cowproof");
    let commands = [
        // Quoted absolute path, as cowproof writes it for a path with spaces.
        format!("\"{pk}\" hook post-tool-use"),
        format!("{pk} hook post-tool-use"),
        format!("\"{cowproof}\" pk hook post-tool-use"),
        "cowproof pk hook post-tool-use".to_string(),
    ];
    for command in commands {
        let settings = root.path().join("settings.json");
        let body = serde_json::json!({
            "hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}
        });
        fs::write(&settings, body.to_string()).expect("write settings");
        let args = [std::ffi::OsStr::new("--settings"), settings.as_os_str()];
        let (_, report) = doctor_json(&config, &home, None, &args, None);
        assert_eq!(
            check_status(&report, "hooks registered"),
            "pass",
            "command not recognised: {command}"
        );
    }

    // A settings file with a different command is still a miss.
    let other = root.path().join("other.json");
    fs::write(
        &other,
        r#"{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"echo hook"}]}]}}"#,
    )
    .expect("write settings");
    let args = [std::ffi::OsStr::new("--settings"), other.as_os_str()];
    let (_, report) = doctor_json(&config, &home, None, &args, None);
    assert_eq!(check_status(&report, "hooks registered"), "miss");
}
