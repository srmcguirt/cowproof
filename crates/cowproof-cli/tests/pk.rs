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
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
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
