//! The compaction watermark, end to end (gap G5).
//!
//! The `pre-compact` and `session-start` hooks write the watermark and
//! `pk-read` reads it. They must agree on where it lives, or `pk-read` keeps
//! answering UNCHANGED for a file the model no longer has in context. These
//! tests drive the hook's real entry point (`handle_hook`, which `pk hook`
//! calls with stdin) and the reader's real entry point (`run_to`, which
//! `pk-read` calls with stdout) from a working directory that is not the
//! state dir.
//!
//! The environment and the working directory are process-wide, so every test
//! takes `LOCK` and uses a [`World`] that restores both on drop. Nothing here
//! reads the real HOME: `World` points it at a temp dir.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use portkit_core::Config;

static LOCK: Mutex<()> = Mutex::new(());

const FILE_BODY: &str = "alpha\nbeta\ngamma\ndelta\nepsilon\n";

/// A throwaway directory tree plus the process state to put back afterwards.
struct World {
    root: PathBuf,
    cwd: PathBuf,
    state: PathBuf,
    file: PathBuf,
    saved_cwd: PathBuf,
    saved_env: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl World {
    fn new(tag: &str) -> Self {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!(
            "portkit-g5-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cwd = root.join("cwd");
        let state = root.join("state");
        let home = root.join("home");
        for d in [&cwd, &state, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let file = root.join("data.txt");
        std::fs::write(&file, FILE_BODY).unwrap();

        let names = ["HOME", "PORTKIT_STATE_DIR", "PORTKIT_SESSION"];
        let saved_env = names.iter().map(|n| (*n, std::env::var_os(n))).collect();
        let saved_cwd = std::env::current_dir().unwrap();

        std::env::set_var("HOME", &home);
        std::env::remove_var("PORTKIT_STATE_DIR");
        std::env::remove_var("PORTKIT_SESSION");
        std::env::set_current_dir(&cwd).unwrap();

        World {
            root,
            cwd,
            state,
            file,
            saved_cwd,
            saved_env,
            _guard: guard,
        }
    }

    /// Read `self.file` through the reader and return what it printed.
    fn read(&self) -> String {
        self.read_args(&[self.file.to_str().unwrap()])
    }

    fn read_args(&self, args: &[&str]) -> String {
        let mut out: Vec<u8> = Vec::new();
        let code = portkit_read::run_to(args.iter().map(|s| s.to_string()).collect(), &mut out);
        assert_eq!(code, ExitCode::SUCCESS);
        String::from_utf8(out).unwrap()
    }

    /// Fire a hook event the way `pk hook <event>` does, with a payload.
    fn hook(&self, event: &str, session_id: &str) {
        let payload = serde_json::json!({ "session_id": session_id }).to_string();
        portkit_cli::handle_hook(event, &payload, &Config::default());
    }

    /// Nothing may be written under the working directory.
    fn assert_cwd_untouched(&self) {
        let entries: Vec<_> = std::fs::read_dir(&self.cwd)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "the hook and the reader must leave the cwd alone, found {entries:?}"
        );
        assert!(!self.cwd.join(".portkit").exists());
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.saved_cwd);
        for (name, value) in &self.saved_env {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_content(out: &str) {
    assert!(
        out.contains("1\u{2502}alpha") && out.contains("5\u{2502}epsilon"),
        "expected the file content, got: {out}"
    );
    assert!(!out.contains("UNCHANGED"), "unexpected UNCHANGED: {out}");
}

fn assert_unchanged(out: &str) {
    assert!(
        out.starts_with("UNCHANGED L1-5 "),
        "expected UNCHANGED, got: {out}"
    );
    assert!(
        !out.contains("alpha"),
        "UNCHANGED must carry no content: {out}"
    );
}

/// The flow the defect broke: read, read (unchanged), compaction, read
/// (re-delivered), read (unchanged), for one hook event.
fn compaction_flow(event: &str, tag: &str) {
    let w = World::new(tag);
    std::env::set_var("PORTKIT_STATE_DIR", &w.state);
    std::env::set_var("PORTKIT_SESSION", "lane-a");

    assert_content(&w.read());
    assert_unchanged(&w.read());

    // Claude's own session id differs from the lane's PORTKIT_SESSION, as it
    // does in a cowproof lane. The watermark must still be seen.
    w.hook(event, "5b3c1e0a-aaaa-bbbb-cccc-0123456789ab");

    assert_content(&w.read());
    assert_unchanged(&w.read());

    w.assert_cwd_untouched();
    // And the state landed under the state dir, nowhere else.
    assert_eq!(World::files_in(&w.state), vec!["lane-a.json".to_string()]);
}

#[test]
fn pre_compact_makes_the_next_read_redeliver() {
    compaction_flow("pre-compact", "pre");
}

#[test]
fn session_start_makes_the_next_read_redeliver() {
    compaction_flow("session-start", "start");
}

#[test]
fn without_a_session_the_default_session_is_invalidated() {
    // PORTKIT_SESSION unset: the reader keys on "default", so the hook must
    // too, whatever session id the payload carries.
    let w = World::new("default");
    std::env::set_var("PORTKIT_STATE_DIR", &w.state);

    assert_content(&w.read());
    assert_unchanged(&w.read());
    w.hook("pre-compact", "some-session");
    assert_content(&w.read());
    assert_unchanged(&w.read());

    w.assert_cwd_untouched();
    assert_eq!(World::files_in(&w.state), vec!["default.json".to_string()]);
}

#[test]
fn a_payload_without_a_session_id_still_marks_the_watermark() {
    let w = World::new("nosid");
    std::env::set_var("PORTKIT_STATE_DIR", &w.state);
    std::env::set_var("PORTKIT_SESSION", "s1");

    assert_content(&w.read());
    portkit_cli::handle_hook("pre-compact", "{}", &Config::default());
    assert_content(&w.read());
    w.assert_cwd_untouched();
}

#[test]
fn without_a_state_dir_both_sides_use_home_and_not_the_cwd() {
    let w = World::new("home");
    std::env::set_var("PORTKIT_SESSION", "s1");
    let home_state = Path::new(&std::env::var_os("HOME").unwrap())
        .join(".portkit")
        .join("read");

    assert_content(&w.read());
    assert_unchanged(&w.read());
    w.hook("pre-compact", "s1");
    assert_content(&w.read());
    assert_unchanged(&w.read());

    w.assert_cwd_untouched();
    assert_eq!(World::files_in(&home_state), vec!["s1.json".to_string()]);
}

#[test]
fn writer_and_reader_resolve_the_same_path() {
    let w = World::new("path");
    std::env::set_var("PORTKIT_STATE_DIR", &w.state);
    std::env::set_var("PORTKIT_SESSION", "lane/../x y");
    // Sanitised the same way on both sides: letters, digits, `-` and `_`.
    assert_eq!(
        portkit_read::session_state_path(),
        w.state.join("lanexy.json")
    );
    assert_eq!(
        portkit_read::session_state_path_for("lane/../x y"),
        portkit_read::session_state_path()
    );
}

#[test]
fn the_compacted_flag_and_the_hook_write_the_same_file() {
    let w = World::new("flag");
    std::env::set_var("PORTKIT_STATE_DIR", &w.state);
    std::env::set_var("PORTKIT_SESSION", "s1");

    assert_content(&w.read());
    assert_eq!(w.read_args(&["--compacted"]), "");
    assert_content(&w.read());
    assert_unchanged(&w.read());
    w.hook("pre-compact", "s1");
    assert_content(&w.read());
    assert_eq!(World::files_in(&w.state), vec!["s1.json".to_string()]);
    w.assert_cwd_untouched();
}

#[test]
fn a_partial_read_after_compaction_does_not_revive_older_ranges() {
    // Read L1-2, compact, read L4-5. L1-2 predates the watermark and must be
    // sent again, not reported UNCHANGED because a later range was delivered.
    let w = World::new("partial");
    std::env::set_var("PORTKIT_STATE_DIR", &w.state);
    std::env::set_var("PORTKIT_SESSION", "s1");
    let f = w.file.to_str().unwrap().to_string();

    assert!(w
        .read_args(&["--range", "1:2", &f])
        .contains("1\u{2502}alpha"));
    w.hook("pre-compact", "s1");
    assert!(w
        .read_args(&["--range", "4:5", &f])
        .contains("4\u{2502}delta"));

    let again = w.read_args(&["--range", "1:2", &f]);
    assert!(
        again.contains("1\u{2502}alpha"),
        "L1-2 was delivered before compaction and must be re-sent: {again}"
    );
    assert!(!again.contains("UNCHANGED"));
}
