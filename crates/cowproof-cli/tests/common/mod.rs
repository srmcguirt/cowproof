//! Shared pieces for the CLI tests that drive a whole lane: a fork lock, sandbox
//! availability, a real git repository, a copy of the `cowproof` binary outside the
//! home, a FAKE `claude`, and the MCP frames the fake sends to `cowproof lane-tools`.
//!
//! `tests/run.rs` keeps its own copies of these (another lane is editing it); new test
//! files use this module so there is one copy to move it to.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use tempfile::TempDir;

pub const REAL_KEY: &str = "sk-test-real-xyz";

/// What the fake prints on stdout: a session, two turns, a result.
const FAKE_STREAM: &str = concat!(
    r#"{"type":"system","subtype":"init","session_id":"0a1b2c3d-1111-2222-3333-444455556666"}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":3,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":7}}}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m2","usage":{"input_tokens":4,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":0}}}"#,
    "\n",
    r#"{"type":"result","subtype":"success","result":"done","num_turns":2}"#,
);

/// Linux refuses to exec a file some process holds open for writing (ETXTBSY), and a
/// fork on another test thread can inherit that handle. Writing executables and
/// forking both take this lock.
static FORK_LOCK: Mutex<()> = Mutex::new(());

pub fn fork_lock() -> std::sync::MutexGuard<'static, ()> {
    FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Command::output` with the spawn under `FORK_LOCK`; only the fork is held.
pub fn output(cmd: &mut Command) -> Output {
    let child = {
        let _g = fork_lock();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child.wait_with_output().unwrap()
}

/// Whether a sandbox can run here. With `COWPROOF_REQUIRE_SANDBOX=1` an unavailable
/// sandbox fails the test; otherwise the test skips.
pub fn sandbox_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let probe = {
        let _g = fork_lock();
        Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    };
    let reason = match probe.and_then(|c| c.wait_with_output()) {
        Ok(o) if o.status.success() => return true,
        Ok(o) => format!(
            "bwrap cannot create a sandbox here: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("bwrap is not installed: {e}"),
    };
    if std::env::var_os("COWPROOF_REQUIRE_SANDBOX").is_some_and(|v| v == "1") {
        panic!("COWPROOF_REQUIRE_SANDBOX=1 but {reason}");
    }
    eprintln!("SKIP: {reason}");
    false
}

/// `kill(-pgid, 0)` fails with ESRCH: no process is left in the process group `pgid`. A
/// permission error or an unanswerable pgid is not "gone".
#[allow(dead_code)] // `tests/host_agent.rs` and `tests/remote.rs` use it; the other test crates that share this module do not
pub fn group_gone(pgid: &str) -> bool {
    // kill(2), not the shell: dash's `kill` (Ubuntu's /bin/sh) rejects `--`, so a shell
    // probe reads every group as alive there.
    let pgid: u32 = pgid.parse().expect("a numeric pgid");
    cowproof_prove::runner::group_exists(pgid) == Some(false)
}

/// A signal by the name `kill` takes without its dash (`"KILL"`, `"TERM"`, `"INT"`, or `"0"`
/// for the existence probe), as its `libc` number. No test starts the `kill` program: Ubuntu's
/// procps `kill` keeps only the first digit of a negative id not preceded by `--`, so
/// `kill -KILL -1234` is `kill(-1, SIGKILL)`, which ends every process of the user. Every
/// signal here goes through `kill(2)` in `cowproof_prove::runner`, which refuses group 0 and 1.
#[allow(dead_code)] // each test crate that shares this module uses some of the helpers
pub fn signal_number(name: &str) -> libc::c_int {
    match name {
        "0" => 0,
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        other => panic!("no signal named {other:?} in tests/common"),
    }
}

/// Send the named signal (see [`signal_number`]) to the one process `pid`. Whether `kill(2)`
/// accepted it; with `"0"` that is "the process exists and is ours to signal".
#[allow(dead_code)]
pub fn signal_pid(name: &str, pid: u32) -> bool {
    cowproof_prove::runner::signal_pid(pid, signal_number(name))
}

/// Send the named signal to every process in the group `pgid` (never 0 or 1: those are
/// refused, and the answer is false).
#[allow(dead_code)]
pub fn signal_group(name: &str, pgid: u32) -> bool {
    cowproof_prove::runner::signal_group(pgid, signal_number(name))
}

/// Whether the process `pid` exists (a zombie does): the system's own answer, `ESRCH` being no.
/// A pid it cannot be asked about is not alive.
#[allow(dead_code)]
pub fn pid_alive(pid: u32) -> bool {
    cowproof_prove::runner::pid_exists(pid) == Some(true)
}

/// A temporary directory under `/var/tmp`: not `/tmp` (bwrap hides it) and not the home
/// (both sandboxes hide it).
pub fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
}

pub fn git(repo: &Path, args: &[&str]) {
    let out = output(
        Command::new("git")
            .args(["-C", repo.to_str().unwrap()])
            .args(args),
    );
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Shell that feeds an MCP session to `cowproof lane-tools` on the lane's own socket
/// and saves the frames to `$rec/<out>`. `calls` are `(id, tool, arguments)`.
pub fn mcp_session(out: &str, calls: &[(u64, &str, Value)]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fake","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    for (id, tool, arguments) in calls {
        lines.push(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}}));
    }
    let printed: String = lines
        .iter()
        .map(|l| format!("printf '%s\\n' '{l}'\n"))
        .collect();
    format!(
        "{{\n{printed}}} | \"$cp_bin\" lane-tools --socket \"$sock\" > \"$rec/{out}\" 2> \"$rec/{out}.err\"\n"
    )
}

/// Shell for a fake that calls `run_check` once for each id, in order.
pub fn run_checks(ids: &[&str]) -> String {
    let calls: Vec<(u64, &str, Value)> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (3 + i as u64, "run_check", json!({ "id": id })))
        .collect();
    mcp_session("mcp.out", &calls)
}

/// One lane of `cowproof run` against a fake `claude`, with a `cowproof` copy outside
/// the home and a `HOME` of its own for every child (so no test touches the real one).
pub struct Lane {
    /// Holds the repository, the packet, the fake and the cowproof copy.
    /// The lane id, unique per lane (see [`unique_lane_id`]).
    pub id: String,
    _work: TempDir,
    /// Holds the lanes, nothing else.
    pub lanes: TempDir,
    /// The `HOME` of every cowproof child: the director store lives under it.
    pub home: TempDir,
    pub repo: PathBuf,
    pub packet: PathBuf,
    fake: PathBuf,
    pub cowproof: PathBuf,
    /// Extra environment for every `cowproof` child (see [`Lane::set_env`]).
    envs: Vec<(String, OsString)>,
}

static LANE_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static LANE_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// A lane id of its own, with a bridge port of its own (D24).
///
/// The builder's bridge port is a hash of the lane id and, on macOS, the sandbox shares
/// the host's loopback, so lanes that run in parallel with one id (or with ids that merely
/// hash alike) would fight over a port. The id is searched for: its port must be unused by
/// every other lane of this process and free on the host right now.
pub fn unique_lane_id() -> String {
    let mut used = LANE_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let n = LANE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = format!("t-ver-{}-{n}", std::process::id());
        let port = cowproof_run::bridge::bridge_port(&id);
        if !used.contains(&port) && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            used.push(port);
            return id;
        }
    }
}

impl Lane {
    /// A committed repository with a README, and a packet that owns `README.md` and
    /// `created.txt` and declares `checks`. The fake edits README.md, creates
    /// created.txt, then runs `fake_body`.
    #[allow(dead_code)] // `tests/slots.rs` builds every lane with a class
    pub fn new(fake_body: &str, checks: Value) -> Self {
        Self::with_class(fake_body, checks, "light")
    }

    /// [`Lane::new`] with the packet's resource `class` (`light`, `crate`, `rust`, `pg`).
    #[allow(dead_code)] // `tests/slots.rs` uses it; the other test crates that share this module do not
    pub fn with_class(fake_body: &str, checks: Value, class: &str) -> Self {
        let id = unique_lane_id();
        let work = var_tmp("cp-ver-work-");
        let lanes = var_tmp("cp-ver-lanes-");
        let home = var_tmp("cp-ver-home-");
        let repo = work.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("README.md"), "base\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let packet = work.path().join("packet.md");
        fs::write(
            &packet,
            format!(
                "# Task\n\n<!-- lane {} -->\n\nChange the README.\n",
                json!({
                    "id": id,
                    "owns": ["README.md", "created.txt"],
                    "class": class,
                    "checks": checks,
                })
            ),
        )
        .unwrap();

        // The test binary lives under the home in a normal checkout, which the sandbox
        // hides, so a copy outside it is what runs.
        let cowproof = work.path().join("cowproof");
        {
            let _g = fork_lock();
            fs::copy(env!("CARGO_BIN_EXE_cowproof"), &cowproof).unwrap();
        }
        let fake = work.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
# The preflight runs `claude --version`; answer it before the lane's body.
if [ "$1" = "--version" ]; then echo "fake-claude 0.0.0"; exit 0; fi
rec="$HOME/fake"
mkdir -p "$rec"
sock="$(dirname "$HOME")/sock/runner.sock"
echo edited >> README.md
echo created > created.txt
cp_bin='{cowproof}'
{fake_body}
printf '%s' '{stream}'
exit 0
"#,
            cowproof = cowproof.display(),
            stream = FAKE_STREAM,
        );
        {
            let _g = fork_lock();
            fs::write(&fake, script).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Lane {
            id,
            _work: work,
            lanes,
            home,
            repo,
            packet,
            fake,
            cowproof,
            envs: Vec::new(),
        }
    }

    /// A lane over a committed copy of the project directory `project` (every file in it,
    /// recursively), with the packet text `packet(lane_id)` gives. Unlike [`Lane::new`], the
    /// fake changes nothing by itself: it runs `fake_body` in the clone, so the lane's patch
    /// is exactly what `fake_body` does to the project.
    #[allow(dead_code)] // `tests/adversarial.rs` uses it; the other test crates that share this module do not
    pub fn from_project(fake_body: &str, project: &Path, packet: &dyn Fn(&str) -> String) -> Self {
        let id = unique_lane_id();
        let work = var_tmp("cp-ver-work-");
        let lanes = var_tmp("cp-ver-lanes-");
        let home = var_tmp("cp-ver-home-");
        let repo = work.path().join("repo");
        copy_tree(project, &repo);
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let packet_path = work.path().join("packet.md");
        fs::write(&packet_path, packet(&id)).unwrap();

        let cowproof = work.path().join("cowproof");
        {
            let _g = fork_lock();
            fs::copy(env!("CARGO_BIN_EXE_cowproof"), &cowproof).unwrap();
        }
        let fake = work.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
# The preflight runs `claude --version`; answer it before the lane's body.
if [ "$1" = "--version" ]; then echo "fake-claude 0.0.0"; exit 0; fi
rec="$HOME/fake"
mkdir -p "$rec"
sock="$(dirname "$HOME")/sock/runner.sock"
cp_bin='{cowproof}'
{fake_body}
printf '%s' '{stream}'
exit 0
"#,
            cowproof = cowproof.display(),
            stream = FAKE_STREAM,
        );
        {
            let _g = fork_lock();
            fs::write(&fake, script).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Lane {
            id,
            _work: work,
            lanes,
            home,
            repo,
            packet: packet_path,
            fake,
            cowproof,
            envs: Vec::new(),
        }
    }

    /// The fake `claude`, for a hosts config that names it as the host's `claude`.
    #[allow(dead_code)] // `tests/remote.rs` uses it; the other test crates that share this module do not
    pub fn fake_claude(&self) -> &Path {
        &self.fake
    }

    /// Set an environment variable for every later `cowproof` child of this lane.
    #[allow(dead_code)] // `tests/deps.rs` uses it; the other test crates that share this module do not
    pub fn set_env(&mut self, key: &str, value: impl Into<OsString>) {
        self.envs.retain(|(k, _)| k != key);
        self.envs.push((key.to_string(), value.into()));
    }

    /// Add `files` (relative path, content) to the repository and commit them, so they
    /// are part of the base the lane starts from.
    #[allow(dead_code)] // `tests/deps.rs` uses it; the other test crates that share this module do not
    pub fn commit_files(&self, files: &[(&str, &str)]) {
        for (rel, content) in files {
            let path = self.repo.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        git(&self.repo, &["add", "-A"]);
        git(&self.repo, &["commit", "-q", "-m", "project files"]);
    }

    /// `cowproof` with the lane's `HOME` and no inherited API key.
    pub fn cowproof_cmd(&self) -> Command {
        let mut c = Command::new(&self.cowproof);
        c.env("HOME", self.home.path())
            .env_remove("ANTHROPIC_API_KEY");
        for (k, v) in &self.envs {
            c.env(k, v);
        }
        c
    }

    /// The `cowproof run` command with the real key set, plus `extra` arguments, not yet
    /// started.
    pub fn run_command(&self, extra: &[&Path]) -> Command {
        let mut c = self.cowproof_cmd();
        c.arg("run")
            .arg(&self.packet)
            .arg("--repo")
            .arg(&self.repo)
            .arg("--lanes-root")
            .arg(self.lanes.path())
            .arg("--claude-bin")
            .arg(&self.fake)
            .args(extra)
            .env("ANTHROPIC_API_KEY", REAL_KEY);
        c
    }

    /// `cowproof run` with the real key set, plus `extra` arguments.
    #[allow(dead_code)] // `tests/slots.rs` starts its runs without waiting
    pub fn run(&self, extra: &[&Path]) -> Output {
        output(&mut self.run_command(extra))
    }

    pub fn lane_dir(&self) -> PathBuf {
        self.lanes.path().canonicalize().unwrap().join(&self.id)
    }

    pub fn capsule_dir(&self) -> PathBuf {
        self.lane_dir().join("control/capsule")
    }

    pub fn verdict(&self) -> Value {
        let p = self.lane_dir().join("control/verdict.json");
        serde_json::from_str(
            &fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        )
        .unwrap()
    }
}

/// Copy the directory `from` to `to`, recursively (regular files and directories only).
#[allow(dead_code)] // `Lane::from_project` uses it; the other test crates that share this module do not
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

/// Start `cmd` without waiting, its stdout dropped and its stderr written to the file
/// `stderr` (read it while the process runs). The spawn is under `FORK_LOCK`.
#[allow(dead_code)] // `tests/slots.rs` uses it; the other test crates that share this module do not
pub fn spawn_to_file(cmd: &mut Command, stderr: &Path) -> std::process::Child {
    let file = fs::File::create(stderr).unwrap();
    let _g = fork_lock();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .unwrap()
}

/// `out`'s stdout and stderr, for assertion messages.
pub fn text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ---------------------------------------------------------------------------------------------
// A FAKE OpenRouter (D28 step 2): the upstream the proxy forwards OpenCode's requests to.
// ---------------------------------------------------------------------------------------------

/// One scripted model reply: some text, then tool calls (`(tool name, arguments)`). A reply
/// with tool calls ends with `finish_reason: tool_calls`, one without ends the turn.
#[allow(dead_code)] // only `tests/opencode.rs` scripts replies
#[derive(Clone, Debug)]
pub struct Reply {
    pub text: Option<String>,
    pub tools: Vec<(String, Value)>,
    /// Wait this long before answering (a slow model).
    pub delay_ms: u64,
}

#[allow(dead_code)]
impl Reply {
    pub fn text(text: &str) -> Self {
        Reply {
            text: Some(text.to_string()),
            tools: Vec::new(),
            delay_ms: 0,
        }
    }

    /// The same reply, `ms` milliseconds late.
    pub fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    pub fn tools(text: &str, tools: Vec<(&str, Value)>) -> Self {
        Reply {
            text: Some(text.to_string()),
            tools: tools.into_iter().map(|(n, a)| (n.to_string(), a)).collect(),
            delay_ms: 0,
        }
    }
}

/// What the fake saw of one request.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub host: Option<String>,
    pub model: Option<String>,
    /// Names of the tools the request offered the model.
    pub tool_names: Vec<String>,
    /// Number of messages in the conversation sent.
    pub messages: usize,
    /// The text of the last message, flattened.
    pub last_message: String,
    /// The system prompt, flattened.
    pub system: String,
    /// Header names, lower case.
    pub header_names: Vec<String>,
}

struct FakeState {
    script: Vec<Reply>,
    next: usize,
    seen: Vec<Seen>,
    /// Answer every chat completion with this status and a JSON error body.
    fail_with: Option<u16>,
    /// What `GET /api/v1/models` answers (see [`FakeOpenRouter::set_models`]).
    models: ModelsMode,
    /// The key `GET /api/v1/models` requires as `Authorization: Bearer <key>`; 403 otherwise.
    expected_key: String,
}

/// The lettered synthetic key the OpenRouter tests give the director, and the one the fake's
/// model list requires. Not a real key and not shaped like one a scanner would flag.
pub fn openrouter_test_key() -> String {
    format!("sk-or-v1-{}", "abcdefghij".repeat(6))
}

/// One entry of the fake's model list, in the shape of OpenRouter's `GET /models`. Prices are
/// the strings OpenRouter sends: USD per token.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FakeModel {
    pub id: String,
    pub prompt: String,
    pub completion: String,
    pub cache_read: Option<String>,
    pub cache_write: Option<String>,
    pub context_length: Option<u64>,
    pub max_completion_tokens: Option<u64>,
}

#[allow(dead_code)]
impl FakeModel {
    /// A model with only a prompt and a completion price, and no limits.
    pub fn new(id: &str, prompt: &str, completion: &str) -> Self {
        FakeModel {
            id: id.to_string(),
            prompt: prompt.to_string(),
            completion: completion.to_string(),
            cache_read: None,
            cache_write: None,
            context_length: None,
            max_completion_tokens: None,
        }
    }

    pub fn cache_read(mut self, price: &str) -> Self {
        self.cache_read = Some(price.to_string());
        self
    }

    pub fn limits(mut self, context_length: u64, max_completion_tokens: u64) -> Self {
        self.context_length = Some(context_length);
        self.max_completion_tokens = Some(max_completion_tokens);
        self
    }

    fn to_json(&self) -> Value {
        let mut pricing = json!({"prompt": self.prompt, "completion": self.completion});
        if let Some(p) = &self.cache_read {
            pricing["input_cache_read"] = json!(p);
        }
        if let Some(p) = &self.cache_write {
            pricing["input_cache_write"] = json!(p);
        }
        json!({
            "id": self.id,
            "name": self.id,
            "context_length": self.context_length,
            "top_provider": {"max_completion_tokens": self.max_completion_tokens},
            "pricing": pricing,
        })
    }
}

/// How the fake answers `GET /api/v1/models`.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum ModelsMode {
    /// 200 with these models.
    List(Vec<FakeModel>),
    /// This status and a JSON error body.
    Status(u16),
    /// 200 with a body that is not JSON.
    Garbage,
    /// Accept the request and never answer.
    Hang,
    /// 200 with a valid JSON body larger than the director's 8 MiB cap.
    Oversize,
}

/// A small HTTP server on 127.0.0.1 that answers OpenAI-style streaming chat completions
/// (`POST /api/v1/chat/completions`) from a script and records every request it gets, whatever
/// the path. A request that offers no tools (a title generator, say) gets a plain reply and does
/// not consume the script.
#[allow(dead_code)]
pub struct FakeOpenRouter {
    addr: std::net::SocketAddr,
    state: std::sync::Arc<Mutex<FakeState>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl FakeOpenRouter {
    pub fn start(script: Vec<Reply>) -> Self {
        Self::start_with(script, None)
    }

    /// A fake that refuses every chat completion with `status` (an expired key, say).
    pub fn failing(status: u16) -> Self {
        Self::start_with(Vec::new(), Some(status))
    }

    /// Change what `GET /api/v1/models` answers. Until it is called the list holds one model,
    /// `z-ai/glm-5.3-flash`, at the prices the old hand-written table gave.
    pub fn set_models(&self, mode: ModelsMode) {
        self.state.lock().unwrap().models = mode;
    }

    /// The requests for the model list, oldest first.
    pub fn models_requests(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|r| r.path == "/api/v1/models")
            .collect()
    }

    /// Every request that is not for the model list, oldest first.
    pub fn other_requests(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|r| r.path != "/api/v1/models")
            .collect()
    }

    fn start_with(script: Vec<Reply>, fail_with: Option<u16>) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = std::sync::Arc::new(Mutex::new(FakeState {
            script,
            next: 0,
            seen: Vec::new(),
            fail_with,
            models: ModelsMode::List(vec![
                FakeModel::new("z-ai/glm-5.3-flash", "0.0000006", "0.0000022")
                    .cache_read("0.00000011")
                    .limits(200_000, 16_000),
            ]),
            expected_key: openrouter_test_key(),
        }));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (st, sp) = (state.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !sp.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let st = st.clone();
                        std::thread::spawn(move || {
                            let _ = fake_serve(conn, st);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeOpenRouter {
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, what `COWPROOF_OPENROUTER_UPSTREAM` is set to.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// Every request so far, oldest first.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// How many scripted replies were given.
    pub fn replies_given(&self) -> usize {
        self.state.lock().unwrap().next
    }
}

impl Drop for FakeOpenRouter {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Flatten a chat message's `content` (a string, or a list of `{type:text,text}` parts).
fn flat_content(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

/// Answer `GET /api/v1/models`, then close the connection.
fn fake_models(
    writer: &mut std::net::TcpStream,
    authorized: bool,
    mode: ModelsMode,
) -> std::io::Result<()> {
    use std::io::Write;
    let (status, body) = if !authorized {
        (
            403,
            json!({"error": {"message": "invalid key", "code": 403}}).to_string(),
        )
    } else {
        match mode {
            ModelsMode::List(models) => (
                200,
                json!({"data": models.iter().map(FakeModel::to_json).collect::<Vec<_>>()})
                    .to_string(),
            ),
            ModelsMode::Status(status) => (
                status,
                json!({"error": {"message": "models are down", "code": status}}).to_string(),
            ),
            ModelsMode::Garbage => (200, "this is { not json".to_string()),
            ModelsMode::Hang => {
                std::thread::sleep(std::time::Duration::from_secs(120));
                return Ok(());
            }
            ModelsMode::Oversize => (
                200,
                format!(
                    r#"{{"data":[],"pad":"{}"}}"#,
                    "x".repeat(8 * 1024 * 1024 + 16)
                ),
            ),
        }
    };
    // The client may stop reading an oversize body; a broken pipe is not the fake's problem.
    let _ = write!(
        writer,
        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.flush();
    Ok(())
}

fn fake_serve(
    conn: std::net::TcpStream,
    state: std::sync::Arc<Mutex<FakeState>>,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    let mut writer = conn.try_clone()?;
    let mut reader = BufReader::new(conn);
    loop {
        // Request line and headers.
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut parts = line.split_whitespace();
        let (method, path) = (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("").to_string(),
        );
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h)? == 0 {
                return Ok(());
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        // Body: Content-Length, or chunked.
        let mut body = Vec::new();
        if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            body.resize(len, 0);
            reader.read_exact(&mut body)?;
        } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
            loop {
                let mut size_line = String::new();
                reader.read_line(&mut size_line)?;
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    let mut end = String::new();
                    reader.read_line(&mut end)?;
                    break;
                }
                let mut chunk = vec![0u8; size];
                reader.read_exact(&mut chunk)?;
                body.extend_from_slice(&chunk);
                let mut crlf = String::new();
                reader.read_line(&mut crlf)?;
            }
        }
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let messages = request["messages"].as_array().cloned().unwrap_or_default();
        let tool_names: Vec<String> = request["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| t["function"]["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let system = messages
            .iter()
            .filter(|m| m["role"] == "system")
            .map(|m| flat_content(&m["content"]))
            .collect::<Vec<_>>()
            .join("\n");
        let reply = {
            let mut st = state.lock().unwrap();
            st.seen.push(Seen {
                method: method.clone(),
                path: path.clone(),
                authorization: header("authorization"),
                host: header("host"),
                model: request["model"].as_str().map(str::to_string),
                tool_names: tool_names.clone(),
                messages: messages.len(),
                last_message: messages
                    .last()
                    .map(|m| flat_content(&m["content"]))
                    .unwrap_or_default(),
                system,
                header_names: headers.iter().map(|(k, _)| k.clone()).collect(),
            });
            if method == "GET" && path == "/api/v1/models" {
                let authorized = header("authorization").as_deref()
                    == Some(format!("Bearer {}", st.expected_key).as_str());
                let mode = st.models.clone();
                drop(st);
                return fake_models(&mut writer, authorized, mode);
            } else if method != "POST" || path != "/api/v1/chat/completions" {
                None
            } else if let Some(status) = st.fail_with {
                let body =
                    json!({"error": {"message": "No auth credentials found", "code": status}})
                        .to_string();
                drop(st);
                write!(
                    writer,
                    "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )?;
                return Ok(());
            } else if tool_names.is_empty() {
                Some(Reply::text("Title"))
            } else {
                let i = st.next;
                st.next += 1;
                Some(
                    st.script
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| Reply::text("(the script is out of replies)")),
                )
            }
        };
        let Some(reply) = reply else {
            writer.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            return Ok(());
        };
        if reply.delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(reply.delay_ms));
        }
        writer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )?;
        let model = request["model"].as_str().unwrap_or("m").to_string();
        let send = |writer: &mut std::net::TcpStream, data: &str| -> std::io::Result<()> {
            let frame = format!("data: {data}\n\n");
            write!(writer, "{:x}\r\n{frame}\r\n", frame.len())?;
            writer.flush()
        };
        let chunk = |delta: Value, finish: Value| {
            json!({"id":"gen-fake","object":"chat.completion.chunk","created":1,"model":model,
                   "choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
            .to_string()
        };
        send(
            &mut writer,
            &chunk(json!({"role":"assistant","content":""}), Value::Null),
        )?;
        if let Some(text) = &reply.text {
            send(&mut writer, &chunk(json!({"content": text}), Value::Null))?;
        }
        for (k, (name, args)) in reply.tools.iter().enumerate() {
            send(
                &mut writer,
                &chunk(
                    json!({"tool_calls":[{"index":k,"id":format!("call_{k}_{}", name.len()),"type":"function",
                          "function":{"name":name,"arguments":args.to_string()}}]}),
                    Value::Null,
                ),
            )?;
        }
        let finish = if reply.tools.is_empty() {
            "stop"
        } else {
            "tool_calls"
        };
        send(&mut writer, &chunk(json!({}), json!(finish)))?;
        send(
            &mut writer,
            &json!({"id":"gen-fake","object":"chat.completion.chunk","created":1,"model":model,"choices":[],
                    "usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,
                             "prompt_tokens_details":{"cached_tokens":10}}})
            .to_string(),
        )?;
        send(&mut writer, "[DONE]")?;
        writer.write_all(b"0\r\n\r\n")?;
        writer.flush()?;
    }
}

// ---------------------------------------------------------------------------------------------
// A FAKE OpenAI (D28 step 3): the upstream the proxy forwards Codex's requests to.
// ---------------------------------------------------------------------------------------------

/// The lettered synthetic key the Codex tests give the director, and the one the fake requires.
/// Not a real key: it is a repeated alphabet fragment, which the scrub check does not flag.
#[allow(dead_code)] // only `tests/codex.rs` uses the fake OpenAI
pub fn openai_test_key() -> String {
    format!("sk-proj-{}", "abcdefghij".repeat(6))
}

/// One scripted reply of the fake OpenAI: some reasoning, some text, then function calls
/// (`(namespace, tool name, arguments)`; a namespace is how Codex offers an MCP server's
/// tools), and the usage the call reports.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ResponsesReply {
    pub reasoning: Option<String>,
    pub text: Option<String>,
    pub calls: Vec<(Option<String>, String, Value)>,
    /// Wait this long before answering (a slow model).
    pub delay_ms: u64,
    /// `(input, cached input, output)` tokens this call reports.
    pub usage: (u64, u64, u64),
}

#[allow(dead_code)]
impl ResponsesReply {
    pub fn text(text: &str) -> Self {
        ResponsesReply {
            reasoning: None,
            text: Some(text.to_string()),
            calls: Vec::new(),
            delay_ms: 0,
            usage: (100, 10, 20),
        }
    }

    /// Text, then calls to Codex's own tools (`exec_command`, ...).
    pub fn tools(text: &str, calls: Vec<(&str, Value)>) -> Self {
        let mut reply = Self::text(text);
        reply.calls = calls
            .into_iter()
            .map(|(name, args)| (None, name.to_string(), args))
            .collect();
        reply
    }

    /// Text, then calls to the tools of the MCP server `server` (`cowproof-tools`).
    pub fn mcp(text: &str, server: &str, calls: Vec<(&str, Value)>) -> Self {
        let mut reply = Self::text(text);
        reply.calls = calls
            .into_iter()
            .map(|(name, args)| {
                (
                    Some(format!("mcp__{}", server.replace('-', "_"))),
                    name.to_string(),
                    args,
                )
            })
            .collect();
        reply
    }

    /// The same reply, `ms` milliseconds late.
    pub fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    /// The same reply, reporting these tokens.
    pub fn with_usage(mut self, input: u64, cached_input: u64, output: u64) -> Self {
        self.usage = (input, cached_input, output);
        self
    }

    /// The same reply with a reasoning summary before its text.
    pub fn reasoning(mut self, text: &str) -> Self {
        self.reasoning = Some(text.to_string());
        self
    }
}

struct OpenAiState {
    script: Vec<ResponsesReply>,
    next: usize,
    seen: Vec<Seen>,
    /// Answer every request with this status and a JSON error body.
    fail_with: Option<u16>,
    expected_key: String,
}

/// A small HTTP server on 127.0.0.1 that answers OpenAI Responses requests
/// (`POST /v1/responses`, streamed) from a script and records every request it gets, whatever
/// the path or method. It requires `Authorization: Bearer <openai_test_key()>`, as OpenAI
/// requires a key, and answers 401 to anything else. A path it does not serve is a 404.
#[allow(dead_code)]
pub struct FakeOpenAi {
    addr: std::net::SocketAddr,
    state: std::sync::Arc<Mutex<OpenAiState>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl FakeOpenAi {
    pub fn start(script: Vec<ResponsesReply>) -> Self {
        Self::start_with(script, None)
    }

    /// A fake that refuses every request with `status` (an expired key, say).
    pub fn failing(status: u16) -> Self {
        Self::start_with(Vec::new(), Some(status))
    }

    fn start_with(script: Vec<ResponsesReply>, fail_with: Option<u16>) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = std::sync::Arc::new(Mutex::new(OpenAiState {
            script,
            next: 0,
            seen: Vec::new(),
            fail_with,
            expected_key: openai_test_key(),
        }));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (st, sp) = (state.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !sp.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let st = st.clone();
                        std::thread::spawn(move || {
                            let _ = openai_serve(conn, st);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeOpenAi {
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, what `COWPROOF_OPENAI_UPSTREAM` is set to.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// Every request so far, oldest first. `tool_names` lists Codex's own tools by name and an
    /// MCP server's as `<namespace>::<tool>`.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// How many scripted replies were given.
    pub fn replies_given(&self) -> usize {
        self.state.lock().unwrap().next
    }
}

impl Drop for FakeOpenAi {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The text of a Responses `input` item or `instructions`, flattened.
fn responses_text(item: &Value) -> String {
    match item.get("content") {
        Some(content) => flat_content(content),
        None => String::new(),
    }
}

/// One HTTP request: method, path, lower-cased headers and the body.
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_http_request(
    reader: &mut std::io::BufReader<std::net::TcpStream>,
) -> std::io::Result<Option<HttpRequest>> {
    use std::io::{BufRead, Read};
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            return Ok(None);
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(len, 0);
        reader.read_exact(&mut body)?;
    } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 {
                let mut end = String::new();
                reader.read_line(&mut end)?;
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            let mut crlf = String::new();
            reader.read_line(&mut crlf)?;
        }
    }
    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }))
}

fn openai_serve(
    conn: std::net::TcpStream,
    state: std::sync::Arc<Mutex<OpenAiState>>,
) -> std::io::Result<()> {
    use std::io::{BufReader, Write};
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    let mut writer = conn.try_clone()?;
    let mut reader = BufReader::new(conn);
    while let Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }) = read_http_request(&mut reader)?
    {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let input = request["input"].as_array().cloned().unwrap_or_default();
        // Codex offers its tools in `tools`, or, for a model in its own catalog, as an
        // `additional_tools` item of the input; either way an MCP server's or a code-mode
        // namespace's tools are listed as `<namespace>::<tool>`.
        let mut offered: Vec<Value> = request["tools"].as_array().cloned().unwrap_or_default();
        for item in &input {
            if item["type"] == "additional_tools" {
                offered.extend(item["tools"].as_array().cloned().unwrap_or_default());
            }
        }
        let mut tool_names: Vec<String> = Vec::new();
        for tool in offered {
            match tool["type"].as_str() {
                Some("namespace") => {
                    let namespace = tool["name"].as_str().unwrap_or("").to_string();
                    for inner in tool["tools"].as_array().cloned().unwrap_or_default() {
                        tool_names.push(format!(
                            "{namespace}::{}",
                            inner["name"].as_str().unwrap_or("")
                        ));
                    }
                }
                _ => tool_names.push(
                    tool["name"]
                        .as_str()
                        .or_else(|| tool["type"].as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
            }
        }
        // Codex's own base prompt is `instructions`; the lane's preamble arrives as a
        // developer message. Both are "the system prompt" to a reader.
        let system = std::iter::once(request["instructions"].as_str().unwrap_or("").to_string())
            .chain(
                input
                    .iter()
                    .filter(|m| m["role"] == "developer")
                    .map(responses_text),
            )
            .collect::<Vec<_>>()
            .join("\n");
        let (reply, refusal) =
            {
                let mut st = state.lock().unwrap();
                st.seen.push(Seen {
                    method: method.clone(),
                    path: path.clone(),
                    authorization: header("authorization"),
                    host: header("host"),
                    model: request["model"].as_str().map(str::to_string),
                    tool_names,
                    messages: input.len(),
                    last_message: input.last().map(responses_text).unwrap_or_default(),
                    system,
                    header_names: headers.iter().map(|(k, _)| k.clone()).collect(),
                });
                let authorized = header("authorization").as_deref()
                    == Some(format!("Bearer {}", st.expected_key).as_str());
                if method != "POST" || path != "/v1/responses" {
                    (None, Some(404))
                } else if let Some(status) = st.fail_with {
                    (None, Some(status))
                } else if !authorized {
                    (None, Some(401))
                } else {
                    let i = st.next;
                    st.next += 1;
                    (
                        Some(st.script.get(i).cloned().unwrap_or_else(|| {
                            ResponsesReply::text("(the script is out of replies)")
                        })),
                        None,
                    )
                }
            };
        if let Some(status) = refusal {
            let body = if status == 404 {
                String::new()
            } else {
                json!({"error": {"message": "Incorrect API key provided.", "type": "invalid_request_error",
                                 "code": "invalid_api_key"}})
                .to_string()
            };
            write!(
                writer,
                "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            return Ok(());
        }
        let reply = reply.expect("a reply when there is no refusal");
        if reply.delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(reply.delay_ms));
        }
        writer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )?;
        let send =
            |writer: &mut std::net::TcpStream, event: &str, data: Value| -> std::io::Result<()> {
                let frame = format!("event: {event}\ndata: {data}\n\n");
                write!(writer, "{:x}\r\n{frame}\r\n", frame.len())?;
                writer.flush()
            };
        let response_id = format!("resp_{}", state.lock().unwrap().next);
        send(
            &mut writer,
            "response.created",
            json!({"type":"response.created","response":{"id":response_id}}),
        )?;
        let mut index = 0;
        let mut output_item = |writer: &mut std::net::TcpStream, item: Value, empty: Value| {
            send(
                writer,
                "response.output_item.added",
                json!({"type":"response.output_item.added","output_index":index,"item":empty}),
            )?;
            send(
                writer,
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":index,"item":item}),
            )?;
            index += 1;
            std::io::Result::Ok(())
        };
        if let Some(reasoning) = &reply.reasoning {
            output_item(
                &mut writer,
                json!({"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":reasoning}]}),
                json!({"type":"reasoning","id":"rs_1","summary":[]}),
            )?;
        }
        if let Some(text) = &reply.text {
            output_item(
                &mut writer,
                json!({"type":"message","role":"assistant","id":"msg_1","content":[{"type":"output_text","text":text}]}),
                json!({"type":"message","role":"assistant","id":"msg_1","content":[]}),
            )?;
        }
        for (k, (namespace, name, args)) in reply.calls.iter().enumerate() {
            let mut item = json!({"type":"function_call","id":format!("fc_{k}"),
                                  "call_id":format!("call_{}_{k}", response_id),
                                  "name":name,"arguments":args.to_string()});
            if let Some(namespace) = namespace {
                item["namespace"] = json!(namespace);
            }
            output_item(&mut writer, item.clone(), item)?;
        }
        let (input_tokens, cached, output_tokens) = reply.usage;
        send(
            &mut writer,
            "response.completed",
            json!({"type":"response.completed","response":{"id":response_id,"usage":{
                "input_tokens":input_tokens,"input_tokens_details":{"cached_tokens":cached},
                "output_tokens":output_tokens,"output_tokens_details":{"reasoning_tokens":0},
                "total_tokens":input_tokens + output_tokens}}}),
        )?;
        writer.write_all(b"0\r\n\r\n")?;
        writer.flush()?;
    }
    Ok(())
}
