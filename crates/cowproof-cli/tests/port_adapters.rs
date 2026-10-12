//! The function-level capture adapters for Node/TypeScript and Python (portkit-integration.md,
//! sections 6.1 and 6.2), through the real `node` and `python3`, the real `pk`, a real `rustc`
//! and, for the last test, a whole `cowproof run` against a FAKE `claude`.
//!
//! Three layers: the adapters alone (request in, result out, errors, `__defaults`, the
//! determinism pins and the canonical output); `pk port adapter`; and the flow a user follows
//! (capture a module through its adapter, replay a Rust port against the fixtures, refute a
//! wrong one) ending in a `kind: port` packet with `adapter: function` and `lang: python`.
//!
//! Which tests run in the published crate. The adapter source comes from the embedded copy
//! (`pk port adapter <lang> --out`, written beside the module like a user's copy), so the
//! adapter-alone tests (request and result, `__defaults`, errors, noisy modules, non-JSON
//! values, canonical output across adapters, raw key order, set order, clock and seed) and
//! `pk_port_adapter_prints_and_writes_the_embedded_files` need nothing above the crate. The
//! tests that read `fixtures/port-adapters/` or the adapter files on disk (TypeScript, the two
//! capture-and-replay flows, the committed-copy and on-disk checks, the proof) read the
//! repository above the crate, so they run in the workspace only (`common/workspace.rs`):
//! without it they print a skip, and fail under `COWPROOF_WORKSPACE_TESTS=1`.
//!
//! A missing `node` or `python3` skips the tests that need it with a printed note, and fails
//! them under `COWPROOF_REQUIRE_RUNTIMES=1`. The proof test needs the sandbox like
//! `tests/port_packets.rs`.

mod common;
#[path = "common/workspace.rs"]
mod workspace;

use common::{Lane, fork_lock, run_checks, sandbox_available, text, var_tmp};
use cowproof_prove::Capsule;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

// ---- paths ---------------------------------------------------------------------------------

/// The adapter files in the workspace (workspace tests only).
fn shipped(lang: &str, file: &str) -> PathBuf {
    workspace::root()
        .unwrap()
        .join("crates/portkit/port/adapters")
        .join(lang)
        .join(file)
}

fn fixtures() -> PathBuf {
    workspace::root().unwrap().join("fixtures/port-adapters")
}

// ---- runtimes ------------------------------------------------------------------------------

/// Whether `runner --version` works. Without it the test skips, or fails under
/// `COWPROOF_REQUIRE_RUNTIMES=1`.
fn have(runner: &str) -> bool {
    let found = {
        let _g = fork_lock();
        Command::new(runner)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !found {
        if std::env::var_os("COWPROOF_REQUIRE_RUNTIMES").is_some_and(|v| v == "1") {
            panic!("COWPROOF_REQUIRE_RUNTIMES=1 but `{runner} --version` does not run");
        }
        eprintln!("SKIP: `{runner}` is not installed");
    }
    found
}

/// Whether this Node strips TypeScript types behind `--experimental-strip-types` (or by default).
fn node_strips_types() -> bool {
    let _g = fork_lock();
    Command::new("node")
        .args(["--experimental-strip-types", "-e", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_with_stdin(cmd: &mut Command, input: &str) -> Output {
    let mut child = {
        let _g = fork_lock();
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

// ---- the two adapters, called alike --------------------------------------------------------

#[derive(Clone, Copy)]
struct Kind {
    name: &'static str,
    runner: &'static str,
    dir: &'static str,
    file: &'static str,
    ext: &'static str,
}

const NODE: Kind = Kind {
    name: "node",
    runner: "node",
    dir: "node",
    file: "adapter.mjs",
    ext: "mjs",
};
const PYTHON: Kind = Kind {
    name: "python",
    runner: "python3",
    dir: "python",
    file: "adapter.py",
    ext: "py",
};

impl Kind {
    /// The embedded adapter, written beside the module the way a user gets it
    /// (`pk port adapter <lang> --out`); written once per directory.
    fn install(&self, dir: &Path) -> PathBuf {
        let target = dir.join(self.file);
        if !target.exists() {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
            cmd.args(["port", "adapter", self.dir, "--out"])
                .arg(&target);
            let out = run_plain(&mut cmd, dir);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        }
        target
    }

    /// Call the adapter in `dir` for `module` (a file name in `dir`) with `args` after it. The
    /// environment holds no pin of ours unless `envs` sets it.
    fn call(&self, dir: &Path, args: &[&str], request: &str, envs: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(self.runner);
        cmd.arg(self.install(dir))
            .args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .env_remove("TZ")
            .env_remove("PORTKIT_NOW")
            .env_remove("PORTKIT_SEED")
            .env_remove("PORTKIT_TOOL")
            .env_remove("PYTHONHASHSEED");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        run_with_stdin(&mut cmd, request)
    }

    /// The module `source` as `m.<ext>` in a fresh directory.
    fn module(&self, source: &str) -> tempfile::TempDir {
        let dir = var_tmp("cp-adapter-");
        fs::write(dir.path().join(format!("m.{}", self.ext)), source).unwrap();
        dir
    }

    /// Call `tool` of the module `source` with `input`; the output.
    fn tool(&self, source: &str, tool: &str, input: Value, envs: &[(&str, &str)]) -> Output {
        let dir = self.module(source);
        let module = format!("m.{}", self.ext);
        let request = json!({"tool": tool, "input": input}).to_string();
        self.call(dir.path(), &[&module], &request, envs)
    }
}

fn out_text(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn err_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// stdout must be exactly one line of JSON: returns it parsed.
fn one_json_line(out: &Output) -> Value {
    assert_eq!(out.status.code(), Some(0), "{}", text(out));
    let stdout = out_text(out);
    assert!(stdout.ends_with('\n'), "{stdout:?}");
    assert_eq!(stdout.matches('\n').count(), 1, "{stdout:?}");
    serde_json::from_str(stdout.trim_end()).unwrap()
}

// Modules the unit tests wrap. Each pair holds the same logic in both languages.

const NODE_BASICS: &str = r#"
export const SCALE = 100;
export const NAME = "basics";
export function double(request) { return { value: request.value * 2 }; }
export function add(a, b) { return a + b; }
export async function later(request) { return { slow: request.value }; }
export function boom() { throw new Error("nope"); }
export function bad() { return { value: NaN }; }
export function items() { return { rows: [1, 2], skip: undefined }; }
"#;

const PYTHON_BASICS: &str = r#"
SCALE = 100
NAME = "basics"
lowercase_is_not_a_default = 1

def double(request):
    return {"value": request["value"] * 2}

def add(a, b):
    return a + b

async def later(request):
    return {"slow": request["value"]}

def boom(request):
    raise ValueError("nope")

def bad(request):
    return {"value": float("nan")}
"#;

const NODE_NOISY: &str = r#"
console.log("noise at load");
export function f(request) {
  console.log("noise in the call");
  process.stdout.write("more noise\n");
  return { ok: true };
}
"#;

const PYTHON_NOISY: &str = r#"
print("noise at load")
def f(request):
    print("noise in the call")
    return {"ok": True}
"#;

const NODE_DEFAULTS: &str = r#"
export const IGNORED = 1;
export const __defaults = { chosen: "this" };
export function f() { return {}; }
"#;

const PYTHON_DEFAULTS: &str = r#"
IGNORED = 1
__defaults = {"chosen": "this"}
def f(request): return {}
"#;

const NODE_DATA: &str = r#"
export function data() {
  return {
    z: [1, 2.5, 3.0, -0, 1e21, 1e-7, 0.1 + 0.2, 123456789012345680000, 5e-324, 1.7976931348623157e308, 100, 0.000001],
    b: { y: null, x: true, "é": "ü\n\t\"\\\u0001", 10: "ten", 9: "nine", a: "A" },
    list: [{ k2: 1, k1: 2 }, []],
    empty: {},
  };
}
"#;

const PYTHON_DATA: &str = r#"
def data(request):
    return {
        "z": [1, 2.5, 3.0, -0.0, 1e21, 1e-7, 0.1 + 0.2, 123456789012345680000.0, 5e-324, 1.7976931348623157e308, 100, 0.000001],
        "b": {"y": None, "x": True, "é": "ü\n\t\"\\\u0001", "10": "ten", "9": "nine", "a": "A"},
        "list": [{"k2": 1, "k1": 2}, []],
        "empty": {},
    }
"#;

/// What both adapters print for `data`: keys sorted, numbers as ECMAScript prints them.
const DATA_CANONICAL: &str = r#"{"b":{"10":"ten","9":"nine","a":"A","x":true,"y":null,"é":"ü\n\t\"\\\u0001"},"empty":{},"list":[{"k1":2,"k2":1},[]],"z":[1,2.5,3,0,1e+21,1e-7,0.30000000000000004,123456789012345680000,5e-324,1.7976931348623157e+308,100,0.000001]}"#;

const NODE_CLOCK: &str = r#"
export function clock() {
  return {
    now: Date.now(),
    iso: new Date().toISOString(),
    callable: typeof Date(),
    explicit: new Date(0).toISOString(),
    is_date: new Date() instanceof Date,
    zone: new Date(2020, 0, 1).toISOString(),
  };
}
export function dice() { return [Math.random(), Math.random(), Math.random()]; }
"#;

const PYTHON_CLOCK: &str = r#"
import datetime, time, random
from datetime import datetime as dt

def clock(request):
    return {
        "now": time.time(),
        "ns": time.time_ns(),
        "iso": dt.now(datetime.timezone.utc).isoformat(),
        "today": datetime.date.today().isoformat(),
        "is_date": isinstance(dt.now(), datetime.date) and isinstance(dt.now(), dt),
        "gm": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "explicit": datetime.datetime(1970, 1, 1).isoformat(),
        "zone": datetime.datetime(2020, 1, 1).astimezone(datetime.timezone.utc).isoformat(),
    }

def dice(request):
    return [random.random(), random.random(), random.random()]
"#;

// ---- request in, result out ----------------------------------------------------------------

#[test]
fn a_request_in_the_result_out_through_each_adapter() {
    for (kind, source) in [(NODE, NODE_BASICS), (PYTHON, PYTHON_BASICS)] {
        if !have(kind.runner) {
            continue;
        }
        // Dispatch on the request's tool.
        let out = kind.tool(source, "double", json!({"value": 21}), &[]);
        assert_eq!(one_json_line(&out), json!({"value": 42}), "{}", kind.name);
        assert_eq!(out_text(&out), "{\"value\":42}\n", "{}", kind.name);

        // PORTKIT_TOOL names the tool when the request has none.
        let dir = kind.module(source);
        let module = format!("m.{}", kind.ext);
        let out = kind.call(
            dir.path(),
            &[&module],
            r#"{"input":{"value":4}}"#,
            &[("PORTKIT_TOOL", "double")],
        );
        assert_eq!(one_json_line(&out), json!({"value": 8}), "{}", kind.name);

        // A function named on the command line is called whatever the tool says.
        let request = json!({"tool": "anything", "input": {"value": 5}}).to_string();
        let out = kind.call(dir.path(), &[&module, "double"], &request, &[]);
        assert_eq!(one_json_line(&out), json!({"value": 10}), "{}", kind.name);

        // {"args": [...]} is a positional call; a coroutine or promise is run to the end.
        let out = kind.tool(source, "add", json!({"args": [2, 3]}), &[]);
        assert_eq!(one_json_line(&out), json!(5), "{}", kind.name);
        let out = kind.tool(source, "later", json!({"value": 9}), &[]);
        assert_eq!(one_json_line(&out), json!({"slow": 9}), "{}", kind.name);
    }
}

#[test]
fn module_constants_are_exposed_as_defaults() {
    for (kind, basics, explicit) in [
        (NODE, NODE_BASICS, NODE_DEFAULTS),
        (PYTHON, PYTHON_BASICS, PYTHON_DEFAULTS),
    ] {
        if !have(kind.runner) {
            continue;
        }
        // No `__defaults` of the module's own: its constants (every exported value in Node,
        // the UPPER_CASE names in Python), never a function.
        let out = kind.tool(basics, "__defaults", json!({}), &[]);
        assert_eq!(
            one_json_line(&out),
            json!({"SCALE": 100, "NAME": "basics"}),
            "{}",
            kind.name
        );
        // The module's own `__defaults` wins.
        let out = kind.tool(explicit, "__defaults", json!({}), &[]);
        assert_eq!(
            one_json_line(&out),
            json!({"chosen": "this"}),
            "{}",
            kind.name
        );
    }
}

#[test]
fn the_module_failing_is_a_result_and_the_adapter_failing_is_not() {
    for (kind, source) in [(NODE, NODE_BASICS), (PYTHON, PYTHON_BASICS)] {
        if !have(kind.runner) {
            continue;
        }
        let name = kind.name;
        // A function that throws is the module's answer: {"error": message}, exit 0.
        let out = kind.tool(source, "boom", json!({}), &[]);
        assert_eq!(out_text(&out), "{\"error\":\"nope\"}\n", "{name}");
        assert_eq!(out.status.code(), Some(0), "{name}");

        // Everything else is the adapter's own setup: exit 2, a reason on stderr, nothing on stdout.
        let dir = kind.module(source);
        let module = format!("m.{}", kind.ext);
        let cases: Vec<(&str, Vec<&str>, String, &str)> = vec![
            (
                "unknown tool",
                vec![&module],
                r#"{"tool":"nosuch","input":{}}"#.into(),
                "nosuch",
            ),
            (
                "a missing module",
                vec!["absent.nope"],
                r#"{"tool":"double","input":{}}"#.into(),
                "cannot load",
            ),
            (
                "not JSON on stdin",
                vec![&module],
                "this is not json".into(),
                "not one JSON request",
            ),
            (
                "a request with no input",
                vec![&module],
                r#"{"tool":"double"}"#.into(),
                "no \"input\"",
            ),
            (
                "a request that is not an object",
                vec![&module],
                "[1]".into(),
                "must be a JSON object",
            ),
            (
                "no arguments",
                vec![],
                r#"{"tool":"double","input":{}}"#.into(),
                "usage",
            ),
            (
                "NaN in the result",
                vec![&module],
                r#"{"tool":"bad","input":{}}"#.into(),
                "not representable",
            ),
        ];
        for (what, args, request, reason) in cases {
            let out = kind.call(dir.path(), &args, &request, &[]);
            assert_eq!(out.status.code(), Some(2), "{name}: {what}: {}", text(&out));
            assert!(out.stdout.is_empty(), "{name}: {what}: {}", out_text(&out));
            let err = err_text(&out);
            assert!(err.contains("portkit-adapter:"), "{name}: {what}: {err}");
            assert!(err.contains(reason), "{name}: {what}: {err}");
        }

        // A bad PORTKIT_* value is refused, not ignored.
        for (key, value) in [("PORTKIT_NOW", "yesterday"), ("PORTKIT_SEED", "seven")] {
            let out = kind.tool(source, "double", json!({"value": 1}), &[(key, value)]);
            assert_eq!(out.status.code(), Some(2), "{name}: {key}: {}", text(&out));
            assert!(
                err_text(&out).contains(key),
                "{name}: {key}: {}",
                err_text(&out)
            );
        }
    }
}

#[test]
fn what_the_module_prints_never_reaches_the_result() {
    for (kind, source) in [(NODE, NODE_NOISY), (PYTHON, PYTHON_NOISY)] {
        if !have(kind.runner) {
            continue;
        }
        let out = kind.tool(source, "f", json!({}), &[]);
        assert_eq!(out_text(&out), "{\"ok\":true}\n", "{}", kind.name);
        assert!(
            err_text(&out).contains("noise at load"),
            "{}: {}",
            kind.name,
            err_text(&out)
        );
    }
}

#[test]
fn non_json_values_become_plain_ones_or_are_refused() {
    if have("node") {
        let source = r#"
export function f() {
  return { map: new Map([["a", 1]]), set: new Set([3, 1]), re: /ab+c/gi, big: 10n ** 20n,
           date: new Date(0), typed: new Uint8Array([1, 2]), arr: [1, undefined, () => 1],
           omitted: undefined, fn: () => 1 };
}
"#;
        let out = NODE.tool(source, "f", json!({}), &[]);
        assert_eq!(
            out_text(&out),
            "{\"arr\":[1,null,null],\"big\":100000000000000000000,\"date\":\"1970-01-01T00:00:00.000Z\",\"map\":[[\"a\",1]],\"re\":\"ab+c\",\"set\":[3,1],\"typed\":[1,2]}\n"
        );
    }
    if have("python3") {
        let source = r#"
import datetime
def f(request):
    return {"t": (1, 2), "s": {3, 1, 2}, "d": datetime.date(2020, 1, 2), "n": None, 5: "five"}
def g(request):
    return {"b": b"bytes"}
"#;
        let out = PYTHON.tool(source, "f", json!({}), &[]);
        assert_eq!(
            out_text(&out),
            "{\"5\":\"five\",\"d\":\"2020-01-02\",\"n\":null,\"s\":[1,2,3],\"t\":[1,2]}\n"
        );
        let out = PYTHON.tool(source, "g", json!({}), &[]);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(err_text(&out).contains("bytes"), "{}", err_text(&out));
    }
}

// ---- determinism ---------------------------------------------------------------------------

#[test]
fn key_order_and_number_format_are_canonical_and_identical_across_adapters() {
    if !(have("node") && have("python3")) {
        return;
    }
    let from_node = NODE.tool(NODE_DATA, "data", json!({}), &[]);
    let from_python = PYTHON.tool(PYTHON_DATA, "data", json!({}), &[]);
    let expected = format!("{DATA_CANONICAL}\n");
    assert_eq!(out_text(&from_node), expected);
    assert_eq!(out_text(&from_python), expected);
    assert_eq!(from_node.stdout, from_python.stdout);

    // Again, in fresh processes: the same bytes.
    for (kind, source) in [(NODE, NODE_DATA), (PYTHON, PYTHON_DATA)] {
        let again = kind.tool(source, "data", json!({}), &[]);
        assert_eq!(again.stdout, from_node.stdout, "{}", kind.name);
    }
}

#[test]
fn the_raw_key_order_of_the_module_is_not_the_canonical_one() {
    // The control for the test above: JavaScript lists integer-like keys first and Python keeps
    // insertion order, so what the modules build differs; only the adapters' output is equal.
    if !(have("node") && have("python3")) {
        return;
    }
    let raw_node = r#"export function f() { return Object.keys({ b: 1, a: 2, 2: 3, 1: 4 }); }"#;
    let raw_python = r#"def f(request): return list({"b": 1, "a": 2, "2": 3, "1": 4})"#;
    let node = NODE.tool(raw_node, "f", json!({}), &[]);
    let python = PYTHON.tool(raw_python, "f", json!({}), &[]);
    assert_eq!(one_json_line(&node), json!(["1", "2", "b", "a"]));
    assert_eq!(one_json_line(&python), json!(["b", "a", "2", "1"]));
}

#[test]
fn python_set_order_is_pinned_by_the_hash_seed() {
    if !have("python3") {
        return;
    }
    let source = r#"def order(request): return list({"alpha", "beta", "gamma", "delta", "epsilon", "zeta"})"#;
    let first = PYTHON.tool(source, "order", json!({}), &[]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    for _ in 0..3 {
        let again = PYTHON.tool(source, "order", json!({}), &[]);
        assert_eq!(again.stdout, first.stdout);
    }
    // It is the seed 0 order: what an explicit PYTHONHASHSEED=0 gives.
    let pinned = PYTHON.tool(source, "order", json!({}), &[("PYTHONHASHSEED", "0")]);
    assert_eq!(pinned.stdout, first.stdout);
}

#[test]
fn the_clock_and_randomness_are_pinned_when_asked_and_left_alone_otherwise() {
    const NOW: &str = "2026-01-02T03:04:05.250+02:00"; // 2026-01-02T01:04:05.250Z
    if have("node") {
        let out = NODE.tool(NODE_CLOCK, "clock", json!({}), &[("PORTKIT_NOW", NOW)]);
        let v = one_json_line(&out);
        assert_eq!(v["now"], json!(1767315845250u64));
        assert_eq!(v["iso"], "2026-01-02T01:04:05.250Z");
        assert_eq!(v["callable"], "string");
        assert_eq!(v["explicit"], "1970-01-01T00:00:00.000Z");
        assert_eq!(v["is_date"], true);
        // TZ was unset, so the adapter made it UTC: local midnight is UTC midnight.
        assert_eq!(v["zone"], "2020-01-01T00:00:00.000Z");

        // Unpinned the module sees the real clock.
        let live = one_json_line(&NODE.tool(NODE_CLOCK, "clock", json!({}), &[]));
        assert_ne!(live["now"], v["now"]);
        assert!(live["now"].as_u64().unwrap() > 1767315845250u64);

        let a = NODE.tool(NODE_CLOCK, "dice", json!({}), &[("PORTKIT_SEED", "42")]);
        let b = NODE.tool(NODE_CLOCK, "dice", json!({}), &[("PORTKIT_SEED", "42")]);
        let c = NODE.tool(NODE_CLOCK, "dice", json!({}), &[("PORTKIT_SEED", "43")]);
        assert_eq!(a.stdout, b.stdout);
        assert_ne!(a.stdout, c.stdout);
        assert_eq!(one_json_line(&a).as_array().unwrap().len(), 3);
        let free1 = NODE.tool(NODE_CLOCK, "dice", json!({}), &[]);
        let free2 = NODE.tool(NODE_CLOCK, "dice", json!({}), &[]);
        assert_ne!(free1.stdout, free2.stdout);
    }
    if have("python3") {
        let out = PYTHON.tool(PYTHON_CLOCK, "clock", json!({}), &[("PORTKIT_NOW", NOW)]);
        let v = one_json_line(&out);
        assert_eq!(v["now"], json!(1767315845.25));
        assert_eq!(v["ns"], json!(1767315845250000000u64));
        assert_eq!(v["iso"], "2026-01-02T01:04:05.250000+00:00");
        assert_eq!(v["today"], "2026-01-02");
        assert_eq!(v["gm"], "2026-01-02 01:04:05");
        assert_eq!(v["is_date"], true);
        assert_eq!(v["explicit"], "1970-01-01T00:00:00");
        assert_eq!(v["zone"], "2020-01-01T00:00:00+00:00");

        let live = one_json_line(&PYTHON.tool(PYTHON_CLOCK, "clock", json!({}), &[]));
        assert_ne!(live["now"], v["now"]);
        assert!(live["now"].as_f64().unwrap() > 1767315845.25);

        // random.seed(42): the first draw of Python's generator, fixed by its documentation.
        let a =
            one_json_line(&PYTHON.tool(PYTHON_CLOCK, "dice", json!({}), &[("PORTKIT_SEED", "42")]));
        assert_eq!(a[0], json!(0.6394267984578837));
        let b = PYTHON.tool(PYTHON_CLOCK, "dice", json!({}), &[("PORTKIT_SEED", "42")]);
        assert_eq!(one_json_line(&b), a);
        let free1 = PYTHON.tool(PYTHON_CLOCK, "dice", json!({}), &[]);
        let free2 = PYTHON.tool(PYTHON_CLOCK, "dice", json!({}), &[]);
        assert_ne!(free1.stdout, free2.stdout);
    }
}

// ---- TypeScript ----------------------------------------------------------------------------

#[test]
fn typescript_runs_through_the_node_adapter_where_node_strips_types() {
    if workspace::skipped("typescript_runs_through_the_node_adapter_where_node_strips_types") {
        return;
    }
    if !have("node") {
        return;
    }
    // A copy under /var/tmp: Node's type stripping writes a cache under HOME, which must not
    // be the repository.
    let work = var_tmp("cp-adapter-ts-");
    let dir = work.path().to_path_buf();
    copy_tree(&fixtures().join("node"), &dir);
    let request = r#"{"tool":"tally","input":{"words":["b","a","2","1","B"]}}"#;
    let expected = "{\"counts\":{\"1\":1,\"2\":1,\"a\":1,\"b\":2},\"distinct\":4,\"total\":5}\n";

    // The same module in JavaScript always works.
    let out = NODE.call(&dir, &["tally.mjs"], request, &[]);
    assert_eq!(out_text(&out), expected, "{}", text(&out));

    if !node_strips_types() {
        eprintln!("SKIP: this Node has no --experimental-strip-types");
        return;
    }
    let mut cmd = Command::new("node");
    cmd.arg("--experimental-strip-types")
        .arg(NODE.install(&dir))
        .arg("tally.ts")
        .current_dir(&dir)
        .env("HOME", &dir);
    let out = run_with_stdin(&mut cmd, request);
    assert_eq!(out_text(&out), expected, "{}", text(&out));
    assert_eq!(
        out.stdout,
        NODE.call(&dir, &["tally.mjs"], request, &[]).stdout
    );
}

// ---- pk port adapter -----------------------------------------------------------------------

fn pk_entries() -> [(&'static str, Command); 2] {
    let pk = Command::new(env!("CARGO_BIN_EXE_pk"));
    let mut cowproof = Command::new(env!("CARGO_BIN_EXE_cowproof"));
    cowproof.arg("pk");
    [("pk", pk), ("cowproof pk", cowproof)]
}

fn run_plain(cmd: &mut Command, home: &Path) -> Output {
    let _g = fork_lock();
    cmd.env("HOME", home).stdin(Stdio::null()).output().unwrap()
}

#[test]
fn pk_port_adapter_prints_and_writes_the_embedded_files() {
    let home = var_tmp("cp-adapter-home-");
    let print = |entry: &Command, lang: &str| {
        let mut cmd = Command::new(entry.get_program());
        cmd.args(entry.get_args()).args(["port", "adapter", lang]);
        run_plain(&mut cmd, home.path())
    };
    let mut printed = Vec::new();
    for (label, mut entry) in pk_entries() {
        let node = print(&entry, "node");
        let python = print(&entry, "python");
        for (lang, out, shebang) in [
            ("node", &node, "#!/usr/bin/env node\n"),
            ("python", &python, "#!/usr/bin/env python3\n"),
        ] {
            assert_eq!(out.status.code(), Some(0), "{label} {lang}: {}", text(out));
            let adapter = out_text(out);
            assert!(adapter.starts_with(shebang), "{label} {lang}");
            for word in ["PORTKIT_NOW", "PORTKIT_SEED", "__defaults"] {
                assert!(adapter.contains(word), "{label} {lang}: {word}");
            }
        }
        // typescript and ts are the Node adapter.
        for alias in ["typescript", "ts"] {
            assert_eq!(print(&entry, alias).stdout, node.stdout, "{label} {alias}");
        }
        printed.push((node.stdout, python.stdout));

        // An unknown language is refused and the message says what exists.
        let out = run_plain(entry.args(["port", "adapter", "shell"]), home.path());
        assert_eq!(out.status.code(), Some(1), "{label}: {}", text(&out));
        assert!(out.stdout.is_empty());
        assert!(
            err_text(&out).contains("no capture adapter for `shell`"),
            "{label}: {}",
            err_text(&out)
        );
        assert!(
            err_text(&out).contains("node, python"),
            "{label}: {}",
            err_text(&out)
        );
    }
    // `pk` and `cowproof pk` print the same files.
    assert_eq!(printed[0], printed[1]);
    let python = String::from_utf8(printed[0].1.clone()).unwrap();

    // --out writes, refuses to overwrite, and --force replaces.
    let dir = var_tmp("cp-adapter-out-");
    let target = dir.path().join("adapter.py");
    let pk = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
        cmd.args(["port", "adapter", "python", "--out"])
            .arg(&target);
        cmd
    };
    let out = run_plain(&mut pk(), home.path());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read_to_string(&target).unwrap(), python);
    assert!(
        err_text(&out).contains("pk port capture --cmd 'python3 "),
        "{}",
        err_text(&out)
    );

    fs::write(&target, "mine").unwrap();
    let out = run_plain(&mut pk(), home.path());
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        err_text(&out).contains("already exists"),
        "{}",
        err_text(&out)
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "mine");

    let out = run_plain(pk().arg("--force"), home.path());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(fs::read_to_string(&target).unwrap(), python);
}

#[test]
fn the_embedded_adapters_are_the_files_on_disk_and_the_committed_python_copy() {
    if workspace::skipped(
        "the_embedded_adapters_are_the_files_on_disk_and_the_committed_python_copy",
    ) {
        return;
    }
    let home = var_tmp("cp-adapter-home-");
    for (lang, file) in [("node", "adapter.mjs"), ("python", "adapter.py")] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
        cmd.args(["port", "adapter", lang]);
        let out = run_plain(&mut cmd, home.path());
        assert_eq!(
            out_text(&out),
            fs::read_to_string(shipped(lang, file)).unwrap(),
            "{lang}"
        );
    }
    // The Python project of the worked example carries the adapter unchanged.
    let committed =
        fs::read_to_string(fixtures().join("python/project/reference/adapter.py")).unwrap();
    assert_eq!(
        committed,
        fs::read_to_string(shipped("python", "adapter.py")).unwrap()
    );
}

// ---- capture, replay, refute ---------------------------------------------------------------

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

/// `pk` in `dir` with a `HOME` of its own: its plugin manifest is `dir/.portkit/plugins.toml`.
fn pk_in(dir: &Path, home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pk"));
    cmd.args(args)
        .current_dir(dir)
        .env_remove("PORTKIT_NOW")
        .env_remove("PORTKIT_SEED");
    run_plain(&mut cmd, home)
}

fn compile(dir: &Path, name: &str, source: &str) {
    fs::create_dir_all(dir.join("target")).unwrap();
    fs::write(dir.join(format!("{name}.rs")), source).unwrap();
    let out = {
        let _g = fork_lock();
        Command::new("rustc")
            .args(["--edition", "2021"])
            .arg(dir.join(format!("{name}.rs")))
            .arg("-o")
            .arg(dir.join("target").join(name))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    assert!(out.status.success(), "rustc: {}", text(&out));
}

fn register(dir: &Path, binary: &str, tools: &[&str]) {
    fs::create_dir_all(dir.join(".portkit")).unwrap();
    let manifest: String = tools
        .iter()
        .map(|tool| format!("[[plugin]]\ncommand = \"target/{binary}\"\nargs = [\"{tool}\"]\n\n"))
        .collect();
    fs::write(dir.join(".portkit/plugins.toml"), manifest).unwrap();
}

/// Exact comparison, the way the verifier replays.
const PARITY_TOML: &str =
    "[parity]\nepsilon = 0.0\nepsilon_rel = 0.0\nignore_paths = []\nunordered_arrays = false\n";

fn replay(dir: &Path, home: &Path, fixtures: &str) -> Output {
    fs::write(dir.join("pk.toml"), PARITY_TOML).unwrap();
    pk_in(
        dir,
        home,
        &[
            "--config",
            "pk.toml",
            "port",
            "replay",
            "--fixtures",
            fixtures,
            "--surface",
            "both",
            "--epsilon",
            "0",
        ],
    )
}

fn fixture_values(root: &Path) -> Vec<Value> {
    let mut all = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "json") {
                let mut v: Value =
                    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
                // The capture time is the one field that differs per run.
                v.as_object_mut().unwrap().remove("captured_at");
                all.push(v);
            }
        }
    }
    all.sort_by_key(|v| (v["tool"].to_string(), v["id"].to_string()));
    all
}

/// `{FOLD}` is how the port folds case: `word.to_lowercase()` is right, `word.clone()` is wrong.
const TALLY_RS: &str = r#"use std::collections::BTreeMap;
use std::io::Read;

fn words(request: &str) -> Vec<String> {
    let Some(start) = request.find("\"words\":[") else { return Vec::new() };
    let rest = &request[start + 9..];
    let end = rest.find(']').unwrap_or(rest.len());
    rest[..end]
        .split(',')
        .map(|w| w.trim().trim_matches('"').to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let tool = args.get(1).map(String::as_str).unwrap_or("tally");
    if args.iter().any(|a| a == "--portkit-spec") {
        println!("{{\"name\":\"{tool}\",\"description\":\"word counts\",\"input_schema\":{{\"type\":\"object\"}}}}");
        return;
    }
    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request).unwrap();
    if tool == "__defaults" {
        println!("{{\"CASE_FOLD\":true,\"MIN_LENGTH\":1}}");
        return;
    }
    let all = words(&request);
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for word in &all {
        let key = {FOLD};
        if key.is_empty() {
            continue;
        }
        *counts.entry(key).or_insert(0) += 1;
    }
    let body: Vec<String> = counts.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    println!("{{\"counts\":{{{}}},\"distinct\":{},\"total\":{}}}", body.join(","), counts.len(), all.len());
}
"#;

/// `{ROUND}` rounds the scaled charge to a whole number of cents: half to even (right: it is
/// what Python's `round` does) or `scaled.round()` (half away from zero: wrong on a tie).
const SHIP_RS: &str = r#"use std::io::Read;

fn number(json: &str, key: &str) -> Option<f64> {
    let marker = format!("\"{key}\":");
    let start = json.find(&marker)? + marker.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || "+-.eE".contains(c)))
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn numbers(json: &str, key: &str) -> Vec<f64> {
    let marker = format!("\"{key}\":[");
    let Some(start) = json.find(&marker) else { return Vec::new() };
    let rest = &json[start + marker.len()..];
    let end = rest.find(']').unwrap_or(rest.len());
    rest[..end].split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

fn round_cents(x: f64) -> f64 {
    let scaled = x * 100.0;
    let cents = {ROUND};
    cents / 100.0
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let tool = args.get(1).map(String::as_str).unwrap_or("quote");
    if args.iter().any(|a| a == "--portkit-spec") {
        println!("{{\"name\":\"{tool}\",\"description\":\"shipping\",\"input_schema\":{{\"type\":\"object\"}}}}");
        return;
    }
    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request).unwrap();
    match tool {
        "__defaults" => println!("{{\"CURRENCY\":\"USD\",\"RATE_PER_KG\":0.5}}"),
        "total" => {
            let charges = numbers(&request, "charges");
            let sum = charges.iter().fold(0.0, |a, b| a + b);
            println!("{{\"count\":{},\"total\":{}}}", charges.len(), sum);
        }
        _ => {
            let kg = number(&request, "kg").unwrap_or(0.0);
            println!("{{\"charge\":{},\"currency\":\"USD\",\"kg\":{}}}", round_cents(kg * 0.5), kg);
        }
    }
}
"#;

const HALF_EVEN: &str = "if (scaled - scaled.trunc()).abs() == 0.5 { 2.0 * (scaled / 2.0).round() } else { scaled.round() }";
const HALF_AWAY: &str = "scaled.round()";

fn tally_rs(fold: &str) -> String {
    TALLY_RS.replace("{FOLD}", fold)
}

fn ship_rs(round: &str) -> String {
    SHIP_RS.replace("{ROUND}", round)
}

fn stdout_of(out: &Output) -> String {
    out_text(out)
}

#[test]
fn a_node_module_is_captured_through_its_adapter_and_a_rust_port_is_replayed_against_it() {
    if workspace::skipped(
        "a_node_module_is_captured_through_its_adapter_and_a_rust_port_is_replayed_against_it",
    ) {
        return;
    }
    if !have("node") {
        return;
    }
    let home = var_tmp("cp-adapter-home-");
    let project = var_tmp("cp-adapter-node-");
    let dir = project.path();
    copy_tree(&fixtures().join("node"), dir);

    // The adapter reaches the project the way a user would get it.
    let out = pk_in(
        dir,
        home.path(),
        &["port", "adapter", "node", "--out", "adapter.mjs"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    let capture = |into: &str| {
        pk_in(
            dir,
            home.path(),
            &[
                "port",
                "capture",
                "--cmd",
                "node adapter.mjs tally.mjs",
                "--cases",
                "cases.jsonl",
                "--out",
                into,
            ],
        )
    };
    let out = capture("fixtures");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout_of(&out).contains("4 captured, 0 failed"),
        "{}",
        text(&out)
    );

    // The trap: the module builds `counts` with integer-like keys, which JavaScript orders
    // before the others. The adapter sorts, so two captures hold the same data and the
    // fixtures do not depend on the engine's key order.
    let out = capture("fixtures-again");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let first = fixture_values(&dir.join("fixtures"));
    assert_eq!(first, fixture_values(&dir.join("fixtures-again")));
    let mixed = first.iter().find(|v| v["id"] == "mixed").unwrap();
    assert_eq!(
        mixed["expected"],
        json!({"counts": {"1": 1, "2": 1, "a": 1, "b": 2}, "distinct": 4, "total": 5})
    );
    let defaults = first.iter().find(|v| v["tool"] == "__defaults").unwrap();
    assert_eq!(
        defaults["expected"],
        json!({"CASE_FOLD": true, "MIN_LENGTH": 1})
    );

    // A right port passes both surfaces with epsilon 0.
    compile(dir, "tally", &tally_rs("word.to_lowercase()"));
    register(dir, "tally", &["tally", "__defaults"]);
    let out = replay(dir, home.path(), "fixtures");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!stdout_of(&out).contains("FAIL"), "{}", text(&out));

    // A port that forgets to fold case is refuted, naming the fixture and the path.
    compile(dir, "tally", &tally_rs("word.clone()"));
    let out = replay(dir, home.path(), "fixtures");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let report = stdout_of(&out);
    assert!(report.contains("fixture mixed"), "{report}");
    assert!(report.contains("fixture repeats"), "{report}");
    assert!(report.contains("/counts/b"), "{report}");
    assert!(!report.contains("fixture empty"), "{report}");
}

#[test]
fn a_python_module_is_captured_through_its_adapter_and_a_wrong_rounding_is_refuted() {
    if workspace::skipped(
        "a_python_module_is_captured_through_its_adapter_and_a_wrong_rounding_is_refuted",
    ) {
        return;
    }
    if !have("python3") {
        return;
    }
    let home = var_tmp("cp-adapter-home-");
    let project = var_tmp("cp-adapter-python-");
    let dir = project.path();
    copy_tree(&fixtures().join("python/project"), dir);
    // The adapter under test is the shipped one, written the way a user gets it.
    let out = pk_in(
        dir,
        home.path(),
        &[
            "port",
            "adapter",
            "python",
            "--out",
            "reference/adapter.py",
            "--force",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // Recapturing through the adapter gives the committed fixtures (a drift guard on the
    // adapter, the module and the fixtures together).
    let out = pk_in(
        dir,
        home.path(),
        &[
            "port",
            "capture",
            "--cmd",
            "python3 reference/adapter.py reference/shipping.py",
            "--cases",
            "ports/shipping/cases.jsonl",
            "--out",
            "fresh",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let fresh = fixture_values(&dir.join("fresh"));
    let committed = fixture_values(&dir.join("ports/shipping/fixtures"));
    assert_eq!(fresh.len(), 6);
    assert_eq!(fresh, committed);
    let tie = committed.iter().find(|v| v["id"] == "tie").unwrap();
    assert_eq!(tie["expected"]["charge"], json!(0.12));
    let pair = committed.iter().find(|v| v["id"] == "pair").unwrap();
    assert_eq!(pair["expected"]["total"], json!(0.30000000000000004));

    // The right port (half to even, a plain float sum) passes with epsilon 0.
    register(dir, "ship", &["quote", "total", "__defaults"]);
    compile(dir, "ship", &ship_rs(HALF_EVEN));
    let out = replay(dir, home.path(), "ports/shipping/fixtures");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // Rounding half away from zero says 0.13 where Python says 0.12: refuted, and only there.
    // The trap is not loosened away: the replay still compares at epsilon 0.
    compile(dir, "ship", &ship_rs(HALF_AWAY));
    let out = replay(dir, home.path(), "ports/shipping/fixtures");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let report = stdout_of(&out);
    assert!(report.contains("fixture tie"), "{report}");
    assert!(report.contains("/charge"), "{report}");
    assert!(
        report.contains("0.12") && report.contains("0.13"),
        "{report}"
    );
    assert!(!report.contains("fixture whole"), "{report}");
    assert!(!report.contains("fixture pair"), "{report}");
}

// ---- cowproof run --------------------------------------------------------------------------

const PACKET_ID: &str = "port-1";

fn python_fixture() -> PathBuf {
    fixtures().join("python")
}

fn packet(id: &str) -> String {
    let text = fs::read_to_string(python_fixture().join("packet.md")).unwrap();
    assert!(text.contains(&format!("\"id\":\"{PACKET_ID}\"")));
    text.replace(
        &format!("\"id\":\"{PACKET_ID}\""),
        &format!("\"id\":\"{id}\""),
    )
}

fn manifest(tools: &[&str]) -> String {
    tools
        .iter()
        .map(|tool| format!("[[plugin]]\ncommand = \"target/ship\"\nargs = [\"{tool}\"]\n"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_python_port_packet_with_a_function_adapter_is_proved() {
    if workspace::skipped("a_python_port_packet_with_a_function_adapter_is_proved") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let source = ship_rs(HALF_EVEN);
    let body = format!(
        "cat > tools/ship.rs <<'RUST'\n{source}RUST\ncat > .portkit/plugins.toml <<'TOML'\n{}TOML\n{}",
        manifest(&["quote", "total", "__defaults"]),
        run_checks(&["build"]),
    );
    let lane = Lane::from_project(&body, &python_fixture().join("project"), &packet);
    let heldout = python_fixture().join("heldout/heldout.toml");
    let out = lane.run(&[Path::new("--heldout"), &heldout]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["failedGates"], json!([]), "{verdict}");

    let gates: Value =
        serde_json::from_str(&fs::read_to_string(lane.capsule_dir().join("gates.json")).unwrap())
            .unwrap();
    let gates = gates["gates"].as_array().unwrap();
    let port = gates.iter().find(|g| g["name"] == "port_replay").unwrap();
    assert_eq!(port["passed"], true, "{port}");
    assert!(port["evidence"].to_string().contains("6 fixture"), "{port}");

    // The capsule records the adapter command and the pins the verifier applied.
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let port = capsule.port.expect("a port capsule");
    let reference = port.reference.as_ref().unwrap();
    assert_eq!(
        reference.cmd,
        "python3 reference/adapter.py reference/shipping.py"
    );
    assert_eq!(reference.env["PORTKIT_NOW"], "2026-01-02T03:04:05Z");
    assert_eq!(port.tools, ["quote", "total", "__defaults"]);
    assert_eq!(port.epsilon, 0.0);
    let result = port.result.expect("the replay is recorded");
    assert!(result.success, "{:?}", result.failures);
    assert_eq!(result.fixture_count, 6);
    assert_eq!(result.surfaces["direct"].passed, 6);
    assert_eq!(result.surfaces["mcp"].passed, 6);

    // The held-out cases (1.25 kg is a tie that rounds to 0.62) were captured through the
    // adapter in the verifier's sandbox, or skipped out loud when the sandbox has no python3.
    let held = &result.held_out;
    match held.state.as_str() {
        "passed" => assert_eq!(held.cases, 3),
        "skipped" => assert!(
            held.reason.as_deref().unwrap_or("").contains("python3"),
            "{:?}",
            held.reason
        ),
        other => panic!("held-out state {other}: {:?}", held.reason),
    }
}
