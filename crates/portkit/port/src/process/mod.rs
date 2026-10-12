//! Whole-process capture: a shell script (or any executable) as the reference.
//!
//! A script has no function to call, so the unit of capture is the process. A case's `input`
//! is what the process is given and `expected` is everything it did:
//!
//! ```text
//! input    {argv, env, stdin, files, shims, record_env}
//! expected {exit, stdout, stderr, files_after, deleted, calls}
//! ```
//!
//! `pk port exec` runs the reference once per case in a fresh root directory, network denied,
//! with PATH shims standing in for the external programs the case declares (see [`shim`]).
//! `pk port wrap` runs a Rust port (a binary that takes the same arguments) in exactly the
//! same harness, so both sides produce the same envelope and `pk port replay` compares like
//! with like.
//!
//! The pieces here are shared by both sides and are plain functions of their inputs, so a Rust
//! port that is a library and not a binary can use them too: [`ProcessInput::parse`],
//! [`Root`], [`PathNormaliser`], [`shim::Scripted`] and [`shim::choose`].

pub mod exec;
pub mod shim;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::fixture::Normalized;
use shim::Scripted;

/// The name of the declared transform that replaces the run's directories with fixed tokens.
pub const PATH_ROOTS_NAME: &str = "path-roots";

/// Its version. A fixture records the version it was captured with, and a replay refuses one
/// it does not know. Bump it when the substitution changes in a way that changes a recorded
/// value (the set of tokens, the boundary rule, the order).
pub const PATH_ROOTS_VERSION: u32 = 1;

/// The tokens `path_roots` may declare, in the order they are tried when two would match the
/// same text (the longest path first): `$HOME` is `$ROOT/home`, `$TMP` is `$ROOT/tmp`, `$ROOT`
/// is the directory the process ran in, `$SRC` is the directory the reference lives in.
pub const ROOT_TOKENS: [&str; 4] = ["$HOME", "$TMP", "$ROOT", "$SRC"];

/// A file of at most this many bytes has its text recorded in `files_after`, beside its hash.
pub const SMALL_FILE: usize = 4096;

/// The subdirectories of the root the harness creates; empty, they are not recorded.
const SCAFFOLD: [&str; 2] = ["home", "tmp"];

/// Check a fixture's declared transform against what this build implements.
pub fn check_normalized(n: &Normalized) -> Result<(), String> {
    if n.name != PATH_ROOTS_NAME || n.version != PATH_ROOTS_VERSION {
        return Err(format!(
            "unknown normalizer `{}` v{} (this build knows `{PATH_ROOTS_NAME}` v{PATH_ROOTS_VERSION})",
            n.name, n.version
        ));
    }
    for root in &n.roots {
        if !ROOT_TOKENS.contains(&root.as_str()) {
            return Err(format!(
                "`{PATH_ROOTS_NAME}` v{PATH_ROOTS_VERSION} does not know the root `{root}` (it knows {})",
                ROOT_TOKENS.join(", ")
            ));
        }
    }
    Ok(())
}

/// The declaration a fixture records for `roots`; `None` when no root is declared (nothing is
/// substituted, and the fixture says nothing).
pub fn normalized_for(roots: &[String]) -> Option<Normalized> {
    if roots.is_empty() {
        return None;
    }
    let mut roots: Vec<String> = roots
        .iter()
        .filter(|r| ROOT_TOKENS.contains(&r.as_str()))
        .cloned()
        .collect();
    roots.sort();
    roots.dedup();
    Some(Normalized {
        name: PATH_ROOTS_NAME.to_string(),
        version: PATH_ROOTS_VERSION,
        roots,
    })
}

// ---- the case input ------------------------------------------------------------------------

/// What a process case gives the process: `input` of the fixture, parsed strictly (an unknown
/// key is an error, not a silently dropped typo).
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInput {
    /// Arguments after the command.
    pub argv: Vec<String>,
    /// Environment on top of the harness's pinned one.
    pub env: BTreeMap<String, String>,
    /// Text on the process's stdin.
    pub stdin: String,
    /// Files materialised into the root before the run, by relative path.
    pub files: BTreeMap<String, InputFile>,
    /// The external programs the case declares, each with its scripted responses.
    pub shims: BTreeMap<String, Vec<Scripted>>,
    /// Names of environment variables each recorded call carries.
    pub record_env: Vec<String>,
}

/// One file to materialise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    pub content: String,
    /// Permission bits; 0o644 when the case gives none.
    pub mode: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInput {
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    stdin: String,
    #[serde(default)]
    files: BTreeMap<String, RawFile>,
    #[serde(default)]
    shims: BTreeMap<String, Vec<Scripted>>,
    #[serde(default)]
    record_env: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawFile {
    Text(String),
    Full(RawFull),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFull {
    content: String,
    #[serde(default)]
    mode: Option<u32>,
}

impl ProcessInput {
    /// Parse and validate a case's `input`.
    pub fn parse(value: &Value) -> Result<Self, String> {
        let raw: RawInput = serde_json::from_value(value.clone())
            .map_err(|e| format!("the case input is not a process input: {e}"))?;
        let mut files = BTreeMap::new();
        for (path, file) in raw.files {
            check_relative(&path)?;
            let (content, mode) = match file {
                RawFile::Text(content) => (content, 0o644),
                RawFile::Full(f) => (f.content, f.mode.unwrap_or(0o644)),
            };
            if mode > 0o777 {
                return Err(format!(
                    "files[{path:?}]: mode {mode:o} is more than the permission bits (0o777)"
                ));
            }
            files.insert(path, InputFile { content, mode });
        }
        for (program, responses) in &raw.shims {
            check_program(program)?;
            for response in responses {
                response.validate(program)?;
            }
        }
        for key in raw.env.keys().chain(raw.record_env.iter()) {
            check_env_name(key)?;
        }
        if raw.argv.iter().any(|a| a.contains('\0')) || raw.stdin.contains('\0') {
            return Err("argv and stdin may not contain a NUL".into());
        }
        Ok(Self {
            argv: raw.argv,
            env: raw.env,
            stdin: raw.stdin,
            files,
            shims: raw.shims,
            record_env: raw.record_env,
        })
    }
}

fn check_relative(path: &str) -> Result<(), String> {
    let ok = !path.is_empty()
        && !path.contains('\0')
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "files[{path:?}]: a path inside the root (relative, no `..`, no empty part)"
        ))
    }
}

fn check_program(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'));
    if !ok {
        return Err(format!(
            "shims: {name:?} is not a program name ([A-Za-z0-9_.+-], not starting with a dot)"
        ));
    }
    // The harness runs the reference through `sh`; a shim of it would answer for the shell.
    if name == "sh" {
        return Err(
            "shims: `sh` cannot be a shim, the harness runs the reference through it".into(),
        );
    }
    Ok(())
}

fn check_env_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let first = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if first && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(())
    } else {
        Err(format!("{name:?} is not an environment variable name"))
    }
}

// ---- path substitution (G13) ---------------------------------------------------------------

/// The declared `path_roots` substitution: a run's directories replaced by fixed tokens, so
/// two runs in two temp roots record the same text.
#[derive(Debug, Clone, Default)]
pub struct PathNormaliser {
    /// `(absolute path, token)`, longest path first.
    subs: Vec<(String, &'static str)>,
}

impl PathNormaliser {
    /// The substitution for `declared` (tokens of [`ROOT_TOKENS`]; others are ignored here and
    /// refused by [`check_normalized`]) in a run rooted at `root`, with the reference's
    /// directory `src`. Nothing declared, nothing substituted.
    pub fn new(declared: &[String], root: &Path, src: &Path) -> Self {
        let mut subs: Vec<(String, &'static str)> = Vec::new();
        for token in ROOT_TOKENS {
            if !declared.iter().any(|d| d == token) {
                continue;
            }
            let mut paths = Vec::new();
            match token {
                "$HOME" => paths.push(root.join("home")),
                "$TMP" => paths.push(root.join("tmp")),
                "$ROOT" => paths.push(root.to_path_buf()),
                _ => {
                    paths.push(src.to_path_buf());
                    if let Ok(real) = src.canonicalize() {
                        paths.push(real);
                    }
                }
            }
            for path in paths {
                if let Some(text) = path.to_str() {
                    if !text.is_empty() && text != "/" && !subs.iter().any(|(p, _)| p == text) {
                        subs.push((text.to_string(), token));
                    }
                }
            }
        }
        subs.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
        Self { subs }
    }

    /// Whether anything is substituted.
    pub fn is_empty(&self) -> bool {
        self.subs.is_empty()
    }

    /// `text` with every declared directory replaced by its token. A directory is replaced
    /// where it stands as a whole path component: the next character is not one that would
    /// continue a name (`[A-Za-z0-9_-]`), so `/x/root` does not eat the start of `/x/rootbeer`.
    pub fn text(&self, text: &str) -> String {
        if self.subs.is_empty() {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        'scan: while at < text.len() {
            let rest = &text[at..];
            for (path, token) in &self.subs {
                if let Some(after) = rest.strip_prefix(path.as_str()) {
                    let continues = after
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                    if !continues {
                        out.push_str(token);
                        at += path.len();
                        continue 'scan;
                    }
                }
            }
            let c = rest.chars().next().expect("at < len");
            out.push(c);
            at += c.len_utf8();
        }
        out
    }

    /// Every string of `value`, substituted.
    pub fn json(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.text(s)),
            Value::Array(items) => Value::Array(items.iter().map(|v| self.json(v)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), self.json(v)))
                    .collect::<Map<String, Value>>(),
            ),
            other => other.clone(),
        }
    }
}

// ---- the root ------------------------------------------------------------------------------

/// The directory a process case runs in: `cwd`, with `home/` and `tmp/` inside it.
#[derive(Debug)]
pub struct Root {
    path: PathBuf,
    initial: BTreeSet<String>,
}

impl Root {
    /// Create `dir` (and `dir/home`, `dir/tmp`) and write the case's files into it, with the
    /// modes the case asks for. `dir` must not exist yet. The root's path is canonical.
    pub fn materialise(dir: &Path, input: &ProcessInput) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.canonicalize()?;
        for name in SCAFFOLD {
            fs::create_dir_all(path.join(name))?;
        }
        let mut initial = BTreeSet::new();
        for (rel, file) in &input.files {
            let target = path.join(rel);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&target, file.content.as_bytes())?;
            fs::set_permissions(&target, fs::Permissions::from_mode(file.mode))?;
            initial.insert(rel.clone());
        }
        Ok(Self { path, initial })
    }

    /// `$ROOT`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `$HOME`.
    pub fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    /// `$TMP`.
    pub fn tmp(&self) -> PathBuf {
        self.path.join("tmp")
    }

    /// What is in the root now, as `(files_after, deleted)`.
    ///
    /// `files_after` maps each path (relative, `/`-separated) to `{sha256, mode, size}` and,
    /// for a file of at most [`SMALL_FILE`] bytes, its `content`. A text file is hashed and
    /// recorded after the path substitution, so a file that holds the root's path hashes the
    /// same in every run; a file that is not UTF-8 is hashed as it is. A symlink is
    /// `{"link": target}`, an empty directory (other than `home` and `tmp`) `{"dir": true}`,
    /// anything else `{"special": true}`. `deleted` lists the files the case materialised that
    /// are no longer there.
    pub fn snapshot(&self, norm: &PathNormaliser) -> io::Result<(Value, Vec<String>)> {
        let mut files = BTreeMap::new();
        walk(&self.path, "", norm, &mut files)?;
        let deleted: Vec<String> = self
            .initial
            .iter()
            .filter(|rel| !files.contains_key(rel.as_str()))
            .cloned()
            .collect();
        let map: Map<String, Value> = files.into_iter().collect();
        Ok((Value::Object(map), deleted))
    }
}

fn walk(
    dir: &Path,
    rel: &str,
    norm: &PathNormaliser,
    out: &mut BTreeMap<String, Value>,
) -> io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<io::Result<_>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let key = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let meta = fs::symlink_metadata(&path)?;
        let kind = meta.file_type();
        if kind.is_symlink() {
            let target = fs::read_link(&path)?;
            out.insert(key, json!({"link": norm.text(&target.to_string_lossy())}));
        } else if kind.is_dir() {
            let before = out.len();
            walk(&path, &key, norm, out)?;
            if out.len() == before && !(rel.is_empty() && SCAFFOLD.contains(&name.as_str())) {
                out.insert(key, json!({"dir": true}));
            }
        } else if kind.is_file() {
            let bytes = fs::read(&path)?;
            out.insert(
                key,
                file_entry(&bytes, meta.permissions().mode() & 0o777, norm),
            );
        } else {
            out.insert(key, json!({"special": true}));
        }
    }
    Ok(())
}

/// `{sha256, mode, size[, content]}` of one file's bytes.
fn file_entry(bytes: &[u8], mode: u32, norm: &PathNormaliser) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let text = norm.text(text);
            let mut entry = json!({
                "sha256": sha256_hex(text.as_bytes()),
                "mode": mode,
                "size": text.len(),
            });
            if text.len() <= SMALL_FILE {
                entry["content"] = Value::String(text);
            }
            entry
        }
        Err(_) => json!({
            "sha256": sha256_hex(bytes),
            "mode": mode,
            "size": bytes.len(),
        }),
    }
}

/// Lowercase hex `sha256` of `bytes`: the hash `files_after` records.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The envelope a process case records.
#[allow(clippy::too_many_arguments)]
pub fn envelope(
    exit: i32,
    stdout: &str,
    stderr: &str,
    files_after: Value,
    deleted: &[String],
    calls: Vec<Value>,
    norm: &PathNormaliser,
) -> Value {
    json!({
        "exit": exit,
        "stdout": norm.text(stdout),
        "stderr": norm.text(stderr),
        "files_after": files_after,
        "deleted": deleted,
        "calls": calls.iter().map(|c| norm.json(c)).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn norm(declared: &[&str], root: &str, src: &str) -> PathNormaliser {
        let declared: Vec<String> = declared.iter().map(|s| s.to_string()).collect();
        PathNormaliser::new(&declared, Path::new(root), Path::new(src))
    }

    #[test]
    fn the_declared_roots_are_replaced_longest_first() {
        let n = norm(&["$ROOT", "$HOME", "$TMP"], "/x/run1/root", "/src");
        assert_eq!(
            n.text("cd /x/run1/root; ls /x/run1/root/home/a /x/run1/root/tmp/b /x/run1/root/c"),
            "cd $ROOT; ls $HOME/a $TMP/b $ROOT/c"
        );
        // Only what is declared: with `$ROOT` alone, home stays a path under it.
        let n = norm(&["$ROOT"], "/x/run1/root", "/src");
        assert_eq!(n.text("/x/run1/root/home/a"), "$ROOT/home/a");
        // Nothing declared, nothing replaced.
        let n = norm(&[], "/x/run1/root", "/src");
        assert!(n.is_empty());
        assert_eq!(n.text("/x/run1/root/a"), "/x/run1/root/a");
    }

    #[test]
    fn a_root_is_a_whole_path_component() {
        let n = norm(&["$ROOT"], "/x/root", "/src");
        assert_eq!(
            n.text("/x/rootbeer /x/root-2 /x/root_a"),
            "/x/rootbeer /x/root-2 /x/root_a"
        );
        assert_eq!(n.text("in /x/root."), "in $ROOT.");
        assert_eq!(n.text("'/x/root'"), "'$ROOT'");
        assert_eq!(n.text("/x/root"), "$ROOT");
    }

    #[test]
    fn two_runs_in_two_roots_record_the_same_text() {
        let a = norm(&["$ROOT", "$HOME"], "/var/tmp/pk-1/root", "/src");
        let b = norm(&["$ROOT", "$HOME"], "/var/tmp/pk-2/root", "/src");
        let one = a.text("wrote /var/tmp/pk-1/root/home/.cfg");
        let two = b.text("wrote /var/tmp/pk-2/root/home/.cfg");
        assert_eq!(one, two);
        assert_eq!(one, "wrote $HOME/.cfg");
    }

    #[test]
    fn json_values_are_substituted_at_every_depth() {
        let n = norm(&["$ROOT"], "/r", "/src");
        assert_eq!(
            n.json(&json!({"a": ["/r/x", {"b": "/r"}], "n": 1, "t": true})),
            json!({"a": ["$ROOT/x", {"b": "$ROOT"}], "n": 1, "t": true})
        );
    }

    #[test]
    fn the_substitution_is_declared_and_versioned() {
        assert_eq!(normalized_for(&[]), None);
        let declared = normalized_for(&["$TMP".into(), "$ROOT".into(), "$ROOT".into()]).unwrap();
        assert_eq!(declared.name, "path-roots");
        assert_eq!(declared.version, 1);
        assert_eq!(declared.roots, ["$ROOT", "$TMP"]);
        assert!(check_normalized(&declared).is_ok());

        // A fixture from another version, another name or another root is refused.
        let mut other = declared.clone();
        other.version = 2;
        assert!(check_normalized(&other).unwrap_err().contains("v2"));
        let mut other = declared.clone();
        other.name = "squash-paths".into();
        assert!(check_normalized(&other)
            .unwrap_err()
            .contains("squash-paths"));
        let mut other = declared;
        other.roots.push("$ELSEWHERE".into());
        assert!(check_normalized(&other).unwrap_err().contains("$ELSEWHERE"));
    }

    #[test]
    fn the_input_is_parsed_strictly() {
        let ok = ProcessInput::parse(&json!({
            "argv": ["a"],
            "env": {"K": "v"},
            "stdin": "in",
            "files": {"x.txt": "hi\n", "bin/run": {"content": "#!/bin/sh\n", "mode": 493}},
            "shims": {"git": [{"stdout": "abc\n"}]},
            "record_env": ["GIT_DIR"]
        }))
        .unwrap();
        assert_eq!(ok.files["x.txt"].mode, 0o644);
        assert_eq!(ok.files["bin/run"].mode, 0o755);
        assert_eq!(ok.shims["git"][0].stdout, "abc\n");
        assert_eq!(
            ProcessInput::parse(&json!({})).unwrap().argv,
            Vec::<String>::new()
        );

        for (bad, why) in [
            (json!({"stdn": "x"}), "stdn"),
            (json!({"files": {"../x": "a"}}), "inside the root"),
            (json!({"files": {"/etc/x": "a"}}), "inside the root"),
            (json!({"files": {"a//b": "a"}}), "inside the root"),
            (
                json!({"files": {"a": {"content": "", "mode": 4095}}}),
                "permission bits",
            ),
            (json!({"shims": {"sh": []}}), "`sh`"),
            (json!({"shims": {"a/b": []}}), "program name"),
            (json!({"env": {"1X": "v"}}), "environment variable name"),
            (json!({"argv": ["a\u{0}b"]}), "NUL"),
            (json!({"shims": {"git": [{"stdot": "x"}]}}), "stdot"),
        ] {
            let err = ProcessInput::parse(&bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pk-process-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_root_is_materialised_and_snapshotted() {
        let input = ProcessInput::parse(&json!({
            "files": {
                "in.txt": "hello\n",
                "bin/run": {"content": "echo\n", "mode": 493},
                "gone.txt": "bye\n",
                "dir/inner.txt": "x"
            }
        }))
        .unwrap();
        let dir = scratch("snap");
        let root = Root::materialise(&dir.join("root"), &input).unwrap();
        assert!(root.home().is_dir() && root.tmp().is_dir());
        let n = PathNormaliser::new(&["$ROOT".to_string()], root.path(), Path::new("/src"));

        // The process writes a file that holds the root's path, a binary file, a symlink and an
        // empty directory, and deletes one input.
        fs::write(
            root.path().join("out.txt"),
            format!("cwd={}\n", root.path().display()),
        )
        .unwrap();
        fs::write(root.path().join("blob.bin"), [0xff, 0xfe, 0x00]).unwrap();
        fs::write(root.path().join("big.txt"), "z".repeat(SMALL_FILE + 1)).unwrap();
        std::os::unix::fs::symlink("in.txt", root.path().join("ln")).unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        fs::remove_file(root.path().join("gone.txt")).unwrap();

        let (files, deleted) = root.snapshot(&n).unwrap();
        assert_eq!(deleted, ["gone.txt"]);
        assert_eq!(files["in.txt"]["content"], "hello\n");
        assert_eq!(files["in.txt"]["mode"], 0o644);
        assert_eq!(files["in.txt"]["size"], 6);
        assert_eq!(files["in.txt"]["sha256"], sha256_hex(b"hello\n"));
        assert_eq!(files["bin/run"]["mode"], 0o755);
        assert_eq!(files["dir/inner.txt"]["content"], "x");
        // The path in a file's text is substituted, and the hash is of the substituted text.
        assert_eq!(files["out.txt"]["content"], "cwd=$ROOT\n");
        assert_eq!(files["out.txt"]["sha256"], sha256_hex(b"cwd=$ROOT\n"));
        // Binary: hash only. Big text: hash and size, no content.
        assert!(files["blob.bin"].get("content").is_none());
        assert_eq!(files["blob.bin"]["sha256"], sha256_hex(&[0xff, 0xfe, 0x00]));
        assert!(files["big.txt"].get("content").is_none());
        assert_eq!(files["big.txt"]["size"], SMALL_FILE + 1);
        assert_eq!(files["ln"], json!({"link": "in.txt"}));
        assert_eq!(files["empty"], json!({"dir": true}));
        // The scaffold directories are not recorded while empty.
        assert!(files.get("home").is_none() && files.get("tmp").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_content_changes_the_hash_and_the_text() {
        let input = ProcessInput::parse(&json!({"files": {"a": "one"}})).unwrap();
        let dir = scratch("hash");
        let root = Root::materialise(&dir.join("root"), &input).unwrap();
        let n = PathNormaliser::default();
        let (before, _) = root.snapshot(&n).unwrap();
        fs::write(root.path().join("a"), "two").unwrap();
        let (after, _) = root.snapshot(&n).unwrap();
        assert_ne!(before["a"]["sha256"], after["a"]["sha256"]);
        assert_eq!(after["a"]["content"], "two");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_envelope_has_the_documented_shape() {
        let n = norm(&["$ROOT"], "/r", "/src");
        let env = envelope(
            2,
            "out /r/a\n",
            "err\n",
            json!({}),
            &["x".to_string()],
            vec![json!({"program": "git", "argv": ["-C", "/r"], "env": {}, "stdin": null})],
            &n,
        );
        assert_eq!(
            env,
            json!({
                "exit": 2,
                "stdout": "out $ROOT/a\n",
                "stderr": "err\n",
                "files_after": {},
                "deleted": ["x"],
                "calls": [{"program": "git", "argv": ["-C", "$ROOT"], "env": {}, "stdin": null}]
            })
        );
    }
}
