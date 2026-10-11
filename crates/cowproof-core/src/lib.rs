#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub mod git_show;
pub mod heldout;
pub mod ladder;
pub mod patch;
pub mod redact;
pub mod status;

pub use git_show::{LinkedFile, git_show_following_links, git_show_optional};
pub use ladder::{PACKET_CLASSES, Routing, Rung, RungSource, Runtime, valid_model_name};
pub use patch::{PatchDelta, parse_patch};
pub use redact::redact;
pub use status::{LaneStatus, StatusClass, StatusFacts, classify_opencode, classify_status};

/// The first port of the lanes' port blocks.
///
/// Every lane holds one slot of the machine-wide `port` class ([`PORT_CLASS`]) for its
/// whole life, beside its resource-class slot, and owns the block
/// `PORT_BASE + n * PORT_BLOCK_SIZE` for `PORT_BLOCK_SIZE` ports (see
/// [`port_base_for_slot`]), `n` being the number of that `port` slot. Blocks are therefore
/// unique across classes on the machine. It is a separate thing from the D24 bridge port,
/// a hash of the lane id in `cowproof_run::bridge`, which carries the builder's API
/// traffic: the block is for the servers a lane's own checks start. The bridge's range
/// ends below `PORT_BASE`, so the two never overlap.
pub const PORT_BASE: u16 = 57000;
/// The number of ports in each lane's block.
pub const PORT_BLOCK_SIZE: u16 = 20;
/// The slot class that numbers the port blocks. It is not a packet class: the runner takes
/// one slot of it per lane, after the lane's own class slot.
pub const PORT_CLASS: &str = "port";
/// The most `port` slots a base may configure: `[classes] port = N` above this would push
/// the blocks past port 65535.
pub const MAX_PORT_SLOTS: usize = 400;
/// The environment variable that holds the first port of the lane's block.
pub const PORT_BASE_ENV: &str = "COWPROOF_PORT_BASE";
/// The environment variable that holds the number of ports in the lane's block.
pub const PORT_COUNT_ENV: &str = "COWPROOF_PORT_COUNT";
/// The environment variable that overrides the slot directory.
pub const SLOT_DIR_ENV: &str = "COWPROOF_SLOT_DIR";
pub const DEFAULT_HANDOFF_DIR: &str = "docs/handoffs";
pub const ALWAYS_PROTECTED: [&str; 4] = [".env", ".env.*", "**/.env", "**/.env.*"];

/// The machine-wide slot directory: `$COWPROOF_SLOT_DIR` when set and not empty, else
/// `~/.cache/cowproof/slots`. A `--slot-dir` flag, where a command has one, wins over both.
pub fn get_slot_dir() -> PathBuf {
    match std::env::var_os(SLOT_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            home.join(".cache/cowproof/slots")
        }
    }
}

/// Marker strings that identify preamble protocol text.
/// Used by lint to detect when a packet restates the preamble protocol (D20 constraint).
/// Markers are distinctive multi-word phrases that appear ONLY in the preamble's protocol
/// sections (ask schema, check results, escalate-early, handback rules), never in normal
/// packets. They must match exactly between cowproof-run's preamble and cowproof-lint's
/// checks. See the preamble source for the exact sentences.
pub const PROTOCOL_MARKERS: &[&str] = &[
    "The schema is strict",
    "If the same check id fails twice with no pass in between",
    "You will be rejected at handback if you report stubs",
    "Confirm that every check in the packet has a `run_check` result",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub id: String,
    pub command: String,
    #[serde(default)]
    pub flaky: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub id: String,
    pub owns: Vec<String>,
    #[serde(default = "default_runner")]
    pub runner: String,
    #[serde(default)]
    pub model: Option<String>,
    /// The rung this packet starts on (`runtime:model`, or a bare Claude model), which must be
    /// on the base commit's ladder (D28). Syntax is checked here; the ladder, by lint and the
    /// runner.
    #[serde(default)]
    pub rung: Option<String>,
    #[serde(default = "default_class", rename = "class")]
    pub class_name: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub timeout_min: Option<u64>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub wide: Option<bool>,
    #[serde(default)]
    pub effort: Option<String>,
    #[serde(default)]
    pub allow_heavy: bool,
    #[serde(default)]
    pub estimate_hours: Option<f64>,
    #[serde(default)]
    pub append_only: BTreeMap<String, usize>,
    #[serde(default)]
    pub keep_build: bool,
    #[serde(default)]
    pub variant: Option<String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub web_search: bool,
    #[serde(default)]
    pub checks: Vec<Check>,
}

fn default_runner() -> String {
    "opencode".into()
}
fn default_class() -> String {
    "light".into()
}

impl Header {
    /// Default timeout in minutes (45 minutes). Legacy codex runner defaulted to 180 minutes,
    /// which has been removed since only Claude Code builders are now supported.
    pub fn timeout(&self) -> u64 {
        self.timeout_min.unwrap_or(45)
    }
    pub fn max_cost(&self) -> f64 {
        self.max_cost_usd.unwrap_or(2.0)
    }
    pub fn is_wide(&self) -> bool {
        self.wide.unwrap_or(false)
    }
    pub fn effort(&self) -> &str {
        self.effort.as_deref().unwrap_or("high")
    }
}

pub fn parse_header(text: &str) -> Result<Header> {
    let start = text
        .find("<!--")
        .and_then(|i| text[i + 4..].find("lane").map(|j| i + 4 + j))
        .ok_or_else(|| anyhow::anyhow!("packet has no <!-- lane {{...}} --> header"))?;
    let tail = &text[start + 4..];
    let open = tail
        .find('{')
        .ok_or_else(|| anyhow::anyhow!("packet has no <!-- lane {{...}} --> header"))?;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut end = None;
    for (i, c) in tail[open..].char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
        } else if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                end = Some(open + i + 1);
                break;
            }
        }
    }
    let json_text = tail
        .get(
            open..end
                .ok_or_else(|| anyhow::anyhow!("packet has no <!-- lane {{...}} --> header"))?,
        )
        .unwrap();
    let mut v: Value = serde_json::from_str(json_text).context("invalid lane header JSON")?;
    if v.get("runner")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        v["runner"] = Value::String("opencode".into());
    }
    let raw_id = v.get("id").and_then(Value::as_str).unwrap_or_default();
    if !valid_id(raw_id) {
        bail!("lane id must be lowercase letters, digits and dashes");
    }
    if !v
        .get("owns")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        bail!("lane {raw_id}: owns must list at least one path");
    }
    let h: Header = serde_json::from_value(v)?;
    if !["opencode", "codex"].contains(&h.runner.as_str()) {
        bail!("lane {}: runner must be opencode or codex (legacy)", h.id);
    }
    if let Some(rung) = &h.rung {
        Rung::parse(rung).with_context(|| format!("lane {}: the header's \"rung\"", h.id))?;
    }
    if !PACKET_CLASSES.contains(&h.class_name.as_str()) {
        bail!(
            "lane {}: class must be one of rust, crate, pg, light, port",
            h.id
        );
    }
    if let Some(model) = &h.model {
        if (model.to_ascii_lowercase().contains("astra")
            || model.to_ascii_lowercase().contains("terra"))
            && !h.allow_heavy
        {
            bail!(
                "lane {}: {} is a heavy model; set \"allowHeavy\": true to use it",
                h.id,
                model
            );
        }
        if model.to_ascii_lowercase().contains("glm")
            && !model.to_ascii_lowercase().contains("flash")
        {
            bail!(
                "lane {}: {} is refused; only GLM flash models may run (user rule, 2026-09-23)",
                h.id,
                model
            );
        }
    }
    Ok(h)
}

fn valid_id(id: &str) -> bool {
    (2..=61).contains(&id.len())
        && (id.as_bytes()[0].is_ascii_lowercase() || id.as_bytes()[0].is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn glob_to_regex(glob: &str) -> String {
    let cs: Vec<char> = glob.chars().collect();
    let mut out = String::from("^");
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c == '*' && cs.get(i + 1) == Some(&'*') {
            out.push_str(".*");
            i += 2;
            if cs.get(i) == Some(&'/') {
                i += 1;
            }
        } else if c == '*' {
            out.push_str("[^/]*");
            i += 1;
        } else if c == '?' {
            out.push_str("[^/]");
            i += 1;
        } else {
            if ".+^${}()|[]\\/".contains(c) {
                out.push('\\');
            }
            out.push(c);
            i += 1;
        }
    }
    out.push('$');
    out
}

pub fn glob_matches(glob: &str, value: &str) -> bool {
    fn go(
        p: &[char],
        s: &[char],
        i: usize,
        j: usize,
        memo: &mut BTreeMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(v) = memo.get(&(i, j)) {
            return *v;
        }
        let result = if i == p.len() {
            j == s.len()
        } else if p[i] == '*' && p.get(i + 1) == Some(&'*') {
            let mut k = i + 2;
            let skip_slash = p.get(k) == Some(&'/');
            if skip_slash {
                k += 1;
            }
            go(p, s, k, j, memo) || (j < s.len() && go(p, s, i, j + 1, memo))
        } else if p[i] == '*' {
            go(p, s, i + 1, j, memo) || (j < s.len() && s[j] != '/' && go(p, s, i, j + 1, memo))
        } else if p[i] == '?' {
            j < s.len() && s[j] != '/' && go(p, s, i + 1, j + 1, memo)
        } else {
            j < s.len() && p[i] == s[j] && go(p, s, i + 1, j + 1, memo)
        };
        memo.insert((i, j), result);
        result
    }
    go(
        &glob.chars().collect::<Vec<_>>(),
        &value.chars().collect::<Vec<_>>(),
        0,
        0,
        &mut BTreeMap::new(),
    )
}

/// The protected globs and handoff directory named by a `lanes.config.json` text.
/// `None`, or text that does not parse, gives the defaults. The one place the
/// defaults live: the working-tree reader below and the gates, which read the file
/// from the base commit, both go through it.
pub fn repo_rules_from_config(text: Option<&str>) -> (Vec<String>, String) {
    let config = text
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({}));
    let protected = config
        .get("protected")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "AGENTS.md",
                "CLAUDE.md",
                ".github/**",
                ".claude/**",
                ".Codex/**",
                ".agents/**",
                ".codex/**",
                "lanes.config.json",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        });
    let handoff = config
        .get("handoffDir")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_HANDOFF_DIR)
        .to_owned();
    (protected, handoff)
}

/// `repo_rules_from_config` over the working tree's `lanes.config.json`. Proof gates
/// must not use this: a lane's patch could edit the file they would read.
pub fn repo_rules(root: &Path) -> (Vec<String>, String) {
    let text = fs::read_to_string(root.join("lanes.config.json")).ok();
    repo_rules_from_config(text.as_deref())
}

pub fn outside_ownership(files: &[String], owns: &[String], protected: &[String]) -> Vec<String> {
    files
        .iter()
        .filter(|f| {
            ALWAYS_PROTECTED
                .iter()
                .copied()
                .chain(protected.iter().map(String::as_str))
                .any(|g| glob_matches(g, f))
                || !owns.iter().any(|g| glob_matches(g, f))
        })
        .cloned()
        .collect()
}

pub fn removed_lines(patch: &str, file: &str) -> usize {
    parse_patch(patch)
        .into_iter()
        .find(|delta| delta.path == file)
        .map(|delta| delta.removed.len())
        .unwrap_or(0)
}

pub fn codex_isolation_args(copy: &Path, codex_home: &Path) -> Vec<String> {
    let mut servers = std::collections::BTreeSet::new();
    let mut plugins = std::collections::BTreeSet::new();
    for file in [
        codex_home.join("config.toml"),
        copy.join(".Codex/config.toml"),
        copy.join(".codex/config.toml"),
    ] {
        if let Ok(s) = fs::read_to_string(file) {
            for line in s.lines() {
                if let Some(name) = line
                    .strip_prefix("[mcp_servers.")
                    .and_then(|x| x.strip_suffix(']'))
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    servers.insert(name.to_owned());
                }
                if let Some(id) = line
                    .strip_prefix("[plugins.\"")
                    .and_then(|x| x.strip_suffix("\"]"))
                {
                    plugins.insert(id.to_owned());
                }
            }
        }
    }
    if let Ok(markets) = fs::read_dir(codex_home.join("plugins/cache")) {
        for market in markets
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        {
            let mn = market.file_name().to_string_lossy().to_string();
            if let Ok(items) = fs::read_dir(market.path()) {
                for p in items
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                {
                    let n = p.file_name().to_string_lossy().to_string();
                    if n.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
                    {
                        plugins.insert(format!("{n}@{mn}"));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for n in servers {
        out.extend(["-c".into(), format!("mcp_servers.{n}.enabled=false")]);
    }
    for id in plugins {
        if !id.contains('"') {
            out.extend(["-c".into(), format!("plugins.\"{id}\".enabled=false")]);
        }
    }
    for setting in [
        "mcp_oauth_credentials_store=\"file\"",
        "features.hooks=false",
        "features.codex_hooks=false",
        "features.memories=false",
    ] {
        out.extend(["-c".into(), setting.into()]);
    }
    out
}

pub fn remove_build_output(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, depth: usize, removed: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name();
            let n = name.to_string_lossy();
            if !p.is_dir() || n == ".git" || n == "node_modules" {
                continue;
            }
            if n == "target" || (depth == 0 && n.starts_with("tmp-")) {
                let _ = fs::remove_dir_all(&p);
                if let Ok(rel) = p.strip_prefix(root) {
                    removed.push(rel.to_string_lossy().into_owned());
                }
            } else if depth < 2 {
                walk(root, &p, depth + 1, removed);
            }
        }
    }
    let mut r = Vec::new();
    walk(root, root, 0, &mut r);
    r
}

/// Take one slot of `class` under `dir`, or `None` when all `limit` are held. A slot whose
/// recorded pid is no longer alive is reclaimed.
///
/// `alive` says whether a pid is still running. This crate forbids unsafe code and never starts
/// the `kill` program, so the caller supplies the probe: `cowproof_prove::runner` wraps this
/// with `kill(2)` signal 0 (`cowproof_prove::runner::try_acquire_slot`).
pub fn try_acquire_slot(
    class: &str,
    limit: usize,
    dir: &Path,
    alive: &dyn Fn(u32) -> bool,
) -> Result<Option<PathBuf>> {
    fs::create_dir_all(dir)?;
    for n in 0..limit {
        if class == "port" && scratch_busy(PORT_BASE + (n as u16) * PORT_BLOCK_SIZE, alive) {
            continue;
        }
        let slot = dir.join(format!("{class}-{n}"));
        match fs::create_dir(&slot) {
            Ok(()) => {
                fs::write(slot.join("pid"), std::process::id().to_string())?;
                return Ok(Some(slot));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let pid = fs::read_to_string(slot.join("pid"))
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok());
                if pid.is_some_and(|p| !alive(p)) {
                    let _ = fs::remove_dir_all(&slot);
                    return try_acquire_slot(class, limit, dir, alive);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(None)
}
fn scratch_busy(port_base: u16, alive: &dyn Fn(u32) -> bool) -> bool {
    let root = PathBuf::from(format!("/tmp/cowproof/l{port_base}"));
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        for pid_file in [
            entry.path().join("data/postmaster.pid"),
            entry.path().join("postmaster.pid"),
        ] {
            if let Ok(pid) = fs::read_to_string(pid_file)
                && let Some(pid) = pid.lines().next().and_then(|line| line.parse().ok())
                && alive(pid)
            {
                return true;
            }
        }
    }
    false
}
pub fn release_slot(slot: Option<&Path>) {
    if let Some(p) = slot {
        let _ = fs::remove_dir_all(p);
    }
}

/// The first port of the block that goes with a held `port` slot. The slot directory is
/// named `<class>-<n>` (see [`try_acquire_slot`]); the block is
/// `PORT_BASE + n * PORT_BLOCK_SIZE`. `None` when the name does not end in a slot number.
///
/// Only a slot of [`PORT_CLASS`] should be passed: its number is machine-wide, so no two
/// lanes share a block. (The number of a resource-class slot counts within its class and
/// would give `rust-0` and `light-0` the same block.)
pub fn port_base_for_slot(slot: &Path) -> Option<u16> {
    let name = slot.file_name()?.to_str()?;
    let (_, n) = name.rsplit_once('-')?;
    let n: u16 = n.parse().ok()?;
    PORT_BASE.checked_add(n.checked_mul(PORT_BLOCK_SIZE)?)
}

/// The environment a lane's processes get for its port block: [`PORT_BASE_ENV`] and
/// [`PORT_COUNT_ENV`].
pub fn port_block_env(port_base: u16) -> [(String, String); 2] {
    [
        (PORT_BASE_ENV.to_string(), port_base.to_string()),
        (PORT_COUNT_ENV.to_string(), PORT_BLOCK_SIZE.to_string()),
    ]
}

/// The class limits when `cowproof.toml` says nothing: `light` 6, `crate` 4, `rust` 2,
/// `pg` 3, and `port` 50 (ports 57000 to 57999).
pub const DEFAULT_CLASS_LIMITS: [(&str, usize); 5] = [
    ("light", 6),
    ("crate", 4),
    ("rust", 2),
    ("pg", 3),
    (PORT_CLASS, 50),
];

/// The limit of a class that is in neither the defaults nor `cowproof.toml`.
pub const OTHER_CLASS_LIMIT: usize = 2;

/// The class limits in a `cowproof.toml`: the defaults, overridden by its `[classes]`
/// table. A limit must be a whole number of at least 1 (a class with no slots could never
/// run a lane), and a file that does not parse is an error. `None` is a repository with
/// no `cowproof.toml`.
pub fn parse_class_limits(text: Option<&str>) -> Result<BTreeMap<String, usize>> {
    let mut limits: BTreeMap<String, usize> = DEFAULT_CLASS_LIMITS
        .iter()
        .map(|(class, limit)| (class.to_string(), *limit))
        .collect();
    let Some(text) = text else {
        return Ok(limits);
    };
    let config: toml::Table = toml::from_str(text).context("cowproof.toml does not parse")?;
    let Some(classes) = config.get("classes") else {
        return Ok(limits);
    };
    let classes = classes
        .as_table()
        .context("cowproof.toml: [classes] must be a table")?;
    for (class, value) in classes {
        let limit = value
            .as_integer()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n >= 1)
            .with_context(|| {
                format!("cowproof.toml: [classes] {class} must be a whole number of at least 1")
            })?;
        if class == PORT_CLASS && limit > MAX_PORT_SLOTS {
            bail!("cowproof.toml: [classes] port must be at most {MAX_PORT_SLOTS}");
        }
        limits.insert(class.clone(), limit);
    }
    Ok(limits)
}

/// The limit of `class` in the `cowproof.toml` of `commit` (the lane's base commit, so a
/// patch cannot raise it).
pub fn class_limit_at_commit(repo: &Path, commit: &str, class: &str) -> Result<usize> {
    let text = git_show_optional(repo, commit, "cowproof.toml")?;
    let limits = parse_class_limits(text.as_deref())
        .with_context(|| format!("reading the class limits at {commit}"))?;
    Ok(limits.get(class).copied().unwrap_or(OTHER_CLASS_LIMIT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_rules_from_config_reads_the_given_text_and_defaults_otherwise() {
        let (defaults, handoff) = repo_rules_from_config(None);
        assert!(defaults.contains(&"AGENTS.md".to_string()));
        assert!(defaults.contains(&"lanes.config.json".to_string()));
        assert_eq!(handoff, DEFAULT_HANDOFF_DIR);
        // Text that does not parse is the defaults, never "protect nothing".
        assert_eq!(repo_rules_from_config(Some("{ not json")).0, defaults);
        let (custom, handoff) =
            repo_rules_from_config(Some(r#"{"protected":["secret/**"],"handoffDir":"h"}"#));
        assert_eq!(custom, vec!["secret/**".to_string()]);
        assert_eq!(handoff, "h");
    }

    #[test]
    fn header_defaults_and_refusals() {
        let h =
            parse_header("<!-- lane {\"id\":\"lane-a\",\"owns\":[\"scripts/x.mjs\"]} -->").unwrap();
        assert_eq!(h.max_cost(), 2.0);
        assert!(
            parse_header("# no header")
                .unwrap_err()
                .to_string()
                .contains("no <!-- lane")
        );
        for (s, m) in [
            ("{\"id\":\"Bad Id\",\"owns\":[\"a\"]}", "lowercase"),
            ("{\"id\":\"lane-b\",\"owns\":[]}", "owns"),
            (
                "{\"id\":\"lane-d\",\"runner\":\"codex\",\"model\":\"gpt-6-astra\",\"owns\":[\"a\"]}",
                "heavy",
            ),
            (
                "{\"id\":\"lane-g\",\"runner\":\"claude\",\"owns\":[\"a\"]}",
                "runner",
            ),
            (
                "{\"id\":\"lane-i\",\"class\":\"gpu\",\"owns\":[\"a\"]}",
                "class",
            ),
            (
                "{\"id\":\"lane-j\",\"model\":\"z-ai/glm-5.3\",\"owns\":[\"a\"]}",
                "only GLM flash",
            ),
        ] {
            assert!(
                parse_header(&format!("<!-- lane {s} -->"))
                    .unwrap_err()
                    .to_string()
                    .contains(m)
            );
        }
        // Legacy codex runner is gone; runner field is kept for parsing tolerance only
        let c =
            parse_header("<!-- lane {\"id\":\"lane-c\",\"runner\":\"codex\",\"owns\":[\"a\"]} -->")
                .unwrap();
        assert_eq!(c.runner, "codex");
        assert!(!c.is_wide()); // No longer defaults to true for codex
        // Explicit model values are preserved even for legacy runners
        let f = parse_header("<!-- lane {\"id\":\"lane-f\",\"runner\":\"codex\",\"model\":\"gpt-6-terra\",\"allowHeavy\":true,\"owns\":[\"a\"]} -->").unwrap();
        assert_eq!(f.model, Some("gpt-6-terra".to_string()));
        // Packet with no runner key defaults to "opencode" for parsing (legacy default)
        let norunner = parse_header("<!-- lane {\"id\":\"lane-g\",\"owns\":[\"a\"]} -->").unwrap();
        assert_eq!(norunner.runner, "opencode");
    }

    #[test]
    fn a_header_may_name_a_rung_and_a_bad_one_is_refused() {
        let header = |rung: &str| {
            parse_header(&format!(
                "<!-- lane {{\"id\":\"lane-r\",\"owns\":[\"a\"],\"rung\":\"{rung}\"}} -->"
            ))
        };
        assert_eq!(
            header("claude:sonnet").unwrap().rung.as_deref(),
            Some("claude:sonnet")
        );
        assert_eq!(header("opus").unwrap().rung.as_deref(), Some("opus"));
        let none = parse_header("<!-- lane {\"id\":\"lane-r\",\"owns\":[\"a\"]} -->").unwrap();
        assert_eq!(none.rung, None);
        for bad in ["gemini:flash", "claude:--x", "claude:a b", ""] {
            let e = format!("{:#}", header(bad).unwrap_err());
            assert!(e.contains("rung"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn header_checks_parses_to_exact_vec() {
        let h = parse_header(
            "<!-- lane {\"id\":\"test-checks\",\"owns\":[\"a\"],\"checks\":[{\"id\":\"unit\",\"command\":\"cargo test\"},{\"id\":\"fmt-all\",\"command\":\"cargo fmt --check\",\"flaky\":true}]} -->"
        )
        .unwrap();
        assert_eq!(
            h.checks,
            vec![
                Check {
                    id: "unit".into(),
                    command: "cargo test".into(),
                    flaky: false,
                },
                Check {
                    id: "fmt-all".into(),
                    command: "cargo fmt --check".into(),
                    flaky: true,
                },
            ]
        );
    }

    #[test]
    fn ownership_globs_and_split() {
        assert!(glob_matches("scripts/schema/*.mjs", "scripts/schema/a.mjs"));
        assert!(!glob_matches(
            "scripts/schema/*.mjs",
            "scripts/schema/sub/a.mjs"
        ));
        assert!(glob_matches("api/src/**", "api/src/routes/domains.rs"));
        assert!(glob_matches("docs/**/x.md", "docs/x.md"));
        assert_eq!(
            outside_ownership(
                &["api/src/a.rs".into(), "AGENTS.md".into()],
                &["api/src/**".into()],
                &["AGENTS.md".into()]
            ),
            vec!["AGENTS.md"]
        );
    }
    #[test]
    fn removed_line_count() {
        let p = "diff --git a/x.test.mjs b/x.test.mjs\n--- a/x.test.mjs\n+++ b/x.test.mjs\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/y b/y\n--- a/y\n+++ b/y\n@@ -1,2 +1 @@\n-a\n-b\n+c";
        assert_eq!(removed_lines(p, "x.test.mjs"), 1);
        assert_eq!(removed_lines(p, "y"), 2);
        assert_eq!(removed_lines(p, "z"), 0);
    }

    #[test]
    fn removed_line_with_sql_comment_is_counted() {
        // Test: removing `-- assert balance >= 0` should count as 1 removed line
        // In the patch, this appears as `--- assert balance >= 0` (dash marker + content starting with --)
        let patch = "diff --git a/schema.sql b/schema.sql\n--- a/schema.sql\n+++ b/schema.sql\n@@ -1,3 +1,2 @@\n CREATE TABLE accounts (\n--- assert balance >= 0\n );";
        assert_eq!(removed_lines(patch, "schema.sql"), 1);
    }

    #[test]
    fn removed_line_starting_with_triple_dash_is_counted() {
        // Test: removing `--- separator ---` in markdown counts as 1
        // In the patch, this appears as `---- separator ---` (dash marker + content starting with ---)
        let patch = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,2 @@\n # Header\n---- separator ---\n some text";
        assert_eq!(removed_lines(patch, "README.md"), 1);
    }

    #[test]
    fn removed_dash_lines_from_a_real_git_diff_are_counted() {
        // Output of `git diff` after deleting `-- assert balance >= 0` and
        // `--- separator ---` from a tracked file: they render as `--- ...`
        // and `---- ...` inside the hunk and must count as removals.
        let patch = "diff --git a/s.sql b/s.sql\nindex 1111111..2222222 100644\n--- a/s.sql\n+++ b/s.sql\n@@ -1,4 +1,2 @@\n CREATE TABLE a (\n--- assert balance >= 0\n---- separator ---\n );\n";
        assert_eq!(removed_lines(patch, "s.sql"), 2);
    }

    #[test]
    fn headers_not_counted_in_multi_file_patch() {
        // Test: a patch with headers for two files counts only body lines
        let patch = "diff --git a/file1.rs b/file1.rs\n--- a/file1.rs\n+++ b/file1.rs\n@@ -1 +1 @@\n-old1\n+new1\ndiff --git a/file2.rs b/file2.rs\n--- a/file2.rs\n+++ b/file2.rs\n@@ -1 +1 @@\n-old2\n+new2";
        assert_eq!(removed_lines(patch, "file1.rs"), 1);
        assert_eq!(removed_lines(patch, "file2.rs"), 1);
    }
    #[test]
    fn slot_capacity_is_shared_by_class_and_released() {
        let dir = std::env::temp_dir().join(format!("lanes-slot-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let a = try_acquire_slot("rust", 2, &dir, &|p| p == std::process::id())
            .unwrap()
            .unwrap();
        let b = try_acquire_slot("rust", 2, &dir, &|p| p == std::process::id())
            .unwrap()
            .unwrap();
        assert_ne!(a, b);
        assert!(
            try_acquire_slot("rust", 2, &dir, &|p| p == std::process::id())
                .unwrap()
                .is_none()
        );
        release_slot(Some(&a));
        assert!(
            try_acquire_slot("rust", 2, &dir, &|p| p == std::process::id())
                .unwrap()
                .is_some()
        );
        assert!(
            try_acquire_slot("light", 1, &dir, &|p| p == std::process::id())
                .unwrap()
                .is_some()
        );
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn build_cleanup_keeps_sources_and_skips_git_and_dependencies() {
        let root = std::env::temp_dir().join(format!("lanes-build-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for rel in [
            "api/target/debug/out",
            "tmp-work/out",
            "api/src/lib.rs",
            ".git/HEAD",
            "node_modules/pkg/target/keep",
            "packages/x/target/out",
            "deep/a/b/target/not-removed",
        ] {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "x").unwrap();
        }
        let mut removed = remove_build_output(&root);
        removed.sort();
        assert_eq!(removed, vec!["api/target", "packages/x/target", "tmp-work"]);
        for rel in [
            "api/src/lib.rs",
            ".git/HEAD",
            "node_modules/pkg/target/keep",
            "deep/a/b/target/not-removed",
        ] {
            assert!(root.join(rel).exists(), "{rel}");
        }
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn codex_isolation_disables_declared_servers_and_plugins() {
        let root = std::env::temp_dir().join(format!("lanes-codex-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let codex = root.join("codex");
        let copy = root.join("repo");
        fs::create_dir_all(codex.join("plugins/cache/market-a/tool-x")).unwrap();
        fs::create_dir_all(copy.join(".Codex")).unwrap();
        fs::write(codex.join("config.toml"),"[mcp_servers.alpha]\ncommand=\"a\"\n[mcp_servers.alpha.env]\nX=\"1\"\n[plugins.\"p@m\"]\nenabled=true\n").unwrap();
        fs::write(
            copy.join(".Codex/config.toml"),
            "[mcp_servers.resend]\nurl=\"https://example.test\"\n",
        )
        .unwrap();
        let args = codex_isolation_args(&copy, &codex);
        let values: Vec<_> = args
            .iter()
            .enumerate()
            .filter_map(|(i, v)| (i % 2 == 1).then_some(v.as_str()))
            .collect();
        for want in [
            "mcp_servers.alpha.enabled=false",
            "mcp_servers.resend.enabled=false",
            "plugins.\"p@m\".enabled=false",
            "plugins.\"tool-x@market-a\".enabled=false",
            "mcp_oauth_credentials_store=\"file\"",
            "features.memories=false",
        ] {
            assert!(values.contains(&want), "{want}");
        }
        assert!(!values.iter().any(|v| v.starts_with("mcp_servers.env")));
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn parity_with_node_if_available() {
        parity_test();
    }
    fn parity_test() {
        use std::process::Command as StdCommand;
        if StdCommand::new("node").arg("--version").output().is_err() {
            eprintln!("skipping Node parity test: node is not installed");
            return;
        }
        // The Node reference runner is not part of this repository. Point
        // COWPROOF_REFERENCE_RUNNER at a run-lane.mjs to check parity against it.
        let Some(runner) = std::env::var_os("COWPROOF_REFERENCE_RUNNER").map(PathBuf::from) else {
            eprintln!("skipping Node parity test: COWPROOF_REFERENCE_RUNNER is not set");
            return;
        };
        let node_src = format!(
            "import {{parseHeader,globToRegExp,outsideOwnership}} from {}; const h=parseHeader('<!-- lane {{\\\"id\\\":\\\"lane-a\\\",\\\"owns\\\":[\\\"src/**\\\"]}} -->'); console.log(JSON.stringify({{header:[h.runner,h.class,h.timeoutMin,h.maxCostUsd,h.wide],glob:globToRegExp('docs/**/x.md').source,owned:outsideOwnership(['src/a.rs','AGENTS.md'],['src/**'])}}));",
            serde_json::to_string(&runner.to_string_lossy()).unwrap()
        );
        let out = StdCommand::new("node")
            .args(["--input-type=module", "-e", &node_src])
            .output()
            .expect("node invocation");
        assert!(
            out.status.success(),
            "Node parity helper failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let node: Value = serde_json::from_slice(&out.stdout).unwrap();
        let h = parse_header("<!-- lane {\"id\":\"lane-a\",\"owns\":[\"src/**\"]} -->").unwrap();
        assert_eq!(
            node["header"],
            json!([
                h.runner,
                h.class_name,
                h.timeout(),
                h.max_cost() as u64,
                h.is_wide()
            ])
        );
        assert_eq!(node["glob"], glob_to_regex("docs/**/x.md"));
        assert_eq!(
            node["owned"],
            json!(outside_ownership(
                &["src/a.rs".into(), "AGENTS.md".into()],
                &["src/**".into()],
                &["AGENTS.md".into()]
            ))
        );
    }

    #[test]
    fn class_limits_default_and_override() {
        let defaults = parse_class_limits(None).unwrap();
        assert_eq!(
            defaults.into_iter().collect::<Vec<_>>(),
            vec![
                ("crate".to_string(), 4),
                ("light".to_string(), 6),
                ("pg".to_string(), 3),
                ("port".to_string(), 50),
                ("rust".to_string(), 2),
            ]
        );
        let none_set = parse_class_limits(Some("[proof]\npacks = []\n")).unwrap();
        assert_eq!(none_set["light"], 6);

        let limits = parse_class_limits(Some("[classes]\nlight = 1\nrust = 5\ngpu = 7\n")).unwrap();
        assert_eq!(limits["light"], 1);
        assert_eq!(limits["rust"], 5);
        assert_eq!(
            limits["crate"], 4,
            "a class the file leaves out keeps its default"
        );
        assert_eq!(limits["gpu"], 7);
    }

    #[test]
    fn class_limits_refuse_a_limit_no_lane_could_use() {
        for bad in [
            "[classes]\nlight = 0\n",
            "[classes]\nlight = -1\n",
            "[classes]\nlight = \"two\"\n",
            "[classes]\nlight = 1.5\n",
            "classes = 3\n",
            "[classes]\nport = 401\n",
            "[classes\n",
        ] {
            assert!(parse_class_limits(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn port_blocks_follow_the_slot_number() {
        let block = |name: &str| port_base_for_slot(&PathBuf::from("/s").join(name));
        assert_eq!(block("port-0"), Some(57000));
        assert_eq!(block("port-1"), Some(57020));
        assert_eq!(block("port-49"), Some(57980));
        assert_eq!(block("no-number"), None);
        assert_eq!(block("plain"), None);
        assert_eq!(
            port_block_env(57020),
            [
                ("COWPROOF_PORT_BASE".to_string(), "57020".to_string()),
                ("COWPROOF_PORT_COUNT".to_string(), "20".to_string())
            ]
        );
    }
}
