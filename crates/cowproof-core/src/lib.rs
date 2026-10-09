#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

pub mod heldout;

pub const PORT_BASE: u16 = 57000;
pub const SLOT_DIR: &str = "/tmp/cowproof-lanes/.slots";
pub const DEFAULT_HANDOFF_DIR: &str = "docs/handoffs";
pub const ALWAYS_PROTECTED: [&str; 4] = [".env", ".env.*", "**/.env", "**/.env.*"];

/// Marker strings that identify preamble protocol text.
/// Used by lint to detect when a packet restates the preamble protocol (D20 constraint).
/// Markers are distinctive multi-word phrases that appear ONLY in the preamble's protocol
/// sections (ask schema, check results, escalate-early, handback rules), never in normal
/// packets. They must match exactly between cowproof-run's preamble and cowproof-lint's
/// checks. See the preamble source for the exact sentences.
pub const PROTOCOL_MARKERS: &[&str] = &[
    "The schema is strict",
    "Read file ranges efficiently without re-reading",
    "If the same check id fails twice with no pass in between",
    "You will be rejected at handback if you report stubs",
    "Confirm that every check in the packet has a `run_check` result",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub id: String,
    pub owns: Vec<String>,
    #[serde(default = "default_runner")]
    pub runner: String,
    #[serde(default)]
    pub model: Option<String>,
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
}

fn default_runner() -> String {
    "opencode".into()
}
fn default_class() -> String {
    "light".into()
}

impl Header {
    pub fn model(&self) -> &str {
        self.model.as_deref().unwrap_or(if self.runner == "codex" {
            "gpt-6-luna"
        } else {
            "z-ai/glm-5.3-flash"
        })
    }
    pub fn timeout(&self) -> u64 {
        self.timeout_min
            .unwrap_or(if self.runner == "codex" { 180 } else { 45 })
    }
    pub fn max_cost(&self) -> f64 {
        self.max_cost_usd.unwrap_or(2.0)
    }
    pub fn is_wide(&self) -> bool {
        self.wide.unwrap_or(self.runner == "codex")
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
        bail!("lane {}: runner must be opencode or codex", h.id);
    }
    if !["rust", "crate", "pg", "light"].contains(&h.class_name.as_str()) {
        bail!(
            "lane {}: class must be one of rust, crate, pg, light, port",
            h.id
        );
    }
    let model = h.model();
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
    if model.to_ascii_lowercase().contains("glm") && !model.to_ascii_lowercase().contains("flash") {
        bail!(
            "lane {}: {} is refused; only GLM flash models may run (user rule, 2026-09-23)",
            h.id,
            model
        );
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

pub fn repo_rules(root: &Path) -> (Vec<String>, String) {
    let config = fs::read(root.join("lanes.config.json"))
        .ok()
        .and_then(|s| serde_json::from_slice::<Value>(&s).ok())
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
    let mut active = false;
    let mut count = 0;
    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            active = line.ends_with(&format!(" b/{file}"));
        } else if active && line.starts_with('-') && !line.starts_with("---") {
            count += 1;
        }
    }
    count
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

pub fn try_acquire_slot(class: &str, limit: usize, dir: &Path) -> Result<Option<PathBuf>> {
    fs::create_dir_all(dir)?;
    for n in 0..limit {
        if class == "port" && scratch_busy(PORT_BASE + (n as u16) * 20) {
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
                if pid.is_some_and(|p| !pid_alive(p)) {
                    let _ = fs::remove_dir_all(&slot);
                    return try_acquire_slot(class, limit, dir);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(None)
}
fn scratch_busy(port_base: u16) -> bool {
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
                && pid_alive(pid)
            {
                return true;
            }
        }
    }
    false
}
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}
pub fn release_slot(slot: Option<&Path>) {
    if let Some(p) = slot {
        let _ = fs::remove_dir_all(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_defaults_and_refusals() {
        let h =
            parse_header("<!-- lane {\"id\":\"lane-a\",\"owns\":[\"scripts/x.mjs\"]} -->").unwrap();
        assert_eq!(h.model(), "z-ai/glm-5.3-flash");
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
        let c =
            parse_header("<!-- lane {\"id\":\"lane-c\",\"runner\":\"codex\",\"owns\":[\"a\"]} -->")
                .unwrap();
        assert_eq!(c.model(), "gpt-6-luna");
        assert!(c.is_wide());
        assert_eq!(parse_header("<!-- lane {\"id\":\"lane-f\",\"runner\":\"codex\",\"model\":\"gpt-6-terra\",\"allowHeavy\":true,\"owns\":[\"a\"]} -->").unwrap().model(),"gpt-6-terra");
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
        let p = "diff --git a/x.test.mjs b/x.test.mjs\n--- a/x.test.mjs\n+++ b/x.test.mjs\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/y b/y\n-a\n-b\n+c";
        assert_eq!(removed_lines(p, "x.test.mjs"), 1);
        assert_eq!(removed_lines(p, "y"), 2);
        assert_eq!(removed_lines(p, "z"), 0);
    }
    #[test]
    fn slot_capacity_is_shared_by_class_and_released() {
        let dir = std::env::temp_dir().join(format!("lanes-slot-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let a = try_acquire_slot("rust", 2, &dir).unwrap().unwrap();
        let b = try_acquire_slot("rust", 2, &dir).unwrap().unwrap();
        assert_ne!(a, b);
        assert!(try_acquire_slot("rust", 2, &dir).unwrap().is_none());
        release_slot(Some(&a));
        assert!(try_acquire_slot("rust", 2, &dir).unwrap().is_some());
        assert!(try_acquire_slot("light", 1, &dir).unwrap().is_some());
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
            "import {{parseHeader,globToRegExp,outsideOwnership}} from {}; const h=parseHeader('<!-- lane {{\\\"id\\\":\\\"lane-a\\\",\\\"owns\\\":[\\\"src/**\\\"]}} -->'); console.log(JSON.stringify({{header:[h.runner,h.model,h.class,h.timeoutMin,h.maxCostUsd,h.wide],glob:globToRegExp('docs/**/x.md').source,owned:outsideOwnership(['src/a.rs','AGENTS.md'],['src/**'])}}));",
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
                h.model(),
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
}
