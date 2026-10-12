//! The Claude Code plugin in `plugin/` and the marketplace in `.claude-plugin/`:
//! its manifests, hook, session-start script and the commands its skills tell Claude to run.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SKILLS: [&str; 3] = [
    "cowproof-dispatch",
    "cowproof-escalate",
    "cowproof-handback",
];
const SCRIPT: &str = "plugin/scripts/check-cowproof.sh";

fn cowproof() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cowproof"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn json(relative: &str) -> serde_json::Value {
    serde_json::from_str(&read(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cowproof-plugin-")
        .tempdir_in("/var/tmp")
        .expect("a scratch directory under /var/tmp")
}

/// The `version` under `[workspace.package]` in the root manifest.
fn workspace_version() -> String {
    let manifest = read("Cargo.toml");
    let section = manifest
        .split("[workspace.package]")
        .nth(1)
        .expect("[workspace.package] section");
    let line = section
        .lines()
        .find(|l| l.trim_start().starts_with("version"))
        .expect("workspace version");
    line.split('"').nth(1).expect("quoted version").to_string()
}

#[test]
fn manifests_agree_with_the_workspace_and_each_other() {
    let plugin = json("plugin/.claude-plugin/plugin.json");
    assert_eq!(plugin["name"], "cowproof");
    assert_eq!(plugin["version"], workspace_version().as_str());

    let market = json(".claude-plugin/marketplace.json");
    let listed = market["plugins"].as_array().expect("plugins array");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["name"], plugin["name"]);
    assert_eq!(listed[0]["source"], "./plugin");

    for skill in SKILLS {
        let text = read(&format!("plugin/skills/{skill}/SKILL.md"));
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("---"), "{skill}: front matter");
        let head: Vec<&str> = lines.by_ref().take_while(|l| *l != "---").collect();
        assert!(
            head.contains(&format!("name: {skill}").as_str()),
            "{skill}: name"
        );
        assert!(
            head.iter()
                .any(|l| l.starts_with("description: ") && l.len() > 40),
            "{skill}: description"
        );
    }
}

#[test]
fn the_session_start_hook_runs_the_script() {
    let hooks = json("plugin/hooks/hooks.json");
    let groups = hooks["hooks"]["SessionStart"]
        .as_array()
        .expect("SessionStart array");
    let commands: Vec<&str> = groups
        .iter()
        .flat_map(|group| {
            group["hooks"]
                .as_array()
                .expect("each group has a hooks array")
        })
        .inspect(|hook| assert_eq!(hook["type"], "command"))
        .map(|hook| hook["command"].as_str().expect("command string"))
        .collect();
    assert_eq!(
        commands,
        ["\"${CLAUDE_PLUGIN_ROOT}/scripts/check-cowproof.sh\""]
    );
}

/// The hook runs the script as a command, so it needs the executable bit in what git
/// commits, not only on this disk.
#[test]
fn the_script_is_executable_in_git_and_on_disk() {
    let staged = Command::new("git")
        .args(["ls-files", "-s", "--", SCRIPT])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files");
    let staged = String::from_utf8_lossy(&staged.stdout);
    assert!(
        staged.starts_with("100755 "),
        "{SCRIPT} must be committed as 100755, git has: {staged:?}"
    );
    let mode = fs::metadata(repo_root().join(SCRIPT))
        .unwrap()
        .permissions()
        .mode();
    assert_ne!(mode & 0o111, 0, "{SCRIPT} must be executable on disk");
}

/// Run the script itself, as the hook does, with `stub` as the only `cowproof` on the
/// PATH (none when `None`). Returns its stdout; it must always exit 0.
fn run_script(plugin_root: &Path, stub: Option<&str>) -> String {
    let bin = scratch();
    let mut path = String::from("/usr/bin:/bin");
    if let Some(body) = stub {
        let exe = bin.path().join("cowproof");
        fs::write(&exe, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        path = format!("{}:{path}", bin.path().display());
    }
    let out = Command::new(repo_root().join(SCRIPT))
        .env_clear()
        .env("CLAUDE_PLUGIN_ROOT", plugin_root)
        .env("PATH", path)
        .output()
        .expect("run the script directly");
    assert!(out.status.success(), "the hook must always exit 0: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn plugin_root_requiring(version: &str) -> tempfile::TempDir {
    let root = scratch();
    fs::create_dir(root.path().join(".claude-plugin")).unwrap();
    let manifest = format!("{{\n  \"name\": \"cowproof\",\n  \"version\": \"{version}\"\n}}\n");
    fs::write(root.path().join(".claude-plugin/plugin.json"), manifest).unwrap();
    root
}

#[test]
fn the_script_compares_versions_numerically_and_never_fails() {
    let root = plugin_root_requiring("0.9.0");
    let says = |version: &str| run_script(root.path(), Some(&format!("echo 'lanes {version}'")));

    for fine in ["0.9.0", "0.9.1", "0.10.0", "1.0.0", "10.0.0"] {
        assert_eq!(says(fine), "", "{fine} satisfies 0.9.0");
    }
    for old in ["0.8.9", "0.0.1"] {
        let said = says(old);
        assert!(
            said.contains(&format!("cowproof {old} is older than the 0.9.0")),
            "{old}: {said}"
        );
        assert!(
            said.contains("cargo install --git https://github.com/srmcguirt/cowproof cowproof"),
            "{old}: {said}"
        );
    }

    let missing = run_script(root.path(), None);
    assert!(
        missing.starts_with("cowproof is not installed."),
        "{missing}"
    );
    assert!(
        missing.contains("cargo install --git https://github.com/srmcguirt/cowproof cowproof"),
        "{missing}"
    );

    // A binary with no `--version` reports nothing the hook can compare.
    assert_eq!(run_script(root.path(), Some("exit 2")), "");

    // No manifest to read, nothing to compare.
    assert_eq!(run_script(scratch().path(), Some("echo 'lanes 0.0.1'")), "");

    // The real plugin accepts the workspace version.
    let real = repo_root().join("plugin");
    assert_eq!(
        run_script(
            &real,
            Some(&format!("echo 'lanes {}'", workspace_version()))
        ),
        ""
    );
}

/// The hook and both READMEs give the one install command the repository README does.
#[test]
fn the_install_line_is_the_same_everywhere() {
    let install = "cargo install --git https://github.com/srmcguirt/cowproof cowproof";
    for file in ["README.md", "plugin/README.md", SCRIPT] {
        assert!(read(file).contains(install), "{file} must say `{install}`");
    }
}

/// Split a shell-like line into words, honouring single and double quotes.
fn words(line: &str) -> Vec<String> {
    let (mut out, mut word, mut quote, mut open) = (Vec::new(), String::new(), None, false);
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '"' | '\'') => (quote, open) = (Some(c), true),
            (None, c) if c.is_whitespace() => {
                if open || !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                    open = false;
                }
            }
            (None, c) => word.push(c),
        }
    }
    if open || !word.is_empty() {
        out.push(word);
    }
    out
}

/// Every `cowproof ...` command in a skill: lines in fenced blocks and inline code spans.
fn cowproof_commands(markdown: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut fenced = false;
    for line in markdown.lines() {
        let line = line.trim();
        if line.starts_with("```") {
            fenced = !fenced;
        } else if fenced {
            let command = line.strip_prefix("$ ").unwrap_or(line);
            found.extend(
                command
                    .starts_with("cowproof ")
                    .then(|| command.to_string()),
            );
        } else {
            found.extend(
                line.split('`')
                    .skip(1)
                    .step_by(2)
                    .filter(|span| span.starts_with("cowproof "))
                    .map(str::to_string),
            );
        }
    }
    found
}

/// Hand each command the skills show to the real argument parser. `--help` goes last, so
/// clap parses everything before it (an unknown subcommand or flag is an error) and then
/// prints help and exits 0.
#[test]
fn every_command_in_the_skills_parses_with_the_real_cli() {
    let mut subcommands = std::collections::BTreeSet::new();
    for skill in SKILLS {
        let text = read(&format!("plugin/skills/{skill}/SKILL.md"));
        let commands = cowproof_commands(&text);
        assert!(!commands.is_empty(), "{skill} shows no cowproof commands");
        for command in commands {
            let args = words(&command);
            subcommands.insert(args[1].clone());
            let out = cowproof().args(&args[1..]).arg("--help").output().unwrap();
            assert!(
                out.status.success(),
                "{skill}: `{command}` is rejected by the cowproof CLI:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    for expected in ["run", "lint", "watch", "rule", "note", "verify"] {
        assert!(
            subcommands.contains(expected),
            "no skill shows `cowproof {expected}`"
        );
    }
}

/// The packet in the dispatch skill, written into a repository that has the folders it
/// owns, must lint with no errors and no warnings.
#[test]
fn the_example_packet_in_the_dispatch_skill_lints_clean() {
    let skill = read("plugin/skills/cowproof-dispatch/SKILL.md");
    let fence = skill
        .split("```markdown\n")
        .nth(1)
        .expect("a markdown example");
    let packet = fence.split("\n```").next().unwrap();
    assert!(packet.starts_with("<!-- lane {"), "the example is a packet");

    let repo = scratch();
    for dir in ["src", "tests", "docs/handoffs"] {
        fs::create_dir_all(repo.path().join(dir)).unwrap();
    }
    fs::write(repo.path().join("packet.md"), packet).unwrap();
    let out = cowproof()
        .args(["lint", "packet.md", "--repo"])
        .arg(repo.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "lint failed:\n{stderr}");
    assert_eq!(stderr, "", "lint printed findings");
}

/// The plugin's `.mcp.json` must parse as valid JSON and declare exactly one server
/// named `cowproof` with command `cowproof` and args `["serve", "--director"]`.
#[test]
fn the_mcp_json_declares_the_cowproof_director_server() {
    let mcp = json("plugin/.mcp.json");
    assert!(mcp["mcpServers"].is_object(), "mcpServers is an object");

    let servers = mcp["mcpServers"].as_object().expect("mcpServers object");
    assert_eq!(servers.len(), 1, "exactly one server declared");

    let (name, config) = servers
        .iter()
        .next()
        .expect("at least one server, just checked len == 1");
    assert_eq!(name, "cowproof", "server name is cowproof");

    assert_eq!(config["command"], "cowproof", "command is cowproof");
    assert_eq!(
        config["args"],
        serde_json::json!(["serve", "--director"]),
        "args are [\"serve\", \"--director\"]"
    );
}

/// The real cowproof binary accepts `serve --director` as arguments and serves the four
/// director tools. Test by driving the process over stdio with initialize and tools/list.
#[test]
fn the_cowproof_binary_serves_the_director_tools_over_stdio() {
    use std::io::Write;
    use std::process::Stdio;

    let root = scratch();
    let mut child = cowproof()
        .args(["serve", "--director"])
        .env("HOME", root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start cowproof serve --director");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    // Send the MCP initialize request.
    let frames = [
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }
        }),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ];
    for frame in frames {
        writeln!(stdin, "{frame}").expect("write frame");
    }
    drop(stdin);

    // Collect responses.
    let reader = std::io::BufReader::new(stdout);
    use std::io::BufRead;
    let mut responses = Vec::new();
    for line in reader.lines() {
        match line {
            Ok(line) if !line.is_empty() => {
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(val) => responses.push(val),
                    Err(e) => panic!("invalid JSON response: {e}\n{line}"),
                }
            }
            Ok(_) => {}
            Err(e) => panic!("failed to read stdout: {e}"),
        }
    }

    let _ = child.wait();

    // Find the tools/list response.
    let tools_response = responses
        .iter()
        .find(|r| r.get("id") == Some(&serde_json::json!(2)))
        .expect("received tools/list response");

    let mut tool_names: Vec<&str> = tools_response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .expect("tools array in result")
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    tool_names.sort_unstable();

    assert_eq!(
        tool_names,
        ["escalations", "events", "lanes", "note", "rule"]
    );
}

/// Every MCP tool mentioned in the skills is served by the real binary.
/// Parse tool references as "the `<name>` tool", assert each one is served, and assert
/// at least one tool reference was found.
#[test]
fn every_mcp_tool_named_in_the_skills_is_served() {
    use std::collections::HashSet;
    use std::io::Write;
    use std::process::Stdio;

    // Parse tool references from all three skills. Extract any identifier in backticks
    // that appears after "Use the" or "The" to catch actual tool references.
    let mut referenced_tools = HashSet::new();
    for skill_name in [
        "cowproof-dispatch",
        "cowproof-escalate",
        "cowproof-handback",
    ] {
        let skill = read(&format!("plugin/skills/{skill_name}/SKILL.md"));
        for line in skill.lines() {
            // Extract tool names from lines containing "the `<name>` tool" or "Use the `<name>` tool".
            if (line.contains("the `") && line.contains("` tool"))
                || (line.contains("Use the `") && line.contains("` "))
            {
                // Simple extraction: look for `<name>` after "the " or "Use the ".
                let searches = [("the `", "` tool"), ("Use the `", "` ")];
                for (prefix, suffix) in &searches {
                    if let Some(start_pos) = line.find(prefix) {
                        let after_prefix = &line[start_pos + prefix.len()..];
                        if let Some(end_pos) = after_prefix.find(suffix) {
                            let tool_name = &after_prefix[..end_pos];
                            // Only accept valid tool-like names (alphanumeric + underscore).
                            if tool_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                referenced_tools.insert(tool_name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // At least one tool reference must be found.
    assert!(
        !referenced_tools.is_empty(),
        "no tool references found in skills"
    );

    // Get the live tools/list from the real binary.
    let root = scratch();
    let mut child = cowproof()
        .args(["serve", "--director"])
        .env("HOME", root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start cowproof serve --director");

    let mut stdin = child.stdin.take().expect("stdin");
    let frames = [
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }
        }),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ];
    for frame in frames {
        writeln!(stdin, "{frame}").expect("write frame");
    }
    drop(stdin);

    let reader = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    use std::io::BufRead;
    let mut responses = Vec::new();
    for line in reader.lines() {
        match line {
            Ok(line) if !line.is_empty() => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    responses.push(val);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = child.wait();

    // Extract served tool names.
    let empty = vec![];
    let tools_array = responses
        .iter()
        .find(|r| r.get("id") == Some(&serde_json::json!(2)))
        .and_then(|r| {
            r.get("result")
                .and_then(|res| res.get("tools").and_then(|t| t.as_array()))
        })
        .unwrap_or(&empty);
    let served_tools: HashSet<&str> = tools_array
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();

    // Every referenced tool must be served.
    for tool in &referenced_tools {
        assert!(
            served_tools.contains(tool.as_str()),
            "tool `{tool}` named in a skill is not served by the server"
        );
    }
}
