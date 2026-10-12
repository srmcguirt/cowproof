//! Subscription mode (D2, D28 clause 6), end to end: a real `cowproof run --credential
//! subscription` against a FAKE `claude` and a FAKE Anthropic on 127.0.0.1
//! (`COWPROOF_ANTHROPIC_UPSTREAM`). Nothing here reaches the internet, the real `claude` is
//! never started, and no real credential exists: the director's "OAuth token" and "API key" are
//! lettered synthetic strings, and the tests check which of them reaches the fake upstream.
//!
//! The finding behind the design (measured with the real Claude Code 2.1.296 against a fake
//! upstream, 2026-10-11): with `CLAUDE_CODE_OAUTH_TOKEN` set and no API key, Claude Code sends
//! `Authorization: Bearer <token>` and an `anthropic-beta` list that includes
//! `oauth-2025-04-20` to `POST /v1/messages?beta=true` on `ANTHROPIC_BASE_URL`, and nothing
//! else there. So the proxy can swap the bearer exactly as it swaps an API key, and the real
//! token never has to enter the lane. The fake `claude` below sends that request through the
//! lane's real bridge and proxy.
//!
//! The lane tests need the sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`). The preflight refusals need neither a lane nor a sandbox.

#[allow(dead_code)]
mod common;

use common::{
    FakeAnthropic, Lane, anthropic_test_key, claude_oauth_test_token, output, run_checks,
    sandbox_available, text,
};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn checks() -> Value {
    json!([{"id": "edit", "command": "grep -q edited README.md"}])
}

/// What the fake `claude` of a lane does after its usual edits: record its argv and its
/// environment, send one Messages request through the bridge with the credential header
/// `header` (a shell fragment naming the header line), record the answer, then run the check.
///
/// The request is the one Claude Code sends in subscription mode when it holds the
/// placeholder in `CLAUDE_CODE_OAUTH_TOKEN`, or in API-key mode when it holds it in
/// `ANTHROPIC_API_KEY`.
fn builder(header: &str, second: &str) -> String {
    let post = |n: &str, target: &str, header: &str| {
        format!(
            r#"
perl -MIO::Socket::INET -e '
  $s = IO::Socket::INET->new(PeerAddr => $ARGV[0], Proto => "tcp", Timeout => 10)
      or die "connect: $!\n";
  $b = "{{\"model\":\"m\"}}";
  print $s "POST {target} HTTP/1.1\r\nHost: $ARGV[0]\r\n"
      . "{header}\r\ncontent-type: application/json\r\n"
      . "connection: close\r\ncontent-length: " . length($b) . "\r\n\r\n$b";
  local $/; print <$s>;' "$host_port" > "$rec/answer{n}" 2> "$rec/answer{n}.err"
echo "$?" > "$rec/answer{n}.status"
"#
        )
    };
    let mut body = String::from(
        r#"
env | sort > "$rec/env.txt"
printf '%s\n' "$@" > "$rec/argv.txt"
host_port="${ANTHROPIC_BASE_URL#http://}"
"#,
    );
    body.push_str(&post("", "/v1/messages?beta=true", header));
    if !second.is_empty() {
        body.push_str(&post("2", "/v1/messages", second));
    }
    body.push_str(&run_checks(&["edit"]));
    body
}

/// The subscription builder: a bearer carrying the placeholder from its OAuth variable, with the
/// OAuth beta flag, as Claude Code sends it; then (second request) the same lane tries an
/// `x-api-key` carrying the same placeholder, which the bearer-only route must refuse.
fn subscription_builder() -> String {
    builder(
        "authorization: Bearer $ENV{CLAUDE_CODE_OAUTH_TOKEN}\\r\\nanthropic-beta: oauth-2025-04-20",
        "x-api-key: $ENV{CLAUDE_CODE_OAUTH_TOKEN}",
    )
}

fn api_key_builder() -> String {
    builder("x-api-key: $ENV{ANTHROPIC_API_KEY}", "")
}

/// `cowproof run` with the credential flags and environment of the case, not yet started.
/// `token` and `key` are the director's `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY`; the
/// test process's own values of both are removed first, so neither case reads a real one.
fn run_command(
    lane: &Lane,
    fake: &FakeAnthropic,
    token: Option<&str>,
    key: Option<&str>,
    extra: &[&str],
) -> Command {
    let mut c = lane.cowproof_cmd();
    c.arg("run")
        .arg(&lane.packet)
        .arg("--repo")
        .arg(&lane.repo)
        .arg("--lanes-root")
        .arg(lane.lanes.path())
        .arg("--claude-bin")
        .arg(lane.fake_claude())
        .args(extra)
        .env_remove("CLAUDE_CODE_OAUTH_TOKEN")
        .env_remove("ANTHROPIC_API_KEY")
        .env("COWPROOF_ANTHROPIC_UPSTREAM", fake.base());
    if let Some(token) = token {
        c.env("CLAUDE_CODE_OAUTH_TOKEN", token);
    }
    if let Some(key) = key {
        c.env("ANTHROPIC_API_KEY", key);
    }
    c
}

fn json_of(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap_or_else(|e| panic!("{path:?}: {e}")))
        .unwrap()
}

fn read(lane: &Lane, rel: &str) -> String {
    let p = lane.lane_dir().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Every regular file under `dir`, links and sockets left alone.
fn files_under(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            files_under(&path, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

/// No file of the lane (clone, home, scratch, control, capsule) holds any of `secrets`.
fn assert_in_no_file(lane: &Lane, secrets: &[&str]) {
    let mut files = Vec::new();
    files_under(&lane.lane_dir(), &mut files);
    assert!(files.len() > 20, "only {} files scanned", files.len());
    for file in files {
        let bytes = fs::read(&file).unwrap_or_default();
        for secret in secrets {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "a credential is in {}",
                file.display()
            );
        }
    }
}

/// A run that stopped at the preflight: exit 4, the message and "nothing was started", no
/// lane directory and no request to the upstream.
fn assert_refused(lane: &Lane, fake: &FakeAnthropic, out: &Output, needles: &[&str]) {
    let err = text(out);
    assert_eq!(out.status.code(), Some(4), "{err}");
    assert!(err.contains("nothing was started"), "{err}");
    for needle in needles {
        assert!(err.contains(needle), "missing {needle:?} in: {err}");
    }
    assert!(!lane.lane_dir().exists(), "a lane was created: {err}");
    assert!(fake.seen().is_empty(), "the upstream was contacted: {err}");
}

#[test]
fn a_subscription_lane_sends_the_real_token_as_the_bearer_and_never_the_api_key() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(&subscription_builder(), checks());
    let fake = FakeAnthropic::start();
    let token = claude_oauth_test_token();
    let key = anthropic_test_key();
    // Both credentials in the director's environment: subscription mode must use the token
    // alone, from the upstream's point of view, not only from the flag's.
    let out = output(&mut run_command(
        &lane,
        &fake,
        Some(&token),
        Some(&key),
        &["--credential", "subscription"],
    ));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // The upstream saw one request, the bearer one: the real token, with the OAuth beta flag
    // the lane sent, no x-api-key, and the placeholder nowhere.
    let seen = fake.messages();
    assert_eq!(seen.len(), 1, "{seen:#?}");
    let request = &seen[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/messages?beta=true");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {token}").as_str())
    );
    assert_eq!(request.header("x-api-key"), None, "{request:#?}");
    assert_eq!(request.header("anthropic-beta"), Some("oauth-2025-04-20"));
    let env = read(&lane, "home/fake/env.txt");
    let placeholder = env
        .lines()
        .find_map(|l| l.strip_prefix("CLAUDE_CODE_OAUTH_TOKEN="))
        .unwrap_or_else(|| panic!("no CLAUDE_CODE_OAUTH_TOKEN in the builder's environment: {env}"))
        .to_string();
    assert!(placeholder.starts_with("placeholder-"), "{placeholder}");
    for (name, value) in &request.headers {
        assert!(
            !value.contains(&placeholder),
            "the placeholder reached the upstream in {name}"
        );
        assert!(!value.contains(&key), "the API key reached the upstream");
    }
    assert!(!String::from_utf8_lossy(&request.body).contains(&key));
    // The second request, an `x-api-key` with the placeholder, was refused by the proxy
    // itself (403) and never forwarded: a subscription lane cannot fall onto a key.
    assert_eq!(fake.seen().len(), 1, "{:#?}", fake.seen());
    let first = read(&lane, "home/fake/answer");
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    let second = read(&lane, "home/fake/answer2");
    assert!(second.starts_with("HTTP/1.1 403"), "{second}");

    // The builder's environment holds the placeholder in the OAuth variable, no API key, and
    // neither real credential.
    assert!(
        !env.lines().any(|l| l.starts_with("ANTHROPIC_API_KEY=")),
        "{env}"
    );
    assert!(!env.contains(&token) && !env.contains(&key), "{env}");
    // The real token and the director's key are in no file of the lane.
    assert_in_no_file(&lane, &[&token, &key]);

    // The isolation flags are on the launch (SC-4), and `--bare`, which would not read the
    // token, is not.
    let argv: Vec<String> = read(&lane, "home/fake/argv.txt")
        .lines()
        .map(str::to_string)
        .collect();
    let at = argv
        .iter()
        .position(|a| a == "--setting-sources")
        .unwrap_or_else(|| panic!("no --setting-sources in {argv:?}"));
    assert_eq!(argv[at + 1], "", "{argv:?}");
    assert!(argv.iter().any(|a| a == "--strict-mcp-config"), "{argv:?}");
    assert!(!argv.iter().any(|a| a == "--bare"), "{argv:?}");

    // The mode is recorded where the lane appears: run.json, verdict.json and the capsule.
    let control = lane.lane_dir().join("control");
    let run = json_of(&control.join("run.json"));
    assert_eq!(run["authMode"], "subscription", "{run}");
    assert_eq!(run["credentialKind"], "claude-oauth-token", "{run}");
    assert_eq!(run["credentialInLane"], false, "{run}");
    assert_eq!(run["anthropicUpstream"], fake.base(), "{run}");
    let verdict = json_of(&control.join("verdict.json"));
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["authMode"], "subscription", "{verdict}");
    assert_eq!(verdict["credentialInLane"], false, "{verdict}");
    let capsule = json_of(&lane.capsule_dir().join("capsule.json"));
    assert_eq!(capsule["auth_mode"], "subscription", "{capsule}");
    assert_eq!(
        capsule["credential_kind"], "claude-oauth-token",
        "{capsule}"
    );
    assert_eq!(capsule["credential_in_lane"], false, "{capsule}");

    // `cowproof watch` shows it, as a column that only appears when a lane is not the default.
    let watch = output(
        lane.cowproof_cmd()
            .arg("watch")
            .arg("--lanes-root")
            .arg(lane.lanes.path()),
    );
    let table = String::from_utf8_lossy(&watch.stdout).into_owned();
    assert!(watch.status.success(), "{table}");
    let mut lines = table.lines();
    let header = lines.next().unwrap();
    assert!(header.ends_with("\tCREDENTIAL"), "{header}");
    let row = lines
        .find(|l| l.starts_with(&lane.id))
        .unwrap_or_else(|| panic!("no row for {} in: {table}", lane.id));
    assert!(
        row.ends_with("\tsubscription (claude-oauth-token)"),
        "{row}"
    );
    assert!(!row.contains("in lane"), "{row}");
}

#[test]
fn a_subscription_lane_needs_no_api_key_at_all() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(&subscription_builder(), checks());
    let fake = FakeAnthropic::start();
    let token = claude_oauth_test_token();
    let out = output(&mut run_command(
        &lane,
        &fake,
        Some(&token),
        None,
        &["--credential", "subscription"],
    ));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let seen = fake.messages();
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {token}").as_str())
    );
    assert_eq!(seen[0].header("x-api-key"), None);
}

#[test]
fn the_default_is_the_api_key_and_ignores_a_token_in_the_directors_environment() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(&api_key_builder(), checks());
    let fake = FakeAnthropic::start();
    let token = claude_oauth_test_token();
    let key = anthropic_test_key();
    // No `--credential`: the API key, with the subscription token also present.
    let out = output(&mut run_command(
        &lane,
        &fake,
        Some(&token),
        Some(&key),
        &[],
    ));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let seen = fake.messages();
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(seen[0].header("x-api-key"), Some(key.as_str()));
    assert_eq!(seen[0].header("authorization"), None, "{:#?}", seen[0]);
    let env = read(&lane, "home/fake/env.txt");
    assert!(
        !env.lines()
            .any(|l| l.starts_with("CLAUDE_CODE_OAUTH_TOKEN=")),
        "{env}"
    );
    assert!(!env.contains(&token) && !env.contains(&key), "{env}");
    assert_in_no_file(&lane, &[&token, &key]);

    let run = json_of(&lane.lane_dir().join("control/run.json"));
    assert_eq!(run["authMode"], "api-key", "{run}");
    assert!(run["credentialKind"].is_null(), "{run}");
    assert_eq!(run["credentialInLane"], false, "{run}");
    let capsule = json_of(&lane.capsule_dir().join("capsule.json"));
    assert_eq!(capsule["auth_mode"], "api-key", "{capsule}");
    assert_eq!(capsule["credential_in_lane"], false, "{capsule}");

    // An API-key lane leaves `watch` as it was: no extra column.
    let watch = output(
        lane.cowproof_cmd()
            .arg("watch")
            .arg("--lanes-root")
            .arg(lane.lanes.path()),
    );
    let table = String::from_utf8_lossy(&watch.stdout).into_owned();
    assert_eq!(
        table.lines().next(),
        Some("LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT"),
        "{table}"
    );
}

#[test]
fn subscription_mode_with_no_token_is_refused_and_never_falls_back_to_the_api_key() {
    let lane = Lane::new("", checks());
    let fake = FakeAnthropic::start();
    let key = anthropic_test_key();
    // The API key is set; the token is not. The lane must not start on the key.
    let out = output(&mut run_command(
        &lane,
        &fake,
        None,
        Some(&key),
        &["--credential", "subscription"],
    ));
    assert_refused(&lane, &fake, &out, &["CLAUDE_CODE_OAUTH_TOKEN"]);
    assert!(!text(&out).contains(&key));

    // An empty token is no token.
    let out = output(&mut run_command(
        &lane,
        &fake,
        Some(""),
        Some(&key),
        &["--credential", "subscription"],
    ));
    assert_refused(&lane, &fake, &out, &["CLAUDE_CODE_OAUTH_TOKEN"]);
}

#[test]
fn api_key_mode_with_no_key_is_refused_and_never_falls_back_to_the_token() {
    let lane = Lane::new("", checks());
    let fake = FakeAnthropic::start();
    let token = claude_oauth_test_token();
    let out = output(&mut run_command(&lane, &fake, Some(&token), None, &[]));
    assert_refused(&lane, &fake, &out, &["ANTHROPIC_API_KEY"]);
    assert!(!text(&out).contains(&token));
}

#[test]
fn subscription_mode_is_refused_with_host_and_names_it() {
    let lane = Lane::new("", checks());
    let fake = FakeAnthropic::start();
    let token = claude_oauth_test_token();
    // The alias names no host config: the refusal comes before the hosts file is read.
    let out = output(&mut run_command(
        &lane,
        &fake,
        Some(&token),
        None,
        &["--credential", "subscription", "--host", "nowhere"],
    ));
    assert_refused(&lane, &fake, &out, &["--host", "subscription"]);
    assert!(!text(&out).contains(&token));
}

#[test]
fn subscription_mode_is_for_claude_rungs_only() {
    let lane = Lane::new("", checks());
    let fake = FakeAnthropic::start();
    let token = claude_oauth_test_token();
    for rung in ["openrouter:glm-5.3-flash", "codex:gpt-6-luna"] {
        let out = output(&mut run_command(
            &lane,
            &fake,
            Some(&token),
            None,
            &["--credential", "subscription", "--model", rung],
        ));
        assert_refused(&lane, &fake, &out, &["subscription", rung]);
    }
}

#[test]
fn an_unknown_credential_mode_is_a_usage_error() {
    let lane = Lane::new("", checks());
    let fake = FakeAnthropic::start();
    let out = output(&mut run_command(
        &lane,
        &fake,
        None,
        None,
        &["--credential", "login"],
    ));
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("api-key"), "{}", text(&out));
    assert!(text(&out).contains("subscription"), "{}", text(&out));
}
