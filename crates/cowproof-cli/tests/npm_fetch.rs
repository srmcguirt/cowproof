//! The npm, yarn and pnpm dependency fetch (D6, D11, D14, F-1), end to end: a real `cowproof
//! run` against a FAKE `claude` and a FAKE `npm`, `yarn` or `pnpm`, with no network at all and
//! no real package tool anywhere.
//!
//! The fake `npm` (`common::fake_npm`) is injected the way `CARGO` names cargo: the lane's
//! environment sets `COWPROOF_NPM` to it. It records its argv, its environment and the
//! `.npmrc` it was given into `$npm_config_cache`, a directory of the cache entry being made
//! (the one place the fetch sandbox lets it write), and installs
//! `node_modules/fake-pkg/index.js`. The checks that need `node_modules` are HELD-OUT checks,
//! because they run only in the verifier: the builder's own sandbox has no `node_modules`.
//!
//! Every test names its own cache root (`COWPROOF_CACHE_ROOT`, under `/var/tmp`) and sets
//! `COWPROOF_FETCH_NETWORK=none`. Needs the sandbox like `tests/run.rs`.

mod common;

use common::{
    FAKE_JS_MUST_NOT_RUN, FAKE_NPM_FAILS, FAKE_NPM_MUST_NOT_RUN, FAKE_NPM_OK, FAKE_PNPM_FAILS,
    FAKE_YARN_FAILS, Lane, capsule, entry, fake_js_ok, fake_npm, fake_tool, files_under, heldout,
    output, run_checks, run_with, sandbox_available, text, var_tmp,
};
use cowproof_prove::Capsule;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const SECRET: &str = "SECRET-TOKEN-0123456789abcdef";

fn npm_project() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "package.json",
            "{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"fake-pkg\":\"1.0.0\"}}\n",
        ),
        (
            "package-lock.json",
            "{\"name\":\"app\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{}}\n",
        ),
    ]
}

/// A lane over `files` whose builder runs the no-op check `ok`, with its own cache root, no
/// fetch network, and the fake `npm` at `npm`.
fn new_lane(files: &[(&str, &str)], cache: &Path, npm: &Path) -> Lane {
    new_lane_for(files, cache, "COWPROOF_NPM", npm)
}

/// [`new_lane`] with the fake tool named by the hook variable `hook` (`COWPROOF_YARN`, ...).
fn new_lane_for(files: &[(&str, &str)], cache: &Path, hook: &str, tool: &Path) -> Lane {
    let mut lane = Lane::new(
        &run_checks(&["ok"]),
        json!([{"id": "ok", "command": "true"}]),
    );
    lane.commit_files(files);
    lane.set_env("COWPROOF_CACHE_ROOT", cache);
    lane.set_env("COWPROOF_FETCH_NETWORK", "none");
    lane.set_env(hook, tool);
    lane
}

/// The check that proves the verifier has the install.
const NEEDS_MODULES: &str =
    "test \"$(cat node_modules/fake-pkg/index.js)\" = 'module.exports = 42;'";

#[test]
fn a_lane_with_a_package_lock_gets_node_modules_in_the_verifier_and_is_proved() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let lane = new_lane(&npm_project(), cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    let out = run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("{}: proved", lane.id)),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "proved");

    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["npm".to_string()]);
    let e = entry(cache.path(), &c);
    assert!(e.join("npm/node_modules/fake-pkg/index.js").is_file());
    assert!(
        !e.join("cargo").exists(),
        "a tree without a Cargo.lock gets no cargo part"
    );
    assert_eq!(
        fs::read_dir(cache.path().join("deps-work"))
            .unwrap()
            .count(),
        0,
        "the work directory is removed"
    );
    // The seal covers the new fields.
    let json = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(json.contains("\"dependency_ecosystems\""), "{json}");
}

#[test]
fn the_fetch_runs_npm_ci_with_ignore_scripts_in_a_sandbox_that_holds_no_key() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let lane = new_lane(&npm_project(), cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);

    let c = capsule(&lane);
    let recorded = entry(cache.path(), &c).join("npm/cache");
    let argv: Vec<String> = fs::read_to_string(recorded.join("argv.txt"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(
        argv,
        ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        "{argv:?}"
    );
    let env = fs::read_to_string(recorded.join("env.txt")).unwrap();
    // npm's cache is a directory of the entry being made: the work directory's `new/npm/cache`
    // is renamed to `deps/<key>/npm/cache`, and what the fake wrote there is in the entry.
    let cache_dir = env
        .lines()
        .find_map(|l| l.strip_prefix("npm_config_cache="))
        .unwrap_or_else(|| panic!("no npm_config_cache in:\n{env}"));
    assert!(
        cache_dir.contains("/deps-work/") && cache_dir.ends_with("/new/npm/cache"),
        "{cache_dir}"
    );
    assert!(
        cache_dir.starts_with(cache.path().to_str().unwrap())
            || cache_dir.starts_with(cache.path().canonicalize().unwrap().to_str().unwrap()),
        "{cache_dir} is not under the cache root {}",
        cache.path().display()
    );
    assert!(env.contains("npm_config_ignore_scripts=true"), "{env}");
    // Nothing is inherited: no key, no proxy to the model, and the host's own home is not it.
    assert!(!env.contains("sk-test-real-xyz"), "{env}");
    assert!(!env.contains("ANTHROPIC"), "{env}");
    let cwd = fs::read_to_string(recorded.join("cwd.txt")).unwrap();
    assert!(cwd.trim_end().ends_with("/npm-project"), "{cwd}");
}

#[test]
fn the_verifier_gets_node_modules_offline_and_without_scripts_from_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let lane = new_lane(&npm_project(), cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    // The npm settings the verifier sets, and a `node_modules` that is the entry's own.
    let check = format!(
        "{NEEDS_MODULES} && test \"$npm_config_offline\" = true \
         && test \"$npm_config_ignore_scripts\" = true \
         && case \"$npm_config_cache\" in */deps/*/npm/cache) true;; *) false;; esac \
         && test -L node_modules"
    );
    run_with(&lane, &heldout(held.path(), &check), 0);
    assert_eq!(lane.verdict()["verdict"], "proved");
}

#[test]
fn a_check_cannot_write_into_the_verifiers_node_modules() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let lane = new_lane(&npm_project(), cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    // The check passes only if EVERY write is refused: a new file, a change to an installed
    // file, a new package directory and a new file in the cache.
    let check = "! touch node_modules/probe 2>/dev/null \
                 && ! (echo hacked > node_modules/fake-pkg/index.js) 2>/dev/null \
                 && ! mkdir node_modules/evil-pkg 2>/dev/null \
                 && ! touch \"$npm_config_cache/probe\" 2>/dev/null";
    run_with(&lane, &heldout(held.path(), check), 0);
    assert_eq!(lane.verdict()["verdict"], "proved");

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    assert_eq!(
        fs::read_to_string(e.join("npm/node_modules/fake-pkg/index.js")).unwrap(),
        "module.exports = 42;\n"
    );
    assert!(!e.join("npm/node_modules/probe").exists());
    assert!(!e.join("npm/node_modules/evil-pkg").exists());
    assert!(!e.join("npm/cache/probe").exists());
}

#[test]
fn a_failing_npm_is_infrastructure_exit_4_naming_npm_never_refuted() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_FAILS);
    let lane = new_lane(&npm_project(), cache.path(), &npm);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains(&format!("{}: infrastructure: ", lane.id))
            && stdout.contains("dependency fetch failed: ")
            && stdout.contains("npm ci --ignore-scripts failed")
            && stdout.contains("npm ERR! code E404"),
        "{}",
        text(&out)
    );
    assert!(
        !stdout.contains("deprecated"),
        "the first ERROR line is named, not the first line: {stdout}"
    );
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "infrastructure", "{verdict}");
    assert_eq!(verdict["exitCode"], 4);
    assert_eq!(verdict["failedChecks"], json!([]));
    assert_eq!(verdict["diverged"], json!([]));

    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("failed"));
    assert!(c.dependency_ecosystems.is_empty());
    assert!(c.dependency_cache_key.is_some());
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(cache.path().join("deps-work"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn an_npmrc_token_reaches_neither_the_fetch_nor_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let mut files = npm_project();
    let npmrc = format!(
        "registry=https://registry.npmjs.org/\n\
         //registry.npmjs.org/:_authToken={SECRET}\n\
         //registry.npmjs.org/:_auth={SECRET}\n\
         always-auth=true\n"
    );
    files.push((".npmrc", &npmrc));
    let lane = new_lane(&files, cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    // What the fake saw: the registry line, no credential, in its file and its environment.
    let seen = fs::read_to_string(e.join("npm/cache/npmrc.txt")).unwrap();
    assert!(
        seen.contains("registry=https://registry.npmjs.org/"),
        "{seen}"
    );
    assert!(seen.contains("always-auth=true"), "{seen}");
    assert!(
        !seen.contains(SECRET) && !seen.contains("_authToken"),
        "{seen}"
    );
    // Nothing anywhere in the entry holds the secret.
    for file in files_under(&e) {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(SECRET),
            "{} holds the token",
            file.display()
        );
    }
    // The capsule says that two credential lines were left out.
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("2 credential line(s) of .npmrc were not used")),
        "{:?}",
        c.dependency_fetch_notes
    );
    let json = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(!json.contains(SECRET));
}

#[test]
fn a_second_lane_with_the_same_lockfile_hits_the_cache_and_does_not_call_npm() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_first_dir, first_npm) = fake_npm(FAKE_NPM_OK);
    let first = new_lane(&npm_project(), cache.path(), &first_npm);
    let held = var_tmp("cp-npm-held-");
    let heldout = heldout(held.path(), NEEDS_MODULES);
    run_with(&first, &heldout, 0);
    let a = capsule(&first);
    let recorded = entry(cache.path(), &a).join("npm/cache/argv.txt");
    let before = fs::read_to_string(&recorded).unwrap();

    // The second lane's `npm` fails if it is run at all.
    let (_second_dir, second_npm) = fake_npm(FAKE_NPM_MUST_NOT_RUN);
    let second = new_lane(&npm_project(), cache.path(), &second_npm);
    run_with(&second, &heldout, 0);
    let b = capsule(&second);
    assert_eq!(a.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(b.dependency_fetch_outcome.as_deref(), Some("hit"));
    assert_eq!(b.dependency_ecosystems, vec!["npm".to_string()]);
    assert_eq!(a.dependency_cache_key, b.dependency_cache_key);
    assert_eq!(fs::read_to_string(&recorded).unwrap(), before);
    assert_eq!(fs::read_dir(cache.path().join("deps")).unwrap().count(), 1);

    // Another lockfile is another key: the fake runs again.
    let (_third_dir, third_npm) = fake_npm(FAKE_NPM_OK);
    let mut changed = npm_project();
    changed[1].1 = "{\"name\":\"app\",\"lockfileVersion\":3,\"packages\":{},\"x\":1}\n";
    let third = new_lane(&changed, cache.path(), &third_npm);
    run_with(&third, &heldout, 0);
    let c = capsule(&third);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_ne!(a.dependency_cache_key, c.dependency_cache_key);
}

#[test]
fn an_npm_shrinkwrap_is_a_lockfile_too() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let files = vec![
        npm_project().remove(0),
        (
            "npm-shrinkwrap.json",
            "{\"name\":\"app\",\"lockfileVersion\":3,\"packages\":{}}\n",
        ),
    ];
    let lane = new_lane(&files, cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["npm".to_string()]);
}

#[test]
fn a_package_json_without_a_lockfile_is_not_fetched_and_the_capsule_says_so() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    // The fake must not run: there is no lockfile to install from.
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_MUST_NOT_RUN);
    let lane = new_lane(&npm_project()[..1], cache.path(), &npm);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("not_fetched"));
    assert_ne!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert!(c.dependency_cache_key.is_none());
    assert!(c.dependency_ecosystems.is_empty());
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("package.json without a package-lock.json")),
        "{:?}",
        c.dependency_fetch_notes
    );
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn verify_on_another_cache_root_fetches_npm_again_and_reproduces() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let lane = new_lane(&npm_project(), cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let key = capsule(&lane).dependency_cache_key.unwrap();

    // Another machine: a fresh clone, an empty cache root, its own fake npm.
    let fresh = var_tmp("cp-npm-fresh-");
    let clone = fresh.path().join("repo");
    let cloned = output(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&lane.repo)
            .arg(&clone),
    );
    assert!(cloned.status.success(), "{}", text(&cloned));
    let other_cache = var_tmp("cp-npm-other-");
    let workdir = var_tmp("cp-npm-wd-");
    let out = output(
        lane.cowproof_cmd()
            .env("COWPROOF_CACHE_ROOT", other_cache.path())
            .env("COWPROOF_FETCH_NETWORK", "none")
            .current_dir(fresh.path())
            .arg("verify")
            .arg(lane.capsule_dir())
            .arg("--repo")
            .arg(&clone)
            .arg("--workdir")
            .arg(workdir.path()),
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).lines().next(),
        Some("reproduced"),
        "{}",
        text(&out)
    );
    assert!(
        other_cache
            .path()
            .join("deps")
            .join(&key)
            .join("npm/node_modules/fake-pkg/index.js")
            .is_file(),
        "verify fetched the capsule's key into its own cache root"
    );

    // And a verify whose npm fails is infrastructure, naming npm, not a divergence.
    let (_bad_dir, bad_npm) = fake_npm(FAKE_NPM_FAILS);
    let third_cache = var_tmp("cp-npm-third-");
    let workdir = var_tmp("cp-npm-wd2-");
    let out = output(
        lane.cowproof_cmd()
            .env("COWPROOF_CACHE_ROOT", third_cache.path())
            .env("COWPROOF_FETCH_NETWORK", "none")
            .env("COWPROOF_NPM", &bad_npm)
            .current_dir(fresh.path())
            .arg("verify")
            .arg(lane.capsule_dir())
            .arg("--repo")
            .arg(&clone)
            .arg("--workdir")
            .arg(workdir.path()),
    );
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("infrastructure: dependency fetch failed")
            && err.contains("npm ci --ignore-scripts failed")
            && err.contains("npm ERR! code E404"),
        "{err}"
    );
}

/// What the fake registry says to whoever the proxy tunnels to it.
const BANNER: &str = "NPM-REGISTRY-BANNER";

/// A fake registry on `127.0.0.1` that greets every connection and counts them.
struct Upstream {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

fn upstream() -> Upstream {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            let _ = writeln!(stream, "{BANNER}");
        }
    });
    Upstream { addr, accepted }
}

/// A fake `npm` that asks the proxy `npm_config_https_proxy` names for a tunnel to
/// `host:443` and, if it gets one, records what the registry at the other end says into the
/// cache, then installs `node_modules/fake-pkg`.
fn tunnelling_npm(host: &str) -> String {
    tunnelling_tool(host, "npm_config_cache")
}

/// [`tunnelling_npm`] for any tool that writes into the cache directory `cache_var` names.
fn tunnelling_tool(host: &str, cache_var: &str) -> String {
    format!(
        r#"#!/bin/bash
case "$npm_config_https_proxy" in http://127.0.0.1:*) ;; *) echo "npm ERR! npm_config_https_proxy=$npm_config_https_proxy" >&2; exit 6 ;; esac
[ "$HTTPS_PROXY" = "$npm_config_https_proxy" ] || {{ echo "npm ERR! HTTPS_PROXY=$HTTPS_PROXY" >&2; exit 6; }}
port="${{npm_config_https_proxy##*:}}"
exec 3<>/dev/tcp/127.0.0.1/$port || exit 7
printf 'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n' >&3
IFS= read -r status <&3
case "$status" in
  *" 200 "*) ;;
  *) echo "npm ERR! the proxy said: $status" >&2; exit 1 ;;
esac
IFS= read -r blank <&3
IFS= read -r banner <&3
printf '%s\n' "$banner" > "${cache_var}/banner"
mkdir -p node_modules/fake-pkg
printf 'module.exports = 42;\n' > node_modules/fake-pkg/index.js
"#
    )
}

#[test]
fn the_default_network_tunnels_npm_to_the_npm_registry_and_to_no_other_host() {
    if !sandbox_available() {
        return;
    }
    // Allowed: registry.npmjs.org, mapped to a live fake on 127.0.0.1 (no DNS).
    let registry = upstream();
    let cache = var_tmp("cp-npm-cache-");
    let (_dir, npm) = fake_npm(&tunnelling_npm("registry.npmjs.org"));
    let mut lane = new_lane(&npm_project(), cache.path(), &npm);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("registry.npmjs.org={}", registry.addr),
    );
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(
        fs::read_to_string(entry(cache.path(), &c).join("npm/cache/banner")).unwrap(),
        format!("{BANNER}\n"),
        "the fetch's bytes came through the tunnel"
    );
    assert_eq!(registry.accepted.load(Ordering::SeqCst), 1);

    // Refused: the crates.io host is for cargo; an npm fetch of the same tree may not reach
    // it, even though the name resolves to a live fake.
    let other = upstream();
    let cache = var_tmp("cp-npm-cache-");
    let (_dir, npm) = fake_npm(&tunnelling_npm("index.crates.io"));
    let mut lane = new_lane(&npm_project(), cache.path(), &npm);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("index.crates.io={}", other.addr),
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("dependency fetch failed: ")
            && stdout.contains("npm ci --ignore-scripts failed")
            && stdout.contains("refused a connection to index.crates.io:443"),
        "{}",
        text(&out)
    );
    assert_eq!(other.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(lane.verdict()["verdict"], "infrastructure");
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_registry_the_base_npmrc_names_is_reached_and_one_it_does_not_name_is_refused() {
    if !sandbox_available() {
        return;
    }
    let registry = upstream();
    let cache = var_tmp("cp-npm-cache-");
    let (_dir, npm) = fake_npm(&tunnelling_npm("npm.corp.example"));
    let mut files = npm_project();
    files.push((".npmrc", "registry=https://npm.corp.example/\n"));
    let mut lane = new_lane(&files, cache.path(), &npm);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("npm.corp.example={}", registry.addr),
    );
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    assert_eq!(registry.accepted.load(Ordering::SeqCst), 1);

    // The same tree without that line in the BASE: the host is refused (the file is not
    // the patch's to add, and without it nothing allows the name).
    let refused = upstream();
    let cache = var_tmp("cp-npm-cache-");
    let (_dir, npm) = fake_npm(&tunnelling_npm("npm.corp.example"));
    let mut lane = new_lane(&npm_project(), cache.path(), &npm);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("npm.corp.example={}", refused.addr),
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("refused a connection to npm.corp.example:443"),
        "{}",
        text(&out)
    );
    assert_eq!(refused.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn npm_client_certificate_settings_reach_neither_the_fetch_nor_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-cache-");
    let (_npm_dir, npm) = fake_npm(FAKE_NPM_OK);
    let mut files = npm_project();
    // The PEM header is built, not written, so the source holds no key-shaped literal.
    let begin = concat!("-----BEGIN ", "PRIVATE KEY-----");
    let npmrc = format!(
        "registry=https://registry.npmjs.org/\n\
         key=\"{begin}\\nPEMBODY-0123\\n-----END PRIVATE KEY-----\"\n\
         //reg.example/:keyfile=/x/KEYFILE-PATH\n\
         certfile=/y/CERTFILE-PATH\n\
         always-auth=true\n"
    );
    files.push((".npmrc", &npmrc));
    let lane = new_lane(&files, cache.path(), &npm);
    let held = var_tmp("cp-npm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    let seen = fs::read_to_string(e.join("npm/cache/npmrc.txt")).unwrap();
    assert!(
        seen.contains("registry=https://registry.npmjs.org/"),
        "{seen}"
    );
    for gone in [
        "PRIVATE KEY",
        "PEMBODY-0123",
        "keyfile",
        "KEYFILE-PATH",
        "certfile",
        "CERTFILE-PATH",
    ] {
        assert!(!seen.contains(gone), "{gone} reached the fake:\n{seen}");
    }
    for file in files_under(&e) {
        let text = String::from_utf8_lossy(&fs::read(&file).unwrap()).into_owned();
        for gone in ["PEMBODY-0123", "KEYFILE-PATH", "CERTFILE-PATH"] {
            assert!(!text.contains(gone), "{} holds {gone}", file.display());
        }
    }
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("3 credential line(s) of .npmrc were not used")),
        "{:?}",
        c.dependency_fetch_notes
    );
}

// ---- yarn and pnpm -----------------------------------------------------------------------

const YARN_V1_LOCK: &str = "# yarn lockfile v1\n";
const YARN_BERRY_LOCK: &str = "__metadata:\n  version: 8\n";

fn manifest() -> (&'static str, &'static str) {
    npm_project().remove(0)
}

fn yarn_project() -> Vec<(&'static str, &'static str)> {
    vec![manifest(), ("yarn.lock", YARN_V1_LOCK)]
}

fn pnpm_project() -> Vec<(&'static str, &'static str)> {
    vec![manifest(), ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")]
}

/// The lines the fake recorded as its argv, in the entry the capsule names.
fn recorded_argv(cache: &Path, c: &Capsule) -> Vec<String> {
    fs::read_to_string(entry(cache, c).join("npm/cache/argv.txt"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// The environment the fake recorded, and the verifier's, for the tool's offline and
/// no-scripts settings.
const YARN_VERIFIER_SETTINGS: &str = "test \"$YARN_ENABLE_SCRIPTS\" = false \
     && test \"$YARN_ENABLE_NETWORK\" = false \
     && test \"$npm_config_ignore_scripts\" = true \
     && case \"$YARN_CACHE_FOLDER\" in */deps/*/npm/cache) true;; *) false;; esac \
     && test -L node_modules";

#[test]
fn a_classic_yarn_lane_gets_node_modules_and_is_proved_with_scripts_off() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-yarn-cache-");
    let (_dir, yarn) = fake_tool("yarn", &fake_js_ok("YARN_CACHE_FOLDER"));
    let lane = new_lane_for(&yarn_project(), cache.path(), "COWPROOF_YARN", &yarn);
    let held = var_tmp("cp-yarn-held-");
    let check = format!("{NEEDS_MODULES} && {YARN_VERIFIER_SETTINGS}");
    let out = run_with(&lane, &heldout(held.path(), &check), 0);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("{}: proved", lane.id)),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "proved");

    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["yarn".to_string()]);
    let e = entry(cache.path(), &c);
    assert!(e.join("npm/node_modules/fake-pkg/index.js").is_file());
    assert!(!e.join("cargo").exists());
    assert_eq!(
        recorded_argv(cache.path(), &c),
        [
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--non-interactive"
        ]
    );
    let env = fs::read_to_string(e.join("npm/cache/env.txt")).unwrap();
    assert!(env.contains("npm_config_ignore_scripts=true"), "{env}");
    assert!(env.contains("YARN_ENABLE_SCRIPTS=false"), "{env}");
    assert!(
        env.lines()
            .any(|l| l.starts_with("YARN_CACHE_FOLDER=") && l.ends_with("/new/npm/cache")),
        "{env}"
    );
    assert!(
        !env.contains("ANTHROPIC") && !env.contains("sk-test-real-xyz"),
        "{env}"
    );
    let cwd = fs::read_to_string(e.join("npm/cache/cwd.txt")).unwrap();
    assert!(cwd.trim_end().ends_with("/yarn-project"), "{cwd}");
}

#[test]
fn a_berry_yarn_lane_with_the_node_modules_linker_installs_immutably_without_builds() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-yarn-cache-");
    let (_dir, yarn) = fake_tool("yarn", &fake_js_ok("YARN_CACHE_FOLDER"));
    let files = vec![
        manifest(),
        ("yarn.lock", YARN_BERRY_LOCK),
        (".yarnrc.yml", "nodeLinker: node-modules\n"),
    ];
    let lane = new_lane_for(&files, cache.path(), "COWPROOF_YARN", &yarn);
    let held = var_tmp("cp-yarn-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["yarn".to_string()]);
    assert_eq!(
        recorded_argv(cache.path(), &c),
        ["install", "--immutable", "--mode=skip-build"]
    );
    let env = fs::read_to_string(entry(cache.path(), &c).join("npm/cache/env.txt")).unwrap();
    assert!(env.contains("YARN_ENABLE_SCRIPTS=false"), "{env}");
    assert!(env.contains("YARN_ENABLE_GLOBAL_CACHE=false"), "{env}");
}

#[test]
fn a_pnpm_lane_gets_node_modules_and_is_proved_with_scripts_off_and_a_hoisted_linker() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-pnpm-cache-");
    let (_dir, pnpm) = fake_tool("pnpm", &fake_js_ok("npm_config_store_dir"));
    let lane = new_lane_for(&pnpm_project(), cache.path(), "COWPROOF_PNPM", &pnpm);
    let held = var_tmp("cp-pnpm-held-");
    let check = format!(
        "{NEEDS_MODULES} && test \"$npm_config_ignore_scripts\" = true \
         && test \"$npm_config_offline\" = true \
         && case \"$npm_config_store_dir\" in */deps/*/npm/cache) true;; *) false;; esac \
         && test -L node_modules"
    );
    let out = run_with(&lane, &heldout(held.path(), &check), 0);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("{}: proved", lane.id)),
        "{}",
        text(&out)
    );

    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["pnpm".to_string()]);
    assert!(
        entry(cache.path(), &c)
            .join("npm/node_modules/fake-pkg/index.js")
            .is_file()
    );
    assert_eq!(
        recorded_argv(cache.path(), &c),
        [
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--config.node-linker=hoisted"
        ]
    );
    let env = fs::read_to_string(entry(cache.path(), &c).join("npm/cache/env.txt")).unwrap();
    assert!(env.contains("npm_config_ignore_scripts=true"), "{env}");
    assert!(
        env.contains("npm_config_manage_package_manager_versions=false"),
        "{env}"
    );
}

#[test]
fn a_berry_tree_on_plug_n_play_is_not_fetched_and_never_reported_as_fetched() {
    if !sandbox_available() {
        return;
    }
    // Spelled out, and by default (no `.yarnrc.yml` at all): neither leaves a node_modules.
    for rc in [
        Some("nodeLinker: pnp\n"),
        Some("enableTelemetry: false\n"),
        None,
    ] {
        let cache = var_tmp("cp-yarn-cache-");
        // The fake must not run: nothing is installed for a tree with no node_modules.
        let (_dir, yarn) = fake_tool("yarn", FAKE_JS_MUST_NOT_RUN);
        let mut files = vec![manifest(), ("yarn.lock", YARN_BERRY_LOCK)];
        files.extend(rc.map(|r| (".yarnrc.yml", r)));
        let lane = new_lane_for(&files, cache.path(), "COWPROOF_YARN", &yarn);
        let out = lane.run(&[]);
        assert_eq!(out.status.code(), Some(0), "{rc:?}: {}", text(&out));
        let c = capsule(&lane);
        assert_eq!(
            c.dependency_fetch_outcome.as_deref(),
            Some("not_fetched"),
            "{rc:?}"
        );
        assert_ne!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
        assert!(c.dependency_cache_key.is_none());
        assert!(c.dependency_ecosystems.is_empty());
        assert!(
            c.dependency_fetch_notes
                .iter()
                .any(|n| n.starts_with("yarn.lock: ") && n.contains("Plug'n'Play")),
            "{rc:?}: {:?}",
            c.dependency_fetch_notes
        );
        assert!(
            fs::read_dir(cache.path().join("deps"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[test]
fn two_javascript_lockfiles_are_not_fetched_and_the_capsule_names_them() {
    if !sandbox_available() {
        return;
    }
    for extra in [
        ("yarn.lock", YARN_V1_LOCK),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
    ] {
        let cache = var_tmp("cp-js-cache-");
        // None of the fakes may run: no tool is guessed.
        let (_n, npm) = fake_tool("npm", FAKE_NPM_MUST_NOT_RUN);
        let (_y, yarn) = fake_tool("yarn", FAKE_JS_MUST_NOT_RUN);
        let (_p, pnpm) = fake_tool("pnpm", FAKE_JS_MUST_NOT_RUN);
        let mut files = npm_project();
        files.push(extra);
        let mut lane = new_lane(&files, cache.path(), &npm);
        lane.set_env("COWPROOF_YARN", &yarn);
        lane.set_env("COWPROOF_PNPM", &pnpm);
        let out = lane.run(&[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let c = capsule(&lane);
        assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("not_fetched"));
        assert!(c.dependency_ecosystems.is_empty());
        assert!(c.dependency_cache_key.is_none());
        let want = format!(
            "package-lock.json, {}: more than one JavaScript lockfile",
            extra.0
        );
        assert!(
            c.dependency_fetch_notes
                .iter()
                .any(|n| n.starts_with(&want)),
            "{want}: {:?}",
            c.dependency_fetch_notes
        );
        assert!(
            fs::read_dir(cache.path().join("deps"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[test]
fn a_yarnrc_yml_token_top_level_or_under_a_scope_reaches_neither_the_fetch_nor_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-yarn-cache-");
    let (_dir, yarn) = fake_tool("yarn", &fake_js_ok("YARN_CACHE_FOLDER"));
    let rc = format!(
        "nodeLinker: node-modules\n\
         npmRegistryServer: \"https://registry.yarnpkg.com\"\n\
         npmAuthToken: {SECRET}\n\
         npmScopes:\n  corp:\n    npmRegistryServer: \"https://registry.yarnpkg.com\"\n    npmAuthToken: {SECRET}\n    npmAlwaysAuth: true\n\
         npmRegistries:\n  \"//registry.yarnpkg.com\":\n    npmAuthIdent: \"user:{SECRET}\"\n"
    );
    let files = vec![
        manifest(),
        ("yarn.lock", YARN_BERRY_LOCK),
        (".yarnrc.yml", rc.as_str()),
    ];
    let lane = new_lane_for(&files, cache.path(), "COWPROOF_YARN", &yarn);
    let held = var_tmp("cp-yarn-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    let seen = fs::read_to_string(e.join("npm/cache/yarnrc_yml.txt")).unwrap();
    assert!(seen.contains("nodeLinker: node-modules"), "{seen}");
    assert!(seen.contains("npmScopes:"), "{seen}");
    assert!(
        !seen.contains(SECRET)
            && !seen.contains("npmAuthToken")
            && !seen.contains("npmAuthIdent")
            && !seen.contains("npmAlwaysAuth"),
        "{seen}"
    );
    for file in files_under(&e) {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(SECRET),
            "{} holds the token",
            file.display()
        );
    }
    // Two tokens, one ident and one alwaysAuth line were left out.
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("yarn: 4 credential line(s) of .yarnrc.yml were not used")),
        "{:?}",
        c.dependency_fetch_notes
    );
    let json = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(!json.contains(SECRET));
}

#[test]
fn a_classic_yarnrc_and_an_npmrc_token_reach_neither_the_yarn_fetch_nor_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-yarn-cache-");
    let (_dir, yarn) = fake_tool("yarn", &fake_js_ok("YARN_CACHE_FOLDER"));
    let yarnrc = format!(
        "registry \"https://registry.yarnpkg.com\"\n\
         \"//registry.yarnpkg.com/:_authToken\" \"{SECRET}\"\n\
         \"//registry.yarnpkg.com/:_auth\" \"{SECRET}\"\n"
    );
    let npmrc = format!("//registry.npmjs.org/:_authToken={SECRET}\n");
    let mut files = yarn_project();
    files.push((".yarnrc", &yarnrc));
    files.push((".npmrc", &npmrc));
    let lane = new_lane_for(&files, cache.path(), "COWPROOF_YARN", &yarn);
    let held = var_tmp("cp-yarn-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    let seen = fs::read_to_string(e.join("npm/cache/yarnrc.txt")).unwrap();
    assert!(
        seen.contains("registry \"https://registry.yarnpkg.com\""),
        "{seen}"
    );
    assert!(!seen.contains(SECRET) && !seen.contains("_auth"), "{seen}");
    let npmrc_seen = fs::read_to_string(e.join("npm/cache/npmrc.txt")).unwrap();
    assert!(!npmrc_seen.contains(SECRET), "{npmrc_seen}");
    for file in files_under(&e) {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(SECRET),
            "{} holds the token",
            file.display()
        );
    }
    for want in [
        "yarn: 2 credential line(s) of .yarnrc were not used",
        "yarn: 1 credential line(s) of .npmrc were not used",
    ] {
        assert!(
            c.dependency_fetch_notes.iter().any(|n| n.contains(want)),
            "{want}: {:?}",
            c.dependency_fetch_notes
        );
    }
}

#[test]
fn a_pnpm_npmrc_token_reaches_neither_the_fetch_nor_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-pnpm-cache-");
    let (_dir, pnpm) = fake_tool("pnpm", &fake_js_ok("npm_config_store_dir"));
    let npmrc = format!(
        "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={SECRET}\n"
    );
    let mut files = pnpm_project();
    files.push((".npmrc", &npmrc));
    let lane = new_lane_for(&files, cache.path(), "COWPROOF_PNPM", &pnpm);
    let held = var_tmp("cp-pnpm-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    let seen = fs::read_to_string(e.join("npm/cache/npmrc.txt")).unwrap();
    assert!(
        seen.contains("registry=https://registry.npmjs.org/"),
        "{seen}"
    );
    for file in files_under(&e) {
        let bytes = fs::read(&file).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    }
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("pnpm: 1 credential line(s) of .npmrc were not used")),
        "{:?}",
        c.dependency_fetch_notes
    );
}

#[test]
fn a_failing_yarn_or_pnpm_is_infrastructure_exit_4_naming_the_tool_and_its_first_error() {
    if !sandbox_available() {
        return;
    }
    for (files, hook, name, body, label, first, skipped) in [
        (
            yarn_project(),
            "COWPROOF_YARN",
            "yarn",
            FAKE_YARN_FAILS,
            "yarn install --frozen-lockfile --ignore-scripts failed",
            "error Couldn't find package \"fake-pkg\"",
            "warning fake-pkg",
        ),
        (
            pnpm_project(),
            "COWPROOF_PNPM",
            "pnpm",
            FAKE_PNPM_FAILS,
            "pnpm install --frozen-lockfile --ignore-scripts failed",
            "ERR_PNPM_FETCH_404",
            "Progress: resolved",
        ),
    ] {
        let cache = var_tmp("cp-js-cache-");
        let (_dir, tool) = fake_tool(name, body);
        let lane = new_lane_for(&files, cache.path(), hook, &tool);
        let out = lane.run(&[]);
        assert_eq!(out.status.code(), Some(4), "{name}: {}", text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains(&format!("{}: infrastructure: ", lane.id))
                && stdout.contains("dependency fetch failed: ")
                && stdout.contains(label)
                && stdout.contains(first),
            "{name}: {}",
            text(&out)
        );
        assert!(
            !stdout.contains(skipped),
            "the first ERROR line is named, not the first line: {stdout}"
        );
        let verdict = lane.verdict();
        assert_eq!(verdict["verdict"], "infrastructure", "{verdict}");
        assert_eq!(verdict["exitCode"], 4);
        let c = capsule(&lane);
        assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("failed"));
        assert!(c.dependency_ecosystems.is_empty());
        assert!(
            fs::read_dir(cache.path().join("deps"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[test]
fn a_second_yarn_or_pnpm_lane_with_the_same_lockfile_hits_the_cache_and_does_not_call_the_tool() {
    if !sandbox_available() {
        return;
    }
    for (files, hook, name, cache_var) in [
        (yarn_project(), "COWPROOF_YARN", "yarn", "YARN_CACHE_FOLDER"),
        (
            pnpm_project(),
            "COWPROOF_PNPM",
            "pnpm",
            "npm_config_store_dir",
        ),
    ] {
        let cache = var_tmp("cp-js-cache-");
        let (_first_dir, first_tool) = fake_tool(name, &fake_js_ok(cache_var));
        let first = new_lane_for(&files, cache.path(), hook, &first_tool);
        let held = var_tmp("cp-js-held-");
        let heldout = heldout(held.path(), NEEDS_MODULES);
        run_with(&first, &heldout, 0);
        let a = capsule(&first);
        let recorded = entry(cache.path(), &a).join("npm/cache/argv.txt");
        let before = fs::read_to_string(&recorded).unwrap();

        let (_second_dir, second_tool) = fake_tool(name, FAKE_JS_MUST_NOT_RUN);
        let second = new_lane_for(&files, cache.path(), hook, &second_tool);
        run_with(&second, &heldout, 0);
        let b = capsule(&second);
        assert_eq!(
            a.dependency_fetch_outcome.as_deref(),
            Some("fetched"),
            "{name}"
        );
        assert_eq!(b.dependency_fetch_outcome.as_deref(), Some("hit"), "{name}");
        assert_eq!(b.dependency_ecosystems, vec![name.to_string()]);
        assert_eq!(a.dependency_cache_key, b.dependency_cache_key);
        assert_eq!(fs::read_to_string(&recorded).unwrap(), before);
        assert_eq!(fs::read_dir(cache.path().join("deps")).unwrap().count(), 1);
    }
}

#[test]
fn yarn_may_reach_yarns_registry_and_pnpm_may_not() {
    if !sandbox_available() {
        return;
    }
    // Allowed for yarn: registry.yarnpkg.com, mapped to a live fake on 127.0.0.1.
    let registry = upstream();
    let cache = var_tmp("cp-yarn-cache-");
    let (_dir, yarn) = fake_tool(
        "yarn",
        &tunnelling_tool("registry.yarnpkg.com", "YARN_CACHE_FOLDER"),
    );
    let mut lane = new_lane_for(&yarn_project(), cache.path(), "COWPROOF_YARN", &yarn);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("registry.yarnpkg.com={}", registry.addr),
    );
    let held = var_tmp("cp-yarn-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(
        fs::read_to_string(entry(cache.path(), &c).join("npm/cache/banner")).unwrap(),
        format!("{BANNER}\n")
    );
    assert_eq!(registry.accepted.load(Ordering::SeqCst), 1);

    // Refused for pnpm: yarn's host is not on its list, though the name resolves.
    let other = upstream();
    let cache = var_tmp("cp-pnpm-cache-");
    let (_dir, pnpm) = fake_tool(
        "pnpm",
        &tunnelling_tool("registry.yarnpkg.com", "npm_config_store_dir"),
    );
    let mut lane = new_lane_for(&pnpm_project(), cache.path(), "COWPROOF_PNPM", &pnpm);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("registry.yarnpkg.com={}", other.addr),
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("refused a connection to registry.yarnpkg.com:443"),
        "{}",
        text(&out)
    );
    assert_eq!(other.accepted.load(Ordering::SeqCst), 0);
}

// ---- corepack and local paths (lane/js-fetch-local-paths-corepack) ----

/// A manifest whose `packageManager` names a release a corepack shim would download.
const PINNED_MANIFEST: &str = "{\"name\":\"app\",\"version\":\"1.0.0\",\"packageManager\":\"yarn@1.22.19+sha256.deadbeef\",\"devEngines\":{\"packageManager\":{\"name\":\"pnpm\",\"version\":\"8.0.0\"}},\"dependencies\":{\"fake-pkg\":\"1.0.0\"}}\n";

/// The three settings that keep a corepack shim from downloading or insisting on a release.
const COREPACK_VERIFIER_SETTINGS: &str = "test \"$COREPACK_ENABLE_NETWORK\" = 0 \
     && test \"$COREPACK_ENABLE_STRICT\" = 0 \
     && test \"$COREPACK_ENABLE_AUTO_PIN\" = 0";

#[test]
fn the_fetch_copy_of_package_json_has_no_package_manager_and_corepack_never_downloads() {
    if !sandbox_available() {
        return;
    }
    // (fake tool body, hook variable, tool name, lockfile)
    let cases = [
        (
            FAKE_NPM_OK.to_string(),
            "COWPROOF_NPM",
            "npm",
            npm_project().remove(1),
        ),
        (
            fake_js_ok("YARN_CACHE_FOLDER"),
            "COWPROOF_YARN",
            "yarn",
            ("yarn.lock", YARN_V1_LOCK),
        ),
        (
            fake_js_ok("npm_config_store_dir"),
            "COWPROOF_PNPM",
            "pnpm",
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ),
    ];
    for (body, hook, name, lockfile) in cases {
        let cache = var_tmp("cp-corepack-cache-");
        let (_dir, tool) = fake_tool(name, &body);
        let lane = new_lane_for(
            &[("package.json", PINNED_MANIFEST), lockfile],
            cache.path(),
            hook,
            &tool,
        );
        let held = var_tmp("cp-corepack-held-");
        let check = format!("{NEEDS_MODULES} && {COREPACK_VERIFIER_SETTINGS}");
        let out = run_with(&lane, &heldout(held.path(), &check), 0);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("{}: proved", lane.id)),
            "{name}: {}",
            text(&out)
        );
        let c = capsule(&lane);
        assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
        let recorded = entry(cache.path(), &c).join("npm/cache");

        // The tool saw a manifest without either field, and everything else of it.
        let seen = fs::read_to_string(recorded.join("package_json.txt")).unwrap();
        assert!(!seen.contains("packageManager"), "{name}: {seen}");
        let doc: serde_json::Value = serde_json::from_str(&seen).unwrap();
        assert_eq!(doc["name"], "app", "{name}");
        assert_eq!(doc["dependencies"]["fake-pkg"], "1.0.0", "{name}");
        // ... and corepack could neither download nor insist on a release.
        let env = fs::read_to_string(recorded.join("env.txt")).unwrap();
        for want in [
            "COREPACK_ENABLE_NETWORK=0",
            "COREPACK_ENABLE_STRICT=0",
            "COREPACK_ENABLE_AUTO_PIN=0",
        ] {
            assert!(env.lines().any(|l| l == want), "{name}: {want} in\n{env}");
        }
        // The capsule counts the removal; the lane's own tree keeps its field.
        assert!(
            c.dependency_fetch_notes
                .iter()
                .any(|n| n.starts_with(&format!(
                    "{name}: 2 packageManager setting(s) of package.json were removed"
                ))),
            "{name}: {:?}",
            c.dependency_fetch_notes
        );
    }
}

/// A Berry lock whose entries are `entries` (each `"descriptor"` and its resolution).
fn berry_lock(entries: &[&str]) -> String {
    let mut lock = String::from("__metadata:\n  version: 8\n");
    for e in entries {
        lock.push_str(&format!(
            "\n\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"{e}\"\n  linkType: hard\n"
        ));
    }
    lock
}

/// A lane over `files` whose fetch must not run: the fake tool refuses, and the capsule says
/// `not_fetched` with a note that starts `<lockfile>: ` and holds `entry`.
fn assert_local_path_refused(
    files: &[(&str, &str)],
    hook: &str,
    tool_name: &str,
    lockfile: &str,
    entry: &str,
) -> Vec<String> {
    let cache = var_tmp("cp-local-cache-");
    let (_dir, tool) = fake_tool(tool_name, FAKE_JS_MUST_NOT_RUN);
    let lane = new_lane_for(files, cache.path(), hook, &tool);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{entry}: {}", text(&out));
    let c = capsule(&lane);
    assert_eq!(
        c.dependency_fetch_outcome.as_deref(),
        Some("not_fetched"),
        "{entry}: {:?}",
        c.dependency_fetch_notes
    );
    assert!(c.dependency_cache_key.is_none(), "{entry}");
    assert!(c.dependency_ecosystems.is_empty(), "{entry}");
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.starts_with(&format!("{lockfile}: ")) && n.contains(entry)),
        "{entry}: {:?}",
        c.dependency_fetch_notes
    );
    c.dependency_fetch_notes
}

#[test]
fn a_yarn_lockfile_entry_with_a_host_path_or_code_is_not_fetched_naming_the_entry() {
    if !sandbox_available() {
        return;
    }
    let rc = (".yarnrc.yml", "nodeLinker: node-modules\n");
    // Classic: file: and link: with an absolute path or a `..` component.
    for entry in [
        "resolved \"file:/etc/passwd\"",
        "resolved \"file:../outside\"",
        "resolved \"link:/home/u/dir\"",
        "resolved \"link:./a/../../b\"",
    ] {
        let lock = format!("# yarn lockfile v1\n\nfoo@^1.0.0:\n  version \"1.0.0\"\n  {entry}\n");
        assert_local_path_refused(
            &[manifest(), ("yarn.lock", &lock)],
            "COWPROOF_YARN",
            "yarn",
            "yarn.lock",
            entry,
        );
    }
    // Berry: portal, link, file, exec and a patch whose path leaves the tree.
    for resolution in [
        "a@portal:/abs::locator=app%40workspace%3A.",
        "a@link:../x::locator=app%40workspace%3A.",
        "a@file:/x.tgz#/x.tgz::hash=abc",
        "a@exec:./gen.js#./gen.js::hash=abc",
        "a@patch:a@npm%3A1.0.0#../x.patch::version=1.0.0&hash=abc",
        "a@patch:a@npm%3A1.0.0#/etc/x.patch::version=1.0.0&hash=abc",
        "a@patch:a@portal%3A/abs#./x.patch::version=1.0.0&hash=abc",
    ] {
        let lock = berry_lock(&[resolution]);
        assert_local_path_refused(
            &[manifest(), ("yarn.lock", &lock), rc],
            "COWPROOF_YARN",
            "yarn",
            "yarn.lock",
            resolution,
        );
    }
}

#[test]
fn a_pnpm_lockfile_entry_with_a_host_path_is_not_fetched_naming_the_entry() {
    if !sandbox_available() {
        return;
    }
    for (body, entry) in [
        (
            "packages:\n  foo@file:../x:\n    resolution: {directory: ../x, type: directory}\n",
            "foo@file:../x:",
        ),
        (
            "packages:\n  foo@1.0.0:\n    resolution: {directory: /abs, type: directory}\n",
            "resolution: {directory: /abs, type: directory}",
        ),
        (
            "importers:\n  .:\n    dependencies:\n      foo:\n        specifier: link:../foo\n        version: link:../foo\n",
            "specifier: link:../foo",
        ),
        (
            "importers:\n  .:\n    dependencies:\n      foo:\n        specifier: ^1.0.0\n        version: file:/abs/foo\n",
            "version: file:/abs/foo",
        ),
        (
            "packages:\n  foo@1.0.0:\n    resolution: {integrity: sha512-x, tarball: file:../x.tgz}\n",
            "tarball: file:../x.tgz",
        ),
    ] {
        let lock = format!("lockfileVersion: '9.0'\n\n{body}");
        assert_local_path_refused(
            &[manifest(), ("pnpm-lock.yaml", &lock)],
            "COWPROOF_PNPM",
            "pnpm",
            "pnpm-lock.yaml",
            entry,
        );
    }
}

#[test]
fn the_note_for_a_host_path_entry_escapes_its_control_characters() {
    if !sandbox_available() {
        return;
    }
    let lock = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      foo:\n        specifier: x\n        version: link:/\u{1b}[2J\u{9b}0c\n";
    let notes = assert_local_path_refused(
        &[manifest(), ("pnpm-lock.yaml", lock)],
        "COWPROOF_PNPM",
        "pnpm",
        "pnpm-lock.yaml",
        "version: link:/\\u{1b}[2J\\u{9b}0c",
    );
    assert!(
        notes.iter().all(|n| !n.chars().any(char::is_control)),
        "{notes:?}"
    );
}

#[test]
fn relative_workspace_paths_in_a_lockfile_are_fetched_and_a_relative_exec_is_not() {
    if !sandbox_available() {
        return;
    }
    // pnpm: link: and file: paths inside the tree.
    let cache = var_tmp("cp-local-cache-");
    let (_dir, pnpm) = fake_tool("pnpm", &fake_js_ok("npm_config_store_dir"));
    let lock = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: link:packages/a\n        version: link:packages/a\n      b:\n        specifier: file:./vendor/b\n        version: file:vendor/b\n\npackages:\n  b@file:vendor/b:\n    resolution: {directory: vendor/b, type: directory}\n";
    let lane = new_lane_for(
        &[manifest(), ("pnpm-lock.yaml", lock)],
        cache.path(),
        "COWPROOF_PNPM",
        &pnpm,
    );
    let held = var_tmp("cp-local-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["pnpm".to_string()]);

    // Berry: portal: and link: paths inside the tree.
    let cache = var_tmp("cp-local-cache-");
    let (_dir, yarn) = fake_tool("yarn", &fake_js_ok("YARN_CACHE_FOLDER"));
    let lock = berry_lock(&[
        "a@portal:packages/a::locator=app%40workspace%3A.",
        "a@link:./packages/b::locator=app%40workspace%3A.",
    ]);
    let rc = (".yarnrc.yml", "nodeLinker: node-modules\n");
    let lane = new_lane_for(
        &[manifest(), ("yarn.lock", &lock), rc],
        cache.path(),
        "COWPROOF_YARN",
        &yarn,
    );
    let held = var_tmp("cp-local-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["yarn".to_string()]);

    // A Berry exec: with a path inside the tree still runs a script at fetch time.
    let lock = berry_lock(&["a@exec:./scripts/gen.js#./scripts/gen.js::hash=abc"]);
    assert_local_path_refused(
        &[manifest(), ("yarn.lock", &lock), rc],
        "COWPROOF_YARN",
        "yarn",
        "yarn.lock",
        "a@exec:./scripts/gen.js",
    );
}

/// An npm lockfile of `packages` entries, as `(key, entry JSON)` pairs.
fn npm_lock(entries: &[(&str, &str)]) -> String {
    let mut packages = String::from("\"\":{\"name\":\"app\",\"version\":\"1.0.0\"}");
    for (key, entry) in entries {
        packages.push_str(&format!(",{}:{entry}", serde_json::to_string(key).unwrap()));
    }
    format!(
        "{{\"name\":\"app\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{{{packages}}}}}\n"
    )
}

#[test]
fn an_npm_lockfile_entry_with_a_host_path_is_not_fetched_naming_the_key() {
    if !sandbox_available() {
        return;
    }
    let cases = [
        // (lockfile, the key the note names)
        (
            npm_lock(&[(
                "node_modules/a",
                "{\"version\":\"1.0.0\",\"resolved\":\"file:/etc/a.tgz\"}",
            )]),
            "node_modules/a",
        ),
        (
            npm_lock(&[("node_modules/b", "{\"resolved\":\"file:../b.tgz\"}")]),
            "node_modules/b",
        ),
        (
            npm_lock(&[("node_modules/c", "{\"resolved\":\"../c\",\"link\":true}")]),
            "node_modules/c",
        ),
        (
            npm_lock(&[(
                "node_modules/d",
                "{\"resolved\":\"/home/u/d\",\"link\":true}",
            )]),
            "node_modules/d",
        ),
        (
            npm_lock(&[("../outside", "{\"version\":\"1.0.0\"}")]),
            "../outside",
        ),
        (
            "{\"lockfileVersion\":1,\"dependencies\":{\"e\":{\"version\":\"file:../e\"}}}\n"
                .to_string(),
            "dependencies.e",
        ),
    ];
    for (lock, key) in cases {
        assert_local_path_refused(
            &[manifest(), ("package-lock.json", &lock)],
            "COWPROOF_NPM",
            "npm",
            "package-lock.json",
            key,
        );
    }
    // npm-shrinkwrap.json is read the same way.
    let lock = npm_lock(&[("node_modules/a", "{\"resolved\":\"file:/etc/a.tgz\"}")]);
    assert_local_path_refused(
        &[manifest(), ("npm-shrinkwrap.json", &lock)],
        "COWPROOF_NPM",
        "npm",
        "npm-shrinkwrap.json",
        "node_modules/a",
    );
}

#[test]
fn the_note_for_an_npm_host_path_key_escapes_its_control_characters() {
    if !sandbox_available() {
        return;
    }
    let lock = npm_lock(&[("../\u{1b}[2J\u{9b}0c", "{\"version\":\"1.0.0\"}")]);
    let notes = assert_local_path_refused(
        &[manifest(), ("package-lock.json", &lock)],
        "COWPROOF_NPM",
        "npm",
        "package-lock.json",
        "../\\u{1b}[2J\\u{9b}0c",
    );
    assert!(
        notes.iter().all(|n| !n.chars().any(char::is_control)),
        "{notes:?}"
    );
}

#[test]
fn an_npm_workspace_link_inside_the_tree_is_fetched() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-npm-local-cache-");
    let (_dir, npm) = fake_npm(FAKE_NPM_OK);
    let lock = npm_lock(&[
        (
            "node_modules/a",
            "{\"resolved\":\"packages/a\",\"link\":true}",
        ),
        ("packages/a", "{\"name\":\"a\",\"version\":\"1.0.0\"}"),
        (
            "node_modules/foo",
            "{\"version\":\"1.0.0\",\"resolved\":\"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz\"}",
        ),
    ]);
    let lane = new_lane(
        &[manifest(), ("package-lock.json", &lock)],
        cache.path(),
        &npm,
    );
    let held = var_tmp("cp-npm-local-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_MODULES), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["npm".to_string()]);
}
