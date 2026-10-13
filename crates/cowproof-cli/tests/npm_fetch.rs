//! The npm dependency fetch (D6, D11, D14, F-1), end to end: a real `cowproof run` against a
//! FAKE `claude` and a FAKE `npm`, with no network at all and no real `npm` anywhere.
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
    FAKE_NPM_FAILS, FAKE_NPM_MUST_NOT_RUN, FAKE_NPM_OK, Lane, fake_npm, output, run_checks,
    sandbox_available, text, var_tmp,
};
use cowproof_prove::Capsule;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
    let mut lane = Lane::new(
        &run_checks(&["ok"]),
        json!([{"id": "ok", "command": "true"}]),
    );
    lane.commit_files(files);
    lane.set_env("COWPROOF_CACHE_ROOT", cache);
    lane.set_env("COWPROOF_FETCH_NETWORK", "none");
    lane.set_env("COWPROOF_NPM", npm);
    lane
}

/// A held-out file with one check, `held`, that runs only in the verifier.
fn heldout(dir: &Path, command: &str) -> PathBuf {
    let path = dir.join("h.toml");
    fs::write(
        &path,
        format!("[[check]]\nid = \"held\"\ncommand = {command:?}\n"),
    )
    .unwrap();
    path
}

fn run_with(lane: &Lane, heldout: &Path, code: i32) -> Output {
    let out = lane.run(&[Path::new("--heldout"), heldout]);
    assert_eq!(
        out.status.code(),
        Some(code),
        "cowproof run:\n{}",
        text(&out)
    );
    out
}

fn capsule(lane: &Lane) -> Capsule {
    Capsule::read(&lane.capsule_dir()).unwrap()
}

fn entry(cache: &Path, capsule: &Capsule) -> PathBuf {
    cache
        .join("deps")
        .join(capsule.dependency_cache_key.as_ref().unwrap())
}

/// Every regular file under `dir`, links not followed.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let kind = e.file_type().unwrap();
            if kind.is_dir() {
                pending.push(e.path());
            } else if kind.is_file() {
                found.push(e.path());
            }
        }
    }
    found
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
printf '%s\n' "$banner" > "$npm_config_cache/banner"
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
