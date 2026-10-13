//! The Bundler dependency fetch (D6, D11, D14, F-1), end to end: a real `cowproof run`
//! against a FAKE `claude`, a FAKE `gem` and a FAKE `bundle`, with no network at all and no
//! real Ruby tool anywhere. Never a real `gem`, `bundle` or rubygems.org.
//!
//! The fetch reads `Gemfile.lock` in Rust and runs one sandboxed `gem fetch` per locked gem
//! (the fake `gem`, named by `COWPROOF_GEM`); it never evaluates a `Gemfile` and never runs
//! `bundle`. The fake `gem` runs in the entry's `bundler/cache` directory, so what it records
//! (`fake-gem-*.txt`, `fake-gem-argv.log`) is in the entry afterwards, and it writes the
//! `.gem` file `gem fetch` would. The verifier runs `bundle install --local` once before its
//! first check (the fake `bundle`, named by `COWPROOF_BUNDLE`); it records into `$BUNDLE_PATH`.
//! The checks that need the gems are HELD-OUT checks, because they run only in the verifier.
//!
//! Every test names its own cache root (`COWPROOF_CACHE_ROOT`, under `/var/tmp`) and sets
//! `COWPROOF_FETCH_NETWORK=none` unless it tests the proxy. Needs the sandbox like
//! `tests/run.rs`.

mod common;

use common::{
    Lane, capsule, entry, fake_tool, files_under, heldout, output, run_checks, run_with,
    sandbox_available, text, var_tmp,
};
use cowproof_run::bundler::Host;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const SECRET: &str = "SECRET-TOKEN-0123456789abcdef";

/// A `Gemfile` that is Ruby code: nothing in the fetch may run or read it.
const GEMFILE: &str =
    "source 'https://rubygems.org'\nraise 'the Gemfile was evaluated'\ngem 'fake-gem', '1.0.0'\n";

/// What the fake `gem` writes for `fake-gem` 1.0.0 on the `ruby` platform.
const GEM_BODY: &str = "fake gem fake-gem 1.0.0 ruby\n";

/// A FAKE `gem` that succeeds. It runs in the entry's gem cache directory and records, there,
/// `fake-gem-argv.log` (one line per call), `fake-gem-env.txt` (its sorted environment),
/// `fake-gem-cwd.txt`, `fake-gem-home.txt` (what is in its `HOME`) and `fake-gem-saw.txt` (any
/// `Gemfile`, `.gemrc` or `.bundle` it could see in its directory or its `HOME`). It writes
/// `NAME-VERSION[-PLATFORM].gem` with the body `fake gem NAME VERSION PLATFORM`.
const FAKE_GEM_OK: &str = r#"#!/bin/sh
{ printf 'argv:'; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'; } >> fake-gem-argv.log
env | sort > fake-gem-env.txt
pwd > fake-gem-cwd.txt
ls -A "$HOME" > fake-gem-home.txt
for f in Gemfile Gemfile.lock gems.rb gems.locked .gemrc .bundle; do
  if [ -e "./$f" ]; then echo "cwd/$f" >> fake-gem-saw.txt; fi
  if [ -e "$HOME/$f" ]; then echo "home/$f" >> fake-gem-saw.txt; fi
done
shift
name=$1; shift
version=; platform=ruby
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=$2; shift 2 ;;
    --platform) platform=$2; shift 2 ;;
    --source) shift 2 ;;
    *) shift ;;
  esac
done
if [ "$platform" = ruby ]; then file="$name-$version.gem"; else file="$name-$version-$platform.gem"; fi
printf 'fake gem %s %s %s\n' "$name" "$version" "$platform" > "$file"
"#;

/// A FAKE `gem` that exits 0 and writes nothing: a gem the lockfile names that never arrives.
const FAKE_GEM_SKIPS: &str = "#!/bin/sh\nexit 0\n";

/// A FAKE `gem` that fails the way a missing gem does.
const FAKE_GEM_FAILS: &str = r#"#!/bin/sh
echo "WARNING:  something unrelated" >&2
echo "ERROR:  Could not find a valid gem 'fake-gem' (= 1.0.0) in any repository" >&2
exit 2
"#;

/// A FAKE `gem` that must not be called: a run that reaches it is a cache miss, or a tree that
/// should not have been fetched at all.
const FAKE_GEM_MUST_NOT_RUN: &str = r#"#!/bin/sh
echo "ERROR:  the fake gem was called although nothing should have been fetched" >&2
exit 1
"#;

/// A FAKE `bundle` that succeeds. It records into `$BUNDLE_PATH` (a writable directory of the
/// verifier's): `fake-bundle-argv.log` (one line per call), `fake-bundle-env.txt`,
/// `fake-bundle-cwd.txt`, `fake-bundle-cache-list.txt` (what `vendor/cache` held) and
/// `installed.txt` (the `.gem` files it "installed").
const FAKE_BUNDLE_OK: &str = r#"#!/bin/sh
mkdir -p "$BUNDLE_PATH" || exit 1
{ printf 'argv:'; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'; } >> "$BUNDLE_PATH/fake-bundle-argv.log"
env | sort > "$BUNDLE_PATH/fake-bundle-env.txt"
pwd > "$BUNDLE_PATH/fake-bundle-cwd.txt"
ls vendor/cache > "$BUNDLE_PATH/fake-bundle-cache-list.txt" || exit 3
: > "$BUNDLE_PATH/installed.txt"
for g in vendor/cache/*.gem; do basename "$g" >> "$BUNDLE_PATH/installed.txt"; done
exit 0
"#;

/// A FAKE `bundle` whose install fails the way a lockfile does that names a gem the entry does
/// not hold: a resolution error of the lane's own, so the lane is refuted (S-8).
const FAKE_BUNDLE_FAILS: &str = r#"#!/bin/sh
echo "Fetching gem metadata from rubygems" >&2
echo "Could not find gem 'fake-gem (= 1.0.0)' in locally installed gems." >&2
exit 7
"#;

/// A FAKE `bundle` that fails in a way nothing ties to the lane (no Bundler resolution error):
/// the verifier cannot tell its own environment from the lane, so it is infrastructure.
const FAKE_BUNDLE_UNKNOWN: &str = r#"#!/bin/sh
echo "something nobody has seen before went wrong" >&2
exit 1
"#;

/// A FAKE `bundle` whose resolution error carries what a hostile `Gemfile` would print first: a
/// screen clear, a cursor move, an OSC 52 clipboard write, and an 8-bit CSI (UTF-8 `C2 9B`).
const FAKE_BUNDLE_HOSTILE: &str = r#"#!/bin/sh
printf 'Could not find gem \033[2J\033[1;1Hverify: reproduced \033]52;c;ZXZpbA==\007 \302\233 31m\n' >&2
exit 7
"#;

fn sha256(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

/// A lockfile of one `GEM` section at `remote` with `specs` (lines, already indented) and the
/// `CHECKSUMS` lines `checksums` (empty: no such section).
fn lockfile(remote: &str, specs: &str, checksums: &str) -> String {
    let checks = if checksums.is_empty() {
        String::new()
    } else {
        format!("\nCHECKSUMS\n{checksums}")
    };
    format!(
        "GEM\n  remote: {remote}\n  specs:\n{specs}\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  fake-gem (= 1.0.0)\n{checks}\nBUNDLED WITH\n   2.5.3\n"
    )
}

const ONE_GEM: &str = "    fake-gem (1.0.0)\n";

/// The plain project: a Gemfile that raises if evaluated, and a lockfile of `fake-gem` 1.0.0
/// from rubygems.org.
fn bundler_project() -> Vec<(&'static str, String)> {
    vec![
        ("Gemfile", GEMFILE.to_string()),
        (
            "Gemfile.lock",
            lockfile("https://rubygems.org/", ONE_GEM, ""),
        ),
    ]
}

fn as_files<'a>(files: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    files.iter().map(|(n, c)| (*n, c.as_str())).collect()
}

/// A lane over `files` whose builder runs the no-op check `ok`, with its own cache root, no
/// fetch network, the fake `gem` at `gem` and the fake `bundle` at `bundle`.
fn new_lane(files: &[(&'static str, String)], cache: &Path, gem: &Path, bundle: &Path) -> Lane {
    let mut lane = Lane::new(
        &run_checks(&["ok"]),
        json!([{"id": "ok", "command": "true"}]),
    );
    lane.commit_files(&as_files(files));
    lane.set_env("COWPROOF_CACHE_ROOT", cache);
    lane.set_env("COWPROOF_FETCH_NETWORK", "none");
    lane.set_env("COWPROOF_GEM", gem);
    lane.set_env("COWPROOF_BUNDLE", bundle);
    lane
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The directory the verifier's `bundle install --local` records into after a `cowproof run`.
fn verifier_install(lane: &Lane) -> PathBuf {
    lane.lane_dir().join("scratch/verify/cache/bundler/install")
}

/// The check that proves the verifier has the gems and that the step ran.
const NEEDS_GEMS: &str = "test -f vendor/cache/fake-gem-1.0.0.gem \
     && grep -qx fake-gem-1.0.0.gem \"$BUNDLE_PATH/installed.txt\"";

#[test]
fn a_bundler_lane_gets_its_gem_files_and_is_proved() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    let out = run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("{}: proved", lane.id)),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "proved");

    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(c.dependency_ecosystems, vec!["bundler".to_string()]);
    let e = entry(cache.path(), &c);
    assert_eq!(read(&e.join("bundler/cache/fake-gem-1.0.0.gem")), GEM_BODY);
    assert!(
        !e.join("cargo").exists() && !e.join("npm").exists(),
        "a Ruby tree gets no other part"
    );
    assert_eq!(
        fs::read_dir(cache.path().join("deps-work"))
            .unwrap()
            .count(),
        0,
        "the work directory is removed"
    );
    // The step is recorded as a dependency note, in the sealed capsule.
    assert!(
        c.dependency_fetch_notes.iter().any(|n| n.contains(
            "`bundle install --local` ran in the verifier before the checks and succeeded"
        )),
        "{:?}",
        c.dependency_fetch_notes
    );
    let json = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(json.contains("\"bundler\""), "{json}");

    // `bundle install --local` ran ONCE for two verifier checks (`ok` and `held`), with
    // `--no-cache` so it cannot write into the read-only entry, in the tree.
    let log = read(&verifier_install(&lane).join("fake-bundle-argv.log"));
    assert_eq!(log, "argv: install --local --no-cache\n");
    assert!(
        read(&verifier_install(&lane).join("fake-bundle-cwd.txt"))
            .trim_end()
            .ends_with("/verify/tree"),
        "the step runs in the verifier's tree"
    );
}

#[test]
fn the_fetch_runs_gem_fetch_with_clear_sources_and_reads_no_gemfile() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);

    let c = capsule(&lane);
    let recorded = entry(cache.path(), &c).join("bundler/cache");
    assert_eq!(
        read(&recorded.join("fake-gem-argv.log")),
        "argv: fetch fake-gem --version 1.0.0 --platform ruby --clear-sources --source https://rubygems.org/\n"
    );
    // No Gemfile, lockfile or Ruby configuration was in reach of the fetch, and the Gemfile
    // that raises when evaluated was never evaluated (the lane would not have been proved).
    assert!(
        !recorded.join("fake-gem-saw.txt").exists(),
        "{}",
        read(&recorded.join("fake-gem-saw.txt"))
    );
    let env = read(&recorded.join("fake-gem-env.txt"));
    // A throwaway HOME, GEM_HOME and GEM_SPEC_CACHE, outside the entry, and nothing inherited.
    for var in ["HOME", "GEM_HOME", "GEM_PATH", "GEM_SPEC_CACHE"] {
        let value = env
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{var}=")))
            .unwrap_or_else(|| panic!("no {var} in:\n{env}"));
        assert!(
            value.contains("/deps-work/") && !value.contains("/deps/"),
            "{var}={value}"
        );
    }
    assert!(!env.contains("sk-test-real-xyz"), "{env}");
    assert!(!env.contains("ANTHROPIC"), "{env}");
    assert!(
        !env.contains("BUNDLE_"),
        "no Bundler setting reaches the fetch: {env}"
    );
    let cwd = read(&recorded.join("fake-gem-cwd.txt"));
    assert!(cwd.trim_end().ends_with("/bundler/cache"), "{cwd}");
    assert_eq!(
        read(&recorded.join("fake-gem-home.txt")),
        "",
        "an empty HOME"
    );
}

#[test]
fn only_ruby_and_the_hosts_platform_variants_are_downloaded() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let specs = "    fake-gem (1.0.0)\n    fake-gem (1.0.0-arm64-darwin)\n    fake-gem (1.0.0-x86_64-linux)\n    fake-gem (1.0.0-java)\n    other (2.0.0)\n";
    let files = vec![
        ("Gemfile", GEMFILE.to_string()),
        ("Gemfile.lock", lockfile("https://rubygems.org/", specs, "")),
    ];
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), "true"), 0);

    let c = capsule(&lane);
    let recorded = entry(cache.path(), &c).join("bundler/cache");
    let mut gems: Vec<String> = fs::read_dir(&recorded)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".gem"))
        .collect();
    gems.sort();
    let host = Host::current();
    let mut expect = vec![
        "fake-gem-1.0.0.gem".to_string(),
        "other-2.0.0.gem".to_string(),
    ];
    for platform in ["arm64-darwin", "x86_64-linux"] {
        if host.matches(platform) {
            expect.push(format!("fake-gem-1.0.0-{platform}.gem"));
        }
    }
    expect.sort();
    assert_eq!(gems, expect, "host {}", host.describe());
    assert!(
        !gems.iter().any(|g| g.contains("java")),
        "a platform that is not the host's is not downloaded: {gems:?}"
    );
    let argv = read(&recorded.join("fake-gem-argv.log"));
    assert_eq!(argv.lines().count(), expect.len(), "{argv}");
    assert!(
        argv.lines().all(|l| l.contains(" --clear-sources ")),
        "{argv}"
    );
}

#[test]
fn a_git_source_is_not_fetched_and_the_capsule_names_it() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    // The fake gem fails if it is called: nothing is fetched for a tree with a GIT section.
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let git = format!(
        "GIT\n  remote: https://git.example/x.git\n  revision: abc123\n  specs:\n    x (1.0)\n\n{}",
        lockfile("https://rubygems.org/", ONE_GEM, "")
    );
    let files = vec![("Gemfile", GEMFILE.to_string()), ("Gemfile.lock", git)];
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("not_fetched"));
    assert!(c.dependency_ecosystems.is_empty());
    assert!(c.dependency_cache_key.is_none(), "no entry, so no key");
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.starts_with("Gemfile.lock: a GIT section")),
        "{:?}",
        c.dependency_fetch_notes
    );
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none(),
        "no entry was made"
    );
}

#[test]
fn a_lockfile_that_does_not_parse_and_http_without_checksums_are_not_fetched_with_the_cause() {
    if !sandbox_available() {
        return;
    }
    for (lock, expect) in [
        (
            "<<<<<<< HEAD\nGEM\n=======\n>>>>>>> branch\n".to_string(),
            "does not parse as a Bundler lockfile",
        ),
        (
            lockfile("http://gems.example/", ONE_GEM, ""),
            "comes from a remote that is not https and the file has no CHECKSUMS section",
        ),
    ] {
        let cache = var_tmp("cp-gem-cache-");
        let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
        let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
        let files = vec![("Gemfile", GEMFILE.to_string()), ("Gemfile.lock", lock)];
        let lane = new_lane(&files, cache.path(), &gem, &bundle);
        let out = lane.run(&[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let c = capsule(&lane);
        assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("not_fetched"));
        assert!(
            c.dependency_fetch_notes.iter().any(|n| n.contains(expect)),
            "{expect}: {:?}",
            c.dependency_fetch_notes
        );
    }
}

#[test]
fn a_tree_with_its_own_vendor_cache_is_not_fetched() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let mut files = bundler_project();
    files.push(("vendor/cache/fake-gem-1.0.0.gem", GEM_BODY.to_string()));
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("not_fetched"));
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("already has a vendor/cache")),
        "{:?}",
        c.dependency_fetch_notes
    );
}

#[test]
fn the_checksums_section_is_compared_with_the_download_and_a_mismatch_is_infrastructure() {
    if !sandbox_available() {
        return;
    }
    // A matching checksum: proved.
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let good = format!("  fake-gem (1.0.0) sha256={}\n", sha256(GEM_BODY));
    let files = vec![
        ("Gemfile", GEMFILE.to_string()),
        (
            "Gemfile.lock",
            lockfile("https://rubygems.org/", ONE_GEM, &good),
        ),
    ];
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    assert_eq!(lane.verdict()["verdict"], "proved");

    // A checksum that is not the download's: exit 4, naming the gem, with no entry left.
    let cache = var_tmp("cp-gem-cache-");
    let wrong = format!("  fake-gem (1.0.0) sha256={}\n", sha256("something else\n"));
    let files = vec![
        ("Gemfile", GEMFILE.to_string()),
        (
            "Gemfile.lock",
            lockfile("https://rubygems.org/", ONE_GEM, &wrong),
        ),
    ];
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains(&format!("{}: infrastructure: ", lane.id))
            && stdout.contains("dependency fetch failed: ")
            && stdout.contains("checksum mismatch for fake-gem (1.0.0)")
            && stdout.contains(&sha256(GEM_BODY)),
        "{}",
        text(&out)
    );
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "infrastructure", "{verdict}");
    assert_eq!(verdict["exitCode"], 4);
    assert_eq!(verdict["failedChecks"], json!([]));
    assert_eq!(verdict["diverged"], json!([]));
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("failed"));
    assert!(c.dependency_ecosystems.is_empty());
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none(),
        "a download that fails its checksum is never installed"
    );
}

/// A lane whose BASE has `base` as its files and whose builder rewrites `Gemfile.lock` to
/// `lane_lock` before its check (so the lane's patch is exactly that rewrite).
fn lane_rewriting_lockfile(
    base: &[(&'static str, String)],
    lane_lock: &str,
    cache: &Path,
    gem: &Path,
    bundle: &Path,
) -> Lane {
    let body = format!(
        "cat > Gemfile.lock <<'COWPROOF_LOCK'\n{lane_lock}COWPROOF_LOCK\n{}",
        run_checks(&["ok"])
    );
    let project = var_tmp("cp-gem-proj-");
    for (rel, content) in base {
        fs::write(project.path().join(rel), content).unwrap();
    }
    let packet = |id: &str| {
        format!(
            "# Task\n\n<!-- lane {} -->\n\nChange the lockfile.\n",
            json!({
                "id": id,
                "owns": ["Gemfile.lock"],
                "class": "light",
                "checks": [{"id": "ok", "command": "true"}],
            })
        )
    };
    let mut lane = Lane::from_project(&body, project.path(), &packet);
    lane.set_env("COWPROOF_CACHE_ROOT", cache);
    lane.set_env("COWPROOF_FETCH_NETWORK", "none");
    lane.set_env("COWPROOF_GEM", gem);
    lane.set_env("COWPROOF_BUNDLE", bundle);
    lane
}

#[test]
fn a_lane_that_drops_checksums_is_still_held_to_the_bases_checksum() {
    if !sandbox_available() {
        return;
    }
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let real = format!("  fake-gem (1.0.0) sha256={}\n", sha256(GEM_BODY));
    let tampered = format!("  fake-gem (1.0.0) sha256={}\n", sha256("the real gem\n"));
    let remote = "https://rubygems.org/";

    // Control: the base's checksum is the download's and the lane drops CHECKSUMS: proved,
    // and nothing is unverified because the base verifies it.
    let cache = var_tmp("cp-gem-cache-");
    let base = vec![
        ("Gemfile", GEMFILE.to_string()),
        ("Gemfile.lock", lockfile(remote, ONE_GEM, &real)),
    ];
    let lane = lane_rewriting_lockfile(
        &base,
        &lockfile(remote, ONE_GEM, ""),
        cache.path(),
        &gem,
        &bundle,
    );
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    assert_eq!(lane.verdict()["verdict"], "proved");
    let c = capsule(&lane);
    assert!(
        !c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("unverified")),
        "{:?}",
        c.dependency_fetch_notes
    );

    // The base's checksum is not the download's (the "real" gem is another file): the lane
    // drops CHECKSUMS, and the download is still refused, as infrastructure.
    let cache = var_tmp("cp-gem-cache-");
    let base = vec![
        ("Gemfile", GEMFILE.to_string()),
        ("Gemfile.lock", lockfile(remote, ONE_GEM, &tampered)),
    ];
    let lane = lane_rewriting_lockfile(
        &base,
        &lockfile(remote, ONE_GEM, ""),
        cache.path(),
        &gem,
        &bundle,
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("dependency fetch failed: ")
            && stdout.contains("checksum mismatch for fake-gem (1.0.0)")
            && stdout.contains("the base's lockfile lists sha256")
            && stdout.contains(&sha256("the real gem\n"))
            && stdout.contains(&sha256(GEM_BODY)),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "infrastructure");
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none(),
        "a download that fails the base's checksum is never installed"
    );

    // The lane writes the DOWNLOAD's checksum into its own lockfile: the base's still wins.
    let cache = var_tmp("cp-gem-cache-");
    let lane = lane_rewriting_lockfile(
        &base,
        &lockfile(remote, ONE_GEM, &real),
        cache.path(),
        &gem,
        &bundle,
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("the base's lockfile lists sha256"),
        "{}",
        text(&out)
    );
}

/// A cache hit is checked again against THIS run's base. The key holds the lane's lockfile and
/// not the base's, so an entry fetched under a base that pinned nothing is hit under a base
/// that pins another sha256 for the same gem; the hit must not stand.
#[test]
fn a_cache_hit_is_checked_against_the_current_bases_checksums() {
    if !sandbox_available() {
        return;
    }
    let remote = "https://rubygems.org/";
    let (_ok_dir, gem_ok) = fake_tool("gem", FAKE_GEM_OK);
    let (_no_dir, gem_must_not_run) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let cache = var_tmp("cp-gem-cache-");
    // Every lane writes this lockfile, so every lane has the one cache key.
    let lane_lock = lockfile(remote, ONE_GEM, "");
    let base_with = |sums: &str| {
        vec![
            ("Gemfile", GEMFILE.to_string()),
            // Another `BUNDLED WITH`, so the lane's rewrite is a real patch.
            (
                "Gemfile.lock",
                lockfile(remote, ONE_GEM, sums).replace("2.5.3", "2.5.2"),
            ),
        ]
    };
    let held = var_tmp("cp-gem-held-");

    // Base A pins nothing: the gem is fetched and the entry installed.
    let first = lane_rewriting_lockfile(&base_with(""), &lane_lock, cache.path(), &gem_ok, &bundle);
    run_with(&first, &heldout(held.path(), NEEDS_GEMS), 0);
    let a = capsule(&first);
    assert_eq!(a.dependency_fetch_outcome.as_deref(), Some("fetched"));

    // Base B pins another sha256 for the same gem. The entry is hit (same key), the gem is not
    // fetched again, and the hit is infrastructure naming the gem and both hashes.
    let wrong = sha256("another file altogether\n");
    let pinned = format!("  fake-gem (1.0.0) sha256={wrong}\n");
    let second = lane_rewriting_lockfile(
        &base_with(&pinned),
        &lane_lock,
        cache.path(),
        &gem_must_not_run,
        &bundle,
    );
    let out = second.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("dependency fetch failed: ")
            && stdout.contains("checksum mismatch for fake-gem (1.0.0)")
            && stdout.contains("the base's lockfile lists sha256")
            && stdout.contains(&wrong)
            && stdout.contains(&sha256(GEM_BODY)),
        "{}",
        text(&out)
    );
    assert_eq!(second.verdict()["verdict"], "infrastructure");
    let b = capsule(&second);
    assert_eq!(b.dependency_fetch_outcome.as_deref(), Some("failed"));
    assert_eq!(b.dependency_cache_key, a.dependency_cache_key);
    assert_eq!(
        fs::read_dir(cache.path().join("deps")).unwrap().count(),
        1,
        "the entry is left for the director to prune, and nothing is fetched into a second one"
    );

    // Base C pins the right sha256: the same entry is a hit and the lane is proved.
    let right = format!("  fake-gem (1.0.0) sha256={}\n", sha256(GEM_BODY));
    let third = lane_rewriting_lockfile(
        &base_with(&right),
        &lane_lock,
        cache.path(),
        &gem_must_not_run,
        &bundle,
    );
    run_with(&third, &heldout(held.path(), NEEDS_GEMS), 0);
    assert_eq!(third.verdict()["verdict"], "proved");
    let c = capsule(&third);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("hit"));
    assert_eq!(c.dependency_cache_key, a.dependency_cache_key);
}

/// A hit on an entry that lost a gem is not a hit. The gem has no checksum anywhere, so the
/// hash comparison cannot be what catches it: the entry must hold every gem the plan lists.
#[test]
fn a_cache_hit_on_an_entry_missing_a_gem_is_infrastructure_and_nothing_is_fetched() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_ok_dir, gem_ok) = fake_tool("gem", FAKE_GEM_OK);
    let (_no_dir, gem_must_not_run) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let held = var_tmp("cp-gem-held-");

    // The first lane fetches the entry (`bundler_project` has no CHECKSUMS section).
    let first = new_lane(&bundler_project(), cache.path(), &gem_ok, &bundle);
    run_with(&first, &heldout(held.path(), NEEDS_GEMS), 0);
    let a = capsule(&first);
    assert_eq!(a.dependency_fetch_outcome.as_deref(), Some("fetched"));
    let gem_file = entry(cache.path(), &a).join("bundler/cache/fake-gem-1.0.0.gem");
    assert!(gem_file.is_file(), "the entry holds the gem before");
    fs::remove_file(&gem_file).unwrap();

    // The second lane has the same key. The entry is complete as a directory, but it lost the
    // gem: infrastructure naming the gem, and the fake `gem` is not run.
    let second = new_lane(&bundler_project(), cache.path(), &gem_must_not_run, &bundle);
    let out = second.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("dependency fetch failed: ")
            && stdout.contains("the cache entry does not hold fake-gem-1.0.0.gem")
            && stdout.contains("fake-gem (1.0.0)"),
        "{}",
        text(&out)
    );
    assert!(
        !stdout.contains("the fake gem was called"),
        "the fake gem ran: {}",
        text(&out)
    );
    assert_eq!(second.verdict()["verdict"], "infrastructure");
    let b = capsule(&second);
    assert_eq!(b.dependency_fetch_outcome.as_deref(), Some("failed"));
    assert_eq!(b.dependency_cache_key, a.dependency_cache_key);
    assert!(
        !gem_file.exists(),
        "nothing was fetched back into the entry"
    );
}

#[test]
fn a_base_gem_the_lane_moves_to_another_remote_is_not_fetched_naming_both_remotes() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    // The fake gem fails if it is called: nothing is fetched for a moved gem.
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let base = vec![
        ("Gemfile", GEMFILE.to_string()),
        (
            "Gemfile.lock",
            lockfile("https://gems.corp.example/", ONE_GEM, ""),
        ),
    ];
    let lane = lane_rewriting_lockfile(
        &base,
        &lockfile("https://rubygems.org/", ONE_GEM, ""),
        cache.path(),
        &gem,
        &bundle,
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("not_fetched"));
    assert!(c.dependency_ecosystems.is_empty());
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("fake-gem (1.0.0)")
                && n.contains("https://rubygems.org/")
                && n.contains("https://gems.corp.example/")
                && n.contains("moved gem")),
        "{:?}",
        c.dependency_fetch_notes
    );
}

#[test]
fn a_new_gem_with_no_checksum_is_fetched_and_listed_as_unverified() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let remote = "https://rubygems.org/";
    let real = format!("  fake-gem (1.0.0) sha256={}\n", sha256(GEM_BODY));
    let base = vec![
        ("Gemfile", GEMFILE.to_string()),
        ("Gemfile.lock", lockfile(remote, ONE_GEM, &real)),
    ];
    let specs = "    fake-gem (1.0.0)\n    new-gem (2.0.0)\n";
    let lane = lane_rewriting_lockfile(
        &base,
        &lockfile(remote, specs, &real),
        cache.path(),
        &gem,
        &bundle,
    );
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    assert_eq!(lane.verdict()["verdict"], "proved");
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    let e = entry(cache.path(), &c);
    assert!(e.join("bundler/cache/new-gem-2.0.0.gem").is_file());
    let notes: Vec<&String> = c
        .dependency_fetch_notes
        .iter()
        .filter(|n| n.contains("unverified"))
        .collect();
    assert_eq!(notes.len(), 1, "{:?}", c.dependency_fetch_notes);
    assert!(
        notes[0].contains("unverified: new-gem 2.0.0") && !notes[0].contains("fake-gem"),
        "{}",
        notes[0]
    );
}

#[test]
fn a_gem_the_lockfile_names_that_gem_fetch_did_not_produce_is_infrastructure() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_SKIPS);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("dependency fetch failed: ")
            && stdout.contains("gem fetch did not produce fake-gem-1.0.0.gem for fake-gem (1.0.0)"),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "infrastructure");
    assert!(
        fs::read_dir(cache.path().join("deps"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_failing_gem_fetch_is_infrastructure_naming_its_first_error_line() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_FAILS);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("gem fetch failed")
            && stdout.contains("ERROR:  Could not find a valid gem 'fake-gem' (= 1.0.0)")
            && !stdout.contains("something unrelated"),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "infrastructure");
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
fn a_remote_credential_reaches_neither_gem_nor_the_entry_and_the_capsule_counts_it() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let files = vec![
        ("Gemfile", GEMFILE.to_string()),
        (
            "Gemfile.lock",
            lockfile(&format!("https://user:{SECRET}@rubygems.org/"), ONE_GEM, ""),
        ),
    ];
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    // The remote reached `gem fetch` without its user:pass@.
    assert_eq!(
        read(&e.join("bundler/cache/fake-gem-argv.log")),
        "argv: fetch fake-gem --version 1.0.0 --platform ruby --clear-sources --source https://rubygems.org/\n"
    );
    for file in files_under(&e) {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(SECRET),
            "{} holds the credential",
            file.display()
        );
    }
    assert!(
        c.dependency_fetch_notes
            .iter()
            .any(|n| n.contains("bundler: 1 remote URL(s) of Gemfile.lock carried credentials")),
        "{:?}",
        c.dependency_fetch_notes
    );
    let json = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(!json.contains(SECRET));
}

#[test]
fn a_bundle_config_and_a_gemrc_with_tokens_are_not_visible_to_the_fetch() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let mut files = bundler_project();
    files.push((
        ".bundle/config",
        format!("---\nBUNDLE_GEMS__CORP__EXAMPLE: \"deploy:{SECRET}\"\nBUNDLE_MIRROR__ALL: \"https://evil.example/\"\n"),
    ));
    files.push((
        ".gemrc",
        format!(":sources:\n- https://user:{SECRET}@gems.corp.example/\n"),
    ));
    let lane = new_lane(&files, cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    let recorded = e.join("bundler/cache");
    // The fake looked in its directory and its HOME: neither file, nor the lockfile, nor the
    // Gemfile, was there; and the sources it was given are `--clear-sources` plus the lockfile's.
    assert!(
        !recorded.join("fake-gem-saw.txt").exists(),
        "{}",
        read(&recorded.join("fake-gem-saw.txt"))
    );
    assert_eq!(read(&recorded.join("fake-gem-home.txt")), "");
    let argv = read(&recorded.join("fake-gem-argv.log"));
    assert!(
        argv.contains(" --clear-sources --source https://rubygems.org/")
            && !argv.contains("corp.example")
            && !argv.contains("evil.example"),
        "{argv}"
    );
    let env = read(&recorded.join("fake-gem-env.txt"));
    assert!(!env.contains(SECRET) && !env.contains("BUNDLE_"), "{env}");
    for file in files_under(&e) {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(SECRET),
            "{} holds the token",
            file.display()
        );
    }
    // Nor does the VERIFIER's Bundler read the tree's configuration: it is told to ignore it.
    let venv = read(&verifier_install(&lane).join("fake-bundle-env.txt"));
    for want in [
        "BUNDLE_IGNORE_CONFIG=true",
        "BUNDLE_FROZEN=true",
        "BUNDLE_DISABLE_SHARED_GEMS=true",
    ] {
        assert!(venv.lines().any(|l| l == want), "{want} missing:\n{venv}");
    }
    assert!(!venv.contains(SECRET), "{venv}");
}

#[test]
fn a_failing_bundle_install_ends_the_lane_refuted_naming_the_step_and_its_first_error() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_FAILS);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    let out = run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 2);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("refuted")
            && stdout.contains("`bundle install --local` failed (exit 7)")
            && stdout
                .contains("Could not find gem 'fake-gem (= 1.0.0)' in locally installed gems."),
        "{}",
        text(&out)
    );
    assert!(
        !stdout.contains("Fetching gem metadata"),
        "the first error line is named, not the first line: {stdout}"
    );
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["exitCode"], 2);
    // The fetch itself was fine: the entry exists, and the capsule records the failed step.
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert!(
        c.dependency_fetch_notes.iter().any(|n| n.starts_with(
            "bundler: the verifier's step failed: `bundle install --local` failed (exit 7)"
        )),
        "{:?}",
        c.dependency_fetch_notes
    );
}

#[test]
fn a_second_lane_with_the_same_lockfile_hits_the_cache_and_does_not_call_gem() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_first_dir, first_gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let first = new_lane(&bundler_project(), cache.path(), &first_gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    let heldout = heldout(held.path(), NEEDS_GEMS);
    run_with(&first, &heldout, 0);
    let a = capsule(&first);
    let recorded = entry(cache.path(), &a).join("bundler/cache/fake-gem-argv.log");
    let before = read(&recorded);

    // The second lane's `gem` fails if it is run at all; its `bundle` still runs in ITS
    // verifier (the install is per lane, the gems are the entry's).
    let (_second_dir, second_gem) = fake_tool("gem", FAKE_GEM_MUST_NOT_RUN);
    let second = new_lane(&bundler_project(), cache.path(), &second_gem, &bundle);
    run_with(&second, &heldout, 0);
    let b = capsule(&second);
    assert_eq!(a.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(b.dependency_fetch_outcome.as_deref(), Some("hit"));
    assert_eq!(b.dependency_ecosystems, vec!["bundler".to_string()]);
    assert_eq!(a.dependency_cache_key, b.dependency_cache_key);
    assert_eq!(read(&recorded), before);
    assert_eq!(fs::read_dir(cache.path().join("deps")).unwrap().count(), 1);
    assert_eq!(
        read(&verifier_install(&second).join("fake-bundle-argv.log")),
        "argv: install --local --no-cache\n"
    );

    // Another lockfile is another key: the fake runs again.
    let (_third_dir, third_gem) = fake_tool("gem", FAKE_GEM_OK);
    let mut changed = bundler_project();
    changed[1].1 = lockfile("https://rubygems.org/", ONE_GEM, "").replace("2.5.3", "2.5.4");
    let third = new_lane(&changed, cache.path(), &third_gem, &bundle);
    run_with(&third, &heldout, 0);
    let c = capsule(&third);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_ne!(a.dependency_cache_key, c.dependency_cache_key);
}

#[test]
fn the_verifier_sees_vendor_cache_as_a_read_only_link_to_the_entry() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    // The check passes only if EVERY write is refused: a new file, a change to a gem, a new
    // gem and a removal. And the install path is the verifier's own writable scratch.
    let check = "test -L vendor/cache \
         && test -f vendor/cache/fake-gem-1.0.0.gem \
         && ! touch vendor/cache/probe 2>/dev/null \
         && ! (echo hacked > vendor/cache/fake-gem-1.0.0.gem) 2>/dev/null \
         && ! (echo evil > vendor/cache/evil-1.0.gem) 2>/dev/null \
         && ! rm vendor/cache/fake-gem-1.0.0.gem 2>/dev/null \
         && case \"$BUNDLE_PATH\" in */verify/cache/bundler/install) true ;; *) false ;; esac \
         && touch \"$BUNDLE_PATH/probe\" \
         && test \"$BUNDLE_FROZEN\" = true \
         && test \"$BUNDLE_IGNORE_CONFIG\" = true \
         && test \"$BUNDLE_DISABLE_SHARED_GEMS\" = true";
    run_with(&lane, &heldout(held.path(), check), 0);
    assert_eq!(lane.verdict()["verdict"], "proved");

    let c = capsule(&lane);
    let e = entry(cache.path(), &c);
    assert_eq!(
        read(&e.join("bundler/cache/fake-gem-1.0.0.gem")),
        GEM_BODY,
        "the entry's gem is untouched"
    );
    assert!(!e.join("bundler/cache/probe").exists());
    assert!(!e.join("bundler/cache/evil-1.0.gem").exists());
}

#[test]
fn verify_on_another_cache_root_fetches_the_gems_again_and_reproduces() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    let key = capsule(&lane).dependency_cache_key.unwrap();

    let fresh = var_tmp("cp-gem-fresh-");
    let clone = fresh.path().join("repo");
    let cloned = output(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&lane.repo)
            .arg(&clone),
    );
    assert!(cloned.status.success(), "{}", text(&cloned));
    let other_cache = var_tmp("cp-gem-other-");
    let workdir = var_tmp("cp-gem-wd-");
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
            .join("bundler/cache/fake-gem-1.0.0.gem")
            .is_file(),
        "verify fetched the capsule's key into its own cache root"
    );

    // A verify whose `bundle install --local` fails diverges, naming the step.
    let (_bad_dir, bad_bundle) = fake_tool("bundle", FAKE_BUNDLE_FAILS);
    let third_cache = var_tmp("cp-gem-third-");
    let workdir = var_tmp("cp-gem-wd2-");
    let out = output(
        lane.cowproof_cmd()
            .env("COWPROOF_CACHE_ROOT", third_cache.path())
            .env("COWPROOF_FETCH_NETWORK", "none")
            .env("COWPROOF_BUNDLE", &bad_bundle)
            .current_dir(fresh.path())
            .arg("verify")
            .arg(lane.capsule_dir())
            .arg("--repo")
            .arg(&clone)
            .arg("--workdir")
            .arg(workdir.path()),
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.starts_with("diverged: check \"ok\"")
            && stdout.contains("setup: `bundle install --local` failed (exit 7): Could not find gem 'fake-gem (= 1.0.0)'"),
        "{}",
        text(&out)
    );

    // And a verify whose `gem` fails is infrastructure, not a divergence.
    let (_badgem_dir, bad_gem) = fake_tool("gem", FAKE_GEM_FAILS);
    let fourth_cache = var_tmp("cp-gem-fourth-");
    let workdir = var_tmp("cp-gem-wd3-");
    let out = output(
        lane.cowproof_cmd()
            .env("COWPROOF_CACHE_ROOT", fourth_cache.path())
            .env("COWPROOF_FETCH_NETWORK", "none")
            .env("COWPROOF_GEM", &bad_gem)
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
            && err.contains("gem fetch failed")
            && err.contains("ERROR:  Could not find a valid gem"),
        "{err}"
    );
}

/// What the fake RubyGems server says to whoever the proxy tunnels to it.
const BANNER: &str = "RUBYGEMS-BANNER";

/// A fake server on `127.0.0.1` that greets every connection and counts them.
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

/// A fake `gem` that asks the proxy `https_proxy` names for a tunnel to `host:443` and, if it
/// gets one, records what the server at the other end says into its directory (the entry's gem
/// cache), then writes the gem.
fn tunnelling_gem(host: &str) -> String {
    format!(
        r#"#!/bin/bash
case "$https_proxy" in http://127.0.0.1:*) ;; *) echo "ERROR:  https_proxy=$https_proxy" >&2; exit 6 ;; esac
[ "$HTTPS_PROXY" = "$https_proxy" ] && [ "$http_proxy" = "$https_proxy" ] || {{ echo "ERROR:  proxy variables differ" >&2; exit 6; }}
port="${{https_proxy##*:}}"
exec 3<>/dev/tcp/127.0.0.1/$port || exit 7
printf 'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n' >&3
IFS= read -r status <&3
case "$status" in
  *" 200 "*) ;;
  *) echo "ERROR:  the proxy said: $status" >&2; exit 1 ;;
esac
IFS= read -r blank <&3
IFS= read -r banner <&3
printf '%s\n' "$banner" > banner
printf 'fake gem fake-gem 1.0.0 ruby\n' > fake-gem-1.0.0.gem
"#
    )
}

#[test]
fn the_default_network_tunnels_gem_to_rubygems_and_to_no_other_host() {
    if !sandbox_available() {
        return;
    }
    // Allowed: rubygems.org, mapped to a live fake on 127.0.0.1 (no DNS).
    let server = upstream();
    let cache = var_tmp("cp-gem-cache-");
    let (_dir, gem) = fake_tool("gem", &tunnelling_gem("rubygems.org"));
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let mut lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("rubygems.org={}", server.addr),
    );
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(
        read(&entry(cache.path(), &c).join("bundler/cache/banner")),
        format!("{BANNER}\n"),
        "the fetch's bytes came through the tunnel"
    );
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);

    // Refused: the npm and crates.io hosts are for other tools; a gem fetch may not reach them.
    for host in ["registry.npmjs.org", "index.crates.io"] {
        let other = upstream();
        let cache = var_tmp("cp-gem-cache-");
        let (_dir, gem) = fake_tool("gem", &tunnelling_gem(host));
        let mut lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
        lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
        lane.set_env("COWPROOF_FETCH_RESOLVE", format!("{host}={}", other.addr));
        let out = lane.run(&[]);
        assert_eq!(out.status.code(), Some(4), "{}", text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("dependency fetch failed: ")
                && stdout.contains("gem fetch failed")
                && stdout.contains(&format!("refused a connection to {host}:443")),
            "{}",
            text(&out)
        );
        assert_eq!(other.accepted.load(Ordering::SeqCst), 0);
        assert_eq!(lane.verdict()["verdict"], "infrastructure");
    }
}

#[test]
fn a_remote_the_base_lockfile_names_is_reached_and_one_it_does_not_name_is_refused() {
    if !sandbox_available() {
        return;
    }
    let server = upstream();
    let cache = var_tmp("cp-gem-cache-");
    let (_dir, gem) = fake_tool("gem", &tunnelling_gem("gems.corp.example"));
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let files = vec![
        ("Gemfile", GEMFILE.to_string()),
        (
            "Gemfile.lock",
            lockfile("https://gems.corp.example/", ONE_GEM, ""),
        ),
    ];
    let mut lane = new_lane(&files, cache.path(), &gem, &bundle);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("gems.corp.example={}", server.addr),
    );
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);

    // The same fake against a base lockfile that names only rubygems.org: refused.
    let refused = upstream();
    let cache = var_tmp("cp-gem-cache-");
    let (_dir, gem) = fake_tool("gem", &tunnelling_gem("gems.corp.example"));
    let mut lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    lane.set_env("COWPROOF_FETCH_NETWORK", "registry");
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("gems.corp.example={}", refused.addr),
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("refused a connection to gems.corp.example:443"),
        "{}",
        text(&out)
    );
    assert_eq!(refused.accepted.load(Ordering::SeqCst), 0);
}

/// A clone of the lane's repository in its own directory, for a `cowproof verify` away from the
/// lane's checkout.
fn fresh_clone(lane: &Lane) -> (tempfile::TempDir, PathBuf) {
    let fresh = var_tmp("cp-gem-fresh-");
    let clone = fresh.path().join("repo");
    let cloned = output(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&lane.repo)
            .arg(&clone),
    );
    assert!(cloned.status.success(), "{}", text(&cloned));
    (fresh, clone)
}

/// `cowproof verify` of the lane's capsule in a fresh clone, with its own cache root and the
/// `bundle` at `bundle`.
fn verify_with_bundle(lane: &Lane, bundle: &Path) -> std::process::Output {
    let (fresh, clone) = fresh_clone(lane);
    let cache = var_tmp("cp-gem-vcache-");
    let workdir = var_tmp("cp-gem-vwd-");
    output(
        lane.cowproof_cmd()
            .env("COWPROOF_CACHE_ROOT", cache.path())
            .env("COWPROOF_FETCH_NETWORK", "none")
            .env("COWPROOF_BUNDLE", bundle)
            .current_dir(fresh.path())
            .arg("verify")
            .arg(lane.capsule_dir())
            .arg("--repo")
            .arg(&clone)
            .arg("--workdir")
            .arg(workdir.path()),
    )
}

/// S-1 and S-8, the print: what a `Gemfile` writes before Bundler gives up reaches the director's
/// terminal through `cowproof verify`'s `setup:` line, and must arrive as escapes. Only the
/// line's own newline may be a control character in what verify prints.
#[test]
fn verify_prints_a_bundler_setup_failure_with_its_escape_sequences_shown_not_sent() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 0);

    let (_hostile_dir, hostile) = fake_tool("bundle", FAKE_BUNDLE_HOSTILE);
    let out = verify_with_bundle(&lane, &hostile);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    for (name, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let shown = String::from_utf8_lossy(bytes);
        assert!(
            !shown.chars().any(|c| c.is_control() && c != '\n'),
            "{name} holds a control character: {shown:?}"
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let setup = stdout
        .lines()
        .find(|l| l.starts_with("setup: "))
        .unwrap_or_else(|| panic!("no setup line:\n{stdout}"));
    assert!(
        setup.contains("\\u{1b}[2J") && setup.contains("\\u{9b}") && setup.contains("\\u{7}"),
        "{setup}"
    );
}

/// S-8: a `bundle` that fails in a way nothing ties to the lane's lockfile does not refute the
/// lane. `cowproof run` ends `infrastructure` (exit 4) and `cowproof verify` exits 4, each
/// naming the cause, and neither prints a `setup:` line.
#[test]
fn an_unexplained_bundle_failure_is_infrastructure_in_run_and_in_verify() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-gem-cache-");
    let (_gem_dir, gem) = fake_tool("gem", FAKE_GEM_OK);
    let (_bundle_dir, bundle) = fake_tool("bundle", FAKE_BUNDLE_OK);
    let ok_lane = new_lane(&bundler_project(), cache.path(), &gem, &bundle);
    let held = var_tmp("cp-gem-held-");
    run_with(&ok_lane, &heldout(held.path(), NEEDS_GEMS), 0);
    let (_unknown_dir, unknown) = fake_tool("bundle", FAKE_BUNDLE_UNKNOWN);
    let out = verify_with_bundle(&ok_lane, &unknown);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("infrastructure: ")
            && err.contains("`bundle install --local` failed (exit 1)")
            && err.contains("cause is unknown")
            && err.contains("something nobody has seen before went wrong"),
        "{err}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("setup: "),
        "{}",
        text(&out)
    );

    let run_cache = var_tmp("cp-gem-cache-");
    let lane = new_lane(&bundler_project(), run_cache.path(), &gem, &unknown);
    let held = var_tmp("cp-gem-held-");
    let out = run_with(&lane, &heldout(held.path(), NEEDS_GEMS), 4);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("infrastructure") && stdout.contains("cause is unknown"),
        "{}",
        text(&out)
    );
    assert_eq!(lane.verdict()["verdict"], "infrastructure");
}
