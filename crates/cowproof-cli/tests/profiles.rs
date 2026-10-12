//! Packet profiles per rung (D28 clause 5), end to end through the binary: `cowproof lint`
//! reports a strict profile's missing requirement, and `cowproof run` stops on that lint error
//! before any lane directory exists. Lint runs before the preflight, so these tests need no
//! sandbox, no fake builder and no network.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const CONFIG: &str = r#"[ladder]
rungs = ["claude:haiku", "claude:sonnet", "claude:opus"]

[profiles.strict]
require = ["tests", "mutations", "done-checklist"]

[routing.profiles]
"claude:haiku" = "strict"
"#;

const TESTS: &str =
    "\n## Tests\n\n- `a_bad_rung_is_refused` asserts that the run stops before any lane exists.\n";
const MUTATIONS: &str =
    "\n## Mutations\n\n- (a) make the parser accept any rung, then run the tests\n";
const DONE: &str = "\n## Done checklist\n\n1. every test passes\n2. fmt is clean\n";

struct Fixture {
    /// Holds the repository, the packet and the throwaway HOME.
    work: TempDir,
    repo: PathBuf,
    home: PathBuf,
}

fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
}

fn run_cmd(cmd: &mut Command, home: &Path) -> Output {
    cmd.env("HOME", home)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENROUTER_API_KEY")
        .output()
        .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let work = var_tmp("cp-profiles-");
        let repo = work.path().join("repo");
        let home = work.path().join("home");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::write(repo.join("README.md"), "base\n").unwrap();
        fs::write(repo.join("cowproof.toml"), CONFIG).unwrap();
        for args in [
            &["init", "-q"][..],
            &["add", "."],
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@localhost",
                "commit",
                "-q",
                "-m",
                "base",
            ],
        ] {
            let out = run_cmd(Command::new("git").current_dir(&repo).args(args), &home);
            assert!(out.status.success(), "git {args:?}: {out:?}");
        }
        Fixture { work, repo, home }
    }

    /// Write a packet routed to `rung` by its header, with `body` after the header.
    fn packet(&self, name: &str, rung: &str, body: &str) -> PathBuf {
        let path = self.work.path().join(name);
        fs::write(
            &path,
            format!(
                "<!-- lane {{\"id\":\"lane-profile\",\"owns\":[\"README.md\"],\"class\":\"light\",\"rung\":\"{rung}\"}} -->\n{body}"
            ),
        )
        .unwrap();
        path
    }

    fn lint(&self, packet: &Path) -> Output {
        run_cmd(
            Command::new(env!("CARGO_BIN_EXE_cowproof"))
                .arg("lint")
                .arg(packet)
                .arg("--repo")
                .arg(&self.repo),
            &self.home,
        )
    }

    fn run(&self, packet: &Path, lanes_root: &Path) -> Output {
        run_cmd(
            Command::new(env!("CARGO_BIN_EXE_cowproof"))
                .arg("run")
                .arg(packet)
                .arg("--repo")
                .arg(&self.repo)
                .arg("--lanes-root")
                .arg(lanes_root),
            &self.home,
        )
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn run_refuses_a_strict_profile_packet_without_mutations_before_any_lane_exists() {
    let f = Fixture::new();
    let packet = f.packet("packet.md", "claude:haiku", &format!("{TESTS}{DONE}"));
    let lanes_root = f.work.path().join("never-created");
    let out = f.run(&packet, &lanes_root);
    let stderr = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("error [profile]: mutations: "), "{stderr}");
    assert!(stderr.contains("packet lint found errors"), "{stderr}");
    assert!(!stderr.contains("error [profile]: tests"), "{stderr}");
    assert!(!lanes_root.exists(), "no lanes root, so no lane directory");
    // Nothing else was created in the work directory either.
    let mut names: Vec<String> = fs::read_dir(f.work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["home", "packet.md", "repo"]);
}

#[test]
fn run_refuses_a_strict_profile_packet_that_lacks_tests_and_the_done_checklist_too() {
    let f = Fixture::new();
    let packet = f.packet("packet.md", "claude:haiku", MUTATIONS);
    let lanes_root = f.work.path().join("never-created");
    let out = f.run(&packet, &lanes_root);
    let stderr = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("error [profile]: tests: "), "{stderr}");
    assert!(
        stderr.contains("error [profile]: done-checklist: "),
        "{stderr}"
    );
    assert!(!lanes_root.exists());
}

#[test]
fn lint_passes_a_complete_strict_packet_and_a_rung_with_no_profile() {
    let f = Fixture::new();
    let full = f.packet(
        "full.md",
        "claude:haiku",
        &format!("{TESTS}{MUTATIONS}{DONE}"),
    );
    let out = f.lint(&full);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("[profile]"), "{}", stderr(&out));

    // The same bare packet on a rung with no profile is not asked for anything.
    let bare = f.packet("bare.md", "claude:sonnet", "\nChange the README.\n");
    let out = f.lint(&bare);
    assert!(!stderr(&out).contains("[profile]"), "{}", stderr(&out));

    // On the strict rung the bare packet fails, once per requirement.
    let bare = f.packet("bare.md", "claude:haiku", "\nChange the README.\n");
    let out = f.lint(&bare);
    let stderr = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert_eq!(stderr.matches("error [profile]").count(), 3, "{stderr}");
}
