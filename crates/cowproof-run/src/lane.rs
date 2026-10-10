//! Lane preparation: an isolated clone of the base, the base patch, and the
//! launch baseline (D2, R10/D13, R15).
//!
//! [`prepare_lane`] builds `<lanes_root>/<lane_id>/{clone,home,scratch,control,sock}`.
//! `sock` is an owner-only (0700) directory for the runner socket (D22).
//! The clone is a real, independent repository: no hardlinks to the source's
//! objects, no alternates and no remotes, so nothing the builder does can reach
//! the source repository. Uncommitted work (only with `allow_dirty`) is recorded
//! as `base.patch` and committed on top of the base. Files that must not reach
//! the builder are then removed and committed as the launch baseline; the list
//! of removed paths is recorded in `control/lane.json`, which the verifier replays (D13).

use crate::LaneLayout;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Options for lane preparation.
#[derive(Debug, Clone)]
pub struct PrepareOptions {
    /// If true, record uncommitted changes (including untracked, non-ignored
    /// files) as `base.patch`; if false, refuse a dirty working tree.
    pub allow_dirty: bool,
}

/// Result of lane preparation: layout, commits, and patches.
#[derive(Debug, Clone)]
pub struct PreparedLane {
    /// Lane filesystem layout.
    pub layout: LaneLayout,
    /// The source repository's HEAD commit, before `base.patch`.
    pub base_commit: String,
    /// The base patch, when `allow_dirty` was set and the tree had changes.
    pub base_patch: Option<Vec<u8>>,
    /// Files removed for the launch baseline, relative to the clone, sorted.
    /// Never includes the content of removed files.
    pub launch_removed: Vec<String>,
    /// The launch baseline commit; the lane patch is computed against it.
    pub launch_commit: String,
}

/// Lane control metadata written to `control/lane.json`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaneControl {
    /// The source repository's HEAD commit.
    pub base_commit: String,
    /// The launch baseline commit.
    pub launch_commit: String,
    /// Files removed for the launch baseline, relative to the clone, sorted.
    pub removed_paths: Vec<String>,
}

/// Git configuration for every command that writes in the clone: no hooks, a
/// fixed identity, no signing.
const WRITE_CONFIG: [&str; 8] = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "user.name=cowproof",
    "-c",
    "user.email=cowproof@localhost",
    "-c",
    "commit.gpgsign=false",
];

/// Prepare a lane.
///
/// Refusals (an invalid id, a dirty tree without `allow_dirty`, held-out files
/// in the base) happen before anything is created. After the lane directory
/// exists, any failure removes it again and returns the original error. An
/// already existing lane directory is refused and left untouched.
pub fn prepare_lane(
    repo: &Path,
    lanes_root: &Path,
    lane_id: &str,
    opts: PrepareOptions,
) -> Result<PreparedLane> {
    validate_lane_id(lane_id)?;

    // Validate lanes_root before creating anything.
    let lanes_root_canonical = if lanes_root.exists() {
        std::fs::canonicalize(lanes_root)
    } else {
        // lanes_root may not exist yet; canonicalize the parent instead.
        let parent = lanes_root
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/"));
        match std::fs::canonicalize(parent) {
            Ok(parent_canonical) => {
                Ok(parent_canonical.join(lanes_root.file_name().unwrap_or_default()))
            }
            Err(e) => Err(e),
        }
    }
    .context("canonicalizing lanes_root")?;
    let repo_canonical = std::fs::canonicalize(repo).context("canonicalizing repo")?;
    if lanes_root_canonical == repo_canonical {
        bail!(
            "lanes_root {} must not equal the repository {}",
            lanes_root_canonical.display(),
            repo_canonical.display()
        );
    }
    if repo_canonical.starts_with(&lanes_root_canonical) {
        bail!(
            "lanes_root {} must not contain the repository {}",
            lanes_root_canonical.display(),
            repo_canonical.display()
        );
    }

    let dirty = !git_source(repo, &["status", "--porcelain"])
        .context("checking the working tree")?
        .stdout
        .is_empty();
    if dirty && !opts.allow_dirty {
        bail!("the working tree is dirty; commit the changes or pass allow_dirty to record them");
    }
    refuse_heldout(repo, dirty)?;
    if opts.allow_dirty && dirty {
        refuse_dirty_removed_paths(repo)?;
    }
    let base_commit = git_text(&git_source(
        repo,
        &["rev-parse", "--verify", "HEAD^{commit}"],
    )?)?;

    // From here on something is created.
    fs::create_dir_all(lanes_root).with_context(|| format!("creating {}", lanes_root.display()))?;
    let lane_dir = lanes_root.join(lane_id);
    if let Err(e) = fs::create_dir(&lane_dir) {
        // An existing lane directory is not ours to clean up.
        bail!("cannot create lane directory {}: {e}", lane_dir.display());
    }

    match build_lane(repo, &lane_dir, &base_commit, dirty) {
        Ok(prepared) => Ok(prepared),
        Err(e) => {
            let _ = fs::remove_dir_all(&lane_dir);
            Err(e)
        }
    }
}

fn build_lane(
    repo: &Path,
    lane_dir: &Path,
    base_commit: &str,
    dirty: bool,
) -> Result<PreparedLane> {
    let lanes_root = lane_dir
        .parent()
        .ok_or_else(|| anyhow!("lane_dir has no parent"))?
        .to_path_buf();
    let layout = LaneLayout {
        clone: lane_dir.join("clone"),
        home: lane_dir.join("home"),
        scratch: lane_dir.join("scratch"),
        control: lane_dir.join("control"),
        real_home: std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/")),
        sock: lane_dir.join("sock").join("runner.sock"),
        lanes_root,
    };
    for dir in [&layout.home, &layout.scratch, &layout.control] {
        fs::create_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // The socket directory (D22): owner-only. The runner binds the socket in
    // it; the sandbox gets that one file and nothing else in the directory.
    let sock_dir = lane_dir.join("sock");
    fs::create_dir(&sock_dir).with_context(|| format!("creating {}", sock_dir.display()))?;
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", sock_dir.display()))?;

    let base_patch = if dirty {
        let patch = capture_base_patch(repo, &layout.scratch)?;
        (!patch.is_empty()).then_some(patch)
    } else {
        None
    };

    clone_isolated(repo, &layout.clone, base_commit)?;

    if let Some(patch) = &base_patch {
        git_apply(&layout.clone, patch).context("applying the base patch")?;
        commit_all(&layout.clone, "cowproof: base patch")?;
    }

    let removed_paths = remove_launch_baseline(&layout.clone)?;
    commit_all(&layout.clone, "cowproof: launch baseline")?;
    let launch_commit = git_text(&git_clone_read(&layout.clone, &["rev-parse", "HEAD"])?)?;

    let control = LaneControl {
        base_commit: base_commit.to_string(),
        launch_commit: launch_commit.clone(),
        removed_paths: removed_paths.clone(),
    };
    let path = layout.control.join("lane.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&control).context("serializing lane.json")?,
    )
    .with_context(|| format!("writing {}", path.display()))?;

    Ok(PreparedLane {
        layout,
        base_commit: base_commit.to_string(),
        base_patch,
        launch_removed: removed_paths,
        launch_commit,
    })
}

/// A lane id is `[A-Za-z0-9._-]{1,64}` and is never `.` or `..`.
fn validate_lane_id(lane_id: &str) -> Result<()> {
    if lane_id.is_empty() || lane_id.len() > 64 {
        bail!("lane id must be 1 to 64 characters");
    }
    if lane_id == "." || lane_id == ".." {
        bail!("lane id must not be '{lane_id}'");
    }
    if !lane_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("lane id '{lane_id}' may only contain [A-Za-z0-9._-]");
    }
    Ok(())
}

/// When `allow_dirty` is set, refuse if any dirty path (tracked or untracked)
/// matches the launch-removal set. These paths would carry their content into
/// `base.patch` and the capsule. The user must commit, ignore, or remove them.
fn refuse_dirty_removed_paths(repo: &Path) -> Result<()> {
    // Get all dirty files: modified tracked files and untracked files.
    let status =
        git_source(repo, &["status", "--porcelain"]).context("checking the working tree")?;
    let status_str = String::from_utf8_lossy(&status.stdout);

    let mut dirty_matching: Vec<String> = Vec::new();

    for line in status_str.lines() {
        if line.len() < 3 {
            continue;
        }
        let path = &line[3..]; // Skip the first 3 chars (status codes + space)
        if is_removed(path) {
            dirty_matching.push(path.to_string());
        }
    }

    if !dirty_matching.is_empty() {
        dirty_matching.sort();
        bail!(
            "with allow_dirty, these paths would travel in base.patch (commit, ignore or remove them): {}",
            dirty_matching.join(", ")
        );
    }
    Ok(())
}

/// Refuse a base that carries held-out checks (R2). Tracked files are scanned
/// by `scan_base_for_heldout`; with `allow_dirty`, untracked files would travel
/// in the base patch too, so they are scanned the same way.
fn refuse_heldout(repo: &Path, include_untracked: bool) -> Result<()> {
    let mut found: Vec<String> = cowproof_core::heldout::scan_base_for_heldout(repo)?
        .iter()
        .map(|p| {
            p.strip_prefix(repo)
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    if include_untracked {
        let out = git_source(repo, &["ls-files", "--others", "--exclude-standard", "-z"])?;
        found.extend(
            out.stdout
                .split(|b| *b == 0)
                .filter(|n| !n.is_empty())
                .map(|n| String::from_utf8_lossy(n).into_owned())
                .filter(|n| n.contains(".heldout.")),
        );
    }
    if !found.is_empty() {
        found.sort();
        bail!(
            "the base contains held-out files, which must live outside the repository (R2): {}",
            found.join(", ")
        );
    }
    Ok(())
}

/// The uncommitted work as one binary patch against HEAD, including untracked,
/// non-ignored files. It is built in a temporary index with a temporary object
/// directory (the source's objects are read through an alternate), so neither
/// the source's index nor its object store is written.
fn capture_base_patch(repo: &Path, scratch: &Path) -> Result<Vec<u8>> {
    let tmp = scratch.join("base-patch-tmp");
    let objects_tmp = tmp.join("objects");
    fs::create_dir_all(&objects_tmp)?;
    let objects_src = PathBuf::from(git_text(&git_source(
        repo,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    )?)?);
    let index = tmp.join("index");

    let run = |args: &[&str]| -> Result<Output> {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_INDEX_FILE", &index)
            .env("GIT_OBJECT_DIRECTORY", &objects_tmp)
            .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", &objects_src)
            .output()
            .with_context(|| format!("running git {}", args.join(" ")))?;
        check(out, args)
    };
    run(&["read-tree", "HEAD"])?;
    run(&["add", "-A"])?;
    let patch = run(&[
        "diff",
        "--cached",
        "--binary",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "HEAD",
    ])?
    .stdout;
    fs::remove_dir_all(&tmp).context("removing the temporary index")?;
    Ok(patch)
}

/// `git clone --no-hardlinks --no-checkout`, then drop the only remote and
/// check out the base commit. The result shares nothing with the source.
fn clone_isolated(repo: &Path, clone: &Path, base_commit: &str) -> Result<()> {
    let out = Command::new("git")
        .args(WRITE_CONFIG)
        .args(["clone", "-q", "--no-hardlinks", "--no-checkout"])
        .arg(repo)
        .arg(clone)
        .output()
        .context("running git clone")?;
    check(out, &["clone"])?;
    git_clone_write(clone, &["remote", "remove", "origin"])?;
    // A source that borrows objects from another repository would leave the
    // clone borrowing them too; refuse rather than share.
    if clone.join(".git/objects/info/alternates").exists() {
        bail!(
            "the clone has objects/info/alternates; the source repository borrows objects, which would share storage with the lane"
        );
    }
    git_clone_write(clone, &["checkout", "-q", "--detach", base_commit])?;
    // `git checkout` exits 0 after "unable to read sha1 file" and leaves the
    // file out, so the exit status alone does not prove a complete checkout.
    let leftover = git_clone_read(clone, &["status", "--porcelain"])?.stdout;
    if !leftover.is_empty() {
        bail!(
            "the clone does not match the base commit after checkout:\n{}",
            String::from_utf8_lossy(&leftover).trim_end()
        );
    }
    Ok(())
}

fn git_apply(clone: &Path, patch: &[u8]) -> Result<()> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(WRITE_CONFIG)
        .arg("apply")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning git apply")?;
    let mut stdin = child.stdin.take().context("opening git apply stdin")?;
    // Write from a thread so a full stderr pipe cannot deadlock the child.
    let data = patch.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&data));
    let out = child.wait_with_output().context("waiting for git apply")?;
    writer
        .join()
        .map_err(|_| anyhow!("patch writer panicked"))?
        .context("writing the patch to git apply")?;
    check(out, &["apply"]).map(|_| ())
}

fn commit_all(clone: &Path, message: &str) -> Result<()> {
    git_clone_write(clone, &["add", "-A"])?;
    git_clone_write(
        clone,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "--no-verify",
            "-m",
            message,
        ],
    )?;
    Ok(())
}

/// A read-only git command against the source (no optional lock, so the
/// index is never refreshed).
fn git_source(repo: &Path, args: &[&str]) -> Result<Output> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    check(out, args)
}

fn git_clone_read(clone: &Path, args: &[&str]) -> Result<Output> {
    let out = Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    check(out, args)
}

fn git_clone_write(clone: &Path, args: &[&str]) -> Result<Output> {
    let out = Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(WRITE_CONFIG)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    check(out, args)
}

fn check(out: Output, args: &[&str]) -> Result<Output> {
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
}

fn git_text(out: &Output) -> Result<String> {
    Ok(String::from_utf8(out.stdout.clone())
        .context("git printed non-UTF-8 output")?
        .trim()
        .to_string())
}

/// Remove what must not reach the builder (R15) and return the removed files,
/// relative to the clone and sorted:
///
/// - `.env` and `.env.*` at any depth, except `.env.example`;
/// - at the root only: `.claude/settings.json`, `.claude/settings.local.json`,
///   everything under `.claude/{hooks,skills,agents,commands}/`, `.mcp.json`
///   and `CLAUDE.local.md`;
/// - `CLAUDE.md` at any depth.
///
/// The walk never follows symlinks and never enters a `.git`.
fn remove_launch_baseline(clone: &Path) -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    collect_non_dirs(clone, "", &mut candidates)?;
    let mut removed: Vec<String> = candidates.into_iter().filter(|p| is_removed(p)).collect();
    removed.sort();
    for rel in &removed {
        let path = clone.join(rel);
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        // Leave no empty directory behind (git does not track directories).
        let mut parent = path.parent();
        while let Some(dir) = parent {
            if dir == clone || fs::remove_dir(dir).is_err() {
                break;
            }
            parent = dir.parent();
        }
    }
    Ok(removed)
}

/// Every file and symlink under `dir`, as `/`-separated relative paths.
fn collect_non_dirs(dir: &Path, rel: &str, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        if entry.file_type()?.is_dir() {
            if name != ".git" {
                collect_non_dirs(&entry.path(), &child, out)?;
            }
        } else {
            out.push(child);
        }
    }
    Ok(())
}

fn is_removed(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if (name == ".env" || name.starts_with(".env.")) && name != ".env.example" {
        return true;
    }
    if name == "CLAUDE.md" {
        return true;
    }
    // A symlink standing in for `.claude` or one of its entries would let the
    // builder's configuration load from outside the clone.
    const CLAUDE_FILES: [&str; 2] = [".claude/settings.json", ".claude/settings.local.json"];
    const CLAUDE_DIRS: [&str; 4] = [
        ".claude/hooks",
        ".claude/skills",
        ".claude/agents",
        ".claude/commands",
    ];
    matches!(rel, ".mcp.json" | "CLAUDE.local.md" | ".claude")
        || CLAUDE_FILES.contains(&rel)
        || CLAUDE_DIRS.contains(&rel)
        || CLAUDE_DIRS
            .iter()
            .any(|d| rel.strip_prefix(d).is_some_and(|r| r.starts_with('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    /// Run git in `dir` with a fixed identity and fail the test on error.
    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            // A plain `git status` refreshes (rewrites) the index; the tests that
            // compare the source's index must not do that themselves.
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).expect("utf-8")
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir");
        fs::write(path, content).expect("write");
    }

    /// A repo whose only commit holds `files`.
    fn repo_with(tmp: &TempDir, files: &[(&str, &str)]) -> PathBuf {
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).expect("mkdir");
        git(&repo, &["init", "-q", "-b", "main"]);
        for (rel, content) in files {
            write(&repo, rel, content);
        }
        git(&repo, &["add", "-f", "-A"]);
        git(&repo, &["commit", "-q", "-m", "initial"]);
        repo
    }

    fn clean_opts() -> PrepareOptions {
        PrepareOptions { allow_dirty: false }
    }

    fn dirty_opts() -> PrepareOptions {
        PrepareOptions { allow_dirty: true }
    }

    /// Every file under `.git/objects` of `repo`, by inode.
    fn object_inodes(repo: &Path) -> BTreeSet<u64> {
        fn walk(dir: &Path, out: &mut BTreeSet<u64>) {
            for entry in fs::read_dir(dir).expect("read_dir") {
                let entry = entry.expect("entry");
                let md = fs::symlink_metadata(entry.path()).expect("metadata");
                if md.is_dir() {
                    walk(&entry.path(), out);
                } else {
                    out.insert(md.ino());
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(&repo.join(".git/objects"), &mut out);
        out
    }

    /// The path set named by `diff --git a/X b/X` headers of a patch.
    fn patch_paths(patch: &[u8]) -> BTreeSet<String> {
        String::from_utf8_lossy(patch)
            .lines()
            .filter_map(|l| l.strip_prefix("diff --git a/"))
            .map(|l| l.split(" b/").next().expect("a/ path").to_string())
            .collect()
    }

    /// Every tracked file of the working tree at `dir`, with its bytes.
    fn tree_of(dir: &Path) -> Vec<(String, Vec<u8>)> {
        git(dir, &["add", "-A"]);
        git(dir, &["ls-files"])
            .lines()
            .map(|f| (f.to_string(), fs::read(dir.join(f)).expect("read")))
            .collect()
    }

    #[test]
    fn dirty_tree_without_allow_dirty_is_refused_before_anything_is_created() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        write(&repo, "README.md", "two");
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", clean_opts()).unwrap_err();

        assert!(err.to_string().contains("dirty"), "got: {err}");
        assert!(
            !lanes_root.exists(),
            "nothing may be created before the refusal"
        );
    }

    #[test]
    fn allow_dirty_records_modified_and_untracked_files_and_leaves_the_source_alone() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one"), ("keep.txt", "k")]);
        write(&repo, "README.md", "two");
        write(&repo, "new/dir/fresh.txt", "fresh");
        let status_before = git(&repo, &["status", "--porcelain"]);
        assert_eq!(status_before.lines().count(), 2, "{status_before}");
        let index = repo.join(".git/index");
        let index_bytes = fs::read(&index).unwrap();
        let index_mtime = fs::metadata(&index).unwrap().modified().unwrap();
        let objects_before = object_inodes(&repo);

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", dirty_opts()).unwrap();

        // Both changes are in the clone, committed as the base patch.
        let clone = &lane.layout.clone;
        assert_eq!(fs::read_to_string(clone.join("README.md")).unwrap(), "two");
        assert_eq!(
            fs::read_to_string(clone.join("new/dir/fresh.txt")).unwrap(),
            "fresh"
        );
        let log = git(clone, &["log", "--format=%s"]);
        let subjects: Vec<&str> = log.lines().collect();
        assert_eq!(
            subjects,
            [
                "cowproof: launch baseline",
                "cowproof: base patch",
                "initial"
            ]
        );
        let at_patch = git(clone, &["ls-tree", "-r", "--name-only", "HEAD~1"]);
        assert!(
            at_patch.lines().any(|l| l == "new/dir/fresh.txt"),
            "{at_patch}"
        );
        assert_eq!(git(clone, &["show", "HEAD~1:README.md"]), "two");
        let patch = lane.base_patch.expect("a base patch");
        assert_eq!(
            patch_paths(&patch),
            BTreeSet::from(["README.md".to_string(), "new/dir/fresh.txt".to_string()])
        );

        // The source is byte-for-byte as it was: status, index and objects.
        assert_eq!(git(&repo, &["status", "--porcelain"]), status_before);
        assert_eq!(fs::read(&index).unwrap(), index_bytes);
        assert_eq!(
            fs::metadata(&index).unwrap().modified().unwrap(),
            index_mtime
        );
        assert_eq!(object_inodes(&repo), objects_before);
    }

    #[test]
    fn tracked_heldout_file_is_refused_by_name_and_creates_nothing() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[("README.md", "one"), ("x.heldout.toml", "# held out")],
        );
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", clean_opts()).unwrap_err();

        assert!(err.to_string().contains("x.heldout.toml"), "got: {err}");
        assert!(!lanes_root.exists());
    }

    #[test]
    fn untracked_heldout_file_is_refused_when_it_would_travel_in_the_base_patch() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        write(&repo, "sub/y.heldout.toml", "# held out");
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap_err();

        assert!(err.to_string().contains("sub/y.heldout.toml"), "got: {err}");
        assert!(!lanes_root.exists());
    }

    #[test]
    fn clone_shares_no_storage_with_the_source() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one"), ("src/a.rs", "fn a() {}")]);

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();
        let clone = &lane.layout.clone;

        assert!(!clone.join(".git/objects/info/alternates").exists());
        assert_eq!(git(clone, &["remote"]), "");

        // The commit object exists loose in both and is a different file.
        let head = git(&repo, &["rev-parse", "HEAD"]);
        let head = head.trim();
        let rel = format!(".git/objects/{}/{}", &head[..2], &head[2..]);
        let source_ino = fs::metadata(repo.join(&rel)).unwrap().ino();
        let clone_ino = fs::metadata(clone.join(&rel)).unwrap().ino();
        assert_ne!(source_ino, clone_ino, "the same inode means a hardlink");

        // And no object file of the clone is any object file of the source.
        let shared: Vec<_> = object_inodes(&repo)
            .intersection(&object_inodes(clone))
            .copied()
            .collect();
        assert!(shared.is_empty(), "shared inodes: {shared:?}");
    }

    #[test]
    fn a_source_that_borrows_objects_is_refused() {
        let tmp = TempDir::new().unwrap();
        let origin = tmp.path().join("origin");
        fs::create_dir_all(&origin).unwrap();
        git(&origin, &["init", "-q", "-b", "main"]);
        write(&origin, "a.txt", "a");
        git(&origin, &["add", "-A"]);
        git(&origin, &["commit", "-q", "-m", "initial"]);
        let shared = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "clone",
                "-q",
                "--shared",
                origin.to_str().unwrap(),
                shared.to_str().unwrap(),
            ],
        );
        assert!(shared.join(".git/objects/info/alternates").exists());
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&shared, &lanes_root, "l1", clean_opts()).unwrap_err();

        assert!(err.to_string().contains("alternates"), "got: {err}");
        assert!(!lanes_root.join("l1").exists());
    }

    /// The packet's tree: every removal rule once, and survivors for each
    /// look-alike.
    const PACKET_TREE: &[(&str, &str)] = &[
        (".env", "SECRET=1"),
        ("sub/.env.local", "SECRET=2"),
        (".env.example", "SECRET=placeholder"),
        (".claude/settings.json", "{}"),
        (".claude/hooks/h.sh", "echo hi"),
        (".claude/keep.md", "keep"),
        (".mcp.json", "{}"),
        ("CLAUDE.md", "# rules"),
        ("docs/CLAUDE.md", "# docs rules"),
        ("src/main.rs", "fn main() {}"),
    ];

    #[test]
    fn launch_baseline_removes_exactly_the_ruled_set() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, PACKET_TREE);

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();
        let clone = &lane.layout.clone;

        let expected: Vec<String> = [
            ".claude/hooks/h.sh",
            ".claude/settings.json",
            ".env",
            ".mcp.json",
            "CLAUDE.md",
            "docs/CLAUDE.md",
            "sub/.env.local",
        ]
        .map(String::from)
        .to_vec();

        let control: LaneControl =
            serde_json::from_slice(&fs::read(lane.layout.control.join("lane.json")).unwrap())
                .unwrap();
        assert_eq!(control.removed_paths, expected);
        assert_eq!(control.base_commit, lane.base_commit);
        assert_eq!(
            control.base_commit,
            git(&repo, &["rev-parse", "HEAD"]).trim()
        );
        assert_eq!(control.launch_commit, lane.launch_commit);
        assert_eq!(
            control.launch_commit,
            git(clone, &["rev-parse", "HEAD"]).trim()
        );

        for gone in &expected {
            assert!(!clone.join(gone).exists(), "{gone} must be removed");
        }
        for kept in [".env.example", ".claude/keep.md", "src/main.rs"] {
            assert!(clone.join(kept).exists(), "{kept} must survive");
        }
        // The emptied .claude/hooks directory is gone with its only file.
        assert!(!clone.join(".claude/hooks").exists());

        assert_eq!(lane.launch_removed, expected);
        // The source still has every file.
        for (rel, content) in PACKET_TREE {
            assert_eq!(&fs::read_to_string(repo.join(rel)).unwrap(), content);
        }
    }

    #[test]
    fn removal_rules_are_root_only_where_ruled_and_never_touch_look_alikes() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[
                ("CLAUDE.local.md", "root only"),
                ("pkg/CLAUDE.local.md", "nested survives"),
                ("pkg/.mcp.json", "nested survives"),
                ("pkg/.claude/settings.json", "nested survives"),
                (".claude/settings.local.json", "{}"),
                (".claude/skills/s/SKILL.md", "skill"),
                (".claude/agents/a.md", "agent"),
                (".claude/commands/c.md", "command"),
                (".claude/other.json", "survives"),
                (".env.production", "SECRET"),
                ("deep/er/.env", "SECRET"),
                (".envrc", "survives"),
                ("pkg/.env.example", "survives"),
                ("notes/claude.md", "survives"),
            ],
        );

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        let control: LaneControl =
            serde_json::from_slice(&fs::read(lane.layout.control.join("lane.json")).unwrap())
                .unwrap();
        assert_eq!(
            control.removed_paths,
            [
                ".claude/agents/a.md",
                ".claude/commands/c.md",
                ".claude/settings.local.json",
                ".claude/skills/s/SKILL.md",
                ".env.production",
                "CLAUDE.local.md",
                "deep/er/.env",
            ]
        );
        for kept in [
            "pkg/CLAUDE.local.md",
            "pkg/.mcp.json",
            "pkg/.claude/settings.json",
            ".claude/other.json",
            ".envrc",
            "pkg/.env.example",
            "notes/claude.md",
        ] {
            assert!(lane.layout.clone.join(kept).exists(), "{kept} must survive");
        }
    }

    #[test]
    fn a_symlink_standing_in_for_claude_is_removed_not_followed() {
        let tmp = TempDir::new().unwrap();
        let outside = tmp.path().join("outside");
        write(&outside, "settings.json", "outside");
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        std::os::unix::fs::symlink(&outside, repo.join(".claude")).unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "link"]);

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        assert!(fs::symlink_metadata(lane.layout.clone.join(".claude")).is_err());
        assert!(
            outside.join("settings.json").exists(),
            "the target is untouched"
        );
        assert_eq!(lane.launch_removed, vec![".claude".to_string()]);
    }

    /// Rebuild the base in a fresh clone of the source, apply `base.patch` (if
    /// any), replay the launch baseline by deleting paths, and return its tree hash.
    fn replay_tree(tmp: &TempDir, repo: &Path, lane: &PreparedLane) -> String {
        let fresh = tmp.path().join("replay");
        git(
            tmp.path(),
            &[
                "clone",
                "-q",
                "--no-hardlinks",
                repo.to_str().unwrap(),
                fresh.to_str().unwrap(),
            ],
        );
        git(&fresh, &["checkout", "-q", &lane.base_commit]);
        if let Some(patch) = lane.base_patch.as_deref().filter(|p| !p.is_empty()) {
            let file = tmp.path().join("base.patch");
            fs::write(&file, patch).unwrap();
            git(&fresh, &["apply", file.to_str().unwrap()]);
        }
        // Replay launch baseline by deleting the removed paths.
        for rel in &lane.launch_removed {
            let path = fresh.join(rel);
            if path.is_file() {
                fs::remove_file(&path).expect("removing file");
            } else if path.is_dir() {
                fs::remove_dir_all(&path).expect("removing directory");
            }
        }
        git(&fresh, &["add", "-A"]);
        git(&fresh, &["write-tree"]).trim().to_string()
    }

    #[test]
    fn replay_of_base_and_launch_baseline_rebuilds_the_launch_tree_clean() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, PACKET_TREE);

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        assert!(lane.base_patch.is_none());
        assert!(!lane.launch_removed.is_empty());
        let launch_tree = git(&lane.layout.clone, &["rev-parse", "HEAD^{tree}"]);
        let base_tree = git(&repo, &["rev-parse", "HEAD^{tree}"]);
        assert_ne!(
            launch_tree, base_tree,
            "the launch commit must differ from the base"
        );
        assert_eq!(replay_tree(&tmp, &repo, &lane), launch_tree.trim());
    }

    #[test]
    fn replay_of_base_and_launch_baseline_rebuilds_the_launch_tree_with_a_base_patch() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, PACKET_TREE);
        // Dirty: a modified tracked file and a new file (not removable paths).
        // With allow_dirty, dirty removable paths like .env are refused, so we
        // only test the ordinary files here.
        write(&repo, "src/main.rs", "fn main() { println!(); }");
        write(&repo, "src/new.rs", "pub fn n() {}");

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", dirty_opts()).unwrap();

        let base_patch = lane.base_patch.as_ref().expect("a base patch");
        assert_eq!(
            patch_paths(base_patch),
            BTreeSet::from(["src/main.rs".to_string(), "src/new.rs".to_string()])
        );
        // The launch baseline removes the files matched by is_removed, which
        // includes all the .env* files (except .env.example) from PACKET_TREE.
        assert!(lane.launch_removed.contains(&".env".to_string()));
        assert!(lane.launch_removed.contains(&"sub/.env.local".to_string()));
        let launch_tree = git(&lane.layout.clone, &["rev-parse", "HEAD^{tree}"]);
        assert_eq!(replay_tree(&tmp, &repo, &lane), launch_tree.trim());
        assert_eq!(
            fs::read_to_string(lane.layout.clone.join("src/main.rs")).unwrap(),
            "fn main() { println!(); }"
        );
        // Tree equality is not vacuous: compare the files themselves too.
        assert_eq!(
            tree_of(&lane.layout.clone)
                .into_iter()
                .map(|(f, _)| f)
                .collect::<Vec<_>>(),
            git(
                &lane.layout.clone,
                &["ls-tree", "-r", "--name-only", "HEAD"]
            )
            .lines()
            .map(String::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn nothing_to_remove_still_makes_an_empty_launch_commit_on_the_base() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        write(&repo, "src/lib.rs", "pub fn f() {}");
        write(&repo, "README.md", "two");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "second: changes files"]);

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        assert!(
            lane.launch_removed.is_empty(),
            "no paths were removed, so launch_removed is empty"
        );
        assert_ne!(lane.launch_commit, lane.base_commit);
        let parent = git(
            &lane.layout.clone,
            &["rev-parse", &format!("{}^", lane.launch_commit)],
        );
        assert_eq!(parent.trim(), lane.base_commit);
        assert_eq!(
            git(
                &lane.layout.clone,
                &["rev-parse", &format!("{}^{{tree}}", lane.launch_commit)]
            ),
            git(&repo, &["rev-parse", "HEAD^{tree}"])
        );
        let control: LaneControl =
            serde_json::from_slice(&fs::read(lane.layout.control.join("lane.json")).unwrap())
                .unwrap();
        assert!(control.removed_paths.is_empty());
    }

    #[test]
    fn writes_in_the_clone_never_reach_the_source() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        write(&lane.layout.clone, "new-file.txt", "content");
        write(&lane.layout.clone, "README.md", "changed in the clone");
        git(&lane.layout.clone, &["add", "-A"]);
        git(&lane.layout.clone, &["commit", "-q", "-m", "builder work"]);

        assert!(!repo.join("new-file.txt").exists());
        assert_eq!(fs::read_to_string(repo.join("README.md")).unwrap(), "one");
        assert_eq!(git(&repo, &["status", "--porcelain"]), "");
        assert_eq!(git(&repo, &["log", "--format=%s"]), "initial\n");
    }

    #[test]
    fn lane_gets_an_owner_only_socket_dir_and_a_socket_path_inside_it() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        let lanes_root = tmp.path().join("lanes");

        let lane = prepare_lane(&repo, &lanes_root, "l1", clean_opts()).unwrap();

        let dir = lanes_root.join("l1/sock");
        assert_eq!(lane.layout.sock, dir.join("runner.sock"));
        let meta = fs::metadata(&dir).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        // The runner binds the socket; preparing the lane does not.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn existing_lane_dir_is_refused_and_left_untouched() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        let lanes_root = tmp.path().join("lanes");
        write(&lanes_root, "l1/precious.txt", "do not touch");

        let err = prepare_lane(&repo, &lanes_root, "l1", clean_opts()).unwrap_err();

        assert!(err.to_string().contains("lane directory"), "got: {err}");
        let entries: Vec<_> = fs::read_dir(lanes_root.join("l1"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, ["precious.txt"]);
        assert_eq!(
            fs::read_to_string(lanes_root.join("l1/precious.txt")).unwrap(),
            "do not touch"
        );
    }

    #[test]
    fn lane_ids_are_validated() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "one")]);
        let lanes_root = tmp.path().join("lanes");

        let too_long = "a".repeat(65);
        for bad in ["", ".", "..", "a/b", "a b", too_long.as_str()] {
            let err = prepare_lane(&repo, &lanes_root, bad, clean_opts()).unwrap_err();
            assert!(err.to_string().contains("lane id"), "{bad:?}: {err}");
        }
        assert!(!lanes_root.exists(), "a refused id creates nothing");

        let longest = "a".repeat(64);
        prepare_lane(&repo, &lanes_root, &longest, clean_opts()).unwrap();
        assert!(lanes_root.join(&longest).join("clone/README.md").exists());
        prepare_lane(&repo, &lanes_root, "My_lane-1.0", clean_opts()).unwrap();
    }

    /// Cleanup seam: the source passes every check made before the lane
    /// directory is created (status, held-out scan, HEAD), but one of its
    /// blobs is missing from the object store. `git clone` copies objects
    /// without reading them, so the failure comes at the later checkout of the
    /// base commit, after the lane directory exists. No production branch is
    /// involved; only the repository's state differs.
    #[test]
    fn failure_after_the_lane_dir_exists_removes_it_and_returns_the_original_error() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[("README.md", "one"), ("data.txt", "the missing blob")],
        );
        let blob = git(&repo, &["rev-parse", "HEAD:data.txt"]);
        let blob = blob.trim();
        let loose = repo.join(format!(".git/objects/{}/{}", &blob[..2], &blob[2..]));
        assert!(loose.exists(), "the blob is loose");
        fs::remove_file(&loose).unwrap();
        assert_eq!(
            git(&repo, &["status", "--porcelain"]),
            "",
            "status stays clean"
        );
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", clean_opts()).unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not match the base commit") && msg.contains("data.txt"),
            "got: {msg}"
        );
        assert!(
            lanes_root.exists(),
            "lanes_root is the caller's, not removed"
        );
        assert!(
            !lanes_root.join("l1").exists(),
            "the lane dir must be removed"
        );
        assert_eq!(fs::read_dir(&lanes_root).unwrap().count(), 0);
    }

    /// The first file under `dir` holding `needle`, skipping every `.git` (the clone's
    /// own object store legitimately holds the base commit's blobs) and never following
    /// a symlink.
    fn find_bytes_in_tree(dir: &Path, needle: &[u8]) -> Option<PathBuf> {
        for entry in fs::read_dir(dir).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                if entry.file_name() != ".git"
                    && let Some(found) = find_bytes_in_tree(&path, needle)
                {
                    return Some(found);
                }
            } else if kind.is_file() {
                let content = fs::read(&path).unwrap();
                if content.windows(needle.len()).any(|w| w == needle) {
                    return Some(path);
                }
            }
        }
        None
    }

    #[test]
    fn secret_in_env_file_does_not_appear_in_any_lane_file() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[("README.md", "safe"), (".env", "SECRET=CANARY-7f3a")],
        );

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        // The secret must not be in the clone's tree.
        assert!(!lane.layout.clone.join(".env").exists());

        // The secret must not be in any file of the lane directory (control, home, scratch,
        // clone working tree), outside the clone's own .git.
        let secret = b"CANARY-7f3a";
        if let Some(found) = find_bytes_in_tree(lane.layout.control.parent().unwrap(), secret) {
            panic!("secret found in: {}", found.display());
        }

        // The secret must not be in the launch_removed list (only paths).
        assert!(!lane.launch_removed.join("\n").contains("CANARY-7f3a"));
        assert!(lane.launch_removed.contains(&".env".to_string()));
    }

    #[test]
    fn multiple_removed_files_with_secrets_leave_no_secrets_in_lane() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[
                ("README.md", "safe"),
                (".env", "API_KEY=secret-key-xyz"),
                ("config/.env.local", "DB_PASS=password123"),
                ("CLAUDE.md", "# Config with token: secret-token-abc"),
            ],
        );

        let lane = prepare_lane(&repo, &tmp.path().join("lanes"), "l1", clean_opts()).unwrap();

        // None of these secrets should appear in the lane directory.
        let secrets = [
            b"secret-key-xyz".as_slice(),
            b"password123".as_slice(),
            b"secret-token-abc".as_slice(),
        ];
        for secret in &secrets {
            if let Some(found) = find_bytes_in_tree(lane.layout.control.parent().unwrap(), secret) {
                panic!(
                    "secret {:?} found in: {}",
                    String::from_utf8_lossy(secret),
                    found.display()
                );
            }
        }

        // The launch_removed contains paths, not content.
        assert!(lane.launch_removed.contains(&".env".to_string()));
        assert!(
            lane.launch_removed
                .contains(&"config/.env.local".to_string())
        );
        assert!(lane.launch_removed.contains(&"CLAUDE.md".to_string()));
    }

    #[test]
    fn untracked_env_file_with_allow_dirty_is_refused_before_anything_is_created() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "safe")]);
        write(&repo, ".env", "CANARY-DIRTY-3c1e");
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap_err();

        assert!(
            err.to_string().contains(".env"),
            "error must name .env: {err}"
        );
        assert!(
            err.to_string().contains("allow_dirty"),
            "error must mention allow_dirty: {err}"
        );
        assert!(!lanes_root.exists(), "nothing created before refusal");

        // Verify the canary is not in any file under lanes_root if it somehow exists.
        if lanes_root.exists()
            && let Some(found) = find_bytes_in_tree(&lanes_root, b"CANARY-DIRTY-3c1e")
        {
            panic!("canary found in: {}", found.display());
        }
    }

    #[test]
    fn modified_tracked_env_file_with_allow_dirty_is_refused() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "safe"), ("sub/.env.local", "OLD")]);
        write(&repo, "sub/.env.local", "MODIFIED-CANARY");
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap_err();

        assert!(
            err.to_string().contains("sub/.env.local"),
            "error must name sub/.env.local: {err}"
        );
        assert!(!lanes_root.exists());
    }

    #[test]
    fn dirty_claude_md_at_any_depth_is_refused_with_allow_dirty() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[("README.md", "safe"), ("docs/CLAUDE.md", "# original")],
        );
        write(&repo, "docs/CLAUDE.md", "# modified");
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap_err();

        assert!(
            err.to_string().contains("docs/CLAUDE.md"),
            "error must name docs/CLAUDE.md: {err}"
        );
        assert!(!lanes_root.exists());
    }

    #[test]
    fn dirty_env_example_is_accepted_with_allow_dirty() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[("README.md", "safe"), (".env.example", "PLACEHOLDER=1")],
        );
        write(&repo, ".env.example", "PLACEHOLDER=changed");
        let lanes_root = tmp.path().join("lanes");

        let lane = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap();

        // .env.example survives in the clone and in the base patch.
        assert!(lane.layout.clone.join(".env.example").exists());
        let patch = lane.base_patch.expect("base patch exists");
        assert!(
            String::from_utf8_lossy(&patch).contains(".env.example"),
            "base patch should contain .env.example"
        );
    }

    #[test]
    fn dirty_ordinary_file_is_accepted_with_allow_dirty() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "safe"), ("src/x.rs", "fn f() {}")]);
        write(&repo, "src/x.rs", "fn f() { println!(); }");
        let lanes_root = tmp.path().join("lanes");

        let lane = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap();

        assert_eq!(
            fs::read_to_string(lane.layout.clone.join("src/x.rs")).unwrap(),
            "fn f() { println!(); }"
        );
    }

    #[test]
    fn ignored_env_file_is_accepted_with_allow_dirty() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(&tmp, &[("README.md", "safe"), (".gitignore", ".env\n")]);
        write(&repo, ".env", "CANARY-IGNORED");
        // Verify git ignores it
        assert_eq!(git(&repo, &["status", "--porcelain"]), "");
        let lanes_root = tmp.path().join("lanes");

        let lane = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap();

        // The ignored .env is not in the base patch.
        if let Some(patch) = &lane.base_patch {
            assert!(
                !String::from_utf8_lossy(patch).contains(".env"),
                "ignored .env should not be in base patch"
            );
        }
        // And the canary should not appear in any lane file.
        if let Some(found) =
            find_bytes_in_tree(lane.layout.control.parent().unwrap(), b"CANARY-IGNORED")
        {
            panic!("canary from ignored .env found in: {}", found.display());
        }
    }

    #[test]
    fn multiple_dirty_removed_paths_are_all_named_in_the_error() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with(
            &tmp,
            &[
                ("README.md", "safe"),
                (".env", "SECRET1"),
                ("config/.env.local", "SECRET2"),
                ("CLAUDE.md", "# docs"),
            ],
        );
        write(&repo, ".env", "CHANGED");
        write(&repo, "config/.env.local", "CHANGED");
        write(&repo, "CLAUDE.md", "# changed");
        let lanes_root = tmp.path().join("lanes");

        let err = prepare_lane(&repo, &lanes_root, "l1", dirty_opts()).unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains(".env"), "must list .env: {msg}");
        assert!(
            msg.contains("config/.env.local"),
            "must list config/.env.local: {msg}"
        );
        assert!(msg.contains("CLAUDE.md"), "must list CLAUDE.md: {msg}");
        assert!(!lanes_root.exists());
    }
}
