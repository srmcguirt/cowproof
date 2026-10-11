//! Reading a file as it is in a commit, never as it is in a working tree.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// `git show <commit>:<path>`: the file's committed text, or `Ok(None)` when the path
/// is not in that commit.
///
/// Only a regular file counts. A path that is a directory, a symlink or a submodule at
/// that commit is an error rather than `None` or a guess (`git show` would print a link's
/// target as if it were the content). A bad commit, or a repository git cannot read, is
/// an error too, never `None`: "missing" means the commit was read and the path is not in it.
pub fn git_show_optional(repo: &Path, commit: &str, path: &str) -> Result<Option<String>> {
    let Some(mode) = tree_entry_mode(repo, commit, path)? else {
        return Ok(None);
    };
    if mode != "100644" && mode != "100755" {
        bail!("{path} at {commit} is not a regular file (mode {mode}); commit a regular file");
    }
    show_text(repo, commit, path).map(Some)
}

/// The mode of `path` in `commit`'s tree (`100644`, `120000`, `040000`, ...), or `None`
/// when the commit has no such path. A bad commit is an error.
fn tree_entry_mode(repo: &Path, commit: &str, path: &str) -> Result<Option<String>> {
    let listing = Command::new("git")
        .current_dir(repo)
        .args(["ls-tree", "-z", "--full-tree", commit, "--", path])
        .output()
        .context("git ls-tree failed to start")?;
    if !listing.status.success() {
        bail!(
            "git ls-tree {commit} -- {path} failed: {}",
            String::from_utf8_lossy(&listing.stderr).trim()
        );
    }
    // One entry per match: "<mode> <type> <object>\t<path>", NUL-terminated.
    let Some(entry) = listing.stdout.split(|b| *b == 0).find(|e| !e.is_empty()) else {
        return Ok(None);
    };
    let mode = entry.split(|b| *b == b' ').next().unwrap_or_default();
    Ok(Some(String::from_utf8_lossy(mode).into_owned()))
}

/// `git show <commit>:<path>` as UTF-8 text.
fn show_text(repo: &Path, commit: &str, path: &str) -> Result<String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["show", &format!("{commit}:{path}")])
        .output()
        .context("git show failed to start")?;
    if !output.status.success() {
        bail!(
            "git show {commit}:{path} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("{path} at {commit} is not valid UTF-8"))
}

/// What reading a committed file through its symlinks found.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkedFile {
    /// The path is not in the commit at all.
    Absent,
    /// The text of the regular file the path is, or links to inside the same tree.
    Text(String),
    /// The path is there but cannot be used (a link that is absolute, leaves the tree,
    /// loops or dangles, or a directory or submodule); the reason is for a warning.
    Unusable(String),
}

/// The most symlinks followed before the chain is refused.
const MAX_LINK_HOPS: usize = 5;

/// Read `path` from `commit` the way `git_show_optional` does, but follow symlinks that
/// stay inside the commit's tree (a committed `CLAUDE.md -> AGENTS.md`). The link's target
/// is read from the committed blob and resolved against the repository root, never the
/// filesystem, so the working tree has no say. At most `MAX_LINK_HOPS` links are followed
/// and a loop is refused. A target that is absolute, climbs out of the tree, is missing, or
/// is a directory or submodule gives `Unusable`, not an error: a caller that treats the file
/// as optional input can warn and go on. A bad commit or an unreadable repository is still
/// an error. The gates keep the strict `git_show_optional`.
pub fn git_show_following_links(repo: &Path, commit: &str, path: &str) -> Result<LinkedFile> {
    let mut current = path.to_string();
    let mut seen = vec![current.clone()];
    for _ in 0..=MAX_LINK_HOPS {
        let Some(mode) = tree_entry_mode(repo, commit, &current)? else {
            return Ok(if current == path {
                LinkedFile::Absent
            } else {
                LinkedFile::Unusable(format!(
                    "{path} links to {current}, which is not in the commit"
                ))
            });
        };
        match mode.as_str() {
            "100644" | "100755" => return show_text(repo, commit, &current).map(LinkedFile::Text),
            "120000" => {
                let target = show_text(repo, commit, &current)?;
                let target = target.trim_end_matches('\n');
                let Some(next) = resolve_link(&current, target) else {
                    return Ok(LinkedFile::Unusable(format!(
                        "{current} links to {target:?}, which is absolute, empty or outside the repository"
                    )));
                };
                if seen.contains(&next) {
                    return Ok(LinkedFile::Unusable(format!(
                        "{path} is in a symlink loop at {next}"
                    )));
                }
                seen.push(next.clone());
                current = next;
            }
            other => {
                return Ok(LinkedFile::Unusable(format!(
                    "{current} is not a regular file or a link to one (mode {other})"
                )));
            }
        }
    }
    Ok(LinkedFile::Unusable(format!(
        "{path} goes through more than {MAX_LINK_HOPS} symlinks"
    )))
}

/// Resolve a symlink's `target` against the directory of `link` (both relative to the
/// repository root). `None` when the target is empty, absolute, or climbs above the root.
fn resolve_link(link: &str, target: &str) -> Option<String> {
    if target.is_empty() || target.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = link.split('/').collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            name => parts.push(name),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Run git in `repo` with no global or system configuration, so the test depends on
    /// neither the home directory nor the machine's git settings.
    fn git(repo: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn repo_with(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        git(dir.path(), &["init", "-q"]);
        for (name, text) in files {
            if let Some(parent) = Path::new(name).parent() {
                fs::create_dir_all(dir.path().join(parent)).unwrap();
            }
            fs::write(dir.path().join(name), text).unwrap();
        }
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-q", "-m", "initial"]);
        dir
    }

    #[test]
    fn reads_the_committed_text() {
        let dir = repo_with(&[("test.txt", "Hello World"), ("sub/a.txt", "nested")]);
        let read = |p| git_show_optional(dir.path(), "HEAD", p).unwrap();
        assert_eq!(read("test.txt").as_deref(), Some("Hello World"));
        assert_eq!(read("sub/a.txt").as_deref(), Some("nested"));
    }

    #[test]
    fn the_working_tree_never_wins() {
        let dir = repo_with(&[("test.txt", "committed")]);
        fs::write(dir.path().join("test.txt"), "edited, not committed").unwrap();
        let text = git_show_optional(dir.path(), "HEAD", "test.txt").unwrap();
        assert_eq!(text.as_deref(), Some("committed"));
    }

    #[test]
    fn a_path_absent_from_the_commit_is_none_even_if_the_working_tree_has_it() {
        let dir = repo_with(&[("existing.txt", "content")]);
        fs::write(dir.path().join("new.txt"), "untracked").unwrap();
        assert_eq!(
            git_show_optional(dir.path(), "HEAD", "nonexistent.txt").unwrap(),
            None
        );
        assert_eq!(
            git_show_optional(dir.path(), "HEAD", "new.txt").unwrap(),
            None
        );
    }

    #[test]
    fn a_bad_commit_is_an_error_not_none() {
        let dir = repo_with(&[("test.txt", "x")]);
        assert!(git_show_optional(dir.path(), "no-such-commit", "test.txt").is_err());
        let not_a_repo = TempDir::new().unwrap();
        assert!(git_show_optional(not_a_repo.path(), "HEAD", "test.txt").is_err());
    }

    #[test]
    fn a_directory_or_a_symlink_is_an_error() {
        let dir = repo_with(&[("sub/a.txt", "nested"), ("real.txt", "real")]);
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();
        git(dir.path(), &["add", "link.txt"]);
        git(dir.path(), &["commit", "-q", "-m", "link"]);
        for path in ["sub", "link.txt"] {
            let err = git_show_optional(dir.path(), "HEAD", path).unwrap_err();
            assert!(
                err.to_string().contains("not a regular file"),
                "{path}: {err}"
            );
        }
    }

    #[test]
    fn text_that_is_not_utf8_is_an_error() {
        let dir = TempDir::new().unwrap();
        git(dir.path(), &["init", "-q"]);
        fs::write(dir.path().join("bin"), [0xff, 0xfe, 0x00]).unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-q", "-m", "binary"]);
        let err = git_show_optional(dir.path(), "HEAD", "bin").unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    /// Commit `files` and the symlinks `(name, target)` in one commit.
    fn repo_with_links(files: &[(&str, &str)], links: &[(&str, &str)]) -> TempDir {
        let dir = repo_with(files);
        for (name, target) in links {
            if let Some(parent) = Path::new(name).parent() {
                fs::create_dir_all(dir.path().join(parent)).unwrap();
            }
            std::os::unix::fs::symlink(target, dir.path().join(name)).unwrap();
        }
        git(dir.path(), &["add", "."]);
        git(
            dir.path(),
            &["commit", "-q", "-m", "links", "--allow-empty"],
        );
        dir
    }

    fn follow(dir: &TempDir, path: &str) -> LinkedFile {
        git_show_following_links(dir.path(), "HEAD", path).unwrap()
    }

    fn unusable(found: LinkedFile) -> String {
        match found {
            LinkedFile::Unusable(reason) => reason,
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    #[test]
    fn following_reads_a_regular_file_and_reports_a_missing_one() {
        let dir = repo_with(&[("CLAUDE.md", "plain")]);
        assert_eq!(follow(&dir, "CLAUDE.md"), LinkedFile::Text("plain".into()));
        assert_eq!(follow(&dir, "nope.md"), LinkedFile::Absent);
    }

    #[test]
    fn following_a_link_inside_the_tree_reads_the_target_blob() {
        let dir = repo_with_links(
            &[("AGENTS.md", "AGENTS-MARKER\n"), ("docs/guide.md", "guide")],
            &[
                ("CLAUDE.md", "AGENTS.md"),
                ("docs/link.md", "guide.md"),
                ("docs/up.md", "../AGENTS.md"),
                ("hop1.md", "hop2.md"),
                ("hop2.md", "./AGENTS.md"),
            ],
        );
        let agents = LinkedFile::Text("AGENTS-MARKER\n".into());
        assert_eq!(follow(&dir, "CLAUDE.md"), agents);
        assert_eq!(follow(&dir, "docs/up.md"), agents);
        assert_eq!(follow(&dir, "hop1.md"), agents);
        assert_eq!(
            follow(&dir, "docs/link.md"),
            LinkedFile::Text("guide".into())
        );
    }

    #[test]
    fn following_never_reads_the_working_tree() {
        let dir = repo_with_links(&[("AGENTS.md", "committed")], &[("CLAUDE.md", "AGENTS.md")]);
        fs::write(dir.path().join("AGENTS.md"), "edited").unwrap();
        assert_eq!(
            follow(&dir, "CLAUDE.md"),
            LinkedFile::Text("committed".into())
        );
    }

    #[test]
    fn following_refuses_links_that_leave_the_tree_or_lead_nowhere() {
        let dir = repo_with_links(
            &[("sub/a.md", "a")],
            &[
                ("outside.md", "../outside"),
                ("deep.md", "sub/../../outside"),
                ("absolute.md", "/etc/passwd"),
                ("dangling.md", "missing.md"),
                ("to-dir.md", "sub"),
                ("loop-a.md", "loop-b.md"),
                ("loop-b.md", "loop-a.md"),
                ("self.md", "self.md"),
            ],
        );
        assert!(unusable(follow(&dir, "outside.md")).contains("outside the repository"));
        assert!(unusable(follow(&dir, "deep.md")).contains("outside the repository"));
        assert!(unusable(follow(&dir, "absolute.md")).contains("absolute"));
        assert!(unusable(follow(&dir, "dangling.md")).contains("not in the commit"));
        assert!(unusable(follow(&dir, "to-dir.md")).contains("not a regular file"));
        assert!(unusable(follow(&dir, "loop-a.md")).contains("loop"));
        assert!(unusable(follow(&dir, "self.md")).contains("loop"));
    }

    #[test]
    fn following_stops_after_a_few_hops() {
        let mut links: Vec<(String, String)> = (0..8)
            .map(|i| (format!("l{i}.md"), format!("l{}.md", i + 1)))
            .collect();
        links.push(("l8.md".into(), "end.md".into()));
        let links: Vec<(&str, &str)> = links
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let dir = repo_with_links(&[("end.md", "end")], &links);
        assert!(unusable(follow(&dir, "l0.md")).contains("more than"));
        // Within the limit it still resolves.
        assert_eq!(follow(&dir, "l6.md"), LinkedFile::Text("end".into()));
    }

    #[test]
    fn following_still_errors_on_a_bad_commit() {
        let dir = repo_with(&[("CLAUDE.md", "x")]);
        assert!(git_show_following_links(dir.path(), "no-such-commit", "CLAUDE.md").is_err());
    }

    #[test]
    fn the_strict_reader_still_refuses_a_link() {
        let dir = repo_with_links(&[("AGENTS.md", "x")], &[("CLAUDE.md", "AGENTS.md")]);
        assert!(git_show_optional(dir.path(), "HEAD", "CLAUDE.md").is_err());
    }
}
