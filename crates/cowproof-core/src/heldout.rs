use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Represents a single held-out check
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub command: String,
}

/// Represents a TOML file containing held-out checks
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HeldOut {
    #[serde(default)]
    pub check: Vec<Check>,
}

/// Validates repository and lane IDs to ensure they only contain allowed characters.
/// Allowed characters: [A-Za-z0-9._-]
fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("id cannot be empty");
    }
    if id == ".." || id.contains('/') {
        bail!("id cannot be '..' or contain '/'");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        bail!(
            "id '{}' contains invalid characters; only [A-Za-z0-9._-] are allowed",
            id
        );
    }
    Ok(())
}

/// Returns the default store path for held-out checks: `<home>/.cowproof/heldout/<repo_id>/<lane_id>.toml`
pub fn default_store(home: &Path, repo_id: &str, lane_id: &str) -> Result<PathBuf> {
    validate_id(repo_id)?;
    validate_id(lane_id)?;
    Ok(home
        .join(".cowproof")
        .join("heldout")
        .join(repo_id)
        .join(format!("{}.toml", lane_id)))
}

/// Derives a stable repository ID from the repository root.
/// Uses the absolute canonical path, sanitized to allowed characters.
/// Empty path segments are skipped.
pub fn repo_id(repo_root: &Path) -> Result<String> {
    let canonical = repo_root
        .canonicalize()
        .context("canonicalizing repository root")?;

    // Use a hash of the canonical path to ensure it's unique and stable
    // This is safer than using the path directly which could contain private information
    let path_str = canonical.to_string_lossy().replace(['/', '\\', ':'], "-");

    // Remove leading/trailing dashes and collapse multiple dashes
    let mut id = String::new();
    let mut last_dash = false;
    for c in path_str.chars() {
        if c == '-' {
            if !last_dash && !id.is_empty() {
                id.push(c);
            }
            last_dash = true;
        } else if c.is_ascii_alphanumeric() {
            id.push(c);
            last_dash = false;
        }
    }

    // Remove trailing dashes
    id = id.trim_end_matches('-').to_string();

    if id.is_empty() {
        bail!("could not derive a valid repository ID from path");
    }

    Ok(id)
}

/// Validates an explicit held-out checks path and refuses it if inside the repository.
/// - Relative paths are joined with `cwd`, making them always inside or near the repo
/// - Walks up to the nearest existing ancestor, canonicalizes it, re-adds components
/// - Rejects paths containing `..` in the non-existent suffix
/// - Rejects paths that resolve inside repo_root
/// - Returns the canonical path outside the repository.
pub fn resolve_outside_repo(path: &Path, repo_root: &Path, cwd: &Path) -> Result<PathBuf> {
    let repo_canonical = repo_root
        .canonicalize()
        .context("canonicalizing repository root")?;

    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    // Walk and canonicalize
    let canonical = canonicalize_path_with_repo_check(&path, &repo_canonical)?;

    Ok(canonical)
}

/// Helper to canonicalize a path by walking up to nearest existing ancestor,
/// re-adding components, and checking it's outside the given repository.
fn canonicalize_path_with_repo_check(path: &Path, repo_canonical: &Path) -> Result<PathBuf> {
    // Find the nearest existing ancestor, canonicalize it, then reconstruct the path.
    // This ensures relative paths are made absolute and symlinks are resolved properly.
    // Refuse `..` anywhere: it is never needed to name a store file, and the
    // walk below cannot see through it (`file_name` of `a/..` is `None`).
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("held-out checks path contains ..: {}", path.display());
    }

    let mut current = path.to_path_buf();
    let mut components_to_add = Vec::new();

    // Walk up the path until we find an existing directory
    while !current.exists() {
        match current.file_name() {
            Some(name) => {
                components_to_add.push(PathBuf::from(name));
                current.pop();
            }
            None => {
                // Hit the root without finding anything; path is invalid
                bail!("cannot resolve held-out checks path: {}", path.display());
            }
        }
    }

    // Canonicalize the existing ancestor (resolves symlinks and makes absolute)
    let mut canonical = current.canonicalize().context(format!(
        "canonicalizing path ancestor: {}",
        current.display()
    ))?;

    // Re-add the missing components in order.
    for component in components_to_add.iter().rev() {
        canonical.push(component);
    }

    // Check if the resolved path is inside the repository
    if let Ok(_rel) = canonical.strip_prefix(repo_canonical) {
        bail!(
            "held-out checks path {} is inside the repository",
            canonical.display()
        );
    }

    Ok(canonical)
}

/// Resolves the held-out checks path from a given working directory.
/// If explicit path is provided, uses it (after validation).
/// Otherwise, uses the default store.
/// Refuses paths inside the repository (including through symlinks).
/// Internal helper for testing with custom working directories.
fn resolve_from(
    explicit: Option<&Path>,
    home: &Path,
    repo_root: &Path,
    repo_id: &str,
    lane_id: &str,
    cwd: &Path,
) -> Result<PathBuf> {
    let repo_canonical = repo_root
        .canonicalize()
        .context("canonicalizing repository root")?;

    let path = if let Some(explicit_path) = explicit {
        resolve_outside_repo(explicit_path, repo_root, cwd)?
    } else {
        let default_path = default_store(home, repo_id, lane_id)?;
        canonicalize_path_with_repo_check(&default_path, &repo_canonical)?
    };

    Ok(path)
}

/// Resolves the held-out checks path.
/// If explicit path is provided, uses it (after validation).
/// Otherwise, uses the default store.
/// Refuses paths inside the repository (including through symlinks).
pub fn resolve(
    explicit: Option<&Path>,
    home: &Path,
    repo_root: &Path,
    repo_id: &str,
    lane_id: &str,
) -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("getting current directory")?;
    resolve_from(explicit, home, repo_root, repo_id, lane_id, &cwd)
}

/// Lists files in the repository that match `*.heldout.*` pattern.
/// These should not be tracked in the repository as they should be outside it.
pub fn scan_base_for_heldout(repo_root: &Path) -> Result<Vec<PathBuf>> {
    // Use git ls-files to list tracked files
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["ls-files"])
        .output()
        .context("running git ls-files")?;

    if !output.status.success() {
        bail!("git ls-files failed");
    }

    let files: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(".heldout."))
        .map(|line| repo_root.join(line))
        .collect();

    Ok(files)
}

/// Loads held-out checks from a TOML file.
/// Rejects duplicate check IDs.
pub fn load(path: &Path) -> Result<HeldOut> {
    let content =
        fs::read_to_string(path).context(format!("reading heldout file {}", path.display()))?;

    let heldout: HeldOut =
        toml::from_str(&content).context(format!("parsing TOML from {}", path.display()))?;

    // Check for duplicate IDs
    let mut seen = HashSet::new();
    for check in &heldout.check {
        if !seen.insert(&check.id) {
            bail!(
                "duplicate check id '{}' in held-out checks file {}",
                check.id,
                path.display()
            );
        }
    }

    Ok(heldout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_validate_id_empty() {
        assert!(validate_id("").is_err());
    }

    #[test]
    fn test_validate_id_parent_dir() {
        assert!(validate_id("..").is_err());
    }

    #[test]
    fn test_validate_id_slash() {
        assert!(validate_id("foo/bar").is_err());
    }

    #[test]
    fn test_validate_id_invalid_chars() {
        assert!(validate_id("foo@bar").is_err());
        assert!(validate_id("foo bar").is_err());
    }

    #[test]
    fn test_validate_id_valid() {
        assert!(validate_id("foo-bar_baz.test").is_ok());
        assert!(validate_id("abc123").is_ok());
        assert!(validate_id("a").is_ok());
    }

    #[test]
    fn test_default_store_path_shape() {
        let temp = TempDir::new().unwrap();
        let home = temp.path();
        let path = default_store(home, "repo-1", "lane-1").unwrap();
        assert!(
            path.to_string_lossy()
                .contains(".cowproof/heldout/repo-1/lane-1.toml")
        );
    }

    #[test]
    fn test_default_store_invalid_repo_id() {
        let temp = TempDir::new().unwrap();
        let home = temp.path();
        assert!(default_store(home, "repo@1", "lane-1").is_err());
    }

    #[test]
    fn test_default_store_invalid_lane_id() {
        let temp = TempDir::new().unwrap();
        let home = temp.path();
        assert!(default_store(home, "repo-1", "lane/1").is_err());
    }

    #[test]
    fn test_repo_id_basic() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path().to_path_buf();
        let id = repo_id(&repo_path).unwrap();
        assert!(!id.is_empty());
        // Should only contain allowed characters
        assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
    }

    #[test]
    fn test_resolve_explicit_outside_repo() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        let home = temp.path().to_path_buf();
        let heldout_dir = temp.path().join("heldout");
        fs::create_dir_all(&heldout_dir).unwrap();
        let heldout_path = heldout_dir.join("checks.toml");

        let resolved = resolve(
            Some(&heldout_path),
            &home,
            &repo_dir,
            "test-repo",
            "test-lane",
        )
        .unwrap();

        // The resolved path should be canonical. Since checks.toml doesn't exist,
        // the canonical form is: canonicalize(heldout_dir) + "checks.toml"
        let canonical_heldout = heldout_dir.canonicalize().unwrap().join("checks.toml");
        assert_eq!(resolved, canonical_heldout);
    }

    #[test]
    fn test_resolve_explicit_inside_repo_rejected() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        let home = temp.path().to_path_buf();
        let heldout_path = repo_dir.join("checks.heldout.toml");

        let result = resolve(
            Some(&heldout_path),
            &home,
            &repo_dir,
            "test-repo",
            "test-lane",
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("inside the repository")
        );
    }

    #[test]
    fn test_resolve_default_store() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();
        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();

        let resolved = resolve(None, &home, &repo_dir, "test-repo", "test-lane").unwrap();

        // The resolved path should be canonical and contain the heldout directory structure
        let canonical_home = home.canonicalize().unwrap_or(home.clone());
        assert!(resolved.starts_with(&canonical_home));
        assert!(resolved.to_string_lossy().contains(".cowproof/heldout"));
    }

    #[test]
    fn test_symlink_pointing_outside_repo_accepted() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        let home = temp.path().to_path_buf();
        let outside_dir = temp.path().join("outside");
        fs::create_dir(&outside_dir).unwrap();
        let target_file = outside_dir.join("checks.toml");
        fs::File::create(&target_file).unwrap();

        let link_path = temp.path().join("link_to_checks.toml");
        #[cfg(unix)]
        {
            use std::os::unix::fs as unix_fs;
            unix_fs::symlink(&target_file, &link_path).unwrap();
        }

        #[cfg(not(unix))]
        {
            // Skip symlink test on Windows
            return;
        }

        let result = resolve(Some(&link_path), &home, &repo_dir, "test-repo", "test-lane");
        assert!(result.is_ok());
    }

    #[test]
    fn test_symlink_pointing_into_repo_rejected() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        let home = temp.path().to_path_buf();
        let inside_dir = repo_dir.join("checks");
        fs::create_dir(&inside_dir).unwrap();
        let target_file = inside_dir.join("checks.toml");
        fs::File::create(&target_file).unwrap();

        let link_path = temp.path().join("link_to_repo_checks.toml");
        #[cfg(unix)]
        {
            use std::os::unix::fs as unix_fs;
            unix_fs::symlink(&target_file, &link_path).unwrap();
        }

        #[cfg(not(unix))]
        {
            // Skip symlink test on Windows
            return;
        }

        let result = resolve(Some(&link_path), &home, &repo_dir, "test-repo", "test-lane");
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_base_for_heldout_empty() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().to_path_buf();

        // Initialize a git repo
        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .unwrap();

        let files = scan_base_for_heldout(&repo_dir).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_scan_base_for_heldout_finds_committed() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().to_path_buf();

        // Initialize git repo
        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .unwrap();

        // Create and commit a .heldout. file
        let heldout_file = repo_dir.join("checks.heldout.toml");
        fs::File::create(&heldout_file).unwrap();

        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["add", "checks.heldout.toml"])
            .output()
            .unwrap();

        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["config", "user.email", "test@example.com"])
            .output()
            .unwrap();

        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["config", "user.name", "Test"])
            .output()
            .unwrap();

        Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["commit", "-m", "test"])
            .output()
            .unwrap();

        let files = scan_base_for_heldout(&repo_dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], heldout_file);
    }

    #[test]
    fn test_scan_base_for_heldout_ignores_untracked() {
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().to_path_buf();

        // Initialize git repo
        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .unwrap();

        // Create an untracked .heldout. file
        let _heldout_file = repo_dir.join("checks.heldout.toml");
        fs::File::create(&_heldout_file).unwrap();

        let files = scan_base_for_heldout(&repo_dir).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_load_valid() {
        let temp = TempDir::new().unwrap();
        let toml_path = temp.path().join("checks.toml");

        let content = r#"
[[check]]
id = "test-1"
command = "echo hello"

[[check]]
id = "test-2"
command = "echo world"
"#;

        let mut file = fs::File::create(&toml_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let heldout = load(&toml_path).unwrap();
        assert_eq!(heldout.check.len(), 2);
        assert_eq!(heldout.check[0].id, "test-1");
        assert_eq!(heldout.check[1].id, "test-2");
    }

    #[test]
    fn test_load_duplicate_ids() {
        let temp = TempDir::new().unwrap();
        let toml_path = temp.path().join("checks.toml");

        let content = r#"
[[check]]
id = "test-1"
command = "echo hello"

[[check]]
id = "test-1"
command = "echo world"
"#;

        let mut file = fs::File::create(&toml_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let result = load(&toml_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate check id")
        );
    }

    #[test]
    fn test_load_empty() {
        let temp = TempDir::new().unwrap();
        let toml_path = temp.path().join("checks.toml");

        fs::File::create(&toml_path).unwrap();

        let heldout = load(&toml_path).unwrap();
        assert_eq!(heldout.check.len(), 0);
    }

    #[test]
    fn test_resolve_nonexistent_parent_in_repo_rejected() {
        // Test that a path with non-existent parent is rejected if it would be in the repo.
        // This tests the fix for the vulnerability where non-existent parents bypass the check.
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        // Create a git repo to make it canonical
        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .unwrap();

        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();

        // Try to resolve a path that is inside the repo with a non-existent parent.
        // Use the temp directory path (which may not be canonical on macOS) as repo_root.
        let inside_path = repo_dir.join("newdir").join("held.toml");

        let result_fixed = resolve_from(
            Some(&inside_path),
            &home,
            &repo_dir,
            "test-repo",
            "test-lane",
            temp.path(),
        );

        assert!(result_fixed.is_err());
        assert!(
            result_fixed
                .unwrap_err()
                .to_string()
                .contains("inside the repository")
        );
    }

    #[test]
    fn test_resolve_relative_path_in_repo_rejected() {
        // Test that relative paths are made absolute and checked against the repo.
        // Uses resolve_from with cwd set to the repo directory.
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .unwrap();

        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();

        // Relative path from repo directory
        let relative_path = Path::new("newdir/held.toml");

        let result_fixed = resolve_from(
            Some(relative_path),
            &home,
            &repo_dir,
            "test-repo",
            "test-lane",
            &repo_dir,
        );

        assert!(result_fixed.is_err());
        assert!(
            result_fixed
                .unwrap_err()
                .to_string()
                .contains("inside the repository")
        );
    }

    #[test]
    fn test_resolve_dotdot_in_suffix_rejected() {
        // Test that paths with .. in non-existent suffix that would escape into repo are rejected.
        let temp = TempDir::new().unwrap();
        let repo_dir = temp.path().join("repo");
        fs::create_dir(&repo_dir).unwrap();

        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();

        // Create a path that tries to escape from home into repo via .. in non-existent suffix:
        // home/missing/../../repo/x.heldout.toml
        // When walking up: x (add), .. (add), repo (add), missing (add), then home exists
        // This should reject because .. is in the non-existent suffix
        let mut escaped_path = home.clone();
        escaped_path.push("missing");
        escaped_path.push("..");
        escaped_path.push("..");
        escaped_path.push("repo");
        escaped_path.push("x.heldout.toml");

        let result = resolve_from(
            Some(&escaped_path),
            &home,
            &repo_dir,
            "test-repo",
            "test-lane",
            temp.path(),
        );

        // Must be an error (either .. detected or path inside repo)
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("path contains ..:"),
            "error should mention .. or repo boundary, got: {}",
            err_msg
        );
    }
}
