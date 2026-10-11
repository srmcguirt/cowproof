//! The lanes root, in one place. `run::lanes_root` re-exports this function;
//! `cowproof run`, `watch`, `rule`, `note` and the director's MCP tools all
//! reach the same default through it.

use anyhow::{Result, anyhow};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The lanes root: `--lanes-root` relative to the working directory, or
/// `~/.cache/cowproof/lanes` (never under `/tmp`, which macOS cleans by access
/// time). `cowproof run` and `cowproof watch` both use this one default.
pub fn lanes_root(arg: Option<&Path>, cwd: &Path, home: &Path) -> PathBuf {
    match arg {
        Some(p) => cwd.join(p),
        None => home.join(".cache/cowproof/lanes"),
    }
}

/// Resolve an executable by name, searching `PATH` if needed.
///
/// If the name contains a `/`, it is treated as a relative or absolute path
/// from the current working directory. Otherwise, it is searched in the `PATH`
/// environment variable.
pub fn resolve_executable(name: &str, path: &str, cwd: &Path) -> Result<PathBuf> {
    let is_executable = |p: &Path| {
        fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    let candidates: Vec<PathBuf> = if name.contains('/') {
        vec![cwd.join(name)]
    } else {
        path.split(':')
            .filter(|d| !d.is_empty() && Path::new(d).is_absolute())
            .map(|d| Path::new(d).join(name))
            .collect()
    };
    candidates
        .into_iter()
        .find(|c| is_executable(c))
        .ok_or_else(|| anyhow!("cannot find an executable {name:?} on this machine's PATH"))
}

/// [`lanes_root`] for this process: the working directory and `HOME` as they are now.
pub fn current_lanes_root(arg: Option<&Path>) -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);
    Ok(lanes_root(arg, &std::env::current_dir()?, &home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_under_the_cache_and_a_flag_is_relative_to_the_working_directory() {
        let (cwd, home) = (Path::new("/work"), Path::new("/home/u"));
        assert_eq!(
            lanes_root(None, cwd, home),
            Path::new("/home/u/.cache/cowproof/lanes")
        );
        assert_eq!(
            lanes_root(Some(Path::new("l")), cwd, home),
            Path::new("/work/l")
        );
        assert_eq!(
            lanes_root(Some(Path::new("/abs")), cwd, home),
            Path::new("/abs")
        );
    }
}
