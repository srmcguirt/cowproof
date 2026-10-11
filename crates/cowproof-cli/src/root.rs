//! The lanes root, in one place. `run::lanes_root` re-exports this function;
//! `cowproof run`, `watch`, `rule`, `note` and the director's MCP tools all
//! reach the same default through it.

use anyhow::{Result, anyhow};
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
