//! Reference runtimes the director grants the verifier (`--runtime-dir`).
//!
//! The verifier's `PATH` is the system directories plus the director's cargo directory, and
//! its sandbox hides the director's home. A reference runtime installed anywhere else (nvm,
//! pyenv, Homebrew under a hidden prefix) reads as missing there, so the held-out cases that
//! need it are skipped. The director can name such a directory, and this module is the one
//! place that decides what a name may be.
//!
//! **Who names the directories.** The director, on the command line (`--runtime-dir`, which
//! repeats) or in `COWPROOF_RUNTIME_DIRS` (colon-separated), read once at startup. Never a
//! repository: not `cowproof.toml`, not the base commit, not a patch. A repository must not
//! choose what of the director's machine the sandbox can read.
//!
//! **What a directory gets.** Each directory is granted read-only (`SandboxPolicy::
//! with_runtime_dirs`, the same class of grant as the rustup home and the cargo bin directory)
//! to the verifier and to the builder's `run_check` sandbox, so the builder's checks and the
//! verifier's agree. Its executables go on `PATH` ahead of the system directories: `<dir>/bin`
//! when the directory has a `bin` subdirectory, else the directory itself when it is named
//! `bin`. A directory that is neither is refused (it has no executable directory to name).
//!
//! **What is refused**, as an error before the lane starts: a relative path or one that does
//! not exist or is not a directory; `/`, the real home and any ancestor of it; a directory that
//! is, or directly holds, a known credential location ([`CREDENTIAL_NAMES`],
//! `.cargo/credentials*`, `Library/Keychains`); and anything that is, holds or lies inside a
//! path the caller protects (the lanes root, the repository, the cowproof cache). That keeps a
//! runtime grant from becoming a home grant.

use crate::canonicalize_for_sandbox;
use anyhow::{Context, Result, anyhow, bail};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The environment variable that names runtime directories, colon-separated.
pub const RUNTIME_DIRS_ENV: &str = "COWPROOF_RUNTIME_DIRS";

/// Names of credential locations. A runtime directory may not have one of these names, and
/// may not directly hold one.
pub const CREDENTIAL_NAMES: [&str; 9] = [
    ".ssh", ".aws", ".gnupg", ".config", ".claude", ".codex", ".docker", ".kube", ".netrc",
];

/// One granted runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDir {
    /// The directory, canonical: what is granted read-only.
    pub dir: PathBuf,
    /// The directory of its executables, canonical: what goes on `PATH`.
    pub path_entry: PathBuf,
}

/// A path the grant must not touch: the caller names it for the message.
#[derive(Debug, Clone, Copy)]
pub struct Protected<'a> {
    pub what: &'a str,
    pub path: &'a Path,
}

/// The directories asked for: `flags` first, then the colon-separated `env` value, in order
/// and without repeats. An empty `env` value names nothing; an empty entry inside a non-empty
/// one is an error (it is not an absolute path).
pub fn requested(flags: &[PathBuf], env: Option<&OsStr>) -> Result<Vec<PathBuf>> {
    let mut asked: Vec<PathBuf> = flags.to_vec();
    if let Some(value) = env.filter(|v| !v.is_empty()) {
        for entry in std::env::split_paths(value) {
            if entry.as_os_str().is_empty() {
                bail!("{RUNTIME_DIRS_ENV} has an empty entry");
            }
            asked.push(entry);
        }
    }
    let mut seen: Vec<PathBuf> = Vec::new();
    asked.retain(|p| {
        let fresh = !seen.contains(p);
        if fresh {
            seen.push(p.clone());
        }
        fresh
    });
    Ok(asked)
}

/// Check and resolve `asked`. The first refused directory is the error, naming it and the
/// rule; nothing is created. `real_home` is the director's home.
pub fn resolve(
    asked: &[PathBuf],
    real_home: &Path,
    protected: &[Protected<'_>],
) -> Result<Vec<RuntimeDir>> {
    let home = canonicalize_for_sandbox(real_home)?;
    let mut shielded = Vec::with_capacity(protected.len());
    for p in protected {
        let absolute = std::path::absolute(p.path)
            .with_context(|| format!("{} {}", p.what, p.path.display()))?;
        shielded.push((p.what, canonicalize_for_sandbox(&absolute)?));
    }
    let mut granted: Vec<RuntimeDir> = Vec::new();
    for path in asked {
        let shown = path.display();
        if !path.is_absolute() {
            bail!("runtime directory {shown} is not an absolute path");
        }
        let dir = std::fs::canonicalize(path)
            .with_context(|| format!("runtime directory {shown} cannot be resolved"))?;
        if !dir.is_dir() {
            bail!("runtime directory {shown} is not a directory");
        }
        refuse(&dir, &home, &shielded)
            .map_err(|why| anyhow!("runtime directory {shown}: {why}"))?;
        let path_entry =
            path_entry(&dir).map_err(|why| anyhow!("runtime directory {shown}: {why}"))?;
        let entry = RuntimeDir { dir, path_entry };
        if !granted.contains(&entry) {
            granted.push(entry);
        }
    }
    Ok(granted)
}

/// Why `dir` (canonical) may not be granted, if it may not.
fn refuse(dir: &Path, home: &Path, protected: &[(&str, PathBuf)]) -> Result<(), String> {
    if dir == Path::new("/") {
        return Err("refused: it is the filesystem root".into());
    }
    if home.starts_with(dir) {
        return Err(format!(
            "refused: it is the home directory {} or holds it",
            home.display()
        ));
    }
    if let Some(name) = dir.file_name().and_then(OsStr::to_str)
        && CREDENTIAL_NAMES.contains(&name)
    {
        return Err(format!("refused: it is a credential location ({name})"));
    }
    if dir.ends_with("Library/Keychains") {
        return Err("refused: it is a credential location (Library/Keychains)".into());
    }
    for name in CREDENTIAL_NAMES {
        if exists(&dir.join(name)) {
            return Err(format!("refused: it holds a credential location ({name})"));
        }
    }
    if exists(&dir.join("Library/Keychains")) {
        return Err("refused: it holds a credential location (Library/Keychains)".into());
    }
    if let Ok(entries) = std::fs::read_dir(dir.join(".cargo")) {
        let credentials = entries
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("credentials"));
        if credentials {
            return Err("refused: it holds a credential location (.cargo/credentials*)".into());
        }
    }
    for (what, path) in protected {
        if dir.starts_with(path) || path.starts_with(dir) {
            return Err(format!(
                "refused: it is, holds or lies inside {what} ({})",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Whether `path` is there, a dangling symlink included.
fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// The directory of `dir`'s executables: `<dir>/bin` when `dir` has a `bin` subdirectory
/// (which must stay inside `dir`, so the grant covers it), else `dir` itself when it is named
/// `bin`.
fn path_entry(dir: &Path) -> Result<PathBuf, String> {
    let sub = dir.join("bin");
    let entry = if sub.is_dir() {
        let resolved = std::fs::canonicalize(&sub).map_err(|e| format!("bin: {e}"))?;
        if !resolved.starts_with(dir) {
            return Err(format!(
                "refused: its bin resolves to {}, outside the directory",
                resolved.display()
            ));
        }
        resolved
    } else if dir.file_name() == Some(OsStr::new("bin")) {
        dir.to_path_buf()
    } else {
        return Err("refused: it has no bin subdirectory and is not itself named bin".into());
    };
    match entry.to_str() {
        Some(s) if !s.contains(':') && !s.chars().any(char::is_control) => Ok(entry),
        _ => Err("refused: its bin directory is not usable on a PATH".into()),
    }
}

/// The directories as text, for `run.json` and the capsule.
pub fn names(dirs: &[RuntimeDir]) -> Vec<String> {
    dirs.iter()
        .map(|d| d.dir.to_string_lossy().into_owned())
        .collect()
}

/// `path` (a `PATH` value) with the runtime executables directories in front, each once.
pub fn prepend_to_path(path: &str, dirs: &[RuntimeDir]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for d in dirs {
        let entry = d.path_entry.to_string_lossy().into_owned();
        if !parts.contains(&entry) {
            parts.push(entry);
        }
    }
    parts.extend(path.split(':').filter(|e| !e.is_empty()).map(String::from));
    parts.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Fx {
        _tmp: TempDir,
        root: PathBuf,
        home: PathBuf,
    }

    fn fx() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        Fx {
            _tmp: tmp,
            root,
            home,
        }
    }

    fn runtime(root: &Path, rel: &str) -> PathBuf {
        let dir = root.join(rel);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/tool"), "#!/bin/sh\n").unwrap();
        dir
    }

    fn err(asked: &[PathBuf], f: &Fx, protected: &[Protected<'_>]) -> String {
        format!("{:#}", resolve(asked, &f.home, protected).unwrap_err())
    }

    #[test]
    fn a_runtime_with_a_bin_directory_names_its_bin() {
        let f = fx();
        let dir = runtime(&f.root, "rt");
        let got = resolve(std::slice::from_ref(&dir), &f.home, &[]).unwrap();
        assert_eq!(
            got,
            [RuntimeDir {
                dir: dir.clone(),
                path_entry: dir.join("bin")
            }]
        );
        assert_eq!(names(&got), [dir.to_string_lossy()]);
    }

    #[test]
    fn a_directory_that_is_itself_named_bin_is_its_own_path_entry() {
        let f = fx();
        let bin = f.root.join("opt/bin");
        fs::create_dir_all(&bin).unwrap();
        let got = resolve(std::slice::from_ref(&bin), &f.home, &[]).unwrap();
        assert_eq!(got[0].dir, bin);
        assert_eq!(got[0].path_entry, bin);
    }

    #[test]
    fn a_directory_with_no_bin_and_not_named_bin_is_refused() {
        let f = fx();
        let dir = f.root.join("plain");
        fs::create_dir_all(&dir).unwrap();
        assert!(err(&[dir], &f, &[]).contains("no bin subdirectory"));
    }

    #[test]
    fn a_bin_that_resolves_outside_the_directory_is_refused() {
        let f = fx();
        let dir = f.root.join("rt");
        let elsewhere = f.root.join("elsewhere");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("bin")).unwrap();
        assert!(err(&[dir], &f, &[]).contains("outside the directory"));
    }

    #[test]
    fn relative_missing_and_file_paths_are_errors() {
        let f = fx();
        assert!(err(&[PathBuf::from("rt")], &f, &[]).contains("not an absolute path"));
        assert!(err(&[f.root.join("nope")], &f, &[]).contains("cannot be resolved"));
        let file = f.root.join("file");
        fs::write(&file, "x").unwrap();
        assert!(err(&[file], &f, &[]).contains("not a directory"));
    }

    #[test]
    fn the_root_the_home_and_an_ancestor_of_the_home_are_refused() {
        let f = fx();
        assert!(err(&[PathBuf::from("/")], &f, &[]).contains("filesystem root"));
        assert!(err(std::slice::from_ref(&f.home), &f, &[]).contains("home directory"));
        assert!(err(std::slice::from_ref(&f.root), &f, &[]).contains("home directory"));
        // A runtime inside the home is fine: that is nvm.
        let inside = runtime(&f.home, ".nvm/node");
        assert_eq!(
            resolve(std::slice::from_ref(&inside), &f.home, &[]).unwrap()[0].dir,
            inside
        );
    }

    #[test]
    fn a_directory_that_is_or_holds_a_credential_location_is_refused() {
        let f = fx();
        for name in CREDENTIAL_NAMES {
            // Itself.
            let itself = f.root.join(format!("a/{name}"));
            fs::create_dir_all(itself.join("bin")).unwrap();
            let why = err(&[itself], &f, &[]);
            assert!(why.contains("credential location"), "{name}: {why}");
            // Holding it, as a directory, a file or a dangling link.
            let holder = runtime(&f.root, &format!("h-{name}"));
            fs::create_dir_all(holder.join(name)).unwrap();
            let why = err(&[holder], &f, &[]);
            assert!(why.contains("holds a credential location"), "{name}: {why}");
        }
        let link = runtime(&f.root, "dangling");
        std::os::unix::fs::symlink("/nonexistent-target", link.join(".ssh")).unwrap();
        assert!(err(&[link], &f, &[]).contains("(.ssh)"));
        let cargo = runtime(&f.root, "cargo-holder");
        fs::create_dir_all(cargo.join(".cargo")).unwrap();
        fs::write(cargo.join(".cargo/credentials.toml"), "x").unwrap();
        assert!(err(&[cargo], &f, &[]).contains(".cargo/credentials*"));
        let lib = runtime(&f.root, "lib-holder");
        fs::create_dir_all(lib.join("Library/Keychains")).unwrap();
        assert!(err(&[lib], &f, &[]).contains("Library/Keychains"));
        let kc = f.root.join("u/Library/Keychains");
        fs::create_dir_all(kc.join("bin")).unwrap();
        assert!(err(&[kc], &f, &[]).contains("Library/Keychains"));
        // A `.cargo` without credentials is not a credential location.
        let ok = runtime(&f.root, "cargo-ok");
        fs::create_dir_all(ok.join(".cargo/bin")).unwrap();
        assert!(resolve(&[ok], &f.home, &[]).is_ok());
    }

    #[test]
    fn protected_paths_are_neither_held_nor_inside_nor_equal() {
        let f = fx();
        let lanes = f.root.join("area/lanes");
        let rt = runtime(&f.root, "area/lanes/inner");
        let p = [Protected {
            what: "the lanes root",
            path: &lanes,
        }];
        assert!(err(&[rt], &f, &p).contains("the lanes root"));
        assert!(err(std::slice::from_ref(&lanes), &f, &p).contains("the lanes root"));
        let area = runtime(&f.root, "area");
        assert!(err(&[area], &f, &p).contains("the lanes root"));
        // A protected path that does not exist yet still counts.
        let later = f.root.join("later/lanes");
        let p = [Protected {
            what: "the lanes root",
            path: &later,
        }];
        let holder = runtime(&f.root, "later");
        assert!(err(&[holder], &f, &p).contains("the lanes root"));
        // And an unrelated runtime passes.
        let fine = runtime(&f.root, "fine");
        assert!(resolve(&[fine], &f.home, &p).is_ok());
    }

    #[test]
    fn requested_joins_flags_then_environment_without_repeats() {
        let flags = [PathBuf::from("/a"), PathBuf::from("/b")];
        let got = requested(&flags, Some(OsStr::new("/b:/c"))).unwrap();
        assert_eq!(
            got,
            [
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c")
            ]
        );
        assert!(requested(&[], Some(OsStr::new(""))).unwrap().is_empty());
        assert!(requested(&[], None).unwrap().is_empty());
        assert!(requested(&[], Some(OsStr::new("/a::/b"))).is_err());
        assert!(requested(&[], Some(OsStr::new("/a:"))).is_err());
    }

    #[test]
    fn the_runtime_bins_go_in_front_of_a_path_once() {
        let f = fx();
        let dir = runtime(&f.root, "rt");
        let got = resolve(std::slice::from_ref(&dir), &f.home, &[]).unwrap();
        let bin = dir.join("bin");
        assert_eq!(
            prepend_to_path("/usr/bin:/bin", &got),
            format!("{}:/usr/bin:/bin", bin.display())
        );
        assert_eq!(prepend_to_path("/usr/bin", &[]), "/usr/bin");
    }
}
