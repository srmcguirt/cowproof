//! The verifier's own compile cache: a seed cargo target directory, built from the BASE
//! commit and never written by a builder or by any verification (R3, D11).
//!
//! # The threat
//!
//! A lane's tree is untrusted. Its `build.rs`, procedural macros and tests run in the
//! verifier. A compile cache that one verification writes and a later one reads would let a
//! lane plant an artifact (a rebuilt dependency `.rlib`, a fingerprint) that another lane's
//! proof silently uses, and that proof would no longer be of the code it names. So no
//! verification ever writes a cache another reads.
//!
//! # The shape that closes it
//!
//! * **The seed** is the `target/` that `cargo test --workspace --locked --offline --no-run`
//!   ([`SEED_COMMAND`]) leaves after compiling the base commit's tree, with the lane's
//!   dependency cache entry, in the verifier sandbox (no network, dependencies read-only). It
//!   is built from the base, never from a lane's patch.
//! * **Where**: `<cache root>/verify-target/<key>/target`, next to the same `.last-used`
//!   marker and per-pid `leases/` a dependency entry has ([`crate::cache`]), pruned by the same
//!   `cowproof cache prune`. The key ([`key`]) hashes the base tree, the dependency cache key,
//!   `rustc -vV`, the host triple and the seed command.
//! * **A miss** builds in a private `deps-work/<pid>-<nanos>` and moves the finished directory
//!   into place with one rename ([`install`]), so a concurrent verification sees either no
//!   seed or a whole one. Two builders racing for one key keep the first; the other drops its
//!   copy and uses the winner's.
//! * **Every verification gets a private copy** ([`copy_tree`]) inside its own scratch and
//!   points `CARGO_TARGET_DIR` at it. The copy is made by the verifier outside any sandbox, with
//!   copy-on-write (`clonefile` on macOS, `FICLONE` on Linux) where the filesystem has it and
//!   bytes otherwise, never a hardlink: cargo rewrites files in place. The seed is not granted to
//!   any sandbox, readable or writable. The copy goes with the verifier's scratch.
//!
//! The cache is an optimisation of the verifier's own build and never part of a verdict. It
//! is switched off with `COWPROOF_VERIFY_CACHE=off` ([`Mode`]), and a seed that cannot be
//! made leaves the verification exactly as it was without one.

use crate::cache::{self, Alive, Area};
use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The environment variable that switches the seed off (`off`) or on (`on`, the default).
/// Read once at startup, like the other `COWPROOF_*` settings.
pub const MODE_ENV: &str = "COWPROOF_VERIFY_CACHE";

/// The command that builds a seed: every target of the workspace, with the test profile's
/// dependencies, compiled but not run. The same command, with the same flags, runs in the
/// verifier's sandbox as one step.
pub const SEED_COMMAND: &str = "cargo test --workspace --locked --offline --no-run";

/// The variable every check of a verification with a seed gets, naming its private copy.
pub const TARGET_DIR_ENV: &str = "CARGO_TARGET_DIR";

/// The directory inside a seed entry that holds the cargo target directory.
pub const TARGET: &str = "target";

/// Whether the verifier builds and uses a seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Build a seed on a miss and verify against a copy of it (the default).
    On,
    /// No seed, no `CARGO_TARGET_DIR`: the verifier builds in the rebuilt tree's own `target/`.
    Off,
}

impl Mode {
    /// The mode `COWPROOF_VERIFY_CACHE` names: unset or empty is `on`; `on` and `off` (any
    /// case) are themselves; anything else is an error, so a typo never silently leaves the
    /// cache on.
    pub fn from_env() -> Result<Mode> {
        Self::parse(std::env::var_os(MODE_ENV))
    }

    fn parse(value: Option<OsString>) -> Result<Mode> {
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            return Ok(Mode::On);
        };
        match value.to_str().map(str::to_ascii_lowercase).as_deref() {
            Some("on") => Ok(Mode::On),
            Some("off") => Ok(Mode::Off),
            _ => bail!(
                "{MODE_ENV} must be `on` or `off`, not {:?}",
                value.to_string_lossy()
            ),
        }
    }
}

/// Everything a seed's key hashes.
#[derive(Debug, Clone, Copy)]
pub struct KeyInputs<'a> {
    /// The base commit's tree hash.
    pub base_tree_hash: &'a str,
    /// The dependency cache key the build mounts, when the tree has one.
    pub dependency_key: Option<&'a str>,
    /// The output of `rustc -vV`.
    pub rustc_vv: &'a str,
    /// The host triple.
    pub host: &'a str,
    /// The command that builds the seed ([`SEED_COMMAND`]).
    pub command: &'a str,
}

/// The seed's key: 64 lowercase hex digits (the shape [`cache::is_key`] accepts), the SHA-256
/// of every input, each with its name and length so no two inputs run together.
pub fn key(inputs: &KeyInputs) -> String {
    let mut hash = Sha256::new();
    hash.update(b"cowproof verify-target v1\n");
    let fields: [(&str, &str); 5] = [
        ("base_tree_hash", inputs.base_tree_hash),
        ("dependency_key", inputs.dependency_key.unwrap_or("")),
        ("rustc_vv", inputs.rustc_vv),
        ("host", inputs.host),
        ("command", inputs.command),
    ];
    for (name, value) in fields {
        hash.update(format!("{name}={}:", value.len()).as_bytes());
        hash.update(value.as_bytes());
        hash.update(b"\n");
    }
    format!("{:x}", hash.finalize())
}

/// The host triple `rustc -vV` reports (its `host:` line), when it has one.
pub fn host_triple(rustc_vv: &str) -> Option<String> {
    rustc_vv
        .lines()
        .find_map(|l| l.strip_prefix("host:"))
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

/// The directory of one seed entry.
pub fn entry_dir(cache_root: &Path, key: &str) -> PathBuf {
    cache_root.join(Area::VerifyTarget.dir()).join(key)
}

/// The cargo target directory inside the entry `entry`: what a verification copies.
pub fn seed_target(entry: &Path) -> PathBuf {
    entry.join(TARGET)
}

/// An entry is complete when it holds its `target` directory. The rename that installs it is
/// the only moment it appears, so it is whole or absent.
fn complete(entry: &Path) -> bool {
    fs::symlink_metadata(seed_target(entry)).is_ok_and(|m| m.is_dir())
}

/// What [`lookup`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A complete seed: this process holds a lease on it and the use marker is touched.
    Hit,
    /// None.
    Absent,
}

/// Look for the seed `key` and, when it is there, use it: take this process's lease and touch
/// the use marker ([`cache::claim`], the same call a dependency hit makes), so a prune neither
/// removes a seed a verification is about to copy nor mistakes it for unused. An entry a prune
/// removed between the look and the claim is looked at again. A directory that is not a
/// complete seed is an error naming it, never replaced.
pub fn lookup(cache_root: &Path, key: &str, alive: Alive) -> Result<Lookup> {
    let entry = entry_dir(cache_root, key);
    for _ in 0..3 {
        match fs::symlink_metadata(&entry) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Lookup::Absent),
            Err(e) => return Err(e.into()),
            Ok(_) if !complete(&entry) => bail!(
                "the compile-cache seed {} exists but is incomplete; remove it",
                entry.display()
            ),
            Ok(_) => {}
        }
        match cache::claim(&entry, std::process::id(), alive) {
            Ok(()) => return Ok(Lookup::Hit),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => bail!(
                "could not record the use of the compile-cache seed {}: {e}",
                entry.display()
            ),
        }
    }
    Ok(Lookup::Absent)
}

/// How [`install`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    /// This call put its seed in place.
    Built,
    /// Another verification installed the same key first; this call's copy was dropped and the
    /// winner's is used. A hit, as far as the caller is concerned.
    Existing,
}

/// Move a finished seed into the cache. `fresh` is a directory holding the built `target`
/// directory; it becomes `verify-target/<key>` in one rename, so a concurrent verification
/// sees either no entry or a whole one, never half of one. If another installed the same key
/// first the rename fails, that entry is complete, and `fresh` is removed: two builders racing
/// for a key keep one sound seed. Either way the entry is then claimed, as a hit is.
pub fn install(fresh: &Path, cache_root: &Path, key: &str, alive: Alive) -> Result<Installed> {
    if !complete(fresh) {
        bail!(
            "{} holds no `{TARGET}` directory to install",
            fresh.display()
        );
    }
    let entry = entry_dir(cache_root, key);
    let outcome = match fs::rename(fresh, &entry) {
        Ok(()) => Installed::Built,
        Err(e) => {
            if complete(&entry) {
                let _ = cowproof_core::fsutil::remove_tree(fresh);
                Installed::Existing
            } else {
                return Err(anyhow!(e).context(format!("moving the seed to {}", entry.display())));
            }
        }
    };
    cache::claim(&entry, std::process::id(), alive).map_err(|e| {
        anyhow!(
            "could not record the use of the compile-cache seed {}: {e}",
            entry.display()
        )
    })?;
    Ok(outcome)
}

/// How a seed was copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    /// Every file was a copy-on-write clone.
    Clone,
    /// At least one file was copied byte by byte (the filesystem cannot clone, or the copy is
    /// across filesystems).
    Copy,
}

impl CopyMethod {
    /// The word the capsule records.
    pub fn name(self) -> &'static str {
        match self {
            CopyMethod::Clone => "clone",
            CopyMethod::Copy => "copy",
        }
    }
}

/// Copy the directory `src` to `dst`, which must not exist: a private, independent copy that
/// the caller may change in place without touching `src`.
///
/// Copy-on-write where the filesystem has it: on macOS one `clonefile(2)` of the whole tree,
/// on Linux a `FICLONE` of each file (a reflink on btrfs, XFS and the like). Bytes otherwise,
/// file by file. Never a hardlink and never a symlink to `src`: cargo rewrites target files in
/// place, and a link would let that reach the seed. Directories, regular files and symlinks
/// are copied (a symlink as a symlink); permissions and modification times are kept, because
/// cargo's freshness check compares them. Any other kind of file is an error.
pub fn copy_tree(src: &Path, dst: &Path) -> io::Result<CopyMethod> {
    copy_tree_with(src, dst, true)
}

/// [`copy_tree`], with copy-on-write switched off when `clone` is false (the byte-copy path,
/// which a test must reach on a filesystem that could clone).
fn copy_tree_with(src: &Path, dst: &Path, clone: bool) -> io::Result<CopyMethod> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", dst.display()),
        ));
    }
    if clone && clone_whole(src, dst).is_ok() {
        return Ok(CopyMethod::Clone);
    }
    // A failed whole-tree clone leaves nothing, but be sure before copying by hand.
    if fs::symlink_metadata(dst).is_ok() {
        remove_all(dst)?;
    }
    let mut stats = Stats::default();
    let result = copy_dir(src, dst, clone, &mut stats);
    if result.is_err() {
        let _ = remove_all(dst);
    }
    result?;
    Ok(if stats.files > 0 && stats.cloned == stats.files {
        CopyMethod::Clone
    } else {
        CopyMethod::Copy
    })
}

/// Remove a copy (or a part of one) whatever modes it holds: [`cowproof_core::fsutil::remove_tree`].
fn remove_all(path: &Path) -> io::Result<()> {
    cowproof_core::fsutil::remove_tree(path)
}

#[derive(Default)]
struct Stats {
    files: u64,
    cloned: u64,
}

#[cfg(target_os = "macos")]
fn clone_whole(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path holds a NUL"))
    };
    let (src, dst) = (c(src)?, c(dst)?);
    // SAFETY: both pointers are NUL-terminated strings that outlive the call.
    if unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn clone_whole(_src: &Path, _dst: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

fn copy_dir(src: &Path, dst: &Path, clone: bool, stats: &mut Stats) -> io::Result<()> {
    let meta = fs::metadata(src)?;
    // Created writable (the umask's default), so its children can be written whatever mode the
    // source has; the source's mode is restored last.
    fs::create_dir(dst)?;
    for item in fs::read_dir(src)? {
        let item = item?;
        let from = item.path();
        let to = dst.join(item.file_name());
        let kind = item.file_type()?;
        if kind.is_dir() {
            copy_dir(&from, &to, clone, stats)?;
        } else if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&from)?, &to)?;
        } else if kind.is_file() {
            stats.files += 1;
            if copy_file(&from, &to, clone)? {
                stats.cloned += 1;
            }
        } else {
            return Err(io::Error::other(format!(
                "{} is neither a file, a directory nor a symlink",
                from.display()
            )));
        }
    }
    // The modification time first, then the mode: a read-only directory cannot be changed
    // once it is read-only, and its children are all written by now.
    fs::File::open(dst)?.set_modified(meta.modified()?)?;
    fs::set_permissions(dst, meta.permissions())
}

/// Copy the regular file `src` to the new file `dst`, keeping its mode and modification time.
/// `true` when the data was cloned, not copied.
fn copy_file(src: &Path, dst: &Path, clone: bool) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(src)?;
    let cloned = clone && clone_file(src, dst, &meta)?;
    if !cloned {
        fs::copy(src, dst)?;
    }
    // The modification time first, through a writable file, then the mode: opening a 0444 file
    // for writing fails, so the file is writable (to its owner) only until the time is set.
    fs::set_permissions(
        dst,
        fs::Permissions::from_mode(meta.permissions().mode() | 0o600),
    )?;
    fs::File::options()
        .write(true)
        .open(dst)?
        .set_modified(meta.modified()?)?;
    fs::set_permissions(dst, meta.permissions())?;
    Ok(cloned)
}

#[cfg(target_os = "macos")]
fn clone_file(src: &Path, dst: &Path, _meta: &fs::Metadata) -> io::Result<bool> {
    // The whole-tree clone failed, so the filesystem very likely cannot clone; try the file
    // anyway (a tree on two volumes) and fall back to bytes.
    Ok(clone_whole(src, dst).is_ok())
}

#[cfg(target_os = "linux")]
fn clone_file(src: &Path, dst: &Path, meta: &fs::Metadata) -> io::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    /// `_IOW(0x94, 9, int)`: clone the data of one file into another.
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let from = fs::File::open(src)?;
    let to = fs::File::options()
        .write(true)
        .create_new(true)
        .mode(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777)
        .open(dst)?;
    // SAFETY: both descriptors are open for the call.
    let done = unsafe { libc::ioctl(to.as_raw_fd(), FICLONE as _, from.as_raw_fd()) } == 0;
    if !done {
        // The file stays, empty; the caller copies the bytes over it.
        drop(to);
        fs::remove_file(dst)?;
    }
    Ok(done)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn clone_file(_src: &Path, _dst: &Path, _meta: &fs::Metadata) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    const LIVE: u32 = 4_100_001;

    fn alive(pid: u32) -> bool {
        pid == LIVE || pid == std::process::id()
    }

    /// A temp dir under /var/tmp, never the real home or cache.
    fn tmp() -> TempDir {
        fs::create_dir_all("/var/tmp").unwrap();
        tempfile::Builder::new()
            .prefix("cp-vt-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    fn inputs<'a>() -> KeyInputs<'a> {
        KeyInputs {
            base_tree_hash: "1111111111111111111111111111111111111111",
            dependency_key: Some("dep"),
            rustc_vv: "rustc 1.90.0\nhost: aarch64-apple-darwin\n",
            host: "aarch64-apple-darwin",
            command: SEED_COMMAND,
        }
    }

    #[test]
    fn the_key_is_a_cache_key_and_depends_on_every_input() {
        let base = key(&inputs());
        assert!(cache::is_key(&base), "{base}");
        assert_eq!(base, key(&inputs()), "the same inputs, the same key");
        let changed: [(&str, KeyInputs); 5] = [
            (
                "base tree",
                KeyInputs {
                    base_tree_hash: "2222222222222222222222222222222222222222",
                    ..inputs()
                },
            ),
            (
                "dependency key",
                KeyInputs {
                    dependency_key: Some("other"),
                    ..inputs()
                },
            ),
            (
                "rustc -vV",
                KeyInputs {
                    rustc_vv: "rustc 1.91.0\nhost: aarch64-apple-darwin\n",
                    ..inputs()
                },
            ),
            (
                "host triple",
                KeyInputs {
                    host: "x86_64-unknown-linux-gnu",
                    ..inputs()
                },
            ),
            (
                "command",
                KeyInputs {
                    command: "cargo test --workspace --no-run",
                    ..inputs()
                },
            ),
        ];
        for (what, other) in changed {
            assert_ne!(base, key(&other), "the key ignores the {what}");
        }
        // No dependency entry is not the same as an entry named "".
        assert_ne!(
            key(&KeyInputs {
                dependency_key: None,
                ..inputs()
            }),
            key(&KeyInputs {
                dependency_key: Some("dep"),
                ..inputs()
            })
        );
        // Inputs do not run together: moving a character across a field edge is another key.
        assert_ne!(
            key(&KeyInputs {
                host: "ab",
                command: "c",
                ..inputs()
            }),
            key(&KeyInputs {
                host: "a",
                command: "bc",
                ..inputs()
            })
        );
    }

    #[test]
    fn the_host_triple_is_read_from_rustc_vv() {
        assert_eq!(
            host_triple(
                "rustc 1.90.0\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: 1.90.0\n"
            )
            .as_deref(),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(host_triple("rustc 1.90.0\n"), None);
        assert_eq!(host_triple("host:   \n"), None);
    }

    #[test]
    fn the_mode_reads_on_off_and_refuses_a_typo() {
        let parse = |v: Option<&str>| Mode::parse(v.map(OsString::from));
        assert_eq!(parse(None).unwrap(), Mode::On);
        assert_eq!(parse(Some("")).unwrap(), Mode::On);
        assert_eq!(parse(Some("on")).unwrap(), Mode::On);
        assert_eq!(parse(Some("off")).unwrap(), Mode::Off);
        assert_eq!(parse(Some("OFF")).unwrap(), Mode::Off);
        let err = parse(Some("of")).unwrap_err().to_string();
        assert!(
            err.contains(MODE_ENV) && err.contains("`on` or `off`"),
            "{err}"
        );
    }

    /// A built-looking directory `<work>/new/target` holding `files`.
    fn fresh(work: &Path, files: &[(&str, &str)]) -> PathBuf {
        let new = work.join("new");
        fs::create_dir_all(new.join(TARGET)).unwrap();
        for (name, content) in files {
            let path = new.join(TARGET).join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        new
    }

    fn root(tmp: &TempDir) -> PathBuf {
        let root = tmp.path().join("cache");
        fs::create_dir_all(root.join(cache::VERIFY_TARGET)).unwrap();
        fs::create_dir_all(root.join(cache::DEPS_WORK)).unwrap();
        fs::write(root.join(cache::MARKER), cache::MARKER_BODY).unwrap();
        root
    }

    #[test]
    fn an_installed_seed_is_found_claimed_and_leased() {
        let t = tmp();
        let root = root(&t);
        let key = key(&inputs());
        assert_eq!(lookup(&root, &key, &alive).unwrap(), Lookup::Absent);
        let new = fresh(t.path(), &[("debug/app", "binary")]);
        assert_eq!(
            install(&new, &root, &key, &alive).unwrap(),
            Installed::Built
        );
        let entry = entry_dir(&root, &key);
        assert_eq!(
            fs::read_to_string(seed_target(&entry).join("debug/app")).unwrap(),
            "binary"
        );
        // The install is a use: the lease and the marker are there.
        assert!(
            entry
                .join(cache::LEASES)
                .join(std::process::id().to_string())
                .is_file()
        );
        assert!(entry.join(cache::LAST_USED).is_file());
        assert_eq!(lookup(&root, &key, &alive).unwrap(), Lookup::Hit);
    }

    #[test]
    fn an_incomplete_directory_is_an_error_not_a_miss() {
        let t = tmp();
        let root = root(&t);
        let key = key(&inputs());
        fs::create_dir_all(entry_dir(&root, &key)).unwrap();
        let err = lookup(&root, &key, &alive).unwrap_err().to_string();
        assert!(err.contains("incomplete"), "{err}");
    }

    #[test]
    fn builders_racing_for_one_key_leave_one_sound_seed() {
        let t = tmp();
        let root = root(&t);
        let key = key(&inputs());
        let gate = AtomicBool::new(false);
        let built = AtomicUsize::new(0);
        let existing = AtomicUsize::new(0);
        let n = 8;
        std::thread::scope(|scope| {
            for i in 0..n {
                let (root, key, gate, built, existing) = (&root, &key, &gate, &built, &existing);
                let work = t.path().join(format!("work-{i}"));
                scope.spawn(move || {
                    fs::create_dir_all(&work).unwrap();
                    // Every builder makes a different, complete, multi-file seed.
                    let files: Vec<(String, String)> = (0..20)
                        .map(|f| (format!("debug/deps/f{f}"), format!("builder {i} file {f}")))
                        .collect();
                    let refs: Vec<(&str, &str)> = files
                        .iter()
                        .map(|(a, b)| (a.as_str(), b.as_str()))
                        .collect();
                    let new = fresh(&work, &refs);
                    while !gate.load(Ordering::SeqCst) {
                        std::thread::yield_now();
                    }
                    match install(&new, root, key, &alive).unwrap() {
                        Installed::Built => built.fetch_add(1, Ordering::SeqCst),
                        Installed::Existing => existing.fetch_add(1, Ordering::SeqCst),
                    };
                });
            }
            gate.store(true, Ordering::SeqCst);
        });
        assert_eq!(built.load(Ordering::SeqCst), 1, "exactly one builder won");
        assert_eq!(existing.load(Ordering::SeqCst), n - 1);
        // The seed is one builder's, whole: every file is from the same builder.
        let target = seed_target(&entry_dir(&root, &key));
        let owner: Vec<String> = (0..20)
            .map(|f| fs::read_to_string(target.join(format!("debug/deps/f{f}"))).unwrap())
            .map(|c| c.split(" file ").next().unwrap().to_string())
            .collect();
        assert!(owner.iter().all(|o| *o == owner[0]), "{owner:?}");
        assert_eq!(fs::read_dir(&target).unwrap().count(), 1, "no stray file");
        // The winner's directory was renamed away and every loser's was removed.
        for i in 0..n {
            assert!(
                !t.path().join(format!("work-{i}/new")).exists(),
                "work-{i}/new was left behind"
            );
        }
    }

    /// A tree with a nested directory, an executable, a symlink and an old modification time.
    fn sample(dir: &Path) {
        fs::create_dir_all(dir.join("debug/deps")).unwrap();
        fs::write(dir.join("debug/deps/lib.rlib"), vec![7u8; 100_000]).unwrap();
        fs::write(dir.join("debug/app"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(dir.join("debug/app"), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("deps/lib.rlib", dir.join("debug/link")).unwrap();
        fs::write(dir.join("empty"), "").unwrap();
        let old = SystemTime::now() - Duration::from_secs(86_400 * 3);
        fs::File::options()
            .write(true)
            .open(dir.join("debug/deps/lib.rlib"))
            .unwrap()
            .set_modified(old)
            .unwrap();
    }

    #[test]
    fn a_copy_is_independent_keeps_modes_links_and_times_and_never_links_back() {
        let t = tmp();
        let (src, dst) = (t.path().join("seed"), t.path().join("copy"));
        sample(&src);
        let method = copy_tree(&src, &dst).unwrap();
        assert!(matches!(method, CopyMethod::Clone | CopyMethod::Copy));
        assert_eq!(
            fs::read(dst.join("debug/deps/lib.rlib")).unwrap(),
            vec![7u8; 100_000]
        );
        assert_eq!(
            fs::metadata(dst.join("debug/app"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::read_link(dst.join("debug/link")).unwrap(),
            PathBuf::from("deps/lib.rlib"),
            "a symlink stays a symlink"
        );
        assert_eq!(
            fs::metadata(src.join("debug/deps/lib.rlib"))
                .unwrap()
                .modified()
                .unwrap(),
            fs::metadata(dst.join("debug/deps/lib.rlib"))
                .unwrap()
                .modified()
                .unwrap(),
            "cargo compares modification times, so they are kept"
        );
        // Changing the copy in place, as cargo does, never reaches the seed.
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .append(true)
                .open(dst.join("debug/deps/lib.rlib"))
                .unwrap();
            f.write_all(b"poison").unwrap();
        }
        fs::write(dst.join("debug/app"), "poisoned").unwrap();
        fs::write(dst.join("new-file"), "x").unwrap();
        assert_eq!(
            fs::read(src.join("debug/deps/lib.rlib")).unwrap(),
            vec![7u8; 100_000]
        );
        assert_eq!(
            fs::read_to_string(src.join("debug/app")).unwrap(),
            "#!/bin/sh\n"
        );
        assert!(!src.join("new-file").exists());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(dst.join("debug/app")).unwrap().nlink(),
            1,
            "not a hardlink"
        );
        assert_ne!(
            fs::metadata(src.join("debug/app")).unwrap().ino(),
            fs::metadata(dst.join("debug/app")).unwrap().ino()
        );
    }

    #[test]
    fn a_copy_over_an_existing_path_is_refused() {
        let t = tmp();
        let (src, dst) = (t.path().join("seed"), t.path().join("copy"));
        sample(&src);
        fs::create_dir(&dst).unwrap();
        assert_eq!(
            copy_tree(&src, &dst).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
    #[test]
    fn a_read_only_file_and_directory_copy_on_the_byte_path_keeping_modes_and_times() {
        let t = tmp();
        let (src, dst) = (t.path().join("seed"), t.path().join("copy"));
        fs::create_dir_all(src.join("ro-dir/inner")).unwrap();
        fs::write(src.join("ro-dir/inner/data"), "in a read-only directory").unwrap();
        fs::write(src.join("locked"), "read only").unwrap();
        let old = SystemTime::now() - Duration::from_secs(86_400 * 5);
        for path in [src.join("locked"), src.join("ro-dir/inner/data")] {
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        fs::File::open(src.join("ro-dir"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(src.join("ro-dir"), fs::Permissions::from_mode(0o555)).unwrap();

        let result = copy_tree_with(&src, &dst, false);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(dst.join("ro-dir"))
            .ok()
            .map(|m| m.permissions().mode() & 0o777);
        // Make both trees removable again before any assertion can unwind.
        for dir in [src.join("ro-dir"), dst.join("ro-dir")] {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
        }
        assert_eq!(result.unwrap(), CopyMethod::Copy);
        let mtime = |p: &Path| fs::metadata(p).unwrap().modified().unwrap();
        assert_eq!(
            fs::read_to_string(dst.join("ro-dir/inner/data")).unwrap(),
            "in a read-only directory"
        );
        assert_eq!(mode(&dst.join("locked")), 0o444);
        assert_eq!(mtime(&dst.join("locked")), old);
        assert_eq!(mtime(&dst.join("ro-dir/inner/data")), old);
        assert_eq!(mtime(&dst.join("ro-dir")), old);
        // The directory was made read-only again after its children were written.
        assert_eq!(dir_mode, Some(0o555));
    }
    #[test]
    fn a_copy_that_holds_a_read_only_directory_is_removed_and_a_link_in_it_is_not_followed() {
        let t = tmp();
        let (src, dst) = (t.path().join("seed"), t.path().join("copy"));
        let outside = t.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), "keep").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o555)).unwrap();
        fs::create_dir_all(src.join("ro-dir/inner")).unwrap();
        fs::write(src.join("ro-dir/inner/data"), "data").unwrap();
        std::os::unix::fs::symlink(&outside, src.join("ro-dir/link")).unwrap();
        fs::set_permissions(src.join("ro-dir/inner"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(src.join("ro-dir"), fs::Permissions::from_mode(0o555)).unwrap();

        let copied = copy_tree_with(&src, &dst, false);
        let copy_mode = fs::metadata(dst.join("ro-dir"))
            .ok()
            .map(|m| m.permissions().mode() & 0o777);
        let removed_copy = remove_all(&dst);
        let removed_seed = remove_all(&src);
        let outside_mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        let kept = fs::read_to_string(outside.join("keep"));
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        copied.unwrap();
        assert_eq!(copy_mode, Some(0o555), "the copy kept the read-only mode");
        removed_copy.unwrap();
        removed_seed.unwrap();
        assert!(fs::symlink_metadata(&dst).is_err() && fs::symlink_metadata(&src).is_err());
        assert_eq!(outside_mode, 0o555, "a link was not followed to a chmod");
        assert_eq!(kept.unwrap(), "keep");
    }

    /// Prune everything the size pass may remove (a limit of 0 bytes, nothing aged out by time).
    fn prune_all(root: &Path, home: &Path) -> cache::PruneReport {
        let opts = cache::PruneOptions {
            older_than: Duration::from_secs(86_400 * 3650),
            max_bytes: Some(0),
            dry_run: false,
            now: SystemTime::now(),
        };
        cache::prune(root, home, &opts, &alive).unwrap()
    }

    fn lease_of_this_process(entry: &Path) -> PathBuf {
        entry
            .join(cache::LEASES)
            .join(std::process::id().to_string())
    }

    #[test]
    fn an_install_and_a_hit_each_lease_the_seed_and_touch_its_marker_so_a_prune_keeps_it() {
        let t = tmp();
        let root = root(&t);
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let key = key(&inputs());
        let entry = entry_dir(&root, &key);
        let long_ago = SystemTime::now() - Duration::from_secs(86_400 * 40);

        // The install path: no lease or marker is written but by `install` itself.
        let before = SystemTime::now() - Duration::from_secs(2);
        let new = fresh(t.path(), &[("debug/app", "binary")]);
        assert_eq!(
            install(&new, &root, &key, &alive).unwrap(),
            Installed::Built
        );
        assert!(
            lease_of_this_process(&entry).is_file(),
            "an install takes a lease"
        );
        let installed_at = fs::metadata(entry.join(cache::LAST_USED))
            .unwrap()
            .modified()
            .unwrap();
        assert!(installed_at > before, "an install touches the marker");
        let report = prune_all(&root, &home);
        assert!(report.removed.is_empty(), "{report:?}");
        assert!(complete(&entry), "a prune kept the installed seed");

        // The hit path: age the marker and drop the lease, as if nobody had used it for weeks,
        // then look it up. The lookup alone must make it a used, leased seed again.
        fs::remove_dir_all(entry.join(cache::LEASES)).unwrap();
        cache::set_last_used(&entry, long_ago).unwrap();
        let before = SystemTime::now() - Duration::from_secs(2);
        assert_eq!(lookup(&root, &key, &alive).unwrap(), Lookup::Hit);
        assert!(
            lease_of_this_process(&entry).is_file(),
            "a hit takes this process's lease"
        );
        let touched = fs::metadata(entry.join(cache::LAST_USED))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            touched > before && touched > long_ago,
            "a hit touches the marker"
        );
        let report = prune_all(&root, &home);
        assert!(report.removed.is_empty(), "{report:?}");
        assert!(complete(&entry), "a prune kept the seed a hit leased");
        assert_eq!(
            fs::read_to_string(seed_target(&entry).join("debug/app")).unwrap(),
            "binary"
        );

        // The control: the same prune does remove a seed nobody holds a lease on.
        fs::remove_dir_all(entry.join(cache::LEASES)).unwrap();
        let report = prune_all(&root, &home);
        assert_eq!(report.removed.len(), 1, "{report:?}");
        assert!(!entry.exists());
    }
}
