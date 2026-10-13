//! The dependency cache's upkeep: when an entry was last used, who is using it, and what
//! `cowproof cache prune` may remove (backlog: the cache grew without bound, and an
//! interrupted run left a directory in `deps-work/`).
//!
//! Layout, under the cache root ([`crate::deps::cache_root`]):
//!
//! * `deps/<key>/` is an entry ([`crate::deps::cache_dir`]).
//! * `deps/<key>/.last-used` is the **use marker**: its modification time is the last time a
//!   fetch hit the entry, installed it, or a verifier was handed it. [`claim`] writes it, and
//!   [`crate::deps::prefetch`] calls [`claim`] on every hit and every install, the one place
//!   both `cowproof run` and `cowproof verify` get the entry they mount. An entry with no
//!   marker (made before the marker existed) counts as last used when its directory was
//!   modified.
//! * `deps/<key>/leases/<pid>` is a **lease**: the process `<pid>` is using the entry. It is
//!   taken with the marker and held for the life of that process (the entry is mounted for
//!   the verifier, which runs long after the fetch returns, and the caller does not hand a
//!   guard around). A lease whose pid is dead is stale: it protects nothing, and the next
//!   [`claim`] or a prune deletes it. An unknown answer from the pid check counts as alive,
//!   because a wrong "alive" costs disk space and a wrong "dead" costs a running lane its
//!   dependencies.
//! * `deps-work/<pid>-<nanos>[-prune]` is a private work directory of the process `<pid>`
//!   (a fetch in progress, or an entry a prune is deleting). One whose pid is dead is stale
//!   ([`remove_stale_work`]); a name that does not start with a pid is never touched.
//!
//! * `<root>/.cowproof-cache` is the **ownership marker**: cowproof writes it when it first
//!   creates a cache root, and `cache ls`, `cache prune` and the fetch's stale-work sweep
//!   refuse a root without it ([`require_owned`]), so a `COWPROOF_CACHE_ROOT` set by mistake
//!   to a directory that merely holds a `deps/` never loses anything. A root made before the
//!   marker existed is adopted (the marker is written) only when everything in it has
//!   cowproof's shape: each name in `deps/` is a cache key ([`is_key`], 64 lowercase hex
//!   digits, the SHA-256 of [`crate::dependency_cache_key`]) and each name in `deps-work/` is
//!   `<pid>-<digits>[-prune]`. Even in a marked root a prune lists and removes only names of
//!   that shape.
//!
//! * `verify-target/<key>/` is a **verifier compile-cache seed** ([`crate::verify_target`]): the
//!   cargo target directory a build of a base commit left, in `verify-target/<key>/target`. It
//!   is an entry like a dependency entry, with the same `.last-used` marker and per-pid leases
//!   (taken by [`claim`]), and it is listed, measured and pruned by the same code, by the same
//!   rules. Its private build directory is a `deps-work/<pid>-<nanos>` like a fetch's.
//!
//! Everything here removes things only under `<root>/deps`, `<root>/verify-target` and
//! `<root>/deps-work`, never follows a symlink (a link is measured as nothing and removed as a link), and refuses a
//! root that is empty, relative, `/` or the home directory ([`check_root`]).

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The use marker inside an entry.
pub const LAST_USED: &str = ".last-used";
/// The lease directory inside an entry.
pub const LEASES: &str = "leases";
/// The directory of cache entries under the root.
pub const DEPS: &str = "deps";
/// The directory of private work directories under the root.
pub const DEPS_WORK: &str = "deps-work";
/// The directory of verifier compile-cache seeds under the root.
pub const VERIFY_TARGET: &str = "verify-target";

/// A kind of cache entry: both live under the cache root, are named by a 64-hex key, carry a
/// use marker and leases, and are pruned together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// A fetched dependency cache, `deps/<key>`.
    Deps,
    /// A verifier compile-cache seed, `verify-target/<key>`.
    VerifyTarget,
}

impl Area {
    /// Every kind, in listing order.
    pub const ALL: [Area; 2] = [Area::Deps, Area::VerifyTarget];

    /// The directory under the cache root.
    pub fn dir(self) -> &'static str {
        match self {
            Area::Deps => DEPS,
            Area::VerifyTarget => VERIFY_TARGET,
        }
    }

    /// How a report names an entry of this kind: the bare key for a dependency entry (as it
    /// always was), `verify-target/<key>` for a seed.
    pub fn label(self, key: &str) -> String {
        match self {
            Area::Deps => key.to_string(),
            Area::VerifyTarget => format!("{VERIFY_TARGET}/{key}"),
        }
    }
}

/// The ownership marker at the cache root.
pub const MARKER: &str = ".cowproof-cache";
/// What the marker holds: a fixed header and a version.
pub const MARKER_BODY: &str = "cowproof dependency cache\nversion 1\n";

/// Whether a pid is a live process. `true` also for "cannot tell".
pub type Alive<'a> = &'a dyn Fn(u32) -> bool;

/// Refuse a cache root that no prune should ever be pointed at: empty, relative, `/`, or
/// the home directory itself (by name or once resolved).
pub fn check_root(root: &Path, home: &Path) -> Result<()> {
    if root.as_os_str().is_empty() {
        bail!("the cache root is empty");
    }
    if !root.is_absolute() {
        bail!("the cache root {} is not an absolute path", root.display());
    }
    let resolved = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if resolved.parent().is_none() || root.parent().is_none() {
        bail!("the cache root {} is the filesystem root", root.display());
    }
    if !home.as_os_str().is_empty() {
        let home_resolved = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
        if root == home || resolved == home_resolved || resolved == home {
            bail!("the cache root {} is the home directory", root.display());
        }
    }
    Ok(())
}

/// Whether `name` is a cache key: the 64 lowercase hex digits of a SHA-256
/// ([`crate::dependency_cache_key`]).
pub fn is_key(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The pid of a `deps-work` directory name, which is `<pid>-<digits>` or
/// `<pid>-<digits>-prune`; any other name is not cowproof's.
fn work_pid(name: &str) -> Option<u32> {
    let rest = name.strip_suffix("-prune").unwrap_or(name);
    let (pid, stamp) = rest.split_once('-')?;
    if stamp.is_empty() || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pid: u32 = pid.parse().ok()?;
    (pid > 0).then_some(pid)
}

fn dir_names(dir: &Path) -> io::Result<Vec<String>> {
    Ok(fs::read_dir(dir)?
        .flatten()
        .map(|i| i.file_name().to_string_lossy().into_owned())
        .collect())
}

/// Write the ownership marker at `root` if it is not there. Never follows a link.
pub fn write_marker(root: &Path) -> io::Result<()> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(MARKER))
    {
        Ok(mut f) => io::Write::write_all(&mut f, MARKER_BODY.as_bytes()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

fn has_marker(root: &Path) -> bool {
    let path = root.join(MARKER);
    fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
        && fs::read_to_string(&path).is_ok_and(|t| t.starts_with("cowproof dependency cache\n"))
}

/// Refuse a root cowproof did not make. Fine: a root with the marker; a root with no
/// `deps/`, `verify-target/` and `deps-work/` entries at all (nothing there to lose); a root without the
/// marker whose every `deps/` and `verify-target/` name is a key and every `deps-work/` name is a work name (an
/// older cowproof's cache), which gets the marker now. Anything else is an error that says
/// how to make a cache there.
pub fn require_owned(root: &Path, home: &Path) -> Result<()> {
    check_root(root, home)?;
    if has_marker(root) {
        return Ok(());
    }
    let mut foreign: Option<String> = None;
    let mut any = false;
    for (sub, ok) in [
        (DEPS, is_key as fn(&str) -> bool),
        (VERIFY_TARGET, is_key as fn(&str) -> bool),
        (DEPS_WORK, |n: &str| work_pid(n).is_some()),
    ] {
        let dir = root.join(sub);
        match fs::symlink_metadata(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
            Ok(m) if !m.is_dir() => {
                foreign = Some(format!("{sub} is not a plain directory"));
                continue;
            }
            Ok(_) => {}
        }
        for name in dir_names(&dir)? {
            any = true;
            if !ok(&name) && foreign.is_none() {
                foreign = Some(format!("{sub}/{name} is not something cowproof makes"));
            }
        }
    }
    match foreign {
        None if !any => Ok(()),
        None => Ok(write_marker(root)?),
        Some(why) => bail!(
            "{} is not a cowproof cache: it has no {MARKER} marker and {why}. cowproof only \
             prunes a cache it created; to make one there, run a lane with \
             COWPROOF_CACHE_ROOT={} (an empty directory is best)",
            root.display(),
            root.display()
        ),
    }
}

/// Make the cache root ready for a new entry of `area`: create `deps-work/` and the area's
/// directory, mark the root as cowproof's, and sweep the stale work directories of
/// interrupted runs. The one place a cache root is first created, for a dependency fetch
/// and for a compile-cache seed alike. Ownership is asked first and the sweep is skipped in
/// a root cowproof did not make (the entry is still made there), so a root that holds things
/// cowproof did not make is never swept.
pub fn prepare(root: &Path, home: &Path, area: Area, alive: Alive) -> Result<()> {
    let owned = require_owned(root, home);
    fs::create_dir_all(root.join(DEPS_WORK)).context("creating the work directory")?;
    fs::create_dir_all(root.join(area.dir()))
        .with_context(|| format!("creating the {} directory", area.dir()))?;
    write_marker(root).context("marking the cache root")?;
    match owned {
        Ok(()) => {
            let _ = remove_stale_work(root, home, alive);
        }
        Err(e) => eprintln!("warning: not sweeping stale work directories: {e:#}"),
    }
    Ok(())
}

/// A new private work directory `deps-work/<pid>-<nanos>` of this process (the name a stale
/// sweep recognises), created empty. Remove it when done.
pub fn new_work_dir(root: &Path) -> Result<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let work = root
        .join(DEPS_WORK)
        .join(format!("{}-{stamp}", std::process::id()));
    fs::create_dir(&work).context("creating the work directory")?;
    Ok(work)
}

/// A lease file's pid: its name.
fn lease_pid(name: &str) -> Option<u32> {
    let pid: u32 = name.parse().ok()?;
    (pid > 0).then_some(pid)
}

/// The leases of the entry directory `entry`: `(live pids, stale lease files)`. A lease
/// file whose name is no pid is stale. A symlink is never followed.
fn leases(entry: &Path, alive: Alive) -> (Vec<u32>, Vec<PathBuf>) {
    let (mut live, mut stale) = (Vec::new(), Vec::new());
    // A `leases` that is a link is not a lease directory: reading it would list, and a
    // sweep would delete from, wherever it points.
    if !is_plain_dir(&entry.join(LEASES)) {
        return (live, stale);
    }
    let Ok(read) = fs::read_dir(entry.join(LEASES)) else {
        return (live, stale);
    };
    for item in read.flatten() {
        let path = item.path();
        match lease_pid(&item.file_name().to_string_lossy()) {
            Some(pid) if alive(pid) => live.push(pid),
            _ => stale.push(path),
        }
    }
    live.sort_unstable();
    (live, stale)
}

/// Record a use of the entry `entry` by the process `pid`: write the lease, drop the
/// leases of dead processes, and touch the use marker. `NotFound` means the entry is gone
/// (a prune took it between the caller's look and now); the caller looks again.
pub fn claim(entry: &Path, pid: u32, alive: Alive) -> io::Result<()> {
    if !is_plain_dir(entry) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not a plain directory", entry.display()),
        ));
    }
    match fs::create_dir(entry.join(LEASES)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    if !is_plain_dir(&entry.join(LEASES)) {
        return Err(io::Error::other(format!(
            "{} is not a plain directory",
            entry.join(LEASES).display()
        )));
    }
    let lease = entry.join(LEASES).join(pid.to_string());
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lease)?;
    for stale in leases(entry, alive).1 {
        let _ = fs::remove_file(stale);
    }
    touch(entry)
}

/// Set the use marker's modification time to now.
fn touch(entry: &Path) -> io::Result<()> {
    set_last_used(entry, SystemTime::now())
}

/// Set the use marker's modification time (tests use this to age an entry).
pub fn set_last_used(entry: &Path, when: SystemTime) -> io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(entry.join(LAST_USED))?
        .set_modified(when)
}

/// One cache entry as a prune sees it.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Which kind of entry this is.
    pub area: Area,
    /// The directory name: the cache key.
    pub key: String,
    pub path: PathBuf,
    /// A symlink in the place of an entry: measured as 0 bytes, removed as a link, never
    /// followed.
    pub link: bool,
    /// Bytes of the regular files in it, symlinks not followed.
    pub bytes: u64,
    pub last_used: SystemTime,
    /// Pids of live leases: a non-empty list protects the entry.
    pub live: Vec<u32>,
    pub stale_leases: Vec<PathBuf>,
}

/// The bytes of the regular files under `dir`. Symlinks count for nothing and are not
/// followed.
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(read) = fs::read_dir(&d) else { continue };
        for item in read.flatten() {
            let Ok(meta) = fs::symlink_metadata(item.path()) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(item.path());
            } else if meta.is_file() {
                total += meta.len();
            }
        }
    }
    total
}

/// `path` is a real directory, not a link to one. The one test every size, walk and removal
/// decision goes through.
fn is_plain_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Every entry under `<root>/deps` and `<root>/verify-target`, oldest use first. An area
/// directory that is a symlink is refused.
pub fn list(root: &Path, home: &Path, alive: Alive) -> Result<Vec<Entry>> {
    require_owned(root, home)?;
    let mut entries = Vec::new();
    for area in Area::ALL {
        list_area(root, area, alive, &mut entries)?;
    }
    entries.sort_by(|a, b| (a.last_used, &a.key).cmp(&(b.last_used, &b.key)));
    Ok(entries)
}

fn list_area(root: &Path, area: Area, alive: Alive, entries: &mut Vec<Entry>) -> Result<()> {
    let dir = root.join(area.dir());
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(m) if !m.is_dir() => bail!("{} is not a plain directory", dir.display()),
        Ok(_) => {}
    }
    for item in fs::read_dir(&dir)?.flatten() {
        let path = item.path();
        let key = item.file_name().to_string_lossy().into_owned();
        // Only what has a cache key's name is cowproof's, marker or not.
        if !is_key(&key) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let plain = is_plain_dir(&path);
        let (live, stale_leases) = if plain {
            leases(&path, alive)
        } else {
            (Vec::new(), Vec::new())
        };
        let marker = if plain {
            fs::symlink_metadata(path.join(LAST_USED))
                .ok()
                .filter(|m| m.is_file())
        } else {
            None
        };
        let last_used = marker
            .as_ref()
            .unwrap_or(&meta)
            .modified()
            .unwrap_or(UNIX_EPOCH);
        entries.push(Entry {
            area,
            key,
            bytes: if plain { dir_bytes(&path) } else { 0 },
            link: !plain,
            path,
            last_used,
            live,
            stale_leases,
        });
    }
    Ok(())
}

impl Entry {
    /// How a report names this entry ([`Area::label`]).
    pub fn label(&self) -> String {
        self.area.label(&self.key)
    }
}

/// What `cowproof cache` prints: the cache at a glance.
#[derive(Debug)]
pub struct Overview {
    pub entries: usize,
    pub bytes: u64,
    /// The oldest last use of any entry (`None` for an empty cache).
    pub oldest: Option<SystemTime>,
}

/// The size, entry count and oldest use of the cache under `root`.
pub fn overview(root: &Path, home: &Path, alive: Alive) -> Result<Overview> {
    let entries = list(root, home, alive)?;
    Ok(Overview {
        entries: entries.len(),
        bytes: entries.iter().map(|e| e.bytes).sum(),
        oldest: entries.iter().map(|e| e.last_used).min(),
    })
}

/// What a prune may remove.
#[derive(Debug, Clone)]
pub struct PruneOptions {
    /// Remove entries last used at least this long ago.
    pub older_than: Duration,
    /// Then remove least recently used entries until the cache is at most this many bytes.
    pub max_bytes: Option<u64>,
    /// List what would go and remove nothing.
    pub dry_run: bool,
    /// The time ages are measured to.
    pub now: SystemTime,
}

/// Why an entry goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Age,
    Size,
}

/// An entry a prune removed (or, in a dry run, would remove).
#[derive(Debug, Clone)]
pub struct Removed {
    pub area: Area,
    pub key: String,
    pub bytes: u64,
    pub last_used: SystemTime,
    pub reason: Reason,
}

/// What a prune did.
#[derive(Debug, Default)]
pub struct PruneReport {
    pub dry_run: bool,
    pub removed: Vec<Removed>,
    /// Entries that would otherwise go but a live process is using: `(label, pids)`
    /// ([`Entry::label`]).
    pub in_use: Vec<(String, Vec<u32>)>,
    /// Stale work directories removed (or that would be).
    pub work_removed: Vec<String>,
    /// Work directories of live processes, left alone.
    pub work_kept: Vec<String>,
    /// Entries that could not be removed: `(label, why)`.
    pub failed: Vec<(String, String)>,
    pub bytes_before: u64,
    /// How many entries the cache held before.
    pub entries_total: usize,
}

impl PruneReport {
    /// The bytes freed (or that would be).
    pub fn bytes_freed(&self) -> u64 {
        self.removed.iter().map(|r| r.bytes).sum()
    }
}

/// Remove the unused part of the cache under `root` (see the module comment): entries of
/// either kind not used within `older_than`, then least recently used entries until
/// `max_bytes` fits, skipping any entry a live process holds a lease on, then every stale
/// work directory.
pub fn prune(root: &Path, home: &Path, opts: &PruneOptions, alive: Alive) -> Result<PruneReport> {
    let entries = list(root, home, alive)?;
    let mut report = PruneReport {
        dry_run: opts.dry_run,
        bytes_before: entries.iter().map(|e| e.bytes).sum(),
        entries_total: entries.len(),
        ..PruneReport::default()
    };

    // Decide first, on the listing: age, then size (least recently used first, and only
    // among what the age pass left).
    let mut doomed: BTreeMap<usize, Reason> = BTreeMap::new();
    for (i, e) in entries.iter().enumerate() {
        let idle = opts.now.duration_since(e.last_used).unwrap_or_default();
        if idle >= opts.older_than && e.live.is_empty() {
            doomed.insert(i, Reason::Age);
        }
    }
    if let Some(max) = opts.max_bytes {
        let mut remaining: u64 = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| !doomed.contains_key(i))
            .map(|(_, e)| e.bytes)
            .sum();
        // `entries` is already oldest use first.
        for (i, e) in entries.iter().enumerate() {
            if remaining <= max {
                break;
            }
            if doomed.contains_key(&i) || !e.live.is_empty() {
                continue;
            }
            doomed.insert(i, Reason::Size);
            remaining -= e.bytes;
        }
    }

    for (i, e) in entries.iter().enumerate() {
        let reason = doomed.get(&i).copied();
        let Some(reason) = reason else {
            // Not removed: in use if it would have been old enough or the cache is over
            // budget, so the director sees why an old entry stays.
            let idle = opts.now.duration_since(e.last_used).unwrap_or_default();
            if !e.live.is_empty() && idle >= opts.older_than {
                report.in_use.push((e.label(), e.live.clone()));
            }
            if !opts.dry_run {
                for stale in &e.stale_leases {
                    let _ = fs::remove_file(stale);
                }
            }
            continue;
        };
        let removed = Removed {
            area: e.area,
            key: e.key.clone(),
            bytes: e.bytes,
            last_used: e.last_used,
            reason,
        };
        if opts.dry_run {
            report.removed.push(removed);
            continue;
        }
        match remove_entry(root, e, alive) {
            Ok(Taken::Removed) => report.removed.push(removed),
            Ok(Taken::InUse(pids)) => report.in_use.push((e.label(), pids)),
            Err(why) => report.failed.push((e.label(), format!("{why:#}"))),
        }
    }
    let work = sweep_work(root, alive, opts.dry_run)?;
    report.work_removed = work.removed;
    report.work_kept = work.kept;
    Ok(report)
}

enum Taken {
    Removed,
    InUse(Vec<u32>),
}

/// Remove one entry. A link is removed as a link. A directory is first renamed into
/// `deps-work/<pid>-<nanos>-prune`, where a fetch can no longer hit it, and its leases are
/// read again: a lease taken since the listing puts it back instead.
fn remove_entry(root: &Path, e: &Entry, alive: Alive) -> Result<Taken> {
    if !is_plain_dir(&e.path) {
        fs::remove_file(&e.path)?;
        return Ok(Taken::Removed);
    }
    let work = root.join(DEPS_WORK);
    match fs::symlink_metadata(&work) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&work)?,
        Err(e) => return Err(e.into()),
        Ok(m) if !m.is_dir() => bail!("{} is not a plain directory", work.display()),
        Ok(_) => {}
    }
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let trash = work.join(format!("{}-{nanos}-prune", std::process::id()));
    fs::rename(&e.path, &trash)?;
    let (live, _) = leases(&trash, alive);
    if !live.is_empty() {
        fs::rename(&trash, &e.path)?;
        return Ok(Taken::InUse(live));
    }
    cowproof_core::fsutil::remove_tree(&trash)?;
    Ok(Taken::Removed)
}

/// What a sweep of `deps-work` found.
#[derive(Debug, Default)]
pub struct WorkSweep {
    pub removed: Vec<String>,
    pub kept: Vec<String>,
}

/// Remove every `deps-work/<pid>-...` whose pid is dead; keep the ones whose pid is alive;
/// leave any other name alone. (A prune's own sweep can also list without removing.)
pub fn remove_stale_work(root: &Path, home: &Path, alive: Alive) -> Result<WorkSweep> {
    require_owned(root, home)?;
    sweep_work(root, alive, false)
}

fn sweep_work(root: &Path, alive: Alive, dry_run: bool) -> Result<WorkSweep> {
    let mut sweep = WorkSweep::default();
    let work = root.join(DEPS_WORK);
    if !is_plain_dir(&work) {
        return Ok(sweep);
    }
    let mut names = dir_names(&work)?;
    names.sort();
    for name in names {
        let Some(pid) = work_pid(&name) else { continue };
        if alive(pid) {
            sweep.kept.push(name);
            continue;
        }
        let path = work.join(&name);
        if !dry_run {
            if fs::symlink_metadata(&path).is_err() {
                continue;
            }
            if cowproof_core::fsutil::remove_tree(&path).is_err() {
                continue;
            }
        }
        sweep.removed.push(name);
    }
    Ok(sweep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const LIVE: u32 = 4_000_001;
    const DEAD: u32 = 4_000_002;
    const DAY: Duration = Duration::from_secs(86_400);

    fn alive(pid: u32) -> bool {
        pid == LIVE
    }

    /// A cache-key-shaped name for a readable label: the label's hex, padded with zeros.
    fn key(label: &str) -> String {
        let hex: String = label.bytes().map(|b| format!("{b:02x}")).collect();
        format!("{hex:0<64}")
    }

    /// The label of [`key`].
    fn label(key: &str) -> String {
        key.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .take_while(|b| *b != 0)
            .map(char::from)
            .collect()
    }

    /// A temp dir under /var/tmp, never the real home or cache.
    fn tmp() -> TempDir {
        fs::create_dir_all("/var/tmp").unwrap();
        tempfile::Builder::new()
            .prefix("cp-cache-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    struct Cache {
        _tmp: TempDir,
        root: PathBuf,
        home: PathBuf,
        now: SystemTime,
    }

    impl Cache {
        fn new() -> Self {
            let t = tmp();
            let root = t.path().join("cache");
            let home = t.path().join("home");
            fs::create_dir_all(root.join(DEPS)).unwrap();
            fs::create_dir_all(&home).unwrap();
            fs::write(root.join(MARKER), MARKER_BODY).unwrap();
            Cache {
                _tmp: t,
                root,
                home,
                now: SystemTime::now(),
            }
        }

        /// An entry of `bytes` bytes, last used `days` days ago.
        fn entry(&self, label: &str, bytes: usize, days: u64) -> PathBuf {
            let dir = self.root.join(DEPS).join(key(label));
            fs::create_dir_all(dir.join("cargo/registry")).unwrap();
            fs::write(dir.join("cargo/registry/crate"), vec![b'x'; bytes]).unwrap();
            set_last_used(&dir, self.now - DAY * days as u32).unwrap();
            dir
        }

        /// A compile-cache seed of `bytes` bytes, last used `days` days ago.
        fn seed(&self, label: &str, bytes: usize, days: u64) -> PathBuf {
            let dir = self.root.join(VERIFY_TARGET).join(key(label));
            fs::create_dir_all(dir.join("target/debug")).unwrap();
            fs::write(dir.join("target/debug/artifact"), vec![b'x'; bytes]).unwrap();
            set_last_used(&dir, self.now - DAY * days as u32).unwrap();
            dir
        }

        fn has_seed(&self, label: &str) -> bool {
            self.root.join(VERIFY_TARGET).join(key(label)).exists()
        }

        fn lease(&self, dir: &Path, pid: u32) {
            fs::create_dir_all(dir.join(LEASES)).unwrap();
            fs::write(dir.join(LEASES).join(pid.to_string()), "").unwrap();
        }

        fn opts(&self, days: u64) -> PruneOptions {
            PruneOptions {
                older_than: DAY * days as u32,
                max_bytes: None,
                dry_run: false,
                now: self.now,
            }
        }

        fn prune(&self, opts: &PruneOptions) -> PruneReport {
            prune(&self.root, &self.home, opts, &alive).unwrap()
        }

        fn has(&self, label: &str) -> bool {
            self.root.join(DEPS).join(key(label)).exists()
        }
    }

    fn keys(report: &PruneReport) -> Vec<String> {
        report.removed.iter().map(|r| label(&r.key)).collect()
    }

    #[test]
    fn an_old_entry_is_removed_and_a_recent_one_kept() {
        let c = Cache::new();
        c.entry("old", 100, 40);
        c.entry("recent", 100, 2);
        let report = c.prune(&c.opts(30));
        assert_eq!(keys(&report), ["old"]);
        assert_eq!(report.removed[0].reason, Reason::Age);
        assert_eq!(report.bytes_freed(), 100);
        assert!(!c.has("old"));
        assert!(c.has("recent"));
        assert!(
            fs::read_dir(c.root.join(DEPS_WORK))
                .map(|r| r.count())
                .unwrap_or(0)
                == 0,
            "the removed entry left nothing in deps-work"
        );
    }

    #[test]
    fn max_size_removes_the_least_recently_used_first_until_the_cache_fits() {
        let c = Cache::new();
        c.entry("a-oldest", 100, 10);
        c.entry("b-middle", 100, 5);
        c.entry("c-newest", 100, 1);
        let mut opts = c.opts(365);
        opts.max_bytes = Some(150);
        let report = c.prune(&opts);
        assert_eq!(keys(&report), ["a-oldest", "b-middle"]);
        assert!(report.removed.iter().all(|r| r.reason == Reason::Size));
        assert!(c.has("c-newest"));
        assert!(!c.has("a-oldest") && !c.has("b-middle"));

        // Exactly at the limit nothing more goes.
        let mut opts = c.opts(365);
        opts.max_bytes = Some(100);
        assert!(c.prune(&opts).removed.is_empty());
        assert!(c.has("c-newest"));
    }

    #[test]
    fn max_size_counts_what_the_age_pass_already_removes() {
        let c = Cache::new();
        c.entry("ancient", 100, 90);
        c.entry("older", 100, 3);
        c.entry("newer", 100, 1);
        let mut opts = c.opts(30);
        opts.max_bytes = Some(200);
        let report = c.prune(&opts);
        assert_eq!(keys(&report), ["ancient"], "the age pass alone made it fit");
        assert!(c.has("older") && c.has("newer"));
    }

    #[test]
    fn an_entry_with_a_live_lease_is_kept_even_when_old() {
        let c = Cache::new();
        let busy = c.entry("busy", 100, 90);
        c.lease(&busy, LIVE);
        c.entry("idle", 100, 90);
        let mut opts = c.opts(30);
        opts.max_bytes = Some(0);
        let report = c.prune(&opts);
        assert_eq!(keys(&report), ["idle"]);
        assert_eq!(report.in_use, [(key("busy"), vec![LIVE])]);
        assert!(c.has("busy"));
        assert!(!c.has("idle"));
        assert!(
            busy.join("cargo/registry/crate").is_file(),
            "the held entry is whole"
        );
    }

    #[test]
    fn an_entry_with_a_dead_lease_is_removed() {
        let c = Cache::new();
        let gone = c.entry("gone", 100, 90);
        c.lease(&gone, DEAD);
        let report = c.prune(&c.opts(30));
        assert_eq!(keys(&report), ["gone"]);
        assert!(report.in_use.is_empty());
        assert!(!c.has("gone"));
    }

    #[test]
    fn a_dead_lease_beside_a_live_one_does_not_hide_the_live_one_and_is_swept() {
        let c = Cache::new();
        let busy = c.entry("busy", 100, 90);
        c.lease(&busy, LIVE);
        c.lease(&busy, DEAD);
        let report = c.prune(&c.opts(30));
        assert!(report.removed.is_empty());
        assert!(c.has("busy"));
        assert!(busy.join(LEASES).join(LIVE.to_string()).exists());
        assert!(
            !busy.join(LEASES).join(DEAD.to_string()).exists(),
            "the stale lease was deleted"
        );
    }

    #[test]
    fn claiming_an_entry_writes_a_lease_a_fresh_marker_and_drops_stale_leases() {
        let c = Cache::new();
        let dir = c.entry("k", 10, 90);
        c.lease(&dir, DEAD);
        claim(&dir, LIVE, &alive).unwrap();
        assert!(dir.join(LEASES).join(LIVE.to_string()).is_file());
        assert!(!dir.join(LEASES).join(DEAD.to_string()).exists());
        let used = fs::metadata(dir.join(LAST_USED))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            SystemTime::now().duration_since(used).unwrap() < Duration::from_secs(60),
            "the marker is fresh"
        );
        // So the entry is neither old nor unprotected now.
        let report = c.prune(&c.opts(1));
        assert!(report.removed.is_empty());
        // A gone entry is NotFound, which a caller reads as "look again".
        let err = claim(&c.root.join(DEPS).join("missing"), LIVE, &alive).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn an_entry_without_a_marker_ages_by_its_directory() {
        let c = Cache::new();
        let dir = c.entry("legacy", 10, 0);
        fs::remove_file(dir.join(LAST_USED)).unwrap();
        // Brand new directory: not old.
        assert!(c.prune(&c.opts(30)).removed.is_empty());
        // Everything older than "now" is removable.
        let mut opts = c.opts(0);
        opts.now = SystemTime::now() + DAY;
        assert_eq!(keys(&c.prune(&opts)), ["legacy"]);
    }

    #[test]
    fn a_work_directory_with_a_dead_pid_is_removed_and_one_with_a_live_pid_kept() {
        let c = Cache::new();
        let work = c.root.join(DEPS_WORK);
        for name in [
            format!("{DEAD}-111"),
            format!("{LIVE}-222"),
            format!("{DEAD}-333-prune"),
            "not-a-pid".to_string(),
            "0-1".to_string(),
        ] {
            fs::create_dir_all(work.join(&name).join("tree")).unwrap();
            fs::write(work.join(&name).join("tree/f"), "x").unwrap();
        }
        let report = c.prune(&c.opts(30));
        assert_eq!(
            report.work_removed,
            [format!("{DEAD}-111"), format!("{DEAD}-333-prune")]
        );
        assert_eq!(report.work_kept, [format!("{LIVE}-222")]);
        assert!(!work.join(format!("{DEAD}-111")).exists());
        assert!(!work.join(format!("{DEAD}-333-prune")).exists());
        assert!(work.join(format!("{LIVE}-222/tree/f")).is_file());
        assert!(
            work.join("not-a-pid").is_dir() && work.join("0-1").is_dir(),
            "a name with no pid is never touched"
        );
    }

    #[test]
    fn the_fetch_time_sweep_removes_only_dead_work_directories() {
        let c = Cache::new();
        let work = c.root.join(DEPS_WORK);
        fs::create_dir_all(work.join(format!("{DEAD}-1"))).unwrap();
        fs::create_dir_all(work.join(format!("{LIVE}-1"))).unwrap();
        let sweep = remove_stale_work(&c.root, &c.home, &alive).unwrap();
        assert_eq!(sweep.removed, [format!("{DEAD}-1")]);
        assert!(work.join(format!("{LIVE}-1")).is_dir());
        // And it refuses the same roots prune does.
        assert!(remove_stale_work(Path::new("/"), &c.home, &alive).is_err());
    }

    #[test]
    fn a_dry_run_lists_what_would_go_and_removes_nothing() {
        let c = Cache::new();
        let stale = c.entry("stale", 100, 90);
        c.lease(&stale, DEAD);
        c.entry("old", 200, 40);
        c.entry("fresh", 50, 1);
        fs::create_dir_all(c.root.join(DEPS_WORK).join(format!("{DEAD}-9"))).unwrap();
        let mut opts = c.opts(30);
        opts.dry_run = true;
        let report = c.prune(&opts);
        assert!(report.dry_run);
        assert_eq!(keys(&report), ["stale", "old"]);
        assert_eq!(report.bytes_freed(), 300);
        assert_eq!(report.work_removed, [format!("{DEAD}-9")]);
        for key in ["stale", "old", "fresh"] {
            assert!(c.has(key), "{key} was removed by a dry run");
        }
        assert!(stale.join(LEASES).join(DEAD.to_string()).exists());
        assert!(c.root.join(DEPS_WORK).join(format!("{DEAD}-9")).is_dir());
    }

    #[test]
    fn a_symlink_in_the_cache_pointing_outside_is_not_followed_and_its_target_survives() {
        let c = Cache::new();
        let outside = c._tmp.path().join("outside");
        fs::create_dir_all(outside.join("deep")).unwrap();
        fs::write(outside.join("deep/precious"), vec![b'p'; 5000]).unwrap();
        let deps = c.root.join(DEPS);

        // 1. An entry that is itself a link to a directory outside.
        std::os::unix::fs::symlink(&outside, deps.join(key("link-entry"))).unwrap();
        // 2. A real entry with a link to the outside inside it.
        let real = c.entry("real", 100, 90);
        std::os::unix::fs::symlink(&outside, real.join("cargo/escape")).unwrap();
        // 3. The lease directory of an entry as a link outside.
        let sneaky = c.entry("sneaky", 100, 90);
        std::os::unix::fs::symlink(&outside, sneaky.join(LEASES)).unwrap();

        // The listing measures the links as nothing.
        let listed = list(&c.root, &c.home, &alive).unwrap();
        let link = listed.iter().find(|e| e.key == key("link-entry")).unwrap();
        assert!(link.link);
        assert_eq!(link.bytes, 0, "the link's target was measured");
        let real_entry = listed.iter().find(|e| e.key == key("real")).unwrap();
        assert_eq!(real_entry.bytes, 100, "the link inside an entry was walked");

        let mut opts = c.opts(0);
        opts.max_bytes = Some(0);
        let report = c.prune(&opts);
        assert_eq!(report.removed.len(), 3, "{report:?}");
        assert!(!deps.join(key("link-entry")).exists());
        assert!(!c.has("real") && !c.has("sneaky"));
        assert_eq!(
            fs::read(outside.join("deep/precious")).unwrap().len(),
            5000,
            "the target of a symlink was removed"
        );
        let freed: u64 = report.bytes_freed();
        assert_eq!(freed, 200, "a link's target counted as freed bytes");
    }

    #[test]
    fn a_deps_directory_that_is_a_symlink_is_refused() {
        let c = Cache::new();
        let outside = c._tmp.path().join("outside");
        fs::create_dir_all(outside.join("victim")).unwrap();
        fs::remove_dir_all(c.root.join(DEPS)).unwrap();
        std::os::unix::fs::symlink(&outside, c.root.join(DEPS)).unwrap();
        let mut opts = c.opts(0);
        opts.max_bytes = Some(0);
        assert!(prune(&c.root, &c.home, &opts, &alive).is_err());
        assert!(outside.join("victim").is_dir());
    }

    #[test]
    fn a_cache_root_of_slash_the_home_directory_or_nothing_is_refused() {
        let c = Cache::new();
        let opts = c.opts(0);
        for root in [Path::new("/"), Path::new(""), Path::new("relative/cache")] {
            assert!(
                prune(root, &c.home, &opts, &alive).is_err(),
                "{} was accepted",
                root.display()
            );
            assert!(overview(root, &c.home, &alive).is_err());
        }
        // The home directory, by name and through a link.
        fs::create_dir_all(c.home.join("deps/victim")).unwrap();
        assert!(prune(&c.home, &c.home, &opts, &alive).is_err());
        let via = c._tmp.path().join("via-link");
        std::os::unix::fs::symlink(&c.home, &via).unwrap();
        assert!(prune(&via, &c.home, &opts, &alive).is_err());
        assert!(c.home.join("deps/victim").is_dir(), "the home was pruned");
        // A real cache root under the home is fine.
        let under = c.home.join(".cache/cowproof");
        fs::create_dir_all(under.join(DEPS)).unwrap();
        assert!(prune(&under, &c.home, &opts, &alive).is_ok());
    }

    #[test]
    fn the_overview_totals_the_cache() {
        let c = Cache::new();
        assert_eq!(overview(&c.root, &c.home, &alive).unwrap().entries, 0);
        c.entry("a", 100, 40);
        c.entry("b", 50, 2);
        let o = overview(&c.root, &c.home, &alive).unwrap();
        assert_eq!((o.entries, o.bytes), (2, 150));
        let oldest = o.oldest.unwrap();
        assert_eq!(c.now.duration_since(oldest).unwrap().as_secs() / 86_400, 40);
    }

    /// A root with no marker, made by hand: `deps/` and `deps-work/` hold what is given.
    fn unmarked(deps: &[&str], work: &[&str]) -> Cache {
        let c = Cache::new();
        fs::remove_file(c.root.join(MARKER)).unwrap();
        for name in deps {
            let d = c.root.join(DEPS).join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("file"), "x").unwrap();
        }
        for name in work {
            fs::create_dir_all(c.root.join(DEPS_WORK).join(name)).unwrap();
        }
        c
    }

    #[test]
    fn a_root_without_the_marker_that_holds_something_else_is_refused_and_nothing_is_deleted() {
        let c = unmarked(&["old-project", "other"], &[&format!("{DEAD}-5")]);
        let mut opts = c.opts(0);
        opts.max_bytes = Some(0);
        let err = prune(&c.root, &c.home, &opts, &alive)
            .unwrap_err()
            .to_string();
        assert!(err.contains(&c.root.display().to_string()), "{err}");
        assert!(err.contains("COWPROOF_CACHE_ROOT"), "{err}");
        assert!(overview(&c.root, &c.home, &alive).is_err());
        assert!(remove_stale_work(&c.root, &c.home, &alive).is_err());
        assert!(c.root.join("deps/old-project/file").is_file());
        assert!(c.root.join("deps/other/file").is_file());
        assert!(c.root.join(DEPS_WORK).join(format!("{DEAD}-5")).is_dir());
        assert!(!c.root.join(MARKER).exists(), "a foreign root was marked");
    }

    #[test]
    fn a_work_name_that_is_not_cowproofs_also_makes_an_unmarked_root_foreign() {
        let c = unmarked(&[&key("a")], &["build-cache"]);
        assert!(prune(&c.root, &c.home, &c.opts(0), &alive).is_err());
        assert!(c.has("a"));
    }

    #[test]
    fn an_unmarked_root_of_cowproof_shaped_entries_is_adopted_and_marked() {
        let c = unmarked(
            &[&key("old")],
            &[&format!("{DEAD}-5"), &format!("{LIVE}-6-prune")],
        );
        set_last_used(&c.root.join(DEPS).join(key("old")), c.now - DAY * 90).unwrap();
        let report = c.prune(&c.opts(30));
        assert_eq!(keys(&report), ["old"]);
        assert_eq!(report.work_removed, [format!("{DEAD}-5")]);
        assert_eq!(
            fs::read_to_string(c.root.join(MARKER)).unwrap(),
            MARKER_BODY,
            "the marker was written on adoption"
        );
        // `ls` adopts too.
        let c = unmarked(&[&key("x")], &[]);
        assert_eq!(overview(&c.root, &c.home, &alive).unwrap().entries, 1);
        assert!(c.root.join(MARKER).is_file());
    }

    #[test]
    fn a_root_with_nothing_in_it_is_not_refused_and_not_marked_by_a_look() {
        let c = unmarked(&[], &[]);
        assert_eq!(overview(&c.root, &c.home, &alive).unwrap().entries, 0);
        assert!(
            prune(&c.root, &c.home, &c.opts(0), &alive)
                .unwrap()
                .removed
                .is_empty()
        );
        assert!(!c.root.join(MARKER).exists());
        let missing = c._tmp.path().join("missing");
        assert_eq!(overview(&missing, &c.home, &alive).unwrap().entries, 0);
    }

    #[test]
    fn a_marked_root_prunes_only_names_shaped_like_keys() {
        let c = Cache::new();
        c.entry("old", 100, 90);
        let keep = c.root.join(DEPS).join("not-a-key");
        fs::create_dir_all(&keep).unwrap();
        let report = c.prune(&c.opts(0));
        assert_eq!(keys(&report), ["old"]);
        assert!(keep.is_dir(), "a name that is no cache key was removed");
    }

    #[test]
    fn keys_and_work_names_have_one_shape() {
        assert!(is_key(&key("x")));
        assert!(!is_key("old-project"));
        assert!(!is_key(&key("j").to_uppercase()), "upper case is not a key");
        assert!(!is_key(&format!("{}0", key("x"))));
        assert_eq!(work_pid("123-456"), Some(123));
        assert_eq!(work_pid("123-456-prune"), Some(123));
        for bad in ["123", "123-", "123-abc", "0-1", "x-1", "-1", "123-1-other"] {
            assert_eq!(work_pid(bad), None, "{bad}");
        }
    }
    #[test]
    fn an_unused_seed_is_pruned_by_the_same_rules_and_a_leased_one_is_kept() {
        let c = Cache::new();
        c.seed("old-seed", 300, 40);
        let held = c.seed("held-seed", 300, 40);
        c.lease(&held, LIVE);
        c.seed("recent-seed", 300, 2);
        c.entry("old-deps", 100, 40);
        let o = c.opts(30);
        let overview = overview(&c.root, &c.home, &alive).unwrap();
        assert_eq!(overview.entries, 4, "both kinds are counted");
        assert_eq!(overview.bytes, 300 * 3 + 100);

        let report = c.prune(&o);
        let mut gone: Vec<(Area, String)> = report
            .removed
            .iter()
            .map(|r| (r.area, label(&r.key)))
            .collect();
        gone.sort_by_key(|(_, l)| l.clone());
        assert_eq!(
            gone,
            [
                (Area::Deps, "old-deps".to_string()),
                (Area::VerifyTarget, "old-seed".to_string())
            ]
        );
        assert!(!c.has_seed("old-seed") && !c.has("old-deps"));
        assert!(c.has_seed("held-seed"), "a live lease protects a seed");
        assert!(c.has_seed("recent-seed"));
        assert_eq!(
            report.in_use,
            [(format!("verify-target/{}", key("held-seed")), vec![LIVE])]
        );
        assert!(
            fs::read_dir(c.root.join(DEPS_WORK))
                .map(|r| r.count())
                .unwrap_or(0)
                == 0,
            "the removed seed left nothing in deps-work"
        );
    }

    #[test]
    fn a_seed_whose_only_lease_is_dead_is_pruned_and_the_size_pass_counts_seeds() {
        let c = Cache::new();
        let stale = c.seed("stale", 500, 5);
        c.lease(&stale, DEAD);
        c.seed("a-newest", 500, 1);
        let mut o = c.opts(30);
        o.max_bytes = Some(500);
        let report = c.prune(&o);
        assert_eq!(keys(&report), ["stale"]);
        assert_eq!(report.removed[0].reason, Reason::Size);
        assert!(!c.has_seed("stale") && c.has_seed("a-newest"));
    }

    /// A read-only directory (0555) with a file inside it, under `parent`, and a symlink
    /// inside it that points at `outside`.
    fn read_only_dir_with_a_link(parent: &Path, outside: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let ro = parent.join("ro");
        fs::create_dir_all(ro.join("inner")).unwrap();
        fs::write(ro.join("inner/data"), "x").unwrap();
        fs::write(ro.join("file"), "y").unwrap();
        std::os::unix::fs::symlink(outside, ro.join("link")).unwrap();
        fs::set_permissions(ro.join("inner"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
    }

    #[test]
    fn a_seed_an_entry_and_a_stale_work_directory_with_a_read_only_directory_are_pruned() {
        use std::os::unix::fs::PermissionsExt;
        let c = Cache::new();
        let outside = c.root.parent().unwrap().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), "keep").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o555)).unwrap();
        let seed = c.seed("ro-seed", 100, 40);
        let entry = c.entry("ro-deps", 100, 40);
        read_only_dir_with_a_link(&seed.join("target/debug"), &outside);
        read_only_dir_with_a_link(&entry.join("cargo"), &outside);
        let work = c.root.join(DEPS_WORK).join(format!("{DEAD}-1"));
        fs::create_dir_all(&work).unwrap();
        read_only_dir_with_a_link(&work, &outside);

        let report = c.prune(&c.opts(30));
        let outside_mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        let kept = fs::read_to_string(outside.join("keep"));
        // Leave the temp tree removable whatever the assertions find.
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        let mut gone = keys(&report);
        gone.sort();
        assert_eq!(gone, ["ro-deps", "ro-seed"]);
        assert!(!c.has_seed("ro-seed") && !c.has("ro-deps"));
        assert!(!work.exists(), "a stale work directory is swept");
        assert_eq!(report.work_removed.len(), 1, "{:?}", report.work_removed);
        assert_eq!(outside_mode, 0o555, "a link was not followed to a chmod");
        assert_eq!(kept.unwrap(), "keep");
    }

    #[test]
    fn an_unmarked_root_with_a_foreign_name_in_verify_target_is_not_adopted() {
        let t = tmp();
        let root = t.path().join("cache");
        fs::create_dir_all(root.join(VERIFY_TARGET).join("not-a-key")).unwrap();
        let err = require_owned(&root, &t.path().join("home")).unwrap_err();
        assert!(
            format!("{err:#}").contains("verify-target/not-a-key"),
            "{err:#}"
        );
        assert!(!root.join(MARKER).exists());
    }
}
