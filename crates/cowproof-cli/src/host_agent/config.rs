//! The host owner's config for a forced key (D27 clause 6): `~/.config/cowproof/host.toml`.
//!
//! A forced-command key limits the director to the host-agent verbs, but three of their
//! arguments reach outside the sandbox or across the host user's files: `doctor --claude-bin`
//! (runs `<path> --version` as the host user), the builder spec's `claude_bin` (the executable
//! the sandbox runs) and `--root` (the lanes directory, which `cleanup` removes under). In
//! forced mode `host-agent` takes all three from this file, which only the host's OWNER writes
//! (`cowproof host setup --write-config`, or by hand); the director may repeat what the file
//! says and nothing else.
//!
//! ```toml
//! claude = "/home/u/.local/bin/claude"
//! root = "/home/u/.cache/cowproof/remote-lanes"
//! ```
//!
//! `claude` is required and absolute; `root` is absolute and defaults to the remote root a
//! direct call uses. No other key is accepted, so a misspelt `root` cannot silently leave the
//! default in force. The file is read only if it is a regular file (not a link) owned by the
//! user running `host-agent`, writable by nobody else, in a directory that nobody else can
//! write either: anything else could have been put there by someone other than the owner.
//!
//! Its place, for a forced key, is always `$HOME/.config/cowproof/host.toml`, where `HOME` is what
//! `sshd` set from the passwd entry. `XDG_CONFIG_HOME` is ignored there: a client can pass `XDG_*`
//! variables through `AcceptEnv`, which it cannot do for `HOME`, and a variable the director
//! controls must not choose the file that limits the director. `cowproof host setup` honours
//! `XDG_CONFIG_HOME` (set to an absolute path, as the XDG rule says) and warns when that is not
//! the file a forced key reads.
//!
//! The file is also refused when it lies under the configured lanes root or under the default
//! remote root (compared by canonical path): a lane directory is filled by the director, so a
//! file there is not the owner's.

use anyhow::{Context, Result, anyhow, bail};
use cowproof_prove::runner::effective_uid;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// The file's name inside `<config home>/cowproof/`.
const FILE_NAME: &str = "host.toml";

/// The most the file may hold. Two paths are far under a kilobyte.
const MAX_BYTES: u64 = 64 * 1024;

/// The file as written: the two paths, and nothing else.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileText {
    claude: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<String>,
}

/// A config that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostConfig {
    /// The `claude` executable on this host, absolute.
    pub claude: PathBuf,
    /// The lanes directory, absolute.
    pub root: PathBuf,
}

/// What reading the owner's config found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Loaded {
    /// There is no file: the owner has not opted in.
    Missing,
    /// There is a file that must not be trusted, or cannot be read; `problem` says why and
    /// never quotes its contents.
    Invalid(String),
    Ok(HostConfig),
}

/// The config file's path for this `HOME` and `XDG_CONFIG_HOME`.
pub(crate) fn config_path(home: &Path, xdg_config_home: Option<&OsStr>) -> PathBuf {
    let base = xdg_config_home
        .map(Path::new)
        .filter(|p| p.is_absolute())
        .map_or_else(|| home.join(".config"), Path::to_path_buf);
    base.join("cowproof").join(FILE_NAME)
}

/// [`config_path`] for this process's environment, honouring `XDG_CONFIG_HOME` only when
/// `honour_xdg` is set. A forced key never does ([`forced_config_path`]).
pub(crate) fn current_config_path(honour_xdg: bool) -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))?;
    let xdg = std::env::var_os("XDG_CONFIG_HOME").filter(|_| honour_xdg);
    Ok(config_path(&home, xdg.as_deref()))
}

/// The file a forced key reads: `$HOME/.config/cowproof/host.toml`, whatever
/// `XDG_CONFIG_HOME` says.
pub(crate) fn forced_config_path() -> Result<PathBuf> {
    current_config_path(false)
}

/// The default `root`: what a direct `host-agent` call uses without `--root`.
fn default_root() -> Result<PathBuf> {
    crate::host_agent::remote_root(None)
}

/// "mode 0666", for a message.
fn mode_text(mode: u32) -> String {
    format!("mode {:04o}", mode & 0o7777)
}

/// Why `meta` (of the file or its directory) cannot be trusted as the owner's, or `None`.
fn untrusted(meta: &fs::Metadata, what: &str, path: &Path) -> Option<String> {
    let me = effective_uid();
    if meta.uid() != me {
        return Some(format!(
            "{what} {} is owned by uid {}, not by the user running host-agent (uid {me})",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Some(format!(
            "{what} {} is writable by its group or by others ({}): only its owner may write it; \
             run chmod go-w on it",
            path.display(),
            mode_text(meta.mode())
        ));
    }
    None
}

/// Read and check the config at `path`.
pub(crate) fn load(path: &Path) -> Loaded {
    match read(path) {
        Ok(found) => found,
        Err(e) => Loaded::Invalid(format!("{e:#}")),
    }
}

fn read(path: &Path) -> Result<Loaded> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Missing),
        Err(e) => bail!("cannot look at the host config {}: {e}", path.display()),
        Ok(meta) if meta.file_type().is_symlink() => bail!(
            "the host config {} is a symbolic link: it must be the file itself",
            path.display()
        ),
        Ok(meta) if !meta.is_file() => {
            bail!("the host config {} is not a regular file", path.display())
        }
        Ok(_) => {}
    }
    // Check what was opened, not what the name said a moment ago.
    let file = fs::File::open(path)
        .with_context(|| format!("opening the host config {}", path.display()))?;
    let meta = file.metadata()?;
    if let Some(problem) = untrusted(&meta, "the host config", path) {
        return Ok(Loaded::Invalid(problem));
    }
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("the host config {} has no directory", path.display()))?;
    let dir_meta = fs::metadata(dir)
        .with_context(|| format!("looking at the host config's directory {}", dir.display()))?;
    if let Some(problem) = untrusted(&dir_meta, "the host config's directory", dir) {
        return Ok(Loaded::Invalid(problem));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading the host config {}", path.display()))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!(
            "the host config {} is larger than {MAX_BYTES} bytes",
            path.display()
        );
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow!("the host config {} is not text", path.display()))?;
    // Only the parser's message: not the offending line of the file.
    let parsed: FileText = toml::from_str(&text).map_err(|e| {
        anyhow!(
            "the host config {} is not valid: {}",
            path.display(),
            e.message()
        )
    })?;
    let claude = absolute(&parsed.claude, "claude")?;
    let root = match &parsed.root {
        Some(root) => absolute(root, "root")?,
        None => default_root()?,
    };
    // A lane is filled by the director: a config inside the lanes root, or inside the default
    // remote root, could be a file the director put there.
    let here = fs::canonicalize(path)
        .with_context(|| format!("resolving the host config {}", path.display()))?;
    for (name, lanes) in [("configured", &root), ("default", &default_root()?)] {
        if here.starts_with(canonical_lenient(lanes)) {
            bail!(
                "the host config {} lies under the {name} lanes root {}: files there can come \
                 from the director; keep the config outside it, or choose another root",
                path.display(),
                lanes.display()
            );
        }
    }
    Ok(Loaded::Ok(HostConfig { claude, root }))
}

/// `path` with its existing part made canonical (links resolved) and the rest, which does not
/// exist yet, kept as written: a lanes root is made on first use.
fn canonical_lenient(path: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut at = path.to_path_buf();
    loop {
        if let Ok(real) = at.canonicalize() {
            return missing.iter().rev().fold(real, |p, part| p.join(part));
        }
        match (at.file_name().map(OsStr::to_os_string), at.parent()) {
            (Some(name), Some(parent)) => {
                missing.push(name);
                at = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// `value` as an absolute path without `..`, or the problem with the key `key`.
fn absolute(value: &str, key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if value.is_empty() || value.contains('\0') || !path.is_absolute() {
        bail!("`{key}` in the host config must be an absolute path");
    }
    if path.components().any(|c| c == Component::ParentDir) {
        bail!("`{key}` in the host config must not contain `..`");
    }
    Ok(path)
}

/// The text of a config naming `claude` and `root`, both absolute and valid UTF-8.
pub(crate) fn render(claude: &Path, root: &Path) -> Result<String> {
    let text = |p: &Path, key: &str| -> Result<String> {
        let s = p
            .to_str()
            .ok_or_else(|| anyhow!("`{key}` is not valid UTF-8"))?;
        absolute(s, key)?;
        Ok(s.to_string())
    };
    let body = toml::to_string(&FileText {
        claude: text(claude, "claude")?,
        root: Some(text(root, "root")?),
    })
    .context("writing the host config")?;
    Ok(format!(
        "# The host owner's settings for `cowproof host-agent --forced` (D27). The director's key\n\
         # runs only these: `claude` is the executable `doctor` and the builder may use, and\n\
         # `root` is the only lanes directory. Edit this file yourself; the key cannot. It is\n\
         # ignored unless only its owner can write it and its directory.\n\
         {body}"
    ))
}

/// Write `text` to `path` with mode 0600, in a directory made with mode 0700 if it is new.
/// Without `force` an existing file is an error and is left as it was; with it the file is
/// replaced whole (a new file renamed over the old one).
pub(crate) fn write(path: &Path, text: &str, force: bool) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no directory", path.display()))?;
    let dir_is_new = !dir.exists();
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    if dir_is_new {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting the mode of {}", dir.display()))?;
    }
    let create = |target: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
    };
    if !force {
        let mut file = create(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!(
                    "{} exists and was left as it was: pass --force to replace it",
                    path.display()
                )
            } else {
                anyhow!("creating {}: {e}", path.display())
            }
        })?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        return Ok(());
    }
    let temp = dir.join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temp);
    let written = create(&temp)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .and_then(|()| fs::rename(&temp, path));
    if let Err(e) = written {
        let _ = fs::remove_file(&temp);
        bail!("writing {}: {e}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("cp-hostconfig-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    /// A config directory of mode 0700 holding `text` at mode 0600.
    fn put(base: &Path, text: &str) -> PathBuf {
        let dir = base.join("cowproof");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(FILE_NAME);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn problem(loaded: Loaded) -> String {
        match loaded {
            Loaded::Invalid(p) => p,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn xdg_config_home_is_honoured_only_when_absolute() {
        let home = Path::new("/home/u");
        let want = |p: &str| PathBuf::from(p);
        assert_eq!(
            config_path(home, None),
            want("/home/u/.config/cowproof/host.toml")
        );
        assert_eq!(
            config_path(home, Some(OsStr::new("/srv/cfg"))),
            want("/srv/cfg/cowproof/host.toml")
        );
        // The XDG rule: a relative value, and an empty one, are ignored.
        for ignored in ["", "cfg", "./cfg"] {
            assert_eq!(
                config_path(home, Some(OsStr::new(ignored))),
                want("/home/u/.config/cowproof/host.toml"),
                "{ignored:?}"
            );
        }
    }

    #[test]
    fn a_config_under_the_lanes_root_or_the_default_root_is_refused() {
        let base = scratch();
        let path = put(base.path(), "claude = \"/opt/claude\"\n");
        let with_root = |root: &Path| {
            put(
                base.path(),
                &format!("claude = \"/opt/claude\"\nroot = \"{}\"\n", root.display()),
            )
        };
        // The root is the config's directory, or a parent of it, or a link to a parent.
        for root in [
            path.parent().unwrap().to_path_buf(),
            base.path().to_path_buf(),
        ] {
            let p = problem(load(&with_root(&root)));
            assert!(p.contains("lanes root") && p.contains("host config"), "{p}");
        }
        let link = tempfile::Builder::new()
            .prefix("cp-hostconfig-link-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let link = link.path().join("l");
        std::os::unix::fs::symlink(base.path(), &link).unwrap();
        assert!(problem(load(&with_root(&link))).contains("lanes root"));
        // A root that does not exist yet is compared by its existing part.
        let missing = base.path().join("not/yet/there");
        assert!(matches!(load(&with_root(&missing)), Loaded::Ok(_)));
        // A root below the config's directory is beside the file, not above it: fine.
        let below = base.path().join("cowproof/lanes");
        assert!(matches!(load(&with_root(&below)), Loaded::Ok(_)));
        // A root beside it is fine.
        let beside = tempfile::Builder::new()
            .prefix("cp-hostconfig-beside-")
            .tempdir_in("/var/tmp")
            .unwrap();
        assert!(matches!(load(&with_root(beside.path())), Loaded::Ok(_)));
    }

    #[test]
    fn what_render_writes_is_what_load_reads_back() {
        let base = scratch();
        let text = render(
            Path::new("/opt/my bin/it's/claude"),
            Path::new("/srv/\"lanes\"/x"),
        )
        .unwrap();
        let path = put(base.path(), &text);
        assert_eq!(
            load(&path),
            Loaded::Ok(HostConfig {
                claude: PathBuf::from("/opt/my bin/it's/claude"),
                root: PathBuf::from("/srv/\"lanes\"/x"),
            })
        );
    }

    #[test]
    fn a_missing_file_is_missing_and_a_root_left_out_is_the_default() {
        let base = scratch();
        assert_eq!(
            load(&base.path().join("cowproof/host.toml")),
            Loaded::Missing
        );
        let path = put(base.path(), "claude = \"/opt/claude\"\n");
        match load(&path) {
            Loaded::Ok(c) => {
                assert_eq!(c.claude, Path::new("/opt/claude"));
                assert!(c.root.ends_with(".cache/cowproof/remote-lanes"), "{c:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_file_others_can_write_or_that_is_not_ours_is_refused_naming_the_problem() {
        let base = scratch();
        let path = put(base.path(), "claude = \"/opt/claude\"\n");
        for mode in [0o666, 0o620, 0o602, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let p = problem(load(&path));
            assert!(
                p.contains("writable by its group or by others") && p.contains("chmod go-w"),
                "{mode:o}: {p}"
            );
            assert!(p.contains(&format!("mode {mode:04o}")), "{p}");
        }
        // Readable by others is not writable by others.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&path), Loaded::Ok(_)));
        // The directory counts too: anyone who can write it can swap the file.
        let dir = path.parent().unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o775)).unwrap();
        let p = problem(load(&path));
        assert!(p.contains("directory") && p.contains("writable"), "{p}");
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(load(&path), Loaded::Ok(_)));
    }

    #[test]
    fn a_link_a_directory_and_a_bad_file_are_refused_without_quoting_the_file() {
        let base = scratch();
        let real = put(base.path(), "claude = \"/opt/claude\"\n");
        let other = base.path().join("other");
        fs::create_dir(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
        let link = other.join("host.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(problem(load(&link)).contains("symbolic link"));
        assert!(problem(load(real.parent().unwrap())).contains("not a regular file"));

        let secret = "SECRET-MARKER-98765";
        for (text, expect) in [
            ("claude = \"relative/claude\"\n".to_string(), "`claude`"),
            ("claude = \"/a/../b\"\n".to_string(), "`..`"),
            (
                "claude = \"/opt/claude\"\nroot = \"lanes\"\n".to_string(),
                "`root`",
            ),
            ("root = \"/srv/x\"\n".to_string(), "not valid"),
            (
                format!("claude = \"/opt/claude\"\nroot_dir = \"{secret}\"\n"),
                "not valid",
            ),
            (format!("claude = [\"{secret}\"\n"), "not valid"),
            ("claude = \"\"\n".to_string(), "`claude`"),
        ] {
            let path = put(base.path(), &text);
            let p = problem(load(&path));
            assert!(p.contains(expect), "{text:?}: {p}");
            assert!(!p.contains(secret), "{p}");
        }
        let path = put(base.path(), "");
        fs::write(&path, vec![b'#'; (MAX_BYTES + 1) as usize]).unwrap();
        assert!(problem(load(&path)).contains("larger than"));
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(problem(load(&path)).contains("not text"));
    }

    #[test]
    fn write_makes_a_private_file_refuses_to_overwrite_and_replaces_with_force() {
        let base = scratch();
        let path = base.path().join("deep/er/cowproof").join(FILE_NAME);
        write(&path, "one\n", false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\n");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        let err = write(&path, "two\n", false).unwrap_err().to_string();
        assert!(
            err.contains("--force") && err.contains("left as it was"),
            "{err}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\n");

        write(&path, "two\n", true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        assert_eq!(mode(&path), 0o600);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [OsStr::new(FILE_NAME)], "no temporary file is left");
    }
}
