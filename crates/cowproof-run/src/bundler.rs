//! The Bundler lockfile, read in Rust (the dependency fetch of a Ruby tree).
//!
//! A `Gemfile` is Ruby code, so the fetch never runs `bundle` and never evaluates one: it
//! reads `Gemfile.lock` (or `gems.locked`) as text, takes the gems the lockfile names, and
//! downloads each as a `.gem` file ([`crate::deps`]). This module is that text reader and the
//! rules that decide, from the text alone, what is fetched and what is `not_fetched`.
//!
//! * **Sections.** `GEM` (each with its `remote:` lines and `specs:`), `PLATFORMS`,
//!   `DEPENDENCIES`, `CHECKSUMS` (Bundler 2.5+), `RUBY VERSION` and `BUNDLED WITH` are read or
//!   skipped. `GIT`, `PATH` and `PLUGIN SOURCE` are recognised so that [`plan`] can refuse
//!   them by name. Any other line at the left margin (a merge-conflict marker, an unknown
//!   section) makes the file not parse: the reader fails closed and never guesses.
//! * **Platforms** ([`Host`], [`wanted`]): a locked gem is downloaded when its platform is
//!   `ruby` (no suffix) or one of the HOST's platforms, matched by CPU and OS only: the CPU
//!   aliases of this machine (`x86_64`, `x64`, `amd64`; `aarch64`, `arm64`; `universal` for
//!   macOS) and its OS (`linux` or `darwin`). A libc suffix (`-gnu`, `-musl`) and a macOS
//!   version (`-23`) are ignored, so `x86_64-linux`, `x86_64-linux-musl` and `arm64-darwin-23`
//!   all match their host. Every other platform (`java`, `mswin`, `x64-mingw-ucrt`, another
//!   CPU) is left out. Bundler chooses among the downloaded variants when it installs.
//! * **Checksums** ([`GemLock::checksum`]): a `sha256=` in `CHECKSUMS` is compared with the
//!   downloaded file by the caller. When the BASE's lockfile lists a gem (same name, version
//!   and platform) with a checksum, that checksum is the one compared, whatever the lane's
//!   lockfile says ([`plan_with_base`]); a gem with none anywhere is fetched and listed as
//!   unverified ([`Fetch::unverified`]).
//! * **Pinned remotes** ([`plan_with_base`]): a gem the base takes from some remotes is fetched
//!   only if the lane's lockfile names the same remotes for it; a moved gem is `not_fetched`.
//! * **Bounds** ([`MAX_SPECS`], [`MAX_REMOTES_PER_SOURCE`], and the 8 MiB the callers read at
//!   most): a lockfile over one makes [`parse`] fail, naming the bound.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The lockfile names Bundler reads at the tree root.
pub const GEM_LOCKFILES: [&str; 2] = ["Gemfile.lock", "gems.locked"];

/// The most locked gems (specs) a lockfile may list, and the most `CHECKSUMS` entries. A real
/// lockfile has hundreds; the plan, the script and the checks are linear in this.
pub const MAX_SPECS: usize = 20_000;

/// The most `remote:` lines one `GEM` section may have. Specs name their section's remotes
/// by index, never copy them (S-3).
pub const MAX_REMOTES_PER_SOURCE: usize = 16;

/// One locked gem: `name (version)` or `name (version-platform)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GemSpec {
    pub name: String,
    pub version: String,
    /// `None` is the `ruby` platform (no suffix in the lockfile).
    pub platform: Option<String>,
}

impl GemSpec {
    /// `name (version)` or `name (version-platform)`: the form the lockfile uses.
    pub fn label(&self) -> String {
        match &self.platform {
            Some(p) => format!("{} ({}-{p})", self.name, self.version),
            None => format!("{} ({})", self.name, self.version),
        }
    }

    /// The file `gem fetch` leaves: `name-version.gem` or `name-version-platform.gem`.
    pub fn file_name(&self) -> String {
        match &self.platform {
            Some(p) => format!("{}-{}-{p}.gem", self.name, self.version),
            None => format!("{}-{}.gem", self.name, self.version),
        }
    }
}

/// A `GEM` section: its remotes and the gems locked from it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GemSource {
    pub remotes: Vec<String>,
    pub specs: Vec<GemSpec>,
}

/// A parsed lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GemLock {
    /// The `GEM` sections, in file order.
    pub sources: Vec<GemSource>,
    /// The headers of the sections that name a source this runner does not fetch (`GIT`,
    /// `PATH`, `PLUGIN SOURCE`), in file order.
    pub other_sources: Vec<String>,
    pub platforms: Vec<String>,
    /// `Some` when the file has a `CHECKSUMS` section (possibly with no entries). A gem maps
    /// to its lowercase hex sha256, or to `None` when its entry has no `sha256=`.
    checksums: Option<BTreeMap<GemSpec, Option<String>>>,
}

impl GemLock {
    /// Whether the file has a `CHECKSUMS` section.
    pub fn has_checksums(&self) -> bool {
        self.checksums.is_some()
    }

    /// The sha256 (lowercase hex) the lockfile gives `spec`, when it gives one.
    pub fn checksum(&self, spec: &GemSpec) -> Option<&str> {
        self.checksums
            .as_ref()?
            .get(spec)
            .and_then(|sum| sum.as_deref())
    }
}

/// Why a file is not a lockfile this reader understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub why: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.why)
    }
}

fn err(line: usize, why: impl Into<String>) -> ParseError {
    ParseError {
        line,
        why: why.into(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Gem,
    Other,
    Platforms,
    Dependencies,
    Checksums,
    Skipped,
}

/// Read `text` as a Bundler lockfile.
///
/// Names and versions end up in command lines, so they are checked here: a gem name is
/// letters, digits, `.`, `_` and `-` and does not start with `-`; a version starts with a
/// digit and holds letters, digits, `.` and `_`; a platform holds letters, digits, `.`, `_`
/// and `-`. Anything else makes the file not parse.
pub fn parse(text: &str) -> Result<GemLock, ParseError> {
    if text.len() as u64 > crate::MAX_DEPENDENCY_INPUT_BYTES {
        return Err(err(
            1,
            format!("larger than the {} bound", crate::MAX_DEPENDENCY_INPUT_TEXT),
        ));
    }
    let mut lock = GemLock::default();
    let mut section = Section::Skipped;
    let mut saw_header = false;
    let mut in_specs = false;
    let mut spec_count = 0usize;
    for (index, raw) in text.lines().enumerate() {
        let n = index + 1;
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            saw_header = true;
            in_specs = false;
            section = match line {
                "GEM" => {
                    lock.sources.push(GemSource::default());
                    Section::Gem
                }
                "GIT" | "PATH" | "PLUGIN SOURCE" => {
                    lock.other_sources.push(line.to_string());
                    Section::Other
                }
                "PLATFORMS" => Section::Platforms,
                "DEPENDENCIES" => Section::Dependencies,
                "CHECKSUMS" => {
                    lock.checksums.get_or_insert_with(BTreeMap::new);
                    Section::Checksums
                }
                "RUBY VERSION" | "BUNDLED WITH" => Section::Skipped,
                other => {
                    return Err(err(n, format!("unknown section {:?}", clip(other))));
                }
            };
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        match section {
            Section::Gem => {
                let source = lock
                    .sources
                    .last_mut()
                    .expect("a GEM header pushed the source");
                if indent == 2 {
                    if let Some(remote) = body.strip_prefix("remote:") {
                        let remote = remote.trim();
                        if remote.is_empty() {
                            return Err(err(n, "an empty remote"));
                        }
                        if source.remotes.len() >= MAX_REMOTES_PER_SOURCE {
                            return Err(err(
                                n,
                                format!(
                                    "more than {MAX_REMOTES_PER_SOURCE} remotes in a GEM section (the bound)"
                                ),
                            ));
                        }
                        source.remotes.push(remote.to_string());
                        in_specs = false;
                    } else if body == "specs:" {
                        in_specs = true;
                    } else {
                        return Err(err(
                            n,
                            format!("unexpected {:?} in a GEM section", clip(body)),
                        ));
                    }
                } else if indent == 4 && in_specs {
                    spec_count += 1;
                    if spec_count > MAX_SPECS {
                        return Err(err(
                            n,
                            format!("more than {MAX_SPECS} locked gems (the bound)"),
                        ));
                    }
                    source
                        .specs
                        .push(parse_spec(body).map_err(|why| err(n, why))?);
                } else if indent < 4 || !in_specs {
                    return Err(err(
                        n,
                        format!("unexpected {:?} in a GEM section", clip(body)),
                    ));
                }
                // Deeper lines are the dependencies of a spec: not needed.
            }
            Section::Platforms => {
                if indent != 2 || !plain(body, true) {
                    return Err(err(n, format!("bad platform {:?}", clip(body))));
                }
                lock.platforms.push(body.to_string());
            }
            Section::Checksums => {
                let sums = lock.checksums.get_or_insert_with(BTreeMap::new);
                let (spec, sum) = parse_checksum(body).map_err(|why| err(n, why))?;
                if sums.len() >= MAX_SPECS && !sums.contains_key(&spec) {
                    return Err(err(
                        n,
                        format!("more than {MAX_SPECS} CHECKSUMS entries (the bound)"),
                    ));
                }
                sums.insert(spec, sum);
            }
            Section::Other | Section::Dependencies | Section::Skipped => {}
        }
    }
    if !saw_header {
        return Err(err(1, "no section headers"));
    }
    Ok(lock)
}

fn clip(text: &str) -> String {
    text.chars().take(60).collect()
}

/// A remote URL cut short for a message (a lane can write a very long one).
fn clip_remote(text: &str) -> String {
    text.chars().take(120).collect()
}

/// `name (version)` or `name (version-platform)`, with nothing after.
fn parse_spec(body: &str) -> Result<GemSpec, String> {
    let (name, rest) = body
        .split_once(" (")
        .ok_or_else(|| format!("{:?} is not `name (version)`", clip(body)))?;
    let inner = rest
        .strip_suffix(')')
        .ok_or_else(|| format!("{:?} is not `name (version)`", clip(body)))?;
    spec_of(name, inner)
}

fn spec_of(name: &str, inner: &str) -> Result<GemSpec, String> {
    if !plain(name, false) {
        return Err(format!("{:?} is not a usable gem name", clip(name)));
    }
    let (version, platform) = match inner.split_once('-') {
        Some((v, p)) => (v, Some(p)),
        None => (inner, None),
    };
    let version_ok = version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
    if !version_ok {
        return Err(format!("{:?} is not a usable gem version", clip(version)));
    }
    if let Some(p) = platform
        && !plain(p, true)
    {
        return Err(format!("{:?} is not a usable platform", clip(p)));
    }
    Ok(GemSpec {
        name: name.to_string(),
        version: version.to_string(),
        platform: platform.map(str::to_string),
    })
}

/// Letters, digits, `.`, `_` and `-`, not empty and (for a name) not starting with `-`.
fn plain(text: &str, allow_leading_dash: bool) -> bool {
    !text.is_empty()
        && (allow_leading_dash || !text.starts_with('-'))
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `name (version[-platform])` or `name (version[-platform]) sha256=<hex>`.
fn parse_checksum(body: &str) -> Result<(GemSpec, Option<String>), String> {
    let (head, sum) = match body.rsplit_once(") ") {
        Some((head, sum)) => (format!("{head})"), Some(sum.trim())),
        None => (body.to_string(), None),
    };
    let spec = parse_spec(&head)?;
    let sum = match sum {
        None => None,
        Some(text) => {
            let hex = text
                .strip_prefix("sha256=")
                .ok_or_else(|| format!("{:?} is not a sha256 checksum", clip(text)))?;
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("{:?} is not a sha256 checksum", clip(hex)));
            }
            Some(hex.to_ascii_lowercase())
        }
    };
    Ok((spec, sum))
}

/// The platforms of the machine the gems are fetched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The CPU names RubyGems uses for this CPU.
    pub cpus: Vec<&'static str>,
    /// `linux` or `darwin`; empty for an OS no gem platform is chosen for.
    pub os: &'static str,
}

impl Host {
    /// This machine.
    pub fn current() -> Self {
        Self::of(std::env::consts::ARCH, std::env::consts::OS)
    }

    /// The host for Rust's `ARCH` and `OS` constants.
    pub fn of(arch: &str, os: &str) -> Self {
        let cpus: Vec<&'static str> = match arch {
            "x86_64" => vec!["x86_64", "x64", "amd64"],
            "aarch64" => vec!["aarch64", "arm64"],
            "x86" => vec!["x86", "i386", "i486", "i586", "i686"],
            _ => Vec::new(),
        };
        let os = match os {
            "linux" => "linux",
            "macos" => "darwin",
            _ => "",
        };
        Self { cpus, os }
    }

    /// Whether a lockfile platform (`x86_64-linux`, `arm64-darwin-23`, `java`, ...) is this
    /// host's: CPU and OS only.
    pub fn matches(&self, platform: &str) -> bool {
        let mut parts = platform.split('-');
        let (Some(cpu), Some(os)) = (parts.next(), parts.next()) else {
            return false;
        };
        if self.os.is_empty() || os != self.os {
            return false;
        }
        self.cpus.contains(&cpu) || (cpu == "universal" && self.os == "darwin")
    }

    /// The word for messages.
    pub fn describe(&self) -> String {
        format!(
            "{}-{}",
            self.cpus.first().copied().unwrap_or("unknown"),
            if self.os.is_empty() {
                "unknown"
            } else {
                self.os
            }
        )
    }
}

/// Whether `spec` is downloaded for `host`: the `ruby` platform, or a platform of the host.
pub fn wanted(spec: &GemSpec, host: &Host) -> bool {
    match &spec.platform {
        None => true,
        Some(p) => host.matches(p),
    }
}

/// A sha256 a download must have, and whose lockfile gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// Lowercase hex.
    pub sha256: String,
    /// The BASE's lockfile gave it (not the lane's own).
    pub from_base: bool,
}

/// One gem to download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    pub spec: GemSpec,
    /// The index, in [`Fetch::sources`], of the remotes of its `GEM` section. Never a copy:
    /// a section's remotes are held once however many gems it has (S-3).
    pub source: usize,
    /// What the download must hash to; `None` when no lockfile says (the gem is unverified).
    pub checksum: Option<Checksum>,
}

/// What a lockfile asks the fetch to download.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fetch {
    /// The remotes of each `GEM` section of the lane's lockfile, once each, in file order.
    pub sources: Vec<Vec<String>>,
    /// The gems (sorted, each once).
    pub downloads: Vec<Download>,
}

impl Fetch {
    /// The remotes `download` is fetched from.
    pub fn remotes(&self, download: &Download) -> &[String] {
        &self.sources[download.source]
    }

    /// The gems no lockfile gives a checksum for: downloaded, but nothing says what they are.
    pub fn unverified(&self) -> Vec<&GemSpec> {
        self.downloads
            .iter()
            .filter(|d| d.checksum.is_none())
            .map(|d| &d.spec)
            .collect()
    }
}

/// What a lockfile asks of the fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Download these gems.
    Fetch(Fetch),
    /// Nothing is fetched, for this reason: the line for the capsule's notes.
    NotFetched(String),
}

/// [`plan_with_base`] with no base lockfile: the lane's lockfile alone.
pub fn plan(file: &str, lock: &GemLock, host: &Host) -> Plan {
    plan_with_base(file, lock, None, host)
}

/// Judge `lock` (the lane's lockfile, read from the file called `file`) for `host`: the gems to
/// download, or the reason nothing is. `base` is the BASE's lockfile (from before the lane's
/// patch), when there is one.
///
/// Not fetched, never guessed: a `GIT`, `PATH` or `PLUGIN SOURCE` section; a `GEM` section
/// without a remote; a remote that is not `http` or `https` (a directory, `file://`); and a
/// gem from a remote that is not https with no sha256 in `CHECKSUMS` (plain http without a
/// checksum could be altered on the way). A gem the lockfile lists only for platforms other
/// than the host's is not fetched either, named.
///
/// The lane's lockfile is the lane's to write, so the base decides what it can (S-9):
///
/// * A gem (name, version and platform) the base lists with a checksum is compared with the
///   BASE's checksum, whatever the lane's lockfile says, a dropped `CHECKSUMS` included.
///   Otherwise the lane's checksum is used; a gem with neither is unverified.
/// * A gem the base takes from some remotes is fetched only from the same remotes (compared
///   without credentials or a trailing `/`); a lane that moves it, or adds a remote to its
///   section, gets `not_fetched` naming the gem and both lists. Gems the base does not list
///   are the lane's own and are not pinned.
pub fn plan_with_base(file: &str, lock: &GemLock, base: Option<&GemLock>, host: &Host) -> Plan {
    if let Some(section) = lock.other_sources.first() {
        return Plan::NotFetched(format!(
            "{file}: a {section} section (a source that is not a gem server) is not supported, so gems are not available to the verifier"
        ));
    }
    // The base's remotes, once per base section (normalised), and where each gem is.
    let base_remotes: Vec<BTreeSet<String>> = base
        .map(|b| b.sources.iter().map(|s| normalised(&s.remotes)).collect())
        .unwrap_or_default();
    let mut base_home: BTreeMap<&GemSpec, Vec<usize>> = BTreeMap::new();
    if let Some(b) = base {
        for (i, source) in b.sources.iter().enumerate() {
            for spec in &source.specs {
                base_home.entry(spec).or_default().push(i);
            }
        }
    }
    let mut fetch = Fetch::default();
    let mut chosen: BTreeMap<GemSpec, (usize, Option<Checksum>)> = BTreeMap::new();
    let mut seen_any = BTreeSet::new();
    for (index, source) in lock.sources.iter().enumerate() {
        if source.remotes.is_empty() {
            return Plan::NotFetched(format!(
                "{file}: a GEM section has no remote, so gems are not available to the verifier"
            ));
        }
        let mut all_https = true;
        for remote in &source.remotes {
            let scheme = remote.split("://").next().unwrap_or("");
            if !remote.contains("://") || !matches!(scheme, "http" | "https") {
                return Plan::NotFetched(format!(
                    "{file}: the remote {:?} is not an http or https gem server, so gems are not available to the verifier",
                    clip_remote(&drop_credentials(remote))
                ));
            }
            all_https &= scheme == "https";
        }
        fetch.sources.push(source.remotes.clone());
        let lane_remotes = normalised(&source.remotes);
        for spec in &source.specs {
            seen_any.insert((spec.name.clone(), spec.version.clone()));
            if !wanted(spec, host) {
                continue;
            }
            if let Some(homes) = base_home.get(spec)
                && !homes.iter().any(|h| base_remotes[*h] == lane_remotes)
            {
                return Plan::NotFetched(format!(
                    "{file}: {} comes from {} but the base lockfile takes it from {}, so a moved gem is not fetched",
                    spec.label(),
                    describe_remotes(&source.remotes),
                    describe_remotes(
                        &base.expect("a home is a base section").sources[homes[0]].remotes
                    ),
                ));
            }
            // The base's checksum wins over the lane's.
            let base_sum = base.and_then(|b| b.checksum(spec));
            let checksum = match (base_sum, lock.checksum(spec)) {
                (Some(sum), _) => Some(Checksum {
                    sha256: sum.to_string(),
                    from_base: true,
                }),
                (None, Some(sum)) => Some(Checksum {
                    sha256: sum.to_string(),
                    from_base: false,
                }),
                (None, None) => None,
            };
            if !all_https && checksum.is_none() {
                let why = if lock.has_checksums() {
                    "has no sha256 in CHECKSUMS"
                } else {
                    "and the file has no CHECKSUMS section"
                };
                return Plan::NotFetched(format!(
                    "{file}: {} comes from a remote that is not https {why}, so it cannot be verified and is not fetched",
                    spec.label()
                ));
            }
            chosen.entry(spec.clone()).or_insert((index, checksum));
        }
    }
    // A name and version with no variant for this host (only `java`, say) cannot be installed
    // here: say so instead of leaving the verifier to fail on a missing gem.
    for (name, version) in &seen_any {
        let have = chosen
            .keys()
            .any(|spec| &spec.name == name && &spec.version == version);
        if !have {
            return Plan::NotFetched(format!(
                "{file}: {name} ({version}) is locked only for platforms other than this host's ({}), so it is not fetched",
                host.describe()
            ));
        }
    }
    fetch.downloads = chosen
        .into_iter()
        .map(|(spec, (source, checksum))| Download {
            spec,
            source,
            checksum,
        })
        .collect();
    Plan::Fetch(fetch)
}

/// `remotes` as a set for comparison: no credentials, no trailing `/`.
fn normalised(remotes: &[String]) -> BTreeSet<String> {
    remotes
        .iter()
        .map(|r| drop_credentials(r).trim_end_matches('/').to_string())
        .collect()
}

/// `remotes` for a message: credentials removed, each cut short, at most the bound of them.
fn describe_remotes(remotes: &[String]) -> String {
    remotes
        .iter()
        .map(|r| clip_remote(&drop_credentials(r)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `url` without a `user:pass@` in its authority (the text unchanged when it has none): the
/// one URL cleaner of the dependency fetch ([`crate::deps`]).
pub fn drop_credentials(url: &str) -> String {
    crate::deps::drop_url_credentials(url).unwrap_or_else(|| url.to_string())
}

/// Whether `url` has a `user:pass@` (or `user@`) in its authority.
pub fn has_credentials(url: &str) -> bool {
    crate::deps::drop_url_credentials(url).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SUM_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn linux() -> Host {
        Host::of("x86_64", "linux")
    }

    fn lock_text() -> String {
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.0)\n      mini_portile2 (~> 2.8)\n    nokogiri (1.15.0-x86_64-linux)\n    nokogiri (1.15.0-arm64-darwin)\n    nokogiri (1.15.0-java)\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n  x86_64-linux\n\nDEPENDENCIES\n  nokogiri\n  rake\n\nCHECKSUMS\n  nokogiri (1.15.0) sha256={SUM_A}\n  rake (13.0.6) sha256={SUM_B}\n\nRUBY VERSION\n   ruby 3.2.2p53\n\nBUNDLED WITH\n   2.5.3\n"
        )
    }

    #[test]
    fn a_lockfile_is_read_into_remotes_specs_platforms_and_checksums() {
        let lock = parse(&lock_text()).unwrap();
        assert_eq!(lock.sources.len(), 1);
        assert_eq!(lock.sources[0].remotes, ["https://rubygems.org/"]);
        let labels: Vec<String> = lock.sources[0].specs.iter().map(GemSpec::label).collect();
        assert_eq!(
            labels,
            [
                "nokogiri (1.15.0)",
                "nokogiri (1.15.0-x86_64-linux)",
                "nokogiri (1.15.0-arm64-darwin)",
                "nokogiri (1.15.0-java)",
                "rake (13.0.6)"
            ]
        );
        assert_eq!(lock.platforms, ["ruby", "x86_64-linux"]);
        assert!(lock.has_checksums());
        let rake = GemSpec {
            name: "rake".into(),
            version: "13.0.6".into(),
            platform: None,
        };
        assert_eq!(lock.checksum(&rake), Some(SUM_B));
        let other = GemSpec {
            name: "rake".into(),
            version: "13.0.7".into(),
            platform: None,
        };
        assert_eq!(lock.checksum(&other), None);
        assert!(lock.other_sources.is_empty());
    }

    #[test]
    fn a_platform_gem_keeps_its_dashes_and_the_file_name_follows_gem_fetch() {
        let spec = parse_spec("grpc (1.60.0-arm64-darwin-23)").unwrap();
        assert_eq!(spec.version, "1.60.0");
        assert_eq!(spec.platform.as_deref(), Some("arm64-darwin-23"));
        assert_eq!(spec.file_name(), "grpc-1.60.0-arm64-darwin-23.gem");
        let plain = parse_spec("rake (13.0.6)").unwrap();
        assert_eq!(plain.file_name(), "rake-13.0.6.gem");
        let dashed_name = parse_spec("net-http (0.4.0)").unwrap();
        assert_eq!(dashed_name.name, "net-http");
        assert_eq!(dashed_name.file_name(), "net-http-0.4.0.gem");
    }

    #[test]
    fn only_ruby_and_the_hosts_platforms_are_wanted() {
        let lock = parse(&lock_text()).unwrap();
        let wanted_on = |host: &Host| -> Vec<String> {
            lock.sources[0]
                .specs
                .iter()
                .filter(|s| wanted(s, host))
                .map(GemSpec::label)
                .collect()
        };
        assert_eq!(
            wanted_on(&linux()),
            [
                "nokogiri (1.15.0)",
                "nokogiri (1.15.0-x86_64-linux)",
                "rake (13.0.6)"
            ]
        );
        assert_eq!(
            wanted_on(&Host::of("aarch64", "macos")),
            [
                "nokogiri (1.15.0)",
                "nokogiri (1.15.0-arm64-darwin)",
                "rake (13.0.6)"
            ]
        );
        // An OS or CPU no platform is chosen for takes the `ruby` gems only.
        assert_eq!(
            wanted_on(&Host::of("riscv64", "freebsd")),
            ["nokogiri (1.15.0)", "rake (13.0.6)"]
        );
    }

    #[test]
    fn host_platforms_match_by_cpu_and_os_and_ignore_libc_and_os_version() {
        let l = linux();
        for yes in [
            "x86_64-linux",
            "x86_64-linux-gnu",
            "x86_64-linux-musl",
            "x64-linux",
            "amd64-linux",
        ] {
            assert!(l.matches(yes), "{yes}");
        }
        for no in [
            "java",
            "jruby",
            "x86-linux",
            "aarch64-linux",
            "arm64-darwin",
            "x64-mingw-ucrt",
            "x86_64-darwin",
            "universal-darwin",
            "mswin32",
            "x86_64",
        ] {
            assert!(!l.matches(no), "{no}");
        }
        let m = Host::of("aarch64", "macos");
        for yes in [
            "arm64-darwin",
            "arm64-darwin-23",
            "aarch64-darwin",
            "universal-darwin-22",
        ] {
            assert!(m.matches(yes), "{yes}");
        }
        assert!(!m.matches("x86_64-darwin"));
        assert!(!m.matches("arm64-linux"));
    }

    #[test]
    fn a_plan_lists_each_wanted_gem_once_with_its_remotes() {
        let lock = parse(&lock_text()).unwrap();
        match plan("Gemfile.lock", &lock, &linux()) {
            Plan::Fetch(fetch) => {
                let names: Vec<String> =
                    fetch.downloads.iter().map(|d| d.spec.file_name()).collect();
                assert_eq!(
                    names,
                    [
                        "nokogiri-1.15.0.gem",
                        "nokogiri-1.15.0-x86_64-linux.gem",
                        "rake-13.0.6.gem"
                    ]
                );
                assert!(
                    fetch
                        .downloads
                        .iter()
                        .all(|d| fetch.remotes(d) == ["https://rubygems.org/"])
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn git_path_and_plugin_sources_are_not_fetched_and_named() {
        for section in ["GIT", "PATH", "PLUGIN SOURCE"] {
            let text = format!(
                "{section}\n  remote: https://git.example/x.git\n  revision: abc\n  specs:\n    x (1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n"
            );
            let lock = parse(&text).unwrap();
            assert_eq!(lock.other_sources, [section]);
            match plan("Gemfile.lock", &lock, &linux()) {
                Plan::NotFetched(note) => assert!(
                    note.starts_with("Gemfile.lock: a ") && note.contains(section),
                    "{note}"
                ),
                other => panic!("{section}: {other:?}"),
            }
        }
    }

    #[test]
    fn plain_http_needs_a_checksum_and_other_schemes_are_never_fetched() {
        let http = |checks: &str| {
            format!(
                "GEM\n  remote: http://gems.example/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n{checks}"
            )
        };
        let none = parse(&http("")).unwrap();
        match plan("Gemfile.lock", &none, &linux()) {
            Plan::NotFetched(note) => assert!(
                note.contains("rake (13.0.6)")
                    && note.contains("not https")
                    && note.contains("no CHECKSUMS section"),
                "{note}"
            ),
            other => panic!("{other:?}"),
        }
        let with = parse(&http(&format!(
            "\nCHECKSUMS\n  rake (13.0.6) sha256={SUM_A}\n"
        )))
        .unwrap();
        assert!(matches!(
            plan("Gemfile.lock", &with, &linux()),
            Plan::Fetch(_)
        ));
        let missing = parse(&http("\nCHECKSUMS\n  rake (13.0.6)\n")).unwrap();
        match plan("Gemfile.lock", &missing, &linux()) {
            Plan::NotFetched(note) => {
                assert!(note.contains("has no sha256 in CHECKSUMS"), "{note}")
            }
            other => panic!("{other:?}"),
        }
        for remote in ["file:///srv/gems/", "/srv/gems", "ftp://gems.example/"] {
            let text = format!(
                "GEM\n  remote: {remote}\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nCHECKSUMS\n  rake (13.0.6) sha256={SUM_A}\n"
            );
            match plan("Gemfile.lock", &parse(&text).unwrap(), &linux()) {
                Plan::NotFetched(note) => {
                    assert!(note.contains("not an http or https gem server"), "{note}")
                }
                other => panic!("{remote}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_gem_with_no_variant_for_the_host_is_named_not_left_to_the_verifier() {
        let text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    ffi (1.16.0-java)\n    rake (13.0.6)\n\nPLATFORMS\n  java\n  ruby\n";
        match plan("Gemfile.lock", &parse(text).unwrap(), &linux()) {
            Plan::NotFetched(note) => assert!(
                note.contains("ffi (1.16.0)") && note.contains("x86_64-linux"),
                "{note}"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_remote_credential_is_dropped_from_the_note_and_detected() {
        assert_eq!(
            drop_credentials("https://user:pw@gems.example/path"),
            "https://gems.example/path"
        );
        assert_eq!(
            drop_credentials("https://token@gems.example"),
            "https://gems.example"
        );
        assert_eq!(
            drop_credentials("https://gems.example/"),
            "https://gems.example/"
        );
        assert!(has_credentials("https://user:pw@gems.example/"));
        assert!(!has_credentials("https://gems.example/@x"));
        let text = "GEM\n  remote: ftp://user:SECRET@gems.example/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n";
        match plan("Gemfile.lock", &parse(text).unwrap(), &linux()) {
            Plan::NotFetched(note) => assert!(!note.contains("SECRET"), "{note}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_file_that_is_not_a_lockfile_does_not_parse() {
        for (text, why) in [
            ("", "no section headers"),
            ("just words\n", "unknown section"),
            ("<<<<<<< HEAD\nGEM\n", "unknown section"),
            (
                "GEM\n  remote: https://r/\n  specs:\n    rake 13\n",
                "not `name (version)`",
            ),
            (
                "GEM\n  remote: https://r/\n  specs:\n    -rf (1.0)\n",
                "usable gem name",
            ),
            (
                "GEM\n  remote: https://r/\n  specs:\n    rake (x1)\n",
                "usable gem version",
            ),
            (
                "GEM\n  remote: https://r/\n  specs:\n    rake (1.0-a b)\n",
                "usable platform",
            ),
            ("GEM\n  remote:\n  specs:\n", "empty remote"),
            ("GEM\n  bogus: 1\n", "unexpected"),
            ("PLATFORMS\n  ru by\n", "bad platform"),
            ("CHECKSUMS\n  rake (1.0) sha256=zz\n", "not a sha256"),
            ("CHECKSUMS\n  rake (1.0) md5=abc\n", "not a sha256"),
        ] {
            let e = parse(text).expect_err(text);
            assert!(e.why.contains(why), "{text:?}: {e}");
        }
    }

    #[test]
    fn a_lockfile_with_two_gem_sections_keeps_each_gems_own_remotes() {
        let text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nGEM\n  remote: https://gems.corp.example/\n  specs:\n    corp-lib (2.0.0)\n\nPLATFORMS\n  ruby\n";
        match plan("Gemfile.lock", &parse(text).unwrap(), &linux()) {
            Plan::Fetch(fetch) => {
                let list = &fetch.downloads;
                assert_eq!(list[0].spec.name, "corp-lib");
                assert_eq!(fetch.remotes(&list[0]), ["https://gems.corp.example/"]);
                assert_eq!(list[1].spec.name, "rake");
                assert_eq!(fetch.remotes(&list[1]), ["https://rubygems.org/"]);
            }
            other => panic!("{other:?}"),
        }
        // An old lockfile with several remotes in one section keeps them all.
        let old = "GEM\n  remote: https://a.example/\n  remote: https://b.example/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n";
        match plan("Gemfile.lock", &parse(old).unwrap(), &linux()) {
            Plan::Fetch(fetch) => assert_eq!(
                fetch.remotes(&fetch.downloads[0]),
                ["https://a.example/", "https://b.example/"]
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_gem_list_is_a_lockfile_with_nothing_to_download() {
        let text =
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n";
        match plan("Gemfile.lock", &parse(text).unwrap(), &linux()) {
            Plan::Fetch(fetch) => assert!(fetch.downloads.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    fn lock_of(remote: &str, specs: &[&str], sums: &[(&str, &str)]) -> GemLock {
        let mut text = format!("GEM\n  remote: {remote}\n  specs:\n");
        for spec in specs {
            text.push_str(&format!("    {spec}\n"));
        }
        text.push_str("\nPLATFORMS\n  ruby\n");
        if !sums.is_empty() {
            text.push_str("\nCHECKSUMS\n");
            for (spec, sum) in sums {
                text.push_str(&format!("  {spec} sha256={sum}\n"));
            }
        }
        parse(&text).unwrap()
    }

    fn fetch_of(plan: Plan) -> Fetch {
        match plan {
            Plan::Fetch(fetch) => fetch,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_section_s_remotes_are_held_once_however_many_gems_it_has() {
        // 16 remotes and 2000 specs: a plan that copied the remotes to each spec would hold
        // 32 000 strings; this holds 16.
        let mut text = String::from("GEM\n");
        for i in 0..MAX_REMOTES_PER_SOURCE {
            text.push_str(&format!("  remote: https://h{i}.example/\n"));
        }
        text.push_str("  specs:\n");
        for i in 0..2000 {
            text.push_str(&format!("    g{i} (1.0.0)\n"));
        }
        text.push_str("\nPLATFORMS\n  ruby\n");
        let fetch = fetch_of(plan("Gemfile.lock", &parse(&text).unwrap(), &linux()));
        assert_eq!(fetch.downloads.len(), 2000);
        let held: usize = fetch.sources.iter().map(Vec::len).sum();
        assert_eq!(held, MAX_REMOTES_PER_SOURCE);
        assert!(fetch.downloads.iter().all(|d| d.source == 0));
    }

    #[test]
    fn a_lockfile_over_a_bound_does_not_parse_and_names_the_bound() {
        // One remote too many.
        let mut text = String::from("GEM\n");
        for i in 0..=MAX_REMOTES_PER_SOURCE {
            text.push_str(&format!("  remote: https://h{i}.example/\n"));
        }
        text.push_str("  specs:\n");
        let e = parse(&text).expect_err("17 remotes");
        assert!(
            e.why.contains("more than 16 remotes") && e.why.contains("bound"),
            "{e}"
        );
        // One spec too many.
        let mut text = String::from("GEM\n  remote: https://r.example/\n  specs:\n");
        for i in 0..=MAX_SPECS {
            text.push_str(&format!("    g{i} (1.0)\n"));
        }
        let e = parse(&text).expect_err("20001 specs");
        assert!(
            e.why.contains("more than 20000 locked gems") && e.why.contains("bound"),
            "{e}"
        );
        assert_eq!(e.line, MAX_SPECS + 4);
        // Exactly at the bounds is fine.
        let mut text = String::from("GEM\n  remote: https://r.example/\n  specs:\n");
        for i in 0..MAX_SPECS {
            text.push_str(&format!("    g{i} (1.0)\n"));
        }
        assert_eq!(parse(&text).unwrap().sources[0].specs.len(), MAX_SPECS);
        // Too many checksum entries.
        let mut text = String::from("CHECKSUMS\n");
        for i in 0..=MAX_SPECS {
            text.push_str(&format!("  g{i} (1.0) sha256={SUM_A}\n"));
        }
        let e = parse(&text).expect_err("20001 checksums");
        assert!(e.why.contains("CHECKSUMS entries"), "{e}");
        // A text over the 8 MiB bound.
        let big = " ".repeat(crate::MAX_DEPENDENCY_INPUT_BYTES as usize + 1);
        let e = parse(&big).expect_err("over 8 MiB");
        assert!(e.why.contains("8 MiB"), "{e}");
    }

    #[test]
    fn the_bases_checksum_is_the_one_compared_whatever_the_lane_says() {
        let rake = "rake (13.0.6)";
        let base = lock_of("https://rubygems.org/", &[rake], &[(rake, SUM_A)]);
        // The lane drops CHECKSUMS.
        let dropped = lock_of("https://rubygems.org/", &[rake], &[]);
        let fetch = fetch_of(plan_with_base(
            "Gemfile.lock",
            &dropped,
            Some(&base),
            &linux(),
        ));
        assert_eq!(
            fetch.downloads[0].checksum,
            Some(Checksum {
                sha256: SUM_A.to_string(),
                from_base: true
            })
        );
        assert!(fetch.unverified().is_empty());
        // The lane gives its own, different checksum: the base's still wins.
        let own = lock_of("https://rubygems.org/", &[rake], &[(rake, SUM_B)]);
        let fetch = fetch_of(plan_with_base("Gemfile.lock", &own, Some(&base), &linux()));
        assert_eq!(fetch.downloads[0].checksum.as_ref().unwrap().sha256, SUM_A);
        // A gem the base does not list uses the lane's.
        let fetch = fetch_of(plan_with_base(
            "Gemfile.lock",
            &lock_of(
                "https://rubygems.org/",
                &[rake, "other (1.0)"],
                &[("other (1.0)", SUM_B)],
            ),
            Some(&base),
            &linux(),
        ));
        let other = fetch
            .downloads
            .iter()
            .find(|d| d.spec.name == "other")
            .unwrap();
        assert_eq!(
            other.checksum,
            Some(Checksum {
                sha256: SUM_B.to_string(),
                from_base: false
            })
        );
        // A base gem with no base checksum falls back to the lane's.
        let bare_base = lock_of("https://rubygems.org/", &[rake], &[]);
        let fetch = fetch_of(plan_with_base(
            "Gemfile.lock",
            &own,
            Some(&bare_base),
            &linux(),
        ));
        assert_eq!(fetch.downloads[0].checksum.as_ref().unwrap().sha256, SUM_B);
        // A different version or platform is a different gem: the base's checksum is not its.
        let bumped = lock_of("https://rubygems.org/", &["rake (13.0.7)"], &[]);
        let fetch = fetch_of(plan_with_base(
            "Gemfile.lock",
            &bumped,
            Some(&base),
            &linux(),
        ));
        assert_eq!(fetch.downloads[0].checksum, None);
    }

    #[test]
    fn a_gem_new_to_the_lane_with_no_checksum_is_unverified() {
        let base = lock_of(
            "https://rubygems.org/",
            &["rake (13.0.6)"],
            &[("rake (13.0.6)", SUM_A)],
        );
        let lane = lock_of(
            "https://rubygems.org/",
            &["rake (13.0.6)", "extra (2.1.0)"],
            &[],
        );
        let fetch = fetch_of(plan_with_base("Gemfile.lock", &lane, Some(&base), &linux()));
        let names: Vec<String> = fetch
            .unverified()
            .iter()
            .map(|s| format!("{} {}", s.name, s.version))
            .collect();
        assert_eq!(names, ["extra 2.1.0"]);
        // With no base at all, a lockfile with no checksums leaves every gem unverified.
        let fetch = fetch_of(plan("Gemfile.lock", &lane, &linux()));
        assert_eq!(fetch.unverified().len(), 2);
    }

    #[test]
    fn a_base_gem_whose_remote_the_lane_changed_is_not_fetched_naming_both() {
        let rake = "rake (13.0.6)";
        let base = lock_of("https://gems.corp.example/", &[rake], &[]);
        // Moved to the always-allowlisted public host.
        let moved = lock_of("https://rubygems.org/", &[rake], &[]);
        match plan_with_base("Gemfile.lock", &moved, Some(&base), &linux()) {
            Plan::NotFetched(note) => assert!(
                note.starts_with("Gemfile.lock: rake (13.0.6) comes from https://rubygems.org/")
                    && note.contains("takes it from https://gems.corp.example/"),
                "{note}"
            ),
            other => panic!("{other:?}"),
        }
        // A remote added to the section is a move too.
        let added = parse(
            "GEM\n  remote: https://gems.corp.example/\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n",
        )
        .unwrap();
        assert!(matches!(
            plan_with_base("Gemfile.lock", &added, Some(&base), &linux()),
            Plan::NotFetched(_)
        ));
        // The same remote spelled with a credential or without the trailing slash is not moved.
        for same in [
            "https://u:p@gems.corp.example/",
            "https://gems.corp.example",
        ] {
            let lane = lock_of(same, &[rake], &[]);
            assert!(
                matches!(
                    plan_with_base("Gemfile.lock", &lane, Some(&base), &linux()),
                    Plan::Fetch(_)
                ),
                "{same}"
            );
        }
        // A gem the base does not list may come from anywhere the allowlist admits.
        let new = lock_of("https://rubygems.org/", &["new-gem (1.0)"], &[]);
        assert!(matches!(
            plan_with_base("Gemfile.lock", &new, Some(&base), &linux()),
            Plan::Fetch(_)
        ));
        // And a base platform other than the host's pins nothing about the host's gems.
        let java_base = lock_of("https://gems.corp.example/", &["rake (13.0.6-java)"], &[]);
        assert!(matches!(
            plan_with_base("Gemfile.lock", &moved, Some(&java_base), &linux()),
            Plan::Fetch(_)
        ));
    }

    #[test]
    fn the_message_of_a_moved_gem_cuts_a_long_remote_and_hides_its_credential() {
        let long = format!("https://u:SECRET@h.example/{}", "a".repeat(5000));
        let base = lock_of("https://gems.corp.example/", &["rake (1.0)"], &[]);
        let lane = lock_of(&long, &["rake (1.0)"], &[]);
        match plan_with_base("Gemfile.lock", &lane, Some(&base), &linux()) {
            Plan::NotFetched(note) => assert!(
                !note.contains("SECRET") && note.len() < 600,
                "{} bytes: {note}",
                note.len()
            ),
            other => panic!("{other:?}"),
        }
    }
}
