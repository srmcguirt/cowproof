//! The registry-only egress proxy of the dependency fetch (D6, F-1).
//!
//! `cargo fetch --locked` reads a lockfile and registry configuration the packet may own, so
//! a git dependency in it could make the fetch reach any host. The fetch sandbox therefore
//! has no network of its own ([`crate::NetworkMode::RegistryReadOnly`]): it reaches one Unix
//! socket, through the same in-sandbox bridge a builder uses for its model proxy
//! (`cowproof net-bridge`, [`crate::bridge`]), and `cargo` is pointed at the bridge with
//! `CARGO_HTTP_PROXY` and `HTTPS_PROXY`.
//!
//! The proxy runs in the runner, outside the sandbox, on a thread of its own with a small
//! current-thread runtime ([`FetchProxy::start`]):
//!
//! * It speaks one thing, `CONNECT host:443`. It never sees what goes through the tunnel
//!   (TLS stays between `cargo` and the registry), holds no credential and writes nothing
//!   to disk. Any other method, including a plain `http://` request, is refused.
//! * It tunnels only to a host on the [`FetchAllowlist`] and only on port 443. The
//!   allowlist is built from the BASE alone (see [`FetchAllowlist::from_tree`]): the
//!   defaults (`index.crates.io`, `static.crates.io`, `crates.io`), the https hosts of the
//!   registries and git sources the base's cargo configuration names, and the base
//!   `cowproof.toml`'s `[proof] fetch_hosts` for hosts the director allows. A patch never
//!   adds to it.
//! * It resolves names itself, outside the sandbox, which has no DNS. [`Resolver`] is the
//!   one place a name becomes an address, so a test maps `index.crates.io` to a fake on
//!   `127.0.0.1` without touching DNS.
//! * Every refusal is recorded by host ([`FetchProxy::refused`]); the fetch then fails as
//!   infrastructure (F-1) with the host named, never as a refutation.
//!
//! Limits: a host on the allowlist is trusted to be the host it names (the proxy does not
//! pin addresses, and the allowlist is the director's); `http://` registries and git over
//! ssh are not served (ssh does not use a proxy at all, and the sandbox has no other way
//! out); a port other than 443 is refused.

use crate::REGISTRY_CONFIGS;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::Semaphore;

/// The hosts every fetch may reach: the crates.io index and its download host.
pub const DEFAULT_HOSTS: [&str; 3] = ["index.crates.io", "static.crates.io", "crates.io"];

/// The one port a tunnel may be opened to.
pub const TUNNEL_PORT: u16 = 443;

/// The file whose `[proof] fetch_hosts` names extra hosts. It is read from the tree after
/// the base is rebuilt and before `lane.patch` is applied (see
/// [`crate::deps::RegistryConfigSnapshot`]), never from the patched tree.
pub const POLICY_FILE: &str = "cowproof.toml";

/// Most tunnels open at once. The 65th is refused, so a fetch cannot exhaust the runner's
/// file descriptors.
const MAX_TUNNELS: usize = 64;
/// Largest request head the proxy reads.
const MAX_HEAD: usize = 8 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest refused-host text kept.
const MAX_REFUSED_TEXT: usize = 200;
/// Most distinct refusals kept.
const MAX_REFUSED: usize = 64;

/// The hosts a fetch may open a tunnel to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchAllowlist {
    hosts: BTreeSet<String>,
}

impl FetchAllowlist {
    /// The defaults alone.
    pub fn defaults() -> Self {
        Self {
            hosts: DEFAULT_HOSTS.iter().map(|h| (*h).to_string()).collect(),
        }
    }

    /// Add `hosts`, each a plain host name (see [`normalize_host`]).
    pub fn with_hosts<I: IntoIterator<Item = String>>(mut self, hosts: I) -> Result<Self> {
        for host in hosts {
            let normal = normalize_host(&host)
                .with_context(|| format!("{host:?} is not a plain host name"))?;
            self.hosts.insert(normal);
        }
        Ok(self)
    }

    /// The allowlist of the tree `tree`, which must be the BASE: the cargo configuration and
    /// the `cowproof.toml` as they were before `lane.patch`. Defaults, then the https hosts
    /// of every registry and git source the cargo configuration names, then
    /// `[proof] fetch_hosts`. A file that does not parse, or a `fetch_hosts` entry that is
    /// not a plain host name, is an error (the fetch then fails as infrastructure), never
    /// "no hosts".
    pub fn from_tree(tree: &Path) -> Result<Self> {
        let mut list = Self::defaults();
        for name in REGISTRY_CONFIGS {
            if !name.starts_with(".cargo/") {
                continue;
            }
            let Some(text) = read_regular(&tree.join(name))? else {
                continue;
            };
            list = list.with_hosts(
                cargo_config_hosts(&text).with_context(|| format!("reading {name}"))?,
            )?;
        }
        if let Some(text) = read_regular(&tree.join(POLICY_FILE))? {
            list = list.with_hosts(
                fetch_hosts(&text).with_context(|| format!("reading {POLICY_FILE}"))?,
            )?;
        }
        Ok(list)
    }

    /// Whether a tunnel to `host:port` is allowed.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        port == TUNNEL_PORT
            && normalize_host(host)
                .map(|h| self.hosts.contains(&h))
                .unwrap_or(false)
    }

    /// The allowed hosts, sorted.
    pub fn hosts(&self) -> Vec<&str> {
        self.hosts.iter().map(String::as_str).collect()
    }
}

/// The contents of a regular file, `None` when it is absent, a directory or a symlink (a
/// symlink in a rebuilt tree could point anywhere).
fn read_regular(path: &Path) -> Result<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => std::fs::read_to_string(path)
            .map(Some)
            .with_context(|| format!("reading {}", path.display())),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// A host name as the allowlist keeps it: lower case, no trailing dot, only letters, digits,
/// `-` and `.`. No port, no scheme, no wildcard, no IP-literal brackets.
pub fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['.', '-'])
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !ok {
        bail!("{host:?} is not a plain host name");
    }
    Ok(host)
}

/// The https host of a registry or git url, when the proxy can serve it: `https://host/...`
/// or `sparse+https://host/...`, with no port or port 443.
fn https_host(url: &str) -> Option<String> {
    let url = url.trim();
    let url = url.strip_prefix("sparse+").unwrap_or(url);
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = match authority.split_once(':') {
        None => authority,
        Some((host, port)) if port.parse::<u16>().ok() == Some(TUNNEL_PORT) => host,
        Some(_) => return None,
    };
    normalize_host(host).ok()
}

/// The https hosts a cargo configuration names: `[source.*]` `registry` and `git`,
/// `[registries.*]` `index`, and `[registry]` `index`.
fn cargo_config_hosts(text: &str) -> Result<Vec<String>> {
    let config: toml::Table =
        toml::from_str(text).context("the cargo configuration does not parse")?;
    let mut urls: Vec<String> = Vec::new();
    let mut take = |table: &toml::Table, keys: &[&str]| {
        for key in keys {
            if let Some(url) = table.get(*key).and_then(toml::Value::as_str) {
                urls.push(url.to_string());
            }
        }
    };
    let tables = |name: &str| -> Vec<toml::Table> {
        config
            .get(name)
            .and_then(toml::Value::as_table)
            .map(|t| {
                t.values()
                    .filter_map(toml::Value::as_table)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    };
    for source in tables("source") {
        take(&source, &["registry", "git"]);
    }
    for registry in tables("registries") {
        take(&registry, &["index"]);
    }
    if let Some(registry) = config.get("registry").and_then(toml::Value::as_table) {
        take(registry, &["index"]);
    }
    Ok(urls.iter().filter_map(|u| https_host(u)).collect())
}

/// `[proof] fetch_hosts` of a `cowproof.toml`.
fn fetch_hosts(text: &str) -> Result<Vec<String>> {
    let config: toml::Table = toml::from_str(text).context("cowproof.toml does not parse")?;
    let Some(proof) = config.get("proof") else {
        return Ok(Vec::new());
    };
    let Some(proof) = proof.as_table() else {
        bail!("[proof] in cowproof.toml must be a table");
    };
    let Some(hosts) = proof.get("fetch_hosts") else {
        return Ok(Vec::new());
    };
    hosts
        .as_array()
        .and_then(|list| {
            list.iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
        })
        .context("[proof] fetch_hosts in cowproof.toml must be a list of host names")
}

/// Where a host name becomes an address: the system's resolver, except for the names given a
/// fixed address.
///
/// This is the only place the proxy touches DNS, which is what lets a test (or a registry
/// behind a split-horizon resolver) map an ALLOWED name to a chosen address. The allowlist is
/// checked on the NAME first; a fixed address never admits a name the allowlist refuses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolver {
    fixed: BTreeMap<String, SocketAddr>,
}

impl Resolver {
    /// The system resolver for every name.
    pub fn system() -> Self {
        Self::default()
    }

    /// Connect `host` to `addr` instead of looking it up. `addr` must be a loopback address
    /// (`127.0.0.0/8` or `::1`): a fixed address can send an allowed name to a fake on this
    /// machine and nowhere else, whoever sets it.
    pub fn with_fixed(mut self, host: &str, addr: SocketAddr) -> Result<Self> {
        if !addr.ip().is_loopback() {
            bail!("{addr} is not a loopback address (127.0.0.0/8 or ::1)");
        }
        self.fixed.insert(normalize_host(host)?, addr);
        Ok(self)
    }

    /// `host=ip:port[,host=ip:port...]`, the form of `COWPROOF_FETCH_RESOLVE`, a testing
    /// hook. Every address must be a loopback `ip:port`; a name, or any other address, is an
    /// error. Empty is the system resolver.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut resolver = Self::system();
        for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (host, addr) = entry
                .split_once('=')
                .with_context(|| format!("{entry:?} is not host=ip:port"))?;
            let addr: SocketAddr = addr.trim().parse().with_context(|| {
                format!("{addr:?} is not a loopback ip:port (an address, not a name)")
            })?;
            resolver = resolver
                .with_fixed(host, addr)
                .with_context(|| format!("{entry:?}"))?;
        }
        Ok(resolver)
    }

    /// The fixed addresses as the `host=ip:port,...` text [`Resolver::parse`] reads, or `None`
    /// when there are none (the system resolver for every name).
    pub fn spec(&self) -> Option<String> {
        if self.fixed.is_empty() {
            return None;
        }
        Some(
            self.fixed
                .iter()
                .map(|(host, addr)| format!("{host}={addr}"))
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        if let Some(addr) = self.fixed.get(host) {
            return Ok(vec![*addr]);
        }
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// The proxy: the allowlist, the resolver and the refusals so far.
#[derive(Debug)]
pub struct FetchProxy {
    allow: FetchAllowlist,
    resolver: Resolver,
    refused: Mutex<Vec<String>>,
}

impl FetchProxy {
    pub fn new(allow: FetchAllowlist, resolver: Resolver) -> Self {
        Self {
            allow,
            resolver,
            refused: Mutex::new(Vec::new()),
        }
    }

    /// The hosts refused so far (`host:port` as the client asked), each once, in order.
    pub fn refused(&self) -> Vec<String> {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The allowlist this proxy enforces.
    pub fn allowlist(&self) -> &FetchAllowlist {
        &self.allow
    }

    fn refuse(&self, what: &str) {
        let what: String = what
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .take(MAX_REFUSED_TEXT)
            .collect();
        let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        if refused.len() < MAX_REFUSED && !refused.contains(&what) {
            refused.push(what);
        }
    }

    /// Serve every connection on `listener` until the task is dropped.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        let slots = Arc::new(Semaphore::new(MAX_TUNNELS));
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let proxy = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
                proxy.handle(stream).await;
            });
        }
    }

    /// One client connection: read a request head, and open a tunnel for an allowed
    /// `CONNECT host:443`. Anything else is answered and closed.
    pub async fn handle<S>(&self, mut client: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some((head, extra)) = read_head(&mut client).await else {
            return;
        };
        let mut parts = head.split_whitespace();
        let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if !method.eq_ignore_ascii_case("CONNECT") {
            self.refuse(&absolute_form_host(target).unwrap_or_else(|| format!("{method}-request")));
            reply(&mut client, "405 Method Not Allowed").await;
            return;
        }
        let Some((host, port)) = split_authority(target) else {
            self.refuse(target);
            reply(&mut client, "400 Bad Request").await;
            return;
        };
        if !self.allow.allows(&host, port) {
            self.refuse(&format!("{host}:{port}"));
            reply(&mut client, "403 Forbidden").await;
            return;
        }
        let Ok(host) = normalize_host(&host) else {
            reply(&mut client, "400 Bad Request").await;
            return;
        };
        let Some(mut upstream) = self.connect(&host, port).await else {
            reply(&mut client, "502 Bad Gateway").await;
            return;
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        if !extra.is_empty() && upstream.write_all(&extra).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }

    async fn connect(&self, host: &str, port: u16) -> Option<TcpStream> {
        let addrs = self.resolver.resolve(host, port).await.ok()?;
        for addr in addrs {
            if let Ok(Ok(stream)) =
                tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await
            {
                return Some(stream);
            }
        }
        None
    }

    /// Bind `socket` (mode 0600) and serve it on a thread of its own until the returned
    /// handle is stopped or dropped. The socket is bound before this returns, so a client
    /// that connects right after finds it.
    pub fn start(self, socket: &Path) -> Result<RunningProxy> {
        let listener = std::os::unix::net::UnixListener::bind(socket)
            .with_context(|| format!("binding the fetch proxy socket {}", socket.display()))?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
            .context("restricting the fetch proxy socket")?;
        listener
            .set_nonblocking(true)
            .context("making the fetch proxy socket non-blocking")?;
        let proxy = Arc::new(self);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let served = proxy.clone();
        let thread = std::thread::Builder::new()
            .name("fetch-proxy".to_string())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok(listener) = UnixListener::from_std(listener) else {
                        return;
                    };
                    tokio::select! {
                        () = served.serve(listener) => {}
                        _ = stopped => {}
                    }
                });
            })
            .context("starting the fetch proxy thread")?;
        Ok(RunningProxy {
            proxy,
            socket: socket.to_path_buf(),
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

/// A proxy serving a socket on its own thread. Dropping it stops the thread, closes every
/// tunnel and removes the socket.
#[derive(Debug)]
pub struct RunningProxy {
    proxy: Arc<FetchProxy>,
    socket: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RunningProxy {
    /// The hosts refused so far.
    pub fn refused(&self) -> Vec<String> {
        self.proxy.refused()
    }

    /// Stop serving and return every host that was refused.
    pub fn stop(mut self) -> Vec<String> {
        self.shut_down();
        self.proxy.refused()
    }

    fn shut_down(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// Read up to the blank line that ends a request head. Returns the head (without the
/// terminator) and whatever followed it in the same reads. `None` on EOF, an oversize head
/// or a timeout.
async fn read_head<S: AsyncRead + Unpin>(client: &mut S) -> Option<(String, Vec<u8>)> {
    let read = async {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(end) = find_end(&buf) {
                let head = String::from_utf8_lossy(&buf[..end.0]).into_owned();
                return Some((head, buf[end.1..].to_vec()));
            }
            if buf.len() > MAX_HEAD {
                return None;
            }
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    tokio::time::timeout(HEAD_TIMEOUT, read)
        .await
        .ok()
        .flatten()
}

/// `(end of the head, start of what follows)` for the first blank line.
fn find_end(buf: &[u8]) -> Option<(usize, usize)> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, i + 4))
}

async fn reply<S: AsyncWrite + Unpin>(client: &mut S, status: &str) {
    let text = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let _ = client.write_all(text.as_bytes()).await;
    let _ = client.shutdown().await;
}

/// `host` and `port` of a CONNECT authority. An IPv6 literal (`[::1]:443`) is returned with
/// its brackets, which no allowlist entry can match.
fn split_authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// The authority of an absolute-form request target (`http://host/path`), for the refusal
/// message.
fn absolute_form_host(target: &str) -> Option<String> {
    let rest = target.split_once("://")?.1;
    let authority = rest.split('/').next()?;
    (!authority.is_empty()).then(|| authority.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    fn sorted(list: &FetchAllowlist) -> Vec<&str> {
        list.hosts()
    }

    #[test]
    fn the_defaults_are_the_crates_io_hosts_on_port_443_only() {
        let list = FetchAllowlist::defaults();
        assert_eq!(
            sorted(&list),
            ["crates.io", "index.crates.io", "static.crates.io"]
        );
        assert!(list.allows("index.crates.io", 443));
        assert!(
            list.allows("INDEX.CRATES.IO.", 443),
            "case and a trailing dot"
        );
        assert!(!list.allows("index.crates.io", 80));
        assert!(!list.allows("index.crates.io", 8443));
        assert!(!list.allows("evil.example", 443));
        assert!(!list.allows("crates.io.evil.example", 443));
        assert!(!list.allows("[::1]", 443));
        assert!(!list.allows("", 443));
    }

    #[test]
    fn registry_and_git_hosts_come_from_the_cargo_configuration() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".cargo")).unwrap();
        std::fs::write(
            tmp.path().join(".cargo/config.toml"),
            "[source.crates-io]\nreplace-with = \"mirror\"\n\n\
             [source.mirror]\nregistry = \"sparse+https://Mirror.Example/index/\"\n\n\
             [source.vendored]\ngit = \"https://git.example/org/repo\"\n\n\
             [source.plain]\nregistry = \"http://plain.example/index\"\n\n\
             [source.odd]\nregistry = \"https://odd.example:8443/index\"\n\n\
             [source.local]\nregistry = \"file:///var/tmp/index\"\n\n\
             [source.dir]\ndirectory = \"vendor\"\n\n\
             [registries.corp]\nindex = \"sparse+https://user@corp.example:443/api/\"\n\n\
             [registry]\nindex = \"https://default.example/index\"\n",
        )
        .unwrap();
        let list = FetchAllowlist::from_tree(tmp.path()).unwrap();
        for host in [
            "mirror.example",
            "git.example",
            "corp.example",
            "default.example",
        ] {
            assert!(list.allows(host, 443), "{host}: {:?}", sorted(&list));
        }
        for host in ["plain.example", "odd.example", "vendor"] {
            assert!(!list.allows(host, 443), "{host}: {:?}", sorted(&list));
        }
        assert!(list.allows("index.crates.io", 443), "the defaults stay");
    }

    #[test]
    fn fetch_hosts_come_from_cowproof_toml_and_a_bad_entry_is_an_error() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("cowproof.toml"),
            "[proof]\nfetch_hosts = [\"Git.Example.\", \"github.com\"]\n",
        )
        .unwrap();
        let list = FetchAllowlist::from_tree(tmp.path()).unwrap();
        assert!(list.allows("git.example", 443) && list.allows("github.com", 443));
        assert!(!list.allows("evil.example", 443));

        for bad in [
            "fetch_hosts = [\"*.example\"]",
            "fetch_hosts = [\"host:443\"]",
            "fetch_hosts = [\"https://host\"]",
            "fetch_hosts = [\"a/b\"]",
            "fetch_hosts = \"host.example\"",
            "fetch_hosts = [1]",
        ] {
            std::fs::write(
                tmp.path().join("cowproof.toml"),
                format!("[proof]\n{bad}\n"),
            )
            .unwrap();
            assert!(
                FetchAllowlist::from_tree(tmp.path()).is_err(),
                "{bad} was accepted"
            );
        }
        std::fs::write(tmp.path().join("cowproof.toml"), "[proof\n").unwrap();
        assert!(FetchAllowlist::from_tree(tmp.path()).is_err());
    }

    #[test]
    fn a_symlinked_configuration_file_is_not_followed() {
        let tmp = TempDir::new().unwrap();
        let outside = tmp.path().join("outside.toml");
        std::fs::write(&outside, "[proof]\nfetch_hosts = [\"evil.example\"]\n").unwrap();
        let tree = tmp.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("cowproof.toml")).unwrap();
        let list = FetchAllowlist::from_tree(&tree).unwrap();
        assert!(!list.allows("evil.example", 443));
    }

    #[test]
    fn the_resolver_spec_is_host_equals_address_and_rejects_the_rest() {
        let r = Resolver::parse("Index.Crates.IO=127.0.0.1:9000, other.example=[::1]:10").unwrap();
        assert_eq!(
            r.fixed.get("index.crates.io"),
            Some(&"127.0.0.1:9000".parse().unwrap())
        );
        assert_eq!(r.fixed.len(), 2);
        assert_eq!(Resolver::parse("").unwrap(), Resolver::system());
        for bad in ["nohost", "h=notanaddress", "=127.0.0.1:1", "h=127.0.0.1"] {
            assert!(Resolver::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            r.spec().unwrap(),
            "index.crates.io=127.0.0.1:9000,other.example=[::1]:10"
        );
        assert_eq!(Resolver::system().spec(), None);
    }

    #[test]
    fn a_fixed_address_must_be_loopback() {
        for ok in [
            "h.example=127.0.0.1:1",
            "h.example=127.9.8.7:443",
            "h.example=[::1]:1",
        ] {
            assert!(Resolver::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "h.example=10.0.0.1:443",
            "h.example=192.168.1.5:443",
            "h.example=93.184.216.34:443",
            "h.example=0.0.0.0:443",
            "h.example=[::]:443",
            "h.example=[2001:db8::1]:443",
            "h.example=localhost:443",
            "h.example=other.example:443",
        ] {
            let e = format!("{:#}", Resolver::parse(bad).unwrap_err());
            assert!(
                e.contains("loopback"),
                "{bad} gave {e:?}, which does not say why"
            );
        }
        let e = Resolver::system()
            .with_fixed("h.example", "10.0.0.1:443".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(e.contains("loopback"), "{e}");
    }

    /// A fake upstream on `127.0.0.1` that greets each connection and counts them.
    async fn fake_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                seen.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = socket.write_all(b"hello-from-upstream\n").await;
                    let mut buf = [0u8; 256];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, count)
    }

    /// Send `request` to a proxy through an in-memory pipe and return what it answers.
    async fn ask(proxy: &Arc<FetchProxy>, request: &str) -> String {
        ask_until(proxy, request, "hello-from-upstream\n").await
    }

    /// [`ask`], reading until the answer ends with `until` (or the proxy closes).
    async fn ask_until(proxy: &Arc<FetchProxy>, request: &str, until: &str) -> String {
        let (mut client, server) = duplex(4096);
        let proxy = proxy.clone();
        let task = tokio::spawn(async move { proxy.handle(server).await });
        client.write_all(request.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        // The status head, then (for a tunnel) the upstream's greeting.
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), client.read(&mut buf))
                .await
                .expect("the proxy answered")
                .unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.ends_with(until.as_bytes()) {
                break;
            }
        }
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        String::from_utf8_lossy(&got).into_owned()
    }

    #[tokio::test]
    async fn an_allowed_host_is_tunnelled_to_the_address_the_resolver_gives() {
        let (upstream, count) = fake_upstream().await;
        let proxy = Arc::new(FetchProxy::new(
            FetchAllowlist::defaults(),
            Resolver::system()
                .with_fixed("index.crates.io", upstream)
                .unwrap(),
        ));
        let got = ask(
            &proxy,
            "CONNECT index.crates.io:443 HTTP/1.1\r\nHost: index.crates.io:443\r\n\r\n",
        )
        .await;
        assert!(got.starts_with("HTTP/1.1 200 "), "{got:?}");
        assert!(got.ends_with("hello-from-upstream\n"), "{got:?}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(proxy.refused().is_empty());
    }

    #[tokio::test]
    async fn bytes_sent_with_the_connect_head_reach_the_upstream() {
        let (upstream, _) = fake_upstream().await;
        let proxy = Arc::new(FetchProxy::new(
            FetchAllowlist::defaults(),
            Resolver::system()
                .with_fixed("crates.io", upstream)
                .unwrap(),
        ));
        let got = ask_until(
            &proxy,
            "CONNECT crates.io:443 HTTP/1.1\r\n\r\nclient-hello-early",
            "client-hello-early",
        )
        .await;
        assert!(got.starts_with("HTTP/1.1 200 "), "{got:?}");
        assert!(got.contains("client-hello-early"), "{got:?}");
    }

    #[tokio::test]
    async fn every_other_host_port_and_method_is_refused_and_the_upstream_never_contacted() {
        let (upstream, count) = fake_upstream().await;
        // Even a name the resolver maps to the fake is refused when the allowlist lacks it.
        let proxy = Arc::new(FetchProxy::new(
            FetchAllowlist::defaults(),
            Resolver::system()
                .with_fixed("evil.example", upstream)
                .unwrap()
                .with_fixed("index.crates.io", upstream)
                .unwrap(),
        ));
        let cases = [
            (
                "CONNECT evil.example:443 HTTP/1.1\r\n\r\n",
                "403",
                "evil.example:443",
            ),
            (
                "CONNECT index.crates.io:80 HTTP/1.1\r\n\r\n",
                "403",
                "index.crates.io:80",
            ),
            (
                "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
                "403",
                "127.0.0.1:443",
            ),
            ("CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "403", "[::1]:443"),
            ("CONNECT noport HTTP/1.1\r\n\r\n", "400", "noport"),
            (
                "GET http://index.crates.io/x HTTP/1.1\r\nHost: index.crates.io\r\n\r\n",
                "405",
                "index.crates.io",
            ),
            ("POST /x HTTP/1.1\r\n\r\n", "405", "POST-request"),
        ];
        for (request, status, named) in cases {
            let got = ask(&proxy, request).await;
            assert!(
                got.starts_with(&format!("HTTP/1.1 {status} ")),
                "{request:?} -> {got:?}"
            );
            assert!(
                !got.contains("hello-from-upstream"),
                "{request:?} reached the upstream"
            );
            assert!(
                proxy.refused().iter().any(|r| r == named),
                "{named} not recorded in {:?}",
                proxy.refused()
            );
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "the upstream was contacted"
        );
    }

    #[tokio::test]
    async fn an_allowed_host_that_cannot_be_reached_is_a_bad_gateway_not_a_refusal() {
        // A port nothing listens on.
        let dead = {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap()
        };
        let proxy = Arc::new(FetchProxy::new(
            FetchAllowlist::defaults(),
            Resolver::system().with_fixed("crates.io", dead).unwrap(),
        ));
        let got = ask(&proxy, "CONNECT crates.io:443 HTTP/1.1\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 502 "), "{got:?}");
        assert!(proxy.refused().is_empty());
    }

    #[tokio::test]
    async fn an_oversize_head_is_dropped_without_a_tunnel() {
        let (upstream, count) = fake_upstream().await;
        let proxy = Arc::new(FetchProxy::new(
            FetchAllowlist::defaults(),
            Resolver::system()
                .with_fixed("crates.io", upstream)
                .unwrap(),
        ));
        let long = format!(
            "CONNECT crates.io:443 HTTP/1.1\r\nX: {}",
            "a".repeat(MAX_HEAD + 2048)
        );
        let got = ask(&proxy, &long).await;
        assert!(got.is_empty(), "{got:?}");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_started_proxy_serves_its_unix_socket_and_removes_it_when_stopped() {
        // /var/tmp keeps the path short enough for a Unix socket.
        let dir = tempfile::Builder::new()
            .prefix("cp-fp-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let socket = dir.path().join("fetch.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (upstream, count) = runtime.block_on(fake_upstream());
        // The fake upstream lives on this runtime, so keep it running on a thread.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let keep = std::thread::spawn(move || {
            runtime.block_on(async move {
                let _ = tokio::task::spawn_blocking(move || done_rx.recv()).await;
            });
        });
        let running = FetchProxy::new(
            FetchAllowlist::defaults(),
            Resolver::system()
                .with_fixed("crates.io", upstream)
                .unwrap(),
        )
        .start(&socket)
        .unwrap();
        assert!(socket.exists());
        use std::io::{Read, Write};
        let mut ok = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        ok.write_all(b"CONNECT crates.io:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut head = [0u8; 39];
        ok.read_exact(&mut head).unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200 "), "{head:?}");
        let mut bad = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        bad.write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut answer = String::new();
        bad.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 403 "), "{answer:?}");
        assert_eq!(running.refused(), ["evil.example:443"]);
        drop(ok);
        assert_eq!(running.stop(), ["evil.example:443"]);
        assert!(!socket.exists(), "the socket is removed on stop");
        // The fake counts a connection when its accept task runs, on another thread, which
        // can come after the proxy has already answered 200: wait for it, briefly.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while count.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        drop(done_tx);
        keep.join().unwrap();
    }
}
