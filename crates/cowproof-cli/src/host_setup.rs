//! `cowproof host setup`: what the OWNER of a remote host does to lock the director's key to
//! `cowproof host-agent` (D27). It runs on the host, as the user the director will log in as.
//! It prints the `authorized_keys` line for the director's public key, the file to put it in,
//! the director-side `hosts.json` entry with this machine's absolute paths, the host config
//! (`host.toml`, see [`crate::host_agent::config`]) that a forced key needs, and this host's
//! `host-agent doctor`, so the owner sees whether `claude` and the sandbox work before the
//! director tries. It writes nothing, except the host config when `--write-config` asks for it
//! (never over an existing one without `--force`). The director never runs it.
//!
//! The line is `command="<cowproof> host-agent --forced",restrict,port-forwarding,permitopen="127.0.0.1:1",permitlisten="127.0.0.1:1" <key>`:
//! `command=` makes sshd run `host-agent --forced` for every session of that key whatever the
//! client asked, `restrict` switches off everything else (pty, agent and X11 forwarding, `rc`
//! files, port forwarding) and `port-forwarding` switches forwarding back on, which the
//! director needs for its two socket forwards. See the README, "Locking the director's key to
//! cowproof".

use crate::host_agent::config;
use crate::host_agent::{doctor, remote_root};
use crate::remote::sh_quote;
use crate::root::resolve_executable;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::io::Read as _;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct SetupArgs {
    /// The director's PUBLIC key: the `.pub` file, holding exactly one OpenSSH public key line.
    /// Left out, only the host config and this host's check are shown (with `--write-config`,
    /// written)
    #[arg(long, required_unless_present = "write_config")]
    key: Option<PathBuf>,
    /// What the director's `ssh` calls this machine (`user@host` or a name from its ssh
    /// config), for the hosts.json entry; a placeholder is printed when it is left out
    #[arg(long)]
    ssh: Option<String>,
    /// The alias the director will use in `--host`, for the hosts.json entry
    #[arg(long, default_value = "remote")]
    alias: String,
    /// The Claude Code executable on this machine (default: `claude` on PATH)
    #[arg(long)]
    claude: Option<PathBuf>,
    /// Write the host config (`$XDG_CONFIG_HOME/cowproof/host.toml`, else
    /// `~/.config/cowproof/host.toml`; a forced key reads only the latter) with this machine's `claude` and lanes root, which a
    /// forced key requires. Without this flag the file is only shown. An existing file is not
    /// replaced unless `--force` is given
    #[arg(long)]
    write_config: bool,
    /// With `--write-config`: replace the host config if there is one
    #[arg(long, requires = "write_config")]
    force: bool,
}

/// The most a public key file may hold. A key line is under 1 KiB; a larger file is not one.
const MAX_KEY_FILE: u64 = 16 * 1024;

/// The key types sshd's `authorized_keys` takes that `ssh-keygen` makes today. `ssh-dss` is
/// disabled in OpenSSH by default and so is left out.
const KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// The public key `text` holds, normalized to `type blob[ comment]`, or why it is not exactly
/// one OpenSSH public key. The text is never echoed back in an error: it may be a private key.
fn public_key_line(text: &str) -> Result<String> {
    if text.contains("PRIVATE KEY") || text.starts_with("PuTTY-User-Key-File") {
        bail!(
            "this file holds a PRIVATE key. Stop: a private key never leaves the machine it \
             belongs to, and nothing here needs it. Pass the matching public key, the file \
             ending in .pub, and treat this one as exposed if it has been copied anywhere"
        );
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let line = match lines.as_slice() {
        [one] => *one,
        [] => bail!("the key file is empty: it must hold exactly one OpenSSH public key line"),
        many => bail!(
            "the key file holds {} lines: it must hold exactly one OpenSSH public key line",
            many.len()
        ),
    };
    if line.chars().any(|c| c.is_control() && c != '\t') {
        bail!("the key line holds a control character");
    }
    let mut parts = line.split_whitespace();
    let (kind, blob) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !KEY_TYPES.contains(&kind) {
        bail!(
            "the line does not start with an OpenSSH key type (ssh-ed25519, ssh-rsa, \
             ecdsa-sha2-nistp256/384/521, sk-ssh-ed25519@openssh.com, \
             sk-ecdsa-sha2-nistp256@openssh.com): pass the .pub file ssh-keygen made, not an authorized_keys line with options"
        );
    }
    // The blob starts with the key type, as a length-prefixed string.
    let decoded = base64_decode(blob).ok_or_else(|| anyhow!("the key is not valid base64"))?;
    let named = decoded
        .get(4..)
        .zip(decoded.get(..4))
        .map(|(rest, len)| (u32::from_be_bytes([len[0], len[1], len[2], len[3]]), rest));
    match named {
        Some((len, rest)) if len as usize == kind.len() && rest.starts_with(kind.as_bytes()) => {}
        _ => bail!("the key data does not match the key type {kind}: the line is damaged"),
    }
    let comment = parts.collect::<Vec<_>>().join(" ");
    Ok(if comment.is_empty() {
        format!("{kind} {blob}")
    } else {
        format!("{kind} {blob} {comment}")
    })
}

/// Standard base64 (RFC 4648, `=` padding). `None` for anything else.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.trim_end_matches('=');
    if text.len() - digits.len() > 2 || text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in digits.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The `authorized_keys` line for `key` (see [`public_key_line`]) that runs `exe host-agent
/// --forced`. The director's hosts.json names the same `exe`, and its commands must name a
/// file called `cowproof`, so `exe` has to be one.
fn authorized_keys_line(exe: &Path, key: &str) -> Result<String> {
    let text = exe
        .to_str()
        .ok_or_else(|| anyhow!("the path of this cowproof is not valid UTF-8"))?;
    if !exe.is_absolute() {
        bail!("the path of this cowproof is not absolute: {text}");
    }
    if exe.file_name().and_then(|n| n.to_str()) != Some("cowproof") {
        bail!(
            "this binary is {text}, and the director's commands must name a file called \
             cowproof: install or link it under that name and run it from there"
        );
    }
    // Inside the double quotes of `command="..."` only `\"` is an escape, and the shell then
    // reads the text; keep quote characters and backslashes out of the path altogether.
    if text
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\'))
    {
        bail!(
            "the path {text:?} holds a quote, a backslash or a control character: install cowproof elsewhere"
        );
    }
    Ok(format!(
        "command=\"{} host-agent --forced\",restrict,port-forwarding,permitopen=\"127.0.0.1:1\",permitlisten=\"127.0.0.1:1\" {key}",
        sh_quote(text)
    ))
}

/// The hosts.json entry of this machine, as the director reads it.
fn hosts_entry(alias: &str, ssh: &str, exe: &Path, claude: &str) -> Value {
    json!({ alias: { "ssh": ssh, "cowproof": exe, "claude": claude } })
}

/// Print the setup. Exit 1 when this host's doctor reports a failure (the text is still
/// printed); an error, with nothing printed or written, when the key file is not one public
/// key, or when `--write-config` cannot write (no `claude` found, or a file in the way).
pub async fn run(args: SetupArgs) -> Result<i32> {
    let key = args.key.as_deref().map(read_key).transpose()?;
    let exe = std::env::current_exe().context("finding this cowproof")?;
    let line = key
        .as_deref()
        .map(|key| authorized_keys_line(&exe, key))
        .transpose()?;

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))?;
    let cwd = std::env::current_dir()?;
    let path = std::env::var("PATH").unwrap_or_default();
    let claude_name = args.claude.as_deref().map_or_else(
        || "claude".to_string(),
        |p| p.to_string_lossy().into_owned(),
    );
    let claude = resolve_executable(&claude_name, &path, &cwd);
    let claude_shown = match &claude {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => "/ABSOLUTE/PATH/TO/claude".to_string(),
    };
    let ssh = args
        .ssh
        .unwrap_or_else(|| "USER@HOST-OR-SSH-CONFIG-NAME".to_string());
    let root = remote_root(None)?;
    let config_path = config::current_config_path(true)?;
    let forced_path = config::forced_config_path()?;
    // The text is made before anything is printed or written, so a `claude` that cannot be
    // found stops `--write-config` while nothing has changed.
    let config_text = match &claude {
        Ok(claude) => Some(config::render(claude, &root)?),
        Err(_) => None,
    };
    let to_write = if args.write_config {
        Some(config_text.as_deref().ok_or_else(|| {
            anyhow!("claude was not found on this machine, so there is nothing to write: pass --claude <path>")
        })?)
    } else {
        None
    };
    // Before anything is printed: a file in the way is an error with nothing else shown.
    if let Some(text) = to_write {
        config::write(&config_path, text, args.force)?;
    }

    let mut step = 0;
    let mut next = || {
        step += 1;
        step
    };
    if let Some(line) = &line {
        println!(
            "{}. Put this line in {}",
            next(),
            home.join(".ssh/authorized_keys").display()
        );
        println!(
            "   (append it as ONE line; create the file with mode 600 and ~/.ssh with mode 700 if"
        );
        println!(
            "   they are missing; the director's key must appear nowhere else on this machine):\n"
        );
        println!("{line}\n");
        println!(
            "{}. On the director's machine, add this to ~/.config/cowproof/hosts.json",
            next()
        );
        println!("   (choose the alias; set \"ssh\" to what its ssh calls this machine):\n");
        println!(
            "{}\n",
            serde_json::to_string_pretty(&hosts_entry(&args.alias, &ssh, &exe, &claude_shown))?
        );
    }
    println!(
        "{}. The host config {}, which a forced key needs: it, not the director, decides which",
        next(),
        if args.write_config {
            "(written)"
        } else {
            "(not written)"
        }
    );
    println!(
        "   `claude` and which lanes directory the key may use. It is {}:\n",
        config_path.display()
    );
    match &config_text {
        Some(text) => println!("{text}"),
        None => println!("   (claude was not found: pass --claude <path> to see it)\n"),
    }
    if config_path != forced_path {
        println!(
            "   WARNING: XDG_CONFIG_HOME points elsewhere, so this is not the file a forced key reads."
        );
        println!(
            "   A forced key reads only {}, whatever XDG_CONFIG_HOME says: copy it there, or",
            forced_path.display()
        );
        println!("   run this again without XDG_CONFIG_HOME, or the key will find no config.\n");
    }
    if to_write.is_some() {
        println!(
            "   Written. Only you can change it; to change it, edit it, or run this again with --force.\n"
        );
    } else {
        println!(
            "   To write it: cowproof host setup --write-config{} (an existing file is kept unless --force).",
            if config_path.exists() { " --force" } else { "" }
        );
        println!(
            "   Until it exists, the forced key refuses every verb except doctor, which says so.\n"
        );
    }
    println!(
        "{}. This machine's check (cowproof host-agent doctor):\n",
        next()
    );
    let report = doctor(&claude_name, &root).await;
    let ok = match &report {
        Ok(v) => {
            println!("   version:  {}", v["version"].as_str().unwrap_or("?"));
            println!("   protocol: {}", v["protocol"]);
            for name in ["sandbox", "claude"] {
                println!(
                    "   {name}: {} - {}",
                    if v[name] == true { "ok" } else { "FAILED" },
                    v[format!("{name}_detail")].as_str().unwrap_or("")
                );
            }
            v["ok"] == true
        }
        Err(e) => {
            println!("   FAILED: {e:#}");
            false
        }
    };
    if claude.is_err() {
        println!(
            "   claude was not found: pass --claude <path> and fix the \"claude\" entry above"
        );
    }
    if ok && claude.is_ok() {
        println!("\nThis machine is ready for the director's key.");
    } else {
        println!("\nNot ready: fix the failures above before the director's first run.");
    }
    Ok(i32::from(!(ok && claude.is_ok())))
}

/// The key file's single public key line.
fn read_key(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening the key file {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading the key file {}", path.display()))?;
    if bytes.len() as u64 > MAX_KEY_FILE {
        bail!(
            "{} is larger than {MAX_KEY_FILE} bytes: a public key file is under 1 KiB",
            path.display()
        );
    }
    let text = String::from_utf8(bytes).map_err(|_| anyhow!("the key file is not text"))?;
    public_key_line(&text).with_context(|| format!("the key file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically real ed25519 public key blob (type string, then 32 bytes of filler),
    /// made up for the tests: it is not anyone's key.
    fn blob(kind: &str) -> String {
        let mut raw = (kind.len() as u32).to_be_bytes().to_vec();
        raw.extend_from_slice(kind.as_bytes());
        raw.extend_from_slice(&[7u8; 32]);
        base64_encode(&raw)
    }

    fn base64_encode(raw: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in raw.chunks(3) {
            let n =
                chunk.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
        out
    }

    #[test]
    fn base64_decode_round_trips_every_length() {
        for len in 0..40usize {
            let raw: Vec<u8> = (0..len).map(|i| (i * 37 + 5) as u8).collect();
            if len == 0 {
                assert_eq!(base64_decode(&base64_encode(&raw)), None);
            } else {
                assert_eq!(base64_decode(&base64_encode(&raw)), Some(raw));
            }
        }
        assert_eq!(base64_decode("AA=A"), None);
        assert_eq!(base64_decode("A$AA"), None);
        assert_eq!(base64_decode("AAA"), None);
    }

    #[test]
    fn one_public_key_is_accepted_and_normalized() {
        let b = blob("ssh-ed25519");
        let expect = format!("ssh-ed25519 {b} director@laptop");
        assert_eq!(public_key_line(&format!("{expect}\n")).unwrap(), expect);
        assert_eq!(
            public_key_line(&format!("\n  ssh-ed25519\t{b}   director@laptop  \r\n\n")).unwrap(),
            expect
        );
        assert_eq!(
            public_key_line(&format!("ssh-ed25519 {b}")).unwrap(),
            format!("ssh-ed25519 {b}")
        );
    }

    #[test]
    fn anything_else_is_refused_without_quoting_the_file() {
        let b = blob("ssh-ed25519");
        let bad = [
            String::new(),
            "\n\n".to_string(),
            format!("ssh-ed25519 {b}\nssh-ed25519 {b}\n"),
            // An authorized_keys line with options is not a public key file.
            format!("command=\"x\" ssh-ed25519 {b}"),
            format!("ssh-dss {b}"),
            // The blob names a different type than the line.
            format!("ssh-rsa {b}"),
            "ssh-ed25519 AAAA".to_string(),
            "ssh-ed25519 not*base64!".to_string(),
            "ssh-ed25519".to_string(),
        ];
        for text in &bad {
            let err = public_key_line(text).unwrap_err().to_string();
            assert!(!err.contains(&b), "{err}");
        }
    }

    #[test]
    fn a_private_key_is_refused_loudly() {
        let filler = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
        for header in ["OPENSSH", "RSA", "EC"] {
            let text = format!(
                "-----BEGIN {header} PRIVATE KEY-----\n{filler}\n-----END {header} PRIVATE KEY-----\n"
            );
            let err = public_key_line(&text).unwrap_err().to_string();
            assert!(err.contains("PRIVATE key"), "{err}");
            assert!(!err.contains(filler), "{err}");
        }
        assert!(
            public_key_line("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n")
                .unwrap_err()
                .to_string()
                .contains("PRIVATE key")
        );
    }

    #[test]
    fn the_line_names_this_binary_and_keeps_the_key_whole() {
        let key = format!("ssh-ed25519 {} d@x", blob("ssh-ed25519"));
        assert_eq!(
            authorized_keys_line(Path::new("/opt/bin/cowproof"), &key).unwrap(),
            format!(
                "command=\"/opt/bin/cowproof host-agent --forced\",restrict,port-forwarding,permitopen=\"127.0.0.1:1\",permitlisten=\"127.0.0.1:1\" {key}"
            )
        );
        // A path with a space is quoted for the shell sshd runs the command with.
        assert_eq!(
            authorized_keys_line(Path::new("/opt/my bin/cowproof"), &key).unwrap(),
            format!(
                "command=\"'/opt/my bin/cowproof' host-agent --forced\",restrict,port-forwarding,permitopen=\"127.0.0.1:1\",permitlisten=\"127.0.0.1:1\" {key}"
            )
        );
        for bad in [
            "cowproof",
            "/opt/bin/cowproof-1.2",
            "/opt/bin/cow\"proof/cowproof",
            "/opt/bin/it's/cowproof",
            "/opt/bin/a\\b/cowproof",
            "/opt/bin/a\nb/cowproof",
        ] {
            assert!(authorized_keys_line(Path::new(bad), &key).is_err(), "{bad}");
        }
    }
}
