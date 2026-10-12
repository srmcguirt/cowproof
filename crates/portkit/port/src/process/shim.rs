//! PATH shims: the external programs a process case declares, scripted and recorded.
//!
//! A reference script that calls `git` must not run the machine's `git`: its answer would be
//! the machine's, and the port could not reproduce it. A case declares the programs it uses in
//! `shims`, each with the responses to give. The harness puts one tiny `sh` script per program
//! first on `PATH`; it re-enters the harness binary (`pk port shim`), which
//!
//! 1. appends `{program, argv, env, stdin}` to `calls.jsonl` in the run's state directory;
//! 2. picks the first scripted response that is unused and whose `argv`, when it names one,
//!    equals the call's, and answers with its `stdout`, `stderr` and `exit`.
//!
//! Responses are consumed once each, in order, unless a response says `repeat`. A call no
//! response answers exits 127 with a message on stderr, and leaves a marker so a capture can
//! refuse the case (a reference that called a program the case did not script is not a
//! reproducible fixture). The Rust port's side is the same code: `pk port wrap` runs the port
//! under the same shims, so the recorded `calls` of both are compared.
//!
//! `date` is shimmed too, unless the case scripts it: with `PORTKIT_NOW` (RFC 3339) set it
//! answers from that instant in UTC; without it, it exits 1 and leaves a marker, so a capture
//! cannot record a script that read an unpinned clock.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The file in the shims directory that holds the declared programs, read by every shim.
pub const CONFIG_FILE: &str = ".shims.json";
/// The state directory's log of calls, one JSON object per line.
pub const CALLS_FILE: &str = "calls.jsonl";
/// Marker: a call that no scripted response answered.
pub const UNSCRIPTED_MARKER: &str = "unscripted";
/// Marker: the `date` shim ran without `PORTKIT_NOW`.
pub const CLOCK_MARKER: &str = "clock-unpinned";
/// The exit status of a call no scripted response answers (as a shell says "not found").
pub const UNSCRIPTED_EXIT: i32 = 127;

/// One scripted response of a declared program.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scripted {
    /// Answers only a call with exactly this argument list. Without it, any call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Exit status to answer with.
    #[serde(default)]
    pub exit: i32,
    /// Text to answer on stdout.
    #[serde(default)]
    pub stdout: String,
    /// Text to answer on stderr.
    #[serde(default)]
    pub stderr: String,
    /// The program reads its stdin; the call's `stdin` is recorded. Off by default: a shim that
    /// swallowed the script's stdin when the real program would not have read it would change
    /// what the next command sees.
    #[serde(default)]
    pub read_stdin: bool,
    /// Do not consume this response: it answers every matching call.
    #[serde(default)]
    pub repeat: bool,
}

impl Scripted {
    /// Check the values the schema cannot.
    pub fn validate(&self, program: &str) -> Result<(), String> {
        if !(0..=255).contains(&self.exit) {
            return Err(format!(
                "shims[{program:?}]: exit {} is not an exit status (0 to 255)",
                self.exit
            ));
        }
        let nul = self.stdout.contains('\0')
            || self.stderr.contains('\0')
            || self.argv.iter().flatten().any(|a| a.contains('\0'));
        if nul {
            return Err(format!("shims[{program:?}]: a NUL in a response"));
        }
        Ok(())
    }
}

/// Which response answers a call: the first, in order, whose `argv` (when given) equals
/// `argv` and that `claim` accepts. `claim(i)` is asked about candidate `i` and says whether
/// this call may have it (it marks it used); a `repeat` response is never asked.
pub fn choose(
    scripted: &[Scripted],
    argv: &[String],
    mut claim: impl FnMut(usize) -> bool,
) -> Option<usize> {
    for (index, response) in scripted.iter().enumerate() {
        if let Some(expected) = &response.argv {
            if expected.as_slice() != argv {
                continue;
            }
        }
        if response.repeat || claim(index) {
            return Some(index);
        }
    }
    None
}

/// What every shim of one run reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShimConfig {
    pub programs: BTreeMap<String, Vec<Scripted>>,
    /// Names of the environment variables each recorded call carries.
    #[serde(default)]
    pub record_env: Vec<String>,
}

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub program: String,
    pub argv: Vec<String>,
    /// The `record_env` variables, `null` where unset.
    pub env: BTreeMap<String, Option<String>>,
    /// The call's stdin when its response says `read_stdin`, else `null`.
    pub stdin: Option<String>,
}

fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The text of the shim for `program`: a POSIX `sh` script that re-enters the harness.
/// `invocation` is the command that runs the harness binary (`[pk]` or `[cowproof, pk]`).
pub fn script_text(invocation: &[String], dir: &Path, state: &Path, program: &str) -> String {
    let command: Vec<String> = invocation.iter().map(|w| quote(w)).collect();
    format!(
        "#!/bin/sh\nexec {} port shim --dir {} --state {} --program {} -- \"$@\"\n",
        command.join(" "),
        quote(&dir.to_string_lossy()),
        quote(&state.to_string_lossy()),
        quote(program),
    )
}

/// Write the shims of one run: a script per declared program (and `date`, unless declared)
/// in `dir`, the configuration beside them, and the state directory.
pub fn install(
    dir: &Path,
    state: &Path,
    invocation: &[String],
    programs: &BTreeMap<String, Vec<Scripted>>,
    record_env: &[String],
) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::create_dir_all(state.join("used"))?;
    let mut names: Vec<&str> = programs.keys().map(String::as_str).collect();
    if !programs.contains_key("date") {
        names.push("date");
    }
    for name in names {
        let path = dir.join(name);
        fs::write(&path, script_text(invocation, dir, state, name))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    let config = ShimConfig {
        programs: programs.clone(),
        record_env: record_env.to_vec(),
    };
    fs::write(
        dir.join(CONFIG_FILE),
        serde_json::to_vec(&config).map_err(io::Error::other)?,
    )
}

/// The calls a run recorded, in order, as JSON.
pub fn read_calls(state: &Path) -> io::Result<Vec<Value>> {
    let path = state.join(CALLS_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(io::Error::other))
        .collect()
}

/// What the shims noticed besides the calls: `(unscripted program lines, clock was unpinned)`.
pub fn read_flags(state: &Path) -> io::Result<(Vec<String>, bool)> {
    let unscripted = match fs::read_to_string(state.join(UNSCRIPTED_MARKER)) {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok((unscripted, state.join(CLOCK_MARKER).exists()))
}

/// Run one shim: `program` called with `args`. Returns the exit status to exit with.
/// `dir` and `state` are the run's shims and state directories.
pub fn run_shim(dir: &Path, state: &Path, program: &str, args: &[String]) -> io::Result<i32> {
    run_shim_with(dir, state, program, args, &|name| std::env::var(name).ok())
}

/// [`run_shim`], reading the environment through `env`, so tests need not change the
/// process environment other tests read at the same time.
fn run_shim_with(
    dir: &Path,
    state: &Path,
    program: &str,
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
) -> io::Result<i32> {
    let config: ShimConfig =
        serde_json::from_slice(&fs::read(dir.join(CONFIG_FILE))?).map_err(io::Error::other)?;
    let Some(scripted) = config.programs.get(program) else {
        if program == "date" {
            return date_shim(state, args, env);
        }
        eprintln!("portkit shim: `{program}` is not declared in this run");
        return Ok(UNSCRIPTED_EXIT);
    };

    let chosen = choose(scripted, args, |index| claim(state, program, index));
    let response = chosen.map(|i| &scripted[i]);

    let stdin = if response.is_some_and(|r| r.read_stdin) {
        let mut bytes = Vec::new();
        io::stdin().lock().read_to_end(&mut bytes)?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        None
    };
    let recorded: BTreeMap<String, Option<String>> = config
        .record_env
        .iter()
        .map(|name| (name.clone(), env(name)))
        .collect();
    let call = Call {
        program: program.to_string(),
        argv: args.to_vec(),
        env: recorded,
        stdin,
    };
    let mut line = serde_json::to_string(&call).map_err(io::Error::other)?;
    line.push('\n');
    // One `write` of the whole line on an append-mode file: calls made at the same moment by
    // a script's background jobs do not interleave inside a line.
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join(CALLS_FILE))?
        .write_all(line.as_bytes())?;

    let Some(response) = response else {
        let shown = args.join(" ");
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(state.join(UNSCRIPTED_MARKER))?
            .write_all(format!("{program} {shown}\n").as_bytes())?;
        eprintln!("portkit shim: no scripted response for `{program} {shown}`");
        return Ok(UNSCRIPTED_EXIT);
    };
    io::stdout().write_all(response.stdout.as_bytes())?;
    io::stdout().flush()?;
    io::stderr().write_all(response.stderr.as_bytes())?;
    Ok(response.exit)
}

/// Take response `index` of `program` for this call: true for the first claimant, false when
/// another call already has it. The claim is a file created exclusively, so concurrent calls
/// (a script's background jobs) cannot both get one response.
fn claim(state: &Path, program: &str, index: usize) -> bool {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(state.join("used").join(format!("{program}.{index}")))
        .is_ok()
}

// ---- date ----------------------------------------------------------------------------------

/// The `date` shim: `date [-u] [+FORMAT]` at the instant `PORTKIT_NOW` names, in UTC.
fn date_shim(
    state: &Path,
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
) -> io::Result<i32> {
    let mut format: Option<&str> = None;
    for arg in args {
        match arg.as_str() {
            "-u" | "--utc" | "--universal" => {}
            other if other.starts_with('+') => format = Some(&other[1..]),
            other => {
                eprintln!("portkit date shim: `{other}` is not supported (date [-u] [+FORMAT])");
                return Ok(2);
            }
        }
    }
    let now = env("PORTKIT_NOW").and_then(|text| OffsetDateTime::parse(&text, &Rfc3339).ok());
    let Some(now) = now else {
        fs::write(state.join(CLOCK_MARKER), b"")?;
        eprintln!("portkit date shim: PORTKIT_NOW is not set to an RFC 3339 time; the clock is not pinned");
        return Ok(1);
    };
    let text = strftime(
        &now.to_offset(time::UtcOffset::UTC),
        format.unwrap_or("%a %b %e %H:%M:%S UTC %Y"),
    );
    println!("{text}");
    Ok(0)
}

/// A subset of `strftime`: `%Y %y %m %d %e %H %I %M %S %p %j %a %A %b %B %Z %z %s %u %w %F %T %D %n %t %%`.
/// An unknown directive is written as it is.
pub fn strftime(at: &OffsetDateTime, format: &str) -> String {
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let mut out = String::new();
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let Some(d) = chars.next() else {
            out.push('%');
            break;
        };
        let weekday = at.weekday().number_days_from_sunday() as usize;
        let month = u8::from(at.month()) as usize;
        let hour12 = match at.hour() % 12 {
            0 => 12,
            h => h,
        };
        match d {
            'Y' => out.push_str(&at.year().to_string()),
            'y' => out.push_str(&format!("{:02}", at.year().rem_euclid(100))),
            'm' => out.push_str(&format!("{month:02}")),
            'd' => out.push_str(&format!("{:02}", at.day())),
            'e' => out.push_str(&format!("{:2}", at.day())),
            'H' => out.push_str(&format!("{:02}", at.hour())),
            'I' => out.push_str(&format!("{hour12:02}")),
            'M' => out.push_str(&format!("{:02}", at.minute())),
            'S' => out.push_str(&format!("{:02}", at.second())),
            'p' => out.push_str(if at.hour() < 12 { "AM" } else { "PM" }),
            'j' => out.push_str(&format!("{:03}", at.ordinal())),
            'a' => out.push_str(&DAYS[weekday][..3]),
            'A' => out.push_str(DAYS[weekday]),
            'b' => out.push_str(&MONTHS[month - 1][..3]),
            'B' => out.push_str(MONTHS[month - 1]),
            'Z' => out.push_str("UTC"),
            'z' => out.push_str("+0000"),
            's' => out.push_str(&at.unix_timestamp().to_string()),
            'u' => out.push_str(&(if weekday == 0 { 7 } else { weekday }).to_string()),
            'w' => out.push_str(&weekday.to_string()),
            'F' => out.push_str(&format!("{}-{month:02}-{:02}", at.year(), at.day())),
            'T' => out.push_str(&format!(
                "{:02}:{:02}:{:02}",
                at.hour(),
                at.minute(),
                at.second()
            )),
            'D' => out.push_str(&format!(
                "{month:02}/{:02}/{:02}",
                at.day(),
                at.year().rem_euclid(100)
            )),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            '%' => out.push('%'),
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

/// The path of a shim's directory entry for `program` in `dir`.
pub fn shim_path(dir: &Path, program: &str) -> PathBuf {
    dir.join(program)
}

/// A call as the envelope carries it: `{program, argv, env, stdin}`.
pub fn call_json(call: &Call) -> Value {
    json!({
        "program": call.program,
        "argv": call.argv,
        "env": call.env,
        "stdin": call.stdin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(argv: Option<&[&str]>, stdout: &str) -> Scripted {
        Scripted {
            argv: argv.map(|a| a.iter().map(|s| s.to_string()).collect()),
            stdout: stdout.to_string(),
            ..Default::default()
        }
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn responses_are_consumed_once_each_in_order() {
        let scripted = vec![resp(None, "one"), resp(None, "two")];
        let mut used = [false; 2];
        let take = |used: &mut [bool; 2]| {
            choose(&scripted, &argv(&["x"]), |i| {
                if used[i] {
                    false
                } else {
                    used[i] = true;
                    true
                }
            })
        };
        assert_eq!(take(&mut used), Some(0));
        assert_eq!(take(&mut used), Some(1));
        // Nothing left: the call is unscripted.
        assert_eq!(take(&mut used), None);
    }

    #[test]
    fn a_response_that_names_an_argv_answers_only_that_call() {
        let scripted = vec![
            resp(Some(&["rev-parse", "HEAD"]), "abc\n"),
            resp(None, "any\n"),
        ];
        let always = |_| true;
        assert_eq!(
            choose(&scripted, &argv(&["rev-parse", "HEAD"]), always),
            Some(0)
        );
        assert_eq!(choose(&scripted, &argv(&["status"]), always), Some(1));
        // Only the exact list: a prefix or a different order is another call.
        let only = vec![resp(Some(&["rev-parse", "HEAD"]), "abc\n")];
        assert_eq!(choose(&only, &argv(&["rev-parse"]), always), None);
        assert_eq!(choose(&only, &argv(&["HEAD", "rev-parse"]), always), None);
        assert_eq!(choose(&only, &argv(&[]), always), None);
    }

    #[test]
    fn a_repeat_response_is_never_consumed() {
        let mut repeating = resp(None, "again");
        repeating.repeat = true;
        let scripted = vec![repeating];
        for _ in 0..3 {
            // `claim` is never asked, so a claimant that always refuses does not matter.
            assert_eq!(choose(&scripted, &argv(&["a"]), |_| false), Some(0));
        }
    }

    #[test]
    fn a_scripted_response_is_checked() {
        assert!(resp(None, "x").validate("git").is_ok());
        let bad = Scripted {
            exit: 300,
            ..Default::default()
        };
        assert!(bad.validate("git").unwrap_err().contains("exit status"));
        let nul = resp(None, "a\u{0}b");
        assert!(nul.validate("git").unwrap_err().contains("NUL"));
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pk-shim-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn installed(
        name: &str,
        programs: BTreeMap<String, Vec<Scripted>>,
        record: &[&str],
    ) -> (PathBuf, PathBuf, PathBuf) {
        let base = scratch(name);
        let (dir, state) = (base.join("shims"), base.join("state"));
        let record: Vec<String> = record.iter().map(|s| s.to_string()).collect();
        install(&dir, &state, &argv(&["/usr/bin/pk"]), &programs, &record).unwrap();
        (base, dir, state)
    }

    #[test]
    fn the_shim_is_a_small_posix_script_that_reenters_the_harness() {
        let text = script_text(
            &argv(&["/opt/co wproof/bin/cowproof", "pk"]),
            Path::new("/w/shims"),
            Path::new("/w/state"),
            "git",
        );
        assert_eq!(
            text,
            "#!/bin/sh\nexec '/opt/co wproof/bin/cowproof' 'pk' port shim --dir '/w/shims' --state '/w/state' --program 'git' -- \"$@\"\n"
        );
        // A quote in a path is closed, escaped and reopened, never left to the shell.
        let quoted = script_text(
            &argv(&["/it's/pk"]),
            Path::new("/d"),
            Path::new("/s"),
            "git",
        );
        assert!(quoted.contains("'/it'\\''s/pk'"), "{quoted}");
    }

    #[test]
    fn install_writes_an_executable_per_program_and_a_date_shim() {
        let mut programs = BTreeMap::new();
        programs.insert("git".to_string(), vec![resp(None, "x")]);
        let (base, dir, state) = installed("install", programs, &[]);
        for name in ["git", "date"] {
            let mode = fs::metadata(dir.join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "{name}");
        }
        assert!(dir.join(CONFIG_FILE).is_file());
        assert!(state.join("used").is_dir());
        // A case that scripts `date` itself gets its own and no default.
        let mut programs = BTreeMap::new();
        programs.insert("date".to_string(), vec![resp(None, "x")]);
        let (base2, dir2, _) = installed("install2", programs, &[]);
        assert!(dir2.join("date").is_file());
        assert_eq!(fs::read_dir(&dir2).unwrap().count(), 2);
        let _ = fs::remove_dir_all(base);
        let _ = fs::remove_dir_all(base2);
    }

    #[test]
    fn calls_are_logged_with_their_argv_and_the_declared_env_and_answered_in_order() {
        let mut programs = BTreeMap::new();
        programs.insert(
            "git".to_string(),
            vec![
                Scripted {
                    argv: Some(argv(&["rev-parse", "HEAD"])),
                    stdout: "abc123\n".into(),
                    ..Default::default()
                },
                Scripted {
                    exit: 3,
                    stderr: "boom\n".into(),
                    ..Default::default()
                },
            ],
        );
        let (base, dir, state) = installed(
            "calls",
            programs,
            &["PK_SHIM_TEST_VAR", "PK_SHIM_UNSET_VAR"],
        );
        let env = |name: &str| (name == "PK_SHIM_TEST_VAR").then(|| "value".to_string());

        // The first call matches the named argv, the second falls to the catch-all, the third
        // finds nothing left.
        assert_eq!(
            run_shim_with(&dir, &state, "git", &argv(&["rev-parse", "HEAD"]), &env).unwrap(),
            0
        );
        assert_eq!(
            run_shim_with(&dir, &state, "git", &argv(&["push", "--force"]), &env).unwrap(),
            3
        );
        assert_eq!(
            run_shim_with(&dir, &state, "git", &argv(&["status"]), &env).unwrap(),
            UNSCRIPTED_EXIT
        );

        let calls = read_calls(&state).unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0]["program"], "git");
        assert_eq!(calls[0]["argv"], json!(["rev-parse", "HEAD"]));
        assert_eq!(calls[1]["argv"], json!(["push", "--force"]));
        assert_eq!(
            calls[0]["env"],
            json!({"PK_SHIM_TEST_VAR": "value", "PK_SHIM_UNSET_VAR": null})
        );
        assert_eq!(calls[0]["stdin"], Value::Null);
        // The unanswered call is flagged for a capture to refuse.
        let (unscripted, clock) = read_flags(&state).unwrap();
        assert_eq!(unscripted, ["git status"]);
        assert!(!clock);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn a_program_that_is_not_declared_is_unscripted_and_exits_127() {
        let (base, dir, state) = installed("undeclared", BTreeMap::new(), &[]);
        assert_eq!(
            run_shim(&dir, &state, "curl", &argv(&["x"])).unwrap(),
            UNSCRIPTED_EXIT
        );
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn strftime_formats_a_pinned_instant() {
        let at = OffsetDateTime::parse("2026-01-02T03:04:05Z", &Rfc3339).unwrap();
        assert_eq!(strftime(&at, "%Y-%m-%d %H:%M:%S"), "2026-01-02 03:04:05");
        assert_eq!(
            strftime(&at, "%F %T %Z %z"),
            "2026-01-02 03:04:05 UTC +0000"
        );
        assert_eq!(
            strftime(&at, "%a %A %b %B %e %j %y %p %I"),
            "Fri Friday Jan January  2 002 26 AM 03"
        );
        assert_eq!(strftime(&at, "%s"), "1767323045");
        assert_eq!(strftime(&at, "%D %u %w 100%% %q"), "01/02/26 5 5 100% %q");
        let late = OffsetDateTime::parse("2026-12-31T23:59:59Z", &Rfc3339).unwrap();
        assert_eq!(strftime(&late, "%j %p %I"), "365 PM 11");
        // A non-UTC input is formatted in UTC by the caller (`to_offset`), and midnight is 12 AM.
        let midnight = OffsetDateTime::parse("2026-01-02T00:30:00Z", &Rfc3339).unwrap();
        assert_eq!(strftime(&midnight, "%I %p"), "12 AM");
    }

    #[test]
    fn the_date_shim_refuses_to_guess_the_time() {
        let base = scratch("date");
        let unset = |_: &str| None;
        assert_eq!(date_shim(&base, &argv(&["+%s"]), &unset).unwrap(), 1);
        assert!(base.join(CLOCK_MARKER).exists());
        // An option it does not implement is a refusal, not a wrong answer.
        assert_eq!(date_shim(&base, &argv(&["-d", "@0"]), &unset).unwrap(), 2);
        let _ = fs::remove_dir_all(base);
    }
}
