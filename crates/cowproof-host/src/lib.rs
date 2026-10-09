#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_FLOOR_GB: f64 = 80.0;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HostConfig {
    #[serde(default)]
    #[serde(alias = "laneRoot")]
    pub lane_root: Option<PathBuf>,
    #[serde(default = "default_floor")]
    #[serde(alias = "floorGb")]
    pub floor_gb: f64,
    #[serde(default)]
    #[serde(alias = "classLimits")]
    pub class_limits: serde_json::Map<String, Value>,
    #[serde(default)]
    pub ssh: Option<String>,
}
fn default_floor() -> f64 {
    DEFAULT_FLOOR_GB
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostFacts {
    pub hostname: String,
    pub os: String,
    pub cpu_count: usize,
    pub load_averages: Vec<f64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub lane_root: String,
    pub lane_root_free_bytes: Option<u64>,
    pub wsl: bool,
    pub windows_drive_free_bytes: Option<u64>,
    pub docker_running: bool,
    pub codex_logged_in: bool,
    pub codex_version: Option<String>,
    pub running_lanes: Vec<RunningLane>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunningLane {
    pub directory: String,
    pub pid: Option<u32>,
    pub id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostLaneStatus {
    pub id: String,
    pub state: String,
    pub age_seconds: u64,
    pub summary_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostRecord {
    pub backend: String,
    pub identifier: String,
    pub pid: Option<u32>,
    pub lane_id: String,
}

pub fn host_record(backend: &str, identifier: &str, pid: Option<u32>, lane_id: &str) -> HostRecord {
    HostRecord {
        backend: backend.to_owned(),
        identifier: identifier.to_owned(),
        pid,
        lane_id: lane_id.to_owned(),
    }
}

pub fn write_host_record(dir: &Path, record: &HostRecord) -> Result<()> {
    fs::write(dir.join("host.json"), serde_json::to_vec_pretty(record)?)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneStatus {
    Running,
    Finished,
    Failed,
    Lost,
}
impl LaneStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Failed => "failed",
            Self::Lost => "lost",
        }
    }
}

pub trait CommandRunner {
    fn output(&self, program: &str, args: &[&str]) -> Result<(bool, String, String)>;
}
pub struct SystemRunner;
impl CommandRunner for SystemRunner {
    fn output(&self, program: &str, args: &[&str]) -> Result<(bool, String, String)> {
        let out = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("starting {program}"))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ))
    }
}

pub fn parse_windows_base_path(output: &str) -> Result<PathBuf> {
    let line = output
        .lines()
        .find_map(|l| l.trim().strip_prefix("BasePath :"))
        .ok_or_else(|| anyhow!("PowerShell output did not contain BasePath"))?;
    let path = line.trim();
    if path.len() < 3 || !path.as_bytes()[1..].starts_with(b":\\") {
        bail!("invalid WSL BasePath: {path}");
    }
    Ok(PathBuf::from(path))
}

pub fn collect_facts(root: &Path, runner: &impl CommandRunner) -> HostFacts {
    let hostname = runner
        .output("hostname", &[])
        .ok()
        .map(|x| x.1)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let version = fs::read_to_string("/proc/version").ok();
    let distro = std::env::var("WSL_DISTRO_NAME").ok();
    let wsl = detect_wsl(version.as_deref(), distro.as_deref());
    let os = if wsl {
        "wsl2".to_owned()
    } else {
        std::env::consts::OS.to_owned()
    };
    let cpu_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let mut load_averages: Vec<f64> = fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| {
            s.split_whitespace()
                .take(3)
                .filter_map(|x| x.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    if load_averages.is_empty() {
        load_averages = runner
            .output("sysctl", &["-n", "vm.loadavg"])
            .ok()
            .map(|r| {
                r.1.trim_matches(['{', '}', ' '])
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
    }
    let mem = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_kb = |name: &str| {
        mem.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
    };
    let (mut total, mut avail) = (
        mem_kb("MemTotal:").map(|v| v * 1024),
        mem_kb("MemAvailable:").map(|v| v * 1024),
    );
    if total.is_none() {
        total = runner
            .output("sysctl", &["-n", "hw.memsize"])
            .ok()
            .and_then(|r| r.1.parse().ok());
    }
    if avail.is_none() {
        avail = runner
            .output("vm_stat", &[])
            .ok()
            .and_then(|r| parse_vm_stat_available(&r.1));
    }
    let probe_path = existing_parent(root);
    let lane_root_free_bytes = fs::metadata(&probe_path)
        .ok()
        .and_then(|_| {
            runner
                .output("df", &["-Pk", probe_path.to_str().unwrap_or(".")])
                .ok()
        })
        .and_then(|x| parse_df_free(&x.1));
    let windows_drive_free_bytes = if wsl {
        // SSH sessions into WSL (systemd sshd) do not carry WSL_DISTRO_NAME; an empty name means "the default".
        let distro = std::env::var("WSL_DISTRO_NAME")
            .ok()
            .filter(|n| !n.is_empty())
            .or_else(|| {
                std::env::var("LANES_WSL_DISTRO")
                    .ok()
                    .filter(|n| !n.is_empty())
            })
            .unwrap_or_default();
        windows_drive_free(&distro, runner)
    } else {
        None
    };
    let docker_running = runner
        .output("docker", &["info", "--format", "{{.ServerVersion}}"])
        .is_ok_and(|x| x.0 && !x.1.is_empty());
    let codex_login = runner.output("codex", &["login", "status"]);
    let codex_logged_in = codex_login.as_ref().is_ok_and(|(ok, out, err)| {
        *ok && format!("{out} {err}")
            .to_ascii_lowercase()
            .contains("logged in")
    });
    let codex_version = runner
        .output("codex", &["--version"])
        .ok()
        .filter(|x| x.0)
        .map(|x| x.1);
    let running_lanes = running_lanes(root);
    HostFacts {
        hostname,
        os,
        cpu_count,
        load_averages,
        memory_total_bytes: total,
        memory_available_bytes: avail,
        lane_root: root.display().to_string(),
        lane_root_free_bytes,
        wsl,
        windows_drive_free_bytes,
        docker_running,
        codex_logged_in,
        codex_version,
        running_lanes,
    }
}

fn existing_parent(path: &Path) -> PathBuf {
    let mut current = path;
    while !current.exists() {
        let Some(parent) = current.parent() else {
            return PathBuf::from("/");
        };
        current = parent;
    }
    current.to_path_buf()
}

pub fn detect_wsl(proc_version: Option<&str>, distro_name: Option<&str>) -> bool {
    distro_name.is_some_and(|name| !name.is_empty())
        || proc_version.is_some_and(|s| s.to_ascii_lowercase().contains("microsoft"))
}

/// Windows PowerShell by absolute path: an SSH session into WSL does not carry the Windows PATH.
fn powershell() -> &'static str {
    const ABSOLUTE: &str = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
    if Path::new(ABSOLUTE).exists() {
        ABSOLUTE
    } else {
        "powershell.exe"
    }
}

pub fn windows_drive_free(distro: &str, runner: &impl CommandRunner) -> Option<u64> {
    let query = if distro.is_empty() {
        "$lx = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss'; $d = (Get-ItemProperty $lx).DefaultDistribution; Get-ItemProperty \"$lx\\$d\" | Format-List BasePath".to_string()
    } else {
        format!(
            "Get-ChildItem 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss' | Get-ItemProperty | Where-Object {{ $_.DistributionName -eq '{}' }} | Format-List BasePath",
            distro.replace('\'', "''")
        )
    };
    runner
        .output(powershell(), &["-NoProfile", "-Command", &query])
        .ok()
        .and_then(|(_, out, _)| parse_windows_base_path(&out).ok())
        .and_then(|p| {
            let drive = p
                .to_string_lossy()
                .chars()
                .next()
                .unwrap_or('C')
                .to_string();
            runner
                .output(
                    powershell(),
                    &[
                        "-NoProfile",
                        "-Command",
                        &format!("(Get-PSDrive -Name {drive}).Free"),
                    ],
                )
                .ok()
                .and_then(|(_, out, _)| out.trim().parse::<u64>().ok())
        })
}

pub fn parse_df_free(output: &str) -> Option<u64> {
    let fields: Vec<_> = output.lines().last()?.split_whitespace().collect();
    fields
        .get(3)?
        .parse::<u64>()
        .ok()
        .map(|kb| kb.saturating_mul(1024))
}

pub fn parse_vm_stat_available(output: &str) -> Option<u64> {
    let page_size = output
        .lines()
        .next()?
        .split("page size of ")
        .nth(1)?
        .split(" bytes")
        .next()?
        .parse::<u64>()
        .ok()?;
    let pages = [
        "Pages free:",
        "Pages inactive:",
        "Pages speculative:",
        "Pages purgeable:",
    ]
    .into_iter()
    .filter_map(|name| output.lines().find_map(|line| line.strip_prefix(name)))
    .filter_map(|value| {
        value
            .trim()
            .trim_end_matches('.')
            .replace(',', "")
            .parse::<u64>()
            .ok()
    })
    .sum::<u64>();
    Some(pages.saturating_mul(page_size))
}

/// Every lane directory without a summary is running (or lost), whoever started it. host.json, written only by
/// detached runs, adds the recorded process id when present. Lanes started by the Node runners have no host.json
/// and must still count: the first real run on the WSL host reported "safe to stop" while an integration lane
/// was running there (2026-09-26).
pub fn running_lanes(root: &Path) -> Vec<RunningLane> {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let name = dir.file_name()?.to_string_lossy().to_string();
            if !dir.is_dir() || !name.starts_with("lane-") || dir.join("summary.json").exists() {
                return None;
            }
            let record: Option<HostRecord> = fs::read(dir.join("host.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            Some(RunningLane {
                directory: dir.display().to_string(),
                pid: record.as_ref().and_then(|r| r.pid),
                id: record
                    .map(|r| r.lane_id)
                    .or_else(|| Some(lane_id_from_directory(&name))),
            })
        })
        .collect()
}

/// List lane-root directories using the same summary-less detection as host facts.
pub fn host_lane_statuses(root: &Path) -> Vec<HostLaneStatus> {
    let running: std::collections::HashMap<String, String> = running_lanes(root)
        .into_iter()
        .map(|lane| (lane.directory, lane.id.unwrap_or_default()))
        .collect();
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let name = dir.file_name()?.to_string_lossy().to_string();
            if !dir.is_dir() || !name.starts_with("lane-") {
                return None;
            }
            let summary = dir.join("summary.json");
            let state = if running.contains_key(&dir.display().to_string()) {
                "running"
            } else if summary.is_file() {
                let parsed: Value = serde_json::from_slice(&fs::read(&summary).ok()?).ok()?;
                if parsed
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.starts_with("finished") && !s.contains("(exit "))
                {
                    "finished"
                } else {
                    "failed"
                }
            } else {
                return None;
            };
            let host_record: Option<HostRecord> = fs::read(dir.join("host.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            let summary_data: Option<Value> = fs::read(&summary)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            let id = summary_data
                .as_ref()
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| host_record.map(|record| record.lane_id))
                .or_else(|| running.get(&dir.display().to_string()).cloned())
                .unwrap_or_else(|| lane_id_from_directory(&name));
            let metadata = fs::metadata(&dir).ok()?;
            let age_seconds = metadata
                .created()
                .or_else(|_| metadata.modified())
                .ok()
                .and_then(|time| time.elapsed().ok())
                .map_or(0, |elapsed| elapsed.as_secs());
            Some(HostLaneStatus {
                id,
                state: state.into(),
                age_seconds,
                summary_path: summary.display().to_string(),
            })
        })
        .collect()
}

fn lane_id_from_directory(name: &str) -> String {
    let timestamp = name.match_indices("-20").find_map(|(index, _)| {
        let tail = name.as_bytes().get(index + 1..)?;
        (tail.len() >= 9 && tail[..8].iter().all(u8::is_ascii_digit) && tail[8] == b'T')
            .then_some(index)
    });
    timestamp
        .map(|index| {
            name[..index]
                .strip_prefix("lane-")
                .unwrap_or(&name[..index])
                .to_owned()
        })
        .unwrap_or_else(|| name.to_owned())
}

pub fn ensure_safe_to_stop(root: &Path) -> Result<Vec<RunningLane>> {
    let lanes = running_lanes(root);
    if !lanes.is_empty() {
        bail!(
            "{} lane(s) are still running; stop them before stopping this host",
            lanes.len()
        );
    }
    Ok(lanes)
}

pub fn enforce_disk_floor(
    root_free: Option<u64>,
    host_free: Option<u64>,
    floor_gb: f64,
    force: bool,
) -> Result<()> {
    let floor = (floor_gb.max(0.0) * 1024f64.powi(3)) as u64;
    if !force && root_free.is_some_and(|b| b < floor) {
        bail!(
            "lane root has {:.1} GB free; need {:.0} GB (use --force-with-running-lanes to override)",
            root_free.unwrap_or(0) as f64 / 1024f64.powi(3),
            floor_gb
        );
    }
    if !force && host_free.is_some_and(|b| b < floor) {
        bail!(
            "WSL Windows drive has {:.1} GB free; need {:.0} GB (use --force-with-running-lanes to override)",
            host_free.unwrap_or(0) as f64 / 1024f64.powi(3),
            floor_gb
        );
    }
    Ok(())
}

pub fn lane_status(dir: &Path, runner: &impl CommandRunner) -> Result<LaneStatus> {
    if dir.join("summary.json").exists() {
        let summary: Value = serde_json::from_slice(&fs::read(dir.join("summary.json"))?)?;
        return Ok(
            if summary
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|s| s.starts_with("finished") && !s.contains("(exit "))
            {
                LaneStatus::Finished
            } else {
                LaneStatus::Failed
            },
        );
    }
    let bytes = fs::read(dir.join("host.json"))
        .with_context(|| format!("reading {}/host.json", dir.display()))?;
    let record: HostRecord = serde_json::from_slice(&bytes)?;
    let alive = match record.backend.as_str() {
        "systemd" => runner
            .output("systemctl", &["--user", "is-active", &record.identifier])
            .is_ok_and(|r| r.0 && r.1 == "active"),
        "process-group" => record.pid.is_some_and(|pid| {
            runner
                .output("kill", &["-0", "--", &format!("-{pid}")])
                .is_ok_and(|r| r.0)
        }),
        _ => false,
    };
    Ok(if alive {
        LaneStatus::Running
    } else {
        LaneStatus::Lost
    })
}

pub fn stop_lane(dir: &Path, runner: &impl CommandRunner) -> Result<()> {
    let record: HostRecord = serde_json::from_slice(
        &fs::read(dir.join("host.json"))
            .with_context(|| format!("reading {}/host.json", dir.display()))?,
    )?;
    let (program, args): (&str, Vec<&str>) = match record.backend.as_str() {
        "systemd" => ("systemctl", vec!["--user", "stop", &record.identifier]),
        "process-group" => {
            let pid = record
                .pid
                .ok_or_else(|| anyhow!("host record has no process group id"))?;
            let pid = format!("-{pid}");
            let leaked = Box::leak(pid.into_boxed_str());
            ("kill", vec!["-TERM", "--", leaked])
        }
        _ => bail!("unsupported host backend {}", record.backend),
    };
    let (ok, _, err) = runner.output(program, &args)?;
    if !ok {
        bail!(
            "could not stop recorded {} {}: {err}",
            record.backend,
            record.identifier
        );
    }
    Ok(())
}

pub fn read_host_config(path: &Path) -> Result<serde_json::Map<String, Value>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: Value = serde_json::from_str(&text)?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("hosts config must be a JSON object"))
}

pub fn compact_facts(f: &HostFacts) -> String {
    format!(
        "{}\t{}\t{} CPUs\t{} lanes\t{} GB root free\t{} GB host drive free",
        f.hostname,
        f.os,
        f.cpu_count,
        f.running_lanes.len(),
        f.lane_root_free_bytes
            .map(|n| format!("{:.0}", n as f64 / 1e9))
            .unwrap_or_else(|| "?".into()),
        f.windows_drive_free_bytes
            .map(|n| format!("{:.0}", n as f64 / 1e9))
            .unwrap_or_else(|| "n/a".into())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Fake {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        answers: Vec<(bool, String, String)>,
    }
    impl CommandRunner for Fake {
        fn output(&self, p: &str, a: &[&str]) -> Result<(bool, String, String)> {
            self.calls
                .borrow_mut()
                .push((p.into(), a.iter().map(|s| (*s).into()).collect()));
            let i = self.calls.borrow().len() - 1;
            Ok(self
                .answers
                .get(i)
                .cloned()
                .unwrap_or((false, String::new(), String::new())))
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: RefCell::new(Vec::new()),
            answers: vec![],
        }
    }
    #[test]
    fn a_lane_started_by_the_node_runner_counts_as_running() {
        let root = test_dir("node-started");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("lane-node-started-20260926T000000-abc/repo")).unwrap();
        fs::create_dir_all(root.join("lane-done-20260926T000000-def")).unwrap();
        fs::write(
            root.join("lane-done-20260926T000000-def/summary.json"),
            "{}",
        )
        .unwrap();
        fs::create_dir_all(root.join(".slots")).unwrap();
        let lanes = running_lanes(&root);
        assert_eq!(
            lanes.len(),
            1,
            "a summary-less lane without host.json must count"
        );
        assert!(ensure_safe_to_stop(&root).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parses_real_powershell_format_list_output() {
        assert_eq!(
            parse_windows_base_path(
                "\nBasePath : C:\\Users\\me\\AppData\\Local\\Packages\\Ubuntu\\LocalState\n"
            )
            .unwrap(),
            PathBuf::from("C:\\Users\\me\\AppData\\Local\\Packages\\Ubuntu\\LocalState")
        );
    }
    #[test]
    fn detects_wsl_from_version_text_helper_shape() {
        assert!(detect_wsl(
            Some("Linux version 5.15.90.1-microsoft-standard-WSL2"),
            None
        ));
        assert!(detect_wsl(None, Some("Ubuntu")));
        assert!(!detect_wsl(Some("Linux version 6.10.0"), None));
    }
    #[test]
    fn floor_requires_force_when_below_threshold() {
        let floor = 80 * 1024u64.pow(3);
        assert!(enforce_disk_floor(Some(floor - 1), None, 80.0, false).is_err());
        assert!(enforce_disk_floor(Some(floor), Some(floor - 1), 80.0, false).is_err());
        assert!(enforce_disk_floor(Some(floor - 1), None, 80.0, true).is_ok());
    }
    #[test]
    fn safe_to_stop_is_running_lane_count() {
        let root = test_dir("safe");
        assert!(
            ensure_safe_to_stop(&root).is_ok(),
            "an empty lane root is safe"
        );
        fs::create_dir_all(root.join("lane-one")).unwrap();
        // A summary-less lane is running even without host.json (Node-runner lanes never write one).
        assert!(ensure_safe_to_stop(&root).is_err());
        write_host_record(
            &root.join("lane-one"),
            &host_record("systemd", "lanes-one", None, "one"),
        )
        .unwrap();
        assert!(ensure_safe_to_stop(&root).is_err());
        fs::write(
            root.join("lane-one/summary.json"),
            r#"{"status":"finished"}"#,
        )
        .unwrap();
        assert!(running_lanes(&root).is_empty());
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn host_status_lists_running_finished_and_failed_lane_directories() {
        let root = test_dir("host-status");
        for name in [
            "lane-run-one-20260926T000000-abc",
            "lane-finished",
            "lane-failed",
        ] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        fs::write(
            root.join("lane-finished/summary.json"),
            r#"{"id":"done-id","status":"finished"}"#,
        )
        .unwrap();
        fs::write(
            root.join("lane-failed/summary.json"),
            r#"{"id":"bad-id","status":"timeout"}"#,
        )
        .unwrap();
        let rows = host_lane_statuses(&root);
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .any(|row| row.id == "run-one" && row.state == "running")
        );
        assert!(
            rows.iter()
                .any(|row| row.id == "done-id" && row.state == "finished")
        );
        assert!(
            rows.iter()
                .any(|row| row.id == "bad-id" && row.state == "failed")
        );
        assert!(
            rows.iter()
                .all(|row| row.summary_path.ends_with("summary.json"))
        );
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn bookkeeping_roundtrips() {
        let dir = test_dir("bookkeeping");
        fs::create_dir_all(&dir).unwrap();
        let x = host_record("process-group", "123", Some(123), "abc");
        write_host_record(&dir, &x).unwrap();
        assert_eq!(
            serde_json::from_slice::<HostRecord>(&fs::read(dir.join("host.json")).unwrap())
                .unwrap()
                .pid,
            Some(123)
        );
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn lost_when_recorded_process_is_gone() {
        let dir = std::env::temp_dir().join(format!("lanes-host-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("host.json"),
            serde_json::to_vec(&HostRecord {
                backend: "process-group".into(),
                identifier: "123".into(),
                pid: Some(123),
                lane_id: "abc".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(lane_status(&dir, &fake()).unwrap(), LaneStatus::Lost);
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn stop_uses_only_recorded_identifier() {
        let dir = test_dir("stop");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("host.json"),
            serde_json::to_vec(&HostRecord {
                backend: "systemd".into(),
                identifier: "lanes-abc".into(),
                pid: None,
                lane_id: "abc".into(),
            })
            .unwrap(),
        )
        .unwrap();
        let f = Fake {
            calls: RefCell::new(Vec::new()),
            answers: vec![(true, String::new(), String::new())],
        };
        stop_lane(&dir, &f).unwrap();
        assert_eq!(f.calls.borrow()[0].0, "systemctl");
        assert_eq!(f.calls.borrow()[0].1, vec!["--user", "stop", "lanes-abc"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn windows_drive_lookup_uses_registry_base_path_and_drive() {
        let runner = Fake {
            calls: RefCell::new(Vec::new()),
            answers: vec![
                (
                    true,
                    "\nBasePath : D:\\WSL\\Ubuntu\\LocalState\n".into(),
                    String::new(),
                ),
                (true, "123456789".into(), String::new()),
            ],
        };
        assert_eq!(windows_drive_free("Ubuntu", &runner), Some(123456789));
        let calls = runner.calls.borrow();
        assert!(
            calls[0].1[2].contains("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss")
        );
        assert!(calls[1].1[2].contains("-Name D"));
    }

    #[test]
    fn mac_memory_available_uses_reclaimable_vm_pages() {
        let output = "Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1,000.\nPages inactive: 2,000.\nPages speculative: 300.\nPages purgeable: 400.\n";
        assert_eq!(parse_vm_stat_available(output), Some(3_700 * 4096));
    }

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lanes-host-{label}-{}", std::process::id()))
    }
}
