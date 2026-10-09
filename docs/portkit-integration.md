# portkit in cowproof: integration and the polyglot port path

Status: design pass, 2026-10-09. Decision document for the director; it changes no code.
Founder decisions folded in today: (1) portkit's code moves into the cowproof workspace rather than staying an external `pk` binary; (2) the porting harness must be polyglot (Python, Node/TypeScript, shell at least; open to Ruby, Go, Perl, PowerShell), engineered into cowproof's processes.

Sources read for this pass (every claim below cites one of them):

| Source | What it is |
| --- | --- |
| `cowproof/docs/design.md` (read only) | the cowproof design under review; crate map at L190-202, portkit section L169-178, capsule L140-150, escalation L95-125 |
| `mail/scripts/lanes/run-lane.mjs` (998 lines), `run-remote.mjs`, `questions.mjs`, `health.mjs`, `repro-concurrency.mjs`, their `*.test.mjs`, `README.md` | the Node lane runner with hundreds of real runs |
| `everydom-lanes/crates/lanes-{core,cli,host,lint,plan,report}` and `docs/*.md` | the private Rust port started 2026-09-26 (`README.md` L5) |
| `mail/.claude/skills/lane-{dispatch,handback,escalate}/SKILL.md` | the director skills |
| `portkit/` (19 commits, all 2026-09-09, remote `github.com/srmcguirt/portkit`, no tags, not on crates.io: `cargo search portkit` returns no crate of that name) | `core`, `mcp`, `port`, `cli`, `plugin`, `read`, `index`, `schema`, `demo`, `src/main.rs`, `tests/`, `README.md`, `CLAUDE.md`, `CHANGELOG.md`, `.github/workflows/ci.yml`, `justfile` |

Conventions: "Node" means `mail/scripts/lanes/*.mjs`; "Rust crates" means `everydom-lanes/crates/*`; "pk" means portkit's CLI (`portkit/cli/src/lib.rs` L74-100).

## 0. Summary of decisions

| # | Decision | Where argued |
| --- | --- | --- |
| D1 | portkit's `core`, `mcp`, `port`, `cli`, `plugin`, `read` and `index` crates are imported into the cowproof workspace with history (`git subtree add`), keeping the `portkit-*` crate names under `crates/portkit/`; `demo`, `schema`, the Python example and the Python CI script are dropped | section 4 |
| D2 | One `cargo install cowproof` installs three binaries from one package: `cowproof`, plus the thin companions `pk` and `pk-read` that Claude Code hooks and the builder shell call by name; `cowproof pk ...` is the same command tree embedded | section 4.5 |
| D3 | The standalone portkit repository is archived with a pointer once cowproof's CI replays portkit's own tests green; nothing is published from it | section 4.6 |
| D4 | The builder's `ask` tool and the director's `rule`/`watch` tools are portkit `Tool` impls served by `portkit_mcp::serve_stdio` from inside the `cowproof` binary; blocking asks are modelled as ticket plus bounded poll, never as one long MCP call | section 3a |
| D5 | Every Claude builder lane runs with portkit hooks, a lane-private state dir, absolute trace paths and a `pk doctor --json` verdict at lane end; Codex and OpenRouter lanes are `untraced` by construction | section 3b |
| D6 | The lane tooling is ported in 16 steps; the pure units go through `pk port capture`/`replay` against a Node adapter; the effectful units are proved by translated tests, a scripted fake worker and recorded effect traces | sections 1 and 2 |
| D7 | Port packets become a first-class cowproof packet kind with their own lint rules, a replay gate in the verifier and a capsule entry; a builder never adds an `accepted` difference without a director ruling id | section 6.4 |
| D8 | The polyglot harness is adapter based: function-level shims for Python and Node, whole-process capture for shell and anything else, with determinism pinned by the capture runner's env and effects recorded by shims and tree snapshots | section 6 |

## 1. Inventory of the lane tooling to port

Classification key:

- **P** pure and portable through portkit's stdin/stdout parity contract as is (the Node function is exported and deterministic given its arguments and a pinned env).
- **PX** portable after extracting a pure core: the row says what to extract and what effect to inject.
- **E** effectful or OS bound: parity fixtures do not fit; the row names the proof instead.
- **R** already covered by a Rust crate: reuse, verify with fixtures, do not re-port.

Effect-capture techniques referred to below:

- **PATH shim**: a fake `ps`, `lsof`, `ss`, `codex`, `log`, `journalctl` or `sqlite3` put first on `PATH` that prints recorded text or records its argv. The Node runner spawns these by name (`run-lane.mjs` L232-236, L244, L372-378, L384, L392), so it needs no edit.
- **Fake worker**: a scripted `codex`/`opencode` executable that emits the JSON event stream the runner parses (`run-lane.mjs` L771-800) and records its own argv and env to a file. `run-lane.test.mjs` L143-160 already uses one (`fake-codex.mjs`).
- **Translated test**: the existing `*.test.mjs` case rewritten in Rust against the same inputs.

### 1.1 `run-lane.mjs`

| Unit (Node location) | Class | Rust crate today | Target crate | Port note and proof |
| --- | --- | --- | --- | --- |
| `parseHeader` L487-504 | P | `lanes-core::parse_header` L83-170 (R) | `cowproof-core` | Node reads `CLASS_LIMITS` from `LANE_CLASS_LIMITS` at import (L67-77) and validates `class` against it (L499); pin the env at capture. Error cases: the adapter returns `{"error": message}` (section 6.2). Everydom rules inside (GLM refusal L502, heavy models L500, default models L60) become config; fixtures captured with Everydom defaults need the defaults as a case input (section 6.2 "config as input"). |
| `globToRegExp` L506-516 | P | `glob_to_regex` L180-208, `glob_matches` L210-247 (R) | `cowproof-core` | Adapter emits `RegExp.source`; V8 escapes `/` in `.source`, so `^docs\/.*x\.md$` on both sides. The ad hoc Node-vs-Rust test in `lanes-core` (L806-868) passed on 2026-10-09; it becomes a committed fixture set instead of a test that spawns `node`. |
| `outsideOwnership` L535-539 with `PROTECTED` L533 and `HANDOFF_DIR` L534 (read from `lanes.config.json` at L531) | PX | `outside_ownership` L285-298, `repo_rules` L249-283 (R) | `cowproof-core` | Node takes `(files, owns)` and closes over the repo's protected list; Rust takes `protected` explicitly. Cases carry `protected`; the adapter errors unless it equals the module's list, so a mismatch surfaces as a capture failure, never a silent fixture. |
| `removedLines` L519-526 | P | `removed_lines` L433-444 (R) | `cowproof-prove` | Append-only gate (design L131). Cases from `run-lane.test.mjs` L135-141 plus a rename case: Node diffs with `--no-renames` (L874, after the 2026-09-28 "move that copies" flaw, `lane-handback/SKILL.md` L68); `lanes-cli::diff_paths` L2234-2266 lacks `--no-renames`, so the fixture will catch it. |
| `classifyStatus` L285-302 and the opencode branch L888-896 | P | none (`lanes-cli` has no status class; `grep -c statusClass` is 0) | `cowproof-core` | Cases from `run-lane.test.mjs` L162-173 plus the opencode table. `lanes-host::lane_status` L497-511 and `host_lane_statuses` L399-412 test `status.starts_with("finished") && !contains("(exit ")`, the older Rust format; Node's `finished-no-handoff` starts with `finished`. cowproof adopts Node's taxonomy and rewrites those two checks. |
| `classLimits` L67-76, `PORT_BASE` L79, `scratchFor` L82, port block index L625 | P | `class_limit` L1471, `PORT_BASE` L11 | `cowproof-run` | Pure parsing and arithmetic. Everydom's defaults (`rust 2, crate 4, pg 3, light 6, port 50`) move to `cowproof.toml [classes]` (design L223-226). |
| `redact` L214-220, `writeDiag` truncation L222-229 | P | `replace_regex_secrets` L2406-2427 (covers `sk-or-` only) | `cowproof-run` | Synthetic token shapes only in cases. Node covers `sk-`, JWT, `Bearer`, `ghp_`, `xox*`, `OPENROUTER_API_KEY=`; Rust covers one. Fixtures settle it. |
| `sandboxProfile` L543-559, `linuxSandboxArgs` L564-577, `sandboxCommand` L579-582 | PX | `sandbox_profile` L303-341, `linux_sandbox_args` L343-410, `sandbox_command` L412-431 (R) | `cowproof-run` | Node reads `HOME` from `os.homedir()` (L51), which honours `$HOME`; pin it at capture. `linuxSandboxArgs` checks `fs.statSync` on `.rustup`, `.cargo`, `.npm-global`, browser dirs (L565-575): cases point `HOME` at a committed fixture tree. Then a golden live test on each OS: `run-lane.test.mjs` L38-52 (sandbox-exec reads the lane, cannot read `HOME`, cargo runs) translated, and a bubblewrap equivalent. |
| `opencodeConfig` L584-589, `preamble` L591-613, `DONE_RULE`/`STALL_NOTE`/`ERROR_NOTE`/`CONTINUE_PROMPT` L418-421 | PX, not exported | `opencode_config` L1966, `preamble` L1999 | `cowproof-run` | Not exported, so not capturable by adapter. Proof: golden artifacts. Every finished lane directory holds `opencode.json` and `prompt.md` (L691, L700); the Rust generator must reproduce `prompt.md` minus the packet text for the recorded header, paths, branch and head. Everydom wording ("A director reviews your work", `$LANE_SCRATCH`) becomes a template in `cowproof.toml`. |
| `codexIsolationArgs` L423-446 | PX | `codex_isolation_args` L446-513 (R) | `cowproof-run` | Reads three config files and the plugin cache directory. Cases point `codexHome` and `copy` at a committed fixture tree (the Node test L190-207 builds exactly that). |
| codex flags and argv L731-751, env L709-714 and L743-747 | E | `codex_argv` L2176, `opencode_argv` L2156, `lane_env` L2103 | `cowproof-run` | Only observable live. Proof: fake worker records argv and env; run Node and cowproof on the same packet with the same fake, diff the recordings with lane paths normalised. Everydom pins (`CARGO_BUILD_JOBS=4`, `CARGO_NET_OFFLINE`, sccache, browser env L40-59) become config. |
| `removeBuildOutput` L449-465 | E | `remove_build_output` L515-540 (R) | `cowproof-run` | Deletes. Translated test (`run-lane.test.mjs` L175-188; `lanes-core` L698-726 already has it). |
| `scratchBusyInfo` L91-104, `tryAcquireSlot` L118-137, `releaseSlot` L138, `portBlockBusyPort` L106-117 | E | `try_acquire_slot` L542-567 (no TCP probe; liveness via a `kill -0` subprocess L588-603) | `cowproof-run` | Atomic `mkdir` slots, pid liveness, a real socket probe. Inject `alive: fn(pid)->bool`; translated tests L54-70 (cross-process cap, dead-owner reclaim) and L72-101 (a bound port skips the block, which Node gained in commit `e7f89ce` and the Rust crate lacks). Use `libc::kill(pid, 0)`, not a subprocess. |
| `stopPostgresUnder` L140-170 | PX | `stop_postgres` L1942 | `cowproof-run` | Node already injects `isAlive` and `kill` (L140). Extract "pid files under root, containment check, pids to signal" as a pure function over a directory listing; proof: translated tests L103-133 plus a recorded `(pid, signal)` trace from the fake `kill`. |
| `listLanePortListeners` L172-212 | PX | none | `cowproof-watch` | Extract `parse_ss(text)` and `parse_lsof(text)`; capture with PATH shims printing recorded `ss -ltnpH` and `lsof -nP -iTCP -sTCP:LISTEN` output so the Node function runs unchanged. |
| `hostFacts` L238-250 | PX | `lanes-host::collect_facts` L133-250 behind a `CommandRunner` trait L103-105 (R) | `cowproof-host` | PATH shim for `ps` and `codex --version`; `ignore_paths` for `at`, `hostname`, `loadavg`, `freeMemMiB`, `freeDiskGiB`, `uptimeSeconds`, `node` (`portkit/core/src/config.rs` L173-174 supports JSON Pointer ignores). Reuse the trait; the Rust facts are richer (WSL drive, Docker, Codex login). |
| `cleanGroup` L305-323, `probeWorkerStop` L326-338, `signalGroup` L304 | E | `terminate` L2392-2405 (single pid, no group) | `cowproof-run` | Process groups and signals. Translated test L143-160 (exit 0 on SIGTERM without a terminal event is `worker-stopped`, group cleaned). cowproof spawns detached groups as Node does (`detached: true` L747, L751); the Rust crate does not. |
| `updateCircuitBreaker` L340-346, `HOST_UNHEALTHY` L86-87, `ensureWitness` L348-365 | E | none | `cowproof-host` | Two worker deaths in 15 minutes mark the host unhealthy (L344-345). Extract the window arithmetic (pure); translated test with injected clock. The witness loop (L348-365) is Everydom diagnostics for a 2026-09-25 Codex incident; port as an optional hook script, not a core feature. |
| `captureFailure` L367-408 | E | none | `cowproof-run` | Platform logs (`log show`, `journalctl`, `sqlite3` on Codex's log). PATH shims make the bundle reproducible; the 3 MB trim order L404-407 is pure and gets a unit test. |
| `copyAuthIn`/`copyAuthBack` L252-269, `redactCodexTextFiles` L271-283 | E | none in Rust (`lanes-cli` reuses the real `~/.codex`, L1695) | `cowproof-run` | Guarded atomic copy-back. Translated tests with temp files and mtime control. |
| clone and baseline: `git clone --no-checkout` plus `rsync` excluding `.git`, build output and `tmp-*` L659-666, `.env*` removal L667, project Codex config removal L669, other-session reset L672-675, baseline commit L677-678, seed patch L679-682 | E | `cp -Rc` / `cp --reflink=auto` of the whole tree L1594-1607 | `cowproof-run` | The Node runner abandoned whole-tree `cp -Rc` for two reasons recorded in the file: a concurrent commit leaves a copied `.git` inconsistent (L656-658) and macOS tmp cleanup deleted clones that kept old access times (L941-942). cowproof-run clones `.git` with git and COW-copies the working files (clonefile/reflink per file, as the design's "COW clone" L87 intends). Proof: translated `run-remote.test.mjs` L29-65 style test on a temp repo (staged, unstaged, untracked all present; secrets absent; history and tags present). |
| worker supervision: event parsing L771-800, cost cap L791, timeout L757, heartbeat L758-767, stall watchdog and `status.json` L808-819, resume loop L820-838, survivors and orphan cleanup L845-851, stderr trim L852-855 | E | `run_worker` L2315-2391 and `consume_event` L2428-2474 (single pass, no watchdog, no resume, no status file, no heartbeat) | `cowproof-run` | The core of the runner. Proof: fake worker scripts (stall, error exit, DONE, length cutoff, provider refusal, cost overrun) driven through both runners; compare `summary.json` with timing fields ignored and `events.jsonl` verbatim. The event parser itself (`consume_event`) is PX: feed recorded `events.jsonl` lines from real lanes (synthetic subset) and compare the accumulated cost, tokens, truncation, refusal and final text. |
| patch extraction L863-882 (`--pathspec-from-file`, `--no-renames`, `--binary`), `SCRATCH` L485 | E | `diff_paths` L2234-2266 (`--pathspec-from-file`, `--binary`, no `--no-renames`) | `cowproof-run` | Git on a temp repo; translated cases for a move (deletion must appear), a binary file, thousands of paths (E2BIG, L867), scratch exclusion. |
| summary L912-920, ledger L930-933, `--quiet` row L992-994 | P (shape) | summary L1853, ledger L1868, `quiet_row` L1334 | `cowproof-run` | The field set is the contract `health.mjs`, `questions.mjs`, `lanes-host` and `lanes-report` read. Freeze it as a JSON Schema in `cowproof-core`; fixtures are real summaries (synthetic subset). |
| retry loop L617-645 (3 attempts, 60 s then 5 min, only `worker-*` statuses, `--retry-with-patch`) | PX | none | `cowproof-run` | Extract `next_attempt(status, class, attempt, has_patch, retry_with_patch) -> Option<delay>`; fixtures. |
| scheduler `main` L939-996 (pump, per-class running counts, 20 GB floor L80, `--check-ports`) | E | `run` L1234 | `cowproof-cli` | Translated test with fake lanes; the floor and root default (`~/.cache/everydom-lanes` L943) become config. |
| sccache L40-49, browser env L52-59 | E, Everydom specific | `find_sccache` L1371, `start_sccache` L1380 | `cowproof-run` (optional) | Keep as an opt-in `[cache]` config; no parity needed. |

### 1.2 `run-remote.mjs`

| Unit | Class | Rust today | Target | Proof |
| --- | --- | --- | --- | --- |
| `rsyncArgs` L31-34, `prepareScript` L124-145 | P | `remote_run` L990-1168 builds equivalents inline | `cowproof-host` | Fixtures from `run-remote.test.mjs` L10-27. |
| `createSnapshot` L72-112, `restoreSnapshot` L114-121 | E | `remote_run` L990-1168 (R, partial) | `cowproof-host` | Git objects via `stash create`, a temporary index, `commit-tree`, a bundle and a filtered tar. Translated test L29-65. Everydom's `OTHER_SESSION_PATHS` L44 becomes config. |
| `main` L155-218 | E | `remote_run` | `cowproof-host` | `ssh`/`rsync` PATH shims recording argv; design defers remote hosts (L39, L265), so this is a late step. |

### 1.3 `questions.mjs`, `health.mjs`, `repro-concurrency.mjs`

| Unit | Class | Rust today | Target | Proof |
| --- | --- | --- | --- | --- |
| `parseQuestions` L22-43 (joins split JSON lines, keeps malformed lines visible), `answeredNumbers` L45-47, `openItems` L75-84 | P | none | `cowproof-escalate` | Fixtures from `questions.test.mjs` L5-32. cowproof's escalation JSON (design L99-108) supersedes the `{question, recommendation, blocking}` line; the reader stays so the director tooling can read lanes from both runners during Everydom's transition. |
| `localLanes` L51-60, `remoteLanes` L62-73, `appendAnswer` L86-98 | E | none | `cowproof-escalate` | Directory listing and `ssh`; translated tests on a temp lane root; `rule --answer` writes `Q<n>:` lines exactly as L94. |
| `health.assess` L40-58 (`now` injectable) | P | `lanes-host::host_lane_statuses` L382-444 (different, coarser) | `cowproof-watch` | Fixtures from `health.test.mjs` L8-19. The idle, runner-silent, recovered and ended-badly kinds are the watch view's stall signals (design L167). |
| `readLocal` L19-25, `readRemote` L27-36 | E | `running_lanes` L355-379 | `cowproof-watch` | Translated. |
| `repro-concurrency.mjs` | E, diagnostic | none | none | An incident harness for a shared Codex home problem (header comment L2). Keep the Node script in the mail repo until Everydom moves; do not port. `parseArgs` L16-33 is pure if it is ever wanted. |

### 1.4 Rust crates that already supersede Node (reuse, do not re-port)

| Crate | Reuse as | Note |
| --- | --- | --- |
| `lanes-core` (869 lines) | `cowproof-core` | Header, globs, ownership, sandbox builders, isolation args, build cleanup, slots. Everydom defaults at L62-67, L264-272, L13 move to config. The `anyhow` error strings are the parity surface for error cases; keep them stable. |
| `lanes-lint` (998 lines) | `cowproof-lint` | Nine rules (`docs/packet-lint.md`). `lint_migrations` L491-516, the `2026092000` migration prefix L521 and contract versions L535-561 are Everydom; move to a project pack. The dependency on `lanes-plan` (L5) exists only for reservations; make it optional. Add the port-packet rules of section 6.4. |
| `lanes-report` (978 lines, a binary) | `cowproof-prove` | `parse_patch` L85-131, `parse_checks` L151-214, `classify` L301-340, `packet_commands` L341-362, `handoff_from_patch` L366-411, `extract_sections` L412-446, assertion counting L447-450, the 13 rules of `rules/flaws.toml` and the verdict ladder L624-658. Restructure as a library with a thin bin. The snapshot fixtures under `tests/fixtures/real/` are real Everydom handoffs (`main_report` tests L763-781): they must be synthesised before cowproof goes public (design L25). Rules 2, 7, 10, 11 and 13 are SQL and Supabase specific: project pack, per design L135. |
| `lanes-host` (812 lines) | `cowproof-host` | `CommandRunner` trait L103-105 with a fake in tests L590-606 is the effect-injection pattern cowproof-run should adopt everywhere. |
| `lanes-plan` (1160 lines) | `cowproof-plan` | Later, per design L201. |
| `lanes-cli` (2499 lines) | `cowproof-cli` | The command tree (L31-119) and the remote and plan dispatch. The lane loop itself (L1579-1886) is behind Node on every supervision feature listed in 1.1; port from Node, not from this file. |

## 2. Port order and packets

Sized for Haiku builders under the escalation model (design L95-125). Each step: unit, target crate, parity cases to capture, proof gate. "Hard" marks steps a Haiku builder should not start without the harness or a stronger model.

Prerequisites, done by the director (they touch protected paths or need judgement):

- **P0 scaffold**: cowproof workspace, `git subtree add` of portkit (section 4.2), `demo/` and `schema/` removed, `portkit_cli::Command::execute` made public (gap G1). Without G1 the `cowproof pk` command tree cannot exist.
- **P1 Node adapter**: `mail/scripts/lanes/portkit-adapter.mjs`, a dispatch file that imports the exports of `run-lane.mjs`, `run-remote.mjs`, `questions.mjs` and `health.mjs` and answers one `{"tool","input"}` request on stdin (section 6.1). It lives under `scripts/lanes/**`, which lanes may not write (`run-lane.mjs` L533), so the director commits it. The capture command is `node scripts/lanes/portkit-adapter.mjs` with `cwd` at the mail checkout and a pinned env (gap G2).
- **P2 fake worker harness**: `cowproof/tests/fake-worker/` with scripted `codex` and `opencode` executables and a PATH-shim kit (`ps`, `lsof`, `ss`, `log`, `journalctl`, `sqlite3`, `ssh`, `rsync`). Hard for Haiku; Sonnet or the director builds it once.

| Step | Unit | Target crate | Parity cases to capture | Proof gate | Haiku? |
| --- | --- | --- | --- | --- | --- |
| 1 | header parse (`parseHeader`, defaults, refusals) | `cowproof-core` | the 13 cases of `run-lane.test.mjs` L10-28, each Everydom-default case with `defaults` in the input, `LANE_CLASS_LIMITS` pinned empty and once set to `pg=6,rust=3` | `pk port replay --surface both`; `cargo test -p cowproof-core` | yes |
| 2 | globs and ownership split | `cowproof-core` | `run-lane.test.mjs` L30-36; every `owns` list from the mail repo's committed packets (data only); protected-list mismatch case | replay; a `not_ported` count of 0 (`ReplayReport::is_success` L120-122 counts unported tools as failure) | yes |
| 3 | `removedLines` and append-only breaches | `cowproof-prove` | L135-141; a rename case; a binary case | replay; the gate test from design L131 against a synthetic patch | yes |
| 4 | status taxonomy (`classifyStatus` plus the opencode branch) | `cowproof-core` | L162-173; one row per opencode outcome at `run-lane.mjs` L890-892 | replay; rewrite `lanes-host` L399-412 and L497-511 to the taxonomy, with their tests | yes |
| 5 | sandbox builders | `cowproof-run` | darwin profile and Linux args for a lane dir inside and outside `HOME`, with and without extra paths, `HOME` pinned to a fixture tree | replay; translated live test L38-52 on macOS and a bubblewrap test on Linux (CI matrix, as portkit's `ci.yml` already runs both) | yes for replay, director runs the live test |
| 6 | redact and diag truncation | `cowproof-run` | synthetic tokens of each shape at L214-220; truncation at the byte limit L225-227 | replay | yes |
| 7 | class limits, port blocks, scratch path, retry policy | `cowproof-run` | `classLimits` cases L209-214; block arithmetic; `next_attempt` table | replay; translated slot tests L54-101 with injected `alive` | yes |
| 8 | question channel readers and health assessment | `cowproof-escalate`, `cowproof-watch` | `questions.test.mjs` L5-32; `health.test.mjs` L8-19 | replay | yes |
| 9 | Codex isolation args | `cowproof-run` | the fixture tree of `run-lane.test.mjs` L190-207 committed under `fixtures/` | replay (the Rust function exists; this step is fixtures only) | yes |
| 10 | event parser and summary schema | `cowproof-run`, `cowproof-core` | recorded `events.jsonl` excerpts (synthetic): step costs, length cutoff, `turn.completed` usage, `thread.started`, provider refusal text; the summary JSON Schema | replay of the accumulator; schema validation of every summary the fake worker produces | yes |
| 11 | preamble, opencode config, argv and env | `cowproof-run` | golden `prompt.md` and `opencode.json` from three lane directories (paths normalised); argv and env recorded by the fake worker | golden comparison; fake-worker recording diff | hard: argv is only observable live; the template is fine for Haiku once the golden files exist |
| 12 | clone, baseline, seed patch, patch extraction | `cowproof-run` | none (git effects) | translated tests on a temp repo: tracked edits, untracked files, secrets gone, project Codex config gone, baseline commit, move with deletion, binary, 5,000 paths | yes with a precise packet; the packet names each case |
| 13 | worker supervision: spawn in a group, timeout, cost cap, heartbeat, stall watchdog, `status.json`, resume until DONE, orphan cleanup, stderr trim | `cowproof-run` | none | fake-worker scenarios (stall, error exit, DONE, cutoff, refusal, cost overrun, SIGTERM) run through Node and cowproof, `summary.json` compared with timing ignored, `events.jsonl` verbatim; translated L143-160 | hard: signals, groups, timers and a resume loop; Sonnet first, Haiku for follow-up scenarios |
| 14 | failure capture, circuit breaker, host facts | `cowproof-host`, `cowproof-run` | PATH-shim recordings for `ps`, `lsof`, `ss`, `log show`, `journalctl` | parser fixtures via the shims; translated breaker test with an injected clock | yes for parsers; the bundle assembly is hard |
| 15 | report and gates as a library | `cowproof-prove` | the existing `lanes-report` snapshot fixtures, synthesised | `cargo test` snapshots; flaw pack split into generic and project | yes (mechanical restructure) |
| 16 | remote snapshot and prepare | `cowproof-host` | `run-remote.test.mjs` L10-27 fixtures | replay; translated L29-65; `ssh` shim trace | yes for fixtures; `main` is hard and deferred per design |

Ordering rationale: steps 1 to 10 give the first slice (design "Next Steps" 2 and 3, L260-261) everything pure before any process is spawned; 11 to 13 are the slice's `run`; 14 to 16 are the "fold the runner in" phase (design L265).

Every packet for steps 1 to 10 has the same skeleton: `kind: port`, `port.lang: node`, the adapter command, the cases file, the fixtures directory in `owns`, the Rust tool names, and the checks `cowproof pk port replay --fixtures <dir> --surface both` plus `cargo test -p <crate>`. See section 6.4 for the packet shape and lint.

## 3. portkit as a runtime part of cowproof

### 3a. Serving `ask` and the director tools from a `Registry`

Yes, with one restriction.

- `portkit_core::Tool` (`core/src/tool.rs` L65-75) is an async `call(input) -> Result<Value>` with a JSON Schema `input_schema` that `Registry::call` validates before dispatch (`core/src/registry.rs` L94-106). The escalation object in design L99-108 (`kind` enum, `question`, `tried`, `options`, `recommend`, `blocking`) is the `input_schema` of an `AskTool`; a Haiku builder that sends a malformed escalation gets `Error::invalid_input`, which the MCP layer reports as retryable (`mcp/src/server.rs` L278-287, `core/src/error.rs` L59-64). That is free schema enforcement of the protocol.
- The MCP surface is `McpServer::new(registry, info)` plus `portkit_mcp::serve_stdio` (`mcp/src/lib.rs` L31-57), started by `cowproof serve --lane <dir>` and named in the builder's `--mcp-config`. The CLI surface for runtimes without MCP (`cowproof ask`, design L97) is `pk run ask` semantics on the same tool. The parity surface replays recorded escalations through both (`port/src/lib.rs` L50-74 checks direct and MCP).
- Director tools (`rule`, `watch --json`, `lanes`) are `Tool` impls in a second registry served by `cowproof serve --director`, so a director agent's own Claude Code session can `claude mcp add cowproof -- cowproof serve --director` and rule without shelling out.
- Restriction: the server handles one line at a time (`serve_stdio` loop L41-53) and has no server-to-client notifications (`dispatch` L155-170 answers `initialize`, `ping`, `tools/list`, `tools/call` only; capabilities advertise `listChanged: false` L189). A `blocking: true` ask therefore cannot be one long tool call that returns when the director rules: it would hold the connection for up to 30 minutes of parked time (design L113) and run into whatever tool-call timeout the host applies (unverified; treat any long call as unsafe). Model it as: `ask` writes the escalation to `escalations.jsonl`, returns `{ticket, state: "pending"}`; `await_ruling {ticket, max_wait_s}` polls the lane's rulings file for a bounded time (60 s default) and returns `pending` or the ruling; the builder loops. Parked time is accounted by cowproof from the file timestamps, not by the MCP call. `ServerInfo::with_instructions` (`mcp/src/protocol.rs` L106) carries the escalate-early rule text to the model.
- Do not route `ask` through portkit's plugin mechanism: `PluginTool` spawns a subprocess per call with a 30 s default timeout (`plugin/src/manifest.rs` L55-57, `plugin/src/tool.rs` L123-135). Fine for stateless helpers, wrong for a queue.

### 3b. Lane usage monitoring

| Piece | How, with the code that makes it so | Caveat |
| --- | --- | --- |
| Hooks in a lane-private Claude config | cowproof writes the hook block of `README.md` L384-390 into the `--settings` file (api-key mode) or `CLAUDE_CONFIG_DIR/settings.json` (subscription mode, design L184-185), using an absolute path to the installed `pk` so the sandboxed shell never depends on `PATH` (`pk doctor` check 1 is `which("pk")`, `cli/src/doctor.rs` L29-37) | `doctor` check 2 greps `$HOME/.claude/settings.json` and `./.claude/settings*.json` for the literal `pk hook` (L110-122); with a lane `HOME` and a `--settings` file elsewhere it reports MISS falsely (gap G7) |
| Per-lane state dir | `PORTKIT_STATE_DIR=<laneDir>/portkit` in the lane env; `pk-read` and the symbol index honour it (`read/src/lib.rs` L34-43, `index/src/index.rs` L129-134). Set `PORTKIT_SESSION=<lane id>` too: `pk-read` reads it from its own env (`read/src/main.rs` L74), and the builder's shell inherits the lane env | Codex drops env it did not set itself (`run-lane.mjs` L736-738 pins through `shell_environment_policy`); Claude builders inherit normally |
| Trace files | `[trace] dir` defaults to `.portkit/traces` relative to the working directory (`core/src/config.rs` L91-102), which inside a lane is the builder's clone, and the runner's scratch exclusion (`run-lane.mjs` L485) does not cover `.portkit/`, so traces would land in the patch. cowproof passes `--config <laneDir>/pk.toml` with an absolute `dir` (gap G6) | the hook payload's `session_id` is what partitions records (`cli/src/hook.rs` L244-270); one lane, one session |
| Rollup into the summary and capsule | `trace::read_jsonl` and `Summary` (`core/src/trace.rs` L241-247, L212-238) over the lane's trace files give calls, produced, delivered, saved and rejected; `pk trace --json` (`cli/src/commands.rs` L329-332) prints the per-tool map. Store `{calls, delivered_bytes, saved_bytes, rejected, reread_rate}` in `summary.json` and the capsule (design L148), and `saved_bytes` as the watch column CTX-SAVED (design L157-161) | re-read rate needs the target field (`CallRecord.target`, L59-60); portkit stores only targets, never arguments (`hook.rs` L213-234, tested in `tests/hook.rs` L149-173) |
| `pk doctor` preflight | run at lane end, not start: check 4 "hooks have fired" is the only evidence check (`doctor.rs` L69-80); a lane with zero agent-surface records is `untraced` (design L174) | needs `--json` (gap G7); today it prints text and exits non-zero |
| Codex and OpenRouter lanes | `codexIsolationArgs` turns Codex hooks off (`run-lane.mjs` L444) and `opencodeConfig` ships no plugins (L587); portkit's watch patterns only know Claude tool names plus `mcp__oc__read` (`core/src/watch.rs` L70-72) | report `untraced` honestly; token counts still come from the event stream |

### 3c. `pk-read` and `sym` as builder token savers

- `pk-read` returns only lines not already delivered this session, keyed on file hash and a compaction watermark (`read/README.md` L19-47). The measured saving on the largest shell shape was 4.9 percent of those bytes (`read/README.md` L16). Treat it as a verified rewrite path, not a headline saving.
- The automatic path is the `PreToolUse` rewrite (`cli/src/hook.rs` L108-145): it fires only when tracing is on, the command shape is hot (3 repeats and 4 KB, L100-101, L148-171) and the replacement has been run and verified (L179-194). It is conservative by design; expect few rewrites per lane.
- `sym` and `outline` are registered by `portkit_index::register(&mut registry, root)` (`index/src/tools.rs` L20-26) and persist their index under the state dir. Serve them from the same lane MCP server as `ask`, rooted at the builder's clone. The index crate is a prototype with a line-scanner extractor and known limits (`index/README.md` L48-58); its win is latency and exact spans over `grep`, not bytes (`index/README.md` L36-40).
- Known mismatch: the watcher's advice text says `pk run sym` (`tests/hook.rs` L119-122), but inside a lane the tool is reached over MCP as `mcp__cowproof__sym`. Make the suggested call configurable (gap G9), or the advice points at a tool the builder cannot run.
- Compaction watermark bug: the `pre-compact` and `session-start` hooks write `.portkit/read/<session>.json` relative to the current directory (`cli/src/hook.rs` L82-84), while `pk-read` reads from `portkit_read::state_dir()` (`read/src/main.rs` L73-81, `read/src/lib.rs` L34-43). Unless the working directory's `.portkit/read` happens to be the state dir, the watermark is never seen and `UNCHANGED` can be stale after compaction, the one failure the README calls dangerous (`read/README.md` L31-36). Fix before any lane relies on it (gap G5).

### 3d. Port packets as a user-facing feature

A `kind: port` packet names the source language, the adapter command, the cases file and the fixtures directory; the builder writes the Rust tool, registers it, and runs `cowproof pk port replay`; the verifier reruns the replay in a fresh clone and the gate reads `ReplayReport::is_success` (`port/src/replay.rs` L120-122). Full shape, lint rules and the escalation path are in section 6.4. Held-out checks (design L134) map directly: the director keeps a second cases file outside the clone; the verifier captures it against the reference at verification time and replays it, so a builder that special-cases the visible fixtures fails the held-out set.

### 3e. Parity reports inside the capsule

Yes. `ReplayReport` serialises (`port/src/replay.rs` L88-97) and `pk port replay --json` emits a map keyed by surface (`cli/src/commands.rs` L246-251). The capsule entry for a port packet is: the reference command and the source commit the fixtures were captured from, a content hash of the fixture set (gap G11: the report does not carry one today), the per-surface report with only failing and accepted outcomes in full and pass counts otherwise (bounded with portkit's own budget), and the `accepted` list verbatim with reasons so a reviewer sees the divergences without rerunning. `cowproof verify <capsule>` replays the fixtures at the recorded hash.

## 4. Bringing portkit into the cowproof workspace

Founder decision 2026-10-09: portkit's code becomes part of cowproof. This section is the how.

### 4.1 Which crates move, under what names

| portkit crate | Verdict | Reason |
| --- | --- | --- |
| `core` (Tool, Registry, config, diff, trace, watch, rewrite, fidelity, budget) | move, keep name `portkit-core` | the heart; nothing cowproof-specific in it |
| `mcp` | move, `portkit-mcp` | serves `ask` and the director tools (3a) |
| `port` | move, `portkit-port` | the parity harness; extended per section 6 |
| `cli` | move, `portkit-cli` | the `pk` command tree; `Command::execute` becomes public (G1) so `cowproof pk ...` embeds it |
| `plugin` | move, `portkit-plugin` | external tools by manifest; also the generic process adapter's spec flag (`--portkit-spec`, `plugin/src/tool.rs` L15) |
| `read` | move, `portkit-read` (lib plus `pk-read` bin) | builder token saver (3c) |
| `index` | move, `portkit-index`, feature `symbols` on by default, drop the `pkx` bin | `sym`/`outline` for builders; prototype status stays in its README; `ast-grep-core` is the heaviest dependency, so keep the feature gate |
| `schema` | leave behind (delete from the import) | `publish = false`, Fellwork fixtures and README (`schema/tests/fixtures/fellwork.json`, `schema/README.md` L7-34), `src/pg/` vendored from another project (`schema/src/pg/mod.rs` L5), 247 dependencies with the `postgres` feature (`schema/Cargo.toml` comment); no cowproof use |
| `demo` | delete | "delete this crate when you fork" (`demo/Cargo.toml` description); referenced only by `src/main.rs` L49 and `tests/parity.rs` L17, L27, both replaced by cowproof's registry and fixtures |
| `examples/python`, `fixtures/`, `scripts/check_fixtures_fresh.py`, the `parity` CI job's Python setup | delete | demo-only; the freshness check is reimplemented in Rust as `pk port check-fresh` (section 6.5) so cowproof's CI needs no Python |
| `src/main.rs` (the `pk` reference binary) | replace | becomes the `pk` companion bin in the cowproof package (4.5) |
| `tests/{cli,hook,mcp_stdio,trace,parity}.rs` | move | `parity.rs` re-targets cowproof's registry; `mcp_stdio.rs` (the stdout rule, `CLAUDE.md` L19-23) keeps guarding the lane MCP server |
| `README.md`, `CLAUDE.md`, `CHANGELOG.md`, `justfile`, `rustfmt.toml`, `.github/workflows/ci.yml` | merge | the hard rules in `CLAUDE.md` L17-44 go into cowproof's agent instructions verbatim; CI jobs `test` (ubuntu and macos), `lint`, `msrv` merge; the `parity` job becomes a replay-only job (section 6.5) |

Naming recommendation: keep `portkit-*`. The crates are a general tool-and-parity kit, the names appear throughout their docs and tests, `pk doctor` greps for the literal `pk hook` (`doctor.rs` L120-122), and nothing is gained by `cowproof-pk-core`. Directory layout: `crates/portkit/{core,mcp,port,cli,plugin,read,index}` beside `crates/cowproof-*`. All crates `publish = false` at first; `portkit-core` and `portkit-port` can be published from the cowproof repository later if outside users appear.

### 4.2 Import with history

`git subtree add --prefix=crates/portkit https://github.com/srmcguirt/portkit.git main` into the fresh cowproof history. Reasons: the 19 commits are public already under MIT/Apache, all by the founder (`git log` authors), and contain no Everydom material (the only "fellwork" mentions are in `schema/` and `index/README.md` benchmark rows); `git log --follow` and blame keep working; a `git subtree pull` can pick up anything that lands in the old repository during the transition. The cowproof-side scrub (design L25, L259) applies to the Everydom crates, not to this import. Delete `schema/`, `demo/` and the Python files in the first commit after the subtree add so the deletions are their own reviewable change.

### 4.3 MSRV and edition

- portkit declares `rust-version = "1.90"` and `edition = "2021"` (`portkit/Cargo.toml` L28, L32) with an MSRV CI job on 1.90 (`ci.yml` `msrv`).
- The Everydom crates use `edition = "2024"`, resolver 3 (`everydom-lanes/Cargo.toml`) and let-chains (`lanes-core/src/lib.rs` L458, `lanes-lint` L527, `lanes-report` L155), which need 1.88 or newer.
- Set the workspace to `rust-version = "1.90"`, resolver 3, edition 2024 for every cowproof crate; leave the imported portkit crates on 2021 until a separate `cargo fix --edition` commit (edition is per package, so this compiles today). Keep the MSRV CI job.

### 4.4 Licence

- portkit: `MIT OR Apache-2.0` (`Cargo.toml` L29, `LICENSE-MIT`, `LICENSE-APACHE`). cowproof: MIT (design L5, L25).
- The founder is the sole author of every portkit commit, so he may relicense; nothing vendored remains once `schema/src/pg/` leaves with the schema crate.
- Recommendation: make the whole cowproof workspace `MIT OR Apache-2.0`. MIT stays available to every user, so nothing in the design's MIT promise is lost; Apache adds the patent grant Rust projects conventionally offer; and it avoids per-crate licence fields diverging inside one workspace. This changes a line in `design.md`, so it is a founder call (open question Q3).

### 4.5 How the harness and the monitor surface in one binary

- One cargo package, `cowproof`, with three `[[bin]]` targets: `cowproof`, `pk` and `pk-read`. `cargo install cowproof` and the release archive install all three in one step, which satisfies "one installable binary" in the sense that matters: one install, no second tool to fetch. `pk` stays a separate executable because Claude Code hooks invoke a command by name on every tool call (`README.md` L384-390), the sandbox grants `~/.cargo/bin` read access (`run-lane.mjs` L556, `lanes-core` L370), and the measured, documented spelling `pk hook post-tool-use` keeps `pk doctor` honest. The `pk` bin is `portkit_cli::run_with(cowproof::registry)` (four lines, like `src/main.rs` L11-14 today).
- `cowproof pk <subcommand>` is the same `portkit_cli::Command` tree embedded (requires G1). `cowproof serve --lane <dir>` and `--director` build the registries of 3a and call `portkit_mcp::serve_stdio`. `cowproof read` is `pk-read`'s `main` behind a subcommand.
- The default registry served to a builder: `ask`, `await_ruling`, `sym`, `outline`, plus any `.portkit/plugins.toml` tools the project declares (`plugin/src/lib.rs` L68-104), with the manifest-only discovery rule kept (`README.md` L219-221).

### 4.6 The standalone portkit repository

Archive it with a README pointer once cowproof's CI runs portkit's moved tests green. Reasons: no tags, 19 commits from one day, not on crates.io, no known external users; keeping two copies manufactures exactly the drift the parity harness exists to catch. Keep the repository readable (do not delete) so the subtree history's links resolve. If outside demand appears later, publish `portkit-core` and `portkit-port` from the cowproof workspace rather than reviving the old repository.

## 5. Gaps: changes to the portkit crates once imported

Each is a concrete change with a one-line rationale. None is made in the standalone repository.

| ID | Change | File | Rationale |
| --- | --- | --- | --- |
| G1 | make `Command::execute` public, or add `pub async fn run_command(Command, Registry, &Config)` | `cli/src/lib.rs` L283 | only `run`/`run_with` exist and they parse argv themselves (L41-45); `cowproof pk ...` cannot embed the tree otherwise |
| G2 | `CaptureOptions { cwd, env, clear_env }` and an optional per-case `env` on `Case` | `port/src/capture.rs` L23-30, L125-150; `port/src/fixture.rs` L88-95 | fixtures must not depend on the capturing shell's `HOME`, `LANE_CLASS_LIMITS`, `TZ` or locale (section 6.2) |
| G3 | a process-capture mode: `pk port exec` materialises `files` into a temp root, runs the reference under the sandbox with shims, and emits `{exit, stdout, stderr, files_after, calls}` | new `port/src/process.rs` | shell scripts and foreign-language scripts have no function to call (section 6.1, 6.3) |
| G4 | error-case convention: a reference that exits non-zero is a capture failure today (`capture.rs` L152-158); add `Case.expect_error` so a "must reject" case records the error envelope | `port/src/capture.rs`, `fixture.rs` | `parseHeader` has six refusal cases (`run-lane.test.mjs` L14-27) that are the most valuable fixtures |
| G5 | `mark_compacted` uses `portkit_read::state_dir()` | `cli/src/hook.rs` L82-84 | the watermark is written where `pk-read` never reads (3c) |
| G6 | `[trace] dir` resolves against `PORTKIT_STATE_DIR` when set, default `<state>/traces`; the daily file name gains the session | `core/src/config.rs` L95-102, `cli/src/commands.rs` L281, `cli/src/hook.rs` L248 | a cwd-relative trace dir lands inside the builder's clone and its patch (3b) |
| G7 | `pk doctor --json`, `--settings <file>`, and `CLAUDE_CONFIG_DIR` awareness; `mentions_hook` matches absolute paths and `cowproof pk hook` | `cli/src/doctor.rs` L83-107, L110-122 | the lane verdict `traced`/`untraced` must be machine readable and must find a lane-private settings file |
| G8 | hook command strings generated with an absolute executable path | cowproof side, documented in `README.md` L384-390 | `which("pk")` inside a sandboxed shell is not guaranteed |
| G9 | watcher tool names and the suggested replacement call configurable (`Thresholds` gains `read_tools`, `suggest_sym_call`) | `core/src/watch.rs` L70-72 and the message builder; `tests/hook.rs` L119-122 | the advice must name a tool the builder can run (`mcp__cowproof__sym`) |
| G10 | `index`: feature `symbols`, remove the `pkx` bin, keep the lib | `index/Cargo.toml`, `index/src/main.rs` | prototype binary not wanted in the release; the tools are |
| G11 | `ReplayReport` carries a fixture-set hash and the reference `source` and capture commit; `--json` includes them | `port/src/replay.rs` L88-97; `port/src/fixture.rs` L23-27 | the capsule pins what was replayed (3e) |
| G12 | `pk port check-fresh <committed> <fresh>` in Rust comparing `tool`, `id`, `input`, `expected` | replaces `scripts/check_fixtures_fresh.py` | no Python in cowproof CI |
| G13 | normalisers for process captures: `path_roots` substitution (`$ROOT`, `$HOME`, `$TMP`), declared and versioned like the `normalized` fidelity class | `core/src/fidelity.rs`, `port/src/process.rs` | temp roots differ per run; a declared transform is checkable, a vague one is not (`README.md` L344-359) |
| G14 | `tests/parity.rs` "every tool has at least one fixture" (L20-33) generalised to the cowproof registry | `tests/parity.rs` | a tool with no fixtures passes vacuously |
| G15 | docs and metadata stop saying Python: `README.md` L3, L19-24, L94-99, L173-193 (plugin example), `CLAUDE.md` L3, L13, `cli/src/lib.rs` L79, `port/src/lib.rs` L3-6, `port/src/capture.rs` L3-5, `port/Cargo.toml` and `Cargo.toml` descriptions, `justfile` `capture` and `check-fixtures`, `ci.yml` `parity` job | listed files | the code is already language neutral (`capture.rs` runs `sh -c <command>`, L128-130); the documentation is not |

What cowproof needs from portkit and already has: the `Tool`/`Registry` abstraction, schema validation at dispatch, output budgets with `x-page-hint` (`core/src/budget.rs` L106, L288), the tolerant differ with `ignore_paths` and `unordered_arrays`, scoped `accepted` differences with mandatory reasons (`fixture.rs` L44-56), both-surface replay, JSONL tracing, the hook handlers and the stdout rule test.

## 6. The polyglot port path

Founder decision 2026-10-09: adoption of scripts into Rust must be polyglot and engineered into the processes.

### 6.1 Per-language capture adapters

The contract never changes: one JSON request `{"tool": name, "input": object}` on stdin, one JSON result on stdout, `PORTKIT_TOOL` in the env (`port/src/capture.rs` L126-147). What changes per language is how a reference gets wrapped without restructuring it.

| Language | Adapter model | What the adapter does | Status in portkit |
| --- | --- | --- | --- |
| Python | function-level shim (`adapter.py`) | imports the module, maps tool names to callables, `json.load(sys.stdin)`, `json.dump(result)`; the pattern of `examples/python/agent.py` | the only one documented today |
| Node, TypeScript | function-level shim (`adapter.mjs`) | `import { ... } from './module.mjs'`, dispatch on `PORTKIT_TOOL` or `request.tool`, serialise non-JSON values (`RegExp` to `.source`, `Map`/`Set` to arrays, thrown `Error` to `{"error": message}`); TypeScript through `tsx` or a compiled output | works unchanged (the capture command is any `sh -c` string); the lane runner adapter (P1) is the first instance |
| shell (bash, zsh, sh) | whole-process capture | no adapter in the script; `pk port exec` (G3) is the adapter: `input` is `{argv, env, stdin, files}`; `output` is `{exit, stdout, stderr, files_after, calls}` | missing (G3) |
| Ruby, Perl, PowerShell, Go, anything else | function-level shim if the language can read stdin JSON in a few lines (all of these can); otherwise whole-process capture | same contract; cowproof ships a template adapter per language under `templates/adapters/` | missing templates only |

Rules for adapters: an adapter is committed beside the source it wraps and listed in the port packet; it never computes anything the module does not; it exposes module-level constants as a `__defaults` tool so fixtures can be captured with them as inputs (section 6.2 "config as input"); it returns `{"error": message}` for thrown errors (G4).

Worked example, the lane runner: `mail/scripts/lanes/portkit-adapter.mjs` imports `parseHeader`, `globToRegExp`, `outsideOwnership`, `removedLines`, `classifyStatus`, `classLimits`, `redact`, `sandboxProfile`, `linuxSandboxArgs`, `sandboxCommand`, `codexIsolationArgs` from `run-lane.mjs`, `rsyncArgs` and `prepareScript` from `run-remote.mjs`, `parseQuestions`, `answeredNumbers`, `openItems` from `questions.mjs` and `assess` from `health.mjs`, plus a `__defaults` tool returning `PROTECTED`, `HANDOFF_DIR`, `CLASS_LIMITS`, `PORT_BASE` and `SLOT_DIR` (`run-lane.mjs` L533-534, L77-79, L85). Capture: `cowproof pk port capture --cmd 'node scripts/lanes/portkit-adapter.mjs' --cwd <mail checkout> --env HOME=/fixtures/home --env LANE_CLASS_LIMITS= --env TZ=UTC --cases cowproof/fixtures/lane-runner/cases.jsonl --out crates/cowproof-core/fixtures/node`. The fixtures commit to cowproof; CI replays them (no Node, no private repo needed); recapture is a director step on a machine with the mail checkout, recorded with the mail commit hash in each case's `note`.

### 6.2 Determinism per language

Common, enforced by the capture runner (G2) and reused unchanged by the replay side:

| Source of nondeterminism | Pin |
| --- | --- |
| clock | `PORTKIT_NOW=<RFC 3339>` in the env; adapters stub the clock when it is set; shell captures shim `date`; outputs that must carry a real time go under `accepted` with reason `nondeterministic: clock` or an `ignore_paths` entry (`config.rs` L173-174) |
| RNG | `PORTKIT_SEED=<int>`; Python `random.seed`, Node a seeded replacement for `Math.random` installed by the adapter, shell cannot pin `$RANDOM`, so such scripts record the divergence |
| env | `clear_env` then an explicit allowlist: `PATH` (shims first), `HOME`, `TMPDIR`, `TZ=UTC`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `PYTHONHASHSEED=0`, `NODE_OPTIONS=` empty |
| cwd | `cwd` set explicitly; relative paths in inputs resolve against it |
| temp paths | `TMPDIR=$ROOT/tmp` and a shimmed `mktemp` that numbers names; outputs normalised with `path_roots` (G13) |
| locale and ordering | `LC_ALL=C.UTF-8`; `unordered_arrays` only where the reference had no ordering guarantee (`config.rs` L176-177) |
| platform | functions that branch on the OS take `platform` as an input (`sandboxCommand` does, `run-lane.mjs` L579); capture runs on both OSes in the CI matrix and fixtures are tagged by platform in their `id` |
| config as input | module constants captured through `__defaults` and passed back as inputs, so Everydom's defaults are data in the fixture, not an assumption in the port |

Per language specifics: Python object key order follows insertion, Node follows insertion for string keys and sorts integer-like keys first, Rust with `preserve_order` (`Cargo.toml` L48) keeps parse order; the differ compares by JSON Pointer path, so object key order is not a difference, array order is. Floats: portkit's epsilon exists for last-place rounding (`README.md` L94-104); the lane tooling has none, so port packets for it set `epsilon = 0`.

### 6.3 Capturing effectful scripts

Three layers, all of which the lane runner's own port needs, so the first worked example exercises every one:

1. **File-system effect snapshot** (G3): the process runner materialises `input.files` into a fresh root, runs the script with `cwd = $ROOT` and `HOME = $ROOT/home`, then records `files_after` as `path -> {blake3, mode, size, content if small}` plus deletions. The Rust port's wrapper runs its function against the same materialised root, so both sides produce the same shape and the differ compares them. Example: `removeBuildOutput` (`run-lane.mjs` L449-465) is captured as `files` before and after; the Node tree in `run-lane.test.mjs` L182 is the case.
2. **Sandboxed runs**: capture uses cowproof-run's own sandbox builders (`sandboxProfile`, `linuxSandboxArgs`) with the real `HOME` denied, plus `(deny network*)` on macOS and `--unshare-net` on Linux for capture runs, so a reference script cannot touch the machine or the network while being recorded. Neither network rule exists in today's profiles (`run-lane.mjs` L550-558, L567-568); they are capture-only additions.
3. **Recorded subprocess calls**: PATH shims log `{program, argv, env subset, stdin}` to `calls.jsonl` and answer from a `responses.json` scripted per case; `calls` becomes part of the output JSON. The Rust port routes its subprocesses through an injected runner (`lanes-host::CommandRunner`, L103-105) whose fake replays the same responses and records the same list. Parity then covers outputs, file effects and the call sequence. The fake worker of P2 is this layer applied to `codex` and `opencode`.

Signals, timers and process groups (step 13) do not fit any of the three; they are proved by the fake-worker scenarios and translated tests, and the design document should say so rather than imply parity fixtures cover the whole runner.

### 6.4 Port packets in cowproof's processes

Packet header additions (`kind: port` is validated by `cowproof-lint`):

| Field | Meaning |
| --- | --- |
| `port.lang` | `python`, `node`, `typescript`, `shell`, `ruby`, `perl`, `powershell`, `go`, `other` |
| `port.adapter` | `function` (an adapter file in the source repo) or `process` (G3); `function` requires `port.reference.cmd` |
| `port.reference` | `{cmd, cwd, env, runtime}`; `runtime` names what the verifier must have installed (`node>=22`), so a verifier without it reports `held-out: skipped` instead of silently passing |
| `port.cases` | the committed visible cases file; the director keeps held-out cases outside the clone |
| `port.fixtures` | directory the builder may write, listed in `owns` |
| `port.tools` | the tool names the Rust registry must answer; the replay's `not_ported` count must be zero |
| `port.parity` | `epsilon`, `ignore_paths`, `unordered_arrays`, `path_roots`; `epsilon` defaults to 0 for non-numeric ports |

Lint rules (added to `lanes-lint`'s rule table, `docs/packet-lint.md`):

| Rule | Catches |
| --- | --- |
| `port-cases-missing` | `port.cases` absent from the repository |
| `port-fixtures-not-owned` | `port.fixtures` not covered by `owns` |
| `port-reference-not-allowed` | a `wide: false` lane whose checks run the reference command without an `allow` entry (`lint_command_permission`, `lanes-lint` L339-361) |
| `port-tool-unregistered` | a tool in `port.tools` with no registration target named in the packet body |
| `port-accepted-unruled` | an `accepted` entry in a fixture whose `reason` does not cite a ruling id (`ruling:<id>`) present in the lane's escalation log |
| `port-epsilon-loosened` | a packet or fixture that raises `epsilon` above the project default (`CLAUDE.md` L36-41 forbids it) |
| `port-nondeterministic-output` | heuristic: a case output containing an RFC 3339 time, a `/tmp` or home path, or a hostname with no matching `ignore_paths` or `path_roots` entry |

Verifier gate: in the fresh clone, `cowproof pk port replay --fixtures <dir> --surface both --json`; fail on `is_success() == false`; then capture and replay the held-out cases if `runtime` is present; record both reports in the capsule (3e). The claimed-versus-run gate (design L136) compares the builder's reported replay line against the verifier's.

Escalation when parity cannot be reached: the builder never edits `accepted` or `epsilon` on its own. It raises `ask` with `kind: "design"`, the fixture id and JSON Pointer, what it tried, and options `a` fix the port, `b` accept with a written reason, `c` the reference is wrong (fix the reference and recapture), with a recommendation. The director's `answer` carries the reason text and a ruling id; the builder writes `accepted: [{path, reason: "ruling:<id> ..."}]`, and `port-accepted-unruled` plus the capsule's escalation log tie the two together mechanically. Escalate-early (design L112) applies: two failed replays on the same fixture force the ask.

### 6.5 What is Python-specific in portkit today

Code: nothing material. `capture.rs` runs the reference through `sh -c` (L128-130) and only requires JSON on stdout; `PluginTool` speaks the same envelope (`plugin/src/tool.rs` L99-101). The Python coupling is documentation, examples and CI:

| Location | What | Change |
| --- | --- | --- |
| `README.md` L1-4, L19-28, L62-92, L94-104 | "porting tested Python agentic processes", Python float rationale, Python workflow | reword to "a reference implementation in any language"; keep the float note as one language pair among others |
| `README.md` L173-193 | plugin example in Python | add Node and shell examples |
| `CLAUDE.md` L3, L13-14 | Python template framing, `just capture` against the Python reference | reword; `just capture` becomes a per-port target |
| `cli/src/lib.rs` L79 | `about` string | reword |
| `port/src/lib.rs` L3-17, `port/src/capture.rs` L3-5 | module docs | reword |
| `Cargo.toml` L12-16, `port/Cargo.toml` description | crate descriptions | reword |
| `examples/python/agent.py`, `examples/cases.jsonl`, `fixtures/` | demo reference and fixtures | delete with `demo/` |
| `scripts/check_fixtures_fresh.py`, `justfile` `check-fixtures`, `ci.yml` `parity` job (Python 3.12 setup) | Python in CI | replace with `pk port check-fresh` (G12); the CI job becomes replay of committed fixtures plus, on a self-hosted or director run, recapture from the Node adapter |
| `core/src/watch.rs` L70-72 | tool names | not Python, but Claude-specific; G9 |

The worked example of the polyglot path is therefore the lane runner's own port: a Node module wrapped by a function-level adapter (6.1), captured with pinned env and config-as-input (6.2), its effectful halves proved by snapshots, shims and the fake worker (6.3), dispatched as `kind: port` packets with the lint rules and gate above (6.4), on a harness that needed no Python to begin with (6.5).

## 7. Risks and open questions

| # | Risk or question | Recommended answer |
| --- | --- | --- |
| R1 | Fixtures captured against the Node runner bake in Everydom defaults (models, protected paths, handoff dir, class limits, scratch names) | config as input through `__defaults` (6.2); any fixture that still encodes an Everydom value gets an `accepted` entry with a ruling, never a silent default in Rust |
| R2 | The Node runner keeps changing while the port proceeds (its backlog is live: `everydom-lanes/docs/backlog.md`) | record the mail commit hash in every case's `note`; recapture per step, not per wave; a fixture diff is a behaviour diff and is reviewed as one (`CLAUDE.md` L42-44) |
| R3 | `lanes-report`'s real-handoff fixtures and the Everydom-specific flaw rules are private material | synthesise the fixtures before the repository goes public; split `flaws.toml` into a generic pack and an Everydom pack in the mail repo (design L135) |
| R4 | Haiku on effect-heavy code (steps 11, 13, 14) | the fake-worker harness is built first by Sonnet or the director; Haiku packets then add scenarios and parsers, each with a single observable file to match |
| R5 | A blocking `ask` as one long MCP call could hit a host timeout and the server is single-threaded | ticket plus bounded poll (3a); measure parked time from file timestamps |
| R6 | Token-saver claims outrun the evidence (`pk-read` 4.9 percent, `sym` wins latency not bytes) | report `saved_bytes` and re-read rate per lane from traces; no headline numbers in the README until a real wave reports them |
| R7 | Trace files or `.portkit/` state leaking into a builder's patch | absolute state and trace dirs (G6) and a scratch-exclusion entry for `.portkit/` in cowproof-run |
| Q1 | Who owns the Node adapter file in the mail repo, given `scripts/lanes/**` is protected from lanes | the director commits it; it is a dispatch table, not logic |
| Q2 | Edition 2021 versus 2024 for the imported crates | per-package editions now; one `cargo fix --edition` commit later |
| Q3 | Licence: keep cowproof MIT-only or adopt `MIT OR Apache-2.0` workspace-wide | adopt dual (4.4); founder confirms since `design.md` says MIT |
| Q4 | When to archive the standalone portkit repository | after cowproof CI replays the moved portkit tests green and the first port packet (step 1) has shipped through the gate |
| Q5 | Does `pk doctor` belong at lane start or end | end; only check 4 is evidence (`doctor.rs` L69-80); start-of-lane preflight is cowproof's own `which pk` plus settings-file write |
| Q6 | Should held-out capture run on the verifier when the reference runtime is missing | no; report `held-out: skipped` in the capsule and let the director decide; never pass silently |
| Q7 | Status taxonomy: Node's `status`/`statusClass` or the Rust crates' string format | Node's; it is newer (2026-09-27), has 13 test cases, and the Rust crates' checks (`lanes-host` L399-412, L497-511) are two lines to change |
