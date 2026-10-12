# Fly.io Sprites as a remote work area for cowproof lanes

Research note, read on 2026-10-11. Research only: nothing was created, installed or called on any Fly account. Everything below comes from public pages, cited by number to the sources list at the end. "(inferred)" marks my reasoning, "not documented" marks a gap. The docs are thin on exactly the points cowproof cares about (exec framing, nested sandboxes, disconnect behavior), so several answers are experiments, not facts.

## 1. What a Sprite is

**Isolation.** The overview calls a Sprite a "persistent, hardware-isolated Linux environment" on a dedicated microVM [1]. The design post says "Sprites are Linux virtual machines. You get root", that they run on Fly Machines today (OCI containers repackaged as KVM microVMs), and that user code sits in an inner container: "We've slid a container between you and the kernel" [2]. Neither official page I read names Firecracker; a secondary summary does [3]. What is shared between tenants on a host is not documented.

**Persistence.** A 100 GB ext4 disk on NVMe, durable in object storage [1][2][4]. Files, packages and git repos survive; processes, memory and open TCP connections do not [4]. Checkpoints are copy-on-write and capture the disk only, not memory or processes. Restore is asynchronous and destructive, ends active sessions, and the last five checkpoints are mounted read-only at `/.sprite/checkpoints/` [5]. Timing: restore "about one second" in the design post [2], "three seconds" in another post [6]. Whether a checkpoint can seed a different sprite is not documented.

**Lifecycle.** Active while a command runs, a session produces output, a TCP connection is open to its URL or a service is handling traffic. After about 30 seconds idle it goes warm (VM suspended, memory kept), then cold (VM stopped). Wake is 100 to 500 ms warm and 1 to 2 s cold [4]. Create took 1.0 s in the launch post's example [7]. Destroy is `sprite destroy` [8].

**Limits.** The sources disagree. The lifecycle page says 8 vCPUs (fixed) and 100 GB, with memory "assigned per Sprite" and autoscaled [4]. A release note says sprites start with 2 GB and autoscale to 16 GB [9]. The JS SDK takes `cpus` and `ramMB` at create time [10]. Org-wide `running_limit` and `warm_limit` exist, with no values published [11]. So 2 vCPU and 4 GB may be configurable or may not.

**Regions.** Not stated in the docs. A Fly staff reply on 2026-01-09 said sprites are created near the caller and a region cannot be chosen [12]; the JS SDK example passes `region: 'ord'` [10]. Unresolved.

## 2. How you drive one

**API and auth.** REST at `api.sprites.dev/v1` with a bearer token [13]. `/v1/sprites/{name}/exec` is a WebSocket that streams stdin, stdout and stderr and supports detachable sessions [14]; I could not read the framing. Tokens come from the account page or `sprite org auth` [15]. A 2026-02-02 release note says tokens can carry a maximum sprite count, a required name prefix, label-based access control and an expiry [9]. The CLI auth page documents none of that [15]. The Go and JS SDKs mint a sprite token by exchanging a Fly credential [10][16]. A token is org-scoped; a name prefix could narrow it to one sprite name (inferred); per-sprite tokens are not documented.

**Commands.** `sprite exec` runs one command and returns output, with `--dir`, `--tty`, `--env` and `--file source:dest` (upload before running) [8][17]. TTY sessions detach and reattach [17]. The SDKs offer `exec.Cmd`-style streaming with stdin pipes [16]. Non-TTY disconnect behavior (does the command die when the WebSocket closes) is not documented. A Tasks API holds a sprite active, one hour maximum per task, refreshed by heartbeat [18].

**Files.** `--file` on exec and `sprite file pull` [8][19]. The REST filesystem pages I could read show only `chmod` [20].

## 3. Networking

**Egress.** Open by default. A per-sprite network policy is a DNS-based allowlist, set from outside through the API and read-only inside at `/.sprite/policy/network.json`. Raw IPs are blocked unless resolved from an allowed domain, private IPs are always blocked, and a deny-all example returns `REFUSED` to DNS [21][22][23]. Rules are `allow` or `deny` per domain pattern, `*` matches all [24]. The `include: defaults` preset adds GitHub, npm, PyPI, Docker Hub and AI APIs, so cowproof would list domains explicitly (crates.io hosts for the dependency prefetch, D26).

**Ingress.** Every sprite has `https://<name>-<org-id>.sprites.app/`, private to org members unless set public [21].

**Reaching back to the director.** Nothing in the docs gives a sprite a route to a socket on the director's machine. `sprite proxy` maps a sprite port to the caller, not the reverse [21]. Private IPs are blocked by policy [21], and a forum poster found sprites are not on Fly's 6PN network (their inference, not confirmed) [25]. What is documented is the other direction: `sprite proxy -W :22` is described as tunneling like SSH, and `--ssh` emulates a session over stdio [8][21]. If sshd runs in the sprite, an ordinary `ssh -R` forward would ride that director-initiated tunnel (inferred). The director opens no public port, the same property D24 relies on today. Unconfirmed: that the proxy carries `-R` Unix-socket forwards, and that sshd survives a pause (services restart after cold wake [4], so it should run as a service).

## 4. Inside the sprite

Code runs as root in the VM, inside an inner container [2]; a `sprite` user and `sudo` appear in the maintenance guide [26]. Ubuntu 25.10 [26]. Whether bwrap or user namespaces work in the inner container is not documented; nested containers and nested virtualization are not covered in any page I read [2][27]. Experiment 1 settles it.

If bwrap does not work, the sprite is the sandbox, and cowproof's policy maps like this:
- *Deny the control dir.* Mostly moot: D27 already keeps the queue, proof, held-out checks and key on the director. The sprite holds only the lane clone.
- *No network except the bridge.* A deny-all network policy set by the director through the API (the builder, even as root, cannot change it [27]); loopback to the bridge is not egress (inferred).
- *Read-only home pieces.* Run the builder as a non-root user created by `cowproof host setup`, with the lane directory the only writable tree (inferred).
- *Cross-lane isolation.* One fresh sprite per lane, or a restore to a clean checkpoint, so nothing from an earlier lane is present.

## 5. Cost

Official pricing [28]: CPU $0.0385 per CPU-hour, memory $0.021875 per GB-hour, hot storage $0.000683 per GB-hour (about $0.50 per GB-month, billed while awake), cold storage $0.000027 per GB-hour (about $0.02 per GB-month). "No plans and no tiers, and nothing charged per Sprite." A dormant sprite incurs no compute charge. Billing is by use, not allocation: CPU is cumulative CPU time from `cpu.stat`, memory is actual usage [29]. Per-second granularity and a free allowance are not stated. This contradicts the January release notes, which describe four plans and older rates ($0.07 per vCPU-hour) [9], and a learn page that mentions a $100 plan [29]. I use the pricing page.

One lane, upper bound (2 vCPU fully busy, 4 GB held, 20 minutes = 0.3333 h):
- CPU: 2 x 0.3333 x $0.0385 = $0.0257
- Memory: 4 x 0.3333 x $0.021875 = $0.0292
- Hot storage while running: 5 GB x 0.3333 x $0.000683 = $0.0011
- Total: about $0.056 per lane. A build that is not saturating both CPUs costs less.

Cache kept between lanes: 5 GB x $0.000027 x 730 h = about $0.10 per month while cold. Model tokens will dominate lane cost; compute is a few cents. The worked example on the learn page (four hours at 30% of 2 CPUs and 1.5 GB = $0.23) is consistent with these rates [29].

## 6. Fit with cowproof

Best candidate, "same design, Sprite as an SSH host" (inferred): sshd as a sprite service, `ssh -o ProxyCommand='sprite proxy -s <name> -W :22'`, and the existing control master and `-R` forwards. Then each piece carries over unchanged:
- *prepare* (git bundle on stdin), *check*, *patch*, *stderr*, *doctor*, *cleanup*: plain commands over the ssh channel.
- *builder and lifeline*: the stdin lifeline is ssh's, not Sprites'. It works if the proxy relays channel close, which Experiment 3 tests.
- *forced-command key*: `authorized_keys` inside the sprite, installed by the director through `exec --file` or by the owner. Because the director could also run commands directly with its API token, the forced key narrows ssh only, not the token (see section 7).
- *proxy.sock and runner.sock*: `-R` over the tunnel. The one assumption that carries the design.
- *prerequisites*: the director needs the `sprite` CLI and a token; the sprite needs `cowproof` (same version), `claude`, `git`, and sshd, all baked into a checkpoint.

Fallback, "new transport": an exec-API adapter in `remote.rs` replacing ssh. It has no equivalent of `-R`, so the two sockets would need a multiplexed relay over the exec stdio, a protocol cowproof does not have today. I would not build this unless the ssh route fails.

**What checkpoint and restore add.** A warm toolchain per repo (rustup, cargo registry, built `target/`) kept as a known-good checkpoint. After each lane, `sprite restore` replaces `cleanup`, resets any poisoned cache, and costs seconds. Limits: restore is destructive and per sprite, so parallel lanes need one sprite each, and sharing one checkpoint across sprites is not documented.

## 7. Risks and unknowns

- **Credentials.** The real key stays on the director; the sprite sees only the placeholder key. Prompts, code and tool output do cross Fly's API proxy and sit on Fly's disk and object storage (inferred from the architecture [2]). The API token is org-wide unless restricted [9]; a leaked token can exec in, read and spend on every matching sprite. Use a dedicated org, a name prefix, a sprite-count cap and an expiry.
- **Residency.** Region choice is contradictory and no residency commitment is documented [10][12].
- **Lock-in.** Low if the ssh route holds: the host entry in `hosts.json` is the only Sprite-specific part.
- **Maturity.** Docs launched 2025-12-23 [9], announced January 2026 [7]. No general-availability statement and no Sprites-specific SLA found. The Sprites Block Device is in private beta, and a status aggregator lists Sprites incidents in September 2026 (search snippets only, not read) [30].
- **Terms.** No AI-agent clause in the AUP; it bans security testing, cryptomining and, by catch-all, anything harmful, with termination at Fly's discretion [31]. A Sprites-specific terms page was not retrieved. A search snippet quotes the general terms as internal use only; a forum question on reselling is unanswered.

## 8. Recommendation

Prototype first. The design looks sound if three things hold (bwrap or a deny-all policy as the sandbox, `-R` through the proxy, a lifeline that ends the builder), and none can be confirmed from the docs. Do not adopt before all three pass.

**Experiment 1: sandbox and resources** (cents). In a new dedicated org:
```
sprite org auth
sprite create cowproof-probe-1
sprite exec -s cowproof-probe-1 bash -lc 'id; nproc; free -m; df -h /; sudo apt-get install -y bubblewrap openssh-server; bwrap --unshare-all --ro-bind / / --dev /dev --proc /proc true && echo BWRAP_OK; unshare -Ur true && echo USERNS_OK'
```
Observe BWRAP_OK, USERNS_OK, the real CPU and memory, whether `-s` is the right flag (`sprite exec --help`), and whether the sprite can be created at 2 vCPU and 4 GB.

**Experiment 2: reverse socket and egress** (cents). Start sshd as a service, install a public key, then from the director:
```
ssh -o ProxyCommand='sprite proxy -s cowproof-probe-1 -W :22' -R /tmp/p.sock:/tmp/local.sock sprite@probe
curl -X POST -H "Authorization: Bearer $SPRITE_TOKEN" -d '{"rules":[{"action":"deny","domain":"*"}]}' https://api.sprites.dev/v1/sprites/cowproof-probe-1/policy/network
```
With a `socat` listener on `/tmp/local.sock` on the director, run `curl --unix-socket /tmp/p.sock http://x/` in the sprite. Observe: the forward works; it still works after the deny-all policy; `curl https://example.com` and a raw IP fail; the forward survives a 10 minute idle.

**Experiment 3: disconnect, checkpoint, cost** (cents). Start `sleep 600; touch /tmp/alive` over the ssh route, `kill -9` the director's ssh, and check later whether `/tmp/alive` appeared (the lifeline needs it to be ended; observe what actually happens). Then `time sprite checkpoint create --comment warm`, build cowproof with `cargo build --release`, `time sprite restore v0`, and compare `cat /sys/fs/cgroup/cpu.stat` before and after against the billed amount on the account page.

**Founder approvals.** None of this can start without him: a new Fly organization for Sprites (not any existing one); his own sign-in and any payment method (I do not type either); a stated spend ceiling, since a cap is not documented; a restricted API token (prefix, sprite-count cap, expiry); and his decision to send private repository code and prompts to Fly, since the Sprites terms were not read.

## 9. Prototype scorecard

The experiments in section 8 cost cents, and they are worth running only if their results are comparable and decide something. Record the numbers below, decide the go or no-go rule before starting, and run each timing at least three times with the time of day noted, since the platform is shared.

| Question | How to measure | Compare against |
|---|---|---|
| Create and wake time | `time sprite create`; a command after the sprite has gone idle, once warm and once cold | The docs: about 1 s to create, 100 to 500 ms warm wake, 1 to 2 s cold wake [4] |
| Real CPU and memory | `nproc`, `free -m`, and `/sys/fs/cgroup/memory.peak` read after a build | The docs: 8 vCPU [4]; memory starts at 2 GB and grows to 16 GB on demand [9] |
| Build speed | `time cargo build --release` of cowproof on a fresh sprite, again after it has gone cold, and again after a checkpoint restore | The same build, same commit, on the owner's Linux host |
| Checkpoint and restore | `time sprite checkpoint create` and `time sprite restore v0` | The docs: about 1 to 3 s [5] |
| Billed cost | CPU time from `/sys/fs/cgroup/cpu.stat` before and after, against the account page | The section 5 upper bound of about $0.056 per lane [28][29] |
| Idle behavior | After the lane, whether the sprite goes cold and billed compute stops; whether any open ssh or proxy connection keeps it awake | The docs: idle after about 30 s, then cold; open connections and running commands keep it active [4][18] |
| Reliability | How many of about 20 create, connect and exec cycles finish cleanly | The status incidents found in search results [30] |
| Reverse socket | Whether `-R` Unix-socket forwards through `sprite proxy` carry traffic, with a deny-all network policy set, and after 10 minutes idle | Experiment 2 |
| Lifeline | Whether killing the director's ssh ends the remote builder | Experiment 3, and the same test on the owner's host (one second, audit of 2026-10-11) |

**Go or no-go, fixed before the first run:**
- The sprite is not a remote work area at all if the reverse socket fails, or if the lifeline fails and cannot be fixed on the cowproof side. The design's key boundary depends on both.
- It is not used for compiling if the release build is more than twice as slow as on the owner's host, or if it is OOM-killed before memory grows. Lanes that mostly edit code and run quick checks could still use it, with builds kept on the owner's host.
- If billed cost per lane exceeds about three times the section 5 upper bound, or idle sprites keep billing compute, record why before deciding.
- Otherwise, the next step is a design decision to add a Sprite entry kind next to the SSH host, which the founder approves.

Who runs it: the founder, or the director once the founder has created a dedicated Fly organization, set a spend ceiling and put a restricted token in the Keychain. No worker lane runs it.

## Sources (all read 2026-10-11)

1. https://docs.fly.io/sprites
2. https://fly.io/blog/design-and-implementation/ and https://fly.io/blog/code-and-let-live/
3. https://devclass.com/2026/01/13/fly-io-introduces-sprites-lightweight-persistent-vms-to-isolate-agentic-ai/ (search summary only)
4. https://docs.fly.io/sprites/concepts/lifecycle.md
5. https://docs.fly.io/sprites/concepts/checkpoints.md
6. https://fly.io/sprites-blog/agent-swarms-on-sprites/
7. https://fly.io/blog/code-and-let-live/
8. https://docs.fly.io/sprites/cli/commands.md
9. https://fly.io/sprites/release-notes
10. https://github.com/superfly/sprites-js
11. https://docs.fly.io/sprites/api/sprites.md
12. https://community.fly.io/t/where-do-sprites-dev-sprites-live-as-in-which-fly-io-region-is-it/26775
13. https://docs.fly.io/sprites/api
14. https://sprites.dev/api (search result text only; exec page https://docs.fly.io/sprites/api/exec showed only session listing)
15. https://docs.fly.io/sprites/cli/authentication
16. https://pkg.go.dev/github.com/superfly/sprites-go
17. https://docs.fly.io/sprites/working-with-sprites.md
18. https://docs.fly.io/sprites/keeping-sprites-running.md
19. https://docs.fly.io/sprites/sprite-maintenance.md
20. https://docs.fly.io/sprites/api/filesystem.md
21. https://docs.fly.io/sprites/concepts/networking.md
22. https://fly.io/sprites-blog/running-untrusted-code/
23. https://fly.io/sprites/
24. https://docs.fly.io/sprites/api/network-policy
25. https://community.fly.io/t/sprites-tokenizer-secret-injecting-proxy-pattern-for-sandboxed-ai-agents/27054
26. https://docs.fly.io/sprites/sprite-maintenance.md
27. https://fly.io/sprites-blog/running-untrusted-code/
28. https://fly.io/pricing/
29. https://fly.io/learn/ai-sandbox-pricing/
30. https://statusgator.com/services/flyio/sprites and https://community.fly.io/t/are-sprites-still-under-active-development/28085 (search result titles only, not fetched)
31. https://fly.io/legal/acceptable-use-policy/
32. https://docs.fly.io/llms.txt (page index)
