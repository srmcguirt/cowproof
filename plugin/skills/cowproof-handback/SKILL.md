---
name: cowproof-handback
description: Judge a finished cowproof lane from its verdict and proof capsule, replay the capsule with `cowproof verify`, review the patch for flaws, apply it, gate once and commit. Use when a lane's `cowproof run` ends, or before any lane patch touches the real tree.
---

# cowproof-handback

A `proved` verdict says the builder's recorded checks reproduced in a sandbox the builder never controlled, and the mechanical gates passed. It does not say the patch is right. Your job at handback is the flaws a check cannot see and the questions the builder raised. Read cheaply: the verdict, the gate report, the diffstat and a targeted grep, not the whole diff, unless a grep flags something.

Below, `<lane>` is `<lanes-root>/<id>` (default lanes root `~/.cache/cowproof/lanes`) and `<repo>` is the repository you launched the lane against.

## 1. Read the verdict

`cowproof run` exits 0 proved, 2 refuted, 3 incomplete, 4 infrastructure, 5 timeout, 6 cost-cap, 7 stopped, 8 escalation-limit (none of these four is proved), 1 failed before a verdict, 130 interrupted. The files it leaves in `<lane>/control/`:

```sh
cat <lane>/control/verdict.json
cat <lane>/control/capsule/gates.json
```

- `verdict.json`: `verdict`, `exitCode`, `reasons`, `unrun` (declared checks never run), `failedChecks`, `heldOutFailed`, `diverged` (checks whose replay disagreed with the builder's record), `failedGates`.
- `gates.json`: five gates, each with `name`, `passed`, `warned` and `evidence`: `ownership`, `append_only`, `protected_paths`, `held_out`, `flaws`.
- `run.json`: how the builder ended (`finished`, `failed`, `stopped`, `escalation-limit`), turns and an estimated cost. The cost is an estimate.
- `capsule/capsule.json`: base commit, builder model, `unsandboxed`, `local_replay_only`, dependency cache key and fetch outcome. `capsule/checks/<id>.json` holds the builder's last run of each check: exit code (-1 when it had none) and `end` (exited, signalled, timed out, not run), attempts, duration and the SHA-256 and length of its output (never the output), and a `verifier` object with the verifier's own run of it (same fields, no attempts; absent from older capsules). When the verifier's output hash differs from the builder's, `cowproof run` and `cowproof verify` print a note; it is not a failure. `capsule/packets/` holds every packet version (`v1.md`, one more per redirect) with `versions.json`. `base_remote` names the remote-tracking ref that held the base commit.
- `capsule/escalations.jsonl`: the builder's questions and your rulings, when there were any.

Read the verdicts this way:

- `proved`: continue.
- `refuted`: a check failed, a replay diverged, or a gate failed. The reasons name it. Rerun with the failing output in the packet, or fix by hand if it is a few lines.
- `incomplete`: a declared check was never run through `run_check`. The lane is not done.
- `infrastructure`: the proof could not run (a failed dependency fetch, a tampered or unreadable capsule, a gate that could not start). This is never a verdict on the patch. Fix the cause and replay with `cowproof verify`.
- A lane that was `stopped`, `failed` or reached `escalation-limit` has `run.json` and `lane.patch` but no verdict. Its work is kept in `<lane>/clone`.

## 2. Replay the capsule

Replay is independent of the run: it rebuilds the base commit from the repository, applies the capsule's patches and reruns every recorded check, then every held-out check, in the verifier sandbox.

```sh
cowproof verify <lane>/control/capsule --repo <repo>
```

Exit 0 reproduced. Exit 2 diverged, with the check named. Exit 4 infrastructure: the capsule was refused as tampered, unsandboxed or unreadable, or the replay or its dependency fetch could not run. A capsule edited after it was sealed is refused (exit 4). The seal catches edits and damage, not someone who rewrites both `capsule.json` and `capsule.sha256`.

Use `--repo` on a fresh clone to replay on another machine.

## 3. Review the patch for flaws

```sh
git apply --stat <lane>/control/lane.patch
```

Then grep the patch for each of these. Every one is a way a lane reaches green without being right, so any hit is a finding:

- Stubs reported as done: placeholder return values, empty bodies, `todo!()`, `unimplemented!()`.
- Weakened tests: assertions deleted or loosened, `#[ignore]` added, thresholds raised, tests that accept either outcome, tests that build a value and read it back instead of calling the real function.
- Test-only branches in production code: `#[cfg(test)]` helpers called from non-test code (green under `cargo test`, broken in a release build), special cases that exist only for a test.
- A check changed to fit the code: edits to the packet's check commands, build scripts or CI configuration in the same patch as the change they judge.
- Security boundaries weakened to get a test through: a permission broadened, a validation removed, a sandbox or allowlist loosened.
- Secrets in the patch, or a secret passed where a test needs a fake.
- The handoff claims something the tree does not show: a check "passed" that the capsule does not list, work called done that sits under "deferred" or "follow-up".

Read the builder's handoff for its limits, unverified items and questions. If the gate report shows files outside `owns`, do not apply them.

Then choose:

- **Apply**: no hits, checks green, questions minor. Answer the questions in the commit message or the next packet.
- **Fix, then apply**: a mechanical flaw you can repair in a few lines.
- **Rerun**: red checks or real flaws. Write the next packet with the verbatim failing output and your rulings.
- **Escalate**: a design or product question a technical call cannot settle goes to the human.

## 4. Prove the proof once

Do one hand mutation. In a scratch copy of the patched tree, break the behavior the patch adds (flip a condition, return a constant) and confirm that a declared check goes red. Then restore the copy. A check that stays green under a broken implementation proves nothing, and the lane needs a stronger check.

## 5. Apply one patch at a time

```sh
git -C <repo> apply --check <lane>/control/lane.patch
git -C <repo> apply <lane>/control/lane.patch
```

Apply patches one at a time, each on top of the last. If the real tree moved since dispatch, try `git apply --3way` and resolve by hand, or rerun the lane on the new tree. Run the packet's checks in the real tree (the same commands the lane declared) and `git diff --check`.

## 6. Commit

Stage exactly the files the patch touches, taken from `git apply --numstat <lane>/control/lane.patch`, never everything. Check `git diff --cached --stat` before you commit. Say in the message what the lane did, what you ruled and the check results you saw.

## 7. Clean up

When you no longer need the lane, remove it: `<lane>` holds the clone, a private home, scratch and the control directory. Keep `<lane>/control/capsule` if you want a proof that can be replayed later.

## Checklist

- [ ] Verdict is `proved`, or the cause of `refuted`, `incomplete` or `infrastructure` is understood
- [ ] `cowproof verify` exits 0
- [ ] Every gate in `gates.json` passed, and any warning is understood
- [ ] No flaw from the list in the patch
- [ ] A hand mutation turned a declared check red
- [ ] The patch applies cleanly and the checks pass in the real tree
- [ ] Only the lane's files are staged
