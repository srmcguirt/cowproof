---
name: cowproof-escalate
description: Watch running cowproof lanes for escalations and rule on them with an answer, a redirect, a reassign or a stop, or send a running lane a note. Use while lanes are running, or when a lane is parked waiting on the director.
---

# cowproof-escalate

A builder asks the director when it is stuck or needs a design ruling, and cowproof forces an escalation when a lane looks like it is thrashing. You watch, rule, and the lane carries on. A lane left parked waits for you, so keep a watch running whenever lanes are.

Pass the same `--lanes-root` to `watch`, `rule` and `note` that you gave `cowproof run`. The default is `~/.cache/cowproof/lanes`.

## Watch

Use the `lanes` tool to list every lane with its state, its parked blocking escalation and its pending notes. The tool returns the most recent state; no waiting or following.

```sh
cowproof watch
```

The shell equivalent is a table of lanes: `LANE`, `STATE`, `PARKED`, `AGE`, `NOTES` and `LAST EVENT`. `STATE` is `running` until the lane ends, then the lane's final status from `run.json` (`finished`, `failed`, `stopped`, `escalation-limit`, `interrupted`). `PARKED` shows the open blocking escalation, and marks it `past cache` once it has waited longer than `--cache-ttl` (default `1h`), so rule before then when you can. `NOTES` counts notes the builder has not read yet.

Use the `events` tool (with the cursor it returns) to follow escalation-queue events. It never waits: you poll it, passing back the cursor from the previous call.

```sh
cowproof watch --events --follow
```

The shell equivalent starts a feed of events, one line per event: `<UTC time> <lane> <kind> <summary>`, kept running. The kinds are:

- `asked`: a new escalation, with its id and whether it is `blocking` or `non-blocking`
- `ruled`: you ruled on it
- `delivered`: the ruling reached the builder (`fresh` session or `resumed`)
- `resume-fallback`: the parked session could not be resumed, so a fresh one started with a summary
- `rejected`: the queue refused something, with the reason
- `note` and `note-delivered`
- `lane-escalation-limit`: the lane ended because it used up its escalations

The `events` tool returns summaries (ids and sizes), not what a builder wrote. To read the question in an escalation, open `<lanes-root>/<lane>/control/escalations.jsonl` and find the `asked` line with that id. Its `ask` object has `kind` (`blocker`, `design`, `scope` or `environment`), `question`, `tried`, `options` (each with `id`, `summary`, `cost`), `recommend` and `blocking`. Its `origin` says whether the builder asked or cowproof forced it. Escalation ids look like `<lane-id>:E1`.

Why a lane escalates:

- The builder asks. A non-blocking ask lets it keep working. It reads your answer on its next `check_ruling`.
- A blocking ask parks the lane. The runner ends the builder's session and resumes it with your ruling.
- cowproof forces a blocking escalation when the same check fails twice with no pass between, when the lane's estimated cost reaches 40% of `--cost-cap-usd`, or when its turns reach `--turn-budget`.
- A lane gets at most 3 escalations, forced ones and resume fallbacks included, and a blocking escalation that waits 30 minutes for a ruling expires. Either ends the lane as `escalation-limit`, with its work kept.

## Rule

Use the `rule` tool to rule on an open escalation of a running lane. Exactly one of `answer`, `redirect`, `reassign` or `stop` per ruling. The tool reaches the lane through its control socket, so it works only while `cowproof run` is still going; against a lane that has ended it fails.

The shell equivalent is:

```sh
cowproof rule <lane-id> <escalation-id> --answer "<text>"
```

**Answer.** Text for the builder. A parked builder's session is resumed with your text as the director's ruling. If the session cannot be resumed, a fresh session starts from the packet plus a summary of the question. A non-blocking ask gets the text on its next `check_ruling`. Name the choice and the reason, not only "yes".

**Redirect.**

```sh
cowproof rule <lane-id> <escalation-id> --redirect <packet.md>
```

Replace the packet. The new file must carry the same lane `id` and lint clean. A fresh session starts on the new packet in the same clone, so the builder's earlier work is still there. The path is resolved from the directory `cowproof run` was started in, so give an absolute path. A packet that fails those checks ends the lane as `failed`, with the ruling recorded and undelivered.

**Reassign.**

```sh
cowproof rule <lane-id> <escalation-id> --reassign
cowproof rule <lane-id> <escalation-id> --reassign --model <name>
```

Hand the lane to a stronger model. Without `--model` it climbs the built-in ladder `haiku`, `sonnet`, `opus`. A fresh session on the new model takes over the same clone, told what the question and the attempts were. This resets the lane's cost and turn counters and its failed-check tallies, but not its escalation count. From `opus`, or from a model off the ladder, `--reassign` alone is refused and the lane ends `failed`, so name a model with `--model`.

**Stop.**

```sh
cowproof rule <lane-id> <escalation-id> --stop
```

End the lane. Its status is `stopped`, its work stays in `<lanes-root>/<lane-id>/clone`, and `control/lane.patch` is written. Nothing is proved: there is no verdict or capsule.

## Notes

Use the `note` tool to send a note to a running lane: guidance the builder reads on its next `check_ruling`, with no escalation opened. The text must not be empty and may be up to 4000 bytes. A lane that has ended refuses it.

The shell equivalent is:

```sh
cowproof note <lane-id> "<text>"
```

## How to rule

- Rule on technical calls yourself. The builder's `recommend` is its best guess, not an instruction. Take it when it is right, and say so.
- Bring product, design and anything with a cost to the human, with the builder's options and your recommendation.
- Prefer a short answer that unblocks over a perfect one that arrives after the lane expires.
- If two lanes ask the same thing, answer both the same way.
- A lane that keeps escalating on the same check is usually a packet problem. Redirect with a clearer packet instead of answering again.
- Do not answer a question from a patch you have not read.
