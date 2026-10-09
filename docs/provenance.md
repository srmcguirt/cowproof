# Provenance

Where cowproof's code comes from and under what authority it is released.

## Everydom lane tooling: relicensed under MIT

On 2026-10-09 Shane McGuirt, founder of Everydom and owner of the code below, authorized it in these words:

> "I authorize relicensing the Everydom lane code under MIT"

Covered, as the lane tooling of the Everydom platform:

| Source | What |
| --- | --- |
| `Everydom/lanes` | the `lanes-core`, `lanes-cli`, `lanes-host`, `lanes-lint`, `lanes-plan` and `lanes-report` crates, including `rules/flaws.toml`, their tests and fixtures, and the tool documentation |
| `Everydom/platform`, `scripts/lanes/` | the lane runner (`run-lane.mjs`, `run-remote.mjs`, `questions.mjs`, `health.mjs`, `repro-concurrency.mjs`), their tests and README |
| `Everydom/platform`, lane skills | `lane-dispatch`, `lane-handback`, `lane-escalate` and the `lane-wave` workflow |

Not covered: anything else in those repositories, including product code, plans, handoffs, packets written for Everydom work, host inventories and git history. Code is copied in, never its history, and every copy passes the scrub check before it is pushed.

## portkit

portkit (`srmcguirt/portkit`) is the founder's own project, published under MIT or Apache-2.0 at the user's option. Its code joins cowproof under MIT, the option portkit already offers. Its copyright notices are kept.
