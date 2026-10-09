<!-- lane {"id": "lane-widget-cache", "runner": "codex", "class": "light", "owns": ["tools/widget/cache.mjs", "tools/widget/cache.test.mjs", "tools/widget/evict.mjs", "tools/report/*.test.mjs", "docs/handoffs/handoff-lane-widget-cache.md"], "wide": false, "timeoutMin": 60} -->

# Lane: add an eviction policy to the widget cache

Synthetic fixture for packet lint. The owned files and their folders do not exist in this repository, and the checks call commands outside the read-only base set without an `allow` list.

## Checks

1. `node --test tools/widget/cache.test.mjs tools/report/summary.test.mjs`
2. `node tools/widget/evict.mjs --dry-run --scratch-parent /tmp/cowproof-$LANE_PORT_BASE`
3. `cargo test --locked --offline --manifest-path tools/widget/Cargo.toml`
4. `git diff --check`

## Handoff

Write `docs/handoffs/handoff-lane-widget-cache.md`: files changed, each check with its result, and questions with a recommended answer.
