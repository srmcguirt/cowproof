#!/usr/bin/env bash
# Claude Code PostToolUse hook (.claude/settings.json): check the one file an agent just wrote
# and hand the findings straight back to it (exit 2 shows stderr to the agent). Semgrep's
# project rules (.semgrep/cowproof.yml) for Rust, docs and workflows; shellcheck for shell.
# Silent when the file is clean or no checker applies. Clippy and the tests stay in CI and
# the pre-push hook: they take too long to run on every edit.
set -u
file=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))' 2>/dev/null)
[ -n "$file" ] && [ -f "$file" ] || exit 0
root=$(git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null) || exit 0
case "$file" in "$root"/*) ;; *) exit 0 ;; esac
rel=${file#"$root"/}
case "$rel" in */fixtures/*|fixtures/*|target/*) exit 0 ;; esac

out=""
case "$rel" in
  *.sh|scripts/*|plugin/scripts/*)
    command -v shellcheck >/dev/null || exit 0
    out=$(shellcheck -S warning -f gcc "$file" 2>&1) && exit 0
    ;;
  *.rs|*.md|*.yml|*.yaml)
    if command -v semgrep >/dev/null; then sg=(semgrep)
    elif command -v uvx >/dev/null; then sg=(uvx semgrep@1.182.1)
    else exit 0; fi
    # Against HEAD, so only what this session's uncommitted edits introduced is reported.
    out=$(cd "$root" && "${sg[@]}" scan --metrics=off --quiet --error --text --baseline-commit HEAD \
      --severity WARNING --severity ERROR --config .semgrep/ "$rel" 2>&1) && exit 0
    ;;
  *) exit 0 ;;
esac

{
  echo "Findings in $rel:"
  echo "$out"
  echo "Fix what your edit introduced. Earlier findings in the file are not part of your task unless it says so."
} >&2
exit 2
