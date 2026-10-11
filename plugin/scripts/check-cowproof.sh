#!/bin/sh
# SessionStart hook: tell the session when the cowproof binary is missing or older
# than this plugin's version. It always exits 0 and prints nothing when all is well.

INSTALL='cargo install --git https://github.com/srmcguirt/cowproof cowproof-cli'

plugin_json="${CLAUDE_PLUGIN_ROOT:-.}/.claude-plugin/plugin.json"
if [ ! -f "$plugin_json" ]; then
  exit 0
fi

required=$(grep '"version"' "$plugin_json" | head -1 | sed 's/.*"\([0-9][0-9.]*\)".*/\1/')
case "$required" in
  *[!0-9.]* | '' | .* | *..* | *.) exit 0 ;;
esac

if ! command -v cowproof >/dev/null 2>&1; then
  printf 'cowproof is not installed. Install it with:\n%s\n' "$INSTALL"
  exit 0
fi

# A binary that reports no version (one built before `--version` existed) is left alone:
# the hook cannot tell it is old, so it stays quiet instead of warning on every session.
actual=$(cowproof --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -z "$actual" ]; then
  exit 0
fi

# Numeric, field by field: actual >= required.
r1=$(printf '%s' "$required" | cut -d. -f1)
r2=$(printf '%s' "$required" | cut -d. -f2)
r3=$(printf '%s' "$required" | cut -d. -f3)
a1=$(printf '%s' "$actual" | cut -d. -f1)
a2=$(printf '%s' "$actual" | cut -d. -f2)
a3=$(printf '%s' "$actual" | cut -d. -f3)
r2=${r2:-0}
r3=${r3:-0}

if [ "$a1" -gt "$r1" ] ||
  { [ "$a1" -eq "$r1" ] && [ "$a2" -gt "$r2" ]; } ||
  { [ "$a1" -eq "$r1" ] && [ "$a2" -eq "$r2" ] && [ "$a3" -ge "$r3" ]; }; then
  exit 0
fi

printf 'cowproof %s is older than the %s this plugin expects. Update it with:\n%s\n' "$actual" "$required" "$INSTALL"
exit 0
