#!/bin/sh
# The reference: portkit's contract. One request on stdin, one JSON result on stdout.
# PORTKIT_TOOL names the tool (`pk port capture` sets it).
text=$(sed -n 's/.*"text":"\([^"]*\)".*/\1/p')
upper=$(printf '%s' "$text" | tr 'a-z' 'A-Z')
case "$PORTKIT_TOOL" in
  shout) printf '{"result":"%s!"}\n' "$upper" ;;
  *) printf '{"result":"%s"}\n' "$upper" ;;
esac
