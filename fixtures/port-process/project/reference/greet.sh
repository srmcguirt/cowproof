#!/bin/sh
# greet.sh NAMEFILE: say hello to the name in NAMEFILE.
#
# Reads the file, asks git which revision it is run in, writes greeting.txt, removes
# stale.txt, and prints where it wrote. Exits 2 when NAMEFILE does not exist.
set -eu
if [ ! -f "${1:-}" ]; then
  echo "no such file: ${1:-}" >&2
  exit 2
fi
name=$(cat "$1")
rev=$(git rev-parse --short HEAD)
printf 'hello %s\nrev %s\n' "$name" "$rev" > greeting.txt
rm -f stale.txt
echo "wrote $(pwd)/greeting.txt"
