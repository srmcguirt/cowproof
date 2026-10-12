#!/bin/sh
# The visible tests for slugify. Run them with: sh tests/test_slugify.sh
cd "$(dirname "$0")/.." || exit 1
. ./slugify.sh

fail=0
check() {
  got=$(slugify "$1")
  if [ "$got" != "$2" ]; then
    echo "FAIL: slugify '$1' gave '$got', wanted '$2'"
    fail=1
  fi
}

check "Hello World" "hello-world"
check "  Hello,   World!  " "hello-world"
check "Rust & Shell" "rust-shell"
check "a--b" "a-b"

exit "$fail"
