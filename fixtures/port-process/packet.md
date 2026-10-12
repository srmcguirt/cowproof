# Port the greeting script to Rust

<!-- lane {"id":"port-1","kind":"port","class":"light","owns":["tools/**",".portkit/plugins.toml","ports/greet/cases.jsonl","ports/greet/fixtures/**"],"allow":["mkdir*","rustc*","cowproof pk port*"],"maxCostUsd":1.0,"timeoutMin":15,"port":{"lang":"shell","adapter":"process","reference":{"cmd":"sh \"$PORTKIT_SRC/reference/greet.sh\""},"cases":"ports/greet/cases.jsonl","fixtures":"ports/greet/fixtures","tools":["greet"],"parity":{"path_roots":["$ROOT","$HOME","$TMP"]}},"checks":[{"id":"build","command":"mkdir -p target && rustc --edition 2021 tools/greet.rs -o target/greet"}]} -->

## Task

`reference/greet.sh` is a POSIX shell script: `greet.sh NAMEFILE` reads the name in `NAMEFILE`, asks `git rev-parse --short HEAD` for a revision, writes `greeting.txt`, removes `stale.txt`, prints where it wrote, and exits 2 with a message on stderr when `NAMEFILE` does not exist. `ports/greet/fixtures/` holds exactly what the script did on three cases: its exit status, stdout, stderr, the files it left (with hashes), the files it deleted, and the calls it made to `git`.

Port it to one Rust program, `tools/greet.rs`, that takes the same arguments and does the same things in its working directory (a standalone executable, no crates). It runs under `pk port wrap`, which materialises each case's files, puts a scripted `git` first on `PATH`, and records what the program did; the program must call `git` through `PATH` and must not use the network. Register it in `.portkit/plugins.toml` as one `[[plugin]]` entry whose `command` is the `cowproof` that is running this lane and whose `args` are `pk port wrap --tool greet --exe target/greet --path-root $ROOT --path-root $HOME --path-root $TMP`. The port must answer every fixture exactly: parity is checked with epsilon 0.

## Checks

- `mkdir -p target && rustc --edition 2021 tools/greet.rs -o target/greet`
