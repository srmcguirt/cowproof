#!/usr/bin/env python3
"""Fail if the committed fixtures no longer match the reference implementation.

Compares only the semantic content — `tool`, `id`, `input`, `expected` — so the
`captured_at` timestamp, which changes on every capture, does not read as drift.

    python3 scripts/check_fixtures_fresh.py fixtures/ /tmp/fresh/
"""

import json
import pathlib
import sys

SEMANTIC = ("tool", "id", "input", "expected")


def load(root: pathlib.Path) -> dict:
    fixtures = {}
    for path in sorted(root.rglob("*.json")):
        data = json.loads(path.read_text())
        key = (data.get("tool"), data.get("id"))
        fixtures[key] = {field: data.get(field) for field in SEMANTIC}
    return fixtures


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <committed-dir> <fresh-dir>", file=sys.stderr)
        return 2

    committed, fresh = (pathlib.Path(a) for a in sys.argv[1:3])
    if not fresh.exists():
        print(f"error: {fresh} does not exist — did capture run?", file=sys.stderr)
        return 2

    old, new = load(committed), load(fresh)
    problems = []

    for key in sorted(new.keys() - old.keys()):
        problems.append(f"  {key[0]}/{key[1]}: produced by the reference but not committed")
    for key in sorted(old.keys() - new.keys()):
        problems.append(f"  {key[0]}/{key[1]}: committed but no longer produced")
    for key in sorted(old.keys() & new.keys()):
        if old[key] != new[key]:
            problems.append(f"  {key[0]}/{key[1]}: the reference now returns something different")

    if problems:
        print("Committed fixtures do not match what the reference implementation produces:")
        print("\n".join(problems))
        print("\nRun 'just capture' and commit the result if the change is intentional.")
        return 1

    print(f"{len(old)} fixtures match the reference implementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
