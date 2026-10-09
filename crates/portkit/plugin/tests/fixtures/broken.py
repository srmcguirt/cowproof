#!/usr/bin/env python3
"""Describes itself, then fails. The failure path has to be legible."""
import json, sys
if "--portkit-spec" in sys.argv:
    json.dump({"name": "broken", "description": "Always fails.",
               "input_schema": {"type": "object"}}, sys.stdout)
    sys.exit(0)
print("the backend was unreachable", file=sys.stderr)
sys.exit(3)
