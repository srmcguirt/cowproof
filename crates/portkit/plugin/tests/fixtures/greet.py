#!/usr/bin/env python3
"""A well-behaved plugin: describes itself, then answers one request."""
import json, sys

SPEC = {
    "name": "greet",
    "description": "Greet someone by name.",
    "input_schema": {
        "type": "object",
        "properties": {"who": {"type": "string"}},
        "required": ["who"],
        "additionalProperties": False,
    },
}

if "--portkit-spec" in sys.argv:
    json.dump(SPEC, sys.stdout)
    sys.exit(0)

req = json.load(sys.stdin)
who = req.get("input", {}).get("who", "world")
json.dump({"greeting": f"hello {who}"}, sys.stdout)
