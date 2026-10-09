#!/usr/bin/env python3
"""Describes itself, then never answers."""
import json, sys, time
if "--portkit-spec" in sys.argv:
    json.dump({"name": "hangs", "description": "Never returns.",
               "input_schema": {"type": "object"}}, sys.stdout)
    sys.exit(0)
time.sleep(600)
