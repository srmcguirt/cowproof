#!/usr/bin/env python3
"""Describes itself, then never answers."""
import json, os, sys, time
if "--portkit-spec" in sys.argv:
    json.dump({"name": "hangs", "description": "Never returns.",
               "input_schema": {"type": "object"}}, sys.stdout)
    sys.exit(0)
# An optional first argument names a file to receive this process's pid, so a
# test can check the process is gone after the timeout.
if len(sys.argv) > 1:
    with open(sys.argv[1], "w") as f:
        f.write(str(os.getpid()))
time.sleep(600)
