#!/usr/bin/env python3
"""Answers with something that is not JSON."""
import json, sys
if "--portkit-spec" in sys.argv:
    json.dump({"name": "garbage", "description": "Returns prose.",
               "input_schema": {"type": "object"}}, sys.stdout)
    sys.exit(0)
print("Sure! Here is your result:")
