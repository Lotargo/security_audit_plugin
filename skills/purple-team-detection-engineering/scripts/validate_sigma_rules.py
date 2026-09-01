#!/usr/bin/env python3
import sys
import os

REQUIRED_FIELDS = ["title", "id", "status", "description", "logsource", "detection", "level"]

def validate_sigma(filepath):
    errors = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    for field in REQUIRED_FIELDS:
        if f"{field}:" not in content:
            errors.append(f"Missing required field: {field}")
    return errors

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = {}
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith(('.yml', '.yaml')) and 'sigma' in f.lower():
                path = os.path.join(root, f)
                errs = validate_sigma(path)
                results[path] = "VALID" if not errs else errs
    import json
    print(json.dumps(results, indent=2))
