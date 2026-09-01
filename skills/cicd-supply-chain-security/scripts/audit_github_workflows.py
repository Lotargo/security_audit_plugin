#!/usr/bin/env python3
import sys
import os
import re

INJECTION_PATTERN = r'run:\s*.*?\$\{\{\s*github\.event\.(issue|pull_request|comment)\.(title|body|head\.ref)'
UNPINNED_ACTION = r'uses:\s*[\w\-\.\/]+@(v[0-9]+|main|master)'

def audit_workflow(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()

    if re.search(INJECTION_PATTERN, content):
        findings.append("CRITICAL: Potential GitHub Actions script injection via untrusted github.event property")

    for line_idx, line in enumerate(content.splitlines(), 1):
        if re.search(UNPINNED_ACTION, line):
            findings.append(f"MEDIUM: Line {line_idx} uses mutable tag instead of commit SHA ({line.strip()})")

    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else ".github/workflows"
    all_findings = []
    if os.path.exists(target):
        for root, _, files in os.walk(target):
            for f in files:
                if f.endswith(('.yml', '.yaml')):
                    p = os.path.join(root, f)
                    issues = audit_workflow(p)
                    if issues:
                        all_findings.append({"file": p, "issues": issues})
    import json
    print(json.dumps(all_findings, indent=2))
