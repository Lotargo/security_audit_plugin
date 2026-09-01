#!/usr/bin/env python3
import sys
import re
import os

PATTERNS = [
    (r'(db\.query|cursor\.execute)\s*\(\s*f?["\'].*?%s|(\+.*?req\.)', "Potential SQL Injection"),
    (r'(child_process\.exec|os\.system|subprocess\.Popen)\s*\(\s*f?["\'].*?(\+|req\.)', "Potential Command Injection"),
    (r'render_template_string\s*\(\s*.*?(request|\+)', "Potential SSTI"),
    (r'pickle\.loads\s*\(', "Insecure Deserialization (pickle)")
]

def scan_file(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()
        for idx, line in enumerate(lines, 1):
            for pattern, name in PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": idx,
                        "type": name,
                        "snippet": line.strip()
                    })
    return findings

if __name__ == '__main__':
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    all_findings = []
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(('.ts', '.js', '.py', '.java', '.go')):
                all_findings.extend(scan_file(os.path.join(root, file)))
    import json
    print(json.dumps(all_findings, indent=2))
