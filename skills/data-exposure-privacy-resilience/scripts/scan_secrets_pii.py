#!/usr/bin/env python3
import sys
import os
import re

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----', "Private Key Header"),
    (r'(?i)(api[_-]?key|secret|password)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "Potential Hardcoded Secret"),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "Potential Credit Card PAN")
]

def scan_file(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()
        for idx, line in enumerate(lines, 1):
            for pattern, name in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": idx,
                        "type": name,
                        "snippet": line.strip()[:100]
                    })
    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = []
    for root, _, files in os.walk(target):
        for f in files:
            if not f.endswith(('.png', '.jpg', '.pdf', '.bin', '.exe', '.lock')):
                results.extend(scan_file(os.path.join(root, f)))
    import json
    print(json.dumps(results, indent=2))
