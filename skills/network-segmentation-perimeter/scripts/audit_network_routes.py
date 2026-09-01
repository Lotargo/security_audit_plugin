#!/usr/bin/env python3
import json
import sys

def audit_routes(rules_file):
    findings = []
    with open(rules_file, 'r', errors='ignore') as f:
        lines = f.readlines()
        for idx, line in enumerate(lines, 1):
            if "0.0.0.0/0" in line and ("22" in line or "3389" in line or "5432" in line or "3306" in line):
                findings.append({
                    "line": idx,
                    "risk": "HIGH: Sensitive management/DB port exposed to 0.0.0.0/0",
                    "rule": line.strip()
                })
    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "firewall_rules.txt"
    try:
        results = audit_routes(target)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
