#!/usr/bin/env python3
import json
import sys

def parse_bloodhound(json_file):
    with open(json_file, 'r', errors='ignore') as f:
        data = json.load(f)

    findings = []
    # Check users with DONT_REQ_PREAUTH
    for user in data.get('data', []):
        props = user.get('Properties', {})
        name = props.get('name', 'Unknown')
        if props.get('dontreqpreauth', False):
            findings.append({"user": name, "risk": "AS-REP Roasting (dontreqpreauth=True)"})
        if props.get('hasspn', False) and props.get('admincount', False):
            findings.append({"user": name, "risk": "High-Value Kerberoasting (SPN on Admin Account)"})
    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "users.json"
    try:
        results = parse_bloodhound(target)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
