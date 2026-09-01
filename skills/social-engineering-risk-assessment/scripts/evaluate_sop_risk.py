#!/usr/bin/env python3
import sys
import json

RISK_KEYWORDS = [
    ("phone call only", "HIGH: Relies on phone call without callback"),
    ("employee id", "MEDIUM: Relies on static employee ID for authentication"),
    ("single approval", "HIGH: Missing dual-authorization for financial changes"),
    ("email request", "HIGH: Accepts email request without out-of-band verification")
]

def evaluate_sop(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        text = f.read().lower()
        for kw, risk in RISK_KEYWORDS:
            if kw in text:
                findings.append(risk)
    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "sop.txt"
    try:
        results = {"file": target, "risks": evaluate_sop(target)}
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
