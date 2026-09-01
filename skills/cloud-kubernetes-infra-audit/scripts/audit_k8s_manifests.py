#!/usr/bin/env python3
import sys
import os
import re

def check_k8s_file(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()

    if "privileged: true" in content:
        findings.append("CRITICAL: privileged: true detected")
    if "hostPID: true" in content:
        findings.append("HIGH: hostPID: true detected")
    if "hostNetwork: true" in content:
        findings.append("HIGH: hostNetwork: true detected")
    if "/var/run/docker.sock" in content:
        findings.append("CRITICAL: Docker socket hostPath mount detected")
    if "allowPrivilegeEscalation: false" not in content and ("kind: Deployment" in content or "kind: Pod" in content):
        findings.append("MEDIUM: allowPrivilegeEscalation: false is missing")

    return [{"file": filepath, "issues": findings}] if findings else []

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    all_issues = []
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith(('.yaml', '.yml')):
                all_issues.extend(check_k8s_file(os.path.join(root, f)))
    import json
    print(json.dumps(all_issues, indent=2))
