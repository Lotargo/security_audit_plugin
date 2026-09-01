# GitHub Actions Hardening & OIDC Best Practices

## 1. Action Commit SHA Pinning
```yaml
# Insecure: Mutable major tag
- uses: actions/checkout@v4

# Hardened: Immutable Git commit SHA + tag comment
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

## 2. Preventing Script Injection in Inline Run Blocks
```yaml
# Insecure: Direct expression evaluation inside bash string
- run: echo "PR title is ${{ github.event.pull_request.title }}"

# Hardened: Pass untrusted values via intermediate environment variables
- name: Log PR Title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title is $PR_TITLE"
```

## 3. Least-Privilege GITHUB_TOKEN Permissions
```yaml
permissions:
  contents: read
  id-token: write # For OIDC only
```
