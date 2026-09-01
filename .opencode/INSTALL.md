# Installing Security Audit Plugin for OpenCode

## Prerequisites

- [OpenCode](https://opencode.ai) installed

## Installation

Add security-audit-plugin to the `plugin` array in your `opencode.json` (global or project-level):

```json
{
  "plugin": ["@security-audit/plugin"]
}
```

Or via Git repository:

```json
{
  "plugin": ["security-audit@git+https://github.com/Lotargo/security_audit_plugin.git"]
}
```

Restart OpenCode. The plugin registers all 19 security audit skills and MCP tools.

## Alternative Zero-Setup Installation (via NPX)

From your terminal, run:

```bash
npx @security-audit/plugin install --target opencode
```

To uninstall:

```bash
npx @security-audit/plugin uninstall --target opencode
```
