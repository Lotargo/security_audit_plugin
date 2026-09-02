# Installing Security Audit Plugin for OpenCode

## Prerequisites

- OpenCode installed
- Node.js >= 20
- Docker Desktop or `dockerd`

## Recommended setup

Register the package as a local MCP server and install its AgentSkills with one command:

```bash
npx @security-audit/plugin setup --target opencode
```

The installer writes only the owned `security-audit-sandbox` MCP entry and preserves unrelated OpenCode configuration.

OpenCode starts the plugin through STDIO using the package CLI:

```json
{
  "mcp": {
    "security-audit-sandbox": {
      "type": "local",
      "command": ["npx", "-y", "@security-audit/plugin", "mcp"]
    }
  }
}
```

If an existing `security-audit-sandbox` entry is present but is not recognized as owned by this package, setup fails instead of overwriting it.

## Skills only

```bash
npx @security-audit/plugin install --target opencode
```

## Remove skills and the owned MCP registration

```bash
npx @security-audit/plugin uninstall --target opencode --mcp
```

The security-audit plugin does not read, copy, or store OpenCode provider credentials. Authentication remains entirely owned by OpenCode and its configured model providers.
