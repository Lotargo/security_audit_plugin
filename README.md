# Security Audit Plugin

Security audit tooling and an isolated Docker execution sandbox for AI coding agents (Google Antigravity, OpenCode, Claude Code, OpenAI Codex, Gemini CLI, Cursor).

The project combines a TypeScript MCP host bridge, a Rust sandbox daemon/kernel layer, a scoped Chromium audit runner, managed Tor routing, an adaptive Evolve deception runtime, and 19 AgentSkills for static and dynamic security assessment workflows.

## Current Architecture

- **Host:** TypeScript / Node.js MCP server, CLI, client integration manager, Ratchet Bridge, Docker lifecycle manager, and programmatic SARIF v2.1.0 builder.
- **Sandbox:** Rust (Axum/Tokio daemon, authenticated control plane, nftables RoE policy, process-identity containment, watchdogs, emergency isolation) plus Node.js/Chromium for managed browser audits.
- **Network:** fail-closed local startup, explicit remote/hybrid scope provisioning, host-pinned direct targets, and an embedded Tor service isolated behind dedicated runtime identities.
- **Client integration:** native MCP lifecycle commands where supported, ownership-checked config fallbacks, and a direct Node launcher for Codex.

The runtime intentionally prefers failing closed over silently exposing partially implemented capabilities. External upstream HTTP/SOCKS intercepting proxies and automatic bundle extraction are not currently exposed as MCP tools.

The plugin does **not** read, copy, proxy, or store model-provider credentials from Codex, Claude Code, OpenCode, Gemini CLI, or Antigravity. Each client keeps its own authentication and subscription state; the client only launches this package as an MCP server over STDIO.

---

## Key Features

### 1. Docker Sandbox Delivery

- Pulls the sandbox image from `ghcr.io/lotargo/security-audit-sandbox:latest` when available.
- Falls back to a local build from `sandbox_runtime/Dockerfile`.
- Provides CLI lifecycle commands for pull, build, start, stop, and reset.
- Starts with a local fail-closed nftables policy before the daemon begins accepting protected control-plane requests.

### 2. Authenticated Host-to-Sandbox Control Plane

- Ed25519 request signatures generated on the host.
- ChaCha20-Poly1305 encrypted request payloads.
- AAD binding to HTTP method, exact path/query, and ratchet epoch.
- Replay protection and nonce tracking in the Rust daemon.
- Protected sandbox routes reject unsigned requests; `/health` remains available for runtime readiness checks.

### 3. Rules-of-Engagement Network Guardrails

- `local` mode opens no new non-loopback agent egress.
- `remote` and `hybrid` direct targets are resolved on the trusted host and pinned to explicit `/32` or `/128` nftables entries.
- Explicit CIDR allowlists are validated; malformed and unbounded `/0` entries are rejected.
- Denied private, loopback, link-local, and metadata ranges take precedence over allow rules.
- Agent-controlled commands run under an unprivileged UID and cannot modify nftables.
- Emergency isolation drops the network policy and flushes existing connection state.
- Once emergency isolation is latched, egress cannot be provisioned again in the same runtime; a clean sandbox recreate is required.

### 4. Evolve Adaptive Deception

- Primary honeytokens remain the first tripwire. A trigger immediately engages the existing fail-closed Kill Switch before any deception workflow continues.
- The deeper inert surface under `.deployment/prod/` is materialized only after containment, so healthy audit tooling does not normally walk the decoy environment.
- Post-containment decoy access is observed with recursive `inotifywait` telemetry and appended to `.evolve/events.jsonl`.
- `.evolve/profile.json` persists behavior categories, techniques, trigger counts, recommendations, and an explicit Evolve generation across sandbox recreations that reuse the workspace.
- New validated TTP observations update a deterministic, explainable defensive profile instead of an opaque online-learning model.
- Evolve never performs external retaliation or widens audit scope. It operates inside the sandbox boundary and cannot disable a latched isolation state.
- Evolve state, deception lifecycle, and feedback writes stay on the authenticated trusted host/operator control plane. They are intentionally absent from the default agent-facing MCP `tools/list`, so a suspicious agent cannot query whether it has entered deception or poison the defensive profile.

The resulting loop is:

`detect -> contain -> substitute surface -> observe -> adapt`

### 5. Managed Browser Audits

- Chromium runs under a dedicated browser UID rather than the daemon or agent UID.
- Browser configuration is passed through stdin JSON instead of process-list arguments.
- Every browser request is checked against the active exact-host RoE list when one is present.
- Direct browser audits retain private/restricted-address SSRF checks.
- Tor browser audits avoid local target DNS resolution and delegate hostname resolution to the managed proxy path.
- WAF heuristics inspect response headers, cookies, body markers, and common challenge signals.
- Optional human-like cursor, delay, and scrolling behavior is available, but no challenge bypass is guaranteed.

### 6. Managed Tor Containment

- Tor listens only on localhost (`9050` SOCKS / `9051` ControlPort).
- ControlPort uses cookie authentication.
- Tor runs under a dedicated UID distinct from both the browser and agent execution UIDs.
- Agent-controlled shell processes are blocked from connecting directly to Tor SOCKS/ControlPort.
- Tor scopes require explicit host-level targets and reject `allowed_cidrs`, preventing a parallel direct target path.
- Agent DNS traffic is rejected while Tor scope is active; managed HTTP probes use `socks5h` so hostname resolution occurs through Tor.
- `.onion` hostnames are kept out of trusted-host DNS resolution.

### 7. Reporting Primitives

- A programmatic OASIS SARIF v2.1.0 builder is exported from the package API.
- Audit artifacts can be read and written through the jailed workspace filesystem MCP tools.
- There is currently no dedicated `sandbox_sarif_export` MCP tool; AgentSkills should generate/report through the available programmatic or filesystem workflow instead of assuming one exists.

### 8. Client CLI Integration

The client integration layer follows the same native-first pattern used by `@lotargo/memory_plugin`:

1. discover the real client configuration path;
2. use the client's native MCP lifecycle command when one is available;
3. verify that the expected owned registration actually appeared;
4. fall back to a minimal ownership-checked config edit when the CLI is missing, old, or non-functional;
5. refuse to overwrite a same-name registration that is not recognized as owned by this package.

Supported setup paths:

- **Claude Code:** native `claude mcp add` with `~/.claude.json` fallback;
- **Gemini CLI:** native `gemini mcp add` with `~/.gemini/settings.json` fallback;
- **Codex:** native `codex mcp add`, normalized to a direct `node -> bin/cli.js mcp` launcher in `~/.codex/config.toml`;
- **OpenCode:** local MCP entry in `~/.config/opencode/opencode.json` (or `OPENCODE_CONFIG_DIR`);
- **Antigravity:** `~/.gemini/config/mcp_config.json`, plus optional workspace-local `.agents/mcp_config.json`.

Codex has an additional protocol smoke test via `doctor --codex`: it validates the TOML registration, starts the configured MCP executable, performs `initialize`, then checks `tools/list` for core sandbox tools.

---

## Skills Registry (19 Modules)

| # | Skill Name | Description |
| :- | :--- | :--- |
| 0 | security-audit-orchestrator | Audit lifecycle, RoE, OPPLAN, skill routing, sandbox control, and reporting coordination. |
| 1 | tor-anonymity-onion-routing | Managed Tor routing, leak checks, circuit rotation, and onion-target workflows. |
| 2 | backend-topology-cartography | API and backend topology discovery from in-scope client/runtime artifacts. |
| 3 | web-appsec-dast | Dynamic web application assessment and browser/probe verification. |
| 4 | abuse-prevention-resilience | Rate limiting, abuse resistance, bot controls, and trust-boundary analysis. |
| 5 | cryptography-token-security | JWT/JWS/JWE validation, entropy, algorithms, and key lifecycle review. |
| 6 | injection-input-validation | SQLi, NoSQLi, command injection, SSTI, and XSS verification. |
| 7 | access-control-business-logic | BOLA/IDOR, privilege boundaries, and multi-tenant authorization checks. |
| 8 | client-supply-chain-magecart | Third-party scripts, SRI, TMS/GTM, and client supply-chain review. |
| 9 | cloud-kubernetes-infra-audit | Kubernetes, RBAC, network policy, and cloud IAM posture review. |
| 10 | data-exposure-privacy-resilience | Sensitive-data exposure, logging, encryption, and privacy controls. |
| 11 | purple-team-detection-engineering | Sigma/YARA engineering, ATT&CK mapping, and detection coverage. |
| 12 | http-smuggling-cache-attacks | Request smuggling, cache poisoning, and cache-deception assessment. |
| 13 | iam-active-directory-audit | Active Directory, Kerberos, OAuth/OIDC, and hybrid IAM review. |
| 14 | mobile-appsec-analysis | Android/iOS static and dynamic application-security workflows. |
| 15 | network-segmentation-perimeter | Segmentation, perimeter, firewall, and lateral-movement modeling. |
| 16 | osint-attack-surface-mapping | External attack-surface and service discovery workflows. |
| 17 | social-engineering-risk-assessment | Human-factor and social-engineering control assessment. |
| 18 | cicd-supply-chain-security | CI/CD, dependency, SBOM, and software supply-chain review. |

---

## Quick Start

### Prerequisites

- Node.js >= 20
- Docker Desktop or `dockerd`
- One or more supported AI coding clients if automatic MCP registration is desired

### One-command client setup

Configure all supported client locations, install the 19 skills, and optionally pre-warm the sandbox image:

```bash
npx @security-audit/plugin setup --docker
```

Target one client when needed:

```bash
npx @security-audit/plugin setup --target codex
npx @security-audit/plugin setup --target claude
npx @security-audit/plugin setup --target gemini
npx @security-audit/plugin setup --target opencode
npx @security-audit/plugin setup --target agy --local
```

The setup process never imports provider authentication from those clients. It only registers the MCP process and installs the packaged AgentSkills.

### Environment diagnostics

```bash
npx @security-audit/plugin doctor
```

For the strict Codex integration check:

```bash
npx @security-audit/plugin doctor --codex
```

The Codex doctor performs a real STDIO MCP handshake and tool-discovery smoke test using the executable chain stored in `~/.codex/config.toml`.

### Skills-only installation

```bash
npx @security-audit/plugin install --docker
```

Target-specific examples:

```bash
npx @security-audit/plugin install --target agy --docker
npx @security-audit/plugin install --target opencode --docker
npx @security-audit/plugin install --target claude --docker
npx @security-audit/plugin install --target codex
npx @security-audit/plugin install --target gemini
```

Add `--mcp` when using `install` if the selected concrete client should also be registered:

```bash
npx @security-audit/plugin install --target claude --mcp
```

Selective skill installation:

```bash
npx @security-audit/plugin install --skills web-appsec-dast,injection-input-validation
```

### Launch the MCP server manually

```bash
npx @security-audit/plugin mcp
```

Generic MCP configuration for clients without a dedicated setup adapter:

```json
{
  "mcpServers": {
    "security-audit-sandbox": {
      "command": "npx",
      "args": ["-y", "@security-audit/plugin", "mcp"]
    }
  }
}
```

### Remove an owned client registration

```bash
npx @security-audit/plugin uninstall --target codex --mcp
npx @security-audit/plugin uninstall --target claude --mcp
npx @security-audit/plugin uninstall --target opencode --mcp
```

Uninstall refuses to delete a same-name registration when it cannot prove that the entry belongs to this package.

---

## CLI Command Reference

| Command | Description |
| :--- | :--- |
| `npx @security-audit/plugin setup` | Install skills and register MCP in supported coding clients |
| `npx @security-audit/plugin doctor` | Check Node.js, Docker, ports, and skill directories |
| `npx @security-audit/plugin doctor --codex` | Validate Codex direct launcher and perform a real MCP protocol smoke test |
| `npx @security-audit/plugin install` | Install skills; add `--mcp` to register a concrete target client |
| `npx @security-audit/plugin uninstall` | Remove installed skills; add `--mcp` to remove owned client registration |
| `npx @security-audit/plugin init` | Run the legacy/local setup workflow |
| `npx @security-audit/plugin mcp` | Launch the MCP server over STDIO |
| `npx @security-audit/plugin pull-sandbox` | Pull the sandbox image |
| `npx @security-audit/plugin build-sandbox` | Build the sandbox image locally |
| `npx @security-audit/plugin start-sandbox` | Start the authenticated sandbox container |
| `npx @security-audit/plugin stop-sandbox` | Stop and remove the sandbox container |
| `npx @security-audit/plugin reset-sandbox` | Destroy and recreate the sandbox container |

---

## MCP Tools Reference (14 Implemented Tools)

1. `sandbox_set_scope` - Configure local/remote/hybrid RoE, pinned egress, optional managed Tor, and canary arming.
2. `sandbox_rotate_tor_ip` - Request a new Tor circuit for an active Tor-enabled scope.
3. `sandbox_exec` - Execute a synchronous command under the unprivileged agent identity.
4. `sandbox_interactive_input` - Send input/keystrokes to an existing tmux audit session.
5. `sandbox_start_background` - Start a long-running command in a background tmux session.
6. `sandbox_poll_logs` - Poll incremental output and active state from a background session.
7. `sandbox_browser_audit` - Run a scoped Chromium audit with per-request RoE enforcement and WAF heuristics.
8. `sandbox_http_probe` - Send scoped HTTP/HTTPS requests with custom method, headers/body, and redirect enforcement.
9. `sandbox_kill_switch` - Trigger emergency network isolation.
10. `sandbox_reset` - Reset or recreate the sandbox runtime.
11. `sandbox_fs_read` - Read a workspace file through JailGuard path validation.
12. `sandbox_fs_write` - Write a workspace artifact through JailGuard path validation.
13. `sandbox_evolve_status` - Read the current adaptive-deception phase, generation, learned behavior patterns, and defensive recommendations.
14. `sandbox_evolve_observe` - Record a validated defensive TTP observation and evolve the persistent behavior profile without widening network scope.

Not currently exposed as MCP tools:

- automatic JS bundle/source-map extraction;
- external Burp/Caido/ZAP HTTP/SOCKS proxy routing;
- custom interception CA injection;
- dedicated SARIF export.

These capabilities should not be assumed by AgentSkills until their runtime implementations and containment tests exist.

---

## Repository Structure

- `skills/` - 19 AgentSkills with instructions, examples, scripts, and references.
- `sandbox_runtime/` - Docker image, Rust kernel/daemon, Chromium runner, and Tor configuration.
- `src/mcp/` - MCP tools, host bridge, authentication, and workspace jail.
- `src/cli/integration/` - client paths, native CLI invocation, ownership checks, setup/uninstall adapters, Codex TOML handling, and protocol diagnostics.
- `src/docker/` - Docker runtime lifecycle management.
- `src/sarif/` - programmatic SARIF types and builder.
- `plugins/` - integration manifests for supported agent environments.
- `tests/` - TypeScript integration/unit tests, including live Docker roundtrip coverage.
- `plan/` - staged implementation documents.
- `ROADMAP.md` - future development tracks.

## Validation

GitHub Actions currently covers:

- TypeScript build and Vitest suite;
- Rust `cargo check`, unit tests, Clippy with warnings denied, and rustfmt verification;
- 19-skill ecosystem validation;
- live authenticated host-to-Docker-to-Rust roundtrip;
- dependency audit and secret scanning.

Client-integration unit tests additionally cover ownership recognition, JSON fallback registration, OpenCode MCP layout, Codex TOML normalization/conflict handling, and safe removal that preserves unrelated configuration.

See [ROADMAP.md](./ROADMAP.md) for planned extensions.
