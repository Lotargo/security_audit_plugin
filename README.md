# Security Audit Plugin

Comprehensive security audit plugin and isolated execution sandbox for AI coding agents (Google Antigravity, OpenCode, Claude Code, OpenAI Codex, Cursor).

## Overview

This project provides an isolated Docker sandbox, a cryptographically hardened host-bridge control plane, a stealth browser with WAF evasion capabilities, Tor onion routing, and a library of 19 standardized AgentSkills for static (SAST) and dynamic (DAST) security assessments, with reporting standardized in OASIS SARIF v2.1.0 format.

Tech Stack:
- Host: TypeScript / Node.js (MCP Server, CLI, SARIF v2.1.0 Builder, Ratchet Bridge).
- Sandbox: Rust (Axum/Tokio daemon, zeroize memory hygiene, nftables firewall, emergency Kill Switch, rquest TLS impersonation) + Node.js (Playwright stealth browser with cubic Bezier ghost-cursor and WafDetector).
- Network and Anonymity: embedded Tor service (SOCKS5 :9050, ControlPort :9051) and support for upstream HTTP/SOCKS5 proxies (Burp Suite, Caido, OWASP ZAP).

---

## Key Features

1. Zero-Touch Docker Delivery:
   - Automatic image resolution with pre-built image pull from GitHub Container Registry (ghcr.io/lotargo/security-audit-sandbox:latest).
   - Transparent local build fallback from bundled sandbox_runtime/Dockerfile for airgapped or offline environments.
   - Lifecycle management commands: pull-sandbox, build-sandbox, start-sandbox, stop-sandbox, reset-sandbox.

2. Cryptographic Host-Bridge Control Plane (Ratchet Bridge):
   - Asymmetric Ed25519 request signing with private key isolation on host.
   - Symmetric payload encryption via ChaCha20-Poly1305 / AES-256-GCM with Authenticated Associated Data (AAD) binding method, path, and epoch to prevent replay attacks and endpoint confusion.
   - Rolling retry on 401/403 with automatic epoch re-synchronization on clock drift.
   - Memory zeroization (zeroize) in the Rust kernel upon epoch advancement or key drop.

3. Isolation and Network Control (RoE Guardrail):
   - Kernel-level nftables packet filtering with dynamic on-link subnet discovery via /proc/net/route and DNS discovery via /etc/resolv.conf.
   - Strict address family separation (IPv4 and IPv6) within nftables sets.
   - Strict blocking of unauthorized traffic to RFC 1918 private subnets and cloud metadata endpoints (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16).
   - Emergency Kill Switch: instant socket connection flushing (conntrack -F) and total container network isolation.

4. Stealth Browser and WAF Evasion Engine:
   - Signature profile database for Akamai Bot Manager, Cloudflare Turnstile, AWS WAF, F5 Big-IP, DataDome, PerimeterX, Imperva Incapsula.
   - Multi-signal WafDetector analyzing response headers, cookies, server banners, and body challenge markers.
   - Warmup Hop phase: initial navigation to domain root to establish legitimate sensor cookies before deep path scanning.
   - In-Browser L7 SSRF Guard (page.route) validating DNS resolution against private network blacklists before dispatching requests.
   - Human-like cursor movement synthesis using cubic Bezier curves (ghost-cursor) incorporating Fitts's Law and jitter.

5. Tor and Traffic Anonymization:
   - Embedded Tor daemon for traffic anonymization and DNS/WebRTC leak prevention.
   - Dynamic circuit rotation and exit IP renewal via SIGNAL NEWNYM over ControlPort.
   - Native support for .onion hidden services and Cloudflare Onion-Location discovery (RFC 8738).

6. Standardized Reporting (OASIS SARIF v2.1.0):
   - Valid SARIF v2.1.0 document generation with CVSS v3.1 scoring and CWE / OWASP Top 10 / MITRE ATT&CK taxonomy tags.
   - Proposed code diff patches (fixes) attached directly to findings.
   - Attack graph synthesis (attackGraph) with automated Mermaid flowchart diagrams rendered in Markdown summaries.

---

## Skills Registry (19 Standardized Modules)

| # | Skill Name | Description |
| :- | :--- | :--- |
| 0 | security-audit-orchestrator | Master orchestrator, manages OPPLAN, mode selection, sandbox lifecycle, SARIF export. |
| 1 | tor-anonymity-onion-routing | Tor routing, DNS/WebRTC leak prevention, IP rotation, .onion hidden services audit. |
| 2 | backend-topology-cartography | Reverse-engineering REST/GraphQL and binary RPC/gRPC (Proteus/Protobuf) APIs from bundles and source maps. |
| 3 | web-appsec-dast | Dynamic web application testing (CSP, cookies, DOM XSS, Chaos Mode heuristics, Decoy traffic). |
| 4 | abuse-prevention-resilience | Botnet resistance, credential stuffing, captcha bypass analysis, rate limiting, L7 IP spoofing (CWE-290). |
| 5 | cryptography-token-security | JWT/JWS/JWE validation, entropy testing, cryptographic algorithm strength, key rotation. |
| 6 | injection-input-validation | Verification of SQLi, NoSQLi, Command Injection, SSTI, XSS vulnerabilities. |
| 7 | access-control-business-logic | BOLA/IDOR analysis, privilege escalation, multi-tenant boundary checks. |
| 8 | client-supply-chain-magecart | Third-party script audit, GTM/TMS analysis, Subresource Integrity (SRI), Magecart defenses, PCI DSS v4.0. |
| 9 | cloud-kubernetes-infra-audit | K8s manifest review, RBAC posture, network policies, Cloud IAM least-privilege checks. |
| 10 | data-exposure-privacy-resilience | Detection of PII/PDN leaks, unmasked logs, unencrypted secrets (GDPR/HIPAA compliance). |
| 11 | purple-team-detection-engineering | Detection rule engineering (Sigma, YARA), MITRE ATT&CK coverage mapping, canary tokens. |
| 12 | http-smuggling-cache-attacks | HTTP Request Smuggling, Web Cache Poisoning, Cache Deception analysis. |
| 13 | iam-active-directory-audit | Active Directory audit, Kerberos attack paths, Hybrid IAM, OAuth2/OIDC delegation. |
| 14 | mobile-appsec-analysis | Static and dynamic analysis of Android/iOS binaries (APK/IPA, certificate pinning). |
| 15 | network-segmentation-perimeter | Network segmentation analysis, DMZ validation, firewall egress, lateral movement modeling. |
| 16 | osint-attack-surface-mapping | External Attack Surface Management (EASM), subdomain enumeration, open port discovery. |
| 17 | social-engineering-risk-assessment | Phishing simulation risk modeling, MFA fatigue resistance, human factor analysis. |
| 18 | cicd-supply-chain-security | CI/CD pipeline audit (GitHub Actions), SBOM verification, dependency pinning, SLSA compliance. |

---

## Quick Start

### Prerequisites
- Node.js >= 20.0.0
- Docker Desktop or dockerd (for isolated container sandbox execution)

### 1. Environment Diagnostics
```bash
npx @security-audit/plugin doctor
```

### 2. Install Skills and Pre-Warm Sandbox Image

Install all 19 skills into your project (.agents/skills) and pre-pull the sandbox Docker image:
```bash
npx @security-audit/plugin install --docker
```

Target-specific installation:
```bash
# For Google Antigravity (AGY):
npx @security-audit/plugin install --target agy --docker

# For OpenCode:
npx @security-audit/plugin install --target opencode --docker

# For Claude Code:
npx @security-audit/plugin install --target claude --docker
```

Selective skill installation:
```bash
npx @security-audit/plugin install --skills web-appsec-dast,injection-input-validation
```

### 3. Launch MCP Server

Run MCP Server over STDIO for integration with AI Agents:
```bash
npx @security-audit/plugin mcp
```

Agent configuration snippet (mcp_config.json / claude_desktop_config.json):
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

---

## CLI Command Reference

| Command | Description |
| :--- | :--- |
| `npx @security-audit/plugin doctor` | Run diagnostics for Node.js, Docker, ports, and skill directories |
| `npx @security-audit/plugin install` | Install skills into target platform (--target, --skills, --docker, --mcp) |
| `npx @security-audit/plugin uninstall` | Remove skills from target platform (--target, --skills, --path) |
| `npx @security-audit/plugin init` | Interactive setup wizard for agent environments |
| `npx @security-audit/plugin mcp` | Launch MCP Server over STDIO |
| `npx @security-audit/plugin pull-sandbox` | Pull pre-built sandbox image from public registry (GHCR) |
| `npx @security-audit/plugin build-sandbox` | Build sandbox container locally from bundled sandbox_runtime |
| `npx @security-audit/plugin start-sandbox` | Start sandbox container in background |
| `npx @security-audit/plugin stop-sandbox` | Stop and remove sandbox container |
| `npx @security-audit/plugin reset-sandbox` | Emergency Hard Reset: destroy and recreate a pristine container |

---

## MCP Tools Reference (12 Tools)

1. `sandbox_set_scope` - Configure audit scope (local, remote, hybrid), update nftables rules and arm honeypots.
2. `sandbox_execute` - Synchronously execute commands and security tools inside the sandbox.
3. `sandbox_tmux_exec` - Manage long-running interactive tmux sessions (start, send, diff, reset).
4. `sandbox_browser_audit` - Execute Playwright stealth Chromium audits with WAF scoring and Bezier cursor simulation.
5. `sandbox_http_probe` - Dispatch low-level HTTP/HTTPS probes with L7 IP spoofing and WAF heuristics.
6. `sandbox_rotate_tor` - Flush Tor circuits and acquire a fresh exit IP address.
7. `sandbox_arm_canary` - Plant and monitor canary file traps (.aws, .ssh, .kube, .gcp, .env) via inotify.
8. `sandbox_isolate` - Trigger Emergency Kill Switch and isolate container networking.
9. `sandbox_reset` - Destroy container and re-spawn from immutable base image.
10. `sandbox_fs_read` - Read file contents from /workspace with JailGuard validation.
11. `sandbox_fs_write` - Write file contents into /workspace with JailGuard validation.
12. `sandbox_sarif_export` - Export audit findings to OASIS SARIF v2.1.0 and Markdown reports.

---

## Roadmap

Detailed strategic milestones and future development tracks are documented in [ROADMAP.md](./ROADMAP.md):
- Dedicated autonomous benchmark suite (security-audit-benchmarks);
- Deep protocol fuzzing (gRPC, Protobuf, WebSockets);
- Enterprise eBPF kernel telemetry and hardware-backed key attestation;
- Continuous multi-model reasoning evaluation in CI pipelines.

---

## Repository Structure

- `skills/` - 19 standardized skills (instructions, examples, references).
- `sandbox_runtime/` - Docker sandbox source code (Rust kernel, daemon, stealth browser, Tor).
- `src/` - TypeScript source code for MCP Server, Ratchet Bridge, SARIF Builder, and CLI.
- `plugins/` - Integration manifests for AGY, OpenCode, Claude Code, Cursor.
- `tests/` - Integration and unit test suite (Vitest).
- `CHANGELOG.md` - Version history and changelog.
- `ROADMAP.md` - Strategic milestones and future development roadmap.
- `package.json` - NPM package configuration and dependencies.
