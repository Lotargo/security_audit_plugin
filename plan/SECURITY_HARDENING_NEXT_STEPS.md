# Security Hardening - Continuation Plan

## Purpose

This document is the current continuation point for the sandbox/runtime security hardening work.

It is intentionally narrower than the original Stage 1-6 implementation plans. The core runtime, authenticated control plane, sandbox execution paths, and live Docker roundtrip already exist. The remaining work is about closing escape paths, making scope enforcement consistent at every network layer, and then cleaning up the public MCP/tool contract.

The order in this document matters. Do not expand the feature set before the security boundary is complete and validated.

---

## Current baseline

The following work is already in place and should be treated as the new baseline rather than reimplemented:

- Authenticated host-to-sandbox control plane using an ephemeral Ed25519 host identity.
- Encrypted request bodies using ChaCha20-Poly1305.
- Request signatures bind method, exact path + query, epoch, nonce, and transmitted body hash.
- Replay protection and fail-closed authentication behavior.
- Docker runtime health/re-key flow owned by the host MCP process.
- Agent-controlled command execution runs as a non-root UID.
- tmux panes do not inherit daemon root privileges.
- Managed browser execution uses a separate non-root runtime identity.
- Tor uses a separate runtime identity from both the agent and browser.
- Startup network policy is fail-closed before an audit scope is provisioned.
- Agent execution cannot directly use the Tor SOCKS/Control ports as an RoE bypass.
- Tor ControlPort authentication uses cookie authentication and localhost binding.
- Active network scope is tracked on the trusted host bridge.
- Managed browser/probe calls are rejected by the bridge when their requested URL is outside the active scope.
- Arbitrary per-call proxy switching is rejected.
- External upstream proxy support is currently fail-closed instead of being allowed as an unsafe generic CONNECT escape route.
- Live Docker roundtrip has already validated the startup containment / privilege-separation layer.
- Rust check, unit tests and clippy have already passed for the containment implementation; the only failure seen in that run was formatting and was corrected separately.

The current direction is therefore: **defense in depth**, not another architectural rewrite.

---

# NEXT - complete L7 scope enforcement inside managed network runtimes

This is the immediate next implementation step.

Host-side scope checks are necessary but not sufficient. The browser and HTTP probe can receive redirects or load secondary resources after the initial URL has already passed the bridge check. Scope enforcement therefore has to exist inside the managed network runtime as well.

## 1. Browser: enforce `allowed_hosts` on every request

Update `sandbox_runtime/stealth/browser_launcher.js` so that the browser treats the host-provided allowlist as authoritative.

Required behavior:

- Accept `allowed_hosts` from the signed browser audit payload.
- Validate the initial navigation URL against the allowlist.
- Validate every request intercepted through `page.route('**/*', ...)`.
- Block cross-host redirects unless the redirected hostname is also explicitly in `allowed_hosts`.
- Block subresources, iframes, scripts, images, XHR/fetch, WebSocket endpoints, and other network destinations outside the active scope.
- Continue to block private/restricted destinations unless the audit mode explicitly permits them.
- Do not silently broaden scope to sibling subdomains.
  - `example.com` must not automatically mean `*.example.com` unless wildcard/subdomain behavior is deliberately added later.
- Treat URL parsing failures as deny, not allow.

### Decoy traffic

`generate_decoy_noise` currently conflicts with strict RoE because decoy requests intentionally leave the audit target.

For the hardened runtime, choose the fail-closed behavior first:

- disable decoy network traffic while strict scope enforcement is active;
- or only permit decoy traffic when every destination is explicitly included in the active scope.

Do not keep a hidden global-internet exception for decoy traffic.

## 2. Browser + Tor: remove host-side DNS leakage

The current browser SSRF guard performs `dns.lookup()` before Chromium navigation. That is acceptable for direct scoped egress but incorrect for Tor operation and prevents proper `.onion` handling.

Required behavior:

- When Tor transport is active, do not perform local/host-side DNS resolution for the target hostname.
- Let hostname resolution happen through the Tor SOCKS transport.
- Keep exact hostname RoE enforcement before the request is allowed.
- Keep direct private-IP literals blocked unless explicitly permitted by the audit mode.
- Ensure `.onion` targets can be validated as hostnames without attempting normal DNS lookup.

The important invariant is:

> Tor must not become a reason to weaken scope validation, and scope validation must not create a Tor DNS leak.

## 3. HTTP probe: enforce scope across redirects

Update `sandbox_runtime/crates/sandbox-daemon/src/routes/probe.rs`.

Required behavior:

- Accept `allowed_hosts` in the signed probe request.
- Validate the initial URL against the allowlist.
- Disable unrestricted automatic redirects.
- Either:
  - process redirects manually and validate every `Location` target before following it, or
  - install an equivalent redirect policy that rejects any destination outside the allowlist.
- Reject malformed redirect URLs fail-closed.
- Keep the redirect count bounded.
- Preserve method/body semantics deliberately for the supported redirect statuses instead of relying on accidental client behavior.
- Ensure proxy use cannot change independently from the active scope selected on the host bridge.

## 4. HTTP probe + Tor transport

Tor proxying for hostname targets must use remote DNS semantics.

Required behavior:

- Use SOCKS hostname resolution through Tor rather than resolving the destination on the host side.
- Do not introduce a bridge-side DNS lookup merely to validate the hostname.
- Scope validation remains based on the exact requested hostname.

## 5. Tests for the L7 boundary

Add tests before considering this block complete.

Minimum cases:

- allowed initial browser target succeeds;
- browser navigation to an out-of-scope hostname is blocked;
- browser secondary request to an out-of-scope hostname is blocked;
- browser redirect to an out-of-scope hostname is blocked;
- same-host redirect remains allowed;
- HTTP probe same-host redirect succeeds;
- HTTP probe cross-host redirect is rejected;
- managed network calls fail when no remote/hybrid scope is active;
- per-call proxy differing from the active scope is rejected;
- Tor scope does not perform normal DNS resolution for `.onion` / Tor-hostname paths;
- decoy traffic cannot escape the active RoE.

### Definition of done for NEXT

This step is complete only when:

1. the bridge checks the initial request;
2. the browser checks every network destination;
3. the HTTP probe checks every redirect destination;
4. Tor does not leak target DNS through the normal resolver;
5. CI is green;
6. the live Docker roundtrip still passes.

---

# AFTER NEXT - make remote/hybrid RoE strict at the network layer

Once L7 checks are complete, tighten the nftables egress model itself.

The goal is that even a compromised or buggy managed tool cannot simply ignore the host allowlist and open an arbitrary TCP connection.

## 6. Remove generic Internet web egress as an implicit permission

Audit the generated nftables policy for any generic rule equivalent to:

```text
tcp dport { 80, 443, 8080, 8443 } accept
```

A remote/hybrid audit must not interpret "web ports" as "the Internet is in scope".

Required policy:

- explicit resolved target IP/CIDR allowlist for direct audits;
- private/metadata deny rules evaluated before any target allow;
- IPv4 and IPv6 handled consistently;
- no fallback broad Internet allow when target resolution fails;
- a scope with no valid target/CIDR and no explicit supported transport remains fail-closed.

## 7. Define DNS pinning semantics

Direct remote targets need a deliberate DNS policy.

We need to decide and document how changes in DNS answers are handled during an audit:

- resolve once at `setScope` and pin those addresses for the lifetime of that scope; or
- use a controlled re-resolution operation which atomically updates the allowlist.

Do not allow arbitrary runtime DNS changes to silently expand the target IP set.

Potential later enhancement:

- expose a signed `refresh_scope_resolution` operation with traceable old/new address sets.

## 8. Separate hostname authorization from IP authorization

Keep two explicit concepts:

- L7 hostname scope - which logical sites managed HTTP/browser tools may request;
- L3/L4 egress scope - which destination addresses the sandbox may connect to.

They should reinforce one another rather than being collapsed into one ambiguous `targets` field internally.

### Definition of done for AFTER NEXT

- Direct remote/hybrid execution cannot connect to arbitrary public IPs outside the approved CIDRs.
- Browser/probe hostname allowlists and nftables IP allowlists agree.
- Private network and cloud metadata destinations remain denied unless a future explicit local-audit mode intentionally permits them.
- IPv6 cannot bypass an IPv4-only policy.
- Live tests attempt real out-of-scope connections and confirm failure.

---

# THEN - safe proxy and Tor lifecycle hardening

## 9. External upstream proxy support

External proxy support is intentionally disabled for now because simply allowlisting the proxy IP would allow unrestricted HTTP CONNECT tunneling.

Do not re-enable it until there is a containment design.

A safe implementation should include:

- proxy endpoint treated as a transport endpoint, not as an audit target;
- agent shell denied direct access to the proxy endpoint;
- only a managed proxy-capable runtime identity may connect to it;
- logical destination hostname still validated against active RoE before CONNECT/request creation;
- proxy credentials passed without exposing them in process arguments/logs;
- redirect handling still subject to the same hostname allowlist;
- tests proving that an allowed proxy cannot tunnel to an out-of-scope hostname.

If this becomes complicated, keeping external proxy support disabled is preferable to a permissive partial implementation.

## 10. Finish Tor lifecycle policy

Verify and harden the remaining Tor lifecycle details:

- `rotateTor()` only works while a Tor-enabled scope is active;
- Tor is stopped/isolated when containment cannot be restored;
- reset/kill-switch invalidates the host-side active Tor scope;
- cookie permissions are restricted to the intended control path;
- stale Tor processes/circuits cannot survive a hard reset in a reusable state;
- agent UID can never access SOCKS/ControlPort directly;
- browser/probe can use Tor only through the managed path;
- no normal DNS leak exists for Tor targets.

---

# THEN - contract and implementation cleanup

Do this only after the network boundary is stable.

## 11. MCP tool contract audit

The current implementation and public documentation have drifted.

Audit every registered MCP tool against the actual runtime implementation.

Known items to reconcile:

- README tool count is stale.
- Some documentation still refers to old names such as `sandbox_execute`.
- Current implementations use names such as `sandbox_exec` and related newer tools.
- Orchestrator skills must call the real registered names.
- Remove references to tools that no longer exist.

## 12. Remove or implement `sandbox_bundle_extract`

The tool is exposed at the MCP layer while the bridge currently reports that the runtime implementation is unavailable.

Choose one:

- remove it from registration/public documentation for the current release; or
- implement it completely and add live tests.

Do not expose a tool that appears functional but deterministically fails at runtime.

## 13. `ca_cert_b64` contract

The public scope/options schema advertises custom CA support while the bridge currently rejects it fail-closed.

For the current hardened release, the simplest correct option is:

- remove `ca_cert_b64` from the public schema/docs until the feature is actually implemented.

Later, if implemented, CA injection needs:

- temporary scoped certificate storage;
- strict cleanup on reset;
- no host trust-store mutation;
- clear browser/probe-only semantics;
- tests proving the CA cannot persist across sessions.

## 14. SARIF export

A SARIF builder exists but the public tool contract is inconsistent.

After security hardening:

- either expose a real `sandbox_sarif_export` path backed by the implementation;
- or remove stale documentation references.

## 15. Documentation accuracy

Correct misleading terminology after the implementation stabilizes.

Known examples:

- do not call regex/text extraction an "AST" analysis if no parser/AST is used;
- do not describe Turnstile handling as a guaranteed "bypass" when it is primarily browser stealth/humanization/detection logic;
- update README tool counts and examples;
- document the real scope model and fail-closed behavior;
- describe Tor/proxy limitations explicitly.

---

# THEN - CI and adversarial validation

## 16. Expand live Docker security tests

The current roundtrip should evolve from a functionality smoke test into an escape-regression suite.

Add cases for:

- startup before `setScope` has no Internet egress;
- agent process is non-root;
- agent cannot invoke nftables successfully;
- agent cannot use Tor SOCKS or ControlPort;
- local mode cannot access public Internet;
- remote scope can reach only approved destination addresses;
- out-of-scope public IP is blocked;
- private RFC1918 destination is blocked during remote audits;
- `169.254.169.254` metadata access is blocked;
- IPv6 out-of-scope destination is blocked;
- browser cross-host navigation/resource is blocked;
- probe cross-host redirect is blocked;
- Tor target works without ordinary DNS leakage;
- kill switch removes active network access;
- hard reset does not retain old network scope or Tor state.

## 17. Make CI failures easier to diagnose

Keep the diagnostic dump on Docker/live failures.

Useful output should include, without leaking secrets:

- container logs;
- effective nftables ruleset;
- process UID/GID overview;
- Tor process/status information;
- browser stderr on browser failure;
- requested test phase;
- redacted scope summary.

Never print session keys, private signing keys, Tor auth cookie contents, proxy credentials, auth headers, or cookies.

---

# Later / optional work

These are not blockers for finishing the current hardening cycle.

## 18. Controlled scope refresh

Potential feature for long audits where DNS addresses legitimately change.

Requirements:

- explicit host-side operation;
- signed request;
- old/new resolution diff;
- atomic nftables replacement;
- trace/event record;
- no automatic unbounded widening.

## 19. Better audit tracing

Persist security-relevant events such as:

- scope provisioned;
- target resolution set;
- blocked out-of-scope browser request;
- blocked redirect;
- Tor enabled/rotated/stopped;
- kill switch triggered;
- runtime re-keyed;
- hard reset performed.

This should be useful for debugging and auditability without recording sensitive request payloads by default.

## 20. Release/documentation pass

Only after the hardening checklist is green:

- update README architecture diagrams/text;
- update CHANGELOG;
- reconcile ROADMAP with what is actually shipped;
- verify package contents and `.npmignore`;
- run clean-install tests;
- verify all supported MCP integrations use the same tool contract.

---

# Execution order summary

Use this sequence when continuing development:

1. **Browser per-request/redirect scope enforcement.**
2. **Tor DNS-leak fix in managed browser/probe paths.**
3. **HTTP probe redirect scope enforcement.**
4. **Tests for the complete L7 boundary.**
5. **Strict nftables remote/hybrid destination allowlist.**
6. **DNS pinning / controlled resolution semantics.**
7. **Adversarial Docker escape tests.**
8. **Tor lifecycle cleanup.**
9. **Safe external proxy design, or keep it disabled.**
10. **MCP tool/schema/documentation contract cleanup.**
11. **Final CI, packaging, README/CHANGELOG/ROADMAP pass.**

---

# Rule for the next development session

Do not start by redesigning the sandbox again.

Start from the current `main`, confirm the active HEAD, then continue with **L7 scope enforcement in the managed browser and HTTP probe**. Keep each security boundary change in a separate commit so that a CI regression can be attributed to one layer.

If a live test fails, diagnose the concrete log first and patch the root cause rather than weakening the security policy to make the test green.
