# Project Roadmap

This document outlines the planned future milestones and strategic development tracks for **`security-audit-plugin`**.

---

## Strategic Development Tracks

### 1. Dedicated Evaluation and Benchmark Suite (security-audit-benchmarks)

- **Independent Benchmark Repository**:
  - Creation of a separate standalone evaluation repository dedicated to benchmarking AI security agents without bloating the production plugin package.
- **Deterministic Synthetic Testbeds**:
  - Curated, reproducible vulnerability scenarios covering OWASP Top 10, business logic flaws, Cloud K8s misconfigurations, and CI/CD supply chain attacks.
- **Automated Evaluation Engine**:
  - Ground-truth vulnerability manifests with automated diffing against generated OASIS SARIF v2.1.0 reports.
  - Standardized metrics: Detection Recall, Precision, False Positive Rate, Code Fix Accuracy, and Token Efficiency.
- **Continuous Multi-Model Scoring**:
  - Automated CI benchmarking runs across leading LLM reasoning backends (Gemini, Claude, OpenAI) to assess agent performance over time.

---

### 2. Deep Protocol Fuzzing and Stateful RPC Analysis

- **Binary RPC and gRPC/Protobuf Introspection**:
  - Integrated stateful fuzzing engines inside the sandbox for binary protocols, Protobuf schema inference, and gRPC endpoint fuzzing.
- **Real-Time Stream Security**:
  - Automated analysis and fuzzing for WebSocket connections, Server-Sent Events (SSE), and GraphQL batch operations.
- **API Surface Cartography Expansion**:
  - Automated reconstruction of hidden API routes from WebAssembly (Wasm) modules and frontend AST trees.

---

### 3. Enterprise Attestation and Kernel Telemetry

- **eBPF-Powered Kernel Telemetry**:
  - Integration of lightweight eBPF probes in the Linux sandbox kernel to monitor sensitive syscalls (execve, connect, ptrace) in real time.
- **Hardware-Assisted Key Attestation**:
  - Support for TPM/HSM-backed key storage for the host-bridge Ed25519 signing keys in zero-trust enterprise deployments.
- **Cryptographic Execution Proofs**:
  - Generation of verifiable execution traces to prove that audit commands were run inside an unaltered, isolated container.

---

### 4. Ecosystem Integration and Platform Expansion

- **Extended Agent Ecosystem Support**:
  - Maintenance and extension of native plugin manifests for Google Antigravity, OpenCode, Claude Code, Cursor, Codex, and upcoming agent platforms.
- **CI/CD Native Orchestration**:
  - Pre-packaged GitHub Actions and GitLab CI runners for automated continuous security auditing on pull requests.
- **Collaborative Purple-Team Mode**:
  - Real-time event streaming between defensive detection rules (Sigma/YARA) and active red-team probes.
