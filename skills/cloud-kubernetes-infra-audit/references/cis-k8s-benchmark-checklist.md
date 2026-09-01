# CIS Kubernetes Benchmark & Pod Security Standards (PSS) Checklist

## Baseline & Restricted Pod Security Standards

| Setting | Insecure (Privileged) | Secure (Restricted Baseline) | Risk / Vector |
| :--- | :--- | :--- | :--- |
| `securityContext.privileged` | `true` | `false` (or omitted) | Full host root takeover / container breakout |
| `securityContext.allowPrivilegeEscalation` | `true` | `false` | SUID binary privilege escalation |
| `securityContext.runAsNonRoot` | `false` (or omitted) | `true` | Root container execution |
| `securityContext.readOnlyRootFilesystem` | `false` | `true` | Malware / payload persistence in container |
| `securityContext.capabilities.drop` | None | `["ALL"]` | Linux kernel capability abuse |
| `hostPath` volume mounts | `/var/run/docker.sock`, `/` | Disallowed / `emptyDir` | Host filesystem traversal & breakout |
| `hostNetwork` / `hostPID` | `true` | `false` | Host network snooping & process injection |
