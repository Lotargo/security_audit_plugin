# Example Kubernetes Security Audit Finding: Docker Socket Mount

### Finding Details
- **Title:** Container Mounts `/var/run/docker.sock` Allowing Host Takeover
- **Severity:** Critical (CVSS 9.8)
- **Standard:** CIS Kubernetes Benchmark 5.2.4
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)

### Vulnerable Manifest
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: build-agent
spec:
  template:
    spec:
      containers:
        - name: runner
          image: custom-runner:latest
          volumeMounts:
            - mountPath: /var/run/docker.sock
              name: docker-socket
      volumes:
        - name: docker-socket
          hostPath:
            path: /var/run/docker.sock # Allows container escape to host daemon
```

### Hardened Manifest
Use daemonless container builders (Kaniko / Buildah) with unprivileged securityContext:
```yaml
spec:
  template:
    spec:
      containers:
        - name: runner
          image: gcr.io/kaniko-project/executor:latest
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```
