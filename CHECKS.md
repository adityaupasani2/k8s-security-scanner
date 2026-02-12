# Security Checks

This document details all 20 security checks performed by the Kubernetes Security Scanner.

## Overview

| Category | Checks | Severity Range |
|----------|--------|----------------|
| Pod Security | 8 | CRITICAL - LOW |
| Resource Management | 3 | HIGH - MEDIUM |
| Image Security | 3 | MEDIUM |
| Secrets Management | 1 | CRITICAL |
| Network Security | 3 | HIGH - MEDIUM |
| RBAC | 2 | MEDIUM |
| **Total** | **20** | |

---

## Pod Security (8 checks)

### 1. Root User Detection
- **ID**: `root-user-check`
- **Severity**: CRITICAL
- **Description**: Detects containers running as root (UID 0)
- **Risk**: Root users can escape containers and compromise the node
- **Compliance**: CIS-5.2.6, PCI-DSS-2.2.5, NIST-800-190

**What it checks:**
- `securityContext.runAsUser: 0`
- `securityContext.runAsNonRoot: false` or not set
- Missing security context (defaults to root)

**Remediation:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 3000
```

---

### 2. Privileged Containers
- **ID**: `privileged-container-check`
- **Severity**: CRITICAL
- **Description**: Detects containers running in privileged mode
- **Risk**: Full access to host, can load kernel modules, escape easily
- **Compliance**: CIS-5.2.1, PCI-DSS-2.2, NIST-800-190

**What it checks:**
- `securityContext.privileged: true`

**Remediation:**
```yaml
securityContext:
  privileged: false  # Remove this or set to false
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE  # Only add what you need
```

---

### 3. Privilege Escalation
- **ID**: `privilege-escalation-check`
- **Severity**: HIGH
- **Description**: Detects containers that allow privilege escalation
- **Risk**: Processes can gain more privileges via setuid/setgid
- **Compliance**: CIS-5.2.5, PCI-DSS-2.2.4, NIST-800-190

**What it checks:**
- `securityContext.allowPrivilegeEscalation: true` or not set
- Implicitly true if container is privileged

**Remediation:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
```

---

### 4. Read-Only Root Filesystem
- **ID**: `readonly-filesystem-check`
- **Severity**: MEDIUM
- **Description**: Detects writable root filesystems
- **Risk**: Attackers can modify binaries, install malware
- **Compliance**: CIS-5.2.6, NIST-800-190, PCI-DSS-2.2.5

**What it checks:**
- `securityContext.readOnlyRootFilesystem: false` or not set

**Remediation:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp  # Mount writable volumes only where needed
volumes:
  - name: tmp
    emptyDir: {}
```

---

### 5. Dangerous Capabilities
- **ID**: `capabilities-check`
- **Severity**: HIGH/MEDIUM
- **Description**: Detects dangerous Linux capabilities
- **Risk**: Capabilities like SYS_ADMIN grant near-root access
- **Compliance**: CIS-5.2.9

**What it checks:**
- `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`
- `SYS_BOOT`, `MAC_ADMIN`, `MAC_OVERRIDE`
- `NET_ADMIN`, `NET_RAW`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`

**Remediation:**
```yaml
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE  # Only add safe, required capabilities
```

---

### 6. Missing Security Context
- **ID**: `missing-security-context-check`
- **Severity**: MEDIUM
- **Description**: Detects containers with no security context
- **Risk**: Uses insecure defaults
- **Compliance**: CIS-5.2.6, Pod Security Standards

**What it checks:**
- Missing `securityContext` entirely

**Remediation:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

---

### 7. AppArmor/SELinux Profiles
- **ID**: `apparmor-selinux-check`
- **Severity**: LOW
- **Description**: Detects missing MAC (Mandatory Access Control) profiles
- **Risk**: Missing defense-in-depth layer
- **Compliance**: CIS-5.7.2

**What it checks:**
- Missing AppArmor annotation
- Missing SELinux options

**Remediation:**
```yaml
# AppArmor (Ubuntu/Debian)
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/myapp: runtime/default

# SELinux (RHEL/CentOS)
securityContext:
  seLinuxOptions:
    level: "s0:c123,c456"
```

---

### 8. Seccomp Profiles
- **ID**: `seccomp-check`
- **Severity**: LOW
- **Description**: Detects missing seccomp profiles
- **Risk**: No syscall filtering
- **Compliance**: CIS-5.7.2

**What it checks:**
- Missing `seccompProfile`

**Remediation:**
```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

---

## Resource Management (3 checks)

### 9. Missing CPU Limits
- **ID**: `cpu-limits-check`
- **Severity**: HIGH
- **Description**: Detects missing CPU limits
- **Risk**: Can consume all CPU, starve other pods
- **Compliance**: CIS-5.2.7, PCI-DSS-2.2

**Remediation:**
```yaml
resources:
  limits:
    cpu: "1000m"
  requests:
    cpu: "500m"
```

---

### 10. Missing Memory Limits
- **ID**: `memory-limits-check`
- **Severity**: HIGH
- **Description**: Detects missing memory limits
- **Risk**: Can trigger OOM kills, crash nodes
- **Compliance**: CIS-5.2.8, PCI-DSS-2.2

**Remediation:**
```yaml
resources:
  limits:
    memory: "512Mi"
  requests:
    memory: "256Mi"
```

---

### 11. Missing Resource Requests
- **ID**: `resource-requests-check`
- **Severity**: MEDIUM
- **Description**: Detects missing CPU/memory requests
- **Risk**: Poor scheduling, oversubscribed nodes
- **Compliance**: CIS-5.2.9

**Remediation:**
```yaml
resources:
  requests:
    cpu: "500m"
    memory: "256Mi"
  limits:
    cpu: "1000m"
    memory: "512Mi"
```

---

## Image Security (3 checks)

### 12. Latest Image Tag
- **ID**: `latest-tag-check`
- **Severity**: MEDIUM
- **Description**: Detects use of :latest tag
- **Risk**: Unpredictable versions, breaks reproducibility
- **Compliance**: CIS-5.4.1

**Remediation:**
```yaml
# Bad
image: nginx:latest

# Good
image: nginx:1.21.6
```

---

### 13. Untagged Images
- **ID**: `untagged-image-check`
- **Severity**: MEDIUM
- **Description**: Detects images with no tag (defaults to :latest)
- **Risk**: Implicitly uses :latest
- **Compliance**: CIS-5.4.1

**Remediation:**
```yaml
# Bad
image: nginx

# Good
image: nginx:1.21.6
```

---

### 14. Untrusted Registry
- **ID**: `image-registry-check`
- **Severity**: MEDIUM
- **Description**: Detects images from untrusted registries
- **Risk**: May contain malware, backdoors
- **Compliance**: CIS-5.4.2

**Trusted registries:**
- gcr.io, us.gcr.io (Google)
- registry.k8s.io (Kubernetes)
- quay.io (Red Hat)
- ghcr.io (GitHub)
- mcr.microsoft.com (Microsoft)

**Remediation:**
```yaml
# Use trusted registry
image: gcr.io/my-project/myapp:1.0.0
```

---

## Secrets Management (1 check)

### 15. Hardcoded Secrets
- **ID**: `secrets-in-env-check`
- **Severity**: CRITICAL
- **Description**: Detects hardcoded secrets in environment variables
- **Risk**: Secrets visible in specs, logs, stored unencrypted
- **Compliance**: CIS-5.4.3, PCI-DSS-3.4, GDPR-Article-32, SOC2-CC6.1

**Patterns detected:**
- PASSWORD, SECRET, API_KEY, TOKEN
- DATABASE_URL, ENCRYPTION_KEY, PRIVATE_KEY

**Remediation:**
```yaml
# Bad
env:
  - name: DATABASE_PASSWORD
    value: "hardcoded-password"  # ❌

# Good
env:
  - name: DATABASE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-secret
        key: password  # ✅
```

---

## Network Security (3 checks)

### 16. Host Network
- **ID**: `host-network-check`
- **Severity**: HIGH
- **Description**: Detects pods using host network
- **Risk**: Can see all node network traffic, intercept packets
- **Compliance**: CIS-5.2.4, PCI-DSS-1.2.1

**Remediation:**
```yaml
# Remove this
spec:
  hostNetwork: true  # ❌
```

---

### 17. Host Path Volumes
- **ID**: `host-path-check`
- **Severity**: HIGH
- **Description**: Detects host path volume mounts
- **Risk**: Direct access to node filesystem
- **Compliance**: CIS-5.2.3

**Remediation:**
```yaml
# Bad
volumes:
  - name: data
    hostPath:
      path: /var/lib/data  # ❌

# Good
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: my-pvc  # ✅
```

---

### 18. Host PID/IPC Namespaces
- **ID**: `host-namespaces-check`
- **Severity**: MEDIUM
- **Description**: Detects pods using host PID or IPC namespaces
- **Risk**: Can see/signal host processes, access shared memory
- **Compliance**: CIS-5.2.2, CIS-5.2.3

**Remediation:**
```yaml
# Remove these
spec:
  hostPID: true   # ❌
  hostIPC: true   # ❌
```

---

## RBAC (2 checks)

### 19. Default Service Account
- **ID**: `default-service-account-check`
- **Severity**: MEDIUM
- **Description**: Detects use of default service account
- **Risk**: Unnecessary API permissions, shared across pods
- **Compliance**: CIS-5.1.5

**Remediation:**
```yaml
spec:
  serviceAccountName: myapp-sa  # Create dedicated SA
```

---

### 20. Automounted Service Account Token
- **ID**: `automount-token-check`
- **Severity**: MEDIUM
- **Description**: Detects automounted tokens when not needed
- **Risk**: Unnecessary attack surface if app doesn't use K8s API
- **Compliance**: CIS-5.1.6

**Remediation:**
```yaml
spec:
  automountServiceAccountToken: false  # If app doesn't need K8s API
```

---

## Summary Matrix

| Check | Severity | Default Behavior | Fix Effort |
|-------|----------|------------------|------------|
| Root User | CRITICAL | Often root | Easy |
| Privileged | CRITICAL | Not privileged | Easy |
| Priv Escalation | HIGH | Allowed | Easy |
| Read-Only FS | MEDIUM | Writable | Medium |
| Capabilities | HIGH/MED | None added | Easy |
| Security Context | MEDIUM | None | Easy |
| AppArmor/SELinux | LOW | None | Medium |
| Seccomp | LOW | None | Easy |
| CPU Limits | HIGH | None | Easy |
| Memory Limits | HIGH | None | Easy |
| Resource Requests | MEDIUM | None | Easy |
| Latest Tag | MEDIUM | Explicit | Easy |
| Untagged Image | MEDIUM | Implicit | Easy |
| Untrusted Registry | MEDIUM | Docker Hub | Medium |
| Hardcoded Secrets | CRITICAL | Common | Medium |
| Host Network | HIGH | Disabled | Easy |
| Host Path | HIGH | Not used | Medium |
| Host Namespaces | MEDIUM | Disabled | Easy |
| Default SA | MEDIUM | Default | Easy |
| Automount Token | MEDIUM | Enabled | Easy |

---

## Quick Fixes

Apply all best practices at once:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  serviceAccountName: myapp-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myregistry.com/myapp:1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      requests:
        cpu: "250m"
        memory: "256Mi"
      limits:
        cpu: "500m"
        memory: "512Mi"
    env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secrets
          key: password
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```
