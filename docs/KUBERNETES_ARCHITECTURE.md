# Kubernetes Orchestration Architecture

> **Project**: Attacker Container Isolation & Access Control  
> **Platform Version**: 1.1.0  
> **Author**: DevOps & Cloud Infrastructure Engineering Team

---

## 1. Architectural Overview

The **Attacker Container Isolation and Access Control** platform implements a dual-mode, pluggable container orchestration architecture. It allows administrators to toggle seamlessly between **Docker Engine** (via Dockerode) and **Kubernetes** (via `@kubernetes/client-node`) without modifying frontend clients or sacrificing security constraints.

```text
                               +-----------------------------+
                               |     SOC WEB DASHBOARD       |
                               | (http://localhost:3000/...) |
                               +-----------------------------+
                                              |
                                              | HTTP REST API
                                              v
                               +-----------------------------+
                               |      EXPRESS BACKEND        |
                               | (orchestrator/index.js:3000)|
                               +-----------------------------+
                                              |
                        +---------------------+---------------------+
                        |                                           |
                        v                                           v
         [ORCHESTRATOR_PROVIDER=docker]             [ORCHESTRATOR_PROVIDER=kubernetes]
         +----------------------------+             +-------------------------------+
         |       DockerProvider       |             |       KubernetesProvider      |
         | (Dockerode Client Library) |             |   (@kubernetes/client-node)   |
         +----------------------------+             +-------------------------------+
                        |                                           |
                        v                                           v
           Docker Daemon / Engine                     Kubernetes API Server (v1.36.1)
           - Bridge Networks                          - Namespace: attacker-lab
           - Direct Container Exec                    - ClusterIP Services
           - Custom JSON Seccomp                      - NetworkPolicies (CNI Ingress/Egress)
                                                      - Pod Exec API
```

---

## 2. Pluggable Provider Pattern

The backend routes decouple session management from the underlying virtualization runtime through a factory pattern (`orchestrator/providers/index.js`):

```text
               +--------------------------------------+
               |          Provider Interface          |
               +--------------------------------------+
               | + checkConnection()                  |
               | + createSession(sessionId)           |
               | + deleteSession(sessionId)           |
               | + getSession(sessionId)              |
               | + getActiveSessionsCount()           |
               | + listActiveContainers()             |
               | + executeCommand(sessionId, command) |
               +--------------------------------------+
                                   ^
                                   |
                  +----------------+----------------+
                  |                                 |
        +--------------------+            +--------------------+
        |   DockerProvider   |            | KubernetesProvider |
        +--------------------+            +--------------------+
```

### Provider Selection:
- Controlled by environment variable: `ORCHESTRATOR_PROVIDER=docker|kubernetes`.
- Defaults safely to `"docker"` if omitted or configured with an unknown value.
- Prevents service disruption and guarantees backward compatibility with existing Docker environments.

---

## 3. Kubernetes Namespace & Resource Topography

Each student laboratory session in Kubernetes operates within the dedicated **`attacker-lab`** namespace:

```text
+----------------------------------------------------------------------------------------------------+
| Namespace: attacker-lab                                                                            |
|                                                                                                    |
|    +-----------------------------+                    +------------------------------------+       |
|    | Attacker Pod                |                    | Target Deployment / Pod            |       |
|    | (attacker-<id>)             |                    | (target-<id>)                      |       |
|    |                             |                    |                                    |       |
|    | - Image: secure-attacker:1.0|                    | - Image: nginx:alpine              |       |
|    | - UID/GID: 1001:1001        |                    | - Port: 80 (HTTP)                  |       |
|    | - ReadOnlyRootfs: true      |                    | - ReadinessProbe: HTTP GET /       |       |
|    | - CapDrop: ALL              |                    | - Limits: 250m CPU, 128Mi RAM      |       |
|    | - CapAdd: NET_RAW           |                    +-----------------+------------------+       |
|    | - Seccomp: RuntimeDefault   |                                      ^                          |
|    | - Tmpfs: /tmp, /run, /work  |                                      |                          |
|    +--------------+--------------+                                      |                          |
|                   |                                                     |                          |
|                   | HTTP Port 80 (ALLOWED)                              |                          |
|                   +-----------------------------------------------------+                          |
|                   |                                                     |                          |
|                   v                                                     v                          |
|    +-----------------------------+                    +------------------------------------+       |
|    | NetworkPolicy: Attacker     |                    | NetworkPolicy: Target              |       |
|    | (isolate-attacker-<id>)     |                    | (isolate-target-<id>)              |       |
|    | - Ingress: DENY ALL         |                    | - Ingress: ALLOW ONLY Attacker <id>|       |
|    | - Egress: Kube-DNS (Port 53)|                    | - Egress: Default                  |       |
|    |   + Target <id> (Port 80)   |                    +------------------------------------+       |
|    +-----------------------------+                                                                 |
|                                                                                                    |
|    +-----------------------------+                                                                 |
|    | Target ClusterIP Service    |                                                                 |
|    | (target-<id>:80)            |                                                                 |
|    +-----------------------------+                                                                 |
|                                                                                                    |
|    +------------------------------------------------------------------------------------------+    |
|    | RBAC Least-Privilege Scope:                                                              |    |
|    | ServiceAccount: attacker-orchestrator-sa                                                 |    |
|    | Role: attacker-orchestrator-role (Pods, Deployments, Services, NetworkPolicies, Exec)   |    |
|    | Scope: Stricly namespaced to "attacker-lab" (Zero cluster-admin privileges)             |    |
|    +------------------------------------------------------------------------------------------+    |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. Workload Hardening Details

### 4.1 Attacker Pod (`attacker-<id>`)
- **Pod Security Standards (PSS)**: Configured with `enforce: privileged` (to admit `NET_RAW` capability) and `warn: baseline` / `audit: baseline`.
- **User Identity**: `runAsUser: 1001`, `runAsGroup: 1001`, `runAsNonRoot: true`, `fsGroup: 1001`.
- **Filesystem Lockdown**: `readOnlyRootFilesystem: true`. Writable paths are explicitly mounted as memory-backed `emptyDir` volumes:
  - `/tmp`: `medium: Memory`, `sizeLimit: 64Mi`
  - `/run`: `medium: Memory`, `sizeLimit: 16Mi`
  - `/home/student/work`: `medium: Memory`, `sizeLimit: 128Mi`
- **Capabilities**: Drops all default capabilities (`drop: ["ALL"]`) and retains only `NET_RAW` for authorized ICMP network diagnostics.
- **Syscall Filtering**: `seccompProfile: { type: RuntimeDefault }`.
- **Credential Protection**: `automountServiceAccountToken: false` prevents pod tokens from being mounted or exfiltrated.
- **Host Isolation**: `hostNetwork: false`, `hostPID: false`, `hostIPC: false`.

### 4.2 Target Workload (`target-<id>`)
- Runs `nginx:alpine` within a 1-replica Deployment.
- Exposes port 80 via an internal `ClusterIP` service.
- Retains minimal worker initialization capabilities (`CHOWN`, `SETUID`, `SETGID`, `NET_BIND_SERVICE`, `DAC_OVERRIDE`) while disallowing privilege escalation (`allowPrivilegeEscalation: false`).
- Does not expose any node ports or public LoadBalancers.

---

## 5. Network Isolation & Policy Matrix

| Source | Destination | Protocol / Port | Policy Status | Enforcement Mechanism |
|---|---|---|:---:|---|
| Attacker A | Target A (Assigned) | TCP 80 | **ALLOWED** | Ingress on Target A + Egress on Attacker A |
| Attacker A | Target B (Other Session) | TCP 80 | **BLOCKED** | NetworkPolicy drop (label mismatch) |
| Attacker A | CoreDNS / Kube-DNS | UDP/TCP 53 | **ALLOWED** | Attacker A Egress rule to `kube-system` |
| Attacker A | Public Internet (`1.1.1.1`) | Any | **BLOCKED** | Attacker A Egress default-deny |
| External Host | Target A | Any | **BLOCKED** | ClusterIP + Ingress NetworkPolicy |
| Target A | Attacker A | Any | **BLOCKED** | Attacker A Ingress default-deny |
