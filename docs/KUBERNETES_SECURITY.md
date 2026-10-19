# Kubernetes Security Controls & Threat Mitigation Guide

> **Project**: Attacker Container Isolation & Access Control  
> **Platform Version**: 1.2.0 (Hardened & Audited)  
> **Security Classification**: Defense-in-Depth Specification

---

## 1. Security Control Mapping & Comparison

The following table provides an exhaustive technical mapping between Docker and Kubernetes security implementations across the platform:

| Security Domain | Existing Docker Control | Kubernetes Implementation | Threat Mitigated |
|---|---|---|---|
| **User Identity** | `User: "1001:1001"` | `runAsUser: 1001`, `runAsGroup: 1001`, `runAsNonRoot: true` | Container breakout via root kernel privilege abuse |
| **Filesystem Lockdown** | `ReadonlyRootfs: true` | `securityContext.readOnlyRootFilesystem: true` | Runtime malware persistence, rootkit installation |
| **Privilege Escalation** | `no-new-privileges` | `securityContext.allowPrivilegeEscalation: false` | SUID/SGID binary exploitation (`NoNewPrivs: 1`) |
| **Capability Dropping** | `CapDrop: ["ALL"]`, `CapAdd: ["NET_RAW"]` | `capabilities.drop: ["ALL"]` (no added caps) | Host kernel device tampering (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) |
| **Pod Security Standards** | N/A (Docker Engine) | `pod-security.kubernetes.io/enforce: baseline`, `audit: restricted` | Namespace-level admission prevention of privileged workloads |
| **Syscall Filtering** | Custom Seccomp JSON profile | `seccompProfile.type: RuntimeDefault` (Mode 2) | Blocks dangerous syscalls (`mount`, `ptrace`, `unshare`, etc.) |
| **Ephemeral Storage** | Docker Tmpfs mounts | `emptyDir` volumes with `medium: Memory` | Memory exhaustion (sizeLimit: 64Mi/16Mi/128Mi) |
| **Session Isolation** | `Internal: true` bridge network | Ingress & Egress `NetworkPolicy` objects | Lateral cross-student attacks and reconnaissance |
| **Egress Filtering** | Docker bridge routing drop | NetworkPolicy default-deny egress | C2 communication and sensitive data exfiltration |
| **Service Tokens** | N/A (Docker daemon) | `automountServiceAccountToken: false` | Kubernetes API credential theft and privilege escalation |
| **Command Gateway** | Shared regex validation module | Shared validator module via Pod Exec | Arbitrary shell injection, package management, chaining |
| **Execution Limits** | 10s timeout, 64KB max output | 10s timeout, 64KB max output | Resource exhaustion, hanging requests, buffer overflows |
| **Audit Trails** | Line-delimited JSON logs | Validated JSONL audit & security logs | Forensics, repudiation defense, SOC alerting |

---

## 2. In-Depth Technical Analysis of Key Security Controls

### 2.1 Pod Security Standards (PSS) & Capability Hardening

In Kubernetes v1.25+, the **Pod Security Admission** controller enforces three built-in profiles:
1. **Privileged**: Unrestricted execution.
2. **Baseline**: Minimally restrictive policy preventing known privilege escalations (disallows privileged pods, hostPID/hostNetwork/hostIPC, hostPath mounts, and non-default capability additions).
3. **Restricted**: Heavily hardened policy adhering to Pod hardening best practices.

#### Admission Hardening & Capability Trade-off:
In earlier iterations, the namespace was labeled with `pod-security.kubernetes.io/enforce: privileged` because the attacker container included `capabilities.add: ["NET_RAW"]`, which the Baseline admission controller rejected.

**Remediation**:
1. In accordance with the security audit findings, `pod-security.kubernetes.io/enforce: baseline` is now strictly enforced, with `audit: restricted` and `warn: restricted` configured in `kubernetes/namespace.yaml`.
2. `NET_RAW` has been eliminated from the Kubernetes attacker workload (`capabilities: { drop: ["ALL"] }`).
3. **Documented Trade-Off**: Raw socket creation (`SOCK_RAW`) is disallowed in Kubernetes, strictly satisfying the Baseline Pod Security Standard at admission time. Standard unprivileged diagnostic tools (e.g. `curl`, `id`, `whoami`, `cat`, `ls`) and unprivileged ICMP sockets function cleanly, while lateral exfiltration and raw packet crafting are completely prevented at the kernel capability boundary.

```yaml
# kubernetes/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: attacker-lab
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

---

### 2.2 Filesystem Immutability & Package Management Prevention

A critical project objective is preventing students from installing unvetted compilers, rootkits, or reconnaissance packages (`apt-get install`, `pip install`).

#### Multi-Tier Defense:
1. **Container Filesystem Layer**: Setting `readOnlyRootFilesystem: true` locks `/usr`, `/lib`, `/bin`, `/etc`, and `/var`. When a student attempts `apt-get update`, the package manager fails with:
   ```text
   Reading package lists...
   E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)
   Exit code: 100
   ```
2. **Command Gateway Layer**: The orchestrator's shared validator module (`orchestrator/security/validator.js`) intercepts all incoming commands *before* sending them to the container or pod:
   ```javascript
   pattern: /\b(?:apt|apt-get)\s+(?:update|install|upgrade|remove|purge|autoremove)\b/i
   action: "APT_COMMAND"
   result: "BLOCKED" (HTTP 403)
   ```
This provides defense-in-depth: even if a student attempts to bypass the gateway, the kernel filesystem layer rejects any write operations.

---

### 2.3 NetworkPolicy Multi-Tenant Isolation via CNI

Kubernetes NetworkPolicies enforce multi-tenant micro-segmentation:
1. **Intra-Session Connectivity**: Attacker can only access the Nginx target belonging to its exact same session (`app=target-nginx, session=<id>`).
2. **Cross-Session Isolation**: Attacker traffic to target pods in other sessions is rejected by both ingress and egress NetworkPolicies.
3. **External Internet Egress**: External internet traffic (e.g. `http://1.1.1.1`) is blocked by default-deny egress policies.
4. **Positive Controls in Testing**: Verification tests confirm probe workloads reach `Ready` before interpreting failed connections as proof of isolation, eliminating false passes.

---

### 2.4 Least-Privilege RBAC Identity

The orchestrator interacts with Kubernetes using a dedicated ServiceAccount (`attacker-orchestrator-sa`) bound to `attacker-orchestrator-role` in `kubernetes/rbac.yaml`:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create", "get"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "create", "delete"]
```

#### Security Guarantees:
- **No Cluster-Admin**: Constrained strictly to `attacker-lab`.
- **No Secret Access**: Cannot read secrets, configmaps, or node tokens.
- **No Node or Cluster Resource Access**: Cannot inspect or modify nodes, cluster roles, or other namespaces (`default`, `kube-system`).
- **Dedicated Kubeconfig Generator**: `npm run generate-sa-kubeconfig` builds `kubernetes/orchestrator-kubeconfig.yaml` using a temporary ServiceAccount token, ensuring live operations and verification tests run under the least-privilege identity.

---

### 2.5 API Exposure & Local Demonstration Limitation

- **Explicit Host Binding**: The Express API binds to `127.0.0.1` (`HOST = process.env.HOST || "127.0.0.1"`).
- **Session ID Validation**: Session identifiers are validated against Kubernetes DNS-1123 label standards (`^[a-z0-9]([-a-z0-9]{0,48}[a-z0-9])?$`).
- **Safe Cleanup & Rollback**: Resource deletion checks session ownership labels and confirms deletion before reporting success. Partial provisioning failures roll back only resources created by that invocation.
- **Command Timeouts & Limits**: 10-second bounded execution timeout (HTTP 408) and 64KB output limit prevent hung connections and memory exhaustion.
- **Production Requirement**: Before exposing this platform on a multi-user network, an external authentication gateway (OAuth2/OIDC/mTLS) and per-session authorization layer must be placed in front of the API.
