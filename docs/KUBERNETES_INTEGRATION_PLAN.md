# Kubernetes Integration Plan

> **Project**: Attacker Container Isolation and Access Control  
> **Target Environment**: Windows 11, Docker Desktop (Kubernetes enabled, v1.36.1, `desktop-control-plane` node), Node.js/Express, `@kubernetes/client-node`.  
> **Status**: Phase 1 Planning & Architectural Specification

---

## 1. Executive Summary & Goals

The objective of this project extension is to introduce **Kubernetes** as an enterprise-grade container orchestration layer alongside the existing working **Docker** orchestration engine.

### Core Objectives:
1. **Preserve Docker Compatibility**: Retain 100% of the working Docker functionality (`DockerOrchestrator`), keeping Docker as the default runtime (`ORCHESTRATOR_PROVIDER=docker`).
2. **First Verify Manifests Standalone**: Fix the previous `Invalid JSON Patch` manifest failure by deploying valid, production-grade Kubernetes YAML manifests in the `attacker-lab` namespace and verifying pod health, security constraints, and network reachability *before* integrating into the Node.js backend.
3. **Pluggable Orchestration Architecture**: Provide a clean provider abstraction (`DockerOrchestrator` and `KubernetesOrchestrator`) selectable via configuration (`ORCHESTRATOR_PROVIDER`).
4. **Parity of Security Controls**: Replicate all 8 container security controls (non-root UID 1001, read-only root filesystem, dropped capabilities, `NET_RAW` retention, Seccomp syscall filtering, ephemeral memory mounts, command gateway allowlisting/blocking, and audit logging).
5. **Truthful NetworkPolicy Verification**: Rigorously test and report whether Docker Desktop's active CNI (`kindnetd`) enforces Kubernetes `NetworkPolicy` objects, adhering to Rule 14 (mark BLOCKED/NOT VERIFIED if CNI lacks enforcement).
6. **Unified SOC Dashboard**: Display real-time telemetry, provider status, cluster connectivity, and container/pod statuses without breaking the existing UI.
7. **Comprehensive Documentation & Testing**: Deliver dedicated Kubernetes security tests outputting to `orchestrator/security-tests/results/kubernetes-security-report.json` without altering the existing Docker report.

---

## 2. Existing Architecture Audit

### 2.1 Component Overview
* **Root Dockerfile**: Builds Ubuntu 24.04 attacker image with tools (`curl`, `iputils-ping`, `ca-certificates`), non-root user `student` (`1001:1001`), and workspace `/home/student/work`.
* **Orchestrator Backend (`orchestrator/index.js`)**:
  * Express server on port 3000 using `dockerode`.
  * Dynamic session creation (`POST /sessions`): generates `sessionId`, provisions private bridge network `session-<id>-net` (`Internal: true`), deploys target container `target-<id>` (`nginx:alpine`), and deploys hardened attacker `attacker-<id>` (`secure-attacker:1.0`).
  * Command Gateway (`POST /sessions/:sessionId/execute`): enforces shell chaining blocking, package management blocking (`apt`, `pip`), Git clone blocking, and strict command regex allowlist (`id`, `whoami`, `pwd`, `ls`, `cat`, `getent hosts`, `ping`, `curl`).
  * Logging (`orchestrator/logger.js`): line-delimited JSON audit logs (`audit.log`) and security event logs (`security-events.log`).
  * Background Monitoring (`orchestrator/security-monitor.js`): periodic shell history inspection for disallowed operations.
  * Static Web Dashboard (`dashboard/`): dark-mode SOC UI with live metrics, session cards, clipboard commands, and security event tables.
* **Security Verification (`orchestrator/security-tests/verify-security.js`)**:
  * 8-point automated test suite verifying non-root, read-only rootfs, dropped capabilities, `NET_RAW`, package manager blocking, target reachability, cross-session isolation, and Seccomp attachment.

---

## 3. Kubernetes Architecture & Security Mapping

### 3.1 Security Control Comparison  Matrix

| Docker Control (Existing) | Kubernetes Equivalent (Target) | Implementation Details |
|---|---|---|
| **Non-root user** (`1001:1001`) | `securityContext.runAsUser: 1001`, `runAsGroup: 1001`, `runAsNonRoot: true` | Defined at pod and container level |
| **Read-only rootfs** (`ReadonlyRootfs: true`) | `securityContext.readOnlyRootFilesystem: true` | Enforced on container specification |
| **Privilege Escalation** (`no-new-privileges`) | `securityContext.allowPrivilegeEscalation: false` | Explicitly disables `setuid`/`setgid` privilege gains |
| **Drop Capabilities** (`CapDrop: ["ALL"]`) | `securityContext.capabilities.drop: ["ALL"]` | Drops all Linux kernel capabilities |
| **Linux capabilities** (`CapDrop: ["ALL"]`, `CapAdd: ["NET_RAW"]` in Docker) | `securityContext.capabilities.drop: ["ALL"]`, with no capabilities added in the attacker manifest | Kubernetes attacker capabilities are stricter than Docker; raw-socket operations requiring `NET_RAW` are not enabled by the manifest |
| **Seccomp Profile** | `securityContext.seccompProfile.type: RuntimeDefault` | Enforces runtime default seccomp profile; custom profile requires node filesystem staging |
| **Ephemeral Writable Storage** (`Tmpfs`) | `emptyDir` volumes with `medium: Memory` | Mounted at `/tmp` (64Mi), `/run` (16Mi), `/home/student/work` (128Mi) |
| **Network Isolation** (`Internal: true` bridge) | Kubernetes `NetworkPolicy` objects | Ingress/Egress rules isolating session pods |
| **Resource Limits** | `resources.requests` & `resources.limits` | CPU (100m/500m) and Memory (64Mi/256Mi) |
| **No Host Exposure** | Pod spec hardening | No `hostNetwork`, no `hostPID`, no `hostIPC`, no `hostPath` |
| **Service Account Token** | `automountServiceAccountToken: false` | Prevents credential exfiltration from compromised pods |
| **Command Gateway** | Kubernetes Pod Exec API | Preserves identical regex validation gateway and audit logging |

### 3.2 Network Isolation & CNI Evaluation
* **Current Cluster CNI**: `kindnetd` (`docker.io/kindest/kindnetd:v20260528-9350166c`) running on `desktop-control-plane`.
* **CNI Capabilities**: Standard `kindnet` provides basic IPAM and routing. While newer nftables-based kindnet versions have partial experimental NetworkPolicy support, many Docker Desktop kind installations do not enforce `NetworkPolicy` resources without Calico/Cilium.
* **Testing Protocol**:
  1. Define explicit `NetworkPolicy` manifests for session isolation.
  2. Execute real network tests between attacker and assigned target, and cross-session targets.
  3. If cross-session traffic is not dropped by the network layer, explicitly record the test as `BLOCKED` / `NOT VERIFIED` due to CNI limitations, rather than falsely claiming isolation.

---

## 4. Kubernetes Manifest Specifications (`kubernetes/`)

The following declarative manifests will be created in the `kubernetes/` directory:

1. `namespace.yaml`: Defines `attacker-lab` namespace with isolation labels.
2. `attacker-pod.yaml`: Standalone deployment/pod manifest using `secure-attacker:1.0`, non-root security context, dropped capabilities, memory `emptyDir` mounts, and resource bounds.
3. `target-deployment.yaml`: Minimal `nginx:alpine` deployment (1 replica) with resource limits and readiness probe.
4. `target-service.yaml`: Internal `ClusterIP` service exposing port 80 to the attacker within the cluster.
5. `network-policy.yaml`: Default deny ingress/egress, allow intra-session target communication, and allow cluster DNS (UDP/TCP 53) to kube-dns/coredns.
6. `kustomization.yaml`: Aggregates all manifests for easy review and application.

---

## 5. Backend Orchestration Integration Plan

### 5.1 Architecture & Provider Pattern
A clean provider abstraction will be introduced in `orchestrator/`:
* `orchestrator/providers/docker-provider.js`: Encapsulates existing Dockerode logic.
* `orchestrator/providers/k8s-provider.js`: Implements `@kubernetes/client-node` operations using CoreV1Api, AppsV1Api, and Exec APIs.
* `orchestrator/providers/index.js`: Factory returning the active provider based on `process.env.ORCHESTRATOR_PROVIDER || "docker"`.

### 5.2 RBAC & Least Privilege
The backend will communicate with Kubernetes using standard in-cluster or kubeconfig credentials (`~/.kube/config`, context `docker-desktop`).
* Target namespace: `attacker-lab`.
* Permissions scoped strictly to Pods (get, list, create, delete, exec), Services, and NetworkPolicies within `attacker-lab`.

### 5.3 API Compatibility Preservation
All existing REST endpoints remain fully backward-compatible:
* `GET /`: Health check + provider identification.
* `GET /docker`: Existing Docker status check (preserved).
* `GET /k8s`: Kubernetes cluster and node status check (added).
* `GET /dashboard`: Aggregates metrics from the active provider.
* `GET /security-summary`: Unchanged event reporting.
* `POST /sessions`: Provisions session in the active provider.
* `GET /sessions/:sessionId`: Inspects session status in the active provider.
* `DELETE /sessions/:sessionId`: Tears down session resources safely.
* `POST /sessions/:sessionId/execute`: Validates command against gateway regexes and runs via container exec or pod exec.

---

## 6. Implementation Phases & Phased Rollout

```
+-----------------------------------------------------------------------------+
| Phase 1: Repository Audit & Integration Plan (COMPLETED)                    |
| - Inspect codebase, verify Docker functionality and cluster state           |
| - Author docs/KUBERNETES_INTEGRATION_PLAN.md                                |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 2: YAML Manifests & Verification (FIRST CRITICAL MILESTONE)           |
| - Create kubernetes/*.yaml manifests                                        |
| - Validate syntax (dry-run) and inspect local image availability            |
| - Deploy to attacker-lab, verify Pod status, security context, connectivity |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 3: Security Controls & CNI Verification                               |
| - Test non-root, read-only rootfs, capabilities, package manager block       |
| - Test target reachability, test NetworkPolicy enforcement                  |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 4 & 5: Backend Provider & Session Lifecycle                           |
| - Add @kubernetes/client-node dependency                                    |
| - Implement KubernetesOrchestrator provider                                 |
| - Connect session lifecycle and command gateway                             |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 6: Dashboard Telemetry Extension                                      |
| - Display active provider (Docker / Kubernetes)                             |
| - Show cluster connectivity and workload health                             |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 7: Testing & Verification                                             |
| - Run Docker verification (ensure zero regressions)                         |
| - Execute Kubernetes security verification suite                            |
| - Persist results to orchestrator/security-tests/results/                   |
|   kubernetes-security-report.json                                           |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 8: Documentation & Final Report                                       |
| - Update root README.md, write SETUP, ARCHITECTURE, SECURITY docs           |
+-----------------------------------------------------------------------------+
```

---

## 7. Acceptance Criteria

1. **Docker Unbroken**: Existing Docker test suite runs and achieves 8/8 PASS.
2. **Kubernetes Workload Verified**: Attacker and Target Pods deploy in `attacker-lab` without `Invalid JSON Patch` or startup errors.
3. **Security Constraints Enforced**: Non-root UID 1001, read-only rootfs, dropped capabilities, and blocked package installation verified via live execution.
4. **Network Isolation Evaluated**: Intra-session target connectivity verified; cross-session isolation verified or limitations accurately reported without false claims.
5. **Least-Privilege Backend**: Node.js orchestrator successfully creates and cleans up Kubernetes sessions without requiring cluster-admin privileges.
6. **Command Gateway Intact**: Regex allowlist and shell chaining rules block prohibited operations in Kubernetes pods identically to Docker containers.
7. **Accurate Reporting**: Separate `kubernetes-security-report.json` generated documenting all test cases, evidence, and verdicts.
8. **No Secret Leakage**: No credentials, tokens, or private configurations exposed in source files, logs, or documentation.
