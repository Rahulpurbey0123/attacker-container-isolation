# Changelog

All notable features and milestones of the **Attacker Container Isolation and Access Control** platform are documented in this file.

---

## [1.2.0] — Security Hardening, Audit Remediation & Test Correctness

### Fixed & Hardened (Audit Remediations)
* **API Authentication & Exposure (Finding 1.1)**:
  * Bound Express server explicitly to `127.0.0.1` (`HOST = process.env.HOST || "127.0.0.1"`).
  * Documented unauthenticated API as local-demo-only; specified production requirement for authentication (OAuth2/OIDC/mTLS) and per-session authorization.
* **Pod Security Standards (PSS) Hardening (Finding 1.2)**:
  * Replaced `enforce: privileged` with `pod-security.kubernetes.io/enforce: baseline`, `audit: restricted`, and `warn: restricted` on `attacker-lab` namespace.
  * Eliminated `NET_RAW` from Kubernetes attacker pod specification to strictly adhere to PSS Baseline admission policy without bypasses.
  * Documented capability trade-off and confirmed all manifests pass both client-side and server-side dry-run validation.
* **Effective Kubernetes RBAC Identity (Finding 1.3)**:
  * Implemented dedicated least-privilege kubeconfig support in `KubernetesProvider` via `K8S_KUBECONFIG` / `KUBECONFIG` and `orchestrator/scripts/generate-sa-kubeconfig.js`.
  * Verified that operations run under `attacker-orchestrator-sa` and that out-of-namespace and cluster-level operations (such as listing nodes) are strictly forbidden by RBAC.
* **Network Isolation Test Correctness (Finding 2.1)**:
  * Corrected `verify-kubernetes-security.js` to establish positive reachability controls before asserting cross-session isolation.
  * Added active readiness polling on probe workloads; inconclusive or failed probe starts are marked `BLOCKED`, never `PASS`.
  * Distinguish blocked external egress from container exec failures or missing tools (`curl`).
* **Command Gateway Shared Validator (Finding 2.2)**:
  * Extracted command validation into shared module `orchestrator/security/validator.js`, eliminating duplicate regexes across test suites and backend.
  * Validated shell chaining, prohibited package managers (`apt`, `pip`, `git clone`), and allowed commands across both unit tests and live API requests.
* **Audit & Seccomp Test Correctness (Finding 2.3)**:
  * Updated audit tests to verify that a new, valid JSONL audit event is written and parses correctly for a test action, rather than merely checking file existence.
  * Separated Seccomp spec configuration check (`RuntimeDefault`) from runtime kernel enforcement evidence (`/proc/1/status` Seccomp filter mode 2).
* **Session ID Validation (Finding 3.1)**:
  * Enforced Kubernetes DNS-1123 label format (`/^[a-z0-9]([-a-z0-9]{0,48}[a-z0-9])?$/`) on all create, get, execute, delete, and event operations, rejecting invalid IDs with HTTP 400 Bad Request.
* **Safe Resource Deletion & Partial Rollback (Finding 3.2)**:
  * Enforced session ownership label checks before deleting resources.
  * Refactored delete handlers to only ignore confirmed 404 NotFound errors and propagate all other API/permission errors.
  * Ensured partial session creation tracks created resources and rolls back only those resources created by that specific invocation.
  * Confirmed resources are deleted before returning success.
* **Command Execution Timeouts & Limits (Finding 3.3)**:
  * Enforced bounded 10-second execution timeouts and 64KB maximum output limits across both Kubernetes and Docker providers, returning HTTP 408 on timeout.
* **Clean Source Packaging (Finding 4.1)**:
  * Created `scripts/package-clean-zip.ps1` to produce clean shareable ZIP archive (151 KB) excluding `.git/`, `node_modules/`, and temporary files without deleting them from the working project.
* **Dependency & Documentation Accuracy (Finding 4.2)**:
  * Maintained strict consistency between `package.json` and `package-lock.json`.
  * Updated all technical documentation with live-verified test results.

---

## [1.1.0] — Kubernetes Orchestration Extension


### Added Features & Capabilities
* **Dual-Mode Pluggable Orchestration Layer**:
  * Implemented pluggable provider architecture with `DockerProvider` and `KubernetesProvider`.
  * Configurable via `ORCHESTRATOR_PROVIDER=docker|kubernetes` with safe automatic fallback to Docker.
  * Added `@kubernetes/client-node` integration with strict least-privilege namespaced permissions.
* **Declarative Kubernetes Security Manifests (`kubernetes/`)**:
  * `namespace.yaml`: Hardened `attacker-lab` namespace with Pod Security Standards (`enforce: privileged`, `warn: baseline`).
  * `attacker-pod.yaml`: Hardened attacker pod specification (non-root UID/GID 1001, read-only rootfs, `allowPrivilegeEscalation: false`, dropped capabilities, `NET_RAW` retention, RuntimeDefault Seccomp, and memory-backed `emptyDir` tmpfs).
  * `target-deployment.yaml`: Target Nginx deployment with health probes, non-root worker capabilities, and resource bounds.
  * `target-service.yaml`: Internal ClusterIP service exposing target without public ingress.
  * `network-policy.yaml`: Strict ingress isolation and egress restrictions enforcing multi-tenant boundaries.
  * `rbac.yaml`: Least-privilege Role and ServiceAccount (`attacker-orchestrator-sa`) scoped to `attacker-lab`.
  * `kustomization.yaml`: Unified Kustomize configuration bundle.
* **Automated Kubernetes Security Verification Suite**:
  * Added 16-point automated security verification harness (`orchestrator/security-tests/verify-kubernetes-security.js`).
  * Automated JSON audit report saved to `orchestrator/security-tests/results/kubernetes-security-report.json` with 16/16 tests passing.
* **SOC Dashboard Telemetry Extension**:
  * Added active provider pill (`PROVIDER: DOCKER` / `PROVIDER: KUBERNETES`) in header telemetry bar.
  * Integrated multi-provider container and active session telemetry.
* **Comprehensive Kubernetes Documentation**:
  * `KUBERNETES_SETUP.md`, `KUBERNETES_ARCHITECTURE.md`, `KUBERNETES_SECURITY.md`, `KUBERNETES_DEMO_GUIDE.md`, `KUBERNETES_TROUBLESHOOTING.md`, and `KUBERNETES_INTEGRATION_PLAN.md`.

---

## [1.0.0] — Initial Docker Implementation

### Added Features & Capabilities
* **Isolated Multi-Tenant Session Orchestration**:
  * Dynamic creation of isolated student laboratory environments via `POST /sessions`.
  * Dedicated per-session internal Docker bridge networks (`session-<sessionId>-net`).
  * Automated provisioning of target containers (`nginx:alpine`) bound strictly to the session's internal network.
  * Session status inspection (`GET /sessions/:sessionId`) and safe teardown (`DELETE /sessions/:sessionId`).
* **Hardened Attacker Container**:
  * Custom `secure-attacker:1.0` image based on Ubuntu 24.04 with pre-baked network tools (`curl`, `ping`).
  * Enforced non-root user execution (`USER student`, UID/GID `1001:1001`).
  * Locked read-only root filesystem (`ReadonlyRootfs: true`).
  * Scoped, size-capped, non-executable tmpfs mounts for `/tmp` (64MB), `/run` (16MB), and `/home/student/work` (128MB).
* **System Call & Capability Restriction**:
  * Stripped all default Linux kernel capabilities (`CapDrop: ["ALL"]`) with minimal `CapAdd: ["NET_RAW"]` retained for ICMP network diagnostics.
  * Custom Seccomp profile blocking dangerous system calls (`mount`, `pivot_root`, `reboot`, `init_module`, `ptrace`, `setns`, `unshare`, etc.).
* **Network-Level Access Controls**:
  * Docker bridge network isolation configured with `Internal: true` to prevent public Internet egress and data exfiltration.
  * Cross-session network isolation preventing unauthorized lateral communication across student environments.
* **Command Execution Gateway**:
  * REST API endpoint (`POST /sessions/:sessionId/execute`) providing filtered command execution.
  * Blocking of package management utilities (`apt`, `apt-get`, `pip`, `pip3`).
  * Blocking of repository cloning (`git clone`).
  * Blocking of shell chaining and redirection syntax (`;`, `&&`, `||`, `|`, `` ` ``, `$()`, `>`, `<`).
  * Approved command allowlist enforcement (`id`, `whoami`, `pwd`, `ls`, `cat`, `getent hosts`, `ping`, `curl`).
* **Structured Security Auditing & Logging**:
  * Line-delimited JSON audit logs recording all lifecycle actions to `orchestrator/logs/audit.log`.
  * Real-time security event ingestion (`POST /sessions/:sessionId/events`) and logging to `orchestrator/logs/security-events.log`.
  * Severity classification support (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **Security Operations Center (SOC) Dashboard**:
  * Web interface served at `/dashboard-ui/` with real-time telemetry polling every 5 seconds.
  * Dynamic student session management panel with one-click `+ CREATE NEW SESSION` action and clipboard-enabled terminal connection command generator.
  * Telemetry metric cards for Active Sessions, Total Events, Blocked Events, Allowed Events, and High/Critical violations.
  * Real-time Security Severity distribution progress bars and live Recent Security Events table.
* **Automated Security Verification**:
  * Automated 8-point security verification script (`orchestrator/security-tests/verify-security.js`) confirming non-root execution, read-only rootfs, dropped capabilities, package blocks, target reachability, cross-session isolation, and Seccomp attachment.
  * Automated JSON audit report persistence to `orchestrator/security-tests/results/security-report.json`.
