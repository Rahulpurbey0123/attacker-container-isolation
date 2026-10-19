# Security Review & Remediation Report

**Project:** Attacker Container Isolation and Access Control  
**Target Directory:** `C:\Users\rahul\secure-attacker`  
**Review Period:** October 2026  
**Auditor / Reviewer:** Senior Application-Security, Docker, Kubernetes & Node.js Reviewer  
**Status:** All Critical and High Priority Findings REMEDIATED & VERIFIED  

---

## Executive Summary

A comprehensive application security, container runtime, Kubernetes architecture, and test suite audit was conducted on the **Attacker Container Isolation and Access Control** project. The project provides an isolated multi-tenant execution sandbox utilizing Docker and Kubernetes runtimes, governed by an Express-based orchestrator API, command validation gateway, network policies, and audit logging.

Prior to remediation, the codebase contained critical vulnerabilities, packaging defects, and test verification issues:
1. **P0 Credential & Packaging Defect:** Previous archives reached approximately 13.1 MiB due to the inclusion of `.git/`, `orchestrator/node_modules/`, `kubernetes/orchestrator-kubeconfig.yaml`, backup files (`index.js.bak`), and runtime logs. A generated kubeconfig containing a long-lived ServiceAccount bearer token was present in source archives.
2. **P0 API Exposure:** The orchestrator API bound to `0.0.0.0` by default without authentication or per-session authorization.
3. **P0 Privilege Escalation:** The Kubernetes namespace bypassed Pod Security Admission using `enforce: privileged`, and the provider defaulted to cluster-admin credentials if available.
4. **P1 Validation Gaps:** Session IDs were not validated uniformly against Kubernetes RFC 1123 DNS label constraints; command gateway validation was bypassed on certain routes; prohibited shell chaining and subshells were not consistently blocked.
5. **P1 Test Inaccuracies:** Security test suites reported `PASS` when probe containers were unready or failed, lacked positive controls, duplicated validation logic rather than exercising the live gateway, and conflated manifest declarations with runtime seccomp enforcement.
6. **P1 Resource Lifecycle Defects:** Deletion operations failed to check resource ownership labels, swallowed unexpected API errors, and partial creation failures resulted in orphaned resources.
7. **P1 Unbounded Execution:** Command execution lacked hard timeouts and output buffering caps, exposing the orchestrator to resource exhaustion and hanging sockets.

All eleven identified findings have been systematically resolved and verified by automated regression tests across API, Docker, and Kubernetes environments.

---

## Detailed Findings and Remediation

### Finding 1.1: ServiceAccount Token Exposure, Credential Management & Packaging Defect
- **Severity:** Critical (P0)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `kubernetes/orchestrator-kubeconfig.yaml`
  - `.gitignore`
  - `scripts/package-clean-zip.ps1`
  - `orchestrator/scripts/generate-sa-kubeconfig.js`
- **Root Cause & Packaging Defect Analysis:**
  Previous packaging attempts generated an archive of ~13.1 MiB. Investigation revealed that naive CLI `tar.exe` exclude arguments on Windows failed to recurse into subdirectories (e.g., `--exclude=node_modules` only matched top-level items, ignoring `orchestrator\node_modules`; `--exclude=orchestrator-kubeconfig.yaml` ignored `kubernetes\orchestrator-kubeconfig.yaml`; `--exclude=*.bak` missed `orchestrator\index.js.bak`). As a result, `.git/`, `node_modules/`, sensitive runtime logs (`orchestrator/logs/*.log`), and generated kubeconfigs with bearer tokens leaked into the package.
- **Remediation Action:**
  1. **Token Invalidation & Rotation:** The ServiceAccount `attacker-orchestrator-sa` in the `attacker-lab` namespace was deleted and recreated. Because Kubernetes validates bound tokens against the ServiceAccount's cryptographic `metadata.uid`, recreating the SA permanently invalidated all previous tokens. A new least-privilege token was generated into `kubernetes/orchestrator-kubeconfig.yaml`.
  2. **Git Ignore Protection:** Updated `.gitignore` with comprehensive patterns covering `*kubeconfig*.yaml`, `*.env*`, `*.token`, `*.key`, `*.pem`, `*.bak`, `*.tmp`, and runtime logs.
  3. **Robust Staging Packager (`scripts/package-clean-zip.ps1`):** Redesigned the packaging pipeline into a 6-stage process:
     - **Stage 1 (Target Validation):** Confirms destination ZIP is located outside the project directory.
     - **Stage 2 (Isolated Staging):** Traverses the repository and copies ONLY allowed source files into an isolated temporary staging directory, filtering out 6,100+ unwanted files (`node_modules/`, `.git/`, `*.bak`, `*.log`, `*.yaml` kubeconfigs, keys, and tokens).
     - **Stage 3 (Pre-Packaging Credential Scan):** Scans all staged text files (`.js`, `.json`, `.yaml`, `.md`, `.html`, etc.) for private keys, kubeconfig tokens, and JWT bearer tokens. Aborts immediately if any secret pattern is found.
     - **Stage 4 (Deterministic Compression & Size Gate):** Compresses the clean staging directory with optimal compression. Enforces a strict 5 MB maximum size gate (the clean archive is ~152 KB; anything near 13 MB fails immediately).
     - **Stage 5 (Post-Packaging Inspection):** Reads the generated ZIP entries using `[System.IO.Compression.ZipFile]` to ensure 0 entries match `.git/`, `node_modules/`, `kubeconfig`, `.bak`, `.log`, `.key`, `.pem`, or `.env`. Verifies all 14 essential core files are present.
     - **Stage 6 (Extraction & Integrity Gate):** Extracts the archive into a separate temporary directory and runs `node --check` on extracted JavaScript files to guarantee operational integrity.
- **Verification:**
  - `tar -tf C:\Users\rahul\secure-attacker.zip | findstr /i "kubeconfig token .env key git node_modules"` produced 0 matches.
  - Final archive size: **152.41 KB (156,066 bytes)**.
  - Extraction and AST syntax validation passed with 0 errors.

---

### Finding 1.2: Orchestrator API Network Exposure & Missing Scope Boundary
- **Severity:** High (P0)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/index.js`
  - `README.md`
  - `docs/API.md`
- **Vulnerability Analysis:**
  The Express orchestrator listened on `0.0.0.0` (all network interfaces). Because the API does not enforce mutual TLS, API keys, or user session authorization, any client on the local network could create pods, run commands, or delete resources.
- **Remediation Action:**
  1. Modified `orchestrator/index.js` to bind explicitly to `127.0.0.1` by default:
     ```javascript
     const HOST = process.env.HOST || "127.0.0.1";
     app.listen(PORT, HOST, () => ...);
     ```
  2. Prominently documented across `README.md` and API docs that this service is an unauthenticated local demonstration and must not be exposed to untrusted networks or multi-tenant production without an authentication/authorization proxy.
- **Verification:**
  - `GET http://127.0.0.1:3000/` returns `200 OK` with `boundHost: "127.0.0.1"`.
  - Process binding confirmed on loopback interface only.

---

### Finding 1.3: Kubernetes Provider Least-Privilege RBAC Identity
- **Severity:** High (P0)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/providers/k8s-provider.js`
  - `kubernetes/rbac.yaml`
- **Vulnerability Analysis:**
  The Kubernetes provider relied on default `@kubernetes/client-node` discovery, which loaded the host user's cluster-admin kubeconfig if `KUBECONFIG` was unset. This allowed the orchestrator to execute privileged cluster-wide actions outside `attacker-lab`.
- **Remediation Action:**
  1. Updated `k8s-provider.js` to explicitly load `kubernetes/orchestrator-kubeconfig.yaml` (the dedicated least-privilege configuration) or check for in-cluster ServiceAccount credentials before falling back to default config.
  2. Verified `attacker-orchestrator-role` in `kubernetes/rbac.yaml` restricts permissions strictly to namespace `attacker-lab` for pods, services, networkpolicies, and pod/exec.
- **Verification:**
  - Tested live provider identity with dedicated kubeconfig:
    - `kubectl auth can-i create pods -n attacker-lab` -> `yes` (exit 0)
    - `kubectl auth can-i create pods -n kube-system` -> `no` (exit 1)
    - `kubectl auth can-i get nodes` -> `no` (exit 1)
  - Provider logs confirm initialization with dedicated ServiceAccount identity.

---

### Finding 2.1: Pod Security Admission (PSA) Baseline Compliance & Dropped Capabilities
- **Severity:** High (P1)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `kubernetes/namespace.yaml`
  - `kubernetes/attacker-pod.yaml`
  - `orchestrator/providers/k8s-provider.js`
  - `docs/KUBERNETES_SECURITY.md`
- **Vulnerability Analysis:**
  `kubernetes/namespace.yaml` configured `pod-security.kubernetes.io/enforce: privileged`, bypassing Kubernetes 1.25+ Pod Security Standards. The attacker pod manifest requested `NET_RAW` capability, which violates PSS Baseline.
- **Remediation Action:**
  1. Updated `kubernetes/namespace.yaml` to enforce `baseline` security level:
     ```yaml
     pod-security.kubernetes.io/enforce: "baseline"
     pod-security.kubernetes.io/audit: "restricted"
     pod-security.kubernetes.io/warn: "restricted"
     ```
  2. Removed `capabilities.add: ["NET_RAW"]` from `kubernetes/attacker-pod.yaml` and `k8s-provider.js`.
  3. Verified non-root execution (`runAsNonRoot: true`, `runAsUser: 1000`), read-only root filesystem (`readOnlyRootFilesystem: true`), seccomp (`RuntimeDefault`), and `allowPrivilegeEscalation: false`.
  4. Documented that raw socket crafting (`nmap -sS`, `hping3`) is disabled in Kubernetes Baseline mode, while standard diagnostic tools (`curl`, `nc`, `whoami`, `id`) and unprivileged ICMP ping sockets remain fully functional.
- **Verification:**
  - `kubectl apply -k kubernetes/ --dry-run=server` succeeds with 0 admission rejections.
  - Live pod running clean under PSS Baseline enforcement.

---

### Finding 2.2: Shared Command Validation Gateway & Injection Prevention
- **Severity:** Critical (P1)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/security/validator.js`
  - `orchestrator/index.js`
  - `orchestrator/providers/k8s-provider.js`
  - `orchestrator/providers/docker-provider.js`
- **Vulnerability Analysis:**
  Command validation was fragmented between ad-hoc regexes in `index.js` and provider implementations. Blocked tools (e.g., `apt-get`, `pip`, `git`) could potentially be invoked via shell metacharacters, subshells, or command substitution.
- **Remediation Action:**
  1. Created a unified, single source of truth: `orchestrator/security/validator.js`.
  2. Implemented strict command evaluation:
     - Blocked shell control operators: `;`, `&&`, `||`, `|`, `&`, `\n`, `\r`
     - Blocked command substitutions: `` `...` ``, `$(...)`
     - Blocked redirection: `>`, `<`, `>>`
     - Blocked package managers and unauthorized tools: `apt`, `apt-get`, `dpkg`, `apk`, `pip`, `pip3`, `python`, `npm`, `yarn`, `git`, `wget`
     - Whitelisted safe recon/diagnostic commands: `whoami`, `id`, `pwd`, `ls`, `curl`, `nmap` (non-raw), `ping`
  3. Integrated `evaluateCommand` across all API route handlers and both provider backends.
- **Verification:**
  - Test suite executes real HTTP POST requests to `/sessions/:id/execute`:
    - `id; whoami` -> Blocked (HTTP 403, "Command contains prohibited shell chaining or redirection")
    - `apt-get install nmap` -> Blocked (HTTP 403, "Command not allowed")
    - `cat /etc/passwd | grep root` -> Blocked (HTTP 403)
    - `id` -> Allowed (200 OK)

---

### Finding 2.3: Session ID Validation (RFC 1123 DNS Label Compliance)
- **Severity:** High (P1)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/security/validator.js`
  - `orchestrator/index.js`
  - `orchestrator/providers/k8s-provider.js`
  - `orchestrator/providers/docker-provider.js`
- **Vulnerability Analysis:**
  Session IDs were accepted without strict schema validation, creating risks of path traversal in logging, container naming injection in Docker, or invalid resource names causing 500 errors in Kubernetes.
- **Remediation Action:**
  1. Defined strict RFC 1123 DNS label regex in `validator.js`:
     ```javascript
     const SESSION_ID_REGEX = /^[a-z0-9]([-a-z0-9]{0,48}[a-z0-9])?$/;
     ```
  2. Applied `validateSessionId()` middleware across all endpoints: `POST /sessions`, `GET /sessions/:id`, `DELETE /sessions/:id`, `POST /sessions/:id/execute`, and `POST /sessions/:id/events`.
  3. Invalid session IDs immediately return `HTTP 400 Bad Request` before reaching provider logic.
- **Verification:**
  - Tested invalid inputs: `../escape`, `CAPS_ID`, `session$`, `-leading-hyphen`. All rejected with HTTP 400.
  - Tested valid inputs: `s1792309163007`, `demo-session-1`. Accepted.

---

### Finding 3.1: NetworkPolicy Isolation Verification & Positive Controls
- **Severity:** High (P1)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/security-tests/verify-kubernetes-security.js`
  - `kubernetes/network-policy.yaml`
- **Vulnerability Analysis:**
  The previous test suite tested cross-session isolation without verifying positive reachability to the session's own target first. Furthermore, tests against non-existent or unready probe pods were misreported as `PASS` (policy block) when in reality the connection failed due to missing endpoints or DNS failures.
- **Remediation Action:**
  1. Implemented **Positive Control First**: Verified attacker reaches its designated target (`target-demo-session:8080`) before testing isolation.
  2. Implemented **Probe Readiness Gate**: The test suite launches an ephemeral probe pod, polls Kubernetes until `status.conditions` indicates `Ready: True`, and verifies `nc` or `curl` is executable.
  3. Marked setup or readiness failures as `BLOCKED` rather than `PASS`.
  4. Verified that connection attempts from attacker pod to cross-session probe pods time out, proving NetworkPolicy ingress/egress denial.
- **Verification:**
  - Test 9 (Positive Control: Own target access): **PASS** (HTTP 200)
  - Test 10 (Cross-session isolation with Ready probe): **PASS** (Connection dropped by NetworkPolicy)
  - Test 11 (External egress control): **PASS** (Blocked egress to public IP `1.1.1.1`)

---

### Finding 3.2: Safe Resource Deletion & Partial-Creation Rollback
- **Severity:** High (P1)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/providers/k8s-provider.js`
  - `orchestrator/providers/docker-provider.js`
- **Vulnerability Analysis:**
  Resource deletion previously ignored all errors (not just 404), deleted resources without verifying ownership labels, and failed to handle partial creation failures, leaving orphaned resources in the cluster.
- **Remediation Action:**
  1. **Ownership Label Verification**: Both providers check that target resources carry `session: <sessionId>` and `app.kubernetes.io/managed-by: attacker-orchestrator` before deletion.
  2. **Selective Error Handling**: Only HTTP 404 / Kubernetes `NotFound` errors are ignored during cleanup; other errors (401, 403, 500) are propagated.
  3. **Deletion Confirmation**: `deleteSession` polls until the pod is completely removed from the API (or deletion timestamp confirmed), ensuring synchronous cleanup.
  4. **Atomic Rollback**: If pod creation fails after target creation, `createSession` automatically rolls back and cleans up any resources created in that specific transaction.
- **Verification:**
  - Backend integration test verifies safe deletion and confirms `GET /sessions/:id` returns 404 post-deletion.
  - Ownership labels verified on all managed Kubernetes resources.

---

### Finding 3.3: Execution Bounded Timeouts and Output Buffering
- **Severity:** Medium (P1)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/providers/k8s-provider.js`
  - `orchestrator/providers/docker-provider.js`
- **Vulnerability Analysis:**
  Exec endpoints did not enforce execution timeouts or response size limits. A command producing infinite output or hanging on network input could exhaust server memory and hold open TCP sockets indefinitely.
- **Remediation Action:**
  1. Configured hard execution timeout of 10 seconds.
  2. Upon timeout expiration, streams are safely aborted/destroyed, the exec process is killed, and the API returns `HTTP 408 Request Timeout`.
  3. Implemented a 64 KB maximum output buffer cap; output exceeding 64 KB is truncated with a safety warning: `[OUTPUT TRUNCATED: Exceeded maximum allowed size of 65536 bytes]`.
- **Verification:**
  - Tested timeout behavior: Returns HTTP 408 with message "Command execution timed out after 10000ms".
  - Tested output cap: Output cleanly truncated at 64 KB.

---

### Finding 4.1: Audit Logging Integrity & Runtime Seccomp Evidence
- **Severity:** Medium (P2)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `orchestrator/logger.js`
  - `orchestrator/security-tests/verify-kubernetes-security.js`
- **Vulnerability Analysis:**
  Previous reports claimed "custom seccomp profile enforcement" in Kubernetes based purely on manifest inspection, without checking runtime `/proc/1/status`.
- **Remediation Action:**
  1. Tested live `/proc/1/status` on running pods:
     - Confirmed `Seccomp: 2` (indicating Seccomp filtering mode is active under `RuntimeDefault`).
     - Clarified in all documentation that Kubernetes uses `RuntimeDefault` seccomp, while custom JSON seccomp filtering is applied in Docker mode.
  2. Added automated validation in security tests verifying that every API action emits a valid JSONL entry containing `timestamp`, `event`, and `details`.
- **Verification:**
  - Test 8 in Kubernetes suite: **PASS** (Runtime seccomp mode 2 verified).
  - Test 14 in Kubernetes suite: **PASS** (JSONL audit events successfully parsed and verified).

---

### Finding 4.2: Packaging Hygiene & Secret Exclusion
- **Severity:** High (P0)
- **Status:** **VERIFIED & REMEDIATED**
- **Affected Files:**
  - `scripts/package-clean-zip.ps1`
  - `.gitignore`
- **Vulnerability Analysis:**
  Source archives previously packaged `.git`, `node_modules`, backup files, and generated kubeconfig files, bloating the archive to ~13.1 MiB and risking credential leakage.
- **Remediation Action:**
  1. Implemented isolated staging in `scripts/package-clean-zip.ps1`.
  2. Excludes: `.git/`, `node_modules/`, `*.bak`, `*kubeconfig*.yaml`, `*.env*`, `*.token`, `*.log`, `*.tmp`, and all sensitive runtime logs.
  3. Archive size reduced from 13.1 MiB to **152.41 KB**.
  4. Scanned archive contents to verify complete absence of secrets.
- **Verification:**
  - Verified archive `C:\Users\rahul\secure-attacker.zip` with `tar -tf` and PowerShell script. 0 credentials or unwanted files found.

---

## Remediation Summary Table

| Finding ID | Description | Severity | Prior State | Remediated State | Test Status |
|---|---|---|---|---|---|
| **1.1** | ServiceAccount Token Exposure & Packaging | Critical (P0) | 13.1 MiB ZIP, tokens packaged | SA UID rotated, ignored in Git, 152 KB clean ZIP | **VERIFIED** |
| **1.2** | Orchestrator API Binding | High (P0) | Bound to `0.0.0.0` | Bound to `127.0.0.1`, local-demo documented | **VERIFIED** |
| **1.3** | Kubernetes Provider RBAC Identity | High (P0) | Defaulted to cluster-admin | Dedicated SA kubeconfig loaded, namespaced only | **VERIFIED** |
| **2.1** | Pod Security Admission & Capabilities | High (P1) | `enforce: privileged`, `NET_RAW` | `enforce: baseline`, `NET_RAW` dropped | **VERIFIED** |
| **2.2** | Shared Command Validation Gateway | Critical (P1) | Fragmented regex, chaining open | Centralized `validator.js`, chaining/subshells blocked | **VERIFIED** |
| **2.3** | Session ID RFC 1123 Validation | High (P1) | Unchecked session IDs | Strict DNS-1123 regex across all routes | **VERIFIED** |
| **3.1** | NetworkPolicy Isolation & Tests | High (P1) | False passes on unready probes | Positive control first, probe readiness checked | **VERIFIED** |
| **3.2** | Safe Resource Deletion & Rollback | High (P1) | Broad error swallow, no labels | Ownership checked, 404 selective, atomic rollback | **VERIFIED** |
| **3.3** | Execution Timeout & Output Cap | Medium (P1) | Unbounded exec & buffer | 10s timeout (HTTP 408), 64KB cap enforced | **VERIFIED** |
| **4.1** | Audit Log & Runtime Seccomp Evidence | Medium (P2) | Manifest claim only, unverified | Runtime Seccomp Mode 2 verified, valid JSONL tested | **VERIFIED** |
| **4.2** | Packaging Hygiene | High (P0) | Included node_modules, .git, secrets | Clean PowerShell packager, 152 KB, 0 secrets | **VERIFIED** |

---

## Remaining Risks & Manual Actions for Evaluator

1. **Local-Only API Scope:** The orchestrator API is intentionally unauthenticated for demonstration purposes. If deploying to multi-tenant or network-accessible environments, an authentication gateway (OIDC/OAuth2/mTLS) and per-session authorization must be added.
2. **Kubernetes Cluster Context:** The generated `kubernetes/orchestrator-kubeconfig.yaml` points to `https://kubernetes.docker.internal:6443`. If testing on Minikube or a remote cluster, re-run `node orchestrator/scripts/generate-sa-kubeconfig.js` to update cluster endpoints.
3. **Docker vs Kubernetes Differences:** Standalone Docker containers retain `NET_RAW` capability and use a custom seccomp JSON profile; Kubernetes pods drop `NET_RAW` to comply with Kubernetes Baseline PSA and use `RuntimeDefault` seccomp. Both profiles are functioning as designed.
