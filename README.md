# Development of an Isolated, Access-Controlled Attacker Container Environment

> **Project Short Name**: Attacker Container Isolation and Access Control
> **Platform Version**: 1.2.0 (Hardened Dual-Orchestration Architecture)
> **Environment**: Windows 10/11, Docker Desktop (Kubernetes v1.36.1 enabled), Node.js, PowerShell

> [!IMPORTANT]
> **LOCAL DEMONSTRATION ONLY — SECURITY ARCHITECTURE NOTICE**
> The Express orchestrator service explicitly binds to `127.0.0.1` (`HOST = process.env.HOST || "127.0.0.1"`). All API endpoints currently operate without authentication or per-user access control. This design is strictly intended for local educational demonstration. Before multi-user network deployment, an external authentication gateway (OAuth2/OIDC/mTLS) and per-session authorization layer must be implemented.

---

## ⚡ Quick Start: Dual Orchestration Modes

The platform supports two orchestration providers selectable via the `ORCHESTRATOR_PROVIDER` environment variable:

```text
+-----------------------------------+-----------------------------------+
|            DOCKER MODE            |          KUBERNETES MODE          |
|      (Default Implementation)     |       (Enterprise Extension)      |
+-----------------------------------+-----------------------------------+
| $env:ORCHESTRATOR_PROVIDER="docker"| $env:ORCHESTRATOR_PROVIDER="kubernetes"|
| node orchestrator/index.js        | node orchestrator/index.js        |
| -> Docker bridge networks         | -> Namespaces & NetworkPolicies   |
| -> Dockerode Engine API           | -> @kubernetes/client-node API    |
+-----------------------------------+-----------------------------------+
```

### Automated Verification Commands
```powershell
# From orchestrator/ directory:
npm test                  # Runs syntax checks, Backend API tests, and Kubernetes security tests
npm run test:api          # Runs Express Backend API endpoint integration audit
npm run test:k8s          # Runs 16-point Kubernetes security verification suite
npm run test:docker       # Runs 8-point Docker security verification suite with auto-cleanup
```


---

### Mode A: Running in Docker Mode (Default)

1. **Start Docker Desktop**: Ensure Docker Desktop is active on Windows.
2. **Build and Pull Images**:
   ```powershell
   cd path\to\secure-attacker
   docker build -t secure-attacker:1.0 .
   docker pull nginx:alpine
   ```
3. **Start the Orchestrator Backend**:
   ```powershell
   cd orchestrator
   $env:ORCHESTRATOR_PROVIDER="docker"
   node index.js
   ```
4. **Open the SOC Dashboard**: [`http://localhost:3000/dashboard-ui/`](http://localhost:3000/dashboard-ui/)
5. **Run Docker Automated Security Verification**:
   ```powershell
   node security-tests/verify-security.js <attackerName> <ownTargetName> <otherTargetName>
   ```

---

### Mode B: Running in Kubernetes Mode

1. **Verify Kubernetes in Docker Desktop**:
   ```powershell
   kubectl config current-context   # Expected: docker-desktop
   kubectl get nodes -o wide        # Expected: desktop-control-plane Ready
   ```
2. **Import Attacker Image into containerd Runtime**:
   ```powershell
   docker save secure-attacker:1.0 -o secure-attacker.tar
   wsl -d docker-desktop -e sh -c "cat /mnt/host/c/Users/rahul/secure-attacker/secure-attacker.tar | nsenter -t \$(pgrep -f 'containerd$' | head -n1) -m -p /usr/local/bin/ctr -n k8s.io image import -"
   wsl -d docker-desktop -e sh -c "nsenter -t \$(pgrep -f 'containerd$' | head -n1) -m -p /usr/local/bin/ctr -n k8s.io images tag docker.io/library/secure-attacker:1.0 secure-attacker:1.0"
   Remove-Item secure-attacker.tar
   ```
3. **Deploy Validated Declarative Manifests**:
   ```powershell
   kubectl apply -k kubernetes/
   ```
4. **Start the Orchestrator in Kubernetes Mode**:
   ```powershell
   cd orchestrator
   $env:ORCHESTRATOR_PROVIDER="kubernetes"
   node index.js
   ```
5. **Open the SOC Dashboard**: [`http://localhost:3000/dashboard-ui/`](http://localhost:3000/dashboard-ui/)
   *(Notice the `PROVIDER: KUBERNETES` status badge in the header telemetry bar)*
6. **Run Kubernetes Automated Security Verification (16 Assertions)**:
   ```powershell
   node security-tests/verify-kubernetes-security.js attacker-demo-session target-demo-session
   ```

---

## 🏛️ System Architecture

```text
                     +---------------------------+
                     |          STUDENT          |
                     +---------------------------+
                                   |
                                   v
                     +---------------------------+
                     |       WEB DASHBOARD       |  (http://localhost:3000/dashboard-ui/)
                     +---------------------------+
                                   |
                                   | HTTP REST API
                                   v
                     +---------------------------+
                     |     NODE.JS / EXPRESS     |  (orchestrator/index.js)
                     |       ORCHESTRATOR        |  (Pluggable Provider Factory)
                     +---------------------------+
                                   |
                   +---------------+---------------+
                   |                               |
       [ORCHESTRATOR_PROVIDER=docker]  [ORCHESTRATOR_PROVIDER=kubernetes]
                   v                               v
     +---------------------------+   +---------------------------+
     |      DOCKER PROVIDER      |   |    KUBERNETES PROVIDER    |
     | - Bridge Networks         |   | - Namespace: attacker-lab |
     | - Custom JSON Seccomp     |   | - ClusterIP Services      |
     | - Dockerode Exec API      |   | - NetworkPolicies (CNI)   |
     | - Tmpfs Mounts            |   | - RuntimeDefault Seccomp  |
     +-------------+-------------+   +-------------+-------------+
                   |                               |
           +-------+-------+               +-------+-------+
           |               |               |               |
           v               v               v               v
     +-----------+   +-----------+   +-----------+   +-----------+
     | ATTACKER  |   |  TARGET   |   | ATTACKER  |   |  TARGET   |
     | CONTAINER |   | CONTAINER |   |    POD    |   |DEPLOYMENT |
     |  (Ubuntu) |   |  (Nginx)  |   |  (Ubuntu) |   |  (Nginx)  |
     +-----------+   +-----------+   +-----------+   +-----------+
```

---

## 🔒 Security Control Matrix

Security controls are configured separately for the Docker and Kubernetes providers. The table describes the configured controls; runtime verification results should be considered separately.

| Security Domain | Docker Engine Implementation | Kubernetes Attacker Implementation | Status |
|---|---|---|---|
| **Non-root user** | `User: "1001:1001"` | `runAsUser: 1001`, `runAsNonRoot: true` | Previously verified |
| **Filesystem immutability** | `ReadonlyRootfs: true` | `readOnlyRootFilesystem: true` | Previously verified |
| **Privilege escalation** | Docker security options | `allowPrivilegeEscalation: false` | Configured |
| **Linux capabilities** | Drops all, then adds `NET_RAW` | Drops all; no capabilities added in the manifest | Configurations differ |
| **Syscall filtering** | Custom JSON seccomp profile | `seccompProfile.type: RuntimeDefault` | Different profiles |
| **Ephemeral memory mounts** | Docker tmpfs mounts | Kubernetes memory-backed `emptyDir` volumes | Configured |
| **Session isolation** | Dedicated internal bridge network | Kubernetes NetworkPolicies | Prior cross-session HTTP matrix passed |
| **Target reachability** | Intra-bridge connectivity | Intra-session ClusterIP Service | Prior connectivity tests passed |

**Note:** The Kubernetes attacker manifest does not add `NET_RAW`. The Kubernetes target container has a separate security context. Docker and Kubernetes capability settings are not identical.---

## 📊 Verification Test Reports

### 1. Kubernetes Test Suite (16/16 Passed)
- **Script**: [orchestrator/security-tests/verify-kubernetes-security.js](orchestrator/security-tests/verify-kubernetes-security.js)
- **Report**: [orchestrator/security-tests/results/kubernetes-security-report.json](orchestrator/security-tests/results/kubernetes-security-report.json)
- **Result**: `16 passed, 0 failed, 0 blocked, 0 skipped` (OVERALL: **PASS**).

### 2. Docker Test Suite (8/8 Passed)
- **Script**: [`orchestrator/security-tests/verify-security.js`](orchestrator/security-tests/verify-security.js)
- **Report**: [`orchestrator/security-tests/results/security-report.json`](orchestrator/security-tests/results/security-report.json)
- **Result**: `8 passed, 0 failed` (OVERALL: **PASS**).

---

## 📁 Repository Structure

```text
secure-attacker/
├── Dockerfile                             # Hardened Ubuntu 24.04 attacker image definition
├── README.md                              # Unified system documentation (this file)
├── CHANGELOG.md                           # Version milestone history
├── .gitignore                             # Ignored dependencies and local artifacts
├── dashboard/                             # Frontend Security Operations Center (SOC) dashboard
│   ├── index.html                         # SOC dashboard markup with provider status pill
│   ├── style.css                          # Dark cyber industrial styling
│   └── dashboard.js                       # Telemetry polling, session parsing, and event rendering
├── kubernetes/                            # Production Kubernetes declarative manifests
│   ├── namespace.yaml                     # Dedicated attacker-lab namespace with PSS standards
│   ├── attacker-pod.yaml                  # Hardened attacker pod specification (UID 1001, read-only)
│   ├── target-deployment.yaml             # Nginx alpine target deployment with worker capabilities
│   ├── target-service.yaml                # Internal ClusterIP service exposing target
│   ├── network-policy.yaml                # Ingress and egress network isolation policies
│   ├── rbac.yaml                          # Least-privilege Role and ServiceAccount for orchestrator
│   └── kustomization.yaml                 # Declarative Kustomize manifest bundle
├── orchestrator/                          # Node.js / Express backend service
│   ├── index.js                           # Express application and security gateway
│   ├── logger.js                          # Line-delimited JSON audit and security logger
│   ├── security-monitor.js                # Shell history background security monitor
│   ├── package.json                       # Dependencies (express, dockerode, @kubernetes/client-node)
│   ├── providers/                         # Pluggable orchestration provider layer
│   │   ├── index.js                       # Provider factory (docker vs kubernetes)
│   │   ├── docker-provider.js             # Native Dockerode container and network management
│   │   └── k8s-provider.js                # Official Kubernetes API client session management
│   ├── security/                          # Kernel security profiles
│   │   └── seccomp-profile.json           # Custom Docker Seccomp syscall filter
│   ├── security-tests/                    # Automated security verification suites
│   │   ├── verify-security.js             # Original 8-point Docker security verification
│   │   ├── verify-kubernetes-security.js  # 16-point Kubernetes security verification
│   │   └── results/                       # Persisted JSON test execution records
│   │       ├── security-report.json       # Docker security verification output
│   │       └── kubernetes-security-report.json # Kubernetes security verification output
│   └── logs/                              # Audit and security event line-delimited logs
│       ├── audit.log                      # Lifecycle events and command executions
│       └── security-events.log            # Security violations and blocked attempts
└── docs/                                  # Extended technical documentation
    ├── KUBERNETES_SETUP.md                # Installation and configuration guide
    ├── KUBERNETES_ARCHITECTURE.md         # In-depth architectural specification
    ├── KUBERNETES_SECURITY.md             # Security controls & threat mitigation guide
    ├── KUBERNETES_DEMO_GUIDE.md           # Step-by-step evaluator demonstration script
    ├── KUBERNETES_TROUBLESHOOTING.md      # Diagnostics and issue resolution
    └── KUBERNETES_INTEGRATION_PLAN.md     # Initial planning and acceptance criteria
```

---

## 🧹 Cleanup Instructions

### Cleaning Up Kubernetes Workloads:
To delete only the resources inside `attacker-lab`:
```powershell
kubectl delete -k kubernetes/
```

### Resetting Orchestrator Mode:
To ensure the orchestrator defaults to Docker mode:
```powershell
Remove-Item Env:\ORCHESTRATOR_PROVIDER -ErrorAction SilentlyContinue
```
