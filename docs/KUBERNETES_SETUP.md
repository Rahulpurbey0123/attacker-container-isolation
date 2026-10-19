# Kubernetes Environment Setup & Installation Guide

> **Project**: Attacker Container Isolation & Access Control  
> **Platform Version**: 1.1.0 (Kubernetes Orchestration Extension)  
> **Target Environment**: Windows 10/11, Docker Desktop with Kubernetes v1.36.1, Node.js, PowerShell

---

## 1. Prerequisites

Before enabling and deploying the Kubernetes orchestration layer, ensure the following components are installed and operational:

| Prerequisite | Minimum Version | Verification Command |
|---|---|---|
| **Windows OS** | Windows 10/11 (x64) with WSL2 | `wsl --status` |
| **Docker Desktop** | 4.30+ | `docker --version` |
| **Kubernetes (Docker Desktop)** | v1.30+ (v1.36.1 verified) | `kubectl version --client` |
| **Node.js** | v20+ (v22.18 verified) | `node --version` |
| **PowerShell** | 5.1 or PowerShell 7 | `$PSVersionTable.PSVersion` |

---

## 2. Enabling Kubernetes in Docker Desktop

1. Open **Docker Desktop Settings** (gear icon in the title bar).
2. Navigate to the **Kubernetes** tab on the left sidebar.
3. Check **Enable Kubernetes**.
4. Click **Apply & restart**. Docker Desktop will automatically initialize a local single-node cluster (`desktop-control-plane`).
5. Confirm that the Kubernetes CLI context is pointing to `docker-desktop`:
   ```powershell
   kubectl config current-context
   ```
   *Expected output*: `docker-desktop`
6. Confirm cluster node readiness:
   ```powershell
   kubectl get nodes -o wide
   ```
   *Expected output*: Node `desktop-control-plane` with status `Ready`.

---

## 3. Image Preparation & Import

The Kubernetes node runtime in Docker Desktop requires access to the custom attacker and target container images.

### Step 3.1: Build Attacker Image in Docker
From the project root directory:
```powershell
cd c:\Users\rahul\secure-attacker
docker build -t secure-attacker:1.0 .
```

### Step 3.2: Pull Target Image
```powershell
docker pull nginx:alpine
```

### Step 3.3: Import Attacker Image to Kubernetes containerd Runtime
Because Docker Desktop's Kubernetes engine runs in its containerd namespace (`k8s.io`), import the locally built image into containerd:
```powershell
docker save secure-attacker:1.0 -o secure-attacker.tar
wsl -d docker-desktop -e sh -c "cat /mnt/host/c/Users/rahul/secure-attacker/secure-attacker.tar | nsenter -t \$(pgrep -f 'containerd$' | head -n1) -m -p /usr/local/bin/ctr -n k8s.io image import -"
wsl -d docker-desktop -e sh -c "nsenter -t \$(pgrep -f 'containerd$' | head -n1) -m -p /usr/local/bin/ctr -n k8s.io images tag docker.io/library/secure-attacker:1.0 secure-attacker:1.0"
Remove-Item secure-attacker.tar
```

---

## 4. Deploying Kubernetes Manifests

Apply the declarative manifests to provision the dedicated namespace, RBAC permissions, target service, and network isolation policies:

```powershell
kubectl apply -k kubernetes/
```

Verify that all resources are active:
```powershell
kubectl get pods,svc,networkpolicy,sa,role,rolebinding -n attacker-lab
```

*Expected output*:
- `pod/attacker-demo-session`: `Running` (1/1)
- `pod/target-demo-session-...`: `Running` (1/1)
- `service/target-demo-session`: `ClusterIP` on port 80
- `networkpolicy/isolate-demo-session-attacker`: Active
- `networkpolicy/isolate-demo-session-target`: Active
- `serviceaccount/attacker-orchestrator-sa`: Created
- `role/attacker-orchestrator-role`: Created
- `rolebinding/attacker-orchestrator-binding`: Created

---

## 5. Starting Backend in Kubernetes Mode

To run the Node.js / Express backend with Kubernetes as the active orchestration provider:

```powershell
cd c:\Users\rahul\secure-attacker\orchestrator
$env:ORCHESTRATOR_PROVIDER="kubernetes"
node index.js
```

Verify that the orchestrator reports:
```text
Orchestrator running at http://localhost:3000
Active Orchestration Provider: [KUBERNETES]
```

To switch back to Docker mode at any time:
```powershell
$env:ORCHESTRATOR_PROVIDER="docker"
node index.js
```

---

## 6. Accessing the SOC Dashboard

Open your browser to:
[`http://localhost:3000/dashboard-ui/`](http://localhost:3000/dashboard-ui/)

The header telemetry pill will display:
- `PROVIDER: KUBERNETES` (when in Kubernetes mode)
- `PROVIDER: DOCKER` (when in Docker mode)
