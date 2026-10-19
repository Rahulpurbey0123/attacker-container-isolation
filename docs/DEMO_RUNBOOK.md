# Demonstrator and Evaluator Runbook

**Project:** Attacker Container Isolation and Access Control  
**Location:** `C:\Users\rahul\secure-attacker`  
**Purpose:** End-to-end evaluation runbook covering startup, web dashboard usage, API session management, security gateway testing, network isolation verification, and cleanup.

---

## 1. Prerequisites and Setup

Ensure Docker Desktop is running with Kubernetes enabled.

```powershell
# Verify Docker is running
docker info --format '{{.ServerVersion}}'

# Verify Kubernetes cluster is reachable
kubectl get nodes
```

Ensure Node.js v18+ is available:
```powershell
node -v
```

---

## 2. Starting the Orchestrator Service

The orchestrator supports two runtime provider backends: **Kubernetes Mode** (default) and **Docker Mode**.

### Option A: Kubernetes Mode (Recommended)
1. Initialize Kubernetes cluster resources and RBAC:
   ```powershell
   kubectl apply -k kubernetes/
   ```
2. Generate least-privilege ServiceAccount kubeconfig (if not already present):
   ```powershell
   node orchestrator/scripts/generate-sa-kubeconfig.js
   ```
3. Start the orchestrator API (bound to `127.0.0.1:3000`):
   ```powershell
   cd orchestrator
   $env:PROVIDER="kubernetes"
   node index.js
   ```

### Option B: Docker Mode
```powershell
cd orchestrator
$env:PROVIDER="docker"
node index.js
```

---

## 3. Accessing the Web Dashboard

Open your web browser and navigate to:
```text
http://127.0.0.1:3000/dashboard-ui/
```

The dashboard displays:
- **System Health:** CPU, Memory, and Provider status (`kubernetes` or `docker`)
- **Active Sessions:** Real-time container/pod inventory
- **Live Command Execution Console:** Submit commands and view output with security status
- **Real-Time Security Audit Stream:** Live SSE stream displaying JSONL audit events

---

## 4. Evaluation Scenarios & Reproducible Commands

You can run these commands from PowerShell or bash against `http://127.0.0.1:3000`.

### Step 4.1: Health & Metrics Check
```powershell
curl.exe -s http://127.0.0.1:3000/health
# Expected: {"status":"ok","timestamp":"...","provider":"kubernetes","activeSessions":1}

curl.exe -s http://127.0.0.1:3000/metrics
# Expected: Prometheus/JSON metrics with active sessions, command counts
```

---

### Step 4.2: Create an Isolated Attacker Session
Session IDs must be valid RFC 1123 DNS labels (lowercase alphanumeric and hyphens, up to 48 characters).

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions `
  -H "Content-Type: application/json" `
  -d '{"sessionId":"eval-demo-1"}'
```
**Expected Response:**
```json
{
  "success": true,
  "sessionId": "eval-demo-1",
  "podName": "attacker-eval-demo-1",
  "targetService": "target-eval-demo-1",
  "status": "created"
}
```

---

### Step 4.3: Test Approved Diagnostic Command
Execute safe reconnaissance commands (`id`, `whoami`, `pwd`, `ls`):

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions/eval-demo-1/execute `
  -H "Content-Type: application/json" `
  -d '{"command":"id"}'
```
*Note: The orchestrator supports both `/execute` and `/exec` endpoints.*
**Expected Output:**
```json
{
  "message": "Command executed successfully",
  "sessionId": "eval-demo-1",
  "command": "id",
  "exitCode": 0,
  "output": "uid=1001(student) gid=1001(student) groups=1001(student)\n"
}
```
*Note: Confirms execution as unprivileged non-root user (uid 1001).*

---

### Step 4.4: Test Blocked Unauthorized Package Manager
Attempt to install tools (`apt`, `apt-get`, `pip`, `git`):

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions/eval-demo-1/execute `
  -H "Content-Type: application/json" `
  -d '{"command":"apt-get update"}'
```
**Expected Output (HTTP 403 Forbidden):**
```json
{
  "message": "Package managers and installation tools are prohibited",
  "action": "APT_COMMAND",
  "result": "BLOCKED",
  "severity": "HIGH"
}
```

---

### Step 4.5: Test Blocked Shell Chaining & Metacharacters
Attempt to chain commands using `;`, `&&`, or piping:

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions/eval-demo-1/execute `
  -H "Content-Type: application/json" `
  -d '{"command":"id; whoami"}'
```
**Expected Output (HTTP 403 Forbidden):**
```json
{
  "message": "Shell chaining operators (; && || |) are prohibited",
  "action": "SHELL_COMMAND_CHAINING",
  "result": "BLOCKED",
  "severity": "HIGH"
}
```

---

### Step 4.6: Positive Control: Own-Target Network Access
Verify the attacker can communicate with its designated target service (`target-eval-demo-1:8080`):

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions/eval-demo-1/execute `
  -H "Content-Type: application/json" `
  -d '{"command":"curl -s -m 3 http://target-eval-demo-1:8080"}'
```
**Expected Output:**
```json
{
  "message": "Command executed successfully",
  "sessionId": "eval-demo-1",
  "command": "curl -s -m 3 http://target-eval-demo-1:8080",
  "exitCode": 0,
  "output": "Target Container OK\n"
}
```

---

### Step 4.7: Negative Control: Cross-Session Network Isolation
Attempt to reach another tenant's target service across session boundaries:

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions/eval-demo-1/execute `
  -H "Content-Type: application/json" `
  -d '{"command":"curl -s -m 3 http://target-demo-session:8080"}'
```
**Expected Output:**
```json
{
  "sessionId": "eval-demo-1",
  "exitCode": 28,
  "output": "curl: (28) Connection timed out after 3000 milliseconds\n"
}
```
*Note: Exit code 28 / timeout confirms NetworkPolicy actively drops unauthorized cross-session traffic.*

---

### Step 4.8: Bounded Timeout Demonstration
Execute a command that exceeds the 10-second limit:

```powershell
curl.exe -s -X POST http://127.0.0.1:3000/sessions/eval-demo-1/execute `
  -H "Content-Type: application/json" `
  -d '{"command":"sleep 15"}'
```
**Expected Output (HTTP 408 Request Timeout):**
```json
{
  "error": "Command execution timed out after 10000ms"
}
```

---

### Step 4.9: Session Cleanup
Delete the session and verify all associated resources are removed:

```powershell
curl.exe -s -X DELETE http://127.0.0.1:3000/sessions/eval-demo-1
```
**Expected Output:**
```json
{
  "success": true,
  "sessionId": "eval-demo-1",
  "status": "deleted"
}
```

Confirm session is completely gone (HTTP 404):
```powershell
curl.exe -s http://127.0.0.1:3000/sessions/eval-demo-1
# Expected: {"error":"Session not found"}
```

---

## 5. Automated Test Suites Quick Reference

To run the automated verification suites:

```powershell
# 1. API Integration Tests (10 tests)
cd orchestrator
npm run test:api

# 2. Kubernetes Security Tests (16 tests)
npm run test:k8s

# 3. Docker Security Tests (8 tests)
npm run test:docker

# 4. Full Regression Suite
npm test
```

---

## 6. Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `kubectl: unable to connect to server` | Docker Desktop Kubernetes not started | In Docker Desktop settings, ensure "Enable Kubernetes" is checked and status is green. |
| `K8S Provider Error: Forbidden` | Stale or missing ServiceAccount token | Run `node orchestrator/scripts/generate-sa-kubeconfig.js` to refresh `kubernetes/orchestrator-kubeconfig.yaml`. |
| `Port 3000 already in use` | Previous node process still running | Run `Get-Process node | Stop-Process` in PowerShell. |
| Probe container setup timeout in tests | Docker image download delay | Pre-pull images: `docker pull alpine:3.19` and `docker pull curlimages/curl:8.5.0`. |
