# Kubernetes Demonstration & Evaluation Walkthrough

> **Project**: Attacker Container Isolation & Access Control  
> **Platform Version**: 1.1.0 (Kubernetes Orchestration Extension)  
> **Target Audience**: Instructors, SOC Administrators, Evaluators, and Students

---

## 1. Demonstration Scenario Overview

This demonstration illustrates how the platform provisions hardened, isolated ethical hacking environments orchestrated by **Kubernetes**, while maintaining real-time telemetry on the administrative Security Operations Center (SOC) dashboard.

---

## 2. Step-by-Step Demonstration Walkthrough

### Step 1: Start the Orchestrator in Kubernetes Mode

Open PowerShell in the project directory:

```powershell
cd c:\Users\rahul\secure-attacker\orchestrator
$env:ORCHESTRATOR_PROVIDER="kubernetes"
node index.js
```

Observe the console output:
```text
Orchestrator running at http://localhost:3000
Active Orchestration Provider: [KUBERNETES]
```

---

### Step 2: Open the SOC Web Dashboard

Open your web browser and navigate to:
[`http://localhost:3000/dashboard-ui/`](http://localhost:3000/dashboard-ui/)

Verify the top telemetry bar:
- Status: **`SYSTEM ONLINE`** (emerald pill)
- Active Provider: **`PROVIDER: KUBERNETES`** (cyan pill)
- Telemetry: Metrics cards showing live Active Sessions, Total Events, and Blocked Events.

---

### Step 3: Inspect Active Workloads via `kubectl`

In a second PowerShell window, verify the current pods in `attacker-lab`:

```powershell
kubectl get pods,svc,networkpolicy -n attacker-lab -o wide
```

*Expected output*:
- `attacker-demo-session` (1/1 Running)
- `target-demo-session-...` (1/1 Running)
- `target-demo-session` ClusterIP Service

---

### Step 4: Execute Approved Commands via the API Gateway

Send approved security testing commands through the orchestrator:

```powershell
# 1. Inspect execution identity (Non-root user UID 1001)
Invoke-RestMethod -Uri "http://localhost:3000/sessions/demo-session/execute" -Method Post -ContentType "application/json" -Body '{"command":"id"}'

# 2. Inspect root filesystem mount (Read-only root)
Invoke-RestMethod -Uri "http://localhost:3000/sessions/demo-session/execute" -Method Post -ContentType "application/json" -Body '{"command":"pwd"}'

# 3. Test intra-session HTTP reachability to assigned target
Invoke-RestMethod -Uri "http://localhost:3000/sessions/demo-session/execute" -Method Post -ContentType "application/json" -Body '{"command":"curl http://target-demo-session"}'
```

All three commands will return `result: "SUCCESS"`.

---

### Step 5: Test Security Policy Enforcement (Blocked Attempts)

Demonstrate how the orchestrator and container defenses actively block unauthorized student actions:

#### 1. Attempt Package Installation (APT Blocked)
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions/demo-session/execute" -Method Post -ContentType "application/json" -Body '{"command":"apt-get install nmap"}'
```
*Expected response*: HTTP 403 Forbidden
```json
{
  "message": "Command blocked by security policy",
  "action": "APT_COMMAND",
  "result": "BLOCKED",
  "severity": "HIGH"
}
```

#### 2. Attempt Shell Chaining & Redirection
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions/demo-session/execute" -Method Post -ContentType "application/json" -Body '{"command":"id; whoami"}'
```
*Expected response*: HTTP 403 Forbidden (`action: "SHELL_COMMAND_CHAINING"`).

#### 3. Attempt Unapproved Utility Execution
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions/demo-session/execute" -Method Post -ContentType "application/json" -Body '{"command":"nmap 10.96.232.63"}'
```
*Expected response*: HTTP 403 Forbidden (`action: "COMMAND_NOT_ALLOWED"`).

---

### Step 6: Observe Real-Time Telemetry on the Dashboard

Return to the SOC Dashboard ([`http://localhost:3000/dashboard-ui/`](http://localhost:3000/dashboard-ui/)):
- **Blocked Events counter** has incremented.
- **Recent Security Events table** displays the blocked `APT_COMMAND`, `SHELL_COMMAND_CHAINING`, and `COMMAND_NOT_ALLOWED` attempts in real time with high severity badges.
- **Severity breakdown bar** dynamically highlights elevated threat levels.

---

### Step 7: Run the Automated Kubernetes Verification Suite

Execute the automated 16-point Kubernetes security test harness:

```powershell
node orchestrator/security-tests/verify-kubernetes-security.js attacker-demo-session target-demo-session
```

*Expected output*:
```text
============================================================
       KUBERNETES SECURITY TEST SUMMARY
============================================================
Total tests   : 16
Passed        : 16
Failed        : 0
Blocked       : 0
Skipped       : 0
OVERALL RESULT: PASS
============================================================
```

The resulting JSON report is persisted to:
[`orchestrator/security-tests/results/kubernetes-security-report.json`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-tests/results/kubernetes-security-report.json)

---

### Step 8: Switch Back to Docker Mode (Zero Regressions)

Demonstrate seamless fallback to Docker:

```powershell
# Stop orchestrator and restart with Docker provider
$env:ORCHESTRATOR_PROVIDER="docker"
node orchestrator/index.js
```

Verify that the dashboard now displays `PROVIDER: DOCKER` and that existing Docker sessions can be managed and verified:

```powershell
# Run the original 8-point Docker security verification suite
node orchestrator/security-tests/verify-security.js attacker-1791179497327 target-1791179497327 target-1791179835716
```
*Result*: 8/8 PASS.
