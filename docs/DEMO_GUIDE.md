# Step-by-Step Demonstration Guide

This guide provides an exact, word-by-word walkthrough for demonstrating all security controls, container isolation mechanisms, the web dashboard, and the command execution gateway of the **Attacker Container Isolation and Access Control** platform.

---

## Part 1: Starting the Orchestrator Service

Open PowerShell and navigate to the project directory:

```powershell
cd c:\Users\rahul\secure-attacker\orchestrator
node index.js
```

Confirm the service starts and displays:

```text
Orchestrator running at http://localhost:3000
```

Keep this PowerShell window open. Open a **new PowerShell window** for the demonstration commands below.

---

## Part 2: Opening the Dashboard & Session Creation

1. Open your web browser and go to:
   ```text
   http://localhost:3000/dashboard-ui/
   ```
2. Confirm the top status badge reads **SYSTEM ONLINE** and telemetry updates every 5 seconds.
3. Locate the **STUDENT SESSION MANAGEMENT** panel.
4. Click the **`+ CREATE NEW SESSION`** button.
5. Observe that the button temporarily changes to **`CREATING SESSION...`** and is disabled to prevent double clicks.
6. Within a few seconds, the **SESSION CREATED** card appears with details similar to:
   * **Session ID**: `1791048868330` *(example timestamp ID)*
   * **Attacker**: `attacker-1791048868330`
   * **Target**: `target-1791048868330`
   * **Network**: `session-1791048868330-net`
   * **Terminal Access Command**: `docker exec -it attacker-1791048868330 bash`
7. Click **`COPY TERMINAL COMMAND`**. Confirm the button text changes to **`COPIED!`**.
8. Scroll down to **SESSION MONITORING** and verify that the newly created session appears with status **ACTIVE**, and the **ACTIVE SESSIONS** card shows `1`.

---

## Part 3: Interactive Container Security Demonstration

In your secondary PowerShell window, connect to the newly created attacker container using the terminal command copied from the dashboard:

```powershell
docker exec -it attacker-<YOUR_SESSION_ID> bash
```

*(Replace `<YOUR_SESSION_ID>` with your actual session ID, e.g., `attacker-1791048868330`)*

### 1. Verify Non-Root User Execution
Inside the container, run:

```bash
id
```
**Expected Output:**
```text
uid=1001(student) gid=1001(student) groups=1001(student)
```
*Security Meaning*: The container executes strictly as a non-privileged user (`1001:1001`), preventing unauthorized host or system access.

### 2. Verify Working Directory
Inside the container, run:

```bash
pwd
```
**Expected Output:**
```text
/home/student
```

### 3. Verify DNS Resolution for Assigned Target
Inside the container, run:

```bash
getent hosts target-<YOUR_SESSION_ID>
```
**Expected Output:**
Resolves the internal IP address (e.g., `172.31.0.2 target-1791048868330`).

### 4. Verify Permitted Access to Own Target
Inside the container, perform an HTTP request against the session target:

```bash
curl --connect-timeout 5 http://target-<YOUR_SESSION_ID>
```
**Expected Output:**
The standard HTML welcome page:
```html
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```
*Security Meaning*: Intended lateral security scanning and HTTP interaction within the student's assigned private network is permitted.

### 5. Verify Egress Restriction (Internet Access Blocked)
Inside the container, attempt to reach an external public host:

```bash
curl --connect-timeout 5 https://google.com
```
**Expected Output:**
```text
curl: (6) Could not resolve host: google.com
```
*Security Meaning*: The session bridge network is configured with `Internal: true`. Containers cannot access the public Internet, preventing unauthorized data exfiltration or external command-and-control connectivity.

### 6. Verify Read-Only Filesystem & Package Block
Inside the container, attempt to install or update packages:

```bash
apt-get update
```
**Expected Output:**
```text
Reading package lists...
E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)
```
*Security Meaning*: The root filesystem is mounted with `ReadonlyRootfs: true`. Runtime package managers cannot modify system binaries or install arbitrary tooling.

Exit the container:

```bash
exit
```

---

## Part 4: Cross-Session Isolation Demonstration

To demonstrate multi-tenant isolation, create a second student session (Session B) from the dashboard or via API:

```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions" -Method POST -ContentType "application/json"
```

Assume we now have:
* **Session A**: `attacker-SESSION_A` and `target-SESSION_A`
* **Session B**: `attacker-SESSION_B` and `target-SESSION_B`

Now, log into `attacker-SESSION_A`:

```powershell
docker exec -it attacker-SESSION_A bash
```

Attempt to reach the target belonging to Session B:

```bash
curl --connect-timeout 5 http://target-SESSION_B
```

**Expected Output:**
```text
curl: (6) Could not resolve host: target-SESSION_B
```

Even if the direct internal IP address of `target-SESSION_B` is targeted:
```bash
curl --connect-timeout 5 http://172.31.0.X
```
The connection times out and fails.

*Security Meaning*: Each session operates on its own dedicated Docker bridge network. Cross-session lateral movement between student environments is blocked at the network level.

Exit the container:
```bash
exit
```

---

## Part 5: Secure Command Execution Gateway Demonstration

The orchestrator provides a secured execution endpoint (`POST /sessions/:sessionId/execute`) that subjects all commands to strict security filtering.

> **Important Windows PowerShell Note**: On Windows PowerShell, avoid typing Unix-style `curl -X POST` because PowerShell aliases `curl` to `Invoke-WebRequest`. Instead, use `Invoke-RestMethod` as shown below.
> 
> Furthermore, when an API blocks a command, the gateway returns an **HTTP 403 Forbidden** status code. By default, PowerShell treats non-2xx status codes as errors and throws a `WebException`. **This HTTP 403 error is expected and indicates the security control successfully blocked the attack.** We wrap each command in a small `try / catch` to print the JSON response returned by the gateway.

### Test 1: Permitted Command (`id`)

Run in PowerShell:

```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions/<YOUR_SESSION_ID>/execute" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"command":"id"}'
```

**Expected Result (HTTP 200 SUCCESS):**
```json
{
  "message": "Command executed",
  "result": "SUCCESS",
  "exitCode": 0,
  "output": "...uid=1001(student) gid=1001(student)..."
}
```

### Test 2: Blocked APT Package Management (`apt-get update`)

Run in PowerShell:

```powershell
try {
  Invoke-RestMethod -Uri "http://localhost:3000/sessions/<YOUR_SESSION_ID>/execute" `
    -Method POST -ContentType "application/json" `
    -Body '{"command":"apt-get update"}'
} catch {
  $stream = $_.Exception.Response.GetResponseStream()
  (New-Object System.IO.StreamReader($stream)).ReadToEnd()
}
```

**Expected Result (HTTP 403 BLOCKED - PASS):**
```json
{
  "message": "Command blocked by security policy",
  "action": "APT_COMMAND",
  "result": "BLOCKED",
  "severity": "HIGH",
  "eventId": "..."
}
```

### Test 3: Blocked Python Package Management (`pip install requests`)

Run in PowerShell:

```powershell
try {
  Invoke-RestMethod -Uri "http://localhost:3000/sessions/<YOUR_SESSION_ID>/execute" `
    -Method POST -ContentType "application/json" `
    -Body '{"command":"pip install requests"}'
} catch {
  $stream = $_.Exception.Response.GetResponseStream()
  (New-Object System.IO.StreamReader($stream)).ReadToEnd()
}
```

**Expected Result (HTTP 403 BLOCKED - PASS):**
```json
{
  "message": "Command blocked by security policy",
  "action": "PIP_INSTALL",
  "result": "BLOCKED",
  "severity": "HIGH",
  "eventId": "..."
}
```

### Test 4: Blocked Git Clone Repository Download (`git clone ...`)

Run in PowerShell:

```powershell
try {
  Invoke-RestMethod -Uri "http://localhost:3000/sessions/<YOUR_SESSION_ID>/execute" `
    -Method POST -ContentType "application/json" `
    -Body '{"command":"git clone https://github.com/test/test.git"}'
} catch {
  $stream = $_.Exception.Response.GetResponseStream()
  (New-Object System.IO.StreamReader($stream)).ReadToEnd()
}
```

**Expected Result (HTTP 403 BLOCKED - PASS):**
```json
{
  "message": "Command blocked by security policy",
  "action": "GIT_CLONE",
  "result": "BLOCKED",
  "severity": "MEDIUM",
  "eventId": "..."
}
```

### Test 5: Blocked Shell Chaining & Command Injection (`id; apt-get update`)

Run in PowerShell:

```powershell
try {
  Invoke-RestMethod -Uri "http://localhost:3000/sessions/<YOUR_SESSION_ID>/execute" `
    -Method POST -ContentType "application/json" `
    -Body '{"command":"id; apt-get update"}'
} catch {
  $stream = $_.Exception.Response.GetResponseStream()
  (New-Object System.IO.StreamReader($stream)).ReadToEnd()
}
```

**Expected Result (HTTP 403 BLOCKED - PASS):**
```json
{
  "message": "Command blocked by security policy",
  "action": "SHELL_COMMAND_CHAINING",
  "result": "BLOCKED",
  "severity": "HIGH",
  "eventId": "..."
}
```

---

## Part 6: Dashboard Telemetry & Audit Verification

1. Return to the browser dashboard at `http://localhost:3000/dashboard-ui/`.
2. Notice the real-time updates:
   * **TOTAL EVENTS**: Incremented with every executed or blocked command.
   * **BLOCKED EVENTS**: Incremented for each blocked attempt.
   * **HIGH SEVERITY**: Incremented reflecting the APT, PIP, and shell chaining blocks.
3. Review the **RECENT SECURITY EVENTS** table:
   * Confirms `SHELL_COMMAND_CHAINING`, `GIT_CLONE`, `PIP_INSTALL`, and `APT_COMMAND` records with timestamps, session IDs, and `BLOCKED` status badges.

---

## Part 7: Running the Automated Security Verification Test

Execute the automated 8-point verification test script using Node.js:

```powershell
node orchestrator/security-tests/verify-security.js `
  attacker-<SESSION_A> `
  target-<SESSION_A> `
  target-<SESSION_B>
```

**Expected Output:**

```text
==============================================
   SECURITY VERIFICATION
==============================================

[PASS] Non-root user
       Configured user: 1001:1001
[PASS] Read-only root filesystem
       ReadonlyRootfs=true
[PASS] All unnecessary capabilities dropped
       CapDrop=["ALL"]
[PASS] Only NET_RAW capability added
       CapAdd=["NET_RAW"]
[PASS] Runtime package management blocked
       apt-get update was blocked (exit code 100)
[PASS] Own target reachable
       Attacker successfully reached assigned target
[PASS] Cross-session target blocked
       Other session target was unreachable
[PASS] Seccomp security profile attached
       Seccomp profile is attached to attacker container

==============================================
SECURITY TEST SUMMARY
==============================================
Total tests : 8
Passed      : 8
Failed      : 0
RESULT: PASS
```

The comprehensive verification report is automatically persisted to:
`orchestrator/security-tests/results/security-report.json`.
