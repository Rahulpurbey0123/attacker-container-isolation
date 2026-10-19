# Updated Final Demo Runbook
## Attacker Container Isolation and Access Control

**Purpose:** Editable, step-by-step instructions for demonstrating the project to a mentor. Copy commands from this file into Windows PowerShell, then explain the expected result in simple language.

> **Demo mode:** The primary live walkthrough below uses Docker, matching the Docker command examples and the 8/8 Docker security suite. The project also supports Kubernetes; separate verification commands are included later.
>
> **Important:** Use the session/container names shown by your own dashboard or `docker ps`. Do not reuse example IDs from an older report. A security command being blocked is an expected PASS, not a failure.

---

## 1. Explain the project in 30 seconds

**Simple explanation:** This project creates a restricted attacker container and an assigned target for each session. A private Docker network separates sessions, while the orchestrator validates commands sent through the API and records security events for the dashboard.

**Architecture:**

```text
Student / Mentor
      |
      v
Web Dashboard
      |
      v
Node.js + Express Orchestrator
      |
      +--> Security Validator + Audit Logs
      |
      +--> Docker Provider OR Kubernetes Provider
                 |
                 +--> Attacker Container / Pod
                 +--> Assigned Nginx Target
                 +--> Session Network / NetworkPolicies
```

**Say to your mentor:**  
“Our goal is to let a student perform controlled security exercises in an isolated environment. The student can reach the target assigned to their session, but other sessions are isolated. The command gateway blocks prohibited commands submitted through the API, and the dashboard shows security events.”

## 2. Before the demo

Open **PowerShell window 1**.

```powershell
cd C:\Users\rahul\secure-attacker
docker --version
docker ps
node --version
npm --version
```

Make sure Docker Desktop is running. If `docker ps` fails, start Docker Desktop and retry.

Check that the attacker image exists:

```powershell
docker image inspect secure-attacker:1.0
```

If the image is missing, stop and build/load it using the project's existing Docker build instructions. Do not improvise image tags during the mentor demo.

**Say:**  
“First I confirm that Docker and Node.js are available and that the expected attacker image exists locally.”

## 3. Start the orchestrator

In PowerShell window 1:

```powershell
cd C:\Users\rahul\secure-attacker\orchestrator
npm ls --depth=0
node index.js
```

Leave this window open. Do not start a second server if one is already running.

Expected: a server-start message and no fatal error.

**Say:**  
“The orchestrator is the backend. It creates sessions, validates commands, calls the selected container provider, and records events.”

For the standard Docker demo, Docker is the default provider unless `ORCHESTRATOR_PROVIDER` is set differently. If needed, in the server window set Docker explicitly **before** starting Node:

```powershell
$env:ORCHESTRATOR_PROVIDER = "docker"
node index.js
```

Do not run both server-start options at once.

## 4. Open the dashboard and create a session

Open this URL in your browser:

<http://localhost:3000/dashboard-ui/>

Use the dashboard's **Student Session Management** area and choose **Create New Session**.

Record the session ID shown by the dashboard. The related Docker names follow this pattern:

- Attacker: `attacker-<SESSION_ID>`
- Target: `target-<SESSION_ID>`
- Network: `session-<SESSION_ID>-net`

In **PowerShell window 2**, set the real session ID shown on your dashboard:

```powershell
$sessionId = "PASTE_REAL_SESSION_ID_HERE"
$attacker = "attacker-$sessionId"
$target = "target-$sessionId"
```

Replace the placeholder with the actual session ID. Do not type the angle brackets.

Check the containers:

```powershell
docker ps --filter "name=$attacker"
docker ps --filter "name=$target"
docker network ls --filter "name=session-$sessionId-net"
```

**Expected:** the attacker and target containers are running, and the session network exists.

**Say:**  
“When I create a session, the orchestrator provisions an attacker container, its Nginx target, and a private network. Each session receives its own resources.”

## 5. Enter the attacker container

In PowerShell window 2:

```powershell
docker exec -it $attacker bash
```

The next commands run **inside the attacker container** until you type `exit`.

### Test 1 — Verify the non-root user

```bash
id
whoami
```

Expected evidence: UID/GID `1001` and user `student` (exact formatting may vary).

**Say:**  
“The attacker runs as a restricted student user, not root. This reduces the privileges available inside the container.”

### Test 2 — Resolve the assigned target

```bash
getent hosts "$target"
```

Expected: the target hostname resolves to an IP address. If the shell does not expand the PowerShell variable inside the container, type the actual target name directly, for example `getent hosts target-s1792312884577`.

**Say:**  
“This confirms that the assigned target can be found through the session's private network.”

### Test 3 — Access the assigned target

```bash
curl --connect-timeout 3 "http://$target"
```

If variable expansion is not applicable in the container, use the actual target name:

```bash
curl --connect-timeout 3 http://target-PASTE_REAL_SESSION_ID
```

Expected: Nginx welcome-page HTML.

**Say:**  
“Access to the assigned target is allowed. This is the positive control: the session must be able to reach its own target.”

### Test 4 — Confirm public internet access is restricted

```bash
curl --connect-timeout 3 https://example.com
```

Expected: connection or name resolution fails in the internal Docker network. The exact error depends on the environment.

**Say:**  
“The session network is configured as an internal network, so unrestricted outbound internet access is not provided.”

### Test 5 — Try runtime package management

```bash
apt-get update
```

Expected: the operation is blocked, commonly because the root filesystem is read-only.

**Say:**  
“The container root filesystem is read-only. This helps prevent runtime changes to the base environment, including package installation.”

**Important:** A blocked package operation is an expected security PASS.

Exit the attacker container:

```bash
exit
```

## 6. Demonstrate cross-session isolation

Create a **second session** in the dashboard. Record the second session ID as `$sessionB` in PowerShell window 2:

```powershell
$sessionB = "PASTE_SECOND_REAL_SESSION_ID_HERE"
$targetB = "target-$sessionB"
docker ps --filter "name=$targetB"
```

Find the second target's IP:

```powershell
$targetBIP = docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" $targetB
$targetBIP
```

Enter the **first session's** attacker container:

```powershell
docker exec -it $attacker bash
```

Inside the attacker container, try to access the second target's IP (replace the example with the IP printed above):

```bash
curl --connect-timeout 3 http://PASTE_TARGET_B_IP
```

Expected: the connection fails or times out. Then exit the container:

```bash
exit
```

**Say:**  
“This is the negative control. Session A's attacker should reach its own target but should not reach Session B's target. Separate private networks are used to isolate sessions.”

If the test unexpectedly succeeds, do not claim isolation is proven. Stop and investigate before the demo.

## 7. Demonstrate the command gateway

These requests are sent from **PowerShell**, not from inside the attacker container. Use the first session ID you recorded.

Set the endpoint:

```powershell
$api = "http://localhost:3000/sessions/$sessionId/execute"
```

### Test 6 — Block APT package-management commands

```powershell
try {
    Invoke-RestMethod -Uri $api -Method POST -ContentType "application/json" -Body '{"command":"apt-get update"}'
} catch {
    $_.ErrorDetails.Message
}
```

Expected: a blocked response with action `APT_COMMAND`, result `BLOCKED`, and severity `HIGH`.

### Test 7 — Block Python package installation

```powershell
try {
    Invoke-RestMethod -Uri $api -Method POST -ContentType "application/json" -Body '{"command":"pip install requests"}'
} catch {
    $_.ErrorDetails.Message
}
```

Expected: `PIP_INSTALL`, `BLOCKED`, severity `HIGH`.

### Test 8 — Block Git cloning

```powershell
try {
    Invoke-RestMethod -Uri $api -Method POST -ContentType "application/json" -Body '{"command":"git clone https://github.com/test/test.git"}'
} catch {
    $_.ErrorDetails.Message
}
```

Expected: `GIT_CLONE`, `BLOCKED`, severity `MEDIUM`.

### Test 9 — Block shell command chaining

```powershell
try {
    Invoke-RestMethod -Uri $api -Method POST -ContentType "application/json" -Body '{"command":"id; whoami"}'
} catch {
    $_.ErrorDetails.Message
}
```

Expected: `SHELL_COMMAND_CHAINING`, `BLOCKED`, severity `HIGH`.

**Say:**  
“The command gateway checks commands against a shared validation policy before forwarding approved commands to the provider. These prohibited requests are rejected and logged. A rejection is the expected security result.”

> The gateway applies to commands submitted through this API. It is not a substitute for container isolation, and it should not be presented as a guarantee against every possible attack.

## 8. Show the dashboard and audit events

Refresh:

<http://localhost:3000/dashboard-ui/>

Look for the events from the tests, such as:

- `APT_COMMAND` — BLOCKED — HIGH
- `PIP_INSTALL` — BLOCKED — HIGH
- `GIT_CLONE` — BLOCKED — MEDIUM
- `SHELL_COMMAND_CHAINING` — BLOCKED — HIGH

Counters depend on what was run during this demo; do not promise fixed totals.

**Say:**  
“The dashboard provides a central view of sessions and security telemetry. It lets us review which command was blocked, the severity, and the session associated with the event.”

Do not describe expected blocked commands as failures. The dashboard's failure counter refers to failed operations, not successful security blocks.

## 9. Inspect Docker security settings

In PowerShell, using the real attacker container name:

```powershell
docker inspect $attacker --format '{{.Config.User}}'
docker inspect $attacker --format '{{.HostConfig.ReadonlyRootfs}}'
docker inspect $attacker --format '{{json .HostConfig.CapDrop}}'
docker inspect $attacker --format '{{json .HostConfig.CapAdd}}'
docker inspect $attacker --format '{{json .HostConfig.SecurityOpt}}'
```

Expected evidence from the tested Docker configuration:

- User: `1001:1001`
- Read-only root filesystem: `true`
- Dropped capabilities: `["ALL"]`
- Added capability: `["NET_RAW"]`
- Security options include the configured Seccomp profile.

**Say:**  
“These inspection commands show the runtime settings applied to the attacker container. Docker drops all capabilities and adds only NET_RAW in this configuration. Kubernetes uses a different configuration and does not add NET_RAW to the attacker pod.”

## 10. Run automated tests

Run these from PowerShell at the project root:

```powershell
cd C:\Users\rahul\secure-attacker\orchestrator
npm run test:syntax
npm run test:api
npm run test:docker
npm run test:k8s
```

These commands may create temporary test sessions and update generated reports/logs. The Docker test runner cleans up its ephemeral sessions.

Previously reported results in the project work session:

- Syntax check: passed.
- Backend API audit: passed.
- Docker security suite: 8/8 passed.
- Kubernetes security suite: 16/16 passed.

**Do not promise these results for a new machine without rerunning the tests there.** If a test fails live, show the actual output and investigate; do not edit code during the mentor presentation to force a PASS.

## 11. Kubernetes demo / verification (optional)

The main live walkthrough above uses Docker. To verify Kubernetes, first ensure the cluster is running, the project image is available on the Kubernetes node, and the configured Kubernetes credentials are valid.

From PowerShell:

```powershell
cd C:\Users\rahul\secure-attacker\orchestrator
$env:ORCHESTRATOR_PROVIDER = "kubernetes"
npm run test:k8s
```

The verification suite uses the configured Kubernetes context and namespace (default: `attacker-lab`) and checks pod security, session isolation, command validation, audit logs, and dashboard telemetry.

To start the backend using Kubernetes after checking the credentials and configuration:

```powershell
node index.js
```

Open <http://localhost:3000/dashboard-ui/> and use the dashboard to create a test session. Keep in mind that Kubernetes uses NetworkPolicies and a pod security context; Docker uses a private bridge network and Docker security settings. Their capability and Seccomp configurations are not identical.

When finished with the Kubernetes demo, close that server window or stop the server with `Ctrl+C`. In a new PowerShell window, the provider environment setting will not carry over unless you set it there too.

## 12. Cleanup after the demo

Use the dashboard's session deletion function to remove sessions you created. Then verify remaining project containers:

```powershell
docker ps --filter "name=attacker-"
docker ps --filter "name=target-"
```

Do not remove unrelated containers or networks. Only clean up the sessions created for this demo.

## 13. Quick checklist

| Step | Action | Expected evidence |
|---|---|---|
| 1 | Start Docker Desktop | `docker ps` works |
| 2 | Start orchestrator | Server starts without fatal error |
| 3 | Open dashboard | Dashboard loads |
| 4 | Create a session | Attacker, target, network appear |
| 5 | Run `id` | UID 1001 / student user |
| 6 | Resolve target | Target hostname resolves |
| 7 | Curl own target | Nginx response |
| 8 | Try public internet | Request restricted in internal network |
| 9 | Try `apt-get update` inside container | Read-only filesystem blocks changes |
| 10 | Try Session A to Session B target | Connection blocked |
| 11 | Submit prohibited API commands | `BLOCKED` with action/severity |
| 12 | Refresh dashboard | Events are visible |
| 13 | Inspect security configuration | Non-root, read-only, capabilities, Seccomp |
| 14 | Run automated tests | Docker 8/8 and Kubernetes 16/16 in the previously verified run |

## 14. Simple viva answers

**Why run as non-root?**  
To reduce privileges and limit potential damage inside the container.

**Why use a read-only root filesystem?**  
To prevent runtime changes to the base filesystem and make package installation harder.

**Why use private Docker networks?**  
To separate sessions so one student's attacker cannot directly reach another student's target.

**Why use NetworkPolicies in Kubernetes?**  
They control which pods can communicate with each other and which network traffic is allowed.

**Why use Seccomp?**  
It restricts system calls available to a process at the kernel interface.

**Why drop Linux capabilities?**  
To remove unnecessary privileges from the container.

**Why use a command gateway?**  
To check submitted commands against an allowlist and block prohibited operations before execution through the API.

**Why use audit logging and a dashboard?**  
To review security events, their session, action, result, and severity.

**Is a blocked command a failure?**  
No. If the policy is expected to block that command, the block is a successful security control.

## 15. Final conclusion to tell your mentor

“To conclude, our project provides an isolated and access-controlled container lab. It combines session-level network isolation, non-root execution, read-only filesystems, restricted Linux capabilities, Seccomp, command validation, audit logging, and dashboard monitoring. In our previously reported test runs, the Docker security suite passed 8 out of 8 tests and the Kubernetes security suite passed 16 out of 16 tests. These results support the security controls covered by those tests. Thank you.”

---

## Editing this runbook

This file is Markdown (`.md`), so you can edit it in VS Code or Notepad. Update the commands or explanations here as the implementation changes. Never store live tokens, passwords, or generated kubeconfig credentials in this documentation.
