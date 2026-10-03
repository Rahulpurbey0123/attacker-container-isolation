# Troubleshooting Guide & Common Issues

This document covers frequently encountered errors, configuration mistakes, and operational troubleshooting steps for the **Attacker Container Isolation and Access Control** platform.

---

## 1. Node.js Cannot Find `verify-security.js`

### Symptom:
```text
Error: Cannot find module '.../security-tests/verify-security.js'
```

### Cause:
Running the verification command with an incorrect relative path or omitting the `orchestrator` directory prefix.

### Solution:
From the project root (`c:\Users\rahul\secure-attacker`), execute the script using the correct path:

```powershell
# Incorrect:
node security-tests/verify-security.js

# Correct:
node orchestrator/security-tests/verify-security.js <attacker> <own-target> <other-target>
```

Remember that the script strictly requires **three positional arguments**:
1. Name of the primary attacker container (`attacker-<id>`)
2. Name of the primary attacker's assigned target (`target-<id>`)
3. Name of a different session's target (`target-<other_id>`)

---

## 2. PowerShell `curl` Command Behavior

### Symptom:
Commands such as `curl -X POST ...` fail with parameter binding errors or behave unexpectedly in PowerShell.

### Cause:
On Windows PowerShell (5.1 and earlier versions), `curl` is a built-in alias for `Invoke-WebRequest`, not the native cURL executable. Passing Unix-style flags (like `-X`, `-d`, or `-H`) produces PowerShell parsing errors.

### Solution:
Always use `Invoke-RestMethod` or `curl.exe` when testing API endpoints from PowerShell:

```powershell
# Recommended for PowerShell:
Invoke-RestMethod -Uri "http://localhost:3000/sessions" -Method POST -ContentType "application/json"

# Alternatively, invoke native curl.exe explicitly:
curl.exe -s -X POST http://localhost:3000/sessions
```

---

## 3. HTTP 403 Error from `Invoke-RestMethod` During Security Tests

### Symptom:
When executing blocked commands (such as `apt-get update` or `pip install`), PowerShell prints a red `WebException`:
```text
Invoke-RestMethod : The remote server returned an error: (403) Forbidden.
```

### Explanation:
**This is expected behavior.** The Command Gateway explicitly returns an **HTTP 403 Forbidden** status when a command violates security policy (e.g. `APT_COMMAND`, `SHELL_COMMAND_CHAINING`, `PIP_INSTALL`, or `GIT_CLONE`). In PowerShell, `Invoke-RestMethod` throws an exception for non-2xx status codes by default.

### Solution:
Catch the exception to read the structured JSON response emitted by the orchestrator:

```powershell
try {
    Invoke-RestMethod -Uri "http://localhost:3000/sessions/<sessionId>/execute" `
        -Method POST `
        -ContentType "application/json" `
        -Body '{"command":"apt-get update"}'
} catch {
    $stream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $reader.ReadToEnd()
}
```

The output will confirm:
```json
{"message":"Command blocked by security policy","action":"APT_COMMAND","result":"BLOCKED","severity":"HIGH",...}
```

---

## 4. Docker Connection Failure (`ENOENT //./pipe/docker_engine`)

### Symptom:
```text
Error: connect ENOENT //./pipe/docker_engine
```
or
```text
docker: connection failed
```

### Cause:
Docker Desktop is either stopped, starting up, or not exposing the named pipe on Windows.

### Solution:
1. Ensure Docker Desktop is launched and the whale icon in the Windows system tray indicates "Docker Desktop is running".
2. In PowerShell, test Docker connectivity directly:
   ```powershell
   docker ps
   ```
3. Restart the orchestrator service after Docker is ready.

---

## 5. Missing Image: `secure-attacker:1.0`

### Symptom:
Session creation fails with:
```text
Failed to create isolated session: No such image: secure-attacker:1.0
```

### Cause:
The custom attacker container image has not yet been built from the root `Dockerfile`.

### Solution:
From the project root (`c:\Users\rahul\secure-attacker`), build the image:

```powershell
docker build -t secure-attacker:1.0 .
```

Verify that the image is present:

```powershell
docker images secure-attacker:1.0
```

---

## 6. Port 3000 Already in Use (`EADDRINUSE`)

### Symptom:
```text
Error: listen EADDRINUSE: address already in use :::3000
```

### Cause:
Another instance of the orchestrator or another service is already listening on TCP port 3000.

### Solution:
Identify and terminate the process holding port 3000:

```powershell
# Identify process using port 3000:
Get-NetTCPConnection -LocalPort 3000 | Select-Object OwningProcess

# Terminate process by PID:
Stop-Process -Id <PID> -Force
```

Then restart `node orchestrator/index.js`.

---

## 7. Cleaning Up Specific Session Resources After Demos

### Safe Individual Session Cleanup:
To clean up a specific session without impacting other containers on your workstation:

```powershell
# Remove attacker and target containers:
docker rm -f attacker-<sessionId>
docker rm -f target-<sessionId>

# Remove the session's isolated bridge network:
docker network rm session-<sessionId>-net
```

### Cleanup via Orchestrator API:
The orchestrator also exposes a session deletion endpoint:

```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions/<sessionId>" -Method DELETE
```

> **Warning**: Avoid running blanket commands like `docker system prune -a --volumes` as this will remove non-project images, containers, and volumes.
