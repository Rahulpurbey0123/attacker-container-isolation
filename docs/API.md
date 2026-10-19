# Orchestrator REST API Specification

This document provides complete documentation for the HTTP endpoints exposed by the Node.js / Express orchestrator service in `orchestrator/index.js` on port `3000` (bound to `127.0.0.1`).

> [!IMPORTANT]
> **LOCAL DEMONSTRATION ONLY — SECURITY ARCHITECTURE NOTICE**
> The Express orchestrator service is explicitly bound to `127.0.0.1` (`HOST = process.env.HOST || "127.0.0.1"`). All API endpoints currently operate without authentication or per-user access control.
> **Deployment Limitation**: This unauthenticated design is intended solely for local educational and laboratory demonstration. Before deploying to untrusted networks or multi-user environments, a security gateway MUST be added providing:
> 1. Authentication (e.g., JWT Bearer tokens, mTLS, or OAuth2/OIDC).
> 2. Per-session authorization (ensuring that a student/caller can only inspect, execute commands within, or delete their own assigned `sessionId`).
> 3. Rate limiting and ingress filtering.

---

## Base URL
```text
http://127.0.0.1:3000
```

---

## 1. System Health & Infrastructure

### `GET /`
Returns the status, version, active orchestration provider, and binding configuration.

* **Method**: `GET`
* **URL**: `/`
* **Response `200 OK`**:
```json
{
  "project": "Attacker Container Isolation and Access Control",
  "status": "Orchestrator is running",
  "version": "1.0.0",
  "orchestratorProvider": "kubernetes",
  "boundHost": "127.0.0.1",
  "securityNotice": "Local-demo-only. Unauthenticated API must not be exposed to untrusted networks."
}
```

---

### `GET /docker`
Checks connectivity with the local Docker daemon and lists currently recognized containers.

* **Method**: `GET`
* **URL**: `/docker`
* **Response `200 OK`**:
```json
{
  "docker": "connected",
  "containers": [
    {
      "name": "/attacker-s1792303072725",
      "image": "secure-attacker:1.0",
      "status": "Up 5 minutes"
    },
    {
      "name": "/target-s1792303072725",
      "image": "nginx:alpine",
      "status": "Up 5 minutes"
    }
  ]
}
```

---

### `GET /k8s`
Checks connectivity with the Kubernetes API server, verifying context and least-privilege identity.

* **Method**: `GET`
* **URL**: `/k8s`
* **Response `200 OK`**:
```json
{
  "status": "connected",
  "provider": "kubernetes",
  "context": "attacker-orchestrator-context",
  "namespace": "attacker-lab",
  "effectiveUser": "attacker-orchestrator-sa",
  "isLeastPrivilege": true,
  "containers": [
    {
      "name": "/attacker-demo-session",
      "image": "secure-attacker:1.0",
      "status": "Running"
    }
  ]
}
```

---

## 2. Session Lifecycle Management

### Session ID Validation Rules
All session endpoints validate the `sessionId` path/body parameter against Kubernetes DNS-1123 label standards:
* Must consist of lowercase alphanumeric characters (`a-z`, `0-9`) or hyphens (`-`).
* Must start and end with an alphanumeric character.
* Must be between 1 and 50 characters in length.
* Uppercase characters, underscores, directory traversal sequences, or shell metacharacters are strictly rejected with `400 Bad Request`.

---

### `POST /sessions`
Provisions an isolated student laboratory session via the active provider (Docker or Kubernetes).
* Under Docker: Creates a private internal bridge network (`session-<id>-net`), a hardened attacker container (`attacker-<id>`), and an Nginx target container (`target-<id>`).
* Under Kubernetes: Deploys target deployment and ClusterIP service, attacker pod, and dual bidirectional NetworkPolicies.

* **Method**: `POST`
* **URL**: `/sessions`
* **Headers**: `Content-Type: application/json`
* **Request Body** (optional):
```json
{
  "sessionId": "demo-session-42"
}
```
*(If omitted, a valid DNS-1123 session ID in format `s<timestamp>` is automatically generated).*

* **Response `201 Created`**:
```json
{
  "message": "Isolated session created successfully",
  "sessionId": "s1792303072725",
  "provider": "kubernetes",
  "network": "k8s-cni-networkpolicy",
  "attacker": "attacker-s1792303072725",
  "target": "target-s1792303072725"
}
```

* **Response `400 Bad Request`** (Invalid session ID format):
```json
{
  "message": "Invalid session ID format. Must be Kubernetes DNS-1123 compatible (lowercase alphanumeric and hyphens, 1-50 characters).",
  "sessionId": "INVALID_UPPERCASE"
}
```

---

### `GET /sessions/:sessionId`
Retrieves the runtime status of an isolated session.

* **Method**: `GET`
* **URL**: `/sessions/:sessionId`
* **Response `200 OK`**:
```json
{
  "sessionId": "s1792303072725",
  "provider": "kubernetes",
  "attacker": {
    "name": "attacker-s1792303072725",
    "status": "Running",
    "running": true
  },
  "target": {
    "name": "target-s1792303072725",
    "status": "running",
    "running": true
  },
  "network": "k8s-cni-networkpolicy"
}
```

* **Response `404 Not Found`**:
```json
{
  "message": "Session not found",
  "sessionId": "s1792303072725",
  "error": "Session not found"
}
```

---

### `DELETE /sessions/:sessionId`
Safely destroys a laboratory session. Verifies resource ownership labels before deletion, only ignores confirmed 404 errors, and confirms owned resources are deleted before reporting success.

* **Method**: `DELETE`
* **URL**: `/sessions/:sessionId`
* **Response `200 OK`**:
```json
{
  "message": "Session deleted successfully",
  "sessionId": "s1792303072725",
  "provider": "kubernetes"
}
```

---

## 3. Secure Command Execution Gateway

### `POST /sessions/:sessionId/execute`
Executes an approved, single-line command inside the student's isolated attacker container.

#### Execution Controls & Limits:
1. **Command Allowlist**: Only pre-approved administrative/diagnostic utilities are permitted (`id`, `whoami`, `pwd`, `ls`, `cat`, `getent hosts`, `ping`, `curl`).
2. **Prohibited Tools**: Package management (`apt`, `apt-get`, `pip`) and repository cloning (`git clone`) are blocked (`403 Forbidden`).
3. **Shell Chaining & Metacharacter Blocking**: Operators `;`, `&&`, `||`, `|`, `` ` ``, `$()`, `>`, `<` are blocked (`403 Forbidden`).
4. **Execution Timeout**: Commands have a strict execution timeout (default 10 seconds). Exceeding this limit terminates streams and returns `408 Request Timeout`.
5. **Output Limit**: Output is capped at 64KB (65,536 bytes). Excess output is safely truncated without buffering exhaustion.

* **Method**: `POST`
* **URL**: `/sessions/:sessionId/execute`
* **Headers**: `Content-Type: application/json`
* **Request Body**:
```json
{
  "command": "id"
}
```

* **Response `200 OK`** (Approved Command):
```json
{
  "message": "Command executed",
  "provider": "kubernetes",
  "result": "SUCCESS",
  "exitCode": 0,
  "output": "uid=1001(student) gid=1001(student) groups=1001(student)\n"
}
```

* **Response `403 Forbidden`** (Blocked Package Management):
```json
{
  "message": "Runtime APT package-management command blocked",
  "action": "APT_COMMAND",
  "result": "BLOCKED",
  "severity": "HIGH",
  "eventId": "f7a3f4b5-6831-4830-b995-1f9e1e2474f8"
}
```

* **Response `403 Forbidden`** (Blocked Shell Chaining):
```json
{
  "message": "Shell operator (SEMICOLON) blocked by security policy",
  "action": "SHELL_COMMAND_CHAINING",
  "result": "BLOCKED",
  "severity": "HIGH",
  "eventId": "1bb3dc75-9c97-4001-ba84-c6f37ee0bf10"
}
```

---

## 4. Security Events & Audit Logging

### `POST /sessions/:sessionId/events`
Records an audit/security event in structured JSONL log files.

* **Method**: `POST`
* **URL**: `/sessions/:sessionId/events`
* **Request Body**:
```json
{
  "action": "PORT_SCAN_ATTEMPT",
  "result": "BLOCKED",
  "severity": "HIGH",
  "description": "Unauthorized scan attempt blocked"
}
```

* **Response `201 Created`**:
```json
{
  "message": "Security event recorded successfully",
  "event": "SECURITY_EVENT",
  "eventId": "2cb1db0e-9477-44ae-b8df-35b8095b2257",
  "sessionId": "s1792303072725",
  "action": "PORT_SCAN_ATTEMPT",
  "result": "BLOCKED",
  "severity": "HIGH"
}
```

---

### `GET /security-summary` & `GET /security-report`
Provides summary metrics and structured audit records of all blocked, allowed, and recorded security events.

---

### `GET /dashboard`
Provides consolidated telemetry for the Web SOC Dashboard, combining active session counts, container statuses, and the 10 most recent security events.
