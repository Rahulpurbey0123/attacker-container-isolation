# Orchestrator REST API Specification

This document provides complete documentation for the HTTP endpoints exposed by the Node.js / Express orchestrator service in `orchestrator/index.js` on port `3000`.

---

## Base URL
```text
http://localhost:3000
```

---

## 1. System Health & Infrastructure

### `GET /`
Returns the status and version of the orchestrator service.

* **Method**: `GET`
* **URL**: `/`
* **Response `200 OK`**:
```json
{
  "project": "Attacker Container Isolation and Access Control",
  "status": "Orchestrator is running",
  "version": "1.0.0"
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
      "name": "/attacker-1791048868330",
      "image": "secure-attacker:1.0",
      "status": "Up 5 minutes"
    },
    {
      "name": "/target-1791048868330",
      "image": "nginx:alpine",
      "status": "Up 5 minutes"
    }
  ]
}
```
* **Response `500 Internal Server Error`**:
```json
{
  "docker": "connection failed",
  "error": "connect ENOENT //./pipe/docker_engine"
}
```

---

## 2. Session Lifecycle Management

### `POST /sessions`
Provisions an isolated student laboratory session. Creates a private internal bridge network (`session-<id>-net`), a hardened attacker container (`attacker-<id>`), and an Nginx target container (`target-<id>`).

* **Method**: `POST`
* **URL**: `/sessions`
* **Headers**: `Content-Type: application/json`
* **Request Body**: `{}` *(no body parameters required; session ID is generated using server epoch timestamp)*
* **Response `201 Created`**:
```json
{
  "message": "Isolated session created successfully",
  "sessionId": "1791048868330",
  "network": "session-1791048868330-net",
  "attacker": "attacker-1791048868330",
  "target": "target-1791048868330"
}
```
* **Response `500 Internal Server Error`**:
```json
{
  "message": "Failed to create isolated session",
  "error": "..."
}
```

---

### `GET /sessions/:sessionId`
Inspects the runtime state and container status of an existing session.

* **Method**: `GET`
* **URL**: `/sessions/:sessionId`
* **Response `200 OK`**:
```json
{
  "sessionId": "1791048868330",
  "attacker": {
    "name": "attacker-1791048868330",
    "status": "running",
    "running": true
  },
  "target": {
    "name": "target-1791048868330",
    "status": "running",
    "running": true
  },
  "network": "session-1791048868330-net"
}
```
* **Response `404 Not Found`**:
```json
{
  "message": "Session not found",
  "sessionId": "1791048868330",
  "error": "..."
}
```

---

### `DELETE /sessions/:sessionId`
Tears down and deletes an isolated session, removing the attacker container, target container, and the session's internal bridge network.

* **Method**: `DELETE`
* **URL**: `/sessions/:sessionId`
* **Response `200 OK`**:
```json
{
  "message": "Session deleted successfully",
  "sessionId": "1791048868330"
}
```
* **Response `500 Internal Server Error`**:
```json
{
  "message": "Failed to delete session",
  "error": "..."
}
```

---

## 3. Secure Command Execution Gateway

### `POST /sessions/:sessionId/execute`
Executes an approved, single command inside the session's hardened attacker container. Checks the command against strict blocked command patterns (APT, PIP, Git) and shell chaining rules before verifying against an allowlist of permitted commands.

* **Method**: `POST`
* **URL**: `/sessions/:sessionId/execute`
* **Headers**: `Content-Type: application/json`
* **Request Body**:
```json
{
  "command": "id"
}
```

#### Gateway Allowlist:
* `id`
* `whoami`
* `pwd`
* `ls [path]`
* `cat <file>`
* `getent hosts <hostname>`
* `ping [-c N] <hostname>`
* `curl [--connect-timeout N] http(s)://<url>`

#### Gateway Blocked Patterns:
* Package management: `apt`, `apt-get`, `pip`, `pip3`
* Repository downloads: `git clone`
* Shell operators / chaining: `;`, `&&`, `||`, `|`, `` ` ``, `$()`, `>`, `<`

#### Responses:
* **Response `200 OK` (Command Permitted & Executed)**:
```json
{
  "message": "Command executed",
  "result": "SUCCESS",
  "exitCode": 0,
  "output": "uid=1001(student) gid=1001(student) groups=1001(student)\n"
}
```
* **Response `403 Forbidden` (Command Blocked by Policy)**:
```json
{
  "message": "Command blocked by security policy",
  "action": "APT_COMMAND",
  "result": "BLOCKED",
  "severity": "HIGH",
  "eventId": "f7d38392-8072-4638-aa03-5d55e0984183"
}
```
* **Response `403 Forbidden` (Command Not in Allowlist)**:
```json
{
  "message": "Command is not allowed",
  "action": "COMMAND_NOT_ALLOWED",
  "result": "BLOCKED",
  "severity": "MEDIUM",
  "eventId": "b968a303-dc30-4e34-9278-dfb234479cb2"
}
```
* **Response `400 Bad Request`**:
```json
{
  "message": "command is required"
}
```
* **Response `404 Not Found`**:
```json
{
  "message": "Session not found",
  "sessionId": "...",
  "error": "..."
}
```
* **Response `409 Conflict`**:
```json
{
  "message": "Attacker container is not running",
  "sessionId": "..."
}
```

---

## 4. Security Telemetry & Event Ingestion

### `POST /sessions/:sessionId/events`
Records a structured security event into `orchestrator/logs/security-events.log` and `orchestrator/logs/audit.log`.

* **Method**: `POST`
* **URL**: `/sessions/:sessionId/events`
* **Headers**: `Content-Type: application/json`
* **Request Body**:
```json
{
  "action": "PORT_SCAN",
  "result": "BLOCKED",
  "severity": "HIGH",
  "description": "Port scan against unauthorized subnet blocked"
}
```
* **Validation Rules**:
  * `action`: Required string, 2 to 100 characters.
  * `result`: Required string, one of `["BLOCKED", "ALLOWED", "FAILED", "SUCCESS"]`.
  * `severity`: Optional string (defaults to `MEDIUM`), one of `["LOW", "MEDIUM", "HIGH", "CRITICAL"]`.
* **Response `201 Created`**:
```json
{
  "message": "Security event recorded successfully",
  "event": "SECURITY_EVENT",
  "eventId": "7a353fe2-3d84-4861-a59e-1dc63c29994c",
  "sessionId": "1791048868330",
  "action": "PORT_SCAN",
  "result": "BLOCKED",
  "severity": "HIGH"
}
```

---

### `GET /security-summary`
Aggregates security event counts categorized by result (`BLOCKED`, `ALLOWED`, `FAILED`, `SUCCESS`) and severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

* **Method**: `GET`
* **URL**: `/security-summary`
* **Response `200 OK`**:
```json
{
  "totalEvents": 14,
  "blockedEvents": 13,
  "allowedEvents": 1,
  "failedEvents": 0,
  "successfulEvents": 0,
  "severity": {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 10,
    "CRITICAL": 1
  }
}
```

---

### `GET /security-report`
Provides a full audit trail report of all logged security events.

* **Method**: `GET`
* **URL**: `/security-report`
* **Response `200 OK`**:
```json
{
  "reportGeneratedAt": "2026-10-03T18:00:00.000Z",
  "summary": {
    "totalEvents": 14,
    "blockedEvents": 13,
    "allowedEvents": 1,
    "failedEvents": 0,
    "successfulEvents": 0,
    "severity": {
      "LOW": 1,
      "MEDIUM": 2,
      "HIGH": 10,
      "CRITICAL": 1
    }
  },
  "events": [
    {
      "timestamp": "2026-10-03T08:12:44.648Z",
      "eventId": "b23ce7d5-3267-4857-818b-ac5f61833b2b",
      "sessionId": "1791014236793",
      "attacker": "attacker-1791014236793",
      "action": "SHELL_COMMAND_CHAINING",
      "result": "BLOCKED",
      "severity": "HIGH",
      "description": "Shell chaining or redirection pattern blocked"
    }
  ]
}
```

---

### `GET /dashboard`
Aggregated telemetry feed consumed by the frontend web dashboard, including active container counts and the 10 most recent security events.

* **Method**: `GET`
* **URL**: `/dashboard`
* **Response `200 OK`**:
```json
{
  "dashboard": "SECURITY DASHBOARD",
  "activeSessions": 1,
  "totalEvents": 14,
  "blockedEvents": 13,
  "allowedEvents": 1,
  "failedEvents": 0,
  "criticalEvents": 1,
  "highEvents": 10,
  "recentEvents": [
    {
      "timestamp": "2026-10-03T08:12:44.648Z",
      "action": "SHELL_COMMAND_CHAINING",
      "result": "BLOCKED",
      "severity": "HIGH",
      "sessionId": "1791014236793",
      "description": "Shell chaining or redirection pattern blocked"
    }
  ]
}
```

---

## 5. Web Dashboard Static Route

### `GET /dashboard-ui/`
Serves the static frontend Security Operations Center (SOC) dashboard from `orchestrator/dashboard/`.

* **Method**: `GET`
* **URL**: `/dashboard-ui/`
* **Response `200 OK`**: `text/html`
