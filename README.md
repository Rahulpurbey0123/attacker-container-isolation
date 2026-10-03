# Development of an Isolated, Access-Controlled Attacker Container Environment

> **Project Short Name**: Attacker Container Isolation and Access Control  
> **Platform Version**: 1.0.0  
> **Environment**: Windows 10/11, Docker Desktop, Node.js, PowerShell

---

## ⚡ Quick Start (Run in 8 Steps)

1. **Start Docker Desktop**: Ensure Docker Desktop is running on Windows.
2. **Open PowerShell & Navigate to Project**:
   ```powershell
   cd c:\Users\rahul\secure-attacker
   ```
3. **Build the Hardened Attacker Image**:
   ```powershell
   docker build -t secure-attacker:1.0 .
   ```
4. **Pull the Target Container Image**:
   ```powershell
   docker pull nginx:alpine
   ```
5. **Install Orchestrator Dependencies**:
   ```powershell
   cd orchestrator
   npm install
   ```
6. **Start the Node.js / Express Orchestrator**:
   ```powershell
   node index.js
   ```
7. **Open the Security Dashboard**:  
   Open your browser to: [`http://localhost:3000/dashboard-ui/`](http://localhost:3000/dashboard-ui/)
8. **Create a Session & Run Automated Security Tests**:
   * Click **`+ CREATE NEW SESSION`** in the dashboard.
   * In a new PowerShell window, run the automated verification suite:
     ```powershell
     node orchestrator/security-tests/verify-security.js <attackerName> <ownTargetName> <otherTargetName>
     ```

---

## Overview

The **Attacker Container Isolation and Access Control** platform creates a secure, Docker-based cybersecurity laboratory where students can perform controlled security testing and ethical hacking exercises inside strictly isolated sessions.

Each student session provisions a dedicated sandbox containing:

```text
Student A
   |
   v
Private Session Network (session-<id>-net)
   |
   +----> Attacker Container (attacker-<id>)
   |
   +----> Target Container   (target-<id>)
```

Every session operates on its own dedicated private bridge network. Communication between different student environments is strictly blocked:

```text
Student A: Attacker A ────► Target A   [ALLOWED - Assigned Session Target]
Student A: Attacker A ───X─► Target B   [BLOCKED - Cross-Session Isolation]
Student A: Attacker A ───X─► Internet   [BLOCKED - No External Egress]
```

---

## Problem Statement

Traditional, unconstrained container laboratories used in cybersecurity training introduce serious operational and security risks:
* **Excessive Privileges**: Attacker containers running as root (`UID 0`) can exploit host-level kernel surfaces.
* **Runtime Package Installation**: Students installing unvetted compilers, rootkits, or attack tools directly into runtime containers.
* **Cross-Session Interference**: Students scanning, attacking, or disrupting neighboring student lab environments.
* **Unrestricted Internet Access**: Containers communicating with external command-and-control servers or exfiltrating data.
* **Dangerous Linux Capabilities**: Retaining administrative capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) allowing device tampering.
* **Dangerous System Calls**: Unrestricted access to kernel manipulation syscalls (`mount`, `pivot_root`, `ptrace`, `unshare`).
* **Lack of Visibility**: Absence of audit trails and real-time security telemetry to detect and record malicious attempts.

---

## Project Objectives

1. **Isolate Attacker Environments**: Provide per-session dedicated Docker sandbox environments.
2. **Restrict Attacker Privileges**: Enforce execution strictly as an unprivileged, non-root user (`1001:1001`).
3. **Prevent Runtime Package Installation**: Lock container root filesystems (`ReadonlyRootfs: true`) and block package manager executions.
4. **Prevent Cross-Session Communication**: Enforce strict network separation between student sessions.
5. **Restrict Internet Access**: Disable public Internet egress for lab bridge networks (`Internal: true`).
6. **Apply Seccomp Restrictions**: Attach custom syscall filtering profiles to block dangerous kernel operations.
7. **Implement Command-Level Security Filtering**: Filter commands through a regex-based execution gateway.
8. **Record Security Events**: Capture structured JSON audit logs for forensics and compliance.
9. **Provide Dashboard-Based Monitoring**: Deliver an administrative Security Operations Center (SOC) dashboard.
10. **Provide Automated Security Verification**: Deliver an automated 8-point test suite ensuring continuous enforcement.

---

## Architecture

The system consists of a four-tier architecture orchestrating isolated Docker resources:

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
                                  | HTTP / REST API
                                  v
                    +---------------------------+
                    |     NODE.JS / EXPRESS     |  (orchestrator/index.js)
                    |       ORCHESTRATOR        |  (Dockerode Client)
                    +---------------------------+
                                  |
                  +---------------+---------------+
                  |                               |
                  v                               v
    +---------------------------+   +---------------------------+
    |      PRIVATE NETWORK      |   |     SECURITY CONTROLS     |
    | (session-<id>-net)        |   | - Non-root (1001:1001)    |
    | (Internal: true)          |   | - Read-only Rootfs        |
    +-------------+-------------+   | - CapDrop: ALL            |
                  |                 | - CapAdd: NET_RAW         |
          +-------+-------+         | - Seccomp Syscall Profile |
          |               |         | - Command Gateway Filter  |
          v               v         | - Structured Audit Logs   |
    +-----------+   +-----------+   +---------------------------+
    | ATTACKER  |   |  TARGET   |
    | CONTAINER |   | CONTAINER |
    |  (Ubuntu) |   |  (Nginx)  |
    +-----------+   +-----------+
```

---

## Technology Stack

The platform is built strictly with the following technologies:

* **Docker & Docker Engine**: Container runtime and network virtualization via Docker Desktop on Windows.
* **Ubuntu 24.04**: Base Linux distribution for the custom hardened attacker container.
* **Nginx Alpine**: Minimal web server image used as the target container for student exercises.
* **Node.js**: Asynchronous JavaScript runtime powering the orchestrator backend and test harness.
* **Express**: Web application framework providing REST API endpoints and static dashboard file serving.
* **Dockerode**: Native Node.js Docker API client library managing containers, networks, and exec instances.
* **JavaScript (Vanilla)**: Clean, native frontend scripting (no external client frameworks).
* **HTML5 & CSS3**: Industrial dark cyber Security Operations Center (SOC) dashboard styling.
* **Linux Seccomp**: Kernel-level system call filtering profile (`orchestrator/security/seccomp-profile.json`).
* **Docker Bridge Networks**: Driver for creating isolated internal virtual subnets.
* **PowerShell**: Windows scripting environment for administration and test verification.

---

## Secure Attacker Container Specification

The attacker container runs the custom **`secure-attacker:1.0`** image built from the root [`Dockerfile`](file:///c:/Users/rahul/secure-attacker/Dockerfile):

* **Base OS**: Ubuntu 24.04 LTS.
* **Approved Build-Time Utilities**: `curl`, `iputils-ping`, `ca-certificates`.
* **Execution Identity**: Non-root user `student` with fixed UID `1001` and GID `1001`.
* **Filesystem Immutability**: `ReadonlyRootfs = true`. The root filesystem is completely locked.
* **Ephemeral Workspaces**: Size-capped tmpfs mounts mapped into memory:
  * `/tmp` (`rw,noexec,nosuid,size=64m`)
  * `/run` (`rw,noexec,nosuid,size=16m`)
  * `/home/student/work` (`rw,nosuid,size=128m`)
* **Capability Restrictions**:
  * `CapDrop = ["ALL"]`: All standard Linux capabilities are removed.
  * `CapAdd = ["NET_RAW"]`: Sole retained capability, enabling `ping` inside the lab network.
* **Seccomp Protection**: Active custom profile filtering kernel system calls.

---

## Network Isolation Architecture

Every session dynamically receives a dedicated Docker bridge network:

```text
Network Name: session-<sessionId>-net
Driver:       bridge
Internal:     true
```

### Security Effects:
1. **Intra-Session Communication**: Attacker container can resolve and access its assigned target container via internal Docker DNS.
2. **Cross-Session Blocking**: Attacker container cannot communicate with targets or attackers in other student sessions.
3. **Egress Prevention**: Setting `Internal: true` configures host iptables to drop all external and public Internet routing. Data exfiltration to the Internet is completely blocked.

---

## Node.js / Express Orchestrator

The backend service [`orchestrator/index.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/index.js) runs on port **`3000`** and handles:
* Connecting to Docker via Dockerode (`//./pipe/docker_engine`).
* Serving the web dashboard at **`http://localhost:3000/dashboard-ui/`**.
* Provisioning and tearing down isolated container pairs and private networks.
* Enforcing the command execution gateway.
* Emitting structured audit and security violation records.

### Confirmed REST API Endpoints:
* `GET /` — Health check
* `GET /docker` — Docker daemon connection and container status
* `POST /sessions` — Create isolated student session
* `GET /sessions/:sessionId` — Check session container status
* `DELETE /sessions/:sessionId` — Delete session and tear down network
* `POST /sessions/:sessionId/execute` — Secure command execution gateway
* `POST /sessions/:sessionId/events` — Ingest and log a security event
* `GET /security-summary` — Aggregated event and severity counts
* `GET /security-report` — Full historical audit report
* `GET /dashboard` — Telemetry and recent security events feed

---

## Session Creation Workflow

When a student clicks **`+ CREATE NEW SESSION`** in the dashboard or sends `POST /sessions`:

```text
Student requests session
         |
         v
Generate Timestamp Session ID (e.g. 1791048868330)
         |
         v
Create Private Internal Network (session-1791048868330-net)
         |
         v
Create & Start Target Container (target-1791048868330 [nginx:alpine])
         |
         v
Create & Start Hardened Attacker (attacker-1791048868330 [secure-attacker:1.0])
  - User: 1001:1001
  - ReadonlyRootfs: true
  - CapDrop: ALL / CapAdd: NET_RAW
  - Seccomp Profile attached
  - Tmpfs on /tmp, /run, /home/student/work
         |
         v
Record Audit Log ("SESSION_CREATED")
         |
         v
Return JSON with Session ID, Network, Attacker, and Target names
```

---

## Command Execution Gateway

The orchestrator exposes an execution gateway at `POST /sessions/:sessionId/execute`:

* **Blocked Package Managers**: Commands matching `apt`, `apt-get`, `pip`, `pip3` (`APT_COMMAND`, `PIP_INSTALL`) are blocked with HTTP 403.
* **Blocked Repository Downloads**: Commands matching `git clone` (`GIT_CLONE`) are blocked with HTTP 403.
* **Blocked Shell Chaining & Redirection**: Shell operators (`;`, `&&`, `||`, `|`, `` ` ``, `$()`, `>`, `<`) are blocked with HTTP 403 (`SHELL_COMMAND_CHAINING`).
* **Command Allowlist**: Only approved commands (`id`, `whoami`, `pwd`, `ls`, `cat`, `getent hosts`, `ping`, `curl`) are permitted to execute.

> **Architectural Boundary**: The Command Gateway is authoritative when users execute commands through the orchestrator API. When direct terminal access (`docker exec`) is used, container-level controls (non-root execution, read-only rootfs, Seccomp, and network isolation) enforce security boundaries.

---

## Audit Logging

The platform maintains two structured, line-delimited JSON log files in `orchestrator/logs/`:

* **`audit.log`**: Tracks administrative operations, session lifecycle events (`SESSION_CREATED`, `SESSION_DELETED`), and command executions.
* **`security-events.log`**: Dedicated log recording policy violations (`COMMAND_BLOCKED`, `SHELL_COMMAND_CHAINING`, `APT_COMMAND`, `PIP_INSTALL`, `GIT_CLONE`).

Each record contains:
* `timestamp`: ISO-8601 UTC timestamp.
* `eventId`: Unique UUID tracking the occurrence.
* `sessionId`: Associated session identifier.
* `attacker`: Name of the offending container.
* `action`: Categorical action identifier.
* `result`: Outcome (`BLOCKED`, `ALLOWED`, `FAILED`, `SUCCESS`).
* `severity`: Severity classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* `description`: Explanatory human-readable summary.

---

## Security Monitoring Utility

The background utility [`orchestrator/security-monitor.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-monitor.js) provides automated history monitoring:
* Periodically polls active attacker containers every 10 seconds.
* Inspects container command histories for unauthorized package manager and download attempts (`apt`, `pip`, `git clone`).
* Emits `AUTOMATED_SECURITY_EVENT` records into `security-events.log` and `audit.log`.

---

## Seccomp System Call Filtering

The custom Seccomp profile [`orchestrator/security/seccomp-profile.json`](file:///c:/Users/rahul/secure-attacker/orchestrator/security/seccomp-profile.json) is loaded at container launch:

* **Default Action**: `SCMP_ACT_ALLOW`
* **Target Architecture**: `SCMP_ARCH_X86_64`
* **Blocked Syscalls (`SCMP_ACT_ERRNO`)**:
  `mount`, `umount`, `umount2`, `pivot_root`, `reboot`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `open_by_handle_at`, `name_to_handle_at`, `swapon`, `swapoff`, `setns`, `unshare`.

*Explanation*: Seccomp restricts low-level Linux kernel system calls that could be leveraged to break out of namespaces, tamper with the host kernel, mount host filesystems, or trace host processes.

---

## Security Operations Center (SOC) Dashboard

Access the real-time web dashboard at:

```text
http://localhost:3000/dashboard-ui/
```

### Dashboard Features:
1. **Telemetry Metrics**: Real-time counters for Active Sessions, Total Events, Blocked Events, Allowed Events, High Severity, and Critical Events.
2. **Student Session Management**: One-click **`+ CREATE NEW SESSION`** button, dynamic loading indicator, session metadata display, and one-click **`COPY TERMINAL COMMAND`** button.
3. **Session Monitoring**: Grid of active container sandboxes with real-time status badges.
4. **Security Controls Enforcement**: Live visual indicators confirming Network Isolation, Read-only Filesystem, Capability Restriction, Seccomp, Command Gateway, and Audit Logging.
5. **Severity Breakdown**: Visual progress bars categorizing event distribution by severity.
6. **Recent Security Events**: Scrollable audit table displaying recent events, timestamps, actions, severities, and blocked results.

---

## Automated Security Verification Suite

The automated test script [`orchestrator/security-tests/verify-security.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-tests/verify-security.js) executes 8 rigorous assertions against active container sandboxes:

```powershell
node orchestrator/security-tests/verify-security.js <attacker> <own-target> <other-target>
```

### Verified Test Assertions:
1. **Non-root user**: Asserts `Config.User == "1001:1001"`.
2. **Read-only root filesystem**: Asserts `HostConfig.ReadonlyRootfs == true`.
3. **All unnecessary capabilities dropped**: Asserts `CapDrop` contains `"ALL"`.
4. **Only NET_RAW capability added**: Asserts `CapAdd` contains strictly `"NET_RAW"`.
5. **Runtime package management blocked**: Asserts `apt-get update` exits with error.
6. **Own target reachable**: Asserts HTTP connection to assigned target succeeds with Nginx welcome page.
7. **Cross-session target blocked**: Asserts HTTP connection to other session's target fails.
8. **Seccomp security profile attached**: Asserts `SecurityOpt` contains `"seccomp=..."`.

### Expected Verification Output:
```text
Total tests : 8
Passed      : 8
Failed      : 0
RESULT: PASS
```

The resulting audit report is stored at [`orchestrator/security-tests/results/security-report.json`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-tests/results/security-report.json).

---

## Safe Session Cleanup

To cleanly remove resources for a specific session without impacting other containers on your system:

```powershell
# Delete containers:
docker rm -f attacker-<sessionId>
docker rm -f target-<sessionId>

# Delete private network:
docker network rm session-<sessionId>-net
```

Alternatively, invoke the orchestrator deletion API:
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/sessions/<sessionId>" -Method DELETE
```

---

## Documentation Index

Detailed guides are available in the [`docs/`](file:///c:/Users/rahul/secure-attacker/docs/) folder:

* [`docs/SETUP.md`](file:///c:/Users/rahul/secure-attacker/docs/SETUP.md): Step-by-step setup and environment configuration.
* [`docs/DEMO_GUIDE.md`](file:///c:/Users/rahul/secure-attacker/docs/DEMO_GUIDE.md): Word-by-word demonstration script and test executions.
* [`docs/TROUBLESHOOTING.md`](file:///c:/Users/rahul/secure-attacker/docs/TROUBLESHOOTING.md): Common configuration issues, PowerShell tips, and fixes.
* [`docs/API.md`](file:///c:/Users/rahul/secure-attacker/docs/API.md): Complete REST API endpoint reference and payloads.
* [`docs/SECURITY_MODEL.md`](file:///c:/Users/rahul/secure-attacker/docs/SECURITY_MODEL.md): 10-layer defense-in-depth threat model.
* [`docs/PROJECT_STRUCTURE.md`](file:///c:/Users/rahul/secure-attacker/docs/PROJECT_STRUCTURE.md): Detailed repository file structure breakdown.
* [`docs/PROJECT_STATUS.md`](file:///c:/Users/rahul/secure-attacker/docs/PROJECT_STATUS.md): Recorded test matrix and verification results.
* [`docs/MEMORY.md`](file:///c:/Users/rahul/secure-attacker/docs/MEMORY.md): Maintainer architecture decisions and rationale.
* [`orchestrator/requirements.md`](file:///c:/Users/rahul/secure-attacker/orchestrator/requirements.md): System dependencies and package requirements.
* [`CHANGELOG.md`](file:///c:/Users/rahul/secure-attacker/CHANGELOG.md): Initial release milestone documentation.
