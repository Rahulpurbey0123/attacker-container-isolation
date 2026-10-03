# Maintainer Architecture & Decision Memory

This document preserves architectural context, design decisions, and operational memory for maintainers and developers working on the **Attacker Container Isolation and Access Control** platform.

---

## 1. Project Background & Core Mission

Cybersecurity education environments face a fundamental tension:
* Students require interactive access to an attacker container equipped with networking and exploration utilities to learn ethical hacking concepts.
* Unconstrained attacker containers can escape isolation, install unauthorized software, attack the host or cloud infrastructure, interfere with other students' environments, or exfiltrate data.

This project resolves this tension by providing an automated orchestrator that provisions isolated, hardened per-student sandboxes managed under defense-in-depth security principles.

---

## 2. Key Security Architecture Decisions

### Why `Internal: true` is Enforced on Docker Networks
* **Rationale**: Docker bridge networks by default permit outbound network egress to the host's default gateway. By setting `Internal: true`, Docker configures iptables rules that completely prevent traffic from being routed outside the bridge network.
* **Effect**: Prevents external command-and-control communication, external malware downloads, and denial-of-service against external systems.

### Why the Container Runs as Non-Root (`1001:1001`)
* **Rationale**: Running containers as root (`UID 0`) gives in-container processes the same user ID as root on the host machine. If a container breakout or kernel vulnerability occurs, the attacker has instant host-level root control.
* **Effect**: Enforcing `USER student` (UID:GID `1001:1001`) both in the image build and at container start prevents privileged operations and mitigates container breakout risk.

### Why the Root Filesystem is Read-Only (`ReadonlyRootfs: true`)
* **Rationale**: Traditional containers allow write access to their root filesystem layer. An attacker can modify system binaries, install rootkits, or alter `/etc` configurations.
* **Effect**: `ReadonlyRootfs: true` ensures the container's base filesystem cannot be written to. Package managers (`apt-get`, `dpkg`) instantly fail. Ephemeral scratch space is strictly isolated to size-capped, non-executable tmpfs mounts (`/tmp`, `/run`, `/home/student/work`).

### Why `ALL` Capabilities are Dropped & Only `NET_RAW` is Added
* **Rationale**: Standard Docker containers run with default Linux capabilities (e.g. `CAP_CHOWN`, `CAP_FOWNER`, `CAP_KILL`, `CAP_SYS_CHROOT`). These capabilities are unnecessary for an attacker lab container and expand the attack surface.
* **Effect**: `CapDrop: ["ALL"]` strips all default capabilities. `CapAdd: ["NET_RAW"]` is added back as the minimum required capability so standard tools like `ping` can craft ICMP packets inside the internal network.

### Why Seccomp Syscall Filtering is Applied
* **Rationale**: Linux capabilities do not restrict all kernel-level system calls. Dangerous syscalls such as `mount`, `pivot_root`, `reboot`, `init_module`, `ptrace`, `setns`, and `unshare` could allow kernel module injection, process tracing, or namespace switching.
* **Effect**: The Seccomp profile blocks these specific syscalls at the kernel entry point, returning `SCMP_ACT_ERRNO`.

### Why the Command Execution Gateway Exists
* **Rationale**: When commands are executed programmatically via the orchestrator API (`POST /sessions/:sessionId/execute`), the gateway adds an application-level security boundary that inspects and rejects suspicious command strings (package managers, git clone, shell chaining) before they reach container execution.
* **Critical Architectural Limitation**: The Command Gateway is authoritative only for commands sent through the orchestrator's HTTP API. When a student uses `docker exec -it` directly, the container-level controls (non-root, read-only rootfs, dropped capabilities, Seccomp, and network isolation) enforce security boundaries.

### Why Structured JSON Audit Logging is Used
* **Rationale**: Plain unstructured text logs are difficult to parse, search, and correlate.
* **Effect**: Every security violation and lifecycle action is assigned a UUID `eventId` and ISO-8601 `timestamp` and written as line-delimited JSON to `audit.log` and `security-events.log`, enabling instant aggregation and dashboard streaming.

---

## 3. Important File Locations & References

| Component | File Path |
|---|---|
| Image Build Specification | [`Dockerfile`](file:///c:/Users/rahul/secure-attacker/Dockerfile) |
| Orchestrator Express Server | [`orchestrator/index.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/index.js) |
| Structured Audit Logger | [`orchestrator/logger.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/logger.js) |
| Background Monitor Daemon | [`orchestrator/security-monitor.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-monitor.js) |
| Seccomp Profile | [`orchestrator/security/seccomp-profile.json`](file:///c:/Users/rahul/secure-attacker/orchestrator/security/seccomp-profile.json) |
| Automated Security Tests | [`orchestrator/security-tests/verify-security.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-tests/verify-security.js) |
| Security Test Results | [`orchestrator/security-tests/results/security-report.json`](file:///c:/Users/rahul/secure-attacker/orchestrator/security-tests/results/security-report.json) |
| Active Frontend Dashboard | [`orchestrator/dashboard/index.html`](file:///c:/Users/rahul/secure-attacker/orchestrator/dashboard/index.html) |
| Active Dashboard Script | [`orchestrator/dashboard/dashboard.js`](file:///c:/Users/rahul/secure-attacker/orchestrator/dashboard/dashboard.js) |
| Active Dashboard Styles | [`orchestrator/dashboard/style.css`](file:///c:/Users/rahul/secure-attacker/orchestrator/dashboard/style.css) |
| Audit Logs | [`orchestrator/logs/audit.log`](file:///c:/Users/rahul/secure-attacker/orchestrator/logs/audit.log) |
| Security Violation Logs | [`orchestrator/logs/security-events.log`](file:///c:/Users/rahul/secure-attacker/orchestrator/logs/security-events.log) |

---

## 4. Key Operational Commands Reference

### Build Image
```powershell
docker build -t secure-attacker:1.0 .
```

### Start Orchestrator
```powershell
cd orchestrator
node index.js
```

### Run 8-Point Verification
```powershell
node orchestrator/security-tests/verify-security.js <attackerName> <ownTargetName> <otherTargetName>
```

### Safe Single-Session Cleanup
```powershell
docker rm -f attacker-<sessionId>
docker rm -f target-<sessionId>
docker network rm session-<sessionId>-net
```
