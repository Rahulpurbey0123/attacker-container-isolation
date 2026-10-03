# Changelog

All notable features and milestones of the **Attacker Container Isolation and Access Control** platform are documented in this file.

---

## [1.0.0] — Current Implementation

### Added Features & Capabilities
* **Isolated Multi-Tenant Session Orchestration**:
  * Dynamic creation of isolated student laboratory environments via `POST /sessions`.
  * Dedicated per-session internal Docker bridge networks (`session-<sessionId>-net`).
  * Automated provisioning of target containers (`nginx:alpine`) bound strictly to the session's internal network.
  * Session status inspection (`GET /sessions/:sessionId`) and safe teardown (`DELETE /sessions/:sessionId`).
* **Hardened Attacker Container**:
  * Custom `secure-attacker:1.0` image based on Ubuntu 24.04 with pre-baked network tools (`curl`, `ping`).
  * Enforced non-root user execution (`USER student`, UID/GID `1001:1001`).
  * Locked read-only root filesystem (`ReadonlyRootfs: true`).
  * Scoped, size-capped, non-executable tmpfs mounts for `/tmp` (64MB), `/run` (16MB), and `/home/student/work` (128MB).
* **System Call & Capability Restriction**:
  * Stripped all default Linux kernel capabilities (`CapDrop: ["ALL"]`) with minimal `CapAdd: ["NET_RAW"]` retained for ICMP network diagnostics.
  * Custom Seccomp profile blocking dangerous system calls (`mount`, `pivot_root`, `reboot`, `init_module`, `ptrace`, `setns`, `unshare`, etc.).
* **Network-Level Access Controls**:
  * Docker bridge network isolation configured with `Internal: true` to prevent public Internet egress and data exfiltration.
  * Cross-session network isolation preventing unauthorized lateral communication across student environments.
* **Command Execution Gateway**:
  * REST API endpoint (`POST /sessions/:sessionId/execute`) providing filtered command execution.
  * Blocking of package management utilities (`apt`, `apt-get`, `pip`, `pip3`).
  * Blocking of repository cloning (`git clone`).
  * Blocking of shell chaining and redirection syntax (`;`, `&&`, `||`, `|`, `` ` ``, `$()`, `>`, `<`).
  * Approved command allowlist enforcement (`id`, `whoami`, `pwd`, `ls`, `cat`, `getent hosts`, `ping`, `curl`).
* **Structured Security Auditing & Logging**:
  * Line-delimited JSON audit logs recording all lifecycle actions to `orchestrator/logs/audit.log`.
  * Real-time security event ingestion (`POST /sessions/:sessionId/events`) and logging to `orchestrator/logs/security-events.log`.
  * Severity classification support (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **Security Operations Center (SOC) Dashboard**:
  * Web interface served at `/dashboard-ui/` with real-time telemetry polling every 5 seconds.
  * Dynamic student session management panel with one-click `+ CREATE NEW SESSION` action and clipboard-enabled terminal connection command generator.
  * Telemetry metric cards for Active Sessions, Total Events, Blocked Events, Allowed Events, and High/Critical violations.
  * Real-time Security Severity distribution progress bars and live Recent Security Events table.
* **Automated Security Verification**:
  * Automated 8-point security verification script (`orchestrator/security-tests/verify-security.js`) confirming non-root execution, read-only rootfs, dropped capabilities, package blocks, target reachability, cross-session isolation, and Seccomp attachment.
  * Automated JSON audit report persistence to `orchestrator/security-tests/results/security-report.json`.
