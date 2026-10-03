# Layered Security Architecture & Threat Model

The **Attacker Container Isolation and Access Control** platform implements a **defense-in-depth** architecture designed to sandbox untrusted student activity during cybersecurity exercises. Rather than relying on a single boundary, the system enforces controls across ten distinct security layers.

---

## The 10 Security Layers

```text
+--------------------------------------------------------------------------+
| Layer 10: Automated Verification (verify-security.js)                    |
+--------------------------------------------------------------------------+
| Layer 9:  Dashboard Monitoring (Web UI & Telemetry Polling)              |
+--------------------------------------------------------------------------+
| Layer 8:  Audit Logging (audit.log & security-events.log)                |
+--------------------------------------------------------------------------+
| Layer 7:  Command Execution Gateway (Regex Filtering & Allowlist)        |
+--------------------------------------------------------------------------+
| Layer 6:  Seccomp Syscall Filtering (seccomp-profile.json)               |
+--------------------------------------------------------------------------+
| Layer 5:  Linux Capability Restrictions (CapDrop: ALL, CapAdd: NET_RAW)  |
+--------------------------------------------------------------------------+
| Layer 4:  Read-Only Filesystem & Tmpfs Mounts (ReadonlyRootfs: true)     |
+--------------------------------------------------------------------------+
| Layer 3:  Non-Root Execution (USER student 1001:1001)                    |
+--------------------------------------------------------------------------+
| Layer 2:  Network Isolation (Docker Bridge, Internal: true)              |
+--------------------------------------------------------------------------+
| Layer 1:  Session Sandbox Isolation (Per-session Docker Environments)    |
+--------------------------------------------------------------------------+
```

---

### Layer 1 — User & Session Sandbox Isolation
* **Description**: Every student session is provisioned as an independent pair of containers (an attacker container and a target container) bound to a dedicated private network.
* **Implementation**: `orchestrator/index.js` (`POST /sessions`).
* **Threat Addressed**: Interference between students, shared state contamination, or simultaneous resource collision.
* **Limitations**: Containers share the underlying host OS kernel. Container breakouts could theoretically compromise the host if kernel-level isolation fails.

---

### Layer 2 — Network Isolation
* **Description**: Each session is assigned its own Docker bridge network (`session-<id>-net`) created with `Internal: true`.
* **Implementation**: `orchestrator/index.js` (`docker.createNetwork`).
* **Threat Addressed**:
  * Cross-session lateral scanning: Attacker A cannot communicate with Target B or Attacker B.
  * Data exfiltration & unauthorized egress: Public Internet access is disabled for the session network.
* **Limitations**: `Internal: true` prevents outbound network traffic originating from the bridge network, but does not provide cryptographic packet inspection or intra-session network segmentation between attacker and its assigned target.

---

### Layer 3 — Non-Root User Execution
* **Description**: The attacker container executes as user `student` with UID `1001` and GID `1001`, explicitly set in both the Dockerfile and container runtime host configuration.
* **Implementation**: `Dockerfile` (`USER student`) and `orchestrator/index.js` (`User: "1001:1001"`).
* **Threat Addressed**: Prevents privileged system operations, UID 0 privilege escalation attacks, root-owned file modifications, and direct device manipulation.
* **Limitations**: A local privilege escalation vulnerability in the Linux kernel or a misconfigured setuid binary could potentially allow a user to elevate privileges.

---

### Layer 4 — Read-Only Root Filesystem & Tmpfs
* **Description**: The container's root filesystem is mounted strictly read-only (`ReadonlyRootfs: true`). Writable storage is limited to explicitly scoped, non-persistent memory mounts:
  * `/tmp` (`rw,noexec,nosuid,size=64m`)
  * `/run` (`rw,noexec,nosuid,size=16m`)
  * `/home/student/work` (`rw,nosuid,size=128m`)
* **Implementation**: `orchestrator/index.js` (`HostConfig.ReadonlyRootfs` and `HostConfig.Tmpfs`).
* **Threat Addressed**: Prevents persistence, malware installation, runtime trojanization of system binaries, and unauthorized modification of configuration files.
* **Limitations**: Files written to `/home/student/work` are writable during container execution; memory exhaustion within tmpfs bounds can consume RAM up to the configured limits.

---

### Layer 5 — Linux Capability Restrictions
* **Description**: The container drops all standard Linux kernel capabilities (`CapDrop: ["ALL"]`) and retains strictly one single capability: `CapAdd: ["NET_RAW"]`.
* **Implementation**: `orchestrator/index.js` (`HostConfig.CapDrop`, `HostConfig.CapAdd`).
* **Threat Addressed**: Strips dangerous privileges such as `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`, and `CAP_CHOWN`. `NET_RAW` is preserved strictly to allow standard security networking tools (such as `ping`) to generate ICMP packets.
* **Limitations**: `NET_RAW` allows raw packet crafting inside the session's private network (which is intentional for cybersecurity lab learning, but restricted to the assigned internal bridge).

---

### Layer 6 — Seccomp System Call Filtering
* **Description**: A custom Seccomp (Secure Computing Mode) profile filters and blocks dangerous system calls at the kernel syscall boundary, returning `SCMP_ACT_ERRNO` on violation.
* **Implementation**: `orchestrator/security/seccomp-profile.json` attached via `orchestrator/index.js` (`SecurityOpt: [seccomp=...]`).
* **Blocked Syscalls**:
  * Filesystem & mount manipulation: `mount`, `umount`, `umount2`, `pivot_root`
  * System control: `reboot`, `kexec_load`, `kexec_file_load`
  * Kernel modules: `init_module`, `finit_module`, `delete_module`
  * Process inspection & memory dumping: `ptrace`, `process_vm_readv`, `process_vm_writev`
  * Namespace manipulation: `setns`, `unshare`
  * Swap & handle operations: `swapon`, `swapoff`, `open_by_handle_at`, `name_to_handle_at`
* **Threat Addressed**: Prevents kernel exploitation, namespace escapes, memory manipulation of other processes, and live kernel patching.
* **Limitations**: Only syscalls explicitly enumerated in the profile are blocked; unlisted standard syscalls default to allow. Seccomp alone does not prevent application-level logic flaws.

---

### Layer 7 — Secure Command Execution Gateway
* **Description**: The orchestrator provides a programmatic command gateway (`POST /sessions/:sessionId/execute`) that sanitizes commands prior to execution:
  * Blocks package management: `apt`, `apt-get`, `pip`, `pip3`
  * Blocks repository cloning: `git clone`
  * Blocks shell chaining & redirection: `;`, `&&`, `||`, `|`, `` ` ``, `$()`, `>`, `<`
  * Enforces an allowlist of approved commands (`id`, `whoami`, `pwd`, `ls`, `cat`, `getent`, `ping`, `curl`)
* **Implementation**: `orchestrator/index.js` (`ALLOWED_COMMAND_RULES`, `BLOCKED_COMMAND_RULES`, `BLOCKED_SHELL_PATTERNS`).
* **Threat Addressed**: Prevents arbitrary script execution, runtime package downloads, and command injection attacks.
* **Limitations**: **Architectural Boundary**: The Command Gateway is authoritative only when user execution is routed through the orchestrator API. If a student is granted direct terminal access (`docker exec`), container-level controls (Layers 2–6) enforce boundaries instead.

---

### Layer 8 — Structured Audit Logging
* **Description**: Every lifecycle event, security policy violation, and command execution generates an immutable, structured JSON record appended to log files.
* **Implementation**: `orchestrator/logger.js` (`orchestrator/logs/audit.log`, `orchestrator/logs/security-events.log`).
* **Threat Addressed**: Non-repudiation, forensics, compliance, and real-time security alerting.
* **Limitations**: Logs are stored as local text files on the host; log rotation and external syslog forwarding are not implemented.

---

### Layer 9 — Real-Time Dashboard Monitoring
* **Description**: An administrative Security Operations Center (SOC) dashboard visualizes real-time metrics, active session containers, severity breakdowns, and event streams.
* **Implementation**: `orchestrator/dashboard/` and `orchestrator/index.js` (`/dashboard`, `/security-summary`).
* **Threat Addressed**: Lack of operational visibility and delayed detection of malicious attempts.
* **Limitations**: Telemetry relies on 5-second HTTP polling; it does not provide active push notifications or automated incident response blocking beyond the gateway.

---

### Layer 10 — Automated Security Verification
* **Description**: An automated test harness programmatically validates that all security controls remain active and functional across containers and networks.
* **Implementation**: `orchestrator/security-tests/verify-security.js`.
* **Threat Addressed**: Security regression, misconfigurations, and untested deployment degradation.
* **Limitations**: The test harness validates pre-defined security assertions; it is a test script, not a continuous intrusion detection system (IDS).
