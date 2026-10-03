# Environment Setup & Installation Guide

This guide provides step-by-step instructions to configure, build, and run the **Attacker Container Isolation and Access Control** laboratory platform on Windows.

---

## Prerequisites Checklist

Ensure the following tools are installed and operational:

1. **Docker Desktop**: Download and install from [Docker.com](https://www.docker.com/products/docker-desktop/). Ensure Linux containers are enabled.
2. **Node.js LTS**: Download and install from [Nodejs.org](https://nodejs.org/) (includes `npm`).
3. **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+.

Verify your environment by running:

```powershell
docker --version
node --version
npm --version
```

---

## Step-by-Step Installation

### Step 1: Open PowerShell and Navigate to the Repository

```powershell
cd c:\Users\rahul\secure-attacker
```

### Step 2: Build the Hardened Attacker Image

Build the custom `secure-attacker:1.0` Docker image using the project's root `Dockerfile`:

```powershell
docker build -t secure-attacker:1.0 .
```

Verify the image was created:

```powershell
docker images secure-attacker:1.0
```

### Step 3: Pull the Target Container Image

The orchestrator utilizes `nginx:alpine` as the target container for each student session:

```powershell
docker pull nginx:alpine
```

### Step 4: Install Orchestrator Dependencies

Navigate to the `orchestrator` folder and install the required npm packages (`express` and `dockerode`):

```powershell
cd orchestrator
npm install
cd ..
```

---

## Starting the Platform

### Step 5: Start the Orchestrator Service

Run the Express orchestrator server from the `orchestrator` folder:

```powershell
cd orchestrator
node index.js
```

Expected terminal output:

```text
Orchestrator running at http://localhost:3000
```

*Note: The server will remain running in your terminal. Open a new PowerShell tab or window for subsequent terminal commands.*

---

## Accessing the Web Dashboard

### Step 6: Open the Dashboard in Your Browser

Navigate to the Security Operations Center (SOC) dashboard:

```text
http://localhost:3000/dashboard-ui/
```

Confirm that:
* The header displays **SYSTEM ONLINE**.
* Security metrics (Active Sessions, Total Events, Blocked Events, etc.) load correctly.
* The **STUDENT SESSION MANAGEMENT** panel is visible with the **`+ CREATE NEW SESSION`** button.
* The **SESSION MONITORING** and **RECENT SECURITY EVENTS** tables render.

---

## Session Provisioning & Verification

### Step 7: Provision a Student Session

1. In the dashboard, click **`+ CREATE NEW SESSION`**.
2. The button temporarily displays **`CREATING SESSION...`** while Docker creates the isolated bridge network and containers.
3. Upon completion, the **SESSION CREATED** card displays:
   * **Session ID**: e.g., `1791048868330`
   * **Attacker**: e.g., `attacker-1791048868330`
   * **Target**: e.g., `target-1791048868330`
   * **Network**: e.g., `session-1791048868330-net`
   * **Terminal Access Command**: `docker exec -it attacker-<sessionId> bash`
4. The **SESSION MONITORING** section and the **ACTIVE SESSIONS** metric increment automatically.

### Step 8: Verify Containers in Docker

From PowerShell:

```powershell
docker ps
```

You should see both the attacker (`secure-attacker:1.0`) and target (`nginx:alpine`) containers actively running with status `Up`.

---

## Running Automated Security Verification

To run the full 8-point automated security test suite, provision two sessions (or note the container names of your primary session and a secondary session) and execute:

```powershell
node orchestrator/security-tests/verify-security.js <attackerName> <ownTargetName> <otherTargetName>
```

Example:

```powershell
node orchestrator/security-tests/verify-security.js `
  attacker-1791048868330 `
  target-1791048868330 `
  target-1791049595567
```

Expected result:

```text
Total tests : 8
Passed      : 8
Failed      : 0
RESULT: PASS
```

The resulting audit report is stored at `orchestrator/security-tests/results/security-report.json`.
