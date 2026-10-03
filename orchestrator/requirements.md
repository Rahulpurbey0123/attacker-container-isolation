# System Requirements & Dependencies

This document describes the software prerequisites, Node.js packages, and Docker container images required to run the **Attacker Container Isolation and Access Control** orchestrator platform.

---

## 1. Software Prerequisites

The system is developed and tested on Windows environments using Docker Desktop and Node.js.

* **Operating System**: Windows 10 / Windows 11 (64-bit) with virtualization enabled (WSL 2 backend recommended).
* **Docker Desktop**: Docker Engine 24+ with Linux containers enabled.
* **Node.js**: Node.js runtime version 18.x or 20.x LTS.
* **npm**: Node Package Manager version 9.x or 10.x (bundled with Node.js).
* **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+ for executing management and verification scripts.

---

## 2. Node.js Dependencies

The orchestrator service is a Node.js / Express application located in `orchestrator/`. The active dependencies defined in `orchestrator/package.json` are:

| Package | Version | Purpose |
|---|---|---|
| [`express`](https://www.npmjs.com/package/express) | `^5.2.1` | HTTP web server, routing, static dashboard file serving, and REST API endpoints. |
| [`dockerode`](https://www.npmjs.com/package/dockerode) | `^5.0.1` | Programmatic Docker Engine API client for container and network lifecycle orchestration. |

To install dependencies within `orchestrator/`:

```powershell
cd orchestrator
npm install
```

---

## 3. Docker Requirements

* The **Docker daemon** must be actively running and accessible through the standard local engine pipe (`//./pipe/docker_engine` on Windows).
* Sufficient disk space and memory allocated to Docker Desktop (minimum 4 GB RAM recommended).

---

## 4. Required Docker Container Images

The orchestrator dynamically provisions two containers per student session. Both images must be present in the local Docker image store prior to creating sessions:

### 1. Attacker Container Image: `secure-attacker:1.0`
* **Base Image**: `ubuntu:24.04`
* **Source**: Built locally from the root [`Dockerfile`](file:///c:/Users/rahul/secure-attacker/Dockerfile).
* **Pre-installed tools**: `curl`, `iputils-ping`, `ca-certificates`.
* **Configured User**: Non-root user `student` (UID:GID `1001:1001`).
* **Build Command**:
  ```powershell
  docker build -t secure-attacker:1.0 .
  ```

### 2. Target Container Image: `nginx:alpine`
* **Base Image**: Official `nginx:alpine`
* **Source**: Docker Hub (`docker.io/library/nginx:alpine`).
* **Role**: Simulates a vulnerable or target web service running on HTTP port 80 inside the isolated bridge network.
* **Pull Command**:
  ```powershell
  docker pull nginx:alpine
  ```
