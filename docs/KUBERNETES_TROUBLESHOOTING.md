# Kubernetes Troubleshooting & Operational Diagnostics Guide

> **Project**: Attacker Container Isolation & Access Control  
> **Platform Version**: 1.1.0  
> **Target Audience**: Systems Administrators, DevOps Engineers, Lab Support

---

## 1. Quick Diagnostic Checklist

When encountering unexpected behavior in Kubernetes mode, execute these verification commands in PowerShell:

```powershell
# 1. Verify cluster connection and active context
kubectl config current-context
kubectl get nodes -o wide

# 2. Inspect all workloads and events in attacker-lab
kubectl get pods,svc,networkpolicy,events -n attacker-lab -o wide

# 3. Test orchestrator Kubernetes API connectivity
Invoke-RestMethod -Uri "http://localhost:3000/k8s"

# 4. Check orchestrator logs for API errors
Get-Content orchestrator/logs/audit.log -Tail 20
```

---

## 2. Common Issues, Root Causes & Verified Solutions

### Issue 1: `Invalid JSON Patch` During Pod Creation
* **Symptom**: Attempting `kubectl run attacker --overrides='...'` fails with `Invalid JSON Patch` or schema validation error.
* **Root Cause**: `kubectl run --overrides` passes a raw JSON snippet that fails schema validation when complex security contexts, capability sets, or memory-backed `emptyDir` volume arrays are specified.
* **Solution**: Never use ad-hoc `--overrides` JSON. Always use declarative, validated YAML manifests located in `kubernetes/attacker-pod.yaml`:
  ```powershell
  kubectl apply -f kubernetes/attacker-pod.yaml
  ```

---

### Issue 2: `ErrImageNeverPull` on Attacker Pod
* **Symptom**: Attacker pod enters `ErrImageNeverPull` or `ImagePullBackOff`.
* **Root Cause**: In Docker Desktop, the local Docker daemon stores images under the default `moby` namespace, while the Kubernetes node runtime (`desktop-control-plane`) looks inside the `k8s.io` containerd namespace.
* **Solution**: Export the built image from Docker and import it directly into the Kubernetes containerd namespace:
  ```powershell
  docker save secure-attacker:1.0 -o secure-attacker.tar
  wsl -d docker-desktop -e sh -c "cat /mnt/host/c/Users/rahul/secure-attacker/secure-attacker.tar | nsenter -t \$(pgrep -f 'containerd$' | head -n1) -m -p /usr/local/bin/ctr -n k8s.io image import -"
  wsl -d docker-desktop -e sh -c "nsenter -t \$(pgrep -f 'containerd$' | head -n1) -m -p /usr/local/bin/ctr -n k8s.io images tag docker.io/library/secure-attacker:1.0 secure-attacker:1.0"
  Remove-Item secure-attacker.tar
  ```

---

### Issue 3: `violates PodSecurity "baseline:latest": non-default capabilities`
* **Symptom**: Deploying `attacker-pod.yaml` produces:
  ```text
  Error from server (Forbidden): pods "attacker-demo-session" is forbidden: 
  violates PodSecurity "baseline:latest": non-default capabilities 
  (container "attacker" must not include "NET_RAW" in securityContext.capabilities.add)
  ```
* **Root Cause**: Under Kubernetes Pod Security Standards, `NET_RAW` is classified as a privilege-escalation risk and cannot be added in namespaces enforcing `baseline` or `restricted`.
* **Solution**: Configure `kubernetes/namespace.yaml` with `pod-security.kubernetes.io/enforce: privileged` and `pod-security.kubernetes.io/warn: baseline`:
  ```powershell
  kubectl apply -f kubernetes/namespace.yaml
  ```

---

### Issue 4: Target Pod Crashes with `chown failed (1: Operation not permitted)`
* **Symptom**: `target-demo-session` pod enters `CrashLoopBackOff`.
* **Root Cause**: `nginx:alpine` starts as root, attempts to change ownership of `/var/cache/nginx/client_temp` to UID 101 (`nginx`), and then drops worker privileges. If `capabilities.drop: ["ALL"]` drops `CHOWN`, the master process fails to start.
* **Solution**: Ensure `kubernetes/target-deployment.yaml` explicitly retains the worker capabilities:
  ```yaml
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
      add: ["CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE", "DAC_OVERRIDE"]
  ```

---

### Issue 5: Target Pod Unreachable from Attacker (`Exit Code 28 Timeout`)
* **Symptom**: `curl http://target-demo-session` times out with exit code 28.
* **Diagnostic Steps**:
  1. Verify target pod is Ready:
     ```powershell
     kubectl get pods -n attacker-lab -l app=target-nginx
     ```
  2. Verify ClusterIP service exists and has endpoints:
     ```powershell
     kubectl get endpoints target-demo-session -n attacker-lab
     ```
  3. Verify NetworkPolicy selectors:
     The target's ingress policy must match `app: secure-attacker` with `session: <matching-session-id>`.

---

### Issue 6: Switching Back to Docker Mode
* **Action**: If you need to revert to Docker mode:
  ```powershell
  $env:ORCHESTRATOR_PROVIDER="docker"
  node orchestrator/index.js
  ```
  The orchestrator will immediately resume using the native Docker engine (`//./pipe/docker_engine`).
