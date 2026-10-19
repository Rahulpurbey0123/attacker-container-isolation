const k8s = require("@kubernetes/client-node");
const stream = require("stream");
const fs = require("fs");
const path = require("path");
const { assertValidSessionId } = require("../security/validator");

const DEFAULT_COMMAND_TIMEOUT_MS = 10000;
const DEFAULT_MAX_OUTPUT_BYTES = 65536;

class KubernetesProvider {
    constructor() {
        this.name = "kubernetes";
        this.namespace = process.env.K8S_NAMESPACE || "attacker-lab";

        this.kubeConfig = new k8s.KubeConfig();

        // 1. Explicit env var K8S_KUBECONFIG or KUBECONFIG
        const customConfig = process.env.K8S_KUBECONFIG || process.env.KUBECONFIG;
        const dedicatedSaConfig = path.join(__dirname, "..", "..", "kubernetes", "orchestrator-kubeconfig.yaml");

        if (customConfig && fs.existsSync(customConfig)) {
            this.kubeConfig.loadFromFile(customConfig);
        } else if (fs.existsSync(dedicatedSaConfig)) {
            // Load dedicated least-privilege kubeconfig if present
            this.kubeConfig.loadFromFile(dedicatedSaConfig);
        } else if (fs.existsSync("/var/run/secrets/kubernetes.io/serviceaccount")) {
            this.kubeConfig.loadFromCluster();
        } else {
            this.kubeConfig.loadFromDefault();
        }

        this.coreApi = this.kubeConfig.makeApiClient(k8s.CoreV1Api);
        this.appsApi = this.kubeConfig.makeApiClient(k8s.AppsV1Api);
        this.netApi = this.kubeConfig.makeApiClient(k8s.NetworkingV1Api);
        this.execClient = new k8s.Exec(this.kubeConfig);
    }

    /**
     * Helper to verify if an error is a confirmed 404 NotFound
     */
    _isNotFoundError(err) {
        if (!err) return false;
        if (err.statusCode === 404) return true;
        if (err.response && err.response.statusCode === 404) return true;
        if (err.body && err.body.code === 404) return true;
        if (typeof err.message === "string" && err.message.toLowerCase().includes("not found")) return true;
        return false;
    }

    async getEffectiveIdentity() {
        const currentContext = this.kubeConfig.getCurrentContext() || "unknown";
        const currentUser = this.kubeConfig.getCurrentUser();
        const isServiceAccount = Boolean(
            currentUser && (currentUser.token || (currentUser.name && currentUser.name.includes("sa")))
        );
        return {
            context: currentContext,
            user: currentUser ? currentUser.name : "unknown",
            namespace: this.namespace,
            isLeastPrivilege: isServiceAccount
        };
    }

    async checkConnection() {
        try {
            const identity = await this.getEffectiveIdentity();
            const podList = await this.coreApi.listNamespacedPod({ namespace: this.namespace });
            const pods = podList.items || [];

            return {
                status: "connected",
                provider: "kubernetes",
                context: identity.context,
                namespace: this.namespace,
                effectiveUser: identity.user,
                isLeastPrivilege: identity.isLeastPrivilege,
                containers: pods.map(pod => ({
                    name: "/" + pod.metadata.name,
                    image: (pod.spec.containers[0] && pod.spec.containers[0].image) || "unknown",
                    status: pod.status ? `${pod.status.phase}` : "Unknown"
                }))
            };
        } catch (error) {
            return {
                status: "disconnected",
                provider: "kubernetes",
                error: error.message
            };
        }
    }

    async getActiveSessionsCount() {
        const podList = await this.coreApi.listNamespacedPod({ namespace: this.namespace });
        const pods = podList.items || [];
        return pods.filter(pod => {
            const name = pod.metadata && pod.metadata.name;
            return name && name.startsWith("attacker-") && pod.status && pod.status.phase === "Running";
        }).length;
    }

    async listActiveContainers() {
        const podList = await this.coreApi.listNamespacedPod({ namespace: this.namespace });
        const pods = podList.items || [];
        return pods.map(pod => ({
            name: "/" + (pod.metadata && pod.metadata.name),
            image: (pod.spec.containers[0] && pod.spec.containers[0].image) || "unknown",
            status: pod.status ? pod.status.phase : "Unknown"
        }));
    }

    async createSession(sessionId) {
        // Enforce Kubernetes DNS-1123 label validation on sessionId
        assertValidSessionId(sessionId);

        const attackerName = `attacker-${sessionId}`;
        const targetName = `target-${sessionId}`;
        const targetSvcName = `target-${sessionId}`;
        const netPolicyAttackerName = `isolate-attacker-${sessionId}`;
        const netPolicyTargetName = `isolate-target-${sessionId}`;

        // Check if session already exists
        try {
            await this.coreApi.readNamespacedPod({ name: attackerName, namespace: this.namespace });
            const conflictErr = new Error(`Session ${sessionId} already exists`);
            conflictErr.statusCode = 409;
            throw conflictErr;
        } catch (e) {
            if (e.statusCode === 409) throw e;
            if (!this._isNotFoundError(e)) {
                // If it is not a 404 (e.g. 403 Forbidden or network failure), propagate error
                throw e;
            }
        }

        // Track resources successfully created by THIS invocation for safe, partial rollback
        const createdResources = [];

        try {
            // 1. Target Deployment (nginx:alpine)
            const targetDeployment = {
                metadata: {
                    name: targetName,
                    namespace: this.namespace,
                    labels: {
                        app: "target-nginx",
                        session: sessionId,
                        role: "target"
                    }
                },
                spec: {
                    replicas: 1,
                    selector: {
                        matchLabels: {
                            app: "target-nginx",
                            session: sessionId
                        }
                    },
                    template: {
                        metadata: {
                            labels: {
                                app: "target-nginx",
                                session: sessionId,
                                role: "target",
                                tier: "backend"
                            }
                        },
                        spec: {
                            automountServiceAccountToken: false,
                            containers: [
                                {
                                    name: "target",
                                    image: "nginx:alpine",
                                    imagePullPolicy: "IfNotPresent",
                                    ports: [
                                        {
                                            containerPort: 80,
                                            name: "http"
                                        }
                                    ],
                                    securityContext: {
                                        allowPrivilegeEscalation: false,
                                        capabilities: {
                                            drop: ["ALL"],
                                            add: [
                                                "CHOWN",
                                                "SETUID",
                                                "SETGID",
                                                "NET_BIND_SERVICE",
                                                "DAC_OVERRIDE"
                                            ]
                                        }
                                    },
                                    resources: {
                                        requests: { cpu: "50m", memory: "32Mi" },
                                        limits: { cpu: "250m", memory: "128Mi" }
                                    },
                                    readinessProbe: {
                                        httpGet: { path: "/", port: 80 },
                                        initialDelaySeconds: 1,
                                        periodSeconds: 2
                                    }
                                }
                            ],
                            terminationGracePeriodSeconds: 2
                        }
                    }
                }
            };

            await this.appsApi.createNamespacedDeployment({
                namespace: this.namespace,
                body: targetDeployment
            });
            createdResources.push({ type: "deployment", name: targetName });

            // 2. Target Service (ClusterIP)
            const targetService = {
                metadata: {
                    name: targetSvcName,
                    namespace: this.namespace,
                    labels: {
                        app: "target-nginx",
                        session: sessionId,
                        role: "target"
                    }
                },
                spec: {
                    type: "ClusterIP",
                    selector: {
                        app: "target-nginx",
                        session: sessionId
                    },
                    ports: [
                        {
                            name: "http",
                            port: 80,
                            targetPort: 80,
                            protocol: "TCP"
                        }
                    ]
                }
            };

            await this.coreApi.createNamespacedService({
                namespace: this.namespace,
                body: targetService
            });
            createdResources.push({ type: "service", name: targetSvcName });

            // 3. NetworkPolicy: Isolate Target (accepts ingress only from same session attacker)
            const netPolicyTarget = {
                metadata: {
                    name: netPolicyTargetName,
                    namespace: this.namespace,
                    labels: { session: sessionId }
                },
                spec: {
                    podSelector: {
                        matchLabels: {
                            app: "target-nginx",
                            session: sessionId
                        }
                    },
                    policyTypes: ["Ingress"],
                    ingress: [
                        {
                            from: [
                                {
                                    podSelector: {
                                        matchLabels: {
                                            app: "secure-attacker",
                                            session: sessionId
                                        }
                                    }
                                }
                            ],
                            ports: [{ protocol: "TCP", port: 80 }]
                        }
                    ]
                }
            };

            console.log("[DIAGNOSTIC] Target ingress:", JSON.stringify(netPolicyTarget.spec.ingress));

            await this.netApi.createNamespacedNetworkPolicy({
                namespace: this.namespace,
                body: netPolicyTarget
            });
            createdResources.push({ type: "networkpolicy", name: netPolicyTargetName });

            // 4. NetworkPolicy: Isolate Attacker (egress to CoreDNS and session target only)
            const netPolicyAttacker = {
                metadata: {
                    name: netPolicyAttackerName,
                    namespace: this.namespace,
                    labels: { session: sessionId }
                },
                spec: {
                    podSelector: {
                        matchLabels: {
                            app: "secure-attacker",
                            session: sessionId
                        }
                    },
                    policyTypes: ["Ingress", "Egress"],
                    ingress: [],
                    egress: [
                        {
                            to: [
                                {
                                    namespaceSelector: {},
                                    podSelector: {
                                        matchLabels: {
                                            "k8s-app": "kube-dns"
                                        }
                                    }
                                }
                            ],
                            ports: [
                                { protocol: "UDP", port: 53 },
                                { protocol: "TCP", port: 53 }
                            ]
                        },
                        {
                            to: [
                                {
                                    podSelector: {
                                        matchLabels: {
                                            app: "target-nginx",
                                            session: sessionId
                                        }
                                    }
                                }
                            ],
                            ports: [{ protocol: "TCP", port: 80 }]
                        }
                    ]
                }
            };

            await this.netApi.createNamespacedNetworkPolicy({
                namespace: this.namespace,
                body: netPolicyAttacker
            });
            createdResources.push({ type: "networkpolicy", name: netPolicyAttackerName });

            // 5. Hardened Attacker Pod
            const attackerPod = {
                metadata: {
                    name: attackerName,
                    namespace: this.namespace,
                    labels: {
                        app: "secure-attacker",
                        session: sessionId,
                        role: "attacker",
                        tier: "frontend"
                    }
                },
                spec: {
                    automountServiceAccountToken: false,
                    hostNetwork: false,
                    hostPID: false,
                    hostIPC: false,
                    securityContext: {
                        runAsUser: 1001,
                        runAsGroup: 1001,
                        runAsNonRoot: true,
                        fsGroup: 1001,
                        seccompProfile: {
                            type: "RuntimeDefault"
                        }
                    },
                    containers: [
                        {
                            name: "attacker",
                            image: "secure-attacker:1.0",
                            imagePullPolicy: "Never",
                            command: ["tail", "-f", "/dev/null"],
                            securityContext: {
                                allowPrivilegeEscalation: false,
                                readOnlyRootFilesystem: true,
                                capabilities: {
                                    drop: ["ALL"]
                                }
                            },
                            resources: {
                                requests: { cpu: "100m", memory: "64Mi" },
                                limits: { cpu: "500m", memory: "256Mi" }
                            },
                            volumeMounts: [
                                { name: "tmp-volume", mountPath: "/tmp" },
                                { name: "run-volume", mountPath: "/run" },
                                { name: "work-volume", mountPath: "/home/student/work" }
                            ]
                        }
                    ],
                    volumes: [
                        {
                            name: "tmp-volume",
                            emptyDir: { medium: "Memory", sizeLimit: "64Mi" }
                        },
                        {
                            name: "run-volume",
                            emptyDir: { medium: "Memory", sizeLimit: "16Mi" }
                        },
                        {
                            name: "work-volume",
                            emptyDir: { medium: "Memory", sizeLimit: "128Mi" }
                        }
                    ],
                    restartPolicy: "Always",
                    terminationGracePeriodSeconds: 2
                }
            };

            await this.coreApi.createNamespacedPod({
                namespace: this.namespace,
                body: attackerPod
            });
            createdResources.push({ type: "pod", name: attackerName });

            // 6. Wait for Attacker Pod to reach Running state (up to 15s)
            await this.waitForPodRunning(attackerName, 15000);

            return {
                sessionId,
                network: "k8s-cni-networkpolicy",
                attacker: attackerName,
                target: targetName,
                targetService: targetSvcName,
                provider: "kubernetes"
            };
        } catch (error) {
            console.error("Kubernetes session provisioning error:", error.message);

            // Safe rollback: roll back ONLY resources created by this invocation in reverse order
            for (let i = createdResources.length - 1; i >= 0; i--) {
                const res = createdResources[i];
                try {
                    if (res.type === "pod") {
                        await this.coreApi.deleteNamespacedPod({ name: res.name, namespace: this.namespace });
                    } else if (res.type === "networkpolicy") {
                        await this.netApi.deleteNamespacedNetworkPolicy({ name: res.name, namespace: this.namespace });
                    } else if (res.type === "service") {
                        await this.coreApi.deleteNamespacedService({ name: res.name, namespace: this.namespace });
                    } else if (res.type === "deployment") {
                        await this.appsApi.deleteNamespacedDeployment({ name: res.name, namespace: this.namespace });
                    }
                } catch (rollbackErr) {
                    if (!this._isNotFoundError(rollbackErr)) {
                        console.error(`Rollback error deleting ${res.type}/${res.name}:`, rollbackErr.message);
                    }
                }
            }

            throw error;
        }
    }

    async waitForPodRunning(podName, timeoutMs = 15000) {
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            try {
                const pod = await this.coreApi.readNamespacedPod({ name: podName, namespace: this.namespace });
                if (pod.status && pod.status.phase === "Running") {
                    return true;
                }
                if (pod.status && pod.status.containerStatuses) {
                    const cs = pod.status.containerStatuses[0];
                    if (cs && cs.state && cs.state.waiting && cs.state.waiting.reason === "CrashLoopBackOff") {
                        throw new Error(`Pod ${podName} failed: CrashLoopBackOff`);
                    }
                }
            } catch (err) {
                if (!this._isNotFoundError(err)) {
                    throw err;
                }
            }
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        throw new Error(`Timed out waiting for pod ${podName} to become Running`);
    }

    async getSession(sessionId) {
        assertValidSessionId(sessionId);

        const attackerName = `attacker-${sessionId}`;
        const targetName = `target-${sessionId}`;

        let attackerInfo;
        try {
            attackerInfo = await this.coreApi.readNamespacedPod({ name: attackerName, namespace: this.namespace });
        } catch (e) {
            if (this._isNotFoundError(e)) {
                const err = new Error("Session not found");
                err.statusCode = 404;
                throw err;
            }
            throw e;
        }

        if (attackerInfo.metadata && attackerInfo.metadata.deletionTimestamp) {
            const err = new Error("Session not found");
            err.statusCode = 404;
            throw err;
        }

        let targetInfo = null;
        try {
            targetInfo = await this.appsApi.readNamespacedDeployment({ name: targetName, namespace: this.namespace });
        } catch (e) {
            if (!this._isNotFoundError(e)) {
                throw e;
            }
        }

        const isRunning = attackerInfo.status && attackerInfo.status.phase === "Running";
        const targetReplicas = targetInfo && targetInfo.status && targetInfo.status.readyReplicas;

        return {
            sessionId,
            provider: "kubernetes",
            attacker: {
                name: attackerName,
                status: (attackerInfo.status && attackerInfo.status.phase) || "Unknown",
                running: isRunning
            },
            target: {
                name: targetName,
                status: targetReplicas > 0 ? "running" : "deploying",
                running: targetReplicas > 0
            },
            network: "k8s-cni-networkpolicy"
        };
    }

    async deleteSession(sessionId) {
        assertValidSessionId(sessionId);

        const attackerName = `attacker-${sessionId}`;
        const targetName = `target-${sessionId}`;
        const targetSvcName = `target-${sessionId}`;
        const netPolicyAttackerName = `isolate-attacker-${sessionId}`;
        const netPolicyTargetName = `isolate-target-${sessionId}`;

        // Helper to verify session ownership label before deleting
        const verifyOwnershipAndDelete = async (readFn, deleteFn, resourceName, resourceType) => {
            try {
                const resource = await readFn();
                const sessionLabel = resource && resource.metadata && resource.metadata.labels && resource.metadata.labels.session;
                if (sessionLabel && sessionLabel !== sessionId) {
                    throw new Error(`Ownership violation: ${resourceType} ${resourceName} belongs to session ${sessionLabel}, not ${sessionId}`);
                }
            } catch (err) {
                if (this._isNotFoundError(err)) {
                    // Resource already gone, nothing to delete
                    return;
                }
                throw err;
            }

            try {
                await deleteFn();
            } catch (err) {
                if (!this._isNotFoundError(err)) {
                    throw err;
                }
            }
        };

        // 1. Delete Pod
        await verifyOwnershipAndDelete(
            () => this.coreApi.readNamespacedPod({ name: attackerName, namespace: this.namespace }),
            () => this.coreApi.deleteNamespacedPod({ name: attackerName, namespace: this.namespace }),
            attackerName,
            "Pod"
        );

        // 2. Delete Target Deployment
        await verifyOwnershipAndDelete(
            () => this.appsApi.readNamespacedDeployment({ name: targetName, namespace: this.namespace }),
            () => this.appsApi.deleteNamespacedDeployment({ name: targetName, namespace: this.namespace }),
            targetName,
            "Deployment"
        );

        // 3. Delete Target Service
        await verifyOwnershipAndDelete(
            () => this.coreApi.readNamespacedService({ name: targetSvcName, namespace: this.namespace }),
            () => this.coreApi.deleteNamespacedService({ name: targetSvcName, namespace: this.namespace }),
            targetSvcName,
            "Service"
        );

        // 4. Delete Attacker NetworkPolicy
        await verifyOwnershipAndDelete(
            () => this.netApi.readNamespacedNetworkPolicy({ name: netPolicyAttackerName, namespace: this.namespace }),
            () => this.netApi.deleteNamespacedNetworkPolicy({ name: netPolicyAttackerName, namespace: this.namespace }),
            netPolicyAttackerName,
            "NetworkPolicy"
        );

        // 5. Delete Target NetworkPolicy
        await verifyOwnershipAndDelete(
            () => this.netApi.readNamespacedNetworkPolicy({ name: netPolicyTargetName, namespace: this.namespace }),
            () => this.netApi.deleteNamespacedNetworkPolicy({ name: netPolicyTargetName, namespace: this.namespace }),
            netPolicyTargetName,
            "NetworkPolicy"
        );

        // Confirm owned resources are gone before reporting successful cleanup (poll up to 8s)
        for (let i = 0; i < 16; i++) {
            try {
                await this.coreApi.readNamespacedPod({ name: attackerName, namespace: this.namespace });
            } catch (err) {
                if (this._isNotFoundError(err)) {
                    break;
                }
                throw err;
            }
            await new Promise(r => setTimeout(r, 500));
        }

        return {
            sessionId,
            provider: "kubernetes",
            status: "deleted"
        };
    }

    async executeCommand(sessionId, command) {
        assertValidSessionId(sessionId);

        const attackerName = `attacker-${sessionId}`;

        // Verify pod is running
        let pod;
        try {
            pod = await this.coreApi.readNamespacedPod({ name: attackerName, namespace: this.namespace });
        } catch (e) {
            if (this._isNotFoundError(e)) {
                const err = new Error("Session not found");
                err.statusCode = 404;
                throw err;
            }
            throw e;
        }

        if (!pod.status || pod.status.phase !== "Running") {
            const err = new Error("Attacker container is not running");
            err.statusCode = 409;
            throw err;
        }

        const timeoutMs = parseInt(process.env.COMMAND_TIMEOUT_MS, 10) || DEFAULT_COMMAND_TIMEOUT_MS;
        const maxOutputBytes = parseInt(process.env.MAX_COMMAND_OUTPUT_BYTES, 10) || DEFAULT_MAX_OUTPUT_BYTES;

        const stdout = new stream.PassThrough();
        const stderr = new stream.PassThrough();

        let output = "";
        let outputTruncated = false;

        const appendChunk = chunk => {
            if (outputTruncated) return;
            const str = chunk.toString();
            if (output.length + str.length > maxOutputBytes) {
                const remaining = maxOutputBytes - output.length;
                if (remaining > 0) output += str.slice(0, remaining);
                output += `\n[Output truncated - exceeded maximum limit of ${maxOutputBytes} bytes]`;
                outputTruncated = true;
            } else {
                output += str;
            }
        };

        stdout.on("data", appendChunk);
        stderr.on("data", appendChunk);

        return new Promise((resolve, reject) => {
            let completed = false;

            const timer = setTimeout(() => {
                if (completed) return;
                completed = true;

                // Close streams safely
                try { stdout.destroy(); } catch (e) {}
                try { stderr.destroy(); } catch (e) {}

                const timeoutErr = new Error(`Command execution timed out after ${timeoutMs}ms`);
                timeoutErr.statusCode = 408;
                reject(timeoutErr);
            }, timeoutMs);

            this.execClient.exec(
                this.namespace,
                attackerName,
                "attacker",
                ["bash", "-c", command],
                stdout,
                stderr,
                null,
                false,
                status => {
                    if (completed) return;
                    completed = true;
                    clearTimeout(timer);

                    try { stdout.destroy(); } catch (e) {}
                    try { stderr.destroy(); } catch (e) {}

                    const isSuccess = status.status === "Success";
                    let exitCode = 0;

                    if (!isSuccess && status.details && status.details.causes) {
                        const exitCause = status.details.causes.find(c => c.reason === "ExitCode");
                        if (exitCause) {
                            exitCode = parseInt(exitCause.message, 10) || 1;
                        } else {
                            exitCode = 1;
                        }
                    }

                    resolve({
                        result: isSuccess && exitCode === 0 ? "SUCCESS" : "FAILED",
                        exitCode,
                        output
                    });
                }
            ).catch(err => {
                if (!completed) {
                    completed = true;
                    clearTimeout(timer);
                    try { stdout.destroy(); } catch (e) {}
                    try { stderr.destroy(); } catch (e) {}
                    reject(err);
                }
            });
        });
    }
}

module.exports = KubernetesProvider;
