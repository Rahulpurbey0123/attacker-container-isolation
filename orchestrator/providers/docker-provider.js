const Docker = require("dockerode");
const fs = require("fs");
const path = require("path");
const { assertValidSessionId } = require("../security/validator");

const DEFAULT_COMMAND_TIMEOUT_MS = 10000;
const DEFAULT_MAX_OUTPUT_BYTES = 65536;

class DockerProvider {
    constructor() {
        this.name = "docker";
        this.docker = new Docker();

        const seccompProfilePath = path.join(
            __dirname,
            "..",
            "security",
            "seccomp-profile.json"
        );
        this.seccompProfile = fs.readFileSync(seccompProfilePath, "utf8");
    }

    _isNotFoundError(err) {
        if (!err) return false;
        if (err.statusCode === 404) return true;
        if (typeof err.message === "string" && (err.message.includes("404") || err.message.toLowerCase().includes("no such container") || err.message.toLowerCase().includes("not found"))) return true;
        return false;
    }

    async checkConnection() {
        const containers = await this.docker.listContainers({ all: true });
        return {
            status: "connected",
            provider: "docker",
            containers: containers.map(container => ({
                name: container.Names[0],
                image: container.Image,
                status: container.Status
            }))
        };
    }

    async getActiveSessionsCount() {
        const containers = await this.docker.listContainers({ all: false });
        return containers.filter(container =>
            container.Names.some(name => name.startsWith("/attacker-"))
        ).length;
    }

    async listActiveContainers() {
        const containers = await this.docker.listContainers({ all: true });
        return containers.map(c => ({
            name: c.Names[0],
            image: c.Image,
            status: c.Status
        }));
    }

    async createSession(sessionId) {
        assertValidSessionId(sessionId);

        const networkName = `session-${sessionId}-net`;
        const attackerName = `attacker-${sessionId}`;
        const targetName = `target-${sessionId}`;

        let networkCreated = false;
        let targetCreated = false;
        let attackerCreated = false;

        try {
            await this.docker.createNetwork({
                Name: networkName,
                Driver: "bridge",
                CheckDuplicate: true,
                Internal: true
            });
            networkCreated = true;

            const target = await this.docker.createContainer({
                Image: "nginx:alpine",
                name: targetName,
                HostConfig: {
                    NetworkMode: networkName
                },
                NetworkingConfig: {
                    EndpointsConfig: {
                        [networkName]: {}
                    }
                }
            });
            targetCreated = true;
            await target.start();

            const attacker = await this.docker.createContainer({
                Image: "secure-attacker:1.0",
                name: attackerName,
                User: "1001:1001",
                Cmd: ["tail", "-f", "/dev/null"],
                HostConfig: {
                    NetworkMode: networkName,
                    ReadonlyRootfs: true,
                    CapDrop: ["ALL"],
                    CapAdd: ["NET_RAW"],
                    SecurityOpt: [`seccomp=${this.seccompProfile}`],
                    Tmpfs: {
                        "/tmp": "rw,noexec,nosuid,size=64m",
                        "/run": "rw,noexec,nosuid,size=16m",
                        "/home/student/work": "rw,nosuid,size=128m"
                    }
                },
                NetworkingConfig: {
                    EndpointsConfig: {
                        [networkName]: {}
                    }
                }
            });
            attackerCreated = true;
            await attacker.start();

            return {
                sessionId,
                network: networkName,
                attacker: attackerName,
                target: targetName,
                provider: "docker"
            };
        } catch (error) {
            if (attackerCreated) {
                try {
                    await this.docker.getContainer(attackerName).remove({ force: true });
                } catch (e) {
                    if (!this._isNotFoundError(e)) console.error("Attacker cleanup failed:", e.message);
                }
            }
            if (targetCreated) {
                try {
                    await this.docker.getContainer(targetName).remove({ force: true });
                } catch (e) {
                    if (!this._isNotFoundError(e)) console.error("Target cleanup failed:", e.message);
                }
            }
            if (networkCreated) {
                try {
                    await this.docker.getNetwork(networkName).remove();
                } catch (e) {
                    if (!this._isNotFoundError(e)) console.error("Network cleanup failed:", e.message);
                }
            }
            throw error;
        }
    }

    async getSession(sessionId) {
        assertValidSessionId(sessionId);

        const networkName = `session-${sessionId}-net`;
        const attackerName = `attacker-${sessionId}`;
        const targetName = `target-${sessionId}`;

        const attacker = this.docker.getContainer(attackerName);
        const target = this.docker.getContainer(targetName);

        let attackerInfo;
        try {
            attackerInfo = await attacker.inspect();
        } catch (e) {
            if (this._isNotFoundError(e)) {
                const err = new Error("Session not found");
                err.statusCode = 404;
                throw err;
            }
            throw e;
        }

        let targetInfo;
        try {
            targetInfo = await target.inspect();
        } catch (e) {
            targetInfo = { State: { Status: "missing", Running: false } };
        }

        return {
            sessionId,
            provider: "docker",
            attacker: {
                name: attackerName,
                status: attackerInfo.State.Status,
                running: attackerInfo.State.Running
            },
            target: {
                name: targetName,
                status: targetInfo.State.Status,
                running: targetInfo.State.Running
            },
            network: networkName
        };
    }

    async deleteSession(sessionId) {
        assertValidSessionId(sessionId);

        const networkName = `session-${sessionId}-net`;
        const attackerName = `attacker-${sessionId}`;
        const targetName = `target-${sessionId}`;

        try {
            await this.docker.getContainer(attackerName).remove({ force: true });
        } catch (e) {
            if (!this._isNotFoundError(e)) throw e;
        }

        try {
            await this.docker.getContainer(targetName).remove({ force: true });
        } catch (e) {
            if (!this._isNotFoundError(e)) throw e;
        }

        try {
            await this.docker.getNetwork(networkName).remove();
        } catch (e) {
            if (!this._isNotFoundError(e)) throw e;
        }

        return {
            sessionId,
            provider: "docker"
        };
    }

    async executeCommand(sessionId, command) {
        assertValidSessionId(sessionId);

        const attackerName = `attacker-${sessionId}`;
        const attacker = this.docker.getContainer(attackerName);

        let info;
        try {
            info = await attacker.inspect();
        } catch (e) {
            if (this._isNotFoundError(e)) {
                const err = new Error("Session not found");
                err.statusCode = 404;
                throw err;
            }
            throw e;
        }

        if (!info.State.Running) {
            const err = new Error("Attacker container is not running");
            err.statusCode = 409;
            throw err;
        }

        const timeoutMs = parseInt(process.env.COMMAND_TIMEOUT_MS, 10) || DEFAULT_COMMAND_TIMEOUT_MS;
        const maxOutputBytes = parseInt(process.env.MAX_COMMAND_OUTPUT_BYTES, 10) || DEFAULT_MAX_OUTPUT_BYTES;

        const exec = await attacker.exec({
            Cmd: ["bash", "-c", command],
            AttachStdout: true,
            AttachStderr: true
        });

        const stream = await exec.start({
            hijack: true,
            stdin: false
        });

        let output = "";
        let outputTruncated = false;

        stream.on("data", chunk => {
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
        });

        return new Promise((resolve, reject) => {
            let completed = false;

            const timer = setTimeout(() => {
                if (completed) return;
                completed = true;
                try { stream.destroy(); } catch (e) {}

                const timeoutErr = new Error(`Command execution timed out after ${timeoutMs}ms`);
                timeoutErr.statusCode = 408;
                reject(timeoutErr);
            }, timeoutMs);

            stream.on("end", async () => {
                if (completed) return;
                completed = true;
                clearTimeout(timer);

                try {
                    const inspection = await exec.inspect();
                    const result = inspection.ExitCode === 0 ? "SUCCESS" : "FAILED";
                    resolve({
                        result,
                        exitCode: inspection.ExitCode,
                        output
                    });
                } catch (inspectErr) {
                    reject(inspectErr);
                }
            });

            stream.on("error", err => {
                if (!completed) {
                    completed = true;
                    clearTimeout(timer);
                    reject(err);
                }
            });
        });
    }
}

module.exports = DockerProvider;
