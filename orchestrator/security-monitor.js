const Docker = require("dockerode");

const {
    writeAuditLog,
    writeSecurityEvent
} = require("./logger");

const docker = new Docker();

const monitoredActions = [
    {
        pattern: /apt(-get)?\s+(update|install|upgrade|remove)/i,
        action: "APT_COMMAND",
        severity: "HIGH",
        description:
            "Runtime APT package-management command detected"
    },

    {
        pattern: /pip3?\s+install/i,
        action: "PIP_INSTALL",
        severity: "HIGH",
        description:
            "Runtime Python package installation command detected"
    },

    {
        pattern: /git\s+clone/i,
        action: "GIT_CLONE",
        severity: "MEDIUM",
        description:
            "Runtime Git repository download attempt detected"
    }
];

async function monitorContainer(containerName, sessionId) {

    try {

        const container =
            docker.getContainer(containerName);

        const exec =
            await container.exec({
                Cmd: [
                    "bash",
                    "-c",
                    "history 2>/dev/null || true"
                ],
                AttachStdout: true,
                AttachStderr: true
            });

        const stream =
            await exec.start({
                hijack: true,
                stdin: false
            });

        let output = "";

        stream.on("data", chunk => {
            output += chunk.toString();
        });

        await new Promise((resolve, reject) => {

            stream.on("end", resolve);

            stream.on("error", reject);

        });

        for (const rule of monitoredActions) {

            if (rule.pattern.test(output)) {

                const securityEvent =
                    writeSecurityEvent({

                        sessionId,

                        attacker:
                            containerName,

                        action:
                            rule.action,

                        result:
                            "BLOCKED",

                        severity:
                            rule.severity,

                        description:
                            rule.description

                    });

                writeAuditLog(
                    "AUTOMATED_SECURITY_EVENT",
                    {
                        sessionId,
                        attacker: containerName,
                        action: rule.action,
                        result: "BLOCKED",
                        severity: rule.severity,
                        eventId:
                            securityEvent.eventId
                    }
                );

                console.log(
                    `[SECURITY] ${rule.action} detected for ${containerName}`
                );
            }
        }

    } catch (error) {

        console.error(
            `[MONITOR ERROR] ${containerName}:`,
            error.message
        );

    }
}

async function startMonitoring() {

    console.log(
        "Automated security monitoring started."
    );

    setInterval(async () => {

        try {

            const containers =
                await docker.listContainers({
                    all: false
                });

            for (const containerInfo of containers) {

                const attacker =
                    containerInfo.Names.find(
                        name =>
                            name.startsWith("/attacker-")
                    );

                if (!attacker) {
                    continue;
                }

                const containerName =
                    attacker.substring(1);

                const sessionId =
                    containerName.replace(
                        "attacker-",
                        ""
                    );

                await monitorContainer(
                    containerName,
                    sessionId
                );
            }

        } catch (error) {

            console.error(
                "[MONITOR ERROR]",
                error.message
            );

        }

    }, 10000);
}

module.exports = {
    startMonitoring
};