const express = require("express");
const Docker = require("dockerode");
const fs = require("fs");
const path = require("path");

const {
    writeAuditLog,
    writeSecurityEvent
} = require("./logger");

const app = express();
const docker = new Docker();

app.use(express.json());

app.use(
    "/dashboard-ui",
    express.static(
        path.join(__dirname, "dashboard")
    )
);

const PORT = 3000;

// =====================================================
// SECCOMP PROFILE
// =====================================================

const seccompProfilePath = path.join(
    __dirname,
    "security",
    "seccomp-profile.json"
);

const seccompProfile = fs.readFileSync(
    seccompProfilePath,
    "utf8"
);

// =====================================================
// SECURITY VALIDATION
// =====================================================

const ALLOWED_SEVERITIES = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
];

const ALLOWED_RESULTS = [
    "BLOCKED",
    "ALLOWED",
    "FAILED",
    "SUCCESS"
];

// =====================================================
// BLOCKED COMMAND RULES
// =====================================================

const BLOCKED_COMMAND_RULES = [
    {
        pattern:
            /\b(?:apt|apt-get)\s+(?:update|install|upgrade|remove|purge|autoremove)\b/i,

        action:
            "APT_COMMAND",

        severity:
            "HIGH",

        description:
            "Runtime APT package-management command blocked"
    },

    {
        pattern:
            /\b(?:pip|pip3)\s+install\b/i,

        action:
            "PIP_INSTALL",

        severity:
            "HIGH",

        description:
            "Runtime Python package installation command blocked"
    },

    {
        pattern:
            /\bgit\s+clone\b/i,

        action:
            "GIT_CLONE",

        severity:
            "MEDIUM",

        description:
            "Runtime Git repository download command blocked"
    }
];

// =====================================================
// ALLOWED COMMANDS
// =====================================================

const ALLOWED_COMMAND_RULES = [

    /^id$/i,

    /^whoami$/i,

    /^pwd$/i,

    /^ls(?:\s+[-a-zA-Z0-9.\/]+)?$/i,

    /^cat\s+[-a-zA-Z0-9_.\/]+$/i,

    /^getent\s+hosts\s+[a-zA-Z0-9._-]+$/i,

    /^ping(?:\s+-c\s+\d+)?\s+[a-zA-Z0-9._-]+$/i,

    /^curl(?:\s+--connect-timeout\s+\d+)?\s+https?:\/\/[a-zA-Z0-9._:-]+(?:\/[a-zA-Z0-9._\/-]*)?$/i
];

// =====================================================
// BLOCK SHELL CHAINING / REDIRECTION
// =====================================================

const BLOCKED_SHELL_PATTERNS = [
    /;/,
    /&&/,
    /\|\|/,
    /\|/,
    /`/,
    /\$\(/,
    />/,
    /</
];

// =====================================================
// HELPER: READ SECURITY EVENTS
// =====================================================

function readSecurityEvents() {

    const logFile = path.join(
        __dirname,
        "logs",
        "security-events.log"
    );

    if (!fs.existsSync(logFile)) {
        return [];
    }

    const lines = fs.readFileSync(
        logFile,
        "utf8"
    )
        .split("\n")
        .filter(line => line.trim());

    const events = [];

    for (const line of lines) {

        try {

            events.push(
                JSON.parse(line)
            );

        } catch (error) {

            // Ignore malformed lines

        }
    }

    return events;
}

// =====================================================
// 1. HEALTH CHECK
// =====================================================

app.get("/", (req, res) => {

    res.json({

        project:
            "Attacker Container Isolation and Access Control",

        status:
            "Orchestrator is running",

        version:
            "1.0.0"

    });

});

// =====================================================
// 2. DOCKER CONNECTION CHECK
// =====================================================

app.get("/docker", async (req, res) => {

    try {

        const containers =
            await docker.listContainers({
                all: true
            });

        res.json({

            docker:
                "connected",

            containers:
                containers.map(container => ({

                    name:
                        container.Names[0],

                    image:
                        container.Image,

                    status:
                        container.Status

                }))

        });

    } catch (error) {

        res.status(500).json({

            docker:
                "connection failed",

            error:
                error.message

        });

    }

});

// =====================================================
// 3. CREATE ISOLATED SESSION
// =====================================================

app.post("/sessions", async (req, res) => {

    const sessionId =
        Date.now().toString();

    const networkName =
        `session-${sessionId}-net`;

    const attackerName =
        `attacker-${sessionId}`;

    const targetName =
        `target-${sessionId}`;

    let networkCreated = false;
    let targetCreated = false;
    let attackerCreated = false;

    try {

        // -------------------------------------------------
        // CREATE PRIVATE INTERNAL NETWORK
        // -------------------------------------------------

        await docker.createNetwork({

            Name:
                networkName,

            Driver:
                "bridge",

            CheckDuplicate:
                true,

            Internal:
                true

        });

        networkCreated = true;

        // -------------------------------------------------
        // CREATE TARGET
        // -------------------------------------------------

        const target =
            await docker.createContainer({

                Image:
                    "nginx:alpine",

                name:
                    targetName,

                HostConfig: {

                    NetworkMode:
                        networkName

                },

                NetworkingConfig: {

                    EndpointsConfig: {

                        [networkName]: {}

                    }

                }

            });

        targetCreated = true;

        await target.start();

        // -------------------------------------------------
        // CREATE HARDENED ATTACKER
        // -------------------------------------------------

        const attacker =
            await docker.createContainer({

                Image:
                    "secure-attacker:1.0",

                name:
                    attackerName,

                User:
                    "1001:1001",

                Cmd: [
                    "tail",
                    "-f",
                    "/dev/null"
                ],

                HostConfig: {

                    NetworkMode:
                        networkName,

                    // Read-only filesystem
                    ReadonlyRootfs:
                        true,

                    // Drop all capabilities
                    CapDrop: [
                        "ALL"
                    ],

                    // Only required capability
                    CapAdd: [
                        "NET_RAW"
                    ],

                    // Seccomp
                    SecurityOpt: [
                        `seccomp=${seccompProfile}`
                    ],

                    // Temporary writable directories
                    Tmpfs: {

                        "/tmp":
                            "rw,noexec,nosuid,size=64m",

                        "/run":
                            "rw,noexec,nosuid,size=16m",

                        "/home/student/work":
                            "rw,nosuid,size=128m"

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

        // -------------------------------------------------
        // AUDIT LOG
        // -------------------------------------------------

        writeAuditLog(
            "SESSION_CREATED",
            {

                sessionId:
                    sessionId,

                network:
                    networkName,

                attacker:
                    attackerName,

                target:
                    targetName

            }
        );

        // -------------------------------------------------
        // RESPONSE
        // -------------------------------------------------

        res.status(201).json({

            message:
                "Isolated session created successfully",

            sessionId:
                sessionId,

            network:
                networkName,

            attacker:
                attackerName,

            target:
                targetName

        });

    } catch (error) {

        console.error(
            "Session creation error:",
            error.message
        );

        // -------------------------------------------------
        // CLEANUP ATTACKER
        // -------------------------------------------------

        if (attackerCreated) {

            try {

                await docker
                    .getContainer(attackerName)
                    .remove({
                        force: true
                    });

            } catch (cleanupError) {

                console.error(
                    "Attacker cleanup failed:",
                    cleanupError.message
                );

            }
        }

        // -------------------------------------------------
        // CLEANUP TARGET
        // -------------------------------------------------

        if (targetCreated) {

            try {

                await docker
                    .getContainer(targetName)
                    .remove({
                        force: true
                    });

            } catch (cleanupError) {

                console.error(
                    "Target cleanup failed:",
                    cleanupError.message
                );

            }
        }

        // -------------------------------------------------
        // CLEANUP NETWORK
        // -------------------------------------------------

        if (networkCreated) {

            try {

                await docker
                    .getNetwork(networkName)
                    .remove();

            } catch (cleanupError) {

                console.error(
                    "Network cleanup failed:",
                    cleanupError.message
                );

            }
        }

        // -------------------------------------------------
        // AUDIT FAILURE
        // -------------------------------------------------

        writeAuditLog(
            "SESSION_CREATION_FAILED",
            {

                sessionId:
                    sessionId,

                error:
                    error.message

            }
        );

        res.status(500).json({

            message:
                "Failed to create isolated session",

            error:
                error.message

        });

    }

});

// =====================================================
// 4. DELETE ISOLATED SESSION
// =====================================================

app.delete(
    "/sessions/:sessionId",
    async (req, res) => {

        const sessionId =
            req.params.sessionId;

        const networkName =
            `session-${sessionId}-net`;

        const attackerName =
            `attacker-${sessionId}`;

        const targetName =
            `target-${sessionId}`;

        try {

            // -------------------------------------------------
            // REMOVE ATTACKER
            // -------------------------------------------------

            try {

                await docker
                    .getContainer(attackerName)
                    .remove({
                        force: true
                    });

            } catch (error) {

                console.log(
                    "Attacker already removed or not found."
                );

            }

            // -------------------------------------------------
            // REMOVE TARGET
            // -------------------------------------------------

            try {

                await docker
                    .getContainer(targetName)
                    .remove({
                        force: true
                    });

            } catch (error) {

                console.log(
                    "Target already removed or not found."
                );

            }

            // -------------------------------------------------
            // REMOVE NETWORK
            // -------------------------------------------------

            try {

                await docker
                    .getNetwork(networkName)
                    .remove();

            } catch (error) {

                console.log(
                    "Network already removed or not found."
                );

            }

            // -------------------------------------------------
            // AUDIT LOG
            // -------------------------------------------------

            writeAuditLog(
                "SESSION_DELETED",
                {

                    sessionId:
                        sessionId,

                    network:
                        networkName,

                    attacker:
                        attackerName,

                    target:
                        targetName

                }
            );

            res.json({

                message:
                    "Session deleted successfully",

                sessionId:
                    sessionId

            });

        } catch (error) {

            writeAuditLog(
                "SESSION_DELETION_FAILED",
                {

                    sessionId:
                        sessionId,

                    error:
                        error.message

                }
            );

            res.status(500).json({

                message:
                    "Failed to delete session",

                error:
                    error.message

            });

        }

    }
);

// =====================================================
// 5. CHECK SESSION STATUS
// =====================================================

app.get(
    "/sessions/:sessionId",
    async (req, res) => {

        const sessionId =
            req.params.sessionId;

        const networkName =
            `session-${sessionId}-net`;

        const attackerName =
            `attacker-${sessionId}`;

        const targetName =
            `target-${sessionId}`;

        try {

            const attacker =
                docker.getContainer(
                    attackerName
                );

            const target =
                docker.getContainer(
                    targetName
                );

            const attackerInfo =
                await attacker.inspect();

            const targetInfo =
                await target.inspect();

            res.json({

                sessionId:
                    sessionId,

                attacker: {

                    name:
                        attackerName,

                    status:
                        attackerInfo.State.Status,

                    running:
                        attackerInfo.State.Running

                },

                target: {

                    name:
                        targetName,

                    status:
                        targetInfo.State.Status,

                    running:
                        targetInfo.State.Running

                },

                network:
                    networkName

            });

        } catch (error) {

            res.status(404).json({

                message:
                    "Session not found",

                sessionId:
                    sessionId,

                error:
                    error.message

            });

        }

    }
);

// =====================================================
// 6. RECORD SECURITY EVENT
// =====================================================

app.post(
    "/sessions/:sessionId/events",
    (req, res) => {

        const sessionId =
            req.params.sessionId;

        const {
            action,
            result,
            severity,
            description
        } = req.body;

        // -------------------------------------------------
        // REQUIRED FIELDS
        // -------------------------------------------------

        if (!action || !result) {

            return res.status(400).json({

                message:
                    "action and result are required"

            });

        }

        // -------------------------------------------------
        // SEVERITY
        // -------------------------------------------------

        const eventSeverity =
            severity || "MEDIUM";

        if (
            !ALLOWED_SEVERITIES.includes(
                eventSeverity
            )
        ) {

            return res.status(400).json({

                message:
                    "Invalid severity",

                allowed:
                    ALLOWED_SEVERITIES

            });

        }

        // -------------------------------------------------
        // RESULT
        // -------------------------------------------------

        if (
            !ALLOWED_RESULTS.includes(
                result
            )
        ) {

            return res.status(400).json({

                message:
                    "Invalid result",

                allowed:
                    ALLOWED_RESULTS

            });

        }

        // -------------------------------------------------
        // ACTION VALIDATION
        // -------------------------------------------------

        if (
            typeof action !== "string" ||
            action.length < 2 ||
            action.length > 100
        ) {

            return res.status(400).json({

                message:
                    "Action must be between 2 and 100 characters"

            });

        }

        // -------------------------------------------------
        // DESCRIPTION VALIDATION
        // -------------------------------------------------

        if (
            description !== undefined &&
            typeof description !== "string"
        ) {

            return res.status(400).json({

                message:
                    "Description must be a string"

            });

        }

        const attackerName =
            `attacker-${sessionId}`;

        // -------------------------------------------------
        // WRITE SECURITY EVENT
        // -------------------------------------------------

        const securityEvent =
            writeSecurityEvent({

                sessionId:
                    sessionId,

                attacker:
                    attackerName,

                action:
                    action,

                result:
                    result,

                severity:
                    eventSeverity,

                description:
                    description || ""

            });

        // -------------------------------------------------
        // WRITE AUDIT EVENT
        // -------------------------------------------------

        writeAuditLog(
            "SECURITY_EVENT_RECORDED",
            {

                sessionId:
                    sessionId,

                attacker:
                    attackerName,

                action:
                    action,

                result:
                    result,

                severity:
                    eventSeverity,

                eventId:
                    securityEvent.eventId

            }
        );

        res.status(201).json({

            message:
                "Security event recorded successfully",

            event:
                "SECURITY_EVENT",

            eventId:
                securityEvent.eventId,

            sessionId:
                sessionId,

            action:
                action,

            result:
                result,

            severity:
                eventSeverity

        });

    }
);

// =====================================================
// 7. SECURITY SUMMARY
// =====================================================

app.get(
    "/security-summary",
    (req, res) => {

        const events =
            readSecurityEvents();

        const summary = {

            totalEvents:
                events.length,

            blockedEvents:
                events.filter(
                    e => e.result === "BLOCKED"
                ).length,

            allowedEvents:
                events.filter(
                    e => e.result === "ALLOWED"
                ).length,

            failedEvents:
                events.filter(
                    e => e.result === "FAILED"
                ).length,

            successfulEvents:
                events.filter(
                    e => e.result === "SUCCESS"
                ).length,

            severity: {

                LOW:
                    events.filter(
                        e => e.severity === "LOW"
                    ).length,

                MEDIUM:
                    events.filter(
                        e => e.severity === "MEDIUM"
                    ).length,

                HIGH:
                    events.filter(
                        e => e.severity === "HIGH"
                    ).length,

                CRITICAL:
                    events.filter(
                        e => e.severity === "CRITICAL"
                    ).length

            }

        };

        res.json(summary);

    }
);

// =====================================================
// 8. SECURITY REPORT
// =====================================================

app.get(
    "/security-report",
    (req, res) => {

        const events =
            readSecurityEvents();

        const report = {

            reportGeneratedAt:
                new Date().toISOString(),

            summary: {

                totalEvents:
                    events.length,

                blockedEvents:
                    events.filter(
                        e => e.result === "BLOCKED"
                    ).length,

                allowedEvents:
                    events.filter(
                        e => e.result === "ALLOWED"
                    ).length,

                failedEvents:
                    events.filter(
                        e => e.result === "FAILED"
                    ).length,

                successfulEvents:
                    events.filter(
                        e => e.result === "SUCCESS"
                    ).length,

                severity: {

                    LOW:
                        events.filter(
                            e => e.severity === "LOW"
                        ).length,

                    MEDIUM:
                        events.filter(
                            e => e.severity === "MEDIUM"
                        ).length,

                    HIGH:
                        events.filter(
                            e => e.severity === "HIGH"
                        ).length,

                    CRITICAL:
                        events.filter(
                            e => e.severity === "CRITICAL"
                        ).length

                }

            },

            events:
                events.map(event => ({

                    timestamp:
                        event.timestamp,

                    eventId:
                        event.eventId,

                    sessionId:
                        event.sessionId,

                    attacker:
                        event.attacker,

                    action:
                        event.action,

                    result:
                        event.result,

                    severity:
                        event.severity,

                    description:
                        event.description

                }))

        };

        res.json(report);

    }
);

// =====================================================
// 9. SECURE COMMAND EXECUTION GATEWAY
// =====================================================

app.post(
    "/sessions/:sessionId/execute",
    async (req, res) => {

        const sessionId =
            req.params.sessionId;

        const {
            command
        } = req.body;

        const attackerName =
            `attacker-${sessionId}`;

        // -------------------------------------------------
        // VALIDATE COMMAND
        // -------------------------------------------------

        if (
            typeof command !== "string" ||
            command.trim().length === 0
        ) {

            return res.status(400).json({

                message:
                    "command is required"

            });

        }

        if (command.length > 500) {

            return res.status(400).json({

                message:
                    "Command is too long"

            });

        }

        const normalizedCommand =
            command
                .trim()
                .replace(/\s+/g, " ");

        // -------------------------------------------------
        // GET ATTACKER CONTAINER
        // -------------------------------------------------

        let attacker;

        try {

            attacker =
                docker.getContainer(
                    attackerName
                );

            const info =
                await attacker.inspect();

            if (!info.State.Running) {

                return res.status(409).json({

                    message:
                        "Attacker container is not running",

                    sessionId:
                        sessionId

                });

            }

        } catch (error) {

            return res.status(404).json({

                message:
                    "Session not found",

                sessionId:
                    sessionId,

                error:
                    error.message

            });

        }

        // -------------------------------------------------
        // BLOCK SHELL CHAINING
        // -------------------------------------------------

        const shellPattern =
            BLOCKED_SHELL_PATTERNS.find(
                pattern =>
                    pattern.test(
                        normalizedCommand
                    )
            );

        if (shellPattern) {

            const event =
                writeSecurityEvent({

                    sessionId:
                        sessionId,

                    attacker:
                        attackerName,

                    action:
                        "SHELL_COMMAND_CHAINING",

                    result:
                        "BLOCKED",

                    severity:
                        "HIGH",

                    description:
                        "Shell chaining or redirection pattern blocked"

                });

            writeAuditLog(
                "COMMAND_BLOCKED",
                {

                    sessionId:
                        sessionId,

                    command:
                        normalizedCommand,

                    action:
                        "SHELL_COMMAND_CHAINING",

                    severity:
                        "HIGH",

                    eventId:
                        event.eventId

                }
            );

            return res.status(403).json({

                message:
                    "Command blocked by security policy",

                action:
                    "SHELL_COMMAND_CHAINING",

                result:
                    "BLOCKED",

                severity:
                    "HIGH",

                eventId:
                    event.eventId

            });

        }

        // -------------------------------------------------
        // BLOCK APT / PIP / GIT
        // -------------------------------------------------

        const blockedRule =
            BLOCKED_COMMAND_RULES.find(
                rule =>
                    rule.pattern.test(
                        normalizedCommand
                    )
            );

        if (blockedRule) {

            const event =
                writeSecurityEvent({

                    sessionId:
                        sessionId,

                    attacker:
                        attackerName,

                    action:
                        blockedRule.action,

                    result:
                        "BLOCKED",

                    severity:
                        blockedRule.severity,

                    description:
                        blockedRule.description

                });

            writeAuditLog(
                "COMMAND_BLOCKED",
                {

                    sessionId:
                        sessionId,

                    command:
                        normalizedCommand,

                    action:
                        blockedRule.action,

                    severity:
                        blockedRule.severity,

                    eventId:
                        event.eventId

                }
            );

            return res.status(403).json({

                message:
                    "Command blocked by security policy",

                action:
                    blockedRule.action,

                result:
                    "BLOCKED",

                severity:
                    blockedRule.severity,

                eventId:
                    event.eventId

            });

        }

        // -------------------------------------------------
        // CHECK COMMAND ALLOWLIST
        // -------------------------------------------------

        const allowed =
            ALLOWED_COMMAND_RULES.some(
                rule =>
                    rule.test(
                        normalizedCommand
                    )
            );

        if (!allowed) {

            const event =
                writeSecurityEvent({

                    sessionId:
                        sessionId,

                    attacker:
                        attackerName,

                    action:
                        "COMMAND_NOT_ALLOWED",

                    result:
                        "BLOCKED",

                    severity:
                        "MEDIUM",

                    description:
                        "Command is not included in the approved command allowlist"

                });

            writeAuditLog(
                "COMMAND_BLOCKED",
                {

                    sessionId:
                        sessionId,

                    command:
                        normalizedCommand,

                    action:
                        "COMMAND_NOT_ALLOWED",

                    severity:
                        "MEDIUM",

                    eventId:
                        event.eventId

                }
            );

            return res.status(403).json({

                message:
                    "Command is not allowed",

                action:
                    "COMMAND_NOT_ALLOWED",

                result:
                    "BLOCKED",

                severity:
                    "MEDIUM",

                eventId:
                    event.eventId

            });

        }

        // -------------------------------------------------
        // EXECUTE APPROVED COMMAND
        // -------------------------------------------------

        try {

            const exec =
                await attacker.exec({

                    Cmd: [
                        "bash",
                        "-c",
                        normalizedCommand
                    ],

                    AttachStdout:
                        true,

                    AttachStderr:
                        true

                });

            const stream =
                await exec.start({

                    hijack:
                        true,

                    stdin:
                        false

                });

            let output = "";

            stream.on(
                "data",
                chunk => {

                    output +=
                        chunk.toString();

                }
            );

            await new Promise(
                (resolve, reject) => {

                    stream.on(
                        "end",
                        resolve
                    );

                    stream.on(
                        "error",
                        reject
                    );

                }
            );

            const inspection =
                await exec.inspect();

            const result =
                inspection.ExitCode === 0
                    ? "SUCCESS"
                    : "FAILED";

            writeAuditLog(
                "COMMAND_EXECUTED",
                {

                    sessionId:
                        sessionId,

                    command:
                        normalizedCommand,

                    result:
                        result,

                    exitCode:
                        inspection.ExitCode

                }
            );

            res.json({

                message:
                    "Command executed",

                result:
                    result,

                exitCode:
                    inspection.ExitCode,

                output:
                    output

            });

        } catch (error) {

            writeAuditLog(
                "COMMAND_EXECUTION_FAILED",
                {

                    sessionId:
                        sessionId,

                    command:
                        normalizedCommand,

                    error:
                        error.message

                }
            );

            res.status(500).json({

                message:
                    "Command execution failed",

                error:
                    error.message

            });

        }

    }
);

// =====================================================
// 10. SECURITY DASHBOARD
// =====================================================

app.get(
    "/dashboard",
    async (req, res) => {

        try {

            const events =
                readSecurityEvents();

            const totalEvents =
                events.length;

            const blockedEvents =
                events.filter(
                    event =>
                        event.result === "BLOCKED"
                ).length;

            const allowedEvents =
                events.filter(
                    event =>
                        event.result === "ALLOWED"
                ).length;

            const failedEvents =
                events.filter(
                    event =>
                        event.result === "FAILED"
                ).length;

            const criticalEvents =
                events.filter(
                    event =>
                        event.severity === "CRITICAL"
                ).length;

            const highEvents =
                events.filter(
                    event =>
                        event.severity === "HIGH"
                ).length;

            const containers =
                await docker.listContainers({
                    all: false
                });

            const activeSessions =
                containers.filter(
                    container =>
                        container.Names.some(
                            name =>
                                name.startsWith(
                                    "/attacker-"
                                )
                        )
                ).length;

            const recentEvents =
                events
                    .slice(-10)
                    .reverse()
                    .map(event => ({

                        timestamp:
                            event.timestamp,

                        action:
                            event.action,

                        result:
                            event.result,

                        severity:
                            event.severity,

                        sessionId:
                            event.sessionId,

                        description:
                            event.description

                    }));

            res.json({

                dashboard:
                    "SECURITY DASHBOARD",

                activeSessions:
                    activeSessions,

                totalEvents:
                    totalEvents,

                blockedEvents:
                    blockedEvents,

                allowedEvents:
                    allowedEvents,

                failedEvents:
                    failedEvents,

                criticalEvents:
                    criticalEvents,

                highEvents:
                    highEvents,

                recentEvents:
                    recentEvents

            });

        } catch (error) {

            res.status(500).json({

                message:
                    "Failed to generate security dashboard",

                error:
                    error.message

            });

        }

    }
);

// =====================================================
// START SERVER
// =====================================================

app.listen(
    PORT,
    () => {

        console.log(
            `Orchestrator running at http://localhost:${PORT}`
        );

    }
);