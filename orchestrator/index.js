const express = require("express");
const fs = require("fs");
const path = require("path");

const {
    writeAuditLog,
    writeSecurityEvent
} = require("./logger");

const {
    getActiveProvider,
    getDockerProvider,
    getKubernetesProvider,
    getProviderName
} = require("./providers");

const {
    isValidSessionId,
    evaluateCommand,
    BLOCKED_COMMAND_RULES,
    ALLOWED_COMMAND_RULES,
    BLOCKED_SHELL_PATTERNS
} = require("./security/validator");

const app = express();
app.use(express.json());

app.use(
    "/dashboard-ui",
    express.static(path.join(__dirname, "dashboard"))
);

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || "127.0.0.1";

// =====================================================
// SECURITY VALIDATION CONSTANTS
// =====================================================

const ALLOWED_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const ALLOWED_RESULTS = ["BLOCKED", "ALLOWED", "FAILED", "SUCCESS"];

// =====================================================
// HELPER: READ SECURITY EVENTS
// =====================================================

function readSecurityEvents() {
    const logFile = path.join(__dirname, "logs", "security-events.log");
    if (!fs.existsSync(logFile)) {
        return [];
    }

    const lines = fs.readFileSync(logFile, "utf8")
        .split("\n")
        .filter(line => line.trim());

    const events = [];
    for (const line of lines) {
        try {
            events.push(JSON.parse(line));
        } catch (error) {
            // Ignore malformed lines
        }
    }
    return events;
}

// =====================================================
// 1. HEALTH CHECK & ACTIVE PROVIDER
// =====================================================

app.get("/", (req, res) => {
    res.json({
        project: "Attacker Container Isolation and Access Control",
        status: "Orchestrator is running",
        version: "1.0.0",
        orchestratorProvider: getProviderName(),
        boundHost: HOST,
        securityNotice: "Local-demo-only. Unauthenticated API must not be exposed to untrusted networks."
    });
});

// =====================================================
// 2. DOCKER CONNECTION CHECK
// =====================================================

app.get("/docker", async (req, res) => {
    try {
        const result = await getDockerProvider().checkConnection();
        res.json({
            docker: "connected",
            containers: result.containers
        });
    } catch (error) {
        res.status(500).json({
            docker: "connection failed",
            error: error.message
        });
    }
});

// =====================================================
// 2B. KUBERNETES CONNECTION CHECK
// =====================================================

app.get("/k8s", async (req, res) => {
    try {
        const result = await getKubernetesProvider().checkConnection();
        if (result.status === "connected") {
            res.json(result);
        } else {
            res.status(500).json(result);
        }
    } catch (error) {
        res.status(500).json({
            status: "disconnected",
            provider: "kubernetes",
            error: error.message
        });
    }
});

// =====================================================
// 3. CREATE ISOLATED SESSION
// =====================================================

app.post("/sessions", async (req, res) => {
    let sessionId = req.body && req.body.sessionId;

    if (sessionId) {
        if (!isValidSessionId(sessionId)) {
            return res.status(400).json({
                message: "Invalid session ID format. Must be Kubernetes DNS-1123 compatible (lowercase alphanumeric and hyphens, 1-50 characters).",
                sessionId
            });
        }
    } else {
        // Generate valid DNS-1123 compatible session ID
        sessionId = `s${Date.now()}`;
    }

    const provider = getActiveProvider();

    try {
        const sessionMeta = await provider.createSession(sessionId);

        writeAuditLog("SESSION_CREATED", {
            sessionId,
            provider: provider.name,
            network: sessionMeta.network,
            attacker: sessionMeta.attacker,
            target: sessionMeta.target
        });

        res.status(201).json({
            message: "Isolated session created successfully",
            sessionId,
            provider: provider.name,
            network: sessionMeta.network,
            attacker: sessionMeta.attacker,
            target: sessionMeta.target
        });
    } catch (error) {
        writeAuditLog("SESSION_CREATION_FAILED", {
            sessionId,
            provider: provider.name,
            error: error.message
        });

        const statusCode = error.statusCode || 500;
        res.status(statusCode).json({
            message: "Failed to create isolated session",
            sessionId,
            provider: provider.name,
            error: error.message
        });
    }
});

// =====================================================
// 4. DELETE ISOLATED SESSION
// =====================================================

app.delete("/sessions/:sessionId", async (req, res) => {
    const sessionId = req.params.sessionId;

    if (!isValidSessionId(sessionId)) {
        return res.status(400).json({
            message: "Invalid session ID format. Must be Kubernetes DNS-1123 compatible.",
            sessionId
        });
    }

    const provider = getActiveProvider();

    try {
        await provider.deleteSession(sessionId);

        writeAuditLog("SESSION_DELETED", {
            sessionId,
            provider: provider.name
        });

        res.json({
            message: "Session deleted successfully",
            sessionId,
            provider: provider.name
        });
    } catch (error) {
        writeAuditLog("SESSION_DELETION_FAILED", {
            sessionId,
            provider: provider.name,
            error: error.message
        });

        const statusCode = error.statusCode || 500;
        res.status(statusCode).json({
            message: "Failed to delete session",
            sessionId,
            error: error.message
        });
    }
});

// =====================================================
// 5. CHECK SESSION STATUS
// =====================================================

app.get("/sessions/:sessionId", async (req, res) => {
    const sessionId = req.params.sessionId;

    if (!isValidSessionId(sessionId)) {
        return res.status(400).json({
            message: "Invalid session ID format. Must be Kubernetes DNS-1123 compatible.",
            sessionId
        });
    }

    const provider = getActiveProvider();

    try {
        const session = await provider.getSession(sessionId);
        res.json(session);
    } catch (error) {
        const statusCode = error.statusCode || 404;
        res.status(statusCode).json({
            message: "Session not found",
            sessionId,
            error: error.message
        });
    }
});

// =====================================================
// 6. RECORD SECURITY EVENT
// =====================================================

app.post("/sessions/:sessionId/events", (req, res) => {
    const sessionId = req.params.sessionId;

    if (!isValidSessionId(sessionId)) {
        return res.status(400).json({
            message: "Invalid session ID format. Must be Kubernetes DNS-1123 compatible.",
            sessionId
        });
    }

    const { action, result, severity, description } = req.body;

    if (!action || !result) {
        return res.status(400).json({
            message: "action and result are required"
        });
    }

    const eventSeverity = severity || "MEDIUM";
    if (!ALLOWED_SEVERITIES.includes(eventSeverity)) {
        return res.status(400).json({
            message: "Invalid severity",
            allowed: ALLOWED_SEVERITIES
        });
    }

    if (!ALLOWED_RESULTS.includes(result)) {
        return res.status(400).json({
            message: "Invalid result",
            allowed: ALLOWED_RESULTS
        });
    }

    if (typeof action !== "string" || action.length < 2 || action.length > 100) {
        return res.status(400).json({
            message: "Action must be between 2 and 100 characters"
        });
    }

    if (description !== undefined && typeof description !== "string") {
        return res.status(400).json({
            message: "Description must be a string"
        });
    }

    const attackerName = `attacker-${sessionId}`;

    const securityEvent = writeSecurityEvent({
        sessionId,
        attacker: attackerName,
        action,
        result,
        severity: eventSeverity,
        description: description || ""
    });

    writeAuditLog("SECURITY_EVENT_RECORDED", {
        sessionId,
        attacker: attackerName,
        action,
        result,
        severity: eventSeverity,
        eventId: securityEvent.eventId
    });

    res.status(201).json({
        message: "Security event recorded successfully",
        event: "SECURITY_EVENT",
        eventId: securityEvent.eventId,
        sessionId,
        action,
        result,
        severity: eventSeverity
    });
});

// =====================================================
// 7. SECURITY SUMMARY
// =====================================================

app.get("/security-summary", (req, res) => {
    const events = readSecurityEvents();
    const summary = {
        totalEvents: events.length,
        blockedEvents: events.filter(e => e.result === "BLOCKED").length,
        allowedEvents: events.filter(e => e.result === "ALLOWED").length,
        failedEvents: events.filter(e => e.result === "FAILED").length,
        successfulEvents: events.filter(e => e.result === "SUCCESS").length,
        severity: {
            LOW: events.filter(e => e.severity === "LOW").length,
            MEDIUM: events.filter(e => e.severity === "MEDIUM").length,
            HIGH: events.filter(e => e.severity === "HIGH").length,
            CRITICAL: events.filter(e => e.severity === "CRITICAL").length
        }
    };
    res.json(summary);
});

// =====================================================
// 8. SECURITY REPORT
// =====================================================

app.get("/security-report", (req, res) => {
    const events = readSecurityEvents();
    const report = {
        reportGeneratedAt: new Date().toISOString(),
        summary: {
            totalEvents: events.length,
            blockedEvents: events.filter(e => e.result === "BLOCKED").length,
            allowedEvents: events.filter(e => e.result === "ALLOWED").length,
            failedEvents: events.filter(e => e.result === "FAILED").length,
            successfulEvents: events.filter(e => e.result === "SUCCESS").length,
            severity: {
                LOW: events.filter(e => e.severity === "LOW").length,
                MEDIUM: events.filter(e => e.severity === "MEDIUM").length,
                HIGH: events.filter(e => e.severity === "HIGH").length,
                CRITICAL: events.filter(e => e.severity === "CRITICAL").length
            }
        },
        events: events.map(event => ({
            timestamp: event.timestamp,
            eventId: event.eventId,
            sessionId: event.sessionId,
            attacker: event.attacker,
            action: event.action,
            result: event.result,
            severity: event.severity,
            description: event.description
        }))
    };
    res.json(report);
});

// =====================================================
// 9. SECURE COMMAND EXECUTION GATEWAY
// =====================================================

app.post(["/sessions/:sessionId/execute", "/sessions/:sessionId/exec"], async (req, res) => {
    const sessionId = req.params.sessionId;

    if (!isValidSessionId(sessionId)) {
        return res.status(400).json({
            message: "Invalid session ID format. Must be Kubernetes DNS-1123 compatible.",
            sessionId
        });
    }

    const { command } = req.body;
    const attackerName = `attacker-${sessionId}`;
    const provider = getActiveProvider();

    // Evaluate command using shared validator
    const evalResult = evaluateCommand(command);

    if (!evalResult.allowed) {
        if (evalResult.action) {
            const event = writeSecurityEvent({
                sessionId,
                attacker: attackerName,
                action: evalResult.action,
                result: "BLOCKED",
                severity: evalResult.severity,
                description: evalResult.description
            });

            writeAuditLog("COMMAND_BLOCKED", {
                sessionId,
                provider: provider.name,
                command: evalResult.normalizedCommand || command,
                action: evalResult.action,
                severity: evalResult.severity,
                eventId: event.eventId
            });

            return res.status(evalResult.statusCode || 403).json({
                message: evalResult.description || "Command blocked by security policy",
                action: evalResult.action,
                result: "BLOCKED",
                severity: evalResult.severity,
                eventId: event.eventId
            });
        }

        return res.status(evalResult.statusCode || 400).json({
            message: evalResult.error || "Invalid command"
        });
    }

    const normalizedCommand = evalResult.normalizedCommand;

    // EXECUTE APPROVED COMMAND VIA ACTIVE PROVIDER
    try {
        const execResult = await provider.executeCommand(sessionId, normalizedCommand);

        writeAuditLog("COMMAND_EXECUTED", {
            sessionId,
            provider: provider.name,
            command: normalizedCommand,
            result: execResult.result,
            exitCode: execResult.exitCode
        });

        res.json({
            message: "Command executed",
            provider: provider.name,
            result: execResult.result,
            exitCode: execResult.exitCode,
            output: execResult.output
        });
    } catch (error) {
        const statusCode = error.statusCode || 500;

        writeAuditLog("COMMAND_EXECUTION_FAILED", {
            sessionId,
            provider: provider.name,
            command: normalizedCommand,
            error: error.message
        });

        res.status(statusCode).json({
            message: "Command execution failed",
            provider: provider.name,
            error: error.message
        });
    }
});

// =====================================================
// 10. SECURITY DASHBOARD
// =====================================================

app.get("/dashboard", async (req, res) => {
    try {
        const events = readSecurityEvents();
        const provider = getActiveProvider();

        const totalEvents = events.length;
        const blockedEvents = events.filter(e => e.result === "BLOCKED").length;
        const allowedEvents = events.filter(e => e.result === "ALLOWED").length;
        const failedEvents = events.filter(e => e.result === "FAILED").length;
        const criticalEvents = events.filter(e => e.severity === "CRITICAL").length;
        const highEvents = events.filter(e => e.severity === "HIGH").length;

        let activeSessions = 0;
        let containers = [];

        try {
            activeSessions = await provider.getActiveSessionsCount();
            containers = await provider.listActiveContainers();
        } catch (provErr) {
            console.error("Error retrieving provider container telemetry:", provErr.message);
        }

        const recentEvents = events
            .slice(-10)
            .reverse()
            .map(event => ({
                timestamp: event.timestamp,
                action: event.action,
                result: event.result,
                severity: event.severity,
                sessionId: event.sessionId,
                description: event.description
            }));

        res.json({
            dashboard: "SECURITY DASHBOARD",
            provider: provider.name,
            activeSessions,
            containers,
            totalEvents,
            blockedEvents,
            allowedEvents,
            failedEvents,
            criticalEvents,
            highEvents,
            recentEvents
        });
    } catch (error) {
        res.status(500).json({
            message: "Failed to generate security dashboard",
            error: error.message
        });
    }
});

// =====================================================
// START SERVER
// =====================================================

if (require.main === module) {
    app.listen(PORT, HOST, () => {
        console.log(`Orchestrator running at http://${HOST}:${PORT}`);
        console.log(`Active Orchestration Provider: [${getProviderName().toUpperCase()}]`);
        console.log(`SECURITY NOTICE: API explicitly bound to ${HOST} (local-demo-only).`);
    });
}

module.exports = app;