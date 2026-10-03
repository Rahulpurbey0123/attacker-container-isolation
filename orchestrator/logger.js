const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// =====================================================
// LOG DIRECTORY
// =====================================================

const logsDirectory = path.join(__dirname, "logs");

if (!fs.existsSync(logsDirectory)) {
    fs.mkdirSync(logsDirectory, {
        recursive: true
    });
}

// =====================================================
// LOG FILES
// =====================================================

const auditLogFile = path.join(
    logsDirectory,
    "audit.log"
);

const securityLogFile = path.join(
    logsDirectory,
    "security-events.log"
);

// =====================================================
// GENERATE EVENT ID
// =====================================================

function generateEventId() {
    return crypto.randomUUID();
}

// =====================================================
// WRITE AUDIT LOG
// =====================================================

function writeAuditLog(event, details = {}) {

    const logEntry = {
        timestamp: new Date().toISOString(),

        eventId: generateEventId(),

        event: event,

        details: details
    };

    fs.appendFileSync(
        auditLogFile,
        JSON.stringify(logEntry) + "\n",
        "utf8"
    );

    return logEntry;
}

// =====================================================
// WRITE SECURITY EVENT
// =====================================================

function writeSecurityEvent({
    sessionId,
    attacker,
    action,
    result,
    severity = "MEDIUM",
    description = ""
}) {

    const securityEvent = {

        timestamp: new Date().toISOString(),

        eventId: generateEventId(),

        event: "SECURITY_EVENT",

        severity: severity,

        sessionId: sessionId,

        attacker: attacker,

        action: action,

        result: result,

        description: description
    };

    fs.appendFileSync(
        securityLogFile,
        JSON.stringify(securityEvent) + "\n",
        "utf8"
    );

    return securityEvent;
}

// =====================================================
// EXPORT
// =====================================================

module.exports = {

    writeAuditLog,

    writeSecurityEvent

};