/**
 * Shared Security Validation Module
 * Enforces session ID formatting, command allowlists/blocklists,
 * and shell metacharacter blocking across orchestrator providers and test suites.
 */

// Kubernetes DNS-1123 subdomain/label compatible format:
// Lowercase alphanumeric and hyphens, starting and ending with alphanumeric.
// Maximum 50 characters so `attacker-${sessionId}` does not exceed 63 characters.
const K8S_SESSION_ID_REGEX = /^[a-z0-9]([-a-z0-9]{0,48}[a-z0-9])?$/;

/**
 * Validates whether a session identifier is Kubernetes DNS-1123 compliant.
 * @param {string} sessionId
 * @returns {boolean}
 */
function isValidSessionId(sessionId) {
    if (typeof sessionId !== "string") return false;
    if (sessionId.length < 1 || sessionId.length > 50) return false;
    return K8S_SESSION_ID_REGEX.test(sessionId);
}

/**
 * Throws or returns an error message if the session ID is invalid.
 * @param {string} sessionId
 */
function assertValidSessionId(sessionId) {
    if (!isValidSessionId(sessionId)) {
        const err = new Error(
            `Invalid session ID "${sessionId}". Session IDs must be Kubernetes DNS-1123 compatible: lowercase alphanumeric and hyphens only, 1 to 50 characters, starting and ending with an alphanumeric character.`
        );
        err.statusCode = 400;
        throw err;
    }
}

/**
 * Prohibited command patterns
 */
const BLOCKED_COMMAND_RULES = [
    {
        pattern: /\b(?:apt|apt-get)\s+(?:update|install|upgrade|remove|purge|autoremove)\b/i,
        action: "APT_COMMAND",
        severity: "HIGH",
        description: "Runtime APT package-management command blocked"
    },
    {
        pattern: /\b(?:pip|pip3)\s+install\b/i,
        action: "PIP_INSTALL",
        severity: "HIGH",
        description: "Runtime Python package installation command blocked"
    },
    {
        pattern: /\bgit\s+clone\b/i,
        action: "GIT_CLONE",
        severity: "MEDIUM",
        description: "Runtime Git repository download command blocked"
    }
];

/**
 * Prohibited shell chaining, subshell, and redirection operators
 */
const BLOCKED_SHELL_PATTERNS = [
    { pattern: /;/, name: "SEMICOLON" },
    { pattern: /&&/, name: "LOGICAL_AND" },
    { pattern: /\|\|/, name: "LOGICAL_OR" },
    { pattern: /\|/, name: "PIPE" },
    { pattern: /`/, name: "BACKTICK" },
    { pattern: /\$\(/, name: "COMMAND_SUBSTITUTION" },
    { pattern: />/, name: "REDIRECT_OUT" },
    { pattern: /</, name: "REDIRECT_IN" }
];

/**
 * Allowed command patterns (strict allowlist)
 */
const ALLOWED_COMMAND_RULES = [
    /^id$/i,
    /^whoami$/i,
    /^pwd$/i,
    /^ls(?:\s+[-a-zA-Z0-9.\/]+)?$/i,
    /^cat\s+[-a-zA-Z0-9_.\/]+$/i,
    /^getent\s+hosts\s+[a-zA-Z0-9._-]+$/i,
    /^ping(?:\s+-c\s+\d+)?\s+[a-zA-Z0-9._-]+$/i,
    /^curl(?:\s+--connect-timeout\s+\d+)?(?:\s+-s)?(?:\s+-I)?(?:\s+-i)?\s+https?:\/\/[a-zA-Z0-9._:-]+(?:\/[a-zA-Z0-9._\/-]*)?$/i
];

/**
 * Validates an input command against security policies.
 * @param {string} rawCommand
 * @returns {{ allowed: boolean, normalizedCommand?: string, error?: string, action?: string, severity?: string, description?: string }}
 */
function evaluateCommand(rawCommand) {
    if (typeof rawCommand !== "string" || rawCommand.trim().length === 0) {
        return {
            allowed: false,
            error: "command is required",
            statusCode: 400
        };
    }

    if (rawCommand.length > 500) {
        return {
            allowed: false,
            error: "Command is too long (maximum 500 characters)",
            statusCode: 400
        };
    }

    const normalizedCommand = rawCommand.trim().replace(/\s+/g, " ");

    // 1. Check for shell chaining / redirection
    const shellMatch = BLOCKED_SHELL_PATTERNS.find(rule => rule.pattern.test(normalizedCommand));
    if (shellMatch) {
        return {
            allowed: false,
            normalizedCommand,
            action: "SHELL_COMMAND_CHAINING",
            severity: "HIGH",
            description: `Shell operator (${shellMatch.name}) blocked by security policy`,
            statusCode: 403
        };
    }

    // 2. Check for prohibited package/repo management commands
    const blockedRule = BLOCKED_COMMAND_RULES.find(rule => rule.pattern.test(normalizedCommand));
    if (blockedRule) {
        return {
            allowed: false,
            normalizedCommand,
            action: blockedRule.action,
            severity: blockedRule.severity,
            description: blockedRule.description,
            statusCode: 403
        };
    }

    // 3. Verify against approved command allowlist
    const isAllowed = ALLOWED_COMMAND_RULES.some(rule => rule.test(normalizedCommand));
    if (!isAllowed) {
        return {
            allowed: false,
            normalizedCommand,
            action: "COMMAND_NOT_ALLOWED",
            severity: "MEDIUM",
            description: "Command is not included in the approved command allowlist",
            statusCode: 403
        };
    }

    return {
        allowed: true,
        normalizedCommand
    };
}

module.exports = {
    K8S_SESSION_ID_REGEX,
    isValidSessionId,
    assertValidSessionId,
    BLOCKED_COMMAND_RULES,
    BLOCKED_SHELL_PATTERNS,
    ALLOWED_COMMAND_RULES,
    evaluateCommand
};
