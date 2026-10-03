/**
 * Security Operations Center (SOC) Admin Dashboard Logic
 * Project: Attacker Container Isolation & Access Control
 * Communicates with existing Node.js / Express Backend APIs:
 *   - GET /dashboard
 *   - GET /security-summary
 *   - GET /docker (optional for session container names)
 */

(function () {
    "use strict";

    // Configuration
    const REFRESH_INTERVAL_MS = 5000;
    const DASHBOARD_API = "/dashboard";
    const SUMMARY_API = "/security-summary";
    const DOCKER_API = "/docker";

    // DOM Elements - Telemetry & Status
    const systemAlertBanner = document.getElementById("system-alert-banner");
    const systemAlertMessage = document.getElementById("system-alert-message");
    const connectionStatusPill = document.getElementById("connection-status-pill");
    const connectionStatusText = document.getElementById("connection-status-text");
    const lastUpdatedText = document.getElementById("last-updated-text");
    const footerLastUpdated = document.getElementById("footer-last-updated");
    const btnManualRefresh = document.getElementById("btn-manual-refresh");

    // DOM Elements - Metrics Cards
    const metricActiveSessions = document.getElementById("metric-active-sessions");
    const metricTotalEvents = document.getElementById("metric-total-events");
    const metricBlockedEvents = document.getElementById("metric-blocked-events");
    const metricAllowedEvents = document.getElementById("metric-allowed-events");
    const metricHighEvents = document.getElementById("metric-high-events");
    const metricCriticalEvents = document.getElementById("metric-critical-events");

    // DOM Elements - Severity & Summary
    const severityErrorBox = document.getElementById("severity-error-box");
    const sevCriticalCount = document.getElementById("sev-critical-count");
    const sevHighCount = document.getElementById("sev-high-count");
    const sevMediumCount = document.getElementById("sev-medium-count");
    const sevLowCount = document.getElementById("sev-low-count");

    const sevCriticalBar = document.getElementById("sev-critical-bar");
    const sevHighBar = document.getElementById("sev-high-bar");
    const sevMediumBar = document.getElementById("sev-medium-bar");
    const sevLowBar = document.getElementById("sev-low-bar");

    const breakdownTotal = document.getElementById("breakdown-total");
    const breakdownBlocked = document.getElementById("breakdown-blocked");
    const breakdownAllowed = document.getElementById("breakdown-allowed");
    const breakdownFailed = document.getElementById("breakdown-failed");

    // DOM Elements - Sessions
    const sessionCountBadge = document.getElementById("session-count-badge");
    const sessionsContainer = document.getElementById("sessions-container");

    // DOM Elements - Events Table
    const dashboardErrorBox = document.getElementById("dashboard-error-box");
    const eventsCountPill = document.getElementById("events-count-pill");
    const eventsTableBody = document.getElementById("events-table-body");

    // DOM Elements - Student Session Management
    const btnCreateSession = document.getElementById("btn-create-session");
    const btnCreateSessionIcon = document.getElementById("btn-create-session-icon");
    const btnCreateSessionText = document.getElementById("btn-create-session-text");
    const sessionCreationError = document.getElementById("session-creation-error");
    const sessionCreationErrorMsg = document.getElementById("session-creation-error-msg");
    const sessionCreationSuccess = document.getElementById("session-creation-success");
    const createdSessionId = document.getElementById("created-session-id");
    const createdAttacker = document.getElementById("created-attacker");
    const createdTarget = document.getElementById("created-target");
    const createdNetwork = document.getElementById("created-network");
    const createdTerminalCmd = document.getElementById("created-terminal-cmd");
    const btnCopyCommand = document.getElementById("btn-copy-command");
    const btnCopyText = document.getElementById("btn-copy-text");

    let isFetching = false;
    let refreshTimer = null;

    // Helper: Safely format date/time
    function formatDateTime(isoString) {
        if (!isoString) return "N/A";
        try {
            const date = new Date(isoString);
            if (isNaN(date.getTime())) return String(isoString);
            return date.toLocaleString(undefined, {
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: true
            });
        } catch (e) {
            return String(isoString);
        }
    }

    // Helper: Format current time as HH:MM:SS
    function getCurrentTimeString() {
        const now = new Date();
        return now.toLocaleTimeString(undefined, {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    }

    // Helper: Create safe text badge element
    function createBadge(text, typeClass) {
        const span = document.createElement("span");
        span.className = "badge " + typeClass;
        span.textContent = text || "";
        return span;
    }

    // Determine badge class for Action Result
    function getResultBadgeClass(result) {
        const r = String(result || "").toUpperCase();
        if (r === "BLOCKED") return "badge-blocked";
        if (r === "ALLOWED" || r === "SUCCESS") return "badge-allowed";
        if (r === "FAILED") return "badge-failed";
        return "badge-medium";
    }

    // Determine badge class for Severity
    function getSeverityBadgeClass(severity) {
        const s = String(severity || "").toUpperCase();
        if (s === "CRITICAL") return "badge-critical";
        if (s === "HIGH") return "badge-high";
        if (s === "MEDIUM") return "badge-medium";
        if (s === "LOW") return "badge-low";
        return "badge-low";
    }

    // Update connection status
    function setSystemOnline(online, errorMessage) {
        if (online) {
            systemAlertBanner.classList.add("hidden");
            connectionStatusPill.className = "status-pill status-online";
            connectionStatusText.textContent = "SYSTEM ONLINE";
        } else {
            systemAlertBanner.classList.remove("hidden");
            systemAlertMessage.textContent = errorMessage || "Backend connection unavailable";
            connectionStatusPill.className = "status-pill status-offline";
            connectionStatusText.textContent = "BACKEND DISCONNECTED";
        }
    }

    // Render Recent Events Table securely
    function renderEventsTable(events) {
        eventsTableBody.innerHTML = "";

        if (!Array.isArray(events) || events.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 6;
            td.className = "table-empty-row";
            td.textContent = "No security events recorded yet";
            tr.appendChild(td);
            eventsTableBody.appendChild(tr);
            eventsCountPill.textContent = "0 Events Displayed";
            return;
        }

        eventsCountPill.textContent = events.length + (events.length === 1 ? " Event Displayed" : " Events Displayed");

        events.forEach(function (ev) {
            const tr = document.createElement("tr");

            // 1. Time
            const tdTime = document.createElement("td");
            tdTime.className = "cell-time";
            tdTime.textContent = formatDateTime(ev.timestamp);
            tr.appendChild(tdTime);

            // 2. Action
            const tdAction = document.createElement("td");
            tdAction.className = "cell-action";
            tdAction.textContent = ev.action || "UNKNOWN";
            tr.appendChild(tdAction);

            // 3. Result
            const tdResult = document.createElement("td");
            const resultBadge = createBadge(ev.result || "UNKNOWN", getResultBadgeClass(ev.result));
            tdResult.appendChild(resultBadge);
            tr.appendChild(tdResult);

            // 4. Severity
            const tdSeverity = document.createElement("td");
            const severityBadge = createBadge(ev.severity || "LOW", getSeverityBadgeClass(ev.severity));
            tdSeverity.appendChild(severityBadge);
            tr.appendChild(tdSeverity);

            // 5. Session
            const tdSession = document.createElement("td");
            tdSession.className = "cell-session";
            tdSession.textContent = ev.sessionId || "N/A";
            tr.appendChild(tdSession);

            // 6. Description
            const tdDesc = document.createElement("td");
            tdDesc.className = "cell-desc";
            tdDesc.textContent = ev.description || "";
            tr.appendChild(tdDesc);

            eventsTableBody.appendChild(tr);
        });
    }

    // Render Active Sessions
    function renderSessions(activeSessionsCount, dockerContainers) {
        sessionsContainer.innerHTML = "";

        const count = typeof activeSessionsCount === "number" ? activeSessionsCount : 0;
        sessionCountBadge.textContent = count + (count === 1 ? " ACTIVE SESSION" : " ACTIVE SESSIONS");

        // Extract session containers if docker containers available
        const sessionMap = {};

        if (Array.isArray(dockerContainers)) {
            dockerContainers.forEach(function (c) {
                const name = c.name || "";
                const isRunning = typeof c.status === "string" && c.status.toLowerCase().startsWith("up");
                if (name.startsWith("/attacker-")) {
                    const sid = name.replace("/attacker-", "");
                    if (!sessionMap[sid]) sessionMap[sid] = {};
                    sessionMap[sid].attacker = name.replace("/", "");
                    sessionMap[sid].status = isRunning ? "ACTIVE" : "EXITED";
                    sessionMap[sid].rawStatus = c.status || "";
                    sessionMap[sid].running = isRunning;
                } else if (name.startsWith("/target-")) {
                    const sid = name.replace("/target-", "");
                    if (!sessionMap[sid]) sessionMap[sid] = {};
                    sessionMap[sid].target = name.replace("/", "");
                }
            });
        }

        const sessionIds = Object.keys(sessionMap);

        if (sessionIds.length > 0) {
            sessionIds.forEach(function (sid) {
                const sessionData = sessionMap[sid];

                const card = document.createElement("div");
                card.className = "session-item-card";

                const header = document.createElement("div");
                header.className = "session-item-header";

                const idTag = document.createElement("span");
                idTag.className = "session-id-tag";
                idTag.textContent = "SESSION: " + sid;

                const isRunning = Boolean(sessionData.running);
                const statusBadge = createBadge(
                    isRunning ? "ACTIVE" : "EXITED",
                    isRunning ? "badge-active" : "badge-failed"
                );

                header.appendChild(idTag);
                header.appendChild(statusBadge);
                card.appendChild(header);

                const details = document.createElement("div");
                details.className = "session-details";

                // Attacker row
                const rowAttacker = document.createElement("div");
                rowAttacker.className = "session-detail-row";
                const lblAttacker = document.createElement("span");
                lblAttacker.textContent = "Attacker:";
                const valAttacker = document.createElement("span");
                valAttacker.className = "session-detail-val";
                valAttacker.textContent = sessionData.attacker || ("attacker-" + sid);
                rowAttacker.appendChild(lblAttacker);
                rowAttacker.appendChild(valAttacker);
                details.appendChild(rowAttacker);

                // Target row
                const rowTarget = document.createElement("div");
                rowTarget.className = "session-detail-row";
                const lblTarget = document.createElement("span");
                lblTarget.textContent = "Target:";
                const valTarget = document.createElement("span");
                valTarget.className = "session-detail-val";
                valTarget.textContent = sessionData.target || ("target-" + sid);
                rowTarget.appendChild(lblTarget);
                rowTarget.appendChild(valTarget);
                details.appendChild(rowTarget);

                card.appendChild(details);
                sessionsContainer.appendChild(card);
            });
        } else if (count > 0) {
            const notice = document.createElement("div");
            notice.className = "no-data-notice";
            notice.textContent = count + " active isolated container session(s) detected via orchestrator.";
            sessionsContainer.appendChild(notice);
        } else {
            const notice = document.createElement("div");
            notice.className = "no-data-notice";
            notice.textContent = "No active isolated container sessions currently running.";
            sessionsContainer.appendChild(notice);
        }
    }

    // Render Severity Distribution Bars & Counts
    function renderSeverity(severityData, totalEvents) {
        const low = (severityData && typeof severityData.LOW === "number") ? severityData.LOW : 0;
        const medium = (severityData && typeof severityData.MEDIUM === "number") ? severityData.MEDIUM : 0;
        const high = (severityData && typeof severityData.HIGH === "number") ? severityData.HIGH : 0;
        const critical = (severityData && typeof severityData.CRITICAL === "number") ? severityData.CRITICAL : 0;

        sevCriticalCount.textContent = critical;
        sevHighCount.textContent = high;
        sevMediumCount.textContent = medium;
        sevLowCount.textContent = low;

        // Calculate progress percentage relative to total
        const denom = (totalEvents && totalEvents > 0) ? totalEvents : Math.max(1, low + medium + high + critical);

        sevCriticalBar.style.width = Math.min(100, Math.round((critical / denom) * 100)) + "%";
        sevHighBar.style.width = Math.min(100, Math.round((high / denom) * 100)) + "%";
        sevMediumBar.style.width = Math.min(100, Math.round((medium / denom) * 100)) + "%";
        sevLowBar.style.width = Math.min(100, Math.round((low / denom) * 100)) + "%";
    }

    // Primary data fetcher
    async function fetchDashboardData() {
        if (isFetching) return;
        isFetching = true;

        btnManualRefresh.classList.add("spinning");

        let backendReachable = false;
        let dashboardData = null;
        let summaryData = null;
        let dockerData = null;

        // 1. Fetch /dashboard
        try {
            const resp = await fetch(DASHBOARD_API, { cache: "no-store" });
            if (resp.ok) {
                dashboardData = await resp.json();
                backendReachable = true;
                dashboardErrorBox.classList.add("hidden");
            } else {
                backendReachable = true;
                dashboardErrorBox.classList.remove("hidden");
                dashboardErrorBox.textContent = "Unable to load dashboard data. (HTTP " + resp.status + ")";
            }
        } catch (err) {
            dashboardErrorBox.classList.remove("hidden");
            dashboardErrorBox.textContent = "Unable to load dashboard data.";
        }

        // 2. Fetch /security-summary
        try {
            const resp = await fetch(SUMMARY_API, { cache: "no-store" });
            if (resp.ok) {
                summaryData = await resp.json();
                backendReachable = true;
                severityErrorBox.classList.add("hidden");
            } else {
                backendReachable = true;
                severityErrorBox.classList.remove("hidden");
                severityErrorBox.textContent = "Unable to load security summary. (HTTP " + resp.status + ")";
            }
        } catch (err) {
            severityErrorBox.classList.remove("hidden");
            severityErrorBox.textContent = "Unable to load security summary.";
        }

        // 3. Optional: Fetch /docker for container names
        try {
            const resp = await fetch(DOCKER_API, { cache: "no-store" });
            if (resp.ok) {
                dockerData = await resp.json();
                backendReachable = true;
            }
        } catch (err) {
            // Optional endpoint error - ignore
        }

        // Handle Connection Status
        if (!backendReachable) {
            setSystemOnline(false, "Backend connection unavailable");
        } else {
            setSystemOnline(true);

            // Update timestamp
            const timeStr = getCurrentTimeString();
            lastUpdatedText.textContent = timeStr;
            footerLastUpdated.textContent = "Last Updated: " + timeStr;

            // Apply Dashboard Data if available
            if (dashboardData) {
                metricActiveSessions.textContent = typeof dashboardData.activeSessions === "number" ? dashboardData.activeSessions : 0;
                metricTotalEvents.textContent = typeof dashboardData.totalEvents === "number" ? dashboardData.totalEvents : 0;
                metricBlockedEvents.textContent = typeof dashboardData.blockedEvents === "number" ? dashboardData.blockedEvents : 0;
                metricAllowedEvents.textContent = typeof dashboardData.allowedEvents === "number" ? dashboardData.allowedEvents : 0;
                metricHighEvents.textContent = typeof dashboardData.highEvents === "number" ? dashboardData.highEvents : 0;
                metricCriticalEvents.textContent = typeof dashboardData.criticalEvents === "number" ? dashboardData.criticalEvents : 0;

                renderEventsTable(dashboardData.recentEvents);
                renderSessions(dashboardData.activeSessions, dockerData ? dockerData.containers : null);
            }

            // Apply Summary Data if available
            if (summaryData) {
                // If dashboardData was missing or failed, populate metrics from summary
                if (!dashboardData) {
                    metricTotalEvents.textContent = summaryData.totalEvents || 0;
                    metricBlockedEvents.textContent = summaryData.blockedEvents || 0;
                    metricAllowedEvents.textContent = summaryData.allowedEvents || 0;
                    metricHighEvents.textContent = summaryData.severity ? (summaryData.severity.HIGH || 0) : 0;
                    metricCriticalEvents.textContent = summaryData.severity ? (summaryData.severity.CRITICAL || 0) : 0;
                }

                breakdownTotal.textContent = summaryData.totalEvents || 0;
                breakdownBlocked.textContent = summaryData.blockedEvents || 0;
                breakdownAllowed.textContent = summaryData.allowedEvents || 0;
                breakdownFailed.textContent = summaryData.failedEvents || 0;

                renderSeverity(summaryData.severity, summaryData.totalEvents);
            } else if (dashboardData) {
                // Fallback to dashboardData numbers if summary failed
                breakdownTotal.textContent = dashboardData.totalEvents || 0;
                breakdownBlocked.textContent = dashboardData.blockedEvents || 0;
                breakdownAllowed.textContent = dashboardData.allowedEvents || 0;
                breakdownFailed.textContent = dashboardData.failedEvents || 0;

                renderSeverity({
                    CRITICAL: dashboardData.criticalEvents || 0,
                    HIGH: dashboardData.highEvents || 0,
                    MEDIUM: 0,
                    LOW: 0
                }, dashboardData.totalEvents);
            }
        }

        btnManualRefresh.classList.remove("spinning");
        isFetching = false;
    }

    // Student Session Creation Handler
    async function handleCreateSession() {
        if (!btnCreateSession) return;

        // Step 1: Disable button temporarily, show CREATING SESSION...
        btnCreateSession.disabled = true;
        if (btnCreateSessionIcon) {
            btnCreateSessionIcon.textContent = "";
            btnCreateSessionIcon.className = "btn-create-icon spinning";
        }
        if (btnCreateSessionText) {
            btnCreateSessionText.textContent = "CREATING SESSION...";
        }

        // Hide any previous error or success box
        if (sessionCreationError) {
            sessionCreationError.classList.add("hidden");
        }
        if (sessionCreationSuccess) {
            sessionCreationSuccess.classList.add("hidden");
        }

        try {
            // Step 2: Send POST /sessions using relative path
            const response = await fetch("/sessions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                // Step 3: Handle success response
                const data = await response.json();

                const sid = data.sessionId || "N/A";
                const attackerName = data.attacker || ("attacker-" + sid);
                const targetName = data.target || ("target-" + sid);
                const networkName = data.network || ("session-" + sid + "-net");
                const terminalCmd = "docker exec -it " + attackerName + " bash";

                // Safe textContent assignment
                if (createdSessionId) createdSessionId.textContent = sid;
                if (createdAttacker) createdAttacker.textContent = attackerName;
                if (createdTarget) createdTarget.textContent = targetName;
                if (createdNetwork) createdNetwork.textContent = networkName;
                if (createdTerminalCmd) createdTerminalCmd.textContent = terminalCmd;

                if (sessionCreationSuccess) {
                    sessionCreationSuccess.classList.remove("hidden");
                }

                // Trigger existing dashboard refresh immediately
                fetchDashboardData();
            } else {
                // Backend returned error status
                let userMessage = "Unable to create a new isolated session. Please check the backend connection.";
                try {
                    const errData = await response.json();
                    if (errData && typeof errData.message === "string") {
                        userMessage = errData.message;
                    }
                } catch (jsonErr) {
                    // Fallback to userMessage
                }

                if (sessionCreationErrorMsg) {
                    sessionCreationErrorMsg.textContent = userMessage;
                }
                if (sessionCreationError) {
                    sessionCreationError.classList.remove("hidden");
                }
            }
        } catch (netErr) {
            // Network failure or backend unreachable
            if (sessionCreationErrorMsg) {
                sessionCreationErrorMsg.textContent = "Unable to create a new isolated session. Please check the backend connection.";
            }
            if (sessionCreationError) {
                sessionCreationError.classList.remove("hidden");
            }
        } finally {
            // Re-enable button and reset text
            btnCreateSession.disabled = false;
            if (btnCreateSessionIcon) {
                btnCreateSessionIcon.className = "btn-create-icon";
                btnCreateSessionIcon.textContent = "+";
            }
            if (btnCreateSessionText) {
                btnCreateSessionText.textContent = "CREATE NEW SESSION";
            }
        }
    }

    // Terminal Command Copy Handler
    async function handleCopyCommand() {
        if (!createdTerminalCmd) return;
        const cmd = createdTerminalCmd.textContent;
        if (!cmd) return;

        let success = false;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            try {
                await navigator.clipboard.writeText(cmd);
                success = true;
            } catch (err) {
                success = false;
            }
        }

        if (!success) {
            try {
                const tempInput = document.createElement("textarea");
                tempInput.value = cmd;
                tempInput.style.position = "fixed";
                tempInput.style.left = "-9999px";
                document.body.appendChild(tempInput);
                tempInput.focus();
                tempInput.select();
                success = document.execCommand("copy");
                document.body.removeChild(tempInput);
            } catch (fallbackErr) {
                success = false;
            }
        }

        if (success) {
            if (btnCopyText) btnCopyText.textContent = "COPIED!";
            if (btnCopyCommand) btnCopyCommand.classList.add("copied");
            setTimeout(function () {
                if (btnCopyText) btnCopyText.textContent = "COPY TERMINAL COMMAND";
                if (btnCopyCommand) btnCopyCommand.classList.remove("copied");
            }, 2000);
        } else {
            if (btnCopyText) btnCopyText.textContent = "SELECT & COPY";
            setTimeout(function () {
                if (btnCopyText) btnCopyText.textContent = "COPY TERMINAL COMMAND";
            }, 2000);
        }
    }

    // Attach Event Listeners
    if (btnCreateSession) {
        btnCreateSession.addEventListener("click", handleCreateSession);
    }
    if (btnCopyCommand) {
        btnCopyCommand.addEventListener("click", handleCopyCommand);
    }

    // Manual Refresh Event
    btnManualRefresh.addEventListener("click", function () {
        fetchDashboardData();
    });

    // Start auto-refresh interval
    function startAutoRefresh() {
        if (refreshTimer) clearInterval(refreshTimer);
        refreshTimer = setInterval(fetchDashboardData, REFRESH_INTERVAL_MS);
    }

    // Initial load
    fetchDashboardData();
    startAutoRefresh();
})();
