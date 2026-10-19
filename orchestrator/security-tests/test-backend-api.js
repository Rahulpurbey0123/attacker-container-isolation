const http = require("http");

process.env.ORCHESTRATOR_PROVIDER = "kubernetes";
const app = require("../index.js");

function request(method, path, body = null) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const options = {
            hostname: "127.0.0.1",
            port: 3001,
            path: path,
            method: method,
            headers: {
                "Content-Type": "application/json"
            }
        };

        if (payload) {
            options.headers["Content-Length"] = Buffer.byteLength(payload);
        }

        const req = http.request(options, res => {
            let data = "";
            res.on("data", chunk => data += chunk.toString());
            res.on("end", () => {
                let parsed;
                try {
                    parsed = JSON.parse(data);
                } catch (e) {
                    parsed = data;
                }
                resolve({
                    status: res.statusCode,
                    body: parsed
                });
            });
        });

        req.on("error", reject);
        if (payload) req.write(payload);
        req.end();
    });
}

async function runBackendAudit() {
    console.log("==================================================");
    console.log("   EXPRESS BACKEND KUBERNETES ENDPOINT AUDIT");
    console.log("==================================================");

    const server = app.listen(3001, "127.0.0.1");
    console.log("Test server started on 127.0.0.1:3001");

    try {
        // 1. Health check & host binding verification
        const health = await request("GET", "/");
        console.log("1. GET / status:", health.status, "Provider:", health.body.orchestratorProvider, "BoundHost:", health.body.boundHost);
        if (health.status !== 200 || health.body.orchestratorProvider !== "kubernetes" || health.body.boundHost !== "127.0.0.1") {
            throw new Error("Health check failed or server not bound to 127.0.0.1");
        }

        // 2. K8s connectivity check
        const k8sStatus = await request("GET", "/k8s");
        console.log("2. GET /k8s status:", k8sStatus.status, "Context:", k8sStatus.body.context, "LeastPrivilege:", k8sStatus.body.isLeastPrivilege);
        if (k8sStatus.status !== 200 || k8sStatus.body.status !== "connected") {
            throw new Error("K8s status check failed");
        }

        // 3. Session ID validation check (reject invalid IDs with 400 Bad Request)
        console.log("3. Testing session ID validation on invalid input...");
        const invalidPost = await request("POST", "/sessions", { sessionId: "INVALID_UPPERCASE" });
        console.log("   POST /sessions (invalid ID) status:", invalidPost.status);
        if (invalidPost.status !== 400) {
            throw new Error("Expected HTTP 400 for invalid session ID creation");
        }

        const invalidGet = await request("GET", "/sessions/invalid_underscore");
        console.log("   GET /sessions/:id (invalid ID) status:", invalidGet.status);
        if (invalidGet.status !== 400) {
            throw new Error("Expected HTTP 400 for invalid session ID retrieval");
        }

        // 4. Create isolated session via POST /sessions
        console.log("4. Creating valid session via POST /sessions...");
        const createRes = await request("POST", "/sessions");
        console.log("   POST /sessions status:", createRes.status, "SessionId:", createRes.body.sessionId);
        if (createRes.status !== 201 || !createRes.body.sessionId) {
            throw new Error("Session creation failed: " + JSON.stringify(createRes.body));
        }
        const sessionId = createRes.body.sessionId;

        // 5. Retrieve session via GET /sessions/:sessionId
        console.log(`5. Retrieving session GET /sessions/${sessionId}...`);
        const getRes = await request("GET", `/sessions/${sessionId}`);
        console.log("   GET /sessions/:id status:", getRes.status, "Attacker status:", getRes.body.attacker.status);
        if (getRes.status !== 200 || !getRes.body.attacker.running) {
            throw new Error("Session retrieval failed: " + JSON.stringify(getRes.body));
        }

        // 6. Execute approved command via POST /sessions/:sessionId/execute
        console.log("6. Executing approved command 'id'...");
        const execApproved = await request("POST", `/sessions/${sessionId}/execute`, { command: "id" });
        console.log("   POST /execute (approved) status:", execApproved.status, "Output:", execApproved.body.output ? execApproved.body.output.trim() : "");
        if (execApproved.status !== 200 || execApproved.body.result !== "SUCCESS" || !execApproved.body.output.includes("uid=1001(student)")) {
            throw new Error("Approved command execution failed: " + JSON.stringify(execApproved.body));
        }

        // 7. Execute prohibited APT command via POST /sessions/:sessionId/execute
        console.log("7. Executing prohibited command 'apt-get install nmap'...");
        const execBlocked = await request("POST", `/sessions/${sessionId}/execute`, { command: "apt-get install nmap" });
        console.log("   POST /execute (blocked) status:", execBlocked.status, "Action:", execBlocked.body.action);
        if (execBlocked.status !== 403 || execBlocked.body.result !== "BLOCKED") {
            throw new Error("Prohibited command was not blocked: " + JSON.stringify(execBlocked.body));
        }

        // 8. Execute prohibited shell chaining operator via POST /sessions/:sessionId/execute
        console.log("8. Executing shell chaining operator 'id; whoami'...");
        const execChaining = await request("POST", `/sessions/${sessionId}/execute`, { command: "id; whoami" });
        console.log("   POST /execute (chaining blocked) status:", execChaining.status, "Action:", execChaining.body.action);
        if (execChaining.status !== 403 || execChaining.body.action !== "SHELL_COMMAND_CHAINING") {
            throw new Error("Shell chaining was not blocked: " + JSON.stringify(execChaining.body));
        }

        // 9. Delete session via DELETE /sessions/:sessionId
        console.log(`9. Deleting session DELETE /sessions/${sessionId}...`);
        const delRes = await request("DELETE", `/sessions/${sessionId}`);
        console.log("   DELETE /sessions/:id status:", delRes.status);
        if (delRes.status !== 200) {
            throw new Error("Session deletion failed: " + JSON.stringify(delRes.body));
        }

        // 10. Confirm session is gone via GET /sessions/:sessionId
        console.log("10. Verifying session is deleted...");
        await new Promise(r => setTimeout(r, 2000));
        const getDeleted = await request("GET", `/sessions/${sessionId}`);
        console.log("    GET /sessions/:id after delete status:", getDeleted.status);
        if (getDeleted.status !== 404) {
            throw new Error("Session still accessible after deletion!");
        }

        console.log("");
        console.log("==================================================");
        console.log("   ALL BACKEND API AUDIT TESTS PASSED!");
        console.log("==================================================");

    } finally {
        server.close();
    }
}

if (require.main === module) {
    runBackendAudit().catch(err => {
        console.error("Backend audit failed:", err.message);
        process.exit(1);
    });
}

module.exports = { runBackendAudit };
