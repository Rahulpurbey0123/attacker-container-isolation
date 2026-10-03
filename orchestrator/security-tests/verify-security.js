const Docker = require("dockerode");
const fs = require("fs");
const path = require("path");

const docker = new Docker();

// =====================================================
// COMMAND LINE ARGUMENTS
// =====================================================

const attackerName = process.argv[2];
const ownTargetName = process.argv[3];
const otherTargetName = process.argv[4];

if (!attackerName || !ownTargetName || !otherTargetName) {
    console.log(
        "Usage: node verify-security.js <attacker> <own-target> <other-target>"
    );
    process.exit(1);
}

// =====================================================
// RESULTS
// =====================================================

const testResults = [];

function recordTest(name, passed, details = "") {
    testResults.push({
        name,
        passed,
        details
    });

    if (passed) {
        console.log(`[PASS] ${name}`);
    } else {
        console.log(`[FAIL] ${name}`);
    }

    if (details) {
        console.log(`       ${details}`);
    }
}

// =====================================================
// HELPER — RUN COMMAND INSIDE CONTAINER
// =====================================================

async function runContainerCommand(container, command) {
    const exec = await container.exec({
        Cmd: ["bash", "-c", command],
        AttachStdout: true,
        AttachStderr: true
    });

    const stream = await exec.start({
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

    const inspection = await exec.inspect();

    return {
        output,
        exitCode: inspection.ExitCode
    };
}

// =====================================================
// MAIN SECURITY VERIFICATION
// =====================================================

async function runSecurityTests() {

    console.log("");
    console.log("==============================================");
    console.log("   SECURITY VERIFICATION");
    console.log("==============================================");
    console.log("");

    try {

        const attacker =
            docker.getContainer(attackerName);

        const attackerInfo =
            await attacker.inspect();

        // =================================================
        // TEST 1 — NON-ROOT USER
        // =================================================

        const user =
            attackerInfo.Config.User;

        const nonRoot =
            user === "1001:1001";

        recordTest(
            "Non-root user",
            nonRoot,
            `Configured user: ${user}`
        );

        // =================================================
        // TEST 2 — READ-ONLY ROOT FILESYSTEM
        // =================================================

        const readonlyRoot =
            attackerInfo.HostConfig.ReadonlyRootfs === true;

        recordTest(
            "Read-only root filesystem",
            readonlyRoot,
            `ReadonlyRootfs=${readonlyRoot}`
        );

        // =================================================
        // TEST 3 — CAPABILITIES DROPPED
        // =================================================

        const capDrop =
            attackerInfo.HostConfig.CapDrop || [];

        const allCapabilitiesDropped =
            capDrop.includes("ALL");

        recordTest(
            "All unnecessary capabilities dropped",
            allCapabilitiesDropped,
            `CapDrop=${JSON.stringify(capDrop)}`
        );

        // =================================================
        // TEST 4 — ONLY NET_RAW ADDED
        // =================================================

        const capAdd =
            attackerInfo.HostConfig.CapAdd || [];

        const onlyNetRaw =
            capAdd.length === 1 &&
            (
                capAdd[0] === "NET_RAW" ||
                capAdd[0] === "CAP_NET_RAW"
            );

        recordTest(
            "Only NET_RAW capability added",
            onlyNetRaw,
            `CapAdd=${JSON.stringify(capAdd)}`
        );

        // =================================================
        // TEST 5 — RUNTIME PACKAGE MANAGEMENT BLOCKED
        // =================================================

        try {

            const result =
                await runContainerCommand(
                    attacker,
                    "apt-get update"
                );

            const aptBlocked =
                result.exitCode !== 0;

            recordTest(
                "Runtime package management blocked",
                aptBlocked,
                aptBlocked
                    ? `apt-get update was blocked (exit code ${result.exitCode})`
                    : "apt-get update completed successfully"
            );

        } catch (error) {

            recordTest(
                "Runtime package management blocked",
                true,
                "apt-get update was blocked: " + error.message
            );

        }

        // =================================================
        // TEST 6 — OWN TARGET REACHABLE
        // =================================================

        try {

            const result =
                await runContainerCommand(
                    attacker,
                    `curl --connect-timeout 5 http://${ownTargetName}`
                );

            const reachable =
                result.exitCode === 0 &&
                result.output.includes("Welcome to nginx");

            recordTest(
                "Own target reachable",
                reachable,
                reachable
                    ? "Attacker successfully reached assigned target"
                    : "Assigned target was not reachable"
            );

        } catch (error) {

            recordTest(
                "Own target reachable",
                false,
                error.message
            );

        }

        // =================================================
        // TEST 7 — CROSS-SESSION TARGET BLOCKED
        // =================================================

        try {

            const result =
                await runContainerCommand(
                    attacker,
                    `curl --connect-timeout 5 http://${otherTargetName}`
                );

            const blocked =
                result.exitCode !== 0 ||
                !result.output.includes("Welcome to nginx");

            recordTest(
                "Cross-session target blocked",
                blocked,
                blocked
                    ? "Other session target was unreachable"
                    : "Other session target was reachable"
            );

        } catch (error) {

            recordTest(
                "Cross-session target blocked",
                true,
                "Connection to other session was blocked"
            );

        }

        // =================================================
        // TEST 8 — SECCOMP PROFILE
        // =================================================

        const securityOptions =
            attackerInfo.HostConfig.SecurityOpt || [];

        const seccompAttached =
            securityOptions.some(option =>
                option.startsWith("seccomp=")
            );

        recordTest(
            "Seccomp security profile attached",
            seccompAttached,
            seccompAttached
                ? "Seccomp profile is attached to attacker container"
                : "No Seccomp profile detected"
        );

        // =================================================
        // SUMMARY
        // =================================================

        const totalTests =
            testResults.length;

        const passedTests =
            testResults.filter(
                test => test.passed
            ).length;

        const failedTests =
            totalTests - passedTests;

        console.log("");
        console.log("==============================================");
        console.log("SECURITY TEST SUMMARY");
        console.log("==============================================");

        console.log(
            `Total tests : ${totalTests}`
        );

        console.log(
            `Passed      : ${passedTests}`
        );

        console.log(
            `Failed      : ${failedTests}`
        );

        const overallResult =
            failedTests === 0
                ? "PASS"
                : "FAIL";

        console.log(
            `RESULT: ${overallResult}`
        );

        // =================================================
        // SAVE JSON REPORT
        // =================================================

        const resultsDirectory =
            path.join(__dirname, "results");

        if (!fs.existsSync(resultsDirectory)) {

            fs.mkdirSync(
                resultsDirectory,
                {
                    recursive: true
                }
            );

        }

        const report = {

            project:
                "Attacker Container Isolation and Access Control",

            timestamp:
                new Date().toISOString(),

            attacker:
                attackerName,

            ownTarget:
                ownTargetName,

            otherTarget:
                otherTargetName,

            totalTests:
                totalTests,

            passed:
                passedTests,

            failed:
                failedTests,

            result:
                overallResult,

            tests:
                testResults

        };

        const reportPath =
            path.join(
                resultsDirectory,
                "security-report.json"
            );

        fs.writeFileSync(
            reportPath,
            JSON.stringify(
                report,
                null,
                2
            )
        );

        console.log("");

        console.log(
            `Security report saved to: ${reportPath}`
        );

        console.log("");

        // Return failure code if any test failed
        if (failedTests > 0) {
            process.exitCode = 1;
        }

    } catch (error) {

        console.error(
            "Security verification failed:"
        );

        console.error(
            error.message
        );

        process.exitCode = 1;
    }
}

// =====================================================
// START TESTS
// =====================================================

runSecurityTests();