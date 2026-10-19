const { spawn } = require("child_process");
const path = require("path");
const DockerProvider = require("../providers/docker-provider");

async function main() {
    const provider = new DockerProvider();
    const id1 = `d1${Date.now().toString().slice(-6)}`;
    const id2 = `d2${Date.now().toString().slice(-6)}`;

    console.log(`[DOCKER TEST RUNNER] Provisioning ephemeral sessions ${id1} and ${id2}...`);
    let s1, s2;

    try {
        s1 = await provider.createSession(id1);
        s2 = await provider.createSession(id2);

        const attackerName = s1.attacker;
        const ownTargetName = s1.target;
        const otherTargetName = s2.target;

        console.log(`[DOCKER TEST RUNNER] Running verify-security.js ${attackerName} ${ownTargetName} ${otherTargetName}...`);

        const verifyScript = path.join(__dirname, "verify-security.js");
        const proc = spawn("node", [verifyScript, attackerName, ownTargetName, otherTargetName], {
            stdio: "inherit"
        });

        await new Promise((resolve, reject) => {
            proc.on("close", code => {
                if (code === 0) resolve();
                else reject(new Error(`verify-security.js exited with code ${code}`));
            });
            proc.on("error", reject);
        });

    } finally {
        console.log("[DOCKER TEST RUNNER] Tearing down ephemeral Docker sessions...");
        if (s1) {
            try { await provider.deleteSession(id1); } catch (e) {}
        }
        if (s2) {
            try { await provider.deleteSession(id2); } catch (e) {}
        }
        console.log("[DOCKER TEST RUNNER] Cleanup complete.");
    }
}

if (require.main === module) {
    main().catch(err => {
        console.error("Docker test run failed:", err.message);
        process.exit(1);
    });
}

module.exports = { main };
