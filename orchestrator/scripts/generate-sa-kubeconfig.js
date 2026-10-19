const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function generateLeastPrivilegeKubeconfig() {
    const namespace = "attacker-lab";
    const serviceAccount = "attacker-orchestrator-sa";
    const targetFile = path.join(__dirname, "..", "..", "kubernetes", "orchestrator-kubeconfig.yaml");

    console.log(`Generating least-privilege kubeconfig for ${serviceAccount} in namespace ${namespace}...`);

    // 1. Get cluster info from current context
    const clusterRaw = execSync("kubectl config view --raw --minify -o json", { encoding: "utf8" });
    const clusterConfig = JSON.parse(clusterRaw);

    const cluster = clusterConfig.clusters && clusterConfig.clusters[0];
    if (!cluster) {
        throw new Error("No active cluster found in kubectl configuration");
    }

    const serverUrl = cluster.cluster.server;
    const caData = cluster.cluster["certificate-authority-data"];

    // 2. Request a ServiceAccount token
    const token = execSync(`kubectl create token ${serviceAccount} -n ${namespace} --duration=720h`, {
        encoding: "utf8"
    }).trim();

    // 3. Construct dedicated least-privilege kubeconfig
    const kubeconfigYaml = `apiVersion: v1
kind: Config
clusters:
  - name: attacker-lab-cluster
    cluster:
      server: ${serverUrl}
      certificate-authority-data: ${caData}
contexts:
  - name: attacker-orchestrator-context
    context:
      cluster: attacker-lab-cluster
      namespace: ${namespace}
      user: ${serviceAccount}
current-context: attacker-orchestrator-context
users:
  - name: ${serviceAccount}
    user:
      token: ${token}
`;

    fs.writeFileSync(targetFile, kubeconfigYaml, "utf8");
    console.log(`Least-privilege kubeconfig written to: ${targetFile}`);
    return targetFile;
}

if (require.main === module) {
    try {
        generateLeastPrivilegeKubeconfig();
    } catch (err) {
        console.error("Failed to generate SA kubeconfig:", err.message);
        process.exit(1);
    }
}

module.exports = { generateLeastPrivilegeKubeconfig };
