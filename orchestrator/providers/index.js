const DockerProvider = require("./docker-provider");
const KubernetesProvider = require("./k8s-provider");

const SUPPORTED_PROVIDERS = ["docker", "kubernetes"];

function getProviderName() {
    const raw = (process.env.ORCHESTRATOR_PROVIDER || "docker").toLowerCase().trim();
    if (SUPPORTED_PROVIDERS.includes(raw)) {
        return raw;
    }
    console.warn(`[ORCHESTRATOR] Unknown provider "${raw}", falling back safely to "docker".`);
    return "docker";
}

let activeProviderInstance = null;
let dockerInstance = null;
let k8sInstance = null;

function getDockerProvider() {
    if (!dockerInstance) {
        dockerInstance = new DockerProvider();
    }
    return dockerInstance;
}

function getKubernetesProvider() {
    if (!k8sInstance) {
        k8sInstance = new KubernetesProvider();
    }
    return k8sInstance;
}

function getActiveProvider() {
    const providerName = getProviderName();
    if (providerName === "kubernetes") {
        return getKubernetesProvider();
    }
    return getDockerProvider();
}

module.exports = {
    SUPPORTED_PROVIDERS,
    getProviderName,
    getActiveProvider,
    getDockerProvider,
    getKubernetesProvider
};
