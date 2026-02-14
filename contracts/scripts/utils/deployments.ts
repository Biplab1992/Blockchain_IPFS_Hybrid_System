// contracts/scripts/utils/deployments.ts
import fs from "fs";
import path from "path";

type Deployments = Record<string, { CertificateRegistry?: string }>;

function deploymentsPath() {
  return path.join(process.cwd(), "deployments.json");
}

export function saveDeployment(networkName: string, contractName: "CertificateRegistry", address: string) {
  const file = deploymentsPath();
  const current: Deployments = fs.existsSync(file)
    ? JSON.parse(fs.readFileSync(file, "utf8"))
    : {};

  current[networkName] = current[networkName] || {};
  current[networkName][contractName] = address;

  fs.writeFileSync(file, JSON.stringify(current, null, 2));
  console.log(`✅ Saved ${contractName} for ${networkName}: ${address}`);
}

export function loadDeployment(networkName: string, contractName: "CertificateRegistry"): string {
  const file = deploymentsPath();
  if (!fs.existsSync(file)) {
    throw new Error(`deployments.json not found. Run deploy.ts first.`);
  }
  const current: Deployments = JSON.parse(fs.readFileSync(file, "utf8"));
  const addr = current?.[networkName]?.[contractName];
  if (!addr) {
    throw new Error(`No deployment for ${contractName} on network "${networkName}". Run deploy.ts again.`);
  }
  return addr;
}
