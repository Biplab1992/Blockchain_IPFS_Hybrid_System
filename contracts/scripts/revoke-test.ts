import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const registry = await ethers.getContractAt("CertificateRegistry", contractAddress);

  const certId = "CERT-006";

  console.log(`Revoking: ${certId} on ${contractAddress}`);

  const tx = await registry.revokeCertificate(certId);
  console.log("Tx sent:", tx.hash);

  const receipt = await tx.wait();
  console.log("Revoked. Block:", receipt?.blockNumber);
}

main().catch((e) => {
  console.error("revoke-test failed:", e);
  process.exit(1);
});
