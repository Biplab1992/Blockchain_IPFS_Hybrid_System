import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const issuer = process.env.ISSUER_ADDRESS;
  if (!issuer) {
    throw new Error("Missing ISSUER_ADDRESS in env");
  }

  const allowed = (process.env.ALLOWED || "true").toLowerCase() === "true";
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const registry = await ethers.getContractAt("CertificateRegistry", contractAddress);

  console.log(`setIssuer(${issuer}, ${allowed}) on ${contractAddress}`);
  const tx = await registry.setIssuer(issuer, allowed);
  console.log("Tx sent:", tx.hash);

  const receipt = await tx.wait();
  console.log("Updated. Block:", receipt?.blockNumber);
}

main().catch((e) => {
  console.error("set-issuer failed:", e);
  process.exit(1);
});
