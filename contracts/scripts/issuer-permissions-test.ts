import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();
  const addr = loadDeployment(networkName, "CertificateRegistry");

  const [owner, issuerCandidate, attacker] = await ethers.getSigners();
  const contract = await ethers.getContractAt("CertificateRegistry", addr);

  console.log("Contract:", addr);
  console.log("Owner:", owner.address);
  console.log("IssuerCandidate:", issuerCandidate.address);
  console.log("Attacker:", attacker.address);

  console.log("\n[1] Owner grants issuerCandidate...");
  const tx1 = await contract.connect(owner).setIssuer(issuerCandidate.address, true);
  await tx1.wait();
  console.log("Granted");

  console.log("\n[2] Attacker tries setIssuer (should fail)...");
  try {
    const tx2 = await contract.connect(attacker).setIssuer(attacker.address, true);
    await tx2.wait();
    console.log("Unexpected: attacker succeeded");
  } catch {
    console.log("Reverted");
  }

  console.log("\n[3] Owner removes issuerCandidate...");
  const tx3 = await contract.connect(owner).setIssuer(issuerCandidate.address, false);
  await tx3.wait();
  console.log("Removed");

  console.log("\nDone.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});