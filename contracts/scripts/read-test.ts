import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const contract = await ethers.getContractAt("CertificateRegistry", contractAddress);

  const certId = "CERT-006";
  let result;
  try {
    result = await contract.getCertificate(certId);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.toLowerCase().includes("certificate not found")) {
      console.log("Certificate does not exist:", certId);
      return;
    }
    throw e;
  }

  console.log("getCertificate(", certId, ") =>");
  console.log(result);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
