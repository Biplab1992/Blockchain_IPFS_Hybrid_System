import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const contract = await ethers.getContractAt("CertificateRegistry", contractAddress);

  const certId = "CERT-006";
  const result = await contract.getCertificate(certId);

  console.log("getCertificate(", certId, ") =>");
  console.log(result);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
