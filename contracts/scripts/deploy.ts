import { network } from "hardhat";
import { saveDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();

  const factory = await ethers.getContractFactory("CertificateRegistry");
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log(`CertificateRegistry deployed to: ${address}`);

  saveDeployment(networkName, "CertificateRegistry", address);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
