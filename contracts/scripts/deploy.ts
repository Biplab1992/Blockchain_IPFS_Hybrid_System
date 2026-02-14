// contracts/scripts/deploy.ts
import { ethers } from "ethers";
import { readFileSync } from "fs";
import path from "path";

async function main() {
  const rpcUrl = "http://127.0.0.1:8545";
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  // Hardhat node has unlocked accounts -> signer(0) works
  const signer = await provider.getSigner(0);

  // Adjust names if your contract/filename differs
  const artifactPath = path.join(
    process.cwd(),
    "artifacts",
    "contracts",
    "CertificateRegistry.sol",
    "CertificateRegistry.json"
  );

  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  const abi = artifact.abi;
  const bytecode = artifact.bytecode;

  const factory = new ethers.ContractFactory(abi, bytecode, signer);

  const contract = await factory.deploy();
  await contract.waitForDeployment();

  console.log("✅ CertificateRegistry deployed to:", await contract.getAddress());
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
