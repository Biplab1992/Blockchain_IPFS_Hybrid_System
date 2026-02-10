import { readFileSync } from "fs";
import path from "path";
import { ethers } from "ethers";

async function main() {
  // 1) RPC URL (your node is running on 8545)
  const rpcUrl = "http://127.0.0.1:8545";
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  // 2) Use account #0 private key from the Hardhat node terminal output
  //    Replace this with YOUR account #0 private key (keep it local)
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY as string;
  if (!privateKey) throw new Error("Missing DEPLOYER_PRIVATE_KEY in env");

  const wallet = new ethers.Wallet(privateKey, provider);

  // 3) Load ABI + bytecode from Hardhat artifacts
  //    Update the contract file name if yours differs
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

  // 4) Deploy
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  console.log("Deployed to:", await contract.getAddress());
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
