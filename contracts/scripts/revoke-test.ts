import { ethers } from "ethers";
import { readFileSync } from "fs";
import path from "path";

async function main() {
  const rpcUrl = "http://127.0.0.1:8545";
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const privateKey = process.env.DEPLOYER_PRIVATE_KEY as string;
  if (!privateKey) throw new Error("Missing DEPLOYER_PRIVATE_KEY");

  const wallet = new ethers.Wallet(privateKey, provider);

  const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

  const artifactPath = path.join(
    process.cwd(),
    "artifacts",
    "contracts",
    "CertificateRegistry.sol",
    "CertificateRegistry.json"
  );

  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  const contract = new ethers.Contract(contractAddress, artifact.abi, wallet);

  const certId = "CERT-001";

  const tx = await contract.revokeCertificate(certId);
  const receipt = await tx.wait();

  console.log("Revoked certId:", certId);
  console.log("Tx hash:", receipt.hash);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
