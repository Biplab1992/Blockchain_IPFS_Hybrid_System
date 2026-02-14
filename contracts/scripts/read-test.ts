import { ethers } from "ethers";
import { readFileSync } from "fs";
import path from "path";

async function main() {
  const rpcUrl = "http://127.0.0.1:8545";
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

  const artifactPath = path.join(
    process.cwd(),
    "artifacts",
    "contracts",
    "CertificateRegistry.sol",
    "CertificateRegistry.json"
  );

  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  const contract = new ethers.Contract(contractAddress, artifact.abi, provider);

  const certId = "CERT-002";

  const result = await contract.getCertificate(certId);

  // result may be tuple/array-like depending on ABI
  console.log("getCertificate(", certId, ") =>");
  console.log(result);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
