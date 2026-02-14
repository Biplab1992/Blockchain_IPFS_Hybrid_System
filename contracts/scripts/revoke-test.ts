import { ethers } from "ethers";
import { readFileSync } from "fs";
import path from "path";

async function main() {
  // 1) RPC + signer (Hardhat node default)
  const rpcUrl = "http://127.0.0.1:8545";
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  // Hardhat node exposes accounts; signer(0) = first account (issuer)
  const signer = await provider.getSigner(0);

  // 2) Contract address (PUT YOUR LATEST DEPLOYED ADDRESS HERE)
  const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

  // 3) Load ABI from artifacts
  const artifactPath = path.join(
    process.cwd(),
    "artifacts",
    "contracts",
    "CertificateRegistry.sol",
    "CertificateRegistry.json"
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));

  // 4) Connect contract with signer (so we can send tx)
  const registry = new ethers.Contract(contractAddress, artifact.abi, signer);

  // 5) Choose certId to revoke
  const certId = "CERT-003";

  console.log(`Revoking: ${certId} on ${contractAddress}`);

  // 6) Send tx
  const tx = await registry.revokeCertificate(certId);
  console.log("Tx sent:", tx.hash);

  const receipt = await tx.wait();
  console.log("✅ Revoked. Block:", receipt.blockNumber);
}

main().catch((e) => {
  console.error("❌ revoke-test failed:", e);
  process.exit(1);
});
