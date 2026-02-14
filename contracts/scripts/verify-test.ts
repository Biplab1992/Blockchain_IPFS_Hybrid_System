import { ethers } from "ethers";
import axios from "axios";
import crypto from "crypto";
import { readFileSync } from "fs";
import path from "path";

function sha256Hex(buf: Buffer) {
  return "0x" + crypto.createHash("sha256").update(buf).digest("hex");
}

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

  // 1) Read on-chain data
  const result = await contract.getCertificate(certId);

  const cid: string = result[0];
  const onChainHash: string = result[1];
  const issuer: string = result[2];
  const issuedAt: bigint = result[3];
  const revoked: boolean = Boolean(result[4]);
  const exists: boolean = Boolean(result[5]);

  console.log("certId   :", certId);
  console.log("cid      :", cid);
  console.log("issuer   :", issuer);
  console.log("issuedAt :", issuedAt.toString());
  console.log("revoked  :", revoked);
  console.log("exists   :", exists);

  if (!exists) {
    console.log("❌ Certificate does not exist");
    return;
  }
  if (revoked) {
    console.log("❌ Certificate is revoked");
    return;
  }

  // 2) Fetch file bytes via backend (avoids public gateway blocking)
  const url = `http://localhost:5050/api/fetch/${cid}`;
  const response = await axios.get(url, {
    responseType: "arraybuffer",
    validateStatus: () => true, // we handle status manually
  });

  if (response.status !== 200) {
    // Try to print error text if any
    const text = Buffer.from(response.data).toString("utf8");
    console.log("❌ Backend fetch failed. HTTP:", response.status);
    console.log("Response:", text.slice(0, 300));
    return;
  }

  const fileBuffer = Buffer.from(response.data);

  // 3) Hash downloaded bytes
  const computedHash = sha256Hex(fileBuffer);

  // 4) Compare
  console.log("On-chain hash :", onChainHash);
  console.log("Computed hash:", computedHash);

  if (computedHash.toLowerCase() === onChainHash.toLowerCase()) {
    console.log("✅ CERTIFICATE IS VALID");
  } else {
    console.log("❌ CERTIFICATE IS INVALID / TAMPERED");
  }
}

main().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
