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

  // ✅ put your latest deployed address here
  const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

  const artifactPath = path.join(
    process.cwd(),
    "artifacts",
    "contracts",
    "CertificateRegistry.sol",
    "CertificateRegistry.json"
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));

  const contract = new ethers.Contract(contractAddress, artifact.abi, provider);

  // ✅ verify this cert
  const certId = "CERT-004";

  const [cid, onChainHash, issuer, issuedAt, revoked, exists] =
    await contract.getCertificate(certId);

  console.log("certId   :", certId);
  console.log("cid      :", cid);
  console.log("issuer   :", issuer);
  console.log("issuedAt :", Number(issuedAt));
  console.log("revoked  :", revoked);
  console.log("exists   :", exists);

  if (!exists) {
    console.log("❌ Certificate does not exist");
    return;
  }

  if (revoked) {
    console.log("❌ Certificate is REVOKED");
    return;
  }

  // Fetch bytes via your backend (make sure backend is running)
  const url = `http://localhost:5050/api/fetch/${cid}`;
  const resp = await axios.get(url, { responseType: "arraybuffer" });
  const fileBuf = Buffer.from(resp.data);

  const computedHash = sha256Hex(fileBuf);

  console.log("On-chain hash :", onChainHash);
  console.log("Computed hash:", computedHash);

  if (computedHash.toLowerCase() === onChainHash.toLowerCase()) {
    console.log("✅ CERTIFICATE IS VALID");
  } else {
    console.log("❌ CERTIFICATE IS INVALID / TAMPERED");
  }
}

main().catch((e) => {
  console.error("❌ verify-test failed:", e);
  process.exit(1);
});
