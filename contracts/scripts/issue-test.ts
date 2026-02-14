// scripts/issue-test.ts
import { ethers } from "ethers";
import axios from "axios";
import crypto from "crypto";
import { readFileSync } from "fs";
import path from "path";

function sha256Hex(buf: Buffer) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function main() {
  // ====== SETTINGS ======
  const rpcUrl = "http://127.0.0.1:8545";
  const backendUrl = "http://localhost:5050";
  const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
  const certId = "CERT-004"; // change each run to avoid duplicate id issues
  const localFilePath = path.join(process.cwd(), "..", "test", "cert.bin"); 
  // If your cert.bin is elsewhere, adjust this path

  // ====== 1) Load file bytes and hash locally ======
  const fileBytes = readFileSync(localFilePath);
  const fileHashHex = sha256Hex(fileBytes); // no 0x prefix yet

  console.log("File:", localFilePath);
  console.log("Original size:", fileBytes.length, "bytes");
  console.log("Local SHA256:", fileHashHex);

  // ====== 2) Upload via backend -> Pinata (returns cid + fileHash) ======
  const form = new FormData();
  // Node 18+ has global FormData + Blob, but in some setups it doesn't.
  // So we do a simple axios multipart fallback:
  const multipart = await import("form-data");
  const fd = new multipart.default();
  fd.append("file", fileBytes, { filename: path.basename(localFilePath) });

  const pinRes = await axios.post(`${backendUrl}/api/pin`, fd, {
    headers: fd.getHeaders(),
    maxBodyLength: Infinity,
  });

  const cid: string = pinRes.data.cid;
  const backendHash: string = pinRes.data.fileHash;

  console.log("CID:", cid);
  console.log("Backend SHA256:", backendHash);

  // ====== 3) Connect to contract and issue ======
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = await provider.getSigner(0);

  const artifactPath = path.join(
    process.cwd(),
    "artifacts",
    "contracts",
    "CertificateRegistry.sol",
    "CertificateRegistry.json"
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));

  const contract = new ethers.Contract(contractAddress, artifact.abi, signer);

  // Store 0x-prefixed hash on-chain
  const onChainHash = ("0x" + backendHash) as `0x${string}`;

  const tx = await contract.issueCertificate(certId, cid, onChainHash);
  const receipt = await tx.wait();

  console.log("Issued certId:", certId);
  console.log("Tx hash:", receipt?.hash ?? tx.hash);
}

main().catch((e) => {
  console.error("❌ issue-test failed:", e);
  process.exit(1);
});
