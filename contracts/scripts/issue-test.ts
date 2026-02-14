import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";
import axios from "axios";
import crypto from "crypto";
import { readFileSync } from "fs";
import path from "path";

function sha256Hex(buf: Buffer) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function main() {
  const backendUrl = "http://localhost:5050";
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const contract = await ethers.getContractAt("CertificateRegistry", contractAddress);
  const certId = "CERT-006";
  const localFilePath = path.join(process.cwd(), "..", "test", "cert.bin");

  const fileBytes = readFileSync(localFilePath);
  const fileHashHex = sha256Hex(fileBytes);

  console.log("File:", localFilePath);
  console.log("Original size:", fileBytes.length, "bytes");
  console.log("Local SHA256:", fileHashHex);

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

  const onChainHash = ("0x" + backendHash) as `0x${string}`;
  const tx = await contract.issueCertificate(certId, cid, onChainHash);
  const receipt = await tx.wait();

  console.log("Issued certId:", certId);
  console.log("Tx hash:", receipt?.hash ?? tx.hash);
}

main().catch((e) => {
  console.error("issue-test failed:", e);
  process.exit(1);
});
