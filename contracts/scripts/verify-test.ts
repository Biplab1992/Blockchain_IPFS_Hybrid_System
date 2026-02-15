import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";
import axios from "axios";
import crypto from "crypto";

function sha256Hex(buf: Buffer) {
  return "0x" + crypto.createHash("sha256").update(buf).digest("hex");
}

async function main() {
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const contract = await ethers.getContractAt("CertificateRegistry", contractAddress);

  const certId = "CERT-006";

  const [metadataCid, fileCidOnChain, onChainHash, issuer, version, replacesCertId, issuedAt, revoked, exists] =
    await contract.getCertificate(certId);

  console.log("certId   :", certId);
  console.log("metadata :", metadataCid);
  console.log("fileCid  :", fileCidOnChain);
  console.log("issuer   :", issuer);
  console.log("version  :", Number(version));
  console.log("replaces :", replacesCertId);
  console.log("issuedAt :", Number(issuedAt));
  console.log("revoked  :", revoked);
  console.log("exists   :", exists);

  if (!exists) {
    console.log("Certificate does not exist");
    return;
  }

  if (revoked) {
    console.log("Certificate is REVOKED");
    return;
  }

  const metadataUrl = `http://localhost:5050/api/fetch/${metadataCid}`;
  const metadataResp = await axios.get(metadataUrl, { responseType: "arraybuffer" });
  const metadataJson = JSON.parse(Buffer.from(metadataResp.data).toString("utf8")) as {
    fileCid?: string;
  };

  const fileCid = metadataJson.fileCid || fileCidOnChain;
  if (!fileCid) {
    throw new Error("No fileCid found in metadata or on-chain record");
  }

  const fileUrl = `http://localhost:5050/api/fetch/${fileCid}`;
  const fileResp = await axios.get(fileUrl, { responseType: "arraybuffer" });
  const fileBuf = Buffer.from(fileResp.data);

  const computedHash = sha256Hex(fileBuf);

  console.log("On-chain hash :", onChainHash);
  console.log("Computed hash:", computedHash);

  if (computedHash.toLowerCase() === onChainHash.toLowerCase()) {
    console.log("CERTIFICATE IS VALID");
  } else {
    console.log("CERTIFICATE IS INVALID / TAMPERED");
  }
}

main().catch((e) => {
  console.error("verify-test failed:", e);
  process.exit(1);
});
