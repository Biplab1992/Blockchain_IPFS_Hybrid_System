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

  const [cid, onChainHash, issuer, issuedAt, revoked, exists] =
    await contract.getCertificate(certId);

  console.log("certId   :", certId);
  console.log("cid      :", cid);
  console.log("issuer   :", issuer);
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

  const url = `http://localhost:5050/api/fetch/${cid}`;
  const resp = await axios.get(url, { responseType: "arraybuffer" });
  const fileBuf = Buffer.from(resp.data);

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
