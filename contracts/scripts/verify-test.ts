import { network } from "hardhat";
import { loadDeployment } from "./utils/deployments";
import axios from "axios";

async function main() {
  const { ethers, networkName } = await network.connect();

  const contractAddress = loadDeployment(networkName, "CertificateRegistry");
  const contract = await ethers.getContractAt("CertificateRegistry", contractAddress);

  const certId = "CERT-006";

  let metadataCid: string;
  let fileCidOnChain: string;
  let onChainHash: string;
  let issuer: string;
  let version: bigint;
  let replacesCertId: string;
  let issuedAt: bigint;
  let revoked: boolean;
  try {
    [metadataCid, fileCidOnChain, onChainHash, issuer, version, replacesCertId, issuedAt, revoked] =
      await contract.getCertificate(certId);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.toLowerCase().includes("certificate not found")) {
      console.log("Certificate does not exist");
      return;
    }
    throw e;
  }

  console.log("certId   :", certId);
  console.log("metadata :", metadataCid);
  console.log("fileCid  :", fileCidOnChain);
  console.log("issuer   :", issuer);
  console.log("version  :", Number(version));
  console.log("replaces :", replacesCertId);
  console.log("issuedAt :", Number(issuedAt));
  console.log("revoked  :", revoked);
  if (revoked) {
    console.log("Certificate is REVOKED");
    return;
  }

  const verifyResp = await axios.get(`http://localhost:5050/api/verify/${encodeURIComponent(certId)}`);
  const verify = verifyResp.data as {
    status: string;
    onChainHash: string;
    computedHash: string;
    integrityMatch: boolean;
    storageMode?: string;
    encryptionAlg?: string;
  };

  console.log("storage  :", verify.storageMode || "unknown");
  console.log("alg      :", verify.encryptionAlg || "unknown");
  console.log("On-chain hash :", verify.onChainHash);
  console.log("Computed hash:", verify.computedHash);

  if (verify.integrityMatch && String(verify.status).toUpperCase() === "VALID") {
    console.log("CERTIFICATE IS VALID");
  } else {
    console.log("CERTIFICATE IS INVALID / TAMPERED");
  }
}

main().catch((e) => {
  console.error("verify-test failed:", e);
  process.exit(1);
});
