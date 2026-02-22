import { network } from "hardhat";
import { sha256 } from "ethers";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();
  const addr = loadDeployment(networkName, "CertificateRegistry");

  const [owner, issuer, otherIssuer, randomUser] = await ethers.getSigners();
  const reg = await ethers.getContractAt("CertificateRegistry", addr);

  const certId = `CERT-REVOKE-TEST-${Date.now()}`;
  const metadataCid = "bafyrevokefakecidmetadata";
  const fileCid = "bafyfakecid";
  const fileHash = sha256(ethers.toUtf8Bytes("dummy")) as `0x${string}`;

  await (await reg.connect(owner).setIssuer(issuer.address, true)).wait();
  await (await reg.connect(owner).setIssuer(otherIssuer.address, true)).wait();

  await (
    await reg.connect(issuer).issueCertificate(certId, metadataCid, fileCid, fileHash, 1, "")
  ).wait();
  console.log("Issued");

  console.log("\n[1] randomUser tries revoke (should fail)...");
  try {
    await (await reg.connect(randomUser).revokeCertificate(certId)).wait();
    console.log("Unexpected: randomUser revoked");
  } catch {
    console.log("Reverted");
  }

  console.log("\n[2] other authorized issuer tries revoke (should fail)...");
  try {
    await (await reg.connect(otherIssuer).revokeCertificate(certId)).wait();
    console.log("Unexpected: other authorized issuer revoked");
  } catch {
    console.log("Reverted");
  }

  console.log("\n[3] issuer revokes (should succeed)...");
  await (await reg.connect(issuer).revokeCertificate(certId)).wait();
  console.log("Revoked");

  console.log("\n[4] issuer tries to revoke again (should fail)...");
  try {
    await (await reg.connect(issuer).revokeCertificate(certId)).wait();
    console.log("Unexpected: double revoke succeeded");
  } catch {
    console.log("Reverted");
  }

  const cert = await reg.getCertificate(certId);
  console.log("\ngetCertificate:", cert);

  console.log("\nDone.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
