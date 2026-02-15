import { network } from "hardhat";
import { sha256 } from "ethers";
import { loadDeployment } from "./utils/deployments";

async function main() {
  const { ethers, networkName } = await network.connect();
  const addr = loadDeployment(networkName, "CertificateRegistry");

  const [owner, issuer, randomUser] = await ethers.getSigners();
  const reg = await ethers.getContractAt("CertificateRegistry", addr);

  const certId = `CERT-AUTH-TEST-${Date.now()}`;
  const metadataCid = "bafyauthmetadatafakecid";
  const fileCid = "bafybeigdyrztwfakecid";
  const fileBytes = ethers.toUtf8Bytes("dummy-file-content");
  const fileHashBytes32 = sha256(fileBytes) as `0x${string}`;

  console.log("Contract:", addr);
  console.log("certId:", certId);
  console.log("fileHash:", fileHashBytes32);

  console.log("\n[0] Owner authorizes issuer...");
  await (await reg.connect(owner).setIssuer(issuer.address, true)).wait();
  console.log("Issuer authorized");

  console.log("\n[1] randomUser tries issueCertificate (should fail)...");
  try {
    await (
      await reg
        .connect(randomUser)
        .issueCertificate(certId, metadataCid, fileCid, fileHashBytes32, 1, "")
    ).wait();
    console.log("Unexpected: randomUser succeeded");
  } catch {
    console.log("Reverted");
  }

  console.log("\n[2] issuer issues certificate (should succeed)...");
  await (
    await reg.connect(issuer).issueCertificate(certId, metadataCid, fileCid, fileHashBytes32, 1, "")
  ).wait();
  console.log("Issued");

  console.log("\n[3] Read back getCertificate...");
  const cert = await reg.getCertificate(certId);
  console.log(cert);

  console.log("\nDone.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
