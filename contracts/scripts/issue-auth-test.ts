import { network } from "hardhat";
import { sha256 } from "ethers";
import { loadDeployment } from "./utils/deployments";

// This script tests the authorization logic for issuing certificates.
async function main() {
  const { ethers, networkName } = await network.connect();
  const addr = loadDeployment(networkName, "CertificateRegistry");

  const [owner, issuer, otherIssuer, randomUser] = await ethers.getSigners();
  const reg = await ethers.getContractAt("CertificateRegistry", addr);

  const certId = `CERT-AUTH-TEST-${Date.now()}`;
  const metadataCid = "bafyauthmetadatafakecid";
  const fileCid = "bafybeigdyrztwfakecid";
  const fileBytes = ethers.toUtf8Bytes("dummy-file-content");
  const fileHashBytes32 = sha256(fileBytes) as `0x${string}`;
  const replacementCertId = `CERT-AUTH-TEST-REPL-${Date.now()}`;
  const replacementHash = sha256(ethers.toUtf8Bytes("dummy-replacement-content")) as `0x${string}`;
  const crossIssuerReplacementCertId = `CERT-AUTH-TEST-REPL-X-${Date.now()}`;

  console.log("Contract:", addr);
  console.log("certId:", certId);
  console.log("fileHash:", fileHashBytes32);

  console.log("\n[0] Owner authorizes issuers...");
  await (await reg.connect(owner).setIssuer(issuer.address, true)).wait();
  await (await reg.connect(owner).setIssuer(otherIssuer.address, true)).wait();
  console.log("Issuers authorized");

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

  console.log("\n[3] issuer revokes original certificate (should succeed)...");
  await (await reg.connect(issuer).revokeCertificate(certId)).wait();
  console.log("Revoked");

  console.log("\n[4] same issuer issues replacement (should succeed)...");
  await (
    await reg
      .connect(issuer)
      .issueCertificate(
        replacementCertId,
        "bafyreplacementmetadatafakecid",
        "bafyreplacementfilefakecid",
        replacementHash,
        2,
        certId
      )
  ).wait();
  console.log("Replacement issued by original issuer");

  console.log("\n[5] other authorized issuer tries replacement of same cert (should fail)...");
  try {
    await (
      await reg
        .connect(otherIssuer)
        .issueCertificate(
          crossIssuerReplacementCertId,
          "bafyxissuerreplacementmetadata",
          "bafyxissuerreplacementfile",
          replacementHash,
          2,
          certId
        )
    ).wait();
    console.log("Unexpected: cross-issuer replacement succeeded");
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("Only original issuer can replace")) {
      console.log("Reverted with expected reason");
    } else {
      console.log("Reverted (unexpected reason):", msg);
    }
  }

  console.log("\n[6] Read back getCertificate...");
  const cert = await reg.getCertificate(certId);
  console.log(cert);

  console.log("\nDone.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
