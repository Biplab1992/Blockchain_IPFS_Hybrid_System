import { expect } from "chai";
import { network } from "hardhat";
import { id, sha256 } from "ethers";

type MaybeError = {
  message?: string;
  shortMessage?: string;
};

function getErrorMessage(err: unknown): string {
  const e = err as MaybeError;
  return String(e?.shortMessage || e?.message || err || "");
}

async function expectRevert(fn: () => Promise<unknown>, reason: string): Promise<void> {
  try {
    await fn();
    expect.fail(`Expected revert with reason: ${reason}`);
  } catch (err: unknown) {
    expect(getErrorMessage(err).toLowerCase()).to.include(reason.toLowerCase());
  }
}

function buildHash(value: string): `0x${string}` {
  return sha256(new TextEncoder().encode(value)) as `0x${string}`;
}

describe("CertificateRegistry", function () {
  async function deployRegistry() {
    const { ethers } = await network.connect();
    const [owner, issuerA, issuerB, randomUser] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("CertificateRegistry");
    const registry = await factory.connect(owner).deploy();
    await registry.waitForDeployment();
    return { ethers, registry, owner, issuerA, issuerB, randomUser };
  }

  it("enforces onlyOwner for setIssuer", async function () {
    const { registry, owner, issuerA, randomUser } = await deployRegistry();

    await (await registry.connect(owner).setIssuer(issuerA.address, true)).wait();
    expect(await registry.authorizedIssuers(issuerA.address)).to.equal(true);

    await expectRevert(
      async () => {
        await (await registry.connect(randomUser).setIssuer(randomUser.address, true)).wait();
      },
      "Not owner"
    );
  });

  it("allows only authorized issuers to issue", async function () {
    const { registry, owner, issuerA, randomUser } = await deployRegistry();

    const certId = `CERT-ISSUE-AUTH-${Date.now()}`;
    const fileHash = buildHash("issue-auth");

    await expectRevert(
      async () => {
        await (
          await registry
            .connect(randomUser)
            .issueCertificate(certId, "bafy-metadata", "bafy-file", fileHash, 1, "")
        ).wait();
      },
      "Issuer not authorised"
    );

    await (await registry.connect(owner).setIssuer(issuerA.address, true)).wait();
    await (
      await registry
        .connect(issuerA)
        .issueCertificate(certId, "bafy-metadata", "bafy-file", fileHash, 1, "")
    ).wait();

    const cert = await registry.getCertificate(certId);
    expect(cert[8]).to.equal(true);
    expect(cert[3]).to.equal(issuerA.address);
    expect(cert[4]).to.equal(1n);
  });

  it("enforces revoke permissions at certificate level", async function () {
    const { registry, owner, issuerA, issuerB, randomUser } = await deployRegistry();
    const certId = `CERT-REVOKE-PERM-${Date.now()}`;
    const fileHash = buildHash("revoke-perm");

    await (await registry.connect(owner).setIssuer(issuerA.address, true)).wait();
    await (await registry.connect(owner).setIssuer(issuerB.address, true)).wait();
    await (
      await registry
        .connect(issuerA)
        .issueCertificate(certId, "bafy-metadata", "bafy-file", fileHash, 1, "")
    ).wait();

    await expectRevert(
      async () => {
        await (await registry.connect(randomUser).revokeCertificate(certId)).wait();
      },
      "Not certificate issuer or owner"
    );

    await expectRevert(
      async () => {
        await (await registry.connect(issuerB).revokeCertificate(certId)).wait();
      },
      "Not certificate issuer or owner"
    );

    await (await registry.connect(owner).revokeCertificate(certId)).wait();
    const cert = await registry.getCertificate(certId);
    expect(cert[7]).to.equal(true);
  });

  it("prevents double revocation", async function () {
    const { registry, owner, issuerA } = await deployRegistry();
    const certId = `CERT-DOUBLE-REVOKE-${Date.now()}`;
    const fileHash = buildHash("double-revoke");

    await (await registry.connect(owner).setIssuer(issuerA.address, true)).wait();
    await (
      await registry
        .connect(issuerA)
        .issueCertificate(certId, "bafy-metadata", "bafy-file", fileHash, 1, "")
    ).wait();
    await (await registry.connect(issuerA).revokeCertificate(certId)).wait();

    await expectRevert(
      async () => {
        await (await registry.connect(issuerA).revokeCertificate(certId)).wait();
      },
      "Certificate already revoked"
    );
  });

  it("enforces version and replacement rules", async function () {
    const { registry, owner, issuerA, issuerB } = await deployRegistry();
    const baseCertId = `CERT-VERSION-BASE-${Date.now()}`;
    const replacementCertId = `CERT-VERSION-REPL-${Date.now()}`;
    const crossIssuerReplacementId = `CERT-VERSION-X-${Date.now()}`;
    const fileHash = buildHash("version-base");
    const replacementHash = buildHash("version-replacement");

    await (await registry.connect(owner).setIssuer(issuerA.address, true)).wait();
    await (await registry.connect(owner).setIssuer(issuerB.address, true)).wait();

    await expectRevert(
      async () => {
        await (
          await registry
            .connect(issuerA)
            .issueCertificate(baseCertId, "bafy-metadata", "bafy-file", fileHash, 2, "")
        ).wait();
      },
      "new certificate must start at version 1"
    );

    await (
      await registry
        .connect(issuerA)
        .issueCertificate(baseCertId, "bafy-metadata", "bafy-file", fileHash, 1, "")
    ).wait();

    await expectRevert(
      async () => {
        await (
          await registry
            .connect(issuerA)
            .issueCertificate(
              `CERT-VERSION-INVALID-${Date.now()}`,
              "bafy-metadata",
              "bafy-file",
              replacementHash,
              1,
              baseCertId
            )
        ).wait();
      },
      "replacement version must be > 1"
    );

    await expectRevert(
      async () => {
        await (
          await registry
            .connect(issuerA)
            .issueCertificate(
              replacementCertId,
              "bafy-replacement",
              "bafy-replacement-file",
              replacementHash,
              2,
              baseCertId
            )
        ).wait();
      },
      "replaced certificate must be revoked"
    );

    await (await registry.connect(issuerA).revokeCertificate(baseCertId)).wait();

    await expectRevert(
      async () => {
        await (
          await registry
            .connect(issuerB)
            .issueCertificate(
              crossIssuerReplacementId,
              "bafy-replacement-other",
              "bafy-replacement-file-other",
              replacementHash,
              2,
              baseCertId
            )
        ).wait();
      },
      "Only original issuer can replace"
    );

    await (
      await registry
        .connect(issuerA)
        .issueCertificate(
          replacementCertId,
          "bafy-replacement",
          "bafy-replacement-file",
          replacementHash,
          2,
          baseCertId
        )
    ).wait();

    const replacementCert = await registry.getCertificate(replacementCertId);
    expect(replacementCert[4]).to.equal(2n);
    expect(replacementCert[5]).to.equal(baseCertId);
    expect(replacementCert[3]).to.equal(issuerA.address);
  });

  it("reverts getCertificate for unknown cert IDs", async function () {
    const { registry } = await deployRegistry();

    await expectRevert(
      async () => {
        await registry.getCertificate("CERT-DOES-NOT-EXIST");
      },
      "Certificate not found"
    );
  });

  it("emits correct events and event schema", async function () {
    const { registry, owner, issuerA } = await deployRegistry();
    const certId = `CERT-EVENT-${Date.now()}`;
    const metadataCid = "bafy-event-metadata";
    const fileCid = "bafy-event-file";
    const fileHash = buildHash("event-hash");

    await (await registry.connect(owner).setIssuer(issuerA.address, true)).wait();
    const issueTx = await registry
      .connect(issuerA)
      .issueCertificate(certId, metadataCid, fileCid, fileHash, 1, "");
    const issueReceipt = await issueTx.wait();
    if (!issueReceipt) {
      expect.fail("Issue tx did not return a receipt");
    }

    const issueEvent = issueReceipt.logs
      .map((log) => {
        try {
          return registry.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === "CertificateIssued");

    expect(issueEvent).to.not.equal(undefined);
    expect(issueEvent?.args[0]?.hash).to.equal(id(certId));
    expect(issueEvent?.args[1]).to.equal(metadataCid);
    expect(issueEvent?.args[2]).to.equal(issuerA.address);
    expect(issueEvent?.args[3]).to.equal(1n);
    expect(issueEvent?.args[4]).to.equal("");
    expect(Number(issueEvent?.args[5] ?? 0n)).to.be.greaterThan(0);

    const issueFragment = registry.interface.getEvent("CertificateIssued");
    expect(issueFragment?.inputs[1]?.name).to.equal("metadataCid");

    const revokeTx = await registry.connect(issuerA).revokeCertificate(certId);
    const revokeReceipt = await revokeTx.wait();
    if (!revokeReceipt) {
      expect.fail("Revoke tx did not return a receipt");
    }
    const revokeEvent = revokeReceipt.logs
      .map((log) => {
        try {
          return registry.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === "CertificateRevoked");

    expect(revokeEvent).to.not.equal(undefined);
    expect(revokeEvent?.args[0]?.hash).to.equal(id(certId));
    expect(revokeEvent?.args[1]).to.equal(issuerA.address);
    expect(Number(revokeEvent?.args[2] ?? 0n)).to.be.greaterThan(0);
  });
});
