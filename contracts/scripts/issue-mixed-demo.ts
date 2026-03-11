import hre from "hardhat";

async function main() {
  const { ethers } = hre;

  const contractAddress = process.env.CERTIFICATE_REGISTRY_ADDRESS as string;
  if (!contractAddress) {
    throw new Error("CERTIFICATE_REGISTRY_ADDRESS is not set");
  }

  const certId = "demo-cert-034";
  const metadataCid = "QmZJQuYhz9fkffKwLRZbU3jMQaAZjqBP63NZ317LQtmEtF";
  const fileCid = "Qme24XohCVieANjDVX7LNMCw4FDNybXXjzRGeG6MQJ3nS6";
  const fileHash = "0x3fa02b4b7faaf21b9b0cebd5f8a39e2811870165ed16b66471b19160e552fa9d";
  const version = 1;
  const replacesCertId = "";

  const registry = await ethers.getContractAt("CertificateRegistry", contractAddress);
  const tx = await registry.issueCertificate(
    certId,
    metadataCid,
    fileCid,
    fileHash,
    version,
    replacesCertId
  );

  console.log("tx sent:", tx.hash);
  const receipt = await tx.wait();
  console.log("mined:", receipt?.hash);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
