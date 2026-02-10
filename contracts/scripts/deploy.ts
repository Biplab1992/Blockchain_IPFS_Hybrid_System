import hre from "hardhat";

async function main() {
  const Contract = await hre.ethers.getContractFactory("CertificateRegistry");
  const deployed = await Contract.deploy();
  await deployed.waitForDeployment();

  console.log("Deployed to:", await deployed.getAddress());
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
