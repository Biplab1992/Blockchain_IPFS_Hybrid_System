// contracts/hardhat.config.ts
import { HardhatUserConfig } from "hardhat/config";

// This line is the key fix 👇 (it injects `ethers` into Hardhat runtime)
import "@nomicfoundation/hardhat-ethers";

const config: HardhatUserConfig = {
  solidity: "0.8.20",
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
  },
};

export default config;
