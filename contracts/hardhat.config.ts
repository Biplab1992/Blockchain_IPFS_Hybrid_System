import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";

export default defineConfig({
  solidity: "0.8.20",
  plugins: [hardhatEthers],
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
    },
  },
});
