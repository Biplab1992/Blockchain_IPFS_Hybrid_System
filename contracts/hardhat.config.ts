import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatVerify from "@nomicfoundation/hardhat-verify";
import fs from "fs";
import path from "path";

function parseDotEnv(filePath: string): Record<string, string> {
  if (!fs.existsSync(filePath)) return {};

  const raw = fs.readFileSync(filePath, "utf8");
  const out: Record<string, string> = {};

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;

    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key) out[key] = value;
  }

  return out;
}

const repoRoot = path.resolve(process.cwd(), "..");
const contractsEnv = parseDotEnv(path.join(process.cwd(), ".env"));
const backendEnv = parseDotEnv(path.join(repoRoot, "backend", ".env"));
const mergedEnv = {
  ...backendEnv,
  ...contractsEnv,
  ...process.env,
};

const sepoliaRpcUrl = mergedEnv.SEPOLIA_RPC_URL || mergedEnv.RPC_URL;
const deployerPrivateKey = mergedEnv.DEPLOYER_PRIVATE_KEY;
const etherscanApiKey = mergedEnv.ETHERSCAN_API_KEY;

export default defineConfig({
  solidity: "0.8.20",
  plugins: [hardhatEthers, hardhatVerify],
  networks: {
    localhost: {
      type: "http",
      url: "http://127.0.0.1:8545",
    },
    ...(sepoliaRpcUrl && deployerPrivateKey
      ? {
          sepolia: {
            type: "http",
            url: sepoliaRpcUrl,
            accounts: [deployerPrivateKey],
          },
        }
      : {}),
  },
  verify: {
    etherscan: {
      apiKey: etherscanApiKey || "",
    },
  },
});
