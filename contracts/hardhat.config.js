require("@nomicfoundation/hardhat-toolbox");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const { SEPOLIA_RPC_URL, SEPOLIA_PRIVATE_KEY, ETHERSCAN_API_KEY } = process.env;

module.exports = {
  solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } },
  networks: {
    ...(SEPOLIA_RPC_URL && SEPOLIA_PRIVATE_KEY
      ? { sepolia: { url: SEPOLIA_RPC_URL, accounts: [SEPOLIA_PRIVATE_KEY], chainId: 11155111 } }
      : {}),
  },
  etherscan: { apiKey: ETHERSCAN_API_KEY || "" },
};
