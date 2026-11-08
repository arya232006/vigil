// Deploys ThreatRegistry, records the deployment, and refreshes the ABI the backend loads.
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const Registry = await hre.ethers.getContractFactory("ThreatRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  const receipt = await registry.deploymentTransaction().wait();
  const { chainId } = await hre.ethers.provider.getNetwork();

  const record = {
    network: hre.network.name,
    chainId: Number(chainId),
    address,
    deployer: deployer.address,
    deployBlock: receipt.blockNumber,
    txHash: receipt.hash,
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${hre.network.name}.json`), JSON.stringify(record, null, 2) + "\n");

  const { abi } = await hre.artifacts.readArtifact("ThreatRegistry");
  const abiPath = path.join(__dirname, "..", "..", "backend", "app", "data", "ThreatRegistry.abi.json");
  fs.writeFileSync(abiPath, JSON.stringify(abi, null, 2) + "\n");

  console.log(`ThreatRegistry deployed on ${hre.network.name} (chain ${chainId})`);
  console.log(`\nSet these in .env:\nCHAIN_CONTRACT_ADDRESS=${address}\nCHAIN_DEPLOY_BLOCK=${receipt.blockNumber}`);
  console.log(`\nSet this in frontend/.env.local:\nNEXT_PUBLIC_CONTRACT_ADDRESS=${address}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
