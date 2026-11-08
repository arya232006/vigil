import { Contract, JsonRpcProvider, sha256, toUtf8Bytes } from "ethers";

const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL;
const CONTRACT_ADDRESS = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS;

const ABI = [
  "function reports(uint256) view returns (address reporter, uint64 timestamp, bytes32 reportHash, bytes32 indicatorHash)",
];

export const browserVerifyAvailable = Boolean(RPC_URL && CONTRACT_ADDRESS);

/** Hashes the report text here and reads the commitment straight from the chain, without trusting our backend's verdict. */
export async function verifyInBrowser(registryId: number, canonical: string) {
  const computedHash = sha256(toUtf8Bytes(canonical));
  const contract = new Contract(CONTRACT_ADDRESS!, ABI, new JsonRpcProvider(RPC_URL));
  const record = await contract.reports(registryId);
  return { computedHash, onchainHash: record.reportHash as string, ok: computedHash === record.reportHash };
}
