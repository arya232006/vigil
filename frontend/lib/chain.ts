import { Contract, JsonRpcProvider, sha256, toUtf8Bytes } from "ethers";

const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL;
const CONTRACT_ADDRESS = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS;
// Anyone can write to the registry, so a matching hash only counts if this address wrote it.
const TRUSTED_REPORTER = process.env.NEXT_PUBLIC_TRUSTED_REPORTER?.toLowerCase();

const ABI = [
  "function reports(uint256) view returns (address reporter, uint64 timestamp, bytes32 reportHash, bytes32 indicatorHash)",
];

export const browserVerifyAvailable = Boolean(RPC_URL && CONTRACT_ADDRESS && TRUSTED_REPORTER);

/** Hashes the report text here and reads the commitment straight from the chain, without trusting our backend's verdict. */
export async function verifyInBrowser(registryId: number, canonical: string) {
  const computedHash = sha256(toUtf8Bytes(canonical));
  const contract = new Contract(CONTRACT_ADDRESS!, ABI, new JsonRpcProvider(RPC_URL));
  const record = await contract.reports(registryId);
  const reporterOk = (record.reporter as string).toLowerCase() === TRUSTED_REPORTER;
  return { computedHash, onchainHash: record.reportHash as string, reporterOk, ok: reporterOk && computedHash === record.reportHash };
}
