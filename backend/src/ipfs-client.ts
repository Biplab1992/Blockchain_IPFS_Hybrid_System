import axios from "axios";
import FormData from "form-data";
import crypto from "crypto";

export class GatewayFetchError extends Error {
  attempts: Array<{
    gateway: string;
    attempt: number;
    status: number | null;
    message: string;
  }>;

  constructor(
    cid: string,
    attempts: Array<{
      gateway: string;
      attempt: number;
      status: number | null;
      message: string;
    }>
  ) {
    super(`Gateway fetch failed for CID ${cid} after ${attempts.length} attempts`);
    this.attempts = attempts;
  }
}

const defaultIpfsGateways = [
  "https://ipfs.filebase.io",
  "https://gateway.pinata.cloud",
  "https://dweb.link",
];

const ipfsCidCache = new Map<string, { bytes: Buffer; expiresAtMs: number; gateway: string }>();

function getIpfsRuntimeConfig() {
  return {
    ipfsGateways: (process.env.IPFS_GATEWAYS || defaultIpfsGateways.join(","))
      .split(",")
      .map((gateway) => gateway.trim().replace(/\/+$/, ""))
      .filter(Boolean),
    ipfsFetchTimeoutMs: Number(process.env.IPFS_FETCH_TIMEOUT_MS || 8000),
    ipfsRetriesPerGateway: Math.max(0, Number(process.env.IPFS_RETRIES_PER_GATEWAY || 1)),
    ipfsCacheTtlMs: Number(process.env.IPFS_CACHE_TTL_MS || 10 * 60 * 1000),
    ipfsCacheMaxEntries: Math.max(1, Number(process.env.IPFS_CACHE_MAX_ENTRIES || 500)),
  };
}

export function sha256Hex(buffer: Buffer): string {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

export function sha256Hex0x(buffer: Buffer): string {
  return `0x${sha256Hex(buffer)}`;
}

export async function fetchCidBytes(cid: string): Promise<Buffer> {
  const { ipfsGateways, ipfsFetchTimeoutMs, ipfsRetriesPerGateway, ipfsCacheTtlMs, ipfsCacheMaxEntries } = getIpfsRuntimeConfig();
  const cached = ipfsCidCache.get(cid);
  if (cached && cached.expiresAtMs > Date.now()) {
    return cached.bytes;
  }
  if (cached) {
    ipfsCidCache.delete(cid);
  }

  const attempts: Array<{
    gateway: string;
    attempt: number;
    status: number | null;
    message: string;
  }> = [];

  for (const gateway of ipfsGateways) {
    for (let attempt = 1; attempt <= ipfsRetriesPerGateway + 1; attempt += 1) {
      const url = `${gateway}/ipfs/${cid}`;

      try {
        const response = await axios.get(url, {
          responseType: "arraybuffer",
          maxBodyLength: Infinity,
          timeout: ipfsFetchTimeoutMs,
          validateStatus: () => true,
        });

        if (response.status === 200) {
          const bytes = Buffer.from(response.data);
          if (ipfsCidCache.size >= ipfsCacheMaxEntries) {
            const oldestKey = ipfsCidCache.keys().next().value;
            if (oldestKey) ipfsCidCache.delete(oldestKey);
          }
          ipfsCidCache.set(cid, {
            bytes,
            expiresAtMs: Date.now() + ipfsCacheTtlMs,
            gateway,
          });
          return bytes;
        }

        const preview = Buffer.from(response.data).toString("utf8").slice(0, 200);
        attempts.push({
          gateway,
          attempt,
          status: response.status,
          message: preview || `HTTP ${response.status}`,
        });
      } catch (err: any) {
        attempts.push({
          gateway,
          attempt,
          status: null,
          message: err?.code ? `${err.code}: ${err.message}` : err?.message || String(err),
        });
      }
    }
  }

  throw new GatewayFetchError(cid, attempts);
}

export async function pinBufferToIpfs(
  buffer: Buffer,
  filename: string,
  jwt: string,
  metadataName?: string
): Promise<string> {
  const url = "https://api.pinata.cloud/pinning/pinFileToIPFS";
  const form = new FormData();
  form.append("file", buffer, { filename });

  if (metadataName) {
    form.append("pinataMetadata", JSON.stringify({ name: metadataName }));
  }

  const pinataRes = await axios.post(url, form, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      ...form.getHeaders(),
    },
    maxBodyLength: Infinity,
  });

  const cid = pinataRes.data?.IpfsHash;
  if (!cid) {
    throw new Error("Pinata response missing IpfsHash");
  }

  return cid;
}

export async function pinJsonToIpfs(obj: unknown, jwt: string, filename: string): Promise<string> {
  const bytes = Buffer.from(JSON.stringify(obj), "utf8");
  return pinBufferToIpfs(bytes, filename, jwt, filename);
}

export async function fetchCidJson<T>(cid: string): Promise<T> {
  const bytes = await fetchCidBytes(cid);
  const jsonText = bytes.toString("utf8");
  try {
    return JSON.parse(jsonText) as T;
  } catch {
    throw new Error(`CID ${cid} did not contain valid JSON`);
  }
}
