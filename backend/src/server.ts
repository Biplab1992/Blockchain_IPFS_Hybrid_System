// backend/src/server.ts
import express from "express";
import cors from "cors";
import multer from "multer";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";
import FormData from "form-data";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import { Contract, JsonRpcProvider, Wallet, getAddress, verifyMessage, type EventLog } from "ethers";

dotenv.config();

// Safe JWT fingerprint (helps confirm backend loaded the right .env)
const loadedJwt = process.env.PINATA_JWT || "";
console.log(
  "PINATA_JWT loaded:",
  loadedJwt ? `${loadedJwt.slice(0, 12)}...${loadedJwt.slice(-6)}` : "(missing)"
);

const app = express();
const corsOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000,http://localhost:5173")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (corsOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || "1mb" }));
app.use(express.urlencoded({ extended: false, limit: process.env.FORM_BODY_LIMIT || "1mb" }));

const pinRateLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_PIN_WINDOW_MS || 60_000),
  max: Number(process.env.RATE_LIMIT_PIN_MAX || 10),
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyRateLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_VERIFY_WINDOW_MS || 60_000),
  max: Number(process.env.RATE_LIMIT_VERIFY_MAX || 60),
  standardHeaders: true,
  legacyHeaders: false,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: Number(process.env.MAX_UPLOAD_BYTES || 10 * 1024 * 1024),
  },
  fileFilter: (_req, file, cb) => {
    const isPdfMime = file.mimetype === "application/pdf";
    const isPdfExt = file.originalname.toLowerCase().endsWith(".pdf");
    if (!isPdfMime || !isPdfExt) {
      cb(new Error("Only PDF uploads are allowed"));
      return;
    }
    cb(null, true);
  },
});

function sha256Hex(buffer: Buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function sha256Hex0x(buffer: Buffer) {
  return `0x${sha256Hex(buffer)}`;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const workspaceRoot = path.resolve(__dirname, "..", "..");

const CERTIFICATE_REGISTRY_ABI = [
  "function getCertificate(string certId) view returns (string metadataCid, string fileCid, bytes32 fileHash, address issuer, uint256 version, string replacesCertId, uint256 issuedAt, bool revoked, bool exists)",
  "function issueCertificate(string certId, string metadataCid, string fileCid, bytes32 fileHash, uint256 version, string replacesCertId)",
  "function revokeCertificate(string certId)",
  "function authorizedIssuers(address issuer) view returns (bool)",
  "event CertificateIssued(string indexed certId, string cid, address indexed issuer, uint256 issuedAt)",
  "event CertificateRevoked(string indexed certId, address indexed issuer, uint256 revokedAt)",
];

type CertificateIndexEntry = {
  certId: string;
  cid: string;
  issuer: string;
  version: number;
  replacesCertId: string;
  issuedAt: number;
  revoked: boolean;
  revokedAt: number | null;
  issueTxHash: string;
  revokeTxHash: string | null;
  issueBlockNumber: number;
  revokeBlockNumber: number | null;
};

const certificateIndexCache = new Map<string, CertificateIndexEntry>();
const certificateIndexRefreshMs = Number(process.env.CERT_INDEX_REFRESH_MS || 15000);
let certificateIndexLastUpdatedAtMs = 0;
let certificateIndexRebuildPromise: Promise<void> | null = null;

class GatewayFetchError extends Error {
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
  "https://ipfs.io",
  "https://gateway.pinata.cloud",
  "https://cloudflare-ipfs.com",
];

const ipfsGateways = (process.env.IPFS_GATEWAYS || defaultIpfsGateways.join(","))
  .split(",")
  .map((g) => g.trim().replace(/\/+$/, ""))
  .filter(Boolean);
const ipfsFetchTimeoutMs = Number(process.env.IPFS_FETCH_TIMEOUT_MS || 8000);
const ipfsRetriesPerGateway = Math.max(0, Number(process.env.IPFS_RETRIES_PER_GATEWAY || 1));
const ipfsCacheTtlMs = Number(process.env.IPFS_CACHE_TTL_MS || 10 * 60 * 1000);
const ipfsCacheMaxEntries = Math.max(1, Number(process.env.IPFS_CACHE_MAX_ENTRIES || 500));
const ipfsCidCache = new Map<string, { bytes: Buffer; expiresAtMs: number; gateway: string }>();

function loadDeploymentAddress(): string {
  const explicitAddress = process.env.CERTIFICATE_REGISTRY_ADDRESS;
  if (explicitAddress) return explicitAddress;

  const networkName = process.env.CONTRACT_NETWORK_NAME || "localhost";
  const deploymentsFile = path.join(workspaceRoot, "contracts", "deployments.json");

  if (!fs.existsSync(deploymentsFile)) {
    throw new Error("Missing contracts/deployments.json and CERTIFICATE_REGISTRY_ADDRESS is not set");
  }

  const deployments = JSON.parse(fs.readFileSync(deploymentsFile, "utf8")) as Record<
    string,
    { CertificateRegistry?: string }
  >;
  const address = deployments?.[networkName]?.CertificateRegistry;

  if (!address) {
    throw new Error(`No CertificateRegistry deployment found for network "${networkName}"`);
  }

  return address;
}

async function fetchCidBytes(cid: string): Promise<Buffer> {
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

type PinnedMetadata = {
  certId: string;
  fileCid: string;
  fileHash: string;
  [key: string]: unknown;
};

async function pinBufferToIpfs(
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

async function pinJsonToIpfs(obj: unknown, jwt: string, filename: string): Promise<string> {
  const bytes = Buffer.from(JSON.stringify(obj), "utf8");
  return pinBufferToIpfs(bytes, filename, jwt, filename);
}

async function fetchCidJson<T>(cid: string): Promise<T> {
  const bytes = await fetchCidBytes(cid);
  const jsonText = bytes.toString("utf8");
  try {
    return JSON.parse(jsonText) as T;
  } catch {
    throw new Error(`CID ${cid} did not contain valid JSON`);
  }
}

type AuthClaims = {
  address: string;
  sub: string;
};

type NonceRecord = {
  nonce: string;
  issuedAtIso: string;
  expiresAtIso: string;
};

const noncesByAddress = new Map<string, NonceRecord>();
const nonceTtlMs = Number(process.env.AUTH_NONCE_TTL_MS || 5 * 60 * 1000);

function normalizeAddress(address: string): string | null {
  try {
    return getAddress(address);
  } catch {
    return null;
  }
}

function signInMessage(address: string, nonce: string, issuedAtIso: string, expiresAtIso: string): string {
  const domain = process.env.AUTH_DOMAIN || "localhost";
  const uri = process.env.AUTH_URI || "http://localhost:5050";
  const chainId = process.env.AUTH_CHAIN_ID || "31337";
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to Certificate Registry issuer backend.",
    "",
    `URI: ${uri}`,
    "Version: 1",
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAtIso}`,
    `Expiration Time: ${expiresAtIso}`,
  ].join("\n");
}

function getBearerToken(req: express.Request): string {
  const auth = req.header("authorization") || "";
  if (!auth.startsWith("Bearer ")) return "";
  return auth.slice("Bearer ".length).trim();
}

function requireJwtAuth(req: express.Request, res: express.Response): AuthClaims | null {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    res.status(500).json({ error: "JWT_SECRET is not configured" });
    return null;
  }

  const token = getBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Missing bearer token" });
    return null;
  }

  try {
    const payload = jwt.verify(token, secret) as jwt.JwtPayload;
    const addressRaw = String(payload?.address || payload?.sub || "");
    const normalized = normalizeAddress(addressRaw);
    if (!normalized) {
      res.status(401).json({ error: "Invalid token payload" });
      return null;
    }

    return {
      address: normalized,
      sub: normalized.toLowerCase(),
    };
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
    return null;
  }
}

function getReadOnlyContract(): Contract {
  const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
  const contractAddress = loadDeploymentAddress();
  const provider = new JsonRpcProvider(rpcUrl);
  return new Contract(contractAddress, CERTIFICATE_REGISTRY_ABI, provider);
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const num = Number(raw);
  if (!Number.isFinite(num) || num <= 0) return fallback;
  return Math.floor(num);
}

function toSingleString(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] || "";
  return value || "";
}

function isEventLog(log: unknown): log is EventLog {
  return Boolean(log && typeof log === "object" && "args" in (log as Record<string, unknown>));
}

async function rebuildCertificateIndexFromEvents(): Promise<void> {
  const contract = getReadOnlyContract();
  const fromBlock = 0;
  const toBlock = "latest";
  const issuedEvent = contract.getEvent("CertificateIssued");
  const revokedEvent = contract.getEvent("CertificateRevoked");

  const issuedLogs = await contract.queryFilter(issuedEvent, fromBlock, toBlock);
  const revokedLogs = await contract.queryFilter(revokedEvent, fromBlock, toBlock);

  certificateIndexCache.clear();

  for (const log of issuedLogs) {
    if (!isEventLog(log)) continue;
    const certId = String(log.args?.[0] ?? "");
    if (!certId) continue;

    certificateIndexCache.set(certId, {
      certId,
      cid: String(log.args?.[1] ?? ""),
      issuer: String(log.args?.[2] ?? "").toLowerCase(),
      version: Number(log.args?.[3] ?? 1),
      replacesCertId: String(log.args?.[4] ?? ""),
      issuedAt: Number(log.args?.[5] ?? 0),
      revoked: false,
      revokedAt: null,
      issueTxHash: log.transactionHash,
      revokeTxHash: null,
      issueBlockNumber: log.blockNumber,
      revokeBlockNumber: null,
    });
  }

  for (const log of revokedLogs) {
    if (!isEventLog(log)) continue;
    const certId = String(log.args?.[0] ?? "");
    if (!certId) continue;

    const current = certificateIndexCache.get(certId);
    if (current) {
      current.revoked = true;
      current.revokedAt = Number(log.args?.[2] ?? 0);
      current.revokeTxHash = log.transactionHash;
      current.revokeBlockNumber = log.blockNumber;
    } else {
      certificateIndexCache.set(certId, {
        certId,
        cid: "",
        issuer: String(log.args?.[1] ?? "").toLowerCase(),
        version: 0,
        replacesCertId: "",
        issuedAt: 0,
        revoked: true,
        revokedAt: Number(log.args?.[2] ?? 0),
        issueTxHash: "",
        revokeTxHash: log.transactionHash,
        issueBlockNumber: 0,
        revokeBlockNumber: log.blockNumber,
      });
    }
  }

  certificateIndexLastUpdatedAtMs = Date.now();
}

async function ensureCertificateIndexFresh(): Promise<void> {
  const isFresh = Date.now() - certificateIndexLastUpdatedAtMs <= certificateIndexRefreshMs;
  if (isFresh && certificateIndexCache.size > 0) return;

  if (!certificateIndexRebuildPromise) {
    certificateIndexRebuildPromise = rebuildCertificateIndexFromEvents().finally(() => {
      certificateIndexRebuildPromise = null;
    });
  }

  await certificateIndexRebuildPromise;
}

async function ensureAddressIsAuthorizedIssuer(address: string): Promise<boolean> {
  const contract = getReadOnlyContract();
  return (await contract.getFunction("authorizedIssuers").staticCall(address)) as boolean;
}

async function ensureJwtAddressIsAuthorizedIssuer(req: express.Request, res: express.Response): Promise<AuthClaims | null> {
  const auth = requireJwtAuth(req, res);
  if (!auth) return null;

  const allowed = await ensureAddressIsAuthorizedIssuer(auth.address);
  if (!allowed) {
    res.status(403).json({ error: "Wallet is not an authorized issuer" });
    return null;
  }

  return auth;
}

function createRelaySignerOrRespond(res: express.Response): Wallet | null {
  const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
  const issuerPrivateKey = process.env.ISSUER_PRIVATE_KEY;
  if (!issuerPrivateKey) {
    res.status(500).json({ error: "ISSUER_PRIVATE_KEY is not configured" });
    return null;
  }

  const provider = new JsonRpcProvider(rpcUrl);
  return new Wallet(issuerPrivateKey, provider);
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/**
 * Generate a nonce for SIWE-style login.
 * Query: /api/auth/nonce?address=0x...
 */
app.get("/api/auth/nonce", (req, res) => {
  const rawAddress = req.query.address;
  if (typeof rawAddress !== "string") {
    return res.status(400).json({ error: "address query param is required" });
  }

  const address = normalizeAddress(rawAddress);
  if (!address) {
    return res.status(400).json({ error: "Invalid wallet address" });
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  const issuedAtIso = new Date().toISOString();
  const expiresAtIso = new Date(Date.now() + nonceTtlMs).toISOString();

  noncesByAddress.set(address.toLowerCase(), {
    nonce,
    issuedAtIso,
    expiresAtIso,
  });

  return res.json({
    address,
    nonce,
    message: signInMessage(address, nonce, issuedAtIso, expiresAtIso),
    expiresAt: expiresAtIso,
  });
});

/**
 * Verify SIWE-style signature and issue JWT.
 * Body: { address: string, nonce: string, signature: string }
 */
app.post("/api/auth/verify", async (req, res) => {
  try {
    const rawAddress = String(req.body?.address || "").trim();
    const nonce = String(req.body?.nonce || "").trim();
    const signature = String(req.body?.signature || "").trim();

    if (!rawAddress || !nonce || !signature) {
      return res.status(400).json({
        error: "Missing required fields",
        required: ["address", "nonce", "signature"],
      });
    }

    const address = normalizeAddress(rawAddress);
    if (!address) {
      return res.status(400).json({ error: "Invalid wallet address" });
    }

    const record = noncesByAddress.get(address.toLowerCase());
    if (!record || record.nonce !== nonce) {
      return res.status(401).json({ error: "Invalid or expired nonce" });
    }

    if (new Date(record.expiresAtIso).getTime() < Date.now()) {
      noncesByAddress.delete(address.toLowerCase());
      return res.status(401).json({ error: "Nonce expired" });
    }

    const message = signInMessage(address, record.nonce, record.issuedAtIso, record.expiresAtIso);
    const recovered = normalizeAddress(verifyMessage(message, signature));

    if (!recovered || recovered !== address) {
      return res.status(401).json({ error: "Signature verification failed" });
    }

    noncesByAddress.delete(address.toLowerCase());

    const secret = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ error: "JWT_SECRET is not configured" });

    const expiresIn = (process.env.JWT_EXPIRES_IN || "1h") as Exclude<
      jwt.SignOptions["expiresIn"],
      undefined
    >;
    const signOptions: jwt.SignOptions = {
      subject: address.toLowerCase(),
      expiresIn,
    };
    const token = jwt.sign(
      { address: address.toLowerCase() },
      secret,
      signOptions
    );

    return res.json({
      token,
      tokenType: "Bearer",
      expiresIn: signOptions.expiresIn,
      address,
    });
  } catch (err: any) {
    console.error("Auth verify failed:", err?.message);
    return res.status(500).json({
      error: "Auth verification failed",
      message: err?.message || String(err),
    });
  }
});


app.post("/api/pin", pinRateLimiter, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const jwt = process.env.PINATA_JWT;
    if (!jwt) return res.status(500).json({ error: "PINATA_JWT not set" });

    const fileHash = sha256Hex(req.file.buffer);
    const cid = await pinBufferToIpfs(req.file.buffer, req.file.originalname, jwt, req.file.originalname);

    return res.json({ cid, fileHash });
  } catch (err: any) {
    const status = err?.response?.status;
    const details = err?.response?.data || err?.message || String(err);

    console.error("Pinata upload failed. Status:", status);
    console.error("Details:", details);

    return res.status(500).json({
      error: "Pinata upload failed",
      status,
      details,
    });
  }
});


app.get("/api/fetch/:cid", async (req, res) => {
  try {
    const { cid } = req.params;
    const rawFile = await fetchCidBytes(cid);
    res.setHeader("Content-Type", "application/octet-stream");
    res.send(rawFile);
  } catch (err: any) {
    if (err instanceof GatewayFetchError) {
      return res.status(502).json({
        error: "Gateway fetch failed",
        cid: req.params.cid,
        attempts: err.attempts,
      });
    }

    console.error("Fetch crashed:", err?.message);
    return res.status(500).json({
      error: "Fetch crashed",
      message: err?.message || String(err),
    });
  }
});


app.get("/api/verify/:certId", verifyRateLimiter, async (req, res) => {
  let metadataCidForError: string | undefined;
  let fileCidForError: string | undefined;

  try {
    const certId = toSingleString(req.params.certId).trim();
    if (!certId) return res.status(400).json({ error: "certId is required" });

    const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
    const contractAddress = loadDeploymentAddress();
    const provider = new JsonRpcProvider(rpcUrl);
    const contract = new Contract(contractAddress, CERTIFICATE_REGISTRY_ABI, provider);

    const [metadataCid, fileCidOnChain, onChainHash, issuer, version, replacesCertId, issuedAt, revoked, exists] =
      (await contract.getFunction("getCertificate").staticCall(certId)) as [
        string,
        string,
        string,
        string,
        bigint,
        string,
        bigint,
        boolean,
        boolean,
      ];
    metadataCidForError = metadataCid;

    if (!exists) {
      return res.status(404).json({
        certId,
        exists: false,
        status: "NOT_FOUND",
      });
    }

    const metadata = await fetchCidJson<PinnedMetadata>(metadataCid);
    const metadataFileCid = String(metadata?.fileCid || "").trim();
    const rawMetadataFileHash = String(metadata?.fileHash || "").trim().toLowerCase();
    const metadataFileHash =
      rawMetadataFileHash && !rawMetadataFileHash.startsWith("0x")
        ? `0x${rawMetadataFileHash}`
        : rawMetadataFileHash;
    const resolvedFileCid = metadataFileCid || fileCidOnChain;
    fileCidForError = resolvedFileCid;

    if (!resolvedFileCid) {
      return res.status(422).json({
        error: "Metadata missing fileCid and no on-chain fileCid available",
        certId,
        metadataCid,
      });
    }

    const fileBytes = await fetchCidBytes(resolvedFileCid);
    const computedHash = sha256Hex0x(fileBytes);
    const integrityMatch = computedHash.toLowerCase() === String(onChainHash).toLowerCase();
    const metadataHashMatch = metadataFileHash ? metadataFileHash === computedHash.toLowerCase() : null;

    return res.json({
      certId,
      exists: true,
      revoked: Boolean(revoked),
      metadataCid,
      fileCid: resolvedFileCid,
      issuer,
      version: Number(version),
      replacesCertId,
      issuedAt: Number(issuedAt),
      onChainHash: String(onChainHash),
      computedHash,
      integrityMatch,
      metadataHashMatch,
      metadata,
      status: integrityMatch && !revoked ? "VALID" : revoked ? "REVOKED" : "TAMPERED",
    });
  } catch (err: any) {
    if (err instanceof GatewayFetchError) {
      return res.status(502).json({
        error: "Gateway fetch failed during verification",
        certId: req.params.certId,
        metadataCid: metadataCidForError,
        fileCid: fileCidForError,
        attempts: err.attempts,
      });
    }

    console.error("Verify failed:", err?.message);
    return res.status(500).json({
      error: "Verification failed",
      message: err?.message || String(err),
    });
  }
});

/**
 * List certificates by indexing on-chain events from block 0.
 * Query:
 * - issuer=0x... (optional)
 * - page=1..N (default 1)
 * - pageSize=1..100 (default 20)
 */
app.get("/api/certificates", async (req, res) => {
  try {
    await ensureCertificateIndexFresh();

    const issuerRaw = typeof req.query.issuer === "string" ? req.query.issuer.trim() : "";
    const issuer = issuerRaw ? normalizeAddress(issuerRaw) : null;
    if (issuerRaw && !issuer) {
      return res.status(400).json({ error: "Invalid issuer address" });
    }

    const page = parsePositiveInt(typeof req.query.page === "string" ? req.query.page : undefined, 1);
    const pageSizeRaw = parsePositiveInt(
      typeof req.query.pageSize === "string" ? req.query.pageSize : undefined,
      20
    );
    const pageSize = Math.min(pageSizeRaw, 100);

    let items = Array.from(certificateIndexCache.values());
    if (issuer) {
      const issuerLower = issuer.toLowerCase();
      items = items.filter((item) => item.issuer === issuerLower);
    }

    items.sort((a, b) => {
      if (b.issuedAt !== a.issuedAt) return b.issuedAt - a.issuedAt;
      return b.issueBlockNumber - a.issueBlockNumber;
    });

    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const currentPage = Math.min(page, totalPages);
    const start = (currentPage - 1) * pageSize;
    const data = items.slice(start, start + pageSize);

    return res.json({
      total,
      page: currentPage,
      pageSize,
      totalPages,
      refreshedAt: new Date(certificateIndexLastUpdatedAtMs).toISOString(),
      issuer: issuer || null,
      data,
    });
  } catch (err: any) {
    console.error("Certificates index failed:", err?.message);
    return res.status(500).json({
      error: "Certificates index failed",
      message: err?.message || String(err),
    });
  }
});

/**
 * Issue certificate from backend signer.
 * Requires JWT bearer auth and an authorized on-chain issuer wallet.
 *
 * Body:
 * {
 *   certId: string,
 *   fileCid: string,
 *   fileHash: string, // 0x + 64 hex chars
 *   version?: number, // default 1 for new cert
 *   replacesCertId?: string, // required when version > 1
 *   metadata?: object, // optional extra fields merged into pinned metadata JSON
 *   metadataCid?: string // optional pre-pinned metadata CID
 * }
 */
app.post("/api/issue", async (req, res) => {
  try {
    const auth = await ensureJwtAddressIsAuthorizedIssuer(req, res);
    if (!auth) return;

    const certId = String(req.body?.certId || "").trim();
    const fileCid = String(req.body?.fileCid || "").trim();
    const fileHash = String(req.body?.fileHash || "").trim();
    const versionRaw = req.body?.version;
    const version = versionRaw === undefined || versionRaw === null ? 1 : Number(versionRaw);
    const replacesCertId = String(req.body?.replacesCertId || "").trim();
    const providedMetadataCid = String(req.body?.metadataCid || "").trim();
    const metadataInput = req.body?.metadata;

    if (!certId || !fileCid || !fileHash) {
      return res.status(400).json({
        error: "Missing required fields",
        required: ["certId", "fileCid", "fileHash"],
      });
    }

    if (!/^0x[0-9a-fA-F]{64}$/.test(fileHash)) {
      return res.status(400).json({
        error: "fileHash must be a bytes32 hex string (0x + 64 hex chars)",
      });
    }

    if (!Number.isInteger(version) || version < 1) {
      return res.status(400).json({
        error: "version must be an integer >= 1",
      });
    }

    if (version === 1 && replacesCertId) {
      return res.status(400).json({
        error: "replacesCertId must be empty when version is 1",
      });
    }

    if (version > 1 && !replacesCertId) {
      return res.status(400).json({
        error: "replacesCertId is required when version > 1",
      });
    }

    const signer = createRelaySignerOrRespond(res);
    if (!signer) return;
    if (signer.address.toLowerCase() !== auth.address.toLowerCase()) {
      return res.status(403).json({
        error: "Authenticated wallet does not match backend issuer signer",
      });
    }

    const contractAddress = loadDeploymentAddress();
    const contract = new Contract(contractAddress, CERTIFICATE_REGISTRY_ABI, signer);
    const pinJwt = process.env.PINATA_JWT;

    let metadataCid = providedMetadataCid;
    let pinnedMetadata: PinnedMetadata | null = null;

    if (!metadataCid) {
      if (!pinJwt) {
        return res.status(500).json({
          error: "PINATA_JWT is not configured and metadataCid was not provided",
        });
      }

      const metadataExtras =
        metadataInput && typeof metadataInput === "object" && !Array.isArray(metadataInput)
          ? (metadataInput as Record<string, unknown>)
          : {};
      pinnedMetadata = {
        ...metadataExtras,
        certId,
        fileCid,
        fileHash: fileHash.toLowerCase(),
        version,
        replacesCertId,
      };
      metadataCid = await pinJsonToIpfs(
        pinnedMetadata,
        pinJwt,
        `${certId}.metadata.json`
      );
    }

    const issueCertificate = contract.getFunction("issueCertificate");
    const tx = await issueCertificate.send(
      certId,
      metadataCid,
      fileCid,
      fileHash as `0x${string}`,
      version,
      replacesCertId
    );
    const receipt = await tx.wait();

    return res.json({
      ok: true,
      certId,
      metadataCid,
      fileCid,
      fileHash,
      version,
      replacesCertId,
      metadata: pinnedMetadata,
      issuer: signer.address,
      txHash: receipt?.hash ?? tx.hash,
      blockNumber: receipt?.blockNumber ?? null,
    });
  } catch (err: any) {
    console.error("Issue failed:", err?.shortMessage || err?.message);
    return res.status(500).json({
      error: "Issue failed",
      message: err?.shortMessage || err?.message || String(err),
    });
  }
});

/**
 * Revoke certificate from backend signer.
 * Requires JWT bearer auth and an authorized on-chain issuer wallet.
 *
 * Body: { certId: string }
 */
app.post("/api/revoke", async (req, res) => {
  try {
    const auth = await ensureJwtAddressIsAuthorizedIssuer(req, res);
    if (!auth) return;

    const certId = String(req.body?.certId || "").trim();
    if (!certId) {
      return res.status(400).json({
        error: "Missing required field",
        required: ["certId"],
      });
    }

    const signer = createRelaySignerOrRespond(res);
    if (!signer) return;
    if (signer.address.toLowerCase() !== auth.address.toLowerCase()) {
      return res.status(403).json({
        error: "Authenticated wallet does not match backend issuer signer",
      });
    }

    const contractAddress = loadDeploymentAddress();
    const contract = new Contract(contractAddress, CERTIFICATE_REGISTRY_ABI, signer);

    const revokeCertificate = contract.getFunction("revokeCertificate");
    const tx = await revokeCertificate.send(certId);
    const receipt = await tx.wait();

    return res.json({
      ok: true,
      certId,
      issuer: signer.address,
      txHash: receipt?.hash ?? tx.hash,
      blockNumber: receipt?.blockNumber ?? null,
    });
  } catch (err: any) {
    console.error("Revoke failed:", err?.shortMessage || err?.message);
    return res.status(500).json({
      error: "Revoke failed",
      message: err?.shortMessage || err?.message || String(err),
    });
  }
});

const port = Number(process.env.PORT || 5050);
app.listen(port, () => {
  console.log(`Backend running on http://localhost:${port}`);
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ error: "Uploaded file exceeds MAX_UPLOAD_BYTES limit" });
    }
    return res.status(400).json({ error: err.message });
  }

  if (err instanceof Error) {
    if (err.message === "Only PDF uploads are allowed") {
      return res.status(400).json({ error: err.message });
    }
    if (err.message === "Origin not allowed by CORS") {
      return res.status(403).json({ error: err.message });
    }
  }

  return res.status(500).json({ error: "Unhandled server error" });
});
