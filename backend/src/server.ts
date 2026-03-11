// backend/src/server.ts
import express from "express";
import cors from "cors";
import multer from "multer";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import { Contract, JsonRpcProvider, Wallet, getAddress, verifyMessage, type EventLog } from "ethers";
import {
  buildPublicPinnedMetadata,
  decodeFileEncryptionKey,
  encryptPinnedFileWithKey,
  type EncryptedBlobSummary,
  type PublicPinnedMetadata,
} from "./file-envelope.js";
import {
  GatewayFetchError,
  fetchCidBytes,
  fetchCidJson,
  pinBufferToIpfs,
  pinJsonToIpfs,
  sha256Hex,
  sha256Hex0x,
} from "./ipfs-client.js";
import { embedVerificationMetadataInPdf } from "./pdf-verification.js";
import { institutionPinGuard, registerSecurityRoutes } from "./security.js";
import {
  createRequestLoggingMiddleware,
  getPreferredLanIpv4,
  getRequestId,
  isLocalDevOrigin,
  logEvent,
} from "./server-observability.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "..", ".env") });

// Safe JWT fingerprint (helps confirm backend loaded the right .env)
const loadedJwt = process.env.PINATA_JWT || "";
logEvent("info", "PINATA_JWT loaded", {
  fingerprint: loadedJwt ? `${loadedJwt.slice(0, 12)}...${loadedJwt.slice(-6)}` : "(missing)",
});

const app = express();
const nodeEnv = (process.env.NODE_ENV || "development").toLowerCase();
const isProduction = nodeEnv === "production";
const corsOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000,http://localhost:5173")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);
const cspConnectSrc = ["'self'", ...corsOrigins];

if (isProduction && corsOrigins.length === 0) {
  throw new Error("CORS_ORIGINS must be set in production");
}

app.disable("x-powered-by");
app.use(createRequestLoggingMiddleware());
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'none'"],
        objectSrc: ["'none'"],
        scriptSrc: ["'none'"],
        styleSrc: ["'none'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: cspConnectSrc,
        fontSrc: ["'none'"],
        manifestSrc: ["'none'"],
        workerSrc: ["'none'"],
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  })
);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (corsOrigins.includes(origin)) return callback(null, true);
    if (!isProduction && isLocalDevOrigin(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-wallet-address", "x-request-id", "idempotency-key"],
  credentials: true,
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

const authRateLimiter = rateLimit({
  windowMs: Number(process.env.AUTH_RATE_WINDOW_MS || 60_000),
  max: Number(process.env.AUTH_RATE_MAX || 40),
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

registerSecurityRoutes(app, authRateLimiter);

function loadFileEncryptionConfig(): { key: Buffer; keyId: string } {
  return {
    key: decodeFileEncryptionKey(String(process.env.FILE_ENCRYPTION_KEY || "")),
    keyId: String(process.env.FILE_ENCRYPTION_KEY_ID || "default").trim() || "default",
  };
}

function encryptPinnedFile(buffer: Buffer): { encryptedBytes: Buffer; summary: EncryptedBlobSummary } {
  const { key, keyId } = loadFileEncryptionConfig();
  return encryptPinnedFileWithKey(buffer, key, keyId);
}

const workspaceRoot = path.resolve(__dirname, "..", "..");

const CERTIFICATE_REGISTRY_ABI = [
  "function owner() view returns (address)",
  "function getCertificate(string certId) view returns (string metadataCid, string fileCid, bytes32 fileHash, address issuer, uint256 version, string replacesCertId, uint256 issuedAt, bool revoked, bool exists)",
  "function issueCertificate(string certId, string metadataCid, string fileCid, bytes32 fileHash, uint256 version, string replacesCertId)",
  "function revokeCertificate(string certId)",
  "function setIssuer(address issuer, bool allowed)",
  "function authorizedIssuers(address issuer) view returns (bool)",
  "event CertificateIssued(string indexed certId, string metadataCid, address indexed issuer, uint256 version, string replacesCertId, uint256 issuedAt)",
  "event CertificateRevoked(string indexed certId, address indexed issuer, uint256 revokedAt)",
  "event IssuerAuthorizationUpdated(address indexed issuer, bool allowed)",
];

type CertificateIndexEntry = {
  certId: string;
  cid: string;
  metadataCid: string;
  title?: string;
  institutionName?: string;
  fileCid: string;
  fileHash: string;
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

type IssuerStatusEntry = {
  issuer: string;
  isAuthorized: boolean;
  lastTxHash: string;
  lastBlockNumber: number;
  lastChangedAt: number;
  changedBy: string | null;
};

type RelayIdempotencyOperation = "issue" | "revoke";

type RelayIdempotencyRecord = {
  state: "in_progress" | "completed";
  fingerprint: string;
  createdAtMs: number;
  statusCode: number | null;
  body: unknown;
};

const certificateIndexCache = new Map<string, CertificateIndexEntry>();
const certificateIndexRefreshMs = Number(process.env.CERT_INDEX_REFRESH_MS || 15000);
const certificateIndexBatchSize = Math.max(
  1,
  Number(process.env.CERT_INDEX_BLOCK_BATCH_SIZE || 2000)
);
const certificateIndexPollMs = Math.max(
  2000,
  Number(process.env.CERT_INDEX_POLL_MS || 15000)
);
const certificateIndexStartBlock = Math.max(
  0,
  Number(process.env.CERT_INDEX_START_BLOCK || 0)
);
const issuerIndexRefreshMs = Number(process.env.ISSUER_INDEX_REFRESH_MS || certificateIndexRefreshMs);
const issuerIndexPollMs = Math.max(
  2000,
  Number(process.env.ISSUER_INDEX_POLL_MS || certificateIndexPollMs)
);
const issuerIndexStartBlock = Math.max(
  0,
  Number(process.env.ISSUER_INDEX_START_BLOCK || certificateIndexStartBlock)
);
const certificateIndexRequestDelayMs = Math.max(
  0,
  Number(process.env.CERT_INDEX_REQUEST_DELAY_MS || 250)
);
const contractNetworkName = process.env.CONTRACT_NETWORK_NAME || "localhost";
const supabaseUrl = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
const supabaseServiceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
const useSupabaseIndexer = Boolean(supabaseUrl && supabaseServiceRoleKey);
const relayTxModeEnabled = /^(1|true|yes|on)$/i.test(
  (process.env.ENABLE_RELAY_TX_MODE || "").trim()
);
const relayIdempotencyTtlMs = Math.max(
  60_000,
  Number(process.env.RELAY_IDEMPOTENCY_TTL_MS || 24 * 60 * 60 * 1000)
);
const certificateMetadataBackfillLimit = Math.max(
  0,
  Number(process.env.CERT_METADATA_BACKFILL_LIMIT || 0)
);
const relayIdempotencyStore = new Map<string, RelayIdempotencyRecord>();
const indexerWriteQueueMaxAttempts = Math.max(
  1,
  Number(process.env.INDEXER_WRITE_QUEUE_MAX_ATTEMPTS || 6)
);
const indexerWriteQueueBaseDelayMs = Math.max(
  200,
  Number(process.env.INDEXER_WRITE_QUEUE_BASE_DELAY_MS || 1000)
);
const indexerWriteQueueMaxDelayMs = Math.max(
  indexerWriteQueueBaseDelayMs,
  Number(process.env.INDEXER_WRITE_QUEUE_MAX_DELAY_MS || 60000)
);
const healthRpcTimeoutMs = Math.max(500, Number(process.env.HEALTH_RPC_TIMEOUT_MS || 4000));
const healthDbTimeoutMs = Math.max(500, Number(process.env.HEALTH_DB_TIMEOUT_MS || 4000));
const healthIpfsTimeoutMs = Math.max(500, Number(process.env.HEALTH_IPFS_TIMEOUT_MS || 5000));
const healthIndexerLagWarnBlocks = Math.max(
  0,
  Number(process.env.HEALTH_INDEXER_LAG_WARN_BLOCKS || 64)
);
const indexerWriteQueue = new Map<
  string,
  {
    entry: CertificateIndexEntry;
    attempts: number;
    nextRunAtMs: number;
    lastError: string;
  }
>();
let indexerWriteFlushPromise: Promise<void> | null = null;

if ((supabaseUrl && !supabaseServiceRoleKey) || (!supabaseUrl && supabaseServiceRoleKey)) {
  console.warn(
    "Supabase indexer not enabled: set both SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY"
  );
}

if (!relayTxModeEnabled) {
  console.log("Relay tx routes disabled (wallet-native mode). Set ENABLE_RELAY_TX_MODE=true to enable.");
}

const certificateIndexStateDir = path.join(workspaceRoot, "backend", ".indexer");
const certificateIndexStateFile = path.join(
  certificateIndexStateDir,
  `certificates-${contractNetworkName}.json`
);

let certificateIndexLastUpdatedAtMs = 0;
let certificateIndexLastIndexedBlock = certificateIndexStartBlock - 1;
let certificateIndexBootstrapPromise: Promise<void> | null = null;
let certificateIndexSyncPromise: Promise<void> | null = null;
let certificateIndexLastError = "";
let providerMaxLogRange = certificateIndexBatchSize;
const issuerStatusCache = new Map<string, IssuerStatusEntry>();
let issuerIndexLastUpdatedAtMs = 0;
let issuerIndexLastIndexedBlock = issuerIndexStartBlock - 1;
let issuerIndexBootstrapPromise: Promise<void> | null = null;
let issuerIndexSyncPromise: Promise<void> | null = null;
let issuerIndexLastError = "";

type CertificateRow = {
  cert_id: string;
  issuer: string | null;
  title?: string | null;
  institution_name?: string | null;
  metadata_cid: string | null;
  file_cid: string | null;
  file_hash: string | null;
  version: number | null;
  replaces_cert_id: string | null;
  revoked: boolean | null;
  issue_tx: string | null;
  revoke_tx: string | null;
  block_number: number | null;
  revoke_block_number?: number | null;
  issued_at?: number | null;
  revoked_at?: number | null;
  updated_at?: string | null;
};

type IssuerStatusRow = {
  issuer: string;
  is_authorized: boolean | null;
  last_tx_hash: string | null;
  last_block_number: number | null;
  last_changed_at: number | null;
  changed_by?: string | null;
  updated_at?: string | null;
};

type IssuerEventRow = {
  tx_hash: string;
  log_index: number;
  block_number: number;
  issuer: string;
  allowed: boolean;
  changed_by: string | null;
  changed_at: number | null;
  created_at?: string | null;
};

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

function resolveRpcUrl(): string {
  const direct = (process.env.RPC_URL || "").trim();
  if (direct) return direct;

  const networkName = (process.env.CONTRACT_NETWORK_NAME || "localhost").toLowerCase();
  if (networkName === "sepolia") {
    const sepolia = (process.env.SEPOLIA_RPC_URL || "").trim();
    if (sepolia) return sepolia;
  }

  return "http://127.0.0.1:8545";
}

type PinnedMetadata = PublicPinnedMetadata;

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
  const rpcUrl = resolveRpcUrl();
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

function normalizeCertId(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function canonicalizeDemoCertId(certId: string): string {
  const normalized = normalizeCertId(certId);
  const match = normalized.match(/^demo-cert-(\d+)$/);
  if (!match) return normalized;
  const padded = String(match[1]).padStart(3, "0");
  return `demo-cert-${padded}`;
}

function isEventLog(log: unknown): log is EventLog {
  return Boolean(log && typeof log === "object" && "args" in (log as Record<string, unknown>));
}

function toCertificateRow(entry: CertificateIndexEntry): CertificateRow {
  const title = String(entry.title || "").trim();
  const institutionName = String(entry.institutionName || "").trim();
  const certId = normalizeCertId(entry.certId);
  const replacesCertId = normalizeCertId(entry.replacesCertId);
  return {
    cert_id: certId,
    issuer: entry.issuer || null,
    ...(title ? { title } : {}),
    ...(institutionName ? { institution_name: institutionName } : {}),
    metadata_cid: entry.metadataCid || entry.cid || null,
    file_cid: entry.fileCid || "",
    file_hash: entry.fileHash || "",
    version: entry.version,
    replaces_cert_id: replacesCertId || null,
    revoked: entry.revoked,
    issue_tx: entry.issueTxHash || null,
    revoke_tx: entry.revokeTxHash || null,
    block_number: entry.issueBlockNumber || null,
    revoke_block_number: entry.revokeBlockNumber || null,
    issued_at: entry.issuedAt || null,
    revoked_at: entry.revokedAt ?? null,
    updated_at: new Date().toISOString(),
  };
}

function fromCertificateRow(row: CertificateRow): CertificateIndexEntry {
  const metadataCid = row.metadata_cid || "";
  return {
    certId: normalizeCertId(row.cert_id),
    cid: metadataCid,
    metadataCid,
    title: row.title || "",
    institutionName: row.institution_name || "",
    fileCid: row.file_cid || "",
    fileHash: row.file_hash || "",
    issuer: (row.issuer || "").toLowerCase(),
    version: Number(row.version || 0),
    replacesCertId: normalizeCertId(row.replaces_cert_id || ""),
    issuedAt: Number(row.issued_at || 0),
    revoked: Boolean(row.revoked),
    revokedAt: row.revoked_at === null || row.revoked_at === undefined ? null : Number(row.revoked_at),
    issueTxHash: row.issue_tx || "",
    revokeTxHash: row.revoke_tx || null,
    issueBlockNumber: Number(row.block_number || 0),
    revokeBlockNumber:
      row.revoke_block_number === null || row.revoke_block_number === undefined
        ? null
        : Number(row.revoke_block_number),
  };
}

function toIssuerStatusRow(entry: IssuerStatusEntry): IssuerStatusRow {
  return {
    issuer: entry.issuer,
    is_authorized: entry.isAuthorized,
    last_tx_hash: entry.lastTxHash || null,
    last_block_number: entry.lastBlockNumber || null,
    last_changed_at: entry.lastChangedAt || null,
    changed_by: entry.changedBy,
    updated_at: new Date().toISOString(),
  };
}

function fromIssuerStatusRow(row: IssuerStatusRow): IssuerStatusEntry {
  return {
    issuer: String(row.issuer || "").toLowerCase(),
    isAuthorized: Boolean(row.is_authorized),
    lastTxHash: String(row.last_tx_hash || ""),
    lastBlockNumber: Number(row.last_block_number || 0),
    lastChangedAt: Number(row.last_changed_at || 0),
    changedBy: row.changed_by === undefined ? null : row.changed_by,
  };
}

function getSupabaseHeaders() {
  return {
    apikey: supabaseServiceRoleKey,
    Authorization: `Bearer ${supabaseServiceRoleKey}`,
    "Content-Type": "application/json",
  };
}

async function supabaseRequest<T>(options: {
  method: "GET" | "POST";
  tablePath: string;
  params?: Record<string, string>;
  body?: unknown;
  prefer?: string;
}): Promise<T> {
  if (!useSupabaseIndexer) {
    throw new Error("Supabase indexer not configured");
  }

  const url = new URL(`${supabaseUrl}/rest/v1/${options.tablePath}`);
  if (options.params) {
    for (const [key, value] of Object.entries(options.params)) {
      url.searchParams.set(key, value);
    }
  }

  const headers: Record<string, string> = getSupabaseHeaders();
  if (options.prefer) headers.Prefer = options.prefer;

  const response = await axios.request<T>({
    method: options.method,
    url: url.toString(),
    headers,
    data: options.body,
    validateStatus: (status) => status >= 200 && status < 300,
  });
  return response.data;
}

function describeAxiosError(err: unknown): string {
  const anyErr = err as any;
  const status = anyErr?.response?.status;
  const data = anyErr?.response?.data;
  if (status) {
    return `status=${status} data=${JSON.stringify(data)}`;
  }
  return anyErr?.message || String(err);
}

function isCertificateNotFoundError(err: unknown): boolean {
  const message = String((err as any)?.shortMessage || (err as any)?.message || err || "").toLowerCase();
  return message.includes("certificate not found");
}

function isRpcQuotaError(err: unknown): boolean {
  const message = String((err as any)?.shortMessage || (err as any)?.message || err || "").toLowerCase();
  return (
    message.includes("daily request limit reached") ||
    message.includes("request limit reached") ||
    message.includes("rate limit")
  );
}

function cleanupRelayIdempotencyStore(): void {
  const now = Date.now();
  for (const [key, record] of relayIdempotencyStore.entries()) {
    if (record.createdAtMs + relayIdempotencyTtlMs < now) {
      relayIdempotencyStore.delete(key);
    }
  }
}

function getRelayIdempotencyKey(req: express.Request, operation: RelayIdempotencyOperation): string | null {
  const header = String(req.header("idempotency-key") || "").trim();
  if (!header) return null;
  return `${operation}:${header}`;
}

function stableSerializeForIdempotency(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "bigint") return `bigint:${value.toString()}`;
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableSerializeForIdempotency(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${stableSerializeForIdempotency(obj[k])}`)
    .join(",")}}`;
}

function makeRelayIdempotencyFingerprint(payload: unknown): string {
  return crypto
    .createHash("sha256")
    .update(stableSerializeForIdempotency(payload), "utf8")
    .digest("hex");
}

function startRelayIdempotency(
  key: string,
  fingerprint: string
):
  | { kind: "proceed" }
  | { kind: "replay"; statusCode: number; body: unknown }
  | { kind: "conflict"; message: string } {
  cleanupRelayIdempotencyStore();
  const existing = relayIdempotencyStore.get(key);
  if (!existing) {
    relayIdempotencyStore.set(key, {
      state: "in_progress",
      fingerprint,
      createdAtMs: Date.now(),
      statusCode: null,
      body: null,
    });
    return { kind: "proceed" };
  }
  if (existing.fingerprint !== fingerprint) {
    return {
      kind: "conflict",
      message: "Idempotency key reuse with different request payload is not allowed",
    };
  }
  if (existing.state === "completed" && existing.statusCode !== null) {
    return { kind: "replay", statusCode: existing.statusCode, body: existing.body };
  }
  return { kind: "conflict", message: "Request with this idempotency key is already in progress" };
}

function completeRelayIdempotency(key: string, fingerprint: string, statusCode: number, body: unknown): void {
  relayIdempotencyStore.set(key, {
    state: "completed",
    fingerprint,
    createdAtMs: Date.now(),
    statusCode,
    body,
  });
}

function releaseRelayIdempotency(key: string, fingerprint: string): void {
  const existing = relayIdempotencyStore.get(key);
  if (!existing) return;
  if (existing.fingerprint !== fingerprint) return;
  if (existing.state !== "in_progress") return;
  relayIdempotencyStore.delete(key);
}

async function loadCertificateEntryFromChain(
  contract: Contract,
  certId: string,
  opts?: { issueTxHash?: string; issueBlockNumber?: number | null; revokeTxHash?: string | null; revokeBlockNumber?: number | null }
): Promise<CertificateIndexEntry> {
  const normalizedCertId = normalizeCertId(certId);
  const cert = (await contract.getFunction("getCertificate").staticCall(normalizedCertId)) as [
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

  return {
    certId: normalizedCertId,
    cid: String(cert[0] || ""),
    metadataCid: String(cert[0] || ""),
    title: "",
    institutionName: "",
    fileCid: String(cert[1] || ""),
    fileHash: String(cert[2] || "").toLowerCase(),
    issuer: String(cert[3] || "").toLowerCase(),
    version: Number(cert[4] || 0),
    replacesCertId: normalizeCertId(cert[5]),
    issuedAt: Number(cert[6] || 0),
    revoked: Boolean(cert[7]),
    revokedAt: null,
    issueTxHash: String(opts?.issueTxHash || "").trim(),
    revokeTxHash: opts?.revokeTxHash ?? null,
    issueBlockNumber:
      Number.isFinite(opts?.issueBlockNumber as number) && Number(opts?.issueBlockNumber) > 0
        ? Number(opts?.issueBlockNumber)
        : 0,
    revokeBlockNumber:
      Number.isFinite(opts?.revokeBlockNumber as number) && Number(opts?.revokeBlockNumber) > 0
        ? Number(opts?.revokeBlockNumber)
        : null,
  };
}

async function rebuildCertificateIndexFromEvents(): Promise<void> {
  certificateIndexCache.clear();
  certificateIndexLastIndexedBlock = certificateIndexStartBlock - 1;
  await saveCertificateIndexerState();
  await syncCertificateIndexToLatest();
}

async function ensureCertificateIndexFresh(): Promise<void> {
  if (!certificateIndexBootstrapPromise) {
    certificateIndexBootstrapPromise = bootstrapCertificateIndexer().finally(() => {
      certificateIndexBootstrapPromise = null;
    });
  }

  await certificateIndexBootstrapPromise;

  const isFresh = Date.now() - certificateIndexLastUpdatedAtMs <= certificateIndexRefreshMs;
  if (isFresh) return;

  if (!certificateIndexSyncPromise) {
    certificateIndexSyncPromise = syncCertificateIndexToLatest().finally(() => {
      certificateIndexSyncPromise = null;
    });
  }
  await certificateIndexSyncPromise;
}

async function rebuildIssuerIndexFromEvents(): Promise<void> {
  issuerStatusCache.clear();
  issuerIndexLastIndexedBlock = issuerIndexStartBlock - 1;
  await saveIssuerIndexerState();
  await syncIssuerIndexToLatest();
}

async function ensureIssuerIndexFresh(): Promise<void> {
  if (!issuerIndexBootstrapPromise) {
    issuerIndexBootstrapPromise = bootstrapIssuerIndexer().finally(() => {
      issuerIndexBootstrapPromise = null;
    });
  }

  await issuerIndexBootstrapPromise;

  const isFresh = Date.now() - issuerIndexLastUpdatedAtMs <= issuerIndexRefreshMs;
  if (isFresh) return;

  if (!issuerIndexSyncPromise) {
    issuerIndexSyncPromise = syncIssuerIndexToLatest().finally(() => {
      issuerIndexSyncPromise = null;
    });
  }
  await issuerIndexSyncPromise;
}

function triggerCertificateIndexerRefreshIfNeeded(): void {
  const isFresh = Date.now() - certificateIndexLastUpdatedAtMs <= certificateIndexRefreshMs;
  if (isFresh || certificateIndexSyncPromise) return;
  certificateIndexSyncPromise = syncCertificateIndexToLatest()
    .catch((err: any) => {
      certificateIndexLastError = err?.message || String(err);
      console.error("Certificate index background refresh failed:", certificateIndexLastError);
    })
    .finally(() => {
      certificateIndexSyncPromise = null;
    });
}

function triggerIssuerIndexerRefreshIfNeeded(): void {
  const isFresh = Date.now() - issuerIndexLastUpdatedAtMs <= issuerIndexRefreshMs;
  if (isFresh || issuerIndexSyncPromise) return;
  issuerIndexSyncPromise = syncIssuerIndexToLatest()
    .catch((err: any) => {
      issuerIndexLastError = err?.message || String(err);
      console.error("Issuer index background refresh failed:", issuerIndexLastError);
    })
    .finally(() => {
      issuerIndexSyncPromise = null;
    });
}

type CertificateIndexerState = {
  networkName: string;
  contractAddress: string;
  lastIndexedBlock: number;
  updatedAtIso: string;
};

function readLocalIndexerState(stateFile: string): CertificateIndexerState | null {
  try {
    if (!fs.existsSync(stateFile)) return null;
    const raw = fs.readFileSync(stateFile, "utf8");
    const parsed = JSON.parse(raw) as Partial<CertificateIndexerState>;
    if (
      typeof parsed?.networkName !== "string" ||
      typeof parsed?.contractAddress !== "string" ||
      typeof parsed?.lastIndexedBlock !== "number"
    ) {
      return null;
    }
    return {
      networkName: parsed.networkName,
      contractAddress: parsed.contractAddress,
      lastIndexedBlock: Math.floor(parsed.lastIndexedBlock),
      updatedAtIso:
        typeof parsed.updatedAtIso === "string"
          ? parsed.updatedAtIso
          : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

async function saveLocalIndexerState(stateFile: string, lastIndexedBlock: number): Promise<void> {
  const contractAddress = loadDeploymentAddress().toLowerCase();
  const payload: CertificateIndexerState = {
    networkName: contractNetworkName,
    contractAddress,
    lastIndexedBlock,
    updatedAtIso: new Date().toISOString(),
  };

  await fs.promises.mkdir(certificateIndexStateDir, { recursive: true });
  await fs.promises.writeFile(stateFile, JSON.stringify(payload, null, 2), "utf8");
}

async function readSupabaseIndexerState(
  stateKey: string,
  fallbackStartBlock: number
): Promise<CertificateIndexerState | null> {
  const rows = await supabaseRequest<Array<{ id: string; last_block: number | null }>>({
    method: "GET",
    tablePath: "indexer_state",
    params: {
      select: "id,last_block",
      id: `eq.${stateKey}`,
      limit: "1",
    },
  });

  const row = rows[0];
  if (!row) return null;

  return {
    networkName: row.id,
    contractAddress: loadDeploymentAddress().toLowerCase(),
    lastIndexedBlock: Math.floor(Number(row.last_block || fallbackStartBlock - 1)),
    updatedAtIso: new Date().toISOString(),
  };
}

async function saveSupabaseIndexerState(stateKey: string, lastIndexedBlock: number): Promise<void> {
  await supabaseRequest<unknown>({
    method: "POST",
    tablePath: "indexer_state",
    params: { on_conflict: "id" },
    body: [
      {
        id: stateKey,
        last_block: lastIndexedBlock,
      },
    ],
    prefer: "resolution=merge-duplicates,return=minimal",
  });
}

function certificateStateKey(): string {
  return `${contractNetworkName}:certificates`;
}

function issuerStateKey(): string {
  return `${contractNetworkName}:issuer-auth`;
}

function readLocalCertificateIndexerState(): CertificateIndexerState | null {
  return readLocalIndexerState(certificateIndexStateFile);
}

async function saveLocalCertificateIndexerState(): Promise<void> {
  await saveLocalIndexerState(certificateIndexStateFile, certificateIndexLastIndexedBlock);
}

async function readSupabaseCertificateIndexerState(): Promise<CertificateIndexerState | null> {
  return readSupabaseIndexerState(certificateStateKey(), certificateIndexStartBlock);
}

async function saveSupabaseCertificateIndexerState(): Promise<void> {
  await saveSupabaseIndexerState(certificateStateKey(), certificateIndexLastIndexedBlock);
}

async function readCertificateIndexerState(): Promise<CertificateIndexerState | null> {
  if (useSupabaseIndexer) {
    try {
      return await readSupabaseCertificateIndexerState();
    } catch (err: any) {
      console.error("Supabase indexer_state read failed:", describeAxiosError(err));
    }
  }
  return readLocalCertificateIndexerState();
}

async function saveCertificateIndexerState(): Promise<void> {
  if (useSupabaseIndexer) {
    try {
      await saveSupabaseCertificateIndexerState();
      return;
    } catch (err: any) {
      console.error("Supabase indexer_state write failed:", describeAxiosError(err));
    }
  }
  await saveLocalCertificateIndexerState();
}

async function upsertSupabaseCertificates(entries: CertificateIndexEntry[]): Promise<void> {
  if (entries.length === 0) return;
  await supabaseRequest<unknown>({
    method: "POST",
    tablePath: "certificates",
    params: { on_conflict: "cert_id" },
    body: entries.map(toCertificateRow),
    prefer: "resolution=merge-duplicates,return=minimal",
  });
}

function queueIndexerWrites(entries: CertificateIndexEntry[], reason: string): void {
  const now = Date.now();
  for (const entry of entries) {
    const existing = indexerWriteQueue.get(entry.certId);
    indexerWriteQueue.set(entry.certId, {
      entry: { ...entry },
      attempts: existing?.attempts || 0,
      nextRunAtMs: existing?.nextRunAtMs || now,
      lastError: reason,
    });
  }
}

async function flushIndexerWriteQueue(): Promise<void> {
  if (!useSupabaseIndexer) return;
  if (indexerWriteFlushPromise) return indexerWriteFlushPromise;
  indexerWriteFlushPromise = (async () => {
    const now = Date.now();
    const due = Array.from(indexerWriteQueue.values()).filter((item) => item.nextRunAtMs <= now);
    if (due.length === 0) return;

    const batch = due.map((item) => item.entry);
    try {
      await upsertSupabaseCertificates(batch);
      for (const item of due) {
        indexerWriteQueue.delete(item.entry.certId);
      }
      if (batch.length > 0) {
        logEvent("info", "indexer_write_queue_flush_ok", {
          count: batch.length,
          remaining: indexerWriteQueue.size,
        });
      }
    } catch (err: any) {
      const errMsg = describeAxiosError(err);
      for (const item of due) {
        const attempts = item.attempts + 1;
        if (attempts >= indexerWriteQueueMaxAttempts) {
          indexerWriteQueue.delete(item.entry.certId);
          logEvent("error", "indexer_write_queue_drop", {
            certId: item.entry.certId,
            attempts,
            error: errMsg,
          });
          continue;
        }
        const delay = Math.min(
          indexerWriteQueueMaxDelayMs,
          indexerWriteQueueBaseDelayMs * Math.pow(2, attempts - 1)
        );
        indexerWriteQueue.set(item.entry.certId, {
          entry: item.entry,
          attempts,
          nextRunAtMs: Date.now() + delay,
          lastError: errMsg,
        });
      }
      logEvent("warn", "indexer_write_queue_flush_retry", {
        attempted: due.length,
        remaining: indexerWriteQueue.size,
        error: errMsg,
      });
    }
  })().finally(() => {
    indexerWriteFlushPromise = null;
  });
  return indexerWriteFlushPromise;
}

async function loadSupabaseCertificatesIntoCache(): Promise<void> {
  const rows = await supabaseRequest<CertificateRow[]>({
    method: "GET",
    tablePath: "certificates",
    params: {
      // Select all columns to stay compatible with partially-migrated tables.
      select: "*",
      order: "block_number.asc",
    },
  });

  for (const row of rows) {
    const entry = fromCertificateRow(row);
    certificateIndexCache.set(entry.certId, entry);
  }
}

async function persistCertificates(entries: CertificateIndexEntry[]): Promise<void> {
  if (useSupabaseIndexer) {
    try {
      await upsertSupabaseCertificates(entries);
      if (indexerWriteQueue.size > 0) {
        void flushIndexerWriteQueue();
      }
      return;
    } catch (err: any) {
      const errMsg = describeAxiosError(err);
      queueIndexerWrites(entries, errMsg);
      logEvent("warn", "supabase_certificates_upsert_queued", {
        queued: entries.length,
        queueDepth: indexerWriteQueue.size,
        error: errMsg,
      });
      return;
    }
  }
}

async function hydrateCacheFromPersistentStore(): Promise<void> {
  if (!useSupabaseIndexer) return;
  try {
    await loadSupabaseCertificatesIntoCache();
  } catch (err: any) {
    console.error("Supabase certificates bootstrap failed:", describeAxiosError(err));
  }
}

async function readSupabaseIssuerIndexerState(): Promise<CertificateIndexerState | null> {
  return readSupabaseIndexerState(issuerStateKey(), issuerIndexStartBlock);
}

async function saveSupabaseIssuerIndexerState(): Promise<void> {
  await saveSupabaseIndexerState(issuerStateKey(), issuerIndexLastIndexedBlock);
}

async function readIssuerIndexerState(): Promise<CertificateIndexerState | null> {
  if (!useSupabaseIndexer) return null;
  try {
    return await readSupabaseIssuerIndexerState();
  } catch (err: any) {
    console.error("Supabase issuer indexer_state read failed:", describeAxiosError(err));
    return null;
  }
}

async function saveIssuerIndexerState(): Promise<void> {
  if (!useSupabaseIndexer) return;
  try {
    await saveSupabaseIssuerIndexerState();
  } catch (err: any) {
    console.error("Supabase issuer indexer_state write failed:", describeAxiosError(err));
  }
}

async function upsertSupabaseIssuerStatuses(entries: IssuerStatusEntry[]): Promise<void> {
  if (entries.length === 0) return;
  await supabaseRequest<unknown>({
    method: "POST",
    tablePath: "issuer_status",
    params: { on_conflict: "issuer" },
    body: entries.map(toIssuerStatusRow),
    prefer: "resolution=merge-duplicates,return=minimal",
  });
}

async function insertSupabaseIssuerEvents(entries: IssuerEventRow[]): Promise<void> {
  if (entries.length === 0) return;
  await supabaseRequest<unknown>({
    method: "POST",
    tablePath: "issuer_events",
    params: { on_conflict: "tx_hash,log_index" },
    body: entries,
    prefer: "resolution=ignore-duplicates,return=minimal",
  });
}

async function loadSupabaseIssuerStatusesIntoCache(): Promise<void> {
  const rows = await supabaseRequest<IssuerStatusRow[]>({
    method: "GET",
    tablePath: "issuer_status",
    params: {
      select: "*",
      order: "last_block_number.asc",
    },
  });

  issuerStatusCache.clear();
  for (const row of rows) {
    const entry = fromIssuerStatusRow(row);
    if (!entry.issuer) continue;
    issuerStatusCache.set(entry.issuer, entry);
  }
}

async function persistIssuerStatusesAndEvents(
  statuses: IssuerStatusEntry[],
  events: IssuerEventRow[]
): Promise<void> {
  if (!useSupabaseIndexer) return;
  try {
    await upsertSupabaseIssuerStatuses(statuses);
    await insertSupabaseIssuerEvents(events);
  } catch (err: any) {
    console.error("Supabase issuer status/events upsert failed:", describeAxiosError(err));
    throw err;
  }
}

async function hydrateIssuerCacheFromPersistentStore(): Promise<void> {
  if (!useSupabaseIndexer) return;
  try {
    await loadSupabaseIssuerStatusesIntoCache();
  } catch (err: any) {
    console.error("Supabase issuer statuses bootstrap failed:", describeAxiosError(err));
  }
}

function applyIssuedLog(log: EventLog): void {
  const certId = normalizeCertId(log.args?.[0]);
  if (!certId || certId === "[object Object]") return;

  certificateIndexCache.set(certId, {
    certId,
    cid: String(log.args?.[1] ?? ""),
    metadataCid: String(log.args?.[1] ?? ""),
    fileCid: "",
    fileHash: "",
    issuer: String(log.args?.[2] ?? "").toLowerCase(),
    version: Number(log.args?.[3] ?? 1),
    replacesCertId: normalizeCertId(log.args?.[4]),
    issuedAt: Number(log.args?.[5] ?? 0),
    revoked: false,
    revokedAt: null,
    issueTxHash: log.transactionHash,
    revokeTxHash: null,
    issueBlockNumber: log.blockNumber,
    revokeBlockNumber: null,
  });
}

function applyRevokedLog(log: EventLog): void {
  const certId = normalizeCertId(log.args?.[0]);
  if (!certId || certId === "[object Object]") return;

  const current = certificateIndexCache.get(certId);
  if (current) {
    current.revoked = true;
    current.revokedAt = Number(log.args?.[2] ?? 0);
    current.revokeTxHash = log.transactionHash;
    current.revokeBlockNumber = log.blockNumber;
    return;
  }

  certificateIndexCache.set(certId, {
    certId,
    cid: "",
    metadataCid: "",
    fileCid: "",
    fileHash: "",
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

function readDirectCertId(arg: unknown): string | null {
  const normalized = normalizeCertId(arg);
  if (!normalized || normalized === "[object object]") return null;
  return normalized;
}

async function resolveCertIdFromTx(contract: Contract, txHash: string, fnName: string): Promise<string | null> {
  const provider = contract.runner?.provider;
  if (!provider) return null;
  const tx = await provider.getTransaction(txHash);
  if (!tx?.data) return null;

  try {
    const parsed = contract.interface.parseTransaction({ data: tx.data, value: tx.value });
    if (!parsed || parsed.name !== fnName) return null;
    return readDirectCertId(parsed.args?.[0]);
  } catch {
    return null;
  }
}

async function enrichEntryFromContract(contract: Contract, entry: CertificateIndexEntry): Promise<void> {
  try {
    const cert = (await contract.getFunction("getCertificate").staticCall(entry.certId)) as [
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

    entry.metadataCid = cert[0];
    entry.cid = cert[0];
    entry.fileCid = cert[1];
    entry.fileHash = String(cert[2] || "").toLowerCase();
    entry.issuer = String(cert[3] || "").toLowerCase();
    entry.version = Number(cert[4] || 0n);
    entry.replacesCertId = normalizeCertId(cert[5]);
    entry.issuedAt = Number(cert[6] || 0n);
    entry.revoked = Boolean(cert[7]);
  } catch {
    // Keep event-derived values if contract read fails.
  }
}

function normalizeMetadataLabel(value: unknown): string {
  return String(value ?? "").trim();
}

async function validateAndBackfillCertificateMetadataLabels(options?: {
  dryRun?: boolean;
  limit?: number;
}): Promise<{
  dryRun: boolean;
  scanned: number;
  matched: number;
  mismatched: number;
  updated: number;
  fetchErrors: number;
  missingMetadataCid: number;
  samples: Array<{
    certId: string;
    metadataCid: string;
    dbTitle: string;
    metadataTitle: string;
    dbInstitutionName: string;
    metadataInstitutionName: string;
    error?: string;
  }>;
}> {
  const dryRun = Boolean(options?.dryRun);
  const limitRaw = Number(options?.limit || 0);
  const requestedLimit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : 0;
  const defaultLimit = Number.isFinite(certificateMetadataBackfillLimit) && certificateMetadataBackfillLimit > 0
    ? certificateMetadataBackfillLimit
    : 0;
  const effectiveLimit = requestedLimit > 0 ? requestedLimit : defaultLimit;
  const maxToScan = effectiveLimit > 0 ? effectiveLimit : Number.POSITIVE_INFINITY;

  const entries = Array.from(certificateIndexCache.values())
    .sort((a, b) => a.certId.localeCompare(b.certId))
    .slice(0, Number.isFinite(maxToScan) ? maxToScan : undefined);

  const toPersist: CertificateIndexEntry[] = [];
  let scanned = 0;
  let matched = 0;
  let mismatched = 0;
  let updated = 0;
  let fetchErrors = 0;
  let missingMetadataCid = 0;
  const samples: Array<{
    certId: string;
    metadataCid: string;
    dbTitle: string;
    metadataTitle: string;
    dbInstitutionName: string;
    metadataInstitutionName: string;
    error?: string;
  }> = [];

  for (const entry of entries) {
    scanned += 1;
    const metadataCid = String(entry.metadataCid || entry.cid || "").trim();
    if (!metadataCid) {
      missingMetadataCid += 1;
      continue;
    }

    try {
      const metadata = await fetchCidJson<Record<string, unknown>>(metadataCid);
      const metadataTitle = normalizeMetadataLabel(metadata?.title);
      const metadataInstitutionName = normalizeMetadataLabel(
        metadata?.institutionName ?? metadata?.institution_name
      );
      const dbTitle = normalizeMetadataLabel(entry.title);
      const dbInstitutionName = normalizeMetadataLabel(entry.institutionName);
      const isConsistent =
        dbTitle === metadataTitle &&
        dbInstitutionName === metadataInstitutionName;

      if (isConsistent) {
        matched += 1;
        continue;
      }

      mismatched += 1;
      if (samples.length < 100) {
        samples.push({
          certId: entry.certId,
          metadataCid,
          dbTitle,
          metadataTitle,
          dbInstitutionName,
          metadataInstitutionName,
        });
      }

      if (!dryRun) {
        entry.title = metadataTitle;
        entry.institutionName = metadataInstitutionName;
        toPersist.push(entry);
      }
    } catch (err: any) {
      fetchErrors += 1;
      if (samples.length < 100) {
        samples.push({
          certId: entry.certId,
          metadataCid,
          dbTitle: normalizeMetadataLabel(entry.title),
          metadataTitle: "",
          dbInstitutionName: normalizeMetadataLabel(entry.institutionName),
          metadataInstitutionName: "",
          error: err?.message || String(err),
        });
      }
    }
  }

  if (!dryRun && toPersist.length > 0) {
    await persistCertificates(toPersist);
    certificateIndexLastUpdatedAtMs = Date.now();
    updated = toPersist.length;
  }

  return {
    dryRun,
    scanned,
    matched,
    mismatched,
    updated,
    fetchErrors,
    missingMetadataCid,
    samples,
  };
}

function isLogRangeLimitError(err: unknown): boolean {
  const message = String((err as any)?.message || "").toLowerCase();
  return message.includes("eth_getlogs is limited to a") || message.includes("range is too wide");
}

function parseLogRangeLimit(err: unknown): number | null {
  const message = String((err as any)?.message || "");
  const match = message.match(/limited to a\s+(\d+)\s+range/i);
  if (!match) return null;
  const parsed = Number(match[1]);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
}

function isRateLimitError(err: unknown): boolean {
  const message = String((err as any)?.message || "").toLowerCase();
  return (
    message.includes("request limit reached") ||
    message.includes("too many requests") ||
    message.includes("rate limit")
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeoutHandle = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

async function syncCertificateIndexToLatest(): Promise<void> {
  certificateIndexLastError = "";
  const contract = getReadOnlyContract();
  const latestBlock = await contract.runner!.provider!.getBlockNumber();
  let fromBlock = Math.max(certificateIndexLastIndexedBlock + 1, certificateIndexStartBlock);

  if (fromBlock > latestBlock) {
    certificateIndexLastUpdatedAtMs = Date.now();
    return;
  }

  const issuedEvent = contract.getEvent("CertificateIssued");
  const revokedEvent = contract.getEvent("CertificateRevoked");

  while (fromBlock <= latestBlock) {
    const activeRange = Math.max(1, Math.min(providerMaxLogRange, certificateIndexBatchSize));
    const toBlock = Math.min(fromBlock + activeRange - 1, latestBlock);
    let issuedLogsRaw: unknown[] = [];
    let revokedLogsRaw: unknown[] = [];
    try {
      issuedLogsRaw = await contract.queryFilter(issuedEvent, fromBlock, toBlock);
      if (certificateIndexRequestDelayMs > 0) {
        await sleep(certificateIndexRequestDelayMs);
      }
      revokedLogsRaw = await contract.queryFilter(revokedEvent, fromBlock, toBlock);
    } catch (err: any) {
      if (isRateLimitError(err)) {
        const backoffMs = Math.max(1000, certificateIndexRequestDelayMs * 8);
        console.warn(`Provider rate limit hit. Backing off for ${backoffMs}ms`);
        await sleep(backoffMs);
        continue;
      }

      if (!isLogRangeLimitError(err)) {
        throw err;
      }

      const parsedLimit = parseLogRangeLimit(err);
      if (parsedLimit !== null) {
        providerMaxLogRange = Math.max(1, parsedLimit);
      } else {
        providerMaxLogRange = Math.max(1, Math.floor(providerMaxLogRange / 2));
      }

      console.warn(
        `Provider log range limit detected. Retrying with block window=${providerMaxLogRange}`
      );
      continue;
    }

    const logs = [...issuedLogsRaw, ...revokedLogsRaw]
      .filter(isEventLog)
      .sort((a, b) => {
        if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
        return a.index - b.index;
      });

    const touchedCertIds = new Set<string>();

    for (const log of logs) {
      if (log.fragment?.name === "CertificateIssued") {
        let certId = readDirectCertId(log.args?.[0]);
        if (!certId) {
          certId = await resolveCertIdFromTx(contract, log.transactionHash, "issueCertificate");
        }
        if (!certId) {
          throw new Error(
            `Unable to resolve certId for CertificateIssued tx ${log.transactionHash} at block ${log.blockNumber}`
          );
        }
        certificateIndexCache.set(certId, {
          certId,
          cid: String(log.args?.[1] ?? ""),
          metadataCid: String(log.args?.[1] ?? ""),
          fileCid: "",
          fileHash: "",
          issuer: String(log.args?.[2] ?? "").toLowerCase(),
          version: Number(log.args?.[3] ?? 1),
          replacesCertId: normalizeCertId(log.args?.[4]),
          issuedAt: Number(log.args?.[5] ?? 0),
          revoked: false,
          revokedAt: null,
          issueTxHash: log.transactionHash,
          revokeTxHash: null,
          issueBlockNumber: log.blockNumber,
          revokeBlockNumber: null,
        });
        touchedCertIds.add(certId);
      } else if (log.fragment?.name === "CertificateRevoked") {
        let certId = readDirectCertId(log.args?.[0]);
        if (!certId) {
          certId = await resolveCertIdFromTx(contract, log.transactionHash, "revokeCertificate");
        }
        if (!certId) {
          throw new Error(
            `Unable to resolve certId for CertificateRevoked tx ${log.transactionHash} at block ${log.blockNumber}`
          );
        }

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
            metadataCid: "",
            fileCid: "",
            fileHash: "",
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
        touchedCertIds.add(certId);
      }
    }

    const touchedEntries: CertificateIndexEntry[] = [];
    for (const certId of touchedCertIds) {
      const entry = certificateIndexCache.get(certId);
      if (!entry) continue;
      await enrichEntryFromContract(contract, entry);
      touchedEntries.push(entry);
    }

    await persistCertificates(touchedEntries);

    certificateIndexLastIndexedBlock = toBlock;
    certificateIndexLastUpdatedAtMs = Date.now();
    await saveCertificateIndexerState();
    fromBlock = toBlock + 1;
  }
}

async function syncIssuerIndexToLatest(): Promise<void> {
  issuerIndexLastError = "";
  const contract = getReadOnlyContract();
  const provider = contract.runner?.provider;
  if (!provider) throw new Error("Provider not available for issuer sync");

  const latestBlock = await provider.getBlockNumber();
  let fromBlock = Math.max(issuerIndexLastIndexedBlock + 1, issuerIndexStartBlock);

  if (fromBlock > latestBlock) {
    issuerIndexLastUpdatedAtMs = Date.now();
    return;
  }

  const issuerAuthEvent = contract.getEvent("IssuerAuthorizationUpdated");
  const txFromCache = new Map<string, string | null>();
  const blockTimestampCache = new Map<number, number>();

  while (fromBlock <= latestBlock) {
    const activeRange = Math.max(1, Math.min(providerMaxLogRange, certificateIndexBatchSize));
    const toBlock = Math.min(fromBlock + activeRange - 1, latestBlock);
    let issuerLogsRaw: unknown[] = [];
    try {
      issuerLogsRaw = await contract.queryFilter(issuerAuthEvent, fromBlock, toBlock);
    } catch (err: any) {
      if (isRateLimitError(err)) {
        const backoffMs = Math.max(1000, certificateIndexRequestDelayMs * 8);
        console.warn(`Provider rate limit hit during issuer sync. Backing off for ${backoffMs}ms`);
        await sleep(backoffMs);
        continue;
      }

      if (!isLogRangeLimitError(err)) {
        throw err;
      }

      const parsedLimit = parseLogRangeLimit(err);
      if (parsedLimit !== null) {
        providerMaxLogRange = Math.max(1, parsedLimit);
      } else {
        providerMaxLogRange = Math.max(1, Math.floor(providerMaxLogRange / 2));
      }

      console.warn(
        `Provider log range limit detected (issuer sync). Retrying with block window=${providerMaxLogRange}`
      );
      continue;
    }

    const logs = issuerLogsRaw
      .filter(isEventLog)
      .sort((a, b) => {
        if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
        return a.index - b.index;
      });

    const touchedIssuers = new Set<string>();
    const issuerEvents: IssuerEventRow[] = [];

    for (const log of logs) {
      const issuerRaw = String(log.args?.[0] ?? "");
      const issuer = normalizeAddress(issuerRaw)?.toLowerCase() || "";
      if (!issuer) continue;
      const allowed = Boolean(log.args?.[1]);
      let changedAt = blockTimestampCache.get(log.blockNumber) ?? 0;
      if (!blockTimestampCache.has(log.blockNumber)) {
        try {
          const block = await provider.getBlock(log.blockNumber);
          changedAt = Number(block?.timestamp || 0);
        } catch {
          changedAt = 0;
        }
        blockTimestampCache.set(log.blockNumber, changedAt);
      }

      let changedBy = txFromCache.get(log.transactionHash) ?? null;
      if (!txFromCache.has(log.transactionHash)) {
        try {
          const tx = await provider.getTransaction(log.transactionHash);
          changedBy = normalizeAddress(String(tx?.from || ""))?.toLowerCase() || null;
        } catch {
          changedBy = null;
        }
        txFromCache.set(log.transactionHash, changedBy);
      }

      const existing = issuerStatusCache.get(issuer);
      if (!existing || existing.lastBlockNumber <= log.blockNumber) {
        issuerStatusCache.set(issuer, {
          issuer,
          isAuthorized: allowed,
          lastTxHash: log.transactionHash,
          lastBlockNumber: log.blockNumber,
          lastChangedAt: changedAt,
          changedBy,
        });
      }
      touchedIssuers.add(issuer);

      issuerEvents.push({
        tx_hash: log.transactionHash,
        log_index: log.index,
        block_number: log.blockNumber,
        issuer,
        allowed,
        changed_by: changedBy,
        changed_at: changedAt || null,
      });
    }

    const touchedEntries = Array.from(touchedIssuers)
      .map((issuer) => issuerStatusCache.get(issuer))
      .filter((entry): entry is IssuerStatusEntry => Boolean(entry));

    await persistIssuerStatusesAndEvents(touchedEntries, issuerEvents);

    issuerIndexLastIndexedBlock = toBlock;
    issuerIndexLastUpdatedAtMs = Date.now();
    await saveIssuerIndexerState();
    fromBlock = toBlock + 1;
  }
}

async function bootstrapCertificateIndexer(): Promise<void> {
  certificateIndexCache.clear();
  await hydrateCacheFromPersistentStore();

  const state = await readCertificateIndexerState();
  const currentAddress = loadDeploymentAddress().toLowerCase();

  const expectedStateName = useSupabaseIndexer ? certificateStateKey() : contractNetworkName;
  if (
    state &&
    state.networkName === expectedStateName &&
    state.contractAddress.toLowerCase() === currentAddress
  ) {
    certificateIndexLastIndexedBlock = Math.max(
      certificateIndexStartBlock - 1,
      state.lastIndexedBlock
    );
  } else {
    certificateIndexLastIndexedBlock = certificateIndexStartBlock - 1;
  }

  await syncCertificateIndexToLatest();
}

async function bootstrapIssuerIndexer(): Promise<void> {
  issuerStatusCache.clear();
  await hydrateIssuerCacheFromPersistentStore();

  const state = await readIssuerIndexerState();
  const currentAddress = loadDeploymentAddress().toLowerCase();

  const expectedStateName = useSupabaseIndexer ? issuerStateKey() : contractNetworkName;
  if (
    state &&
    state.networkName === expectedStateName &&
    state.contractAddress.toLowerCase() === currentAddress
  ) {
    issuerIndexLastIndexedBlock = Math.max(
      issuerIndexStartBlock - 1,
      state.lastIndexedBlock
    );
  } else {
    issuerIndexLastIndexedBlock = issuerIndexStartBlock - 1;
  }

  await syncIssuerIndexToLatest();
}

function startCertificateIndexerPolling(): void {
  setInterval(() => {
    if (certificateIndexSyncPromise) return;
    certificateIndexSyncPromise = syncCertificateIndexToLatest()
      .catch((err: any) => {
        console.error("Certificate index poll failed:", err?.message || String(err));
      })
      .finally(() => {
        certificateIndexSyncPromise = null;
      });
  }, certificateIndexPollMs);

  setInterval(() => {
    if (issuerIndexSyncPromise) return;
    issuerIndexSyncPromise = syncIssuerIndexToLatest()
      .catch((err: any) => {
        console.error("Issuer index poll failed:", err?.message || String(err));
      })
      .finally(() => {
        issuerIndexSyncPromise = null;
      });
  }, issuerIndexPollMs);

  setInterval(() => {
    if (!useSupabaseIndexer) return;
    void flushIndexerWriteQueue();
  }, Math.min(indexerWriteQueueBaseDelayMs, 5000));
}

function buildCertificateHistory(seedCertId: string): {
  rootCertId: string;
  chain: CertificateIndexEntry[];
} | null {
  const byCertId = certificateIndexCache;
  const normalizedSeedCertId = normalizeCertId(seedCertId);
  const seed = byCertId.get(normalizedSeedCertId);
  if (!seed) return null;

  const visited = new Set<string>();

  // Walk backwards to root.
  let root = seed;
  while (root.replacesCertId) {
    if (visited.has(root.certId)) break;
    visited.add(root.certId);
    const parent = byCertId.get(normalizeCertId(root.replacesCertId));
    if (!parent) break;
    root = parent;
  }

  // Walk forward root -> latest.
  const chain: CertificateIndexEntry[] = [];
  let cursor: CertificateIndexEntry | undefined = root;
  const forwardVisited = new Set<string>();

  while (cursor && !forwardVisited.has(cursor.certId)) {
    const current: CertificateIndexEntry = cursor;
    chain.push(current);
    forwardVisited.add(current.certId);

    const children: CertificateIndexEntry[] = Array.from(byCertId.values())
      .filter((item) => normalizeCertId(item.replacesCertId) === current.certId)
      .sort((a, b) => {
        if (a.version !== b.version) return a.version - b.version;
        return a.issuedAt - b.issuedAt;
      });

    cursor = children[0];
  }

  return {
    rootCertId: root.certId,
    chain,
  };
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
  const rpcUrl = resolveRpcUrl();
  const issuerPrivateKey = process.env.ISSUER_PRIVATE_KEY;
  if (!issuerPrivateKey) {
    res.status(500).json({ error: "ISSUER_PRIVATE_KEY is not configured" });
    return null;
  }

  const provider = new JsonRpcProvider(rpcUrl);
  return new Wallet(issuerPrivateKey, provider);
}

function requireRelayTxModeEnabled(res: express.Response): boolean {
  if (relayTxModeEnabled) return true;
  res.status(404).json({
    error: "Relay tx mode is disabled",
    hint: "Use wallet-native issuance/revocation, or set ENABLE_RELAY_TX_MODE=true.",
  });
  return false;
}

async function probeRpcHealth(): Promise<{ ok: boolean; latestBlock: number | null; error?: string }> {
  try {
    const provider = new JsonRpcProvider(resolveRpcUrl());
    const latestBlock = await withTimeout(
      provider.getBlockNumber(),
      healthRpcTimeoutMs,
      `rpc health timeout after ${healthRpcTimeoutMs}ms`
    );
    return { ok: Number.isFinite(latestBlock), latestBlock };
  } catch (err: any) {
    return { ok: false, latestBlock: null, error: err?.message || String(err) };
  }
}

async function probeDbHealth(): Promise<{ ok: boolean; enabled: boolean; error?: string }> {
  if (!useSupabaseIndexer) {
    return { ok: true, enabled: false };
  }
  try {
    await withTimeout(
      supabaseRequest<unknown>({
        method: "GET",
        tablePath: "indexer_state",
        params: { select: "id", limit: "1" },
      }),
      healthDbTimeoutMs,
      `db health timeout after ${healthDbTimeoutMs}ms`
    );
    return { ok: true, enabled: true };
  } catch (err: any) {
    return { ok: false, enabled: true, error: describeAxiosError(err) };
  }
}

async function probeIpfsPinningHealth(): Promise<{ ok: boolean; enabled: boolean; error?: string }> {
  const jwt = String(process.env.PINATA_JWT || "").trim();
  if (!jwt) return { ok: false, enabled: false, error: "PINATA_JWT not configured" };
  try {
    await withTimeout(
      axios.get("https://api.pinata.cloud/data/testAuthentication", {
        headers: { Authorization: `Bearer ${jwt}` },
        validateStatus: (status) => status >= 200 && status < 300,
      }),
      healthIpfsTimeoutMs,
      `ipfs health timeout after ${healthIpfsTimeoutMs}ms`
    );
    return { ok: true, enabled: true };
  } catch (err: any) {
    return {
      ok: false,
      enabled: true,
      error: err?.response?.data?.error || err?.message || String(err),
    };
  }
}

function getIndexerLagStatus(latestBlock: number | null): {
  ok: boolean;
  latestBlock: number | null;
  certificateLagBlocks: number | null;
  issuerLagBlocks: number | null;
  queueDepth: number;
  lastError: string;
} {
  if (!Number.isFinite(latestBlock as number)) {
    return {
      ok: false,
      latestBlock,
      certificateLagBlocks: null,
      issuerLagBlocks: null,
      queueDepth: indexerWriteQueue.size,
      lastError: certificateIndexLastError || issuerIndexLastError || "",
    };
  }
  const lb = Number(latestBlock);
  const certificateLagBlocks = Math.max(0, lb - Math.max(certificateIndexLastIndexedBlock, 0));
  const issuerLagBlocks = Math.max(0, lb - Math.max(issuerIndexLastIndexedBlock, 0));
  const ok =
    certificateLagBlocks <= healthIndexerLagWarnBlocks &&
    issuerLagBlocks <= healthIndexerLagWarnBlocks &&
    !certificateIndexLastError &&
    !issuerIndexLastError;
  return {
    ok,
    latestBlock: lb,
    certificateLagBlocks,
    issuerLagBlocks,
    queueDepth: indexerWriteQueue.size,
    lastError: certificateIndexLastError || issuerIndexLastError || "",
  };
}

app.get("/health", async (req, res) => {
  const [rpc, db, ipfs] = await Promise.all([
    probeRpcHealth(),
    probeDbHealth(),
    probeIpfsPinningHealth(),
  ]);
  const indexer = getIndexerLagStatus(rpc.latestBlock);
  const ok = rpc.ok && db.ok && ipfs.ok && indexer.ok;
  const statusCode = ok ? 200 : 503;
  const payload = {
    ok,
    requestId: getRequestId(req),
    relayTxModeEnabled,
    checks: {
      rpc,
      db,
      ipfs,
      indexer,
    },
  };
  return res.status(statusCode).json(payload);
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


app.post("/api/pin", ...institutionPinGuard(authRateLimiter), pinRateLimiter, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const jwt = process.env.PINATA_JWT;
    if (!jwt) return res.status(500).json({ error: "PINATA_JWT not set" });

    const certId = normalizeCertId(req.body?.certId);
    const title = String(req.body?.title || "").trim();
    const recipient = String(req.body?.recipient || "").trim();
    const institutionName = String(req.body?.institutionName || "").trim();
    const replacesCertId = normalizeCertId(req.body?.replacesCertId);
    const versionRaw = Number(req.body?.version);
    const version = Number.isFinite(versionRaw) && versionRaw > 0 ? Math.floor(versionRaw) : 1;
    const requestOrigin = String(req.headers.origin || "").trim();
    const hasExplicitVerifyBase = Boolean(
      String(process.env.PUBLIC_VERIFY_BASE_URL || process.env.APP_VERIFY_BASE_URL || "").trim()
    );
    let appVerifyBaseUrl = String(
      process.env.PUBLIC_VERIFY_BASE_URL || process.env.APP_VERIFY_BASE_URL || ""
    ).trim();
    if (!appVerifyBaseUrl && requestOrigin) {
      appVerifyBaseUrl = `${requestOrigin.replace(/\/+$/, "")}/verify`;
    }
    if (!appVerifyBaseUrl) {
      const lanIp = getPreferredLanIpv4();
      appVerifyBaseUrl = lanIp ? `http://${lanIp}:5173/verify` : "http://localhost:5173/verify";
    }
    appVerifyBaseUrl = appVerifyBaseUrl.replace(/\/+$/, "");
    const verificationUrl = `${appVerifyBaseUrl}?certId=${encodeURIComponent(certId)}`;
    if (!hasExplicitVerifyBase && verificationUrl.includes("localhost")) {
      console.warn(
        "Verification URL uses localhost. Set PUBLIC_VERIFY_BASE_URL for mobile scanning."
      );
    }
    const sourceHash = `0x${sha256Hex(req.file.buffer)}`;
    const embeddedAtIso = new Date().toISOString();

    let pdfBytesForPinning = req.file.buffer;
    let pdfMetadataEmbedded = false;
    let pdfMetadataEmbedError = "";
    try {
      if (req.file.mimetype === "application/pdf") {
        pdfBytesForPinning = await embedVerificationMetadataInPdf(req.file.buffer, {
          certId,
          version,
          replacesCertId,
          sourceHash,
          embeddedAtIso,
        });
        pdfMetadataEmbedded = true;
      }
    } catch (embedErr: any) {
      pdfMetadataEmbedError = embedErr?.message || String(embedErr);
      console.warn("PDF metadata embedding failed, continuing with original file:", pdfMetadataEmbedError);
    }

    const plaintextPinnedHash = `0x${sha256Hex(pdfBytesForPinning)}`;
    const { encryptedBytes, summary: encryptedBlob } = encryptPinnedFile(pdfBytesForPinning);
    const encryptedFilenameBase = path.parse(req.file.originalname || "certificate").name || "certificate";
    const encryptedFilename = `${encryptedFilenameBase}.enc.bin`;
    const fileHash = sha256Hex(encryptedBytes);
    const fileCid = await pinBufferToIpfs(
      encryptedBytes,
      encryptedFilename,
      jwt,
      encryptedFilename
    );

    const metadataDoc = buildPublicPinnedMetadata({
      certId,
      fileHash: `0x${fileHash}`,
      version,
      replacesCertId,
    });
    const issueSummary: Record<string, unknown> = {
      certId,
      fileCid,
      fileHash: `0x${fileHash}`,
      plaintextPinnedHash,
      storageMode: "encrypted-blob",
      encryptionAlg: encryptedBlob.alg,
      fileEnvelopeFormat: encryptedBlob.format,
      encryptionKeyId: encryptedBlob.keyId,
      encryptedBlob,
      title,
      recipient,
      institutionName,
      sourceFileName: req.file.originalname,
      sourceFileType: req.file.mimetype,
      createdAt: embeddedAtIso,
      verificationUrl,
      sourceHash,
      pdfMetadataEmbedded,
      embeddedPdfMetadata: {
        certId,
        version,
        replacesCertId,
        sourceHash,
        embeddedAtIso,
      },
    };
    if (pdfMetadataEmbedError) {
      issueSummary.pdfMetadataEmbedError = pdfMetadataEmbedError;
    }

    const metadataCid = await pinJsonToIpfs(
      metadataDoc,
      jwt,
      `${certId || "certificate"}.metadata.json`
    );

    return res.json({
      metadataCid,
      fileCid,
      fileHash: `0x${fileHash}`,
      plaintextPinnedHash,
      verificationUrl,
      sourceHash,
      pdfMetadataEmbedded,
      pdfMetadataEmbedError: pdfMetadataEmbedError || null,
      storageMode: "encrypted-blob",
      encryptionAlg: encryptedBlob.alg,
      metadata: issueSummary,
      publicMetadata: metadataDoc,
      // Backward-compat alias
      cid: fileCid,
    });
  } catch (err: any) {
    const status = err?.response?.status;
    const details = err?.response?.data || err?.message || String(err);
    const isPinataFailure = Number.isInteger(status) && status > 0;

    console.error(isPinataFailure ? "Pinata upload failed. Status:" : "Pin/encryption failed. Status:", status);
    console.error("Details:", details);

    return res.status(500).json(
      isPinataFailure
        ? {
            error: "Pinata upload failed",
            status,
            details,
          }
        : {
            error: "Pin/encryption failed",
            details,
          }
    );
  }
});


app.get("/api/fetch/:cid", async (req, res) => {
  return res.status(403).json({
    error: "Raw file download is disabled on the public API",
    message: "Use an authenticated issuer workflow to access certificate files.",
  });
});


app.get("/api/verify/:certId", verifyRateLimiter, async (req, res) => {
  let metadataCidForError: string | undefined;

  try {
    const requestedCertId = normalizeCertId(toSingleString(req.params.certId));
    if (!requestedCertId) return res.status(400).json({ error: "certId is required" });
    const certIdCandidates = Array.from(
      new Set([requestedCertId, canonicalizeDemoCertId(requestedCertId)])
    );

    const rpcUrl = resolveRpcUrl();
    const contractAddress = loadDeploymentAddress();
    const provider = new JsonRpcProvider(rpcUrl);
    const contract = new Contract(contractAddress, CERTIFICATE_REGISTRY_ABI, provider);

    let certId = requestedCertId;
    let chainTuple:
      | [string, string, string, string, bigint, string, bigint, boolean, boolean]
      | null = null;
    let lastErr: unknown = null;
    for (const candidate of certIdCandidates) {
      try {
        chainTuple = (await contract.getFunction("getCertificate").staticCall(candidate)) as [
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
        const exists = Boolean(chainTuple[8]);
        if (!exists) {
          chainTuple = null;
          continue;
        }
        certId = candidate;
        break;
      } catch (err) {
        lastErr = err;
      }
    }
    if (!chainTuple) {
      if (lastErr) throw lastErr;
      return res.status(404).json({ error: "Certificate not found", certId: requestedCertId });
    }

    const [metadataCid, fileCidOnChain, onChainHash, issuer, version, replacesCertIdRaw, issuedAt, revoked] = chainTuple;
    const replacesCertId = normalizeCertId(replacesCertIdRaw);
    metadataCidForError = metadataCid;
    if (!String(metadataCid || "").trim()) {
      return res.status(422).json({
        error: "Certificate metadata CID is missing on-chain",
        certId,
      });
    }

    const metadata = await fetchCidJson<PinnedMetadata>(metadataCid);
    const rawMetadataFileHash = String(metadata?.fileHash || "").trim().toLowerCase();
    const metadataFileHash =
      rawMetadataFileHash && !rawMetadataFileHash.startsWith("0x")
        ? `0x${rawMetadataFileHash}`
        : rawMetadataFileHash;
    const storageMode = String(metadata?.storageMode || "encrypted-blob").trim() || "encrypted-blob";
    const encryptionAlg = String(metadata?.encryptionAlg || "aes-256-gcm").trim() || "aes-256-gcm";
    const resolvedFileCid = String(fileCidOnChain || "").trim();

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
      requestedCertId,
      exists: true,
      revoked: Boolean(revoked),
      metadataCid,
      storageMode,
      encryptionAlg,
      issuer,
      version: Number(version),
      replacesCertId,
      issuedAt: Number(issuedAt),
      onChainHash: String(onChainHash),
      computedHash,
      integrityMatch,
      metadataHashMatch,
      status: integrityMatch && !revoked ? "VALID" : revoked ? "REVOKED" : "TAMPERED",
    });
  } catch (err: any) {
    if (isCertificateNotFoundError(err)) {
      return res.status(404).json({
        certId: normalizeCertId(req.params.certId),
        exists: false,
        status: "NOT_FOUND",
      });
    }

    if (isRpcQuotaError(err)) {
      return res.status(503).json({
        error: "Verification temporarily unavailable",
        message: "RPC provider quota/rate limit reached. Please retry shortly.",
      });
    }

    if (err instanceof GatewayFetchError) {
      return res.status(502).json({
        error: "Gateway fetch failed during verification",
        certId: normalizeCertId(req.params.certId),
        metadataCid: metadataCidForError,
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

async function buildVerificationProof(certIdInput: string): Promise<{
  certId: string;
  status: "VALID" | "REVOKED" | "TAMPERED";
  verifiedAtIso: string;
  txHash: string;
  revokeTxHash: string | null;
  metadataCid: string;
  storageMode: string;
  encryptionAlg: string;
  onChainHash: string;
  computedHash: string;
  metadataFileHash: string | null;
  integrityMatch: boolean;
  metadataHashMatch: boolean | null;
  issuer: string;
  version: number;
  replacesCertId: string;
  issuedAt: number;
  revoked: boolean;
}> {
  const requestedCertId = normalizeCertId(certIdInput);
  if (!requestedCertId) {
    throw new Error("certId is required");
  }

  const certIdCandidates = Array.from(new Set([requestedCertId, canonicalizeDemoCertId(requestedCertId)]));
  const provider = new JsonRpcProvider(resolveRpcUrl());
  const contract = new Contract(loadDeploymentAddress(), CERTIFICATE_REGISTRY_ABI, provider);
  let certId = requestedCertId;
  let chainTuple:
    | [string, string, string, string, bigint, string, bigint, boolean, boolean]
    | null = null;
  for (const candidate of certIdCandidates) {
    try {
      const tuple = (await contract.getFunction("getCertificate").staticCall(candidate)) as [
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
      if (!tuple[8]) continue;
      certId = candidate;
      chainTuple = tuple;
      break;
    } catch {
      // Try next candidate.
    }
  }
  if (!chainTuple) {
    throw new Error("Certificate not found");
  }

  const [metadataCid, fileCidOnChain, onChainHash, issuer, version, replacesCertIdRaw, issuedAt, revoked] = chainTuple;
  const replacesCertId = normalizeCertId(replacesCertIdRaw);
  if (!String(metadataCid || "").trim()) {
    throw new Error("Certificate metadata CID is missing on-chain");
  }
  const metadata = await fetchCidJson<PinnedMetadata>(metadataCid);
  const rawMetadataFileHash = String(metadata?.fileHash || "").trim().toLowerCase();
  const metadataFileHash =
    rawMetadataFileHash && !rawMetadataFileHash.startsWith("0x")
      ? `0x${rawMetadataFileHash}`
      : rawMetadataFileHash || null;
  const storageMode = String(metadata?.storageMode || "encrypted-blob").trim() || "encrypted-blob";
  const encryptionAlg = String(metadata?.encryptionAlg || "aes-256-gcm").trim() || "aes-256-gcm";
  const resolvedFileCid = String(fileCidOnChain || "").trim();
  if (!resolvedFileCid) {
    throw new Error("Metadata missing fileCid and no on-chain fileCid available");
  }
  const fileBytes = await fetchCidBytes(resolvedFileCid);
  const computedHash = sha256Hex0x(fileBytes);
  const integrityMatch = computedHash.toLowerCase() === String(onChainHash).toLowerCase();
  const metadataHashMatch = metadataFileHash ? metadataFileHash === computedHash.toLowerCase() : null;
  const status = integrityMatch && !revoked ? "VALID" : revoked ? "REVOKED" : "TAMPERED";

  await ensureCertificateIndexFresh();
  const history = buildCertificateHistory(certId);
  const historyEntry = history?.chain.find((item) => item.certId === certId) || null;

  return {
    certId,
    status,
    verifiedAtIso: new Date().toISOString(),
    txHash: String(historyEntry?.issueTxHash || ""),
    revokeTxHash: historyEntry?.revokeTxHash || null,
    metadataCid: String(metadataCid || ""),
    storageMode,
    encryptionAlg,
    onChainHash: String(onChainHash || ""),
    computedHash,
    metadataFileHash,
    integrityMatch,
    metadataHashMatch,
    issuer: String(issuer || ""),
    version: Number(version || 0),
    replacesCertId,
    issuedAt: Number(issuedAt || 0),
    revoked: Boolean(revoked),
  };
}

app.get("/api/proof/:certId.json", async (req, res) => {
  try {
    const proof = await buildVerificationProof(toSingleString(req.params.certId));
    return res.json(proof);
  } catch (err: any) {
    if (isCertificateNotFoundError(err) || String(err?.message || "").toLowerCase().includes("not found")) {
      return res.status(404).json({ error: "Certificate not found" });
    }
    if (err instanceof GatewayFetchError) {
      return res.status(502).json({ error: "Gateway fetch failed", attempts: err.attempts });
    }
    return res.status(500).json({ error: "Proof generation failed", message: err?.message || String(err) });
  }
});

app.get("/api/proof/:certId.pdf", async (req, res) => {
  try {
    const proof = await buildVerificationProof(toSingleString(req.params.certId));
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const titleFont = await pdf.embedFont(StandardFonts.HelveticaBold);
    let y = 800;
    page.drawText("Certificate Verification Proof", {
      x: 40,
      y,
      size: 18,
      font: titleFont,
      color: rgb(0.1, 0.14, 0.2),
    });
    y -= 30;
    const lines: Array<[string, string]> = [
      ["Status", proof.status],
      ["certId", proof.certId],
      ["Issuer", proof.issuer],
      ["storageMode", proof.storageMode],
      ["encryptionAlg", proof.encryptionAlg],
      ["txHash", proof.txHash || "-"],
      ["revokeTxHash", proof.revokeTxHash || "-"],
      ["metadataCid", proof.metadataCid],
      ["onChainHash", proof.onChainHash],
      ["computedHash", proof.computedHash],
      ["metadataFileHash", proof.metadataFileHash || "-"],
      ["integrityMatch", String(proof.integrityMatch)],
      ["metadataHashMatch", String(proof.metadataHashMatch)],
      ["verifiedAt", proof.verifiedAtIso],
    ];
    for (const [label, value] of lines) {
      if (y < 50) break;
      page.drawText(`${label}: ${value}`, {
        x: 40,
        y,
        size: 10,
        font,
        color: rgb(0.15, 0.18, 0.22),
      });
      y -= 16;
    }
    const bytes = await pdf.save();
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${proof.certId}-verification-proof.pdf"`
    );
    return res.send(Buffer.from(bytes));
  } catch (err: any) {
    if (isCertificateNotFoundError(err) || String(err?.message || "").toLowerCase().includes("not found")) {
      return res.status(404).json({ error: "Certificate not found" });
    }
    if (err instanceof GatewayFetchError) {
      return res.status(502).json({ error: "Gateway fetch failed", attempts: err.attempts });
    }
    return res.status(500).json({ error: "Proof generation failed", message: err?.message || String(err) });
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

app.get("/api/indexer/status", async (_req, res) => {
  try {
    triggerCertificateIndexerRefreshIfNeeded();
    triggerIssuerIndexerRefreshIfNeeded();

    let latestBlock: number | null = null;
    try {
      const contract = getReadOnlyContract();
      latestBlock = await withTimeout(
        contract.runner!.provider!.getBlockNumber(),
        5000,
        "latestBlock timeout"
      );
    } catch {
      latestBlock = null;
    }

    return res.json({
      network: contractNetworkName,
      contractAddress: loadDeploymentAddress(),
      storage: useSupabaseIndexer ? "supabase" : "local-file",
      indexedCertificates: certificateIndexCache.size,
      lastIndexedBlock: certificateIndexLastIndexedBlock,
      indexedIssuers: issuerStatusCache.size,
      issuerLastIndexedBlock: issuerIndexLastIndexedBlock,
      latestBlock,
      lag: latestBlock === null ? null : Math.max(0, latestBlock - certificateIndexLastIndexedBlock),
      issuerLag: latestBlock === null ? null : Math.max(0, latestBlock - issuerIndexLastIndexedBlock),
      refreshedAt: new Date(certificateIndexLastUpdatedAtMs).toISOString(),
      issuerRefreshedAt: new Date(issuerIndexLastUpdatedAtMs).toISOString(),
      certificateSyncRunning: Boolean(certificateIndexSyncPromise || certificateIndexBootstrapPromise),
      issuerSyncRunning: Boolean(issuerIndexSyncPromise || issuerIndexBootstrapPromise),
      certificateLastError: certificateIndexLastError || null,
      issuerLastError: issuerIndexLastError || null,
      stateFile: certificateIndexStateFile,
    });
  } catch (err: any) {
    return res.status(500).json({
      error: "Indexer status failed",
      message: err?.message || String(err),
    });
  }
});

/**
 * Validate/backfill title + institution_name consistency between metadata JSON and stored rows.
 * Body (optional): { dryRun?: boolean, limit?: number }
 */
app.post("/api/indexer/backfill-metadata-labels", async (req, res) => {
  try {
    if (!useSupabaseIndexer) {
      return res.status(400).json({
        error: "Supabase indexer is not enabled",
        required: ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"],
      });
    }

    await ensureCertificateIndexFresh();
    const dryRun = Boolean(req.body?.dryRun);
    const limitRaw = Number(req.body?.limit);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : undefined;

    const report = await validateAndBackfillCertificateMetadataLabels(
      limit === undefined ? { dryRun } : { dryRun, limit }
    );

    return res.json({
      ok: true,
      ...report,
    });
  } catch (err: any) {
    console.error("Metadata label backfill/validation failed:", err?.message || String(err));
    return res.status(500).json({
      error: "Metadata label backfill/validation failed",
      message: err?.message || String(err),
    });
  }
});

app.get("/api/issuers", async (_req, res) => {
  try {
    triggerIssuerIndexerRefreshIfNeeded();
    const data = Array.from(issuerStatusCache.values()).sort((a, b) =>
      a.issuer.localeCompare(b.issuer)
    );
    return res.json({
      total: data.length,
      refreshedAt: new Date(issuerIndexLastUpdatedAtMs).toISOString(),
      syncRunning: Boolean(issuerIndexSyncPromise || issuerIndexBootstrapPromise),
      lastError: issuerIndexLastError || null,
      data,
    });
  } catch (err: any) {
    console.error("Issuer index failed:", err?.message || String(err));
    return res.status(500).json({
      error: "Issuer index failed",
      message: err?.message || String(err),
    });
  }
});

app.get("/api/issuers/:issuer/status", async (req, res) => {
  try {
    const issuer = normalizeAddress(toSingleString(req.params.issuer));
    if (!issuer) {
      return res.status(400).json({ error: "Invalid issuer address" });
    }
    const issuerLower = issuer.toLowerCase();
    const onChainAuthorized = await ensureAddressIsAuthorizedIssuer(issuerLower);
    const indexed = issuerStatusCache.get(issuerLower) || null;
    return res.json({
      issuer: issuerLower,
      onChainAuthorized,
      indexedAuthorized: indexed ? Boolean(indexed.isAuthorized) : null,
      indexedLastBlock: indexed?.lastBlockNumber || null,
      indexerRefreshedAt: new Date(issuerIndexLastUpdatedAtMs).toISOString(),
      indexerSyncRunning: Boolean(issuerIndexSyncPromise || issuerIndexBootstrapPromise),
      indexerLastError: issuerIndexLastError || null,
    });
  } catch (err: any) {
    console.error("Issuer status failed:", err?.message || String(err));
    return res.status(500).json({
      error: "Issuer status failed",
      message: err?.message || String(err),
    });
  }
});

app.post("/api/indexer/sync-issuers", async (_req, res) => {
  try {
    const started = !issuerIndexSyncPromise;
    if (started) {
      issuerIndexSyncPromise = rebuildIssuerIndexFromEvents()
        .catch((err: any) => {
          issuerIndexLastError = err?.message || String(err);
          console.error("Issuer index rebuild failed:", issuerIndexLastError);
        })
        .finally(() => {
          issuerIndexSyncPromise = null;
        });
    }
    return res.status(202).json({
      ok: true,
      started,
      syncRunning: true,
      indexedIssuers: issuerStatusCache.size,
      lastIndexedBlock: issuerIndexLastIndexedBlock,
      refreshedAt: new Date(issuerIndexLastUpdatedAtMs).toISOString(),
      lastError: issuerIndexLastError || null,
    });
  } catch (err: any) {
    console.error("Issuer index rebuild failed:", err?.message || String(err));
    return res.status(500).json({
      error: "Issuer index rebuild failed",
      message: err?.message || String(err),
    });
  }
});

/**
 * Force-upsert one certificate into index cache + persistent store.
 * Useful when provider log limits make full historical scanning slow.
 */
app.post("/api/indexer/upsert-cert", async (req, res) => {
  try {
    const certId = normalizeCertId(req.body?.certId);
    if (!certId) {
      return res.status(400).json({ error: "certId is required" });
    }
    const issueTxHash = String(req.body?.issueTxHash || "").trim();
    const title = String(req.body?.title || "").trim();
    const institutionName = String(req.body?.institutionName || "").trim();
    const issueBlockNumberRaw = Number(req.body?.issueBlockNumber);
    const issueBlockNumber =
      Number.isFinite(issueBlockNumberRaw) && issueBlockNumberRaw > 0
        ? Math.floor(issueBlockNumberRaw)
        : null;

    const contract = getReadOnlyContract();
    const entry = await loadCertificateEntryFromChain(contract, certId, {
      issueTxHash,
      issueBlockNumber,
    });
    entry.title = title;
    entry.institutionName = institutionName;
    if (!entry.issueTxHash) {
      return res.status(422).json({
        error: "issueTxHash is required to persist this schema",
        certId,
      });
    }
    certificateIndexCache.set(certId, entry);
    await persistCertificates([entry]);
    certificateIndexLastUpdatedAtMs = Date.now();

    return res.json({
      ok: true,
      certId,
      entry,
    });
  } catch (err: any) {
    if (isCertificateNotFoundError(err)) {
      return res.status(404).json({ error: "Certificate not found" });
    }
    console.error("Indexer upsert-cert failed:", err?.message || String(err));
    return res.status(500).json({
      error: "Indexer upsert-cert failed",
      message: err?.message || String(err),
    });
  }
});

/**
 * Full replacement/version chain for a certificate.
 * Example: CERT-DEMO-001 -> CERT-DEMO-003 -> CERT-DEMO-005
 */
app.get("/api/certificates/:certId/history", async (req, res) => {
  try {
    await ensureCertificateIndexFresh();
    const certId = normalizeCertId(toSingleString(req.params.certId));
    if (!certId) {
      return res.status(400).json({ error: "certId is required" });
    }

    const history = buildCertificateHistory(certId);
    if (!history) {
      return res.status(404).json({
        error: "Certificate not found",
        certId,
      });
    }

    const chainIds = history.chain.map((item) => item.certId);
    const requestedIndex = chainIds.indexOf(certId);

    return res.json({
      certId,
      rootCertId: history.rootCertId,
      chainLength: history.chain.length,
      chainIds,
      requestedIndex,
      chain: history.chain,
    });
  } catch (err: any) {
    console.error("Certificate history failed:", err?.message);
    return res.status(500).json({
      error: "Certificate history failed",
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
 *
 * Optional header: Idempotency-Key: <unique-client-key>
 */
app.post("/api/issue", async (req, res) => {
  let issueIdempotency: { key: string; fingerprint: string } | null = null;
  const respondIssue = (statusCode: number, body: unknown) => {
    if (issueIdempotency) {
      completeRelayIdempotency(
        issueIdempotency.key,
        issueIdempotency.fingerprint,
        statusCode,
        body
      );
    }
    return res.status(statusCode).json(body);
  };

  try {
    if (!requireRelayTxModeEnabled(res)) return;

    const auth = await ensureJwtAddressIsAuthorizedIssuer(req, res);
    if (!auth) return;

    const certId = normalizeCertId(req.body?.certId);
    const fileCid = String(req.body?.fileCid || "").trim();
    const fileHash = String(req.body?.fileHash || "").trim();
    const versionRaw = req.body?.version;
    const version = versionRaw === undefined || versionRaw === null ? 1 : Number(versionRaw);
    const replacesCertId = normalizeCertId(req.body?.replacesCertId);
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

    const idempotencyKey = getRelayIdempotencyKey(req, "issue");
    if (idempotencyKey) {
      const fingerprint = makeRelayIdempotencyFingerprint({
        operation: "issue",
        issuer: auth.address.toLowerCase(),
        certId,
        fileCid,
        fileHash: fileHash.toLowerCase(),
        version,
        replacesCertId,
        metadataCid: providedMetadataCid,
        metadata: metadataInput ?? null,
      });
      const idempotencyState = startRelayIdempotency(idempotencyKey, fingerprint);
      if (idempotencyState.kind === "replay") {
        return res.status(idempotencyState.statusCode).json(idempotencyState.body);
      }
      if (idempotencyState.kind === "conflict") {
        return res.status(409).json({ error: idempotencyState.message });
      }
      issueIdempotency = { key: idempotencyKey, fingerprint };
    }

    const readContract = getReadOnlyContract();
    try {
      await readContract.getFunction("getCertificate").staticCall(certId);
      return respondIssue(409, {
        error: "Certificate already exists",
        certId,
      });
    } catch (err) {
      if (!isCertificateNotFoundError(err)) {
        throw err;
      }
    }

    if (version > 1) {
      let replacedCert: [
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
      try {
        replacedCert = (await readContract.getFunction("getCertificate").staticCall(replacesCertId)) as [
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
      } catch (err) {
        if (isCertificateNotFoundError(err)) {
          return respondIssue(400, {
            error: "Replaced certificate not found",
            replacesCertId,
          });
        }
        throw err;
      }

      const replacedRevoked = replacedCert[7];
      const replacedIssuer = String(replacedCert[3] || "").toLowerCase();
      if (!replacedRevoked) {
        return respondIssue(400, {
          error: "Replaced certificate must be revoked before issuing a replacement",
          replacesCertId,
        });
      }
      if (replacedIssuer !== auth.address.toLowerCase()) {
        return respondIssue(403, {
          error: "Only original issuer can replace this certificate",
          replacesCertId,
        });
      }
    }

    const signer = createRelaySignerOrRespond(res);
    if (!signer) {
      if (issueIdempotency) {
        releaseRelayIdempotency(issueIdempotency.key, issueIdempotency.fingerprint);
      }
      return;
    }
    if (signer.address.toLowerCase() !== auth.address.toLowerCase()) {
      return respondIssue(403, {
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
        return respondIssue(500, {
          error: "PINATA_JWT is not configured and metadataCid was not provided",
        });
      }

      if (metadataInput && (typeof metadataInput !== "object" || Array.isArray(metadataInput))) {
        return respondIssue(400, {
          error: "metadata must be an object when provided",
        });
      }
      pinnedMetadata = buildPublicPinnedMetadata({
        certId,
        fileHash: fileHash.toLowerCase(),
        version,
        replacesCertId,
      });
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

    return respondIssue(200, {
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
    if (issueIdempotency) {
      releaseRelayIdempotency(issueIdempotency.key, issueIdempotency.fingerprint);
    }
    console.error("Issue failed:", err?.shortMessage || err?.message);
    const issueError = String(err?.shortMessage || err?.message || "");
    if (issueError.toLowerCase().includes("missing revert data")) {
      return res.status(400).json({
        error: "Transaction reverted. Check version/replacement rules and issuer permissions.",
      });
    }
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
 * Optional header: Idempotency-Key: <unique-client-key>
 */
app.post("/api/revoke", async (req, res) => {
  let revokeIdempotency: { key: string; fingerprint: string } | null = null;
  const respondRevoke = (statusCode: number, body: unknown) => {
    if (revokeIdempotency) {
      completeRelayIdempotency(
        revokeIdempotency.key,
        revokeIdempotency.fingerprint,
        statusCode,
        body
      );
    }
    return res.status(statusCode).json(body);
  };

  try {
    if (!requireRelayTxModeEnabled(res)) return;

    const auth = await ensureJwtAddressIsAuthorizedIssuer(req, res);
    if (!auth) return;

    const certId = normalizeCertId(req.body?.certId);
    if (!certId) {
      return res.status(400).json({
        error: "Missing required field",
        required: ["certId"],
      });
    }

    const idempotencyKey = getRelayIdempotencyKey(req, "revoke");
    if (idempotencyKey) {
      const fingerprint = makeRelayIdempotencyFingerprint({
        operation: "revoke",
        issuer: auth.address.toLowerCase(),
        certId,
      });
      const idempotencyState = startRelayIdempotency(idempotencyKey, fingerprint);
      if (idempotencyState.kind === "replay") {
        return res.status(idempotencyState.statusCode).json(idempotencyState.body);
      }
      if (idempotencyState.kind === "conflict") {
        return res.status(409).json({ error: idempotencyState.message });
      }
      revokeIdempotency = { key: idempotencyKey, fingerprint };
    }

    const signer = createRelaySignerOrRespond(res);
    if (!signer) {
      if (revokeIdempotency) {
        releaseRelayIdempotency(revokeIdempotency.key, revokeIdempotency.fingerprint);
      }
      return;
    }
    if (signer.address.toLowerCase() !== auth.address.toLowerCase()) {
      return respondRevoke(403, {
        error: "Authenticated wallet does not match backend issuer signer",
      });
    }

    const contractAddress = loadDeploymentAddress();
    const contract = new Contract(contractAddress, CERTIFICATE_REGISTRY_ABI, signer);

    const revokeCertificate = contract.getFunction("revokeCertificate");
    const tx = await revokeCertificate.send(certId);
    const receipt = await tx.wait();

    return respondRevoke(200, {
      ok: true,
      certId,
      issuer: signer.address,
      txHash: receipt?.hash ?? tx.hash,
      blockNumber: receipt?.blockNumber ?? null,
    });
  } catch (err: any) {
    if (revokeIdempotency) {
      releaseRelayIdempotency(revokeIdempotency.key, revokeIdempotency.fingerprint);
    }
    console.error("Revoke failed:", err?.shortMessage || err?.message);
    return res.status(500).json({
      error: "Revoke failed",
      message: err?.shortMessage || err?.message || String(err),
    });
  }
});

/**
 * Admin: add/remove issuer on-chain.
 * Requires JWT bearer auth, authorized issuer wallet, and backend signer must be contract owner.
 *
 * Body: { issuer: string, allowed: boolean }
 */
app.post("/api/admin/issuer", async (req, res) => {
  try {
    if (!requireRelayTxModeEnabled(res)) return;

    const auth = await ensureJwtAddressIsAuthorizedIssuer(req, res);
    if (!auth) return;

    const issuerRaw = String(req.body?.issuer || "").trim();
    const issuer = normalizeAddress(issuerRaw);
    const allowed = Boolean(req.body?.allowed);

    if (!issuer) {
      return res.status(400).json({ error: "Invalid issuer address" });
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

    const owner = String((await contract.getFunction("owner").staticCall()) as string).toLowerCase();
    if (owner !== signer.address.toLowerCase()) {
      return res.status(403).json({
        error: "Backend signer is not contract owner",
      });
    }

    const setIssuerFn = contract.getFunction("setIssuer");
    const tx = await setIssuerFn.send(issuer, allowed);
    const receipt = await tx.wait();

    return res.json({
      ok: true,
      issuer,
      allowed,
      txHash: receipt?.hash ?? tx.hash,
      blockNumber: receipt?.blockNumber ?? null,
    });
  } catch (err: any) {
    logEvent("error", "set_issuer_failed", {
      requestId: getRequestId(req),
      error: err?.shortMessage || err?.message || String(err),
    });
    return res.status(500).json({
      error: "Set issuer failed",
      message: err?.shortMessage || err?.message || String(err),
    });
  }
});

const port = Number(process.env.PORT || 5050);
app.listen(port, () => {
  logEvent("info", "backend_started", { port });
  ensureCertificateIndexFresh().catch((err: any) => {
    logEvent("error", "certificate_index_bootstrap_failed", {
      error: err?.message || String(err),
    });
  });
  ensureIssuerIndexFresh().catch((err: any) => {
    logEvent("error", "issuer_index_bootstrap_failed", {
      error: err?.message || String(err),
    });
  });
  startCertificateIndexerPolling();
});

app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
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
    logEvent("error", "unhandled_server_error", {
      requestId: getRequestId(req),
      error: err.message,
      stack: err.stack || "",
    });
    return res.status(500).json({ error: "Unhandled server error", message: err.message });
  }

  return res.status(500).json({ error: "Unhandled server error" });
});

