function isLoopbackHost(hostname) {
  const normalized = String(hostname || "").toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function resolveApiBase() {
  const configured = String(import.meta.env.VITE_API_BASE_URL || "").trim();
  const pageHost = typeof window !== "undefined" ? window.location.hostname : "localhost";

  if (!configured) {
    return `http://${pageHost}:5050`;
  }

  try {
    const parsed = new URL(configured);
    if (!isLoopbackHost(pageHost) && isLoopbackHost(parsed.hostname)) {
      parsed.hostname = pageHost;
    }
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return configured.replace(/\/+$/, "");
  }
}

const AUTH_STORAGE_KEY = "certchain_auth_session_v1";

export const API_BASE = resolveApiBase();
export const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || "0x5FbDB2315678afecb367f032d93F642f64180aa3";
export const RPC_URL = import.meta.env.VITE_RPC_URL || "http://127.0.0.1:8545";
export const REQUIRED_CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID || 31337);
export const REQUIRED_CHAIN_ID_HEX = `0x${REQUIRED_CHAIN_ID.toString(16)}`;
export const SITE_TITLE = "TrustMyCert - Decentralized Academic Verification";
export const CONTRACT_ABI = [
  "function issueCertificate(string certId, string metadataCid, string fileCid, bytes32 fileHash, uint256 version, string replacesCertId)",
  "function revokeCertificate(string certId)",
  "function setIssuer(address issuer, bool allowed)",
];

export async function apiJson(url, options = {}) {
  const { timeoutMs = 20000, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, { credentials: "include", ...fetchOptions, signal: controller.signal });
  } catch (err) {
    if (err?.name === "AbortError") {
      throw new Error("Request timed out. Please try again.");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }

  const text = await response.text();
  let parsed = {};
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }
  }

  if (!response.ok) {
    const parsedError = String(parsed.error || "").trim();
    const parsedMessage = String(parsed.message || "").trim();
    throw new Error(parsedError || parsedMessage || `HTTP ${response.status}`);
  }

  return parsed;
}

export function loadSession() {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed?.accessToken || !parsed?.user) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveSession(session) {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
}

export function clearSession() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
}

export function normalizeUserFacingError(err) {
  const candidates = [
    err?.shortMessage,
    err?.reason,
    err?.message,
    err?.info?.error?.message,
    err?.error?.message,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);

  const combined = `${candidates.join(" ")} ${String(err || "")}`.toLowerCase();

  if (
    combined.includes("issuer not authorised") ||
    combined.includes("issuer not authorized") ||
    combined.includes("wallet is not an authorized issuer") ||
    combined.includes("wallet is not an authorised issuer")
  ) {
    return "Issuer not authorized";
  }

  const raw = candidates[0] || String(err?.message || err || "").trim();
  return raw || "Request failed";
}

export function buildVerifyUrl(certId) {
  const safeId = normalizeCertId(certId);
  const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost:5173";
  return `${origin}/verify?certId=${encodeURIComponent(safeId)}`;
}

export function normalizeCertId(value) {
  return String(value || "").trim().toLowerCase();
}

export function extractCertIdFromScanInput(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    const queryCertId = normalizeCertId(parsed.searchParams.get("certId"));
    if (queryCertId) return queryCertId;
    const parts = parsed.pathname.split("/").filter(Boolean);
    const last = parts[parts.length - 1] || "";
    if (last.endsWith(".json") || last.endsWith(".pdf")) {
      return normalizeCertId(last.replace(/\.(json|pdf)$/i, ""));
    }
  } catch {
    // Treat as direct cert ID.
  }
  return normalizeCertId(raw);
}

export function institutionBrandFrom(inputName, issuer) {
  const name = String(inputName || "").trim() || "Institution";
  const initials = name
    .split(/\s+/)
    .slice(0, 2)
    .map((segment) => segment[0] || "")
    .join("")
    .toUpperCase() || "IN";
  const seed = String(issuer || name).toLowerCase();
  let hash = 0;
  for (let i = 0; i < seed.length; i += 1) hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
  const hueA = hash % 360;
  const hueB = (hueA + 48) % 360;
  return {
    name,
    initials,
    style: {
      background: `linear-gradient(135deg, hsl(${hueA} 72% 45%), hsl(${hueB} 68% 34%))`,
    },
  };
}

export function issuerRowsFromResponse(resp) {
  return Array.isArray(resp?.data) ? resp.data : [];
}

export async function listAllCertificatesByIssuer(authApi, issuerWallet) {
  const wallet = String(issuerWallet || "").trim().toLowerCase();
  if (!wallet) return [];
  const pageSize = 100;
  let page = 1;
  let totalPages = 1;
  const out = [];
  while (page <= totalPages) {
    const resp = await authApi(
      `/api/certificates?issuer=${encodeURIComponent(wallet)}&page=${page}&pageSize=${pageSize}`
    );
    const rows = Array.isArray(resp?.data) ? resp.data : [];
    out.push(...rows);
    totalPages = Math.max(1, Number(resp?.totalPages || 1));
    page += 1;
  }
  return out;
}

export function buildQrCodeImageUrl(data) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=240x240&margin=8&data=${encodeURIComponent(data)}`;
}

export function isLikelyPublicVerifyUrl(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") return false;
    if (/^10\./.test(host)) return false;
    if (/^192\.168\./.test(host)) return false;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}
