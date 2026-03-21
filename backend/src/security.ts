import crypto from "crypto";
import fs from "fs";
import path from "path";
import type express from "express";
import axios from "axios";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Contract, JsonRpcProvider, getAddress, verifyMessage } from "ethers";
import { z } from "zod";
import {
  canRecipientAccessCertificate,
  normalizeEmail,
  sanitizeDownloadFilename,
  toCertificatePrivateAccessRow,
  type CertificatePrivateAccessInput,
  type CertificatePrivateAccessRow,
} from "./certificate-private-access.js";
import {
  ENCRYPTED_FILE_MAGIC,
  decodeFileEncryptionKey,
  decryptPinnedFileWithKey,
} from "./file-envelope.js";
import { fetchCidBytes, sha256Hex0x } from "./ipfs-client.js";

type LogLevel = "info" | "warn" | "error";

function logEvent(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
  const payload = {
    ts: new Date().toISOString(),
    level,
    message,
    ...(fields || {}),
  };
  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
}

type Role = "MOE_ADMIN" | "INSTITUTION_ADMIN" | "INDIVIDUAL";
type InstitutionStatus = "PENDING" | "ACTIVE" | "SUSPENDED";

type AuthReq = express.Request & {
  auth?: { userId: string; role: Role; email: string };
};

type User = { id: string; email: string; password_hash: string; role: Role; email_verified: boolean };
type Institution = {
  id: string;
  name: string;
  status: InstitutionStatus;
  admin_email: string;
  issuer_wallet: string;
  authorization_request_status?: string | null;
  authorization_request_note?: string | null;
  authorization_requested_at?: string | null;
  authorization_request_resolved_at?: string | null;
};
type InstitutionUser = { user_id: string; institution_id: string; is_primary_admin: boolean };
type WalletBinding = { institution_id: string; wallet_address: string; verified: boolean; verified_at: string | null };
type CertificatePrivateAccess = CertificatePrivateAccessRow;
type RefreshToken = { user_id: string; token_hash: string; expires_at: string; revoked_at: string | null };
type AuthorizationRequestStatus = "PENDING" | "APPROVED" | "REJECTED" | "CANCELLED";
type AuthorizationRequest = {
  id: string;
  institution_id: string;
  requester_user_id: string | null;
  issuer_wallet: string;
  status: AuthorizationRequestStatus;
  note: string | null;
  resolved_by_user_id: string | null;
  resolved_at: string | null;
  created_at?: string | null;
};
type PasswordResetToken = {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: string;
  used_at: string | null;
};

const ACCESS_TTL_SEC = Number(process.env.JWT_ACCESS_TTL_SEC || 900);
const REFRESH_TTL_SEC = Number(process.env.JWT_REFRESH_TTL_SEC || 604800);
const nonceTtlMs = Number(process.env.AUTH_NONCE_TTL_MS || 5 * 60 * 1000);
const loginTrackWindowMs = Number(process.env.AUTH_LOGIN_TRACK_WINDOW_MS || 30 * 60 * 1000);
const loginDelayStartAfterFailures = Number(process.env.AUTH_LOGIN_DELAY_START_AFTER || 2);
const loginDelayBaseMs = Number(process.env.AUTH_LOGIN_DELAY_BASE_MS || 250);
const loginDelayMaxMs = Number(process.env.AUTH_LOGIN_DELAY_MAX_MS || 5000);
const loginLockoutThreshold = Number(process.env.AUTH_LOGIN_LOCKOUT_THRESHOLD || 8);
const loginLockoutMs = Number(process.env.AUTH_LOGIN_LOCKOUT_MS || 15 * 60 * 1000);
const emailSendQueueMaxAttempts = Math.max(1, Number(process.env.EMAIL_SEND_QUEUE_MAX_ATTEMPTS || 6));
const emailSendQueueBaseDelayMs = Math.max(200, Number(process.env.EMAIL_SEND_QUEUE_BASE_DELAY_MS || 1000));
const emailSendQueueMaxDelayMs = Math.max(emailSendQueueBaseDelayMs, Number(process.env.EMAIL_SEND_QUEUE_MAX_DELAY_MS || 60000));
const emailSendQueueTickMs = Math.max(250, Number(process.env.EMAIL_SEND_QUEUE_TICK_MS || 2000));
const passwordResetTtlMs = Math.max(5 * 60 * 1000, Number(process.env.PASSWORD_RESET_TTL_MS || 30 * 60 * 1000));

const CERT_ABI = [
  "function authorizedIssuers(address issuer) view returns (bool)",
  "function getCertificate(string certId) view returns (string metadataCid, string fileCid, bytes32 fileHash, address issuer, uint256 version, string replacesCertId, uint256 issuedAt, bool revoked, bool exists)",
];
const walletNonceByKey = new Map<string, { nonce: string; expiresAt: number }>();
const failedLoginByEmail = new Map<string, { failCount: number; firstFailedAt: number; lastFailedAt: number; lockedUntil: number }>();
const emailSendQueue = new Map<
  string,
  {
    input: { to: string; inviteUrl: string; institutionName: string };
    attempts: number;
    nextRunAt: number;
    lastError: string;
  }
>();
let emailSendWorkerStarted = false;
let emailSendFlushPromise: Promise<void> | null = null;

function accessSecret(): string {
  return (process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET || "").trim();
}

function refreshSecret(): string {
  return (process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || "").trim();
}

function supabaseUrl(): string {
  return (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
}

function serviceKey(): string {
  return (process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
}

function workspaceRoot(): string {
  return path.resolve(process.cwd());
}

function resolveContractAddress(): string {
  const direct = (process.env.CERTIFICATE_REGISTRY_ADDRESS || "").trim();
  if (direct) return direct;

  const deploymentsFile = path.join(workspaceRoot(), "contracts", "deployments.json");
  if (!fs.existsSync(deploymentsFile)) return "";

  const networkName = (process.env.CONTRACT_NETWORK_NAME || "localhost").trim();
  const deployments = JSON.parse(fs.readFileSync(deploymentsFile, "utf8")) as Record<
    string,
    { CertificateRegistry?: string }
  >;
  return String(deployments?.[networkName]?.CertificateRegistry || "").trim();
}

function resolveRpcUrl(): string {
  const direct = (process.env.RPC_URL || "").trim();
  if (direct) return direct;

  const networkName = (process.env.CONTRACT_NETWORK_NAME || "localhost").trim().toLowerCase();
  if (networkName === "sepolia") {
    const sepolia = (process.env.SEPOLIA_RPC_URL || "").trim();
    if (sepolia) return sepolia;
  }

  return "http://127.0.0.1:8545";
}

function authDomain(): string {
  return process.env.AUTH_DOMAIN || "localhost";
}

function authUri(): string {
  return process.env.AUTH_URI || "http://localhost:5050";
}

function authChainId(): string {
  return process.env.AUTH_CHAIN_ID || "11155111";
}

function resendApiKey(): string {
  return (process.env.RESEND_API_KEY || "").trim();
}

function resendFromEmail(): string {
  return (process.env.RESEND_FROM_EMAIL || "").trim();
}

function inviteSubjectPrefix(): string {
  return (process.env.INVITE_EMAIL_SUBJECT_PREFIX || "CertChain").trim();
}

function passwordResetUrlBase(): string {
  const raw = String(process.env.PASSWORD_RESET_URL_BASE || "").trim();
  if (raw) return raw.replace(/\/+$/, "");
  return `${authUri().replace(/\/+$/, "")}/reset-password`;
}

function refreshCookieName(): string {
  return (process.env.AUTH_REFRESH_COOKIE_NAME || "tmc_refresh").trim();
}

function refreshCookieSecure(): boolean {
  return String(process.env.AUTH_REFRESH_COOKIE_SECURE || "").trim().toLowerCase() === "true";
}

function refreshCookieSameSite(): "lax" | "strict" | "none" {
  const raw = String(process.env.AUTH_REFRESH_COOKIE_SAMESITE || "lax").trim().toLowerCase();
  if (raw === "strict" || raw === "none") return raw;
  return "lax";
}

function refreshCookieDomain(): string | undefined {
  const d = String(process.env.AUTH_REFRESH_COOKIE_DOMAIN || "").trim();
  return d || undefined;
}

function emailQueueKey(input: { to: string; inviteUrl: string; institutionName: string }): string {
  return `${input.to.toLowerCase()}|${sha256(input.inviteUrl)}|${sha256(input.institutionName.toLowerCase())}`;
}

async function sendInviteEmailNow(input: { to: string; inviteUrl: string; institutionName: string }): Promise<void> {
  const key = resendApiKey();
  const from = resendFromEmail();
  if (!key || !from) throw new Error("RESEND_API_KEY/RESEND_FROM_EMAIL not configured");
  const subject = `${inviteSubjectPrefix()} institution invite`;
  const html =
    `<p>You have been invited to administer <strong>${input.institutionName}</strong> on CertChain.</p>` +
    `<p>Open this link to accept your invite and set your password:</p>` +
    `<p><a href="${input.inviteUrl}">${input.inviteUrl}</a></p>` +
    "<p>This invite expires in 7 days.</p>";
  await axios.post(
    "https://api.resend.com/emails",
    { from, to: [input.to], subject, html },
    {
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
    },
  );
}

function enqueueInviteEmail(input: { to: string; inviteUrl: string; institutionName: string }, error: string): void {
  const k = emailQueueKey(input);
  const existing = emailSendQueue.get(k);
  emailSendQueue.set(k, {
    input,
    attempts: existing?.attempts || 0,
    nextRunAt: Date.now(),
    lastError: error,
  });
}

async function flushEmailSendQueue(): Promise<void> {
  if (emailSendFlushPromise) return emailSendFlushPromise;
  emailSendFlushPromise = (async () => {
    const now = Date.now();
    const due = Array.from(emailSendQueue.entries()).filter(([, item]) => item.nextRunAt <= now);
    for (const [k, item] of due) {
      try {
        await sendInviteEmailNow(item.input);
        emailSendQueue.delete(k);
        logEvent("info", "invite_email_queue_sent", {
          to: item.input.to,
          remaining: emailSendQueue.size,
        });
      } catch (e: any) {
        const attempts = item.attempts + 1;
        const errMsg = e?.response?.data?.message || e?.message || "Resend send failed";
        if (attempts >= emailSendQueueMaxAttempts) {
          emailSendQueue.delete(k);
          logEvent("error", "invite_email_queue_drop", {
            to: item.input.to,
            attempts,
            error: errMsg,
          });
          continue;
        }
        const delay = Math.min(
          emailSendQueueMaxDelayMs,
          emailSendQueueBaseDelayMs * Math.pow(2, attempts - 1)
        );
        emailSendQueue.set(k, {
          input: item.input,
          attempts,
          nextRunAt: Date.now() + delay,
          lastError: errMsg,
        });
        logEvent("warn", "invite_email_queue_retry", {
          to: item.input.to,
          attempts,
          delayMs: delay,
          error: errMsg,
        });
      }
    }
  })().finally(() => {
    emailSendFlushPromise = null;
  });
  return emailSendFlushPromise;
}

function ensureEmailSendWorker(): void {
  if (emailSendWorkerStarted) return;
  emailSendWorkerStarted = true;
  setInterval(() => {
    void flushEmailSendQueue();
  }, emailSendQueueTickMs);
}

async function sendInviteEmail(input: { to: string; inviteUrl: string; institutionName: string }): Promise<{ sent: boolean; error?: string; queued?: boolean }> {
  ensureEmailSendWorker();
  let lastError = "";
  const immediateAttempts = Math.min(3, emailSendQueueMaxAttempts);
  for (let i = 0; i < immediateAttempts; i += 1) {
    try {
      await sendInviteEmailNow(input);
      return { sent: true };
    } catch (e: any) {
      lastError = e?.response?.data?.message || e?.message || "Resend send failed";
      const delay = Math.min(emailSendQueueMaxDelayMs, emailSendQueueBaseDelayMs * Math.pow(2, i));
      if (i < immediateAttempts - 1) {
        await sleep(delay);
      }
    }
  }
  enqueueInviteEmail(input, lastError || "Resend send failed");
  return { sent: false, queued: true, error: lastError || "Resend send failed (queued for retry)" };
}

async function sendPasswordResetEmail(input: { to: string; resetUrl: string }): Promise<void> {
  const key = resendApiKey();
  const from = resendFromEmail();
  if (!key || !from) {
    logEvent("warn", "password_reset_email_skipped", {
      reason: "RESEND_API_KEY/RESEND_FROM_EMAIL not configured",
      to: input.to,
    });
    return;
  }

  const subject = `${inviteSubjectPrefix()} password reset`;
  const html =
    "<p>We received a request to reset your password on TrustMyCert.</p>" +
    `<p>Open this link to set a new password:</p><p><a href="${input.resetUrl}">${input.resetUrl}</a></p>` +
    "<p>This link expires shortly. If you did not request this, you can ignore this email.</p>";

  await axios.post(
    "https://api.resend.com/emails",
    { from, to: [input.to], subject, html },
    {
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
    },
  );
}

function guardConfig(): void {
  if (!supabaseUrl() || !serviceKey()) throw new Error("SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY required");
  if (!accessSecret() || !refreshSecret()) throw new Error("JWT_ACCESS_SECRET + JWT_REFRESH_SECRET required");
}

function dbHeaders(prefer?: string): Record<string, string> {
  const h: Record<string, string> = {
    apikey: serviceKey(),
    Authorization: `Bearer ${serviceKey()}`,
    "Content-Type": "application/json",
  };
  if (prefer) h.Prefer = prefer;
  return h;
}

async function db<T>(o: { method: "GET" | "POST" | "PATCH" | "DELETE"; table: string; params?: Record<string, string>; body?: unknown; prefer?: string }): Promise<T> {
  guardConfig();
  const u = new URL(`${supabaseUrl()}/rest/v1/${o.table}`);
  for (const [k, v] of Object.entries(o.params || {})) u.searchParams.set(k, v);
  const r = await axios.request<T>({
    method: o.method,
    url: u.toString(),
    headers: dbHeaders(o.prefer),
    data: o.body,
    validateStatus: (s) => s >= 200 && s < 300,
  });
  return r.data;
}

function isMissingPrivateAccessTableError(err: unknown): boolean {
  const status = Number((err as any)?.response?.status || 0);
  const url = String((err as any)?.config?.url || "");
  return status === 404 && url.includes("/certificate_private_access");
}

async function audit(input: { actorUserId?: string | null; actorWallet?: string | null; action: string; entityType: string; entityId?: string | null; metadata?: Record<string, unknown> }): Promise<void> {
  try {
    await db({
      method: "POST",
      table: "audit_logs",
      body: [{ actor_user_id: input.actorUserId || null, actor_wallet: input.actorWallet || null, action: input.action, entity_type: input.entityType, entity_id: input.entityId || null, metadata: input.metadata || {} }],
      prefer: "return=minimal",
    });
  } catch (e: any) {
    logEvent("error", "audit_log_failed", { error: e?.message || String(e) });
  }
}

function sha256(v: string): string {
  return crypto.createHash("sha256").update(v, "utf8").digest("hex");
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getFailedLoginState(email: string): { failCount: number; firstFailedAt: number; lastFailedAt: number; lockedUntil: number } | null {
  const k = email.trim().toLowerCase();
  if (!k) return null;
  const s = failedLoginByEmail.get(k) || null;
  if (!s) return null;
  const now = Date.now();
  if (s.lastFailedAt + loginTrackWindowMs < now && s.lockedUntil <= now) {
    failedLoginByEmail.delete(k);
    return null;
  }
  return s;
}

function computeLoginDelayMs(failCount: number): number {
  if (failCount <= loginDelayStartAfterFailures) return 0;
  const extraFailures = failCount - loginDelayStartAfterFailures - 1;
  const raw = loginDelayBaseMs * Math.pow(2, Math.max(0, extraFailures));
  return Math.min(loginDelayMaxMs, Math.max(0, Math.floor(raw)));
}

function getLoginThrottle(email: string): { lockedUntil: number; delayMs: number } {
  const s = getFailedLoginState(email);
  if (!s) return { lockedUntil: 0, delayMs: 0 };
  const now = Date.now();
  if (s.lockedUntil > now) return { lockedUntil: s.lockedUntil, delayMs: 0 };
  return { lockedUntil: 0, delayMs: computeLoginDelayMs(s.failCount) };
}

function recordFailedLogin(email: string): { failCount: number; lockedUntil: number } {
  const k = email.trim().toLowerCase();
  const now = Date.now();
  const s = getFailedLoginState(k);
  const next = s
    ? {
        failCount: s.failCount + 1,
        firstFailedAt: s.firstFailedAt,
        lastFailedAt: now,
        lockedUntil: s.lockedUntil,
      }
    : {
        failCount: 1,
        firstFailedAt: now,
        lastFailedAt: now,
        lockedUntil: 0,
      };

  if (next.failCount >= loginLockoutThreshold) {
    next.lockedUntil = now + loginLockoutMs;
  }
  failedLoginByEmail.set(k, next);
  return { failCount: next.failCount, lockedUntil: next.lockedUntil };
}

function clearFailedLogin(email: string): void {
  const k = email.trim().toLowerCase();
  if (!k) return;
  failedLoginByEmail.delete(k);
}

function normAddr(v: string): string | null {
  try {
    return getAddress(v);
  } catch {
    return null;
  }
}

function bearer(req: express.Request): string {
  const a = req.header("authorization") || "";
  return a.startsWith("Bearer ") ? a.slice(7).trim() : "";
}

function parseCookies(req: express.Request): Record<string, string> {
  const raw = String(req.header("cookie") || "");
  if (!raw) return {};
  const out: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

function refreshTokenFromRequest(req: express.Request): string {
  const bodyToken = String(req.body?.refreshToken || "").trim();
  if (bodyToken) return bodyToken;
  const cookies = parseCookies(req);
  return String(cookies[refreshCookieName()] || "").trim();
}

function setRefreshCookie(res: express.Response, refreshToken: string): void {
  res.cookie(refreshCookieName(), refreshToken, {
    httpOnly: true,
    secure: refreshCookieSecure(),
    sameSite: refreshCookieSameSite(),
    domain: refreshCookieDomain(),
    path: "/api/auth",
    maxAge: REFRESH_TTL_SEC * 1000,
  });
}

function clearRefreshCookie(res: express.Response): void {
  res.clearCookie(refreshCookieName(), {
    httpOnly: true,
    secure: refreshCookieSecure(),
    sameSite: refreshCookieSameSite(),
    domain: refreshCookieDomain(),
    path: "/api/auth",
  });
}

function signToken(payload: { sub: string; role: Role; email: string; tokenType: "access" | "refresh" }): string {
  const secret = payload.tokenType === "access" ? accessSecret() : refreshSecret();
  const exp = payload.tokenType === "access" ? ACCESS_TTL_SEC : REFRESH_TTL_SEC;
  return jwt.sign(payload, secret, { expiresIn: exp });
}

function verifyToken(token: string, type: "access" | "refresh"): { sub: string; role: Role; email: string } {
  const secret = type === "access" ? accessSecret() : refreshSecret();
  const p = jwt.verify(token, secret) as jwt.JwtPayload;
  if (String(p.tokenType || "") !== type) throw new Error("wrong token type");
  return { sub: String(p.sub || ""), role: String(p.role || "") as Role, email: String(p.email || "") };
}

function auth(req: AuthReq, res: express.Response, next: express.NextFunction): void {
  try {
    const t = bearer(req);
    if (!t) return void res.status(401).json({ error: "Missing bearer token" });
    const c = verifyToken(t, "access");
    req.auth = { userId: c.sub, role: c.role, email: c.email };
    next();
  } catch {
    res.status(401).json({ error: "Invalid/expired access token" });
  }
}

function roles(...allowed: Role[]) {
  return (req: AuthReq, res: express.Response, next: express.NextFunction): void => {
    if (!req.auth) return void res.status(401).json({ error: "Not authenticated" });
    if (!allowed.includes(req.auth.role)) return void res.status(403).json({ error: "Insufficient role" });
    next();
  };
}

async function userByEmail(email: string): Promise<User | null> {
  const rows = await db<User[]>({ method: "GET", table: "users", params: { select: "*", email: `eq.${email.toLowerCase()}`, limit: "1" } });
  return rows[0] || null;
}

async function userById(id: string): Promise<User | null> {
  const rows = await db<User[]>({ method: "GET", table: "users", params: { select: "*", id: `eq.${id}`, limit: "1" } });
  return rows[0] || null;
}

async function hasMoeAdmin(): Promise<boolean> {
  const rows = await db<User[]>({
    method: "GET",
    table: "users",
    params: {
      select: "id",
      role: "eq.MOE_ADMIN",
      limit: "1",
    },
  });
  return rows.length > 0;
}

async function institutionCtx(userId: string): Promise<{ institution: Institution; mapping: InstitutionUser; binding: WalletBinding | null } | null> {
  const mappings = await db<InstitutionUser[]>({ method: "GET", table: "institution_users", params: { select: "*", user_id: `eq.${userId}`, limit: "1" } });
  const m = mappings[0];
  if (!m) return null;
  const inst = await db<Institution[]>({ method: "GET", table: "institutions", params: { select: "*", id: `eq.${m.institution_id}`, limit: "1" } });
  const i = inst[0];
  if (!i) return null;
  const binds = await db<WalletBinding[]>({ method: "GET", table: "wallet_bindings", params: { select: "*", institution_id: `eq.${i.id}`, verified: "eq.true", order: "verified_at.desc", limit: "1" } });
  return { institution: i, mapping: m, binding: binds[0] || null };
}

async function certificatePrivateAccessByCertId(certId: string): Promise<CertificatePrivateAccess | null> {
  const normalizedCertId = normalizeCertId(certId);
  if (!normalizedCertId) return null;
  try {
    const rows = await db<CertificatePrivateAccess[]>({
      method: "GET",
      table: "certificate_private_access",
      params: {
        select: "*",
        cert_id: `eq.${normalizedCertId}`,
        limit: "1",
      },
    });
    return rows[0] || null;
  } catch (err) {
    if (isMissingPrivateAccessTableError(err)) {
      logEvent("warn", "certificate_private_access_table_missing", {
        certId: normalizedCertId,
      });
      return null;
    }
    throw err;
  }
}

export async function persistCertificatePrivateAccess(
  input: CertificatePrivateAccessInput
): Promise<boolean> {
  const row = toCertificatePrivateAccessRow(input);
  try {
    await db({
      method: "POST",
      table: "certificate_private_access",
      params: { on_conflict: "cert_id" },
      body: [row],
      prefer: "resolution=merge-duplicates,return=minimal",
    });
    return true;
  } catch (err) {
    if (isMissingPrivateAccessTableError(err)) {
      logEvent("warn", "certificate_private_access_table_missing", {
        certId: row.cert_id,
        institutionId: row.institution_id || null,
      });
      return false;
    }
    throw err;
  }
}

function loadFileEncryptionKey(): Buffer {
  return decodeFileEncryptionKey(String(process.env.FILE_ENCRYPTION_KEY || ""));
}

function buildCertificateDownloadFilename(
  certId: string,
  accessRow: CertificatePrivateAccess | null
): string {
  const sourceName = String(accessRow?.source_file_name || "").trim();
  const title = String(accessRow?.title || "").trim();
  const base =
    (sourceName ? path.parse(sourceName).name : "") ||
    title ||
    certId;
  return `${sanitizeDownloadFilename(base, certId)}.pdf`;
}

function isEncryptedFileEnvelope(buffer: Buffer): boolean {
  return buffer.length >= ENCRYPTED_FILE_MAGIC.length
    && buffer.subarray(0, ENCRYPTED_FILE_MAGIC.length).equals(ENCRYPTED_FILE_MAGIC);
}

function looksLikePdf(buffer: Buffer): boolean {
  return buffer.length >= 5 && buffer.subarray(0, 5).toString("utf8") === "%PDF-";
}

function isCertificateNotFoundError(err: unknown): boolean {
  const message = String((err as any)?.shortMessage || (err as any)?.message || err || "").toLowerCase();
  return message.includes("certificate not found");
}

async function onchainAuthorized(wallet: string): Promise<boolean> {
  const rpc = resolveRpcUrl();
  const caddr = resolveContractAddress();
  if (!rpc || !caddr) return false;
  const c = new Contract(caddr, CERT_ABI, new JsonRpcProvider(rpc));
  return (await c.getFunction("authorizedIssuers").staticCall(wallet)) as boolean;
}

async function gateInstitutionAction(req: AuthReq, res: express.Response): Promise<{ user: User; institution: Institution; wallet: string } | null> {
  if (!req.auth) return null;
  const user = await userById(req.auth.userId);
  if (!user) {
    res.status(401).json({ error: "User not found" });
    return null;
  }
  const ctx = await institutionCtx(user.id);
  if (!ctx) {
    res.status(403).json({ error: "No institution mapping" });
    return null;
  }
  if (ctx.institution.status !== "ACTIVE") {
    res.status(403).json({ error: "Institution not ACTIVE" });
    return null;
  }
  const wRaw = String(req.body?.connectedWallet || req.header("x-wallet-address") || "").trim();
  const w = normAddr(wRaw);
  if (!w) {
    res.status(400).json({ error: "connectedWallet required" });
    return null;
  }
  if (w.toLowerCase() !== ctx.institution.issuer_wallet.toLowerCase()) {
    res.status(403).json({ error: "Wallet mismatch with issuer_wallet" });
    return null;
  }
  if (!ctx.binding || !ctx.binding.verified || ctx.binding.wallet_address.toLowerCase() !== w.toLowerCase()) {
    res.status(403).json({ error: "Wallet not bound/verified" });
    return null;
  }
  if (!(await onchainAuthorized(w))) {
    res.status(403).json({ error: "Wallet not authorized on-chain" });
    return null;
  }
  return { user, institution: ctx.institution, wallet: w.toLowerCase() };
}

async function issueTokens(user: User): Promise<{ accessToken: string; refreshToken: string }> {
  const accessToken = signToken({ sub: user.id, role: user.role, email: user.email, tokenType: "access" });
  const refreshToken = signToken({ sub: user.id, role: user.role, email: user.email, tokenType: "refresh" });
  await db({
    method: "POST",
    table: "refresh_tokens",
    body: [{ user_id: user.id, token_hash: sha256(refreshToken), expires_at: new Date(Date.now() + REFRESH_TTL_SEC * 1000).toISOString() }],
    prefer: "return=minimal",
  });
  return { accessToken, refreshToken };
}

const zRegister = z.object({
  email: z.string().email().transform((v) => v.toLowerCase()),
  password: z.string().min(8).max(128),
  role: z.enum(["MOE_ADMIN", "INDIVIDUAL", "INSTITUTION_ADMIN"]).optional(),
  bootstrapSecret: z.string().min(8).optional(),
});
const zLogin = zRegister;
const zRefresh = z.object({ refreshToken: z.string().min(20).optional() });
const zAcceptInvite = z.object({ token: z.string().min(16), password: z.string().min(8).max(128) });
const zForgotPassword = z.object({ email: z.string().email().transform((v) => v.toLowerCase()) });
const zResetPassword = z.object({ token: z.string().min(16), password: z.string().min(8).max(128) });
const zChangePassword = z.object({
  currentPassword: z.string().min(8).max(128),
  newPassword: z.string().min(8).max(128),
});
const zCreateInstitution = z.object({ name: z.string().min(2).max(200), adminEmail: z.string().email().transform((v) => v.toLowerCase()), issuerWallet: z.string().min(42).max(42) });
const zStatus = z.object({ status: z.enum(["ACTIVE", "SUSPENDED"]) });
const zResend = z.object({ email: z.string().email().transform((v) => v.toLowerCase()).optional() });
const zWalletNonce = z.object({ walletAddress: z.string().min(42).max(42) });
const zWalletVerify = z.object({ walletAddress: z.string().min(42).max(42), nonce: z.string().min(8), signature: z.string().min(20) });
const zAuthorizationRequestCreate = z.object({ note: z.string().max(500).optional() });

export function institutionPinGuard(authLimiter: express.RequestHandler): express.RequestHandler[] {
  return [
    authLimiter,
    auth,
    roles("INSTITUTION_ADMIN"),
    async (req: AuthReq, res: express.Response, next: express.NextFunction) => {
      const gate = await gateInstitutionAction(req, res);
      if (!gate) {
        await audit({ actorUserId: req.auth?.userId || null, actorWallet: String(req.body?.connectedWallet || "").toLowerCase() || null, action: "PIN_ATTEMPT_BLOCKED", entityType: "institution", metadata: { reason: "PIN_GUARD_FAILED" } });
        return;
      }
      next();
    },
  ];
}

export function registerSecurityRoutes(app: express.Express, authLimiter: express.RequestHandler): void {
  app.post("/api/auth/register", authLimiter, async (req, res) => {
    try {
      const b = zRegister.parse(req.body || {});
      if (await userByEmail(b.email)) return res.status(409).json({ error: "Email already registered" });
      const role = b.role || "INDIVIDUAL";
      if (role === "INSTITUTION_ADMIN") {
        return res.status(400).json({ error: "Institution admins must onboard via invitation" });
      }
      if (role === "MOE_ADMIN") {
        const existingMoe = await hasMoeAdmin();
        const bootstrap = (process.env.MOE_BOOTSTRAP_SECRET || "").trim();
        const provided = String(b.bootstrapSecret || "").trim();
        const allowFirstWithoutSecret = !existingMoe;
        const allowedBySecret = Boolean(bootstrap) && provided === bootstrap;
        if (!allowFirstWithoutSecret && !allowedBySecret) {
          return res.status(403).json({ error: "MoE bootstrap secret required" });
        }
      }
      const users = await db<User[]>({
        method: "POST",
        table: "users",
        body: [{ email: b.email, password_hash: await bcrypt.hash(b.password, 12), role, email_verified: role === "MOE_ADMIN" }],
        prefer: "return=representation",
      });
      const u = users[0];
      if (!u) return res.status(500).json({ error: "Registration failed" });
      const t = await issueTokens(u);
      await audit({ actorUserId: u.id, action: `AUTH_REGISTER_${u.role}`, entityType: "user", entityId: u.id });
      setRefreshCookie(res, t.refreshToken);
      return res.status(201).json({ accessToken: t.accessToken, user: { id: u.id, email: u.email, role: u.role, emailVerified: u.email_verified } });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid register payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/login", authLimiter, async (req, res) => {
    try {
      const b = zLogin.parse(req.body || {});
      const throttle = getLoginThrottle(b.email);
      if (throttle.lockedUntil > Date.now()) {
        const retryAfterSec = Math.max(1, Math.ceil((throttle.lockedUntil - Date.now()) / 1000));
        res.setHeader("Retry-After", String(retryAfterSec));
        return res.status(429).json({ error: "Too many failed login attempts. Try again later." });
      }
      if (throttle.delayMs > 0) {
        await sleep(throttle.delayMs);
      }

      const u = await userByEmail(b.email);
      if (!u || !(await bcrypt.compare(b.password, u.password_hash))) {
        const failure = recordFailedLogin(b.email);
        if (failure.lockedUntil > Date.now()) {
          const retryAfterSec = Math.max(1, Math.ceil((failure.lockedUntil - Date.now()) / 1000));
          res.setHeader("Retry-After", String(retryAfterSec));
          return res.status(429).json({ error: "Too many failed login attempts. Try again later." });
        }
        return res.status(401).json({ error: "Invalid credentials" });
      }
      clearFailedLogin(b.email);
      const t = await issueTokens(u);
      await audit({ actorUserId: u.id, action: "AUTH_LOGIN", entityType: "user", entityId: u.id });
      setRefreshCookie(res, t.refreshToken);
      return res.json({ accessToken: t.accessToken, user: { id: u.id, email: u.email, role: u.role, emailVerified: u.email_verified } });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid login payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/refresh", authLimiter, async (req, res) => {
    try {
      const b = zRefresh.parse(req.body || {});
      const refreshToken = String(b.refreshToken || refreshTokenFromRequest(req) || "").trim();
      if (!refreshToken) return res.status(401).json({ error: "Missing refresh token" });
      const c = verifyToken(refreshToken, "refresh");
      const rows = await db<RefreshToken[]>({
        method: "GET",
        table: "refresh_tokens",
        params: { select: "*", user_id: `eq.${c.sub}`, token_hash: `eq.${sha256(refreshToken)}`, revoked_at: "is.null", limit: "1" },
      });
      const rt = rows[0];
      if (!rt || new Date(rt.expires_at).getTime() < Date.now()) return res.status(401).json({ error: "Invalid refresh token" });
      await db({ method: "PATCH", table: "refresh_tokens", params: { user_id: `eq.${c.sub}`, token_hash: `eq.${sha256(refreshToken)}` }, body: { revoked_at: new Date().toISOString() }, prefer: "return=minimal" });
      const u = await userById(c.sub);
      if (!u) return res.status(401).json({ error: "User not found" });
      const t = await issueTokens(u);
      setRefreshCookie(res, t.refreshToken);
      return res.json({ accessToken: t.accessToken });
    } catch {
      return res.status(401).json({ error: "Invalid refresh token" });
    }
  });

  app.post("/api/auth/logout", authLimiter, async (req, res) => {
    try {
      const b = zRefresh.parse(req.body || {});
      const refreshToken = String(b.refreshToken || refreshTokenFromRequest(req) || "").trim();
      if (refreshToken) {
        await db({ method: "PATCH", table: "refresh_tokens", params: { token_hash: `eq.${sha256(refreshToken)}`, revoked_at: "is.null" }, body: { revoked_at: new Date().toISOString() }, prefer: "return=minimal" });
      }
      clearRefreshCookie(res);
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid logout payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/forgot-password", authLimiter, async (req, res) => {
    try {
      const b = zForgotPassword.parse(req.body || {});
      const u = await userByEmail(b.email);
      if (u) {
        await db({
          method: "PATCH",
          table: "password_reset_tokens",
          params: { user_id: `eq.${u.id}`, used_at: "is.null" },
          body: { used_at: new Date().toISOString() },
          prefer: "return=minimal",
        });
        const token = crypto.randomBytes(24).toString("hex");
        const expiresAt = new Date(Date.now() + passwordResetTtlMs).toISOString();
        await db({
          method: "POST",
          table: "password_reset_tokens",
          body: [{ user_id: u.id, token_hash: sha256(token), expires_at: expiresAt }],
          prefer: "return=minimal",
        });
        const resetUrl = `${passwordResetUrlBase()}?token=${encodeURIComponent(token)}`;
        try {
          await sendPasswordResetEmail({ to: u.email, resetUrl });
        } catch (e: any) {
          logEvent("error", "password_reset_email_failed", {
            userId: u.id,
            email: u.email,
            error: e?.response?.data?.message || e?.message || String(e),
          });
        }
        await audit({ actorUserId: u.id, action: "AUTH_FORGOT_PASSWORD_REQUESTED", entityType: "user", entityId: u.id });
      }
      return res.json({ ok: true, message: "If an account exists for that email, a reset link has been sent." });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid forgot password payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/reset-password", authLimiter, async (req, res) => {
    try {
      const b = zResetPassword.parse(req.body || {});
      const tokenHash = sha256(b.token);
      const rows = await db<PasswordResetToken[]>({
        method: "GET",
        table: "password_reset_tokens",
        params: { select: "*", token_hash: `eq.${tokenHash}`, limit: "1" },
      });
      const row = rows[0];
      if (!row || row.used_at || new Date(row.expires_at).getTime() < Date.now()) {
        return res.status(400).json({ error: "Invalid or expired reset token" });
      }
      const u = await userById(row.user_id);
      if (!u) return res.status(400).json({ error: "Invalid or expired reset token" });
      const nextHash = await bcrypt.hash(b.password, 12);
      await db({
        method: "PATCH",
        table: "users",
        params: { id: `eq.${u.id}` },
        body: { password_hash: nextHash },
        prefer: "return=minimal",
      });
      await db({
        method: "PATCH",
        table: "password_reset_tokens",
        params: { id: `eq.${row.id}` },
        body: { used_at: new Date().toISOString() },
        prefer: "return=minimal",
      });
      await db({
        method: "PATCH",
        table: "refresh_tokens",
        params: { user_id: `eq.${u.id}`, revoked_at: "is.null" },
        body: { revoked_at: new Date().toISOString() },
        prefer: "return=minimal",
      });
      clearFailedLogin(u.email);
      await audit({ actorUserId: u.id, action: "AUTH_PASSWORD_RESET", entityType: "user", entityId: u.id });
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid reset password payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/change-password", authLimiter, auth, async (req: AuthReq, res) => {
    try {
      const b = zChangePassword.parse(req.body || {});
      if (b.currentPassword === b.newPassword) {
        return res.status(400).json({ error: "New password must be different from current password" });
      }
      const u = await userById(req.auth!.userId);
      if (!u) return res.status(401).json({ error: "User not found" });
      const valid = await bcrypt.compare(b.currentPassword, u.password_hash);
      if (!valid) return res.status(401).json({ error: "Current password is incorrect" });
      const nextHash = await bcrypt.hash(b.newPassword, 12);
      await db({
        method: "PATCH",
        table: "users",
        params: { id: `eq.${u.id}` },
        body: { password_hash: nextHash },
        prefer: "return=minimal",
      });
      await db({
        method: "PATCH",
        table: "password_reset_tokens",
        params: { user_id: `eq.${u.id}`, used_at: "is.null" },
        body: { used_at: new Date().toISOString() },
        prefer: "return=minimal",
      });
      await audit({ actorUserId: u.id, action: "AUTH_PASSWORD_CHANGED", entityType: "user", entityId: u.id });
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid change password payload", details: e?.message || String(e) });
    }
  });

  app.get("/api/auth/me", auth, async (req: AuthReq, res) => {
    const u = await userById(req.auth!.userId);
    if (!u) return res.status(401).json({ error: "User not found" });
    const ctx = u.role === "INSTITUTION_ADMIN" ? await institutionCtx(u.id) : null;
    return res.json({
      id: u.id,
      email: u.email,
      role: u.role,
      emailVerified: u.email_verified,
      institution: ctx
        ? {
            id: ctx.institution.id,
            name: ctx.institution.name,
            status: ctx.institution.status,
            issuerWallet: ctx.institution.issuer_wallet,
            walletBound: Boolean(ctx.binding?.verified),
            boundWallet: ctx.binding?.wallet_address || null,
          }
        : null,
    });
  });

  app.post("/api/auth/invitations/accept", authLimiter, async (req, res) => {
    try {
      const b = zAcceptInvite.parse(req.body || {});
      const invRows = await db<Array<{ id: string; institution_id: string; email: string; token_hash: string; expires_at: string; used_at: string | null }>>({
        method: "GET",
        table: "invitations",
        params: { select: "*", token_hash: `eq.${sha256(b.token)}`, limit: "1" },
      });
      const inv = invRows[0];
      if (!inv || inv.used_at || new Date(inv.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "Invalid invite" });
      let u = await userByEmail(inv.email);
      const ph = await bcrypt.hash(b.password, 12);
      if (!u) {
        const created = await db<User[]>({ method: "POST", table: "users", body: [{ email: inv.email, password_hash: ph, role: "INSTITUTION_ADMIN", email_verified: true }], prefer: "return=representation" });
        u = created[0] || null;
      } else {
        await db({ method: "PATCH", table: "users", params: { id: `eq.${u.id}` }, body: { password_hash: ph, role: "INSTITUTION_ADMIN", email_verified: true }, prefer: "return=minimal" });
      }
      if (!u) return res.status(500).json({ error: "Invite accept failed" });
      await db({ method: "POST", table: "institution_users", body: [{ user_id: u.id, institution_id: inv.institution_id, is_primary_admin: true }], prefer: "resolution=ignore-duplicates,return=minimal" });
      await db({ method: "PATCH", table: "invitations", params: { id: `eq.${inv.id}` }, body: { used_at: new Date().toISOString() }, prefer: "return=minimal" });
      await audit({ actorUserId: u.id, action: "INSTITUTION_INVITE_ACCEPTED", entityType: "institution", entityId: inv.institution_id });
      const t = await issueTokens(u);
      setRefreshCookie(res, t.refreshToken);
      return res.json({ ok: true, accessToken: t.accessToken });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid invite payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/moe/institutions", auth, roles("MOE_ADMIN"), async (req: AuthReq, res) => {
    try {
      const b = zCreateInstitution.parse(req.body || {});
      const wallet = normAddr(b.issuerWallet);
      if (!wallet) return res.status(400).json({ error: "Invalid issuerWallet" });
      const rows = await db<Institution[]>({ method: "POST", table: "institutions", body: [{ name: b.name, status: "PENDING", admin_email: b.adminEmail, issuer_wallet: wallet.toLowerCase() }], prefer: "return=representation" });
      const inst = rows[0];
      if (!inst) return res.status(500).json({ error: "Institution create failed" });
      const token = crypto.randomBytes(24).toString("hex");
      await db({ method: "POST", table: "invitations", body: [{ institution_id: inst.id, email: b.adminEmail, token_hash: sha256(token), expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() }], prefer: "return=minimal" });
      const inviteUrl = `${authUri().replace(/\/+$/, "")}/invite?token=${token}`;
      const mail = await sendInviteEmail({ to: b.adminEmail, inviteUrl, institutionName: inst.name });
      await audit({ actorUserId: req.auth!.userId, action: "MOE_INSTITUTION_CREATED", entityType: "institution", entityId: inst.id, metadata: { issuerWallet: inst.issuer_wallet, adminEmail: inst.admin_email } });
      return res.status(201).json({ institution: inst, inviteToken: token, inviteUrl, emailSent: mail.sent, emailQueued: Boolean(mail.queued), emailError: mail.error || null });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid institution payload", details: e?.message || String(e) });
    }
  });

  app.patch("/api/moe/institutions/:id/status", auth, roles("MOE_ADMIN"), async (req: AuthReq, res) => {
    try {
      const b = zStatus.parse(req.body || {});
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ error: "Institution id required" });
      await db({ method: "PATCH", table: "institutions", params: { id: `eq.${id}` }, body: { status: b.status }, prefer: "return=minimal" });
      await audit({ actorUserId: req.auth!.userId, action: "MOE_INSTITUTION_STATUS_CHANGED", entityType: "institution", entityId: id, metadata: { status: b.status } });
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid status payload", details: e?.message || String(e) });
    }
  });

  app.delete("/api/moe/institutions/:id", auth, roles("MOE_ADMIN"), async (req: AuthReq, res) => {
    try {
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ error: "Institution id required" });
      const existing = await db<Institution[]>({ method: "GET", table: "institutions", params: { select: "id,name", id: `eq.${id}`, limit: "1" } });
      if (!existing[0]) return res.status(404).json({ error: "Institution not found" });
      await db({ method: "DELETE", table: "institutions", params: { id: `eq.${id}` }, prefer: "return=minimal" });
      await audit({ actorUserId: req.auth!.userId, action: "MOE_INSTITUTION_DELETED", entityType: "institution", entityId: id, metadata: { name: existing[0].name } });
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid delete payload", details: e?.message || String(e) });
    }
  });

  app.get("/api/moe/institutions", auth, roles("MOE_ADMIN"), async (_req, res) => {
    const rows = await db<Institution[]>({ method: "GET", table: "institutions", params: { select: "*", order: "created_at.desc" } });
    return res.json({ data: rows });
  });

  app.get("/api/moe/authorization-requests", auth, roles("MOE_ADMIN"), async (req, res) => {
    const status = String(req.query.status || "").trim().toUpperCase();
    const params: Record<string, string> = {
      select: "id,name,issuer_wallet,authorization_request_status,authorization_request_note,authorization_requested_at",
      order: "authorization_requested_at.desc",
    };
    if (status) params.authorization_request_status = `eq.${status}`;
    const rows = await db<Institution[]>({
      method: "GET",
      table: "institutions",
      params,
    });
    return res.json({
      data: rows
        .filter((row) => String(row?.authorization_request_status || "").trim())
        .map((row) => ({
          id: `${row.id}:institution-request`,
          institution_id: row.id,
          issuer_wallet: row.issuer_wallet,
          status: row.authorization_request_status,
          note: row.authorization_request_note || null,
          created_at: row.authorization_requested_at || null,
          institution_name: row.name,
        })),
    });
  });

  app.post("/api/moe/institutions/:id/authorization-requests/approve", auth, roles("MOE_ADMIN"), async (req: AuthReq, res) => {
    try {
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ error: "Institution id required" });
      await db({
        method: "PATCH",
        table: "institutions",
        params: {
          id: `eq.${id}`,
        },
        body: {
          authorization_request_status: "APPROVED",
          authorization_request_resolved_at: new Date().toISOString(),
        },
        prefer: "return=minimal",
      });
      await db({
        method: "PATCH",
        table: "authorization_requests",
        params: {
          institution_id: `eq.${id}`,
          status: "eq.PENDING",
        },
        body: {
          status: "APPROVED",
          resolved_by_user_id: req.auth!.userId,
          resolved_at: new Date().toISOString(),
        },
        prefer: "return=minimal",
      }).catch(() => {});
      await audit({
        actorUserId: req.auth!.userId,
        action: "MOE_AUTHORIZATION_REQUEST_APPROVED",
        entityType: "institution",
        entityId: id,
      });
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Failed to approve authorization requests", details: e?.message || String(e) });
    }
  });

  app.post("/api/moe/institutions/:id/resend-invite", auth, roles("MOE_ADMIN"), async (req: AuthReq, res) => {
    try {
      const b = zResend.parse(req.body || {});
      const id = String(req.params.id || "").trim();
      const inst = (await db<Institution[]>({ method: "GET", table: "institutions", params: { select: "*", id: `eq.${id}`, limit: "1" } }))[0];
      if (!inst) return res.status(404).json({ error: "Institution not found" });
      const email = b.email || inst.admin_email;
      const token = crypto.randomBytes(24).toString("hex");
      await db({ method: "POST", table: "invitations", body: [{ institution_id: inst.id, email, token_hash: sha256(token), expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() }], prefer: "return=minimal" });
      const inviteUrl = `${authUri().replace(/\/+$/, "")}/invite?token=${token}`;
      const mail = await sendInviteEmail({ to: email, inviteUrl, institutionName: inst.name });
      await audit({ actorUserId: req.auth!.userId, action: "MOE_INSTITUTION_INVITE_RESENT", entityType: "institution", entityId: inst.id, metadata: { email } });
      return res.json({ ok: true, inviteToken: token, inviteUrl, emailSent: mail.sent, emailQueued: Boolean(mail.queued), emailError: mail.error || null });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid resend payload", details: e?.message || String(e) });
    }
  });

  app.get("/api/institution/profile", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    const ctx = await institutionCtx(req.auth!.userId);
    if (!ctx) return res.status(403).json({ error: "No institution mapping" });
    return res.json({
      institution: { id: ctx.institution.id, name: ctx.institution.name, status: ctx.institution.status, adminEmail: ctx.institution.admin_email, issuerWallet: ctx.institution.issuer_wallet },
      binding: { verified: Boolean(ctx.binding?.verified), walletAddress: ctx.binding?.wallet_address || null, verifiedAt: ctx.binding?.verified_at || null },
    });
  });

  app.get("/api/institution/authorization-requests/latest", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    const ctx = await institutionCtx(req.auth!.userId);
    if (!ctx) return res.status(403).json({ error: "No institution mapping" });
    if (String(ctx.institution.authorization_request_status || "").trim()) {
      return res.json({
        request: {
          id: `${ctx.institution.id}:institution-request`,
          institution_id: ctx.institution.id,
          requester_user_id: req.auth!.userId,
          issuer_wallet: ctx.institution.issuer_wallet,
          status: ctx.institution.authorization_request_status,
          note: ctx.institution.authorization_request_note || null,
          resolved_by_user_id: null,
          resolved_at: ctx.institution.authorization_request_resolved_at || null,
          created_at: ctx.institution.authorization_requested_at || null,
        },
      });
    }
    const rows = await db<AuthorizationRequest[]>({
      method: "GET",
      table: "authorization_requests",
      params: {
        select: "*",
        institution_id: `eq.${ctx.institution.id}`,
        order: "created_at.desc",
        limit: "1",
      },
    });
    return res.json({ request: rows[0] || null });
  });

  app.post("/api/institution/authorization-requests", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    try {
      const b = zAuthorizationRequestCreate.parse(req.body || {});
      const ctx = await institutionCtx(req.auth!.userId);
      if (!ctx) return res.status(403).json({ error: "No institution mapping" });

      const issuerWallet = String(ctx.institution.issuer_wallet || "").trim().toLowerCase();
      if (!issuerWallet) return res.status(400).json({ error: "Institution issuer wallet is missing" });
      if (await onchainAuthorized(issuerWallet)) {
        return res.status(409).json({ error: "Institution wallet is already authorized on-chain" });
      }

      if (String(ctx.institution.authorization_request_status || "").trim().toUpperCase() === "PENDING") {
        return res.status(409).json({
          error: "A pending authorization request already exists",
          request: {
            id: `${ctx.institution.id}:institution-request`,
            institution_id: ctx.institution.id,
            requester_user_id: req.auth!.userId,
            issuer_wallet: issuerWallet,
            status: "PENDING",
            note: ctx.institution.authorization_request_note || null,
            resolved_by_user_id: null,
            resolved_at: ctx.institution.authorization_request_resolved_at || null,
            created_at: ctx.institution.authorization_requested_at || null,
          },
        });
      }

      const existing = await db<AuthorizationRequest[]>({
        method: "GET",
        table: "authorization_requests",
        params: {
          select: "*",
          institution_id: `eq.${ctx.institution.id}`,
          status: "eq.PENDING",
          order: "created_at.desc",
          limit: "1",
        },
      });
      if (existing[0]) {
        return res.status(409).json({ error: "A pending authorization request already exists", request: existing[0] });
      }

      const requestedAt = new Date().toISOString();
      await db({
        method: "PATCH",
        table: "institutions",
        params: { id: `eq.${ctx.institution.id}` },
        body: {
          authorization_request_status: "PENDING",
          authorization_request_note: String(b.note || "").trim() || null,
          authorization_requested_at: requestedAt,
          authorization_request_resolved_at: null,
        },
        prefer: "return=minimal",
      });

      const created = await db<AuthorizationRequest[]>({
        method: "POST",
        table: "authorization_requests",
        body: [{
          institution_id: ctx.institution.id,
          requester_user_id: req.auth!.userId,
          issuer_wallet: issuerWallet,
          status: "PENDING",
          note: String(b.note || "").trim() || null,
        }],
        prefer: "return=representation",
      }).catch(() => []);
      await audit({
        actorUserId: req.auth!.userId,
        actorWallet: ctx.binding?.wallet_address || null,
        action: "INSTITUTION_AUTHORIZATION_REQUESTED",
        entityType: "institution",
        entityId: ctx.institution.id,
        metadata: { issuerWallet, note: String(b.note || "").trim() || null },
      });
      logEvent("info", "institution_authorization_request_created", {
        institutionId: ctx.institution.id,
        requesterUserId: req.auth!.userId,
        issuerWallet,
      });
      return res.status(201).json({
        ok: true,
        request: created[0] || {
          id: `${ctx.institution.id}:institution-request`,
          institution_id: ctx.institution.id,
          requester_user_id: req.auth!.userId,
          issuer_wallet: issuerWallet,
          status: "PENDING",
          note: String(b.note || "").trim() || null,
          resolved_by_user_id: null,
          resolved_at: null,
          created_at: requestedAt,
        },
      });
    } catch (e: any) {
      logEvent("error", "institution_authorization_request_failed", {
        error: e?.message || String(e),
        details: e?.response?.data || null,
      });
      return res.status(400).json({ error: "Invalid authorization request payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/institution/wallet/nonce", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    try {
      const b = zWalletNonce.parse(req.body || {});
      const ctx = await institutionCtx(req.auth!.userId);
      if (!ctx) return res.status(403).json({ error: "No institution mapping" });
      if (ctx.institution.status !== "ACTIVE") return res.status(403).json({ error: "Institution must be ACTIVE" });
      const w = normAddr(b.walletAddress);
      if (!w) return res.status(400).json({ error: "Invalid wallet" });
      if (w.toLowerCase() !== ctx.institution.issuer_wallet.toLowerCase()) return res.status(403).json({ error: "Wallet mismatch with issuer_wallet" });
      const nonce = crypto.randomBytes(16).toString("hex");
      const key = `${req.auth!.userId}:${ctx.institution.id}:${w.toLowerCase()}`;
      walletNonceByKey.set(key, { nonce, expiresAt: Date.now() + nonceTtlMs });
      const message = [`${authDomain()} wants you to bind wallet for institution access.`, "", `URI: ${authUri()}`, "Version: 1", `Chain ID: ${authChainId()}`, `Institution ID: ${ctx.institution.id}`, `Wallet: ${w.toLowerCase()}`, `Nonce: ${nonce}`].join("\n");
      return res.json({ nonce, walletAddress: w, message });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid wallet nonce payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/institution/wallet/verify-signature", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    try {
      const b = zWalletVerify.parse(req.body || {});
      const ctx = await institutionCtx(req.auth!.userId);
      if (!ctx) return res.status(403).json({ error: "No institution mapping" });
      const w = normAddr(b.walletAddress);
      if (!w || w.toLowerCase() !== ctx.institution.issuer_wallet.toLowerCase()) return res.status(403).json({ error: "Wallet mismatch with issuer_wallet" });
      const key = `${req.auth!.userId}:${ctx.institution.id}:${w.toLowerCase()}`;
      const rec = walletNonceByKey.get(key);
      if (!rec || rec.nonce !== b.nonce || rec.expiresAt < Date.now()) return res.status(401).json({ error: "Invalid/expired nonce" });
      const msg = [`${authDomain()} wants you to bind wallet for institution access.`, "", `URI: ${authUri()}`, "Version: 1", `Chain ID: ${authChainId()}`, `Institution ID: ${ctx.institution.id}`, `Wallet: ${w.toLowerCase()}`, `Nonce: ${rec.nonce}`].join("\n");
      const recovered = normAddr(verifyMessage(msg, b.signature));
      if (!recovered || recovered.toLowerCase() !== w.toLowerCase()) return res.status(401).json({ error: "Signature verification failed" });
      walletNonceByKey.delete(key);
      await db({ method: "POST", table: "wallet_bindings", params: { on_conflict: "institution_id,wallet_address" }, body: [{ institution_id: ctx.institution.id, wallet_address: w.toLowerCase(), verified: true, verified_at: new Date().toISOString() }], prefer: "resolution=merge-duplicates,return=minimal" });
      await audit({ actorUserId: req.auth!.userId, actorWallet: w.toLowerCase(), action: "INSTITUTION_WALLET_BOUND", entityType: "institution", entityId: ctx.institution.id });
      return res.json({ ok: true, verified: true, wallet: w.toLowerCase() });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid wallet verify payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/certificates/issue", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    const gate = await gateInstitutionAction(req, res);
    if (!gate) {
      await audit({ actorUserId: req.auth?.userId || null, actorWallet: String(req.body?.connectedWallet || "").toLowerCase() || null, action: "CERT_ISSUE_ATTEMPT_FAILED", entityType: "certificate", entityId: normalizeCertId(req.body?.certId), metadata: { reason: "GATE_CHECK_FAILED" } });
      return;
    }
    const certId = normalizeCertId(req.body?.certId);
    const txHash = String(req.body?.txHash || "").trim() || null;
    const metadataCid = String(req.body?.metadataCid || "").trim() || null;
    const fileCid = String(req.body?.fileCid || "").trim() || null;
    const title = String(req.body?.title || "").trim() || null;
    const recipientName = String(req.body?.recipient || "").trim() || null;
    const recipientEmail = normalizeEmail(req.body?.recipientEmail) || null;
    const sourceFileName = String(req.body?.sourceFileName || "").trim() || null;
    const sourceFileType = String(req.body?.sourceFileType || "").trim() || null;
    const shouldPersistPrivateAccess = Boolean(certId && (txHash || metadataCid || fileCid || recipientEmail));
    let privateAccessStored = false;

    if (shouldPersistPrivateAccess) {
      privateAccessStored = await persistCertificatePrivateAccess({
        certId,
        institutionId: gate.institution.id,
        issuerWallet: gate.wallet,
        title,
        recipientName,
        recipientEmail,
        metadataCid,
        fileCid,
        issueTx: txHash,
        sourceFileName,
        sourceFileType,
        issuedByUserId: gate.user.id,
      });
    }

    await audit({
      actorUserId: gate.user.id,
      actorWallet: gate.wallet,
      action: "CERT_ISSUE_ATTEMPT_ALLOWED",
      entityType: "certificate",
      entityId: certId,
      metadata: {
        txHash,
        metadataCid,
        fileCid,
        recipientEmail,
        privateAccessStored,
      },
    });
    return res.json({
      ok: true,
      allowed: true,
      mode: "wallet-native",
      message: "Authorized. Submit issue tx via MetaMask.",
      privateAccessStored,
    });
  });

  app.get("/api/certificates/:certId/download", auth, roles("MOE_ADMIN", "INSTITUTION_ADMIN", "INDIVIDUAL"), async (req: AuthReq, res) => {
    const requestedCertId = normalizeCertId(req.params.certId);
    if (!requestedCertId) {
      return res.status(400).json({ error: "certId is required" });
    }
    const certIdCandidates = Array.from(
      new Set([requestedCertId, canonicalizeDemoCertId(requestedCertId)])
    );

    let certId = requestedCertId;

    let accessRow: CertificatePrivateAccess | null = null;
    let actorWallet: string | null = null;

    try {
      const user = await userById(req.auth!.userId);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      const contractAddress = resolveContractAddress();
      if (!contractAddress) {
        return res.status(500).json({ error: "Certificate registry address is not configured" });
      }
      const provider = new JsonRpcProvider(resolveRpcUrl());
      const contract = new Contract(contractAddress, CERT_ABI, provider);

      let chainTuple:
        | [string, string, string, string, bigint, string, bigint, boolean, boolean]
        | null = null;
      let lastErr: unknown = null;
      for (const candidate of certIdCandidates) {
        accessRow = await certificatePrivateAccessByCertId(candidate);
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
          if (!chainTuple || !chainTuple[8]) {
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
        if (lastErr && !isCertificateNotFoundError(lastErr)) {
          throw lastErr;
        }
        return res.status(404).json({ error: "Certificate not found", certId: requestedCertId });
      }

      const [, fileCidOnChain, onChainHash, issuer] = chainTuple;
      const issuerWallet = String(issuer || "").trim().toLowerCase();
      const resolvedFileCid = String(fileCidOnChain || accessRow?.file_cid || "").trim();
      if (!resolvedFileCid) {
        return res.status(422).json({ error: "Certificate file CID is missing", certId });
      }

      if (req.auth!.role === "INSTITUTION_ADMIN") {
        const ctx = await institutionCtx(user.id);
        if (!ctx) {
          return res.status(403).json({ error: "No institution mapping" });
        }
        if (ctx.institution.status !== "ACTIVE") {
          return res.status(403).json({ error: "Institution not ACTIVE" });
        }
        actorWallet = String(ctx.binding?.wallet_address || ctx.institution.issuer_wallet || "").trim().toLowerCase() || null;
        const institutionMatches =
          Boolean(accessRow?.institution_id) && accessRow!.institution_id === ctx.institution.id;
        const issuerMatches = Boolean(issuerWallet) && issuerWallet === ctx.institution.issuer_wallet.toLowerCase();
        if (!institutionMatches && !issuerMatches) {
          await audit({
            actorUserId: user.id,
            actorWallet,
            action: "CERT_DOWNLOAD_DENIED",
            entityType: "certificate",
            entityId: certId,
            metadata: { role: user.role, reason: "INSTITUTION_SCOPE_MISMATCH" },
          });
          return res.status(403).json({ error: "You are not allowed to download this certificate" });
        }
      } else if (req.auth!.role === "INDIVIDUAL") {
        if (!accessRow?.recipient_email) {
          await audit({
            actorUserId: user.id,
            action: "CERT_DOWNLOAD_DENIED",
            entityType: "certificate",
            entityId: certId,
            metadata: { role: user.role, reason: "RECIPIENT_EMAIL_NOT_LINKED" },
          });
          return res.status(403).json({
            error: "This certificate is not linked to a student email yet. Ask the issuer or MoE to backfill recipientEmail for this certificate.",
          });
        }
        if (!canRecipientAccessCertificate(user.email, accessRow)) {
          await audit({
            actorUserId: user.id,
            action: "CERT_DOWNLOAD_DENIED",
            entityType: "certificate",
            entityId: certId,
            metadata: { role: user.role, reason: "RECIPIENT_EMAIL_MISMATCH" },
          });
          return res.status(403).json({
            error: "This certificate is linked to a different student email address.",
          });
        }
      }

      const encryptedBytes = await fetchCidBytes(resolvedFileCid);
      const computedHash = sha256Hex0x(encryptedBytes);
      if (computedHash.toLowerCase() !== String(onChainHash || "").toLowerCase()) {
        return res.status(409).json({
          error: "Certificate file integrity mismatch",
          certId,
        });
      }

      const decryptedBytes = isEncryptedFileEnvelope(encryptedBytes)
        ? decryptPinnedFileWithKey(encryptedBytes, loadFileEncryptionKey())
        : looksLikePdf(encryptedBytes)
          ? encryptedBytes
          : (() => {
              throw new Error("Certificate file is neither an encrypted envelope nor a PDF");
            })();
      const filename = buildCertificateDownloadFilename(certId, accessRow);
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Cache-Control", "private, no-store, max-age=0");
      res.setHeader("X-Content-Type-Options", "nosniff");

      await audit({
        actorUserId: user.id,
        actorWallet,
        action: "CERT_DOWNLOAD_ALLOWED",
        entityType: "certificate",
        entityId: certId,
        metadata: {
          role: user.role,
          issuerWallet,
          fileCid: resolvedFileCid,
        },
      });
      return res.send(decryptedBytes);
    } catch (e: any) {
      logEvent("error", "certificate_download_failed", {
        certId,
        userId: req.auth?.userId || null,
        role: req.auth?.role || null,
        error: e?.message || String(e),
      });
      await audit({
        actorUserId: req.auth?.userId || null,
        actorWallet,
        action: "CERT_DOWNLOAD_FAILED",
        entityType: "certificate",
        entityId: certId,
        metadata: { error: e?.message || String(e) },
      });
      return res.status(500).json({ error: "Secure certificate download failed", message: e?.message || String(e) });
    }
  });

  app.post("/api/certificates/revoke", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    const gate = await gateInstitutionAction(req, res);
    if (!gate) {
      await audit({ actorUserId: req.auth?.userId || null, actorWallet: String(req.body?.connectedWallet || "").toLowerCase() || null, action: "CERT_REVOKE_ATTEMPT_FAILED", entityType: "certificate", entityId: normalizeCertId(req.body?.certId), metadata: { reason: "GATE_CHECK_FAILED" } });
      return;
    }
    await audit({ actorUserId: gate.user.id, actorWallet: gate.wallet, action: "CERT_REVOKE_ATTEMPT_ALLOWED", entityType: "certificate", entityId: normalizeCertId(req.body?.certId), metadata: { txHash: String(req.body?.txHash || "") || null } });
    return res.json({ ok: true, allowed: true, mode: "wallet-native", message: "Authorized. Submit revoke tx via MetaMask." });
  });
}
