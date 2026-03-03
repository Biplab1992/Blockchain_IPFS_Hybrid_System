import crypto from "crypto";
import type express from "express";
import axios from "axios";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Contract, JsonRpcProvider, getAddress, verifyMessage } from "ethers";
import { z } from "zod";

type Role = "MOE_ADMIN" | "INSTITUTION_ADMIN" | "INDIVIDUAL";
type InstitutionStatus = "PENDING" | "ACTIVE" | "SUSPENDED";

type AuthReq = express.Request & {
  auth?: { userId: string; role: Role; email: string };
};

type User = { id: string; email: string; password_hash: string; role: Role; email_verified: boolean };
type Institution = { id: string; name: string; status: InstitutionStatus; admin_email: string; issuer_wallet: string };
type InstitutionUser = { user_id: string; institution_id: string; is_primary_admin: boolean };
type WalletBinding = { institution_id: string; wallet_address: string; verified: boolean; verified_at: string | null };
type RefreshToken = { user_id: string; token_hash: string; expires_at: string; revoked_at: string | null };

const ACCESS_TTL_SEC = Number(process.env.JWT_ACCESS_TTL_SEC || 900);
const REFRESH_TTL_SEC = Number(process.env.JWT_REFRESH_TTL_SEC || 604800);
const nonceTtlMs = Number(process.env.AUTH_NONCE_TTL_MS || 5 * 60 * 1000);

const CERT_ABI = ["function authorizedIssuers(address issuer) view returns (bool)"];
const walletNonceByKey = new Map<string, { nonce: string; expiresAt: number }>();

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

async function sendInviteEmail(input: { to: string; inviteUrl: string; institutionName: string }): Promise<{ sent: boolean; error?: string }> {
  const key = resendApiKey();
  const from = resendFromEmail();
  if (!key || !from) return { sent: false, error: "RESEND_API_KEY/RESEND_FROM_EMAIL not configured" };
  const subject = `${inviteSubjectPrefix()} institution invite`;
  const html =
    `<p>You have been invited to administer <strong>${input.institutionName}</strong> on CertChain.</p>` +
    `<p>Open this link to accept your invite and set your password:</p>` +
    `<p><a href="${input.inviteUrl}">${input.inviteUrl}</a></p>` +
    "<p>This invite expires in 7 days.</p>";
  try {
    const r = await axios.post(
      "https://api.resend.com/emails",
      { from, to: [input.to], subject, html },
      {
        headers: {
          Authorization: `Bearer ${key}`,
          "Content-Type": "application/json",
        },
      },
    );
    return { sent: r.status >= 200 && r.status < 300 };
  } catch (e: any) {
    return { sent: false, error: e?.response?.data?.message || e?.message || "Resend send failed" };
  }
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

async function audit(input: { actorUserId?: string | null; actorWallet?: string | null; action: string; entityType: string; entityId?: string | null; metadata?: Record<string, unknown> }): Promise<void> {
  try {
    await db({
      method: "POST",
      table: "audit_logs",
      body: [{ actor_user_id: input.actorUserId || null, actor_wallet: input.actorWallet || null, action: input.action, entity_type: input.entityType, entity_id: input.entityId || null, metadata: input.metadata || {} }],
      prefer: "return=minimal",
    });
  } catch (e: any) {
    console.error("audit log failed:", e?.message || String(e));
  }
}

function sha256(v: string): string {
  return crypto.createHash("sha256").update(v, "utf8").digest("hex");
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

async function onchainAuthorized(wallet: string): Promise<boolean> {
  const rpc = process.env.RPC_URL || "";
  const caddr = process.env.CERTIFICATE_REGISTRY_ADDRESS || "";
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
const zRefresh = z.object({ refreshToken: z.string().min(20) });
const zAcceptInvite = z.object({ token: z.string().min(16), password: z.string().min(8).max(128) });
const zCreateInstitution = z.object({ name: z.string().min(2).max(200), adminEmail: z.string().email().transform((v) => v.toLowerCase()), issuerWallet: z.string().min(42).max(42) });
const zStatus = z.object({ status: z.enum(["ACTIVE", "SUSPENDED"]) });
const zResend = z.object({ email: z.string().email().transform((v) => v.toLowerCase()).optional() });
const zWalletNonce = z.object({ walletAddress: z.string().min(42).max(42) });
const zWalletVerify = z.object({ walletAddress: z.string().min(42).max(42), nonce: z.string().min(8), signature: z.string().min(20) });

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
      return res.status(201).json({ ...t, user: { id: u.id, email: u.email, role: u.role, emailVerified: u.email_verified } });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid register payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/login", authLimiter, async (req, res) => {
    try {
      const b = zLogin.parse(req.body || {});
      const u = await userByEmail(b.email);
      if (!u || !(await bcrypt.compare(b.password, u.password_hash))) return res.status(401).json({ error: "Invalid credentials" });
      const t = await issueTokens(u);
      await audit({ actorUserId: u.id, action: "AUTH_LOGIN", entityType: "user", entityId: u.id });
      return res.json({ ...t, user: { id: u.id, email: u.email, role: u.role, emailVerified: u.email_verified } });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid login payload", details: e?.message || String(e) });
    }
  });

  app.post("/api/auth/refresh", authLimiter, async (req, res) => {
    try {
      const b = zRefresh.parse(req.body || {});
      const c = verifyToken(b.refreshToken, "refresh");
      const rows = await db<RefreshToken[]>({
        method: "GET",
        table: "refresh_tokens",
        params: { select: "*", user_id: `eq.${c.sub}`, token_hash: `eq.${sha256(b.refreshToken)}`, revoked_at: "is.null", limit: "1" },
      });
      const rt = rows[0];
      if (!rt || new Date(rt.expires_at).getTime() < Date.now()) return res.status(401).json({ error: "Invalid refresh token" });
      await db({ method: "PATCH", table: "refresh_tokens", params: { user_id: `eq.${c.sub}`, token_hash: `eq.${sha256(b.refreshToken)}` }, body: { revoked_at: new Date().toISOString() }, prefer: "return=minimal" });
      const u = await userById(c.sub);
      if (!u) return res.status(401).json({ error: "User not found" });
      return res.json(await issueTokens(u));
    } catch {
      return res.status(401).json({ error: "Invalid refresh token" });
    }
  });

  app.post("/api/auth/logout", authLimiter, async (req, res) => {
    try {
      const b = zRefresh.parse(req.body || {});
      await db({ method: "PATCH", table: "refresh_tokens", params: { token_hash: `eq.${sha256(b.refreshToken)}`, revoked_at: "is.null" }, body: { revoked_at: new Date().toISOString() }, prefer: "return=minimal" });
      return res.json({ ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: "Invalid logout payload", details: e?.message || String(e) });
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
      return res.json({ ok: true, ...(await issueTokens(u)) });
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
      return res.status(201).json({ institution: inst, inviteToken: token, inviteUrl, emailSent: mail.sent, emailError: mail.error || null });
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
      return res.json({ ok: true, inviteToken: token, inviteUrl, emailSent: mail.sent, emailError: mail.error || null });
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
      await audit({ actorUserId: req.auth?.userId || null, actorWallet: String(req.body?.connectedWallet || "").toLowerCase() || null, action: "CERT_ISSUE_ATTEMPT_FAILED", entityType: "certificate", entityId: String(req.body?.certId || ""), metadata: { reason: "GATE_CHECK_FAILED" } });
      return;
    }
    await audit({ actorUserId: gate.user.id, actorWallet: gate.wallet, action: "CERT_ISSUE_ATTEMPT_ALLOWED", entityType: "certificate", entityId: String(req.body?.certId || ""), metadata: { txHash: String(req.body?.txHash || "") || null, metadataCid: String(req.body?.metadataCid || "") || null, fileCid: String(req.body?.fileCid || "") || null } });
    return res.json({ ok: true, allowed: true, mode: "wallet-native", message: "Authorized. Submit issue tx via MetaMask." });
  });

  app.post("/api/certificates/revoke", auth, roles("INSTITUTION_ADMIN"), async (req: AuthReq, res) => {
    const gate = await gateInstitutionAction(req, res);
    if (!gate) {
      await audit({ actorUserId: req.auth?.userId || null, actorWallet: String(req.body?.connectedWallet || "").toLowerCase() || null, action: "CERT_REVOKE_ATTEMPT_FAILED", entityType: "certificate", entityId: String(req.body?.certId || ""), metadata: { reason: "GATE_CHECK_FAILED" } });
      return;
    }
    await audit({ actorUserId: gate.user.id, actorWallet: gate.wallet, action: "CERT_REVOKE_ATTEMPT_ALLOWED", entityType: "certificate", entityId: String(req.body?.certId || ""), metadata: { txHash: String(req.body?.txHash || "") || null } });
    return res.json({ ok: true, allowed: true, mode: "wallet-native", message: "Authorized. Submit revoke tx via MetaMask." });
  });
}
