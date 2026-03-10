import assert from "assert";
import axios from "axios";
import FormData from "form-data";
import { Contract, JsonRpcProvider, Wallet } from "ethers";
import crypto from "crypto";

const API = String(process.env.TEST_API_BASE || "").trim();
const RPC_URL = String(process.env.TEST_RPC_URL || process.env.RPC_URL || "").trim();
const REGISTRY_ADDRESS = String(
  process.env.TEST_CERTIFICATE_REGISTRY_ADDRESS || process.env.CERTIFICATE_REGISTRY_ADDRESS || ""
).trim();
const OWNER_PRIVATE_KEY = String(process.env.TEST_OWNER_PRIVATE_KEY || "").trim();
const ENABLE_CHAIN_FLOW = String(process.env.TEST_FULL_CHAIN_E2E || "").trim() === "1";
const moeBootstrapSecret = String(process.env.TEST_MOE_BOOTSTRAP_SECRET || "").trim();
const existingMoeEmail = String(process.env.TEST_MOE_ADMIN_EMAIL || "").trim().toLowerCase();
const existingMoePassword = String(process.env.TEST_MOE_ADMIN_PASSWORD || "").trim();

const REGISTRY_ABI = [
  "function setIssuer(address issuer, bool allowed)",
  "function issueCertificate(string certId, string metadataCid, string fileCid, bytes32 fileHash, uint256 version, string replacesCertId)",
];

async function req(path: string, init?: RequestInit): Promise<{ status: number; body: any }> {
  const r = await fetch(`${API}${path}`, init);
  const t = await r.text();
  let body: any = {};
  try {
    body = t ? JSON.parse(t) : {};
  } catch {
    body = { raw: t };
  }
  return { status: r.status, body };
}

function sha256Hex(buffer: Buffer): string {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

async function waitFor<T>(fn: () => Promise<T>, ok: (value: T) => boolean, attempts = 15, delayMs = 1200): Promise<T> {
  let lastValue: T | null = null;
  for (let i = 0; i < attempts; i += 1) {
    lastValue = await fn();
    if (ok(lastValue)) return lastValue;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  if (lastValue !== null) return lastValue;
  throw new Error("waitFor received no value");
}

async function login(email: string, password: string): Promise<string> {
  const r = await req("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(r.status, 200, `login failed for ${email}: ${r.status} ${JSON.stringify(r.body)}`);
  return String(r.body.accessToken || "");
}

async function ensureMoeToken(): Promise<string> {
  if (existingMoeEmail && existingMoePassword) {
    return login(existingMoeEmail, existingMoePassword);
  }
  const email = `moe_e2e_${Date.now()}@example.com`;
  const password = "MoeE2ePass123!";
  const reg = await req("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password,
      role: "MOE_ADMIN",
      bootstrapSecret: moeBootstrapSecret || undefined,
    }),
  });
  if (reg.status !== 201) {
    throw new Error(
      `Cannot create MOE admin (${reg.status}). Set TEST_MOE_ADMIN_EMAIL/TEST_MOE_ADMIN_PASSWORD or TEST_MOE_BOOTSTRAP_SECRET. Body=${JSON.stringify(reg.body)}`
    );
  }
  return String(reg.body.accessToken || "");
}

async function pinFile(buffer: Buffer, filename: string, token: string, connectedWallet: string): Promise<{ cid: string }> {
  const fd = new FormData();
  fd.append("file", buffer, { filename });
  const resp = await axios.post(`${API}/api/pin`, fd, {
    headers: {
      ...fd.getHeaders(),
      Authorization: `Bearer ${token}`,
      "x-wallet-address": connectedWallet,
    },
    maxBodyLength: Infinity,
    validateStatus: () => true,
  });
  if (resp.status < 200 || resp.status >= 300) {
    throw new Error(`pin failed (${resp.status}): ${JSON.stringify(resp.data)}`);
  }
  return resp.data as { cid: string };
}

async function main() {
  if (!API) {
    console.log("Skipping full e2e flow (TEST_API_BASE is not set).");
    return;
  }

  const institutionAdminPassword = "InstitutionE2ePass123!";
  const institutionAdminEmail = `inst_e2e_${Date.now()}@example.com`;
  const issuerWallet = Wallet.createRandom();

  const moeToken = await ensureMoeToken();
  assert.ok(moeToken, "missing MOE token");

  const createInstitution = await req("/api/moe/institutions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${moeToken}`,
    },
    body: JSON.stringify({
      name: `E2E Institute ${Date.now()}`,
      adminEmail: institutionAdminEmail,
      issuerWallet: issuerWallet.address.toLowerCase(),
    }),
  });
  assert.equal(
    createInstitution.status,
    201,
    `create institution failed: ${createInstitution.status} ${JSON.stringify(createInstitution.body)}`
  );

  const institutionId = String(createInstitution.body?.institution?.id || "");
  const inviteToken = String(createInstitution.body?.inviteToken || "");
  assert.ok(institutionId, "missing institution id");
  assert.ok(inviteToken, "missing invite token");

  const activate = await req(`/api/moe/institutions/${encodeURIComponent(institutionId)}/status`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${moeToken}`,
    },
    body: JSON.stringify({ status: "ACTIVE" }),
  });
  assert.equal(activate.status, 200, `activate failed: ${activate.status} ${JSON.stringify(activate.body)}`);

  const acceptInvite = await req("/api/auth/invitations/accept", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: inviteToken, password: institutionAdminPassword }),
  });
  assert.equal(acceptInvite.status, 200, `invite accept failed: ${acceptInvite.status} ${JSON.stringify(acceptInvite.body)}`);

  const institutionToken = await login(institutionAdminEmail, institutionAdminPassword);

  const nonceResp = await req("/api/institution/wallet/nonce", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${institutionToken}`,
    },
    body: JSON.stringify({ walletAddress: issuerWallet.address.toLowerCase() }),
  });
  assert.equal(nonceResp.status, 200, `wallet nonce failed: ${nonceResp.status} ${JSON.stringify(nonceResp.body)}`);
  const signature = await issuerWallet.signMessage(String(nonceResp.body?.message || ""));
  const verifyWallet = await req("/api/institution/wallet/verify-signature", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${institutionToken}`,
    },
    body: JSON.stringify({
      walletAddress: issuerWallet.address.toLowerCase(),
      nonce: String(nonceResp.body?.nonce || ""),
      signature,
    }),
  });
  assert.equal(
    verifyWallet.status,
    200,
    `wallet verify failed: ${verifyWallet.status} ${JSON.stringify(verifyWallet.body)}`
  );

  const profile = await req("/api/institution/profile", {
    headers: { Authorization: `Bearer ${institutionToken}` },
  });
  assert.equal(profile.status, 200, `institution profile failed: ${profile.status} ${JSON.stringify(profile.body)}`);
  assert.equal(Boolean(profile.body?.binding?.verified), true, "wallet binding should be verified");

  if (!ENABLE_CHAIN_FLOW) {
    console.log("E2E base flow passed (auth + invite + wallet bind).");
    console.log("Chain flow skipped (set TEST_FULL_CHAIN_E2E=1 to run issue + verify).");
    return;
  }

  if (!RPC_URL || !REGISTRY_ADDRESS || !OWNER_PRIVATE_KEY) {
    throw new Error("Chain flow requires TEST_FULL_CHAIN_E2E=1 plus TEST_RPC_URL, TEST_CERTIFICATE_REGISTRY_ADDRESS, TEST_OWNER_PRIVATE_KEY.");
  }

  const provider = new JsonRpcProvider(RPC_URL);
  const owner = new Wallet(OWNER_PRIVATE_KEY, provider);
  const contract = new Contract(REGISTRY_ADDRESS, REGISTRY_ABI, owner);

  const authorizeTx = await contract.getFunction("setIssuer").send(issuerWallet.address, true);
  await authorizeTx.wait();
  await req("/api/indexer/sync-issuers", { method: "POST" });

  const preflightIssue = await req("/api/certificates/issue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${institutionToken}`,
    },
    body: JSON.stringify({
      certId: `e2e-preflight-${Date.now()}`,
      connectedWallet: issuerWallet.address.toLowerCase(),
    }),
  });
  assert.equal(preflightIssue.status, 200, `issue preflight failed: ${preflightIssue.status} ${JSON.stringify(preflightIssue.body)}`);

  const certId = `e2e-cert-${Date.now()}`.toLowerCase();
  const fileBytes = Buffer.from(`e2e-file-${Date.now()}`, "utf8");
  const fileHash = `0x${sha256Hex(fileBytes)}`;

  const pinnedFile = await pinFile(fileBytes, `${certId}.bin`, institutionToken, issuerWallet.address.toLowerCase());
  const metadata = {
    certId,
    title: "E2E Certificate",
    institutionName: String(profile.body?.institution?.name || "E2E Institute"),
    fileCid: pinnedFile.cid,
    fileHash,
    version: 1,
    replacesCertId: "",
  };
  const pinnedMetadata = await pinFile(
    Buffer.from(JSON.stringify(metadata), "utf8"),
    `${certId}.metadata.json`,
    institutionToken,
    issuerWallet.address.toLowerCase()
  );

  const issuerSigner = new Wallet(issuerWallet.privateKey, provider);
  const issuerContract = new Contract(REGISTRY_ADDRESS, REGISTRY_ABI, issuerSigner);
  const issueTx = await issuerContract
    .getFunction("issueCertificate")
    .send(certId, pinnedMetadata.cid, pinnedFile.cid, fileHash, 1, "");
  await issueTx.wait();

  const verifyResp = await waitFor(
    async () => req(`/api/verify/${encodeURIComponent(certId)}`),
    (r) => r.status === 200 && String(r.body?.status || "") === "VALID",
    20,
    1500
  );
  assert.equal(verifyResp.status, 200, `verify failed: ${verifyResp.status} ${JSON.stringify(verifyResp.body)}`);
  assert.equal(String(verifyResp.body?.status || ""), "VALID", `expected VALID, got ${JSON.stringify(verifyResp.body)}`);

  console.log("Full e2e flow passed (auth + invite + wallet bind + issue + verify).");
}

main().catch((err) => {
  console.error("Full e2e flow failed:", err?.message || String(err));
  process.exit(1);
});

