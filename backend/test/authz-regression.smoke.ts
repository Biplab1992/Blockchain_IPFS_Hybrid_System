import assert from "assert";
import { Wallet } from "ethers";

const API = String(process.env.TEST_API_BASE || "").trim();
const moeBootstrapSecret = String(process.env.TEST_MOE_BOOTSTRAP_SECRET || "").trim();
const existingMoeEmail = String(process.env.TEST_MOE_ADMIN_EMAIL || "").trim().toLowerCase();
const existingMoePassword = String(process.env.TEST_MOE_ADMIN_PASSWORD || "").trim();

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

async function login(email: string, password: string): Promise<string> {
  const r = await req("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(r.status, 200, `login failed for ${email}: ${r.status} ${JSON.stringify(r.body)}`);
  assert.ok(r.body?.accessToken, "missing accessToken");
  return String(r.body.accessToken);
}

async function ensureMoeToken(): Promise<string> {
  if (existingMoeEmail && existingMoePassword) {
    return login(existingMoeEmail, existingMoePassword);
  }

  const email = `moe_reg_${Date.now()}@example.com`;
  const password = "MoePass123!";
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
      `MOE admin bootstrap failed (${reg.status}). Set TEST_MOE_ADMIN_EMAIL/TEST_MOE_ADMIN_PASSWORD or TEST_MOE_BOOTSTRAP_SECRET. Body=${JSON.stringify(reg.body)}`
    );
  }
  return String(reg.body.accessToken || "");
}

async function main() {
  if (!API) {
    console.log("Skipping authorization regression checks (TEST_API_BASE is not set).");
    return;
  }

  const individualEmail = `ind_${Date.now()}@example.com`;
  const individualPassword = "IndividualPass123!";
  const institutionAdminPassword = "InstitutionPass123!";

  const individualReg = await req("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: individualEmail, password: individualPassword }),
  });
  assert.equal(individualReg.status, 201, `individual register failed: ${individualReg.status} ${JSON.stringify(individualReg.body)}`);
  const individualToken = String(individualReg.body.accessToken || "");
  assert.ok(individualToken, "missing individual access token");

  const deniedMoeForIndividual = await req("/api/moe/institutions", {
    headers: { Authorization: `Bearer ${individualToken}` },
  });
  assert.equal(
    deniedMoeForIndividual.status,
    403,
    `expected 403 for individual->MOE route, got ${deniedMoeForIndividual.status} ${JSON.stringify(deniedMoeForIndividual.body)}`
  );

  const moeToken = await ensureMoeToken();
  assert.ok(moeToken, "missing MOE token");

  const issuerWallet = Wallet.createRandom().address.toLowerCase();
  const institutionAdminEmail = `inst_admin_${Date.now()}@example.com`;
  const createInstitution = await req("/api/moe/institutions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${moeToken}`,
    },
    body: JSON.stringify({
      name: `Regression College ${Date.now()}`,
      adminEmail: institutionAdminEmail,
      issuerWallet,
    }),
  });
  assert.equal(
    createInstitution.status,
    201,
    `MOE create institution failed: ${createInstitution.status} ${JSON.stringify(createInstitution.body)}`
  );

  const institutionId = String(createInstitution.body?.institution?.id || "");
  const inviteToken = String(createInstitution.body?.inviteToken || "");
  assert.ok(institutionId, "missing institution id");
  assert.ok(inviteToken, "missing invite token");

  const suspended = await req(`/api/moe/institutions/${encodeURIComponent(institutionId)}/status`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${moeToken}`,
    },
    body: JSON.stringify({ status: "SUSPENDED" }),
  });
  assert.equal(suspended.status, 200, `failed to suspend institution: ${suspended.status} ${JSON.stringify(suspended.body)}`);

  const acceptInvite = await req("/api/auth/invitations/accept", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: inviteToken, password: institutionAdminPassword }),
  });
  assert.equal(acceptInvite.status, 200, `invite accept failed: ${acceptInvite.status} ${JSON.stringify(acceptInvite.body)}`);

  const institutionToken = await login(institutionAdminEmail, institutionAdminPassword);

  const deniedMoeForInstitutionAdmin = await req("/api/moe/institutions", {
    headers: { Authorization: `Bearer ${institutionToken}` },
  });
  assert.equal(
    deniedMoeForInstitutionAdmin.status,
    403,
    `expected 403 for institution-admin->MOE route, got ${deniedMoeForInstitutionAdmin.status} ${JSON.stringify(deniedMoeForInstitutionAdmin.body)}`
  );

  const wrongWallet = Wallet.createRandom().address.toLowerCase();
  const walletMismatch = await req("/api/certificates/issue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${institutionToken}`,
    },
    body: JSON.stringify({
      certId: `reg-wallet-mismatch-${Date.now()}`,
      connectedWallet: wrongWallet,
    }),
  });
  assert.equal(
    walletMismatch.status,
    403,
    `expected 403 wallet mismatch, got ${walletMismatch.status} ${JSON.stringify(walletMismatch.body)}`
  );

  const suspendedInstitutionIssue = await req("/api/certificates/issue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${institutionToken}`,
    },
    body: JSON.stringify({
      certId: `reg-suspended-${Date.now()}`,
      connectedWallet: issuerWallet,
    }),
  });
  assert.equal(
    suspendedInstitutionIssue.status,
    403,
    `expected 403 for suspended institution, got ${suspendedInstitutionIssue.status} ${JSON.stringify(suspendedInstitutionIssue.body)}`
  );

  console.log("Authorization regression checks passed.");
}

main().catch((err) => {
  console.error("Authorization regression checks failed:", err?.message || String(err));
  process.exit(1);
});

