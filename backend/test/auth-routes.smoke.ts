import assert from "assert";

const API = String(process.env.TEST_API_BASE || "").trim();

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

async function main() {
  if (!API) {
    console.log("Skipping auth smoke checks (TEST_API_BASE is not set).");
    return;
  }

  const email = `smoke_${Date.now()}@example.com`;
  const password = "SmokePass123!";

  const reg = await req("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  assert.ok([201, 409].includes(reg.status), `register failed: ${reg.status} ${JSON.stringify(reg.body)}`);

  const login = await req("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(login.status, 200, `login failed: ${login.status} ${JSON.stringify(login.body)}`);
  assert.ok(login.body.accessToken, "missing accessToken");

  const me = await req("/api/auth/me", {
    headers: { Authorization: `Bearer ${login.body.accessToken}` },
  });
  assert.equal(me.status, 200, `me failed: ${me.status} ${JSON.stringify(me.body)}`);

  const denyIssue = await req("/api/certificates/issue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${login.body.accessToken}`,
    },
    body: JSON.stringify({
      certId: "SMOKE-CERT-001",
      connectedWallet: "0x000000000000000000000000000000000000dEaD",
    }),
  });
  assert.equal(denyIssue.status, 403, `expected deny issue 403, got ${denyIssue.status} ${JSON.stringify(denyIssue.body)}`);

  console.log("Auth smoke checks passed.");
}

main().catch((err) => {
  console.error("Auth smoke checks failed:", err?.message || String(err));
  process.exit(1);
});
