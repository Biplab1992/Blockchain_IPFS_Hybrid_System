import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Navigate, Route, Routes, useNavigate, useSearchParams } from "react-router-dom";
import { BrowserProvider, Contract } from "ethers";

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
    // If app is opened via LAN IP but API is configured as localhost, switch to page host.
    if (!isLoopbackHost(pageHost) && isLoopbackHost(parsed.hostname)) {
      parsed.hostname = pageHost;
    }
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return configured.replace(/\/+$/, "");
  }
}

const API_BASE = resolveApiBase();
const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const RPC_URL = import.meta.env.VITE_RPC_URL || "http://127.0.0.1:8545";
const REQUIRED_CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID || 31337);
const REQUIRED_CHAIN_ID_HEX = `0x${REQUIRED_CHAIN_ID.toString(16)}`;
const SITE_TITLE = "TrustMyCert - Decentralized Academic Verification";
const AUTH_STORAGE_KEY = "certchain_auth_session_v1";

const CONTRACT_ABI = [
  "function issueCertificate(string certId, string metadataCid, string fileCid, bytes32 fileHash, uint256 version, string replacesCertId)",
  "function revokeCertificate(string certId)",
  "function setIssuer(address issuer, bool allowed)",
];

async function apiJson(url, options = {}) {
  const { timeoutMs = 20000, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, { ...fetchOptions, signal: controller.signal });
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

function loadSession() {
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

function saveSession(session) {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
}

function clearSession() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
}

function normalizeUserFacingError(err) {
  const candidates = [
    err?.shortMessage,
    err?.reason,
    err?.message,
    err?.info?.error?.message,
    err?.error?.message,
  ]
    .map((v) => String(v || "").trim())
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

async function ensureCorrectWalletNetwork() {
  if (!window.ethereum) {
    throw new Error("Wallet not found. Install MetaMask.");
  }

  try {
    await window.ethereum.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: REQUIRED_CHAIN_ID_HEX }],
    });
  } catch (switchError) {
    if (switchError?.code === 4902) {
      await window.ethereum.request({
        method: "wallet_addEthereumChain",
        params: [
          {
            chainId: REQUIRED_CHAIN_ID_HEX,
            chainName: "Hardhat Local",
            rpcUrls: [RPC_URL],
            nativeCurrency: {
              name: "Ether",
              symbol: "ETH",
              decimals: 18,
            },
          },
        ],
      });
      return;
    }
    throw switchError;
  }
}

async function assertContractDeployed(provider) {
  const code = await provider.getCode(CONTRACT_ADDRESS);
  if (!code || code === "0x") {
    throw new Error(
      `No contract bytecode at ${CONTRACT_ADDRESS} on chain ${REQUIRED_CHAIN_ID}. Check VITE_CONTRACT_ADDRESS / network.`
    );
  }
}

function buildVerifyUrl(certId) {
  const safeId = String(certId || "").trim();
  const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost:5173";
  return `${origin}/verify?certId=${encodeURIComponent(safeId)}`;
}

function buildQrCodeImageUrl(data) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=240x240&margin=8&data=${encodeURIComponent(data)}`;
}

function isLikelyPublicVerifyUrl(url) {
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

function BlockchainLogo() {
  return (
    <svg
      className="brand-logo"
      viewBox="0 0 72 72"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00a7c7" />
          <stop offset="100%" stopColor="#1f2b57" />
        </linearGradient>
      </defs>
      <rect x="8" y="8" width="56" height="56" rx="16" fill="url(#logoGradient)" />
      <circle cx="24" cy="24" r="5" fill="#ffffff" />
      <circle cx="48" cy="24" r="5" fill="#ffffff" />
      <circle cx="24" cy="48" r="5" fill="#ffffff" />
      <circle cx="48" cy="48" r="5" fill="#ffffff" />
      <path d="M24 24H48M24 24V48M48 24V48M24 48H48" stroke="#ffffff" strokeWidth="3" />
      <rect x="31" y="31" width="10" height="10" rx="2" fill="#ffffff" />
    </svg>
  );
}

function App() {
  const [walletAddress, setWalletAddress] = useState("");
  const [session, setSession] = useState(() => loadSession());

  useEffect(() => {
    document.title = SITE_TITLE;
  }, []);

  const isConnected = useMemo(() => Boolean(walletAddress), [walletAddress]);
  const isLoggedIn = useMemo(() => Boolean(session?.accessToken), [session]);
  const userRole = session?.user?.role || "";

  async function authApi(path, options = {}) {
    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${session?.accessToken || ""}`,
    };
    return apiJson(`${API_BASE}${path}`, { ...options, headers });
  }

  async function connectWallet() {
    if (!window.ethereum) {
      throw new Error("Wallet not found. Install MetaMask.");
    }
    await ensureCorrectWalletNetwork();
    const provider = new BrowserProvider(window.ethereum);
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== REQUIRED_CHAIN_ID) {
      throw new Error(`Wrong network. Please switch to chainId ${REQUIRED_CHAIN_ID}.`);
    }
    const signer = await provider.getSigner();
    const address = await signer.getAddress();
    setWalletAddress(address);
    return { provider, signer, address };
  }

  async function ensureWallet() {
    if (!window.ethereum) {
      throw new Error("Wallet not found. Install MetaMask.");
    }
    await ensureCorrectWalletNetwork();
    const provider = new BrowserProvider(window.ethereum);
    await provider.send("eth_requestAccounts", []);
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== REQUIRED_CHAIN_ID) {
      throw new Error(`Wrong network. Please switch to chainId ${REQUIRED_CHAIN_ID}.`);
    }
    await assertContractDeployed(provider);
    const signer = await provider.getSigner();
    const address = await signer.getAddress();
    if (!walletAddress || walletAddress.toLowerCase() !== address.toLowerCase()) {
      setWalletAddress(address);
    }
    return { provider, signer, address };
  }

  async function handleLogout() {
    try {
      if (session?.refreshToken) {
        await apiJson(`${API_BASE}/api/auth/logout`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refreshToken: session.refreshToken }),
        });
      }
    } catch {
      // Ignore logout network errors.
    }
    clearSession();
    setSession(null);
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand-lockup">
          <button
            type="button"
            className="logo-button"
            onClick={() => window.location.reload()}
            title="Refresh page"
          >
            <BlockchainLogo />
          </button>
          <div className="brand-text">
            <div className="brand-main">TrustMyCert</div>
            <div className="brand-sub">Decentralized Academic Verification</div>
          </div>
        </div>
        <div className="header-right">
          <div className="auth-pill">
            {isConnected ? (
              <>
                <span>{walletAddress.slice(0, 6)}...{walletAddress.slice(-4)}</span>
                <button onClick={() => setWalletAddress("")}>Disconnect</button>
              </>
            ) : (
              <button
                onClick={async () => {
                  try {
                    await connectWallet();
                  } catch (error) {
                    alert(error.message || String(error));
                  }
                }}
              >
                Connect Wallet
              </button>
            )}
          </div>
          <nav className="nav">
            <NavLink to="/verify">Verify</NavLink>
            {userRole === "INSTITUTION_ADMIN" ? <NavLink to="/institution">My Institution</NavLink> : null}
            {userRole === "MOE_ADMIN" ? <NavLink to="/moe/institutions" end>Institutions</NavLink> : null}
            {userRole === "MOE_ADMIN" ? <NavLink to="/moe" end>MoE</NavLink> : null}
            {userRole === "INSTITUTION_ADMIN" ? <NavLink to="/issue">Issue</NavLink> : null}
            {!isLoggedIn ? <NavLink to="/login">Login</NavLink> : null}
            {!isLoggedIn ? <NavLink to="/register">Register</NavLink> : null}
            {isLoggedIn ? (
              <button type="button" onClick={handleLogout}>Logout</button>
            ) : null}
          </nav>
        </div>
      </header>

      <main className="page">
        <Routes>
          <Route path="/" element={<Navigate to="/verify" replace />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route path="/login" element={<LoginPage setSession={setSession} />} />
          <Route path="/register" element={<RegisterPage setSession={setSession} />} />
          <Route path="/invite" element={<InviteAcceptPage setSession={setSession} />} />
          <Route path="/moe" element={
            <RoleGuard session={session} allow={["MOE_ADMIN"]}>
              <MoePage authApi={authApi} />
            </RoleGuard>
          } />
          <Route path="/moe/institutions" element={
            <RoleGuard session={session} allow={["MOE_ADMIN"]}>
              <MoeInstitutionsPage authApi={authApi} />
            </RoleGuard>
          } />
          <Route path="/institution" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <InstitutionPage authApi={authApi} />
            </RoleGuard>
          } />
          <Route path="/institution/wallet-bind" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <InstitutionWalletBindPage authApi={authApi} ensureWallet={ensureWallet} />
            </RoleGuard>
          } />
          <Route path="/issue" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <IssuePage ensureWallet={ensureWallet} session={session} authApi={authApi} />
            </RoleGuard>
          } />
        </Routes>
      </main>
    </div>
  );
}

function RoleGuard({ session, allow, children }) {
  if (!session?.accessToken) return <Navigate to="/login" replace />;
  const role = session?.user?.role || "";
  if (!allow.includes(role)) return <Navigate to="/verify" replace />;
  return children;
}

function LoginPage({ setSession }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  async function onSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const resp = await apiJson(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const session = {
        accessToken: resp.accessToken,
        refreshToken: resp.refreshToken,
        user: resp.user,
      };
      saveSession(session);
      setSession(session);
      if (session?.user?.role === "MOE_ADMIN") {
        navigate("/moe", { replace: true });
      } else if (session?.user?.role === "INSTITUTION_ADMIN") {
        navigate("/institution", { replace: true });
      } else {
        navigate("/verify", { replace: true });
      }
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }
  return (
    <section className="card">
      <h1>Login</h1>
      <form className="form" onSubmit={onSubmit}>
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        <button type="submit" disabled={loading}>{loading ? "Logging in..." : "Login"}</button>
      </form>
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}

function RegisterPage({ setSession }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("INDIVIDUAL");
  const [bootstrapSecret, setBootstrapSecret] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  async function onSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const resp = await apiJson(`${API_BASE}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
          role,
          bootstrapSecret: role === "MOE_ADMIN" ? bootstrapSecret : undefined,
        }),
      });
      const session = {
        accessToken: resp.accessToken,
        refreshToken: resp.refreshToken,
        user: resp.user,
      };
      saveSession(session);
      setSession(session);
      if (session?.user?.role === "MOE_ADMIN") {
        navigate("/moe", { replace: true });
      } else {
        navigate("/verify", { replace: true });
      }
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }
  return (
    <section className="card">
      <h1>Register</h1>
      <form className="form" onSubmit={onSubmit}>
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        <label>
          Role
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="INDIVIDUAL">INDIVIDUAL</option>
            <option value="MOE_ADMIN">MOE_ADMIN</option>
          </select>
        </label>
        {role === "MOE_ADMIN" ? (
          <label>
            MoE Bootstrap Secret
            <input type="password" value={bootstrapSecret} onChange={(e) => setBootstrapSecret(e.target.value)} required />
          </label>
        ) : null}
        <button type="submit" disabled={loading}>{loading ? "Creating..." : "Create Account"}</button>
      </form>
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}

function InviteAcceptPage({ setSession }) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = String(params.get("token") || "").trim();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState("");

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    if (!token) {
      setError("Invite token is missing in URL.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    try {
      const resp = await apiJson(`${API_BASE}/api/auth/invitations/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const me = await apiJson(`${API_BASE}/api/auth/me`, {
        headers: { Authorization: `Bearer ${resp.accessToken}` },
      });
      const session = {
        accessToken: resp.accessToken,
        refreshToken: resp.refreshToken,
        user: me,
      };
      saveSession(session);
      setSession(session);
      setSuccess("Invitation accepted. Redirecting...");
      navigate("/institution/wallet-bind", { replace: true });
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="card">
      <h1>Accept Institution Invite</h1>
      {!token ? <p className="error">Invite link is invalid. Missing token.</p> : null}
      <form className="form" onSubmit={onSubmit}>
        <label>
          New Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        <label>
          Confirm Password
          <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
        </label>
        <button type="submit" disabled={loading || !token}>
          {loading ? "Accepting..." : "Accept Invite"}
        </button>
      </form>
      {error ? <p className="error">{error}</p> : null}
      {success ? <p>{success}</p> : null}
    </section>
  );
}

function MoePage({ authApi }) {
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [name, setName] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [issuerWallet, setIssuerWallet] = useState("");
  async function createInst(e) {
    e.preventDefault();
    setError("");
    setInfo("");
    try {
      const created = await authApi("/api/moe/institutions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, adminEmail, issuerWallet }),
      });
      setName(""); setAdminEmail(""); setIssuerWallet("");
      if (created?.emailSent) {
        setInfo(`Invite email sent to ${adminEmail}.`);
      } else {
        const fallback = String(created?.inviteUrl || "").trim();
        const err = String(created?.emailError || "").trim();
        setInfo(`Invite created${fallback ? ` (manual link: ${fallback})` : ""}${err ? `; email error: ${err}` : ""}`);
      }
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }

  return (
    <section className="card">
      <h1>MoE Dashboard</h1>
      <form className="form" onSubmit={createInst}>
        <label>Institution Name<input value={name} onChange={(e) => setName(e.target.value)} required /></label>
        <label>Admin Email<input value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} required /></label>
        <label>Issuer Wallet<input value={issuerWallet} onChange={(e) => setIssuerWallet(e.target.value)} required /></label>
        <button type="submit">Create + Invite</button>
      </form>
      {error ? <p className="error">{error}</p> : null}
      {info ? <p>{info}</p> : null}
    </section>
  );
}

function MoeInstitutionsPage({ authApi }) {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  async function load() {
    try {
      const r = await authApi("/api/moe/institutions");
      setRows(Array.isArray(r.data) ? r.data : []);
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }
  useEffect(() => { void load(); }, []);

  async function updateStatus(id, status) {
    setError("");
    setInfo("");
    try {
      await authApi(`/api/moe/institutions/${encodeURIComponent(id)}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      setInfo(`Institution status updated to ${status}.`);
      await load();
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }

  async function deleteInstitution(id, name) {
    const ok = window.confirm(`Delete institution "${name}" permanently? This cannot be undone.`);
    if (!ok) return;
    setError("");
    setInfo("");
    try {
      await authApi(`/api/moe/institutions/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      setInfo("Institution deleted.");
      await load();
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }

  return (
    <section className="card">
      <h1>Institutions</h1>
      {error ? <p className="error">{error}</p> : null}
      {info ? <p>{info}</p> : null}
      <div className="result">
        {rows.length === 0 ? <p>No institutions yet.</p> : null}
        {rows.map((row) => (
          <div key={row.id} className="result" style={{ marginBottom: 12 }}>
            <p><strong>Name:</strong> {row.name}</p>
            <p><strong>Status:</strong> {row.status}</p>
            <p><strong>Admin:</strong> {row.admin_email}</p>
            <p><strong>Issuer Wallet:</strong> {row.issuer_wallet}</p>
            <p><strong>ID:</strong> {row.id}</p>
            <div className="action-row">
              <button type="button" onClick={() => updateStatus(row.id, "ACTIVE")} disabled={row.status === "ACTIVE"}>
                Activate
              </button>
              <button type="button" className="revoke-button" onClick={() => updateStatus(row.id, "SUSPENDED")} disabled={row.status === "SUSPENDED"}>
                Suspend
              </button>
              <button type="button" className="revoke-button" onClick={() => deleteInstitution(row.id, row.name)}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function InstitutionPage({ authApi }) {
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    void authApi("/api/institution/profile")
      .then(setProfile)
      .catch((err) => setError(normalizeUserFacingError(err)));
  }, []);
  const isBound = Boolean(profile?.binding?.verified);
  const boundAddress = String(profile?.binding?.walletAddress || "").trim();
  return (
    <section className="card">
      <h1>Institution Dashboard</h1>
      <p><strong>Wallet status:</strong> {isBound ? "Bound" : "Not bound"}</p>
      {isBound ? <p><strong>Bound address:</strong> {boundAddress || "-"}</p> : null}
      {!isBound ? (
        <p><Link to="/institution/wallet-bind">Bind Wallet</Link></p>
      ) : (
        <p><Link to="/institution/wallet-bind">Rebind Wallet</Link></p>
      )}
      {error ? <p className="error">{error}</p> : null}
      <pre>{JSON.stringify(profile || {}, null, 2)}</pre>
    </section>
  );
}

function InstitutionWalletBindPage({ authApi, ensureWallet }) {
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [boundWallet, setBoundWallet] = useState("");
  const [alreadyBound, setAlreadyBound] = useState(false);

  useEffect(() => {
    void authApi("/api/institution/profile")
      .then((p) => {
        const verified = Boolean(p?.binding?.verified);
        const wallet = String(p?.binding?.walletAddress || "").trim();
        setAlreadyBound(verified);
        setBoundWallet(wallet);
      })
      .catch(() => {
        // If profile fetch fails, keep bind action available.
      });
  }, []);

  async function run() {
    if (alreadyBound) return;
    setLoading(true);
    setError("");
    try {
      const { signer, address } = await ensureWallet();
      const nonceResp = await authApi("/api/institution/wallet/nonce", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ walletAddress: address }),
      });
      const signature = await signer.signMessage(nonceResp.message);
      const verifyResp = await authApi("/api/institution/wallet/verify-signature", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          walletAddress: address,
          nonce: nonceResp.nonce,
          signature,
        }),
      });
      setResult(verifyResp);
      setAlreadyBound(Boolean(verifyResp?.verified));
      setBoundWallet(String(verifyResp?.wallet || "").trim());
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }
  return (
    <section className="card">
      <h1>Bind Institution Wallet</h1>
      <button type="button" disabled={loading || alreadyBound} onClick={run}>
        {alreadyBound ? "Wallet Already Bound" : (loading ? "Binding..." : "Connect + Sign")}
      </button>
      {alreadyBound ? <p>Bound wallet: {boundWallet || "verified"}</p> : null}
      {error ? <p className="error">{error}</p> : null}
      {result ? <pre>{JSON.stringify(result, null, 2)}</pre> : null}
    </section>
  );
}

function IssuePage({ ensureWallet, session, authApi }) {
  const [certId, setCertId] = useState("");
  const [title, setTitle] = useState("");
  const [recipient, setRecipient] = useState("");
  const [institutionName, setInstitutionName] = useState("");
  const [version, setVersion] = useState(1);
  const [replacesCertId, setReplacesCertId] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const [revokeCertId, setRevokeCertId] = useState("");
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [revokeResult, setRevokeResult] = useState(null);
  const [revokeError, setRevokeError] = useState("");
  const [issuerAddress, setIssuerAddress] = useState("");
  const [issuerLoading, setIssuerLoading] = useState(false);
  const [issuerResult, setIssuerResult] = useState(null);
  const [issuerError, setIssuerError] = useState("");

  useEffect(() => {
    if (!session?.accessToken || session?.user?.role !== "INSTITUTION_ADMIN") return;
    void authApi("/api/institution/profile")
      .then((p) => setInstitutionName(String(p?.institution?.name || "").trim()))
      .catch(() => setInstitutionName(""));
  }, [session?.accessToken, session?.user?.role]);

  async function onSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!session?.accessToken || session?.user?.role !== "INSTITUTION_ADMIN") {
      setError("Institution login required for issuance.");
      return;
    }

    if (!file) {
      setError("Select a PDF first.");
      return;
    }

    setLoading(true);
    try {
      const { signer, address } = await ensureWallet();

      const form = new FormData();
      form.append("file", file);
      form.append("certId", certId);
      form.append("title", title);
      form.append("recipient", recipient);
      form.append("institutionName", institutionName);
      form.append("version", String(version));
      form.append("replacesCertId", replacesCertId);

      const pinResp = await apiJson(`${API_BASE}/api/pin`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
          "x-wallet-address": address,
        },
        body: form,
      });

      const metadataCid = String(pinResp.metadataCid || "").trim();
      const fileCid = String(pinResp.fileCid || pinResp.cid || "").trim();
      const fileHash = String(pinResp.fileHash || "").trim();
      if (!metadataCid || !fileCid || !/^0x[0-9a-fA-F]{64}$/.test(fileHash)) {
        throw new Error("Pin response missing metadataCid/fileCid/fileHash");
      }

      const contract = new Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.issueCertificate(
        certId.trim(),
        metadataCid,
        fileCid,
        fileHash,
        BigInt(Number(version)),
        replacesCertId.trim()
      );
      const receipt = await tx.wait();
      try {
        await authApi("/api/certificates/issue", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            certId: certId.trim(),
            metadataCid,
            fileCid,
            txHash: receipt?.hash || tx.hash,
            connectedWallet: address,
          }),
        });
      } catch {
        // Do not fail issuance UI if audit endpoint fails.
      }
      let indexed = false;
      try {
        await apiJson(`${API_BASE}/api/indexer/upsert-cert`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            certId: certId.trim(),
            issueTxHash: receipt?.hash || tx.hash,
            issueBlockNumber: receipt?.blockNumber || null,
          }),
          timeoutMs: 30000,
        });
        indexed = true;
      } catch {
        indexed = false;
      }

      setResult({
        certId: certId.trim(),
        title: String(pinResp?.metadata?.title || title || "").trim(),
        metadataCid,
        fileCid,
        fileHash,
        indexed,
        verifyUrl: String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(certId),
        qrCodeImageUrl: buildQrCodeImageUrl(String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(certId)),
        txHash: receipt?.hash || tx.hash,
        issuer: address,
        institutionName: String(pinResp?.metadata?.institutionName || institutionName || "").trim(),
      });
    } catch (submitError) {
      setError(normalizeUserFacingError(submitError));
    } finally {
      setLoading(false);
    }
  }

  async function onRevoke(event) {
    event.preventDefault();
    setRevokeError("");
    setRevokeResult(null);

    if (!revokeCertId.trim()) {
      setRevokeError("Enter certificate ID to revoke.");
      return;
    }

    setRevokeLoading(true);
    try {
      const { signer, address } = await ensureWallet();
      const contract = new Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.revokeCertificate(revokeCertId.trim());
      const receipt = await tx.wait();
      if (session?.accessToken && session?.user?.role === "INSTITUTION_ADMIN") {
        try {
          await authApi("/api/certificates/revoke", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              certId: revokeCertId.trim(),
              txHash: receipt?.hash || tx.hash,
              connectedWallet: address,
            }),
          });
        } catch {
          // audit endpoint failures are non-blocking
        }
      }
      setRevokeResult({
        certId: revokeCertId.trim(),
        txHash: receipt?.hash || tx.hash,
        issuer: address,
      });
    } catch (submitError) {
      setRevokeError(normalizeUserFacingError(submitError));
    } finally {
      setRevokeLoading(false);
    }
  }

  async function onSetIssuer(allowed) {
    setIssuerError("");
    setIssuerResult(null);

    if (!issuerAddress.trim()) {
      setIssuerError("Enter issuer wallet address.");
      return;
    }

    setIssuerLoading(true);
    try {
      const { signer } = await ensureWallet();
      const contract = new Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.setIssuer(issuerAddress.trim(), allowed);
      const receipt = await tx.wait();
      setIssuerResult({
        issuer: issuerAddress.trim(),
        allowed,
        txHash: receipt?.hash || tx.hash,
      });
    } catch (submitError) {
      setIssuerError(normalizeUserFacingError(submitError));
    } finally {
      setIssuerLoading(false);
    }
  }

  return (
    <section className="card">
      <div className="title-row">
        <h1>Issue Certificate</h1>
        <div className="info-wrap">
          <span className="info-button" aria-label="About issue flow" tabIndex={0}>i</span>
          <div className="info-tooltip">Wallet-native issue flow. Backend is used for IPFS pinning only.</div>
        </div>
      </div>
      {!session?.accessToken || session?.user?.role !== "INSTITUTION_ADMIN" ? (
        <p className="error">Login as INSTITUTION_ADMIN and bind wallet before issuing certificates.</p>
      ) : null}

      <form className="form" onSubmit={onSubmit}>
        <label>
          Certificate ID
          <input value={certId} onChange={(e) => setCertId(e.target.value)} required />
        </label>
        <label>
          Title
          <input value={title} onChange={(e) => setTitle(e.target.value)} />
        </label>
        <label>
          Recipient
          <input value={recipient} onChange={(e) => setRecipient(e.target.value)} />
        </label>
        <label>
          Institution Name
          <input value={institutionName} readOnly />
        </label>
        <label>
          Version
          <input type="number" min={1} value={version} onChange={(e) => setVersion(e.target.value)} required />
        </label>
        <label>
          Replaces Cert ID (for version {">"} 1)
          <input value={replacesCertId} onChange={(e) => setReplacesCertId(e.target.value)} />
        </label>
        <label>
          Upload PDF
          <input
            type="file"
            accept=".pdf,application/pdf"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            required
          />
        </label>

        <button type="submit" disabled={loading}>
          {loading ? "Issuing..." : "Issue"}
        </button>
      </form>

      {error ? <p className="error">{error}</p> : null}
      {result ? (
        <div className="result">
          <h2>Issued</h2>
          <p><strong>certId:</strong> {result.certId}</p>
          <p><strong>title:</strong> {result.title || "-"}</p>
          <p><strong>institutionName:</strong> {result.institutionName || "-"}</p>
          <p><strong>metadataCid:</strong> {result.metadataCid}</p>
          <p><strong>fileCid:</strong> {result.fileCid}</p>
          <p><strong>fileHash:</strong> {result.fileHash}</p>
          <p><strong>Indexed to Supabase:</strong> {result.indexed ? "true" : "pending"}</p>
          <p><strong>txHash:</strong> {result.txHash}</p>
          <p>
            <strong>Verify URL:</strong>{" "}
            <a href={result.verifyUrl} target="_blank" rel="noreferrer">
              {result.verifyUrl}
            </a>
          </p>
          <p>
            <strong>QR Reachability:</strong>{" "}
            {isLikelyPublicVerifyUrl(result.verifyUrl) ? "Public (any network)" : "Local/LAN only"}
          </p>
          <div className="qr-block">
            <img className="qr-image" src={result.qrCodeImageUrl} alt={`Verification QR for ${result.certId}`} />
            <p className="sub">Scan to open verification page with certId prefilled.</p>
          </div>
        </div>
      ) : null}

      <hr className="section-divider" />

      <div className="title-row">
        <h2>Revoke Certificate</h2>
        <div className="info-wrap">
          <span className="info-button" aria-label="About revoke flow" tabIndex={0}>i</span>
          <div className="info-tooltip">Wallet-native revoke by certificate ID.</div>
        </div>
      </div>
      <form className="form" onSubmit={onRevoke}>
        <label>
          Certificate ID
          <input value={revokeCertId} onChange={(e) => setRevokeCertId(e.target.value)} required />
        </label>
        <button className="revoke-button" type="submit" disabled={revokeLoading}>
          {revokeLoading ? "Revoking..." : "Revoke"}
        </button>
      </form>

      {revokeError ? <p className="error">{revokeError}</p> : null}
      {revokeResult ? (
        <div className="result">
          <h2>Revoked</h2>
          <p><strong>certId:</strong> {revokeResult.certId}</p>
          <p><strong>txHash:</strong> {revokeResult.txHash}</p>
        </div>
      ) : null}

      <hr className="section-divider" />

      <div className="title-row">
        <h2>Issuer Admin Panel</h2>
        <div className="info-wrap">
          <span className="info-button" aria-label="About issuer admin panel" tabIndex={0}>i</span>
          <div className="info-tooltip">Owner-only action on contract: add/remove authorized issuers.</div>
        </div>
      </div>
      <div className="form">
        <label>
          Issuer Wallet Address
          <input value={issuerAddress} onChange={(e) => setIssuerAddress(e.target.value)} />
        </label>
        <div className="action-row">
          <button type="button" disabled={issuerLoading} onClick={() => onSetIssuer(true)}>
            {issuerLoading ? "Saving..." : "Add Issuer"}
          </button>
          <button
            type="button"
            className="revoke-button"
            disabled={issuerLoading}
            onClick={() => onSetIssuer(false)}
          >
            {issuerLoading ? "Saving..." : "Remove Issuer"}
          </button>
        </div>
      </div>

      {issuerError ? <p className="error">{issuerError}</p> : null}
      {issuerResult ? (
        <div className="result">
          <h2>Issuer Updated</h2>
          <p><strong>issuer:</strong> {issuerResult.issuer}</p>
          <p><strong>allowed:</strong> {String(issuerResult.allowed)}</p>
          <p><strong>txHash:</strong> {issuerResult.txHash}</p>
        </div>
      ) : null}
    </section>
  );
}

function VerifyPage() {
  const [certId, setCertId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState(null);
  const [historyError, setHistoryError] = useState("");

  async function runVerification(targetCertId) {
    const certIdValue = String(targetCertId || "").trim();
    if (!certIdValue) {
      setError("Certificate ID is required.");
      return;
    }

    setError("");
    setResult(null);
    setHistory(null);
    setHistoryError("");
    setLoading(true);
    try {
      const encodedCertId = encodeURIComponent(certIdValue);
      const verifyResp = await apiJson(`${API_BASE}/api/verify/${encodedCertId}`, {
        timeoutMs: 70000,
      });
      setResult(verifyResp);

      void apiJson(`${API_BASE}/api/certificates/${encodedCertId}/history`, {
        timeoutMs: 15000,
      })
        .then((historyResp) => {
          setHistory(historyResp);
        })
        .catch((historyErr) => {
          setHistoryError(historyErr.message || String(historyErr));
        });
    } catch (verifyError) {
      setError(verifyError.message || String(verifyError));
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(event) {
    event.preventDefault();
    await runVerification(certId);
  }

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const queryCertId = String(params.get("certId") || "").trim();
    if (!queryCertId) return;
    setCertId(queryCertId);
    void runVerification(queryCertId);
    // Intentionally run once on first render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const statusClass =
    result?.status === "VALID"
      ? "status-valid"
      : result?.status === "REVOKED"
        ? "status-revoked"
        : "status-tampered";

  return (
    <section className="card">
      <div className="title-row">
        <h1>Verify Certificate</h1>
        <div className="info-wrap">
          <span className="info-button" aria-label="About verification" tabIndex={0}>i</span>
          <div className="info-tooltip">Public route. Verify on-chain hash and metadata.</div>
        </div>
      </div>

      <form className="form" onSubmit={onSubmit}>
        <label>
          Certificate ID
          <input value={certId} onChange={(e) => setCertId(e.target.value)} required />
        </label>
        <button type="submit" disabled={loading}>
          {loading ? "Verifying..." : "Verify"}
        </button>
      </form>

      {error ? <p className="error">{error}</p> : null}

      {result ? (
        <div className="result">
          <h2 className={statusClass}>{result.status}</h2>
          <p><strong>Issuer:</strong> {result.issuer}</p>
          <p><strong>Title:</strong> {String(result?.metadata?.title || "").trim() || "-"}</p>
          <p><strong>Institution:</strong> {String(result?.metadata?.institutionName || "").trim() || "-"}</p>
          <p><strong>Metadata CID:</strong> {result.metadataCid}</p>
          <p><strong>File CID:</strong> {result.fileCid}</p>
          <p><strong>Integrity Match:</strong> {String(result.integrityMatch)}</p>
          <p><strong>Revoked:</strong> {String(result.revoked)}</p>
          <a href={`${API_BASE}/api/fetch/${result.fileCid}`} target="_blank" rel="noreferrer">
            Download File
          </a>
          <pre>{JSON.stringify(result.metadata || {}, null, 2)}</pre>
        </div>
      ) : null}

      {history ? (
        <div className="result chain-panel">
          <h2>Version Chain</h2>
          <p>
            <strong>Root:</strong> {history.rootCertId} <strong>Length:</strong> {history.chainLength}
          </p>
          <div className="chain-row">
            {history.chain.map((item, index) => (
              <div key={item.certId} className="chain-item-wrap">
                <div className={item.certId === certId ? "chain-item chain-item-active" : "chain-item"}>
                  <div className="chain-id">{item.certId}</div>
                  <div className="chain-meta">v{item.version}</div>
                  <div className="chain-meta">{item.revoked ? "Revoked" : "Active"}</div>
                </div>
                {index < history.chain.length - 1 ? <span className="chain-arrow">{"->"}</span> : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {historyError ? <p className="error">{historyError}</p> : null}
    </section>
  );
}

export default App;
