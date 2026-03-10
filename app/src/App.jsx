import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
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
  const safeId = normalizeCertId(certId);
  const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost:5173";
  return `${origin}/verify?certId=${encodeURIComponent(safeId)}`;
}

function normalizeCertId(value) {
  return String(value || "").trim().toLowerCase();
}

function extractCertIdFromScanInput(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    const q = normalizeCertId(parsed.searchParams.get("certId"));
    if (q) return q;
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

function institutionBrandFrom(inputName, issuer) {
  const name = String(inputName || "").trim() || "Institution";
  const initials = name
    .split(/\s+/)
    .slice(0, 2)
    .map((s) => s[0] || "")
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

function issuerRowsFromResponse(resp) {
  const rows = Array.isArray(resp?.data) ? resp.data : [];
  return rows;
}

async function listAllCertificatesByIssuer(authApi, issuerWallet) {
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
  const navigate = useNavigate();
  const location = useLocation();
  const [walletAddress, setWalletAddress] = useState("");
  const [session, setSession] = useState(() => loadSession());
  const [toast, setToast] = useState(null);

  useEffect(() => {
    document.title = SITE_TITLE;
  }, []);

  const isConnected = useMemo(() => Boolean(walletAddress), [walletAddress]);
  const isLoggedIn = useMemo(() => Boolean(session?.accessToken), [session]);
  const userRole = session?.user?.role || "";
  const showPublicBrandText = location.pathname === "/login" || location.pathname === "/register";

  function showToast(message, type = "success") {
    setToast({ message: String(message || "").trim(), type });
  }

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(t);
  }, [toast]);

  async function refreshAccessToken() {
    const resp = await apiJson(`${API_BASE}/api/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const nextSession = {
      ...(session || {}),
      accessToken: resp.accessToken,
    };
    saveSession(nextSession);
    setSession(nextSession);
    return nextSession.accessToken;
  }

  async function authApi(path, options = {}, retried = false) {
    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${session?.accessToken || ""}`,
    };
    try {
      return await apiJson(`${API_BASE}${path}`, { ...options, headers });
    } catch (err) {
      const msg = String(err?.message || "").toLowerCase();
      const shouldTryRefresh = !retried && (msg.includes("http 401") || msg.includes("invalid/expired access token"));
      if (!shouldTryRefresh) throw err;
      const nextAccessToken = await refreshAccessToken();
      const retryHeaders = {
        ...(options.headers || {}),
        Authorization: `Bearer ${nextAccessToken}`,
      };
      return apiJson(`${API_BASE}${path}`, { ...options, headers: retryHeaders });
    }
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
      await apiJson(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
    } catch {
      // Ignore logout network errors.
    }
    setWalletAddress("");
    clearSession();
    setSession(null);
    navigate("/", { replace: true });
  }

  return (
    <div className="shell">
      {isLoggedIn ? (
        <header className="topbar">
          <div className="brand-lockup">
            <button
              type="button"
              className="logo-button"
              onClick={() => window.location.assign("/")}
              title="Go to homepage"
            >
              <BlockchainLogo />
            </button>
            <div className="brand-text">
              <div className="brand-main">TrustMyCert</div>
              <div className="brand-sub">Decentralized Academic Verification</div>
            </div>
          </div>
          <div className="nav-center">
            <nav className="nav">
              {userRole === "INSTITUTION_ADMIN" ? <NavLink to="/institution">My Institution</NavLink> : null}
              {userRole === "INSTITUTION_ADMIN" ? <NavLink to="/issue">Issue</NavLink> : null}
              {userRole === "INSTITUTION_ADMIN" ? <NavLink to="/revoke">Revoke</NavLink> : null}
              <NavLink to="/verify">Verify</NavLink>
              {userRole === "INDIVIDUAL" ? <NavLink to="/profile">Profile</NavLink> : null}
              {userRole === "INSTITUTION_ADMIN" ? <NavLink to="/issuer-admin">Issuer Admin</NavLink> : null}
              {userRole === "MOE_ADMIN" ? <NavLink to="/moe/institutions" end>Institutions</NavLink> : null}
              {userRole === "MOE_ADMIN" ? <NavLink to="/moe" end>MoE</NavLink> : null}
            </nav>
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
              <button type="button" onClick={handleLogout}>Logout</button>
            </div>
            {userRole === "MOE_ADMIN" ? (
              <Link className="header-secondary-link" to="/account/password">Change password</Link>
            ) : null}
          </div>
        </header>
      ) : (
        <header className="topbar topbar-public">
          <div className="brand-lockup">
            <button
              type="button"
              className="logo-button"
              onClick={() => window.location.assign("/")}
              title="Go to homepage"
            >
              <BlockchainLogo />
            </button>
            {showPublicBrandText ? (
              <div className="brand-text">
                <div className="brand-main">TrustMyCert</div>
                <div className="brand-sub">Decentralized Academic Verification</div>
              </div>
            ) : null}
          </div>
          <div className="public-header-right">
            <Link className="public-moe-login" to="/login?moe=1">MOE LOGIN</Link>
          </div>
        </header>
      )}

      <main className="page">
        <Routes>
          <Route path="/" element={isLoggedIn ? <Navigate to="/verify" replace /> : <HomePage />} />
          <Route path="/scan" element={<Navigate to="/verify" replace />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route path="/certificate/:certId" element={<CertificateProfilePage />} />
          <Route path="/institutions/:issuer" element={<InstitutionPublicPage />} />
          <Route path="/login" element={<LoginPage setSession={setSession} />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage showToast={showToast} />} />
          <Route path="/reset-password" element={<ResetPasswordPage showToast={showToast} />} />
          <Route path="/register" element={<RegisterPage setSession={setSession} />} />
          <Route path="/invite" element={<InviteAcceptPage setSession={setSession} />} />
          <Route path="/profile" element={
            <RoleGuard session={session} allow={["INDIVIDUAL"]}>
              <IndividualProfilePage session={session} />
            </RoleGuard>
          } />
          <Route path="/account/password" element={
            <RoleGuard session={session} allow={["MOE_ADMIN", "INSTITUTION_ADMIN", "INDIVIDUAL"]}>
              <ChangePasswordPage authApi={authApi} showToast={showToast} />
            </RoleGuard>
          } />
          <Route path="/moe" element={
            <RoleGuard session={session} allow={["MOE_ADMIN"]}>
              <MoePage authApi={authApi} showToast={showToast} />
            </RoleGuard>
          } />
          <Route path="/moe/institutions" element={
            <RoleGuard session={session} allow={["MOE_ADMIN"]}>
              <MoeInstitutionsPage authApi={authApi} showToast={showToast} ensureWallet={ensureWallet} />
            </RoleGuard>
          } />
          <Route path="/institution" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN", "MOE_ADMIN"]}>
              <InstitutionPage authApi={authApi} session={session} ensureWallet={ensureWallet} showToast={showToast} />
            </RoleGuard>
          } />
          <Route path="/institution/wallet-bind" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <InstitutionWalletBindPage authApi={authApi} ensureWallet={ensureWallet} showToast={showToast} />
            </RoleGuard>
          } />
          <Route path="/issue" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <IssuePage ensureWallet={ensureWallet} session={session} authApi={authApi} />
            </RoleGuard>
          } />
          <Route path="/revoke" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <RevokePage ensureWallet={ensureWallet} session={session} authApi={authApi} />
            </RoleGuard>
          } />
          <Route path="/issuer-admin" element={
            <RoleGuard session={session} allow={["INSTITUTION_ADMIN"]}>
              <IssuerAdminPage ensureWallet={ensureWallet} />
            </RoleGuard>
          } />
        </Routes>
      </main>
      {toast ? <div className={`toast toast-${toast.type || "success"}`}>{toast.message}</div> : null}
    </div>
  );
}

function HomePage() {
  return (
    <section className="card home-hero">
      <h1>TrustMyCert</h1>
      <p className="home-copy">
        Decentralized Academic Verification Platform
      </p>
      <div className="action-row">
        <Link className="home-secondary" to="/login">Sign In</Link>
        <Link className="home-primary" to="/register">Get Started</Link>
      </div>
    </section>
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
  const [params] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const showMoeHint = params.get("moe") === "1";
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
      const role = String(resp?.user?.role || "");
      if (showMoeHint && role !== "MOE_ADMIN") {
        try {
          await apiJson(`${API_BASE}/api/auth/logout`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });
        } catch {
          // Best-effort cookie cleanup only.
        }
        clearSession();
        setSession(null);
        setError("MOE LOGIN only allows MOE admin accounts.");
        return;
      }
      if (!showMoeHint && role === "MOE_ADMIN") {
        try {
          await apiJson(`${API_BASE}/api/auth/logout`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });
        } catch {
          // Best-effort cookie cleanup only.
        }
        clearSession();
        setSession(null);
        setError("MOE admins must sign in from the MOE LOGIN tab.");
        return;
      }
      const session = {
        accessToken: resp.accessToken,
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
    <section className="auth-page">
      <div className="auth-title-row">
        <h1>Login</h1>
        {showMoeHint ? <Link className="auth-title-link" to="/register?moe=1">Get started</Link> : null}
      </div>
      {showMoeHint ? <p className="sub">Use your ministry admin credentials.</p> : null}
      <form className="form" onSubmit={onSubmit}>
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        <button type="submit" disabled={loading}>{loading ? "Logging in..." : "Login"}</button>
      </form>
      <div className="auth-links">
        <Link to="/forgot-password">Forgot password?</Link>
      </div>
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}

function ForgotPasswordPage({ showToast }) {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setInfo("");
    setLoading(true);
    try {
      const resp = await apiJson(`${API_BASE}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const message = String(resp?.message || "If an account exists for that email, a reset link has been sent.");
      setInfo(message);
      showToast?.("Password reset link requested");
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="auth-page">
      <h1>Forgot Password</h1>
      <p className="sub">Enter your account email to receive a reset link.</p>
      <form className="form" onSubmit={onSubmit}>
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <button type="submit" disabled={loading}>{loading ? "Sending..." : "Send Reset Link"}</button>
      </form>
      <div className="auth-links">
        <Link to="/login">Back to login</Link>
      </div>
      {error ? <p className="error">{error}</p> : null}
      {info ? <p className="sub">{info}</p> : null}
    </section>
  );
}

function ResetPasswordPage({ showToast }) {
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
      setError("Reset token is missing in URL.");
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
      await apiJson(`${API_BASE}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      setSuccess("Password reset successful. Redirecting to login...");
      showToast?.("Password reset successful");
      setTimeout(() => navigate("/login", { replace: true }), 700);
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="auth-page">
      <h1>Reset Password</h1>
      {!token ? <p className="error">Reset link is invalid. Missing token.</p> : null}
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
          {loading ? "Resetting..." : "Reset Password"}
        </button>
      </form>
      <div className="auth-links">
        <Link to="/login">Back to login</Link>
      </div>
      {error ? <p className="error">{error}</p> : null}
      {success ? <p className="sub">{success}</p> : null}
    </section>
  );
}

function ChangePasswordPage({ authApi, showToast }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState("");

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      return;
    }
    setLoading(true);
    try {
      await authApi("/api/auth/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setSuccess("Password updated.");
      showToast?.("Password changed");
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="auth-page">
      <h1>Change Password</h1>
      <p className="sub">Update your account password.</p>
      <form className="form" onSubmit={onSubmit}>
        <label>
          Current Password
          <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
        </label>
        <label>
          New Password
          <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
        </label>
        <label>
          Confirm New Password
          <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
        </label>
        <button type="submit" disabled={loading}>
          {loading ? "Updating..." : "Change Password"}
        </button>
      </form>
      {error ? <p className="error">{error}</p> : null}
      {success ? <p className="sub">{success}</p> : null}
    </section>
  );
}

function IndividualProfilePage({ session }) {
  return (
    <section className="card">
      <h1>Profile</h1>
      <div className="result">
        <p><strong>Email:</strong> {String(session?.user?.email || "").trim() || "-"}</p>
        <p><strong>Role:</strong> {String(session?.user?.role || "").trim() || "-"}</p>
      </div>
      <div className="result">
        <h2>Security</h2>
        <p className="sub">Manage your account password here.</p>
        <div className="action-row">
          <Link to="/account/password">Change Password</Link>
        </div>
      </div>
    </section>
  );
}

function RegisterPage({ setSession }) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [bootstrapSecret, setBootstrapSecret] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const isMoeSignup = params.get("moe") === "1";
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
          role: isMoeSignup ? "MOE_ADMIN" : "INDIVIDUAL",
          bootstrapSecret: isMoeSignup ? bootstrapSecret : undefined,
        }),
      });
      const session = {
        accessToken: resp.accessToken,
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
    <section className="auth-page">
      <h1>
        Register <span className="auth-role-note">({isMoeSignup ? "MOE Admin" : "Individual"})</span>
      </h1>
      {isMoeSignup ? <p className="sub">Create a new MoE admin account (bootstrap secret required).</p> : null}
      <form className="form" onSubmit={onSubmit}>
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        {isMoeSignup ? (
          <label>
            Bootstrap Secret
            <input
              type="password"
              value={bootstrapSecret}
              onChange={(e) => setBootstrapSecret(e.target.value)}
              required
            />
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
    <section className="auth-page">
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

function MoePage({ authApi, showToast }) {
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [name, setName] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [issuerWallet, setIssuerWallet] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});

  function validateForm() {
    const next = {};
    if (!String(name || "").trim()) next.name = "Institution name is required.";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(adminEmail || "").trim())) {
      next.adminEmail = "Enter a valid email address.";
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(String(issuerWallet || "").trim())) {
      next.issuerWallet = "Issuer wallet must be a valid 0x address.";
    }
    setFieldErrors(next);
    return Object.keys(next).length === 0;
  }

  async function createInst(e) {
    e.preventDefault();
    setError("");
    setInfo("");
    if (!validateForm()) return;
    try {
      const created = await authApi("/api/moe/institutions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, adminEmail, issuerWallet }),
      });
      setName(""); setAdminEmail(""); setIssuerWallet("");
      setFieldErrors({});
      if (created?.emailSent) {
        setInfo(`Invite email sent to ${adminEmail}.`);
        showToast?.(`Invite sent to ${adminEmail}`);
      } else {
        const fallback = String(created?.inviteUrl || "").trim();
        const err = String(created?.emailError || "").trim();
        setInfo(`Invite created${fallback ? ` (manual link: ${fallback})` : ""}${err ? `; email error: ${err}` : ""}`);
        showToast?.("Institution created. Email queued/manual follow-up may be required.", "warning");
      }
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }

  return (
    <section className="card">
      <h1>MoE Dashboard</h1>
      <form className="form" onSubmit={createInst}>
        <label>
          Institution Name
          <input value={name} onChange={(e) => setName(e.target.value)} required />
          {fieldErrors.name ? <span className="field-error">{fieldErrors.name}</span> : null}
        </label>
        <label>
          Admin Email
          <input value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} required />
          {fieldErrors.adminEmail ? <span className="field-error">{fieldErrors.adminEmail}</span> : null}
        </label>
        <label>
          Issuer Wallet
          <input value={issuerWallet} onChange={(e) => setIssuerWallet(e.target.value)} required />
          {fieldErrors.issuerWallet ? <span className="field-error">{fieldErrors.issuerWallet}</span> : null}
        </label>
        <button type="submit">Create + Invite</button>
      </form>
      {error ? <p className="error">{error}</p> : null}
      {info ? <p className="sub">{info}</p> : null}
    </section>
  );
}

function MoeInstitutionsPage({ authApi, showToast, ensureWallet }) {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [authorizingId, setAuthorizingId] = useState("");
  const [issuerAuthByWallet, setIssuerAuthByWallet] = useState({});
  async function load() {
    try {
      const [r, issuers] = await Promise.all([
        authApi("/api/moe/institutions"),
        authApi("/api/issuers"),
      ]);
      setRows(Array.isArray(r.data) ? r.data : []);
      const authMap = {};
      for (const row of issuerRowsFromResponse(issuers)) {
        authMap[String(row?.issuer || "").toLowerCase()] = Boolean(row?.isAuthorized);
      }
      setIssuerAuthByWallet(authMap);
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
      showToast?.(`Status set to ${status}`);
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
      showToast?.("Institution deleted", "warning");
      await load();
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }

  async function authorizeInstitution(row) {
    const wallet = String(row?.issuer_wallet || "").trim();
    const walletLower = wallet.toLowerCase();
    const currentlyAuthorized = Boolean(issuerAuthByWallet[walletLower]);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      setError("Institution issuer wallet is invalid.");
      return;
    }
    setError("");
    setInfo("");
    setAuthorizingId(String(row.id || ""));
    try {
      const { signer } = await ensureWallet();
      const contract = new Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.setIssuer(wallet, !currentlyAuthorized);
      const receipt = await tx.wait();
      try {
        await authApi("/api/indexer/sync-issuers", { method: "POST" });
      } catch {
        // best-effort cache refresh trigger
      }
      const label = currentlyAuthorized ? "deauthorized" : "authorized";
      setInfo(`Issuer wallet ${label} for ${row.name}. Tx: ${receipt?.hash || tx.hash}`);
      showToast?.(`${row.name}: ${currentlyAuthorized ? "Deauthorized" : "Authorized"}`);
      await load();
    } catch (err) {
      setError(normalizeUserFacingError(err));
    } finally {
      setAuthorizingId("");
    }
  }

  return (
    <section className="card">
      <h1>Institutions</h1>
      {error ? <p className="error">{error}</p> : null}
      {info ? <p className="sub">{info}</p> : null}
      {rows.length === 0 ? (
        <div className="empty-state">
          <h2>No institutions yet</h2>
          <p>Create your first institution in the MoE Dashboard to start invitation onboarding.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Admin</th>
                <th>Issuer Wallet</th>
                <th>Authorization</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.name}</td>
                  <td><span className={`pill pill-${String(row.status || "").toLowerCase()}`}>{row.status}</span></td>
                  <td>{row.admin_email}</td>
                  <td className="mono">{row.issuer_wallet}</td>
                  <td>
                    <span className={`pill ${issuerAuthByWallet[String(row.issuer_wallet || "").toLowerCase()] ? "pill-active" : "pill-suspended"}`}>
                      {issuerAuthByWallet[String(row.issuer_wallet || "").toLowerCase()] ? "AUTHORIZED" : "NOT AUTHORIZED"}
                    </span>
                  </td>
                  <td>
                    <div className="action-row">
                      <button
                        type="button"
                        onClick={() => authorizeInstitution(row)}
                        disabled={authorizingId === row.id}
                      >
                        {authorizingId === row.id
                          ? "Saving..."
                          : issuerAuthByWallet[String(row.issuer_wallet || "").toLowerCase()]
                            ? "Deauthorize"
                            : "Authorize"}
                      </button>
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
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function InstitutionPage({ authApi, session, ensureWallet, showToast }) {
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState("");
  const [issuerAuthorized, setIssuerAuthorized] = useState(false);
  const [issuedTotal, setIssuedTotal] = useState(0);
  const [moeInstitutions, setMoeInstitutions] = useState([]);
  const [selectedInstitutionId, setSelectedInstitutionId] = useState("");
  const [moeIssuerWallet, setMoeIssuerWallet] = useState("");
  const [authorizeError, setAuthorizeError] = useState("");
  const [authorizing, setAuthorizing] = useState(false);
  const role = String(session?.user?.role || "");
  const isMoe = role === "MOE_ADMIN";
  const isInstitutionAdmin = role === "INSTITUTION_ADMIN";

  useEffect(() => {
    if (isInstitutionAdmin) {
      void authApi("/api/institution/profile")
        .then(async (p) => {
          setProfile(p);
          const wallet = String(p?.institution?.issuerWallet || "").trim().toLowerCase();
          const institutionName = String(p?.institution?.name || "").trim().toLowerCase();
          try {
            const [issuerStatus, certRows] = await Promise.all([
              wallet ? authApi(`/api/issuers/${encodeURIComponent(wallet)}/status`) : Promise.resolve({ onChainAuthorized: false }),
              wallet ? listAllCertificatesByIssuer(authApi, wallet) : Promise.resolve([]),
            ]);
            setIssuerAuthorized(Boolean(issuerStatus?.onChainAuthorized));
            const institutionScopedCount = certRows.filter((row) => {
              const rowInstitution = String(row?.institutionName || "").trim().toLowerCase();
              return rowInstitution && institutionName && rowInstitution === institutionName;
            }).length;
            setIssuedTotal(institutionScopedCount);
          } catch {
            setIssuerAuthorized(false);
            setIssuedTotal(0);
          }
        })
        .catch((err) => setError(normalizeUserFacingError(err)));
    }
    if (isMoe) {
      void authApi("/api/moe/institutions")
        .then((r) => {
          const rows = Array.isArray(r?.data) ? r.data : [];
          setMoeInstitutions(rows);
          if (rows[0]?.id) {
            setSelectedInstitutionId(rows[0].id);
            setMoeIssuerWallet(String(rows[0].issuer_wallet || "").trim());
          }
        })
        .catch((err) => setError(normalizeUserFacingError(err)));
    }
  }, [isInstitutionAdmin, isMoe]);

  const isBound = Boolean(profile?.binding?.verified);
  const boundAddress = String(profile?.binding?.walletAddress || "").trim();
  const status = String(profile?.institution?.status || "").trim();
  const checklist = [
    { label: "Activate", done: status === "ACTIVE", helper: status || "PENDING" },
    { label: "Bind Wallet", done: isBound, helper: boundAddress || "Not bound" },
    { label: "Authorize", done: issuerAuthorized, helper: issuerAuthorized ? "On-chain authorized" : "Not authorized" },
    { label: "Issue", done: issuedTotal > 0, helper: issuedTotal > 0 ? `${issuedTotal} cert(s) issued` : "No certificates issued yet" },
  ];

  const selectedInstitution =
    moeInstitutions.find((r) => String(r?.id || "") === String(selectedInstitutionId || "")) || null;

  async function authorizeWalletDirect(targetWallet) {
    const wallet = String(targetWallet || "").trim();
    setAuthorizeError("");
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      setAuthorizeError("Enter a valid issuer wallet address.");
      return;
    }
    setAuthorizing(true);
    try {
      const { signer } = await ensureWallet();
      const contract = new Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.setIssuer(wallet, true);
      await tx.wait();
      setIssuerAuthorized(true);
      showToast?.(`Authorized ${wallet.slice(0, 8)}...${wallet.slice(-6)}`);
    } catch (err) {
      setAuthorizeError(normalizeUserFacingError(err));
    } finally {
      setAuthorizing(false);
    }
  }

  return (
    <section className="card">
      <h1>Institution Dashboard</h1>
      {isMoe ? <p className="sub">MoE quick-action mode. Authorize institution wallets directly from here.</p> : null}
      <div className="result">
        <p><strong>Institution Name:</strong> {String(profile?.institution?.name || "").trim() || "-"}</p>
        <p><strong>Status:</strong> {status || "-"}</p>
        <p><strong>Wallet status:</strong> {isBound ? "Bound" : "Not bound"}</p>
        {isBound ? <p><strong>Bound address:</strong> {boundAddress || "-"}</p> : null}
        <p><strong>Issuer authorization:</strong> {issuerAuthorized ? "Authorized" : "Not authorized"}</p>
        <p><strong>Total issued certificates:</strong> {issuedTotal}</p>
      </div>
      {isInstitutionAdmin ? (
        <div className="result">
          <h2>Onboarding Checklist</h2>
          <ul className="checklist">
            {checklist.map((item) => (
              <li key={item.label} className={item.done ? "check-done" : "check-pending"}>
                <span className="check-mark">{item.done ? "✓" : "○"}</span>
                <span className="check-label">{item.label}</span>
                <span className="check-helper">{item.helper}</span>
              </li>
            ))}
          </ul>
          {!isBound ? (
            <p><Link to="/institution/wallet-bind">Continue: Bind Wallet</Link></p>
          ) : (
            <p><Link to="/issue">Continue: Issue Certificate</Link></p>
          )}
          <hr className="section-divider" />
          <h2>Account Security</h2>
          <div className="action-row">
            <Link to="/account/password">Change Password</Link>
          </div>
        </div>
      ) : null}
      {isMoe ? (
        <div className="result">
          <h2>MoE Quick Authorize</h2>
          <label className="inline-label">
            Institution
            <select
              value={selectedInstitutionId}
              onChange={(e) => {
                const id = e.target.value;
                setSelectedInstitutionId(id);
                const row = moeInstitutions.find((r) => String(r?.id || "") === id);
                setMoeIssuerWallet(String(row?.issuer_wallet || "").trim());
              }}
            >
              {moeInstitutions.map((row) => (
                <option key={row.id} value={row.id}>
                  {row.name} ({row.status})
                </option>
              ))}
            </select>
          </label>
          <label>
            Issuer Wallet
            <input value={moeIssuerWallet} onChange={(e) => setMoeIssuerWallet(e.target.value)} />
          </label>
          {selectedInstitution ? <p className="sub">Admin: {selectedInstitution.admin_email}</p> : null}
          <div className="action-row">
            <button type="button" disabled={authorizing} onClick={() => authorizeWalletDirect(moeIssuerWallet)}>
              {authorizing ? "Authorizing..." : "Authorize this wallet"}
            </button>
          </div>
          {authorizeError ? <p className="error">{authorizeError}</p> : null}
        </div>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}

function InstitutionWalletBindPage({ authApi, ensureWallet, showToast }) {
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
      showToast?.("Wallet successfully bound.");
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
      {result ? (
        <div className="result">
          <h2>Wallet Bound</h2>
          <p><strong>Wallet:</strong> {String(result?.wallet || "").trim() || "-"}</p>
          <p><strong>Verified:</strong> {String(Boolean(result?.verified))}</p>
        </div>
      ) : null}
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
      const normalizedCertId = normalizeCertId(certId);
      const normalizedReplacesCertId = normalizeCertId(replacesCertId);

      const form = new FormData();
      form.append("file", file);
      form.append("certId", normalizedCertId);
      form.append("title", title);
      form.append("recipient", recipient);
      form.append("institutionName", institutionName);
      form.append("version", String(version));
      form.append("replacesCertId", normalizedReplacesCertId);

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
        normalizedCertId,
        metadataCid,
        fileCid,
        fileHash,
        BigInt(Number(version)),
        normalizedReplacesCertId
      );
      const receipt = await tx.wait();
      try {
        await authApi("/api/certificates/issue", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            certId: normalizedCertId,
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
            certId: normalizedCertId,
            issueTxHash: receipt?.hash || tx.hash,
            issueBlockNumber: receipt?.blockNumber || null,
            title: title.trim(),
            institutionName: institutionName.trim(),
          }),
          timeoutMs: 30000,
        });
        indexed = true;
      } catch {
        indexed = false;
      }

      setResult({
        certId: normalizedCertId,
        title: String(pinResp?.metadata?.title || title || "").trim(),
        metadataCid,
        fileCid,
        fileHash,
        indexed,
        verifyUrl: String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(normalizedCertId),
        qrCodeImageUrl: buildQrCodeImageUrl(String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(normalizedCertId)),
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
    </section>
  );
}

function RevokePage({ ensureWallet, session, authApi }) {
  const [revokeCertId, setRevokeCertId] = useState("");
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [revokeResult, setRevokeResult] = useState(null);
  const [revokeError, setRevokeError] = useState("");

  async function onRevoke(event) {
    event.preventDefault();
    setRevokeError("");
    setRevokeResult(null);
    const normalizedCertId = normalizeCertId(revokeCertId);
    if (!normalizedCertId) {
      setRevokeError("Enter certificate ID to revoke.");
      return;
    }
    setRevokeLoading(true);
    try {
      const { signer, address } = await ensureWallet();
      const contract = new Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.revokeCertificate(normalizedCertId);
      const receipt = await tx.wait();
      if (session?.accessToken && session?.user?.role === "INSTITUTION_ADMIN") {
        try {
          await authApi("/api/certificates/revoke", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              certId: normalizedCertId,
              txHash: receipt?.hash || tx.hash,
              connectedWallet: address,
            }),
          });
        } catch {
          // audit endpoint failures are non-blocking
        }
      }
      setRevokeResult({
        certId: normalizedCertId,
        txHash: receipt?.hash || tx.hash,
        issuer: address,
      });
    } catch (submitError) {
      setRevokeError(normalizeUserFacingError(submitError));
    } finally {
      setRevokeLoading(false);
    }
  }

  return (
    <section className="card">
      <div className="title-row">
        <h1>Revoke Certificate</h1>
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
    </section>
  );
}

function IssuerAdminPage({ ensureWallet }) {
  const [issuerAddress, setIssuerAddress] = useState("");
  const [issuerLoading, setIssuerLoading] = useState(false);
  const [issuerResult, setIssuerResult] = useState(null);
  const [issuerError, setIssuerError] = useState("");

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
        <h1>Issuer Admin Panel</h1>
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

function VerifyPage({ fixedCertId = "", profileMode = false }) {
  const [certId, setCertId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState(null);
  const [historyError, setHistoryError] = useState("");

  async function runVerification(targetCertId) {
    const certIdValue = normalizeCertId(targetCertId);
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
    const parsed = extractCertIdFromScanInput(certId);
    if (!parsed) {
      setError("Enter a certificate ID or paste a QR verification URL.");
      return;
    }
    setCertId(parsed);
    await runVerification(parsed);
  }

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const queryCertId = normalizeCertId(params.get("certId"));
    const seed = normalizeCertId(fixedCertId) || queryCertId;
    if (!seed) return;
    setCertId(seed);
    void runVerification(seed);
    // Intentionally run once on first render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fixedCertId]);

  function downloadProofJson() {
    if (!result?.certId) return;
    const url = `${API_BASE}/api/proof/${encodeURIComponent(result.certId)}.json`;
    window.open(url, "_blank", "noopener,noreferrer");
  }

  function downloadProofPdf() {
    if (!result?.certId) return;
    const url = `${API_BASE}/api/proof/${encodeURIComponent(result.certId)}.pdf`;
    window.open(url, "_blank", "noopener,noreferrer");
  }

  const statusClass =
    result?.status === "VALID"
      ? "status-valid"
      : result?.status === "REVOKED"
        ? "status-revoked"
        : "status-tampered";
  const statusTone =
    result?.status === "VALID"
      ? "tone-valid"
      : result?.status === "REVOKED"
        ? "tone-revoked"
        : result?.status === "TAMPERED"
          ? "tone-tampered"
          : "tone-pending";

  const timeline = history?.chain
    ? history.chain.flatMap((item, idx) => {
        const out = [];
        out.push({
          key: `${item.certId}-issued`,
          kind: idx === 0 ? "ISSUED" : "UPGRADED",
          certId: item.certId,
          txHash: item.issueTxHash || "",
          at: item.issuedAt || 0,
        });
        if (item.revoked) {
          out.push({
            key: `${item.certId}-revoked`,
            kind: "REVOKED",
            certId: item.certId,
            txHash: item.revokeTxHash || "",
            at: item.revokedAt || 0,
          });
        }
        return out;
      })
    : [];
  const institutionName = String(result?.metadata?.institutionName || "").trim();
  const issuer = String(result?.issuer || "").trim().toLowerCase();

  return (
    <section className="card">
      <div className="title-row">
        <h1>{profileMode ? "Certificate Profile" : "Verify Certificate"}</h1>
        <div className="info-wrap">
          <span className="info-button" aria-label="About verification" tabIndex={0}>i</span>
          <div className="info-tooltip">Paste certificate ID or QR URL to verify on-chain hash, timeline, and proof.</div>
        </div>
      </div>

      {!profileMode ? (
        <form className="form" onSubmit={onSubmit}>
          <label>
            Scan/Paste QR URL or Certificate ID
            <input
              value={certId}
              onChange={(e) => setCertId(e.target.value)}
              placeholder="https://.../verify?certId=... or cert-id"
              required
            />
          </label>
          <button type="submit" disabled={loading}>
            {loading ? "Verifying..." : "Verify"}
          </button>
        </form>
      ) : null}

      {error ? <p className="error">{error}</p> : null}

      {result ? (
        <div className={`result verify-hero ${statusTone}`}>
          <h2 className={statusClass}>{result.status}</h2>
          <p><strong>Certificate:</strong> {result.certId}</p>
          <p><strong>Issuer:</strong> {result.issuer}</p>
          <p><strong>Title:</strong> {String(result?.metadata?.title || "").trim() || "-"}</p>
          <p><strong>Institution:</strong> {String(result?.metadata?.institutionName || "").trim() || "-"}</p>
          <p><strong>Metadata CID:</strong> {result.metadataCid}</p>
          <p><strong>File CID:</strong> {result.fileCid}</p>
          <p><strong>Integrity Match:</strong> {String(result.integrityMatch)}</p>
          <p><strong>Revoked:</strong> {String(result.revoked)}</p>
          <div className="action-row">
            <button type="button" onClick={downloadProofJson}>Download Proof JSON</button>
            <button type="button" onClick={downloadProofPdf}>Download Proof PDF</button>
            {issuer ? <Link to={`/institutions/${encodeURIComponent(issuer)}`}>Institution Page</Link> : null}
          </div>
          <p className="sub">Status color updates instantly after verification.</p>
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
          {timeline.length > 0 ? (
            <div className="timeline-wrap">
              <h3>Timeline</h3>
              <ul className="timeline-list">
                {timeline.map((item) => (
                  <li key={item.key} className={`timeline-item timeline-${String(item.kind).toLowerCase()}`}>
                    <div className="timeline-kind">{item.kind}</div>
                    <div className="timeline-cert">{item.certId}</div>
                    <div className="timeline-meta">
                      {item.at ? new Date(Number(item.at) * 1000).toLocaleString() : "-"}
                    </div>
                    <div className="timeline-meta">
                      {item.txHash ? `${String(item.txHash).slice(0, 10)}...${String(item.txHash).slice(-8)}` : "-"}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}

      {institutionName && issuer ? (
        <div className="result">
          <h2>Public Profile</h2>
          <p>
            Open branded institution view:{" "}
            <Link to={`/institutions/${encodeURIComponent(issuer)}`}>{institutionName}</Link>
          </p>
        </div>
      ) : null}

      {historyError ? <p className="error">{historyError}</p> : null}
    </section>
  );
}

function CertificateProfilePage() {
  const params = useParams();
  const certId = normalizeCertId(params.certId || "");
  return <VerifyPage fixedCertId={certId} profileMode />;
}

function InstitutionPublicPage() {
  const params = useParams();
  const issuer = String(params.issuer || "").trim().toLowerCase();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [items, setItems] = useState([]);
  const [trust, setTrust] = useState(null);

  useEffect(() => {
    if (!issuer) {
      setError("Issuer is required.");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    Promise.all([
      apiJson(`${API_BASE}/api/certificates?issuer=${encodeURIComponent(issuer)}&limit=50`),
      apiJson(`${API_BASE}/api/issuers`),
    ])
      .then(([certsResp, issuersResp]) => {
        const list = Array.isArray(certsResp?.items) ? certsResp.items : [];
        setItems(list);
        const issuerRows = issuerRowsFromResponse(issuersResp);
        const row = issuerRows.find((x) => String(x.issuer || "").toLowerCase() === issuer) || null;
        setTrust(row);
      })
      .catch((e) => {
        setError(e.message || String(e));
      })
      .finally(() => setLoading(false));
  }, [issuer]);

  const top = items[0] || {};
  const institutionName = String(top.institutionName || "").trim() || "Institution";
  const brand = institutionBrandFrom(institutionName, issuer);
  const trustLabel = trust?.isAuthorized ? "Trusted Issuer" : "Unverified Issuer";
  const trustClass = trust?.isAuthorized ? "badge-trusted" : "badge-untrusted";

  return (
    <section className="card">
      <div className="institution-hero">
        <div className="institution-logo" style={brand.style}>{brand.initials}</div>
        <div>
          <h1>{brand.name}</h1>
          <p className="sub">{issuer}</p>
          <span className={`trust-badge ${trustClass}`}>{trustLabel}</span>
        </div>
      </div>
      {loading ? <p>Loading institution profile...</p> : null}
      {error ? <p className="error">{error}</p> : null}
      {!loading && !error ? (
        <div className="result">
          <h2>Certificates</h2>
          <p><strong>Total:</strong> {items.length}</p>
          <div className="timeline-wrap">
            <ul className="timeline-list">
              {items.map((item) => (
                <li key={item.certId} className="timeline-item">
                  <div className="timeline-kind">{item.revoked ? "REVOKED" : "ACTIVE"}</div>
                  <div className="timeline-cert">{item.certId}</div>
                  <div className="timeline-meta">{String(item.title || "").trim() || "-"}</div>
                  <div className="timeline-meta">
                    <Link to={`/certificate/${encodeURIComponent(item.certId)}`}>View profile</Link>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
    </section>
  );
}

export default App;
