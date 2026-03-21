import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { BrowserProvider, Contract } from "ethers";
import {
  API_BASE,
  CONTRACT_ABI,
  CONTRACT_ADDRESS,
  REQUIRED_CHAIN_ID,
  REQUIRED_CHAIN_ID_HEX,
  RPC_URL,
  SITE_TITLE,
  apiJson,
  buildQrCodeImageUrl,
  buildVerifyUrl,
  clearSession,
  isLikelyPublicVerifyUrl,
  issuerRowsFromResponse,
  listAllCertificatesByIssuer,
  loadSession,
  normalizeCertId,
  normalizeUserFacingError,
  saveSession,
} from "./lib/app-core";
import { CertificateProfilePage, InstitutionPublicPage, VerifyPage } from "./pages/PublicPages";

const ISSUER_STATUS_CACHE_KEY = "certchain_issuer_status_v1";
const ISSUER_STATUS_CACHE_TTL_MS = 10 * 60 * 1000;

function loadIssuerStatusCache() {
  try {
    return JSON.parse(localStorage.getItem(ISSUER_STATUS_CACHE_KEY) || "{}");
  } catch {
    return {};
  }
}

function readCachedIssuerStatus(wallet) {
  const key = String(wallet || "").trim().toLowerCase();
  if (!key) return null;
  const cache = loadIssuerStatusCache();
  const entry = cache?.[key];
  if (!entry || typeof entry !== "object") return null;
  const updatedAt = Number(entry.updatedAt || 0);
  if (!updatedAt || Date.now() - updatedAt > ISSUER_STATUS_CACHE_TTL_MS) return null;
  return {
    authorized: entry.authorized === true,
    source: String(entry.source || "").trim() || "cached",
    updatedAt,
  };
}

function writeCachedIssuerStatus(wallet, authorized, source = "live") {
  const key = String(wallet || "").trim().toLowerCase();
  if (!key) return;
  const cache = loadIssuerStatusCache();
  cache[key] = {
    authorized: authorized === true,
    source: String(source || "").trim() || "live",
    updatedAt: Date.now(),
  };
  localStorage.setItem(ISSUER_STATUS_CACHE_KEY, JSON.stringify(cache));
}

function deriveIssuerAuthorization(issuerStatus, cachedStatus = null) {
  const onChainAuthorized =
    typeof issuerStatus?.onChainAuthorized === "boolean"
      ? issuerStatus.onChainAuthorized
      : null;
  const indexedAuthorized =
    typeof issuerStatus?.indexedAuthorized === "boolean"
      ? issuerStatus.indexedAuthorized
      : null;

  if (onChainAuthorized === true) {
    return { authorized: true, source: "on-chain" };
  }
  if (indexedAuthorized === true) {
    return { authorized: true, source: "indexed" };
  }
  if (
    cachedStatus?.authorized === true &&
    onChainAuthorized === false &&
    (issuerStatus?.indexerSyncRunning || indexedAuthorized === null)
  ) {
    return { authorized: true, source: "cached" };
  }
  if (onChainAuthorized === false) {
    return { authorized: false, source: "on-chain" };
  }
  if (indexedAuthorized === false) {
    return { authorized: false, source: "indexed" };
  }
  if (cachedStatus?.authorized === true) {
    return { authorized: true, source: "cached" };
  }
  return { authorized: null, source: "" };
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

  async function authDownloadWithToken(path, fallbackFilename, accessToken) {
    const response = await fetch(`${API_BASE}${path}`, {
      credentials: "include",
      headers: {
        Authorization: `Bearer ${accessToken || ""}`,
      },
    });
    if (!response.ok) {
      const text = await response.text();
      let parsed = {};
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = { message: text };
        }
      }
      const parsedError = String(parsed.error || "").trim();
      const parsedMessage = String(parsed.message || "").trim();
      const message =
        (parsedError === "Secure certificate download failed" && parsedMessage
          ? parsedMessage
          : parsedError || parsedMessage) ||
        `HTTP ${response.status}`;
      throw new Error(message);
    }
    const blob = await response.blob();
    const disposition = String(response.headers.get("content-disposition") || "");
    const match = disposition.match(/filename="?([^";]+)"?/i);
    const filename = String(match?.[1] || fallbackFilename || "certificate.pdf").trim() || "certificate.pdf";
    const objectUrl = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(objectUrl);
    return { ok: true, filename };
  }

  async function authDownload(path, fallbackFilename, retried = false) {
    try {
      return await authDownloadWithToken(path, fallbackFilename, session?.accessToken || "");
    } catch (err) {
      const msg = String(err?.message || "").toLowerCase();
      const shouldTryRefresh = !retried && (msg.includes("http 401") || msg.includes("invalid/expired access token"));
      if (!shouldTryRefresh) throw err;
      const nextAccessToken = await refreshAccessToken();
      return authDownloadWithToken(path, fallbackFilename, nextAccessToken);
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
          <Route path="/verify" element={<VerifyPage session={session} authDownload={authDownload} />} />
          <Route path="/certificate/:certId" element={<CertificateProfilePage session={session} authDownload={authDownload} />} />
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
        <h2>Secure Certificate Downloads</h2>
        <p className="sub">Use the Verify page to open a certificate profile, then download the original PDF when the issuing institution linked that certificate to your account email.</p>
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
  const [pendingRequests, setPendingRequests] = useState([]);
  const [institutionNamesById, setInstitutionNamesById] = useState({});

  async function loadPendingRequests() {
    try {
      const [institutionsResp, requestsResp] = await Promise.all([
        authApi("/api/moe/institutions"),
        authApi("/api/moe/authorization-requests?status=PENDING"),
      ]);
      const institutions = Array.isArray(institutionsResp?.data) ? institutionsResp.data : [];
      const requestRows = Array.isArray(requestsResp?.data) ? requestsResp.data : [];
      const nextNames = {};
      for (const row of institutions) {
        const id = String(row?.id || "").trim();
        if (!id) continue;
        nextNames[id] = String(row?.name || "").trim() || id;
      }
      setInstitutionNamesById(nextNames);
      setPendingRequests(requestRows);
    } catch (err) {
      setError(normalizeUserFacingError(err));
    }
  }

  useEffect(() => {
    void loadPendingRequests();
  }, []);

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
      await loadPendingRequests();
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
      <div className="result">
        <h2>Pending Authorization Requests</h2>
        {pendingRequests.length === 0 ? (
          <p className="sub">No pending institution authorization requests.</p>
        ) : (
          <ul className="timeline-list">
            {pendingRequests.map((row) => {
              const institutionId = String(row?.institution_id || "").trim();
              const label = institutionNamesById[institutionId] || institutionId || "Institution";
              return (
                <li key={String(row?.id || institutionId)} className="timeline-item">
                  <div className="timeline-kind">PENDING</div>
                  <div className="timeline-cert">{label}</div>
                  <div className="timeline-meta mono">{String(row?.issuer_wallet || "").trim() || "-"}</div>
                  <div className="timeline-meta">{String(row?.note || "").trim() || "No note"}</div>
                </li>
              );
            })}
          </ul>
        )}
        <p className="sub">Open the Institutions page to authorize the wallet and clear the request.</p>
      </div>
    </section>
  );
}

function MoeInstitutionsPage({ authApi, showToast, ensureWallet }) {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [authorizingId, setAuthorizingId] = useState("");
  const [issuerAuthByWallet, setIssuerAuthByWallet] = useState({});
  const [pendingRequestsByInstitution, setPendingRequestsByInstitution] = useState({});
  async function load() {
    try {
      const [r, issuers, requests] = await Promise.all([
        authApi("/api/moe/institutions"),
        authApi("/api/issuers"),
        authApi("/api/moe/authorization-requests?status=PENDING"),
      ]);
      setRows(Array.isArray(r.data) ? r.data : []);
      const authMap = {};
      for (const row of issuerRowsFromResponse(issuers)) {
        authMap[String(row?.issuer || "").toLowerCase()] = Boolean(row?.isAuthorized);
      }
      setIssuerAuthByWallet(authMap);
      const requestMap = {};
      for (const row of Array.isArray(requests?.data) ? requests.data : []) {
        const institutionId = String(row?.institution_id || "").trim();
        if (!institutionId || requestMap[institutionId]) continue;
        requestMap[institutionId] = row;
      }
      for (const row of Array.isArray(r.data) ? r.data : []) {
        const institutionId = String(row?.id || "").trim();
        if (!institutionId || requestMap[institutionId]) continue;
        if (String(row?.authorization_request_status || "").trim().toUpperCase() === "PENDING") {
          requestMap[institutionId] = {
            institution_id: institutionId,
            issuer_wallet: String(row?.issuer_wallet || "").trim(),
            status: "PENDING",
            note: String(row?.authorization_request_note || "").trim() || null,
          };
        }
      }
      setPendingRequestsByInstitution(requestMap);
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
      if (!currentlyAuthorized && row?.id) {
        try {
          await authApi(`/api/moe/institutions/${encodeURIComponent(row.id)}/authorization-requests/approve`, {
            method: "POST",
          });
        } catch {
          // best-effort request resolution
        }
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
                    {pendingRequestsByInstitution[String(row.id || "")] ? (
                      <p className="sub">Request pending</p>
                    ) : null}
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
  const [issuerAuthorized, setIssuerAuthorized] = useState(null);
  const [issuerStatusDetails, setIssuerStatusDetails] = useState(null);
  const [issuerStatusError, setIssuerStatusError] = useState("");
  const [issuerStatusSource, setIssuerStatusSource] = useState("");
  const [issuedTotal, setIssuedTotal] = useState(0);
  const [latestAuthRequest, setLatestAuthRequest] = useState(null);
  const [requestAuthorizeNote, setRequestAuthorizeNote] = useState("");
  const [requestAuthorizeLoading, setRequestAuthorizeLoading] = useState(false);
  const [requestAuthorizeNotice, setRequestAuthorizeNotice] = useState("");
  const [moeInstitutions, setMoeInstitutions] = useState([]);
  const [selectedInstitutionId, setSelectedInstitutionId] = useState("");
  const [moeIssuerWallet, setMoeIssuerWallet] = useState("");
  const [authorizeError, setAuthorizeError] = useState("");
  const [authorizing, setAuthorizing] = useState(false);
  const role = String(session?.user?.role || "");
  const isMoe = role === "MOE_ADMIN";
  const isInstitutionAdmin = role === "INSTITUTION_ADMIN";

  useEffect(() => {
    let cancelled = false;

    async function fetchIssuerStatusWithRetry(wallet, attempts = 3) {
      let lastError = null;
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        try {
          return await authApi(`/api/issuers/${encodeURIComponent(wallet)}/status`);
        } catch (err) {
          lastError = err;
          if (attempt < attempts - 1) {
            await new Promise((resolve) => setTimeout(resolve, 1200 * (attempt + 1)));
          }
        }
      }
      throw lastError || new Error("Issuer status lookup failed");
    }

    if (isInstitutionAdmin) {
      void authApi("/api/institution/profile")
        .then(async (p) => {
          if (cancelled) return;
          setProfile(p);
          const wallet = String(p?.institution?.issuerWallet || "").trim().toLowerCase();
          const cachedIssuerStatus = readCachedIssuerStatus(wallet);
          if (cachedIssuerStatus) {
            setIssuerAuthorized(cachedIssuerStatus.authorized);
            setIssuerStatusSource(cachedIssuerStatus.source);
          } else {
            setIssuerAuthorized(null);
            setIssuerStatusSource("");
          }
          const institutionName = String(p?.institution?.name || "").trim().toLowerCase();
          const [issuerStatusResult, certRowsResult, latestRequestResult] = await Promise.allSettled([
            wallet
              ? fetchIssuerStatusWithRetry(wallet)
              : Promise.resolve({ onChainAuthorized: null, indexedAuthorized: null }),
            wallet ? listAllCertificatesByIssuer(authApi, wallet) : Promise.resolve([]),
            authApi("/api/institution/authorization-requests/latest").catch(() => ({ request: null })),
          ]);
          if (cancelled) return;

          if (issuerStatusResult.status === "fulfilled") {
            const issuerStatus = issuerStatusResult.value;
            const derivedIssuerStatus = deriveIssuerAuthorization(issuerStatus, cachedIssuerStatus);
            setIssuerAuthorized(derivedIssuerStatus.authorized);
            setIssuerStatusDetails(issuerStatus || null);
            setIssuerStatusSource(derivedIssuerStatus.source);
            if (derivedIssuerStatus.authorized !== null) {
              writeCachedIssuerStatus(wallet, derivedIssuerStatus.authorized, derivedIssuerStatus.source);
            }
            setIssuerStatusError("");
          } else {
            if (!cachedIssuerStatus) {
              setIssuerAuthorized(null);
              setIssuerStatusSource("");
            }
            setIssuerStatusDetails(null);
            setIssuerStatusError(normalizeUserFacingError(issuerStatusResult.reason));
          }

          if (latestRequestResult.status === "fulfilled") {
            const latestRequestResp = latestRequestResult.value;
            setLatestAuthRequest(latestRequestResp?.request || null);
            setRequestAuthorizeNotice(
              latestRequestResp?.request?.status === "PENDING"
                ? "Authorization request sent. It is now waiting for review in the MoE dashboard."
                : ""
            );
          } else {
            setLatestAuthRequest(null);
            setRequestAuthorizeNotice("");
          }

          if (certRowsResult.status === "fulfilled") {
            const certRows = Array.isArray(certRowsResult.value) ? certRowsResult.value : [];
            const institutionScopedCount = certRows.filter((row) => {
              const rowInstitution = String(row?.institutionName || "").trim().toLowerCase();
              return rowInstitution && institutionName && rowInstitution === institutionName;
            }).length;
            setIssuedTotal(institutionScopedCount);
          } else {
            setIssuedTotal(0);
          }
        })
        .catch((err) => {
          if (cancelled) return;
          setError(normalizeUserFacingError(err));
        });
    }
    if (isMoe) {
      void authApi("/api/moe/institutions")
        .then((r) => {
          if (cancelled) return;
          const rows = Array.isArray(r?.data) ? r.data : [];
          setMoeInstitutions(rows);
          if (rows[0]?.id) {
            setSelectedInstitutionId(rows[0].id);
            setMoeIssuerWallet(String(rows[0].issuer_wallet || "").trim());
          }
        })
        .catch((err) => {
          if (cancelled) return;
          setError(normalizeUserFacingError(err));
        });
    }

    return () => {
      cancelled = true;
    };
  }, [isInstitutionAdmin, isMoe]);

  const isBound = Boolean(profile?.binding?.verified);
  const boundAddress = String(profile?.binding?.walletAddress || "").trim();
  const status = String(profile?.institution?.status || "").trim();
  const issuerAuthorizationLabel =
    issuerAuthorized === true
      ? "On-chain authorized"
      : issuerAuthorized === false
        ? "Not authorized"
        : "Status unavailable";
  const issuerAuthorizationText =
    issuerAuthorized === true
      ? "Authorized"
      : issuerAuthorized === false
        ? "Not authorized"
        : "Unavailable";
  const issuerAuthorizationSourceNote =
    issuerAuthorized === true && issuerStatusSource === "indexed"
      ? "Using indexed authorization while the live wallet check catches up."
      : issuerAuthorized === true && issuerStatusSource === "cached"
        ? "Using the last confirmed authorization status while refreshing."
        : "";
  const checklist = [
    { label: "Activate", done: status === "ACTIVE", helper: status || "PENDING" },
    { label: "Bind Wallet", done: isBound, helper: boundAddress || "Not bound" },
    { label: "Authorize", done: issuerAuthorized === true, helper: issuerAuthorizationLabel },
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

  async function submitAuthorizationRequest() {
    setAuthorizeError("");
    setRequestAuthorizeNotice("");
    setRequestAuthorizeLoading(true);
    try {
      await authApi("/api/institution/authorization-requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: requestAuthorizeNote }),
      });
      const latestResp = await authApi("/api/institution/authorization-requests/latest");
      const nextRequest = latestResp?.request || null;
      setLatestAuthRequest(nextRequest);
      setRequestAuthorizeNote("");
      setRequestAuthorizeNotice(
        nextRequest?.status === "PENDING"
          ? "Authorization request sent. It is now waiting for review in the MoE dashboard."
          : "Authorization request submitted."
      );
      showToast?.("Authorization request sent to MoE.");
    } catch (err) {
      try {
        const latestResp = await authApi("/api/institution/authorization-requests/latest");
        const nextRequest = latestResp?.request || null;
        if (nextRequest?.status === "PENDING") {
          setLatestAuthRequest(nextRequest);
          setRequestAuthorizeNotice("Authorization request sent. It is now waiting for review in the MoE dashboard.");
          setRequestAuthorizeNote("");
          return;
        }
      } catch {
        // Ignore follow-up fetch errors and show the original submit error.
      }
      setAuthorizeError(normalizeUserFacingError(err));
    } finally {
      setRequestAuthorizeLoading(false);
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
        <p><strong>Issuer authorization:</strong> {issuerAuthorizationText}</p>
        {issuerStatusDetails ? (
          <p className="sub">
            On-chain: {String(Boolean(issuerStatusDetails?.onChainAuthorized))} | Indexed: {issuerStatusDetails?.indexedAuthorized === null ? "n/a" : String(Boolean(issuerStatusDetails?.indexedAuthorized))}
          </p>
        ) : null}
        {issuerAuthorizationSourceNote ? <p className="sub">{issuerAuthorizationSourceNote}</p> : null}
        {issuerStatusError ? <p className="sub">Authorization status check failed: {issuerStatusError}</p> : null}
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
          {issuerAuthorized === false && isBound ? (
            <>
              <hr className="section-divider" />
              <div className="title-row">
                <h2>Request Authorization</h2>
                <div className="info-wrap">
                  <span className="info-button" aria-label="About authorization request" tabIndex={0}>i</span>
                  <div className="info-tooltip">
                    If MoE authorization has not propagated or was not approved on-chain, send a request to appear in the MoE dashboard.
                  </div>
                </div>
              </div>
              {requestAuthorizeNotice ? (
                <div className="request-status-banner">
                  <strong>Request sent</strong>
                  <span>{requestAuthorizeNotice}</span>
                </div>
              ) : null}
              {latestAuthRequest?.status === "PENDING" ? (
                <div className="request-status-card">
                  <h3>Current Request</h3>
                  <p><strong>Status:</strong> PENDING</p>
                  <p><strong>Wallet:</strong> {String(profile?.institution?.issuerWallet || "").trim() || "-"}</p>
                  <p><strong>Note:</strong> {String(latestAuthRequest?.note || "").trim() || "No note provided"}</p>
                </div>
              ) : null}
              <div className="form request-form">
                <label>
                  Note (optional)
                  <textarea
                    value={requestAuthorizeNote}
                    onChange={(e) => setRequestAuthorizeNote(e.target.value)}
                    rows={3}
                  />
                </label>
              </div>
              <div className="action-row request-action-row">
                <button
                  type="button"
                  className={latestAuthRequest?.status === "PENDING" ? "success-button" : ""}
                  disabled={requestAuthorizeLoading || latestAuthRequest?.status === "PENDING"}
                  onClick={submitAuthorizationRequest}
                >
                  {requestAuthorizeLoading ? "Sending..." : latestAuthRequest?.status === "PENDING" ? "Request Pending" : "Request Authorization"}
                </button>
              </div>
            </>
          ) : null}
          {issuerAuthorized === null && isBound ? (
            <p className="sub">
              Authorization status is still being confirmed. If the backend just restarted, wait a moment and refresh this page.
            </p>
          ) : null}
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
  const [recipientEmail, setRecipientEmail] = useState("");
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

  async function pinCurrentFile(address) {
    const normalizedCertId = normalizeCertId(certId);
    const normalizedReplacesCertId = normalizeCertId(replacesCertId);
    if (!normalizedCertId) {
      throw new Error("Certificate ID is required.");
    }
    if (!file) {
      throw new Error("Select a PDF first.");
    }

    const form = new FormData();
    form.append("file", file);
    form.append("certId", normalizedCertId);
    form.append("title", title);
    form.append("recipient", recipient);
    form.append("recipientEmail", recipientEmail);
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

    const nextPinResult = {
      certId: normalizedCertId,
      title: String(pinResp?.metadata?.title || title || "").trim(),
      recipient: String(pinResp?.metadata?.recipient || recipient || "").trim(),
      recipientEmail: String(pinResp?.metadata?.recipientEmail || recipientEmail || "").trim(),
      institutionName: String(pinResp?.metadata?.institutionName || institutionName || "").trim(),
      metadataCid,
      fileCid,
      fileHash,
      verifyUrl: String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(normalizedCertId),
      sourceHash: String(pinResp.sourceHash || "").trim(),
      pdfMetadataEmbedded: Boolean(pinResp.pdfMetadataEmbedded),
      metadata: pinResp?.metadata || null,
    };
    return nextPinResult;
  }

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
      const pinned = await pinCurrentFile(address);
      const metadataCid = pinned.metadataCid;
      const fileCid = pinned.fileCid;
      const fileHash = pinned.fileHash;

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
      let privateAccessStored = false;
      let privateAccessWarning = "";
      try {
        const persistResp = await authApi("/api/certificates/issue", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            certId: normalizedCertId,
            metadataCid,
            fileCid,
            txHash: receipt?.hash || tx.hash,
            connectedWallet: address,
            title: title.trim(),
            recipient: recipient.trim(),
            recipientEmail: recipientEmail.trim(),
            institutionName: institutionName.trim(),
            sourceFileName: file?.name || "",
            sourceFileType: file?.type || "",
          }),
        });
        privateAccessStored = Boolean(persistResp?.privateAccessStored);
      } catch (persistError) {
        privateAccessWarning = normalizeUserFacingError(persistError);
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
        title: pinned.title,
        metadataCid,
        fileCid,
        fileHash,
        indexed,
        verifyUrl: pinned.verifyUrl,
        qrCodeImageUrl: buildQrCodeImageUrl(pinned.verifyUrl),
        txHash: receipt?.hash || tx.hash,
        issuer: address,
        institutionName: pinned.institutionName,
        privateAccessStored,
        privateAccessWarning,
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
          Recipient Name
          <input value={recipient} onChange={(e) => setRecipient(e.target.value)} />
        </label>
        <label>
          Recipient Email
          <input
            type="email"
            value={recipientEmail}
            onChange={(e) => setRecipientEmail(e.target.value)}
            placeholder="student@example.com"
          />
        </label>
        <p className="sub">Use the student account email here if the student should be able to download the original PDF securely.</p>
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

        <div className="action-row">
          <button type="submit" disabled={loading}>
            {loading ? "Issuing..." : "Issue"}
          </button>
        </div>
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
          <p><strong>Secure download access saved:</strong> {result.privateAccessStored ? "true" : "false"}</p>
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
          {result.privateAccessWarning ? (
            <p className="error">Secure download access was not saved: {result.privateAccessWarning}</p>
          ) : null}
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

export default App;
