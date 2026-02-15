import { useMemo, useState } from "react";
import { Link, Navigate, Route, Routes } from "react-router-dom";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:5050";
const TOKEN_KEY = "cert_demo_jwt";
const ADDRESS_KEY = "cert_demo_wallet";

function getStoredAuth() {
  return {
    token: localStorage.getItem(TOKEN_KEY) || "",
    address: localStorage.getItem(ADDRESS_KEY) || "",
  };
}

async function apiJson(url, options = {}) {
  const response = await fetch(url, options);
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
    throw new Error(parsed.error || parsed.message || `HTTP ${response.status}`);
  }
  return parsed;
}

async function signInWithWallet() {
  if (!window.ethereum) {
    throw new Error("Wallet not found. Install MetaMask or another EVM wallet.");
  }

  const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
  const address = accounts?.[0];
  if (!address) throw new Error("No wallet account selected.");

  const nonceResp = await apiJson(
    `${API_BASE}/api/auth/nonce?address=${encodeURIComponent(address)}`
  );
  const message = nonceResp.message;
  const nonce = nonceResp.nonce;

  const signature = await window.ethereum.request({
    method: "personal_sign",
    params: [message, address],
  });

  const verifyResp = await apiJson(`${API_BASE}/api/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address, nonce, signature }),
  });

  const token = verifyResp.token;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(ADDRESS_KEY, address);
  return { token, address };
}

function App() {
  const [auth, setAuth] = useState(() => getStoredAuth());

  const isAuthenticated = useMemo(() => Boolean(auth.token), [auth.token]);

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ADDRESS_KEY);
    setAuth({ token: "", address: "" });
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">Cert Registry Demo</div>
        <nav className="nav">
          <Link to="/verify">Verify</Link>
          <Link to="/issue">Issue</Link>
        </nav>
        <div className="auth-pill">
          {isAuthenticated ? (
            <>
              <span>{auth.address.slice(0, 6)}...{auth.address.slice(-4)}</span>
              <button onClick={logout}>Logout</button>
            </>
          ) : (
            <button
              onClick={async () => {
                try {
                  const nextAuth = await signInWithWallet();
                  setAuth(nextAuth);
                } catch (error) {
                  alert(error.message || String(error));
                }
              }}
            >
              Wallet Sign-In
            </button>
          )}
        </div>
      </header>

      <main className="page">
        <Routes>
          <Route path="/" element={<Navigate to="/verify" replace />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route
            path="/issue"
            element={<IssuePage auth={auth} onAuthChange={setAuth} />}
          />
        </Routes>
      </main>
    </div>
  );
}

function IssuePage({ auth, onAuthChange }) {
  const [certId, setCertId] = useState("");
  const [title, setTitle] = useState("");
  const [recipient, setRecipient] = useState("");
  const [version, setVersion] = useState(1);
  const [replacesCertId, setReplacesCertId] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function ensureAuth() {
    if (auth.token) return auth;
    const nextAuth = await signInWithWallet();
    onAuthChange(nextAuth);
    return nextAuth;
  }

  async function onSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!file) {
      setError("Select a PDF first.");
      return;
    }

    setLoading(true);
    try {
      const currentAuth = await ensureAuth();

      const form = new FormData();
      form.append("file", file);
      const pinResp = await apiJson(`${API_BASE}/api/pin`, {
        method: "POST",
        body: form,
      });

      const fileCid = pinResp.cid;
      const fileHash = `0x${String(pinResp.fileHash || "").replace(/^0x/, "")}`;

      const metadata = {
        title,
        recipient,
        sourceFileName: file.name,
        sourceFileType: file.type,
      };

      const issueResp = await apiJson(`${API_BASE}/api/issue`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${currentAuth.token}`,
        },
        body: JSON.stringify({
          certId,
          fileCid,
          fileHash,
          version: Number(version),
          replacesCertId,
          metadata,
        }),
      });

      setResult(issueResp);
    } catch (submitError) {
      setError(submitError.message || String(submitError));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="card">
      <h1>Issue Certificate</h1>
      <p className="sub">Protected route. Wallet login + JWT required.</p>

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
          Version
          <input
            type="number"
            min={1}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            required
          />
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
          <p><strong>metadataCid:</strong> {result.metadataCid}</p>
          <p><strong>txHash:</strong> {result.txHash}</p>
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

  async function onSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const verifyResp = await apiJson(
        `${API_BASE}/api/verify/${encodeURIComponent(certId)}`
      );
      setResult(verifyResp);
    } catch (verifyError) {
      setError(verifyError.message || String(verifyError));
    } finally {
      setLoading(false);
    }
  }

  const statusClass =
    result?.status === "VALID"
      ? "status-valid"
      : result?.status === "REVOKED"
        ? "status-revoked"
        : "status-tampered";

  return (
    <section className="card">
      <h1>Verify Certificate</h1>
      <p className="sub">Public route. Verify on-chain hash and metadata.</p>

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
          <p><strong>Metadata CID:</strong> {result.metadataCid}</p>
          <p><strong>File CID:</strong> {result.fileCid}</p>
          <p><strong>Integrity Match:</strong> {String(result.integrityMatch)}</p>
          <p><strong>Revoked:</strong> {String(result.revoked)}</p>
          <a
            href={`${API_BASE}/api/fetch/${result.fileCid}`}
            target="_blank"
            rel="noreferrer"
          >
            Download File
          </a>
          <pre>{JSON.stringify(result.metadata || {}, null, 2)}</pre>
        </div>
      ) : null}
    </section>
  );
}

export default App;
