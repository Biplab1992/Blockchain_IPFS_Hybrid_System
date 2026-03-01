import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, Route, Routes } from "react-router-dom";
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
const SITE_TITLE = "CertChain - Decentralized Academic Verification";

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

  useEffect(() => {
    document.title = SITE_TITLE;
  }, []);

  const isConnected = useMemo(() => Boolean(walletAddress), [walletAddress]);

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
            <div className="brand-main">CertChain</div>
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
            <Link to="/verify">Verify</Link>
            <Link to="/issue">Issue</Link>
          </nav>
        </div>
      </header>

      <main className="page">
        <Routes>
          <Route path="/" element={<Navigate to="/verify" replace />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route path="/issue" element={<IssuePage ensureWallet={ensureWallet} />} />
        </Routes>
      </main>
    </div>
  );
}

function IssuePage({ ensureWallet }) {
  const [certId, setCertId] = useState("");
  const [title, setTitle] = useState("");
  const [recipient, setRecipient] = useState("");
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
      const { signer, address } = await ensureWallet();

      const form = new FormData();
      form.append("file", file);
      form.append("certId", certId);
      form.append("title", title);
      form.append("recipient", recipient);
      form.append("version", String(version));
      form.append("replacesCertId", replacesCertId);

      const pinResp = await apiJson(`${API_BASE}/api/pin`, {
        method: "POST",
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
        metadataCid,
        fileCid,
        fileHash,
        indexed,
        verifyUrl: String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(certId),
        qrCodeImageUrl: buildQrCodeImageUrl(String(pinResp.verificationUrl || "").trim() || buildVerifyUrl(certId)),
        txHash: receipt?.hash || tx.hash,
        issuer: address,
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
