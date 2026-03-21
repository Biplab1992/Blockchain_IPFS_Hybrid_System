import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  API_BASE,
  apiJson,
  extractCertIdFromScanInput,
  institutionBrandFrom,
  issuerRowsFromResponse,
  normalizeCertId,
} from "../lib/app-core";

export function VerifyPage({ fixedCertId = "", profileMode = false, session = null, authDownload = null }) {
  const [certId, setCertId] = useState("");
  const [loading, setLoading] = useState(false);
  const [downloadLoading, setDownloadLoading] = useState(false);
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

  async function downloadOriginalPdf() {
    if (!result?.certId || !authDownload) return;
    setError("");
    setDownloadLoading(true);
    try {
      await authDownload(
        `/api/certificates/${encodeURIComponent(result.certId)}/download`,
        `${result.certId}.pdf`
      );
    } catch (downloadError) {
      setError(downloadError.message || String(downloadError));
    } finally {
      setDownloadLoading(false);
    }
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
              onChange={(event) => setCertId(event.target.value)}
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
          <p><strong>Metadata CID:</strong> {result.metadataCid}</p>
          <p><strong>Storage:</strong> {String(result.storageMode || "-")} ({String(result.encryptionAlg || "-")})</p>
          <p><strong>Version:</strong> {String(result.version ?? "-")}</p>
          <p><strong>Replaces:</strong> {String(result.replacesCertId || "-")}</p>
          <p><strong>Integrity Match:</strong> {String(result.integrityMatch)}</p>
          <p><strong>Revoked:</strong> {String(result.revoked)}</p>
          <p className="sub">
            Public verification hides recipient details.
            {session?.accessToken
              ? " Authorized users can download the original PDF."
              : " Sign in as an authorized user to download the original PDF."}
          </p>
          <div className="action-row">
            <button type="button" onClick={downloadProofJson}>Download Proof JSON</button>
            <button type="button" onClick={downloadProofPdf}>Download Proof PDF</button>
            {session?.accessToken && authDownload ? (
              <button type="button" onClick={downloadOriginalPdf} disabled={downloadLoading}>
                {downloadLoading ? "Downloading..." : "Download Original PDF"}
              </button>
            ) : null}
            {issuer ? <Link to={`/institutions/${encodeURIComponent(issuer)}`}>Institution Page</Link> : null}
          </div>
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

      {historyError ? <p className="error">{historyError}</p> : null}
    </section>
  );
}

export function CertificateProfilePage({ session = null, authDownload = null }) {
  const params = useParams();
  const certId = normalizeCertId(params.certId || "");
  return <VerifyPage fixedCertId={certId} profileMode session={session} authDownload={authDownload} />;
}

export function InstitutionPublicPage() {
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
        const row = issuerRows.find((item) => String(item.issuer || "").toLowerCase() === issuer) || null;
        setTrust(row);
      })
      .catch((err) => {
        setError(err.message || String(err));
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
