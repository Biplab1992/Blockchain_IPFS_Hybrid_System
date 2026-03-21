import assert from "assert";
import {
  canRecipientAccessCertificate,
  normalizeEmail,
  sanitizeDownloadFilename,
  toCertificatePrivateAccessRow,
} from "../src/certificate-private-access.js";

function main() {
  assert.equal(normalizeEmail(" Student@Example.com "), "student@example.com");
  assert.equal(normalizeEmail("not-an-email"), "");

  const row = toCertificatePrivateAccessRow({
    certId: " CERT-ABC-001 ",
    institutionId: "inst-1",
    issuerWallet: "0xAbCd",
    title: "Bachelor of Science",
    recipientName: "Ada Lovelace",
    recipientEmail: "Ada@Example.com",
    metadataCid: "bafy-meta",
    fileCid: "bafy-file",
    issueTx: "0x123",
    sourceFileName: "Ada Certificate.pdf",
    sourceFileType: "application/pdf",
    issuedByUserId: "user-1",
  });

  assert.equal(row.cert_id, "cert-abc-001");
  assert.equal(row.issuer_wallet, "0xabcd");
  assert.equal(row.recipient_email, "ada@example.com");
  assert.equal(row.title, "Bachelor of Science");
  assert.ok(row.updated_at, "updated_at should be populated");

  assert.equal(canRecipientAccessCertificate("ada@example.com", row), true);
  assert.equal(canRecipientAccessCertificate("other@example.com", row), false);
  assert.equal(canRecipientAccessCertificate("ada@example.com", null), false);

  assert.equal(
    sanitizeDownloadFilename('Ada: Certificate / 2026?', "fallback"),
    "Ada Certificate 2026"
  );
  assert.equal(sanitizeDownloadFilename("", "fallback"), "fallback");

  console.log("Certificate private access unit checks passed.");
}

main();
