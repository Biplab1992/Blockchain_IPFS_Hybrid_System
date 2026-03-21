export type CertificatePrivateAccessRow = {
  cert_id: string;
  institution_id: string | null;
  issuer_wallet: string | null;
  title: string | null;
  recipient_name: string | null;
  recipient_email: string | null;
  metadata_cid: string | null;
  file_cid: string | null;
  issue_tx: string | null;
  source_file_name: string | null;
  source_file_type: string | null;
  issued_by_user_id: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

export type CertificatePrivateAccessInput = {
  certId: string;
  institutionId?: string | null;
  issuerWallet?: string | null;
  title?: string | null;
  recipientName?: string | null;
  recipientEmail?: string | null;
  metadataCid?: string | null;
  fileCid?: string | null;
  issueTx?: string | null;
  sourceFileName?: string | null;
  sourceFileType?: string | null;
  issuedByUserId?: string | null;
};

function normalizeCertId(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function toNullableTrimmed(value: unknown): string | null {
  const trimmed = String(value ?? "").trim();
  return trimmed || null;
}

export function normalizeEmail(value: unknown): string {
  const trimmed = String(value ?? "").trim().toLowerCase();
  if (!trimmed) return "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return "";
  return trimmed;
}

export function sanitizeDownloadFilename(value: unknown, fallbackBase = "certificate"): string {
  const fallback = String(fallbackBase || "certificate").trim() || "certificate";
  const cleaned = String(value ?? "")
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\.+$/g, "");
  return cleaned || fallback;
}

export function toCertificatePrivateAccessRow(
  input: CertificatePrivateAccessInput
): CertificatePrivateAccessRow {
  const certId = normalizeCertId(input.certId);
  if (!certId) {
    throw new Error("certId is required");
  }

  const recipientEmail = normalizeEmail(input.recipientEmail);

  return {
    cert_id: certId,
    institution_id: toNullableTrimmed(input.institutionId),
    issuer_wallet: toNullableTrimmed(input.issuerWallet)?.toLowerCase() || null,
    title: toNullableTrimmed(input.title),
    recipient_name: toNullableTrimmed(input.recipientName),
    recipient_email: recipientEmail || null,
    metadata_cid: toNullableTrimmed(input.metadataCid),
    file_cid: toNullableTrimmed(input.fileCid),
    issue_tx: toNullableTrimmed(input.issueTx),
    source_file_name: toNullableTrimmed(input.sourceFileName),
    source_file_type: toNullableTrimmed(input.sourceFileType),
    issued_by_user_id: toNullableTrimmed(input.issuedByUserId),
    updated_at: new Date().toISOString(),
  };
}

export function canRecipientAccessCertificate(
  userEmail: unknown,
  row: Pick<CertificatePrivateAccessRow, "recipient_email"> | null | undefined
): boolean {
  if (!row?.recipient_email) return false;
  return normalizeEmail(userEmail) === normalizeEmail(row.recipient_email);
}
