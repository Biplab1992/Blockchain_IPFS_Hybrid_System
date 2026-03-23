function normalizeCertId(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function canonicalizeDemoCertId(certId: string): string {
  const normalized = normalizeCertId(certId);
  const match = normalized.match(/^demo-cert-(\d+)$/);
  if (!match) return normalized;
  const padded = String(match[1]).padStart(3, "0");
  return `demo-cert-${padded}`;
}

function configuredTamperCertIds(): Set<string> {
  return new Set(
    String(process.env.DEMO_TAMPER_CERT_IDS || "")
      .split(",")
      .map((value) => canonicalizeDemoCertId(value))
      .filter(Boolean)
  );
}

export function shouldSimulateTamper(certId: string): boolean {
  const normalized = canonicalizeDemoCertId(certId);
  if (!normalized) return false;
  return configuredTamperCertIds().has(normalized);
}

export function bytesForIntegrityCheck(certId: string, bytes: Buffer): Buffer {
  if (!shouldSimulateTamper(certId)) {
    return bytes;
  }
  if (bytes.length === 0) {
    return Buffer.from([0x01]);
  }

  const tampered = Buffer.from(bytes);
  const lastIndex = tampered.length - 1;
  const lastByte = tampered[lastIndex] ?? 0;
  tampered[lastIndex] = lastByte ^ 0x01;
  return tampered;
}
