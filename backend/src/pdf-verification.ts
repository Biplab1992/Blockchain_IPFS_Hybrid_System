import { PDFDocument } from "pdf-lib";

export type EmbeddedPdfMetadata = {
  certId: string;
  version: number;
  replacesCertId: string;
  sourceHash: string;
  embeddedAtIso: string;
};

export async function embedVerificationMetadataInPdf(input: Buffer, metadata: EmbeddedPdfMetadata): Promise<Buffer> {
  const pdf = await PDFDocument.load(input, {
    ignoreEncryption: true,
    updateMetadata: true,
  });

  const subject = `CertChain Verification | certId=${metadata.certId || "N/A"}`;
  const keywords = [
    `certId:${metadata.certId || ""}`,
    `version:${metadata.version}`,
    `replaces:${metadata.replacesCertId || ""}`,
    `sourceHash:${metadata.sourceHash}`,
  ].filter(Boolean);

  pdf.setTitle(`Certificate ${metadata.certId || "Verification"}`);
  pdf.setSubject(subject);
  pdf.setProducer("CertChain Backend");
  pdf.setCreator("CertChain Verification Pipeline");
  pdf.setCreationDate(new Date(metadata.embeddedAtIso));
  pdf.setModificationDate(new Date(metadata.embeddedAtIso));
  pdf.setKeywords(keywords);

  return Buffer.from(await pdf.save());
}
