import crypto from "crypto";

export type EncryptedBlobSummary = {
  format: "certchain-encrypted-file/v1";
  alg: "aes-256-gcm";
  keyId: string;
  ivBase64: string;
  authTagBase64: string;
  plaintextBytes: number;
  ciphertextBytes: number;
};

export type PublicPinnedMetadata = {
  schema: "certchain-public-metadata/v2";
  visibility: "public-minimal";
  storageMode: "encrypted-blob";
  fileEnvelopeFormat: "certchain-encrypted-file/v1";
  encryptionAlg: "aes-256-gcm";
  certId: string;
  fileHash: string;
  version: number;
  replacesCertId: string;
};

export const ENCRYPTED_FILE_MAGIC = Buffer.from("CCEF1", "utf8");
export const ENCRYPTED_FILE_IV_BYTES = 12;
export const ENCRYPTED_FILE_AUTH_TAG_BYTES = 16;

export function decodeFileEncryptionKey(raw: string): Buffer {
  const trimmed = String(raw || "").trim();
  if (!trimmed) {
    throw new Error("FILE_ENCRYPTION_KEY is not configured");
  }

  let key: Buffer;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    key = Buffer.from(trimmed, "hex");
  } else {
    try {
      key = Buffer.from(trimmed, "base64");
    } catch {
      throw new Error("FILE_ENCRYPTION_KEY must be 32-byte hex or base64");
    }
  }

  if (key.length !== 32) {
    throw new Error("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes");
  }

  return key;
}

export function encryptPinnedFileWithKey(
  buffer: Buffer,
  key: Buffer,
  keyId: string
): { encryptedBytes: Buffer; summary: EncryptedBlobSummary } {
  const iv = crypto.randomBytes(ENCRYPTED_FILE_IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedBytes = Buffer.concat([ENCRYPTED_FILE_MAGIC, iv, authTag, ciphertext]);

  return {
    encryptedBytes,
    summary: {
      format: "certchain-encrypted-file/v1",
      alg: "aes-256-gcm",
      keyId,
      ivBase64: iv.toString("base64"),
      authTagBase64: authTag.toString("base64"),
      plaintextBytes: buffer.length,
      ciphertextBytes: ciphertext.length,
    },
  };
}

export function decryptPinnedFileWithKey(encryptedBytes: Buffer, key: Buffer): Buffer {
  const minBytes =
    ENCRYPTED_FILE_MAGIC.length + ENCRYPTED_FILE_IV_BYTES + ENCRYPTED_FILE_AUTH_TAG_BYTES;
  if (encryptedBytes.length < minBytes) {
    throw new Error("Encrypted file envelope is too short");
  }

  const magic = encryptedBytes.subarray(0, ENCRYPTED_FILE_MAGIC.length);
  if (!magic.equals(ENCRYPTED_FILE_MAGIC)) {
    throw new Error("Encrypted file envelope magic mismatch");
  }

  const ivStart = ENCRYPTED_FILE_MAGIC.length;
  const ivEnd = ivStart + ENCRYPTED_FILE_IV_BYTES;
  const tagEnd = ivEnd + ENCRYPTED_FILE_AUTH_TAG_BYTES;
  const iv = encryptedBytes.subarray(ivStart, ivEnd);
  const authTag = encryptedBytes.subarray(ivEnd, tagEnd);
  const ciphertext = encryptedBytes.subarray(tagEnd);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function buildPublicPinnedMetadata(input: {
  certId: string;
  fileHash: string;
  version: number;
  replacesCertId: string;
}): PublicPinnedMetadata {
  return {
    schema: "certchain-public-metadata/v2",
    visibility: "public-minimal",
    storageMode: "encrypted-blob",
    fileEnvelopeFormat: "certchain-encrypted-file/v1",
    encryptionAlg: "aes-256-gcm",
    certId: input.certId,
    fileHash: input.fileHash,
    version: input.version,
    replacesCertId: input.replacesCertId,
  };
}
