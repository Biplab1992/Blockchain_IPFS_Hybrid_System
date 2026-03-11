import assert from "assert";
import {
  buildPublicPinnedMetadata,
  decodeFileEncryptionKey,
  decryptPinnedFileWithKey,
  encryptPinnedFileWithKey,
} from "../src/file-envelope.js";

function main() {
  const keyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const key = decodeFileEncryptionKey(keyHex);
  assert.equal(key.length, 32, "decoded key must be 32 bytes");

  const plaintext = Buffer.from("unit-test-certificate-payload", "utf8");
  const { encryptedBytes, summary } = encryptPinnedFileWithKey(plaintext, key, "unit-test");
  assert.ok(encryptedBytes.length > plaintext.length, "envelope should be larger than plaintext");
  assert.equal(summary.alg, "aes-256-gcm");
  assert.equal(summary.keyId, "unit-test");
  assert.equal(summary.plaintextBytes, plaintext.length);

  const decrypted = decryptPinnedFileWithKey(encryptedBytes, key);
  assert.deepEqual(decrypted, plaintext, "decrypt(encrypt(x)) should roundtrip");

  const metadata = buildPublicPinnedMetadata({
    certId: "cert-unit-001",
    fileHash: "0xabc123",
    version: 1,
    replacesCertId: "",
  });
  assert.deepEqual(metadata, {
    schema: "certchain-public-metadata/v2",
    visibility: "public-minimal",
    storageMode: "encrypted-blob",
    fileEnvelopeFormat: "certchain-encrypted-file/v1",
    encryptionAlg: "aes-256-gcm",
    certId: "cert-unit-001",
    fileHash: "0xabc123",
    version: 1,
    replacesCertId: "",
  });
  assert.equal("fileCid" in metadata, false, "public metadata must not expose fileCid");
  assert.equal("recipient" in metadata, false, "public metadata must not expose recipient");

  console.log("File envelope unit checks passed.");
}

main();
