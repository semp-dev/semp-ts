/**
 * Large attachments per ATTACHMENTS.md.
 *
 * Sender-side encrypt + recipient-side decrypt flow, per-attachment
 * key derivation, AAD construction, ciphertext-hash binding,
 * extension-map helpers, plus a reference in-memory blob store.
 *
 * @module
 */

export {
  type ExtensionData,
  type Item,
  AEADChaCha20Poly1305,
  AEADXChaCha20Poly1305,
  ExtensionKey,
  HKDFInfoPrefix,
  HashAlgorithmSHA256,
} from "./types.js";

export {
  additionalData,
  ciphertextHash,
  deriveAttachmentKey,
  validateItem,
  validateUrl,
  verifyCiphertextHash,
} from "./crypto.js";

export {
  type AttachmentSuite,
  type EncryptAttachmentInput,
  type EncryptAttachmentResult,
  CiphertextHashMismatchError,
  decryptAttachment,
  encryptAttachment,
} from "./upload.js";

export {
  appendToExtensions,
  findById,
  readFromExtensions,
  removeFromExtensions,
  setOnExtensions,
} from "./enclosure.js";

export {
  type AttachmentStore,
  InMemoryAttachmentStore,
} from "./store.js";
