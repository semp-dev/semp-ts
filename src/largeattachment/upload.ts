/**
 * Sender-side encrypt + recipient-side decrypt per ATTACHMENTS.md
 * §5 / §6.
 *
 * @module
 */

import { aeadOpen, aeadSeal } from "../crypto/index.js";

import {
  additionalData,
  ciphertextHash,
  deriveAttachmentKey,
  validateItem,
  validateUrl,
  verifyCiphertextHash,
} from "./crypto.js";
import {
  type Item,
  AEADChaCha20Poly1305,
  AEADXChaCha20Poly1305,
} from "./types.js";

/** Suite identifier for which AEAD an item uses per §3.2. */
export type AttachmentSuite =
  | "x25519-chacha20-poly1305"
  | "pq-kyber768-x25519";

/** Inputs to {@link encryptAttachment}. */
export interface EncryptAttachmentInput {
  /** Negotiated session suite — selects the AEAD per §3.2. */
  suite: AttachmentSuite;
  /** 32-byte K_enclosure from the envelope this item belongs to. */
  kEnclosure: Uint8Array;
  /** Plaintext bytes to encrypt. */
  plaintext: Uint8Array;
  /** Original filename. MUST NOT contain path separators. */
  filename: string;
  /** Plaintext MIME type. */
  mimeType: string;
  /** HTTPS URL the ciphertext will be retrievable at. */
  url: string;
  /** Optional pre-assigned attachment id; when omitted, a fresh ULID is minted. */
  id?: string;
  /** Optional pre-assigned AEAD nonce; when omitted, fresh entropy is sourced. */
  aeadNonce?: Uint8Array;
  /** Optional non-normative retrieval hints. */
  extensions?: Record<string, unknown>;
}

/** Result of a successful {@link encryptAttachment} call. */
export interface EncryptAttachmentResult {
  /** Fully populated item ready to drop into the enclosure. */
  item: Item;
  /** AEAD ciphertext bytes — uploaded by the caller to `item.url`. */
  ciphertext: Uint8Array;
}

/**
 * §5 sender-side flow: derive K_attachment, AEAD-seal the
 * plaintext, populate the item with `ciphertext_hash` and return
 * the bytes the caller uploads to `item.url`.
 *
 * Does NOT upload anything — the caller PUTs `ciphertext` to `url`.
 */
export function encryptAttachment(
  input: EncryptAttachmentInput,
): EncryptAttachmentResult {
  if (input.kEnclosure.length === 0) {
    throw new Error("largeattachment: empty K_enclosure");
  }
  if (input.filename === "" || input.mimeType === "" || input.url === "") {
    throw new Error("largeattachment: filename, mimeType, and url are required");
  }
  validateUrl(input.url);

  const algo = aeadAlgorithmFor(input.suite);
  const nonceLen = nonceLengthFor(algo);
  const keyLen = 32; // Both AEAD algorithms use a 32-byte key.

  const id = input.id ?? newULID();
  let nonce = input.aeadNonce;
  if (nonce === undefined) {
    nonce = new Uint8Array(nonceLen);
    globalThis.crypto.getRandomValues(nonce);
  } else if (nonce.length !== nonceLen) {
    throw new Error(
      `largeattachment: nonce length ${nonce.length}, want ${nonceLen} for ${algo}`,
    );
  }

  const kAttachment = deriveAttachmentKey(input.kEnclosure, id, keyLen);

  // Build the partly-populated item for AAD. The AAD function
  // strips ciphertext_hash + extensions internally so we leave them
  // out of the input; aead_nonce is also stripped but we still set
  // it on the item so the final result is complete.
  const item: Item = {
    id,
    filename: input.filename,
    mime_type: input.mimeType,
    plaintext_size: input.plaintext.length,
    url: input.url,
    aead_algorithm: algo,
    aead_nonce: base64Encode(nonce),
    ciphertext_hash: "",
  };
  const aad = additionalData(item);
  const ciphertext = aeadSeal(algo, kAttachment, nonce, input.plaintext, aad);
  item.ciphertext_hash = ciphertextHash(ciphertext);
  if (input.extensions !== undefined) {
    item.extensions = input.extensions;
  }
  return { item, ciphertext };
}

/**
 * §6 recipient-side flow: verify ciphertext_hash, derive
 * K_attachment, AEAD-open the ciphertext, return plaintext.
 *
 * Throws {@link CiphertextHashMismatchError} on §7.2 ciphertext-
 * integrity failure (BEFORE attempting AEAD open). Throws on
 * §7.3 decryption-integrity failure when AEAD open fails.
 */
export function decryptAttachment(
  suite: AttachmentSuite,
  kEnclosure: Uint8Array,
  item: Item,
  ciphertext: Uint8Array,
): Uint8Array {
  if (kEnclosure.length === 0) {
    throw new Error("largeattachment: empty K_enclosure");
  }
  validateItem(item);

  const expectedAlgo = aeadAlgorithmFor(suite);
  if (item.aead_algorithm !== expectedAlgo) {
    throw new Error(
      `largeattachment: item aead_algorithm ${JSON.stringify(item.aead_algorithm)} does not match suite ${JSON.stringify(suite)} (expected ${expectedAlgo})`,
    );
  }
  if (!verifyCiphertextHash(item, ciphertext)) {
    throw new CiphertextHashMismatchError(
      "largeattachment: ciphertext hash mismatch",
    );
  }

  const nonce = base64Decode(item.aead_nonce);
  const nonceLen = nonceLengthFor(expectedAlgo);
  if (nonce.length !== nonceLen) {
    throw new Error(
      `largeattachment: aead_nonce length ${nonce.length}, want ${nonceLen} for ${expectedAlgo}`,
    );
  }
  const kAttachment = deriveAttachmentKey(kEnclosure, item.id, 32);
  const aad = additionalData(item);
  return aeadOpen(expectedAlgo, kAttachment, nonce, ciphertext, aad);
}

/**
 * Thrown by {@link decryptAttachment} when `item.ciphertext_hash`
 * does not match the SHA-256 of the supplied ciphertext per §7.2.
 */
export class CiphertextHashMismatchError extends Error {
  override readonly name = "CiphertextHashMismatchError";
}

// ---------------------------------------------------------------------------
// Suite → AEAD mapping per §3.2

function aeadAlgorithmFor(
  suite: AttachmentSuite,
): "chacha20-poly1305" | "xchacha20-poly1305" {
  switch (suite) {
    case "x25519-chacha20-poly1305":
      return AEADChaCha20Poly1305;
    case "pq-kyber768-x25519":
      return AEADXChaCha20Poly1305;
    default:
      throw new Error(`largeattachment: no attachment AEAD wired for suite ${JSON.stringify(suite)}`);
  }
}

function nonceLengthFor(
  algo: "chacha20-poly1305" | "xchacha20-poly1305",
): number {
  return algo === "chacha20-poly1305" ? 12 : 24;
}

// ---------------------------------------------------------------------------
// ULID minting (inlined; matches semp-go's local helper)

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newULID(): string {
  const bits = new Uint8Array(16);
  const ms = BigInt(Date.now());
  bits[0] = Number((ms >> 40n) & 0xffn);
  bits[1] = Number((ms >> 32n) & 0xffn);
  bits[2] = Number((ms >> 24n) & 0xffn);
  bits[3] = Number((ms >> 16n) & 0xffn);
  bits[4] = Number((ms >> 8n) & 0xffn);
  bits[5] = Number(ms & 0xffn);
  globalThis.crypto.getRandomValues(bits.subarray(6));

  // Crockford base32 encoding of 16 bytes → 26 chars.
  // Treat bits as two big-endian 64-bit words.
  let u = 0n;
  for (let i = 0; i < 8; i++) {
    u = (u << 8n) | BigInt(bits[i] ?? 0);
  }
  let u2 = 0n;
  for (let i = 8; i < 16; i++) {
    u2 = (u2 << 8n) | BigInt(bits[i] ?? 0);
  }
  const out = new Array<string>(26);
  for (let i = 25; i >= 13; i--) {
    out[i] = ULID_ALPHABET[Number(u2 & 31n)] ?? "0";
    u2 >>= 5n;
  }
  for (let i = 12; i >= 0; i--) {
    out[i] = ULID_ALPHABET[Number(u & 31n)] ?? "0";
    u >>= 5n;
  }
  return out.join("");
}

function base64Encode(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
}

function base64Decode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
