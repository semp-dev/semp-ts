/**
 * Per-attachment key derivation, AAD construction, ciphertext hash,
 * URL/item validation per ATTACHMENTS.md §2.3, §3.1, §3.2, §4.1.
 *
 * @module
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

import { marshal as canonicalMarshal } from "../canonical/index.js";

import {
  type Item,
  HKDFInfoPrefix,
  HashAlgorithmSHA256,
} from "./types.js";

/**
 * Derive K_attachment from K_enclosure per §3.1: `HKDF-Expand(PRK =
 * K_enclosure, info = "semp-attachment:" || attachment_id, L)`.
 *
 * `kEnclosure` is used directly as the PRK (no Extract step). This
 * runs the RFC 5869 §2.3 expansion loop manually because @noble's
 * strict `expand` rejects PRK shorter than HashLen, while §3.1
 * passes a 32-byte K_enclosure as the PRK to a SHA-512-based HKDF.
 *
 * `outputLen` MUST equal the AEAD's key length for the negotiated
 * suite (32 bytes for both ChaCha20-Poly1305 and XChaCha20-Poly1305).
 */
export function deriveAttachmentKey(
  kEnclosure: Uint8Array,
  attachmentId: string,
  outputLen: number,
): Uint8Array {
  if (kEnclosure.length === 0) {
    throw new Error("largeattachment: empty K_enclosure");
  }
  if (attachmentId === "") {
    throw new Error("largeattachment: empty attachment_id");
  }
  if (!Number.isInteger(outputLen) || outputLen <= 0) {
    throw new Error(`largeattachment: invalid output length ${outputLen}`);
  }
  const info = new TextEncoder().encode(HKDFInfoPrefix + attachmentId);
  return hkdfExpandSHA512(kEnclosure, info, outputLen);
}

/**
 * AEAD additional-data input bound into each attachment's
 * ciphertext per §3.2: canonical UTF-8 JSON of the item with
 * `ciphertext_hash`, `aead_nonce`, and `extensions` set to empty
 * values (`""`, `""`, `{}` - but `extensions` is dropped by the
 * canonicalizer when it's the optional `extensions` field).
 *
 * Binding the metadata into AAD prevents an attacker from swapping
 * `filename` or `mime_type` while leaving the ciphertext intact.
 */
export function additionalData(item: Item): Uint8Array {
  const clone: Record<string, unknown> = { ...item };
  clone.ciphertext_hash = "";
  clone.aead_nonce = "";
  // Per §3.2 the AAD form has extensions zeroed. Drop the optional
  // field entirely so omission and an empty object produce identical
  // canonical bytes.
  delete clone.extensions;
  return canonicalMarshal(clone);
}

/** §2.3 ciphertext_hash for `ciphertext`, in `sha256:hex` form. */
export function ciphertextHash(ciphertext: Uint8Array): string {
  const sum = sha256(ciphertext);
  return HashAlgorithmSHA256 + ":" + bytesToHex(sum);
}

/**
 * Report whether `item.ciphertext_hash` matches the SHA-256 of
 * `ciphertext` per §6 step 3c. Returns true on match.
 */
export function verifyCiphertextHash(
  item: Item,
  ciphertext: Uint8Array,
): boolean {
  if (item.ciphertext_hash === "") {
    return false;
  }
  const colon = item.ciphertext_hash.indexOf(":");
  if (colon < 0) {
    return false;
  }
  const algo = item.ciphertext_hash.slice(0, colon);
  const hex = item.ciphertext_hash.slice(colon + 1);
  if (algo !== HashAlgorithmSHA256) {
    return false;
  }
  let want: Uint8Array;
  try {
    want = hexToBytes(hex);
  } catch {
    return false;
  }
  const got = sha256(ciphertext);
  return bytesEqual(want, got);
}

/**
 * Apply the §4.1 URL rules: scheme MUST be `https`; host MUST be a
 * fully qualified domain name or an IPv6 literal in brackets; bare
 * IPv4 literals MUST NOT be used. Throws on the first violation.
 */
export function validateUrl(raw: string): void {
  if (raw === "") {
    throw new Error("largeattachment: empty url");
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch (err) {
    throw new Error(
      `largeattachment: parse url: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (u.protocol !== "https:") {
    throw new Error(
      `largeattachment: url scheme ${JSON.stringify(u.protocol.replace(/:$/, ""))}, want https`,
    );
  }
  const host = u.hostname;
  if (host === "") {
    throw new Error("largeattachment: url has no host");
  }
  // u.hostname strips brackets from IPv6 literals; the original raw
  // URL may still reveal them. We accept IPv6 if it parses as an IP
  // and contains ':'.
  if (looksLikeIPv6(host)) {
    return; // IPv6 literal - accepted
  }
  if (looksLikeIPv4(host)) {
    throw new Error(
      `largeattachment: url host ${JSON.stringify(host)} is a bare IPv4 literal; FQDN required`,
    );
  }
  if (!host.includes(".")) {
    throw new Error(
      `largeattachment: url host ${JSON.stringify(host)} is not a fully qualified domain name`,
    );
  }
}

/** Structural validation per §2.3 + §4.1. Throws on first violation. */
export function validateItem(item: Item): void {
  if (typeof item.id !== "string" || item.id === "") {
    throw new Error("largeattachment: item missing id");
  }
  if (typeof item.filename !== "string" || item.filename === "") {
    throw new Error("largeattachment: item missing filename");
  }
  if (item.filename.includes("/") || item.filename.includes("\\")) {
    throw new Error(
      `largeattachment: filename ${JSON.stringify(item.filename)} contains path separator`,
    );
  }
  if (typeof item.mime_type !== "string" || item.mime_type === "") {
    throw new Error("largeattachment: item missing mime_type");
  }
  if (!Number.isInteger(item.plaintext_size) || item.plaintext_size < 0) {
    throw new Error(
      `largeattachment: plaintext_size ${item.plaintext_size} MUST be >= 0`,
    );
  }
  validateUrl(item.url);
  if (typeof item.ciphertext_hash !== "string" || item.ciphertext_hash === "") {
    throw new Error("largeattachment: item missing ciphertext_hash");
  }
  if (typeof item.aead_algorithm !== "string" || item.aead_algorithm === "") {
    throw new Error("largeattachment: item missing aead_algorithm");
  }
  if (typeof item.aead_nonce !== "string" || item.aead_nonce === "") {
    throw new Error("largeattachment: item missing aead_nonce");
  }
}

// ---------------------------------------------------------------------------
// Internal helpers

function looksLikeIPv6(host: string): boolean {
  // u.hostname for `https://[::1]/` returns `::1` (no brackets).
  return host.includes(":");
}

function looksLikeIPv4(host: string): boolean {
  // Strict dotted-quad: 4 numeric octets in [0, 255].
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  for (const p of parts) {
    if (p === "" || /[^\d]/.test(p)) {
      return false;
    }
    const n = Number.parseInt(p, 10);
    if (!Number.isFinite(n) || n < 0 || n > 255) {
      return false;
    }
  }
  return true;
}

/**
 * RFC 5869 HKDF-Expand with HMAC-SHA-512. Permits PRK shorter than
 * HashLen (matches §3.1's "PRK = K_enclosure" semantics).
 */
function hkdfExpandSHA512(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const hashLen = 64;
  const N = Math.ceil(length / hashLen);
  if (N > 255) {
    throw new Error("largeattachment: HKDF-Expand requested length too large");
  }
  let prev = new Uint8Array(0);
  const out = new Uint8Array(length);
  let written = 0;
  for (let i = 1; i <= N; i++) {
    const buf = new Uint8Array(prev.length + info.length + 1);
    buf.set(prev, 0);
    buf.set(info, prev.length);
    buf[prev.length + info.length] = i;
    const t = hmac(sha512, prk, buf);
    const take = Math.min(hashLen, length - written);
    out.set(t.slice(0, take), written);
    written += take;
    prev = t;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function bytesToHex(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("hex");
  }
  let out = "";
  for (let i = 0; i < b.length; i++) {
    out += (b[i] ?? 0).toString(16).padStart(2, "0");
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hex: odd length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error("hex: invalid character");
    }
    out[i] = byte;
  }
  return out;
}
