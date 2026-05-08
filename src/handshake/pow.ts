/**
 * Proof-of-Work verification per HANDSHAKE.md §2.2b and REPUTATION.md §8.3.
 *
 * Two PoW preimages exist in the spec:
 *
 * - **Challenge PoW** (this module): preimage is the UTF-8 string
 *   `base64(prefix) || ":" || challenge_id || ":" || base64(nonce)`.
 *   Used by the standard handshake-time difficulty challenge.
 * - **First-contact PoW** (HANDSHAKE.md §2.2a.4): preimage is the
 *   raw byte concatenation `prefix || nonce`. Different shape because
 *   §2.2a.4 binds the first-contact tuple via the prefix derivation
 *   itself, not via the preimage. See {@link verifyFirstContactSolution}.
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

/** Maximum difficulty the verifier accepts (HANDSHAKE.md §2.2b). */
export const MaxPoWDifficulty = 28;

/**
 * Verify a challenge-PoW solution. Returns null on success; an Error
 * on rejection so callers can surface a specific failure reason.
 *
 * - `prefix` is the raw 16-byte challenge prefix.
 * - `challengeId` is the ULID of the issued challenge.
 * - `nonceB64` is the candidate nonce as base64 (RFC 4648 §4).
 * - `claimedHashHex` is the hex digest the sender claims; the
 *   verifier MUST recompute and compare.
 * - `difficulty` is the required leading-zero-bit count of the SHA-256
 *   digest; verification rejects if the recomputed hash has fewer
 *   leading zeros.
 *
 * Cap at {@link MaxPoWDifficulty}: a verifier that accepts a higher
 * difficulty would silently validate a non-conformant challenge.
 */
export function verifyChallengeSolution(
  prefix: Uint8Array,
  challengeId: string,
  nonceB64: string,
  claimedHashHex: string,
  difficulty: number,
): Error | null {
  if (difficulty < 0) {
    return new Error("handshake: negative PoW difficulty");
  }
  if (difficulty > MaxPoWDifficulty) {
    return new Error("handshake: PoW difficulty exceeds protocol cap (28)");
  }
  if (challengeId === "") {
    return new Error("handshake: empty PoW challenge_id");
  }
  if (nonceB64 === "") {
    return new Error("handshake: empty PoW nonce");
  }
  // Nonce must be valid base64 — but we accept its bytes as-is in
  // the preimage (the spec hashes the base64 string, not the
  // decoded bytes).
  try {
    decodeBase64Strict(nonceB64);
  } catch {
    return new Error("handshake: PoW nonce is not valid base64");
  }
  const preimage = challengePreimage(prefix, challengeId, nonceB64);
  const sum = sha256(preimage);
  const computedHex = bytesToHex(sum);
  if (computedHex.toLowerCase() !== claimedHashHex.toLowerCase()) {
    return new Error("handshake: PoW hash mismatch");
  }
  if (leadingZeroBits(sum) < difficulty) {
    return new Error("handshake: PoW insufficient difficulty");
  }
  return null;
}

/**
 * First-contact PoW verifier per HANDSHAKE.md §2.2a.4. The
 * preimage is the raw concatenation `prefix || nonce`, hashed with
 * SHA-256. Returns the recomputed hash and the leading-zero bit
 * count; the caller decides whether the bit count meets its
 * difficulty threshold (the difficulty is a recipient policy, not a
 * protocol constant here).
 */
export function firstContactDigest(
  prefix: Uint8Array,
  nonce: Uint8Array,
): { hash: Uint8Array; leadingZeroBits: number } {
  const buf = new Uint8Array(prefix.length + nonce.length);
  buf.set(prefix, 0);
  buf.set(nonce, prefix.length);
  const sum = sha256(buf);
  return { hash: sum, leadingZeroBits: leadingZeroBits(sum) };
}

/**
 * Count the number of leading zero bits in a hash. Used by both
 * PoW preimages to assess whether a candidate solution meets the
 * required difficulty.
 */
export function leadingZeroBits(hash: Uint8Array): number {
  let n = 0;
  for (let i = 0; i < hash.length; i++) {
    const b = hash[i] ?? 0;
    if (b === 0) {
      n += 8;
      continue;
    }
    let bb = b;
    let bits = 8;
    while (bb !== 0) {
      bb = bb >>> 1;
      bits--;
    }
    n += bits;
    return n;
  }
  return n;
}

function challengePreimage(
  prefix: Uint8Array,
  challengeId: string,
  nonceB64: string,
): Uint8Array {
  const prefixB64 = bytesToBase64(prefix);
  return new TextEncoder().encode(`${prefixB64}:${challengeId}:${nonceB64}`);
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += (b[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
}

function bytesToBase64(b: Uint8Array): string {
  // Node and modern browsers both support btoa via TextDecoder, but
  // the cleanest portable path is Buffer when available, falling
  // back to a binary-string + btoa for browsers.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
}

function decodeBase64Strict(s: string): Uint8Array {
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
