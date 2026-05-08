/**
 * HMAC-SHA-256 helpers per ENVELOPE.md §4.3 (envelope session_mac)
 * and SESSION.md §2.1 (per-direction message MAC keys).
 *
 * @module
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Compute HMAC-SHA-256 over `message` keyed by `key`. The output is
 * always 32 bytes — the same width every SEMP MAC field expects.
 */
export function computeMAC(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha256, key, message);
}

/**
 * Constant-time MAC comparison. Returns true iff `expected` and
 * `actual` are byte-for-byte identical. Use when verifying a
 * received MAC against a recomputed one to avoid leaking bit-by-bit
 * timing information about the expected value.
 */
export function verifyMAC(expected: Uint8Array, actual: Uint8Array): boolean {
  if (expected.length !== actual.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= (expected[i] ?? 0) ^ (actual[i] ?? 0);
  }
  return diff === 0;
}
