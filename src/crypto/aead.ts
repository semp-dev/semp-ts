/**
 * AEAD primitives for SEMP.
 *
 * The two currently defined algorithm suites use different AEAD
 * variants:
 *
 *   - `x25519-chacha20-poly1305` - ChaCha20-Poly1305, 12-byte nonce.
 *   - `pq-kyber768-x25519`       - XChaCha20-Poly1305, 24-byte nonce.
 *
 * The sealing flow is identical in both cases: AEAD.Seal(key, nonce,
 * plaintext, aad) -> ciphertext || tag. Returns a single byte slice
 * with the authentication tag appended.
 *
 * @module
 */

import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js";

/** Algorithm name used in vectors and on the wire. */
export type AEADAlgorithm = "chacha20-poly1305" | "xchacha20-poly1305";

/**
 * Seal `plaintext` with the negotiated AEAD. Returns
 * `ciphertext || tag` (no nonce prefix; the caller composes the
 * wire layout per ENVELOPE.md §7.1.1).
 */
export function aeadSeal(
  algorithm: AEADAlgorithm,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const c = newCipher(algorithm, key, nonce, aad);
  return c.encrypt(plaintext);
}

/**
 * Open AEAD ciphertext. Throws on tag mismatch (Poly1305 fail).
 * Returns the plaintext on success.
 */
export function aeadOpen(
  algorithm: AEADAlgorithm,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const c = newCipher(algorithm, key, nonce, aad);
  return c.decrypt(ciphertext);
}

function newCipher(
  algorithm: AEADAlgorithm,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): { encrypt(pt: Uint8Array): Uint8Array; decrypt(ct: Uint8Array): Uint8Array } {
  switch (algorithm) {
    case "chacha20-poly1305":
      if (nonce.length !== 12) {
        throw new Error(`chacha20-poly1305 nonce must be 12 bytes, got ${nonce.length}`);
      }
      return chacha20poly1305(key, nonce, aad);
    case "xchacha20-poly1305":
      if (nonce.length !== 24) {
        throw new Error(`xchacha20-poly1305 nonce must be 24 bytes, got ${nonce.length}`);
      }
      return xchacha20poly1305(key, nonce, aad);
  }
}
