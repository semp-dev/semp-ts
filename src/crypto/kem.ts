/**
 * Key encapsulation primitives for the two SEMP suites.
 *
 *   - X25519 (baseline, classical ECDH treated as a KEM).
 *   - Kyber768 + X25519 hybrid (PQ; ML-KEM-768 final per FIPS 203).
 *
 * The hybrid wire layout matches ENVELOPE.md §4.4.1 and the
 * cross-language vectors:
 *
 *   - public key:  kyber_pub (1184)  || x25519_pub (32)        = 1216
 *   - private key: kyber_priv (2400) || x25519_priv (32)       = 2432
 *   - ciphertext:  kyber_ct (1088)   || x25519_eph_pub (32)    = 1120
 *   - shared:      K_kyber (32)      || K_x25519 (32)          = 64
 *
 * The order is Kyber-FIRST in every layout. Earlier semp-go releases
 * placed X25519 first; the cross-language vectors enforce this
 * ordering.
 *
 * @module
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

/** ML-KEM-768 public key size. */
export const Kyber768PublicKeySize = 1184;
/** ML-KEM-768 private key size. */
export const Kyber768PrivateKeySize = 2400;
/** ML-KEM-768 ciphertext size. */
export const Kyber768CiphertextSize = 1088;
/** ML-KEM-768 shared-key size (also matches X25519). */
export const Kyber768SharedKeySize = 32;
/** X25519 byte width (point + scalar). */
export const X25519Size = 32;

/** Hybrid public-key wire size. */
export const HybridPublicKeySize = Kyber768PublicKeySize + X25519Size; // 1216
/** Hybrid private-key wire size. */
export const HybridPrivateKeySize = Kyber768PrivateKeySize + X25519Size; // 2432
/** Hybrid ciphertext wire size. */
export const HybridCiphertextSize = Kyber768CiphertextSize + X25519Size; // 1120
/** Combined hybrid shared secret width. */
export const HybridSharedSecretSize = Kyber768SharedKeySize + X25519Size; // 64

// ---------------------------------------------------------------------------
// X25519 (baseline KEM)

/** X25519 ECDH treated as KEM: pub^priv = shared secret. */
export function x25519Agree(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(secretKey, publicKey);
}

/** X25519 derive public key from a 32-byte secret seed. */
export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(secretKey);
}

// ---------------------------------------------------------------------------
// Kyber768 / ML-KEM-768

/**
 * Derive an ML-KEM-768 keypair deterministically from a 64-byte
 * seed (FIPS 203 internal `d || z`). USE CASES are intentionally
 * narrow: cross-language test vectors and determinism audits.
 * Production keygen MUST use entropy.
 */
export function kyber768KeyPairFromSeed(seed: Uint8Array): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  if (seed.length !== 64) {
    throw new Error(`kyber768KeyPairFromSeed: seed must be 64 bytes, got ${seed.length}`);
  }
  const { secretKey, publicKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

/**
 * ML-KEM-768 deterministic encapsulation. `m` is the 32-byte
 * randomness FIPS 203 names; pinning it lets the wrap output be
 * byte-deterministic for cross-language test vectors.
 */
export function kyber768EncapsulateDeterministic(
  publicKey: Uint8Array,
  m: Uint8Array,
): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, m);
  return { ciphertext: cipherText, sharedSecret };
}

/** ML-KEM-768 decapsulation. */
export function kyber768Decapsulate(
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

// ---------------------------------------------------------------------------
// Hybrid (Kyber768 + X25519) per SEMP suite `pq-kyber768-x25519`.

/**
 * Assemble a hybrid private key from the Kyber768 private bytes
 * and an X25519 32-byte private. Layout: `kyberPriv || x25519Priv`.
 *
 * Test/vector-only helper. Production code MUST get hybrid keys
 * from a real entropy-driven keygen.
 */
export function hybridPrivateKeyFromKyberAndX25519(
  x25519Priv: Uint8Array,
  kyberPriv: Uint8Array,
): Uint8Array {
  if (x25519Priv.length !== X25519Size) {
    throw new Error(`x25519 priv must be ${X25519Size} bytes`);
  }
  if (kyberPriv.length !== Kyber768PrivateKeySize) {
    throw new Error(`kyber priv must be ${Kyber768PrivateKeySize} bytes`);
  }
  const out = new Uint8Array(HybridPrivateKeySize);
  out.set(kyberPriv, 0);
  out.set(x25519Priv, Kyber768PrivateKeySize);
  return out;
}

/**
 * Generate a fresh hybrid keypair. The public half is
 * `kyberPub || x25519Pub` (1216 bytes), the private half is
 * `kyberPriv || x25519Priv` (2432 bytes). Used by the initiator
 * side of the handshake to produce an ephemeral hybrid pub for
 * INIT.
 *
 * Both halves are entropy-driven via `globalThis.crypto`. The
 * Kyber half uses ML-KEM-768 keygen with a fresh 64-byte seed.
 */
export function hybridGenerateKeyPair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  const xPriv = new Uint8Array(X25519Size);
  globalThis.crypto.getRandomValues(xPriv);
  const xPub = x25519PublicKey(xPriv);
  const seed = new Uint8Array(64);
  globalThis.crypto.getRandomValues(seed);
  const { secretKey: kyberPriv, publicKey: kyberPub } = ml_kem768.keygen(seed);
  const pub = new Uint8Array(HybridPublicKeySize);
  pub.set(kyberPub, 0);
  pub.set(xPub, Kyber768PublicKeySize);
  const priv = new Uint8Array(HybridPrivateKeySize);
  priv.set(kyberPriv, 0);
  priv.set(xPriv, Kyber768PrivateKeySize);
  return { publicKey: pub, secretKey: priv };
}

/**
 * Hybrid Encapsulate. Responder-side: takes the initiator's
 * hybrid public key (`kyberPub || x25519Pub`), generates a fresh
 * ephemeral X25519 keypair, encapsulates a Kyber shared key
 * under the initiator's Kyber pub, and returns:
 *
 *   - sharedSecret: `K_kyber || K_x25519` (64 bytes)
 *   - ciphertext:   `kyberCt || responderX25519Pub` (1120 bytes)
 *
 * Wire layout matches `ENVELOPE.md` §4.4.1 (Kyber FIRST).
 */
export function hybridEncapsulate(
  remotePub: Uint8Array,
): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  if (remotePub.length !== HybridPublicKeySize) {
    throw new Error(
      `hybrid Encapsulate: remote pub ${remotePub.length} bytes, want ${HybridPublicKeySize}`,
    );
  }
  const kyberRemote = remotePub.slice(0, Kyber768PublicKeySize);
  const xRemote = remotePub.slice(Kyber768PublicKeySize);
  const xEphPriv = new Uint8Array(X25519Size);
  globalThis.crypto.getRandomValues(xEphPriv);
  const xEphPub = x25519PublicKey(xEphPriv);
  const xSS = x25519Agree(xEphPriv, xRemote);
  // Burn the X25519 ephemeral private now that the shared
  // secret is in hand.
  xEphPriv.fill(0);
  // ML-KEM-768 entropy-driven encapsulation. The noble API
  // expects the FIPS 203 `m` randomness as the second argument;
  // when omitted it pulls from `globalThis.crypto`.
  const m = new Uint8Array(32);
  globalThis.crypto.getRandomValues(m);
  const { cipherText: kyberCt, sharedSecret: kyberSS } = ml_kem768.encapsulate(
    kyberRemote,
    m,
  );
  const ciphertext = new Uint8Array(HybridCiphertextSize);
  ciphertext.set(kyberCt, 0);
  ciphertext.set(xEphPub, Kyber768CiphertextSize);
  const sharedSecret = new Uint8Array(HybridSharedSecretSize);
  sharedSecret.set(kyberSS, 0);
  sharedSecret.set(xSS, Kyber768SharedKeySize);
  return { ciphertext, sharedSecret };
}

/**
 * Hybrid Decapsulate. Reverses the responder-side encapsulation
 * (kyber half + X25519 ECDH against the sender's ephemeral pub)
 * and returns the combined shared secret `K_kyber || K_x25519`.
 *
 * Wire layout:
 *   - localPriv:  kyberPriv (2400) || x25519Priv (32)
 *   - ciphertext: kyberCt   (1088) || x25519EphPub (32)
 *
 * Used by the seal Unwrap path. Production code goes through the
 * seal package; this primitive is exposed for the vectors runner.
 */
export function hybridDecapsulate(
  ciphertext: Uint8Array,
  localPriv: Uint8Array,
): Uint8Array {
  if (ciphertext.length !== HybridCiphertextSize) {
    throw new Error(
      `hybrid Decapsulate: ciphertext ${ciphertext.length} bytes, want ${HybridCiphertextSize}`,
    );
  }
  if (localPriv.length !== HybridPrivateKeySize) {
    throw new Error(
      `hybrid Decapsulate: priv ${localPriv.length} bytes, want ${HybridPrivateKeySize}`,
    );
  }
  const kyberCt = ciphertext.slice(0, Kyber768CiphertextSize);
  const xEphPub = ciphertext.slice(Kyber768CiphertextSize);
  const kyberPriv = localPriv.slice(0, Kyber768PrivateKeySize);
  const xLocalPriv = localPriv.slice(Kyber768PrivateKeySize);

  const kyberSS = kyber768Decapsulate(kyberPriv, kyberCt);
  const xSS = x25519Agree(xLocalPriv, xEphPub);

  const shared = new Uint8Array(HybridSharedSecretSize);
  shared.set(kyberSS, 0);
  shared.set(xSS, Kyber768SharedKeySize);
  return shared;
}
