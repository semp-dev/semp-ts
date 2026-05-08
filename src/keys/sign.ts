/**
 * Ed25519 signature primitives for SEMP signed documents.
 *
 * SEMP uses Ed25519 for every signature (sender, forwarder,
 * domain, identity, recovery, transparency-STH, etc.). Each is
 * computed over a canonical-JSON representation prefixed with a
 * domain-separation tag from `ENVELOPE.md` §4.3.
 *
 * The keypair encoding follows libsodium / @noble convention:
 *   - secret seed: 32 bytes (the only secret material)
 *   - public key:  32 bytes (Ed25519 point)
 *
 * Some legacy APIs use a 64-byte "secret key" that concatenates the
 * seed and the public key. SEMP and this module deal exclusively
 * with the 32-byte seed form; convert at the boundary if needed.
 *
 * @module
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** Length of an Ed25519 public key (32 bytes). */
export const PublicKeySize = 32;
/** Length of an Ed25519 secret seed (32 bytes). */
export const SeedSize = 32;
/** Length of an Ed25519 signature (64 bytes). */
export const SignatureSize = 64;

/**
 * Derive the Ed25519 public key for the given secret seed.
 *
 * @param seed 32-byte secret seed.
 */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  expectLength("seed", seed, SeedSize);
  return ed25519.getPublicKey(seed);
}

/**
 * Sign `message` with the Ed25519 secret seed. Returns a 64-byte
 * detached signature.
 */
export function sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  expectLength("seed", seed, SeedSize);
  return ed25519.sign(message, seed);
}

/**
 * Verify a 64-byte detached Ed25519 signature against `publicKey`
 * over `message`. Returns true on accept, false on reject. Never
 * throws on a malformed signature; callers see false and surface
 * an `auth_failed` reason.
 */
export function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): boolean {
  if (publicKey.length !== PublicKeySize || signature.length !== SignatureSize) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Compute the SEMP key fingerprint per `KEY.md` §3 — SHA-256 of
 * the raw 32-byte public key, lowercase-hex encoded. Used as the
 * `key_id` field everywhere keys are referenced.
 */
export function fingerprint(publicKey: Uint8Array): string {
  expectLength("publicKey", publicKey, PublicKeySize);
  const sum = sha256(publicKey);
  let s = "";
  for (let i = 0; i < sum.length; i++) {
    s += (sum[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
}

function expectLength(name: string, b: Uint8Array, want: number): void {
  if (b.length !== want) {
    throw new Error(`keys: ${name} length ${b.length}, want ${want}`);
  }
}
