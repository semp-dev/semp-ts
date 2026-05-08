/**
 * Argon2id KDF wrapper for SEMP recovery bundles per RECOVERY.md
 * §2.4. The vectors fix all four parameters (memory, iterations,
 * parallelism, output length) so the runner can re-derive the
 * bundle key deterministically.
 *
 * @module
 */

import { argon2id } from "@noble/hashes/argon2.js";

/**
 * Argon2id key derivation.
 *
 * @param secret raw secret bytes (the recovery secret).
 * @param salt 16-byte salt.
 * @param memoryKB memory cost in KiB (e.g. 65536 for 64 MiB).
 * @param iterations time cost.
 * @param parallelism degree of parallelism (lanes).
 * @param outputLength output length in bytes (typically 32).
 */
export function argon2idKDF(
  secret: Uint8Array,
  salt: Uint8Array,
  memoryKB: number,
  iterations: number,
  parallelism: number,
  outputLength: number,
): Uint8Array {
  return argon2id(secret, salt, {
    m: memoryKB,
    t: iterations,
    p: parallelism,
    dkLen: outputLength,
  });
}
