/**
 * Bundle-payload encryption + recovery key derivation per
 * RECOVERY.md §2.5 + §3.2 + §3.3.
 *
 *   - {@link normalizeRecoverySecret}: NFKC for passphrases /
 *     lower+space-join for recovery codes per §3.2.
 *   - {@link deriveBundleKey}: Argon2id over the normalized secret
 *     yields the 32-byte K_bundle per §2.5.
 *   - {@link deriveRecoverySignKey}: HKDF-Expand(K_bundle, ...) →
 *     Ed25519 (recovery_sign_sk, recovery_verify_pk) per §3.3.
 *   - {@link encryptBundlePayload} / {@link decryptBundlePayload}:
 *     XChaCha20-Poly1305 per §2.5.
 *
 * @module
 */

import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";

import { publicKeyFromSeed } from "../keys/index.js";

import {
  type BundleKDF,
  KDFAlgorithmArgon2id,
  MinKDFIterations,
  MinKDFMemoryKB,
  MinKDFParallelism,
  MinKDFSaltBytes,
} from "./types.js";

/** Recovery secret encoding per §3.1. */
export type SecretForm = "passphrase" | "recovery_code";

/** Hard minimum on a passphrase secret's UTF-8 byte length per §3.1. */
export const MinPassphraseBytes = 12;

/** HKDF info string for the recovery signing-key seed per §3.3. */
export const RecoverySignKeyInfo = "SEMP-RECOVERY-SIGN-KEY-v1";

/**
 * Return the UTF-8 byte representation of `raw` after applying the
 * §3.2 normalization rules for `form`:
 *
 *  - `passphrase`: NFKC, trimmed of leading/trailing whitespace.
 *  - `recovery_code`: split on whitespace, lowercase each token,
 *    join with single ASCII space.
 */
export function normalizeRecoverySecret(
  form: SecretForm,
  raw: string,
): Uint8Array {
  switch (form) {
    case "passphrase": {
      const s = raw.normalize("NFKC").trim();
      const bytes = new TextEncoder().encode(s);
      if (bytes.length < MinPassphraseBytes) {
        throw new Error(
          `recovery: passphrase length ${bytes.length} below ${MinPassphraseBytes}-byte minimum`,
        );
      }
      return bytes;
    }
    case "recovery_code": {
      const fields = raw.trim().split(/\s+/).filter((s) => s !== "");
      if (fields.length === 0) {
        throw new Error("recovery: recovery code is empty");
      }
      const joined = fields.map((w) => w.toLowerCase()).join(" ");
      return new TextEncoder().encode(joined);
    }
    default:
      throw new Error(`recovery: unsupported secret form ${JSON.stringify(form)}`);
  }
}

/**
 * Run Argon2id over `secretBytes` with the parameters in `kdf` and
 * return the 32-byte K_bundle per §2.5. Validates that `kdf` meets
 * the §2.5 minima before computing.
 */
export function deriveBundleKey(
  secretBytes: Uint8Array,
  kdf: BundleKDF,
): Uint8Array {
  if (secretBytes.length === 0) {
    throw new Error("recovery: empty recovery secret bytes");
  }
  validateKDFParams(kdf);
  const salt = base64Decode(kdf.salt);
  if (salt.length < MinKDFSaltBytes) {
    throw new Error(
      `recovery: kdf salt length ${salt.length} below ${MinKDFSaltBytes}-byte minimum`,
    );
  }
  return argon2id(secretBytes, salt, {
    t: kdf.iterations,
    m: kdf.memory_kb,
    p: kdf.parallelism,
    dkLen: 32,
  });
}

/**
 * Derive the (recovery_sign_seed, recovery_verify_pk) Ed25519 key
 * pair per §3.3:
 *
 *   seed = HKDF-Expand(K_bundle, "SEMP-RECOVERY-SIGN-KEY-v1", 32)
 *
 * Returns the 32-byte Ed25519 seed (used directly as the secret
 * key per @noble/curves) and the corresponding 32-byte public key.
 */
export function deriveRecoverySignKey(bundleKey: Uint8Array): {
  signSeed: Uint8Array;
  verifyPub: Uint8Array;
} {
  if (bundleKey.length === 0) {
    throw new Error("recovery: empty bundle key");
  }
  const info = new TextEncoder().encode(RecoverySignKeyInfo);
  const seed = hkdfExpandSHA512(bundleKey, info, 32);
  const verifyPub = publicKeyFromSeed(seed);
  return { signSeed: seed, verifyPub };
}

/**
 * XChaCha20-Poly1305-encrypt the JSON-encoded `payload` under
 * `bundleKey` with a 24-byte `nonce`. AAD is empty per §2.5.
 *
 * Returns the ciphertext (with the 16-byte AEAD tag appended).
 */
export function encryptBundlePayload(
  bundleKey: Uint8Array,
  nonce: Uint8Array,
  payload: unknown,
): Uint8Array {
  if (bundleKey.length !== 32) {
    throw new Error(`recovery: bundle key length ${bundleKey.length}, want 32`);
  }
  if (nonce.length !== 24) {
    throw new Error(
      `recovery: payload nonce length ${nonce.length}, want 24`,
    );
  }
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  return xchacha20poly1305(bundleKey, nonce).encrypt(plaintext);
}

/** Reverse {@link encryptBundlePayload}. */
export function decryptBundlePayload<T = unknown>(
  bundleKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): T {
  if (bundleKey.length !== 32) {
    throw new Error(`recovery: bundle key length ${bundleKey.length}, want 32`);
  }
  if (nonce.length !== 24) {
    throw new Error(
      `recovery: payload nonce length ${nonce.length}, want 24`,
    );
  }
  const plaintext = xchacha20poly1305(bundleKey, nonce).decrypt(ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext)) as T;
}

// ---------------------------------------------------------------------------
// Helpers

function validateKDFParams(kdf: BundleKDF): void {
  if (kdf.algorithm !== KDFAlgorithmArgon2id) {
    throw new Error(
      `recovery: kdf.algorithm ${JSON.stringify(kdf.algorithm)}, want ${KDFAlgorithmArgon2id}`,
    );
  }
  if (typeof kdf.salt !== "string" || kdf.salt === "") {
    throw new Error("recovery: kdf.salt missing");
  }
  if (!Number.isInteger(kdf.memory_kb) || kdf.memory_kb < MinKDFMemoryKB) {
    throw new Error(
      `recovery: kdf.memory_kb ${kdf.memory_kb} below ${MinKDFMemoryKB} minimum`,
    );
  }
  if (!Number.isInteger(kdf.iterations) || kdf.iterations < MinKDFIterations) {
    throw new Error(
      `recovery: kdf.iterations ${kdf.iterations} below ${MinKDFIterations} minimum`,
    );
  }
  if (
    !Number.isInteger(kdf.parallelism) ||
    kdf.parallelism < MinKDFParallelism
  ) {
    throw new Error(
      `recovery: kdf.parallelism ${kdf.parallelism} below ${MinKDFParallelism} minimum`,
    );
  }
}

/**
 * RFC 5869 HKDF-Expand with HMAC-SHA-512. Permits PRK shorter than
 * HashLen (§3.3 passes 32-byte K_bundle as the PRK).
 */
function hkdfExpandSHA512(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const hashLen = 64;
  const N = Math.ceil(length / hashLen);
  if (N > 255) {
    throw new Error("recovery: HKDF-Expand requested length too large");
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
