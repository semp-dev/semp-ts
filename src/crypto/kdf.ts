/**
 * HKDF-SHA-512 derivation per HANDSHAKE.md §2.4 and SESSION.md §2.1.
 *
 * SEMP uses HKDF-SHA-512 for both currently defined algorithm suites.
 * The five per-key info labels (and the resumption label) are bound
 * contexts that prevent cross-context key confusion if an
 * implementation accidentally reuses a PRK across derivations.
 *
 * @module
 */

import { extract, expand } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";

/**
 * Per-key HKDF info labels for the five session keys derived from
 * the initial-handshake PRK. Per VECTORS.md §2.2, the rekey
 * derivation reuses these same labels - cross-context separation
 * comes from the salt change (rekey nonces vs handshake nonces),
 * not from a different label namespace.
 */
export const InfoSessionEncC2S = "SEMP-v1-session-enc-c2s";
export const InfoSessionEncS2C = "SEMP-v1-session-enc-s2c";
export const InfoSessionMACC2S = "SEMP-v1-session-mac-c2s";
export const InfoSessionMACS2C = "SEMP-v1-session-mac-s2c";
export const InfoSessionEnvMAC = "SEMP-v1-session-env-mac";

/**
 * K_resumption label per HANDSHAKE.md §2.8.3 and SESSION.md §2.7.
 * K_resumption is NOT used to encrypt or MAC any message in the
 * current session; it is the secret a server retains so that, mixed
 * with a fresh ephemeral DH on a later resume attempt, the resumed
 * session derives a new key schedule.
 */
export const InfoSessionResumption = "SEMP-v1-session-resumption";

/** Length in bytes of every derived session key (SESSION.md §2.1). */
export const SessionKeyLength = 32;

/**
 * Generic KDF interface. Both currently defined SEMP suites use
 * HKDF-SHA-512; future suites may swap to a different hash.
 */
export interface KDF {
  /** HKDF-Extract(salt, ikm) -> PRK. */
  extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array;
  /** HKDF-Expand(prk, info, length) -> length bytes of OKM. */
  expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array;
}

class HKDFSHA512 implements KDF {
  extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
    return extract(sha512, ikm, salt);
  }
  expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    return expand(sha512, prk, info, length);
  }
}

/**
 * Returns a stateless HKDF-SHA-512 KDF instance. Safe for concurrent
 * use; no state is held between calls.
 */
export function newHKDFSHA512(): KDF {
  return new HKDFSHA512();
}

/** The five session keys derived from a handshake PRK. */
export interface SessionKeys {
  /** Client -> server message encryption key. */
  encC2S: Uint8Array;
  /** Server -> client message encryption key. */
  encS2C: Uint8Array;
  /** Client -> server message MAC key. */
  macC2S: Uint8Array;
  /** Server -> client message MAC key. */
  macS2C: Uint8Array;
  /** Envelope-layer MAC key (HMAC-SHA-256 over canonical envelopes). */
  envMAC: Uint8Array;
  /**
   * Resumption secret (32 bytes). Set on initial-handshake derivation
   * via {@link deriveSessionKeysWithResumption}; absent on rekey
   * derivations.
   */
  resumption?: Uint8Array;
}

/**
 * Derive the five session keys from a handshake. The salt is
 * `clientNonce || serverNonce`. Per VECTORS.md §2.1, the IKM is the
 * shared secret from the negotiated KEM; for rekey, the same five
 * keys are derived under the rekey nonces but the resumption secret
 * is NOT regenerated.
 */
export function deriveSessionKeys(
  kdf: KDF,
  sharedSecret: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
): SessionKeys {
  const salt = concat(clientNonce, serverNonce);
  const prk = kdf.extract(salt, sharedSecret);
  return {
    encC2S: kdf.expand(prk, utf8(InfoSessionEncC2S), SessionKeyLength),
    encS2C: kdf.expand(prk, utf8(InfoSessionEncS2C), SessionKeyLength),
    macC2S: kdf.expand(prk, utf8(InfoSessionMACC2S), SessionKeyLength),
    macS2C: kdf.expand(prk, utf8(InfoSessionMACS2C), SessionKeyLength),
    envMAC: kdf.expand(prk, utf8(InfoSessionEnvMAC), SessionKeyLength),
  };
}

/**
 * Like {@link deriveSessionKeys} but also derives K_resumption.
 * Used on the initial handshake; rekey derivations skip the
 * resumption expansion.
 */
export function deriveSessionKeysWithResumption(
  kdf: KDF,
  sharedSecret: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
): SessionKeys {
  const salt = concat(clientNonce, serverNonce);
  const prk = kdf.extract(salt, sharedSecret);
  return {
    encC2S: kdf.expand(prk, utf8(InfoSessionEncC2S), SessionKeyLength),
    encS2C: kdf.expand(prk, utf8(InfoSessionEncS2C), SessionKeyLength),
    macC2S: kdf.expand(prk, utf8(InfoSessionMACC2S), SessionKeyLength),
    macS2C: kdf.expand(prk, utf8(InfoSessionMACS2C), SessionKeyLength),
    envMAC: kdf.expand(prk, utf8(InfoSessionEnvMAC), SessionKeyLength),
    resumption: kdf.expand(prk, utf8(InfoSessionResumption), SessionKeyLength),
  };
}

/**
 * Derive the resumed-session keys from a rekey ECDH and a retained
 * resumption secret per HANDSHAKE.md §2.8.3 and SESSION.md §2.7.
 * IKM is `ephemeralSharedSecret || kResumption`, salt is
 * `clientNonce || serverNonce`. The five expand labels are the same
 * SEMP-v1-session-* labels as the initial derivation.
 */
export function deriveResumedSessionKeys(
  kdf: KDF,
  ephemeralSharedSecret: Uint8Array,
  kResumption: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
): SessionKeys {
  const ikm = concat(ephemeralSharedSecret, kResumption);
  const salt = concat(clientNonce, serverNonce);
  const prk = kdf.extract(salt, ikm);
  return {
    encC2S: kdf.expand(prk, utf8(InfoSessionEncC2S), SessionKeyLength),
    encS2C: kdf.expand(prk, utf8(InfoSessionEncS2C), SessionKeyLength),
    macC2S: kdf.expand(prk, utf8(InfoSessionMACC2S), SessionKeyLength),
    macS2C: kdf.expand(prk, utf8(InfoSessionMACS2C), SessionKeyLength),
    envMAC: kdf.expand(prk, utf8(InfoSessionEnvMAC), SessionKeyLength),
  };
}

/**
 * Derive rekey keys per SESSION.md §3.3. Identical to the initial
 * derivation in label set; the cross-context separation comes from
 * the salt construction (rekeyNonce || responderNonce) and a fresh
 * shared secret.
 */
export function deriveRekeyKeys(
  kdf: KDF,
  sharedSecret: Uint8Array,
  rekeyNonce: Uint8Array,
  responderNonce: Uint8Array,
): SessionKeys {
  return deriveSessionKeys(kdf, sharedSecret, rekeyNonce, responderNonce);
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
