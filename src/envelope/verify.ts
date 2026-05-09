/**
 * Envelope verification primitives per ENVELOPE.md §6 + §7.2.
 *
 * The compose path produces `seal.signature` (Ed25519 over canonical
 * bytes prefixed with `SEMP-ENVELOPE:`) and `seal.session_mac`
 * (HMAC-SHA-256 over the same canonical bytes). This module exposes
 * the corresponding verifiers as standalone primitives that callers
 * use in receipt-side checks before opening the envelope.
 *
 * @module
 */

import { computeMAC } from "../crypto/index.js";
import { verify as ed25519Verify } from "../keys/index.js";

import { type Envelope, canonicalEnvelopeFor } from "./compose.js";

/** Domain-separation prefix for the seal signature, per §4.3. */
const EnvelopePrefix = "SEMP-ENVELOPE:";

/**
 * Verify `env.seal.signature` against `senderDomainPub`. Returns
 * true when the Ed25519 signature over the canonical envelope bytes
 * (prefixed with `SEMP-ENVELOPE:`) verifies. Does NOT cross-check
 * that the supplied public key actually belongs to the
 * `postmark.from_domain` — that lookup is the caller's responsibility.
 */
export function verifySealSignature(
  env: Envelope,
  senderDomainPub: Uint8Array,
): boolean {
  if (env.seal?.signature === undefined || env.seal.signature === "") {
    return false;
  }
  let sig: Uint8Array;
  try {
    sig = base64Decode(env.seal.signature);
  } catch {
    return false;
  }
  const canonical = canonicalEnvelopeFor(env);
  const signingInput = concat(
    new TextEncoder().encode(EnvelopePrefix),
    canonical,
  );
  return ed25519Verify(senderDomainPub, sig, signingInput);
}

/**
 * Verify `env.seal.session_mac` against `kEnvMAC`. Returns true when
 * the HMAC-SHA-256 of the canonical envelope bytes equals the
 * decoded MAC value. The session-MAC key is the per-session
 * symmetric key derived from the receiving server's federation
 * handshake; it changes on rekey.
 */
export function verifySessionMAC(env: Envelope, kEnvMAC: Uint8Array): boolean {
  if (env.seal?.session_mac === undefined || env.seal.session_mac === "") {
    return false;
  }
  let want: Uint8Array;
  try {
    want = base64Decode(env.seal.session_mac);
  } catch {
    return false;
  }
  const canonical = canonicalEnvelopeFor(env);
  const got = computeMAC(kEnvMAC, canonical);
  return constantTimeEqual(want, got);
}

// ---------------------------------------------------------------------------
// Helpers

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
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
