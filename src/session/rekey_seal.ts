/**
 * Sealed-rekey wire format per SESSION.md §3.2.
 *
 * Rekey messages are AEAD-encrypted under the CURRENT session's
 * directional keys. Receiving a valid sealed rekey is itself the
 * authentication - only a holder of the live session keys can
 * forge one - so the rekey messages carry no separate identity
 * signature.
 *
 * Wire shape:
 *
 *   {
 *     "type":      "SEMP_REKEY",
 *     "sealed":    true,
 *     "direction": "c2s" | "s2c",
 *     "version":   "1.0.0",
 *     "session_id": "<current session_id>",
 *     "nonce":     "<base64 12-byte AEAD nonce>",
 *     "ciphertext":"<base64 AEAD ciphertext (RekeyInit/Accepted/Rejected JSON)>"
 *   }
 *
 * AEAD: ChaCha20-Poly1305 (12-byte nonce). The AAD is a
 * length-prefixed concatenation of:
 *
 *   AAD = LP(direction) || LP(session_id) || LP(directional_mac_key)
 *
 * where LP(x) prepends a 4-byte big-endian length to x. Mixing the
 * MAC key into the AAD ensures that compromising the encryption
 * key alone is insufficient - an attacker would also need the MAC
 * key, which satisfies the spec's "MACed under the MAC key"
 * requirement.
 *
 * @module
 */

import { aeadOpen, aeadSeal } from "../crypto/index.js";
import type { Session } from "./session.js";

/** Wire shape of a sealed rekey message. */
export interface SealedRekey {
  type: "SEMP_REKEY";
  sealed: true;
  direction: "c2s" | "s2c";
  version: "1.0.0";
  session_id: string;
  nonce: string;
  ciphertext: string;
}

/**
 * Seal a rekey-message body. The body is the canonical JSON of
 * RekeyInit / RekeyAccepted / RekeyRejected. Returns the wire
 * envelope.
 *
 * @param session the CURRENT session (pre-rekey).
 * @param direction "c2s" if the caller is the side that sent INIT
 *   in the original handshake (or for federation: the side that
 *   opened the connection); "s2c" otherwise.
 * @param plaintext the canonical message body bytes.
 * @param nonce optional 12-byte nonce; production callers omit
 *   this and let the function source fresh entropy.
 */
export function sealRekeyMessage(
  session: Session,
  direction: "c2s" | "s2c",
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): SealedRekey {
  const { encKey, macKey } = pickRekeyKeys(session, direction);
  const n = nonce ?? randomBytes(12);
  if (n.length !== 12) {
    throw new Error(`sealRekeyMessage: nonce must be 12 bytes, got ${n.length}`);
  }
  const aad = rekeyAAD(direction, session.sessionId, macKey);
  const ct = aeadSeal("chacha20-poly1305", encKey, n, plaintext, aad);
  return {
    type: "SEMP_REKEY",
    sealed: true,
    direction,
    version: "1.0.0",
    session_id: session.sessionId,
    nonce: base64Encode(n),
    ciphertext: base64Encode(ct),
  };
}

/**
 * Open a sealed rekey message. Returns the plaintext body bytes.
 * Throws on tag mismatch, direction mismatch, or session_id
 * mismatch.
 */
export function openRekeyMessage(session: Session, msg: SealedRekey): Uint8Array {
  if (msg.type !== "SEMP_REKEY") {
    throw new Error(`openRekeyMessage: type=${msg.type}, want SEMP_REKEY`);
  }
  if (!msg.sealed) {
    throw new Error("openRekeyMessage: cleartext rekey not supported");
  }
  if (msg.session_id !== session.sessionId) {
    throw new Error(
      `openRekeyMessage: session_id ${msg.session_id} does not match current ${session.sessionId}`,
    );
  }
  const { encKey, macKey } = pickRekeyKeys(session, msg.direction);
  const nonce = base64Decode(msg.nonce);
  const ct = base64Decode(msg.ciphertext);
  const aad = rekeyAAD(msg.direction, session.sessionId, macKey);
  return aeadOpen("chacha20-poly1305", encKey, nonce, ct, aad);
}

/**
 * Pick the (encryption_key, mac_key) pair for the given
 * direction, mirroring semp-go's session.pickRekeyKeys. The
 * session keys are owned by both endpoints, so the same
 * (direction, sessionId) pair selects the same pair on both sides.
 */
function pickRekeyKeys(
  session: Session,
  direction: "c2s" | "s2c",
): { encKey: Uint8Array; macKey: Uint8Array } {
  switch (direction) {
    case "c2s":
      return { encKey: session.keys.encC2S, macKey: session.keys.macC2S };
    case "s2c":
      return { encKey: session.keys.encS2C, macKey: session.keys.macS2C };
  }
}

/**
 * Length-prefixed AAD per the rekey wire format. Each component
 * is preceded by a 4-byte big-endian length so an attacker can't
 * shift the boundary between fields.
 */
function rekeyAAD(direction: string, sessionId: string, macKey: Uint8Array): Uint8Array {
  const dirBytes = new TextEncoder().encode(direction);
  const idBytes = new TextEncoder().encode(sessionId);
  const total = 4 + dirBytes.length + 4 + idBytes.length + 4 + macKey.length;
  const out = new Uint8Array(total);
  let off = 0;
  off = appendLP(out, off, dirBytes);
  off = appendLP(out, off, idBytes);
  appendLP(out, off, macKey);
  return out;
}

function appendLP(buf: Uint8Array, off: number, b: Uint8Array): number {
  const n = b.length;
  buf[off++] = (n >>> 24) & 0xff;
  buf[off++] = (n >>> 16) & 0xff;
  buf[off++] = (n >>> 8) & 0xff;
  buf[off++] = n & 0xff;
  buf.set(b, off);
  return off + n;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function base64Encode(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
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
