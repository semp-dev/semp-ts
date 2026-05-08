/**
 * Rekey driver per SESSION.md §3.3.
 *
 * Both peers can initiate. The flow:
 *
 *   1. Initiator generates a new ephemeral X25519 keypair + a
 *      32-byte rekey nonce. Builds RekeyInit, seals under the
 *      current session's directional keys, sends.
 *   2. Responder receives + opens the sealed init. Generates its
 *      own new ephemeral + a 32-byte responder nonce + a new
 *      session_id. Computes the new shared secret via X25519,
 *      derives the five new session keys via HKDF-SHA-512 with
 *      salt = rekey_nonce || responder_nonce.
 *   3. Responder builds RekeyAccepted, seals under the current
 *      session's directional keys, sends.
 *   4. Both call session.applyRekey() to swap in the new keys
 *      and new session_id atomically.
 *
 * On rejection (session_expired, rekey_unsupported, rate_limited),
 * the responder sends a sealed RekeyRejected; the caller sees a
 * RekeyRejectedError.
 *
 * Rekey messages carry no separate identity signature: receiving
 * a valid sealed message is itself authentication, since only a
 * holder of the live session keys can forge one.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  deriveRekeyKeys,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint } from "../keys/index.js";

import type { Session } from "./session.js";
import {
  type SealedRekey,
  openRekeyMessage,
  sealRekeyMessage,
} from "./rekey_seal.js";

/** Rekey-init message (decrypted body). */
export interface RekeyInit {
  type: "SEMP_REKEY";
  step: "rekey-init";
  version: "1.0.0";
  session_id: string;
  new_ephemeral_key: { algorithm: string; key: string; key_id: string };
  rekey_nonce: string;
}

/** Rekey-accepted message (decrypted body). */
export interface RekeyAccepted {
  type: "SEMP_REKEY";
  step: "rekey-accepted";
  version: "1.0.0";
  session_id: string;
  new_session_id: string;
  new_ephemeral_key: { algorithm: string; key: string; key_id: string };
  rekey_nonce: string;
  responder_nonce: string;
}

/** Rekey-rejected message (decrypted body). */
export interface RekeyRejected {
  type: "SEMP_REKEY";
  step: "rekey-rejected";
  version: "1.0.0";
  session_id: string;
  reason_code: string;
  reason?: string;
}

/** Error thrown when the responder rejects a rekey attempt. */
export class RekeyRejectedError extends Error {
  readonly reasonCode: string;
  readonly reason: string | undefined;
  constructor(reasonCode: string, reason: string | undefined) {
    super(`rekey rejected: ${reasonCode}${reason !== undefined ? ` (${reason})` : ""}`);
    this.reasonCode = reasonCode;
    this.reason = reason;
  }
}

/** Inputs to the initiator side of rekey (deterministic-friendly). */
export interface RekeyClientOptions {
  /** Optional pinned ephemeral private (32 bytes) for tests. */
  ephemeralPriv?: Uint8Array;
  /** Optional pinned 32-byte rekey nonce for tests. */
  rekeyNonce?: Uint8Array;
}

/**
 * Initiate a rekey. The session installs new keys + a new
 * session_id on success and resolves with the new session_id.
 *
 * @throws RekeyRejectedError when the responder sends a sealed
 * RekeyRejected.
 */
export async function rekeyClient(
  session: Session,
  options: RekeyClientOptions = {},
): Promise<string> {
  const direction = directionFromRole(session.role);
  const oppositeDir = otherDirection(direction);

  // Step 1: build + send RekeyInit.
  const ephPriv = options.ephemeralPriv ?? randomBytes(32);
  const ephPub = x25519PublicKey(ephPriv);
  const rekeyNonce = options.rekeyNonce ?? randomBytes(32);
  const init: RekeyInit = {
    type: "SEMP_REKEY",
    step: "rekey-init",
    version: "1.0.0",
    session_id: session.sessionId,
    new_ephemeral_key: {
      algorithm: "x25519-chacha20-poly1305",
      key: base64Encode(ephPub),
      key_id: fingerprint(ephPub),
    },
    rekey_nonce: base64Encode(rekeyNonce),
  };
  const sealed = sealRekeyMessage(session, direction, canonicalMarshal(init));
  await session.send(new TextEncoder().encode(JSON.stringify(sealed)));

  // Step 2: receive + open the response.
  const respBytes = await session.receive();
  if (respBytes === null) {
    throw new Error("rekey: connection closed waiting for response");
  }
  const wrapper = JSON.parse(new TextDecoder().decode(respBytes)) as SealedRekey;
  if (wrapper.type !== "SEMP_REKEY") {
    throw new Error(`rekey: expected SEMP_REKEY, got ${wrapper.type}`);
  }
  if (wrapper.direction !== oppositeDir) {
    throw new Error(
      `rekey: expected response direction=${oppositeDir}, got ${wrapper.direction}`,
    );
  }
  const respPlain = openRekeyMessage(session, wrapper);
  const respBody = JSON.parse(new TextDecoder().decode(respPlain)) as
    | RekeyAccepted
    | RekeyRejected;

  // Discriminate on `step` defensively; the wire body could carry
  // either an accepted or rejected outcome.
  const step = (respBody as { step: string }).step;
  if (step === "rekey-rejected") {
    const r = respBody as RekeyRejected;
    throw new RekeyRejectedError(r.reason_code, r.reason);
  }
  if (step !== "rekey-accepted") {
    throw new Error(`rekey: expected step=rekey-accepted, got ${step}`);
  }
  const accepted = respBody as RekeyAccepted;

  // Step 3: derive + apply new keys.
  const responderPub = base64Decode(accepted.new_ephemeral_key.key);
  const sharedSecret = x25519Agree(ephPriv, responderPub);
  const responderNonce = base64Decode(accepted.responder_nonce);
  const kdf = newHKDFSHA512();
  const newKeys = deriveRekeyKeys(kdf, sharedSecret, rekeyNonce, responderNonce);

  session.applyRekey({
    newSessionId: accepted.new_session_id,
    newKeys,
  });
  return accepted.new_session_id;
}

/** Inputs to the responder side of rekey (deterministic-friendly). */
export interface RekeyServerOptions {
  /** Optional pinned ephemeral private for tests. */
  ephemeralPriv?: Uint8Array;
  /** Optional pinned 32-byte responder nonce for tests. */
  responderNonce?: Uint8Array;
  /** Generator for the new session_id. Required for production. */
  generateSessionId: () => string;
}

/**
 * Respond to a rekey. Reads one sealed message off the session
 * transport, validates it as a RekeyInit, derives new keys,
 * sends a sealed RekeyAccepted, and applies the rekey to the
 * session. Resolves with the new session_id.
 *
 * Production callers wire this into their session-message
 * dispatcher: when an inbound SEMP_REKEY arrives, route the
 * sealed bytes here.
 */
export async function rekeyServer(
  session: Session,
  options: RekeyServerOptions,
): Promise<string> {
  const initDir = directionFromRole(otherRole(session.role));
  const respDir = otherDirection(initDir);

  // Step 1: receive + open the init.
  const initBytes = await session.receive();
  if (initBytes === null) {
    throw new Error("rekey: connection closed waiting for init");
  }
  const wrapper = JSON.parse(new TextDecoder().decode(initBytes)) as SealedRekey;
  if (wrapper.type !== "SEMP_REKEY") {
    throw new Error(`rekey: expected SEMP_REKEY, got ${wrapper.type}`);
  }
  if (wrapper.direction !== initDir) {
    throw new Error(
      `rekey: expected init direction=${initDir}, got ${wrapper.direction}`,
    );
  }
  const initPlain = openRekeyMessage(session, wrapper);
  const init = JSON.parse(new TextDecoder().decode(initPlain)) as RekeyInit;
  if (init.step !== "rekey-init") {
    throw new Error(`rekey: expected step=rekey-init, got ${init.step}`);
  }

  // Step 2: ephemeral + responder nonce + new session_id.
  const ephPriv = options.ephemeralPriv ?? randomBytes(32);
  const ephPub = x25519PublicKey(ephPriv);
  const responderNonce = options.responderNonce ?? randomBytes(32);
  const newSessionId = options.generateSessionId();

  // Step 3: derive new keys.
  const initiatorPub = base64Decode(init.new_ephemeral_key.key);
  const rekeyNonce = base64Decode(init.rekey_nonce);
  const sharedSecret = x25519Agree(ephPriv, initiatorPub);
  const kdf = newHKDFSHA512();
  const newKeys = deriveRekeyKeys(kdf, sharedSecret, rekeyNonce, responderNonce);

  // Step 4: build + send RekeyAccepted.
  const accepted: RekeyAccepted = {
    type: "SEMP_REKEY",
    step: "rekey-accepted",
    version: "1.0.0",
    session_id: session.sessionId,
    new_session_id: newSessionId,
    new_ephemeral_key: {
      algorithm: "x25519-chacha20-poly1305",
      key: base64Encode(ephPub),
      key_id: fingerprint(ephPub),
    },
    rekey_nonce: init.rekey_nonce,
    responder_nonce: base64Encode(responderNonce),
  };
  const sealedResp = sealRekeyMessage(session, respDir, canonicalMarshal(accepted));
  await session.send(new TextEncoder().encode(JSON.stringify(sealedResp)));

  // Step 5: apply rekey.
  session.applyRekey({ newSessionId, newKeys });
  return newSessionId;
}

// ---------------------------------------------------------------------------
// Helpers

function directionFromRole(role: "client" | "server"): "c2s" | "s2c" {
  return role === "client" ? "c2s" : "s2c";
}

function otherDirection(d: "c2s" | "s2c"): "c2s" | "s2c" {
  return d === "c2s" ? "s2c" : "c2s";
}

function otherRole(r: "client" | "server"): "client" | "server" {
  return r === "client" ? "server" : "client";
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
