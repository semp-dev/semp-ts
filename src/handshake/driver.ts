/**
 * Handshake client driver per HANDSHAKE.md §2.
 *
 * Drives one transport through the v1 handshake flow:
 *
 *   1. Generate a client ephemeral X25519 keypair and a 32-byte
 *      client nonce.
 *   2. Build and send INIT (capabilities, ephemeral pub, nonce,
 *      transport identifier).
 *   3. Receive RESPONSE. Verify the server signature with the
 *      pinned domain pub. Pull the server's ephemeral, server
 *      nonce, and session_id.
 *   4. Compute the X25519 shared secret. Derive the five SEMP
 *      session keys via HKDF-SHA-512 with salt =
 *      `client_nonce || server_nonce`.
 *   5. Compute the confirmation hash over canonical(INIT) ||
 *      canonical(RESPONSE).
 *   6. Build and send CONFIRM with the confirmation hash and an
 *      opaque identity_proof (the v1 driver leaves identity_proof
 *      empty; a future revision will bind a per-session identity
 *      claim there per §2.5).
 *   7. Receive ACCEPTED (or REJECTED). On REJECTED, surface the
 *      reason_code as a typed error.
 *
 * The PQ suite path is structurally identical; only the KEM is
 * different. The v1 driver supports the baseline suite end to end;
 * PQ requires hooking the hybrid KEM in step 4 and is left as a
 * straightforward extension.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  type SessionKeys,
  deriveSessionKeysWithResumption,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint, verify as ed25519Verify } from "../keys/index.js";
import type { Transport } from "../transport/index.js";

import { confirmationHash } from "./confirm.js";
import {
  type AcceptedMessage,
  type Capabilities,
  type ConfirmMessage,
  type InitMessage,
  type RejectedMessage,
  type ResponseMessage,
  HandshakePrefix,
  buildConfirm,
  buildInit,
} from "./messages.js";

/** Configuration for the client side of a handshake. */
export interface ClientConfig {
  /** Algorithm suite to negotiate. v1 driver: "x25519-chacha20-poly1305". */
  suite: "x25519-chacha20-poly1305";
  /** Capability set to advertise. */
  capabilities: Capabilities;
  /** Transport identifier ("ws", "h2", "quic"). Echoed in INIT. */
  transport: string;
  /**
   * Server domain signing public key (32-byte Ed25519). Pre-shared
   * via discovery; the client uses it to verify the server's
   * RESPONSE and ACCEPTED signatures.
   */
  serverDomainPub: Uint8Array;
  /**
   * Optional pre-generated client ephemeral. If omitted, the driver
   * generates a fresh keypair via globalThis.crypto. Tests pin this
   * to make the run deterministic.
   */
  clientEphemeralPriv?: Uint8Array;
  /**
   * Optional client nonce. If omitted, the driver generates 32
   * bytes of fresh entropy.
   */
  clientNonce?: Uint8Array;
}

/** Outcome of a successful handshake. */
export interface ClientSession {
  sessionId: string;
  sessionTTL: number;
  permissions: string[];
  keys: SessionKeys;
  /** Server identity proof from the RESPONSE (forwarded for higher layers). */
  serverIdentityProofKeyId: string;
  /** Server identity proof signature (opaque base64; per-application). */
  serverIdentityProofSignature: string;
  /** ACCEPTED extensions echoed back from the server. */
  extensions: Record<string, unknown>;
  /** Optional resumption ticket for later resume. */
  resumptionTicket?: { value: string; expires_at: string };
}

/** Error thrown when the server rejects the handshake. */
export class HandshakeRejectedError extends Error {
  readonly sessionId: string;
  readonly reasonCode: string;
  readonly reason: string | undefined;
  constructor(sessionId: string, reasonCode: string, reason: string | undefined) {
    super(`handshake rejected: ${reasonCode}${reason !== undefined ? ` (${reason})` : ""}`);
    this.sessionId = sessionId;
    this.reasonCode = reasonCode;
    this.reason = reason;
  }
}

/**
 * Drive a handshake to completion over `transport`. Resolves with a
 * `ClientSession` carrying derived keys and server-published session
 * parameters; rejects with `HandshakeRejectedError` on a server
 * REJECTED, or a generic Error on protocol violation.
 *
 * On error the transport is closed so the peer's pending `receive`
 * unblocks. Successful completion leaves the transport open for the
 * higher-layer session machine to use.
 */
export async function runClient(
  transport: Transport,
  config: ClientConfig,
): Promise<ClientSession> {
  if (config.suite !== "x25519-chacha20-poly1305") {
    throw new Error(`handshake: v1 driver only supports baseline suite, got ${config.suite}`);
  }
  try {
    return await runClientInner(transport, config);
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // already closed
    }
    throw err;
  }
}

async function runClientInner(
  transport: Transport,
  config: ClientConfig,
): Promise<ClientSession> {

  // Step 1: ephemeral + nonce.
  const ephPriv = config.clientEphemeralPriv ?? randomBytes(32);
  const ephPub = x25519PublicKey(ephPriv);
  const clientNonce = config.clientNonce ?? randomBytes(32);
  const ephKeyId = fingerprint(ephPub);

  // Step 2: INIT.
  const init: InitMessage = buildInit({
    nonce: base64Encode(clientNonce),
    transport: config.transport,
    clientEphemeralKey: {
      algorithm: config.suite,
      key: base64Encode(ephPub),
      key_id: ephKeyId,
    },
    capabilities: config.capabilities,
  });
  const initCanonical = canonicalMarshal(init);
  await transport.send(initCanonical);

  // Step 3: RESPONSE.
  const respBytes = await receiveOrThrow(transport, "response");
  const respMsg = parseHandshakeMessage(respBytes);
  if (respMsg.step === "rejected") {
    const rej = respMsg as RejectedMessage;
    throw new HandshakeRejectedError(rej.session_id, rej.reason_code, rej.reason);
  }
  if (respMsg.step !== "response") {
    throw new Error(`handshake: expected step="response", got "${respMsg.step}"`);
  }
  const resp = respMsg as ResponseMessage;
  verifyServerSignature(
    resp as unknown as Record<string, unknown>,
    "server_signature",
    config.serverDomainPub,
  );

  const serverNonce = base64Decode(resp.server_nonce);
  const serverEphPub = base64Decode(resp.server_ephemeral_key.key);

  // Step 4: derive session keys.
  const sharedSecret = x25519Agree(ephPriv, serverEphPub);
  const kdf = newHKDFSHA512();
  const keys = deriveSessionKeysWithResumption(
    kdf,
    sharedSecret,
    clientNonce,
    serverNonce,
  );

  // Step 5: confirmation hash.
  const respCanonical = canonicalMarshal(resp);
  const confirmHashBytes = confirmationHash(initCanonical, respCanonical);

  // Step 6: CONFIRM.
  const confirm: ConfirmMessage = buildConfirm({
    sessionId: resp.session_id,
    confirmationHashB64: base64Encode(confirmHashBytes),
    // The v1 driver leaves identity_proof empty. A higher-level
    // client wraps this driver and supplies a real proof —
    // typically AEAD(K_enc_c2s, identity_block) per §2.5.3.
    identityProofB64: "",
  });
  await transport.send(canonicalMarshal(confirm));

  // Step 7: ACCEPTED (or REJECTED).
  const acceptedBytes = await receiveOrThrow(transport, "accepted");
  const acceptedMsg = parseHandshakeMessage(acceptedBytes);
  if (acceptedMsg.step === "rejected") {
    const rej = acceptedMsg as RejectedMessage;
    throw new HandshakeRejectedError(rej.session_id, rej.reason_code, rej.reason);
  }
  if (acceptedMsg.step !== "accepted") {
    throw new Error(`handshake: expected step="accepted", got "${acceptedMsg.step}"`);
  }
  const accepted = acceptedMsg as AcceptedMessage;
  verifyServerSignature(
    accepted as unknown as Record<string, unknown>,
    "server_signature",
    config.serverDomainPub,
  );

  return {
    sessionId: accepted.session_id,
    sessionTTL: accepted.session_ttl,
    permissions: accepted.permissions,
    keys,
    serverIdentityProofKeyId: resp.server_identity_proof.key_id,
    serverIdentityProofSignature: resp.server_identity_proof.signature,
    extensions: accepted.extensions,
    ...(accepted.resumption_ticket !== undefined
      ? { resumptionTicket: accepted.resumption_ticket }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Internals

async function receiveOrThrow(transport: Transport, expected: string): Promise<Uint8Array> {
  const msg = await transport.receive();
  if (msg === null) {
    throw new Error(`handshake: connection closed waiting for ${expected}`);
  }
  return msg;
}

function parseHandshakeMessage(bytes: Uint8Array): { step: string } {
  const text = new TextDecoder().decode(bytes);
  const obj = JSON.parse(text) as { type?: string; step?: string };
  if (obj.type !== "SEMP_HANDSHAKE") {
    throw new Error(`handshake: expected type=SEMP_HANDSHAKE, got "${obj.type ?? "?"}"`);
  }
  if (typeof obj.step !== "string") {
    throw new Error("handshake: missing step field");
  }
  return obj as { step: string };
}

function verifyServerSignature(
  message: Record<string, unknown>,
  signatureField: string,
  serverDomainPub: Uint8Array,
): void {
  const sigB64 = message[signatureField];
  if (typeof sigB64 !== "string" || sigB64 === "") {
    throw new Error(`handshake: ${signatureField} missing or empty`);
  }
  // Re-canonicalize with the signature blanked, prepend the
  // SEMP-HANDSHAKE: prefix, verify.
  const clone = JSON.parse(JSON.stringify(message)) as Record<string, unknown>;
  clone[signatureField] = "";
  const canonical = canonicalMarshal(clone);
  const signingInput = concat(new TextEncoder().encode(HandshakePrefix), canonical);
  const sig = base64Decode(sigB64);
  if (!ed25519Verify(serverDomainPub, sig, signingInput)) {
    throw new Error(`handshake: ${signatureField} did not verify under server domain key`);
  }
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
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
