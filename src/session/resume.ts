/**
 * Session resumption driver per HANDSHAKE.md §2.8 / SESSION.md §2.7.
 *
 * Resume condenses the full handshake into ONE round trip:
 *
 *   client -> server  step=resume     (client_eph + client_nonce +
 *                                      resumption_ticket from prior session)
 *   server -> client  step=accepted   (server_eph + server_nonce +
 *                                      new session_id + new ticket +
 *                                      server_signature)
 *
 * Both peers derive new session keys by mixing the FRESH X25519
 * shared secret with the K_resumption secret retained from the
 * previous session. The retained secret proves continuity of
 * identity, so no separate identity proof is required.
 *
 * Production callers use this when they want a low-latency
 * reconnect after a brief disconnection. If the server has lost
 * the session state (or the ticket has expired), the server
 * MUST respond with step=rejected and the client falls back to
 * a full {@link "../handshake/driver".runClient} handshake.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  deriveResumedSessionKeys,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint, publicKeyFromSeed, signSignedDoc, verify as ed25519Verify } from "../keys/index.js";
import {
  HandshakePrefix,
  type ResumptionTicket,
} from "../handshake/messages.js";
import { HandshakeRejectedError } from "../handshake/driver.js";
import type { Transport } from "../transport/index.js";

import { Session } from "./session.js";

/** Wire shape of step=resume (unsigned). */
export interface ResumeRequest {
  type: "SEMP_HANDSHAKE";
  step: "resume";
  party: "client";
  version: "1.0.0";
  nonce: string;
  resumption_ticket: string;
  client_ephemeral_key: { algorithm: string; key: string; key_id: string };
  transport: string;
  extensions: Record<string, unknown>;
}

/** Wire shape of step=accepted in the resume flow (signed). */
export interface ResumeAccepted {
  type: "SEMP_HANDSHAKE";
  step: "accepted";
  party: "server";
  version: "1.0.0";
  session_id: string;
  session_ttl: number;
  server_nonce: string;
  server_ephemeral_key: { algorithm: string; key: string; key_id: string };
  resumption_ticket: ResumptionTicket;
  server_signature: string;
  extensions: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Client side

export interface ResumeClientConfig {
  /** Server domain signing public key (32-byte Ed25519). */
  serverDomainPub: Uint8Array;
  /** Transport identifier echoed in the resume request. */
  transport: string;
  /** K_resumption from the prior session. */
  kResumption: Uint8Array;
  /** Opaque resumption_ticket value from the prior session. */
  resumptionTicket: string;
  /** Optional pinned ephemeral private (32 bytes) for tests. */
  clientEphemeralPriv?: Uint8Array;
  /** Optional pinned 32-byte client nonce for tests. */
  clientNonce?: Uint8Array;
  /** Optional extensions to advertise. */
  extensions?: Record<string, unknown>;
}

/**
 * Drive the client side of a resume. Resolves with a fresh
 * {@link Session} on success; throws {@link HandshakeRejectedError}
 * if the server rejects.
 */
export async function resumeClient(
  transport: Transport,
  config: ResumeClientConfig,
): Promise<Session> {
  try {
    return await resumeClientInner(transport, config);
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // already closed
    }
    throw err;
  }
}

async function resumeClientInner(
  transport: Transport,
  config: ResumeClientConfig,
): Promise<Session> {
  const ephPriv = config.clientEphemeralPriv ?? randomBytes(32);
  const ephPub = x25519PublicKey(ephPriv);
  const clientNonce = config.clientNonce ?? randomBytes(32);

  // Build + send resume request.
  const req: ResumeRequest = {
    type: "SEMP_HANDSHAKE",
    step: "resume",
    party: "client",
    version: "1.0.0",
    nonce: base64Encode(clientNonce),
    resumption_ticket: config.resumptionTicket,
    client_ephemeral_key: {
      algorithm: "x25519-chacha20-poly1305",
      key: base64Encode(ephPub),
      key_id: fingerprint(ephPub),
    },
    transport: config.transport,
    extensions: config.extensions ?? {},
  };
  await transport.send(canonicalMarshal(req));

  // Receive accepted (or rejected).
  const respBytes = await transport.receive();
  if (respBytes === null) {
    throw new Error("resume: connection closed waiting for response");
  }
  const respMsg = JSON.parse(new TextDecoder().decode(respBytes)) as { step?: string };
  if (respMsg.step === "rejected") {
    const r = respMsg as { session_id?: string; reason_code?: string; reason?: string };
    throw new HandshakeRejectedError(
      r.session_id ?? "",
      r.reason_code ?? "auth_failed",
      r.reason,
    );
  }
  if (respMsg.step !== "accepted") {
    throw new Error(`resume: expected step=accepted, got ${respMsg.step ?? "?"}`);
  }
  const accepted = respMsg as ResumeAccepted;

  // Verify server_signature.
  verifyAcceptedSignature(accepted, config.serverDomainPub);

  // Derive new session keys.
  const serverEphPub = base64Decode(accepted.server_ephemeral_key.key);
  const serverNonce = base64Decode(accepted.server_nonce);
  const ephSharedSecret = x25519Agree(ephPriv, serverEphPub);
  const kdf = newHKDFSHA512();
  const keys = deriveResumedSessionKeys(
    kdf,
    ephSharedSecret,
    config.kResumption,
    clientNonce,
    serverNonce,
  );

  return new Session({
    role: "client",
    sessionId: accepted.session_id,
    sessionTTL: accepted.session_ttl,
    establishedAt: new Date(),
    permissions: [],  // resume preserves the prior permission set; the
    // higher-level client carries it over from the previous session
    keys,
    transport,
    resumptionTicket: accepted.resumption_ticket,
    extensions: accepted.extensions,
  });
}

function verifyAcceptedSignature(
  accepted: ResumeAccepted,
  serverDomainPub: Uint8Array,
): void {
  const sig = base64Decode(accepted.server_signature);
  const blanked = { ...accepted, server_signature: "" };
  const canonical = canonicalMarshal(blanked);
  const signingInput = concat(new TextEncoder().encode(HandshakePrefix), canonical);
  if (!ed25519Verify(serverDomainPub, sig, signingInput)) {
    throw new Error("resume: server_signature did not verify under server domain pub");
  }
}

// ---------------------------------------------------------------------------
// Server side

/** Outcome of a ticket lookup performed by the server. */
export type TicketLookupResult =
  | {
      ok: true;
      /** K_resumption retained from the prior session. */
      kResumption: Uint8Array;
      /** Permissions to grant on the resumed session. */
      permissions: ReadonlyArray<string>;
    }
  | { ok: false; reasonCode: string; reason?: string };

export interface ResumeServerConfig {
  /** 32-byte Ed25519 secret seed for the server domain signing key. */
  serverDomainSigningSeed: Uint8Array;
  /**
   * Look up the resumption_ticket from the request. Production
   * servers route through a per-process cache + transparent
   * persistence layer; tests pass an in-memory map.
   */
  lookupTicket: (ticket: string) => Promise<TicketLookupResult> | TicketLookupResult;
  /** Mint a fresh resumption_ticket for the new session. */
  generateNewTicket: () => ResumptionTicket;
  /** Mint a fresh session_id for the new session. */
  generateSessionId: () => string;
  /** Session TTL in seconds. */
  sessionTTL: number;
  /** Optional extensions echoed in the accepted message. */
  acceptedExtensions?: Record<string, unknown>;
  /** Optional pinned ephemeral private for tests. */
  serverEphemeralPriv?: Uint8Array;
  /** Optional pinned 32-byte server nonce for tests. */
  serverNonce?: Uint8Array;
}

/**
 * Drive the server side of a resume. Reads the resume request,
 * looks up the ticket, generates a fresh ephemeral + nonce + new
 * session_id, builds and signs the accepted response, and returns
 * a Session.
 */
export async function resumeServer(
  transport: Transport,
  config: ResumeServerConfig,
): Promise<Session> {
  try {
    return await resumeServerInner(transport, config);
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // already closed
    }
    throw err;
  }
}

async function resumeServerInner(
  transport: Transport,
  config: ResumeServerConfig,
): Promise<Session> {
  // Receive resume request.
  const reqBytes = await transport.receive();
  if (reqBytes === null) {
    throw new Error("resume: connection closed waiting for request");
  }
  const req = JSON.parse(new TextDecoder().decode(reqBytes)) as ResumeRequest;
  if (req.type !== "SEMP_HANDSHAKE" || req.step !== "resume") {
    throw new Error(`resume: expected step=resume, got ${req.step}`);
  }

  // Validate ticket.
  const lookup = await config.lookupTicket(req.resumption_ticket);
  if (!lookup.ok) {
    await sendRejected(transport, req, lookup.reasonCode, lookup.reason, config.serverDomainSigningSeed);
    throw new Error(`resume: ticket invalid: ${lookup.reasonCode}`);
  }

  // Fresh ephemeral + nonce + new session_id + new ticket.
  const ephPriv = config.serverEphemeralPriv ?? randomBytes(32);
  const ephPub = x25519PublicKey(ephPriv);
  const serverNonce = config.serverNonce ?? randomBytes(32);
  const newSessionId = config.generateSessionId();
  const newTicket = config.generateNewTicket();

  // Derive new session keys using the retained K_resumption.
  const clientEphPub = base64Decode(req.client_ephemeral_key.key);
  const clientNonce = base64Decode(req.nonce);
  const ephSharedSecret = x25519Agree(ephPriv, clientEphPub);
  const kdf = newHKDFSHA512();
  const keys = deriveResumedSessionKeys(
    kdf,
    ephSharedSecret,
    lookup.kResumption,
    clientNonce,
    serverNonce,
  );

  // Build + sign accepted.
  const accepted: ResumeAccepted = {
    type: "SEMP_HANDSHAKE",
    step: "accepted",
    party: "server",
    version: "1.0.0",
    session_id: newSessionId,
    session_ttl: config.sessionTTL,
    server_nonce: base64Encode(serverNonce),
    server_ephemeral_key: {
      algorithm: "x25519-chacha20-poly1305",
      key: base64Encode(ephPub),
      key_id: fingerprint(ephPub),
    },
    resumption_ticket: newTicket,
    server_signature: "",
    extensions: config.acceptedExtensions ?? {},
  };
  const { signedJSON } = signSignedDoc({
    preSignJSON: accepted as unknown as Record<string, unknown>,
    seed: config.serverDomainSigningSeed,
    signaturePath: "server_signature",
    prefix: HandshakePrefix,
  });
  await transport.send(canonicalMarshal(signedJSON));

  return new Session({
    role: "server",
    sessionId: newSessionId,
    sessionTTL: config.sessionTTL,
    establishedAt: new Date(),
    permissions: [...lookup.permissions],
    keys,
    transport,
    resumptionTicket: newTicket,
    serverIdentityProofKeyId: fingerprint(publicKeyFromSeed(config.serverDomainSigningSeed)),
    extensions: config.acceptedExtensions ?? {},
  });
}

async function sendRejected(
  transport: Transport,
  req: ResumeRequest,
  reasonCode: string,
  reason: string | undefined,
  serverDomainSigningSeed: Uint8Array,
): Promise<void> {
  const rejected: Record<string, unknown> = {
    type: "SEMP_HANDSHAKE",
    step: "rejected",
    party: "server",
    version: "1.0.0",
    session_id: "",
    reason_code: reasonCode,
    server_signature: "",
    extensions: {},
  };
  if (reason !== undefined) {
    rejected.reason = reason;
  }
  void req; // request kept for trace context if logging is added later
  const { signedJSON } = signSignedDoc({
    preSignJSON: rejected,
    seed: serverDomainSigningSeed,
    signaturePath: "server_signature",
    prefix: HandshakePrefix,
  });
  try {
    await transport.send(canonicalMarshal(signedJSON));
  } catch {
    // peer may have already disconnected
  }
}

// ---------------------------------------------------------------------------
// Helpers

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
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
