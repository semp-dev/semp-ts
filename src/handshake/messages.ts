/**
 * Handshake message builders per HANDSHAKE.md §2.
 *
 * Five message kinds in the v1 handshake flow:
 *
 *   INIT      client -> server (step="init", no signature)
 *   RESPONSE  server -> client (step="response", server_signature)
 *   CONFIRM   client -> server (step="confirm", carries identity_proof)
 *   ACCEPTED  server -> client (step="accepted", server_signature)
 *   REJECTED  server -> client (step="rejected", reason_code,
 *                               server_signature)
 *
 * The signed messages share the canonical-bytes pattern every other
 * SEMP-signed document uses: blank `server_signature`, canonicalize,
 * prepend `SEMP-HANDSHAKE:`, Ed25519-sign with the server domain
 * signing key, write the signature back into the message.
 *
 * @module
 */

import { signSignedDoc } from "../keys/signed.js";

/** Domain-separation prefix for all handshake signatures. */
export const HandshakePrefix = "SEMP-HANDSHAKE:";

/** Common version string. */
export const HandshakeVersion = "1.0.0";

/** A keyref (algorithm + key bytes + fingerprint) shared by both parties. */
export interface KeyRef {
  algorithm: string;
  /** base64 encoding of the public key bytes */
  key: string;
  /** lowercase-hex SHA-256 fingerprint of the key */
  key_id: string;
}

/** Capabilities section advertised by the client in INIT. */
export interface Capabilities {
  encryption_algorithms: string[];
  extensions: string[];
}

/** Negotiated subset agreed on in RESPONSE. */
export interface Negotiated {
  encryption_algorithm: string;
  extensions: string[];
  /**
   * Optional max envelope size negotiation. The server may pin a
   * stricter ceiling than the protocol default; the client honors
   * whichever value the server returns.
   */
  max_envelope_size?: number;
}

/** Server's identity-proof signature reference attached to RESPONSE. */
export interface ServerIdentityProof {
  domain: string;
  key_id: string;
  /** base64 of the identity-proof signature; computation defined in §2.3. */
  signature: string;
}

// ---------------------------------------------------------------------------
// INIT (client -> server)

export interface InitMessage {
  type: "SEMP_HANDSHAKE";
  step: "init";
  party: "client";
  version: string;
  /** base64 of 32-byte client nonce */
  nonce: string;
  /** Transport identifier; one of "ws", "h2", "quic". */
  transport: string;
  /** Client ephemeral public key for the negotiated KEM. */
  client_ephemeral_key: KeyRef;
  capabilities: Capabilities;
  extensions: Record<string, unknown>;
}

export interface BuildInitInput {
  nonce: string;
  transport: string;
  clientEphemeralKey: KeyRef;
  capabilities: Capabilities;
  extensions?: Record<string, unknown>;
}

/** Build a canonical-shape INIT message. INIT is unsigned. */
export function buildInit(input: BuildInitInput): InitMessage {
  return {
    type: "SEMP_HANDSHAKE",
    step: "init",
    party: "client",
    version: HandshakeVersion,
    nonce: input.nonce,
    transport: input.transport,
    client_ephemeral_key: input.clientEphemeralKey,
    capabilities: input.capabilities,
    extensions: input.extensions ?? {},
  };
}

// ---------------------------------------------------------------------------
// RESPONSE (server -> client, signed)

export interface ResponseMessage {
  type: "SEMP_HANDSHAKE";
  step: "response";
  party: "server";
  version: string;
  session_id: string;
  client_nonce: string;
  server_nonce: string;
  server_ephemeral_key: KeyRef;
  server_identity_proof: ServerIdentityProof;
  negotiated: Negotiated;
  server_signature: string;
  extensions: Record<string, unknown>;
}

export interface BuildResponseInput {
  sessionId: string;
  clientNonce: string;
  serverNonce: string;
  serverEphemeralKey: KeyRef;
  serverIdentityProof: ServerIdentityProof;
  negotiated: Negotiated;
  /** 32-byte Ed25519 secret seed for the server domain signing key. */
  serverDomainSigningSeed: Uint8Array;
  extensions?: Record<string, unknown>;
}

/**
 * Build a signed RESPONSE message. Composes the canonical pre-sign
 * shape, signs over `SEMP-HANDSHAKE: || canonical(blanked)`, and
 * writes the base64-encoded signature back into `server_signature`.
 */
export function buildResponse(input: BuildResponseInput): ResponseMessage {
  const preSign: ResponseMessage = {
    type: "SEMP_HANDSHAKE",
    step: "response",
    party: "server",
    version: HandshakeVersion,
    session_id: input.sessionId,
    client_nonce: input.clientNonce,
    server_nonce: input.serverNonce,
    server_ephemeral_key: input.serverEphemeralKey,
    server_identity_proof: input.serverIdentityProof,
    negotiated: input.negotiated,
    server_signature: "",
    extensions: input.extensions ?? {},
  };
  const { signedJSON } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.serverDomainSigningSeed,
    signaturePath: "server_signature",
    prefix: HandshakePrefix,
  });
  return signedJSON as unknown as ResponseMessage;
}

// ---------------------------------------------------------------------------
// CONFIRM (client -> server)

export interface ConfirmMessage {
  type: "SEMP_HANDSHAKE";
  step: "confirm";
  party: "client";
  version: string;
  session_id: string;
  /** base64 of the SHA-256 confirmation hash; see handshake.confirmationHash. */
  confirmation_hash: string;
  /** Opaque identity-proof ciphertext (encrypted under the agreed session key). */
  identity_proof: string;
  extensions: Record<string, unknown>;
}

export interface BuildConfirmInput {
  sessionId: string;
  confirmationHashB64: string;
  identityProofB64: string;
  extensions?: Record<string, unknown>;
}

/** Build a canonical-shape CONFIRM message. CONFIRM is unsigned at this layer. */
export function buildConfirm(input: BuildConfirmInput): ConfirmMessage {
  return {
    type: "SEMP_HANDSHAKE",
    step: "confirm",
    party: "client",
    version: HandshakeVersion,
    session_id: input.sessionId,
    confirmation_hash: input.confirmationHashB64,
    identity_proof: input.identityProofB64,
    extensions: input.extensions ?? {},
  };
}

// ---------------------------------------------------------------------------
// ACCEPTED (server -> client, signed)

export interface ResumptionTicket {
  /** Opaque ticket value (server-defined opaque blob). */
  value: string;
  /** ISO 8601 timestamp at which the ticket stops being valid. */
  expires_at: string;
}

export interface AcceptedMessage {
  type: "SEMP_HANDSHAKE";
  step: "accepted";
  party: "server";
  version: string;
  session_id: string;
  session_ttl: number;
  permissions: string[];
  resumption_ticket?: ResumptionTicket;
  server_signature: string;
  extensions: Record<string, unknown>;
}

export interface BuildAcceptedInput {
  sessionId: string;
  sessionTTL: number;
  permissions: string[];
  resumptionTicket?: ResumptionTicket;
  serverDomainSigningSeed: Uint8Array;
  extensions?: Record<string, unknown>;
}

export function buildAccepted(input: BuildAcceptedInput): AcceptedMessage {
  const preSign: AcceptedMessage = {
    type: "SEMP_HANDSHAKE",
    step: "accepted",
    party: "server",
    version: HandshakeVersion,
    session_id: input.sessionId,
    session_ttl: input.sessionTTL,
    permissions: input.permissions,
    server_signature: "",
    extensions: input.extensions ?? {},
  };
  if (input.resumptionTicket !== undefined) {
    preSign.resumption_ticket = input.resumptionTicket;
  }
  const { signedJSON } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.serverDomainSigningSeed,
    signaturePath: "server_signature",
    prefix: HandshakePrefix,
  });
  return signedJSON as unknown as AcceptedMessage;
}

// ---------------------------------------------------------------------------
// REJECTED (server -> client, signed)

export interface RejectedMessage {
  type: "SEMP_HANDSHAKE";
  step: "rejected";
  party: "server";
  version: string;
  session_id: string;
  reason_code: string;
  /** Optional human-readable reason. */
  reason?: string;
  server_signature: string;
  extensions: Record<string, unknown>;
}

export interface BuildRejectedInput {
  sessionId: string;
  reasonCode: string;
  reason?: string;
  serverDomainSigningSeed: Uint8Array;
  extensions?: Record<string, unknown>;
}

export function buildRejected(input: BuildRejectedInput): RejectedMessage {
  const preSign: RejectedMessage = {
    type: "SEMP_HANDSHAKE",
    step: "rejected",
    party: "server",
    version: HandshakeVersion,
    session_id: input.sessionId,
    reason_code: input.reasonCode,
    server_signature: "",
    extensions: input.extensions ?? {},
  };
  if (input.reason !== undefined) {
    preSign.reason = input.reason;
  }
  const { signedJSON } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.serverDomainSigningSeed,
    signaturePath: "server_signature",
    prefix: HandshakePrefix,
  });
  return signedJSON as unknown as RejectedMessage;
}
