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
 * different. Both the baseline X25519 suite and the hybrid
 * Kyber768 + X25519 PQ suite are supported end to end. On the PQ
 * path step 1 generates a hybrid keypair, step 4 decapsulates the
 * server's hybrid KEM ciphertext to recover the same combined
 * shared secret the responder produced.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  type SessionKeys,
  HybridPublicKeySize,
  deriveSessionKeysWithResumption,
  hybridDecapsulate,
  hybridGenerateKeyPair,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint, verify as ed25519Verify } from "../keys/index.js";
import { Session } from "../session/index.js";
import type { Transport } from "../transport/index.js";

import { sha256 } from "@noble/hashes/sha2.js";

import { confirmationHash } from "./confirm.js";
import { composeIdentityProof } from "./identity.js";
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

/**
 * Negotiable handshake suite. The driver supports both the
 * baseline X25519 + ChaCha20-Poly1305 suite and the hybrid
 * Kyber768 + X25519 PQ suite. The negotiator picks one of these
 * based on capability overlap; supplying `pq-kyber768-x25519`
 * gives you the hybrid PQ KEM end-to-end and `x25519-chacha20-poly1305`
 * gives you the classical baseline.
 */
export type HandshakeSuite =
  | "x25519-chacha20-poly1305"
  | "pq-kyber768-x25519";

/** Configuration for the client side of a handshake. */
export interface ClientConfig {
  /** Algorithm suite to negotiate. */
  suite: HandshakeSuite;
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
  /**
   * Optional identity-proof material. When supplied, the driver
   * constructs a proper §2.5.2 block: identity_signature over
   * SEMP-IDENTITY: || session_id || confirmation_hash, then
   * AEAD-Seal under K_enc_c2s with AAD = session_id.
   *
   * When omitted (the default), the driver leaves identity_proof
   * empty - the higher-level client wraps runClient with its
   * own auth supply.
   */
  identity?: {
    clientId: string;
    /** Full address: user@domain. */
    clientIdentity: string;
    /** 32-byte Ed25519 secret seed for the long-term identity key. */
    longTermSeed: Uint8Array;
    /** Fingerprint of the long-term public key. */
    longTermKeyId: string;
    /**
     * Optional 12-byte AEAD nonce for deterministic tests. Production
     * callers omit this and let the driver source fresh entropy.
     */
    proofNonce?: Uint8Array;
  };
}

/**
 * Outcome of a successful handshake. The lower-level driver returns
 * the bare ClientSession structure; {@link runClient} wraps it in
 * a {@link Session} object that owns the transport.
 */
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
 * {@link Session} that owns `transport` and the derived session
 * keys; rejects with {@link HandshakeRejectedError} on a server
 * REJECTED, or a generic Error on protocol violation.
 *
 * On error the transport is closed so the peer's pending `receive`
 * unblocks. Successful completion leaves the transport owned by
 * the returned Session - closing the Session closes the transport.
 */
export async function runClient(
  transport: Transport,
  config: ClientConfig,
): Promise<Session> {
  if (
    config.suite !== "x25519-chacha20-poly1305" &&
    config.suite !== "pq-kyber768-x25519"
  ) {
    throw new Error(
      `handshake: unsupported suite ${JSON.stringify(config.suite)}`,
    );
  }
  try {
    const result = await runClientInner(transport, config);
    return new Session({
      role: "client",
      sessionId: result.sessionId,
      sessionTTL: result.sessionTTL,
      establishedAt: new Date(),
      permissions: result.permissions,
      keys: result.keys,
      transport,
      ...(result.resumptionTicket !== undefined
        ? { resumptionTicket: result.resumptionTicket }
        : {}),
      serverIdentityProofKeyId: result.serverIdentityProofKeyId,
      serverIdentityProofSignature: result.serverIdentityProofSignature,
      extensions: result.extensions,
    });
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

  // Step 1: ephemeral + nonce. The wire shape of the ephemeral
  // key depends on the suite: 32-byte X25519 pub for baseline,
  // 1216-byte hybrid (kyberPub || x25519Pub) for PQ.
  const isPQ = config.suite === "pq-kyber768-x25519";
  let ephPriv: Uint8Array;
  let ephPub: Uint8Array;
  if (isPQ) {
    const kp = hybridGenerateKeyPair();
    ephPriv = kp.secretKey;
    ephPub = kp.publicKey;
  } else {
    ephPriv = config.clientEphemeralPriv ?? randomBytes(32);
    ephPub = x25519PublicKey(ephPriv);
  }
  const clientNonce = config.clientNonce ?? randomBytes(32);
  // The hybrid pub is too large to fingerprint with the 32-byte
  // KEY.md primitive; we use a stable SHA-256 over the wire bytes
  // for the key_id field. For baseline this stays the same as
  // before.
  const ephKeyId = isPQ
    ? hexSha256(ephPub)
    : fingerprint(ephPub);

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

  // Step 4: derive session keys. For the PQ suite the wire
  // server_ephemeral_key is a hybrid KEM ciphertext (kyberCt ||
  // responderX25519Pub) that we decapsulate with the hybrid
  // private key we generated in step 1; for baseline we run the
  // legacy X25519 ECDH.
  let sharedSecret: Uint8Array;
  if (isPQ) {
    if (ephPub.length !== HybridPublicKeySize) {
      throw new Error(
        `handshake: PQ ephemeral pub ${ephPub.length} bytes, want ${HybridPublicKeySize}`,
      );
    }
    sharedSecret = hybridDecapsulate(serverEphPub, ephPriv);
  } else {
    sharedSecret = x25519Agree(ephPriv, serverEphPub);
  }
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

  // Step 6: CONFIRM. If `config.identity` is supplied, build the
  // §2.5.2 encrypted proof block; otherwise leave identity_proof
  // empty (the spec permits a placeholder for tests that don't
  // exercise identity verification).
  let identityProofB64 = "";
  if (config.identity !== undefined) {
    identityProofB64 = composeIdentityProof({
      clientId: config.identity.clientId,
      clientIdentity: config.identity.clientIdentity,
      clientLongTermSeed: config.identity.longTermSeed,
      clientLongTermKeyId: config.identity.longTermKeyId,
      sessionId: resp.session_id,
      confirmationHash: confirmHashBytes,
      encC2S: keys.encC2S,
      ...(config.identity.proofNonce !== undefined
        ? { proofNonce: config.identity.proofNonce }
        : {}),
    }).identityProofB64;
  }
  const confirm: ConfirmMessage = buildConfirm({
    sessionId: resp.session_id,
    confirmationHashB64: base64Encode(confirmHashBytes),
    identityProofB64,
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

function hexSha256(bytes: Uint8Array): string {
  // Hybrid ephemeral pubs are larger than 32 bytes, so we cannot
  // route them through `keys.fingerprint` (which enforces a
  // 32-byte input for KEY.md compatibility). The handshake uses
  // ephemeral key_ids as opaque correlation tags only; SHA-256
  // of the wire bytes gives a stable identifier of the right
  // shape (lowercase hex).
  const sum = sha256(bytes);
  let s = "";
  for (let i = 0; i < sum.length; i++) {
    s += (sum[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
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
