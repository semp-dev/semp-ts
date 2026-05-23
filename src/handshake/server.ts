/**
 * Handshake server driver per HANDSHAKE.md §2.
 *
 * Mirror of {@link "./driver".runClient}: drives one transport
 * through the v1 handshake from the server side, producing a
 * Session on success.
 *
 * Flow:
 *
 *   1. Receive INIT. Pull capabilities, transport identifier,
 *      client ephemeral key, client nonce.
 *   2. Negotiate the encryption algorithm (server picks the
 *      strongest mutually supported suite per HANDSHAKE.md §3).
 *   3. Generate a server ephemeral X25519 keypair and a 32-byte
 *      server nonce. Pick a session_id (ULID by convention).
 *   4. Derive the five SEMP session keys + K_resumption via
 *      HKDF-SHA-512 over the X25519 shared secret with salt
 *      `client_nonce || server_nonce`.
 *   5. Build and send a signed RESPONSE.
 *   6. Receive CONFIRM. Verify the confirmation hash matches
 *      SHA-256(canonical(INIT) || canonical(RESPONSE)).
 *   7. (Optional) Verify the identity proof via a caller-supplied
 *      hook. v1 driver: if no hook is supplied, skip; otherwise
 *      reject on hook rejection.
 *   8. Build and send a signed ACCEPTED with permissions, TTL,
 *      and an optional resumption ticket.
 *
 * Errors close the transport so the peer's pending receive
 * unblocks.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  type SessionKeys,
  deriveSessionKeysWithResumption,
  hybridEncapsulate,
  hybridEncapsulateWithRandomness,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint, publicKeyFromSeed, verify as ed25519Verify } from "../keys/index.js";

import { sha256 } from "@noble/hashes/sha2.js";
import { Session } from "../session/index.js";
import type { Transport } from "../transport/index.js";

import { confirmationHash } from "./confirm.js";
import type { HandshakeSuite } from "./driver.js";
import {
  type IdentityProofBlock,
  IdentityPrefix,
  openIdentityProof,
} from "./identity.js";
import {
  type AcceptedMessage,
  type ConfirmMessage,
  type InitMessage,
  type ResponseMessage,
  type ResumptionTicket,
  type ServerIdentityProof,
  buildAccepted,
  buildRejected,
  buildResponse,
} from "./messages.js";

/** Result the identity-proof hook returns. */
export interface IdentityProofVerdict {
  /** True if the proof is acceptable. */
  ok: boolean;
  /**
   * On `ok=false`, the reason_code surfaced in the REJECTED
   * message (default: "auth_failed").
   */
  reasonCode?: string;
  /** On `ok=false`, the optional human-readable reason. */
  reason?: string;
}

/** Configuration for the server side of a handshake. */
export interface ServerConfig {
  /** 32-byte Ed25519 secret seed for the server's domain signing key. */
  serverDomainSigningSeed: Uint8Array;
  /** The server's domain, surfaced in `server_identity_proof.domain`. */
  domain: string;
  /**
   * Suites this server accepts, in preference order. The server
   * picks the first one that's also in the client's offered set.
   */
  supportedSuites: ReadonlyArray<HandshakeSuite>;
  /**
   * Per-session identity-proof signature. The driver embeds this
   * into RESPONSE.server_identity_proof. Production servers compute
   * it per HANDSHAKE.md §2.3 over the agreed handshake parameters;
   * v1 driver accepts a caller-supplied callback so the higher
   * layer keeps the per-session signing key out of this module.
   */
  identityProofSignature: (input: {
    serverEphemeralKey: { algorithm: string; key: string; key_id: string };
    clientNonce: string;
    serverNonce: string;
  }) => string;
  /**
   * Optional verifier for the client's identity proof carried in
   * CONFIRM. If omitted, the v1 driver accepts any non-empty
   * proof (and an empty proof, since the v1 client driver leaves
   * it empty).
   *
   * The `block` field is the AEAD-decrypted identity-proof block
   * when the proof bytes successfully unwrapped under K_enc_c2s.
   * It is undefined when the wrapped proof is empty or when AEAD
   * open failed (in which case the driver has already rejected
   * with `auth_failed` before invoking this callback). Consumers
   * that already needed to decrypt the proof can read `block`
   * instead of re-running {@link openIdentityProof}.
   */
  verifyIdentityProof?: (input: {
    identityProofB64: string;
    sessionKeys: SessionKeys;
    block?: import("./identity.js").IdentityProofBlock;
  }) => IdentityProofVerdict;
  /**
   * Optional lookup of the public key for a client's long-term
   * identity key. When supplied, the driver verifies the
   * inner identity_signature inside the decrypted identity-proof
   * block over `SEMP-IDENTITY: || session_id || confirmation_hash`
   * and rejects with `auth_failed` on signature failure.
   *
   * When omitted, the inner signature is not checked. Callers
   * that want to enforce identity binding without supplying this
   * lookup can do so themselves inside
   * {@link verifyIdentityProof}.
   *
   * Throw to reject the handshake with the `auth_failed` reason.
   */
  lookupClientIdentityKey?: (
    clientIdentity: string,
    clientLongTermKeyId: string,
  ) => Uint8Array;
  /**
   * Permissions to grant on ACCEPTED. v1 driver does no
   * authorization; the caller decides.
   */
  permissions: ReadonlyArray<string>;
  /** Session TTL in seconds. */
  sessionTTL: number;
  /** Optional resumption ticket builder; called once after CONFIRM. */
  resumptionTicket?: (sessionKeys: SessionKeys) => ResumptionTicket;
  /** Generator for session_id (ULID-shaped string). Required. */
  generateSessionId: () => string;
  /** Optional bytes for the server ephemeral private key (tests; baseline suite). */
  serverEphemeralPriv?: Uint8Array;
  /**
   * Optional pre-pinned hybrid encapsulation randomness (deterministic
   * tests + replay; PQ suite). See
   * {@link "./federation".FederationResponderConfig.responderHybridRandomness}.
   */
  serverHybridRandomness?: {
    kyberEncapsRandomnessM: Uint8Array;
    ephemeralX25519Priv: Uint8Array;
  };
  /** Optional 32-byte server nonce (tests). */
  serverNonce?: Uint8Array;
  /** Optional extensions echoed back on ACCEPTED. */
  acceptedExtensions?: Record<string, unknown>;
}

/**
 * Drive a handshake from the server side over `transport`. Resolves
 * with a Session (role="server") that owns the transport on
 * success. On rejection (suite mismatch, identity proof failure,
 * confirmation hash mismatch) sends a signed REJECTED then closes
 * the transport.
 */
export async function runServer(
  transport: Transport,
  config: ServerConfig,
): Promise<Session> {
  try {
    return await runServerInner(transport, config);
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // already closed
    }
    throw err;
  }
}

async function runServerInner(
  transport: Transport,
  config: ServerConfig,
): Promise<Session> {
  // Step 1: receive INIT.
  const initBytes = await receiveOrThrow(transport, "init");
  const initMsg = parseHandshakeMessage(initBytes);
  if (initMsg.step !== "init") {
    throw new Error(`handshake: expected step="init", got "${initMsg.step}"`);
  }
  const init = JSON.parse(new TextDecoder().decode(initBytes)) as InitMessage;

  // Step 2: negotiate.
  const negotiated = pickSuite(init.capabilities.encryption_algorithms, config.supportedSuites);
  const sessionId = config.generateSessionId();
  if (negotiated === undefined) {
    await sendRejected(transport, sessionId, "version_unsupported", config.serverDomainSigningSeed);
    throw new Error("handshake: no mutually supported suite");
  }

  // Step 3: ephemeral + nonce + session_id. The wire form of
  // server_ephemeral_key depends on the suite: a 32-byte X25519
  // pub for baseline, a 1120-byte hybrid KEM ciphertext
  // (kyberCt || responderX25519Pub) for PQ. The server holds no
  // ephemeral private key on the PQ path because Encapsulate
  // produces the shared secret directly.
  const isPQ = negotiated === "pq-kyber768-x25519";
  const clientEphPub = base64Decode(init.client_ephemeral_key.key);
  const clientNonce = base64Decode(init.nonce);
  const serverNonce = config.serverNonce ?? randomBytes(32);
  let serverEphPub: Uint8Array;
  let sharedSecret: Uint8Array;
  if (isPQ) {
    const enc =
      config.serverHybridRandomness !== undefined
        ? hybridEncapsulateWithRandomness(
            clientEphPub,
            config.serverHybridRandomness,
          )
        : hybridEncapsulate(clientEphPub);
    serverEphPub = enc.ciphertext;
    sharedSecret = enc.sharedSecret;
  } else {
    const serverEphPriv = config.serverEphemeralPriv ?? randomBytes(32);
    serverEphPub = x25519PublicKey(serverEphPriv);
    sharedSecret = x25519Agree(serverEphPriv, clientEphPub);
    serverEphPriv.fill(0);
  }
  const serverEphKeyId = isPQ
    ? hexSha256(serverEphPub)
    : fingerprint(serverEphPub);

  // Step 4: derive session keys.
  const kdf = newHKDFSHA512();
  const keys = deriveSessionKeysWithResumption(
    kdf,
    sharedSecret,
    clientNonce,
    serverNonce,
  );

  // Step 5: signed RESPONSE.
  const serverIdentityProof: ServerIdentityProof = {
    domain: config.domain,
    key_id: fingerprint(publicKeyFromSeed(config.serverDomainSigningSeed)),
    signature: config.identityProofSignature({
      serverEphemeralKey: {
        algorithm: negotiated,
        key: base64Encode(serverEphPub),
        key_id: serverEphKeyId,
      },
      clientNonce: init.nonce,
      serverNonce: base64Encode(serverNonce),
    }),
  };
  const resp: ResponseMessage = buildResponse({
    sessionId,
    clientNonce: init.nonce,
    serverNonce: base64Encode(serverNonce),
    serverEphemeralKey: {
      algorithm: negotiated,
      key: base64Encode(serverEphPub),
      key_id: serverEphKeyId,
    },
    serverIdentityProof,
    negotiated: {
      encryption_algorithm: negotiated,
      extensions: [],
    },
    serverDomainSigningSeed: config.serverDomainSigningSeed,
  });
  await transport.send(canonicalMarshal(resp));

  // Step 6: CONFIRM.
  const confirmBytes = await receiveOrThrow(transport, "confirm");
  const confirmMsg = parseHandshakeMessage(confirmBytes);
  if (confirmMsg.step !== "confirm") {
    throw new Error(`handshake: expected step="confirm", got "${confirmMsg.step}"`);
  }
  const confirm = JSON.parse(new TextDecoder().decode(confirmBytes)) as ConfirmMessage;

  // Verify confirmation_hash.
  const wantHash = confirmationHash(initBytes, canonicalMarshal(resp));
  const gotHash = base64Decode(confirm.confirmation_hash);
  if (!constantTimeEqual(gotHash, wantHash)) {
    await sendRejected(transport, sessionId, "handshake_invalid", config.serverDomainSigningSeed);
    throw new Error("handshake: confirmation hash mismatch");
  }

  // Step 7: identity proof. Decrypt the AEAD-protected block when it
  // is non-empty and surface it to the verifier; verify the inner
  // identity_signature against `lookupClientIdentityKey` when
  // supplied. The driver rejects with `auth_failed` on AEAD open
  // failure, on a missing identity key, or on signature failure.
  let identityBlock: IdentityProofBlock | undefined;
  if (confirm.identity_proof !== "") {
    try {
      identityBlock = openIdentityProof({
        identityProofB64: confirm.identity_proof,
        encC2S: keys.encC2S,
        sessionId,
      });
    } catch (err) {
      await sendRejected(
        transport,
        sessionId,
        "auth_failed",
        config.serverDomainSigningSeed,
        err instanceof Error ? err.message : String(err),
      );
      throw new Error(
        `handshake: identity_proof open failed (${err instanceof Error ? err.message : String(err)})`,
      );
    }
    if (config.lookupClientIdentityKey !== undefined) {
      let clientPub: Uint8Array;
      try {
        clientPub = config.lookupClientIdentityKey(
          identityBlock.client_identity,
          identityBlock.client_long_term_key_id,
        );
      } catch (err) {
        await sendRejected(
          transport,
          sessionId,
          "auth_failed",
          config.serverDomainSigningSeed,
          err instanceof Error ? err.message : String(err),
        );
        throw new Error(
          `handshake: identity key lookup failed (${err instanceof Error ? err.message : String(err)})`,
        );
      }
      const sessionIdBytes = new TextEncoder().encode(sessionId);
      const signed = concat(
        new TextEncoder().encode(IdentityPrefix),
        concat(sessionIdBytes, wantHash),
      );
      const sig = base64Decode(identityBlock.identity_signature);
      if (!ed25519Verify(clientPub, sig, signed)) {
        await sendRejected(
          transport,
          sessionId,
          "auth_failed",
          config.serverDomainSigningSeed,
          "identity_signature did not verify",
        );
        throw new Error("handshake: identity_signature did not verify");
      }
    }
  }
  if (config.verifyIdentityProof !== undefined) {
    const verdict = config.verifyIdentityProof({
      identityProofB64: confirm.identity_proof,
      sessionKeys: keys,
      ...(identityBlock !== undefined ? { block: identityBlock } : {}),
    });
    if (!verdict.ok) {
      await sendRejected(
        transport,
        sessionId,
        verdict.reasonCode ?? "auth_failed",
        config.serverDomainSigningSeed,
        verdict.reason,
      );
      throw new Error(
        `handshake: identity proof rejected (${verdict.reasonCode ?? "auth_failed"})`,
      );
    }
  }

  // Step 8: signed ACCEPTED.
  const ticket = config.resumptionTicket?.(keys);
  const accepted: AcceptedMessage = buildAccepted({
    sessionId,
    sessionTTL: config.sessionTTL,
    permissions: [...config.permissions],
    serverDomainSigningSeed: config.serverDomainSigningSeed,
    ...(ticket !== undefined ? { resumptionTicket: ticket } : {}),
    ...(config.acceptedExtensions !== undefined
      ? { extensions: config.acceptedExtensions }
      : {}),
  });
  await transport.send(canonicalMarshal(accepted));

  return new Session({
    role: "server",
    sessionId,
    sessionTTL: config.sessionTTL,
    establishedAt: new Date(),
    permissions: [...config.permissions],
    keys,
    transport,
    ...(ticket !== undefined ? { resumptionTicket: ticket } : {}),
    serverIdentityProofKeyId: serverIdentityProof.key_id,
    serverIdentityProofSignature: serverIdentityProof.signature,
    extensions: config.acceptedExtensions ?? {},
  });
}

// ---------------------------------------------------------------------------
// Internals

function pickSuite(
  clientOffers: string[],
  serverSupports: ReadonlyArray<HandshakeSuite>,
): HandshakeSuite | undefined {
  for (const s of serverSupports) {
    if (clientOffers.includes(s)) {
      return s;
    }
  }
  return undefined;
}

async function sendRejected(
  transport: Transport,
  sessionId: string,
  reasonCode: string,
  serverDomainSigningSeed: Uint8Array,
  reason?: string,
): Promise<void> {
  const r = buildRejected({
    sessionId,
    reasonCode,
    serverDomainSigningSeed,
    ...(reason !== undefined ? { reason } : {}),
  });
  try {
    await transport.send(canonicalMarshal(r));
  } catch {
    // peer may have already disconnected; ignore.
  }
}

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

function hexSha256(bytes: Uint8Array): string {
  // Hybrid ephemeral pubs / KEM ciphertexts are larger than the
  // 32-byte input `keys.fingerprint` accepts, so this opaque
  // SHA-256-of-the-wire-bytes is what we surface as the
  // ephemeral key_id field for the PQ suite. The handshake uses
  // ephemeral key_ids as opaque correlation tags only.
  const sum = sha256(bytes);
  let s = "";
  for (let i = 0; i < sum.length; i++) {
    s += (sum[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
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
