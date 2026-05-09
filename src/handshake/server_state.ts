/**
 * Stateful handshake server per HANDSHAKE.md §2.
 *
 * Mirror of `semp-go/handshake.Server`: a state machine the caller
 * drives over a transport. The class never performs network I/O
 * directly — the caller moves bytes between this object and the
 * underlying transport.
 *
 * Lifecycle:
 *
 * ```ts
 * const s = new HandshakeServer({ ... });
 * const initBytes = await transport.receive();
 * const respBytes = s.onInit(initBytes);
 * await transport.send(respBytes);
 *
 * const confirmBytes = await transport.receive();
 * const acceptedBytes = s.onConfirm(confirmBytes);
 * await transport.send(acceptedBytes);
 *
 * // s.session() now usable
 * ```
 *
 * The high-level {@link "./server".runServer} wraps this state
 * machine with the transport plumbing for callers who don't want
 * to manage step ordering manually.
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
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import { confirmationHash } from "./confirm.js";
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
import type { IdentityProofVerdict, ServerConfig } from "./server.js";

/**
 * Configuration for a {@link HandshakeServer}. Same fields as
 * {@link "./server".ServerConfig}; surfaced as a separate type so
 * the stateful class lifecycle is independent of the high-level
 * `runServer` orchestrator.
 */
export type HandshakeServerConfig = ServerConfig;

/** Outcome of a successful server-side handshake. */
export interface HandshakeServerSession {
  sessionId: string;
  sessionTTL: number;
  permissions: string[];
  keys: SessionKeys;
  serverIdentityProofKeyId: string;
  serverIdentityProofSignature: string;
  extensions: Record<string, unknown>;
  resumptionTicket?: ResumptionTicket;
}

/**
 * Error thrown when a built-in policy check rejects the peer
 * (suite mismatch, confirmation-hash mismatch, identity-proof
 * verdict). The associated `step="rejected"` bytes have already
 * been written to {@link HandshakeServer.lastRejectedBytes} so the
 * caller can transmit them before closing the transport.
 */
export class HandshakeServerRejectionError extends Error {
  override readonly name = "HandshakeServerRejectionError";
  constructor(
    public readonly reasonCode: string,
    public readonly reason: string | undefined,
    public readonly rejectedBytes: Uint8Array,
  ) {
    super(
      `handshake server rejected: ${reasonCode}${reason !== undefined ? ` (${reason})` : ""}`,
    );
  }
}

/**
 * Stateful handshake server. One instance handles exactly one
 * handshake — discard after success or error. Re-using an instance
 * is a programming error (the state machine is single-shot).
 */
export class HandshakeServer {
  private readonly cfg: HandshakeServerConfig;

  private sessionId = "";
  private serverEphPriv: Uint8Array | null = null;
  private serverNonce: Uint8Array | null = null;
  private initCanonical: Uint8Array | null = null;
  private respCanonical: Uint8Array | null = null;
  private sessionKeys: SessionKeys | null = null;
  private serverIdProof: ServerIdentityProof | null = null;
  private finalSession: HandshakeServerSession | null = null;

  constructor(cfg: HandshakeServerConfig) {
    if (cfg.supportedSuites.length === 0) {
      throw new Error("handshake: server has no supported suites");
    }
    if (cfg.serverDomainSigningSeed.length === 0) {
      throw new Error("handshake: empty server domain signing seed");
    }
    if (cfg.domain === "") {
      throw new Error("handshake: empty server domain");
    }
    this.cfg = cfg;
  }

  /**
   * Process the client's INIT and produce signed RESPONSE bytes per
   * §2.2 / §2.3. Throws {@link HandshakeServerRejectionError} on
   * suite mismatch — the rejection bytes are accessible on the
   * thrown error for the caller to transmit before closing the
   * transport.
   */
  onInit(data: Uint8Array): Uint8Array {
    if (this.initCanonical !== null) {
      throw new Error("handshake: onInit called twice");
    }
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as Partial<InitMessage> & {
      step?: string;
      type?: string;
    };
    if (m.type !== "SEMP_HANDSHAKE" || m.step !== "init") {
      throw new Error("handshake: init type/step mismatch");
    }
    const init = m as InitMessage;
    this.initCanonical = data;

    this.sessionId = this.cfg.generateSessionId();
    const negotiated = pickSuite(
      init.capabilities.encryption_algorithms,
      this.cfg.supportedSuites,
    );
    if (negotiated === undefined) {
      const rej = buildRejectedSigned(
        this.sessionId,
        "version_unsupported",
        undefined,
        this.cfg.serverDomainSigningSeed,
      );
      throw new HandshakeServerRejectionError(
        "version_unsupported",
        undefined,
        rej,
      );
    }
    this.serverEphPriv = this.cfg.serverEphemeralPriv ?? randomBytes(32);
    const serverEphPub = x25519PublicKey(this.serverEphPriv);
    const serverEphKeyId = fingerprint(serverEphPub);
    this.serverNonce = this.cfg.serverNonce ?? randomBytes(32);

    const clientEphPub = base64Decode(init.client_ephemeral_key.key);
    const clientNonce = base64Decode(init.nonce);
    const shared = x25519Agree(this.serverEphPriv, clientEphPub);
    const kdf = newHKDFSHA512();
    this.sessionKeys = deriveSessionKeysWithResumption(
      kdf,
      shared,
      clientNonce,
      this.serverNonce,
    );

    this.serverIdProof = {
      domain: this.cfg.domain,
      key_id: fingerprint(publicKeyFromSeed(this.cfg.serverDomainSigningSeed)),
      signature: this.cfg.identityProofSignature({
        serverEphemeralKey: {
          algorithm: negotiated,
          key: base64Encode(serverEphPub),
          key_id: serverEphKeyId,
        },
        clientNonce: init.nonce,
        serverNonce: base64Encode(this.serverNonce),
      }),
    };
    const resp: ResponseMessage = buildResponse({
      sessionId: this.sessionId,
      clientNonce: init.nonce,
      serverNonce: base64Encode(this.serverNonce),
      serverEphemeralKey: {
        algorithm: negotiated,
        key: base64Encode(serverEphPub),
        key_id: serverEphKeyId,
      },
      serverIdentityProof: this.serverIdProof,
      negotiated: {
        encryption_algorithm: negotiated,
        extensions: [],
      },
      serverDomainSigningSeed: this.cfg.serverDomainSigningSeed,
    });
    this.respCanonical = canonicalMarshal(resp);
    return this.respCanonical;
  }

  /**
   * Process the client's CONFIRM and produce signed ACCEPTED bytes
   * per §2.4 / §2.5. Throws {@link HandshakeServerRejectionError}
   * on confirmation-hash mismatch or identity-proof verdict
   * failure.
   */
  onConfirm(data: Uint8Array): Uint8Array {
    if (
      this.initCanonical === null ||
      this.respCanonical === null ||
      this.sessionKeys === null ||
      this.serverIdProof === null
    ) {
      throw new Error("handshake: onConfirm before onInit");
    }
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as Partial<ConfirmMessage> & {
      step?: string;
      type?: string;
    };
    if (m.type !== "SEMP_HANDSHAKE" || m.step !== "confirm") {
      throw new Error("handshake: confirm type/step mismatch");
    }
    const confirm = m as ConfirmMessage;
    const wantHash = confirmationHash(this.initCanonical, this.respCanonical);
    const gotHash = base64Decode(confirm.confirmation_hash);
    if (!constantTimeEqual(gotHash, wantHash)) {
      const rej = buildRejectedSigned(
        this.sessionId,
        "handshake_invalid",
        undefined,
        this.cfg.serverDomainSigningSeed,
      );
      throw new HandshakeServerRejectionError(
        "handshake_invalid",
        "confirmation hash mismatch",
        rej,
      );
    }

    if (this.cfg.verifyIdentityProof !== undefined) {
      const verdict = this.cfg.verifyIdentityProof({
        identityProofB64: confirm.identity_proof,
        sessionKeys: this.sessionKeys,
      });
      if (!verdict.ok) {
        const code = verdict.reasonCode ?? "auth_failed";
        const rej = buildRejectedSigned(
          this.sessionId,
          code,
          verdict.reason,
          this.cfg.serverDomainSigningSeed,
        );
        throw new HandshakeServerRejectionError(code, verdict.reason, rej);
      }
    }

    const ticket = this.cfg.resumptionTicket?.(this.sessionKeys);
    const accepted: AcceptedMessage = buildAccepted({
      sessionId: this.sessionId,
      sessionTTL: this.cfg.sessionTTL,
      permissions: [...this.cfg.permissions],
      serverDomainSigningSeed: this.cfg.serverDomainSigningSeed,
      ...(ticket !== undefined ? { resumptionTicket: ticket } : {}),
      ...(this.cfg.acceptedExtensions !== undefined
        ? { extensions: this.cfg.acceptedExtensions }
        : {}),
    });
    this.finalSession = {
      sessionId: this.sessionId,
      sessionTTL: this.cfg.sessionTTL,
      permissions: [...this.cfg.permissions],
      keys: this.sessionKeys,
      serverIdentityProofKeyId: this.serverIdProof.key_id,
      serverIdentityProofSignature: this.serverIdProof.signature,
      extensions: this.cfg.acceptedExtensions ?? {},
      ...(ticket !== undefined ? { resumptionTicket: ticket } : {}),
    };
    if (this.serverEphPriv !== null) {
      this.serverEphPriv.fill(0);
      this.serverEphPriv = null;
    }
    return canonicalMarshal(accepted);
  }

  /** Final session, populated by {@link onConfirm}. */
  session(): HandshakeServerSession {
    if (this.finalSession === null) {
      throw new Error(
        "handshake: server session not yet established (call onConfirm first)",
      );
    }
    return this.finalSession;
  }

  /** Wipe in-memory secret state. Idempotent. */
  erase(): void {
    if (this.serverEphPriv !== null) {
      this.serverEphPriv.fill(0);
      this.serverEphPriv = null;
    }
    this.sessionKeys = null;
  }
}

function pickSuite(
  offered: ReadonlyArray<string>,
  supported: ReadonlyArray<"x25519-chacha20-poly1305">,
): "x25519-chacha20-poly1305" | undefined {
  for (const s of supported) {
    if (offered.includes(s)) {
      return s;
    }
  }
  return undefined;
}

function buildRejectedSigned(
  sessionId: string,
  reasonCode: string,
  reason: string | undefined,
  serverDomainSigningSeed: Uint8Array,
): Uint8Array {
  const rej = buildRejected({
    sessionId,
    reasonCode,
    reason,
    serverDomainSigningSeed,
  });
  return canonicalMarshal(rej);
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

// Suppress IdentityProofVerdict unused warning by re-exporting it.
export type { IdentityProofVerdict };
