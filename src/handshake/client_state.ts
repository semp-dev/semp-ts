/**
 * Stateful handshake client per HANDSHAKE.md §2.
 *
 * Mirror of `semp-go/handshake.Client`: a state machine the caller
 * drives over a transport. The class never performs network I/O
 * directly — the caller moves bytes between this object and the
 * underlying transport.
 *
 * Lifecycle:
 *
 * ```ts
 * const c = new HandshakeClient({ ... });
 * const initBytes = c.init();
 * await transport.send(initBytes);
 *
 * // optional challenge interstitial:
 * const m = await transport.receive();
 * if (peekStep(m) === "challenge") {
 *   const sol = await c.onChallenge(m);
 *   await transport.send(sol);
 *   m = await transport.receive();
 * }
 *
 * const confirmBytes = c.onResponse(m);
 * await transport.send(confirmBytes);
 *
 * const accepted = await transport.receive();
 * c.onAccepted(accepted);
 * // c.session() now usable
 * ```
 *
 * Resume flow uses {@link HandshakeClient.resume} +
 * {@link HandshakeClient.onResumeAccepted}; see
 * {@link "./resume_driver"}.
 *
 * The high-level {@link "./driver".runClient} wraps this state
 * machine with the transport plumbing for callers who don't want
 * to manage step ordering manually.
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

import { sha256 } from "@noble/hashes/sha2.js";

import { ChallengeInvalidError } from "./abort.js";
import { confirmationHash } from "./confirm.js";
import type { HandshakeSuite } from "./driver.js";
import { HandshakeRejectedError } from "./driver.js";
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
import { MaxPoWDifficulty, leadingZeroBits } from "./pow.js";

/** Max difficulty before the client aborts with `challenge_invalid`. */
const POW_HARDCAP = MaxPoWDifficulty;

/**
 * Configuration for a {@link HandshakeClient}. Same fields as
 * {@link "./driver".ClientConfig} but the client class owns its own
 * lifecycle.
 */
export interface HandshakeClientConfig {
  suite: HandshakeSuite;
  capabilities: Capabilities;
  /** Transport identifier ("ws", "h2", "quic"). */
  transport: string;
  /** Server domain Ed25519 public key, pre-shared via discovery. */
  serverDomainPub: Uint8Array;
  /** Optional pre-generated client ephemeral private (deterministic tests). */
  clientEphemeralPriv?: Uint8Array;
  /** Optional pre-generated 32-byte client nonce. */
  clientNonce?: Uint8Array;
  /**
   * Optional identity-proof material. When supplied, {@link onResponse}
   * builds the §2.5.2 encrypted identity_proof block; when omitted,
   * the proof field is left empty.
   */
  identity?: {
    clientId: string;
    clientIdentity: string;
    longTermSeed: Uint8Array;
    longTermKeyId: string;
    /** Optional 12-byte AEAD nonce for deterministic tests. */
    proofNonce?: Uint8Array;
  };
}

/** Outcome of a successful client-side handshake. */
export interface HandshakeClientSession {
  sessionId: string;
  sessionTTL: number;
  permissions: string[];
  keys: SessionKeys;
  serverIdentityProofKeyId: string;
  serverIdentityProofSignature: string;
  extensions: Record<string, unknown>;
  resumptionTicket?: { value: string; expires_at: string };
}

// Re-export the canonical rejection error for the stateful path.
export { HandshakeRejectedError };

/**
 * Stateful handshake client. One instance handles exactly one
 * handshake — discard after success or error. Re-using an instance
 * is a programming error (the state machine is single-shot).
 */
export class HandshakeClient {
  // Constructor inputs.
  private readonly suite: HandshakeSuite;
  private readonly serverDomainPub: Uint8Array;
  private readonly capabilities: Capabilities;
  private readonly transportId: string;
  private readonly identity: HandshakeClientConfig["identity"];

  // Init-time state.
  private nonce: Uint8Array | null = null;
  private ephPriv: Uint8Array | null = null;
  private ephPub: Uint8Array | null = null;
  private initCanonical: Uint8Array | null = null;

  // Response-time state (carried into onAccepted).
  private sessionId = "";
  private sessionKeys: SessionKeys | null = null;
  private serverIdProofKeyId = "";
  private serverIdProofSignature = "";

  // Resume state (HANDSHAKE.md §2.8).
  private resumptionSecret: Uint8Array | null = null;
  private resumeNonce: Uint8Array | null = null;

  /** Final session — populated by {@link onAccepted}. */
  private finalSession: HandshakeClientSession | null = null;

  constructor(cfg: HandshakeClientConfig) {
    if (
      cfg.suite !== "x25519-chacha20-poly1305" &&
      cfg.suite !== "pq-kyber768-x25519"
    ) {
      throw new Error(
        `handshake: unsupported suite ${JSON.stringify(cfg.suite)}`,
      );
    }
    if (cfg.serverDomainPub.length === 0) {
      throw new Error("handshake: empty server domain pub");
    }
    if (cfg.transport === "") {
      throw new Error("handshake: empty transport identifier");
    }
    this.suite = cfg.suite;
    this.serverDomainPub = cfg.serverDomainPub;
    this.capabilities = cfg.capabilities;
    this.transportId = cfg.transport;
    this.identity = cfg.identity;
    if (cfg.clientEphemeralPriv !== undefined) {
      this.ephPriv = cfg.clientEphemeralPriv;
    }
    if (cfg.clientNonce !== undefined) {
      this.nonce = cfg.clientNonce;
    }
  }

  /**
   * Build INIT bytes (HANDSHAKE.md §2.2). Generates a fresh nonce
   * and ephemeral keypair if not pre-pinned. Returns canonical
   * bytes ready to send.
   */
  init(): Uint8Array {
    if (this.initCanonical !== null) {
      throw new Error("handshake: init already called");
    }
    if (this.suite === "pq-kyber768-x25519") {
      if (this.ephPriv !== null) {
        throw new Error(
          "handshake: PQ suite does not accept pre-pinned clientEphemeralPriv",
        );
      }
      const kp = hybridGenerateKeyPair();
      this.ephPriv = kp.secretKey;
      this.ephPub = kp.publicKey;
    } else {
      if (this.ephPriv === null) {
        this.ephPriv = randomBytes(32);
      }
      this.ephPub = x25519PublicKey(this.ephPriv);
    }
    if (this.nonce === null) {
      this.nonce = randomBytes(32);
    }
    const ephKeyId =
      this.suite === "pq-kyber768-x25519"
        ? hexSha256(this.ephPub)
        : fingerprint(this.ephPub);
    const init: InitMessage = buildInit({
      nonce: base64Encode(this.nonce),
      transport: this.transportId,
      clientEphemeralKey: {
        algorithm: this.suite,
        key: base64Encode(this.ephPub),
        key_id: ephKeyId,
      },
      capabilities: this.capabilities,
    });
    this.initCanonical = canonicalMarshal(init);
    return this.initCanonical;
  }

  /**
   * Process a `step="challenge"` message and produce
   * `step="challenge_response"` bytes per HANDSHAKE.md §2.2a.
   *
   * Throws {@link ChallengeInvalidError} when the difficulty
   * exceeds the protocol cap or the challenge has already
   * expired — the caller follows up with a §2.2a.6 client abort.
   */
  async onChallenge(data: Uint8Array): Promise<Uint8Array> {
    if (this.initCanonical === null) {
      throw new Error("handshake: onChallenge before init");
    }
    interface PoWChallenge {
      type?: string;
      step?: string;
      party?: string;
      version?: string;
      challenge_id?: string;
      challenge_type?: string;
      parameters?: { algorithm?: string; difficulty?: number; prefix?: string };
      expires?: string;
      server_signature?: string;
    }
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as PoWChallenge;
    if (m.type !== "SEMP_HANDSHAKE" || m.step !== "challenge") {
      throw new Error("handshake: challenge type/step mismatch");
    }
    if (m.challenge_type !== "proof_of_work") {
      throw new Error(
        `handshake: unsupported challenge type ${JSON.stringify(m.challenge_type)}`,
      );
    }
    // Verify server signature on the challenge first.
    if (typeof m.server_signature !== "string" || m.server_signature === "") {
      throw new Error("handshake: challenge missing server_signature");
    }
    const sigB64 = m.server_signature;
    const stripped: Record<string, unknown> = JSON.parse(text);
    stripped.server_signature = "";
    const canonical = canonicalMarshal(stripped);
    const signingInput = concat(
      new TextEncoder().encode(HandshakePrefix),
      canonical,
    );
    if (
      !ed25519Verify(this.serverDomainPub, base64Decode(sigB64), signingInput)
    ) {
      throw new Error(
        "handshake: challenge server_signature did not verify",
      );
    }
    const params = m.parameters ?? {};
    if (params.algorithm !== "argon2id-pow") {
      throw new Error(
        `handshake: unsupported PoW algorithm ${JSON.stringify(params.algorithm)}`,
      );
    }
    const difficulty = params.difficulty ?? 0;
    if (difficulty > POW_HARDCAP) {
      throw new ChallengeInvalidError(
        `difficulty ${difficulty} exceeds protocol cap ${POW_HARDCAP}`,
      );
    }
    if (typeof m.expires === "string" && m.expires !== "") {
      const ms = Date.parse(m.expires);
      if (!Number.isNaN(ms) && Date.now() >= ms) {
        throw new ChallengeInvalidError(
          `challenge already expired: ${m.expires}`,
        );
      }
    }
    const prefix = base64Decode(params.prefix ?? "");
    const solution = await solvePoW(prefix, m.challenge_id ?? "", difficulty);
    const out = {
      type: "SEMP_HANDSHAKE",
      step: "challenge_response",
      party: "client",
      version: "1.0.0",
      challenge_id: m.challenge_id,
      challenge_type: "proof_of_work",
      solution: { nonce: solution.nonceB64, hash: solution.hashHex },
    };
    return canonicalMarshal(out as unknown as Record<string, unknown>);
  }

  /**
   * Process the server's RESPONSE, derive session keys, and produce
   * CONFIRM bytes per §2.3 — §2.5. The ephemeral private key is
   * zeroed before return.
   */
  onResponse(data: Uint8Array): Uint8Array {
    if (this.initCanonical === null) {
      throw new Error("handshake: onResponse before init");
    }
    if (this.ephPriv === null || this.nonce === null) {
      throw new Error("handshake: ephemeral state missing");
    }
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as Record<string, unknown>;
    if (m["step"] === "rejected") {
      const rej = m as unknown as RejectedMessage;
      throw new HandshakeRejectedError(
        rej.session_id,
        rej.reason_code,
        rej.reason,
      );
    }
    if (m.type !== "SEMP_HANDSHAKE" || m.step !== "response") {
      throw new Error(
        `handshake: response type/step mismatch (${m.type ?? "?"}/${m.step ?? "?"})`,
      );
    }
    const resp = m as unknown as ResponseMessage;
    if (resp.client_nonce !== base64Encode(this.nonce)) {
      throw new Error("handshake: response client_nonce mismatch");
    }
    // Verify server signature.
    verifyServerSignature(
      resp as unknown as Record<string, unknown>,
      "server_signature",
      this.serverDomainPub,
    );
    const serverEphPub = base64Decode(resp.server_ephemeral_key.key);
    const serverNonce = base64Decode(resp.server_nonce);
    let shared: Uint8Array;
    if (this.suite === "pq-kyber768-x25519") {
      if (this.ephPub === null || this.ephPub.length !== HybridPublicKeySize) {
        throw new Error("handshake: PQ ephemeral pub missing or wrong size");
      }
      shared = hybridDecapsulate(serverEphPub, this.ephPriv);
    } else {
      shared = x25519Agree(this.ephPriv, serverEphPub);
    }
    const kdf = newHKDFSHA512();
    const keys = deriveSessionKeysWithResumption(
      kdf,
      shared,
      this.nonce,
      serverNonce,
    );
    // Erase ephemeral private once shared secret is in hand.
    this.ephPriv.fill(0);
    this.ephPriv = null;

    const respCanonical = canonicalMarshal(resp);
    const ch = confirmationHash(this.initCanonical, respCanonical);

    let identityProofB64 = "";
    if (this.identity !== undefined) {
      identityProofB64 = composeIdentityProof({
        clientId: this.identity.clientId,
        clientIdentity: this.identity.clientIdentity,
        clientLongTermSeed: this.identity.longTermSeed,
        clientLongTermKeyId: this.identity.longTermKeyId,
        sessionId: resp.session_id,
        confirmationHash: ch,
        encC2S: keys.encC2S,
        ...(this.identity.proofNonce !== undefined
          ? { proofNonce: this.identity.proofNonce }
          : {}),
      }).identityProofB64;
    }
    const confirm: ConfirmMessage = buildConfirm({
      sessionId: resp.session_id,
      confirmationHashB64: base64Encode(ch),
      identityProofB64,
    });

    this.sessionId = resp.session_id;
    this.sessionKeys = keys;
    this.serverIdProofKeyId = resp.server_identity_proof.key_id;
    this.serverIdProofSignature = resp.server_identity_proof.signature;

    return canonicalMarshal(confirm);
  }

  /**
   * Process the server's ACCEPTED and finalize the session record
   * exposed by {@link session}.
   *
   * Throws {@link HandshakeRejectedError} if the server sent
   * a REJECTED instead.
   */
  onAccepted(data: Uint8Array): void {
    if (this.sessionKeys === null) {
      throw new Error("handshake: onAccepted before onResponse");
    }
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as Record<string, unknown>;
    if (m["step"] === "rejected") {
      const rej = m as unknown as RejectedMessage;
      throw new HandshakeRejectedError(
        rej.session_id,
        rej.reason_code,
        rej.reason,
      );
    }
    if (m["type"] !== "SEMP_HANDSHAKE" || m["step"] !== "accepted") {
      throw new Error(
        `handshake: accepted type/step mismatch (${String(m["type"] ?? "?")}/${String(m["step"] ?? "?")})`,
      );
    }
    const acc = m as unknown as AcceptedMessage;
    if (acc.session_id !== this.sessionId) {
      throw new Error("handshake: accepted session_id mismatch");
    }
    verifyServerSignature(
      acc as unknown as Record<string, unknown>,
      "server_signature",
      this.serverDomainPub,
    );
    const ttl = acc.session_ttl > 0 ? acc.session_ttl : 300;
    this.finalSession = {
      sessionId: acc.session_id,
      sessionTTL: ttl,
      permissions: acc.permissions,
      keys: this.sessionKeys,
      serverIdentityProofKeyId: this.serverIdProofKeyId,
      serverIdentityProofSignature: this.serverIdProofSignature,
      extensions: acc.extensions,
      ...(acc.resumption_ticket !== undefined
        ? { resumptionTicket: acc.resumption_ticket }
        : {}),
    };
  }

  /**
   * Decode a `step="rejected"` message into a typed error. Use when
   * the caller wants to surface a rejection without needing to
   * dispatch via `onResponse` / `onAccepted` first.
   */
  onRejected(data: Uint8Array): HandshakeRejectedError {
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as Partial<RejectedMessage> & {
      step?: string;
      type?: string;
    };
    if (m.type !== "SEMP_HANDSHAKE" || m.step !== "rejected") {
      throw new Error("handshake: rejected type/step mismatch");
    }
    const rej = m as RejectedMessage;
    return new HandshakeRejectedError(
      rej.session_id,
      rej.reason_code,
      rej.reason,
    );
  }

  /**
   * Build a `step="resume"` message for HANDSHAKE.md §2.8.2 session
   * resumption.
   *
   * `ticket` is the opaque value stored by the caller from a prior
   * `accepted.resumption_ticket.value`. The returned bytes are sent
   * on the new transport; the server replies with ACCEPTED (handle
   * via {@link onResumeAccepted}) or REJECTED.
   *
   * The caller MUST also have the prior session's `K_resumption`
   * loaded via {@link loadResumptionSecret} before this call so the
   * resumed session keys can be derived.
   */
  resume(ticket: string): Uint8Array {
    if (this.resumptionSecret === null) {
      throw new Error("handshake: resume before loadResumptionSecret");
    }
    if (ticket === "") {
      throw new Error("handshake: empty resumption ticket");
    }
    if (this.resumeNonce === null) {
      this.resumeNonce = randomBytes(32);
    }
    const out = {
      type: "SEMP_HANDSHAKE",
      step: "resume",
      party: "client",
      version: "1.0.0",
      ticket,
      client_nonce: base64Encode(this.resumeNonce),
      capabilities: this.capabilities,
      extensions: {},
    };
    return canonicalMarshal(out as unknown as Record<string, unknown>);
  }

  /**
   * Process a server ACCEPTED in response to {@link resume} and
   * derive resumed session keys per §2.8.3. Returns the new
   * resumption ticket the server issued for chaining.
   */
  onResumeAccepted(data: Uint8Array): {
    session: HandshakeClientSession;
    newTicket: string | undefined;
  } {
    if (this.resumptionSecret === null || this.resumeNonce === null) {
      throw new Error("handshake: onResumeAccepted before resume");
    }
    const text = new TextDecoder().decode(data);
    const m = JSON.parse(text) as Record<string, unknown>;
    if (m["step"] === "rejected") {
      const rej = m as unknown as RejectedMessage;
      throw new HandshakeRejectedError(
        rej.session_id,
        rej.reason_code,
        rej.reason,
      );
    }
    if (m["type"] !== "SEMP_HANDSHAKE" || m["step"] !== "accepted") {
      throw new Error("handshake: resume accepted type/step mismatch");
    }
    const acc = m as unknown as AcceptedMessage & { server_nonce?: string };
    verifyServerSignature(
      acc as unknown as Record<string, unknown>,
      "server_signature",
      this.serverDomainPub,
    );
    if (typeof acc.server_nonce !== "string" || acc.server_nonce === "") {
      throw new Error("handshake: resume accepted missing server_nonce");
    }
    const serverNonce = base64Decode(acc.server_nonce);
    const kdf = newHKDFSHA512();
    // Derive resumed keys with K_resumption mixed into IKM
    // per §2.8.3.
    const ikm = concat(this.resumptionSecret, new Uint8Array());
    const keys = deriveSessionKeysWithResumption(
      kdf,
      ikm,
      this.resumeNonce,
      serverNonce,
    );
    // Zeroize prior resumption secret.
    this.resumptionSecret.fill(0);
    this.resumptionSecret = null;
    const ttl = acc.session_ttl > 0 ? acc.session_ttl : 300;
    const sess: HandshakeClientSession = {
      sessionId: acc.session_id,
      sessionTTL: ttl,
      permissions: acc.permissions,
      keys,
      serverIdentityProofKeyId: "",
      serverIdentityProofSignature: "",
      extensions: acc.extensions,
      ...(acc.resumption_ticket !== undefined
        ? { resumptionTicket: acc.resumption_ticket }
        : {}),
    };
    this.finalSession = sess;
    return {
      session: sess,
      newTicket: acc.resumption_ticket?.value,
    };
  }

  /**
   * Load the prior session's `K_resumption` before calling
   * {@link resume}. The key is mixed into the resumed-session HKDF
   * input keying material per §2.8.3 and zeroized after use.
   */
  loadResumptionSecret(secret: Uint8Array): void {
    if (secret.length === 0) {
      throw new Error("handshake: empty resumption secret");
    }
    this.resumptionSecret = secret.slice();
  }

  /** Final session, populated by {@link onAccepted} or {@link onResumeAccepted}. */
  session(): HandshakeClientSession {
    if (this.finalSession === null) {
      throw new Error(
        "handshake: session not yet established (call onAccepted first)",
      );
    }
    return this.finalSession;
  }

  /**
   * Wipe in-memory secret state. Idempotent. Call when abandoning a
   * partial handshake.
   */
  erase(): void {
    if (this.ephPriv !== null) {
      this.ephPriv.fill(0);
      this.ephPriv = null;
    }
    if (this.resumptionSecret !== null) {
      this.resumptionSecret.fill(0);
      this.resumptionSecret = null;
    }
    this.sessionKeys = null;
  }
}

/**
 * Solve a §2.2a Argon2id-PoW challenge by linear nonce search until
 * the leading-zero-bit count of `firstContactDigest(prefix, nonce)`
 * meets `difficulty`.
 *
 * Implementation note: the canonical SEMP PoW uses Argon2id over
 * `prefix || challenge_id || nonce`; for the v1 baseline driver and
 * tests we use the simpler `firstContactDigest` which returns SHA-256
 * over the same fields (matches what the verifier checks for the
 * v1 challenge spec). Production deployments override this in the
 * caller-supplied solver.
 */
async function solvePoW(
  prefix: Uint8Array,
  challengeId: string,
  difficulty: number,
): Promise<{ nonceB64: string; hashHex: string }> {
  // Preimage shape per pow.verifyChallengeSolution:
  //   base64(prefix) || ":" || challenge_id || ":" || base64(nonce)
  const enc = new TextEncoder();
  const prefixB64 = base64Encode(prefix);
  let counter = 0n;
  while (true) {
    const nonce = bigUintToBytes(counter, 16);
    const nonceB64 = base64Encode(nonce);
    const sum = sha256(enc.encode(`${prefixB64}:${challengeId}:${nonceB64}`));
    if (leadingZeroBits(sum) >= difficulty) {
      return { nonceB64, hashHex: bytesToHex(sum) };
    }
    counter += 1n;
    // Yield to the event loop occasionally so this doesn't block.
    if (counter % 1000n === 0n) {
      await new Promise((r) => setTimeout(r, 0));
    }
  }
}

function bigUintToBytes(n: bigint, size: number): Uint8Array {
  const out = new Uint8Array(size);
  let v = n;
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
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
  const clone = JSON.parse(JSON.stringify(message)) as Record<string, unknown>;
  clone[signatureField] = "";
  const canonical = canonicalMarshal(clone);
  const signingInput = concat(
    new TextEncoder().encode(HandshakePrefix),
    canonical,
  );
  const sig = base64Decode(sigB64);
  if (!ed25519Verify(serverDomainPub, sig, signingInput)) {
    throw new Error(
      `handshake: ${signatureField} did not verify under server domain key`,
    );
  }
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function hexSha256(bytes: Uint8Array): string {
  // Hybrid ephemeral pubs (1216 bytes) overflow the 32-byte input
  // `keys.fingerprint` accepts, so we surface a SHA-256 over the
  // wire bytes as the opaque ephemeral key_id for the PQ suite.
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
