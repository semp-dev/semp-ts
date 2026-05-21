/**
 * Federation handshake (server ↔ server) per HANDSHAKE.md §5.
 *
 * Two servers establish a federation session by exchanging four
 * messages - symmetric in shape to the client handshake but with
 * domain identity in plaintext on both sides plus a domain-proof
 * verification step:
 *
 *   1. ServerInit (initiator -> responder) carrying the initiator's
 *      domain, ephemeral key, identity proof, and a {@link DomainProof}
 *      that the responder verifies via DNS / certificate / well-known.
 *   2. FederationResponse (responder -> initiator) carrying the
 *      responder's identity material, the {@link DomainVerificationResult},
 *      negotiated capabilities, and the responder's
 *      {@link FederationPolicy}.
 *   3. FederationConfirm (initiator -> responder) with the
 *      confirmation hash and a {@link FederationAcceptance} block
 *      stating whether the initiator accepts the policy.
 *   4. FederationAccepted (responder -> initiator) finalizing the
 *      session and (optionally) issuing a resumption ticket.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  type SessionKeys,
  HybridPublicKeySize,
  deriveSessionKeysWithResumption,
  hybridDecapsulate,
  hybridEncapsulate,
  hybridGenerateKeyPair,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import {
  fingerprint,
  publicKeyFromSeed,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "../keys/index.js";

import { confirmationHash } from "./confirm.js";
import { HandshakeRejectedError } from "./driver.js";
import { IdentityPrefix } from "./identity.js";
import {
  type Capabilities,
  type Negotiated,
  type ResumptionTicket,
  HandshakePrefix,
  HandshakeVersion,
} from "./messages.js";

/**
 * Algorithm suites the federation handshake supports. Mirrors the
 * client handshake's {@link "./driver".HandshakeSuite}.
 */
export type FederationSuite =
  | "x25519-chacha20-poly1305"
  | "pq-kyber768-x25519";

/** Wire-level discriminators (shared with the client handshake). */
export const FederationMessageType = "SEMP_HANDSHAKE";

/**
 * Federation domain-proof verification methods per HANDSHAKE.md
 * §5.3.
 */
export type DomainProofMethod =
  | "dns-txt"
  | "certificate"
  | "well-known"
  /** Test fixture; production deployments MUST NOT accept this method. */
  | "test-trust";

/** Domain ownership proof per §5.3. */
export interface DomainProof {
  method: DomainProofMethod;
  /** Verification payload, format determined by `method`. */
  data: string;
}

/** Result of a {@link DomainVerifier} check per §5.4. */
export interface DomainVerificationResult {
  /** `"verified"` on success; `"rejected"` or `"unverified"` otherwise. */
  status: "verified" | "rejected" | "unverified";
  /** Echoes the verification method that was attempted. */
  method: DomainProofMethod;
  /** Optional human-readable detail; operator-facing. */
  detail?: string;
}

/** Operator-defined federation policy per §5.4. */
export interface FederationPolicy {
  /** Duration string (e.g. `"7d"`, `"30d"`, `"0"`). */
  message_retention: string;
  /** `"allowed"` or `"denied"`. */
  user_discovery: "allowed" | "denied";
  /** Whether the responder forwards envelopes on behalf of third parties. */
  relay_allowed: boolean;
}

/**
 * Initiator's acceptance of the responder's policy per §5.5. When
 * `accepted === false`, a `reason` is REQUIRED and the responder
 * MUST treat the handshake as rejected.
 */
export interface FederationAcceptance {
  accepted: boolean;
  policy_acknowledged: boolean;
  reason?: string;
}

/**
 * Abbreviated identity proof used inside federation init / response
 * messages. The signature is over the canonical bytes:
 *
 *   - init:     `eph_pub || nonce_bytes`
 *   - response: `eph_pub || responder_nonce || initiator_nonce`
 *
 * with the `SEMP-IDENTITY:` domain-separation prefix. Binds the
 * long-term domain key to the ephemeral key without depending on
 * the surrounding message envelope.
 */
export interface FederationProof {
  key_id: string;
  /** Base64 Ed25519 signature. */
  signature: string;
}

/** Reusable ephemeral-key block. */
export interface FederationEphemeralKey {
  algorithm: string;
  /** Base64. */
  key: string;
  key_id: string;
}

/** Server-init message per §5.2. */
export interface ServerInit {
  type: typeof FederationMessageType;
  step: "init";
  party: "server";
  version: string;
  /** Base64 32-byte initiator nonce. */
  nonce: string;
  server_id: string;
  server_domain: string;
  server_ephemeral_key: FederationEphemeralKey;
  server_identity_proof: FederationProof;
  domain_proof: DomainProof;
  capabilities: Capabilities;
  /** Base64 outer Ed25519 signature. */
  server_signature: string;
  extensions: Record<string, unknown>;
}

/** Responder's response per §5.4. */
export interface FederationResponse {
  type: typeof FederationMessageType;
  step: "response";
  party: "server";
  version: string;
  session_id: string;
  /** Echo of the initiator's nonce. */
  client_nonce: string;
  /** Base64 32-byte responder nonce. */
  server_nonce: string;
  server_id: string;
  server_domain: string;
  server_ephemeral_key: FederationEphemeralKey;
  server_identity_proof: FederationProof;
  domain_verification_result: DomainVerificationResult;
  negotiated: Negotiated;
  federation_policy: FederationPolicy;
  /** Base64 outer Ed25519 signature. */
  server_signature: string;
  extensions: Record<string, unknown>;
}

/** Initiator's confirm per §5.5. */
export interface FederationConfirm {
  type: typeof FederationMessageType;
  step: "confirm";
  party: "server";
  version: string;
  session_id: string;
  /** Base64 SHA-256(canonical(init) || canonical(response)). */
  confirmation_hash: string;
  federation_acceptance: FederationAcceptance;
  /** Base64 outer Ed25519 signature. */
  server_signature: string;
  extensions: Record<string, unknown>;
}

/** Responder's accepted per §5.6 / §2.8.7. */
export interface FederationAccepted {
  type: typeof FederationMessageType;
  step: "accepted";
  party: "server";
  version: string;
  session_id: string;
  status: "accepted";
  session_ttl: number;
  /** Resumption-only fields, present when responding to FederationResume. */
  server_nonce?: string;
  server_ephemeral_key?: FederationEphemeralKey;
  resumption_ticket?: ResumptionTicket;
  /** Base64 outer Ed25519 signature. */
  server_signature: string;
  extensions: Record<string, unknown>;
}

/** Initiator-side resume per §2.8.7. */
export interface FederationResume {
  type: typeof FederationMessageType;
  step: "resume";
  party: "server";
  version: string;
  /** Base64 32-byte initiator nonce. */
  nonce: string;
  server_id: string;
  server_domain: string;
  /** Initiator's discovery cache revision; 0 omits. */
  peer_configuration_revision?: number;
  /** Base64 opaque ticket bytes from the prior FederationAccepted. */
  resumption_ticket: string;
  client_ephemeral_key: FederationEphemeralKey;
  transport: string;
  extensions: Record<string, unknown>;
}

/**
 * Domain-ownership verifier invoked by the responder during the
 * handshake. `verify` resolves on success; rejects (or throws) on
 * failure - the rejection reason is surfaced in
 * {@link DomainVerificationResult.detail}.
 */
export interface DomainVerifier {
  verify(
    domain: string,
    proof: DomainProof,
    initiatorNonce: string,
  ): Promise<void>;
}

/**
 * Permissive verifier that accepts every proof. Tests / single-
 * process deployments only - production MUST NOT use it.
 */
export class TrustingDomainVerifier implements DomainVerifier {
  async verify(): Promise<void> {
    return;
  }
}

/**
 * Decide which of two simultaneously-initiated federation handshakes
 * proceeds per SESSION.md §2.5.2. Both peers agree on the winner
 * without external coordination - lexicographic compare provides
 * exactly this property.
 *
 * Returns the winning `session_id` (the one that proceeds).
 */
export function resolveCollision(idA: string, idB: string): string {
  return idA > idB ? idA : idB;
}

/** Hook deciding whether to accept a {@link FederationPolicy}. */
export type PolicyAcceptor = (policy: FederationPolicy) => string | null;

/** Default acceptor that accepts every policy (tests). */
export const acceptAllPolicies: PolicyAcceptor = () => null;

// =============================================================================
// Initiator
// =============================================================================

/** Configuration for {@link FederationInitiator}. */
export interface FederationInitiatorConfig {
  /**
   * Algorithm suite. Either `"x25519-chacha20-poly1305"` (baseline)
   * or `"pq-kyber768-x25519"` (hybrid post-quantum); the latter
   * generates a 1216-byte hybrid ephemeral pub and decapsulates the
   * responder's 1120-byte hybrid KEM ciphertext per ENVELOPE.md
   * §4.4.1. The negotiated suite recorded on the wire is taken from
   * this field; for multi-suite operators, run multiple initiators.
   */
  suite: FederationSuite;
  /** Capability set to advertise. */
  capabilities: Capabilities;
  /** Initiator's own domain. */
  localDomain: string;
  /**
   * Stable id of the initiator server instance within `localDomain`.
   * If empty, callers MUST set one before calling {@link init}.
   */
  localServerID: string;
  /** 32-byte Ed25519 secret seed for the initiator's domain key. */
  localDomainSeed: Uint8Array;
  /** Lookup hook returning the responder's published domain pub. */
  peerDomainPubLookup: (domain: string) => Uint8Array;
  /** Responder's domain (the one the initiator wants to federate with). */
  peerDomain: string;
  /** {@link DomainProof} the initiator presents. */
  domainProof: DomainProof;
  /** Defaults to {@link acceptAllPolicies}. */
  policyAcceptor?: PolicyAcceptor;
  /** Optional pre-pinned ephemeral private (deterministic tests). */
  initiatorEphemeralPriv?: Uint8Array;
  /** Optional pre-pinned 32-byte initiator nonce. */
  initiatorNonce?: Uint8Array;
}

/** Outcome of a successful federation handshake (initiator side). */
export interface FederationInitiatorSession {
  sessionId: string;
  sessionTTL: number;
  keys: SessionKeys;
  peerDomain: string;
  resumptionTicket?: ResumptionTicket;
  extensions: Record<string, unknown>;
}

/**
 * Stateful federation initiator. Mirror of `semp-go/handshake.Initiator`.
 * Single-shot - discard after success or error.
 */
export class FederationInitiator {
  private readonly cfg: FederationInitiatorConfig;
  private readonly localDomainPub: Uint8Array;
  private readonly localDomainKeyId: string;

  private nonce: Uint8Array | null = null;
  private ephPriv: Uint8Array | null = null;
  private ephPub: Uint8Array | null = null;
  private initCanonical: Uint8Array | null = null;
  private respCanonical: Uint8Array | null = null;
  private sessionId = "";
  private sessionKeys: SessionKeys | null = null;
  private finalSession: FederationInitiatorSession | null = null;
  private resumptionSecret: Uint8Array | null = null;
  private resumeNonce: Uint8Array | null = null;

  constructor(cfg: FederationInitiatorConfig) {
    if (
      cfg.suite !== "x25519-chacha20-poly1305" &&
      cfg.suite !== "pq-kyber768-x25519"
    ) {
      throw new Error(
        `handshake: federation initiator unknown suite ${JSON.stringify(cfg.suite)}`,
      );
    }
    if (cfg.localDomain === "") {
      throw new Error("handshake: federation initiator empty localDomain");
    }
    if (cfg.localServerID === "") {
      throw new Error("handshake: federation initiator empty localServerID");
    }
    if (cfg.localDomainSeed.length === 0) {
      throw new Error("handshake: federation initiator empty localDomainSeed");
    }
    if (cfg.peerDomain === "") {
      throw new Error("handshake: federation initiator empty peerDomain");
    }
    this.cfg = cfg;
    this.localDomainPub = publicKeyFromSeed(cfg.localDomainSeed);
    this.localDomainKeyId = fingerprint(this.localDomainPub);
    if (cfg.initiatorEphemeralPriv !== undefined) {
      this.ephPriv = cfg.initiatorEphemeralPriv;
    }
    if (cfg.initiatorNonce !== undefined) {
      this.nonce = cfg.initiatorNonce;
    }
  }

  /** Build ServerInit bytes (message 1). */
  init(): Uint8Array {
    if (this.initCanonical !== null) {
      throw new Error("handshake: federation initiator init already called");
    }
    // Suite branch: baseline generates a 32-byte X25519 ephemeral
    // pub; PQ generates a 1216-byte hybrid (kyberPub || x25519Pub)
    // ephemeral pub. The responder branches symmetrically: baseline
    // ECDH against the responder's X25519 eph pub, PQ hybrid
    // decapsulate against the responder's KEM ciphertext.
    const isPQ = this.cfg.suite === "pq-kyber768-x25519";
    if (isPQ) {
      if (this.cfg.initiatorEphemeralPriv !== undefined) {
        throw new Error(
          "handshake: federation initiator PQ ephemeral pinning not supported",
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
    const ephKeyId = fingerprint(this.ephPub);
    // Inner identity proof: sig over eph_pub || nonce with SEMP-IDENTITY: prefix.
    const innerInput = concat(
      new TextEncoder().encode(IdentityPrefix),
      concat(this.ephPub, this.nonce),
    );
    const innerSig = ed25519Sign(this.cfg.localDomainSeed, innerInput);

    const msg: ServerInit = {
      type: FederationMessageType,
      step: "init",
      party: "server",
      version: HandshakeVersion,
      nonce: base64Encode(this.nonce),
      server_id: this.cfg.localServerID,
      server_domain: this.cfg.localDomain,
      server_ephemeral_key: {
        algorithm: this.cfg.suite,
        key: base64Encode(this.ephPub),
        key_id: ephKeyId,
      },
      server_identity_proof: {
        key_id: this.localDomainKeyId,
        signature: base64Encode(innerSig),
      },
      domain_proof: this.cfg.domainProof,
      capabilities: this.cfg.capabilities,
      server_signature: "",
      extensions: {},
    };
    msg.server_signature = signServerMessage(msg, this.cfg.localDomainSeed);
    this.initCanonical = canonicalMarshal(
      msg as unknown as Record<string, unknown>,
    );
    return this.initCanonical;
  }

  /** Process FederationResponse (message 2) and produce FederationConfirm bytes. */
  onResponse(data: Uint8Array): Uint8Array {
    if (this.initCanonical === null) {
      throw new Error("handshake: onResponse before init");
    }
    if (this.ephPriv === null || this.nonce === null) {
      throw new Error("handshake: federation initiator state missing");
    }
    const m = JSON.parse(new TextDecoder().decode(data)) as Record<
      string,
      unknown
    >;
    if (m["step"] === "rejected") {
      const rej = m as unknown as {
        session_id: string;
        reason_code: string;
        reason?: string;
      };
      throw new HandshakeRejectedError(
        rej.session_id,
        rej.reason_code,
        rej.reason,
      );
    }
    if (
      m["type"] !== FederationMessageType ||
      m["step"] !== "response" ||
      m["party"] !== "server"
    ) {
      throw new Error(
        `handshake: federation response type/step/party mismatch`,
      );
    }
    const resp = m as unknown as FederationResponse;
    if (resp.server_domain !== this.cfg.peerDomain) {
      throw new Error(
        `handshake: response server_domain ${JSON.stringify(resp.server_domain)} != configured peer ${JSON.stringify(this.cfg.peerDomain)}`,
      );
    }
    if (resp.client_nonce !== base64Encode(this.nonce)) {
      throw new Error("handshake: federation response client_nonce mismatch");
    }
    if (resp.domain_verification_result.status !== "verified") {
      throw new Error(
        `handshake: peer rejected our domain proof: ${resp.domain_verification_result.detail ?? ""}`,
      );
    }

    const peerDomainPub = this.cfg.peerDomainPubLookup(resp.server_domain);
    if (
      !verifyServerMessage(
        resp as unknown as Record<string, unknown>,
        resp.server_signature,
        peerDomainPub,
      )
    ) {
      throw new Error(
        "handshake: federation response server_signature did not verify",
      );
    }

    // Inner identity proof check.
    const serverEphPub = base64Decode(resp.server_ephemeral_key.key);
    const serverNonce = base64Decode(resp.server_nonce);
    const innerInput = concat(
      new TextEncoder().encode(IdentityPrefix),
      concat(concat(serverEphPub, serverNonce), this.nonce),
    );
    const innerSig = base64Decode(resp.server_identity_proof.signature);
    if (!ed25519Verify(peerDomainPub, innerSig, innerInput)) {
      throw new Error(
        "handshake: peer inner identity_signature did not verify",
      );
    }

    // Suite branch: for baseline serverEphPub is a 32-byte X25519
    // pub and we run ECDH; for PQ it's a 1120-byte hybrid KEM
    // ciphertext (kyberCt || responderX25519Pub) and we hybrid-
    // decapsulate against the local hybrid ephemeral private key.
    const isPQ = this.cfg.suite === "pq-kyber768-x25519";
    let shared: Uint8Array;
    if (isPQ) {
      if (this.ephPub === null || this.ephPub.length !== HybridPublicKeySize) {
        throw new Error(
          `handshake: federation PQ ephemeral pub size mismatch (have ${this.ephPub?.length ?? 0}, want ${HybridPublicKeySize})`,
        );
      }
      shared = hybridDecapsulate(serverEphPub, this.ephPriv);
    } else {
      shared = x25519Agree(this.ephPriv, serverEphPub);
    }
    const kdf = newHKDFSHA512();
    this.sessionKeys = deriveSessionKeysWithResumption(
      kdf,
      shared,
      this.nonce,
      serverNonce,
    );
    // Erase ephemeral private once shared secret is in hand.
    this.ephPriv.fill(0);
    this.ephPriv = null;

    this.respCanonical = canonicalMarshal(
      resp as unknown as Record<string, unknown>,
    );
    const ch = confirmationHash(this.initCanonical, this.respCanonical);

    const acceptor = this.cfg.policyAcceptor ?? acceptAllPolicies;
    const reason = acceptor(resp.federation_policy);
    const acceptance: FederationAcceptance =
      reason === null
        ? { accepted: true, policy_acknowledged: true }
        : { accepted: false, policy_acknowledged: false, reason };

    const confirm: FederationConfirm = {
      type: FederationMessageType,
      step: "confirm",
      party: "server",
      version: HandshakeVersion,
      session_id: resp.session_id,
      confirmation_hash: base64Encode(ch),
      federation_acceptance: acceptance,
      server_signature: "",
      extensions: {},
    };
    confirm.server_signature = signServerMessage(
      confirm,
      this.cfg.localDomainSeed,
    );
    this.sessionId = resp.session_id;
    return canonicalMarshal(confirm as unknown as Record<string, unknown>);
  }

  /** Process FederationAccepted (message 4) and finalize the session. */
  onAccepted(data: Uint8Array): void {
    if (this.sessionKeys === null) {
      throw new Error("handshake: onAccepted before onResponse");
    }
    const m = JSON.parse(new TextDecoder().decode(data)) as Record<
      string,
      unknown
    >;
    if (m["step"] === "rejected") {
      const rej = m as unknown as {
        session_id: string;
        reason_code: string;
        reason?: string;
      };
      throw new HandshakeRejectedError(
        rej.session_id,
        rej.reason_code,
        rej.reason,
      );
    }
    if (
      m["type"] !== FederationMessageType ||
      m["step"] !== "accepted" ||
      m["party"] !== "server"
    ) {
      throw new Error("handshake: federation accepted type/step/party mismatch");
    }
    const acc = m as unknown as FederationAccepted;
    if (acc.session_id !== this.sessionId) {
      throw new Error("handshake: federation accepted session_id mismatch");
    }
    const peerDomainPub = this.cfg.peerDomainPubLookup(this.cfg.peerDomain);
    if (
      !verifyServerMessage(
        acc as unknown as Record<string, unknown>,
        acc.server_signature,
        peerDomainPub,
      )
    ) {
      throw new Error(
        "handshake: federation accepted server_signature did not verify",
      );
    }
    const ttl = acc.session_ttl > 0 ? acc.session_ttl : 3600;
    this.finalSession = {
      sessionId: acc.session_id,
      sessionTTL: ttl,
      keys: this.sessionKeys,
      peerDomain: this.cfg.peerDomain,
      ...(acc.resumption_ticket !== undefined
        ? { resumptionTicket: acc.resumption_ticket }
        : {}),
      extensions: acc.extensions,
    };
  }

  /** Final session populated by {@link onAccepted}. */
  session(): FederationInitiatorSession {
    if (this.finalSession === null) {
      throw new Error("handshake: federation session not yet established");
    }
    return this.finalSession;
  }

  /** Load `K_resumption` recovered from a prior session before {@link resume}. */
  loadResumptionSecret(secret: Uint8Array): void {
    if (secret.length === 0) {
      throw new Error("handshake: empty resumption secret");
    }
    this.resumptionSecret = secret.slice();
  }

  /**
   * Build a {@link FederationResume} bytes per §2.8.7. `ticket` is
   * the opaque value from the prior FederationAccepted's
   * `resumption_ticket.value` (already base64-decoded). Pass
   * `peerConfigurationRevision = 0` to omit it.
   */
  resume(ticket: Uint8Array, peerConfigurationRevision = 0): Uint8Array {
    if (this.resumptionSecret === null) {
      throw new Error("handshake: resume before loadResumptionSecret");
    }
    if (ticket.length === 0) {
      throw new Error("handshake: empty federation resumption ticket");
    }
    if (this.resumeNonce === null) {
      this.resumeNonce = randomBytes(32);
    }
    if (this.ephPriv === null) {
      this.ephPriv = randomBytes(32);
    }
    this.ephPub = x25519PublicKey(this.ephPriv);
    const ephKeyId = fingerprint(this.ephPub);
    const out: FederationResume = {
      type: FederationMessageType,
      step: "resume",
      party: "server",
      version: HandshakeVersion,
      nonce: base64Encode(this.resumeNonce),
      server_id: this.cfg.localServerID,
      server_domain: this.cfg.localDomain,
      ...(peerConfigurationRevision > 0
        ? { peer_configuration_revision: peerConfigurationRevision }
        : {}),
      resumption_ticket: base64Encode(ticket),
      client_ephemeral_key: {
        algorithm: this.cfg.suite,
        key: base64Encode(this.ephPub),
        key_id: ephKeyId,
      },
      transport: "websocket",
      extensions: {},
    };
    return canonicalMarshal(out as unknown as Record<string, unknown>);
  }

  /**
   * Process the responder's FederationAccepted in response to
   * {@link resume} and derive resumed session keys per §2.8.3.
   */
  onResumeAccepted(data: Uint8Array): {
    session: FederationInitiatorSession;
    newTicket: Uint8Array | undefined;
  } {
    if (this.resumptionSecret === null || this.resumeNonce === null) {
      throw new Error("handshake: onResumeAccepted before resume");
    }
    if (this.ephPriv === null) {
      throw new Error("handshake: federation resume ephemeral missing");
    }
    const m = JSON.parse(new TextDecoder().decode(data)) as Record<
      string,
      unknown
    >;
    if (m["step"] === "rejected") {
      const rej = m as unknown as {
        session_id: string;
        reason_code: string;
        reason?: string;
      };
      throw new HandshakeRejectedError(
        rej.session_id,
        rej.reason_code,
        rej.reason,
      );
    }
    if (
      m["type"] !== FederationMessageType ||
      m["step"] !== "accepted" ||
      m["party"] !== "server"
    ) {
      throw new Error(
        "handshake: resumed federation accepted type/step/party mismatch",
      );
    }
    const acc = m as unknown as FederationAccepted;
    if (
      acc.server_ephemeral_key === undefined ||
      acc.server_nonce === undefined ||
      acc.resumption_ticket === undefined
    ) {
      throw new Error(
        "handshake: resumed federation accepted missing server_ephemeral_key / server_nonce / resumption_ticket",
      );
    }
    const peerDomainPub = this.cfg.peerDomainPubLookup(this.cfg.peerDomain);
    if (
      !verifyServerMessage(
        acc as unknown as Record<string, unknown>,
        acc.server_signature,
        peerDomainPub,
      )
    ) {
      throw new Error(
        "handshake: resumed federation accepted server_signature did not verify",
      );
    }
    const serverNonce = base64Decode(acc.server_nonce);
    const serverEphPub = base64Decode(acc.server_ephemeral_key.key);
    const ephShared = x25519Agree(this.ephPriv, serverEphPub);
    this.ephPriv.fill(0);
    this.ephPriv = null;

    // K_resumption mixes into IKM per §2.8.3.
    const ikm = concat(this.resumptionSecret, ephShared);
    const kdf = newHKDFSHA512();
    const resumed = deriveSessionKeysWithResumption(
      kdf,
      ikm,
      this.resumeNonce,
      serverNonce,
    );
    this.resumptionSecret.fill(0);
    this.resumptionSecret = null;

    const ttl = acc.session_ttl > 0 ? acc.session_ttl : 3600;
    const sess: FederationInitiatorSession = {
      sessionId: acc.session_id,
      sessionTTL: ttl,
      keys: resumed,
      peerDomain: this.cfg.peerDomain,
      resumptionTicket: acc.resumption_ticket,
      extensions: acc.extensions,
    };
    this.finalSession = sess;
    return {
      session: sess,
      newTicket: base64Decode(acc.resumption_ticket.value),
    };
  }

  /** Wipe in-memory secret state. */
  erase(): void {
    if (this.ephPriv !== null) {
      this.ephPriv.fill(0);
      this.ephPriv = null;
    }
    if (this.nonce !== null) {
      this.nonce.fill(0);
      this.nonce = null;
    }
    if (this.resumptionSecret !== null) {
      this.resumptionSecret.fill(0);
      this.resumptionSecret = null;
    }
    this.sessionKeys = null;
  }
}

// =============================================================================
// Responder
// =============================================================================

/** Configuration for {@link FederationResponder}. */
export interface FederationResponderConfig {
  /**
   * Algorithm suite. Either `"x25519-chacha20-poly1305"` (baseline)
   * or `"pq-kyber768-x25519"` (hybrid post-quantum). The responder
   * accepts only this suite during negotiation; multi-suite support
   * requires running multiple responders.
   */
  suite: FederationSuite;
  capabilities: Capabilities;
  /** Responder's own domain. */
  localDomain: string;
  /** Stable id of the responder server instance within `localDomain`. */
  localServerID: string;
  /** 32-byte Ed25519 secret seed for the responder's domain key. */
  localDomainSeed: Uint8Array;
  /** Lookup hook returning the initiator's published domain pub. */
  peerDomainPubLookup: (domain: string) => Uint8Array;
  /** Verifier for the initiator's {@link DomainProof}. */
  verifier?: DomainVerifier;
  /** Federation policy returned in message 2. */
  policy: FederationPolicy;
  /** Session TTL in seconds. Defaults to 3600. */
  sessionTTL?: number;
  /** Generator for `session_id`. Required. */
  generateSessionId: () => string;
  /** Optional pre-pinned ephemeral private (deterministic tests). */
  responderEphemeralPriv?: Uint8Array;
  /** Optional pre-pinned 32-byte responder nonce. */
  responderNonce?: Uint8Array;
}

/** Outcome of a successful federation handshake (responder side). */
export interface FederationResponderSession {
  sessionId: string;
  sessionTTL: number;
  keys: SessionKeys;
  peerDomain: string;
}

/**
 * Stateful federation responder. Mirror of `semp-go/handshake.Responder`.
 * Single-shot - discard after success or error.
 */
export class FederationResponder {
  private readonly cfg: FederationResponderConfig;
  private readonly localDomainPub: Uint8Array;
  private readonly localDomainKeyId: string;
  private readonly verifier: DomainVerifier;
  private readonly sessionTTL: number;

  private sessionId = "";
  private peerDomain = "";
  private peerNonce: Uint8Array | null = null;
  private serverNonce: Uint8Array | null = null;
  private respEphPriv: Uint8Array | null = null;
  private initCanonical: Uint8Array | null = null;
  private respCanonical: Uint8Array | null = null;
  private sessionKeys: SessionKeys | null = null;
  private finalSession: FederationResponderSession | null = null;

  constructor(cfg: FederationResponderConfig) {
    if (
      cfg.suite !== "x25519-chacha20-poly1305" &&
      cfg.suite !== "pq-kyber768-x25519"
    ) {
      throw new Error(
        `handshake: federation responder unknown suite ${JSON.stringify(cfg.suite)}`,
      );
    }
    if (cfg.localDomain === "") {
      throw new Error("handshake: federation responder empty localDomain");
    }
    if (cfg.localDomainSeed.length === 0) {
      throw new Error("handshake: federation responder empty localDomainSeed");
    }
    this.cfg = cfg;
    this.localDomainPub = publicKeyFromSeed(cfg.localDomainSeed);
    this.localDomainKeyId = fingerprint(this.localDomainPub);
    this.verifier = cfg.verifier ?? new TrustingDomainVerifier();
    this.sessionTTL = cfg.sessionTTL ?? 3600;
  }

  /**
   * Process ServerInit (message 1) and produce FederationResponse
   * bytes. Throws on signature, identity-proof, or domain-proof
   * verification failure.
   */
  async onInit(data: Uint8Array): Promise<Uint8Array> {
    if (this.initCanonical !== null) {
      throw new Error("handshake: federation responder onInit called twice");
    }
    const m = JSON.parse(new TextDecoder().decode(data)) as Record<
      string,
      unknown
    >;
    if (
      m["type"] !== FederationMessageType ||
      m["step"] !== "init" ||
      m["party"] !== "server"
    ) {
      throw new Error("handshake: federation init type/step/party mismatch");
    }
    const init = m as unknown as ServerInit;
    if (init.server_domain === "") {
      throw new Error("handshake: empty initiator server_domain");
    }
    const peerDomainPub = this.cfg.peerDomainPubLookup(init.server_domain);
    if (
      !verifyServerMessage(
        init as unknown as Record<string, unknown>,
        init.server_signature,
        peerDomainPub,
      )
    ) {
      throw new Error("handshake: federation init server_signature did not verify");
    }
    // Inner identity proof: sig over eph_pub || nonce.
    const clientEphPub = base64Decode(init.server_ephemeral_key.key);
    const clientNonce = base64Decode(init.nonce);
    const innerInput = concat(
      new TextEncoder().encode(IdentityPrefix),
      concat(clientEphPub, clientNonce),
    );
    const innerSig = base64Decode(init.server_identity_proof.signature);
    if (!ed25519Verify(peerDomainPub, innerSig, innerInput)) {
      throw new Error(
        "handshake: federation init inner identity_signature did not verify",
      );
    }
    // Domain-proof verification.
    let result: DomainVerificationResult = {
      status: "verified",
      method: init.domain_proof.method,
    };
    try {
      await this.verifier.verify(
        init.server_domain,
        init.domain_proof,
        init.nonce,
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      result = {
        status: "rejected",
        method: init.domain_proof.method,
        detail,
      };
      throw new Error(
        `handshake: federation domain proof verification failed: ${detail}`,
      );
    }
    // Capability negotiation: pick the first mutually-supported suite.
    const negotiated = pickSuite(
      init.capabilities.encryption_algorithms,
      this.cfg.capabilities.encryption_algorithms,
    );
    if (negotiated === undefined) {
      throw new Error("handshake: federation no mutually supported suite");
    }
    if (negotiated !== this.cfg.suite) {
      throw new Error(
        `handshake: federation negotiated suite ${negotiated} != responder suite ${this.cfg.suite}`,
      );
    }
    // Suite branch: baseline derives a fresh X25519 keypair and runs
    // ECDH against the initiator's 32-byte X25519 ephemeral pub. PQ
    // hybrid-encapsulates against the initiator's 1216-byte hybrid
    // pub, producing a 1120-byte KEM ciphertext that becomes the
    // wire `server_ephemeral_key.key` and the shared secret. The
    // responder holds no ephemeral private on the PQ path because
    // Encapsulate produces the shared secret directly.
    const isPQ = this.cfg.suite === "pq-kyber768-x25519";
    let respEphPub: Uint8Array;
    let shared: Uint8Array;
    if (isPQ) {
      if (this.cfg.responderEphemeralPriv !== undefined) {
        throw new Error(
          "handshake: federation responder PQ ephemeral pinning not supported",
        );
      }
      const enc = hybridEncapsulate(clientEphPub);
      respEphPub = enc.ciphertext;
      shared = enc.sharedSecret;
    } else {
      this.respEphPriv = this.cfg.responderEphemeralPriv ?? randomBytes(32);
      respEphPub = x25519PublicKey(this.respEphPriv);
      shared = x25519Agree(this.respEphPriv, clientEphPub);
    }
    const respEphKeyId = fingerprint(respEphPub);
    this.serverNonce = this.cfg.responderNonce ?? randomBytes(32);
    this.sessionId = this.cfg.generateSessionId();

    const kdf = newHKDFSHA512();
    this.sessionKeys = deriveSessionKeysWithResumption(
      kdf,
      shared,
      clientNonce,
      this.serverNonce,
    );

    // Inner identity proof: sig over eph_pub || server_nonce || client_nonce.
    const proofInput = concat(
      new TextEncoder().encode(IdentityPrefix),
      concat(concat(respEphPub, this.serverNonce), clientNonce),
    );
    const proofSig = ed25519Sign(this.cfg.localDomainSeed, proofInput);

    const resp: FederationResponse = {
      type: FederationMessageType,
      step: "response",
      party: "server",
      version: HandshakeVersion,
      session_id: this.sessionId,
      client_nonce: init.nonce,
      server_nonce: base64Encode(this.serverNonce),
      server_id: this.cfg.localServerID,
      server_domain: this.cfg.localDomain,
      server_ephemeral_key: {
        algorithm: this.cfg.suite,
        key: base64Encode(respEphPub),
        key_id: respEphKeyId,
      },
      server_identity_proof: {
        key_id: this.localDomainKeyId,
        signature: base64Encode(proofSig),
      },
      domain_verification_result: result,
      negotiated: {
        encryption_algorithm: negotiated,
        extensions: [],
      },
      federation_policy: this.cfg.policy,
      server_signature: "",
      extensions: {},
    };
    resp.server_signature = signServerMessage(resp, this.cfg.localDomainSeed);

    this.peerDomain = init.server_domain;
    this.peerNonce = clientNonce;
    this.initCanonical = data;
    this.respCanonical = canonicalMarshal(
      resp as unknown as Record<string, unknown>,
    );
    return this.respCanonical;
  }

  /**
   * Process FederationConfirm (message 3) and produce
   * FederationAccepted bytes (message 4). Throws if the initiator
   * rejected the policy or the confirmation hash doesn't match.
   */
  onConfirm(
    data: Uint8Array,
    opts: {
      issueResumptionTicket?: (keys: SessionKeys) => ResumptionTicket;
    } = {},
  ): Uint8Array {
    if (
      this.initCanonical === null ||
      this.respCanonical === null ||
      this.sessionKeys === null
    ) {
      throw new Error("handshake: federation onConfirm before onInit");
    }
    const m = JSON.parse(new TextDecoder().decode(data)) as Record<
      string,
      unknown
    >;
    if (
      m["type"] !== FederationMessageType ||
      m["step"] !== "confirm" ||
      m["party"] !== "server"
    ) {
      throw new Error(
        "handshake: federation confirm type/step/party mismatch",
      );
    }
    const confirm = m as unknown as FederationConfirm;
    if (confirm.session_id !== this.sessionId) {
      throw new Error("handshake: federation confirm session_id mismatch");
    }
    const peerDomainPub = this.cfg.peerDomainPubLookup(this.peerDomain);
    if (
      !verifyServerMessage(
        confirm as unknown as Record<string, unknown>,
        confirm.server_signature,
        peerDomainPub,
      )
    ) {
      throw new Error(
        "handshake: federation confirm server_signature did not verify",
      );
    }
    const wantHash = confirmationHash(this.initCanonical, this.respCanonical);
    const gotHash = base64Decode(confirm.confirmation_hash);
    if (!constantTimeEqual(gotHash, wantHash)) {
      throw new Error("handshake: federation confirmation hash mismatch");
    }
    if (!confirm.federation_acceptance.accepted) {
      throw new Error(
        `handshake: federation initiator rejected our policy: ${confirm.federation_acceptance.reason ?? ""}`,
      );
    }

    const ticket = opts.issueResumptionTicket?.(this.sessionKeys);
    const acc: FederationAccepted = {
      type: FederationMessageType,
      step: "accepted",
      party: "server",
      version: HandshakeVersion,
      session_id: this.sessionId,
      status: "accepted",
      session_ttl: this.sessionTTL,
      ...(ticket !== undefined ? { resumption_ticket: ticket } : {}),
      server_signature: "",
      extensions: {},
    };
    acc.server_signature = signServerMessage(acc, this.cfg.localDomainSeed);

    this.finalSession = {
      sessionId: this.sessionId,
      sessionTTL: this.sessionTTL,
      keys: this.sessionKeys,
      peerDomain: this.peerDomain,
    };
    if (this.respEphPriv !== null) {
      this.respEphPriv.fill(0);
      this.respEphPriv = null;
    }
    return canonicalMarshal(acc as unknown as Record<string, unknown>);
  }

  /** Final session populated by {@link onConfirm}. */
  session(): FederationResponderSession {
    if (this.finalSession === null) {
      throw new Error(
        "handshake: federation responder session not yet established",
      );
    }
    return this.finalSession;
  }

  /** Wipe in-memory secret state. */
  erase(): void {
    if (this.respEphPriv !== null) {
      this.respEphPriv.fill(0);
      this.respEphPriv = null;
    }
    if (this.peerNonce !== null) {
      this.peerNonce.fill(0);
      this.peerNonce = null;
    }
    if (this.serverNonce !== null) {
      this.serverNonce.fill(0);
      this.serverNonce = null;
    }
    this.sessionKeys = null;
  }
}

// ---------------------------------------------------------------------------
// Helpers

function signServerMessage(msg: object, seed: Uint8Array): string {
  const clone = JSON.parse(JSON.stringify(msg)) as Record<string, unknown>;
  clone.server_signature = "";
  const canonical = canonicalMarshal(clone);
  const signingInput = concat(
    new TextEncoder().encode(HandshakePrefix),
    canonical,
  );
  return base64Encode(ed25519Sign(seed, signingInput));
}

function verifyServerMessage(
  msg: Record<string, unknown>,
  signatureB64: string,
  domainPub: Uint8Array,
): boolean {
  if (signatureB64 === "") {
    return false;
  }
  const clone = JSON.parse(JSON.stringify(msg)) as Record<string, unknown>;
  clone["server_signature"] = "";
  const canonical = canonicalMarshal(clone);
  const signingInput = concat(
    new TextEncoder().encode(HandshakePrefix),
    canonical,
  );
  return ed25519Verify(domainPub, base64Decode(signatureB64), signingInput);
}

function pickSuite(
  offered: ReadonlyArray<string>,
  supported: ReadonlyArray<string>,
): string | undefined {
  for (const s of supported) {
    if (offered.includes(s)) {
      return s;
    }
  }
  return undefined;
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
