/**
 * Federation forwarder per DELIVERY.md §5 and HANDSHAKE.md §5.
 *
 * Establishes and caches federation sessions to remote peers and
 * forwards envelopes across them. Each `(localDomain, peerDomain)`
 * pair gets at most one live session at a time; the forwarder
 * re-runs the federation handshake if the cached session has
 * expired or been torn down.
 *
 * On forward, the forwarder:
 *
 *   1. Updates `postmark.session_id` to reference the federation
 *      session id (so the peer's receive pipeline matches).
 *   2. Re-signs the envelope with the local domain key and
 *      recomputes `seal.session_mac` under the federation
 *      session's `K_env_mac`.
 *   3. Sends the encoded envelope over the federation transport.
 *   4. Returns the peer's parsed {@link SubmissionResponse}.
 *
 * The original sender's domain proof of provenance does NOT need
 * to be preserved separately — in the SEMP architecture the
 * sender's home server and the federation initiator are the SAME
 * server, so re-signing with the local domain key is functionally
 * identical to "the sender's domain signed this envelope".
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import { computeMAC } from "../crypto/index.js";
import {
  type Envelope,
  canonicalEnvelopeFor,
  encodeEnvelope,
} from "../envelope/index.js";
import { sign as ed25519Sign } from "../keys/index.js";
import {
  type Capabilities,
  type FederationInitiatorSession,
  type FederationPolicy,
  FederationInitiator,
} from "../handshake/index.js";
import type { Transport } from "../transport/index.js";

import type { SubmissionResponse } from "./submission.js";

/** Domain-separation prefix for the seal signature, per §4.3. */
const EnvelopePrefix = "SEMP-ENVELOPE:";

/** Per-peer routing information. */
export interface PeerConfig {
  /** Peer's domain (e.g. `"b.example"`). */
  domain: string;
  /**
   * Federation endpoint URL (e.g. `"ws://127.0.0.1:18082/v1/federate"`).
   * The forwarder passes this verbatim to {@link Dialer}.
   */
  endpoint: string;
  /**
   * Peer's long-term Ed25519 signing public key. Used by the
   * federation Initiator to verify the peer's response / accepted
   * messages.
   */
  domainSigningPub: Uint8Array;
}

/** Domain → {@link PeerConfig} map. */
export class PeerRegistry {
  private readonly peers = new Map<string, PeerConfig>();

  put(cfg: PeerConfig): void {
    if (cfg.domain === "") {
      throw new Error("delivery: PeerConfig missing domain");
    }
    this.peers.set(cfg.domain, { ...cfg });
  }

  lookup(domain: string): PeerConfig | null {
    return this.peers.get(domain) ?? null;
  }
}

/** Opens a transport to a peer's federation endpoint. */
export type Dialer = (endpoint: string) => Promise<Transport>;

/** Inputs to {@link Forwarder}. */
export interface ForwarderConfig {
  /** Local server's domain. */
  localDomain: string;
  /** Stable id of the local server instance. */
  localServerID: string;
  /** Local 32-byte Ed25519 secret seed. */
  localDomainSeed: Uint8Array;
  /** Static peer registry. */
  peers: PeerRegistry;
  /** Transport dialer. */
  dial: Dialer;
  /**
   * Capabilities advertised on outbound federation handshakes.
   * Defaults to `{ encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] }`.
   */
  capabilities?: Capabilities;
  /** Policy hook. Defaults to `acceptAllPolicies`. */
  policyAcceptor?: (policy: FederationPolicy) => string | null;
}

interface CachedSession {
  transport: Transport;
  session: FederationInitiatorSession;
  /** Lock for serializing wire access (acquire across send/recv). */
  wireMu: { locked: boolean };
}

/**
 * Federation forwarder.
 *
 * `forward()` is concurrency-safe: per-peer wire access is
 * serialized by a software lock so concurrent calls don't
 * interleave on the same stream. Use {@link Forwarder.close} on
 * shutdown to tear down every cached session.
 */
export class Forwarder {
  private readonly cfg: ForwarderConfig;
  private readonly sessions = new Map<string, CachedSession>();
  private readonly connecting = new Map<string, Promise<CachedSession>>();

  constructor(cfg: ForwarderConfig) {
    if (cfg.localDomain === "") {
      throw new Error("delivery: forwarder empty localDomain");
    }
    if (cfg.localServerID === "") {
      throw new Error("delivery: forwarder empty localServerID");
    }
    if (cfg.localDomainSeed.length === 0) {
      throw new Error("delivery: forwarder empty localDomainSeed");
    }
    this.cfg = cfg;
  }

  /**
   * Re-bind `seal.session_mac` under the federation session's
   * `K_env_mac` and ship `env` across the cached session for
   * `peerDomain`. Returns the peer's parsed submission response.
   *
   * Opens a federation session lazily on first call per peer.
   */
  async forward(
    peerDomain: string,
    env: Envelope,
  ): Promise<SubmissionResponse> {
    const cfg = this.cfg.peers.lookup(peerDomain);
    if (cfg === null) {
      throw new Error(`delivery: forwarder: unknown peer ${peerDomain}`);
    }
    const fs = await this.getSession(cfg);
    try {
      return await this.forwardOnSession(fs, env);
    } catch (err) {
      // Drop the session on transport-layer failure; next call
      // re-handshakes.
      this.dropSession(peerDomain);
      throw err;
    }
  }

  /** Tear down every cached session. Call on shutdown. */
  async close(): Promise<void> {
    const sessions = Array.from(this.sessions.values());
    this.sessions.clear();
    for (const fs of sessions) {
      try {
        await fs.transport.close();
      } catch {
        // best-effort
      }
    }
  }

  /** Diagnostic: peer domains with a live cached session. */
  cachedPeers(): string[] {
    return Array.from(this.sessions.keys()).sort();
  }

  // ---------------------------------------------------------------------------

  private async getSession(cfg: PeerConfig): Promise<CachedSession> {
    const cached = this.sessions.get(cfg.domain);
    if (cached !== undefined) {
      return cached;
    }
    // Coalesce concurrent connects so we don't open two sessions to
    // the same peer in parallel.
    const inflight = this.connecting.get(cfg.domain);
    if (inflight !== undefined) {
      return inflight;
    }
    const p = this.openSession(cfg).finally(() => {
      this.connecting.delete(cfg.domain);
    });
    this.connecting.set(cfg.domain, p);
    return p;
  }

  private async openSession(cfg: PeerConfig): Promise<CachedSession> {
    const transport = await this.cfg.dial(cfg.endpoint);
    const initiator = new FederationInitiator({
      suite: "x25519-chacha20-poly1305",
      capabilities: this.cfg.capabilities ?? {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: this.cfg.localDomain,
      localServerID: this.cfg.localServerID,
      localDomainSeed: this.cfg.localDomainSeed,
      peerDomainPubLookup: (d) => {
        if (d !== cfg.domain) {
          throw new Error(
            `forwarder: peer domain pub lookup for unknown domain ${d}`,
          );
        }
        return cfg.domainSigningPub;
      },
      peerDomain: cfg.domain,
      domainProof: { method: "test-trust", data: this.cfg.localDomain },
      ...(this.cfg.policyAcceptor !== undefined
        ? { policyAcceptor: this.cfg.policyAcceptor }
        : {}),
    });
    try {
      const initBytes = initiator.init();
      await transport.send(initBytes);
      const respBytes = await transport.receive();
      if (respBytes === null) {
        throw new Error("forwarder: connection closed waiting for response");
      }
      const confirmBytes = initiator.onResponse(respBytes);
      await transport.send(confirmBytes);
      const acceptedBytes = await transport.receive();
      if (acceptedBytes === null) {
        throw new Error("forwarder: connection closed waiting for accepted");
      }
      initiator.onAccepted(acceptedBytes);
      const session = initiator.session();
      const fs: CachedSession = {
        transport,
        session,
        wireMu: { locked: false },
      };
      this.sessions.set(cfg.domain, fs);
      return fs;
    } catch (err) {
      try {
        await transport.close();
      } catch {
        // already closed
      }
      throw err;
    }
  }

  private async forwardOnSession(
    fs: CachedSession,
    env: Envelope,
  ): Promise<SubmissionResponse> {
    // Serialize wire access — JS run-to-completion makes this a soft
    // latch sufficient for the single-thread model.
    while (fs.wireMu.locked) {
      await new Promise((r) => setTimeout(r, 0));
    }
    fs.wireMu.locked = true;
    try {
      // Update postmark.session_id so the peer's pipeline matches.
      env.postmark.session_id = fs.session.sessionId;

      // Re-sign with our local domain key + re-MAC under federation
      // K_env_mac. Both proofs cover the SAME canonical bytes (with
      // signature + mac blanked).
      env.seal.signature = "";
      env.seal.session_mac = "";
      const canonical = canonicalEnvelopeFor(env);
      const signingInput = concat(
        new TextEncoder().encode(EnvelopePrefix),
        canonical,
      );
      env.seal.signature = base64Encode(
        ed25519Sign(this.cfg.localDomainSeed, signingInput),
      );
      env.seal.session_mac = base64Encode(
        computeMAC(fs.session.keys.envMAC, canonical),
      );

      const wire = encodeEnvelope(env);
      await fs.transport.send(wire);
      const respBytes = await fs.transport.receive();
      if (respBytes === null) {
        throw new Error(
          "forwarder: connection closed waiting for federation response",
        );
      }
      const parsed = JSON.parse(new TextDecoder().decode(respBytes));
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed)
      ) {
        throw new Error("forwarder: federation response is not a JSON object");
      }
      return parsed as SubmissionResponse;
    } finally {
      fs.wireMu.locked = false;
    }
  }

  private dropSession(peerDomain: string): void {
    const fs = this.sessions.get(peerDomain);
    if (fs === undefined) {
      return;
    }
    this.sessions.delete(peerDomain);
    fs.transport.close().catch(() => {
      // best-effort
    });
  }
}

void canonicalMarshal;

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
