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
 * to be preserved separately; in the SEMP architecture the
 * sender's home server and the federation initiator are the SAME
 * server, so re-signing with the local domain key is functionally
 * identical to "the sender's domain signed this envelope".
 *
 * The forwarder is protocol-pure: the two pluggable inputs it
 * requires ({@link EndpointResolver} and {@link PeerDomainKeyLookup})
 * cover everything the spec defines for federation peer addressing.
 * Peer endpoint URLs come from `endpointResolver`, which the
 * operator can wire to a discovery-driven lookup
 * (DISCOVERY.md §5.1) or a static peer map. Peer signing keys
 * come from `peerDomainKey`, which the operator can wire to a
 * pre-loaded map (loaded at startup) or to a KEY.md fetcher
 * ({@link "../discovery".fetchDomainKeys}). Neither shape is
 * privileged; both satisfy the spec.
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

/**
 * Returns the federation endpoint URL the {@link Forwarder} should
 * dial for `peerDomain`. Implementations cover the full range of
 * peer-endpoint sourcing: a discovery-driven lookup over DNS SRV
 * plus the well-known URI per DISCOVERY.md §5.1, a static map for
 * operators that pre-pin known peers, or a hybrid that consults the
 * static map first and falls back to discovery.
 *
 * Throwing blocks the federation handshake. The {@link Forwarder}
 * surfaces the error to whoever asked for the forward.
 */
export type EndpointResolver = (peerDomain: string) => Promise<string>;

/**
 * Returns the long-term Ed25519 signing public key for a peer
 * domain. Operators populate this from a startup-time map, from a
 * KEY.md fetcher
 * ({@link "../discovery".fetchDomainKeys}), or from a hybrid.
 *
 * Throwing blocks the federation handshake; the
 * {@link Forwarder} surfaces the error to whoever asked for the
 * forward.
 */
export type PeerDomainKeyLookup = (peerDomain: string) => Promise<Uint8Array>;

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
  /**
   * Resolves a peer domain to a federation endpoint URL. Required.
   *
   * For pre-pinned static peers, supply a function that looks the
   * domain up in an in-memory map. For discovery-driven lookups,
   * compose a custom resolver around
   * {@link "../discovery".fetchConfiguration} or
   * {@link "../discovery".resolveServer}.
   */
  endpointResolver: EndpointResolver;
  /**
   * Resolves a peer domain to its long-term signing public key.
   * Required.
   *
   * For pre-pinned static peers, supply a function that looks the
   * domain up in an in-memory map. For lazy KEY.md fetch, compose a
   * resolver around {@link "../discovery".fetchDomainKeys}.
   */
  peerDomainKey: PeerDomainKeyLookup;
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
   * Opens a federation session lazily on first call per peer. The
   * peer endpoint is resolved through `cfg.endpointResolver`; the
   * peer signing key is resolved through `cfg.peerDomainKey`. Both
   * lookups happen before the dial, so an unknown peer fails fast.
   */
  async forward(
    peerDomain: string,
    env: Envelope,
  ): Promise<SubmissionResponse> {
    const fs = await this.getSession(peerDomain);
    try {
      return await this.forwardOnSession(fs, env);
    } catch (err) {
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

  private async getSession(peerDomain: string): Promise<CachedSession> {
    const cached = this.sessions.get(peerDomain);
    if (cached !== undefined) {
      return cached;
    }
    const inflight = this.connecting.get(peerDomain);
    if (inflight !== undefined) {
      return inflight;
    }
    const p = this.openSession(peerDomain).finally(() => {
      this.connecting.delete(peerDomain);
    });
    this.connecting.set(peerDomain, p);
    return p;
  }

  private async openSession(peerDomain: string): Promise<CachedSession> {
    const endpoint = await this.cfg.endpointResolver(peerDomain);
    if (endpoint === "") {
      throw new Error(
        `delivery: endpointResolver returned empty URL for ${peerDomain}`,
      );
    }
    const peerPub = await this.cfg.peerDomainKey(peerDomain);
    if (peerPub.length === 0) {
      throw new Error(
        `delivery: peerDomainKey returned empty key for ${peerDomain}`,
      );
    }

    const transport = await this.cfg.dial(endpoint);
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
        if (d !== peerDomain) {
          throw new Error(
            `forwarder: peer domain pub lookup for unknown domain ${d}`,
          );
        }
        return peerPub;
      },
      peerDomain,
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
      this.sessions.set(peerDomain, fs);
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
    while (fs.wireMu.locked) {
      await new Promise((r) => setTimeout(r, 0));
    }
    fs.wireMu.locked = true;
    try {
      env.postmark.session_id = fs.session.sessionId;

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
