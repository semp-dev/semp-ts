/**
 * Session lifecycle per `SESSION.md` §2.
 *
 * A Session holds the post-handshake state both peers retain:
 *
 *   - The five SEMP session keys (encC2S, encS2C, macC2S, macS2C,
 *     envMAC) plus K_resumption.
 *   - session_id and the negotiated TTL.
 *   - permissions and resumption_ticket if the server supplied one.
 *   - The underlying transport, surfaced for the next-layer envelope
 *     sender/receiver.
 *
 * State transitions:
 *
 *   active   ── close() ──>  closed
 *   active   ── ttl elapsed, isExpired() returns true ──>  active
 *                (state stays "active"; callers MUST check
 *                 isExpired() before trusting envelope verification)
 *   active   ── erase() ──>  closed (keys zeroized)
 *
 * The v1 module is intentionally minimal: it does not implement
 * rekey, resume, or per-direction sequence number tracking. Those
 * land in the next slice.
 *
 * @module
 */

import { type SessionKeys } from "../crypto/index.js";
import type { Transport } from "../transport/index.js";

/** Session role: "client" if the local end ran runClient. */
export type Role = "client" | "server";

/** New keys + new session id installed by a successful rekey. */
export interface RekeyApply {
  /** Replacement session_id from RekeyAccepted. */
  newSessionId: string;
  /** Newly derived session keys per SESSION.md §3.3. */
  newKeys: SessionKeys;
}

/** Configuration to construct a Session from a completed handshake. */
export interface SessionConfig {
  role: Role;
  sessionId: string;
  /** TTL in seconds returned by ACCEPTED. */
  sessionTTL: number;
  /** Wall-clock instant when the session was established. */
  establishedAt: Date;
  permissions: string[];
  keys: SessionKeys;
  transport: Transport;
  /** Optional resumption ticket from ACCEPTED. */
  resumptionTicket?: { value: string; expires_at: string };
  /** Server identity proof from RESPONSE (forwarded for higher layers). */
  serverIdentityProofKeyId?: string;
  serverIdentityProofSignature?: string;
  /** Extensions echoed back from ACCEPTED. */
  extensions?: Record<string, unknown>;
}

/**
 * Live SEMP session. Outlives the handshake; lives until close()
 * or until the underlying transport drops. Higher-level senders
 * borrow `keys.envMAC` for envelope MAC computation and the
 * transport for raw send/receive of envelope bytes.
 */
export class Session {
  readonly role: Role;
  /**
   * Current session_id. Mutable: a successful rekey installs a new
   * id atomically with the new keys (see {@link applyRekey}).
   */
  sessionId: string;
  readonly sessionTTL: number;
  readonly establishedAt: Date;
  readonly permissions: ReadonlySet<string>;
  readonly resumptionTicket: { value: string; expires_at: string } | undefined;
  readonly serverIdentityProofKeyId: string | undefined;
  readonly serverIdentityProofSignature: string | undefined;
  readonly extensions: Readonly<Record<string, unknown>>;

  private _keys: SessionKeys | null;
  private _transport: Transport;
  private _closed = false;

  constructor(config: SessionConfig) {
    this.role = config.role;
    this.sessionId = config.sessionId;
    this.sessionTTL = config.sessionTTL;
    this.establishedAt = config.establishedAt;
    this.permissions = new Set(config.permissions);
    this.resumptionTicket = config.resumptionTicket;
    this.serverIdentityProofKeyId = config.serverIdentityProofKeyId;
    this.serverIdentityProofSignature = config.serverIdentityProofSignature;
    this.extensions = Object.freeze({ ...(config.extensions ?? {}) });
    this._keys = config.keys;
    this._transport = config.transport;
  }

  /** True after close() or erase(). */
  get closed(): boolean {
    return this._closed;
  }

  /** Wall-clock instant the session expires (establishedAt + TTL). */
  expiresAt(): Date {
    return new Date(this.establishedAt.getTime() + this.sessionTTL * 1000);
  }

  /** Reports whether the session has passed its TTL relative to `now`. */
  isExpired(now: Date = new Date()): boolean {
    return now.getTime() >= this.expiresAt().getTime();
  }

  /**
   * Live session keys. Throws if the session has been closed or
   * erased — once erase() runs, the bytes are zeroized and any
   * caller still holding a Session reference cannot accidentally
   * encrypt under invalidated material.
   */
  get keys(): SessionKeys {
    if (this._keys === null) {
      throw new Error("session: keys have been erased");
    }
    return this._keys;
  }

  /** The underlying transport. Throws if the session is closed. */
  get transport(): Transport {
    if (this._closed) {
      throw new Error("session: closed");
    }
    return this._transport;
  }

  /**
   * Send raw bytes (typically a canonical envelope) over the
   * transport. Caller is responsible for envelope composition,
   * including the envelope-level MAC computed over the canonical
   * bytes with `keys.envMAC`.
   */
  async send(message: Uint8Array): Promise<void> {
    if (this._closed) {
      throw new Error("session: closed");
    }
    await this._transport.send(message);
  }

  /**
   * Receive raw bytes from the transport. Returns null on clean
   * peer close. Caller verifies the envelope's session_mac with
   * `keys.envMAC` before trusting the contents.
   */
  async receive(): Promise<Uint8Array | null> {
    if (this._closed) {
      throw new Error("session: closed");
    }
    return this._transport.receive();
  }

  /**
   * Close the session and the underlying transport. Idempotent.
   * Does NOT zeroize keys — callers that want zeroization use
   * {@link erase}.
   */
  async close(): Promise<void> {
    if (this._closed) {
      return;
    }
    this._closed = true;
    try {
      await this._transport.close();
    } catch {
      // already closing
    }
  }

  /**
   * Atomically install new session keys + a new session_id from a
   * successful rekey. Zeroizes the prior keys before swapping. The
   * session retains its TTL boundary (TTL counts from the original
   * establishedAt) — rekey rolls forward the keys, not the lifetime.
   */
  applyRekey(apply: RekeyApply): void {
    if (this._keys === null) {
      throw new Error("session: applyRekey after erase");
    }
    if (this._closed) {
      throw new Error("session: applyRekey on closed session");
    }
    // Zeroize previous keys before dropping the reference.
    const prev = this._keys;
    zero(prev.encC2S);
    zero(prev.encS2C);
    zero(prev.macC2S);
    zero(prev.macS2C);
    zero(prev.envMAC);
    if (prev.resumption !== undefined) {
      zero(prev.resumption);
    }
    this._keys = apply.newKeys;
    this.sessionId = apply.newSessionId;
  }

  /**
   * Close the session AND zeroize all session keys. After this,
   * `keys` throws and the underlying byte buffers are filled with
   * zero. Safe to call multiple times. RECOMMENDED on logout / app
   * suspend / any time the session is no longer needed.
   */
  async erase(): Promise<void> {
    await this.close();
    if (this._keys !== null) {
      const k = this._keys;
      zero(k.encC2S);
      zero(k.encS2C);
      zero(k.macC2S);
      zero(k.macS2C);
      zero(k.envMAC);
      if (k.resumption !== undefined) {
        zero(k.resumption);
      }
      this._keys = null;
    }
  }
}

function zero(b: Uint8Array): void {
  for (let i = 0; i < b.length; i++) {
    b[i] = 0;
  }
}
