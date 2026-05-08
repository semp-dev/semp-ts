/**
 * Transport abstraction per `TRANSPORT.md` §2.
 *
 * SEMP messages are exchanged as opaque byte slices over a stream
 * the higher layers treat as bidirectional, ordered, and
 * framed. The handshake driver, session machine, and inbox
 * client all consume this same interface; the choice of
 * underlying transport (WebSocket, HTTP/2, QUIC) is swapped at
 * the boundary.
 *
 * Each `send` writes one SEMP message per spec §4.1.2 (no
 * splitting across frames). Each `receive` returns one complete
 * SEMP message (the underlying transport reassembles fragmented
 * frames before yielding). When the remote side closes,
 * `receive` returns `null`; subsequent calls also return `null`.
 *
 * @module
 */

/**
 * One direction of a connected SEMP transport. Implementations
 * MUST guarantee message boundary preservation: one `send` on
 * one peer corresponds to exactly one `receive` on the other,
 * with the same byte sequence.
 */
export interface Transport {
  /** Send one SEMP message. Resolves once the bytes are committed to the underlying transport. */
  send(message: Uint8Array): Promise<void>;

  /**
   * Receive the next SEMP message. Resolves with the message bytes
   * on success; with `null` when the remote side has cleanly closed
   * AND no buffered messages remain.
   *
   * Rejects if the underlying transport surfaces an error (network
   * failure, framing violation, subprotocol mismatch). The caller
   * SHOULD treat any rejection as terminal for the connection.
   */
  receive(): Promise<Uint8Array | null>;

  /** Close the underlying connection. Idempotent. */
  close(code?: number, reason?: string): Promise<void>;
}

/** Optional context passed through to dialers. */
export interface DialOptions {
  /**
   * Abort signal observed by dialers. When fired before connect
   * completes, the returned promise rejects with the abort reason.
   */
  signal?: AbortSignal;
  /**
   * Timeout in milliseconds for the connect handshake. Default: 30s.
   * Ignored if `signal` is also supplied.
   */
  timeoutMs?: number;
}
