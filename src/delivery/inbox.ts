/**
 * Reference per-user envelope inbox — minimal in-memory FIFO.
 *
 * Intended for in-process tests, embedded servers, and the
 * reference {@link "./fetch".FetchResponse} producer. NOT a
 * production storage layer:
 *
 *   - No persistence: process restart loses all queued envelopes.
 *   - No fairness controls, no per-address access control, no
 *     retention rules.
 *   - Concurrency boundary is single-process; multi-writer use is
 *     safe under the JavaScript run-to-completion model but not
 *     across worker threads.
 *
 * Production deployments MUST back this with a durable store,
 * retention rules, fairness controls, and per-address access
 * control — none of which are present here.
 *
 * @module
 */

/** Default maximum per-address queue depth. */
export const DefaultMaxQueueDepth = 10_000;

/** Reference in-memory inbox keyed by canonical user@domain string. */
export class Inbox {
  private readonly queues = new Map<string, Uint8Array[]>();
  private readonly maxDepth: number;

  constructor(maxDepth: number = DefaultMaxQueueDepth) {
    if (maxDepth <= 0) {
      this.maxDepth = DefaultMaxQueueDepth;
    } else {
      this.maxDepth = maxDepth;
    }
  }

  /**
   * Append `payload` to the queue for `address`. If the queue is at
   * its maximum depth, the oldest entry is dropped to make room.
   */
  store(address: string, payload: Uint8Array): void {
    if (address === "") {
      throw new Error("delivery: inbox.store empty address");
    }
    const list = this.queues.get(address);
    if (list === undefined) {
      this.queues.set(address, [payload.slice()]);
      return;
    }
    if (list.length >= this.maxDepth) {
      list.shift(); // drop oldest
    }
    list.push(payload.slice());
  }

  /**
   * Return every queued envelope for `address` and clear the queue.
   * Returns an empty array when the address has no waiting
   * envelopes.
   */
  drain(address: string): Uint8Array[] {
    const list = this.queues.get(address) ?? [];
    this.queues.delete(address);
    return list;
  }

  /** Number of waiting envelopes for `address`. */
  pending(address: string): number {
    return this.queues.get(address)?.length ?? 0;
  }
}
