/**
 * Sending-server transient holding area for delivery receipts per
 * DELIVERY.md §1.1.1.6.
 *
 * The sending server retains a receipt only until at least one
 * authenticated client device of the sending user has acknowledged
 * the delivery event carrying it; after that acknowledgment the
 * server SHOULD drop the receipt so it does not accumulate a
 * long-term receipts archive (which would conflict with the §2.5
 * correspondent-graph privacy posture).
 *
 * Production deployments plug in a durable backend (a Redis cache, a
 * relational table) by implementing {@link ReceiptStore} directly.
 * Tests and demos use {@link InMemoryReceiptStore}.
 *
 * @module
 */

import type { DeliveryReceipt } from "./receipt.js";

/**
 * The transient holding area. Implementations MUST be safe for
 * concurrent use; the in-memory reference uses a mutex.
 */
export interface ReceiptStore {
  /**
   * Insert a receipt issued by a recipient server, keyed by
   * `(envelopeId, recipient)`. `storedAt` is the wall-clock time the
   * receipt entered the store; the prune path uses it to enforce the
   * push-notification retention window for receipts that no client
   * ever acknowledged.
   */
  put(
    envelopeId: string,
    recipient: string,
    receipt: DeliveryReceipt,
    storedAt: Date,
  ): Promise<void>;

  /**
   * Fetch the receipt for `(envelopeId, recipient)`. Returns `null`
   * for unknown records.
   */
  get(envelopeId: string, recipient: string): Promise<DeliveryReceipt | null>;

  /**
   * Mark the receipt for `(envelopeId, recipient)` as having been
   * delivered to a client device per §1.1.1.6. The implementation MAY
   * drop the receipt immediately on acknowledge (the spec's "MAY drop"
   * allowance), or retain it briefly for cross-device propagation. The
   * reference in-memory implementation drops on acknowledge.
   *
   * A no-op on unknown records: the §1.1.1.6 retention rule does not
   * require acknowledgment to be exact-once, only that the server
   * eventually drop the receipt.
   */
  acknowledge(envelopeId: string, recipient: string): Promise<void>;

  /**
   * Remove receipts whose `storedAt` is older than `cutoff` and that
   * have not been acknowledged. Returns the number of receipts pruned.
   * The §1.1.1.6 retention rule says receipts MAY be dropped on the
   * same schedule as undelivered notifications; this method
   * implements that pruning.
   */
  pruneUnacknowledged(cutoff: Date): Promise<number>;
}

/**
 * Default push-notification window the §1.1.1.6 prune path uses when
 * the operator has not configured a tighter value. Three days matches
 * the 72h `server_max_retry_horizon` default per §2.4: any envelope
 * that hits the queue's hard deadline cannot have a delivered
 * acknowledgment past that point, so retaining receipts longer offers
 * no value.
 */
export const DefaultReceiptRetentionMs = 72 * 60 * 60 * 1000;

interface ReceiptRecord {
  receipt: DeliveryReceipt;
  storedAt: Date;
}

/**
 * Reference {@link ReceiptStore} backed by a Map. Acknowledge drops
 * the receipt immediately so no plaintext archive accumulates.
 *
 * Single-process only — production deployments replace this with a
 * durable backend.
 */
export class InMemoryReceiptStore implements ReceiptStore {
  private readonly records = new Map<string, ReceiptRecord>();

  async put(
    envelopeId: string,
    recipient: string,
    receipt: DeliveryReceipt,
    storedAt: Date,
  ): Promise<void> {
    if (envelopeId === "") {
      throw new Error("ReceiptStore.put: empty envelopeId");
    }
    if (recipient === "") {
      throw new Error("ReceiptStore.put: empty recipient");
    }
    const k = recordKey(envelopeId, recipient);
    if (this.records.has(k)) {
      throw new Error(
        `ReceiptStore.put: receipt already stored for (${envelopeId}, ${recipient})`,
      );
    }
    this.records.set(k, { receipt, storedAt });
  }

  async get(
    envelopeId: string,
    recipient: string,
  ): Promise<DeliveryReceipt | null> {
    const rec = this.records.get(recordKey(envelopeId, recipient));
    return rec === undefined ? null : rec.receipt;
  }

  async acknowledge(envelopeId: string, recipient: string): Promise<void> {
    this.records.delete(recordKey(envelopeId, recipient));
  }

  async pruneUnacknowledged(cutoff: Date): Promise<number> {
    const cutoffMs = cutoff.getTime();
    const stale: string[] = [];
    for (const [k, rec] of this.records) {
      if (rec.storedAt.getTime() <= cutoffMs) {
        stale.push(k);
      }
    }
    stale.sort();
    for (const k of stale) {
      this.records.delete(k);
    }
    return stale.length;
  }
}

function recordKey(envelopeId: string, recipient: string): string {
  return `${envelopeId}\x00${recipient}`;
}
