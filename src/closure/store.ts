/**
 * Persistence interface for closure state per CLOSURE.md §2.4 +
 * §6.1.
 *
 * Used by the {@link "./driver".Driver} for two distinct concerns:
 *
 *  - Pending state: active closure requests (submit / cancel /
 *    tick-due).
 *  - Finalized state: closed accounts within the §6.1 retention
 *    window. Used by ingress enforcement (§5) and by §6 local-part
 *    reassignment checks.
 *
 * Production deployments plug in a durable backend; tests + demos
 * use {@link InMemoryClosureStore}.
 *
 * @module
 */

import type { ClosureRecord } from "./closure.js";
import { finalizationAt } from "./closure.js";

/**
 * Spec-mandated retention bounds for the §6.1 post-finalization
 * retention window: at least 180 days, RECOMMENDED 365 days.
 */
export const MinRetentionMs = 180 * 24 * 60 * 60 * 1000;
export const RecommendedRetentionMs = 365 * 24 * 60 * 60 * 1000;

/** Thrown by {@link ClosureStore.putPending} on collision. */
export class AlreadyPendingError extends Error {
  override readonly name = "AlreadyPendingError";
}

/** Persistence interface for closure state. */
export interface ClosureStore {
  /**
   * Insert `record` as the active pending request for
   * `record.user_id`. Throws {@link AlreadyPendingError} if a
   * request is already pending for the same user (the §2.4
   * "at most one active closure" rule).
   */
  putPending(record: ClosureRecord): Promise<void>;

  /** Return the pending request for `userId`, or null when none. */
  getPending(userId: string): Promise<ClosureRecord | null>;

  /** Remove the pending request for `userId`. Idempotent. */
  deletePending(userId: string): Promise<void>;

  /**
   * Return every pending request whose finalization timestamp is
   * at or before `now`, in deterministic order (by user_id
   * ascending). The driver's `tick` consumes this slice.
   */
  duePending(now: Date): Promise<ClosureRecord[]>;

  /** Number of pending requests, for operator monitoring. */
  countPending(): Promise<number>;

  /**
   * Record that `userId`'s closure finalized at the given timestamp.
   * Used by `isAccountClosed` and the §6.1 retention prune.
   */
  putFinalized(userId: string, finalizedAt: Date): Promise<void>;

  /**
   * Return the finalization timestamp for `userId`, or null if no
   * finalization is recorded.
   */
  getFinalized(userId: string): Promise<Date | null>;

  /**
   * Evict finalized entries older than `retainForMs`. Values smaller
   * than {@link MinRetentionMs} are clamped up. Returns the number
   * of entries evicted.
   */
  pruneFinalized(retainForMs: number, now?: Date): Promise<number>;
}

/** Reference in-memory {@link ClosureStore}. Single-process only. */
export class InMemoryClosureStore implements ClosureStore {
  private readonly pending = new Map<string, ClosureRecord>();
  private readonly finalized = new Map<string, Date>();

  async putPending(record: ClosureRecord): Promise<void> {
    if (record.user_id === "") {
      throw new Error("closure: store put_pending missing user_id");
    }
    if (this.pending.has(record.user_id)) {
      throw new AlreadyPendingError(
        `closure: pending request already exists for ${record.user_id}`,
      );
    }
    this.pending.set(record.user_id, { ...record });
  }

  async getPending(userId: string): Promise<ClosureRecord | null> {
    const r = this.pending.get(userId);
    return r === undefined ? null : { ...r };
  }

  async deletePending(userId: string): Promise<void> {
    this.pending.delete(userId);
  }

  async duePending(now: Date): Promise<ClosureRecord[]> {
    const due: ClosureRecord[] = [];
    for (const r of this.pending.values()) {
      if (now.getTime() >= finalizationAt(r).getTime()) {
        due.push({ ...r });
      }
    }
    due.sort((a, b) => (a.user_id < b.user_id ? -1 : a.user_id > b.user_id ? 1 : 0));
    return due;
  }

  async countPending(): Promise<number> {
    return this.pending.size;
  }

  async putFinalized(userId: string, finalizedAt: Date): Promise<void> {
    if (userId === "") {
      throw new Error("closure: store put_finalized missing user_id");
    }
    if (Number.isNaN(finalizedAt.getTime())) {
      throw new Error("closure: store put_finalized invalid timestamp");
    }
    this.finalized.set(userId, finalizedAt);
  }

  async getFinalized(userId: string): Promise<Date | null> {
    return this.finalized.get(userId) ?? null;
  }

  async pruneFinalized(retainForMs: number, now: Date = new Date()): Promise<number> {
    if (retainForMs < MinRetentionMs) {
      retainForMs = MinRetentionMs;
    }
    const cutoff = now.getTime() - retainForMs;
    let removed = 0;
    for (const [userId, finalizedAtTs] of this.finalized) {
      if (finalizedAtTs.getTime() < cutoff) {
        this.finalized.delete(userId);
        removed++;
      }
    }
    return removed;
  }
}
