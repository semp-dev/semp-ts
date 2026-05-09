/**
 * Backup-bundle persistence per RECOVERY.md §2.6.
 *
 * The home server retains the user's most recent bundle plus the
 * recent superseded chain (so a client recovering after a long
 * offline period can fetch the bundle that matches whichever
 * recovery secret the user remembers). Pruning honors the §2.6
 * floor of 30 days for superseded entries.
 *
 * @module
 */

import type { BackupBundle } from "./types.js";

/**
 * Spec-mandated retention floor for superseded bundles per §2.6:
 * at least 30 days. Operators MAY use a larger value; smaller
 * values are clamped up by {@link InMemoryBundleStore.pruneSuperseded}.
 */
export const MinSupersededRetentionMs = 30 * 24 * 60 * 60 * 1000;

interface BundleRecord {
  bundle: BackupBundle;
  /** ISO 8601 UTC timestamp the bundle was superseded; "" while current. */
  supersededAt: string;
}

/** Persistence interface for backup bundles. */
export interface BundleStore {
  /**
   * Replace the current bundle for `userId`. The previous current
   * bundle (if any) becomes superseded as of `supersededAt`.
   * Throws when the new bundle's `supersedes` field doesn't point
   * at the existing current bundle's id (or when the existing
   * record's user_id doesn't match).
   */
  putCurrent(
    userId: string,
    bundle: BackupBundle,
    supersededAt: Date,
  ): Promise<void>;

  /** Fetch the current bundle for `userId`, or null when none. */
  getCurrent(userId: string): Promise<BackupBundle | null>;

  /**
   * Return every bundle (current + superseded) for `userId` in
   * descending order by created_at. Empty list when no bundles.
   */
  history(userId: string): Promise<BackupBundle[]>;

  /** Remove every bundle for `userId`. */
  deleteAll(userId: string): Promise<void>;

  /**
   * Drop superseded bundles whose `supersededAt` is older than
   * `now - retainForMs`. Values smaller than
   * {@link MinSupersededRetentionMs} are clamped up. Returns the
   * number pruned.
   */
  pruneSuperseded(retainForMs: number, now?: Date): Promise<number>;
}

/** Reference {@link BundleStore}. Single-process only. */
export class InMemoryBundleStore implements BundleStore {
  private readonly byUser = new Map<string, BundleRecord[]>();
  private readonly nowFn: () => Date;

  constructor(nowFn: () => Date = () => new Date()) {
    this.nowFn = nowFn;
  }

  async putCurrent(
    userId: string,
    bundle: BackupBundle,
    supersededAt: Date,
  ): Promise<void> {
    if (userId === "") {
      throw new Error("recovery: empty userId");
    }
    if (bundle.user_id !== userId) {
      throw new Error(
        `recovery: bundle.user_id ${JSON.stringify(bundle.user_id)} does not match ${JSON.stringify(userId)}`,
      );
    }
    const existing = this.byUser.get(userId) ?? [];
    const current = existing.find((r) => r.supersededAt === "");
    if (current === undefined) {
      // First put for this user. supersedes MUST be null.
      if (bundle.supersedes !== null && bundle.supersedes !== "") {
        throw new Error(
          `recovery: initial bundle for ${userId} sets supersedes=${JSON.stringify(bundle.supersedes)}; expected null`,
        );
      }
    } else {
      if (bundle.supersedes !== current.bundle.bundle_id) {
        throw new Error(
          `recovery: bundle.supersedes ${JSON.stringify(bundle.supersedes)} does not match current bundle id ${JSON.stringify(current.bundle.bundle_id)}`,
        );
      }
      current.supersededAt = supersededAt.toISOString().replace(/\.\d{3}Z$/, "Z");
    }
    existing.push({ bundle: deepClone(bundle), supersededAt: "" });
    this.byUser.set(userId, existing);
  }

  async getCurrent(userId: string): Promise<BackupBundle | null> {
    const list = this.byUser.get(userId);
    if (list === undefined) {
      return null;
    }
    const cur = list.find((r) => r.supersededAt === "");
    return cur === undefined ? null : deepClone(cur.bundle);
  }

  async history(userId: string): Promise<BackupBundle[]> {
    const list = this.byUser.get(userId) ?? [];
    return [...list]
      .sort((a, b) => {
        const ax = Date.parse(a.bundle.created_at);
        const bx = Date.parse(b.bundle.created_at);
        return bx - ax;
      })
      .map((r) => deepClone(r.bundle));
  }

  async deleteAll(userId: string): Promise<void> {
    this.byUser.delete(userId);
  }

  async pruneSuperseded(
    retainForMs: number,
    now?: Date,
  ): Promise<number> {
    if (retainForMs < MinSupersededRetentionMs) {
      retainForMs = MinSupersededRetentionMs;
    }
    const cutoff = (now ?? this.nowFn()).getTime() - retainForMs;
    let pruned = 0;
    for (const [user, list] of this.byUser) {
      const next = list.filter((r) => {
        if (r.supersededAt === "") {
          return true; // current bundle: always retain
        }
        const ts = Date.parse(r.supersededAt);
        if (Number.isNaN(ts)) {
          return true; // malformed — be conservative
        }
        if (ts < cutoff) {
          pruned++;
          return false;
        }
        return true;
      });
      if (next.length === 0) {
        this.byUser.delete(user);
      } else {
        this.byUser.set(user, next);
      }
    }
    return pruned;
  }
}

function deepClone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}
