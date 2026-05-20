/**
 * Persistent silent recipient state per
 * draft-gokce-semp-delivery §4.5 / DELIVERY.md §2.5.
 *
 * After repeated `silent` outcomes for the same recipient the
 * sending server tightens its retry deadline so it does not waste
 * effort retrying a recipient that consistently fails to
 * acknowledge.
 *
 * The state is purely sender-side. It MUST NOT be transmitted on
 * the wire and MUST NOT be published as a trust-gossip observation.
 * Two senders correctly disagree on which recipients are
 * persistently silent because each only sees its own envelopes.
 *
 * @module
 */

/** §4.5 spec defaults. */
export const PersistentSilentDefaults = {
  /** Consecutive silents required before tightening engages. */
  threshold: 5,
  /** Minimum observation window before tightening engages. */
  observationWindowMs: 24 * 60 * 60 * 1000,
  /** Tightened retry deadline once the trigger fires. */
  shortDeadlineMs: 4 * 60 * 60 * 1000,
  /** Idle expiry after which the counter for a recipient is dropped. */
  idleExpiryMs: 30 * 24 * 60 * 60 * 1000,
} as const;

/** Counter configuration. Zero / undefined falls back to the spec defaults. */
export interface PersistentSilentConfig {
  threshold?: number;
  observationWindowMs?: number;
  shortDeadlineMs?: number;
  idleExpiryMs?: number;
}

interface PersistentSilentEntry {
  count: number;
  firstSeenMs: number;
  lastSeenMs: number;
}

/**
 * Sender-side ledger of per-recipient silent-acknowledgment
 * counters.
 *
 * Usage:
 *
 *  - `inc(addr, now)` on every `silent` outcome.
 *  - `reset(addr)` on every non-silent outcome (delivered /
 *    rejected).
 *  - `effective(addr, now)` returns the tightened retry deadline
 *    (in ms) once the count + observation-window thresholds are
 *    met, or null to keep the caller's default.
 *  - `pruneExpired(now)` on a janitor cadence so the map does not
 *    grow without bound.
 */
export class PersistentSilentCounter {
  private readonly cfg: Required<PersistentSilentConfig>;
  private readonly entries = new Map<string, PersistentSilentEntry>();

  constructor(cfg: PersistentSilentConfig = {}) {
    this.cfg = {
      threshold: cfg.threshold && cfg.threshold > 0
        ? cfg.threshold
        : PersistentSilentDefaults.threshold,
      observationWindowMs:
        cfg.observationWindowMs && cfg.observationWindowMs > 0
          ? cfg.observationWindowMs
          : PersistentSilentDefaults.observationWindowMs,
      shortDeadlineMs:
        cfg.shortDeadlineMs && cfg.shortDeadlineMs > 0
          ? cfg.shortDeadlineMs
          : PersistentSilentDefaults.shortDeadlineMs,
      idleExpiryMs:
        cfg.idleExpiryMs && cfg.idleExpiryMs > 0
          ? cfg.idleExpiryMs
          : PersistentSilentDefaults.idleExpiryMs,
    };
  }

  /** Record one silent outcome for `recipient` at `now`. Returns the running count. */
  inc(recipient: string, now: Date): number {
    if (recipient === "") {
      return 0;
    }
    const t = now.getTime();
    const e = this.entries.get(recipient);
    if (e === undefined) {
      this.entries.set(recipient, { count: 1, firstSeenMs: t, lastSeenMs: t });
      return 1;
    }
    e.count++;
    e.lastSeenMs = t;
    return e.count;
  }

  /** Clear the counter for `recipient`. Idempotent on missing entries. */
  reset(recipient: string): void {
    this.entries.delete(recipient);
  }

  /**
   * Returns the §4.5 shortened deadline (in ms) once the count and
   * minimum-observation-window thresholds are met. Returns null
   * when the trigger has not fired yet - caller falls back to its
   * default per-envelope deadline.
   */
  effective(recipient: string, now: Date): number | null {
    const e = this.entries.get(recipient);
    if (e === undefined) {
      return null;
    }
    if (e.count < this.cfg.threshold) {
      return null;
    }
    if (now.getTime() - e.firstSeenMs < this.cfg.observationWindowMs) {
      return null;
    }
    return this.cfg.shortDeadlineMs;
  }

  /** Current silent count for `recipient`. */
  count(recipient: string): number {
    return this.entries.get(recipient)?.count ?? 0;
  }

  /** Drop entries whose lastSeen is older than IdleExpiry. Returns the removed count. */
  pruneExpired(now: Date): number {
    const t = now.getTime();
    let removed = 0;
    for (const [k, e] of this.entries) {
      if (t - e.lastSeenMs >= this.cfg.idleExpiryMs) {
        this.entries.delete(k);
        removed++;
      }
    }
    return removed;
  }
}
