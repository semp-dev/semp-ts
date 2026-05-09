/**
 * Local-part lockout registry per MIGRATION.md §6.
 *
 * After a cooperative migration finalizes, the old provider MUST
 * lock out the old local-part for the duration of the forwarding
 * window so a different account cannot be reassigned the old
 * address while forwarding is still expected to honor it.
 *
 * @module
 */

/** Reservation record held by the registry. */
export interface LockoutReservation {
  localpart: string;
  /** ISO 8601 UTC. */
  until: string;
  /** record_id of the migration record that triggered the lockout. */
  recordId: string;
}

/** Persistence interface for lockout state. */
export interface LockoutRegistry {
  /**
   * Reserve `localpart` until `until`, attributed to `recordId`.
   * Throws when the local-part is already reserved.
   */
  reserve(
    localpart: string,
    until: Date,
    recordId: string,
  ): Promise<void>;

  /**
   * Report whether `localpart` is currently locked out at `now`.
   * Returns the active reservation or null when none exists / has
   * already expired.
   */
  isLockedOut(
    localpart: string,
    now: Date,
  ): Promise<LockoutReservation | null>;

  /** Clear the reservation for `localpart`. Idempotent. */
  release(localpart: string): Promise<void>;

  /**
   * Drop reservations whose `until` is at or before `now`.
   * Returns the number pruned.
   */
  pruneExpired(now: Date): Promise<number>;
}

/** Reference {@link LockoutRegistry}. Single-process only. */
export class InMemoryLockoutRegistry implements LockoutRegistry {
  private readonly entries = new Map<string, LockoutReservation>();

  async reserve(
    localpart: string,
    until: Date,
    recordId: string,
  ): Promise<void> {
    if (localpart === "") {
      throw new Error("migration: empty localpart");
    }
    const key = localpart.toLowerCase();
    if (this.entries.has(key)) {
      const existing = this.entries.get(key)!;
      throw new Error(
        `migration: localpart ${JSON.stringify(localpart)} already locked out until ${existing.until} (record ${existing.recordId})`,
      );
    }
    this.entries.set(key, {
      localpart,
      until: until.toISOString(),
      recordId,
    });
  }

  async isLockedOut(
    localpart: string,
    now: Date,
  ): Promise<LockoutReservation | null> {
    const key = localpart.toLowerCase();
    const r = this.entries.get(key);
    if (r === undefined) {
      return null;
    }
    const untilMs = Date.parse(r.until);
    if (Number.isNaN(untilMs) || untilMs <= now.getTime()) {
      this.entries.delete(key);
      return null;
    }
    return { ...r };
  }

  async release(localpart: string): Promise<void> {
    this.entries.delete(localpart.toLowerCase());
  }

  async pruneExpired(now: Date): Promise<number> {
    let pruned = 0;
    for (const [key, r] of this.entries) {
      const untilMs = Date.parse(r.until);
      if (Number.isNaN(untilMs) || untilMs <= now.getTime()) {
        this.entries.delete(key);
        pruned++;
      }
    }
    return pruned;
  }
}
