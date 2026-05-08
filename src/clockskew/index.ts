/**
 * Tiered clock-skew tolerance per CONFORMANCE.md §9.3.
 *
 * SEMP timestamps appear in many places: postmark.expires, PoW
 * challenge expires, session expires_at, block list sync timestamps,
 * queue state records, backup bundle created_at, migration
 * migrated_at, forwarder attestations, and delegated certificate
 * lifetimes. Every validator MUST enforce a consistent tolerance.
 *
 * Tiers:
 *   - Future-dated: MUST reject if T > now + 15 min; SHOULD reject
 *     if T > now + 5 min; MUST accept T within 0..5 min of now.
 *   - Expired:      MUST reject when now > T + 15 min; SHOULD reject
 *     at now > T; MAY grace 5 min.
 *
 * Senders MUST NOT rely on grace windows. Senders MUST set expiry
 * far enough in the future that a well-behaved verifier accepts
 * them without grace.
 *
 * @module
 */

/** Clock-skew tolerance, in milliseconds on each side. */
export interface Tolerance {
  /** Maximum (T - now) accepted for a future-dated timestamp. */
  forwardMs: number;
  /** Maximum (now - T) accepted for an expired timestamp. */
  graceMs: number;
}

/**
 * MUST-level tolerance: 15 minutes on either side. Matches the
 * boundary CONFORMANCE.md §9.3.1 sets as the hard reject threshold.
 */
export function defaultTolerance(): Tolerance {
  return { forwardMs: 15 * 60 * 1000, graceMs: 15 * 60 * 1000 };
}

/**
 * SHOULD-level tolerance: 5 minutes future, no grace on expiry.
 * Verifiers that want the tighter SHOULD interpretation use this.
 */
export function strictTolerance(): Tolerance {
  return { forwardMs: 5 * 60 * 1000, graceMs: 0 };
}

/**
 * Check that `t` is not too far in the future relative to `now`.
 * Returns null on accept; an Error on reject. A timestamp at or
 * before `now` is always accepted (past timestamps are the expiry
 * path, not the future-dated path).
 */
export function checkFutureTimestamp(
  t: Date,
  now: Date,
  tol: Tolerance,
): Error | null {
  if (t.getTime() <= now.getTime()) {
    return null;
  }
  if (t.getTime() - now.getTime() > tol.forwardMs) {
    return new Error(
      `clockskew: timestamp ${t.toISOString()} is more than ${tol.forwardMs}ms in the future of ${now.toISOString()}`,
    );
  }
  return null;
}

/**
 * Check that `expiresAt` is not too far in the past relative to
 * `now`. Returns null on accept; an Error on reject. A timestamp
 * after `now` is always accepted.
 */
export function checkExpiry(
  expiresAt: Date,
  now: Date,
  tol: Tolerance,
): Error | null {
  if (now.getTime() <= expiresAt.getTime() + tol.graceMs) {
    return null;
  }
  return new Error(
    `clockskew: expiry ${expiresAt.toISOString()} is more than ${tol.graceMs}ms in the past of ${now.toISOString()}`,
  );
}
