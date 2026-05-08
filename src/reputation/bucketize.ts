/**
 * Metric bucketing per REPUTATION.md §4.5.1 + §4.5.2.
 *
 * Counts published on the wire are rounded UP to the nearest power
 * of two in the sequence 0, 1, 2, 4, 8, ..., 1048576. Above the cap
 * they clamp to MaxMetricBucket. AbuseCategories are deduplicated
 * (a receiver could otherwise read the array's length and recover
 * the raw `abuse_reports` count, defeating the §4.5.1 bucketing).
 *
 * @module
 */

import type { AbuseCategory, Metrics } from "./types.js";
import { MaxMetricBucket } from "./types.js";

/**
 * Round `n` up to the nearest power-of-two bucket per §4.5.1.
 * Values above {@link MaxMetricBucket} clamp to MaxMetricBucket.
 */
export function bucketize(n: number): number {
  if (!Number.isFinite(n) || n <= 0) {
    return 0;
  }
  if (n >= MaxMetricBucket) {
    return MaxMetricBucket;
  }
  let b = 1;
  while (b < n) {
    b <<= 1;
  }
  return b;
}

/**
 * Apply bucketing + abuse-category deduplication to `m` IN PLACE
 * per §4.5.1 + §4.5.2. Called by signObservation before the
 * canonical bytes are computed so the signed record carries
 * bucketed counts and a deduplicated category set.
 */
export function applyBucketing(m: Metrics): void {
  m.envelopes_received = bucketize(m.envelopes_received);
  m.envelopes_rejected = bucketize(m.envelopes_rejected);
  m.abuse_reports = bucketize(m.abuse_reports);
  if (m.unique_senders_observed !== undefined) {
    m.unique_senders_observed = bucketize(m.unique_senders_observed);
  }
  if (m.handshakes_completed !== undefined) {
    m.handshakes_completed = bucketize(m.handshakes_completed);
  }
  if (m.handshakes_rejected !== undefined) {
    m.handshakes_rejected = bucketize(m.handshakes_rejected);
  }
  m.abuse_categories = dedupeAbuseCategories(m.abuse_categories);
  if (m.abuse_categories === undefined) {
    delete m.abuse_categories;
  }
}

/**
 * Return a new array of distinct non-empty categories in
 * first-occurrence order. Returns `undefined` for empty input so
 * the JSON omits the field entirely.
 */
export function dedupeAbuseCategories(
  cats: AbuseCategory[] | undefined,
): AbuseCategory[] | undefined {
  if (cats === undefined || cats.length === 0) {
    return undefined;
  }
  const seen = new Set<AbuseCategory>();
  const out: AbuseCategory[] = [];
  for (const c of cats) {
    if (typeof c !== "string" || (c as string) === "") {
      continue;
    }
    if (seen.has(c)) {
      continue;
    }
    seen.add(c);
    out.push(c);
  }
  return out.length === 0 ? undefined : out;
}
