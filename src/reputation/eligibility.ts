/**
 * Publication eligibility helpers per REPUTATION.md §4.6.2 /
 * draft-gokce-semp-delivery §11.7.
 *
 * A server SHOULD NOT publish an observation about a subject
 * domain unless it has directly observed enough interaction with
 * the subject to back the metrics. The two publisher-side gates:
 *
 *  - At least {@link MinPublishVolumeEnvelopes} envelopes (or
 *    equivalent handshake attempts) observed during the window.
 *  - At least one metrics field non-zero. Records with uniformly
 *    zero metrics MUST NOT be published.
 *
 * A consumer that receives an observation violating either rule
 * SHOULD treat the publishing observer as a candidate for
 * `observation_record_abuse` reporting per §3.4.
 *
 * @module
 */

import type { Metrics } from "./types.js";

/**
 * §4.6.2 RECOMMENDED minimum number of envelopes (or handshake
 * attempts) the observer should have observed during the window
 * before publishing an observation about a subject domain.
 */
export const MinPublishVolumeEnvelopes = 16;

/**
 * Reports whether the metrics carry at least
 * {@link MinPublishVolumeEnvelopes} envelopes or handshake
 * attempts (post-bucketing).
 */
export function meetsPublishVolume(m: Metrics): boolean {
  const total =
    (m.envelopes_received ?? 0) +
    (m.handshakes_completed ?? 0) +
    (m.handshakes_rejected ?? 0);
  return total >= MinPublishVolumeEnvelopes;
}

/**
 * Reports whether every metric field is zero and
 * `abuse_categories` is empty.
 */
export function allMetricsZero(m: Metrics): boolean {
  return (
    (m.envelopes_received ?? 0) === 0 &&
    (m.envelopes_rejected ?? 0) === 0 &&
    (m.abuse_reports ?? 0) === 0 &&
    (m.unique_senders_observed ?? 0) === 0 &&
    (m.handshakes_completed ?? 0) === 0 &&
    (m.handshakes_rejected ?? 0) === 0 &&
    (m.abuse_categories === undefined || m.abuse_categories.length === 0)
  );
}

/**
 * Convenience predicate: true when the metrics satisfy both the
 * volume threshold and the non-all-zero rule. Publishers SHOULD
 * gate every outgoing observation on this check.
 */
export function eligibleForPublication(m: Metrics): boolean {
  return meetsPublishVolume(m) && !allMetricsZero(m);
}
