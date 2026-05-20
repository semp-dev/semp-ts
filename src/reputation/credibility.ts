/**
 * Consumer-side observation weighting per REPUTATION.md §5.5.4 /
 * draft-gokce-semp-delivery §11.8.
 *
 * A consumer aggregating observations from multiple peers SHOULD
 * weight each observation by its locally-computed credibility for
 * the publishing observer. Inputs to credibility are
 * implementation-defined and include:
 *
 *  - Evidence-hash verification rate.
 *  - Alignment with the consumer's own direct experience.
 *  - Schema conformance history.
 *  - Observer domain-stability signals.
 *
 * Per §5.5.4 consumer credibility is per-consumer local state. A
 * consumer MUST NOT publish or share credibility scores about
 * other observers as part of trust gossip or any other SEMP wire
 * artifact. Shared scores would introduce transitive trust, which
 * is incompatible with the no-transitive-trust principle.
 *
 * The {@link CredibilityLedger} class is in-memory by design and
 * does not expose serialization helpers.
 *
 * @module
 */

import type { Observation } from "./types.js";

/**
 * Starting credibility weight applied to an observer the consumer
 * has no prior signals for. Conservative middle value.
 */
export const DefaultCredibility = 0.5;

/**
 * Per-consumer local store of observer credibility weights in
 * [0, 1]. Intentionally in-memory; never published.
 */
export class CredibilityLedger {
  private readonly scores = new Map<string, number>();

  /** Record a credibility score for `observer`. Clamps into [0, 1]. */
  set(observer: string, score: number): void {
    if (observer === "") {
      return;
    }
    let clamped = score;
    if (clamped < 0) clamped = 0;
    if (clamped > 1) clamped = 1;
    this.scores.set(observer, clamped);
  }

  /** Recorded credibility for `observer`, or {@link DefaultCredibility} when unknown. */
  get(observer: string): number {
    if (observer === "") {
      return DefaultCredibility;
    }
    return this.scores.get(observer) ?? DefaultCredibility;
  }

  /**
   * Fold a list of observations into a single weighted-mean
   * value. `metric` extracts the scalar to aggregate from one
   * observation (typical: abuse_rate, reject_rate, etc.).
   *
   * Returns 0 when observations is empty or when every observation
   * has zero credibility.
   */
  weightedAggregate(
    observations: Observation[],
    metric: (o: Observation) => number,
  ): number {
    if (observations.length === 0) {
      return 0;
    }
    let weighted = 0;
    let total = 0;
    for (const o of observations) {
      const w = this.get(o.observer);
      if (w === 0) {
        continue;
      }
      weighted += metric(o) * w;
      total += w;
    }
    if (total === 0) {
      return 0;
    }
    return weighted / total;
  }
}
