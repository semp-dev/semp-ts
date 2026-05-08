/**
 * Per-domain signal ledger + Score derivation per REPUTATION.md §4.
 *
 * The store records raw counters as they happen (one call per
 * handshake/envelope/abuse) and exposes a {@link Score} query that
 * turns the counters into a Score + {@link Assessment} + the
 * "currently suspicious" verdict operators plug into their PoW
 * policy hook.
 *
 * Production deployments wrap a durable backend; this is the
 * reference in-memory store.
 *
 * @module
 */

import type { AbuseCategory, Assessment, Metrics } from "./types.js";

/** Domain counters block. */
interface DomainCounters {
  handshakes_completed: number;
  handshakes_rejected: number;
  envelopes_accepted: number;
  envelopes_rejected: number;
  abuse_reports: number;
  abuse_categories: AbuseCategory[];
}

/** Derived reputation verdict per §4.6. */
export interface Score {
  domain: string;
  total_envelopes: number;
  /** [0, 1]. Zero when total_envelopes is zero. */
  abuse_rate: number;
  /** [0, 1]. */
  reject_rate: number;
  /** [0, 1] over handshakes attempted. */
  handshake_reject_rate: number;
  /** First time any signal was recorded. `null` if unobserved. */
  first_seen: Date | null;
  /** Whole-day age, or -1 if first_seen is null. */
  age_days: number;
  assessment: Assessment;
}

/** In-memory {@link ObservationStore}. Single-process. */
export class ObservationStore {
  private readonly domains = new Map<string, DomainCounters>();
  private readonly firstSeen = new Map<string, Date>();
  private readonly nowFn: () => Date;

  constructor(nowFn: () => Date = () => new Date()) {
    this.nowFn = nowFn;
  }

  /** Record one handshake outcome. */
  recordHandshake(domain: string, ok: boolean): void {
    const c = this.touch(domain);
    if (ok) {
      c.handshakes_completed++;
    } else {
      c.handshakes_rejected++;
    }
  }

  /** Record one envelope outcome. */
  recordEnvelope(domain: string, accepted: boolean): void {
    const c = this.touch(domain);
    if (accepted) {
      c.envelopes_accepted++;
    } else {
      c.envelopes_rejected++;
    }
  }

  /**
   * Record one abuse report. The caller is expected to have
   * verified the report's authenticity and any embedded disclosure
   * authorization before calling.
   */
  recordAbuseReport(domain: string, category: AbuseCategory | ""): void {
    const c = this.touch(domain);
    c.abuse_reports++;
    if (category !== "") {
      c.abuse_categories.push(category);
    }
  }

  /** Snapshot of the current counters as a publishable {@link Metrics}. */
  metrics(domain: string): Metrics {
    const c = this.domains.get(normalize(domain));
    if (c === undefined) {
      return {
        envelopes_received: 0,
        envelopes_rejected: 0,
        abuse_reports: 0,
      };
    }
    const m: Metrics = {
      envelopes_received: c.envelopes_accepted + c.envelopes_rejected,
      envelopes_rejected: c.envelopes_rejected,
      abuse_reports: c.abuse_reports,
      handshakes_completed: c.handshakes_completed,
      handshakes_rejected: c.handshakes_rejected,
    };
    if (c.abuse_categories.length > 0) {
      m.abuse_categories = c.abuse_categories.slice();
    }
    return m;
  }

  /** Compute the current {@link Score} for `domain`. */
  score(domain: string): Score {
    const d = normalize(domain);
    const c = this.domains.get(d);
    const firstSeen = this.firstSeen.get(d) ?? null;
    const ageDays = firstSeen === null
      ? -1
      : Math.floor(
          (this.nowFn().getTime() - firstSeen.getTime()) / (1000 * 60 * 60 * 24),
        );
    if (c === undefined) {
      return {
        domain,
        total_envelopes: 0,
        abuse_rate: 0,
        reject_rate: 0,
        handshake_reject_rate: 0,
        first_seen: firstSeen,
        age_days: ageDays,
        assessment: "neutral",
      };
    }
    const total = c.envelopes_accepted + c.envelopes_rejected;
    const handshakes = c.handshakes_completed + c.handshakes_rejected;
    const score: Score = {
      domain,
      total_envelopes: total,
      abuse_rate: total > 0 ? c.abuse_reports / total : 0,
      reject_rate: total > 0 ? c.envelopes_rejected / total : 0,
      handshake_reject_rate: handshakes > 0 ? c.handshakes_rejected / handshakes : 0,
      first_seen: firstSeen,
      age_days: ageDays,
      assessment: "neutral",
    };
    score.assessment = classifyScore(score);
    return score;
  }

  /** Clear all counters for `domain`. */
  reset(domain: string): void {
    const d = normalize(domain);
    this.domains.delete(d);
    this.firstSeen.delete(d);
  }

  /** Number of domains with at least one recorded signal. */
  size(): number {
    return this.domains.size;
  }

  private touch(domain: string): DomainCounters {
    const d = normalize(domain);
    let c = this.domains.get(d);
    if (c === undefined) {
      c = {
        handshakes_completed: 0,
        handshakes_rejected: 0,
        envelopes_accepted: 0,
        envelopes_rejected: 0,
        abuse_reports: 0,
        abuse_categories: [],
      };
      this.domains.set(d, c);
      this.firstSeen.set(d, this.nowFn());
    }
    return c;
  }
}

/**
 * Default scoring curve (REPUTATION.md §4.6 + §8.3.2):
 *
 *  - abuse_rate ≥ 0.05 OR reject_rate ≥ 0.50 → hostile
 *  - abuse_rate ≥ 0.01 OR reject_rate ≥ 0.20 → suspicious
 *  - abuse_rate == 0 AND reject_rate < 0.05 AND total ≥ 100 → trusted
 *  - otherwise → neutral
 */
export function classifyScore(s: Score): Assessment {
  const HOSTILE_ABUSE = 0.05;
  const HOSTILE_REJECT = 0.5;
  const SUSPICIOUS_ABUSE = 0.01;
  const SUSPICIOUS_REJECT = 0.2;
  const TRUSTED_MIN_ENVELOPES = 100;
  const TRUSTED_MAX_REJECT = 0.05;
  if (s.abuse_rate >= HOSTILE_ABUSE || s.reject_rate >= HOSTILE_REJECT) {
    return "hostile";
  }
  if (s.abuse_rate >= SUSPICIOUS_ABUSE || s.reject_rate >= SUSPICIOUS_REJECT) {
    return "suspicious";
  }
  if (
    s.total_envelopes >= TRUSTED_MIN_ENVELOPES &&
    s.abuse_rate === 0 &&
    s.reject_rate < TRUSTED_MAX_REJECT
  ) {
    return "trusted";
  }
  return "neutral";
}

function normalize(domain: string): string {
  return domain.trim().toLowerCase();
}
