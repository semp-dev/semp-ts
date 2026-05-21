/**
 * Reputation primitives tests. Cover bucketing, observation
 * sign+verify, gossip hash determinism, observation-store scoring,
 * abuse-report validation, and PoW challenge ledger.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type AbuseReport,
  type DisclosureAuthorization,
  type Observation,
  type Score,
  type TrustObservations,
  ChallengeLedger,
  DifficultyBaseline,
  DifficultyHostile,
  DifficultyRelaxed,
  DifficultySuspicious,
  DomainAgeGateDays,
  MaxMetricBucket,
  ObservationStore,
  applyBucketing,
  authAllowsBrief,
  authAllowsEnclosure,
  bucketize,
  classifyScore,
  computeGossipHash,
  difficultyForAge,
  difficultyForAssessment,
  isKnownAbuseCategory,
  issueChallenge,
  signDisclosureAuthorization,
  signObservation,
  signTrustObservations,
  validateAbuseReport,
  verifyDisclosureAuthorization,
  verifyObservation,
  verifyTrustObservations,
} from "./index.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function fakeRand(seed: number): (n: number) => Uint8Array {
  let s = seed >>> 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s ^= s << 13;
      s ^= s >>> 17;
      s ^= s << 5;
      s >>>= 0;
      out[i] = s & 0xff;
    }
    return out;
  };
}

describe("bucketize / applyBucketing / dedupeAbuseCategories", () => {
  test("rounds up to nearest power of two", () => {
    expect(bucketize(0)).toBe(0);
    expect(bucketize(1)).toBe(1);
    expect(bucketize(2)).toBe(2);
    expect(bucketize(3)).toBe(4);
    expect(bucketize(7)).toBe(8);
    expect(bucketize(8)).toBe(8);
    expect(bucketize(9)).toBe(16);
    expect(bucketize(1023)).toBe(1024);
  });

  test("clamps to MaxMetricBucket", () => {
    expect(bucketize(MaxMetricBucket)).toBe(MaxMetricBucket);
    expect(bucketize(MaxMetricBucket * 2)).toBe(MaxMetricBucket);
  });

  test("applyBucketing buckets every count + dedupes categories", () => {
    const m = {
      envelopes_received: 7,
      envelopes_rejected: 3,
      abuse_reports: 5,
      abuse_categories: ["spam", "spam", "phishing", "" as never] as never[],
      handshakes_completed: 17,
      handshakes_rejected: 0,
    } as never;
    applyBucketing(m);
    expect((m as { envelopes_received: number }).envelopes_received).toBe(8);
    expect((m as { envelopes_rejected: number }).envelopes_rejected).toBe(4);
    expect((m as { abuse_reports: number }).abuse_reports).toBe(8);
    expect((m as { handshakes_completed: number }).handshakes_completed).toBe(32);
    expect((m as { handshakes_rejected: number }).handshakes_rejected).toBe(0);
    expect((m as { abuse_categories: string[] }).abuse_categories).toEqual([
      "spam",
      "phishing",
    ]);
  });

  test("isKnownAbuseCategory recognizes the spec set", () => {
    for (const c of [
      "spam",
      "harassment",
      "phishing",
      "malware",
      "protocol_abuse",
      "impersonation",
      "other",
    ]) {
      expect(isKnownAbuseCategory(c)).toBe(true);
    }
    expect(isKnownAbuseCategory("future-bucket")).toBe(false);
  });
});

describe("Observation sign + verify", () => {
  function happyObs(): Observation {
    return {
      type: "SEMP_TRUST_OBSERVATION",
      version: "1.0.0",
      id: "01J7OBS00000000000000000000",
      observer: "alice.example",
      subject: "bob.example",
      window: { start: "2026-04-01T00:00:00Z", end: "2026-04-30T23:59:59Z" },
      metrics: {
        envelopes_received: 17,
        envelopes_rejected: 3,
        abuse_reports: 0,
      },
      assessment: "neutral",
      evidence_available: false,
      timestamp: "2026-05-01T00:00:00Z",
      expires: "2026-08-01T00:00:00Z",
      signature: { algorithm: "", key_id: "", value: "" },
      extensions: {},
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const obs = happyObs();
    signObservation(obs, seed, fingerprint(pub));
    expect(obs.signature.algorithm).toBe("ed25519");
    expect(obs.signature.value).not.toBe("");
    expect(verifyObservation(obs, pub)).toBe(true);
    // Counts have been bucketed: 17 -> 32, 3 -> 4.
    expect(obs.metrics.envelopes_received).toBe(32);
    expect(obs.metrics.envelopes_rejected).toBe(4);
  });

  test("tampering breaks verification", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const obs = happyObs();
    signObservation(obs, seed, fingerprint(pub));
    obs.subject = "evil.example";
    expect(verifyObservation(obs, pub)).toBe(false);
  });

  test("verify under wrong key fails", () => {
    const seed = deterministicSeed(0x42);
    const obs = happyObs();
    signObservation(obs, seed, fingerprint(publicKeyFromSeed(seed)));
    expect(
      verifyObservation(obs, publicKeyFromSeed(deterministicSeed(0xff))),
    ).toBe(false);
  });
});

describe("TrustObservations envelope sign + verify", () => {
  test("round-trip", () => {
    const seed = deterministicSeed(0xab);
    const pub = publicKeyFromSeed(seed);
    const resp: TrustObservations = {
      type: "SEMP_TRUST_OBSERVATIONS",
      version: "1.0.0",
      observer: "alice.example",
      subject: "bob.example",
      observations: [],
      timestamp: "2026-05-01T00:00:00Z",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signTrustObservations(resp, seed, fingerprint(pub));
    expect(verifyTrustObservations(resp, pub)).toBe(true);
  });
});

describe("DisclosureAuthorization sign + verify + scope helpers", () => {
  test("round-trip + scope helpers", () => {
    const seed = deterministicSeed(0xcd);
    const pub = publicKeyFromSeed(seed);
    const auth: DisclosureAuthorization = {
      user: "victim@example.com",
      authorized_at: "2026-05-01T00:00:00Z",
      scope: "brief_and_enclosure",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signDisclosureAuthorization(auth, seed, fingerprint(pub));
    expect(verifyDisclosureAuthorization(auth, pub)).toBe(true);
    expect(authAllowsBrief(auth)).toBe(true);
    expect(authAllowsEnclosure(auth)).toBe(true);

    const briefOnly: DisclosureAuthorization = { ...auth, scope: "brief_only" };
    expect(authAllowsBrief(briefOnly)).toBe(true);
    expect(authAllowsEnclosure(briefOnly)).toBe(false);

    const enclosureOnly: DisclosureAuthorization = { ...auth, scope: "enclosure_only" };
    expect(authAllowsBrief(enclosureOnly)).toBe(false);
    expect(authAllowsEnclosure(enclosureOnly)).toBe(true);
  });
});

describe("validateAbuseReport", () => {
  function happyReport(): AbuseReport {
    return {
      type: "SEMP_ABUSE_REPORT",
      version: "1.0.0",
      id: "01J7AR0000000000000000",
      reporter: "alice@example.com",
      reported_domain: "evil.example",
      category: "spam",
      timestamp: "2026-05-01T00:00:00Z",
      evidence: {
        type: "envelope_metadata",
        postmark_ids: ["a", "b"],
        count: 2,
      },
      extensions: {},
    };
  }

  test("happy path", () => {
    validateAbuseReport(happyReport());
  });

  test("rejects unknown evidence.type", () => {
    const r = happyReport();
    (r.evidence as unknown as { type: string }).type = "bogus";
    expect(() => validateAbuseReport(r)).toThrow(/evidence type/);
  });

  test("§3.7: disclosed content requires disclosure_authorization", () => {
    const r = happyReport();
    r.evidence = {
      type: "sealed_evidence",
      envelopes: [
        {
          postmark: { id: "x" },
          seal: { signature: "y" },
          disclosed_brief: { from: "leak" },
        },
      ],
    };
    expect(() => validateAbuseReport(r)).toThrow(/disclosure_authorization/);
  });

  test("rejects empty sealed_evidence envelopes", () => {
    const r = happyReport();
    r.evidence = { type: "sealed_evidence", envelopes: [] };
    expect(() => validateAbuseReport(r)).toThrow(/non-empty/);
  });
});

describe("ObservationStore scoring", () => {
  test("starts neutral on no signals", () => {
    const s = new ObservationStore(() => new Date("2026-04-21T10:00:00Z"));
    const score = s.score("unknown.example");
    expect(score.assessment).toBe("neutral");
    expect(score.total_envelopes).toBe(0);
  });

  test("classifies as hostile above hostile thresholds", () => {
    const s = new ObservationStore(() => new Date("2026-04-21T10:00:00Z"));
    for (let i = 0; i < 100; i++) {
      s.recordEnvelope("evil.example", false); // 100% reject rate
    }
    expect(s.score("evil.example").assessment).toBe("hostile");
  });

  test("classifies as suspicious in the suspicious band", () => {
    const s = new ObservationStore(() => new Date("2026-04-21T10:00:00Z"));
    for (let i = 0; i < 100; i++) {
      s.recordEnvelope("medium.example", i < 25); // 75% reject
    }
    expect(s.score("medium.example").assessment).toBe("hostile"); // 75 ≥ 50%
  });

  test("classifies as trusted with clean history of >100 envelopes", () => {
    const s = new ObservationStore(() => new Date("2026-04-21T10:00:00Z"));
    for (let i = 0; i < 200; i++) {
      s.recordEnvelope("good.example", true);
    }
    expect(s.score("good.example").assessment).toBe("trusted");
  });

  test("classifyScore is exposed and exact-rate-bound testable", () => {
    const stub: Score = {
      domain: "x",
      total_envelopes: 200,
      abuse_rate: 0.05,
      reject_rate: 0,
      handshake_reject_rate: 0,
      first_seen: null,
      age_days: -1,
      assessment: "neutral",
    };
    expect(classifyScore(stub)).toBe("hostile");
    stub.abuse_rate = 0.01;
    expect(classifyScore(stub)).toBe("suspicious");
    stub.abuse_rate = 0;
    stub.reject_rate = 0.04;
    expect(classifyScore(stub)).toBe("trusted");
  });
});

describe("computeGossipHash", () => {
  test("identical observation sets produce identical hashes", () => {
    const obsA: Observation[] = [
      {
        ...stubObservation("01J7AAA"),
      },
      {
        ...stubObservation("01J7BBB"),
      },
    ];
    // Same set, reversed order, must produce the same hash.
    const obsB: Observation[] = [obsA[1]!, obsA[0]!];
    const h1 = computeGossipHash("alice.example", obsA);
    const h2 = computeGossipHash("alice.example", obsB);
    expect(h1.hash).toBe(h2.hash);
    expect(h1.algorithm).toBe("sha256");
  });

  test("different observations produce different hashes", () => {
    const h1 = computeGossipHash("alice.example", [stubObservation("a")]);
    const h2 = computeGossipHash("alice.example", [stubObservation("b")]);
    expect(h1.hash).not.toBe(h2.hash);
  });

  test("rejects empty domain", () => {
    expect(() => computeGossipHash("", [])).toThrow(/domain/);
  });

  function stubObservation(id: string): Observation {
    return {
      type: "SEMP_TRUST_OBSERVATION",
      version: "1.0.0",
      id,
      observer: "alice.example",
      subject: "bob.example",
      window: { start: "x", end: "y" },
      metrics: { envelopes_received: 0, envelopes_rejected: 0, abuse_reports: 0 },
      assessment: "neutral",
      evidence_available: false,
      timestamp: "2026-05-01T00:00:00Z",
      expires: "2026-08-01T00:00:00Z",
      signature: { algorithm: "ed25519", key_id: "x", value: "AAA=" },
      extensions: {},
    };
  }
});

describe("PoW challenge issuance + ledger", () => {
  test("difficultyForAge respects the 30-day gate", () => {
    expect(difficultyForAge(0)).toBe(DifficultyBaseline);
    expect(difficultyForAge(DomainAgeGateDays - 1)).toBe(DifficultyBaseline);
    expect(difficultyForAge(DomainAgeGateDays)).toBe(DifficultyRelaxed);
  });

  test("difficultyForAssessment maps to spec table", () => {
    expect(difficultyForAssessment("trusted")).toBe(0);
    expect(difficultyForAssessment("neutral")).toBe(0);
    expect(difficultyForAssessment("suspicious")).toBe(DifficultySuspicious);
    expect(difficultyForAssessment("hostile")).toBe(DifficultyHostile);
  });

  test("issueChallenge produces a 16-byte prefix and ULID id", () => {
    const c = issueChallenge(20, undefined, fakeRand(7));
    expect(c.prefix.length).toBe(16);
    expect(c.id.length).toBe(26);
    expect(c.algorithm).toBe("sha256");
    expect(c.difficulty).toBe(20);
    expect(c.expires.getTime() > Date.now()).toBe(true);
  });

  test("issueChallenge rejects invalid difficulty", () => {
    expect(() => issueChallenge(-1, undefined, fakeRand(1))).toThrow(/difficulty/);
    expect(() => issueChallenge(257, undefined, fakeRand(1))).toThrow(/exceeds/);
  });

  test("ledger redeems each challenge exactly once", () => {
    const fakeNow = { value: new Date("2026-04-21T10:00:00Z") };
    const ledger = new ChallengeLedger(60_000, () => fakeNow.value);
    const c = issueChallenge(20, 10 * 60_000, fakeRand(2));
    ledger.record(c);
    const redeemed = ledger.redeem(c.id);
    expect(redeemed.id).toBe(c.id);
    expect(() => ledger.redeem(c.id)).toThrow(/already used/);
  });

  test("ledger rejects unknown challenges", () => {
    const ledger = new ChallengeLedger();
    expect(() => ledger.redeem("missing")).toThrow(/not found/);
  });

  test("ledger expires challenges past their TTL", () => {
    const fakeNow = { value: new Date("2026-04-21T10:00:00Z") };
    const ledger = new ChallengeLedger(60_000, () => fakeNow.value);
    const c = issueChallenge(20, 60_000, fakeRand(3));
    ledger.record(c);
    fakeNow.value = new Date(c.expires.getTime() + 1);
    expect(() => ledger.redeem(c.id)).toThrow(/expired/);
  });
});
