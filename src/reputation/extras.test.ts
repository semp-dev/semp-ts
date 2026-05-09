/**
 * Tests for the post-mirror reputation primitives:
 * whois floor, abuse-report builder, evidence validator,
 * trust-gossip HTTP fetch.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  newAbuseReport,
  validateEvidence,
} from "./abuse_report.js";
import { fetchTrustObservations } from "./gossip_fetch.js";
import {
  signDisclosureAuthorization,
  signTrustObservations,
} from "./sign.js";
import {
  type DisclosureAuthorization,
  type Evidence,
  type TrustObservations,
  ObservationsEnvelopeType,
  Version,
} from "./types.js";
import { MinDomainAgeMs, meetsMinAge } from "./whois.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

describe("WHOIS floor", () => {
  test("MinDomainAgeMs is 30 days", () => {
    expect(MinDomainAgeMs).toBe(30 * 24 * 3_600 * 1_000);
  });

  test("meetsMinAge", () => {
    expect(meetsMinAge(0)).toBe(false);
    expect(meetsMinAge(MinDomainAgeMs - 1)).toBe(false);
    expect(meetsMinAge(MinDomainAgeMs)).toBe(true);
    expect(meetsMinAge(MinDomainAgeMs * 2)).toBe(true);
  });
});

describe("newAbuseReport", () => {
  test("populates type/version/timestamp/extensions", () => {
    const r = newAbuseReport({
      id: "01JAR",
      reporter: "alice@example.com",
      reported_domain: "bad.com",
      reported_address: "spammer@bad.com",
      category: "spam",
      evidence: {
        type: "envelope_metadata",
        postmark_ids: ["env-1", "env-2"],
        count: 2,
      },
      description: "received 2 spammy envelopes",
      nowFn: () => new Date("2026-05-08T10:00:00Z"),
    });
    expect(r.type).toBe("SEMP_ABUSE_REPORT");
    expect(r.version).toBe(Version);
    expect(r.timestamp).toBe("2026-05-08T10:00:00Z");
    expect(r.extensions).toEqual({});
    expect(r.reported_address).toBe("spammer@bad.com");
    expect(r.description).toBe("received 2 spammy envelopes");
  });

  test("rejects missing fields", () => {
    expect(() =>
      newAbuseReport({
        id: "",
        reporter: "x@y",
        reported_domain: "y",
        category: "spam",
        evidence: { type: "envelope_metadata" },
      }),
    ).toThrow(/id/);
    expect(() =>
      newAbuseReport({
        id: "01JAR",
        reporter: "",
        reported_domain: "y",
        category: "spam",
        evidence: { type: "envelope_metadata" },
      }),
    ).toThrow(/reporter/);
    expect(() =>
      newAbuseReport({
        id: "01JAR",
        reporter: "x@y",
        reported_domain: "",
        category: "spam",
        evidence: { type: "envelope_metadata" },
      }),
    ).toThrow(/reported_domain/);
    expect(() =>
      newAbuseReport({
        id: "01JAR",
        reporter: "x@y",
        reported_domain: "y",
        category: "",
        evidence: { type: "envelope_metadata" },
      }),
    ).toThrow(/category/);
  });
});

describe("validateEvidence", () => {
  test("metadata-only is always acceptable", async () => {
    const ev: Evidence = {
      type: "envelope_metadata",
      postmark_ids: ["env-1"],
      count: 1,
    };
    await expect(validateEvidence(ev, null)).resolves.toBeUndefined();
  });

  test("sealed evidence with no decrypted content is acceptable", async () => {
    const ev: Evidence = {
      type: "sealed_evidence",
      envelopes: [
        {
          postmark: { id: "env-1" },
          seal: { algorithm: "x" },
        },
      ],
    };
    await expect(validateEvidence(ev, null)).resolves.toBeUndefined();
  });

  test("disclosed brief without authorization fails", async () => {
    const ev: Evidence = {
      type: "sealed_evidence",
      envelopes: [
        {
          postmark: { id: "env-1" },
          seal: { algorithm: "x" },
          disclosed_brief: { from: "alice" },
        },
      ],
    };
    await expect(validateEvidence(ev, null)).rejects.toThrow(
      /without disclosure authorization/,
    );
  });

  test("brief disclosure outside scope fails", async () => {
    const userSeed = seed(0xa1);
    const userPub = publicKeyFromSeed(userSeed);
    const userFp = fingerprint(userPub);
    const auth: DisclosureAuthorization = {
      user: "alice@example.com",
      authorized_at: "2026-05-08T10:00:00Z",
      scope: "enclosure_only", // does NOT cover brief
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signDisclosureAuthorization(auth, userSeed, userFp);
    const ev: Evidence = {
      type: "sealed_evidence",
      envelopes: [
        {
          postmark: { id: "env-1" },
          seal: { algorithm: "x" },
          disclosed_brief: { from: "alice" },
          disclosure_authorization: auth,
        },
      ],
    };
    await expect(
      validateEvidence(ev, async () => userPub),
    ).rejects.toThrow(/brief disclosure outside authorized scope/);
  });

  test("happy path: properly scoped + signed authorization passes", async () => {
    const userSeed = seed(0xb2);
    const userPub = publicKeyFromSeed(userSeed);
    const userFp = fingerprint(userPub);
    const auth: DisclosureAuthorization = {
      user: "alice@example.com",
      authorized_at: "2026-05-08T10:00:00Z",
      scope: "brief_and_enclosure",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signDisclosureAuthorization(auth, userSeed, userFp);
    const ev: Evidence = {
      type: "sealed_evidence",
      envelopes: [
        {
          postmark: { id: "env-1" },
          seal: { algorithm: "x" },
          disclosed_brief: { from: "alice" },
          disclosed_enclosure: { body: "spam" },
          disclosure_authorization: auth,
        },
      ],
    };
    await expect(
      validateEvidence(ev, async () => userPub),
    ).resolves.toBeUndefined();
  });

  test("unknown user lookup fails", async () => {
    const userSeed = seed(0xc3);
    const userPub = publicKeyFromSeed(userSeed);
    const userFp = fingerprint(userPub);
    const auth: DisclosureAuthorization = {
      user: "alice@example.com",
      authorized_at: "2026-05-08T10:00:00Z",
      scope: "brief_only",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signDisclosureAuthorization(auth, userSeed, userFp);
    const ev: Evidence = {
      type: "sealed_evidence",
      envelopes: [
        {
          postmark: { id: "env-1" },
          seal: { algorithm: "x" },
          disclosed_brief: { from: "alice" },
          disclosure_authorization: auth,
        },
      ],
    };
    void userPub;
    await expect(
      validateEvidence(ev, async () => null),
    ).rejects.toThrow(/unknown user/);
  });

  test("metadata-only with no user key lookup is fine", async () => {
    const ev: Evidence = {
      type: "envelope_metadata",
      postmark_ids: ["env-1"],
      count: 1,
    };
    await expect(validateEvidence(ev, null)).resolves.toBeUndefined();
  });
});

describe("fetchTrustObservations", () => {
  function makeFetchImpl(envelope: TrustObservations) {
    return async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify(envelope),
    });
  }

  test("happy path: fetches, parses, verifies envelope sig", async () => {
    const obsSeed = seed(0xd4);
    const obsPub = publicKeyFromSeed(obsSeed);
    const obsFp = fingerprint(obsPub);
    const env: TrustObservations = {
      type: ObservationsEnvelopeType,
      version: Version,
      observer: "watcher.example.com",
      subject: "bad.com",
      observations: [],
      timestamp: "2026-05-08T10:00:00Z",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signTrustObservations(env, obsSeed, obsFp);
    const out = await fetchTrustObservations(
      "watcher.example.com",
      "bad.com",
      obsPub,
      { fetchImpl: makeFetchImpl(env) },
    );
    expect(out.subject).toBe("bad.com");
  });

  test("rejects bad observer pub", async () => {
    const obsSeed = seed(0xe5);
    const obsPub = publicKeyFromSeed(obsSeed);
    const obsFp = fingerprint(obsPub);
    const wrongPub = publicKeyFromSeed(seed(0xf6));
    const env: TrustObservations = {
      type: ObservationsEnvelopeType,
      version: Version,
      observer: "watcher.example.com",
      subject: "bad.com",
      observations: [],
      timestamp: "2026-05-08T10:00:00Z",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signTrustObservations(env, obsSeed, obsFp);
    await expect(
      fetchTrustObservations(
        "watcher.example.com",
        "bad.com",
        wrongPub,
        { fetchImpl: makeFetchImpl(env) },
      ),
    ).rejects.toThrow(/signature did not verify/);
  });

  test("rejects HTTP error", async () => {
    const obsPub = publicKeyFromSeed(seed(0x77));
    await expect(
      fetchTrustObservations("w.com", "s.com", obsPub, {
        fetchImpl: async () => ({
          ok: false,
          status: 503,
          headers: { get: () => null },
          text: async () => "",
        }),
      }),
    ).rejects.toThrow(/HTTP 503/);
  });

  test("rejects body cap overflow", async () => {
    const obsSeed = seed(0x88);
    const obsPub = publicKeyFromSeed(obsSeed);
    const obsFp = fingerprint(obsPub);
    const env: TrustObservations = {
      type: ObservationsEnvelopeType,
      version: Version,
      observer: "w.com",
      subject: "s.com",
      observations: [],
      timestamp: "2026-05-08T10:00:00Z",
      signature: { algorithm: "", key_id: "", value: "" },
    };
    signTrustObservations(env, obsSeed, obsFp);
    await expect(
      fetchTrustObservations("w.com", "s.com", obsPub, {
        fetchImpl: makeFetchImpl(env),
        maxBytes: 1,
      }),
    ).rejects.toThrow(/exceeds 1 bytes/);
  });

  test("rejects empty observer / subject / pub", async () => {
    const pub = publicKeyFromSeed(seed(0x99));
    await expect(fetchTrustObservations("", "s.com", pub)).rejects.toThrow(
      /empty observer/,
    );
    await expect(fetchTrustObservations("w.com", "", pub)).rejects.toThrow(
      /empty subject/,
    );
    await expect(
      fetchTrustObservations("w.com", "s.com", new Uint8Array()),
    ).rejects.toThrow(/empty observer public key/);
  });
});
