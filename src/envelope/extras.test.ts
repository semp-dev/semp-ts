/**
 * Tests for the new envelope primitives: encode/decode wire,
 * verifySealSignature/verifySessionMAC, openBriefAny/openEnclosureAny,
 * openAndVerify, padding, sendTimeDelay, EnvelopeRejection.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type AEADAlgorithm,
  aeadSeal,
  computeMAC,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type Envelope,
  type PostmarkFields,
  type RecipientCandidate,
  EnvelopeFileExtension,
  EnvelopeMIMEType,
  EnvelopeRejection,
  buildPaddingValue,
  compose,
  decodeEnvelope,
  encodeEnvelope,
  fillPadding,
  isEnvelopeRejection,
  openAndVerify,
  openBriefAny,
  openEnclosureAny,
  sendTimeDelay,
  verifySealSignature,
  verifySessionMAC,
} from "./index.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

interface ComposedFixture {
  env: Envelope;
  senderDomainPub: Uint8Array;
  kEnvMAC: Uint8Array;
  bobCandidate: RecipientCandidate;
}

function composeFixture(): ComposedFixture {
  // Deterministic everything for repeatability.
  const senderSeed = deterministicSeed(0x10);
  const senderPub = publicKeyFromSeed(senderSeed);

  const bobPriv = deterministicSeed(0x20);
  const bobPub = x25519PublicKey(bobPriv);
  const bobFp = fingerprint(bobPub);

  const kBrief = deterministicSeed(0x30);
  const kEnclosure = deterministicSeed(0x31);
  const kEnvMAC = deterministicSeed(0x40);

  const briefAEADNonce = new Uint8Array(12).fill(0x50);
  const enclosureAEADNonce = new Uint8Array(12).fill(0x51);

  const wrapEntry = { ephemeralX25519Priv: deterministicSeed(0x60) };
  const wrapRandomness = new Map<string, typeof wrapEntry>();
  wrapRandomness.set(bobFp, wrapEntry);
  wrapRandomness.set(`enclosure:${bobFp}`, wrapEntry);

  const postmark: PostmarkFields = {
    id: "01J7TESTPOSTMARK0000000000000",
    session_id: "01J7TESTSESSION00000000000000",
    from_domain: "alice.example",
    to_domain: "bob.example",
    expires: "2099-12-31T23:59:59Z",
    extensions: {},
  };

  const env = compose({
    suite: "x25519-chacha20-poly1305",
    sealKeyId: fingerprint(senderPub),
    senderDomainSigningSeed: senderSeed,
    postmark,
    briefPlaintext: { from: "alice@alice.example" },
    enclosurePlaintext: { body: "hello" },
    briefRecipients: [{ keyId: bobFp, publicKey: bobPub }],
    enclosureRecipients: [{ keyId: bobFp, publicKey: bobPub }],
    kBrief,
    kEnclosure,
    kEnvMAC,
    briefAEADNonce,
    enclosureAEADNonce,
    wrapRandomness,
  });

  return {
    env,
    senderDomainPub: senderPub,
    kEnvMAC,
    bobCandidate: {
      keyId: bobFp,
      privateKey: bobPriv,
      publicKey: bobPub,
    },
  };
}

describe("encode/decode envelope wire form", () => {
  test("round-trip via JSON", () => {
    const fix = composeFixture();
    const wire = encodeEnvelope(fix.env);
    const decoded = decodeEnvelope(wire);
    expect(decoded.type).toBe("SEMP_ENVELOPE");
    expect(decoded.postmark.id).toBe(fix.env.postmark.id);
    expect(decoded.seal.signature).toBe(fix.env.seal.signature);
  });

  test("decode rejects malformed JSON", () => {
    expect(() => decodeEnvelope("not-json")).toThrow(/parse/);
  });

  test("decode rejects empty input", () => {
    expect(() => decodeEnvelope("")).toThrow(/empty/);
  });

  test("decode rejects non-SEMP_ENVELOPE type", () => {
    expect(() => decodeEnvelope('{"type":"WRONG"}')).toThrow(
      /not SEMP_ENVELOPE/,
    );
  });

  test("MIME constants match spec", () => {
    expect(EnvelopeMIMEType).toBe("application/semp-envelope");
    expect(EnvelopeFileExtension).toBe(".semp");
  });
});

describe("verifySealSignature / verifySessionMAC", () => {
  test("happy path: both verify under correct keys", () => {
    const fix = composeFixture();
    expect(verifySealSignature(fix.env, fix.senderDomainPub)).toBe(true);
    expect(verifySessionMAC(fix.env, fix.kEnvMAC)).toBe(true);
  });

  test("verifySealSignature fails under wrong key", () => {
    const fix = composeFixture();
    const wrong = publicKeyFromSeed(deterministicSeed(0xff));
    expect(verifySealSignature(fix.env, wrong)).toBe(false);
  });

  test("verifySessionMAC fails under wrong K_env_mac", () => {
    const fix = composeFixture();
    expect(verifySessionMAC(fix.env, deterministicSeed(0xff))).toBe(false);
  });

  test("blank signature / mac fail", () => {
    const fix = composeFixture();
    fix.env.seal.signature = "";
    expect(verifySealSignature(fix.env, fix.senderDomainPub)).toBe(false);
    fix.env.seal.session_mac = "";
    expect(verifySessionMAC(fix.env, fix.kEnvMAC)).toBe(false);
  });
});

describe("openBriefAny / openEnclosureAny", () => {
  test("happy path with single matching candidate", () => {
    const fix = composeFixture();
    const brief = openBriefAny("x25519-chacha20-poly1305", fix.env, [
      fix.bobCandidate,
    ]);
    expect(brief.candidate.keyId).toBe(fix.bobCandidate.keyId);
    expect((brief.brief as { from: string }).from).toBe(
      "alice@alice.example",
    );

    const enc = openEnclosureAny("x25519-chacha20-poly1305", fix.env, [
      fix.bobCandidate,
    ]);
    expect((enc.enclosure as { body: string }).body).toBe("hello");
  });

  test("ignores irrelevant candidates", () => {
    const fix = composeFixture();
    const ghost: RecipientCandidate = {
      keyId: "ghost-fp",
      privateKey: deterministicSeed(0x99),
      publicKey: x25519PublicKey(deterministicSeed(0x99)),
    };
    const brief = openBriefAny("x25519-chacha20-poly1305", fix.env, [
      ghost,
      fix.bobCandidate,
    ]);
    expect(brief.candidate.keyId).toBe(fix.bobCandidate.keyId);
  });

  test("fails when no candidate matches", () => {
    const fix = composeFixture();
    const ghost: RecipientCandidate = {
      keyId: "ghost-fp",
      privateKey: deterministicSeed(0x99),
      publicKey: x25519PublicKey(deterministicSeed(0x99)),
    };
    expect(() =>
      openBriefAny("x25519-chacha20-poly1305", fix.env, [ghost]),
    ).toThrow(/no candidate matches/);
  });

  test("fails on empty candidate list", () => {
    const fix = composeFixture();
    expect(() =>
      openBriefAny("x25519-chacha20-poly1305", fix.env, []),
    ).toThrow(/empty candidate list/);
  });
});

describe("openAndVerify", () => {
  test("end-to-end: verify + open", async () => {
    const fix = composeFixture();
    const result = await openAndVerify({
      suite: "x25519-chacha20-poly1305",
      envelope: fix.env,
      candidates: [fix.bobCandidate],
      resolver: async (_domain, _keyId) => fix.senderDomainPub,
    });
    expect(result.candidate.keyId).toBe(fix.bobCandidate.keyId);
    expect((result.brief as { from: string }).from).toBe(
      "alice@alice.example",
    );
    expect((result.enclosure as { body: string }).body).toBe("hello");
  });

  test("rejects when resolver returns null", async () => {
    const fix = composeFixture();
    await expect(
      openAndVerify({
        suite: "x25519-chacha20-poly1305",
        envelope: fix.env,
        candidates: [fix.bobCandidate],
        resolver: async () => null,
      }),
    ).rejects.toThrow(/null/);
  });

  test("rejects when resolver returns wrong key", async () => {
    const fix = composeFixture();
    const wrong = publicKeyFromSeed(deterministicSeed(0xff));
    await expect(
      openAndVerify({
        suite: "x25519-chacha20-poly1305",
        envelope: fix.env,
        candidates: [fix.bobCandidate],
        resolver: async () => wrong,
      }),
    ).rejects.toThrow(/did not verify/);
  });

  test("accepts SenderKeyResolver object form", async () => {
    const fix = composeFixture();
    const result = await openAndVerify({
      suite: "x25519-chacha20-poly1305",
      envelope: fix.env,
      candidates: [fix.bobCandidate],
      resolver: {
        async lookupSenderDomainPub() {
          return fix.senderDomainPub;
        },
      },
    });
    expect(result.candidate.keyId).toBe(fix.bobCandidate.keyId);
  });
});

describe("padding (size buckets §2.4)", () => {
  test("buildPaddingValue produces exactly targetLen base64-alphabet chars", () => {
    for (const target of [0, 1, 2, 3, 4, 7, 16, 100, 1024]) {
      const out = buildPaddingValue(target, (n) =>
        new Uint8Array(n).fill(0xab),
      );
      expect(out.length).toBe(target);
      // Each char must be in the base64 alphabet.
      for (const c of out) {
        expect(/^[A-Za-z0-9+/]$/.test(c)).toBe(true);
      }
    }
  });

  test("fillPadding lands the wire size exactly on the chosen bucket", () => {
    const fix = composeFixture();
    const bucket = fillPadding(fix.env, { maxEnvelopeSize: 25 * 1024 * 1024 });
    const wireBytes = new TextEncoder().encode(JSON.stringify(fix.env)).length;
    expect(wireBytes).toBe(bucket);
    // Bucket should be a power of 2 >= 4096 (the floor).
    expect(bucket).toBeGreaterThanOrEqual(4096);
    expect((bucket & (bucket - 1)) === 0 || bucket === 25 * 1024 * 1024).toBe(
      true,
    );
  });

  test("fillPadding works pre-sign (placeholder substitution)", () => {
    const fix = composeFixture();
    fix.env.seal.signature = "";
    fix.env.seal.session_mac = "";
    fillPadding(fix.env);
    // Placeholders restored to empty strings after measurement.
    expect(fix.env.seal.signature).toBe("");
    expect(fix.env.seal.session_mac).toBe("");
  });

  test("fillPadding rejects below-floor first bucket in custom sequence", () => {
    const fix = composeFixture();
    expect(() =>
      fillPadding(fix.env, { bucketSequence: [1024, 4096] }),
    ).toThrow(/below protocol floor/);
  });
});

describe("sendTimeDelay (CLIENT.md §3.8)", () => {
  test("returns immediately when timeSensitive=true", async () => {
    const fix = composeFixture();
    const t0 = Date.now();
    await sendTimeDelay(fix.env, { ceilingMs: 60_000, timeSensitive: true });
    expect(Date.now() - t0).toBeLessThan(50);
  });

  test("returns immediately when ceiling=0", async () => {
    const fix = composeFixture();
    await sendTimeDelay(fix.env, { ceilingMs: 0 });
    // No throw, no observable delay.
  });

  test("draws random in [0, ceilingMs] honoring postmark.expires", async () => {
    const fix = composeFixture();
    const t0 = Date.now();
    await sendTimeDelay(fix.env, {
      ceilingMs: 30,
      rand: () => 0.5,
    });
    expect(Date.now() - t0).toBeGreaterThanOrEqual(10);
  });

  test("rejects an already-expired envelope", async () => {
    const fix = composeFixture();
    fix.env.postmark.expires = "2000-01-01T00:00:00Z";
    await expect(
      sendTimeDelay(fix.env, { ceilingMs: 100 }),
    ).rejects.toThrow(/already-expired/);
  });

  test("respects AbortSignal", async () => {
    const fix = composeFixture();
    const ctrl = new AbortController();
    queueMicrotask(() => ctrl.abort());
    await expect(
      sendTimeDelay(fix.env, {
        ceilingMs: 60_000,
        signal: ctrl.signal,
        rand: () => 0.99,
      }),
    ).rejects.toThrow();
  });
});

describe("EnvelopeRejection", () => {
  test("carries reason code + optional reason text", () => {
    const e = new EnvelopeRejection("policy_forbidden", "blocked sender");
    expect(e.reasonCode).toBe("policy_forbidden");
    expect(e.reasonText).toBe("blocked sender");
    expect(e.message).toContain("policy_forbidden");
    expect(e.message).toContain("blocked sender");
  });

  test("isEnvelopeRejection type guard", () => {
    const e = new EnvelopeRejection("seal_invalid");
    expect(isEnvelopeRejection(e)).toBe(true);
    expect(isEnvelopeRejection(new Error("plain"))).toBe(false);
    expect(isEnvelopeRejection(null)).toBe(false);
  });
});

// Quiet unused imports.
void aeadSeal;
void newHKDFSHA512;
void x25519Agree;
void computeMAC;
type _AEAD = AEADAlgorithm;
void 0 as unknown as _AEAD;
