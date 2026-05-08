/**
 * Device certificate tests. Cover sign/verify roundtrip, structural
 * validation, scope-mode enforcement, and the scope-check helpers
 * for `send` and `receive` matchers.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type DeviceCertificate,
  type RateLimitTier,
  type Scope,
  type ScopeEntry,
  type ScopeMatcher,
  type ScopeResource,
  MaxScopeMatcherEntries,
  MaxScopeRateLimitTiers,
  scopeAllowsRecipient,
  scopeAllowsSender,
  signDeviceCertificate,
  validateDeviceCertificate,
  validateScope,
  verifyDeviceCertificate,
} from "./device_certificate.js";
import { fingerprint, publicKeyFromSeed } from "./sign.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function noPermResource(): ScopeResource {
  return { read: false, write: false, rate_limits: [] };
}

function happyScope(): Scope {
  return {
    send: {
      mode: "restricted",
      allow: [
        { type: "user", address: "subscriber1@example.com" },
        { type: "domain", domain: "company.example" },
      ],
      rate_limits: [
        { period_seconds: 3600, amount_allowed: 200 },
        { period_seconds: 86400, amount_allowed: 2000 },
      ],
    },
    receive: { mode: "none", rate_limits: [], delivery_stage: 1 },
    blocklist: noPermResource(),
    keys: noPermResource(),
    devices: noPermResource(),
  };
}

function happyCertificate(): DeviceCertificate {
  return {
    type: "SEMP_DEVICE_CERTIFICATE",
    version: "1.0.0",
    device_id: "01JDELEGATE0000000000000000",
    device_public_key: "AAAA",
    account: "user@example.com",
    issued_by: "01JPRIMARY00000000000000000",
    issued_at: "2025-06-15T10:00:00Z",
    expires_at: "2025-12-15T10:00:00Z",
    scope: happyScope(),
    signature: { algorithm: "ed25519", key_id: "issuer-fp", value: "" },
  };
}

describe("device certificate sign + verify", () => {
  test("round-trip", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const issuerFp = fingerprint(pub);
    const cert = happyCertificate();
    cert.signature.key_id = issuerFp;

    const { certificate } = signDeviceCertificate({
      certificate: cert,
      issuerSigningSeed: seed,
      issuerKeyId: issuerFp,
    });

    expect(certificate.signature.value).not.toBe("");
    expect(certificate.signature.algorithm).toBe("ed25519");
    expect(certificate.signature.key_id).toBe(issuerFp);
    expect(verifyDeviceCertificate(certificate, pub)).toBe(true);
  });

  test("verify fails under wrong issuer key", () => {
    const seed = deterministicSeed(0x42);
    const issuerFp = fingerprint(publicKeyFromSeed(seed));
    const { certificate } = signDeviceCertificate({
      certificate: happyCertificate(),
      issuerSigningSeed: seed,
      issuerKeyId: issuerFp,
    });
    expect(
      verifyDeviceCertificate(certificate, publicKeyFromSeed(deterministicSeed(0xff))),
    ).toBe(false);
  });

  test("tampering scope mode breaks verify", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const { certificate } = signDeviceCertificate({
      certificate: happyCertificate(),
      issuerSigningSeed: seed,
      issuerKeyId: fingerprint(pub),
    });
    // After signing, mutate scope.send.mode and confirm verify fails.
    certificate.scope.send.mode = "unrestricted";
    certificate.scope.send.allow = [];
    expect(verifyDeviceCertificate(certificate, pub)).toBe(false);
  });

  test("compose rejects empty issuerKeyId", () => {
    expect(() =>
      signDeviceCertificate({
        certificate: happyCertificate(),
        issuerSigningSeed: deterministicSeed(0x42),
        issuerKeyId: "",
      }),
    ).toThrow(/issuer key_id/);
  });
});

describe("validateDeviceCertificate", () => {
  test("happy path", () => {
    const seed = deterministicSeed(0x42);
    const issuerFp = fingerprint(publicKeyFromSeed(seed));
    const { certificate } = signDeviceCertificate({
      certificate: happyCertificate(),
      issuerSigningSeed: seed,
      issuerKeyId: issuerFp,
    });
    validateDeviceCertificate(certificate);
  });

  test("rejects wrong type discriminator", () => {
    const c = happyCertificate();
    c.type = "WRONG" as never;
    expect(() => validateDeviceCertificate(c, { skipSignatureCheck: true })).toThrow(
      /type/,
    );
  });

  test("rejects malformed timestamps", () => {
    const c = happyCertificate();
    c.issued_at = "not a date";
    expect(() => validateDeviceCertificate(c, { skipSignatureCheck: true })).toThrow(
      /issued_at/,
    );
  });

  test("rejects expires_at <= issued_at", () => {
    const c = happyCertificate();
    c.expires_at = c.issued_at;
    expect(() => validateDeviceCertificate(c, { skipSignatureCheck: true })).toThrow(
      /expires_at/,
    );
  });

  test("rejects lifetime > 365 days", () => {
    const c = happyCertificate();
    c.issued_at = "2025-01-01T00:00:00Z";
    c.expires_at = "2026-01-02T00:00:00Z";
    expect(() => validateDeviceCertificate(c, { skipSignatureCheck: true })).toThrow(
      /365-day cap/,
    );
  });

  test("rejects unsigned cert when not skipped", () => {
    const c = happyCertificate();
    expect(() => validateDeviceCertificate(c)).toThrow(/unsigned/);
  });
});

describe("validateScope matcher modes", () => {
  test("restricted requires allow", () => {
    const s = happyScope();
    s.send = { mode: "restricted", rate_limits: [] };
    expect(() => validateScope(s)).toThrow(/restricted/);
  });

  test("denylist requires deny + forbids allow", () => {
    const s = happyScope();
    s.send = {
      mode: "denylist",
      deny: [{ type: "user", address: "spammer@x" }],
      rate_limits: [],
    };
    validateScope(s);
    s.send.allow = [{ type: "user", address: "x@x" }];
    expect(() => validateScope(s)).toThrow(/forbids allow/);
  });

  test("unrestricted forbids non-empty allow/deny", () => {
    const s = happyScope();
    s.send = {
      mode: "unrestricted",
      allow: [{ type: "user", address: "x@x" }],
      rate_limits: [],
    };
    expect(() => validateScope(s)).toThrow(/empty/);
  });

  test("none forbids non-empty allow/deny", () => {
    const s = happyScope();
    s.send = {
      mode: "none",
      allow: [{ type: "user", address: "x@x" }],
      rate_limits: [],
    };
    expect(() => validateScope(s)).toThrow(/empty/);
  });

  test("delivery_stage forbidden on send matcher", () => {
    const s = happyScope();
    (s.send as ScopeMatcher).delivery_stage = 1;
    expect(() => validateScope(s)).toThrow(/delivery_stage/);
  });

  test("delivery_stage allowed on receive matcher", () => {
    const s = happyScope();
    s.receive = { mode: "unrestricted", rate_limits: [], delivery_stage: 2 };
    validateScope(s);
  });

  test("delivery_stage MUST be positive integer", () => {
    const s = happyScope();
    s.receive = { mode: "unrestricted", rate_limits: [], delivery_stage: 0 };
    expect(() => validateScope(s)).toThrow(/positive integer/);
  });
});

describe("validateScope rate_limits + entries", () => {
  test("rate_limits cap enforced", () => {
    const s = happyScope();
    const tooMany: RateLimitTier[] = [];
    for (let i = 0; i < MaxScopeRateLimitTiers + 1; i++) {
      tooMany.push({ period_seconds: 60, amount_allowed: 1 });
    }
    s.send.rate_limits = tooMany;
    expect(() => validateScope(s)).toThrow(/exceeds cap/);
  });

  test("rate_limits.period_seconds must be >= 1", () => {
    const s = happyScope();
    s.send.rate_limits = [{ period_seconds: 0, amount_allowed: 1 }];
    expect(() => validateScope(s)).toThrow(/period_seconds/);
  });

  test("rate_limits.amount_allowed must be >= 0", () => {
    const s = happyScope();
    s.send.rate_limits = [{ period_seconds: 60, amount_allowed: -1 }];
    expect(() => validateScope(s)).toThrow(/amount_allowed/);
  });

  test("scope-entry user requires address", () => {
    const s = happyScope();
    s.send.allow = [{ type: "user" }];
    expect(() => validateScope(s)).toThrow(/address/);
  });

  test("scope-entry domain requires domain", () => {
    const s = happyScope();
    s.send.allow = [{ type: "domain" }];
    expect(() => validateScope(s)).toThrow(/domain/);
  });

  test("scope-entry server accepts either server or domain", () => {
    const s = happyScope();
    s.send.allow = [{ type: "server", server: "router.example.com" }];
    validateScope(s);
    s.send.allow = [{ type: "server", domain: "router.example.com" }];
    validateScope(s);
    s.send.allow = [{ type: "server" }];
    expect(() => validateScope(s)).toThrow(/server or domain/);
  });

  test("matcher entry total respects MaxScopeMatcherEntries", () => {
    // Hit just over the cap to ensure the check fires.
    const s = happyScope();
    const allow: ScopeEntry[] = [];
    for (let i = 0; i < MaxScopeMatcherEntries + 1; i++) {
      allow.push({ type: "user", address: `u${i}@example.com` });
    }
    s.send.allow = allow;
    expect(() => validateScope(s)).toThrow(/exceeds cap/);
  });
});

describe("scopeAllowsRecipient / scopeAllowsSender", () => {
  test("unrestricted permits any peer", () => {
    const m: ScopeMatcher = { mode: "unrestricted", rate_limits: [] };
    expect(scopeAllowsRecipient(m, { address: "any@x" })).toBe(true);
  });

  test("none refuses any peer", () => {
    const m: ScopeMatcher = { mode: "none", rate_limits: [] };
    expect(scopeAllowsRecipient(m, { address: "any@x" })).toBe(false);
  });

  test("restricted user-allow-list match", () => {
    const m: ScopeMatcher = {
      mode: "restricted",
      allow: [{ type: "user", address: "subscriber1@example.com" }],
      rate_limits: [],
    };
    expect(scopeAllowsRecipient(m, { address: "subscriber1@example.com" })).toBe(true);
    expect(scopeAllowsRecipient(m, { address: "OTHER@example.com" })).toBe(false);
  });

  test("restricted domain match", () => {
    const m: ScopeMatcher = {
      mode: "restricted",
      allow: [{ type: "domain", domain: "company.example" }],
      rate_limits: [],
    };
    expect(scopeAllowsRecipient(m, { address: "anyone@company.example" })).toBe(true);
    expect(scopeAllowsRecipient(m, { address: "anyone@other.example" })).toBe(false);
  });

  test("denylist excludes listed users only", () => {
    const m: ScopeMatcher = {
      mode: "denylist",
      deny: [{ type: "user", address: "spammer@x" }],
      rate_limits: [],
    };
    expect(scopeAllowsRecipient(m, { address: "spammer@x" })).toBe(false);
    expect(scopeAllowsRecipient(m, { address: "alice@x" })).toBe(true);
  });

  test("comparisons are case-insensitive", () => {
    const m: ScopeMatcher = {
      mode: "restricted",
      allow: [{ type: "user", address: "Alice@A.Example" }],
      rate_limits: [],
    };
    expect(scopeAllowsRecipient(m, { address: "ALICE@a.example" })).toBe(true);
  });

  test("server entry matches by routing server when known", () => {
    const m: ScopeMatcher = {
      mode: "restricted",
      allow: [{ type: "server", server: "router.example.com" }],
      rate_limits: [],
    };
    expect(
      scopeAllowsRecipient(m, {
        address: "anyone@example.com",
        server: "router.example.com",
      }),
    ).toBe(true);
    expect(
      scopeAllowsRecipient(m, { address: "anyone@example.com", server: "other.example.com" }),
    ).toBe(false);
  });

  test("scopeAllowsSender mirrors scopeAllowsRecipient", () => {
    const m: ScopeMatcher = {
      mode: "restricted",
      allow: [{ type: "user", address: "alice@x" }],
      rate_limits: [],
    };
    expect(scopeAllowsSender(m, { address: "alice@x" })).toBe(true);
    expect(scopeAllowsSender(m, { address: "bob@x" })).toBe(false);
  });

  test("unknown mode fails closed", () => {
    const m = { mode: "future" } as unknown as ScopeMatcher;
    expect(scopeAllowsRecipient(m, { address: "x@x" })).toBe(false);
  });
});
