/**
 * Closure record + driver tests.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type ClosureRecord,
  AccountClosurePrefix,
  MaxGracePeriodSeconds,
  MinGracePeriodSeconds,
  RecommendedGracePeriodSeconds,
  finalizationAt,
  isFinalizable,
  signClosureRecord,
  validateClosureRecord,
  verifyClosureRecord,
} from "./closure.js";
import { Driver } from "./driver.js";
import { InMemoryClosureStore, MinRetentionMs } from "./store.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function happyRecord(): ClosureRecord {
  return {
    type: "SEMP_ACCOUNT_CLOSURE",
    step: "request",
    version: "1.0.0",
    user_id: "alice@example.com",
    requested_at: "2026-04-21T10:00:00Z",
    grace_period_seconds: RecommendedGracePeriodSeconds,
    issued_by: "primary-device-fp",
    signature: { algorithm: "", key_id: "", value: "" },
  };
}

describe("signClosureRecord + verifyClosureRecord", () => {
  test("round-trip", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const keyId = fingerprint(pub);
    const { record } = signClosureRecord({
      record: happyRecord(),
      deviceSigningSeed: seed,
      deviceKeyId: keyId,
    });
    expect(record.signature.algorithm).toBe("ed25519");
    expect(record.signature.key_id).toBe(keyId);
    expect(record.signature.value).not.toBe("");
    expect(verifyClosureRecord(record, pub)).toBe(true);
  });

  test("verify under wrong key fails", () => {
    const seed = deterministicSeed(0x42);
    const { record } = signClosureRecord({
      record: happyRecord(),
      deviceSigningSeed: seed,
      deviceKeyId: fingerprint(publicKeyFromSeed(seed)),
    });
    expect(verifyClosureRecord(record, publicKeyFromSeed(deterministicSeed(0xff)))).toBe(false);
  });

  test("tampering breaks verification", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const { record } = signClosureRecord({
      record: happyRecord(),
      deviceSigningSeed: seed,
      deviceKeyId: fingerprint(pub),
    });
    record.user_id = "evil@example.com";
    expect(verifyClosureRecord(record, pub)).toBe(false);
  });

  test("prefix matches spec table", () => {
    expect(AccountClosurePrefix).toBe("SEMP-ACCOUNT-CLOSURE:");
  });

  test("rejects empty device key_id", () => {
    expect(() =>
      signClosureRecord({
        record: happyRecord(),
        deviceSigningSeed: deterministicSeed(0x42),
        deviceKeyId: "",
      }),
    ).toThrow(/key_id/);
  });
});

describe("validateClosureRecord", () => {
  test("rejects unknown step", () => {
    expect(() =>
      validateClosureRecord({ ...happyRecord(), step: "delete" as never }, { skipSignatureCheck: true }),
    ).toThrow(/step/);
  });

  test("rejects grace_period below 7 days", () => {
    const r = { ...happyRecord(), grace_period_seconds: MinGracePeriodSeconds - 1 };
    expect(() => validateClosureRecord(r, { skipSignatureCheck: true })).toThrow(/below minimum/);
  });

  test("rejects grace_period above 90 days", () => {
    const r = { ...happyRecord(), grace_period_seconds: MaxGracePeriodSeconds + 1 };
    expect(() => validateClosureRecord(r, { skipSignatureCheck: true })).toThrow(/exceeds maximum/);
  });

  test("cancel step skips grace_period bound check", () => {
    const r = { ...happyRecord(), step: "cancel" as const, grace_period_seconds: 0 };
    validateClosureRecord(r, { skipSignatureCheck: true });
  });

  test("rejects missing user_id / requested_at / issued_by", () => {
    for (const field of ["user_id", "requested_at", "issued_by"] as const) {
      const r = { ...happyRecord() };
      r[field] = "" as never;
      expect(() => validateClosureRecord(r, { skipSignatureCheck: true })).toThrow(
        new RegExp(field),
      );
    }
  });
});

describe("finalizationAt + isFinalizable", () => {
  test("finalizationAt = requested_at + grace_period", () => {
    const r = { ...happyRecord(), requested_at: "2026-04-21T10:00:00Z" };
    const at = finalizationAt(r);
    expect(at.toISOString()).toBe("2026-05-21T10:00:00.000Z");
  });

  test("isFinalizable false before grace ends", () => {
    expect(isFinalizable(happyRecord(), new Date("2026-04-21T10:00:01Z"))).toBe(false);
  });

  test("isFinalizable true at/after grace ends", () => {
    expect(isFinalizable(happyRecord(), new Date("2026-05-22T00:00:00Z"))).toBe(true);
  });

  test("cancel records are never finalizable", () => {
    expect(
      isFinalizable({ ...happyRecord(), step: "cancel" }, new Date("2030-01-01")),
    ).toBe(false);
  });
});

describe("Driver lifecycle", () => {
  test("submit pending → tick finalizes after grace", async () => {
    const store = new InMemoryClosureStore();
    const driver = new Driver({
      store,
      nowFn: () => new Date("2026-05-22T10:00:00Z"),
    });
    const r = happyRecord();
    r.signature = { algorithm: "ed25519", key_id: "x", value: "AAA=" };

    const out = await driver.submit(r);
    expect(out.kind).toBe("accepted");
    expect(await store.countPending()).toBe(1);

    const finalized = await driver.tick();
    expect(finalized).toHaveLength(1);
    expect(finalized[0]!.user_id).toBe("alice@example.com");
    expect(await store.countPending()).toBe(0);
    expect(await driver.isAccountClosed("alice@example.com")).toBe(true);
  });

  test("submit returns already_pending on collision", async () => {
    const store = new InMemoryClosureStore();
    const driver = new Driver({ store });
    const r = happyRecord();
    r.signature = { algorithm: "ed25519", key_id: "x", value: "AAA=" };

    expect((await driver.submit(r)).kind).toBe("accepted");
    expect((await driver.submit(r)).kind).toBe("already_pending");
  });

  test("cancel deletes pending request", async () => {
    const store = new InMemoryClosureStore();
    const driver = new Driver({ store });
    const r = happyRecord();
    r.signature = { algorithm: "ed25519", key_id: "x", value: "AAA=" };

    await driver.submit(r);
    const cancel = { ...r, step: "cancel" as const };
    expect((await driver.submit(cancel)).kind).toBe("accepted");
    expect(await store.countPending()).toBe(0);
  });

  test("cancel without pending returns not_pending", async () => {
    const store = new InMemoryClosureStore();
    const driver = new Driver({ store });
    const cancel = {
      ...happyRecord(),
      step: "cancel" as const,
      signature: { algorithm: "ed25519", key_id: "x", value: "AAA=" },
    };
    expect((await driver.submit(cancel)).kind).toBe("not_pending");
  });

  test("tick before grace ends does nothing", async () => {
    const store = new InMemoryClosureStore();
    const driver = new Driver({
      store,
      nowFn: () => new Date("2026-04-22T00:00:00Z"),
    });
    const r = happyRecord();
    r.signature = { algorithm: "ed25519", key_id: "x", value: "AAA=" };
    await driver.submit(r);
    expect(await driver.tick()).toEqual([]);
    expect(await store.countPending()).toBe(1);
  });

  test("invalid record returns kind=invalid", async () => {
    const store = new InMemoryClosureStore();
    const driver = new Driver({ store });
    const r: ClosureRecord = {
      ...happyRecord(),
      grace_period_seconds: 100,
      signature: { algorithm: "ed25519", key_id: "x", value: "AAA=" },
    };
    const out = await driver.submit(r);
    expect(out.kind).toBe("invalid");
    if (out.kind === "invalid") {
      expect(out.reason).toMatch(/below minimum/);
    }
  });
});

describe("recipientPolicy", () => {
  test("rejects closed accounts with policy_forbidden by default", async () => {
    const store = new InMemoryClosureStore();
    await store.putFinalized("alice@example.com", new Date());
    const driver = new Driver({ store });
    const policy = driver.recipientPolicy();
    const result = await policy("alice@example.com");
    expect(result?.acknowledgment).toBe("rejected");
    expect(result?.reason_code).toBe("policy_forbidden");
  });

  test("returns silent when configured", async () => {
    const store = new InMemoryClosureStore();
    await store.putFinalized("alice@example.com", new Date());
    const driver = new Driver({ store });
    const policy = driver.recipientPolicy({ useSilent: true });
    const result = await policy("alice@example.com");
    expect(result?.acknowledgment).toBe("silent");
  });

  test("passes through (returns null) for active accounts", async () => {
    const driver = new Driver({ store: new InMemoryClosureStore() });
    const policy = driver.recipientPolicy();
    expect(await policy("alice@example.com")).toBeNull();
  });
});

describe("InMemoryClosureStore", () => {
  test("pruneFinalized clamps retainFor up to MinRetentionMs", async () => {
    const store = new InMemoryClosureStore();
    const finalizedAt = new Date("2026-01-01T00:00:00Z");
    await store.putFinalized("alice@example.com", finalizedAt);
    const now = new Date("2026-04-01T00:00:00Z"); // 90 days later
    // Pass a tiny retainForMs; the store clamps up to MinRetentionMs
    // (180 days), so the entry MUST survive.
    const pruned = await store.pruneFinalized(60 * 1000, now);
    expect(pruned).toBe(0);
    expect(await store.getFinalized("alice@example.com")).not.toBeNull();
  });

  test("pruneFinalized evicts entries older than the cutoff", async () => {
    const store = new InMemoryClosureStore();
    // 180-day MinRetention cutoff against now=2026-12-01 is 2026-06-04.
    // Alice (2024-01-01) is older → pruned.
    // Bob (2026-09-01) is newer → kept.
    await store.putFinalized("alice@example.com", new Date("2024-01-01T00:00:00Z"));
    await store.putFinalized("bob@example.com", new Date("2026-09-01T00:00:00Z"));
    const now = new Date("2026-12-01T00:00:00Z");
    const pruned = await store.pruneFinalized(MinRetentionMs, now);
    expect(pruned).toBe(1);
    expect(await store.getFinalized("alice@example.com")).toBeNull();
    expect(await store.getFinalized("bob@example.com")).not.toBeNull();
  });
});
