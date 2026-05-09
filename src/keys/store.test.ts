/**
 * Tests for the reference {@link InMemoryKeyStore}.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { InMemoryKeyStore, type KeyStoreRecord } from "./store.js";

function makeRecord(
  overrides: Partial<KeyStoreRecord> = {},
): KeyStoreRecord {
  return {
    address: "alice@example.com",
    key_type: "encryption",
    algorithm: "x25519",
    public_key: "AAAA",
    key_id: "fp-001",
    created: "2026-05-08T10:00:00Z",
    ...overrides,
  };
}

describe("InMemoryKeyStore", () => {
  test("user keys are persisted and looked up by address", () => {
    const s = new InMemoryKeyStore();
    s.putRecord(makeRecord({ key_type: "encryption", key_id: "enc-1" }));
    s.putRecord(makeRecord({ key_type: "identity", key_id: "id-1" }));
    expect(s.lookupUserKeys("alice@example.com")).toHaveLength(2);
    expect(
      s.lookupUserKeys("alice@example.com", ["identity"]).map((r) => r.key_id),
    ).toEqual(["id-1"]);
    expect(s.lookupUserKeys("nobody@example.com")).toHaveLength(0);
  });

  test("domain key round-trips via putDomainRecord", () => {
    const s = new InMemoryKeyStore();
    s.putDomainRecord(
      "example.com",
      makeRecord({
        address: undefined,
        key_type: "domain",
        algorithm: "ed25519",
        key_id: "domain-1",
      }),
    );
    const looked = s.lookupDomainKey("example.com");
    expect(looked).not.toBeNull();
    expect(looked!.key_id).toBe("domain-1");
    expect(s.lookupDomainKey("other.com")).toBeNull();
  });

  test("putRecord on a domain record is a no-op", () => {
    const s = new InMemoryKeyStore();
    s.putRecord(
      makeRecord({
        key_type: "domain",
        address: undefined,
      }),
    );
    expect(s.lookupDomainKey("example.com")).toBeNull();
  });

  test("putRevocation surfaces on subsequent lookups", () => {
    const s = new InMemoryKeyStore();
    s.putRecord(makeRecord({ key_id: "enc-1" }));
    s.putRevocation("enc-1", {
      reason: "key_compromise",
      revoked_at: "2026-05-08T11:00:00Z",
    });
    const r = s.lookupUserKeys("alice@example.com")[0]!;
    expect(r.revocation?.reason).toBe("key_compromise");
  });

  test("private key store: store + load round-trip; missing throws", () => {
    const s = new InMemoryKeyStore();
    s.storePrivateKey("fp-123", new Uint8Array([1, 2, 3, 4]));
    const out = s.loadPrivateKey("fp-123");
    expect(Array.from(out)).toEqual([1, 2, 3, 4]);
    expect(() => s.loadPrivateKey("fp-missing")).toThrow(/not found/);
  });

  test("private key bytes are copied on store and load", () => {
    const s = new InMemoryKeyStore();
    const buf = new Uint8Array([9, 9, 9, 9]);
    s.storePrivateKey("fp-1", buf);
    buf[0] = 1; // mutate caller's buffer
    const a = s.loadPrivateKey("fp-1");
    expect(a[0]).toBe(9);
    a[0] = 7; // mutate returned buffer
    const b = s.loadPrivateKey("fp-1");
    expect(b[0]).toBe(9);
  });
});
