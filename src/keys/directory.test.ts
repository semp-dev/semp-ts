/**
 * Tests for the consumer-side {@link DirectoryCache} (rollback
 * detection per §10.6.2 / §10.6.3) and the server-side
 * {@link DirectoryState} / {@link DirectoryStore} (per-user signed
 * directory emission per §10.6).
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  DirectoryCache,
  DirectoryRollbackError,
} from "./directory_cache.js";
import {
  DirectoryState,
  DirectoryStore,
} from "./directory_state.js";
import { fingerprint, publicKeyFromSeed } from "./sign.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function makeFixture() {
  const idSeed = seed(0xa1);
  const idPub = publicKeyFromSeed(idSeed);
  const idFp = fingerprint(idPub);
  const userId = "alice@example.com";
  return { idSeed, idPub, idFp, userId };
}

describe("DirectoryState", () => {
  test("starts empty and emits revision 1 on first add", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
      now: () => new Date("2026-05-08T10:00:00Z"),
    });
    expect(st.current()).toBeNull();
    expect(st.revision()).toBe(0);

    const dir = st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "Laptop",
      device_type: "computer",
    });
    expect(dir.revision).toBe(1);
    expect(dir.devices).toHaveLength(1);
    expect(dir.signature.value).not.toBe("");
    expect(st.revision()).toBe(1);
  });

  test("entries are sorted by device_id; revision monotonically increases", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
      now: () => new Date("2026-05-08T10:00:00Z"),
    });
    st.addDevice({
      device_id: "01JZZZ",
      device_public_key: "BBBB",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "B",
      device_type: "phone",
    });
    const dir2 = st.addDevice({
      device_id: "01JAAA",
      device_public_key: "CCCC",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "A",
      device_type: "phone",
    });
    expect(dir2.revision).toBe(2);
    expect(dir2.devices.map((d) => d.device_id)).toEqual([
      "01JAAA",
      "01JZZZ",
    ]);
  });

  test("revoke a known device emits a new revision", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    const { directory, removed } = st.revokeDevice("01JDEV01");
    expect(removed).toBe(true);
    expect(directory!.revision).toBe(2);
    expect(directory!.devices).toHaveLength(0);
  });

  test("revoke unknown device leaves state unchanged", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    const before = st.revision();
    const { removed } = st.revokeDevice("01JNONE");
    expect(removed).toBe(false);
    expect(st.revision()).toBe(before);
  });

  test("rejects duplicate device_id on add", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    expect(() =>
      st.addDevice({
        device_id: "01JDEV01",
        device_public_key: "BBBB",
        device_identity_pubkey_algorithm: "ed25519",
        role: "full_access",
        certificate_id: null,
        enrolled_at: "2026-05-08T10:00:00Z",
        device_name: "L2",
        device_type: "computer",
      }),
    ).toThrow(/already contains/);
  });
});

describe("DirectoryStore", () => {
  test("register + lookup round-trips", () => {
    const f = makeFixture();
    const store = new DirectoryStore();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    store.register(f.userId, st);
    expect(store.lookup(f.userId)).toBe(st);
    expect(store.lookup("nobody@example.com")).toBeNull();
  });

  test("register rejects duplicate user_id", () => {
    const f = makeFixture();
    const store = new DirectoryStore();
    store.register(
      f.userId,
      new DirectoryState({
        userId: f.userId,
        identitySeed: f.idSeed,
        identityKeyId: f.idFp,
      }),
    );
    expect(() =>
      store.register(
        f.userId,
        new DirectoryState({
          userId: f.userId,
          identitySeed: f.idSeed,
          identityKeyId: f.idFp,
        }),
      ),
    ).toThrow(/already has user/);
  });
});

describe("DirectoryCache", () => {
  test("accepts increasing revisions and rejects rollback", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    const r1 = st.current()!;
    st.addDevice({
      device_id: "01JDEV02",
      device_public_key: "BBBB",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "P",
      device_type: "phone",
    });
    const r2 = st.current()!;

    const cache = new DirectoryCache();
    cache.verifyAndCache(r1, f.idPub);
    expect(cache.highestRevision(f.userId)).toBe(1);
    cache.verifyAndCache(r2, f.idPub);
    expect(cache.highestRevision(f.userId)).toBe(2);

    // Rollback attempt: replaying r1 after caching r2.
    expect(() => cache.verifyAndCache(r1, f.idPub)).toThrow(
      DirectoryRollbackError,
    );
  });

  test("rejects directory whose signature does not verify", () => {
    const f = makeFixture();
    const wrong = publicKeyFromSeed(seed(0x99));
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    const dir = st.current()!;
    const cache = new DirectoryCache();
    expect(() => cache.verifyAndCache(dir, wrong)).toThrow(
      /signature did not verify/,
    );
  });

  test("invokes certCheck for each delegated entry", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "delegated",
      certificate_id: "cert-001",
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    const dir = st.current()!;

    const seen: string[] = [];
    const cache = new DirectoryCache();
    cache.verifyAndCache(dir, f.idPub, (id) => {
      seen.push(id);
    });
    expect(seen).toEqual(["cert-001"]);

    // certCheck that throws fails the verify.
    const cache2 = new DirectoryCache();
    expect(() =>
      cache2.verifyAndCache(dir, f.idPub, () => {
        throw new Error("expired");
      }),
    ).toThrow(/expired/);
  });

  test("reset forgets cached revision", () => {
    const f = makeFixture();
    const st = new DirectoryState({
      userId: f.userId,
      identitySeed: f.idSeed,
      identityKeyId: f.idFp,
    });
    st.addDevice({
      device_id: "01JDEV01",
      device_public_key: "AAAA",
      device_identity_pubkey_algorithm: "ed25519",
      role: "full_access",
      certificate_id: null,
      enrolled_at: "2026-05-08T10:00:00Z",
      device_name: "L",
      device_type: "computer",
    });
    const dir = st.current()!;
    const cache = new DirectoryCache();
    cache.verifyAndCache(dir, f.idPub);
    expect(cache.highestRevision(f.userId)).toBe(1);
    cache.reset(f.userId);
    expect(cache.highestRevision(f.userId)).toBe(0);
  });
});
