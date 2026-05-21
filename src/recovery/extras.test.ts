/**
 * Tests for the new recovery primitives: bundle crypto + bundle store
 * + manifest cross-check.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type BackupBundle,
  type BundlePayload,
  type DirectoryView,
  type RecoverySetManifest,
  InMemoryBundleStore,
  ManifestCrossCheckError,
  MinPassphraseBytes,
  MinSupersededRetentionMs,
  RecommendedKDFIterations,
  RecommendedKDFMemoryKB,
  RecommendedKDFParallelism,
  crossCheckManifestContributors,
  decryptBundlePayload,
  deriveBundleKey,
  deriveRecoverySignKey,
  encryptBundlePayload,
  normalizeRecoverySecret,
} from "./index.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

const FAST_KDF = {
  algorithm: "argon2id",
  // Use 64 KiB / t=2 / p=1 - meets §2.5 minima but stays fast in tests.
  salt: base64(new Uint8Array(16).fill(0x42)),
  memory_kb: 65_536,
  iterations: 2,
  parallelism: 1,
};

describe("normalizeRecoverySecret", () => {
  test("passphrase: NFKC + trim + min length check", () => {
    const out = normalizeRecoverySecret(
      "passphrase",
      "  correct horse battery staple  ",
    );
    expect(new TextDecoder().decode(out)).toBe("correct horse battery staple");
  });

  test("passphrase: rejects below MinPassphraseBytes", () => {
    expect(() => normalizeRecoverySecret("passphrase", "short")).toThrow(
      new RegExp(`below ${MinPassphraseBytes}`),
    );
  });

  test("passphrase: NFKC normalizes compatibility forms", () => {
    // ﬁ (U+FB01 LATIN SMALL LIGATURE FI) -> "fi" under NFKC.
    const out = normalizeRecoverySecret(
      "passphrase",
      "ﬁnal answer answer",
    );
    expect(new TextDecoder().decode(out)).toBe("final answer answer");
  });

  test("recovery_code: lowercase + space-join", () => {
    const out = normalizeRecoverySecret(
      "recovery_code",
      " WORD1   wOrD2\twoRD3\n",
    );
    expect(new TextDecoder().decode(out)).toBe("word1 word2 word3");
  });

  test("recovery_code: rejects empty input", () => {
    expect(() => normalizeRecoverySecret("recovery_code", "   ")).toThrow(
      /empty/,
    );
  });

  test("rejects unknown form", () => {
    expect(() =>
      normalizeRecoverySecret("future" as never, "x"),
    ).toThrow(/unsupported/);
  });
});

describe("deriveBundleKey", () => {
  test("derives a 32-byte key deterministically", () => {
    const secret = normalizeRecoverySecret(
      "passphrase",
      "correct horse battery staple",
    );
    const k1 = deriveBundleKey(secret, FAST_KDF);
    const k2 = deriveBundleKey(secret, FAST_KDF);
    expect(k1.length).toBe(32);
    expect(k1).toEqual(k2);
  });

  test("different secrets produce different keys", () => {
    const a = normalizeRecoverySecret("passphrase", "alpha alpha alpha alpha");
    const b = normalizeRecoverySecret("passphrase", "bravo bravo bravo bravo");
    expect(deriveBundleKey(a, FAST_KDF)).not.toEqual(
      deriveBundleKey(b, FAST_KDF),
    );
  });

  test("rejects below-floor KDF parameters", () => {
    const secret = normalizeRecoverySecret(
      "passphrase",
      "correct horse battery staple",
    );
    expect(() =>
      deriveBundleKey(secret, { ...FAST_KDF, memory_kb: 1024 }),
    ).toThrow(/memory_kb/);
  });
});

describe("deriveRecoverySignKey", () => {
  test("returns deterministic 32-byte seed + matching pub", () => {
    const k = new Uint8Array(32).fill(0xab);
    const a = deriveRecoverySignKey(k);
    const b = deriveRecoverySignKey(k);
    expect(a.signSeed.length).toBe(32);
    expect(a.verifyPub.length).toBe(32);
    expect(a.signSeed).toEqual(b.signSeed);
    expect(a.verifyPub).toEqual(b.verifyPub);
  });

  test("rejects empty bundle key", () => {
    expect(() => deriveRecoverySignKey(new Uint8Array(0))).toThrow(/empty/);
  });
});

describe("encryptBundlePayload + decryptBundlePayload", () => {
  function fixture(): {
    bundleKey: Uint8Array;
    nonce: Uint8Array;
    payload: BundlePayload;
  } {
    return {
      bundleKey: deterministicSeed(0xcd),
      nonce: new Uint8Array(24).fill(0xee),
      payload: {
        identity_key: {
          algorithm: "ed25519",
          public_key: "AAAA",
          private_key: "BBBB",
          created: "2026-04-21T10:00:00Z",
        },
        encryption_keys: [],
      },
    };
  }

  test("round-trip recovers the same payload", () => {
    const fix = fixture();
    const ct = encryptBundlePayload(fix.bundleKey, fix.nonce, fix.payload);
    const pt = decryptBundlePayload<BundlePayload>(
      fix.bundleKey,
      fix.nonce,
      ct,
    );
    expect(pt).toEqual(fix.payload);
  });

  test("decrypt under wrong key throws", () => {
    const fix = fixture();
    const ct = encryptBundlePayload(fix.bundleKey, fix.nonce, fix.payload);
    const wrong = deterministicSeed(0xff);
    expect(() => decryptBundlePayload(wrong, fix.nonce, ct)).toThrow();
  });

  test("decrypt under wrong nonce throws", () => {
    const fix = fixture();
    const ct = encryptBundlePayload(fix.bundleKey, fix.nonce, fix.payload);
    expect(() =>
      decryptBundlePayload(fix.bundleKey, new Uint8Array(24), ct),
    ).toThrow();
  });

  test("rejects wrong key length", () => {
    expect(() =>
      encryptBundlePayload(
        new Uint8Array(31),
        new Uint8Array(24),
        {} as never,
      ),
    ).toThrow(/key length/);
  });

  test("rejects wrong nonce length", () => {
    expect(() =>
      encryptBundlePayload(
        deterministicSeed(0xab),
        new Uint8Array(12),
        {} as never,
      ),
    ).toThrow(/nonce length/);
  });
});

describe("InMemoryBundleStore", () => {
  function makeBundle(
    userId: string,
    bundleId: string,
    supersedes: string | null = null,
    createdAt = "2026-04-21T10:00:00Z",
  ): BackupBundle {
    return {
      type: "SEMP_BACKUP_BUNDLE",
      version: "1.0.0",
      user_id: userId,
      bundle_id: bundleId,
      created_at: createdAt,
      supersedes,
      kdf: FAST_KDF,
      payload_algorithm: "xchacha20-poly1305",
      payload_nonce: base64(new Uint8Array(24)),
      encrypted_payload: "AAA=",
      recovery_verify_pk: { algorithm: "ed25519", public_key: "AAAA" },
      signature: { algorithm: "ed25519", key_id: "x", value: "AAA=" },
    };
  }

  test("putCurrent + getCurrent round-trip", async () => {
    const store = new InMemoryBundleStore();
    const b = makeBundle("alice@example.com", "b-1", null);
    await store.putCurrent("alice@example.com", b, new Date());
    expect(await store.getCurrent("alice@example.com")).toEqual(b);
  });

  test("supersedes chain accepted", async () => {
    const store = new InMemoryBundleStore();
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-1", null, "2026-04-01T00:00:00Z"),
      new Date(),
    );
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-2", "b-1", "2026-04-21T00:00:00Z"),
      new Date("2026-04-21T00:00:00Z"),
    );
    expect((await store.getCurrent("alice@example.com"))?.bundle_id).toBe("b-2");
    expect((await store.history("alice@example.com")).map((b) => b.bundle_id)).toEqual([
      "b-2",
      "b-1",
    ]);
  });

  test("supersedes mismatch rejected", async () => {
    const store = new InMemoryBundleStore();
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-1", null),
      new Date(),
    );
    await expect(
      store.putCurrent(
        "alice@example.com",
        makeBundle("alice@example.com", "b-2", "wrong-parent"),
        new Date(),
      ),
    ).rejects.toThrow(/supersedes/);
  });

  test("user_id mismatch rejected", async () => {
    const store = new InMemoryBundleStore();
    await expect(
      store.putCurrent(
        "alice@example.com",
        makeBundle("bob@example.com", "b-1", null),
        new Date(),
      ),
    ).rejects.toThrow(/user_id/);
  });

  test("pruneSuperseded clamps retention up to MinSupersededRetentionMs", async () => {
    const store = new InMemoryBundleStore(
      () => new Date("2026-04-01T00:00:00Z"),
    );
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-1", null, "2026-01-01T00:00:00Z"),
      new Date(),
    );
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-2", "b-1", "2026-04-01T00:00:00Z"),
      new Date("2026-04-01T00:00:00Z"),
    );
    // Retention floor clamps tiny values up to 30 days, so b-1 (just
    // superseded) is still retained.
    expect(await store.pruneSuperseded(60 * 1000)).toBe(0);
    expect(MinSupersededRetentionMs).toBe(30 * 24 * 60 * 60 * 1000);
  });

  test("pruneSuperseded drops old superseded entries", async () => {
    const fakeNow = new Date("2026-12-01T00:00:00Z");
    const store = new InMemoryBundleStore(() => fakeNow);
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-1", null, "2025-01-01T00:00:00Z"),
      new Date(),
    );
    await store.putCurrent(
      "alice@example.com",
      makeBundle("alice@example.com", "b-2", "b-1", "2025-06-01T00:00:00Z"),
      new Date("2025-06-01T00:00:00Z"), // superseded at this timestamp
    );
    expect(await store.pruneSuperseded(MinSupersededRetentionMs)).toBe(1);
  });
});

describe("crossCheckManifestContributors", () => {
  function manifest(): RecoverySetManifest {
    return {
      type: "SEMP_RECOVERY_SET_MANIFEST",
      version: "1.0.0",
      bundle_id: "b-1",
      threshold: 2,
      total_shares: 2,
      contributors: [
        {
          share_index: 1,
          device_id: "dev-1",
          device_identity_pubkey: {
            algorithm: "ed25519",
            public_key: "PUB-1",
            key_id: "fp-1",
          },
        },
        {
          share_index: 2,
          device_id: "dev-2",
          device_identity_pubkey: {
            algorithm: "ed25519",
            public_key: "PUB-2",
            key_id: "fp-2",
          },
        },
      ],
      issued_at: "2026-04-21T10:00:00Z",
      signature: { algorithm: "ed25519", key_id: "x", value: "AAA=" },
    };
  }

  function dirOf(
    userId: string,
    devices: Record<string, { algorithm: string; publicKey: string }>,
  ): DirectoryView {
    return {
      userId: () => userId,
      findDevice: (id) => {
        const d = devices[id];
        if (d === undefined) {
          return { algorithm: "", publicKey: "", found: false };
        }
        return { algorithm: d.algorithm, publicKey: d.publicKey, found: true };
      },
    };
  }

  test("happy path", () => {
    crossCheckManifestContributors(
      manifest(),
      dirOf("alice@example.com", {
        "dev-1": { algorithm: "ed25519", publicKey: "PUB-1" },
        "dev-2": { algorithm: "ed25519", publicKey: "PUB-2" },
      }),
      "alice@example.com",
    );
  });

  test("user mismatch", () => {
    expect(() =>
      crossCheckManifestContributors(
        manifest(),
        dirOf("bob@example.com", {}),
        "alice@example.com",
      ),
    ).toThrowError(ManifestCrossCheckError);
  });

  test("missing device", () => {
    try {
      crossCheckManifestContributors(
        manifest(),
        dirOf("alice@example.com", {
          "dev-1": { algorithm: "ed25519", publicKey: "PUB-1" },
        }),
        "alice@example.com",
      );
      throw new Error("expected throw");
    } catch (err) {
      if (!(err instanceof ManifestCrossCheckError)) {
        throw err;
      }
      expect(err.reason).toBe("device_missing");
      expect(err.deviceId).toBe("dev-2");
    }
  });

  test("pubkey mismatch", () => {
    try {
      crossCheckManifestContributors(
        manifest(),
        dirOf("alice@example.com", {
          "dev-1": { algorithm: "ed25519", publicKey: "WRONG" },
          "dev-2": { algorithm: "ed25519", publicKey: "PUB-2" },
        }),
        "alice@example.com",
      );
      throw new Error("expected throw");
    } catch (err) {
      if (!(err instanceof ManifestCrossCheckError)) {
        throw err;
      }
      expect(err.reason).toBe("pubkey_mismatch");
    }
  });
});

// Keep imports active.
void RecommendedKDFIterations;
void RecommendedKDFMemoryKB;
void RecommendedKDFParallelism;
