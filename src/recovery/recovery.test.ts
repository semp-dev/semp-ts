/**
 * Recovery primitives tests. Cover Shamir round-trip across the
 * threshold spectrum, plus sign+verify for successor (3 sigs),
 * manifest, share record, bundle, and the manifest cross-check.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  MaxShamirTotalShares,
  MinShamirThreshold,
  combineShares,
  splitSecret,
} from "./shamir.js";
import {
  type BackupBundle,
  type RecoverySetManifest,
  type RecoveryShareRecord,
  type SuccessorRecord,
  RecommendedKDFIterations,
  RecommendedKDFMemoryKB,
  RecommendedKDFParallelism,
} from "./types.js";
import {
  checkShareMatchesManifest,
  prepareSuccessorSignatures,
  signManifest,
  signShareRecord,
  signSuccessorDomain,
  signSuccessorNewKey,
  signSuccessorRecovery,
  verifyManifest,
  verifyShareRecord,
  verifySuccessorRecord,
  verifySuccessorTwoSignatures,
} from "./sign.js";
import { signBundle, validateBundle, verifyBundle } from "./bundle.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function deterministicRand(seed: number): (n: number) => Uint8Array {
  let state = seed >>> 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      // xorshift32
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      state >>>= 0;
      out[i] = state & 0xff;
    }
    return out;
  };
}

describe("Shamir splitSecret + combineShares", () => {
  test("3-of-5 reconstructs from any 3 shares", () => {
    const secret = new TextEncoder().encode("a 32-byte recovery secret here.");
    const shares = splitSecret(secret, 3, 5, deterministicRand(0xaa));
    expect(shares.length).toBe(5);

    // Pick 3 different subsets and confirm each reconstructs.
    expect(combineShares([shares[0]!, shares[1]!, shares[2]!])).toEqual(secret);
    expect(combineShares([shares[1]!, shares[3]!, shares[4]!])).toEqual(secret);
    expect(combineShares([shares[0]!, shares[2]!, shares[4]!])).toEqual(secret);
  });

  test("2-of-2 round-trip", () => {
    const secret = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const shares = splitSecret(secret, 2, 2, deterministicRand(1));
    expect(combineShares(shares)).toEqual(secret);
  });

  test("max bounds 16-of-16 round-trip", () => {
    const secret = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      secret[i] = (i * 7) & 0xff;
    }
    const shares = splitSecret(secret, 16, 16, deterministicRand(2));
    expect(combineShares(shares)).toEqual(secret);
  });

  test("rejects threshold < MinShamirThreshold", () => {
    expect(() =>
      splitSecret(new Uint8Array([1]), 1, 3, deterministicRand(0)),
    ).toThrow(/threshold/);
  });

  test("rejects total_shares < threshold", () => {
    expect(() =>
      splitSecret(new Uint8Array([1]), 3, 2, deterministicRand(0)),
    ).toThrow(/total_shares/);
  });

  test("rejects total_shares > MaxShamirTotalShares", () => {
    expect(() =>
      splitSecret(
        new Uint8Array([1]),
        2,
        MaxShamirTotalShares + 1,
        deterministicRand(0),
      ),
    ).toThrow(/maximum/);
  });

  test("rejects empty secret", () => {
    expect(() =>
      splitSecret(new Uint8Array(0), 2, 3, deterministicRand(0)),
    ).toThrow(/empty/);
  });

  test("combine rejects shares with duplicate index", () => {
    expect(() =>
      combineShares([
        { index: 1, value: new Uint8Array([1]) },
        { index: 1, value: new Uint8Array([2]) },
      ]),
    ).toThrow(/more than once/);
  });

  test("combine rejects share with index 0", () => {
    expect(() =>
      combineShares([{ index: 0, value: new Uint8Array([1]) }]),
    ).toThrow(/index 0/);
  });

  test("MinShamirThreshold/MaxShamirTotalShares match spec", () => {
    expect(MinShamirThreshold).toBe(2);
    expect(MaxShamirTotalShares).toBe(16);
  });
});

describe("SuccessorRecord 3-signature flow", () => {
  function emptyRecord(): SuccessorRecord {
    return {
      type: "SEMP_SUCCESSOR",
      version: "1.0.0",
      user_id: "alice@example.com",
      prior_key_id: "prior-fp",
      new_key_id: "new-fp",
      new_public_key: "AAAA",
      recovered_at: "2026-04-21T10:00:00Z",
      recovery_signature: { algorithm: "", key_id: "", value: "" },
      new_key_signature: { algorithm: "", key_id: "", value: "" },
      domain_signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("verify after all three signatures applied", () => {
    const recoverySeed = deterministicSeed(0xa1);
    const newKeySeed = deterministicSeed(0xa2);
    const domainSeed = deterministicSeed(0xa3);
    const recoveryPub = publicKeyFromSeed(recoverySeed);
    const newKeyPub = publicKeyFromSeed(newKeySeed);
    const domainPub = publicKeyFromSeed(domainSeed);

    const r = emptyRecord();
    prepareSuccessorSignatures(
      r,
      fingerprint(recoveryPub),
      fingerprint(newKeyPub),
      fingerprint(domainPub),
    );
    signSuccessorRecovery(r, recoverySeed, fingerprint(recoveryPub));
    signSuccessorNewKey(r, newKeySeed, fingerprint(newKeyPub));
    signSuccessorDomain(r, domainSeed, fingerprint(domainPub));

    expect(verifySuccessorRecord(r, recoveryPub, newKeyPub, domainPub)).toBe(true);
  });

  test("verifySuccessorTwoSignatures accepts device-side pair before domain signs", () => {
    const recoverySeed = deterministicSeed(0xa1);
    const newKeySeed = deterministicSeed(0xa2);
    const recoveryPub = publicKeyFromSeed(recoverySeed);
    const newKeyPub = publicKeyFromSeed(newKeySeed);

    const r = emptyRecord();
    prepareSuccessorSignatures(
      r,
      fingerprint(recoveryPub),
      fingerprint(newKeyPub),
      "domain-fp",
    );
    signSuccessorRecovery(r, recoverySeed, fingerprint(recoveryPub));
    signSuccessorNewKey(r, newKeySeed, fingerprint(newKeyPub));

    expect(verifySuccessorTwoSignatures(r, recoveryPub, newKeyPub)).toBe(true);
    expect(() =>
      verifySuccessorTwoSignatures(
        { ...r, domain_signature: { ...r.domain_signature, value: "AAA=" } },
        recoveryPub,
        newKeyPub,
      ),
    ).toThrow(/fully-signed/);
  });

  test("tampering breaks all three signature checks", () => {
    const recoverySeed = deterministicSeed(0xa1);
    const newKeySeed = deterministicSeed(0xa2);
    const domainSeed = deterministicSeed(0xa3);
    const recoveryPub = publicKeyFromSeed(recoverySeed);
    const newKeyPub = publicKeyFromSeed(newKeySeed);
    const domainPub = publicKeyFromSeed(domainSeed);

    const r = emptyRecord();
    prepareSuccessorSignatures(
      r,
      fingerprint(recoveryPub),
      fingerprint(newKeyPub),
      fingerprint(domainPub),
    );
    signSuccessorRecovery(r, recoverySeed, fingerprint(recoveryPub));
    signSuccessorNewKey(r, newKeySeed, fingerprint(newKeyPub));
    signSuccessorDomain(r, domainSeed, fingerprint(domainPub));

    r.user_id = "evil@example.com";
    expect(verifySuccessorRecord(r, recoveryPub, newKeyPub, domainPub)).toBe(false);
  });

  test("rejects sign before prepareSuccessorSignatures", () => {
    const r = emptyRecord();
    expect(() => signSuccessorRecovery(r, deterministicSeed(1), "x")).toThrow(
      /prepareSuccessorSignatures/,
    );
  });

  test("rejects key_id mismatch on sign call", () => {
    const r = emptyRecord();
    prepareSuccessorSignatures(r, "a", "b", "c");
    expect(() => signSuccessorRecovery(r, deterministicSeed(1), "different")).toThrow(
      /key_id/,
    );
  });
});

describe("RecoverySetManifest sign + verify", () => {
  function emptyManifest(): RecoverySetManifest {
    return {
      type: "SEMP_RECOVERY_SET_MANIFEST",
      version: "1.0.0",
      bundle_id: "bundle-1",
      threshold: 2,
      total_shares: 3,
      contributors: [
        {
          share_index: 1,
          device_id: "dev-1",
          device_identity_pubkey: { algorithm: "ed25519", public_key: "AAAA", key_id: "fp1" },
        },
        {
          share_index: 2,
          device_id: "dev-2",
          device_identity_pubkey: { algorithm: "ed25519", public_key: "BBBB", key_id: "fp2" },
        },
        {
          share_index: 3,
          device_id: "dev-3",
          device_identity_pubkey: { algorithm: "ed25519", public_key: "CCCC", key_id: "fp3" },
        },
      ],
      issued_at: "2026-04-21T10:00:00Z",
      signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xbb);
    const pub = publicKeyFromSeed(seed);
    const m = emptyManifest();
    signManifest(m, seed, fingerprint(pub));
    expect(verifyManifest(m, pub)).toBe(true);
  });

  test("validate rejects duplicate share_index", () => {
    const m = emptyManifest();
    m.contributors[1]!.share_index = 1; // collide with [0]
    expect(() => signManifest(m, deterministicSeed(1), "x")).toThrow(/share_index/);
  });

  test("validate rejects duplicate device_id", () => {
    const m = emptyManifest();
    m.contributors[1]!.device_id = "dev-1";
    expect(() => signManifest(m, deterministicSeed(1), "x")).toThrow(/device_id/);
  });

  test("validate rejects contributors length != total_shares", () => {
    const m = emptyManifest();
    m.contributors.pop();
    expect(() => signManifest(m, deterministicSeed(1), "x")).toThrow(/total_shares/);
  });
});

describe("RecoveryShareRecord sign + verify + cross-check", () => {
  function emptyShare(index: number, deviceId: string): RecoveryShareRecord {
    return {
      type: "SEMP_RECOVERY_SHARE",
      version: "1.0.0",
      bundle_id: "bundle-1",
      share_index: index,
      device_id: deviceId,
      threshold: 2,
      total_shares: 3,
      share_value: "AAAA",
      issued_at: "2026-04-21T10:00:00Z",
      device_signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xcc);
    const pub = publicKeyFromSeed(seed);
    const s = emptyShare(1, "dev-1");
    signShareRecord(s, seed, fingerprint(pub));
    expect(verifyShareRecord(s, pub)).toBe(true);
  });

  test("checkShareMatchesManifest accepts matching pair", () => {
    const m: RecoverySetManifest = {
      type: "SEMP_RECOVERY_SET_MANIFEST",
      version: "1.0.0",
      bundle_id: "bundle-1",
      threshold: 2,
      total_shares: 3,
      contributors: [
        {
          share_index: 1,
          device_id: "dev-1",
          device_identity_pubkey: { algorithm: "ed25519", public_key: "AAAA", key_id: "fp1" },
        },
        {
          share_index: 2,
          device_id: "dev-2",
          device_identity_pubkey: { algorithm: "ed25519", public_key: "BBBB", key_id: "fp2" },
        },
        {
          share_index: 3,
          device_id: "dev-3",
          device_identity_pubkey: { algorithm: "ed25519", public_key: "CCCC", key_id: "fp3" },
        },
      ],
      issued_at: "2026-04-21T10:00:00Z",
      signature: { algorithm: "ed25519", key_id: "x", value: "AAA=" },
    };
    expect(checkShareMatchesManifest(emptyShare(1, "dev-1"), m)).toBe(true);
    expect(checkShareMatchesManifest(emptyShare(1, "dev-2"), m)).toBe(false);
    expect(checkShareMatchesManifest(emptyShare(99, "dev-1"), m)).toBe(false);
  });

  test("validate rejects inconsistent (threshold, total_shares, share_index)", () => {
    const s = emptyShare(5, "dev-1"); // share_index > total_shares
    expect(() => signShareRecord(s, deterministicSeed(1), "x")).toThrow(
      /inconsistent/,
    );
  });
});

describe("BackupBundle sign + verify + validate", () => {
  function emptyBundle(): BackupBundle {
    return {
      type: "SEMP_BACKUP_BUNDLE",
      version: "1.0.0",
      user_id: "alice@example.com",
      bundle_id: "bundle-1",
      created_at: "2026-04-21T10:00:00Z",
      supersedes: null,
      kdf: {
        algorithm: "argon2id",
        salt: "QUFBQUFBQUFBQUFBQUFBQQ==", // 16 'A' bytes
        memory_kb: RecommendedKDFMemoryKB,
        iterations: RecommendedKDFIterations,
        parallelism: RecommendedKDFParallelism,
      },
      payload_algorithm: "xchacha20-poly1305",
      payload_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      encrypted_payload: "Zm9v",
      recovery_verify_pk: { algorithm: "ed25519", public_key: "BBBB" },
      signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xdd);
    const pub = publicKeyFromSeed(seed);
    const b = emptyBundle();
    signBundle(b, seed, fingerprint(pub));
    expect(verifyBundle(b, pub)).toBe(true);
  });

  test("validate rejects below-floor KDF parameters", () => {
    const b = emptyBundle();
    b.kdf.memory_kb = 1024;
    expect(() => validateBundle(b)).toThrow(/memory_kb/);
  });

  test("validate rejects salt below 16 bytes", () => {
    const b = emptyBundle();
    b.kdf.salt = "QUFB"; // 3 bytes after b64 decode
    expect(() => validateBundle(b)).toThrow(/salt/);
  });

  test("validate rejects wrong payload_algorithm", () => {
    const b = emptyBundle();
    b.payload_algorithm = "aes-gcm";
    expect(() => validateBundle(b)).toThrow(/payload_algorithm/);
  });

  test("validate rejects wrong KDF algorithm", () => {
    const b = emptyBundle();
    b.kdf.algorithm = "scrypt";
    expect(() => validateBundle(b)).toThrow(/kdf.algorithm/);
  });

  test("validate accepts non-null supersedes string", () => {
    const b = emptyBundle();
    b.supersedes = "bundle-0";
    validateBundle(b, { skipSignatureCheck: true });
  });
});
