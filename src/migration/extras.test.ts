/**
 * Tests for the new migration primitives: verify, validate, lockout,
 * notice, publication store, build/accept submission, third-party.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type MigrationRecord,
  type ThirdPartyPolicy,
  InMemoryLockoutRegistry,
  InMemoryPublicationStore,
  MaxNoticeWindowMs,
  MinNoticeWindowMs,
  RecommendedNoticeWindowMs,
  acceptSubmission,
  applyThirdPartyPolicy,
  buildMigrationNotice,
  buildSubmission,
  checkMigratedAtBound,
  composeMigrationRecord,
  newMigrationNoticeRejection,
  validateMigrationRecord,
  verifyMigrationPass,
  verifyMigrationRecord,
} from "./index.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

interface FullChainKeys {
  oldIdSeed: Uint8Array;
  oldIdPub: Uint8Array;
  oldIdKeyId: string;
  newIdSeed: Uint8Array;
  newIdPub: Uint8Array;
  newIdKeyId: string;
  oldDomSeed: Uint8Array;
  oldDomPub: Uint8Array;
  oldDomKeyId: string;
  newDomSeed: Uint8Array;
  newDomPub: Uint8Array;
  newDomKeyId: string;
}

function buildKeys(): FullChainKeys {
  const oldIdSeed = deterministicSeed(0xa1);
  const oldIdPub = publicKeyFromSeed(oldIdSeed);
  const newIdSeed = deterministicSeed(0xa2);
  const newIdPub = publicKeyFromSeed(newIdSeed);
  const oldDomSeed = deterministicSeed(0xa3);
  const oldDomPub = publicKeyFromSeed(oldDomSeed);
  const newDomSeed = deterministicSeed(0xa4);
  const newDomPub = publicKeyFromSeed(newDomSeed);
  return {
    oldIdSeed,
    oldIdPub,
    oldIdKeyId: fingerprint(oldIdPub),
    newIdSeed,
    newIdPub,
    newIdKeyId: fingerprint(newIdPub),
    oldDomSeed,
    oldDomPub,
    oldDomKeyId: fingerprint(oldDomPub),
    newDomSeed,
    newDomPub,
    newDomKeyId: fingerprint(newDomPub),
  };
}

function base64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

describe("composeMigrationRecord + verifyMigrationRecord", () => {
  test("cooperative: 4-sig round-trip verifies", () => {
    const k = buildKeys();
    const r = composeMigrationRecord({
      mode: "cooperative",
      recordId: "01J7MIGRATE0000000000000",
      migratedAt: "2026-04-21T10:00:00Z",
      noticeWindowUntil: "2027-04-21T10:00:00Z", // 365d ≈ within bounds
      oldAddress: "alice@old.example",
      newAddress: "alice@new.example",
      oldIdentityKeyId: k.oldIdKeyId,
      oldIdentitySeed: k.oldIdSeed,
      newIdentityKeyId: k.newIdKeyId,
      newIdentityPublicKey: base64(k.newIdPub),
      newIdentitySeed: k.newIdSeed,
      newDomainKeyId: k.newDomKeyId,
      newDomainSeed: k.newDomSeed,
      oldDomainKeyId: k.oldDomKeyId,
      oldDomainSeed: k.oldDomSeed,
    });
    expect(verifyMigrationRecord(r, k.oldIdPub, k.newIdPub, k.newDomPub, k.oldDomPub)).toBe(
      true,
    );
  });

  test("unilateral: 3-sig round-trip verifies (no old_domain_signature)", () => {
    const k = buildKeys();
    const r = composeMigrationRecord({
      mode: "unilateral",
      recordId: "01J7MIGRATEUNI000000000000",
      migratedAt: "2026-04-21T10:00:00Z",
      oldAddress: "alice@old.example",
      newAddress: "alice@new.example",
      oldIdentityKeyId: k.oldIdKeyId,
      oldIdentitySeed: k.oldIdSeed,
      newIdentityKeyId: k.newIdKeyId,
      newIdentityPublicKey: base64(k.newIdPub),
      newIdentitySeed: k.newIdSeed,
      newDomainKeyId: k.newDomKeyId,
      newDomainSeed: k.newDomSeed,
    });
    expect(r.old_domain_signature).toBeNull();
    expect(verifyMigrationRecord(r, k.oldIdPub, k.newIdPub, k.newDomPub, null)).toBe(true);
  });

  test("verify fails when one slot tampered", () => {
    const k = buildKeys();
    const r = composeMigrationRecord({
      mode: "cooperative",
      recordId: "01J7MIGRATE0000000000000",
      migratedAt: "2026-04-21T10:00:00Z",
      noticeWindowUntil: "2027-04-21T10:00:00Z",
      oldAddress: "alice@old.example",
      newAddress: "alice@new.example",
      oldIdentityKeyId: k.oldIdKeyId,
      oldIdentitySeed: k.oldIdSeed,
      newIdentityKeyId: k.newIdKeyId,
      newIdentityPublicKey: base64(k.newIdPub),
      newIdentitySeed: k.newIdSeed,
      newDomainKeyId: k.newDomKeyId,
      newDomainSeed: k.newDomSeed,
      oldDomainKeyId: k.oldDomKeyId,
      oldDomainSeed: k.oldDomSeed,
    });
    r.new_address = "evil@new.example";
    expect(verifyMigrationRecord(r, k.oldIdPub, k.newIdPub, k.newDomPub, k.oldDomPub)).toBe(
      false,
    );
  });

  test("verifyMigrationPass works on partial submission", () => {
    const k = buildKeys();
    const r = buildSubmission({
      oldAddress: "alice@old.example",
      newAddress: "alice@new.example",
      oldIdentityKeyId: k.oldIdKeyId,
      newIdentityKeyId: k.newIdKeyId,
      newIdentityPublicKey: base64(k.newIdPub),
      oldIdentityPriv: k.oldIdSeed,
      newIdentityPriv: k.newIdSeed,
      newDomainKeyId: k.newDomKeyId,
      newDomainPriv: k.newDomSeed,
      oldDomainKeyId: k.oldDomKeyId, // populated up front so canonical bytes are stable
      mode: "cooperative",
      noticeWindowMs: RecommendedNoticeWindowMs,
      migratedAt: "2026-04-21T10:00:00Z",
    });
    // Three signatures present, fourth empty - partial submission.
    expect(r.old_domain_signature?.value).toBe("");
    expect(verifyMigrationPass(r, 0, k.oldIdPub)).toBe(true);
    expect(verifyMigrationPass(r, 1, k.newIdPub)).toBe(true);
    expect(verifyMigrationPass(r, 2, k.newDomPub)).toBe(true);
  });
});

describe("validateMigrationRecord", () => {
  test("rejects below-min notice window in cooperative mode", () => {
    const r = stubRecord();
    r.notice_window_until = "2026-05-01T10:00:00Z"; // 10 days < 30
    expect(() => validateMigrationRecord(r)).toThrow(/below minimum/);
  });

  test("rejects above-max notice window", () => {
    const r = stubRecord();
    r.notice_window_until = "2030-04-21T10:00:00Z"; // 4 years > 2
    expect(() => validateMigrationRecord(r)).toThrow(/exceeds maximum/);
  });

  test("rejects unknown mode", () => {
    const r = stubRecord();
    (r as unknown as { mode: string }).mode = "future";
    expect(() => validateMigrationRecord(r)).toThrow(/mode/);
  });

  test("unilateral record forbids old_domain_signature", () => {
    const r = stubRecord();
    r.mode = "unilateral";
    r.notice_window_until = null;
    r.old_domain_signature = { algorithm: "ed25519", key_id: "x", value: "AAA=" };
    expect(() => validateMigrationRecord(r)).toThrow(
      /unilateral record MUST NOT carry/,
    );
  });
});

describe("checkMigratedAtBound", () => {
  test("rejects migrated_at before old key created", () => {
    const r = stubRecord();
    r.migrated_at = "2025-01-01T00:00:00Z";
    expect(() =>
      checkMigratedAtBound(
        r,
        new Date("2026-01-01T00:00:00Z"),
        new Date("2026-04-21T10:00:00Z"),
      ),
    ).toThrow(/precedes/);
  });

  test("rejects migrated_at in the future beyond skew", () => {
    const r = stubRecord();
    r.migrated_at = "2030-01-01T00:00:00Z";
    expect(() =>
      checkMigratedAtBound(
        r,
        null,
        new Date("2026-04-21T10:00:00Z"),
      ),
    ).toThrow(/in the future/);
  });

  test("permits migrated_at within skew", () => {
    const r = stubRecord();
    r.migrated_at = "2026-04-21T10:01:00Z";
    checkMigratedAtBound(
      r,
      null,
      new Date("2026-04-21T10:00:00Z"),
      5 * 60 * 1000,
    );
  });
});

describe("buildSubmission + acceptSubmission", () => {
  test("cooperative round-trip ends with verifiable 4-sig record", async () => {
    const k = buildKeys();
    const submission = buildSubmission({
      oldAddress: "alice@old.example",
      newAddress: "alice@new.example",
      oldIdentityKeyId: k.oldIdKeyId,
      newIdentityKeyId: k.newIdKeyId,
      newIdentityPublicKey: base64(k.newIdPub),
      oldIdentityPriv: k.oldIdSeed,
      newIdentityPriv: k.newIdSeed,
      newDomainKeyId: k.newDomKeyId,
      newDomainPriv: k.newDomSeed,
      oldDomainKeyId: k.oldDomKeyId,
      mode: "cooperative",
      noticeWindowMs: RecommendedNoticeWindowMs,
      migratedAt: "2026-04-21T10:00:00Z",
    });
    expect(submission.old_domain_signature?.value).toBe("");

    const lockout = new InMemoryLockoutRegistry();
    const store = new InMemoryPublicationStore();

    const accepted = await acceptSubmission({
      record: submission,
      oldIdentityPub: k.oldIdPub,
      newDomainPub: k.newDomPub,
      oldDomainPriv: k.oldDomSeed,
      oldDomainKeyId: k.oldDomKeyId,
      now: new Date("2026-04-21T10:30:00Z"),
      lockout,
      store,
    });
    expect(accepted.old_domain_signature?.value).not.toBe("");
    expect(verifyMigrationRecord(accepted, k.oldIdPub, k.newIdPub, k.newDomPub, k.oldDomPub)).toBe(
      true,
    );

    expect(await store.getByOldAddress("alice@old.example")).not.toBeNull();
    expect(
      await lockout.isLockedOut("alice", new Date("2026-04-21T11:00:00Z")),
    ).not.toBeNull();
  });

  test("acceptSubmission rejects unilateral records", async () => {
    const k = buildKeys();
    const r = composeMigrationRecord({
      mode: "unilateral",
      recordId: "01J7UNILAT000000000000",
      migratedAt: "2026-04-21T10:00:00Z",
      oldAddress: "alice@old.example",
      newAddress: "alice@new.example",
      oldIdentityKeyId: k.oldIdKeyId,
      oldIdentitySeed: k.oldIdSeed,
      newIdentityKeyId: k.newIdKeyId,
      newIdentityPublicKey: base64(k.newIdPub),
      newIdentitySeed: k.newIdSeed,
      newDomainKeyId: k.newDomKeyId,
      newDomainSeed: k.newDomSeed,
    });
    await expect(
      acceptSubmission({
        record: r,
        oldIdentityPub: k.oldIdPub,
        newDomainPub: k.newDomPub,
        oldDomainPriv: k.oldDomSeed,
        oldDomainKeyId: k.oldDomKeyId,
        now: new Date("2026-04-21T10:30:00Z"),
      }),
    ).rejects.toThrow(/cooperative/);
  });

  test("notice policy hook can refuse the submission", async () => {
    const k = buildKeys();
    const r = buildSubmission(stubBuildSubmission(k));
    await expect(
      acceptSubmission({
        record: r,
        oldIdentityPub: k.oldIdPub,
        newDomainPub: k.newDomPub,
        oldDomainPriv: k.oldDomSeed,
        oldDomainKeyId: k.oldDomKeyId,
        now: new Date("2026-04-21T10:30:00Z"),
        noticePolicy: () => {
          throw new Error("policy refused");
        },
      }),
    ).rejects.toThrow(/policy refused/);
  });
});

describe("LockoutRegistry", () => {
  test("reserve + isLockedOut + release", async () => {
    const reg = new InMemoryLockoutRegistry();
    await reg.reserve("alice", new Date("2026-12-31T23:59:59Z"), "rec-1");
    const r = await reg.isLockedOut("alice", new Date("2026-04-21T10:00:00Z"));
    expect(r?.localpart).toBe("alice");
    await reg.release("alice");
    expect(await reg.isLockedOut("alice", new Date())).toBeNull();
  });

  test("double reserve throws", async () => {
    const reg = new InMemoryLockoutRegistry();
    await reg.reserve("alice", new Date("2099-01-01T00:00:00Z"), "r1");
    await expect(
      reg.reserve("alice", new Date("2099-01-01T00:00:00Z"), "r2"),
    ).rejects.toThrow(/already locked/);
  });

  test("expired entries auto-clear on isLockedOut", async () => {
    const reg = new InMemoryLockoutRegistry();
    await reg.reserve("alice", new Date("2020-01-01T00:00:00Z"), "rec-1");
    expect(
      await reg.isLockedOut("alice", new Date("2026-04-21T10:00:00Z")),
    ).toBeNull();
  });

  test("pruneExpired drops past-due entries", async () => {
    const reg = new InMemoryLockoutRegistry();
    await reg.reserve("alice", new Date("2020-01-01T00:00:00Z"), "r1");
    await reg.reserve("bob", new Date("2099-01-01T00:00:00Z"), "r2");
    expect(await reg.pruneExpired(new Date("2026-04-21T10:00:00Z"))).toBe(1);
  });
});

describe("MigrationNotice + rejection", () => {
  test("buildMigrationNotice substitutes record_id into URL pattern", () => {
    const r = stubRecord();
    const notice = buildMigrationNotice({
      record: r,
      recordUrlPattern: "https://old.example/migration/<record_id>",
    });
    expect(notice.new_address).toBe(r.new_address);
    expect(notice.migration_record_id).toBe(r.record_id);
    expect(notice.migration_record_url).toBe(
      `https://old.example/migration/${r.record_id}`,
    );
  });

  test("buildMigrationNotice omits migration_record_url when pattern is empty", () => {
    const notice = buildMigrationNotice({ record: stubRecord() });
    expect(notice.migration_record_url).toBeUndefined();
  });

  test("buildMigrationNotice uses pattern verbatim when no placeholder present", () => {
    const r = stubRecord();
    const notice = buildMigrationNotice({
      record: r,
      recordUrlPattern: "https://old.example/migration/fixed",
    });
    expect(notice.migration_record_url).toBe(
      "https://old.example/migration/fixed",
    );
  });

  test("newMigrationNoticeRejection wraps a notice in the §5.3 rejection shape", () => {
    const r = stubRecord();
    const notice = buildMigrationNotice({
      record: r,
      recordUrlPattern: "https://old.example/migration/<record_id>",
    });
    const rejection = newMigrationNoticeRejection(notice, "Recipient has migrated.");
    expect(rejection.type).toBe("SEMP_ENVELOPE");
    expect(rejection.step).toBe("rejected");
    expect(rejection.reason_code).toBe("policy_forbidden");
    expect(rejection.reason).toBe("Recipient has migrated.");
    expect(rejection.migration_notice).toBe(notice);
  });
});

describe("PublicationStore", () => {
  test("putRecord + getByOldAddress + getByRecordId", async () => {
    const store = new InMemoryPublicationStore();
    const r = stubRecord();
    await store.putRecord(r);
    expect(await store.getByOldAddress(r.old_address)).not.toBeNull();
    expect(await store.getByRecordId(r.record_id)).not.toBeNull();
    expect(await store.getByOldAddress("ghost@x")).toBeNull();
    expect(await store.getByRecordId("ghost-id")).toBeNull();
  });

  test("case-insensitive old address lookup", async () => {
    const store = new InMemoryPublicationStore();
    const r = stubRecord();
    await store.putRecord(r);
    expect(
      await store.getByOldAddress(r.old_address.toUpperCase()),
    ).not.toBeNull();
  });

  test("rejects empty record_id / old_address", async () => {
    const store = new InMemoryPublicationStore();
    const r = stubRecord();
    r.record_id = "";
    await expect(store.putRecord(r)).rejects.toThrow(/record_id/);
  });
});

describe("applyThirdPartyPolicy", () => {
  test("runs every non-nil hook; aggregates errors", async () => {
    const r = stubRecord();
    const policy: ThirdPartyPolicy = {
      verifyChain: () => undefined,
      acceptability: () => {
        throw new Error("untrusted");
      },
      transparency: () => {
        throw new Error("not in log");
      },
    };
    await expect(applyThirdPartyPolicy(r, policy)).rejects.toThrow(
      /untrusted.*not in log/,
    );
  });

  test("succeeds when every hook returns", async () => {
    const r = stubRecord();
    await applyThirdPartyPolicy(r, {
      verifyChain: () => undefined,
      acceptability: async () => {},
    });
  });
});

// ---------------------------------------------------------------------------
// Helpers

function stubRecord(): MigrationRecord {
  return {
    type: "SEMP_MIGRATION",
    version: "1.0.0",
    record_id: "01J7MIGRATE0000000000000",
    old_address: "alice@old.example",
    new_address: "alice@new.example",
    old_identity_key_id: "old-fp",
    new_identity_key_id: "new-fp",
    new_identity_public_key: "AAAA",
    migrated_at: "2026-04-21T10:00:00Z",
    notice_window_until: "2027-04-21T10:00:00Z", // 365 days
    mode: "cooperative",
    old_identity_signature: {
      algorithm: "ed25519",
      key_id: "old-fp",
      value: "AAA=",
    },
    new_identity_signature: {
      algorithm: "ed25519",
      key_id: "new-fp",
      value: "AAA=",
    },
    new_domain_signature: {
      algorithm: "ed25519",
      key_id: "newdom-fp",
      value: "AAA=",
    },
    old_domain_signature: {
      algorithm: "ed25519",
      key_id: "olddom-fp",
      value: "AAA=",
    },
  };
}

function stubBuildSubmission(k: FullChainKeys) {
  return {
    oldAddress: "alice@old.example",
    newAddress: "alice@new.example",
    oldIdentityKeyId: k.oldIdKeyId,
    newIdentityKeyId: k.newIdKeyId,
    newIdentityPublicKey: base64(k.newIdPub),
    oldIdentityPriv: k.oldIdSeed,
    newIdentityPriv: k.newIdSeed,
    newDomainKeyId: k.newDomKeyId,
    newDomainPriv: k.newDomSeed,
    oldDomainKeyId: k.oldDomKeyId,
    mode: "cooperative" as const,
    noticeWindowMs: RecommendedNoticeWindowMs,
    migratedAt: "2026-04-21T10:00:00Z",
  };
}

// Keep imports active.
void MinNoticeWindowMs;
void MaxNoticeWindowMs;
