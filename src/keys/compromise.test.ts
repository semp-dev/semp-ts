/**
 * Tests for the KEY.md §10.5.5 atomic identity-key rotation cascade.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  buildCompromiseRotation,
  verifyCompromiseRotation,
} from "./compromise.js";
import { fingerprint, publicKeyFromSeed } from "./sign.js";

function seedAt(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

interface Pair {
  seed: Uint8Array;
  pub: Uint8Array;
  fp: string;
}

function pair(byte: number): Pair {
  const seed = seedAt(byte);
  const pub = publicKeyFromSeed(seed);
  return { seed, pub, fp: fingerprint(pub) };
}

function freshFixture(): {
  prior: Pair;
  newId: Pair;
  newEnc: Pair;
  recovery: Pair;
} {
  return {
    prior: pair(0x11),
    newId: pair(0x22),
    newEnc: pair(0x33),
    recovery: pair(0x44),
  };
}

describe("buildCompromiseRotation / verifyCompromiseRotation", () => {
  test("round-trip: every artifact present, two-sig successor verified", () => {
    const f = freshFixture();
    const r = buildCompromiseRotation({
      userId: "alice@example.com",
      compromisedDeviceId: "01JCOMPROMISED00000000000001",
      revokingDeviceId: "01JREVOKING000000000000000001",
      priorIdentitySeed: f.prior.seed,
      priorIdentityKeyId: f.prior.fp,
      newIdentitySeed: f.newId.seed,
      newIdentityPublicKey: f.newId.pub,
      newIdentityKeyId: f.newId.fp,
      newEncryptionPublicKey: f.newEnc.pub,
      newEncryptionKeyId: f.newEnc.fp,
      recoverySeed: f.recovery.seed,
      recoveryKeyId: "recovery-fp-001",
      now: new Date("2026-05-08T10:00:00Z"),
    });

    expect(r.device_revocation.reason).toBe("key_compromise");
    expect(r.device_revocation.revoked_by_device_id).toBe(
      "01JREVOKING000000000000000001",
    );
    expect(r.successor.recovery_signature.value).not.toBe("");
    expect(r.successor.new_key_signature.value).not.toBe("");
    expect(r.successor.domain_signature.value).toBe(""); // home server fills later
    expect(r.successor.domain_signature.key_id).toBe(""); // empty until home server
    expect(r.new_identity_key_id).toBe(f.newId.fp);
    expect(r.prior_identity_revocation.revoked_keys).toHaveLength(1);
    expect(r.prior_identity_revocation.revoked_keys[0]!.replacement_key_id).toBe(
      f.newId.fp,
    );

    expect(() =>
      verifyCompromiseRotation(r, f.prior.pub, f.recovery.pub),
    ).not.toThrow();
  });

  test("rejects tampered device-revocation reason (not key_compromise)", () => {
    const f = freshFixture();
    const r = buildCompromiseRotation({
      userId: "alice@example.com",
      compromisedDeviceId: "d-old",
      revokingDeviceId: "d-new",
      priorIdentitySeed: f.prior.seed,
      priorIdentityKeyId: f.prior.fp,
      newIdentitySeed: f.newId.seed,
      newIdentityPublicKey: f.newId.pub,
      newIdentityKeyId: f.newId.fp,
      newEncryptionPublicKey: f.newEnc.pub,
      newEncryptionKeyId: f.newEnc.fp,
      recoverySeed: f.recovery.seed,
      recoveryKeyId: "rfp",
    });
    r.device_revocation.reason = "lost";
    expect(() =>
      verifyCompromiseRotation(r, f.prior.pub, f.recovery.pub),
    ).toThrow(/key_compromise/);
  });

  test("rejects mismatched replacement_key_id between revocation and cascade", () => {
    const f = freshFixture();
    const r = buildCompromiseRotation({
      userId: "alice@example.com",
      compromisedDeviceId: "d-old",
      revokingDeviceId: "d-new",
      priorIdentitySeed: f.prior.seed,
      priorIdentityKeyId: f.prior.fp,
      newIdentitySeed: f.newId.seed,
      newIdentityPublicKey: f.newId.pub,
      newIdentityKeyId: f.newId.fp,
      newEncryptionPublicKey: f.newEnc.pub,
      newEncryptionKeyId: f.newEnc.fp,
      recoverySeed: f.recovery.seed,
      recoveryKeyId: "rfp",
    });
    // Mutate the cascade's new_identity_key_id; the embedded revocation
    // was signed against the original new fp, so the cross-check fails.
    r.new_identity_key_id = "attacker-fp";
    expect(() =>
      verifyCompromiseRotation(r, f.prior.pub, f.recovery.pub),
    ).toThrow(/replacement/);
  });

  test("rejects wrong recovery verify pub", () => {
    const f = freshFixture();
    const wrongRecovery = pair(0x55);
    const r = buildCompromiseRotation({
      userId: "alice@example.com",
      compromisedDeviceId: "d-old",
      revokingDeviceId: "d-new",
      priorIdentitySeed: f.prior.seed,
      priorIdentityKeyId: f.prior.fp,
      newIdentitySeed: f.newId.seed,
      newIdentityPublicKey: f.newId.pub,
      newIdentityKeyId: f.newId.fp,
      newEncryptionPublicKey: f.newEnc.pub,
      newEncryptionKeyId: f.newEnc.fp,
      recoverySeed: f.recovery.seed,
      recoveryKeyId: "rfp",
    });
    expect(() =>
      verifyCompromiseRotation(r, f.prior.pub, wrongRecovery.pub),
    ).toThrow(/successor/);
  });

  test("rejects identical prior and new identity fingerprints", () => {
    const f = freshFixture();
    expect(() =>
      buildCompromiseRotation({
        userId: "alice@example.com",
        compromisedDeviceId: "d-old",
        revokingDeviceId: "d-new",
        priorIdentitySeed: f.prior.seed,
        priorIdentityKeyId: f.prior.fp,
        newIdentitySeed: f.prior.seed,
        newIdentityPublicKey: f.prior.pub,
        newIdentityKeyId: f.prior.fp,
        newEncryptionPublicKey: f.newEnc.pub,
        newEncryptionKeyId: f.newEnc.fp,
        recoverySeed: f.recovery.seed,
        recoveryKeyId: "rfp",
      }),
    ).toThrow(/prior and new identity/);
  });

  test("rejects missing inputs", () => {
    const f = freshFixture();
    expect(() =>
      buildCompromiseRotation({
        userId: "",
        compromisedDeviceId: "d-old",
        revokingDeviceId: "d-new",
        priorIdentitySeed: f.prior.seed,
        priorIdentityKeyId: f.prior.fp,
        newIdentitySeed: f.newId.seed,
        newIdentityPublicKey: f.newId.pub,
        newIdentityKeyId: f.newId.fp,
        newEncryptionPublicKey: f.newEnc.pub,
        newEncryptionKeyId: f.newEnc.fp,
        recoverySeed: f.recovery.seed,
        recoveryKeyId: "rfp",
      }),
    ).toThrow(/user_id/);
  });
});
