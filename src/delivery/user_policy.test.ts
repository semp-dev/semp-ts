/**
 * Tests for SEMP_USER_POLICY records.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  PolicyKindBlock,
  PolicyKindFirstContact,
  type UserPolicyMessage,
  UserPolicyStep,
  UserPolicyType,
  UserPolicyVersion,
  signUserPolicyMessage,
  validateUserPolicyMessage,
  verifyUserPolicyMessage,
} from "./user_policy.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function emptyMessage(): UserPolicyMessage {
  return {
    type: UserPolicyType,
    step: UserPolicyStep,
    version: UserPolicyVersion,
    user_id: "alice@example.com",
    device_id: "01JDEV01",
    policy_version: 1,
    timestamp: "2026-05-08T10:00:00Z",
    operations: [
      {
        op: "add",
        kind: PolicyKindBlock,
        entry: { entry_id: "b1" },
      },
    ],
    signature: { algorithm: "", key_id: "", value: "" },
  };
}

describe("signUserPolicyMessage / verifyUserPolicyMessage", () => {
  test("round-trip", () => {
    const s = seed(0x22);
    const pub = publicKeyFromSeed(s);
    const fp = fingerprint(pub);
    const m = emptyMessage();
    signUserPolicyMessage(m, s, fp);
    expect(verifyUserPolicyMessage(m, pub)).toBe(true);
  });

  test("verify under wrong pub returns false", () => {
    const m = emptyMessage();
    signUserPolicyMessage(m, seed(0x22), fingerprint(publicKeyFromSeed(seed(0x22))));
    expect(verifyUserPolicyMessage(m, publicKeyFromSeed(seed(0x99)))).toBe(
      false,
    );
  });

  test("singleton kind first_contact accepts only modify", () => {
    const m = emptyMessage();
    m.operations = [
      {
        op: "add",
        kind: PolicyKindFirstContact,
        entry: { policy: "default" },
      },
    ];
    expect(() =>
      validateUserPolicyMessage(m, { skipSignatureCheck: true }),
    ).toThrow(/accepts only modify/);
  });

  test("singleton kind first_contact MUST NOT carry entry_id", () => {
    const m = emptyMessage();
    m.operations = [
      {
        op: "modify",
        kind: PolicyKindFirstContact,
        entry_id: "x",
        entry: { policy: "x" },
      },
    ];
    expect(() =>
      validateUserPolicyMessage(m, { skipSignatureCheck: true }),
    ).toThrow(/MUST NOT carry entry_id/);
  });

  test("singleton kind first_contact modify MUST carry entry", () => {
    const m = emptyMessage();
    m.operations = [
      {
        op: "modify",
        kind: PolicyKindFirstContact,
      },
    ];
    expect(() =>
      validateUserPolicyMessage(m, { skipSignatureCheck: true }),
    ).toThrow(/MUST carry entry/);
  });

  test("policy_version must be >= 1", () => {
    const m = emptyMessage();
    m.policy_version = 0;
    expect(() =>
      validateUserPolicyMessage(m, { skipSignatureCheck: true }),
    ).toThrow(/policy_version/);
  });

  test("requires non-empty operations", () => {
    const m = emptyMessage();
    m.operations = [];
    expect(() =>
      validateUserPolicyMessage(m, { skipSignatureCheck: true }),
    ).toThrow(/non-empty/);
  });

  test("remove op must set entry_id", () => {
    const m = emptyMessage();
    m.operations = [{ op: "remove", kind: PolicyKindBlock }];
    expect(() =>
      validateUserPolicyMessage(m, { skipSignatureCheck: true }),
    ).toThrow(/remove op MUST set entry_id/);
  });
});
