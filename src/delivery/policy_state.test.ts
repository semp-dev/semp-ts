/**
 * Tests for {@link PolicyState} — the per-user authoritative policy
 * view per DELIVERY.md §7.2.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  PolicyApplyError,
  PolicyState,
  defaultPolicyKinds,
} from "./policy_state.js";
import {
  type UserPolicyMessage,
  PolicyKindBlock,
  PolicyKindFirstContact,
  UserPolicyStep,
  UserPolicyType,
  UserPolicyVersion,
} from "./user_policy.js";

function buildMessage(
  overrides: Partial<UserPolicyMessage> = {},
): UserPolicyMessage {
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
        entry: { id: "block-1", entity: "spam@bad.com" },
      },
    ],
    signature: { algorithm: "ed25519", key_id: "fp-1", value: "sig" },
    ...overrides,
  };
}

describe("PolicyState", () => {
  test("initial state has version 0 and default kinds registered", () => {
    const s = new PolicyState("alice@example.com");
    expect(s.userId()).toBe("alice@example.com");
    expect(s.currentVersion()).toBe(0);
    expect(s.lastTimestamp()).toBe("");
    for (const k of defaultPolicyKinds()) {
      expect(s.supportsKind(k)).toBe(true);
    }
    expect(s.supportsKind("custom.dev/x")).toBe(false);
  });

  test("apply add advances version and persists entry", () => {
    const s = new PolicyState("alice@example.com");
    s.apply(buildMessage());
    expect(s.currentVersion()).toBe(1);
    expect(s.lastTimestamp()).toBe("2026-05-08T10:00:00Z");
    const list = s.listEntries(PolicyKindBlock);
    expect(list["block-1"]).toBeDefined();
  });

  test("apply singleton modify upserts the singleton", () => {
    const s = new PolicyState("alice@example.com");
    s.apply(
      buildMessage({
        operations: [
          {
            op: "modify",
            kind: PolicyKindFirstContact,
            entry: { policy: "default-allow" },
          },
        ],
      }),
    );
    expect(s.singleton(PolicyKindFirstContact)).toEqual({
      policy: "default-allow",
    });
  });

  test("rejects unsupported kind atomically (state unchanged)", () => {
    const s = new PolicyState("alice@example.com");
    expect(() =>
      s.apply(
        buildMessage({
          operations: [
            {
              op: "add",
              kind: "custom.dev/unknown",
              entry: { id: "x" },
            },
          ],
        }),
      ),
    ).toThrow(PolicyApplyError);
    expect(s.currentVersion()).toBe(0);
    expect(s.listEntries(PolicyKindBlock)).toEqual({});
  });

  test("rejects mixed-kind message atomically when one kind is unknown", () => {
    const s = new PolicyState("alice@example.com");
    expect(() =>
      s.apply(
        buildMessage({
          operations: [
            {
              op: "add",
              kind: PolicyKindBlock,
              entry: { id: "block-1" },
            },
            {
              op: "add",
              kind: "custom.dev/unknown",
              entry: { id: "x" },
            },
          ],
        }),
      ),
    ).toThrow(/policy operation\[1\] kind "custom\.dev\/unknown"/);
    // First op MUST NOT have been applied.
    expect(s.listEntries(PolicyKindBlock)).toEqual({});
  });

  test("rejects stale policy_version", () => {
    const s = new PolicyState("alice@example.com");
    s.apply(buildMessage());
    expect(() =>
      s.apply(
        buildMessage({
          policy_version: 1,
          timestamp: "2026-05-08T10:00:00Z",
        }),
      ),
    ).toThrow(/not greater than current/);
  });

  test("rejects mismatched user_id", () => {
    const s = new PolicyState("alice@example.com");
    expect(() => s.apply(buildMessage({ user_id: "bob@example.com" }))).toThrow(
      /does not match state user_id/,
    );
  });

  test("remove deletes by entry_id", () => {
    const s = new PolicyState("alice@example.com");
    s.apply(buildMessage());
    s.apply(
      buildMessage({
        policy_version: 2,
        timestamp: "2026-05-08T11:00:00Z",
        operations: [
          {
            op: "remove",
            kind: PolicyKindBlock,
            entry_id: "block-1",
          },
        ],
      }),
    );
    expect(s.listEntries(PolicyKindBlock)).toEqual({});
  });

  test("snapshot returns a deep copy", () => {
    const s = new PolicyState("alice@example.com");
    s.apply(buildMessage());
    const snap = s.snapshot();
    expect(snap.policy_version).toBe(1);
    expect(snap.user_id).toBe("alice@example.com");
    // Mutate snap; live state must be unaffected.
    snap.list_entries[PolicyKindBlock] = {};
    expect(s.listEntries(PolicyKindBlock)["block-1"]).toBeDefined();
  });
});
