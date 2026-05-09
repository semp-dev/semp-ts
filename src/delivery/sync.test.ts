/**
 * Tests for SEMP_BLOCK sync messages.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type SyncMessage,
  SyncMessageType,
  SyncMessageVersion,
  SyncStep,
  signSyncMessage,
  validateSyncMessage,
  verifySyncMessage,
} from "./sync.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function emptyMessage(): SyncMessage {
  return {
    type: SyncMessageType,
    step: SyncStep,
    version: SyncMessageVersion,
    user_id: "alice@example.com",
    device_id: "01JDEV01",
    list_version: 1,
    timestamp: "2026-05-08T10:00:00Z",
    operations: [
      {
        op: "add",
        entry: {
          id: "block-1",
          entity: { type: "user", address: "spam@bad.com" },
          acknowledgment: "rejected",
          scope: "all",
          created_at: "2026-05-08T10:00:00Z",
          created_by_device_id: "01JDEV01",
        },
      },
    ],
    signature: { algorithm: "", key_id: "", value: "" },
  };
}

describe("signSyncMessage / verifySyncMessage", () => {
  test("round-trip: sign then verify under matching pub", () => {
    const s = seed(0x11);
    const pub = publicKeyFromSeed(s);
    const fp = fingerprint(pub);
    const m = emptyMessage();
    signSyncMessage(m, s, fp);
    expect(m.signature.algorithm).toBe("ed25519");
    expect(m.signature.key_id).toBe(fp);
    expect(m.signature.value).not.toBe("");
    expect(verifySyncMessage(m, pub)).toBe(true);
  });

  test("verify under wrong pub returns false", () => {
    const m = emptyMessage();
    signSyncMessage(m, seed(0x11), fingerprint(publicKeyFromSeed(seed(0x11))));
    const wrong = publicKeyFromSeed(seed(0x99));
    expect(verifySyncMessage(m, wrong)).toBe(false);
  });

  test("validateSyncMessage catches bad list_version", () => {
    const m = emptyMessage();
    m.list_version = -1;
    expect(() => validateSyncMessage(m, { skipSignatureCheck: true })).toThrow(
      /list_version/,
    );
  });

  test("validateSyncMessage catches malformed remove op", () => {
    const m = emptyMessage();
    m.operations = [{ op: "remove" }];
    expect(() => validateSyncMessage(m, { skipSignatureCheck: true })).toThrow(
      /MUST set entry_id/,
    );
  });

  test("validateSyncMessage requires non-empty operations", () => {
    const m = emptyMessage();
    m.operations = [];
    expect(() => validateSyncMessage(m, { skipSignatureCheck: true })).toThrow(
      /non-empty/,
    );
  });
});
