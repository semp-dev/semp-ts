/**
 * Per-attempt delivery acknowledgment tests. Cover the wire-shape
 * builders, recipient-status visibility decision matrix from
 * `recipient-status.json` vector, and recipient_status length
 * validation.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { canonicalEnvelopeFor } from "../envelope/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type RecipientStatus,
  type Visibility,
  MaxStatusMessageBytes,
  buildDeliveredAck,
  buildRejectedAck,
  matchVisibility,
  validateRecipientStatus,
} from "./ack.js";
import { computeEnvelopeHash, signDeliveryReceipt } from "./receipt.js";

function fakeReceipt() {
  const seed = new Uint8Array(32).fill(0xc1);
  const pub = publicKeyFromSeed(seed);
  const env = {
    type: "SEMP_ENVELOPE",
    version: "1.0.0",
    postmark: {
      id: "01J7ACK0000000000000000000",
      session_id: "01J7ACKSESSION0000000000000",
      from_domain: "alice.example",
      to_domain: "bob.example",
      expires: "2026-04-22T00:00:00Z",
      extensions: {},
    },
    seal: {
      algorithm: "x25519-chacha20-poly1305",
      key_id: "alice-fp",
      signature: "SIG",
      session_mac: "MAC",
      brief_recipients: { "bob-fp": "X" },
      enclosure_recipients: { "bob-fp": "Y" },
      extensions: {},
    },
    brief: "B",
    enclosure: "E",
  };
  const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));
  return signDeliveryReceipt({
    envelopeHashB64: envHash,
    recipientDomain: "bob.example",
    acceptedAt: "2026-04-21T10:15:32Z",
    domainKeyId: fingerprint(pub),
    domainSigningSeed: seed,
  }).receipt;
}

describe("delivery.ack builders", () => {
  test("buildDeliveredAck without status omits the field", () => {
    const ack = buildDeliveredAck(fakeReceipt());
    expect(ack.acknowledgment).toBe("delivered");
    expect(ack.receipt).toBeDefined();
    expect("recipient_status" in ack).toBe(false);
    expect("reason_code" in ack).toBe(false);
  });

  test("buildDeliveredAck with status attaches it", () => {
    const status: RecipientStatus = {
      state: "away",
      message: "On leave until July.",
      until: "2025-07-01T00:00:00Z",
    };
    const ack = buildDeliveredAck(fakeReceipt(), status);
    expect(ack.recipient_status).toEqual(status);
  });

  test("buildRejectedAck populates reason_code only", () => {
    const ack = buildRejectedAck("policy_forbidden");
    expect(ack.acknowledgment).toBe("rejected");
    expect(ack.reason_code).toBe("policy_forbidden");
    expect("receipt" in ack).toBe(false);
    expect("reason" in ack).toBe(false);
  });

  test("buildRejectedAck attaches optional reason", () => {
    const ack = buildRejectedAck("rate_limited", "global cap reached");
    expect(ack.reason).toBe("global cap reached");
  });

  test("buildRejectedAck drops empty-string reason", () => {
    const ack = buildRejectedAck("rate_limited", "");
    expect("reason" in ack).toBe(false);
  });
});

describe("delivery.matchVisibility", () => {
  // Mirrors `recipient-status.json` vector samples; the vector pins
  // the decision-table outcomes, this test pins the implementation.

  test("undefined visibility never discloses", () => {
    expect(matchVisibility(undefined, { address: "anyone@x" })).toBe(false);
  });

  test("mode=nobody never discloses", () => {
    const v: Visibility = { mode: "nobody", allow: [{ type: "user", address: "a@b" }] };
    expect(matchVisibility(v, { address: "a@b" })).toBe(false);
  });

  test("mode=everyone always discloses", () => {
    const v: Visibility = { mode: "everyone" };
    expect(matchVisibility(v, {})).toBe(true);
    expect(matchVisibility(v, { address: "anyone@x" })).toBe(true);
  });

  test("mode=users matches listed addresses, ignores listed domains/servers", () => {
    const v: Visibility = {
      mode: "users",
      allow: [
        { type: "user", address: "alice@a.example" },
        { type: "domain", domain: "a.example" }, // ignored under mode=users
        { type: "server", server: "router.x" },  // ignored
      ],
    };
    expect(matchVisibility(v, { address: "alice@a.example" })).toBe(true);
    expect(matchVisibility(v, { address: "bob@a.example" })).toBe(false);
    // domain/server-only sender does NOT match because mode=users
    // requires a listed address.
    expect(matchVisibility(v, { domain: "a.example" })).toBe(false);
    expect(matchVisibility(v, { server: "router.x" })).toBe(false);
  });

  test("mode=domains matches listed domains, ignores listed users", () => {
    const v: Visibility = {
      mode: "domains",
      allow: [
        { type: "domain", domain: "work.example.com" },
        { type: "user", address: "alice@personal.example" }, // ignored
      ],
    };
    expect(matchVisibility(v, { domain: "work.example.com" })).toBe(true);
    expect(matchVisibility(v, { domain: "other.example.com" })).toBe(false);
    expect(
      matchVisibility(v, { address: "alice@personal.example" }),
    ).toBe(false);
  });

  test("mode=servers matches listed servers", () => {
    const v: Visibility = {
      mode: "servers",
      allow: [{ type: "server", server: "router.example.com" }],
    };
    expect(matchVisibility(v, { server: "router.example.com" })).toBe(true);
    expect(matchVisibility(v, { server: "other.example.com" })).toBe(false);
  });

  test("comparisons are case-insensitive", () => {
    const v: Visibility = {
      mode: "users",
      allow: [{ type: "user", address: "Alice@A.Example" }],
    };
    expect(matchVisibility(v, { address: "ALICE@a.example" })).toBe(true);
  });

  test("empty sender field disables matching for that entry type", () => {
    const v: Visibility = {
      mode: "users",
      allow: [{ type: "user", address: "alice@a.example" }],
    };
    expect(matchVisibility(v, {})).toBe(false);
    expect(matchVisibility(v, { address: "" })).toBe(false);
  });

  test("unknown mode fails closed", () => {
    const v = { mode: "future" } as unknown as Visibility;
    expect(matchVisibility(v, { address: "alice@a.example" })).toBe(false);
  });

  test("multiple rules combine as union", () => {
    const v: Visibility = {
      mode: "users",
      allow: [
        { type: "user", address: "alice@a.example" },
        { type: "user", address: "bob@b.example" },
      ],
    };
    expect(matchVisibility(v, { address: "alice@a.example" })).toBe(true);
    expect(matchVisibility(v, { address: "bob@b.example" })).toBe(true);
    expect(matchVisibility(v, { address: "carol@c.example" })).toBe(false);
  });
});

describe("delivery.validateRecipientStatus", () => {
  test("accepts the three documented states", () => {
    validateRecipientStatus({ state: "available" });
    validateRecipientStatus({ state: "away" });
    validateRecipientStatus({ state: "do_not_disturb" });
  });

  test("rejects unknown state", () => {
    expect(() =>
      validateRecipientStatus({ state: "vacation" as never }),
    ).toThrow(/state/);
  });

  test("rejects message that exceeds 256 UTF-8 bytes", () => {
    const overlong = "x".repeat(MaxStatusMessageBytes + 1);
    expect(() =>
      validateRecipientStatus({ state: "away", message: overlong }),
    ).toThrow(/256 UTF-8 bytes/);
  });

  test("uses UTF-8 byte length, not character count", () => {
    // Each "🦀" is 4 UTF-8 bytes.
    const justUnder = "🦀".repeat(MaxStatusMessageBytes / 4);
    validateRecipientStatus({ state: "away", message: justUnder });
    const justOver = "🦀".repeat(MaxStatusMessageBytes / 4 + 1);
    expect(() =>
      validateRecipientStatus({ state: "away", message: justOver }),
    ).toThrow();
  });
});
