/**
 * In-memory ReceiptStore tests. Cover put/get/acknowledge/prune
 * round-trip, double-put rejection, and prune cutoff semantics.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { canonicalEnvelopeFor } from "../envelope/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  computeEnvelopeHash,
  signDeliveryReceipt,
} from "./receipt.js";
import { InMemoryReceiptStore } from "./receipt_store.js";

function makeReceipt() {
  const seed = new Uint8Array(32).fill(0xc1);
  const pub = publicKeyFromSeed(seed);
  const env = {
    type: "SEMP_ENVELOPE",
    version: "1.0.0",
    postmark: {
      id: "01J7STORE0000000000000000",
      session_id: "01J7STORESESSION00000000",
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

describe("delivery.receipt_store", () => {
  test("put + get + acknowledge round-trip", async () => {
    const store = new InMemoryReceiptStore();
    const receipt = makeReceipt();
    const now = new Date("2026-04-21T10:15:33Z");

    expect(await store.get("env-1", "bob@bob.example")).toBeNull();

    await store.put("env-1", "bob@bob.example", receipt, now);
    const got = await store.get("env-1", "bob@bob.example");
    expect(got).toEqual(receipt);

    await store.acknowledge("env-1", "bob@bob.example");
    expect(await store.get("env-1", "bob@bob.example")).toBeNull();
  });

  test("double put rejects", async () => {
    const store = new InMemoryReceiptStore();
    const receipt = makeReceipt();
    const now = new Date();
    await store.put("env-1", "bob@bob.example", receipt, now);
    await expect(store.put("env-1", "bob@bob.example", receipt, now)).rejects.toThrow(
      /already stored/,
    );
  });

  test("acknowledge of unknown record is a no-op", async () => {
    const store = new InMemoryReceiptStore();
    await expect(store.acknowledge("nope", "ghost")).resolves.toBeUndefined();
  });

  test("pruneUnacknowledged drops only records older or equal to cutoff", async () => {
    const store = new InMemoryReceiptStore();
    const receipt = makeReceipt();
    await store.put("old-1", "bob@bob.example", receipt, new Date("2026-04-20T00:00:00Z"));
    await store.put("old-2", "bob@bob.example", receipt, new Date("2026-04-20T12:00:00Z"));
    await store.put("recent", "bob@bob.example", receipt, new Date("2026-04-21T12:00:00Z"));

    const cutoff = new Date("2026-04-20T12:00:00Z");
    const pruned = await store.pruneUnacknowledged(cutoff);
    expect(pruned).toBe(2);

    expect(await store.get("old-1", "bob@bob.example")).toBeNull();
    expect(await store.get("old-2", "bob@bob.example")).toBeNull();
    expect(await store.get("recent", "bob@bob.example")).toEqual(receipt);
  });

  test("put rejects empty keys", async () => {
    const store = new InMemoryReceiptStore();
    const receipt = makeReceipt();
    await expect(store.put("", "bob@bob.example", receipt, new Date())).rejects.toThrow(/envelopeId/);
    await expect(store.put("env-1", "", receipt, new Date())).rejects.toThrow(/recipient/);
  });
});
