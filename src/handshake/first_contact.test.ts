/**
 * First-contact prefix binding tests.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  FirstContactBindingHashSize,
  FirstContactPrefixRandBytes,
  computeFirstContactPrefix,
  decodeFirstContactPrefix,
  verifyFirstContactBinding,
} from "./first_contact.js";

function fixedRand(byte: number): (n: number) => Uint8Array {
  return (n) => new Uint8Array(n).fill(byte);
}

describe("computeFirstContactPrefix + verifyFirstContactBinding", () => {
  test("round-trip succeeds for matching triple", () => {
    const prefix = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xab),
    );
    expect(prefix.length).toBe(
      FirstContactPrefixRandBytes + FirstContactBindingHashSize,
    );
    expect(
      verifyFirstContactBinding(
        prefix,
        "alice.example",
        "bob@bob.example",
        "01J7POSTMARK000",
      ),
    ).toBe(true);
  });

  test("fails when sender_domain differs", () => {
    const prefix = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xab),
    );
    expect(
      verifyFirstContactBinding(
        prefix,
        "evil.example",
        "bob@bob.example",
        "01J7POSTMARK000",
      ),
    ).toBe(false);
  });

  test("fails when recipient_address differs", () => {
    const prefix = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xab),
    );
    expect(
      verifyFirstContactBinding(
        prefix,
        "alice.example",
        "carol@bob.example",
        "01J7POSTMARK000",
      ),
    ).toBe(false);
  });

  test("fails when postmark_id differs", () => {
    const prefix = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xab),
    );
    expect(
      verifyFirstContactBinding(
        prefix,
        "alice.example",
        "bob@bob.example",
        "01J7DIFFERENT00",
      ),
    ).toBe(false);
  });

  test("fails on too-short prefix", () => {
    expect(
      verifyFirstContactBinding(
        new Uint8Array(10),
        "alice.example",
        "bob@bob.example",
        "01J7POSTMARK000",
      ),
    ).toBe(false);
  });

  test("rejects empty inputs at compose time", () => {
    expect(() =>
      computeFirstContactPrefix("", "bob@bob.example", "01J7POSTMARK000"),
    ).toThrow(/sender_domain/);
    expect(() =>
      computeFirstContactPrefix("alice.example", "", "01J7POSTMARK000"),
    ).toThrow(/recipient_address/);
    expect(() =>
      computeFirstContactPrefix("alice.example", "bob@bob.example", ""),
    ).toThrow(/postmark_id/);
  });

  test("two prefixes for the same triple differ in their random nonce", () => {
    const a = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xa1),
    );
    const b = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xb2),
    );
    // First 16 bytes (nonce) differ; trailing 32 bytes (binding) match.
    expect(a.subarray(0, FirstContactPrefixRandBytes)).not.toEqual(
      b.subarray(0, FirstContactPrefixRandBytes),
    );
    expect(a.subarray(FirstContactPrefixRandBytes)).toEqual(
      b.subarray(FirstContactPrefixRandBytes),
    );
  });

  test("decodeFirstContactPrefix base64 round-trip", () => {
    const prefix = computeFirstContactPrefix(
      "alice.example",
      "bob@bob.example",
      "01J7POSTMARK000",
      fixedRand(0xab),
    );
    const b64 = Buffer.from(prefix).toString("base64");
    expect(decodeFirstContactPrefix(b64)).toEqual(prefix);
  });
});
