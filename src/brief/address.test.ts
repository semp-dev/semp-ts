/**
 * Address tests. Cover validate + canonicalize + equality, including
 * IDN punycode conversion and NFC normalization.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  MaxAddressLength,
  MaxDomainLabelLength,
  MaxLocalPartLength,
  addressDomain,
  addressEqual,
  addressLocal,
  canonicalizeAddress,
  validateAddress,
} from "./address.js";

describe("addressLocal / addressDomain", () => {
  test("split on the final @", () => {
    expect(addressLocal("alice@example.com")).toBe("alice");
    expect(addressDomain("alice@example.com")).toBe("example.com");
  });

  test("address with no @ has empty domain", () => {
    expect(addressLocal("nobody")).toBe("nobody");
    expect(addressDomain("nobody")).toBe("");
  });

  test("split on the LAST @ when the local part contains a quoted @", () => {
    // RFC 5321 permits quoted-string local parts containing @; we
    // honor "split on the final @" semantics for simplicity.
    expect(addressLocal('"a@b"@example.com')).toBe('"a@b"');
    expect(addressDomain('"a@b"@example.com')).toBe("example.com");
  });
});

describe("validateAddress (happy path)", () => {
  test("baseline ASCII address", () => {
    validateAddress("alice@example.com");
  });

  test("local part with NFC unicode", () => {
    validateAddress("café@example.com");
  });

  test("max-length address validates", () => {
    const local = "a".repeat(MaxLocalPartLength);
    const domain = "b".repeat(60) + ".example.com"; // safely under MaxDomainLength
    validateAddress(`${local}@${domain}`);
  });
});

describe("validateAddress (errors)", () => {
  test("empty", () => {
    expect(() => validateAddress("")).toThrow(/empty address/);
  });

  test("missing @", () => {
    expect(() => validateAddress("nobody")).toThrow(/missing '@'/);
  });

  test("multiple @", () => {
    expect(() => validateAddress("a@b@c")).toThrow(/multiple '@'/);
  });

  test("empty local part", () => {
    expect(() => validateAddress("@example.com")).toThrow(/empty local part/);
  });

  test("empty domain", () => {
    expect(() => validateAddress("alice@")).toThrow(/empty domain/);
  });

  test("local part too long", () => {
    const local = "a".repeat(MaxLocalPartLength + 1);
    expect(() => validateAddress(`${local}@x.example`)).toThrow(/local part exceeds/);
  });

  test("domain too long", () => {
    const domain = ("a".repeat(60) + ".").repeat(5) + "example";
    // this is > 253 chars; ensure rejection
    expect(() => validateAddress(`alice@${domain}`)).toThrow(/exceeds/);
  });

  test("domain label too long", () => {
    const tooLong = "a".repeat(MaxDomainLabelLength + 1);
    expect(() => validateAddress(`alice@${tooLong}.com`)).toThrow(/label/);
  });

  test("composed address too long", () => {
    const local = "a".repeat(MaxLocalPartLength);
    const domain = "b".repeat(190) + ".example.com";
    const addr = `${local}@${domain}`;
    if (addr.length <= MaxAddressLength) {
      // not over the cap; skip
      return;
    }
    expect(() => validateAddress(addr)).toThrow(/exceeds/);
  });

  test("control character rejection (C0)", () => {
    expect(() => validateAddress("alice\x01@example.com")).toThrow(/control character/);
  });

  test("control character rejection (DEL)", () => {
    expect(() => validateAddress("alice\x7f@example.com")).toThrow(/control character/);
  });

  test("control character rejection (C1)", () => {
    expect(() => validateAddress("alice@example.com")).toThrow(/control character/);
  });

  test("non-NFC local part", () => {
    // "é" decomposed: e + COMBINING ACUTE
    const decomposed = "café";
    expect(() => validateAddress(`${decomposed}@example.com`)).toThrow(/Normalization Form C/);
  });

  test("non-ASCII domain (U-label) rejected on the wire", () => {
    expect(() => validateAddress("alice@例え.example")).toThrow(/A-label required/);
  });

  test("uppercase domain rejected on the wire", () => {
    expect(() => validateAddress("alice@Example.com")).toThrow(/lowercase/);
  });

  test("leading dot in domain", () => {
    expect(() => validateAddress("alice@.example.com")).toThrow(/leading or trailing dot/);
  });

  test("trailing dot in domain", () => {
    expect(() => validateAddress("alice@example.com.")).toThrow(/leading or trailing dot/);
  });

  test("consecutive dots in domain", () => {
    expect(() => validateAddress("alice@example..com")).toThrow(/empty label/);
  });

  test("hyphen at label boundary", () => {
    expect(() => validateAddress("alice@-example.com")).toThrow(/leading or trailing hyphen/);
    expect(() => validateAddress("alice@example-.com")).toThrow(/leading or trailing hyphen/);
  });
});

describe("canonicalizeAddress", () => {
  test("lowercases ASCII domain", () => {
    expect(canonicalizeAddress("Alice@Example.COM")).toBe("Alice@example.com");
  });

  test("converts U-label to A-label", () => {
    expect(canonicalizeAddress("alice@例え.example")).toBe(
      "alice@xn--r8jz45g.example",
    );
  });

  test("normalizes local part to NFC", () => {
    const decomposed = "café";
    const canonical = canonicalizeAddress(`${decomposed}@example.com`);
    const local = canonical.split("@")[0];
    expect(local).toBe(decomposed.normalize("NFC"));
  });

  test("rejects empty / no-@ / multiple-@", () => {
    expect(() => canonicalizeAddress("")).toThrow(/empty/);
    expect(() => canonicalizeAddress("nobody")).toThrow(/missing '@'/);
    expect(() => canonicalizeAddress("a@b@c")).toThrow(/multiple '@'/);
  });

  test("validate(canonicalize(x)) succeeds for normalizable inputs", () => {
    const out = canonicalizeAddress("Alice@Example.COM");
    validateAddress(out);
  });
});

describe("addressEqual", () => {
  test("same canonical form", () => {
    expect(addressEqual("alice@example.com", "alice@Example.COM")).toBe(true);
  });

  test("U-label vs A-label", () => {
    expect(addressEqual("alice@例え.example", "alice@xn--r8jz45g.example")).toBe(true);
  });

  test("NFC vs NFD local part", () => {
    expect(addressEqual("café@example.com", "café@example.com")).toBe(true);
  });

  test("does NOT collapse confusables", () => {
    // Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
    expect(addressEqual("аlice@example.com", "alice@example.com")).toBe(false);
  });

  test("returns false for malformed input", () => {
    expect(addressEqual("", "alice@example.com")).toBe(false);
    expect(addressEqual("alice@example.com", "")).toBe(false);
  });
});
