/**
 * Tests for `.onion` domain validation per DISCOVERY.md §2.5.1.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  isOnionDomain,
  validateOnionDomain,
} from "./onion.js";

// A canonical-shape v3 onion identifier: 56 chars in [a-z2-7].
const v3Label = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";
// A v2-shape (16 chars) — must be rejected.
const v2Label = "abcdefghij234567";

describe("isOnionDomain", () => {
  test("accepts .onion suffix", () => {
    expect(isOnionDomain(`${v3Label}.onion`)).toBe(true);
    expect(isOnionDomain(`sub.${v3Label}.onion`)).toBe(true);
    expect(isOnionDomain(`${v3Label}.ONION`)).toBe(true);
  });

  test("rejects non-onion", () => {
    expect(isOnionDomain("example.com")).toBe(false);
    expect(isOnionDomain(".onionish")).toBe(false);
  });
});

describe("validateOnionDomain", () => {
  test("accepts a valid v3 label", () => {
    expect(() => validateOnionDomain(`${v3Label}.onion`)).not.toThrow();
  });

  test("accepts multi-label v3", () => {
    expect(() =>
      validateOnionDomain(`hidden.svc.${v3Label}.onion`),
    ).not.toThrow();
  });

  test("rejects non-onion", () => {
    expect(() => validateOnionDomain("example.com")).toThrow(/not an .onion/);
  });

  test("rejects empty label", () => {
    expect(() => validateOnionDomain(".onion")).toThrow(/empty label/);
  });

  test("rejects v2 (16-char)", () => {
    expect(() => validateOnionDomain(`${v2Label}.onion`)).toThrow(
      /version-2/,
    );
  });

  test("rejects wrong length", () => {
    expect(() => validateOnionDomain(`abc.onion`)).toThrow(
      /not a valid v3 identifier/,
    );
  });

  test("rejects out-of-alphabet character", () => {
    // 56 chars but with a '!' in the middle.
    const bad = "abcdefghijklmnopqrstuvwxyz234567abcdefghi!klmnopqrstuvwxy";
    expect(bad.length).toBe(57); // sanity guard
    const trimmed = `${bad.slice(0, 56)}.onion`;
    expect(() => validateOnionDomain(trimmed)).toThrow(/v3 base32/);
  });
});
