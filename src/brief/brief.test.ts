/**
 * Brief tests - focused on the BCC fan-out helper.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { type Brief, splitForBCC } from "./brief.js";

function baseBrief(): Brief {
  return {
    message_id: "01J7BRIEF0000000000000000",
    from: "alice@example.com",
    to: ["bob@example.com"],
    cc: ["carol@example.com"],
    bcc: ["dan@example.com", "eve@other.example"],
    sent_at: "2026-04-21T10:15:32Z",
    extensions: { tag: "x" },
  };
}

describe("splitForBCC", () => {
  test("no BCC returns the input unchanged", () => {
    const b: Brief = { ...baseBrief(), bcc: undefined };
    const out = splitForBCC(b);
    expect(out).toEqual([b]);
    expect(out[0]).toBe(b);
  });

  test("empty BCC array returns the input unchanged", () => {
    const b: Brief = { ...baseBrief(), bcc: [] };
    const out = splitForBCC(b);
    expect(out).toEqual([b]);
  });

  test("two BCC recipients produce 3 copies (visible + per-recipient)", () => {
    const b = baseBrief();
    const out = splitForBCC(b);
    expect(out).toHaveLength(3);

    // Copy 0: visible - bcc absent
    expect(out[0]?.bcc).toBeUndefined();
    expect(out[0]?.to).toEqual(b.to);
    expect(out[0]?.cc).toEqual(b.cc);

    // Copies 1..N: each carries exactly one bcc
    expect(out[1]?.bcc).toEqual(["dan@example.com"]);
    expect(out[2]?.bcc).toEqual(["eve@other.example"]);

    // Each per-bcc copy preserves to/cc
    expect(out[1]?.to).toEqual(b.to);
    expect(out[1]?.cc).toEqual(b.cc);
    expect(out[2]?.to).toEqual(b.to);
    expect(out[2]?.cc).toEqual(b.cc);
  });

  test("input is not mutated", () => {
    const b = baseBrief();
    const before = JSON.stringify(b);
    splitForBCC(b);
    expect(JSON.stringify(b)).toBe(before);
  });

  test("each copy preserves message_id, from, sent_at, extensions", () => {
    const b = baseBrief();
    const out = splitForBCC(b);
    for (const copy of out) {
      expect(copy.message_id).toBe(b.message_id);
      expect(copy.from).toBe(b.from);
      expect(copy.sent_at).toBe(b.sent_at);
      expect(copy.extensions).toEqual(b.extensions);
    }
  });
});
