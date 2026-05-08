/**
 * RFC 6962 Merkle math tests. Includes round-trip checks against
 * the local Log so PATH/SUBPROOF and verify round-trip stay in sync.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { sha256 } from "@noble/hashes/sha2.js";

import {
  auditPath,
  hashInterior,
  hashLeaf,
  largestPowerOfTwoLessThan,
  subproof,
  subtreeRoot,
  verifyConsistencyProof,
  verifyInclusionProof,
} from "./merkle.js";
import { Log } from "./log.js";
import type { LogEntry } from "./types.js";

function bytes(...vals: number[]): Uint8Array {
  return new Uint8Array(vals);
}

function toLeaves(n: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    out.push(hashLeaf(new Uint8Array([i])));
  }
  return out;
}

function entry(i: number): LogEntry {
  return {
    event: "publish",
    user_id: `user${i}@example.com`,
    key_id: `keyid${i}`,
    key_type: "identity",
    algorithm: "ed25519",
    public_key: "AAAA",
    created: "2026-04-21T10:00:00Z",
    log_timestamp: "2026-04-21T10:01:00Z",
  };
}

const SEED = new Uint8Array(32).fill(0xab);
const KEY_ID = "deadbeef".repeat(8);

describe("hashLeaf / hashInterior", () => {
  test("leaf is SHA-256(0x00 || data)", () => {
    const data = bytes(1, 2, 3);
    const want = sha256(new Uint8Array([0x00, 1, 2, 3]));
    expect(hashLeaf(data)).toEqual(want);
  });

  test("interior is SHA-256(0x01 || left || right)", () => {
    const left = new Uint8Array(32).fill(0x10);
    const right = new Uint8Array(32).fill(0x20);
    const buf = new Uint8Array(65);
    buf[0] = 0x01;
    buf.set(left, 1);
    buf.set(right, 33);
    expect(hashInterior(left, right)).toEqual(sha256(buf));
  });
});

describe("largestPowerOfTwoLessThan", () => {
  test("matches RFC 6962 examples", () => {
    expect(largestPowerOfTwoLessThan(1)).toBe(0);
    expect(largestPowerOfTwoLessThan(2)).toBe(1);
    expect(largestPowerOfTwoLessThan(3)).toBe(2);
    expect(largestPowerOfTwoLessThan(4)).toBe(2);
    expect(largestPowerOfTwoLessThan(5)).toBe(4);
    expect(largestPowerOfTwoLessThan(7)).toBe(4);
    expect(largestPowerOfTwoLessThan(8)).toBe(4);
    expect(largestPowerOfTwoLessThan(9)).toBe(8);
  });
});

describe("subtreeRoot", () => {
  test("single leaf returns itself", () => {
    const l = hashLeaf(bytes(1));
    expect(subtreeRoot([l])).toEqual(l);
  });

  test("two leaves: hashInterior(l, r)", () => {
    const a = hashLeaf(bytes(1));
    const b = hashLeaf(bytes(2));
    expect(subtreeRoot([a, b])).toEqual(hashInterior(a, b));
  });

  test("three leaves: hashInterior(hashInterior(a,b), c)", () => {
    const a = hashLeaf(bytes(1));
    const b = hashLeaf(bytes(2));
    const c = hashLeaf(bytes(3));
    expect(subtreeRoot([a, b, c])).toEqual(hashInterior(hashInterior(a, b), c));
  });
});

describe("inclusion proof round-trip", () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 16, 17]) {
    test(`tree of size ${n}: every leaf produces a verifying proof`, () => {
      const leaves = toLeaves(n);
      const root = subtreeRoot(leaves);
      for (let i = 0; i < n; i++) {
        const path = auditPath(i, leaves);
        const ok = verifyInclusionProof(
          {
            log_size: n,
            leaf_hash: Buffer.from(leaves[i]!).toString("base64"),
            leaf_index: i,
            path: path.map((p) => Buffer.from(p).toString("base64")),
          },
          root,
        );
        expect(ok, `n=${n} i=${i}`).toBe(true);
      }
    });
  }

  test("wrong root fails", () => {
    const leaves = toLeaves(7);
    const path = auditPath(3, leaves);
    const wrongRoot = new Uint8Array(32).fill(0xff);
    const ok = verifyInclusionProof(
      {
        log_size: 7,
        leaf_hash: Buffer.from(leaves[3]!).toString("base64"),
        leaf_index: 3,
        path: path.map((p) => Buffer.from(p).toString("base64")),
      },
      wrongRoot,
    );
    expect(ok).toBe(false);
  });

  test("malformed proof fails closed", () => {
    const leaves = toLeaves(4);
    const root = subtreeRoot(leaves);
    expect(
      verifyInclusionProof(
        {
          log_size: 4,
          leaf_hash: Buffer.from(leaves[0]!).toString("base64"),
          leaf_index: 0,
          path: ["not-base64-or-too-short"],
        },
        root,
      ),
    ).toBe(false);
    expect(
      verifyInclusionProof(
        {
          log_size: 0,
          leaf_hash: Buffer.from(leaves[0]!).toString("base64"),
          leaf_index: 0,
          path: [],
        },
        root,
      ),
    ).toBe(false);
  });
});

describe("consistency proof round-trip", () => {
  for (const [a, b] of [
    [1, 2],
    [2, 4],
    [3, 7],
    [4, 7],
    [5, 8],
    [6, 11],
    [7, 16],
  ] as Array<[number, number]>) {
    test(`from=${a} to=${b}`, () => {
      const all = toLeaves(b);
      const firstRoot = subtreeRoot(all.slice(0, a));
      const secondRoot = subtreeRoot(all);
      const path = subproof(a, all, true);
      const ok = verifyConsistencyProof(
        {
          from_size: a,
          to_size: b,
          path: path.map((p) => Buffer.from(p).toString("base64")),
        },
        firstRoot,
        secondRoot,
      );
      expect(ok, `${a}→${b}`).toBe(true);
    });
  }

  test("equal sizes: empty path, equal roots", () => {
    const root = subtreeRoot(toLeaves(4));
    expect(
      verifyConsistencyProof({ from_size: 4, to_size: 4, path: [] }, root, root),
    ).toBe(true);
    const otherRoot = new Uint8Array(32).fill(0xff);
    expect(
      verifyConsistencyProof({ from_size: 4, to_size: 4, path: [] }, root, otherRoot),
    ).toBe(false);
  });

  test("from=0: trivially consistent with empty path", () => {
    const root = subtreeRoot(toLeaves(7));
    expect(
      verifyConsistencyProof({ from_size: 0, to_size: 7, path: [] }, new Uint8Array(32), root),
    ).toBe(true);
  });
});

describe("Log integration", () => {
  test("appends produce verifying proofs against issued STH", () => {
    const log = new Log({ domainSigningSeed: SEED, domainKeyId: KEY_ID });
    for (let i = 0; i < 7; i++) {
      log.append(entry(i));
    }
    const sth = log.issueSTH();
    expect(sth.log_size).toBe(7);
    const root = Buffer.from(sth.root_hash, "base64");

    for (let i = 0; i < 7; i++) {
      const proof = log.inclusionProof(i, 7);
      expect(verifyInclusionProof(proof, root)).toBe(true);
    }
  });

  test("consistency proof verifies after subsequent appends", () => {
    const log = new Log({ domainSigningSeed: SEED, domainKeyId: KEY_ID });
    for (let i = 0; i < 4; i++) {
      log.append(entry(i));
    }
    const firstSTH = log.issueSTH();
    for (let i = 4; i < 9; i++) {
      log.append(entry(i));
    }
    const secondSTH = log.issueSTH();
    const proof = log.consistencyProof(4, 9);
    const firstRoot = Buffer.from(firstSTH.root_hash, "base64");
    const secondRoot = Buffer.from(secondSTH.root_hash, "base64");
    expect(verifyConsistencyProof(proof, firstRoot, secondRoot)).toBe(true);
  });

  test("inclusionProof rejects out-of-range leafIndex", () => {
    const log = new Log({ domainSigningSeed: SEED, domainKeyId: KEY_ID });
    log.append(entry(0));
    expect(() => log.inclusionProof(1, 1)).toThrow(/out of/);
  });

  test("consistencyProof rejects firstSize > secondSize", () => {
    const log = new Log({ domainSigningSeed: SEED, domainKeyId: KEY_ID });
    for (let i = 0; i < 3; i++) {
      log.append(entry(i));
    }
    expect(() => log.consistencyProof(3, 1)).toThrow(/secondSize/);
  });
});
