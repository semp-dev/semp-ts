/**
 * Tests for partition strategy resolution per DISCOVERY.md §2.4.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { type DNSLookup, type SRVRecord } from "./dns.js";

import {
  type PartitionConfig,
  defaultAlphaRanges,
  parsePartitionTXT,
  resolvePartition,
} from "./partition.js";

function fakeDNS(records: Record<string, SRVRecord[]>): DNSLookup {
  return {
    async lookupSRV(name: string) {
      return records[name] ?? [];
    },
    async lookupTXT() {
      return [];
    },
    async lookupMX() {
      return [];
    },
  };
}

describe("defaultAlphaRanges", () => {
  test("4 servers split a-f / g-m / n-s / t-z", () => {
    const r = defaultAlphaRanges(4);
    expect(r.map((x) => `${x.start_char}-${x.end_char}`)).toEqual([
      "a-g",
      "h-n",
      "o-t",
      "u-z",
    ]);
  });

  test("0 servers → empty", () => {
    expect(defaultAlphaRanges(0)).toEqual([]);
  });

  test("more than 26 → clamped to 26", () => {
    expect(defaultAlphaRanges(40)).toHaveLength(26);
  });
});

describe("parsePartitionTXT", () => {
  test("parses a hash-strategy record", () => {
    const cfg = parsePartitionTXT(
      "example.com",
      "v=semp1;strategy=hash;servers=8;algorithm=sha256",
    );
    expect(cfg.version).toBe("semp1");
    expect(cfg.strategy).toBe("hash");
    expect(cfg.servers).toBe(8);
    expect(cfg.algorithm).toBe("sha256");
    expect(cfg.domain).toBe("example.com");
  });

  test("rejects empty TXT", () => {
    expect(() => parsePartitionTXT("d", "")).toThrow(/empty/);
  });

  test("rejects missing version", () => {
    expect(() => parsePartitionTXT("d", "strategy=alpha")).toThrow(/version/);
  });

  test("rejects missing strategy", () => {
    expect(() => parsePartitionTXT("d", "v=semp1")).toThrow(/strategy/);
  });

  test("rejects invalid strategy", () => {
    expect(() => parsePartitionTXT("d", "v=semp1;strategy=bogus")).toThrow(
      /invalid partition strategy/,
    );
  });

  test("ignores unknown keys (forward compat)", () => {
    const cfg = parsePartitionTXT(
      "d",
      "v=semp1;strategy=alpha;new-future-key=ok",
    );
    expect(cfg.strategy).toBe("alpha");
  });
});

describe("resolvePartition", () => {
  test("strategy=alpha uses pre-resolved alpha_ranges fast path", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "alpha",
      domain: "example.com",
      alpha_ranges: [
        { start_char: "a", end_char: "m", server: "low.example.com" },
        { start_char: "n", end_char: "z", server: "high.example.com" },
      ],
    };
    expect(
      await resolvePartition(cfg, {}, "alice@example.com"),
    ).toBe("low.example.com");
    expect(
      await resolvePartition(cfg, {}, "zara@example.com"),
    ).toBe("high.example.com");
  });

  test("strategy=alpha falls back to last range for non-alpha first char", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "alpha",
      domain: "example.com",
      alpha_ranges: [
        { start_char: "a", end_char: "m", server: "low.example.com" },
        { start_char: "n", end_char: "z", server: "high.example.com" },
      ],
    };
    expect(
      await resolvePartition(cfg, {}, "1user@example.com"),
    ).toBe("high.example.com");
  });

  test("strategy=alpha uses DNS path when ranges have no server", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "alpha",
      domain: "example.com",
      servers: 4,
    };
    const dns = fakeDNS({
      "_semp-partition-a-g._tcp.example.com": [
        { priority: 10, weight: 0, port: 443, target: "low.example.com." },
      ],
    });
    expect(
      await resolvePartition(cfg, { dns }, "alice@example.com"),
    ).toBe("low.example.com");
  });

  test("strategy=hash dispatches via SHA-256 mod N", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "hash",
      servers: 4,
      domain: "example.com",
    };
    // SHA-256("alice@example.com").substr(0, 8) → an 8-byte BE
    // unsigned int. We don't predict the exact value here; just
    // assert the resolver dispatches to whatever index it computes
    // and uses it to query SRV. To assert determinism, run twice
    // and check we get the same answer.
    const dns = fakeDNS({
      "_semp-partition-0._tcp.example.com": [
        { priority: 10, weight: 0, port: 443, target: "p0.example.com." },
      ],
      "_semp-partition-1._tcp.example.com": [
        { priority: 10, weight: 0, port: 443, target: "p1.example.com." },
      ],
      "_semp-partition-2._tcp.example.com": [
        { priority: 10, weight: 0, port: 443, target: "p2.example.com." },
      ],
      "_semp-partition-3._tcp.example.com": [
        { priority: 10, weight: 0, port: 443, target: "p3.example.com." },
      ],
    });
    const a = await resolvePartition(cfg, { dns }, "alice@example.com");
    const b = await resolvePartition(cfg, { dns }, "alice@example.com");
    expect(a).toBe(b);
    expect(a).toMatch(/^p[0-3]\.example\.com$/);
  });

  test("strategy=hash with 0 servers fails", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "hash",
      servers: 0,
      domain: "example.com",
    };
    await expect(
      resolvePartition(cfg, { dns: fakeDNS({}) }, "alice@example.com"),
    ).rejects.toThrow(/servers > 0/);
  });

  test("strategy=lookup delegates to lookupFunc", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "lookup",
      domain: "example.com",
    };
    const out = await resolvePartition(
      cfg,
      { lookupFunc: async () => "looked-up.example.com" },
      "alice@example.com",
    );
    expect(out).toBe("looked-up.example.com");
  });

  test("strategy=lookup without lookupFunc fails", async () => {
    const cfg: PartitionConfig = {
      version: "semp1",
      strategy: "lookup",
      domain: "example.com",
    };
    await expect(
      resolvePartition(cfg, {}, "alice@example.com"),
    ).rejects.toThrow(/requires a lookupFunc/);
  });
});
