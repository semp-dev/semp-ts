/**
 * Tests for discovery extras: DNS, cache, signed lookup.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type DNSLookup,
  type DiscoveryResponse,
  InMemoryDiscoveryCache,
  lookupSRV,
  lookupTXT,
  signDiscoveryResponse,
  validateDiscoveryRequest,
  verifyDiscoveryResponse,
} from "./index.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function fakeDNS(opts: {
  srv?: Record<string, Array<{ priority: number; weight: number; port: number; target: string }>>;
  txt?: Record<string, string[]>;
  mx?: Record<string, Array<{ preference: number; exchange: string }>>;
} = {}): DNSLookup {
  return {
    async lookupSRV(name: string) {
      return opts.srv?.[name] ?? [];
    },
    async lookupTXT(name: string) {
      return opts.txt?.[name] ?? [];
    },
    async lookupMX(name: string) {
      return opts.mx?.[name] ?? [];
    },
  };
}

describe("lookupSRV", () => {
  test("queries _semp._tcp.<domain> + sorts by priority", async () => {
    const dns = fakeDNS({
      srv: {
        "_semp._tcp.example.com": [
          { priority: 20, weight: 1, port: 443, target: "alt.example.com" },
          { priority: 10, weight: 1, port: 443, target: "primary.example.com" },
        ],
      },
    });
    const recs = await lookupSRV("example.com", dns);
    expect(recs).toEqual([
      { priority: 10, weight: 1, port: 443, target: "primary.example.com" },
      { priority: 20, weight: 1, port: 443, target: "alt.example.com" },
    ]);
  });

  test("returns empty array when no records", async () => {
    expect(await lookupSRV("example.com", fakeDNS())).toEqual([]);
  });
});

describe("lookupTXT", () => {
  test("returns first record with v=semp1", async () => {
    const dns = fakeDNS({
      txt: {
        "_semp._tcp.example.com": [
          "spf1=...",
          "v=semp1;c=ws,h2",
          "v=semp1;c=quic", // ignored - first match wins
        ],
      },
    });
    const cap = await lookupTXT("example.com", dns);
    expect(cap?.v).toBe("semp1");
    expect(cap?.c).toEqual(["ws", "h2"]);
  });

  test("returns null when no SEMP record present", async () => {
    const dns = fakeDNS({
      txt: { "_semp._tcp.example.com": ["spf1=..."] },
    });
    expect(await lookupTXT("example.com", dns)).toBeNull();
  });
});

describe("InMemoryDiscoveryCache", () => {
  test("get + put + invalidate", async () => {
    let now = new Date("2026-04-21T10:00:00Z");
    const cache = new InMemoryDiscoveryCache<string>(() => now);
    expect(await cache.get("alice@example.com")).toBeNull();
    await cache.put("alice@example.com", "result", 60_000);
    expect(await cache.get("alice@example.com")).toBe("result");
    await cache.invalidate("alice@example.com");
    expect(await cache.get("alice@example.com")).toBeNull();
  });

  test("expires entries past TTL", async () => {
    let now = new Date("2026-04-21T10:00:00Z");
    const cache = new InMemoryDiscoveryCache<string>(() => now);
    await cache.put("alice@example.com", "result", 60_000);
    now = new Date("2026-04-21T10:02:00Z");
    expect(await cache.get("alice@example.com")).toBeNull();
  });

  test("normalizes addresses to lowercase", async () => {
    const cache = new InMemoryDiscoveryCache<string>();
    await cache.put("Alice@Example.COM", "result", 60_000);
    expect(await cache.get("alice@example.com")).toBe("result");
  });

  test("ttl=0 means no expiry", async () => {
    let now = new Date("2026-04-21T10:00:00Z");
    const cache = new InMemoryDiscoveryCache<string>(() => now);
    await cache.put("alice@example.com", "result", 0);
    now = new Date("2050-01-01T00:00:00Z");
    expect(await cache.get("alice@example.com")).toBe("result");
  });
});

describe("DiscoveryRequest validation", () => {
  test("happy", () => {
    validateDiscoveryRequest({
      type: "SEMP_DISCOVERY",
      step: "request",
      version: "1.0.0",
      id: "01J7DISC000",
      timestamp: "2026-04-21T10:00:00Z",
      addresses: ["alice@example.com"],
    });
  });

  test("rejects empty addresses", () => {
    expect(() =>
      validateDiscoveryRequest({
        type: "SEMP_DISCOVERY",
        step: "request",
        version: "1.0.0",
        id: "01J7DISC000",
        timestamp: "2026-04-21T10:00:00Z",
        addresses: [],
      }),
    ).toThrow(/addresses/);
  });

  test("rejects wrong step", () => {
    expect(() =>
      validateDiscoveryRequest({
        type: "SEMP_DISCOVERY",
        step: "response" as never,
        version: "1.0.0",
        id: "01J7DISC000",
        timestamp: "2026-04-21T10:00:00Z",
        addresses: ["x@example.com"],
      }),
    ).toThrow(/step/);
  });
});

describe("DiscoveryResponse sign + verify", () => {
  function happyResponse(): DiscoveryResponse {
    return {
      type: "SEMP_DISCOVERY",
      step: "response",
      version: "1.0.0",
      id: "01J7DISC000",
      timestamp: "2026-04-21T10:00:00Z",
      results: [
        {
          address: "alice@example.com",
          status: "found",
          transports: ["ws", "h2"],
          suites: ["x25519-chacha20-poly1305"],
          server: "semp.example.com",
          ttl: 3600,
        },
      ],
      signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xab);
    const pub = publicKeyFromSeed(seed);
    const resp = happyResponse();
    signDiscoveryResponse(resp, seed, fingerprint(pub));
    expect(verifyDiscoveryResponse(resp, pub)).toBe(true);
  });

  test("tampering breaks verification", () => {
    const seed = deterministicSeed(0xab);
    const pub = publicKeyFromSeed(seed);
    const resp = happyResponse();
    signDiscoveryResponse(resp, seed, fingerprint(pub));
    resp.results[0]!.address = "evil@example.com";
    expect(verifyDiscoveryResponse(resp, pub)).toBe(false);
  });

  test("rejects unknown status", () => {
    const resp = happyResponse();
    resp.results[0]!.status = "bogus" as never;
    expect(() => signDiscoveryResponse(resp, deterministicSeed(1), "x")).toThrow(
      /status/,
    );
  });
});
