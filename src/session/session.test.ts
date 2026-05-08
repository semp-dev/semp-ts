import { describe, expect, test } from "vitest";

import { newMemoryPair } from "../transport/index.js";
import { Session } from "./session.js";

function dummyKeys(): {
  encC2S: Uint8Array;
  encS2C: Uint8Array;
  macC2S: Uint8Array;
  macS2C: Uint8Array;
  envMAC: Uint8Array;
} {
  return {
    encC2S: new Uint8Array(32).fill(0x11),
    encS2C: new Uint8Array(32).fill(0x22),
    macC2S: new Uint8Array(32).fill(0x33),
    macS2C: new Uint8Array(32).fill(0x44),
    envMAC: new Uint8Array(32).fill(0x55),
  };
}

describe("Session", () => {
  test("expiresAt and isExpired honor the TTL", () => {
    const [t] = newMemoryPair();
    const established = new Date("2026-01-01T12:00:00Z");
    const s = new Session({
      role: "client",
      sessionId: "01JTESTSESSION00000000000000",
      sessionTTL: 300,
      establishedAt: established,
      permissions: ["send"],
      keys: dummyKeys(),
      transport: t,
    });
    expect(s.expiresAt().toISOString()).toBe("2026-01-01T12:05:00.000Z");
    expect(s.isExpired(new Date("2026-01-01T12:04:59Z"))).toBe(false);
    expect(s.isExpired(new Date("2026-01-01T12:05:00Z"))).toBe(true);
  });

  test("close prevents further send/receive", async () => {
    const [t] = newMemoryPair();
    const s = new Session({
      role: "client",
      sessionId: "x",
      sessionTTL: 300,
      establishedAt: new Date(),
      permissions: [],
      keys: dummyKeys(),
      transport: t,
    });
    expect(s.closed).toBe(false);
    await s.close();
    expect(s.closed).toBe(true);
    await expect(s.send(new Uint8Array(1))).rejects.toThrow(/closed/);
    await expect(s.receive()).rejects.toThrow(/closed/);
  });

  test("erase zeroizes keys and prevents further key access", async () => {
    const [t] = newMemoryPair();
    const keys = dummyKeys();
    const s = new Session({
      role: "client",
      sessionId: "x",
      sessionTTL: 300,
      establishedAt: new Date(),
      permissions: [],
      keys,
      transport: t,
    });
    expect(s.keys.envMAC[0]).toBe(0x55);
    await s.erase();
    // Both the in-memory bytes AND the accessor MUST be neutralized.
    for (let i = 0; i < keys.envMAC.length; i++) {
      expect(keys.envMAC[i]).toBe(0);
    }
    expect(() => s.keys).toThrow(/erased/);
  });

  test("permissions surface as a Set", () => {
    const [t] = newMemoryPair();
    const s = new Session({
      role: "client",
      sessionId: "x",
      sessionTTL: 300,
      establishedAt: new Date(),
      permissions: ["send", "receive"],
      keys: dummyKeys(),
      transport: t,
    });
    expect(s.permissions.has("send")).toBe(true);
    expect(s.permissions.has("admin")).toBe(false);
  });

  test("close is idempotent", async () => {
    const [t] = newMemoryPair();
    const s = new Session({
      role: "client",
      sessionId: "x",
      sessionTTL: 300,
      establishedAt: new Date(),
      permissions: [],
      keys: dummyKeys(),
      transport: t,
    });
    await s.close();
    await s.close();
    await s.erase();
    await s.erase();
    expect(s.closed).toBe(true);
  });
});
