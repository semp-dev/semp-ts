/**
 * Configuration parser unit tests. Cover happy path + every required
 * field's missing variant + the §3.2 baseline rules (h2, x25519,
 * max_envelope_size).
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { parseConfiguration } from "./configuration.js";

function happyConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "SEMP_CONFIGURATION",
    version: "1.0.0",
    domain: "example.com",
    revision: 17,
    ttl_seconds: 3600,
    endpoints: {
      client: { h2: "https://semp.example.com/h2", ws: "wss://semp.example.com/ws" },
      federation: { h2: "https://semp.example.com/fed/h2" },
      register: "https://semp.example.com/register",
      keys: "https://semp.example.com/keys/",
      domain_keys: "https://semp.example.com/domain-keys",
    },
    suites: ["pq-kyber768-x25519", "x25519-chacha20-poly1305"],
    limits: { max_envelope_size: 26214400 },
    extensions: [],
    ...overrides,
  };
}

describe("parseConfiguration", () => {
  test("happy path returns the typed object", () => {
    const cfg = parseConfiguration(happyConfig());
    expect(cfg.type).toBe("SEMP_CONFIGURATION");
    expect(cfg.domain).toBe("example.com");
    expect(cfg.revision).toBe(17);
    expect(cfg.endpoints.client.h2).toBeDefined();
    expect(cfg.suites).toContain("x25519-chacha20-poly1305");
    expect(cfg.limits.max_envelope_size).toBe(26214400);
  });

  test("rejects non-object input", () => {
    expect(() => parseConfiguration("not an object")).toThrow(/JSON object/);
    expect(() => parseConfiguration(null)).toThrow(/JSON object/);
    expect(() => parseConfiguration([])).toThrow(/JSON object/);
  });

  test("rejects wrong type discriminator", () => {
    expect(() => parseConfiguration(happyConfig({ type: "SEMP_OTHER" }))).toThrow(/type/);
  });

  test.each([
    "version",
    "domain",
  ])("rejects missing %s", (field) => {
    expect(() =>
      parseConfiguration(happyConfig({ [field]: undefined })),
    ).toThrow(new RegExp(field));
  });

  test("rejects missing revision / ttl_seconds", () => {
    expect(() => parseConfiguration(happyConfig({ revision: undefined }))).toThrow(/revision/);
    expect(() => parseConfiguration(happyConfig({ ttl_seconds: undefined }))).toThrow(/ttl_seconds/);
  });

  test("rejects non-integer revision", () => {
    expect(() => parseConfiguration(happyConfig({ revision: 1.5 }))).toThrow(/revision/);
  });

  test("rejects missing endpoints.client.h2 (mandatory baseline)", () => {
    const bad = happyConfig();
    (bad.endpoints as Record<string, unknown>).client = { ws: "wss://x" };
    expect(() => parseConfiguration(bad)).toThrow(/h2/);
  });

  test("rejects missing endpoints.federation.h2", () => {
    const bad = happyConfig();
    (bad.endpoints as Record<string, unknown>).federation = { ws: "wss://x" };
    expect(() => parseConfiguration(bad)).toThrow(/h2/);
  });

  test("rejects missing endpoints.register / keys / domain_keys", () => {
    for (const field of ["register", "keys", "domain_keys"]) {
      const bad = happyConfig();
      delete (bad.endpoints as Record<string, unknown>)[field];
      expect(() => parseConfiguration(bad), `missing ${field}`).toThrow(new RegExp(field));
    }
  });

  test("rejects suites missing x25519-chacha20-poly1305", () => {
    expect(() =>
      parseConfiguration(happyConfig({ suites: ["pq-kyber768-x25519"] })),
    ).toThrow(/x25519-chacha20-poly1305/);
  });

  test("rejects missing limits.max_envelope_size", () => {
    expect(() =>
      parseConfiguration(happyConfig({ limits: {} })),
    ).toThrow(/max_envelope_size/);
  });

  test("validates extension entries", () => {
    parseConfiguration(
      happyConfig({
        extensions: [
          { id: "semp.dev/large-attachment", required: false },
          { id: "vendor.example/x", required: true },
        ],
      }),
    );
    expect(() =>
      parseConfiguration(happyConfig({ extensions: [{ id: "x" }] })),
    ).toThrow(/required/);
    expect(() =>
      parseConfiguration(happyConfig({ extensions: [{ id: "", required: false }] })),
    ).toThrow(/id/);
  });

  test("preserves unknown top-level fields", () => {
    const cfg = parseConfiguration(happyConfig({ future_field: "ok" }));
    expect((cfg as { future_field?: string }).future_field).toBe("ok");
  });
});
