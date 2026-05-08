/**
 * Resolver tests. Drive a fake fetch and assert
 * fetchConfiguration / fetchDomainKeys / resolveServer behave per
 * DISCOVERY.md §3 and §3.5.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type FetchLike,
  fetchConfiguration,
  fetchDomainKeys,
  resolveServer,
  wellKnownUrl,
} from "./resolver.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function happyConfigDoc(): Record<string, unknown> {
  return {
    type: "SEMP_CONFIGURATION",
    version: "1.0.0",
    domain: "example.com",
    revision: 1,
    ttl_seconds: 3600,
    endpoints: {
      client: { h2: "https://semp.example.com/h2" },
      federation: { h2: "https://semp.example.com/fed/h2" },
      register: "https://semp.example.com/register",
      keys: "https://semp.example.com/keys/",
      domain_keys: "https://semp.example.com/domain-keys",
    },
    suites: ["x25519-chacha20-poly1305"],
    limits: { max_envelope_size: 26214400 },
  };
}

function happyDomainKeysDoc(): Record<string, unknown> {
  const sigSeed = deterministicSeed(0x10);
  const sigPub = publicKeyFromSeed(sigSeed);
  const encPub = deterministicSeed(0x20);
  return {
    type: "SEMP_DOMAIN_KEYS",
    version: "1.0.0",
    domain: "example.com",
    signing_key: {
      algorithm: "ed25519",
      public_key: base64(sigPub),
      key_id: fingerprint(sigPub),
    },
    encryption_key: {
      algorithm: "x25519-chacha20-poly1305",
      public_key: base64(encPub),
      key_id: fingerprint(encPub),
    },
  };
}

function fakeFetch(routes: Record<string, { status?: number; body: string; contentType?: string }>): {
  fetch: FetchLike;
  calls: string[];
} {
  const calls: string[] = [];
  const fetch: FetchLike = async (url) => {
    calls.push(url);
    const route = routes[url];
    if (route === undefined) {
      throw new Error(`fake fetch: no route for ${url}`);
    }
    const status = route.status ?? 200;
    const ct = route.contentType ?? "application/json";
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name) => (name.toLowerCase() === "content-type" ? ct : null) },
      text: async () => route.body,
    };
  };
  return { fetch, calls };
}

describe("wellKnownUrl", () => {
  test("composes the canonical path", () => {
    expect(wellKnownUrl("example.com")).toBe(
      "https://example.com/.well-known/semp/configuration",
    );
  });

  test("rejects empty host", () => {
    expect(() => wellKnownUrl("")).toThrow(/host/);
  });
});

describe("fetchConfiguration", () => {
  test("happy path", async () => {
    const url = wellKnownUrl("example.com");
    const { fetch } = fakeFetch({ [url]: { body: JSON.stringify(happyConfigDoc()) } });
    const cfg = await fetchConfiguration(url, { fetchImpl: fetch });
    expect(cfg.domain).toBe("example.com");
    expect(cfg.endpoints.domain_keys).toBe("https://semp.example.com/domain-keys");
  });

  test("propagates non-200", async () => {
    const url = wellKnownUrl("example.com");
    const { fetch } = fakeFetch({ [url]: { status: 404, body: "not found" } });
    await expect(fetchConfiguration(url, { fetchImpl: fetch })).rejects.toThrow(/404/);
  });

  test("rejects malformed JSON", async () => {
    const url = wellKnownUrl("example.com");
    const { fetch } = fakeFetch({ [url]: { body: "not json" } });
    await expect(fetchConfiguration(url, { fetchImpl: fetch })).rejects.toThrow(/parse/);
  });

  test("rejects bodies above the size cap", async () => {
    const url = wellKnownUrl("example.com");
    const oversized = JSON.stringify({
      ...happyConfigDoc(),
      pad: "x".repeat(70 * 1024),
    });
    const { fetch } = fakeFetch({ [url]: { body: oversized } });
    await expect(fetchConfiguration(url, { fetchImpl: fetch })).rejects.toThrow(/exceeds/);
  });

  test("rejects unexpected content-type", async () => {
    const url = wellKnownUrl("example.com");
    const { fetch } = fakeFetch({
      [url]: { body: JSON.stringify(happyConfigDoc()), contentType: "text/html" },
    });
    await expect(fetchConfiguration(url, { fetchImpl: fetch })).rejects.toThrow(
      /content-type/,
    );
  });

  test("permits application/octet-stream content-type", async () => {
    const url = wellKnownUrl("example.com");
    const { fetch } = fakeFetch({
      [url]: { body: JSON.stringify(happyConfigDoc()), contentType: "application/octet-stream" },
    });
    const cfg = await fetchConfiguration(url, { fetchImpl: fetch });
    expect(cfg.domain).toBe("example.com");
  });
});

describe("fetchDomainKeys", () => {
  test("happy path returns parsed doc + decoded pub bytes", async () => {
    const url = "https://semp.example.com/domain-keys";
    const doc = happyDomainKeysDoc();
    const { fetch } = fakeFetch({ [url]: { body: JSON.stringify(doc) } });
    const result = await fetchDomainKeys(url, { fetchImpl: fetch });
    expect(result.domainKeys.domain).toBe("example.com");
    expect(result.signingPub.length).toBe(32);
    expect(result.encryptionPub.length).toBe(32);
  });

  test("rejects when signing_key fingerprint mismatches", async () => {
    const url = "https://semp.example.com/domain-keys";
    const doc = happyDomainKeysDoc();
    (doc.signing_key as Record<string, unknown>).key_id = "0".repeat(64);
    const { fetch } = fakeFetch({ [url]: { body: JSON.stringify(doc) } });
    await expect(fetchDomainKeys(url, { fetchImpl: fetch })).rejects.toThrow(
      /signing_key.key_id/,
    );
  });

  test("rejects when encryption_key fingerprint mismatches", async () => {
    const url = "https://semp.example.com/domain-keys";
    const doc = happyDomainKeysDoc();
    (doc.encryption_key as Record<string, unknown>).key_id = "0".repeat(64);
    const { fetch } = fakeFetch({ [url]: { body: JSON.stringify(doc) } });
    await expect(fetchDomainKeys(url, { fetchImpl: fetch })).rejects.toThrow(
      /encryption_key.key_id/,
    );
  });
});

describe("resolveServer", () => {
  test("end-to-end: configuration + domain keys + signingPub", async () => {
    const cfgUrl = wellKnownUrl("example.com");
    const dkUrl = "https://semp.example.com/domain-keys";
    const cfg = happyConfigDoc();
    const dk = happyDomainKeysDoc();
    const { fetch, calls } = fakeFetch({
      [cfgUrl]: { body: JSON.stringify(cfg) },
      [dkUrl]: { body: JSON.stringify(dk) },
    });

    const result = await resolveServer("example.com", { fetchImpl: fetch });

    expect(calls).toEqual([cfgUrl, dkUrl]);
    expect(result.configuration.domain).toBe("example.com");
    expect(result.signingPub.length).toBe(32);
    expect(result.signingKeyId).toBe(
      (dk.signing_key as { key_id: string }).key_id,
    );
    expect(result.encryptionPub.length).toBe(32);
    expect(result.encryptionKeyId).toBe(
      (dk.encryption_key as { key_id: string }).key_id,
    );
  });

  test("uses configurationUrl override when supplied", async () => {
    const customUrl = "http://localhost:9999/.well-known/semp/configuration";
    const dkUrl = "https://semp.example.com/domain-keys";
    const cfg = happyConfigDoc();
    const dk = happyDomainKeysDoc();
    const { fetch, calls } = fakeFetch({
      [customUrl]: { body: JSON.stringify(cfg) },
      [dkUrl]: { body: JSON.stringify(dk) },
    });

    const result = await resolveServer("example.com", {
      fetchImpl: fetch,
      configurationUrl: customUrl,
    });

    expect(calls[0]).toBe(customUrl);
    expect(result.configuration.domain).toBe("example.com");
  });

  test("rejects empty domain", async () => {
    await expect(resolveServer("")).rejects.toThrow(/domain/);
  });

  test("propagates fetch failures from either leg", async () => {
    const cfgUrl = wellKnownUrl("example.com");
    const dkUrl = "https://semp.example.com/domain-keys";
    const cfg = happyConfigDoc();
    const { fetch } = fakeFetch({
      [cfgUrl]: { body: JSON.stringify(cfg) },
      [dkUrl]: { status: 500, body: "boom" },
    });
    await expect(
      resolveServer("example.com", { fetchImpl: fetch }),
    ).rejects.toThrow(/500/);
  });

  test("respects external AbortSignal", async () => {
    const cfgUrl = wellKnownUrl("example.com");
    let abortListener: (() => void) | undefined;
    const fetch: FetchLike = (_url, init) => {
      // Pretend to start a request that hangs forever; resolve only when
      // signal aborts.
      return new Promise((_resolve, reject) => {
        const sig = init?.signal;
        if (sig === undefined) {
          reject(new Error("expected signal"));
          return;
        }
        if (sig.aborted) {
          reject(new Error("aborted"));
          return;
        }
        abortListener = () => reject(new Error("aborted"));
        sig.addEventListener("abort", abortListener);
      });
    };

    const controller = new AbortController();
    const promise = resolveServer("example.com", { fetchImpl: fetch, signal: controller.signal });
    // Abort right after kick-off.
    queueMicrotask(() => controller.abort());
    await expect(promise).rejects.toThrow(/aborted/);
    expect(abortListener).toBeDefined();
    void cfgUrl;
  });
});
