/**
 * Domain-keys parser tests. Cover the parse path + the
 * fingerprint cross-check (verifyDomainKeyFingerprint).
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  decodeKeyBlockPublic,
  parseDomainKeys,
  verifyDomainKeyFingerprint,
} from "./domain_keys.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function happyDomainKeys(): Record<string, unknown> {
  const sigSeed = deterministicSeed(0x10);
  const sigPub = publicKeyFromSeed(sigSeed);
  const encPub = deterministicSeed(0x20); // X25519 pub: just bytes for the test
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

describe("parseDomainKeys", () => {
  test("happy path returns the typed object", () => {
    const dk = parseDomainKeys(happyDomainKeys());
    expect(dk.type).toBe("SEMP_DOMAIN_KEYS");
    expect(dk.domain).toBe("example.com");
    expect(dk.signing_key.algorithm).toBe("ed25519");
    expect(dk.encryption_key.algorithm).toBe("x25519-chacha20-poly1305");
  });

  test("rejects wrong type", () => {
    const bad = happyDomainKeys();
    bad.type = "SEMP_OTHER";
    expect(() => parseDomainKeys(bad)).toThrow(/type/);
  });

  test("rejects missing version / domain", () => {
    const bad = happyDomainKeys();
    delete bad.version;
    expect(() => parseDomainKeys(bad)).toThrow(/version/);

    const bad2 = happyDomainKeys();
    delete bad2.domain;
    expect(() => parseDomainKeys(bad2)).toThrow(/domain/);
  });

  test("rejects missing signing_key / encryption_key", () => {
    const bad = happyDomainKeys();
    delete bad.signing_key;
    expect(() => parseDomainKeys(bad)).toThrow(/signing_key/);

    const bad2 = happyDomainKeys();
    delete bad2.encryption_key;
    expect(() => parseDomainKeys(bad2)).toThrow(/encryption_key/);
  });

  test("rejects key block missing algorithm/public_key/key_id", () => {
    for (const field of ["algorithm", "public_key", "key_id"]) {
      const bad = happyDomainKeys();
      delete (bad.signing_key as Record<string, unknown>)[field];
      expect(() => parseDomainKeys(bad), `missing signing_key.${field}`).toThrow(
        new RegExp(field),
      );
    }
  });
});

describe("verifyDomainKeyFingerprint", () => {
  test("matches when key_id is the SHA-256 of public_key", () => {
    const dk = parseDomainKeys(happyDomainKeys());
    expect(verifyDomainKeyFingerprint(dk.signing_key)).toBe(true);
    expect(verifyDomainKeyFingerprint(dk.encryption_key)).toBe(true);
  });

  test("rejects when key_id does not match", () => {
    const dk = parseDomainKeys(happyDomainKeys());
    const tampered = { ...dk.signing_key, key_id: "0".repeat(64) };
    expect(verifyDomainKeyFingerprint(tampered)).toBe(false);
  });

  test("comparison is case-insensitive on key_id", () => {
    const dk = parseDomainKeys(happyDomainKeys());
    const upper = { ...dk.signing_key, key_id: dk.signing_key.key_id.toUpperCase() };
    expect(verifyDomainKeyFingerprint(upper)).toBe(true);
  });
});

describe("decodeKeyBlockPublic", () => {
  test("returns the original bytes", () => {
    const seed = deterministicSeed(0x10);
    const pub = publicKeyFromSeed(seed);
    const block = {
      algorithm: "ed25519",
      public_key: base64(pub),
      key_id: fingerprint(pub),
    };
    const decoded = decodeKeyBlockPublic(block);
    expect(decoded).toEqual(pub);
  });
});
