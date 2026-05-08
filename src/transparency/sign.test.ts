/**
 * STH sign / verify / freshness tests.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  type LogEntry,
  type SignedTreeHead,
  MaxSTHFreshnessMs,
} from "./types.js";
import {
  TransparencySTHPrefix,
  checkSTHFresh,
  signSTH,
  validateLogEntry,
  validateSTH,
  verifySTH,
} from "./sign.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function happySTH(): SignedTreeHead {
  return {
    log_size: 17,
    root_hash: Buffer.from(new Uint8Array(32).fill(0xab)).toString("base64"),
    timestamp: "2026-04-21T10:00:00Z",
    signature: { algorithm: "", key_id: "", value: "" },
  };
}

describe("signSTH + verifySTH round-trip", () => {
  test("sign + verify under the same key succeeds", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const keyId = fingerprint(pub);
    const { sth } = signSTH({
      sth: happySTH(),
      domainSigningSeed: seed,
      domainKeyId: keyId,
    });
    expect(sth.signature.algorithm).toBe("ed25519");
    expect(sth.signature.key_id).toBe(keyId);
    expect(sth.signature.value).not.toBe("");
    expect(verifySTH(sth, pub)).toBe(true);
  });

  test("verify under a different key fails", () => {
    const seed = deterministicSeed(0x42);
    const { sth } = signSTH({
      sth: happySTH(),
      domainSigningSeed: seed,
      domainKeyId: fingerprint(publicKeyFromSeed(seed)),
    });
    const wrongPub = publicKeyFromSeed(deterministicSeed(0xff));
    expect(verifySTH(sth, wrongPub)).toBe(false);
  });

  test("tampering after signing breaks verification", () => {
    const seed = deterministicSeed(0x42);
    const pub = publicKeyFromSeed(seed);
    const { sth } = signSTH({
      sth: happySTH(),
      domainSigningSeed: seed,
      domainKeyId: fingerprint(pub),
    });
    sth.log_size = 99;
    expect(verifySTH(sth, pub)).toBe(false);
  });

  test("blank signature fails", () => {
    const sth: SignedTreeHead = {
      ...happySTH(),
      signature: { algorithm: "ed25519", key_id: "x", value: "" },
    };
    expect(verifySTH(sth, publicKeyFromSeed(deterministicSeed(0x42)))).toBe(
      false,
    );
  });

  test("rejects empty domain key_id", () => {
    expect(() =>
      signSTH({
        sth: happySTH(),
        domainSigningSeed: deterministicSeed(0x42),
        domainKeyId: "",
      }),
    ).toThrow(/key_id/);
  });

  test("prefix matches spec table", () => {
    expect(TransparencySTHPrefix).toBe("SEMP-TRANSPARENCY-STH:");
  });
});

describe("checkSTHFresh", () => {
  test("fresh STH passes", () => {
    const sth: SignedTreeHead = {
      ...happySTH(),
      timestamp: "2026-04-21T10:00:00Z",
    };
    const now = new Date("2026-04-21T10:30:00Z");
    expect(checkSTHFresh(sth, now)).toBe(true);
  });

  test("stale STH fails", () => {
    const sth: SignedTreeHead = {
      ...happySTH(),
      timestamp: "2026-04-21T08:00:00Z",
    };
    const now = new Date("2026-04-21T10:00:00Z");
    expect(checkSTHFresh(sth, now)).toBe(false);
  });

  test("exactly at the freshness boundary passes", () => {
    const ts = "2026-04-21T09:00:00Z";
    const now = new Date(Date.parse(ts) + MaxSTHFreshnessMs);
    expect(checkSTHFresh({ ...happySTH(), timestamp: ts }, now)).toBe(true);
  });

  test("malformed timestamp fails", () => {
    expect(
      checkSTHFresh({ ...happySTH(), timestamp: "not a date" }, new Date()),
    ).toBe(false);
  });
});

describe("validateSTH", () => {
  test("rejects negative log_size", () => {
    expect(() => validateSTH({ ...happySTH(), log_size: -1 })).toThrow(
      /log_size/,
    );
  });

  test("rejects empty root_hash", () => {
    expect(() => validateSTH({ ...happySTH(), root_hash: "" })).toThrow(
      /root_hash/,
    );
  });

  test("rejects empty timestamp", () => {
    expect(() => validateSTH({ ...happySTH(), timestamp: "" })).toThrow(
      /timestamp/,
    );
  });
});

describe("validateLogEntry", () => {
  function happyEntry(): LogEntry {
    return {
      event: "publish",
      user_id: "alice@example.com",
      key_id: "keyid",
      key_type: "identity",
      algorithm: "ed25519",
      public_key: "AAAA",
      created: "2026-04-21T10:00:00Z",
      log_timestamp: "2026-04-21T10:01:00Z",
    };
  }

  test("happy publish", () => {
    validateLogEntry(happyEntry());
  });

  test("rejects unknown event", () => {
    expect(() =>
      validateLogEntry({ ...happyEntry(), event: "bogus" as never }),
    ).toThrow(/event/);
  });

  test("rotate requires supersedes", () => {
    const e = { ...happyEntry(), event: "rotate" as const };
    expect(() => validateLogEntry(e)).toThrow(/supersedes/);
    e.supersedes = "old-keyid";
    validateLogEntry(e);
  });

  test("publish forbids supersedes", () => {
    const e = { ...happyEntry(), supersedes: "should-not-be-here" };
    expect(() => validateLogEntry(e)).toThrow(/supersedes/);
  });

  test("revoke requires revoked_at + revoked_reason", () => {
    const e = { ...happyEntry(), event: "revoke" as const };
    expect(() => validateLogEntry(e)).toThrow(/revoked_at/);
    e.revoked_at = "2026-04-21T11:00:00Z";
    expect(() => validateLogEntry(e)).toThrow(/revoked_reason/);
    e.revoked_reason = "compromise";
    validateLogEntry(e);
  });

  test("rejects unknown key_type", () => {
    expect(() =>
      validateLogEntry({ ...happyEntry(), key_type: "auth" as never }),
    ).toThrow(/key_type/);
  });

  test("rejects malformed timestamps", () => {
    expect(() =>
      validateLogEntry({ ...happyEntry(), created: "not a date" }),
    ).toThrow(/created/);
  });
});
