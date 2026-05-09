/**
 * Dispatcher tests. Drive frames into one end of a memory transport
 * and assert the dispatcher routes them to the correct handlers.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { newMemoryPair } from "../transport/index.js";

import { runDispatcher } from "./dispatcher.js";
import { Session } from "./session.js";

function dummyKeys(): {
  encC2S: Uint8Array;
  encS2C: Uint8Array;
  macC2S: Uint8Array;
  macS2C: Uint8Array;
  envMAC: Uint8Array;
} {
  return {
    encC2S: new Uint8Array(32),
    encS2C: new Uint8Array(32),
    macC2S: new Uint8Array(32),
    macS2C: new Uint8Array(32),
    envMAC: new Uint8Array(32),
  };
}

function makeSession(transport: import("../transport/index.js").Transport): Session {
  return new Session({
    role: "server",
    sessionId: "x",
    sessionTTL: 300,
    establishedAt: new Date(),
    permissions: [],
    keys: dummyKeys(),
    transport,
  });
}

function frame(obj: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(obj));
}

describe("runDispatcher", () => {
  test("routes envelope, rekey, keys, fetch, delivery to their handlers; unknown to onUnknown", async () => {
    const [a, b] = newMemoryPair();
    const session = makeSession(b);
    const seen: Array<{ kind: string; type?: string }> = [];

    const dispatch = runDispatcher(session, {
      onEnvelope: () => {
        seen.push({ kind: "envelope" });
      },
      onRekey: () => {
        seen.push({ kind: "rekey" });
      },
      onKeys: () => {
        seen.push({ kind: "keys" });
      },
      onFetch: () => {
        seen.push({ kind: "fetch" });
      },
      onDelivery: () => {
        seen.push({ kind: "delivery" });
      },
      onUnknown: (type) => {
        seen.push({ kind: "unknown", type });
      },
    });

    await a.send(frame({ type: "SEMP_ENVELOPE" }));
    await a.send(frame({ type: "SEMP_REKEY" }));
    await a.send(frame({ type: "SEMP_KEYS" }));
    await a.send(frame({ type: "SEMP_FETCH" }));
    await a.send(frame({ type: "SEMP_DELIVERY_ACK" }));
    await a.send(frame({ type: "SEMP_DELIVERY_RECEIPT" }));
    await a.send(frame({ type: "SEMP_FUTURE_TYPE" }));
    await a.close();

    await dispatch;

    expect(seen).toEqual([
      { kind: "envelope" },
      { kind: "rekey" },
      { kind: "keys" },
      { kind: "fetch" },
      { kind: "delivery" },
      { kind: "delivery" },
      { kind: "unknown", type: "SEMP_FUTURE_TYPE" },
    ]);
  });

  test("SEMP_FETCH falls through to onUnknown when onFetch is not registered", async () => {
    const [a, b] = newMemoryPair();
    const session = makeSession(b);
    const seen: Array<{ kind: string; type?: string }> = [];

    const dispatch = runDispatcher(session, {
      onUnknown: (type) => {
        seen.push({ kind: "unknown", type });
      },
    });

    await a.send(frame({ type: "SEMP_FETCH" }));
    await a.close();

    await dispatch;

    expect(seen).toEqual([{ kind: "unknown", type: "SEMP_FETCH" }]);
  });

  test("clean EOF resolves the dispatcher; no error", async () => {
    const [a, b] = newMemoryPair();
    const session = makeSession(b);
    const dispatch = runDispatcher(session, {});
    await a.close();
    await dispatch;
    // No assertion needed; resolving without throw is the test.
  });

  test("malformed frame triggers onFatal and resolves", async () => {
    const [a, b] = newMemoryPair();
    const session = makeSession(b);
    let fatal: Error | null = null;
    const dispatch = runDispatcher(session, {
      onFatal: (err) => {
        fatal = err;
      },
    });
    await a.send(new TextEncoder().encode("not-json"));
    await dispatch;
    expect(fatal).not.toBeNull();
    if (fatal !== null) {
      expect((fatal as Error).message).toMatch(/malformed/);
    }
  });

  test("handler error is non-fatal; loop continues; onHandlerError invoked", async () => {
    const [a, b] = newMemoryPair();
    const session = makeSession(b);
    const seen: string[] = [];
    let handlerErr: Error | null = null;
    const dispatch = runDispatcher(session, {
      onEnvelope: () => {
        seen.push("envelope");
        throw new Error("synthetic envelope handler failure");
      },
      onKeys: () => {
        seen.push("keys");
      },
      onHandlerError: (err) => {
        handlerErr = err;
      },
    });
    await a.send(frame({ type: "SEMP_ENVELOPE" }));
    await a.send(frame({ type: "SEMP_KEYS" }));
    await a.close();
    await dispatch;
    expect(seen).toEqual(["envelope", "keys"]);
    expect(handlerErr).not.toBeNull();
    if (handlerErr !== null) {
      expect((handlerErr as Error).message).toMatch(/synthetic/);
    }
  });
});
