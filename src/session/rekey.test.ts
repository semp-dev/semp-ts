/**
 * Rekey end-to-end test.
 *
 * Stand up a connected pair of Sessions over the in-memory
 * transport (using a precomputed key set, since runClient/runServer
 * already cover full handshake setup), drive a rekey on both
 * sides concurrently, and assert both ends end up with identical
 * NEW session keys + the same new session_id.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type SessionKeys,
  computeMAC,
} from "../crypto/index.js";
import { newMemoryPair } from "../transport/index.js";

import { rekeyClient, rekeyServer } from "./rekey.js";
import { Session } from "./session.js";

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function encodeBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

/** Build matching session keys for both peers. Both sides share
 * the same bytes since session keys are symmetric. */
function makeSharedKeys(): SessionKeys {
  return {
    encC2S: randomBytes(32),
    encS2C: randomBytes(32),
    macC2S: randomBytes(32),
    macS2C: randomBytes(32),
    envMAC: randomBytes(32),
  };
}

function clone(keys: SessionKeys): SessionKeys {
  return {
    encC2S: new Uint8Array(keys.encC2S),
    encS2C: new Uint8Array(keys.encS2C),
    macC2S: new Uint8Array(keys.macC2S),
    macS2C: new Uint8Array(keys.macS2C),
    envMAC: new Uint8Array(keys.envMAC),
  };
}

describe("session.rekey", () => {
  test("rekey end-to-end: both peers install identical new keys + new session_id", async () => {
    const [tClient, tServer] = newMemoryPair();
    const keys = makeSharedKeys();
    const established = new Date();

    const clientSession = new Session({
      role: "client",
      sessionId: "01JOLD000000000000000000000",
      sessionTTL: 300,
      establishedAt: established,
      permissions: ["send", "receive"],
      keys: clone(keys),
      transport: tClient,
    });
    const serverSession = new Session({
      role: "server",
      sessionId: "01JOLD000000000000000000000",
      sessionTTL: 300,
      establishedAt: established,
      permissions: ["send", "receive"],
      keys: clone(keys),
      transport: tServer,
    });

    const newSessionId = "01JNEW000000000000000000000";

    const [clientNewId, serverNewId] = await Promise.all([
      rekeyClient(clientSession),
      rekeyServer(serverSession, {
        generateSessionId: () => newSessionId,
      }),
    ]);

    expect(clientNewId).toBe(newSessionId);
    expect(serverNewId).toBe(newSessionId);
    expect(clientSession.sessionId).toBe(newSessionId);
    expect(serverSession.sessionId).toBe(newSessionId);

    // The new session keys MUST be identical on both sides.
    expect(encodeBase64(clientSession.keys.encC2S)).toBe(
      encodeBase64(serverSession.keys.encC2S),
    );
    expect(encodeBase64(clientSession.keys.encS2C)).toBe(
      encodeBase64(serverSession.keys.encS2C),
    );
    expect(encodeBase64(clientSession.keys.macC2S)).toBe(
      encodeBase64(serverSession.keys.macC2S),
    );
    expect(encodeBase64(clientSession.keys.macS2C)).toBe(
      encodeBase64(serverSession.keys.macS2C),
    );
    expect(encodeBase64(clientSession.keys.envMAC)).toBe(
      encodeBase64(serverSession.keys.envMAC),
    );

    // And the NEW envMAC differs from the OLD one (proof that
    // rekey actually changed keys, not just propagated).
    expect(encodeBase64(clientSession.keys.envMAC)).not.toBe(encodeBase64(keys.envMAC));

    // Sanity: after rekey both sides agree on a fresh MAC.
    const sample = new TextEncoder().encode("post-rekey envelope sample");
    expect(encodeBase64(computeMAC(clientSession.keys.envMAC, sample))).toBe(
      encodeBase64(computeMAC(serverSession.keys.envMAC, sample)),
    );

    await Promise.all([clientSession.erase(), serverSession.erase()]);
  });

  test("Session.applyRekey throws after erase", () => {
    const [t] = newMemoryPair();
    const s = new Session({
      role: "client",
      sessionId: "x",
      sessionTTL: 300,
      establishedAt: new Date(),
      permissions: [],
      keys: makeSharedKeys(),
      transport: t,
    });
    void s.erase();
    // erase() awaits internally; the synchronous applyRekey will
    // see either "applyRekey after erase" or "applyRekey on closed
    // session" depending on which guard the engine reached first.
    // Both are acceptable.
    expect(() =>
      s.applyRekey({ newSessionId: "y", newKeys: makeSharedKeys() }),
    ).toThrow();
  });
});
