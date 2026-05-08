/**
 * End-to-end handshake test. Pairs runClient and runServer over the
 * in-memory transport and asserts both peers end up with identical
 * session keys.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { computeMAC } from "../crypto/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";
import { newMemoryPair } from "../transport/index.js";

import { HandshakeRejectedError, runClient } from "./driver.js";
import { runServer } from "./server.js";

function encodeBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

const TestSessionId = "01J7TESTSESSIONID0000000000";

/** Build a ServerConfig from the most common test inputs. */
function serverConfig(
  serverSeed: Uint8Array,
  overrides?: { permissions?: string[]; verifyIdentityProof?: () => { ok: boolean; reasonCode?: string } },
): Parameters<typeof runServer>[1] {
  return {
    serverDomainSigningSeed: serverSeed,
    domain: "test.example",
    supportedSuites: ["x25519-chacha20-poly1305"],
    permissions: overrides?.permissions ?? ["send", "receive"],
    sessionTTL: 300,
    generateSessionId: () => TestSessionId,
    identityProofSignature: () => "PLACEHOLDER-IDENTITY-PROOF",
    ...(overrides?.verifyIdentityProof !== undefined
      ? { verifyIdentityProof: overrides.verifyIdentityProof }
      : {}),
  };
}

describe("handshake.runClient + runServer", () => {
  test("baseline handshake: both peers derive identical session keys", async () => {
    const [c, s] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const [clientSession, serverSession] = await Promise.all([
      runClient(c, {
        suite: "x25519-chacha20-poly1305",
        capabilities: {
          encryption_algorithms: ["x25519-chacha20-poly1305"],
          extensions: [],
        },
        transport: "memory",
        serverDomainPub,
      }),
      runServer(s, serverConfig(serverSeed)),
    ]);

    expect(clientSession.sessionId).toBe(TestSessionId);
    expect(serverSession.sessionId).toBe(TestSessionId);
    expect(clientSession.role).toBe("client");
    expect(serverSession.role).toBe("server");

    // Identical session keys (the gating interop check).
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

    // Sanity: symmetric MAC on a sample envelope-canonical-bytes
    // sequence agrees both ways.
    const sample = new TextEncoder().encode("sample envelope canonical bytes");
    expect(encodeBase64(computeMAC(clientSession.keys.envMAC, sample))).toBe(
      encodeBase64(computeMAC(serverSession.keys.envMAC, sample)),
    );

    // server_identity_proof flows through the client session.
    expect(clientSession.serverIdentityProofKeyId).toBe(fingerprint(serverDomainPub));
    expect(clientSession.serverIdentityProofSignature).toBe("PLACEHOLDER-IDENTITY-PROOF");

    await Promise.all([clientSession.erase(), serverSession.erase()]);
  });

  test("server rejects handshake when verifyIdentityProof returns ok=false", async () => {
    const [c, s] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const [clientResult, serverResult] = await Promise.allSettled([
      runClient(c, {
        suite: "x25519-chacha20-poly1305",
        capabilities: { encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] },
        transport: "memory",
        serverDomainPub,
      }),
      runServer(
        s,
        serverConfig(serverSeed, {
          verifyIdentityProof: () => ({ ok: false, reasonCode: "auth_failed" }),
        }),
      ),
    ]);

    expect(clientResult.status).toBe("rejected");
    if (clientResult.status === "rejected") {
      expect(clientResult.reason).toBeInstanceOf(HandshakeRejectedError);
      const err = clientResult.reason as HandshakeRejectedError;
      expect(err.reasonCode).toBe("auth_failed");
    }
    expect(serverResult.status).toBe("rejected");
  });

  test("server rejects handshake when no mutually supported suite", async () => {
    const [c, s] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    // Client offers ONLY a suite the server doesn't know.
    const fakeFutureSuite = "future-suite" as unknown as "x25519-chacha20-poly1305";

    const [clientResult, serverResult] = await Promise.allSettled([
      runClient(c, {
        suite: "x25519-chacha20-poly1305",
        capabilities: {
          encryption_algorithms: [fakeFutureSuite],
          extensions: [],
        },
        transport: "memory",
        serverDomainPub,
      }),
      runServer(s, serverConfig(serverSeed)),
    ]);

    expect(clientResult.status).toBe("rejected");
    if (clientResult.status === "rejected") {
      expect(clientResult.reason).toBeInstanceOf(HandshakeRejectedError);
      const err = clientResult.reason as HandshakeRejectedError;
      expect(err.reasonCode).toBe("version_unsupported");
    }
    expect(serverResult.status).toBe("rejected");
  });

  test("client rejects when server signature does not verify under pinned pub", async () => {
    const [c, s] = newMemoryPair();
    const serverSeed = randomBytes(32);
    // Client believes the server's pub is something else entirely.
    const wrongPub = publicKeyFromSeed(randomBytes(32));

    const [clientResult, serverResult] = await Promise.allSettled([
      runClient(c, {
        suite: "x25519-chacha20-poly1305",
        capabilities: { encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] },
        transport: "memory",
        serverDomainPub: wrongPub,
      }),
      runServer(s, serverConfig(serverSeed)),
    ]);

    expect(clientResult.status).toBe("rejected");
    if (clientResult.status === "rejected") {
      expect(String(clientResult.reason)).toMatch(/did not verify/);
    }
    // Server side returns once the client closes the transport
    // after receiving the response that doesn't verify.
    expect(serverResult.status).toBe("rejected");
  });
});
