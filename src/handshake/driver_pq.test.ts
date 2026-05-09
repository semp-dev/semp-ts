/**
 * End-to-end PQ handshake test. Pairs runClient and runServer over
 * the in-memory transport with `suite: "pq-kyber768-x25519"` and
 * asserts both peers end up with identical session keys derived
 * from the hybrid Kyber768 + X25519 KEM.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { computeMAC } from "../crypto/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";
import { Session } from "../session/index.js";
import { newMemoryPair } from "../transport/index.js";

import { HandshakeClient } from "./client_state.js";
import { runClient } from "./driver.js";
import { HandshakeServer } from "./server_state.js";
import { runServer } from "./server.js";

function encodeBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

const TestSessionId = "01J7TESTPQSESSIONID0000000";

describe("handshake PQ suite", () => {
  test("runClient + runServer derive identical session keys with pq-kyber768-x25519", async () => {
    const [c, s] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const [clientSession, serverSession] = await Promise.all([
      runClient(c, {
        suite: "pq-kyber768-x25519",
        capabilities: {
          encryption_algorithms: ["pq-kyber768-x25519"],
          extensions: [],
        },
        transport: "memory",
        serverDomainPub,
      }),
      runServer(s, {
        serverDomainSigningSeed: serverSeed,
        domain: "test.example",
        supportedSuites: ["pq-kyber768-x25519"],
        permissions: ["send", "receive"],
        sessionTTL: 300,
        generateSessionId: () => TestSessionId,
        identityProofSignature: () => "PLACEHOLDER",
      }),
    ]);

    expect(clientSession.sessionId).toBe(TestSessionId);
    expect(serverSession.sessionId).toBe(TestSessionId);
    expect(clientSession.role).toBe("client");
    expect(serverSession.role).toBe("server");

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

    // Sanity: the symmetric MAC on a sample envelope-canonical-bytes
    // sequence agrees both ways. This is the gating interop check
    // for the post-handshake envelope flow.
    const sample = new TextEncoder().encode("sample envelope canonical bytes");
    expect(encodeBase64(computeMAC(clientSession.keys.envMAC, sample))).toBe(
      encodeBase64(computeMAC(serverSession.keys.envMAC, sample)),
    );

    expect(clientSession.serverIdentityProofKeyId).toBe(
      fingerprint(serverDomainPub),
    );
    expect(clientSession.serverIdentityProofSignature).toBe("PLACEHOLDER");

    // First envelope round-trips: send a bytes blob from client to
    // server and back.
    await firstEnvelopeRoundtrip(clientSession, serverSession);

    await Promise.all([clientSession.erase(), serverSession.erase()]);
  });

  test("HandshakeClient + HandshakeServer state-machine path agrees on PQ keys", () => {
    const serverSeed = randomBytes(32);
    const serverPub = publicKeyFromSeed(serverSeed);

    const client = new HandshakeClient({
      suite: "pq-kyber768-x25519",
      capabilities: {
        encryption_algorithms: ["pq-kyber768-x25519"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: serverPub,
    });
    const server = new HandshakeServer({
      serverDomainSigningSeed: serverSeed,
      domain: "test.example",
      supportedSuites: ["pq-kyber768-x25519"],
      permissions: ["send", "receive"],
      sessionTTL: 300,
      generateSessionId: () => "01J7PQSTATEFULID0000000000",
      identityProofSignature: () => "PLACEHOLDER",
    });

    const initBytes = client.init();
    const respBytes = server.onInit(initBytes);
    const confirmBytes = client.onResponse(respBytes);
    const acceptedBytes = server.onConfirm(confirmBytes);
    client.onAccepted(acceptedBytes);

    const cs = client.session();
    const ss = server.session();
    expect(cs.sessionId).toBe("01J7PQSTATEFULID0000000000");
    expect(ss.sessionId).toBe(cs.sessionId);
    expect(encodeBase64(cs.keys.encC2S)).toBe(encodeBase64(ss.keys.encC2S));
    expect(encodeBase64(cs.keys.encS2C)).toBe(encodeBase64(ss.keys.encS2C));
    expect(encodeBase64(cs.keys.macC2S)).toBe(encodeBase64(ss.keys.macC2S));
    expect(encodeBase64(cs.keys.macS2C)).toBe(encodeBase64(ss.keys.macS2C));
  });

  test("server picks PQ when both sides offer baseline + PQ", async () => {
    const [c, s] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const [clientSession, serverSession] = await Promise.all([
      runClient(c, {
        suite: "pq-kyber768-x25519",
        capabilities: {
          encryption_algorithms: [
            "pq-kyber768-x25519",
            "x25519-chacha20-poly1305",
          ],
          extensions: [],
        },
        transport: "memory",
        serverDomainPub,
      }),
      runServer(s, {
        serverDomainSigningSeed: serverSeed,
        domain: "test.example",
        // PQ first in the server's preference list.
        supportedSuites: [
          "pq-kyber768-x25519",
          "x25519-chacha20-poly1305",
        ],
        permissions: ["send", "receive"],
        sessionTTL: 300,
        generateSessionId: () => "01J7PQNEGOTIATIONID000000",
        identityProofSignature: () => "PLACEHOLDER",
      }),
    ]);
    expect(encodeBase64(clientSession.keys.envMAC)).toBe(
      encodeBase64(serverSession.keys.envMAC),
    );
    await Promise.all([clientSession.erase(), serverSession.erase()]);
  });
});

/**
 * Send one envelope-shaped frame from client to server and one
 * back. Verifies the post-handshake transport is wired correctly
 * for both sides under the PQ suite.
 */
async function firstEnvelopeRoundtrip(
  client: Session,
  server: Session,
): Promise<void> {
  const c2sFrame = new TextEncoder().encode(
    JSON.stringify({ type: "SEMP_ENVELOPE", probe: "client to server" }),
  );
  await client.send(c2sFrame);
  const c2sSeen = await server.receive();
  expect(c2sSeen).not.toBeNull();
  if (c2sSeen !== null) {
    const obj = JSON.parse(new TextDecoder().decode(c2sSeen)) as {
      probe?: string;
    };
    expect(obj.probe).toBe("client to server");
  }
  const s2cFrame = new TextEncoder().encode(
    JSON.stringify({ type: "SEMP_ENVELOPE", probe: "server to client" }),
  );
  await server.send(s2cFrame);
  const s2cSeen = await client.receive();
  expect(s2cSeen).not.toBeNull();
  if (s2cSeen !== null) {
    const obj = JSON.parse(new TextDecoder().decode(s2cSeen)) as {
      probe?: string;
    };
    expect(obj.probe).toBe("server to client");
  }
}
