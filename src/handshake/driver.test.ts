/**
 * End-to-end handshake driver test. Spawns a fake server inside
 * the test that drives the protocol from the other side of an
 * in-memory transport pair. Asserts the driver returns a session
 * whose keys agree with the server's keys (i.e., HKDF over the
 * shared X25519 secret produces matching outputs).
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  computeMAC,
  deriveSessionKeysWithResumption,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "../crypto/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";
import type { Transport } from "../transport/index.js";
import { newMemoryPair } from "../transport/index.js";

import { confirmationHash } from "./confirm.js";
import { HandshakeRejectedError, runClient } from "./driver.js";
import {
  buildAccepted,
  buildRejected,
  buildResponse,
} from "./messages.js";

function decodeBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

function encodeBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

/**
 * Drive the server side of one handshake to a successful ACCEPTED.
 * Returns the server-derived session keys so the test can assert
 * they match the client's.
 */
async function fakeServer(
  transport: Transport,
  serverDomainSeed: Uint8Array,
  opts: { rejectAt?: "response" | "accepted"; rejectReason?: string } = {},
): Promise<ReturnType<typeof deriveSessionKeysWithResumption>> {
  // Wait for INIT.
  const initBytes = await transport.receive();
  if (initBytes === null) {
    throw new Error("server: connection closed before INIT");
  }
  const initText = new TextDecoder().decode(initBytes);
  const init = JSON.parse(initText) as Record<string, unknown>;

  if (opts.rejectAt === "response") {
    const reject = buildRejected({
      sessionId: "01J7TESTSESSIONID0000000000",
      reasonCode: opts.rejectReason ?? "auth_failed",
      serverDomainSigningSeed: serverDomainSeed,
    });
    await transport.send(canonicalMarshal(reject));
    // Server treats the handshake as terminated; client raises.
    return null as unknown as ReturnType<typeof deriveSessionKeysWithResumption>;
  }

  // Server picks a fresh ephemeral and nonce.
  const serverEphPriv = randomBytes(32);
  const serverEphPub = x25519PublicKey(serverEphPriv);
  const serverNonce = randomBytes(32);
  const sessionId = "01J7TESTSESSIONID0000000000";

  // Pull client's ephemeral pub + nonce.
  const clientEph = init.client_ephemeral_key as { key: string };
  const clientEphPub = decodeBase64(clientEph.key);
  const clientNonce = decodeBase64(init.nonce as string);

  // Compute shared secret + session keys.
  const sharedSecret = x25519Agree(serverEphPriv, clientEphPub);
  const kdf = newHKDFSHA512();
  const serverKeys = deriveSessionKeysWithResumption(
    kdf,
    sharedSecret,
    clientNonce,
    serverNonce,
  );

  // Build + sign RESPONSE.
  const resp = buildResponse({
    sessionId,
    clientNonce: init.nonce as string,
    serverNonce: encodeBase64(serverNonce),
    serverEphemeralKey: {
      algorithm: "x25519-chacha20-poly1305",
      key: encodeBase64(serverEphPub),
      key_id: fingerprint(serverEphPub),
    },
    serverIdentityProof: {
      domain: "test.example",
      key_id: fingerprint(publicKeyFromSeed(serverDomainSeed)),
      // The identity proof signature itself is opaque at this
      // layer; tests pass a placeholder.
      signature: "PLACEHOLDER-IDENTITY-PROOF",
    },
    negotiated: {
      encryption_algorithm: "x25519-chacha20-poly1305",
      extensions: [],
    },
    serverDomainSigningSeed: serverDomainSeed,
  });
  await transport.send(canonicalMarshal(resp));

  // Wait for CONFIRM, verify the confirmation hash. If the client
  // closed the transport before sending CONFIRM (e.g. it rejected
  // our RESPONSE signature), exit cleanly so the test's Promise.all
  // doesn't hang.
  const confBytes = await transport.receive();
  if (confBytes === null) {
    return serverKeys;
  }
  const confirm = JSON.parse(new TextDecoder().decode(confBytes)) as Record<string, unknown>;
  const wantHash = confirmationHash(initBytes, canonicalMarshal(resp));
  const gotHash = decodeBase64(confirm.confirmation_hash as string);
  if (encodeBase64(wantHash) !== encodeBase64(gotHash)) {
    throw new Error("server: confirmation hash mismatch");
  }

  if (opts.rejectAt === "accepted") {
    const reject = buildRejected({
      sessionId,
      reasonCode: opts.rejectReason ?? "policy_forbidden",
      serverDomainSigningSeed: serverDomainSeed,
    });
    await transport.send(canonicalMarshal(reject));
    return serverKeys;
  }

  // Build + sign ACCEPTED.
  const accepted = buildAccepted({
    sessionId,
    sessionTTL: 300,
    permissions: ["send", "receive"],
    serverDomainSigningSeed: serverDomainSeed,
  });
  await transport.send(canonicalMarshal(accepted));
  return serverKeys;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

describe("handshake.runClient", () => {
  test("baseline handshake completes; client and server derive the same keys", async () => {
    const [client, server] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const [session, serverKeys] = await Promise.all([
      runClient(client, {
        suite: "x25519-chacha20-poly1305",
        capabilities: {
          encryption_algorithms: ["x25519-chacha20-poly1305"],
          extensions: [],
        },
        transport: "memory",
        serverDomainPub,
      }),
      fakeServer(server, serverSeed),
    ]);

    expect(session.sessionId).toBe("01J7TESTSESSIONID0000000000");
    expect(session.sessionTTL).toBe(300);
    expect([...session.permissions]).toEqual(["send", "receive"]);
    expect(session.role).toBe("client");
    expect(session.closed).toBe(false);

    // The two sides MUST derive identical session keys.
    expect(encodeBase64(session.keys.encC2S)).toBe(encodeBase64(serverKeys.encC2S));
    expect(encodeBase64(session.keys.encS2C)).toBe(encodeBase64(serverKeys.encS2C));
    expect(encodeBase64(session.keys.macC2S)).toBe(encodeBase64(serverKeys.macC2S));
    expect(encodeBase64(session.keys.macS2C)).toBe(encodeBase64(serverKeys.macS2C));
    expect(encodeBase64(session.keys.envMAC)).toBe(encodeBase64(serverKeys.envMAC));

    // Sanity: the derived envMAC actually authenticates a sample
    // message symmetrically. Both sides compute the same MAC.
    const sample = new TextEncoder().encode("sample envelope canonical bytes");
    const clientMAC = computeMAC(session.keys.envMAC, sample);
    const serverMAC = computeMAC(serverKeys.envMAC, sample);
    expect(encodeBase64(clientMAC)).toBe(encodeBase64(serverMAC));

    await session.erase();
    expect(session.closed).toBe(true);
    expect(() => session.keys).toThrow(/erased/);

    await server.close();
  });

  test("server REJECTED at response surfaces as HandshakeRejectedError", async () => {
    const [client, server] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    await Promise.all([
      expect(
        runClient(client, {
          suite: "x25519-chacha20-poly1305",
          capabilities: { encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] },
          transport: "memory",
          serverDomainPub,
        }),
      ).rejects.toBeInstanceOf(HandshakeRejectedError),
      fakeServer(server, serverSeed, { rejectAt: "response", rejectReason: "auth_failed" }),
    ]);
  });

  test("server REJECTED at accepted surfaces as HandshakeRejectedError", async () => {
    const [client, server] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    await Promise.all([
      expect(
        runClient(client, {
          suite: "x25519-chacha20-poly1305",
          capabilities: { encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] },
          transport: "memory",
          serverDomainPub,
        }),
      ).rejects.toBeInstanceOf(HandshakeRejectedError),
      fakeServer(server, serverSeed, { rejectAt: "accepted", rejectReason: "policy_forbidden" }),
    ]);
  });

  test("wrong server domain pub causes signature failure", async () => {
    const [client, server] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const wrongPub = publicKeyFromSeed(randomBytes(32));

    await Promise.all([
      expect(
        runClient(client, {
          suite: "x25519-chacha20-poly1305",
          capabilities: { encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] },
          transport: "memory",
          serverDomainPub: wrongPub,
        }),
      ).rejects.toThrow(/did not verify/),
      fakeServer(server, serverSeed),
    ]);
  });
});
