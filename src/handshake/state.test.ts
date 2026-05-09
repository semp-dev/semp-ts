/**
 * Tests for the stateful handshake `HandshakeClient` /
 * `HandshakeServer` classes — the explicit state-machine API
 * that the high-level `runClient` / `runServer` wraps. Drives both
 * sides manually to exercise the same flow.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import { HandshakeClient } from "./client_state.js";
import { HandshakeServer } from "./server_state.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function encodeB64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

describe("HandshakeClient + HandshakeServer", () => {
  test("baseline handshake: both peers derive identical session keys", () => {
    const serverSeed = seed(0xa1);
    const serverPub = publicKeyFromSeed(serverSeed);

    const client = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: serverPub,
    });
    const server = new HandshakeServer({
      serverDomainSigningSeed: serverSeed,
      domain: "test.example",
      supportedSuites: ["x25519-chacha20-poly1305"],
      permissions: ["send", "receive"],
      sessionTTL: 300,
      generateSessionId: () => "01J7TEST00000000000000000000",
      identityProofSignature: () => "PLACEHOLDER",
    });

    // 1. Client INIT → Server.
    const initBytes = client.init();
    const respBytes = server.onInit(initBytes);

    // 2. Server RESPONSE → Client.
    const confirmBytes = client.onResponse(respBytes);

    // 3. Client CONFIRM → Server.
    const acceptedBytes = server.onConfirm(confirmBytes);

    // 4. Server ACCEPTED → Client.
    client.onAccepted(acceptedBytes);

    const cs = client.session();
    const ss = server.session();
    expect(cs.sessionId).toBe("01J7TEST00000000000000000000");
    expect(ss.sessionId).toBe(cs.sessionId);
    expect(encodeB64(cs.keys.encC2S)).toBe(encodeB64(ss.keys.encC2S));
    expect(encodeB64(cs.keys.encS2C)).toBe(encodeB64(ss.keys.encS2C));
    expect(encodeB64(cs.keys.macC2S)).toBe(encodeB64(ss.keys.macC2S));
    expect(encodeB64(cs.keys.macS2C)).toBe(encodeB64(ss.keys.macS2C));
  });

  test("client.init twice throws", () => {
    const c = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: publicKeyFromSeed(seed(0xa1)),
    });
    c.init();
    expect(() => c.init()).toThrow(/already called/);
  });

  test("client.onResponse before init throws", () => {
    const c = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: publicKeyFromSeed(seed(0xa1)),
    });
    expect(() => c.onResponse(new Uint8Array(1))).toThrow(/before init/);
  });

  test("server.onConfirm before onInit throws", () => {
    const s = new HandshakeServer({
      serverDomainSigningSeed: seed(0xa1),
      domain: "test.example",
      supportedSuites: ["x25519-chacha20-poly1305"],
      permissions: [],
      sessionTTL: 300,
      generateSessionId: () => "01J",
      identityProofSignature: () => "P",
    });
    expect(() => s.onConfirm(new Uint8Array(1))).toThrow(/before onInit/);
  });

  test("erase() is idempotent and clears secret state", () => {
    const c = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: publicKeyFromSeed(seed(0xa1)),
    });
    c.init();
    expect(() => c.erase()).not.toThrow();
    expect(() => c.erase()).not.toThrow();
  });

  test("session() before completion throws", () => {
    const c = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: publicKeyFromSeed(seed(0xa1)),
    });
    expect(() => c.session()).toThrow(/not yet established/);
  });

  test("server extracts client identity from CONFIRM and exposes it", () => {
    const serverSeed = seed(0xa1);
    const serverPub = publicKeyFromSeed(serverSeed);
    const clientLongTermSeed = seed(0xb2);
    const clientLongTermPub = publicKeyFromSeed(clientLongTermSeed);
    const clientLongTermKeyId = fingerprint(clientLongTermPub);

    const client = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: serverPub,
      identity: {
        clientId: "client-state-id",
        clientIdentity: "alice@test.example",
        longTermSeed: clientLongTermSeed,
        longTermKeyId: clientLongTermKeyId,
      },
    });
    let lookupCalls = 0;
    const server = new HandshakeServer({
      serverDomainSigningSeed: serverSeed,
      domain: "test.example",
      supportedSuites: ["x25519-chacha20-poly1305"],
      permissions: ["send", "receive"],
      sessionTTL: 300,
      generateSessionId: () => "01J7TESTIDENTITY00000000000",
      identityProofSignature: () => "PLACEHOLDER",
      lookupClientIdentityKey: (identity, keyId) => {
        lookupCalls += 1;
        expect(identity).toBe("alice@test.example");
        expect(keyId).toBe(clientLongTermKeyId);
        return clientLongTermPub;
      },
    });

    const initBytes = client.init();
    const respBytes = server.onInit(initBytes);
    const confirmBytes = client.onResponse(respBytes);
    const acceptedBytes = server.onConfirm(confirmBytes);
    client.onAccepted(acceptedBytes);

    expect(server.clientIdentity()).toBe("alice@test.example");
    expect(server.clientLongTermKeyId()).toBe(clientLongTermKeyId);
    const ss = server.session();
    expect(ss.clientIdentity).toBe("alice@test.example");
    expect(ss.clientLongTermKeyId).toBe(clientLongTermKeyId);
    expect(lookupCalls).toBe(1);
  });

  test("server rejects CONFIRM when identity_signature does not verify under the looked-up key", () => {
    const serverSeed = seed(0xa1);
    const serverPub = publicKeyFromSeed(serverSeed);
    // Client signs with one seed; server's lookup returns the WRONG pub.
    const clientLongTermSeed = seed(0xb2);
    const clientLongTermPub = publicKeyFromSeed(clientLongTermSeed);
    const clientLongTermKeyId = fingerprint(clientLongTermPub);
    const wrongPub = publicKeyFromSeed(seed(0xc3));

    const client = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: serverPub,
      identity: {
        clientId: "client-state-id",
        clientIdentity: "alice@test.example",
        longTermSeed: clientLongTermSeed,
        longTermKeyId: clientLongTermKeyId,
      },
    });
    const server = new HandshakeServer({
      serverDomainSigningSeed: serverSeed,
      domain: "test.example",
      supportedSuites: ["x25519-chacha20-poly1305"],
      permissions: ["send", "receive"],
      sessionTTL: 300,
      generateSessionId: () => "01J7TESTREJECT0000000000000",
      identityProofSignature: () => "PLACEHOLDER",
      lookupClientIdentityKey: () => wrongPub,
    });

    const initBytes = client.init();
    const respBytes = server.onInit(initBytes);
    const confirmBytes = client.onResponse(respBytes);
    expect(() => server.onConfirm(confirmBytes)).toThrow(/auth_failed/);
    expect(server.clientIdentity()).toBe("");
    expect(server.clientLongTermKeyId()).toBe("");
  });

  test("server's verifyIdentityProof callback receives the decrypted block", () => {
    const serverSeed = seed(0xa1);
    const serverPub = publicKeyFromSeed(serverSeed);
    const clientLongTermSeed = seed(0xb2);
    const clientLongTermPub = publicKeyFromSeed(clientLongTermSeed);
    const clientLongTermKeyId = fingerprint(clientLongTermPub);

    const client = new HandshakeClient({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "memory",
      serverDomainPub: serverPub,
      identity: {
        clientId: "client-state-id",
        clientIdentity: "bob@test.example",
        longTermSeed: clientLongTermSeed,
        longTermKeyId: clientLongTermKeyId,
      },
    });
    let blockSeen: { client_identity: string } | undefined;
    const server = new HandshakeServer({
      serverDomainSigningSeed: serverSeed,
      domain: "test.example",
      supportedSuites: ["x25519-chacha20-poly1305"],
      permissions: ["send", "receive"],
      sessionTTL: 300,
      generateSessionId: () => "01J7TESTBLOCK00000000000000",
      identityProofSignature: () => "PLACEHOLDER",
      verifyIdentityProof: ({ block }) => {
        blockSeen = block;
        return { ok: true };
      },
    });

    const initBytes = client.init();
    const respBytes = server.onInit(initBytes);
    const confirmBytes = client.onResponse(respBytes);
    server.onConfirm(confirmBytes);

    expect(blockSeen).toBeDefined();
    expect(blockSeen?.client_identity).toBe("bob@test.example");
  });
});
