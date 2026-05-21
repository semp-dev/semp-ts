/**
 * Tests for the federation (server↔server) handshake state machine.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  FederationInitiator,
  FederationResponder,
  TrustingDomainVerifier,
  resolveCollision,
} from "./federation.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function encodeB64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

describe("FederationInitiator + FederationResponder", () => {
  test("baseline federation handshake: both peers derive identical keys", async () => {
    // Peer A: initiator.
    const aSeed = seed(0xa1);
    const aPub = publicKeyFromSeed(aSeed);
    void fingerprint(aPub);

    // Peer B: responder.
    const bSeed = seed(0xb2);
    const bPub = publicKeyFromSeed(bSeed);
    void fingerprint(bPub);

    const lookup = (domain: string): Uint8Array => {
      if (domain === "alice.example") return aPub;
      if (domain === "bob.example") return bPub;
      throw new Error(`unknown domain ${domain}`);
    };

    const initiator = new FederationInitiator({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: "alice.example",
      localServerID: "01J7ALICE000000000000000000",
      localDomainSeed: aSeed,
      peerDomainPubLookup: lookup,
      peerDomain: "bob.example",
      domainProof: { method: "test-trust", data: "alice-attest" },
    });
    const responder = new FederationResponder({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: "bob.example",
      localServerID: "01J7BOB00000000000000000000",
      localDomainSeed: bSeed,
      peerDomainPubLookup: lookup,
      verifier: new TrustingDomainVerifier(),
      policy: {
        message_retention: "30d",
        user_discovery: "allowed",
        relay_allowed: false,
      },
      sessionTTL: 3600,
      generateSessionId: () => "01J7TESTFEDSESSION0000000000",
    });

    // Drive the four messages.
    const initBytes = initiator.init();
    const respBytes = await responder.onInit(initBytes);
    const confirmBytes = initiator.onResponse(respBytes);
    const acceptedBytes = responder.onConfirm(confirmBytes);
    initiator.onAccepted(acceptedBytes);

    const ai = initiator.session();
    const br = responder.session();
    expect(ai.sessionId).toBe("01J7TESTFEDSESSION0000000000");
    expect(br.sessionId).toBe(ai.sessionId);
    expect(ai.peerDomain).toBe("bob.example");
    expect(br.peerDomain).toBe("alice.example");
    expect(encodeB64(ai.keys.encC2S)).toBe(encodeB64(br.keys.encC2S));
    expect(encodeB64(ai.keys.encS2C)).toBe(encodeB64(br.keys.encS2C));
    expect(encodeB64(ai.keys.macC2S)).toBe(encodeB64(br.keys.macC2S));
    expect(encodeB64(ai.keys.macS2C)).toBe(encodeB64(br.keys.macS2C));
  });

  test("PQ federation handshake: hybrid KEM derives identical session keys", async () => {
    // Same shape as the baseline test, but with suite =
    // pq-kyber768-x25519 on both sides. The initiator publishes a
    // 1216-byte hybrid ephemeral pub; the responder hybrid-
    // encapsulates against it and ships a 1120-byte KEM ciphertext;
    // both sides derive the same session keys from the combined
    // (kyberSS || x25519SS) shared secret per ENVELOPE.md §4.4.1.
    const aSeed = seed(0xa2);
    const aPub = publicKeyFromSeed(aSeed);
    const bSeed = seed(0xb3);
    const bPub = publicKeyFromSeed(bSeed);
    const lookup = (domain: string): Uint8Array => {
      if (domain === "alice.pq") return aPub;
      if (domain === "bob.pq") return bPub;
      throw new Error(`unknown domain ${domain}`);
    };

    const initiator = new FederationInitiator({
      suite: "pq-kyber768-x25519",
      capabilities: {
        encryption_algorithms: ["pq-kyber768-x25519"],
        extensions: [],
      },
      localDomain: "alice.pq",
      localServerID: "01J7ALICEPQ00000000000000000",
      localDomainSeed: aSeed,
      peerDomainPubLookup: lookup,
      peerDomain: "bob.pq",
      domainProof: { method: "test-trust", data: "alice-attest" },
    });
    const responder = new FederationResponder({
      suite: "pq-kyber768-x25519",
      capabilities: {
        encryption_algorithms: ["pq-kyber768-x25519"],
        extensions: [],
      },
      localDomain: "bob.pq",
      localServerID: "01J7BOBPQ0000000000000000000",
      localDomainSeed: bSeed,
      peerDomainPubLookup: lookup,
      verifier: new TrustingDomainVerifier(),
      policy: {
        message_retention: "30d",
        user_discovery: "allowed",
        relay_allowed: false,
      },
      sessionTTL: 3600,
      generateSessionId: () => "01J7TESTPQFEDSESSION00000000",
    });

    const initBytes = initiator.init();
    const respBytes = await responder.onInit(initBytes);
    const confirmBytes = initiator.onResponse(respBytes);
    const acceptedBytes = responder.onConfirm(confirmBytes);
    initiator.onAccepted(acceptedBytes);

    const ai = initiator.session();
    const br = responder.session();
    expect(ai.sessionId).toBe("01J7TESTPQFEDSESSION00000000");
    expect(br.sessionId).toBe(ai.sessionId);
    expect(ai.peerDomain).toBe("bob.pq");
    expect(br.peerDomain).toBe("alice.pq");
    expect(encodeB64(ai.keys.encC2S)).toBe(encodeB64(br.keys.encC2S));
    expect(encodeB64(ai.keys.encS2C)).toBe(encodeB64(br.keys.encS2C));
    expect(encodeB64(ai.keys.macC2S)).toBe(encodeB64(br.keys.macC2S));
    expect(encodeB64(ai.keys.macS2C)).toBe(encodeB64(br.keys.macS2C));
  });

  test("policy rejection by initiator surfaces to caller", async () => {
    const aSeed = seed(0xc3);
    const bSeed = seed(0xd4);
    const aPub = publicKeyFromSeed(aSeed);
    const bPub = publicKeyFromSeed(bSeed);
    const lookup = (d: string): Uint8Array =>
      d === "a.example" ? aPub : bPub;

    const initiator = new FederationInitiator({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: "a.example",
      localServerID: "01J",
      localDomainSeed: aSeed,
      peerDomainPubLookup: lookup,
      peerDomain: "b.example",
      domainProof: { method: "test-trust", data: "x" },
      policyAcceptor: () => "retention too short",
    });
    const responder = new FederationResponder({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: "b.example",
      localServerID: "02J",
      localDomainSeed: bSeed,
      peerDomainPubLookup: lookup,
      policy: {
        message_retention: "1d",
        user_discovery: "allowed",
        relay_allowed: false,
      },
      generateSessionId: () => "01J7FED0000000000000000000",
    });
    const initBytes = initiator.init();
    const respBytes = await responder.onInit(initBytes);
    const confirmBytes = initiator.onResponse(respBytes);
    expect(() => responder.onConfirm(confirmBytes)).toThrow(
      /rejected our policy/,
    );
  });

  test("rejects unknown peer domain", async () => {
    const aSeed = seed(0xe5);
    const bSeed = seed(0xf6);
    const aPub = publicKeyFromSeed(aSeed);
    const bPub = publicKeyFromSeed(bSeed);
    const initiator = new FederationInitiator({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: "a.example",
      localServerID: "01J",
      localDomainSeed: aSeed,
      peerDomainPubLookup: (d) =>
        d === "a.example" ? aPub : d === "b.example" ? bPub : (() => { throw new Error("unknown"); })(),
      peerDomain: "b.example",
      domainProof: { method: "test-trust", data: "x" },
    });
    const responder = new FederationResponder({
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      localDomain: "wrong.example", // <-- mismatch
      localServerID: "02J",
      localDomainSeed: bSeed,
      peerDomainPubLookup: (d) =>
        d === "a.example" ? aPub : d === "b.example" ? bPub : (() => { throw new Error("unknown"); })(),
      policy: {
        message_retention: "30d",
        user_discovery: "allowed",
        relay_allowed: false,
      },
      generateSessionId: () => "01J",
    });
    const initBytes = initiator.init();
    const respBytes = await responder.onInit(initBytes);
    expect(() => initiator.onResponse(respBytes)).toThrow(
      /server_domain.*configured peer/,
    );
  });

  test("resolveCollision picks the lexicographically larger id", () => {
    expect(resolveCollision("01JBBB", "01JAAA")).toBe("01JBBB");
    expect(resolveCollision("01JAAA", "01JBBB")).toBe("01JBBB");
  });
});
