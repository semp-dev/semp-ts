/**
 * Tests for the federation {@link Forwarder}.
 *
 * Exercises a real federation handshake roundtrip via the in-memory
 * transport pair: forwarder dials a "peer" stub on one end while a
 * {@link FederationResponder} runs on the other end and produces a
 * canned submission response.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type Envelope,
  compose,
} from "../envelope/index.js";
import {
  fingerprint,
  publicKeyFromSeed,
} from "../keys/index.js";
import { x25519PublicKey } from "../crypto/index.js";
import {
  FederationResponder,
  TrustingDomainVerifier,
} from "../handshake/index.js";
import { newMemoryPair, type Transport } from "../transport/index.js";

import {
  Forwarder,
  PeerRegistry,
} from "./forwarder.js";
import {
  type SubmissionResponse,
  newSubmissionResponse,
} from "./submission.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

interface Fix {
  initiatorSeed: Uint8Array;
  initiatorPub: Uint8Array;
  responderSeed: Uint8Array;
  responderPub: Uint8Array;
  envelope: Envelope;
}

function buildFix(): Fix {
  const initSeed = seed(0xa1);
  const initPub = publicKeyFromSeed(initSeed);
  const respSeed = seed(0xb2);
  const respPub = publicKeyFromSeed(respSeed);

  // Build a minimal envelope (the forwarder doesn't actually decrypt
  // anything; it just re-MACs and ships).
  const senderSigningSeed = seed(0xc3);
  const senderSigningPub = publicKeyFromSeed(senderSigningSeed);
  const senderSigningFp = fingerprint(senderSigningPub);
  const recipientPriv = seed(0xd4);
  const recipientPub = x25519PublicKey(recipientPriv);
  const recipientFp = fingerprint(recipientPub);
  const wrap = new Map<string, { ephemeralX25519Priv: Uint8Array }>();
  wrap.set(recipientFp, { ephemeralX25519Priv: seed(0xe5) });
  wrap.set(`enclosure:${recipientFp}`, { ephemeralX25519Priv: seed(0xe6) });
  const env = compose({
    suite: "x25519-chacha20-poly1305",
    sealKeyId: senderSigningFp,
    senderDomainSigningSeed: senderSigningSeed,
    postmark: {
      id: "01J7TESTENVELOPE000000000000",
      session_id: "01J7ORIGSESSION00000000000000",
      from_domain: "alice.example",
      to_domain: "bob.example",
      expires: "2099-01-01T00:00:00Z",
      extensions: {},
    },
    briefPlaintext: { from: "alice@alice.example", to: ["bob@bob.example"] },
    enclosurePlaintext: { body: "hi" },
    briefRecipients: [{ keyId: recipientFp, publicKey: recipientPub }],
    enclosureRecipients: [{ keyId: recipientFp, publicKey: recipientPub }],
    kBrief: seed(0xf1),
    kEnclosure: seed(0xf2),
    kEnvMAC: seed(0xfa),
    briefAEADNonce: new Uint8Array(12).fill(1),
    enclosureAEADNonce: new Uint8Array(12).fill(2),
    wrapRandomness: wrap,
  });
  return {
    initiatorSeed: initSeed,
    initiatorPub: initPub,
    responderSeed: respSeed,
    responderPub: respPub,
    envelope: env,
  };
}

/**
 * Run a federation responder on `transport` and write a canned
 * submission response after the handshake completes.
 */
async function runFakeResponder(
  transport: Transport,
  responderSeed: Uint8Array,
  initiatorPub: Uint8Array,
  cannedResponse: SubmissionResponse,
): Promise<void> {
  const responder = new FederationResponder({
    suite: "x25519-chacha20-poly1305",
    capabilities: {
      encryption_algorithms: ["x25519-chacha20-poly1305"],
      extensions: [],
    },
    localDomain: "bob.example",
    localServerID: "01J7BOB00000000000000000000",
    localDomainSeed: responderSeed,
    peerDomainPubLookup: (d) => {
      if (d === "alice.example") return initiatorPub;
      throw new Error(`responder: unknown peer ${d}`);
    },
    verifier: new TrustingDomainVerifier(),
    policy: {
      message_retention: "30d",
      user_discovery: "allowed",
      relay_allowed: false,
    },
    sessionTTL: 3600,
    generateSessionId: () => "01J7FEDSESSION00000000000000",
  });
  const initBytes = await transport.receive();
  if (initBytes === null) throw new Error("init not received");
  const respBytes = await responder.onInit(initBytes);
  await transport.send(respBytes);
  const confirmBytes = await transport.receive();
  if (confirmBytes === null) throw new Error("confirm not received");
  const acceptedBytes = responder.onConfirm(confirmBytes);
  await transport.send(acceptedBytes);

  // Now consume the forwarded envelope and reply with the canned
  // response.
  const envBytes = await transport.receive();
  if (envBytes === null) throw new Error("forwarded envelope not received");
  const json = JSON.stringify(cannedResponse);
  await transport.send(new TextEncoder().encode(json));
}

describe("Forwarder", () => {
  test("forward round-trips through a federation handshake", async () => {
    const f = buildFix();
    const peers = new PeerRegistry();
    peers.put({
      domain: "bob.example",
      endpoint: "memory://bob",
      domainSigningPub: f.responderPub,
    });
    const [initSide, respSide] = newMemoryPair();
    const cannedResponse = newSubmissionResponse(
      "01J7TESTENVELOPE000000000000",
      [
        {
          recipient: "bob@bob.example",
          status: "delivered",
        },
      ],
      () => new Date("2026-05-08T10:00:00Z"),
    );
    // Start the fake responder.
    const responderTask = runFakeResponder(
      respSide,
      f.responderSeed,
      f.initiatorPub,
      cannedResponse,
    );

    const forwarder = new Forwarder({
      localDomain: "alice.example",
      localServerID: "01J7ALICE000000000000000000",
      localDomainSeed: f.initiatorSeed,
      peers,
      dial: async () => initSide,
    });

    const resp = await forwarder.forward("bob.example", f.envelope);
    expect(resp.envelope_id).toBe("01J7TESTENVELOPE000000000000");
    expect(resp.results[0]!.status).toBe("delivered");

    await responderTask;
    await forwarder.close();
  });

  test("rejects unknown peer", async () => {
    const f = buildFix();
    const peers = new PeerRegistry();
    const forwarder = new Forwarder({
      localDomain: "alice.example",
      localServerID: "01J7ALICE000000000000000000",
      localDomainSeed: f.initiatorSeed,
      peers,
      dial: async () => {
        throw new Error("dial not used");
      },
    });
    await expect(
      forwarder.forward("nobody.example", f.envelope),
    ).rejects.toThrow(/unknown peer/);
  });

  test("close drops cached sessions", async () => {
    const f = buildFix();
    const peers = new PeerRegistry();
    peers.put({
      domain: "bob.example",
      endpoint: "memory://bob",
      domainSigningPub: f.responderPub,
    });
    const [initSide, respSide] = newMemoryPair();
    const cannedResponse = newSubmissionResponse(
      "01J7TESTENVELOPE000000000000",
      [{ recipient: "bob@bob.example", status: "delivered" }],
    );
    const responderTask = runFakeResponder(
      respSide,
      f.responderSeed,
      f.initiatorPub,
      cannedResponse,
    );
    const forwarder = new Forwarder({
      localDomain: "alice.example",
      localServerID: "01J7ALICE000000000000000000",
      localDomainSeed: f.initiatorSeed,
      peers,
      dial: async () => initSide,
    });
    await forwarder.forward("bob.example", f.envelope);
    expect(forwarder.cachedPeers()).toEqual(["bob.example"]);
    await forwarder.close();
    expect(forwarder.cachedPeers()).toEqual([]);
    await responderTask;
  });
});
