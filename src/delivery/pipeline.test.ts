/**
 * End-to-end pipeline tests: compose an envelope, run through the
 * receive-side pipeline, assert step-by-step behavior.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type RecipientCandidate,
  compose,
} from "../envelope/index.js";
import {
  fingerprint,
  publicKeyFromSeed,
  sign as ed25519Sign,
} from "../keys/index.js";
import { x25519PublicKey } from "../crypto/index.js";

import { Inbox } from "./inbox.js";
import { Pipeline } from "./pipeline.js";
import { StaticBlockListLookup } from "./blocklist.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function randomBytes(n: number, base = 0): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = (base + i) & 0xff;
  }
  return out;
}

interface Fixture {
  /** Sender domain signing keys. */
  senderSigningSeed: Uint8Array;
  senderSigningPub: Uint8Array;
  senderSigningFp: string;
  /** Recipient (home server) domain encryption keys. */
  domainEncPriv: Uint8Array;
  domainEncPub: Uint8Array;
  domainEncFp: string;
  /** Recipient client encryption keys. */
  clientEncPriv: Uint8Array;
  clientEncPub: Uint8Array;
  clientEncFp: string;
  envMac: Uint8Array;
  envelope: ReturnType<typeof compose>;
}

function buildFixture(opts: {
  briefTo?: string[];
  fromDomain?: string;
  toDomain?: string;
  expires?: string;
  briefFrom?: string;
} = {}): Fixture {
  const senderSigningSeed = seed(0xa1);
  const senderSigningPub = publicKeyFromSeed(senderSigningSeed);
  const senderSigningFp = fingerprint(senderSigningPub);

  const domainEncPriv = seed(0xb2);
  const domainEncPub = x25519PublicKey(domainEncPriv);
  const domainEncFp = fingerprint(domainEncPub);

  const clientEncPriv = seed(0xc3);
  const clientEncPub = x25519PublicKey(clientEncPriv);
  const clientEncFp = fingerprint(clientEncPub);

  const wrapRandomness = new Map<
    string,
    { ephemeralX25519Priv: Uint8Array }
  >();
  wrapRandomness.set(domainEncFp, { ephemeralX25519Priv: seed(0xd1) });
  wrapRandomness.set(clientEncFp, { ephemeralX25519Priv: seed(0xd2) });
  wrapRandomness.set(`enclosure:${clientEncFp}`, {
    ephemeralX25519Priv: seed(0xd3),
  });

  const envMac = seed(0xee);

  const envelope = compose({
    suite: "x25519-chacha20-poly1305",
    sealKeyId: senderSigningFp,
    senderDomainSigningSeed: senderSigningSeed,
    postmark: {
      id: "01J7TESTENVELOPE000000000000",
      session_id: "01J7TESTSESSION0000000000000",
      from_domain: opts.fromDomain ?? "alice.example",
      to_domain: opts.toDomain ?? "bob.example",
      expires: opts.expires ?? "2099-01-01T00:00:00Z",
      extensions: {},
    },
    briefPlaintext: {
      from: opts.briefFrom ?? "alice@alice.example",
      to: opts.briefTo ?? ["bob@bob.example"],
    },
    enclosurePlaintext: { body: "hi" },
    briefRecipients: [
      { keyId: domainEncFp, publicKey: domainEncPub },
      { keyId: clientEncFp, publicKey: clientEncPub },
    ],
    enclosureRecipients: [
      { keyId: clientEncFp, publicKey: clientEncPub },
    ],
    kBrief: seed(0xb1),
    kEnclosure: seed(0xb2),
    kEnvMAC: envMac,
    briefAEADNonce: randomBytes(12, 0),
    enclosureAEADNonce: randomBytes(12, 12),
    wrapRandomness,
  });
  return {
    senderSigningSeed,
    senderSigningPub,
    senderSigningFp,
    domainEncPriv,
    domainEncPub,
    domainEncFp,
    clientEncPriv,
    clientEncPub,
    clientEncFp,
    envMac,
    envelope,
  };
}

function briefRecipientsFor(f: Fixture): RecipientCandidate[] {
  return [
    {
      keyId: f.domainEncFp,
      privateKey: f.domainEncPriv,
      publicKey: f.domainEncPub,
    },
  ];
}

describe("Pipeline", () => {
  test("delivered: envelope flows through every step to the inbox", async () => {
    const f = buildFixture();
    const inbox = new Inbox();
    const pipeline = new Pipeline({
      domainKeys: async (d) =>
        d === "alice.example" ? f.senderSigningPub : null,
      envMAC: () => f.envMac,
      isLocal: (a) => a === "bob@bob.example",
      inbox,
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
    });

    const r = await pipeline.process(f.envelope);
    expect(r.rejection).toBeUndefined();
    expect(r.results).toHaveLength(1);
    expect(r.results[0]!.status).toBe("delivered");
    expect(inbox.pending("bob@bob.example")).toBe(1);
  });

  test("step 1 reject: no domain key on file", async () => {
    const f = buildFixture();
    const pipeline = new Pipeline({
      domainKeys: async () => null,
      envMAC: () => f.envMac,
      isLocal: () => true,
      briefRecipients: briefRecipientsFor(f),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.rejection?.reasonCode).toBe("seal_invalid");
  });

  test("step 1 reject: tampered signature does not verify", async () => {
    const f = buildFixture();
    const wrongPub = publicKeyFromSeed(seed(0x99));
    const pipeline = new Pipeline({
      domainKeys: async () => wrongPub,
      envMAC: () => f.envMac,
      isLocal: () => true,
      briefRecipients: briefRecipientsFor(f),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.rejection?.reasonCode).toBe("seal_invalid");
  });

  test("step 2 reject: expired envelope outside clock-skew tolerance", async () => {
    const f = buildFixture({ expires: "2026-05-01T00:00:00Z" });
    const pipeline = new Pipeline({
      domainKeys: async () => f.senderSigningPub,
      envMAC: () => f.envMac,
      isLocal: () => true,
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.rejection?.reasonCode).toBe("envelope_expired");
  });

  test("step 4 reject: bad K_env_mac", async () => {
    const f = buildFixture();
    const pipeline = new Pipeline({
      domainKeys: async () => f.senderSigningPub,
      envMAC: () => seed(0x42),
      isLocal: () => true,
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.rejection?.reasonCode).toBe("session_mac_invalid");
  });

  test("step 5 reject: domain policy says no", async () => {
    const f = buildFixture();
    const pipeline = new Pipeline({
      domainKeys: async () => f.senderSigningPub,
      envMAC: () => f.envMac,
      isLocal: () => true,
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
      domainPolicy: () => ({
        ack: "rejected",
        reasonCode: "policy_forbidden",
        reason: "denylisted",
      }),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.rejection?.reasonCode).toBe("policy_forbidden");
  });

  test("per-recipient: non-local recipient → recipient_not_found", async () => {
    const f = buildFixture({ briefTo: ["dave@remote.example"] });
    const pipeline = new Pipeline({
      domainKeys: async () => f.senderSigningPub,
      envMAC: () => f.envMac,
      isLocal: (a) => a === "bob@bob.example",
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.rejection).toBeUndefined();
    expect(r.results[0]!.status).toBe("rejected");
    expect(r.results[0]!.reason_code).toBe("recipient_not_found");
  });

  test("per-recipient: blocked sender → blocked", async () => {
    const f = buildFixture({
      briefTo: ["bob@bob.example"],
      briefFrom: "spammer@bad.example",
    });
    const lookup = new StaticBlockListLookup({
      "bob@bob.example": {
        user_id: "bob@bob.example",
        list_version: 1,
        entries: [
          {
            id: "block-1",
            entity: { type: "user", address: "spammer@bad.example" },
            acknowledgment: "rejected",
            scope: "all",
            created_at: "2026-05-01T00:00:00Z",
            created_by_device_id: "01JDEV01",
          },
        ],
      },
    });
    const pipeline = new Pipeline({
      domainKeys: async () => f.senderSigningPub,
      envMAC: () => f.envMac,
      isLocal: () => true,
      blockList: lookup,
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.results[0]!.status).toBe("rejected");
    expect(r.results[0]!.reason_code).toBe("blocked_recipient");
  });

  test("recipientPolicy gate short-circuits before block-list", async () => {
    const f = buildFixture();
    const pipeline = new Pipeline({
      domainKeys: async () => f.senderSigningPub,
      envMAC: () => f.envMac,
      isLocal: () => true,
      briefRecipients: briefRecipientsFor(f),
      now: () => new Date("2026-05-08T10:00:00Z"),
      recipientPolicy: () => ({
        ack: "rejected",
        reasonCode: "policy_forbidden",
        reason: "account closed",
      }),
    });
    const r = await pipeline.process(f.envelope);
    expect(r.results[0]!.status).toBe("rejected");
    expect(r.results[0]!.reason_code).toBe("policy_forbidden");
  });

  // Suppress unused warning — we use ed25519Sign indirectly via the
  // envelope.compose path, but a TS-side import is still needed to
  // keep the dependency graph clear.
  void ed25519Sign;
});
