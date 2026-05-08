/**
 * Delivery receipt unit tests. Cover compose+verify roundtrip,
 * envelope-binding cross-check, structural validation, and the
 * tampered-signature / tampered-body negative paths.
 *
 * Vector-level byte-for-byte parity is exercised separately by the
 * vectors-runner; this file is the production-API surface check.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { canonicalEnvelopeFor } from "../envelope/index.js";
import { fingerprint, publicKeyFromSeed } from "../keys/index.js";

import {
  DeliveryReceiptPrefix,
  DeliveryReceiptType,
  DeliveryReceiptVersion,
  EnvelopeHashAlgorithmSHA256,
  ReceiptSignatureAlgorithmEd25519,
  computeEnvelopeHash,
  signDeliveryReceipt,
  validateReceipt,
  verifyDeliveryReceipt,
  verifyEnvelopeBinding,
} from "./receipt.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function fakeEnvelope(): Record<string, unknown> {
  return {
    type: "SEMP_ENVELOPE",
    version: "1.0.0",
    postmark: {
      id: "01J7TESTRECEIPTPOSTMARKXXXXXX",
      session_id: "01J7TESTRECEIPTSESSIONXXXXXXX",
      from_domain: "alice.example",
      to_domain: "bob.example",
      expires: "2026-04-22T00:00:00Z",
      extensions: {},
    },
    seal: {
      algorithm: "x25519-chacha20-poly1305",
      key_id: "alice-domain-fp",
      signature: "EXAMPLE_SIGNATURE",
      session_mac: "EXAMPLE_SESSION_MAC",
      brief_recipients: { "bob-fp": "WRAPPED_K_BRIEF" },
      enclosure_recipients: { "bob-fp": "WRAPPED_K_ENCLOSURE" },
      extensions: {},
    },
    brief: "BRIEF_CIPHERTEXT_PLACEHOLDER",
    enclosure: "ENCLOSURE_CIPHERTEXT_PLACEHOLDER",
  };
}

describe("delivery.receipt", () => {
  test("sign + verify round-trip", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const keyId = fingerprint(pub);
    const env = fakeEnvelope();
    const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));

    const { receipt, signatureB64 } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: keyId,
      domainSigningSeed: seed,
    });

    expect(receipt.type).toBe(DeliveryReceiptType);
    expect(receipt.version).toBe(DeliveryReceiptVersion);
    expect(receipt.envelope_hash.algorithm).toBe(EnvelopeHashAlgorithmSHA256);
    expect(receipt.envelope_hash.value).toBe(envHash);
    expect(receipt.recipient_domain).toBe("bob.example");
    expect(receipt.signature.algorithm).toBe(ReceiptSignatureAlgorithmEd25519);
    expect(receipt.signature.key_id).toBe(keyId);
    expect(receipt.signature.value).toBe(signatureB64);
    expect(signatureB64).not.toBe("");

    const ok = verifyDeliveryReceipt({ receipt, domainPub: pub });
    expect(ok).toBe(true);
  });

  test("verify under wrong public key fails", () => {
    const seed = deterministicSeed(0xc1);
    const env = fakeEnvelope();
    const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));
    const { receipt } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: fingerprint(publicKeyFromSeed(seed)),
      domainSigningSeed: seed,
    });

    const wrongPub = publicKeyFromSeed(deterministicSeed(0xff));
    const ok = verifyDeliveryReceipt({ receipt, domainPub: wrongPub });
    expect(ok).toBe(false);
  });

  test("tampered receipt body fails to verify", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const env = fakeEnvelope();
    const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));
    const { receipt } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: fingerprint(pub),
      domainSigningSeed: seed,
    });

    // Mutate the recipient_domain field after signing.
    const tampered = { ...receipt, recipient_domain: "evil.example" };
    const ok = verifyDeliveryReceipt({ receipt: tampered, domainPub: pub });
    expect(ok).toBe(false);
  });

  test("envelope-binding cross-check holds for the original envelope and breaks for a tampered one", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const env = fakeEnvelope();
    const canonicalOriginal = canonicalEnvelopeFor(env);
    const envHash = computeEnvelopeHash(canonicalOriginal);

    const { receipt } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: fingerprint(pub),
      domainSigningSeed: seed,
    });

    expect(verifyEnvelopeBinding(receipt, canonicalOriginal)).toBe(true);

    // The receipt's signature is unaffected by envelope mutation —
    // tampering the envelope only breaks the envelope-binding check.
    const tamperedEnv = fakeEnvelope();
    const tamperedPostmark = tamperedEnv.postmark as Record<string, unknown>;
    tamperedPostmark.id = "01J7TAMPEREDPOSTMARKXXXXXXXXXX";
    const canonicalTampered = canonicalEnvelopeFor(tamperedEnv);
    expect(verifyEnvelopeBinding(receipt, canonicalTampered)).toBe(false);

    // Receipt itself still verifies — separation of concerns per
    // §1.1.1.7 step 3 vs step 4.
    expect(verifyDeliveryReceipt({ receipt, domainPub: pub })).toBe(true);
  });

  test("envelope-binding rejects unsupported hash algorithm", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const env = fakeEnvelope();
    const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));
    const { receipt } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: fingerprint(pub),
      domainSigningSeed: seed,
    });

    const wrongAlg = { ...receipt, envelope_hash: { algorithm: "sha-512", value: envHash } };
    expect(verifyEnvelopeBinding(wrongAlg, canonicalEnvelopeFor(env))).toBe(false);
  });

  test("validateReceipt rejects malformed inputs", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const env = fakeEnvelope();
    const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));
    const { receipt } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: fingerprint(pub),
      domainSigningSeed: seed,
    });

    // Sanity: well-formed receipt validates.
    validateReceipt(receipt);

    expect(() => validateReceipt({ ...receipt, type: "WRONG" as never })).toThrow(/type/);
    expect(() => validateReceipt({ ...receipt, version: "" })).toThrow(/version/);
    expect(() =>
      validateReceipt({ ...receipt, envelope_hash: { algorithm: "", value: envHash } }),
    ).toThrow(/envelope_hash.algorithm/);
    expect(() =>
      validateReceipt({ ...receipt, envelope_hash: { algorithm: "sha-256", value: "" } }),
    ).toThrow(/envelope_hash.value/);
    expect(() => validateReceipt({ ...receipt, recipient_domain: "" })).toThrow(/recipient_domain/);
    expect(() => validateReceipt({ ...receipt, accepted_at: "" })).toThrow(/accepted_at/);
  });

  test("signDeliveryReceipt rejects empty inputs", () => {
    const seed = deterministicSeed(0xc1);
    const keyId = fingerprint(publicKeyFromSeed(seed));
    const baseInput = {
      envelopeHashB64: "AAAA",
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: keyId,
      domainSigningSeed: seed,
    };
    expect(() =>
      signDeliveryReceipt({ ...baseInput, envelopeHashB64: "" }),
    ).toThrow(/envelope_hash.value/);
    expect(() =>
      signDeliveryReceipt({ ...baseInput, recipientDomain: "" }),
    ).toThrow(/recipient_domain/);
    expect(() =>
      signDeliveryReceipt({ ...baseInput, acceptedAt: "" }),
    ).toThrow(/accepted_at/);
    expect(() =>
      signDeliveryReceipt({ ...baseInput, domainKeyId: "" }),
    ).toThrow(/key_id/);
  });

  test("unsigned receipt does not verify", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const env = fakeEnvelope();
    const envHash = computeEnvelopeHash(canonicalEnvelopeFor(env));
    const { receipt } = signDeliveryReceipt({
      envelopeHashB64: envHash,
      recipientDomain: "bob.example",
      acceptedAt: "2026-04-21T10:15:32Z",
      domainKeyId: fingerprint(pub),
      domainSigningSeed: seed,
    });
    const blanked = { ...receipt, signature: { ...receipt.signature, value: "" } };
    expect(verifyDeliveryReceipt({ receipt: blanked, domainPub: pub })).toBe(false);
  });

  test("DeliveryReceiptPrefix matches spec table", () => {
    expect(DeliveryReceiptPrefix).toBe("SEMP-DELIVERY-RECEIPT:");
  });
});
