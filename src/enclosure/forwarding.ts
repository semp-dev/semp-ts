/**
 * Forwarding compose per ENVELOPE.md §6.6.
 *
 * A forwarded enclosure carries three signatures, layered:
 *
 *   1. The ORIGINAL sender's `sender_signature` over their inner
 *      enclosure (subject, content_type, body, attachments,
 *      extensions). Prefix: `SEMP-ENCLOSURE-SENDER:`.
 *      Signed scope: the `original_enclosure_plaintext` subtree.
 *
 *   2. The FORWARDER's `forwarder_attestation` over the
 *      `forwarded_from` block - the inner sender_signature is
 *      already populated by step 1, so this signs over canonical
 *      bytes that include it. Prefix: `SEMP-FORWARDER-ATTESTATION:`.
 *      Signed scope: the entire `forwarded_from` subtree.
 *
 *   3. The FORWARDER acting as outer sender: `sender_signature`
 *      over the outer enclosure. Prefix: `SEMP-ENCLOSURE-SENDER:`.
 *      Signed scope: the entire outer enclosure object.
 *
 * The verify path (handlers-wave4.ts) walks these three steps in
 * reverse to verify.
 *
 * @module
 */

import { fingerprint, publicKeyFromSeed, signSignedDoc } from "../keys/index.js";

/** A keyref for a sender identity (`{algorithm, key_id, value}` style). */
interface IdentitySigBlock {
  algorithm: "ed25519";
  key_id: string;
  value: string;
}

/** Inner sender's enclosure plaintext (the original message body). */
export interface InnerEnclosurePlaintext {
  subject: string;
  content_type: string;
  body: Record<string, string>;
  attachments?: unknown[];
  extensions?: Record<string, unknown>;
  /** Set to null for an inner (un-forwarded) enclosure. */
  forwarded_from?: null;
}

/** Outer enclosure plaintext (forwarder's own added content). */
export interface OuterEnclosurePlaintext {
  subject: string;
  content_type: string;
  body: Record<string, string>;
  attachments?: unknown[];
  extensions?: Record<string, unknown>;
}

/** Reference to the original envelope's seal + postmark. */
export interface OriginalEnvelopeRef {
  /** seal.algorithm + seal.key_id of the original envelope. */
  original_seal: { algorithm: string; key_id: string };
  /** Pinned postmark fields from the original envelope. */
  original_postmark: {
    id: string;
    from_domain: string;
    to_domain: string;
    expires: string;
    session_id: string;
  };
  /** Original sender address (`alice@a.example`). */
  original_sender_address: string;
}

/** Inputs to {@link composeForwarded}. */
export interface ComposeForwardedInput {
  /** Inner sender's 32-byte Ed25519 secret seed. */
  innerSenderSeed: Uint8Array;
  /** Inner sender's identity key_id. */
  innerSenderKeyId: string;
  /** Inner enclosure plaintext (no sender_signature yet). */
  innerEnclosurePlaintext: InnerEnclosurePlaintext;

  /** Forwarder's 32-byte Ed25519 secret seed (used twice: for the
   * forwarder_attestation AND for the outer sender_signature). */
  forwarderSeed: Uint8Array;
  /** Forwarder's identity key_id. */
  forwarderKeyId: string;
  /** Outer enclosure plaintext (no sender_signature yet). */
  outerEnclosurePlaintext: OuterEnclosurePlaintext;

  /** Pinned reference to the original envelope. */
  originalEnvelope: OriginalEnvelopeRef;
  /** ISO 8601 timestamp when the forwarder received the original. */
  receivedAt: string;
}

/** Fully-signed outer enclosure, ready to wrap as an envelope payload. */
export interface SignedForwardedEnclosure {
  subject: string;
  content_type: string;
  body: Record<string, string>;
  attachments: unknown[];
  forwarded_from: {
    original_enclosure_plaintext: InnerEnclosurePlaintext & {
      sender_signature: IdentitySigBlock;
    };
    original_seal: OriginalEnvelopeRef["original_seal"];
    original_postmark: OriginalEnvelopeRef["original_postmark"];
    original_sender_address: string;
    received_at: string;
    forwarder_attestation: IdentitySigBlock;
  };
  extensions: Record<string, unknown>;
  sender_signature: IdentitySigBlock;
}

/**
 * Compose a 3-signature forwarded enclosure. Returns the
 * fully-signed object whose canonical bytes match the spec.
 *
 * Step 1: sign the inner enclosure with the original sender's
 *   identity key. The signed inner becomes
 *   `forwarded_from.original_enclosure_plaintext`.
 *
 * Step 2: assemble the `forwarded_from` block with the signed
 *   inner, original_seal/postmark/address, received_at, and a
 *   `forwarder_attestation` placeholder. Sign the block with the
 *   forwarder's identity key under the
 *   SEMP-FORWARDER-ATTESTATION: prefix.
 *
 * Step 3: assemble the outer enclosure with the signed
 *   forwarded_from block and a `sender_signature` placeholder.
 *   Sign with the forwarder's identity key under the
 *   SEMP-ENCLOSURE-SENDER: prefix.
 */
export function composeForwarded(input: ComposeForwardedInput): SignedForwardedEnclosure {
  // Step 1: sign the inner enclosure as the original sender.
  const innerPreSign = {
    subject: input.innerEnclosurePlaintext.subject,
    content_type: input.innerEnclosurePlaintext.content_type,
    body: input.innerEnclosurePlaintext.body,
    attachments: input.innerEnclosurePlaintext.attachments ?? [],
    forwarded_from: input.innerEnclosurePlaintext.forwarded_from ?? null,
    extensions: input.innerEnclosurePlaintext.extensions ?? {},
    sender_signature: {
      algorithm: "ed25519",
      key_id: input.innerSenderKeyId,
      value: "",
    },
  };
  const innerSigned = signSignedDoc({
    preSignJSON: innerPreSign,
    seed: input.innerSenderSeed,
    signaturePath: "sender_signature.value",
    prefix: "SEMP-ENCLOSURE-SENDER:",
  });
  // Cross-check: the inner key_id MUST match the forwarder-claimed
  // key. Fingerprint mismatches surface here, not at the verify
  // layer.
  const innerKeyIdActual = fingerprint(
    publicKeyFromSeed(input.innerSenderSeed),
  );
  if (innerKeyIdActual !== input.innerSenderKeyId) {
    throw new Error(
      `composeForwarded: innerSenderKeyId ${input.innerSenderKeyId} does not match seed-derived ${innerKeyIdActual}`,
    );
  }

  // Step 2: forwarder_attestation over forwarded_from.
  const forwardedFromPreSign = {
    original_enclosure_plaintext: innerSigned.signedJSON,
    original_seal: input.originalEnvelope.original_seal,
    original_postmark: input.originalEnvelope.original_postmark,
    original_sender_address: input.originalEnvelope.original_sender_address,
    received_at: input.receivedAt,
    forwarder_attestation: {
      algorithm: "ed25519",
      key_id: input.forwarderKeyId,
      value: "",
    },
  };
  const fromSigned = signSignedDoc({
    preSignJSON: forwardedFromPreSign,
    seed: input.forwarderSeed,
    signaturePath: "forwarder_attestation.value",
    prefix: "SEMP-FORWARDER-ATTESTATION:",
  });

  const forwarderKeyIdActual = fingerprint(
    publicKeyFromSeed(input.forwarderSeed),
  );
  if (forwarderKeyIdActual !== input.forwarderKeyId) {
    throw new Error(
      `composeForwarded: forwarderKeyId ${input.forwarderKeyId} does not match seed-derived ${forwarderKeyIdActual}`,
    );
  }

  // Step 3: outer sender_signature.
  const outerPreSign = {
    subject: input.outerEnclosurePlaintext.subject,
    content_type: input.outerEnclosurePlaintext.content_type,
    body: input.outerEnclosurePlaintext.body,
    attachments: input.outerEnclosurePlaintext.attachments ?? [],
    forwarded_from: fromSigned.signedJSON,
    extensions: input.outerEnclosurePlaintext.extensions ?? {},
    sender_signature: {
      algorithm: "ed25519",
      key_id: input.forwarderKeyId,
      value: "",
    },
  };
  const outerSigned = signSignedDoc({
    preSignJSON: outerPreSign,
    seed: input.forwarderSeed,
    signaturePath: "sender_signature.value",
    prefix: "SEMP-ENCLOSURE-SENDER:",
  });
  return outerSigned.signedJSON as unknown as SignedForwardedEnclosure;
}
