/**
 * Signed delivery receipts per DELIVERY.md §1.1.1.
 *
 * Every `delivered` acknowledgment a recipient server returns to a
 * sending server MUST carry a signed receipt. The receipt binds
 * `(envelope_hash, recipient_domain, accepted_at)` under the recipient
 * domain's Ed25519 signing key with the `SEMP-DELIVERY-RECEIPT:`
 * domain-separation prefix. It is a portable, non-repudiable artifact
 * the sending user can later export to a `.semp-receipt` file.
 *
 * This module provides:
 *
 *  - {@link computeEnvelopeHash}: SHA-256 over canonical envelope bytes
 *    (the same canonical form `seal.signature` is computed over -
 *    `signature` and `session_mac` blanked).
 *  - {@link signDeliveryReceipt}: build + sign a receipt from
 *    pre-sign inputs.
 *  - {@link verifyDeliveryReceipt}: Ed25519-verify a receipt against
 *    a recipient domain public key.
 *  - {@link verifyEnvelopeBinding}: cross-check the receipt's
 *    `envelope_hash.value` against a fresh canonical envelope hash.
 *  - {@link validateReceipt}: structural checks per §1.1.1.2.
 *
 * The companion {@link "./receipt_store"} module holds receipts the
 * sending server has issued to its sending users until at least one
 * client device acknowledges the delivery event carrying it.
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

import {
  signSignedDoc,
  verifySignedDoc,
} from "../keys/index.js";

/** Domain-separation prefix for the receipt signature, per ENVELOPE.md §4.3. */
export const DeliveryReceiptPrefix = "SEMP-DELIVERY-RECEIPT:";

/** `type` discriminator for the receipt JSON. */
export const DeliveryReceiptType = "SEMP_DELIVERY_RECEIPT";

/** Receipt schema version per §1.1.1.1. */
export const DeliveryReceiptVersion = "1.0.0";

/** Only digest algorithm defined for v1.0.0 receipts per §1.1.1.3. */
export const EnvelopeHashAlgorithmSHA256 = "sha-256";

/** Receipt signature algorithm. */
export const ReceiptSignatureAlgorithmEd25519 = "ed25519";

/**
 * Receiver-side tolerance window per §1.1.1.5: "Verifiers MUST NOT
 * reject a receipt solely because `accepted_at` is within 120 seconds
 * of their own current time in either direction."
 */
export const ReceiptClockSkewToleranceSeconds = 120;

/** Hash binding inside a {@link DeliveryReceipt} per §1.1.1.3. */
export interface EnvelopeHash {
  algorithm: string;
  /** Base64-encoded digest. */
  value: string;
}

/** Signature block per §1.1.1.4. */
export interface ReceiptSignature {
  algorithm: string;
  /** Lowercase-hex SHA-256 fingerprint of the recipient domain pub. */
  key_id: string;
  /** Base64-encoded Ed25519 signature. Empty when blanked. */
  value: string;
}

/**
 * SEMP_DELIVERY_RECEIPT record per §1.1.1. The wire form is a JSON
 * object with these exact field names; canonical bytes are produced
 * by {@link "../canonical".marshal}.
 */
export interface DeliveryReceipt {
  type: typeof DeliveryReceiptType;
  version: string;
  envelope_hash: EnvelopeHash;
  recipient_domain: string;
  /** ISO 8601 UTC timestamp, second precision. */
  accepted_at: string;
  signature: ReceiptSignature;
}

/** Inputs to {@link signDeliveryReceipt}. */
export interface SignDeliveryReceiptInput {
  /** Base64 SHA-256 of canonical envelope bytes per §1.1.1.3. */
  envelopeHashB64: string;
  /** Recipient server's domain. */
  recipientDomain: string;
  /** ISO 8601 UTC timestamp of the recipient's accept decision. */
  acceptedAt: string;
  /** Lowercase-hex SHA-256 fingerprint of the signing public key. */
  domainKeyId: string;
  /** 32-byte Ed25519 secret seed for the recipient domain signing key. */
  domainSigningSeed: Uint8Array;
}

/** Result of a successful {@link signDeliveryReceipt} call. */
export interface SignDeliveryReceiptResult {
  /** Receipt with `signature.value` populated. */
  receipt: DeliveryReceipt;
  /** Bare base64 signature value (also present in `receipt.signature.value`). */
  signatureB64: string;
}

/**
 * SHA-256 of canonical envelope bytes, base64-encoded, per
 * §1.1.1.3. The caller is responsible for producing the canonical
 * bytes - typically via `envelope.canonicalEnvelopeFor(env)` which
 * applies §4.3 elision (signature and session_mac blanked).
 */
export function computeEnvelopeHash(canonicalEnvelopeBytes: Uint8Array): string {
  const sum = sha256(canonicalEnvelopeBytes);
  return base64Encode(sum);
}

/**
 * Build and Ed25519-sign a SEMP_DELIVERY_RECEIPT under the recipient
 * domain's signing key, following §1.1.1.4.
 */
export function signDeliveryReceipt(
  input: SignDeliveryReceiptInput,
): SignDeliveryReceiptResult {
  if (input.envelopeHashB64 === "") {
    throw new Error("delivery receipt: empty envelope_hash.value");
  }
  if (input.recipientDomain === "") {
    throw new Error("delivery receipt: empty recipient_domain");
  }
  if (input.acceptedAt === "") {
    throw new Error("delivery receipt: empty accepted_at");
  }
  if (input.domainKeyId === "") {
    throw new Error("delivery receipt: empty domain key_id");
  }

  const preSign: DeliveryReceipt = {
    type: DeliveryReceiptType,
    version: DeliveryReceiptVersion,
    envelope_hash: {
      algorithm: EnvelopeHashAlgorithmSHA256,
      value: input.envelopeHashB64,
    },
    recipient_domain: input.recipientDomain,
    accepted_at: input.acceptedAt,
    signature: {
      algorithm: ReceiptSignatureAlgorithmEd25519,
      key_id: input.domainKeyId,
      value: "",
    },
  };

  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.domainSigningSeed,
    signaturePath: "signature.value",
    prefix: DeliveryReceiptPrefix,
  });

  return {
    receipt: signedJSON as unknown as DeliveryReceipt,
    signatureB64,
  };
}

/** Inputs to {@link verifyDeliveryReceipt}. */
export interface VerifyDeliveryReceiptInput {
  /** Receipt as received. */
  receipt: DeliveryReceipt;
  /** 32-byte Ed25519 public key for the recipient domain. */
  domainPub: Uint8Array;
}

/**
 * Ed25519-verify a delivery receipt's signature against the
 * recipient domain public key. Returns true on success. Throws on
 * structural validation failure (use {@link validateReceipt} ahead
 * of time to surface those as boolean false instead).
 *
 * Does NOT cross-check `accepted_at` against the verifier's clock -
 * that is a §1.1.1.5 caller-side decision and MUST be applied with
 * the {@link ReceiptClockSkewToleranceSeconds} tolerance.
 */
export function verifyDeliveryReceipt(
  input: VerifyDeliveryReceiptInput,
): boolean {
  validateReceipt(input.receipt);
  if (input.receipt.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: input.receipt as unknown as Record<string, unknown>,
    publicKey: input.domainPub,
    signaturePath: "signature.value",
    prefix: DeliveryReceiptPrefix,
  });
  return ok;
}

/**
 * Cross-check that the receipt's `envelope_hash.value` matches the
 * fresh hash of the supplied canonical envelope bytes per §1.1.1.7
 * step 4. Returns true when the binding holds.
 */
export function verifyEnvelopeBinding(
  receipt: DeliveryReceipt,
  canonicalEnvelopeBytes: Uint8Array,
): boolean {
  if (receipt.envelope_hash.algorithm !== EnvelopeHashAlgorithmSHA256) {
    return false;
  }
  const want = computeEnvelopeHash(canonicalEnvelopeBytes);
  return receipt.envelope_hash.value === want;
}

/**
 * Structural validation per §1.1.1.2. Throws on the first missing or
 * malformed field. Callers that want a boolean outcome can wrap in
 * try/catch.
 */
export function validateReceipt(r: DeliveryReceipt): void {
  if (r.type !== DeliveryReceiptType) {
    throw new Error(
      `delivery receipt: type ${JSON.stringify(r.type)}, want ${DeliveryReceiptType}`,
    );
  }
  if (typeof r.version !== "string" || r.version === "") {
    throw new Error("delivery receipt: missing version");
  }
  if (typeof r.envelope_hash?.algorithm !== "string" || r.envelope_hash.algorithm === "") {
    throw new Error("delivery receipt: missing envelope_hash.algorithm");
  }
  if (typeof r.envelope_hash?.value !== "string" || r.envelope_hash.value === "") {
    throw new Error("delivery receipt: missing envelope_hash.value");
  }
  if (typeof r.recipient_domain !== "string" || r.recipient_domain === "") {
    throw new Error("delivery receipt: missing recipient_domain");
  }
  if (typeof r.accepted_at !== "string" || r.accepted_at === "") {
    throw new Error("delivery receipt: missing accepted_at");
  }
  if (typeof r.signature?.algorithm !== "string" || r.signature.algorithm === "") {
    throw new Error("delivery receipt: missing signature.algorithm");
  }
  if (typeof r.signature?.key_id !== "string" || r.signature.key_id === "") {
    throw new Error("delivery receipt: missing signature.key_id");
  }
  if (typeof r.signature?.value !== "string") {
    throw new Error("delivery receipt: missing signature.value");
  }
}

function base64Encode(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
}
