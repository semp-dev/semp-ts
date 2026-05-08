/**
 * Per-key revocation primitives per KEY.md §8.
 *
 * The published wire shape is `SEMP_KEY_REVOCATION` — a list of
 * revoked keys signed by the publishing party (a domain or a user).
 * The signature uses the `SEMP-REVOCATION:` domain-separation
 * prefix per ENVELOPE.md §4.3.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "./signed.js";

/** Wire-level constants. */
export const RevocationPublicationType = "SEMP_KEY_REVOCATION";
export const RevocationVersion = "1.0.0";
export const RevocationPrefix = "SEMP-REVOCATION:";

/** Reasons per §8.2 + ERRORS.md §8. */
export type RevocationReason =
  | "key_compromise"
  | "superseded"
  | "cessation_of_operation"
  | "temporary_hold";

/** Report whether the revocation is potentially reversible. */
export function isReversibleReason(r: RevocationReason): boolean {
  return r === "temporary_hold";
}

/** Reusable signature block. */
export interface PublicationSignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/**
 * Per-key revocation record per §8.4 — embedded in a key response
 * or in a {@link RevocationPublication}.
 */
export interface Revocation {
  reason: RevocationReason;
  /** ISO 8601 UTC timestamp the key was revoked. */
  revoked_at: string;
  /** Fingerprint of the successor key, when known. */
  replacement_key_id?: string;
}

/** One row inside a {@link RevocationPublication}. */
export interface RevokedKeyEntry {
  key_id: string;
  /** Address (for user-key revocations); empty for domain-key revocations. */
  address?: string;
  reason: RevocationReason;
  /** ISO 8601 UTC. */
  revoked_at: string;
  replacement_key_id?: string;
}

/** Wire shape per §8.1. */
export interface RevocationPublication {
  type: typeof RevocationPublicationType;
  version: string;
  revoked_keys: RevokedKeyEntry[];
  signature: PublicationSignature;
}

/** Sign a {@link RevocationPublication} under the publisher's identity key. */
export function signRevocationPublication(
  pub: RevocationPublication,
  signingPriv: Uint8Array,
  signingKeyId: string,
): string {
  if (signingKeyId === "") {
    throw new Error("keys: empty signing key_id");
  }
  validateRevocationPublication(pub, { skipSignatureCheck: true });
  pub.signature.algorithm = "ed25519";
  pub.signature.key_id = signingKeyId;
  pub.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: pub as unknown as Record<string, unknown>,
    seed: signingPriv,
    signaturePath: "signature.value",
    prefix: RevocationPrefix,
  });
  pub.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify a {@link RevocationPublication} under the publisher's identity public key. */
export function verifyRevocationPublication(
  pub: RevocationPublication,
  publisherPub: Uint8Array,
): boolean {
  validateRevocationPublication(pub);
  if (pub.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: pub as unknown as Record<string, unknown>,
    publicKey: publisherPub,
    signaturePath: "signature.value",
    prefix: RevocationPrefix,
  });
  return ok;
}

/** Structural validation per §8.1. Throws on first violation. */
export function validateRevocationPublication(
  pub: RevocationPublication,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (pub.type !== RevocationPublicationType) {
    throw new Error(
      `keys: revocation publication type ${JSON.stringify(pub.type)}, want ${RevocationPublicationType}`,
    );
  }
  if (typeof pub.version !== "string" || pub.version === "") {
    throw new Error("keys: revocation publication missing version");
  }
  if (!Array.isArray(pub.revoked_keys)) {
    throw new Error("keys: revocation publication revoked_keys must be an array");
  }
  for (let i = 0; i < pub.revoked_keys.length; i++) {
    const e = pub.revoked_keys[i]!;
    if (typeof e.key_id !== "string" || e.key_id === "") {
      throw new Error(`keys: revoked_keys[${i}] missing key_id`);
    }
    if (
      e.reason !== "key_compromise" &&
      e.reason !== "superseded" &&
      e.reason !== "cessation_of_operation" &&
      e.reason !== "temporary_hold"
    ) {
      throw new Error(
        `keys: revoked_keys[${i}] reason ${JSON.stringify(e.reason)} is invalid`,
      );
    }
    if (typeof e.revoked_at !== "string" || e.revoked_at === "") {
      throw new Error(`keys: revoked_keys[${i}] missing revoked_at`);
    }
    if (Number.isNaN(Date.parse(e.revoked_at))) {
      throw new Error(`keys: revoked_keys[${i}] revoked_at is not ISO 8601`);
    }
  }
  if (typeof pub.signature?.value !== "string") {
    throw new Error("keys: revocation publication signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && pub.signature.value === "") {
    throw new Error("keys: revocation publication is unsigned");
  }
}
