/**
 * SEMP_REPUTATION_REFERENCES document per
 * draft-gokce-semp-delivery §12.2.
 *
 * Lists third-party observers a subject domain points peers at
 * when they want to cross-check the subject's reputation. The
 * subject domain signs the document with its domain signing key
 * under the SEMP-REPUTATION-REFERENCES: prefix; consumers verify
 * against the published domain key.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

import type { Assessment, ReputationSignature } from "./types.js";

/** Wire-level type discriminator. */
export const ReferencesType = "SEMP_REPUTATION_REFERENCES";

/** Wire-level version. */
export const ReferencesVersion = "1.0.0";

/** Domain-separation prefix for SEMP_REPUTATION_REFERENCES signatures. */
export const ReferencesPrefix = "SEMP-REPUTATION-REFERENCES:";

/** Single observer reference. */
export interface ReferenceEntry {
  observer: string;
  uri: string;
  /** ISO 8601 UTC. */
  fetched_at: string;
  /** Optional cached classification hint; informational. */
  assessment?: Assessment;
}

/** SEMP_REPUTATION_REFERENCES record per §12.2. */
export interface References {
  type: typeof ReferencesType;
  version: string;
  domain: string;
  references: ReferenceEntry[];
  /** ISO 8601 UTC. */
  timestamp: string;
  signature: ReputationSignature;
}

/**
 * Sign `r.signature` with the subject domain's signing key under
 * the SEMP-REPUTATION-REFERENCES: prefix. Mutates r in place and
 * returns the base64 signature value.
 */
export function signReferences(
  r: References,
  domainPriv: Uint8Array,
  domainKeyId: string,
): string {
  if (domainKeyId === "") {
    throw new Error("reputation: empty domain key_id");
  }
  if ((r.type as string) === "") {
    r.type = ReferencesType;
  }
  if (r.version === "") {
    r.version = ReferencesVersion;
  }
  validateReferences(r, { skipSignatureCheck: true });
  r.signature.algorithm = "ed25519";
  r.signature.key_id = domainKeyId;
  r.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: r as unknown as Record<string, unknown>,
    seed: domainPriv,
    signaturePath: "signature.value",
    prefix: ReferencesPrefix,
  });
  r.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify `r.signature` against the subject domain's public key. */
export function verifyReferences(
  r: References,
  domainPub: Uint8Array,
): boolean {
  validateReferences(r);
  if (r.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: r as unknown as Record<string, unknown>,
    publicKey: domainPub,
    signaturePath: "signature.value",
    prefix: ReferencesPrefix,
  });
  return ok;
}

/** Structural validation per §12.2. */
export function validateReferences(
  r: References,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (r.type !== ReferencesType) {
    throw new Error(
      `reputation: references type ${JSON.stringify(r.type)}, want ${ReferencesType}`,
    );
  }
  if (r.version === "") {
    throw new Error("reputation: references missing version");
  }
  if (r.domain === "") {
    throw new Error("reputation: references missing domain");
  }
  if (r.timestamp === "") {
    throw new Error("reputation: references missing timestamp");
  }
  for (let i = 0; i < r.references.length; i++) {
    const e = r.references[i];
    if (e === undefined) {
      continue;
    }
    if (e.observer === "") {
      throw new Error(`reputation: references[${i}] missing observer`);
    }
    if (e.uri === "") {
      throw new Error(`reputation: references[${i}] missing uri`);
    }
    if (e.fetched_at === "") {
      throw new Error(`reputation: references[${i}] missing fetched_at`);
    }
  }
  if (!opts.skipSignatureCheck && r.signature === undefined) {
    throw new Error("reputation: references missing signature");
  }
}
