/**
 * Envelope-specific canonicalization per ENVELOPE.md §4.3.
 *
 * On top of the generic canonical-JSON rules ({@link
 * "../canonical/marshal"}), envelope canonicalization applies four
 * specific elisions:
 *
 *   - `seal.signature` is set to ""
 *   - `seal.session_mac` is set to ""
 *   - `postmark.hop_count` is omitted entirely
 *   - `padding` is omitted entirely
 *
 * These rules apply identically to the input of seal.signature
 * (Ed25519) and seal.session_mac (HMAC-SHA-256); both proofs cover
 * exactly the same byte stream so neither depends on the value of
 * the other.
 *
 * @module
 */

import { marshalWithElision } from "../canonical/index.js";

/**
 * Compute the §4.3 canonical bytes from any envelope-shaped value.
 * The input is treated as opaque JSON: navigate to `seal.*` and
 * `postmark.*` if they exist, blank/omit the relevant fields, and
 * canonicalize. Inputs without those keys are returned with the
 * generic canonicalization only.
 */
export function canonicalEnvelopeBytes(envelope: unknown): Uint8Array {
  return marshalWithElision(envelope, envelopeElider);
}

function envelopeElider(v: unknown): void {
  if (!isRecord(v)) {
    return;
  }
  // Top-level: drop `padding` if present.
  delete v.padding;

  const seal = v.seal;
  if (isRecord(seal)) {
    if ("signature" in seal) {
      seal.signature = "";
    }
    if ("session_mac" in seal) {
      seal.session_mac = "";
    }
  }

  const postmark = v.postmark;
  if (isRecord(postmark)) {
    delete postmark.hop_count;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
