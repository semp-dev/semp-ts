/**
 * Sign / verify primitives for reputation wire records per
 * REPUTATION.md §4.2 + §3.5 + §5.
 *
 * Reputation records use a NO-PREFIX signing input - the canonical
 * bytes with `signature.value` elided are signed directly under
 * Ed25519. Other SEMP records use SEMP-* domain-separation
 * prefixes (registered in ENVELOPE.md §4.3) but reputation ones do
 * not in the current spec.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "../keys/index.js";

import { applyBucketing } from "./bucketize.js";
import {
  type AbuseReport,
  type DisclosureAuthorization,
  type Observation,
  type ReputationSignature,
  type TrustObservations,
} from "./types.js";

/** Only signature algorithm currently defined. */
export const SignatureAlgorithmEd25519 = "ed25519";

// ---------------------------------------------------------------------------
// Observation

/**
 * Bucketize metrics in place (per §4.5.1), then Ed25519-sign
 * `obs.signature` over the canonical bytes with `signature.value`
 * elided.
 */
export function signObservation(
  obs: Observation,
  observerPriv: Uint8Array,
  observerKeyId: string,
): string {
  if (observerKeyId === "") {
    throw new Error("reputation: empty observer key_id");
  }
  if (obs.extensions === undefined) {
    obs.extensions = {};
  }
  applyBucketing(obs.metrics);

  obs.signature.algorithm = SignatureAlgorithmEd25519;
  obs.signature.key_id = observerKeyId;
  obs.signature.value = "";

  const canonicalBytes = canonicalRecordBytes(
    obs as unknown as Record<string, unknown>,
    "signature",
  );
  const sig = ed25519Sign(observerPriv, canonicalBytes);
  const sigB64 = base64Encode(sig);
  obs.signature.value = sigB64;
  return sigB64;
}

/** Verify `obs.signature` against `observerPub`. */
export function verifyObservation(
  obs: Observation,
  observerPub: Uint8Array,
): boolean {
  if (obs.signature.value === "") {
    return false;
  }
  let sig: Uint8Array;
  try {
    sig = base64Decode(obs.signature.value);
  } catch {
    return false;
  }
  const canonicalBytes = canonicalRecordBytes(
    obs as unknown as Record<string, unknown>,
    "signature",
  );
  return ed25519Verify(observerPub, sig, canonicalBytes);
}

// ---------------------------------------------------------------------------
// TrustObservations envelope

/** Sign a {@link TrustObservations} response under the observer's signing key. */
export function signTrustObservations(
  resp: TrustObservations,
  observerPriv: Uint8Array,
  observerKeyId: string,
): string {
  if (observerKeyId === "") {
    throw new Error("reputation: empty observer key_id");
  }
  resp.signature.algorithm = SignatureAlgorithmEd25519;
  resp.signature.key_id = observerKeyId;
  resp.signature.value = "";
  const canonicalBytes = canonicalRecordBytes(
    resp as unknown as Record<string, unknown>,
    "signature",
  );
  const sig = ed25519Sign(observerPriv, canonicalBytes);
  const sigB64 = base64Encode(sig);
  resp.signature.value = sigB64;
  return sigB64;
}

/** Verify a {@link TrustObservations} response. */
export function verifyTrustObservations(
  resp: TrustObservations,
  observerPub: Uint8Array,
): boolean {
  if (resp.signature.value === "") {
    return false;
  }
  let sig: Uint8Array;
  try {
    sig = base64Decode(resp.signature.value);
  } catch {
    return false;
  }
  const canonicalBytes = canonicalRecordBytes(
    resp as unknown as Record<string, unknown>,
    "signature",
  );
  return ed25519Verify(observerPub, sig, canonicalBytes);
}

// ---------------------------------------------------------------------------
// DisclosureAuthorization (embedded inside abuse reports)

/** Sign a {@link DisclosureAuthorization} under the affected user's identity key. */
export function signDisclosureAuthorization(
  auth: DisclosureAuthorization,
  userPriv: Uint8Array,
  userKeyId: string,
): string {
  if (userKeyId === "") {
    throw new Error("reputation: empty user key_id");
  }
  auth.signature.algorithm = SignatureAlgorithmEd25519;
  auth.signature.key_id = userKeyId;
  auth.signature.value = "";
  const canonicalBytes = canonicalRecordBytes(
    auth as unknown as Record<string, unknown>,
    "signature",
  );
  const sig = ed25519Sign(userPriv, canonicalBytes);
  const sigB64 = base64Encode(sig);
  auth.signature.value = sigB64;
  return sigB64;
}

/** Verify a {@link DisclosureAuthorization} against the user's identity public key. */
export function verifyDisclosureAuthorization(
  auth: DisclosureAuthorization,
  userPub: Uint8Array,
): boolean {
  if (auth.signature.value === "") {
    return false;
  }
  let sig: Uint8Array;
  try {
    sig = base64Decode(auth.signature.value);
  } catch {
    return false;
  }
  const canonicalBytes = canonicalRecordBytes(
    auth as unknown as Record<string, unknown>,
    "signature",
  );
  return ed25519Verify(userPub, sig, canonicalBytes);
}

/** Report whether the scope permits disclosing brief content. */
export function authAllowsBrief(auth: DisclosureAuthorization): boolean {
  return auth.scope === "brief_only" || auth.scope === "brief_and_enclosure";
}

/** Report whether the scope permits disclosing enclosure content. */
export function authAllowsEnclosure(auth: DisclosureAuthorization): boolean {
  return auth.scope === "enclosure_only" || auth.scope === "brief_and_enclosure";
}

// ---------------------------------------------------------------------------
// AbuseReport - sent over an authenticated session, no own signature

/** Structural validation of an {@link AbuseReport} per §3.2. Throws on first violation. */
export function validateAbuseReport(r: AbuseReport): void {
  if (r.type !== "SEMP_ABUSE_REPORT") {
    throw new Error(
      `reputation: abuse report type ${JSON.stringify(r.type)}, want SEMP_ABUSE_REPORT`,
    );
  }
  for (const f of ["id", "reporter", "reported_domain", "category", "timestamp"] as const) {
    if (typeof r[f] !== "string" || r[f] === "") {
      throw new Error(`reputation: abuse report missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(r.timestamp))) {
    throw new Error("reputation: abuse report timestamp is not ISO 8601");
  }
  if (r.evidence === undefined || r.evidence === null) {
    throw new Error("reputation: abuse report missing evidence");
  }
  const evType = (r.evidence as { type: string }).type;
  if (evType !== "envelope_metadata" && evType !== "sealed_evidence") {
    throw new Error(
      `reputation: abuse report evidence type ${JSON.stringify(evType)} is not valid`,
    );
  }
  if (r.evidence.type === "sealed_evidence") {
    if (!Array.isArray(r.evidence.envelopes) || r.evidence.envelopes.length === 0) {
      throw new Error(
        "reputation: sealed_evidence requires non-empty envelopes array",
      );
    }
    // §3.7 MUST: when disclosed_brief / disclosed_enclosure is
    // present, disclosure_authorization MUST also be present.
    for (let i = 0; i < r.evidence.envelopes.length; i++) {
      const env = r.evidence.envelopes[i]!;
      const hasDisclosed =
        env.disclosed_brief !== undefined || env.disclosed_enclosure !== undefined;
      if (hasDisclosed && env.disclosure_authorization === undefined) {
        throw new Error(
          `reputation: envelopes[${i}]: disclosed content requires disclosure_authorization (§3.7)`,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers

/**
 * Canonical bytes with `<topField>.value` elided. The reputation
 * records sign the canonical bytes directly (no domain-separation
 * prefix); other SEMP records use SEMP-* prefixes.
 */
function canonicalRecordBytes(
  obj: Record<string, unknown>,
  topField: string,
): Uint8Array {
  const clone = JSON.parse(JSON.stringify(obj)) as Record<string, unknown>;
  const sig = clone[topField] as Record<string, unknown> | undefined;
  if (sig === undefined) {
    throw new Error(`reputation: object has no ${topField} block`);
  }
  sig.value = "";
  return canonicalMarshal(clone);
}

/** Re-export so callers can wire the algorithm tag explicitly. */
export type { ReputationSignature };

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

function base64Decode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
