/**
 * Evidence-hash binding helpers per REPUTATION.md §5.5.1.
 *
 * A SEMP_TRUST_OBSERVATION that claims `evidence_available: true`
 * carries an `evidence_hash` over the bytes returned by
 * `evidence_uri`. A consumer MUST verify the fetched bytes against
 * the hash before treating the evidence as authoritative; a
 * mismatch is equivalent to a signature failure.
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { type Observation, MaxObservationBytes } from "./types.js";

/** Sentinel error class returned on any evidence-hash divergence. */
export class EvidenceHashMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceHashMismatchError";
  }
}

/** Sentinel error class returned on observation size violations. */
export class ObservationOversizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ObservationOversizedError";
  }
}

/**
 * Enforce the §4.2 rules linking `evidence_available`,
 * `evidence_uri`, and `evidence_hash`:
 *
 *  - true  -> both `evidence_uri` and `evidence_hash` MUST be present.
 *  - false -> both `evidence_uri` and `evidence_hash` MUST be absent.
 *
 * Throws with a descriptive message on any violation.
 */
export function validateEvidenceFields(observation: Observation): void {
  if (observation.evidence_available) {
    if (
      observation.evidence_uri === undefined ||
      observation.evidence_uri === ""
    ) {
      throw new Error(
        "reputation: evidence_available=true requires evidence_uri",
      );
    }
    if (observation.evidence_hash === undefined) {
      throw new Error(
        "reputation: evidence_available=true requires evidence_hash",
      );
    }
    if (
      observation.evidence_hash.algorithm === "" ||
      observation.evidence_hash.value === ""
    ) {
      throw new Error(
        "reputation: evidence_hash requires algorithm and value",
      );
    }
    return;
  }
  if (observation.evidence_uri !== undefined) {
    throw new Error(
      "reputation: evidence_available=false MUST NOT carry evidence_uri",
    );
  }
  if (observation.evidence_hash !== undefined) {
    throw new Error(
      "reputation: evidence_available=false MUST NOT carry evidence_hash",
    );
  }
}

/**
 * Verify that `evidence` hashes to the observation's
 * `evidence_hash.value` under `evidence_hash.algorithm`. Throws
 * {@link EvidenceHashMismatchError} on any divergence (algorithm
 * unsupported, base64 decode failure, digest mismatch).
 *
 * Currently the only defined algorithm is "sha-256".
 */
export function verifyEvidenceBytes(
  observation: Observation,
  evidence: Uint8Array,
): void {
  if (observation.evidence_hash === undefined) {
    throw new EvidenceHashMismatchError(
      "reputation: observation has no evidence_hash",
    );
  }
  let want: Uint8Array;
  try {
    want = decodeBase64(observation.evidence_hash.value);
  } catch (err) {
    throw new EvidenceHashMismatchError(
      `reputation: evidence_hash.value not base64: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  let got: Uint8Array;
  switch (observation.evidence_hash.algorithm) {
    case "sha-256":
      got = sha256(evidence);
      break;
    default:
      throw new EvidenceHashMismatchError(
        `reputation: unsupported evidence_hash algorithm "${observation.evidence_hash.algorithm}"`,
      );
  }
  if (got.length !== want.length) {
    throw new EvidenceHashMismatchError(
      "reputation: evidence_hash length mismatch",
    );
  }
  for (let i = 0; i < got.length; i++) {
    if (got[i] !== want[i]) {
      throw new EvidenceHashMismatchError(
        "reputation: evidence_hash digest does not match fetched bytes",
      );
    }
  }
}

/**
 * Throw {@link ObservationOversizedError} when the canonical UTF-8
 * JSON form of an observation exceeds {@link MaxObservationBytes}.
 * Servers MUST run this before propagating a received observation
 * per §4.6.1.
 */
export function checkObservationSize(canonicalBytes: Uint8Array): void {
  if (canonicalBytes.length > MaxObservationBytes) {
    throw new ObservationOversizedError(
      `reputation: observation ${canonicalBytes.length} bytes exceeds 16 KiB cap`,
    );
  }
}

function decodeBase64(s: string): Uint8Array {
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
