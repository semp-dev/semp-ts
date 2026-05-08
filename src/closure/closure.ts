/**
 * SEMP_ACCOUNT_CLOSURE record types and signing primitives per
 * CLOSURE.md.
 *
 * A closure is a two-step lifecycle: a full-access device submits
 * a `request` with a grace period; during the grace period any
 * full-access device may submit a `cancel` to abort. At
 * `requested_at + grace_period_seconds` the home server finalizes
 * per §4.
 *
 * This module covers the wire records and their signing /
 * verifying primitives. Home-server orchestration (driver state,
 * finalization side effects, ingress handling, local-part
 * reassignment) lives in {@link "./driver"} + {@link "./store"}.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

/** Wire-level constants per §2.1. */
export const RecordType = "SEMP_ACCOUNT_CLOSURE";
export const RecordVersion = "1.0.0";

/** Domain-separation prefix per ENVELOPE.md §4.3. */
export const AccountClosurePrefix = "SEMP-ACCOUNT-CLOSURE:";

/** Only signature algorithm currently defined. */
export const SignatureAlgorithmEd25519 = "ed25519";

/** Step discriminator per §2.2. */
export type Step = "request" | "cancel";

/** Grace-period bounds per §3.1, in seconds. */
export const MinGracePeriodSeconds = 7 * 24 * 60 * 60;
export const MaxGracePeriodSeconds = 90 * 24 * 60 * 60;
export const RecommendedGracePeriodSeconds = 30 * 24 * 60 * 60;

/** Reusable signature block. */
export interface ClosureSignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/**
 * SEMP_ACCOUNT_CLOSURE request or cancel record per §2.1. The same
 * shape covers both steps; `step` disambiguates.
 */
export interface ClosureRecord {
  type: typeof RecordType;
  step: Step;
  version: string;
  user_id: string;
  /** ISO 8601 UTC timestamp. */
  requested_at: string;
  grace_period_seconds: number;
  /** Issuing device's fingerprint. */
  issued_by: string;
  signature: ClosureSignature;
}

/** Inputs to {@link signClosureRecord}. */
export interface SignClosureRecordInput {
  /** Pre-sign record; signature will be replaced. */
  record: ClosureRecord;
  /** 32-byte Ed25519 secret seed for the issuing full-access device. */
  deviceSigningSeed: Uint8Array;
  /** Lowercase-hex SHA-256 fingerprint of the device public key. */
  deviceKeyId: string;
}

/** Result of a successful {@link signClosureRecord}. */
export interface SignClosureRecordResult {
  record: ClosureRecord;
  signatureB64: string;
}

/**
 * Build and Ed25519-sign a closure record per §2.3. Pre-populates
 * `signature.{algorithm,key_id}` so the canonical bytes cover them
 * (defense against algorithm/issuer downgrade).
 */
export function signClosureRecord(
  input: SignClosureRecordInput,
): SignClosureRecordResult {
  if (input.deviceKeyId === "") {
    throw new Error("closure: empty device key_id");
  }
  validateClosureRecord(input.record, { skipSignatureCheck: true });

  const preSign: ClosureRecord = {
    ...input.record,
    signature: {
      algorithm: SignatureAlgorithmEd25519,
      key_id: input.deviceKeyId,
      value: "",
    },
  };
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.deviceSigningSeed,
    signaturePath: "signature.value",
    prefix: AccountClosurePrefix,
  });
  return {
    record: signedJSON as unknown as ClosureRecord,
    signatureB64,
  };
}

/**
 * Ed25519-verify a closure record under `devicePub`. Returns true
 * on success. Does NOT enforce the §2.3 authority rule (the signing
 * device MUST be a current full-access device of the account); the
 * home server applies that check via the device directory.
 */
export function verifyClosureRecord(
  record: ClosureRecord,
  devicePub: Uint8Array,
): boolean {
  validateClosureRecord(record);
  if (record.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: record as unknown as Record<string, unknown>,
    publicKey: devicePub,
    signaturePath: "signature.value",
    prefix: AccountClosurePrefix,
  });
  return ok;
}

/** Options for {@link validateClosureRecord}. */
export interface ValidateClosureOptions {
  /**
   * When true, do not require `signature.value` to be a non-empty
   * string. Used during the compose path before signing.
   */
  skipSignatureCheck?: boolean;
}

/**
 * Structural validation per §2.2. Throws on the first violation.
 * Cancel records skip the grace-period bound check (§3.2: the
 * cancellation does not introduce a new grace period; the request
 * being canceled already validated its bound).
 */
export function validateClosureRecord(
  r: ClosureRecord,
  opts: ValidateClosureOptions = {},
): void {
  if (r.type !== RecordType) {
    throw new Error(`closure: type ${JSON.stringify(r.type)}, want ${RecordType}`);
  }
  if (r.step !== "request" && r.step !== "cancel") {
    throw new Error(`closure: step ${JSON.stringify(r.step)} is not request or cancel`);
  }
  if (typeof r.version !== "string" || r.version === "") {
    throw new Error("closure: missing version");
  }
  if (typeof r.user_id !== "string" || r.user_id === "") {
    throw new Error("closure: missing user_id");
  }
  if (typeof r.requested_at !== "string" || r.requested_at === "") {
    throw new Error("closure: missing requested_at");
  }
  if (Number.isNaN(Date.parse(r.requested_at))) {
    throw new Error("closure: requested_at is not ISO 8601");
  }
  if (typeof r.issued_by !== "string" || r.issued_by === "") {
    throw new Error("closure: missing issued_by");
  }
  if (r.step === "request") {
    if (!Number.isInteger(r.grace_period_seconds)) {
      throw new Error("closure: grace_period_seconds must be an integer");
    }
    if (r.grace_period_seconds < MinGracePeriodSeconds) {
      throw new Error(
        `closure: grace_period_seconds ${r.grace_period_seconds} below minimum ${MinGracePeriodSeconds} (7 days)`,
      );
    }
    if (r.grace_period_seconds > MaxGracePeriodSeconds) {
      throw new Error(
        `closure: grace_period_seconds ${r.grace_period_seconds} exceeds maximum ${MaxGracePeriodSeconds} (90 days)`,
      );
    }
  }
  if (typeof r.signature?.algorithm !== "string") {
    throw new Error("closure: missing signature.algorithm");
  }
  if (typeof r.signature?.key_id !== "string") {
    throw new Error("closure: missing signature.key_id");
  }
  if (typeof r.signature?.value !== "string") {
    throw new Error("closure: signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && r.signature.value === "") {
    throw new Error("closure: record is unsigned");
  }
}

/**
 * Wall-clock at which the home server MUST finalize per §4.1:
 * `requested_at + grace_period_seconds`.
 */
export function finalizationAt(record: ClosureRecord): Date {
  const ts = Date.parse(record.requested_at);
  if (Number.isNaN(ts)) {
    throw new Error("closure: requested_at is not ISO 8601");
  }
  return new Date(ts + record.grace_period_seconds * 1000);
}

/**
 * Report whether `now` has reached or passed the finalization
 * timestamp per §4.1. Returns false for cancel records (only
 * requests finalize).
 */
export function isFinalizable(record: ClosureRecord, now: Date): boolean {
  if (record.step !== "request") {
    return false;
  }
  return now.getTime() >= finalizationAt(record).getTime();
}
