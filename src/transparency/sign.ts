/**
 * STH signing + verification + freshness checks per
 * TRANSPARENCY.md §2.3.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

import {
  type LogEntry,
  type SignedTreeHead,
  MaxSTHFreshnessMs,
} from "./types.js";

/** Domain-separation prefix per ENVELOPE.md §4.3. */
export const TransparencySTHPrefix = "SEMP-TRANSPARENCY-STH:";

/** Only signature algorithm defined for STH signatures. */
export const SignatureAlgorithmEd25519 = "ed25519";

/** Inputs to {@link signSTH}. */
export interface SignSTHInput {
  /** Pre-sign STH; `signature.value` will be replaced. */
  sth: SignedTreeHead;
  /** 32-byte Ed25519 secret seed for the domain signing key. */
  domainSigningSeed: Uint8Array;
  /** Lowercase-hex SHA-256 fingerprint of the domain signing pub. */
  domainKeyId: string;
}

/** Result of a successful {@link signSTH}. */
export interface SignSTHResult {
  sth: SignedTreeHead;
  signatureB64: string;
}

/**
 * Build and Ed25519-sign an STH per §2.3. Pre-populates
 * `signature.{algorithm,key_id}` so the canonical bytes cover them
 * (defense against algorithm/issuer downgrade).
 */
export function signSTH(input: SignSTHInput): SignSTHResult {
  if (input.domainKeyId === "") {
    throw new Error("transparency: empty domain key_id");
  }
  validateSTH(input.sth);

  const preSign: SignedTreeHead = {
    ...input.sth,
    signature: {
      algorithm: SignatureAlgorithmEd25519,
      key_id: input.domainKeyId,
      value: "",
    },
  };
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.domainSigningSeed,
    signaturePath: "signature.value",
    prefix: TransparencySTHPrefix,
  });
  return {
    sth: signedJSON as unknown as SignedTreeHead,
    signatureB64,
  };
}

/**
 * Ed25519-verify an STH's signature against `domainPub`. Returns
 * true on success. Does NOT enforce staleness; pair with
 * {@link checkSTHFresh} for the §2.3 1-hour bound.
 */
export function verifySTH(
  sth: SignedTreeHead,
  domainPub: Uint8Array,
): boolean {
  validateSTH(sth);
  if (sth.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: sth as unknown as Record<string, unknown>,
    publicKey: domainPub,
    signaturePath: "signature.value",
    prefix: TransparencySTHPrefix,
  });
  return ok;
}

/**
 * Enforce §2.3 freshness: reject STHs whose timestamp is more than
 * {@link MaxSTHFreshnessMs} old. Returns true when the STH is
 * fresh under the supplied `now`.
 */
export function checkSTHFresh(sth: SignedTreeHead, now: Date): boolean {
  const ts = Date.parse(sth.timestamp);
  if (Number.isNaN(ts)) {
    return false;
  }
  return now.getTime() - ts <= MaxSTHFreshnessMs;
}

/** Structural validation of `sth` per §2.3. Throws on first violation. */
export function validateSTH(sth: SignedTreeHead): void {
  if (!Number.isInteger(sth.log_size) || sth.log_size < 0) {
    throw new Error(`transparency: STH log_size ${sth.log_size} MUST be >= 0`);
  }
  if (typeof sth.root_hash !== "string" || sth.root_hash === "") {
    throw new Error("transparency: STH missing root_hash");
  }
  if (typeof sth.timestamp !== "string" || sth.timestamp === "") {
    throw new Error("transparency: STH missing timestamp");
  }
  if (Number.isNaN(Date.parse(sth.timestamp))) {
    throw new Error("transparency: STH timestamp is not ISO 8601");
  }
  if (typeof sth.signature?.algorithm !== "string") {
    throw new Error("transparency: STH missing signature.algorithm");
  }
  if (typeof sth.signature?.key_id !== "string") {
    throw new Error("transparency: STH missing signature.key_id");
  }
  if (typeof sth.signature?.value !== "string") {
    throw new Error("transparency: STH signature.value must be a string");
  }
}

/** Structural validation of a {@link LogEntry} per §2.2. Throws on first violation. */
export function validateLogEntry(e: LogEntry): void {
  if (e.event !== "publish" && e.event !== "rotate" && e.event !== "revoke") {
    throw new Error(`transparency: log entry event ${JSON.stringify(e.event)} is invalid`);
  }
  for (const f of ["user_id", "key_id", "algorithm", "public_key"] as const) {
    if (typeof e[f] !== "string" || e[f] === "") {
      throw new Error(`transparency: log entry missing ${f}`);
    }
  }
  if (e.key_type !== "identity" && e.key_type !== "encryption") {
    throw new Error(
      `transparency: log entry key_type ${JSON.stringify(e.key_type)} is invalid`,
    );
  }
  if (typeof e.created !== "string" || e.created === "" || Number.isNaN(Date.parse(e.created))) {
    throw new Error("transparency: log entry missing or invalid created");
  }
  if (
    typeof e.log_timestamp !== "string" ||
    e.log_timestamp === "" ||
    Number.isNaN(Date.parse(e.log_timestamp))
  ) {
    throw new Error("transparency: log entry missing or invalid log_timestamp");
  }
  switch (e.event) {
    case "rotate":
      if (e.supersedes === undefined || e.supersedes === null || e.supersedes === "") {
        throw new Error("transparency: rotate event MUST set supersedes");
      }
      break;
    case "publish":
      if (e.supersedes !== undefined && e.supersedes !== null && e.supersedes !== "") {
        throw new Error("transparency: publish event MUST NOT set supersedes");
      }
      break;
    case "revoke":
      if (e.revoked_at === undefined || e.revoked_at === null || e.revoked_at === "") {
        throw new Error("transparency: revoke event MUST set revoked_at");
      }
      if (
        e.revoked_reason === undefined ||
        e.revoked_reason === null ||
        e.revoked_reason === ""
      ) {
        throw new Error("transparency: revoke event MUST set revoked_reason");
      }
      break;
  }
}
