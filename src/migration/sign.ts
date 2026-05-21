/**
 * Sequential four-signature compose / verify per MIGRATION.md §3.3.
 *
 * The migration record carries a chain of signatures:
 *
 *   1. old_identity_signature
 *   2. new_identity_signature
 *   3. new_domain_signature
 *   4. old_domain_signature   (cooperative only)
 *
 * Each signature commits to all prior signatures' final values so
 * walking them in order detects after-the-fact tampering with an
 * earlier signing party's commitment.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import {
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "../keys/index.js";

import {
  type MigrationMode,
  type MigrationRecord,
  type MigrationSignatureBlock,
  MaxNoticeWindowMs,
  MigrationPrefix,
  MigrationRecordType,
  MinNoticeWindowMs,
  SignatureAlgorithmEd25519,
} from "./types.js";

/** Order of signature slots per §3.3. */
const SIGNATURE_FIELDS = [
  "old_identity_signature",
  "new_identity_signature",
  "new_domain_signature",
  "old_domain_signature",
] as const;
type SigField = (typeof SIGNATURE_FIELDS)[number];

/**
 * Pre-populate algorithm + key_id on every signature slot so the
 * chained-signature canonical bytes are stable across passes per
 * §3.3. Each later signature commits to prior slots' final state
 * (including algorithm and key_id).
 *
 * In cooperative mode this allocates the `old_domain_signature`
 * slot with the old provider's key id populated up front; the old
 * provider populates only the `value` field at AcceptSubmission
 * time. In unilateral mode the slot stays null.
 */
export function prepareSignatures(
  r: MigrationRecord,
  oldIdentityKeyId: string,
  newIdentityKeyId: string,
  newDomainKeyId: string,
  oldDomainKeyId?: string,
): void {
  r.old_identity_signature = {
    algorithm: SignatureAlgorithmEd25519,
    key_id: oldIdentityKeyId,
    value: "",
  };
  r.new_identity_signature = {
    algorithm: SignatureAlgorithmEd25519,
    key_id: newIdentityKeyId,
    value: "",
  };
  r.new_domain_signature = {
    algorithm: SignatureAlgorithmEd25519,
    key_id: newDomainKeyId,
    value: "",
  };
  if (r.mode === "cooperative") {
    if (oldDomainKeyId === undefined || oldDomainKeyId === "") {
      throw new Error(
        "migration: cooperative mode requires oldDomainKeyId",
      );
    }
    r.old_domain_signature = {
      algorithm: SignatureAlgorithmEd25519,
      key_id: oldDomainKeyId,
      value: "",
    };
  } else {
    r.old_domain_signature = null;
  }
}

/** Sign signing-pass 1 (old identity). */
export function signOldIdentity(
  r: MigrationRecord,
  oldIdentityPriv: Uint8Array,
  oldIdentityKeyId: string,
): string {
  return signSlot(r, "old_identity_signature", oldIdentityPriv, oldIdentityKeyId);
}

/** Sign signing-pass 2 (new identity). */
export function signNewIdentity(
  r: MigrationRecord,
  newIdentityPriv: Uint8Array,
  newIdentityKeyId: string,
): string {
  if (r.old_identity_signature.value === "") {
    throw new Error("migration: signOldIdentity MUST run before signNewIdentity");
  }
  return signSlot(r, "new_identity_signature", newIdentityPriv, newIdentityKeyId);
}

/** Sign signing-pass 3 (new domain). */
export function signNewDomain(
  r: MigrationRecord,
  newDomainPriv: Uint8Array,
  newDomainKeyId: string,
): string {
  if (
    r.old_identity_signature.value === "" ||
    r.new_identity_signature.value === ""
  ) {
    throw new Error(
      "migration: signNewDomain requires old_identity and new_identity signatures",
    );
  }
  return signSlot(r, "new_domain_signature", newDomainPriv, newDomainKeyId);
}

/** Sign signing-pass 4 (old domain, cooperative only). */
export function signOldDomain(
  r: MigrationRecord,
  oldDomainPriv: Uint8Array,
  oldDomainKeyId: string,
): string {
  if (r.mode !== "cooperative") {
    throw new Error(
      `migration: signOldDomain only valid for mode=cooperative (got ${JSON.stringify(r.mode)})`,
    );
  }
  if (r.old_domain_signature === null) {
    throw new Error(
      "migration: prepareSignatures MUST run before signOldDomain (cooperative mode)",
    );
  }
  if (
    r.old_identity_signature.value === "" ||
    r.new_identity_signature.value === "" ||
    r.new_domain_signature.value === ""
  ) {
    throw new Error(
      "migration: signOldDomain requires all three prior signatures",
    );
  }
  return signSlot(r, "old_domain_signature", oldDomainPriv, oldDomainKeyId);
}

/**
 * Verify a single signature pass (zero-indexed: 0=old identity,
 * 1=new identity, 2=new domain, 3=old domain). Used by orchestration
 * code that validates partial submissions before the chain is
 * complete.
 */
export function verifyMigrationPass(
  r: MigrationRecord,
  passIdx: number,
  pub: Uint8Array,
): boolean {
  if (!Number.isInteger(passIdx) || passIdx < 0 || passIdx >= SIGNATURE_FIELDS.length) {
    return false;
  }
  const field = SIGNATURE_FIELDS[passIdx]!;
  return verifySlot(r, field, passIdx, pub);
}

/**
 * Verify all signatures in §3.3 order: old identity -> new identity
 * -> new domain -> old domain. Returns true on full success.
 *
 * `oldDomainPub` is consulted only in cooperative mode; pass any
 * value (including a zero-length array) for unilateral records.
 */
export function verifyMigrationRecord(
  r: MigrationRecord,
  oldIdentityPub: Uint8Array,
  newIdentityPub: Uint8Array,
  newDomainPub: Uint8Array,
  oldDomainPub: Uint8Array | null,
): boolean {
  validateMigrationRecord(r);
  if (!verifySlot(r, "old_identity_signature", 0, oldIdentityPub)) {
    return false;
  }
  if (!verifySlot(r, "new_identity_signature", 1, newIdentityPub)) {
    return false;
  }
  if (!verifySlot(r, "new_domain_signature", 2, newDomainPub)) {
    return false;
  }
  if (r.mode === "cooperative") {
    if (r.old_domain_signature === null) {
      return false;
    }
    if (oldDomainPub === null || oldDomainPub.length === 0) {
      return false;
    }
    if (!verifySlot(r, "old_domain_signature", 3, oldDomainPub)) {
      return false;
    }
  } else if (r.old_domain_signature !== null) {
    return false;
  }
  return true;
}

/** Structural validation per §3.2. Throws on the first violation. */
export function validateMigrationRecord(r: MigrationRecord): void {
  if (r.type !== MigrationRecordType) {
    throw new Error(
      `migration: type ${JSON.stringify(r.type)}, want ${MigrationRecordType}`,
    );
  }
  for (const f of [
    "version",
    "record_id",
    "old_address",
    "new_address",
    "old_identity_key_id",
    "new_identity_key_id",
    "new_identity_public_key",
    "migrated_at",
  ] as const) {
    if (typeof r[f] !== "string" || r[f] === "") {
      throw new Error(`migration: missing ${f}`);
    }
  }
  const migratedMs = Date.parse(r.migrated_at);
  if (Number.isNaN(migratedMs)) {
    throw new Error("migration: migrated_at is not ISO 8601");
  }
  if (r.mode !== "cooperative" && r.mode !== "unilateral") {
    throw new Error(`migration: mode ${JSON.stringify(r.mode)} is invalid`);
  }
  if (r.mode === "cooperative") {
    if (typeof r.notice_window_until !== "string" || r.notice_window_until === "") {
      throw new Error("migration: cooperative mode MUST set notice_window_until");
    }
    const untilMs = Date.parse(r.notice_window_until);
    if (Number.isNaN(untilMs)) {
      throw new Error("migration: notice_window_until is not ISO 8601");
    }
    const window = untilMs - migratedMs;
    if (window < MinNoticeWindowMs) {
      throw new Error(
        `migration: cooperative notice window ${window} below minimum ${MinNoticeWindowMs}`,
      );
    }
    if (window > MaxNoticeWindowMs) {
      throw new Error(
        `migration: cooperative notice window ${window} exceeds maximum ${MaxNoticeWindowMs}`,
      );
    }
  }
  for (const f of [
    "old_identity_signature",
    "new_identity_signature",
    "new_domain_signature",
  ] as const) {
    const sig = r[f];
    if (typeof sig?.algorithm !== "string" || sig.algorithm === "") {
      throw new Error(`migration: ${f}.algorithm missing`);
    }
    if (typeof sig?.key_id !== "string" || sig.key_id === "") {
      throw new Error(`migration: ${f}.key_id missing`);
    }
    if (typeof sig?.value !== "string") {
      throw new Error(`migration: ${f}.value must be a string`);
    }
  }
  if (r.mode === "cooperative") {
    if (r.old_domain_signature === null) {
      throw new Error("migration: cooperative record requires old_domain_signature");
    }
    if (typeof r.old_domain_signature.value !== "string") {
      throw new Error("migration: old_domain_signature.value must be a string");
    }
  } else if (r.old_domain_signature !== null) {
    throw new Error(
      "migration: unilateral record MUST NOT carry old_domain_signature",
    );
  }
}

/**
 * Enforce the §3.3 rule: `migrated_at` MUST be at or after the old
 * identity key's `created` timestamp, and MUST NOT be in the future
 * relative to `now` beyond ordinary clock-skew tolerance.
 *
 * `oldKeyCreated` is the `created` timestamp of the old identity
 * key record (resolved from the old key endpoint).
 * `clockSkewMs` defaults to 5 minutes.
 */
export function checkMigratedAtBound(
  r: MigrationRecord,
  oldKeyCreated: Date | null,
  now: Date,
  clockSkewMs = 5 * 60 * 1000,
): void {
  const migratedMs = Date.parse(r.migrated_at);
  if (Number.isNaN(migratedMs)) {
    throw new Error("migration: migrated_at is not ISO 8601");
  }
  if (oldKeyCreated !== null && migratedMs < oldKeyCreated.getTime()) {
    throw new Error(
      `migration: migrated_at ${r.migrated_at} precedes old identity key created ${oldKeyCreated.toISOString()}`,
    );
  }
  if (migratedMs > now.getTime() + clockSkewMs) {
    throw new Error(
      `migration: migrated_at ${r.migrated_at} is in the future beyond clock-skew tolerance`,
    );
  }
}

// ---------------------------------------------------------------------------
// Internal helpers

function signSlot(
  r: MigrationRecord,
  field: SigField,
  priv: Uint8Array,
  expectedKeyId: string,
): string {
  const slot = r[field] as MigrationSignatureBlock | null;
  if (slot === null) {
    throw new Error(`migration: ${field} slot is null (call prepareSignatures)`);
  }
  if (slot.algorithm === "" || slot.key_id === "") {
    throw new Error(
      `migration: ${field} requires algorithm + key_id pre-populated (call prepareSignatures)`,
    );
  }
  if (slot.key_id !== expectedKeyId) {
    throw new Error(
      `migration: ${field}.key_id ${JSON.stringify(slot.key_id)} does not match passed ${JSON.stringify(expectedKeyId)}`,
    );
  }
  // Build a deep copy + blank from this slot onward.
  const view = JSON.parse(JSON.stringify(r)) as Record<string, unknown>;
  blankFromIndex(view, fieldIndex(field, r.mode));
  const canonical = canonicalMarshal(view);
  const signingInput = concat(
    new TextEncoder().encode(MigrationPrefix),
    canonical,
  );
  const sig = ed25519Sign(priv, signingInput);
  const sigB64 = base64Encode(sig);
  slot.value = sigB64;
  return sigB64;
}

function verifySlot(
  r: MigrationRecord,
  field: SigField,
  passIdx: number,
  pub: Uint8Array,
): boolean {
  const slot = r[field] as MigrationSignatureBlock | null;
  if (slot === null) {
    return false;
  }
  if (slot.value === "") {
    return false;
  }
  let sig: Uint8Array;
  try {
    sig = base64Decode(slot.value);
  } catch {
    return false;
  }
  // Recreate the signing-time canonical bytes: this slot blanked,
  // every later slot also blanked (they hadn't been signed yet).
  const view = JSON.parse(JSON.stringify(r)) as Record<string, unknown>;
  blankFromIndex(view, passIdx);
  const canonical = canonicalMarshal(view);
  const signingInput = concat(
    new TextEncoder().encode(MigrationPrefix),
    canonical,
  );
  return ed25519Verify(pub, sig, signingInput);
}

function fieldIndex(field: SigField, mode: MigrationMode): number {
  // Skip old_domain_signature in unilateral mode.
  void mode;
  return SIGNATURE_FIELDS.indexOf(field);
}

function blankFromIndex(
  view: Record<string, unknown>,
  fromIndex: number,
): void {
  for (let i = fromIndex; i < SIGNATURE_FIELDS.length; i++) {
    const field = SIGNATURE_FIELDS[i] ?? "";
    const slot = view[field];
    if (slot === null || slot === undefined) {
      continue;
    }
    if (typeof slot !== "object" || Array.isArray(slot)) {
      continue;
    }
    (slot as Record<string, unknown>).value = "";
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
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
