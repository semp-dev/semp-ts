/**
 * Convenience compose for the full migration record per MIGRATION.md §3.
 *
 * Wraps {@link prepareSignatures} + the four `sign*` passes into a
 * single deterministic composer. Production callers that need the
 * cooperative submit / accept flow use
 * {@link "./orchestrate".buildSubmission} +
 * {@link "./orchestrate".acceptSubmission} instead.
 *
 * @module
 */

import {
  prepareSignatures,
  signNewDomain,
  signNewIdentity,
  signOldDomain,
  signOldIdentity,
} from "./sign.js";
import {
  type MigrationMode,
  type MigrationRecord,
  MigrationPrefix,
  MigrationRecordType,
  MigrationRecordVersion,
} from "./types.js";

/** Inputs to {@link composeMigrationRecord}. */
export interface ComposeMigrationInput {
  mode: MigrationMode;
  /** ULID for the migration record. */
  recordId: string;
  /** ISO 8601 UTC timestamp the migration was effected. */
  migratedAt: string;
  /**
   * ISO 8601 UTC timestamp until which the old domain forwards.
   * REQUIRED when `mode === "cooperative"`. Pass null/undefined in
   * unilateral mode to omit.
   */
  forwardingWindowUntil?: string | null;
  oldAddress: string;
  newAddress: string;

  oldIdentityKeyId: string;
  oldIdentitySeed: Uint8Array;

  newIdentityKeyId: string;
  /** Base64-encoded new identity public key. */
  newIdentityPublicKey: string;
  newIdentitySeed: Uint8Array;

  newDomainKeyId: string;
  newDomainSeed: Uint8Array;

  /** Cooperative mode only. */
  oldDomainKeyId?: string;
  /** Cooperative mode only. */
  oldDomainSeed?: Uint8Array;

  extensions?: Record<string, unknown>;
}

/**
 * Compose a fully-signed migration record. The four (or three, in
 * unilateral mode) signatures are applied in §3.3 chain order.
 */
export function composeMigrationRecord(
  input: ComposeMigrationInput,
): MigrationRecord {
  const r: MigrationRecord = {
    type: MigrationRecordType,
    version: MigrationRecordVersion,
    record_id: input.recordId,
    old_address: input.oldAddress,
    new_address: input.newAddress,
    old_identity_key_id: input.oldIdentityKeyId,
    new_identity_key_id: input.newIdentityKeyId,
    new_identity_public_key: input.newIdentityPublicKey,
    migrated_at: input.migratedAt,
    forwarding_window_until:
      input.forwardingWindowUntil === undefined ||
      input.forwardingWindowUntil === ""
        ? null
        : input.forwardingWindowUntil,
    mode: input.mode,
    old_identity_signature: { algorithm: "", key_id: "", value: "" },
    new_identity_signature: { algorithm: "", key_id: "", value: "" },
    new_domain_signature: { algorithm: "", key_id: "", value: "" },
    old_domain_signature: null,
  };
  if (input.extensions !== undefined) {
    r.extensions = input.extensions;
  }
  prepareSignatures(
    r,
    input.oldIdentityKeyId,
    input.newIdentityKeyId,
    input.newDomainKeyId,
    input.oldDomainKeyId,
  );
  signOldIdentity(r, input.oldIdentitySeed, input.oldIdentityKeyId);
  signNewIdentity(r, input.newIdentitySeed, input.newIdentityKeyId);
  signNewDomain(r, input.newDomainSeed, input.newDomainKeyId);
  if (input.mode === "cooperative") {
    if (
      input.oldDomainSeed === undefined ||
      input.oldDomainKeyId === undefined ||
      input.oldDomainKeyId === ""
    ) {
      throw new Error(
        "migration: cooperative mode requires oldDomainSeed + oldDomainKeyId",
      );
    }
    signOldDomain(r, input.oldDomainSeed, input.oldDomainKeyId);
  }
  return r;
}

// Re-export so old import paths keep working.
export { MigrationPrefix };
