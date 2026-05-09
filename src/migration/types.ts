/**
 * Wire-record types and constants for SEMP_MIGRATION per
 * MIGRATION.md §3.
 *
 * @module
 */

/** Wire-level type discriminators. */
export const MigrationRecordType = "SEMP_MIGRATION";
export const MigrationRecordVersion = "1.0.0";

/** Domain-separation prefix per ENVELOPE.md §4.3. */
export const MigrationPrefix = "SEMP-MIGRATION-RECORD:";

/** Notice message type per §4. */
export const MigrationNoticeType = "SEMP_MIGRATION_NOTICE";

/** Migration mode per §2. */
export type MigrationMode = "cooperative" | "unilateral";

/**
 * Forwarding window bounds per §5.1, in milliseconds.
 *
 *  - Min:         30 days  (cooperative servers MUST NOT accept below this)
 *  - Recommended: 180 days
 *  - Max:         730 days (~2 years; servers MAY decline above this)
 */
export const MinForwardingWindowMs = 30 * 24 * 60 * 60 * 1000;
export const RecommendedForwardingWindowMs = 180 * 24 * 60 * 60 * 1000;
export const MaxForwardingWindowMs = 730 * 24 * 60 * 60 * 1000;

/** Only signature algorithm currently defined for migration records. */
export const SignatureAlgorithmEd25519 = "ed25519";

/** Reusable signature block. */
export interface MigrationSignatureBlock {
  algorithm: string;
  key_id: string;
  value: string;
}

/** SEMP_MIGRATION record per §3.1. */
export interface MigrationRecord {
  type: typeof MigrationRecordType;
  version: string;
  record_id: string;
  old_address: string;
  new_address: string;
  old_identity_key_id: string;
  new_identity_key_id: string;
  /** Base64. */
  new_identity_public_key: string;
  /** ISO 8601 UTC. */
  migrated_at: string;
  /**
   * ISO 8601 UTC, or null when no forwarding is offered (typical
   * for unilateral mode where the old provider is non-cooperative).
   */
  forwarding_window_until: string | null;
  mode: MigrationMode;

  old_identity_signature: MigrationSignatureBlock;
  new_identity_signature: MigrationSignatureBlock;
  new_domain_signature: MigrationSignatureBlock;
  /** Required when mode === "cooperative"; null in unilateral mode. */
  old_domain_signature: MigrationSignatureBlock | null;

  /**
   * Optional extension entries. Every signature in the §3.3 chain
   * covers `extensions`; any content captured here is attested by
   * all signers.
   */
  extensions?: Record<string, unknown>;
}

/**
 * SEMP_MIGRATION_NOTICE message a server sends to inform a sender
 * that the recipient has migrated. Per §4.
 */
export interface MigrationNotice {
  type: typeof MigrationNoticeType;
  version: string;
  /** ULID for the notice. */
  notice_id: string;
  /** Reference to the published migration record. */
  record_id: string;
  /** URL where the migration record can be fetched. */
  record_url: string;
  /** Old address (the one the sender attempted to deliver to). */
  old_address: string;
  /** New address the sender SHOULD redirect to. */
  new_address: string;
  /** Migration mode (informational). */
  mode: MigrationMode;
  /** ISO 8601 UTC timestamp the notice was issued. */
  issued_at: string;
}

/** Rejection wrapper a sender returns when it refuses to honor a notice. */
export interface MigrationNoticeRejection {
  notice: MigrationNotice;
  reason: string;
}
