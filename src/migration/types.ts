/**
 * Wire-record types and constants for SEMP_MIGRATION per
 * MIGRATION.md §3 and §5.
 *
 * @module
 */

/** Wire-level type discriminators. */
export const MigrationRecordType = "SEMP_MIGRATION";
export const MigrationRecordVersion = "1.0.0";

/** Domain-separation prefix per ENVELOPE.md §4.3. */
export const MigrationPrefix = "SEMP-MIGRATION-RECORD:";

/** Migration mode per §2. */
export type MigrationMode = "cooperative" | "unilateral";

/**
 * Notice window bounds per §5.1, in milliseconds.
 *
 *  - Min:         30 days  (cooperative servers MUST NOT accept below this)
 *  - Recommended: 180 days
 *  - Max:         730 days (~2 years; servers MAY decline above this)
 */
export const MinNoticeWindowMs = 30 * 24 * 60 * 60 * 1000;
export const RecommendedNoticeWindowMs = 180 * 24 * 60 * 60 * 1000;
export const MaxNoticeWindowMs = 730 * 24 * 60 * 60 * 1000;

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
   * ISO 8601 UTC end of the migration notice window. During this
   * window the old provider returns policy_forbidden with a
   * migration_notice body and key fetches carry a migration_to
   * field. After the window the old provider stops returning the
   * notice and handles the old address the same way it handles
   * non-existent addresses. Null when no notice window is offered
   * (typical for unilateral mode where the old provider is
   * non-cooperative).
   */
  notice_window_until: string | null;
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
 * Migration notice body field attached to a policy_forbidden
 * envelope rejection emitted by the old provider during the
 * migration notice window per §5.3. The sender's client surfaces
 * the new_address to the user and offers an address-book update;
 * the client MUST NOT auto-redirect correspondence.
 */
export interface MigrationNotice {
  /** Address the sender SHOULD redirect to after user confirmation. */
  new_address: string;
  /** ULID of the published migration record. */
  migration_record_id: string;
  /** Optional URL where the migration record can be fetched. */
  migration_record_url?: string;
}

/**
 * Envelope-rejection wire shape carrying a {@link MigrationNotice}
 * body. The old provider's HTTP layer emits this as the
 * SEMP_ENVELOPE step=rejected response for envelopes addressed to
 * a migrated address during the notice window per §5.3.
 */
export interface MigrationNoticeRejection {
  type: "SEMP_ENVELOPE";
  step: "rejected";
  version: string;
  reason_code: "policy_forbidden";
  reason: string;
  migration_notice: MigrationNotice;
}
