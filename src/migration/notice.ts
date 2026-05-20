/**
 * Migration notice body construction per MIGRATION.md §5.3.
 *
 * The migration notice is a body field attached to a
 * policy_forbidden envelope rejection that the old provider emits
 * during the migration notice window. It points the sender at the
 * recipient's new address and at the published migration record
 * (URL + record_id) so the sender's stack can fetch and verify the
 * record before redirecting.
 *
 * After the notice window elapses the old provider stops attaching
 * the notice and handles the old address the same way it handles a
 * non-existent address.
 *
 * @module
 */

import {
  type MigrationNotice,
  type MigrationNoticeRejection,
  type MigrationRecord,
  MigrationRecordVersion,
} from "./types.js";

/** Inputs to {@link buildMigrationNotice}. */
export interface BuildMigrationNoticeInput {
  record: MigrationRecord;
  /**
   * Optional URL template the operator uses to expose published
   * records (typically
   * "https://<old-domain>/.well-known/semp/migration/<record_id>"
   * per §5.3 example). When the template contains the literal
   * "<record_id>" placeholder the record's ID is substituted;
   * otherwise the template is used verbatim. Omit to exclude
   * migration_record_url from the notice.
   */
  recordUrlPattern?: string;
}

/**
 * Build a {@link MigrationNotice} from a published migration
 * record. The notice is unsigned; the receiving sender verifies
 * the underlying record by fetching migration_record_url and
 * running `verifyMigrationRecord`.
 */
export function buildMigrationNotice(
  input: BuildMigrationNoticeInput,
): MigrationNotice {
  const notice: MigrationNotice = {
    new_address: input.record.new_address,
    migration_record_id: input.record.record_id,
  };
  if (input.recordUrlPattern !== undefined && input.recordUrlPattern !== "") {
    notice.migration_record_url = input.recordUrlPattern.includes("<record_id>")
      ? input.recordUrlPattern.replaceAll(
          "<record_id>",
          input.record.record_id,
        )
      : input.recordUrlPattern;
  }
  return notice;
}

/**
 * Wrap a {@link MigrationNotice} in the §5.3 SEMP_ENVELOPE
 * step=rejected response. The reason is a human-readable
 * description; the spec example uses "Recipient has migrated."
 */
export function newMigrationNoticeRejection(
  notice: MigrationNotice,
  reason = "Recipient has migrated.",
): MigrationNoticeRejection {
  return {
    type: "SEMP_ENVELOPE",
    step: "rejected",
    version: MigrationRecordVersion,
    reason_code: "policy_forbidden",
    reason,
    migration_notice: notice,
  };
}
