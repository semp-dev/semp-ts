/**
 * Migration layer per MIGRATION.md.
 *
 * Wire records (4-signature MIGRATION chain), signing primitives,
 * full submission/acceptance flow, lockout registry, notice
 * messages, third-party verification hooks, publication store.
 *
 * @module
 */

export {
  type MigrationMode,
  type MigrationNotice,
  type MigrationNoticeRejection,
  type MigrationRecord,
  type MigrationSignatureBlock,
  MaxNoticeWindowMs,
  MigrationPrefix,
  MigrationRecordType,
  MigrationRecordVersion,
  MinNoticeWindowMs,
  RecommendedNoticeWindowMs,
  SignatureAlgorithmEd25519,
} from "./types.js";

export {
  checkMigratedAtBound,
  prepareSignatures,
  signNewDomain,
  signNewIdentity,
  signOldDomain,
  signOldIdentity,
  validateMigrationRecord,
  verifyMigrationPass,
  verifyMigrationRecord,
} from "./sign.js";

export {
  type ComposeMigrationInput,
  composeMigrationRecord,
} from "./migration.js";

export {
  type AcceptSubmissionInput,
  type BuildSubmissionInput,
  type ThirdPartyHook,
  type ThirdPartyPolicy,
  acceptSubmission,
  applyThirdPartyPolicy,
  buildSubmission,
} from "./orchestrate.js";

export {
  type LockoutRegistry,
  type LockoutReservation,
  InMemoryLockoutRegistry,
} from "./lockout.js";

export {
  type BuildMigrationNoticeInput,
  buildMigrationNotice,
  newMigrationNoticeRejection,
} from "./notice.js";

export {
  type PublicationStore,
  InMemoryPublicationStore,
} from "./publication_store.js";
