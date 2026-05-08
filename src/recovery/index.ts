/**
 * Recovery layer per RECOVERY.md.
 *
 * Wire records (successor, recovery-set manifest, share record,
 * backup bundle), Shamir secret splitting + recombination,
 * sign / verify primitives, and manifest cross-check.
 *
 * The high-level recovery flow (Argon2id-derived bundle payload
 * encryption / decryption) sits one layer up; this module ships
 * the record-level primitives those flows compose.
 *
 * @module
 */

export {
  type BackupBundle,
  type BundleKDF,
  type DeviceIdentityPubkey,
  type RecoveryContributor,
  type RecoverySetManifest,
  type RecoveryShareRecord,
  type RecoverySignatureBlock,
  type RecoveryVerifyPK,
  type SuccessorRecord,
  BundlePayloadAEAD,
  BundleType,
  KDFAlgorithmArgon2id,
  MinKDFIterations,
  MinKDFMemoryKB,
  MinKDFParallelism,
  MinKDFSaltBytes,
  RecommendedKDFIterations,
  RecommendedKDFMemoryKB,
  RecommendedKDFParallelism,
  RecordVersion,
  RecoveryBundlePrefix,
  RecoveryManifestPrefix,
  RecoverySetManifestType,
  RecoveryShareRecordType,
  RecoveryShareSignaturePrefix,
  SignatureAlgorithmEd25519,
  SuccessorRecordPrefix,
  SuccessorRecordType,
} from "./types.js";

export {
  type RandSource,
  type ShamirShare,
  MaxShamirTotalShares,
  MinShamirThreshold,
  combineShares,
  splitSecret,
} from "./shamir.js";

export {
  checkShareMatchesManifest,
  prepareSuccessorSignatures,
  signManifest,
  signShareRecord,
  signSuccessorDomain,
  signSuccessorNewKey,
  signSuccessorRecovery,
  validateManifest,
  validateShareRecord,
  validateSuccessorRecord,
  verifyManifest,
  verifyShareRecord,
  verifySuccessorRecord,
  verifySuccessorTwoSignatures,
} from "./sign.js";

export { signBundle, validateBundle, verifyBundle } from "./bundle.js";
