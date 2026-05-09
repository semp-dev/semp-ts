/**
 * Recovery layer per RECOVERY.md.
 *
 * Wire records (successor, recovery-set manifest, share record,
 * backup bundle), Shamir secret splitting + recombination, full
 * sign / verify primitives, manifest cross-check, Argon2id-derived
 * bundle-payload encryption + decryption, recovery key derivation,
 * and a reference {@link BundleStore}.
 *
 * @module
 */

export {
  type BackupBundle,
  type BundleKDF,
  type BundlePayload,
  type DeviceIdentityPubkey,
  type EncryptionKey,
  type IdentityKey,
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

export {
  type SecretForm,
  MinPassphraseBytes,
  RecoverySignKeyInfo,
  decryptBundlePayload,
  deriveBundleKey,
  deriveRecoverySignKey,
  encryptBundlePayload,
  normalizeRecoverySecret,
} from "./bundle_crypto.js";

export {
  type BundleStore,
  InMemoryBundleStore,
  MinSupersededRetentionMs,
} from "./bundle_store.js";

export {
  type CrossCheckReason,
  type DirectoryView,
  ManifestCrossCheckError,
  crossCheckManifestContributors,
} from "./manifest_crosscheck.js";
