/**
 * Wire-record types for SEMP account recovery per RECOVERY.md.
 *
 * @module
 */

/** Wire-level type discriminators per RECOVERY.md. */
export const SuccessorRecordType = "SEMP_SUCCESSOR";
export const RecoverySetManifestType = "SEMP_RECOVERY_SET_MANIFEST";
export const RecoveryShareRecordType = "SEMP_RECOVERY_SHARE";
export const BundleType = "SEMP_BACKUP_BUNDLE";
export const RecordVersion = "1.0.0";

/** Domain-separation prefixes per ENVELOPE.md §4.3. */
export const SuccessorRecordPrefix = "SEMP-SUCCESSOR-RECORD:";
export const RecoveryManifestPrefix = "SEMP-RECOVERY-MANIFEST:";
export const RecoveryShareSignaturePrefix = "SEMP-RECOVERY-SHARE:";
export const RecoveryBundlePrefix = "SEMP-RECOVERY-BUNDLE:";

/** Only signature algorithm currently defined for recovery records. */
export const SignatureAlgorithmEd25519 = "ed25519";

/** Bundle payload AEAD per §2.5: xchacha20-poly1305 with 24-byte nonce. */
export const BundlePayloadAEAD = "xchacha20-poly1305";

/** Bundle KDF per §2.5: Argon2id. */
export const KDFAlgorithmArgon2id = "argon2id";

/** Argon2id parameter floors per §2.5. */
export const MinKDFMemoryKB = 65_536;
export const MinKDFIterations = 2;
export const MinKDFParallelism = 1;
export const MinKDFSaltBytes = 16;
export const RecommendedKDFMemoryKB = 262_144;
export const RecommendedKDFIterations = 3;
export const RecommendedKDFParallelism = 4;

/** Reusable signature block. */
export interface RecoverySignatureBlock {
  algorithm: string;
  key_id: string;
  value: string;
}

/**
 * SEMP_SUCCESSOR per §7.2 — links a prior identity key to a new one
 * after recovery or rotation. Carries three independent signatures
 * so third-party domains can verify continuity without needing the
 * prior identity private key.
 */
export interface SuccessorRecord {
  type: typeof SuccessorRecordType;
  version: string;
  user_id: string;
  prior_key_id: string;
  new_key_id: string;
  /** Base64. */
  new_public_key: string;
  /** ISO 8601 UTC. */
  recovered_at: string;
  recovery_signature: RecoverySignatureBlock;
  new_key_signature: RecoverySignatureBlock;
  domain_signature: RecoverySignatureBlock;
}

/** Embedded device-key block carried in each manifest contributor entry. */
export interface DeviceIdentityPubkey {
  algorithm: string;
  /** Base64. */
  public_key: string;
  key_id: string;
}

/** One device's binding to a Shamir share inside a manifest. */
export interface RecoveryContributor {
  share_index: number;
  device_id: string;
  device_identity_pubkey: DeviceIdentityPubkey;
}

/**
 * SEMP_RECOVERY_SET_MANIFEST per §5.2 — binds each Shamir share
 * index to a specific device's identity public key.
 */
export interface RecoverySetManifest {
  type: typeof RecoverySetManifestType;
  version: string;
  bundle_id: string;
  threshold: number;
  total_shares: number;
  contributors: RecoveryContributor[];
  /** ISO 8601 UTC. */
  issued_at: string;
  signature: RecoverySignatureBlock;
}

/**
 * SEMP_RECOVERY_SHARE per §5.3 — one device's holding of a Shamir
 * share, authenticated by the device's identity-key signature.
 */
export interface RecoveryShareRecord {
  type: typeof RecoveryShareRecordType;
  version: string;
  bundle_id: string;
  share_index: number;
  device_id: string;
  threshold: number;
  total_shares: number;
  /** Base64. */
  share_value: string;
  /** ISO 8601 UTC. */
  issued_at: string;
  device_signature: RecoverySignatureBlock;
}

/** KDF parameter block carried in a backup bundle per §2.1 / §2.5. */
export interface BundleKDF {
  algorithm: string;
  /** Base64 salt. */
  salt: string;
  memory_kb: number;
  iterations: number;
  parallelism: number;
}

/** Public half of the deterministic recovery key pair per §3.3. */
export interface RecoveryVerifyPK {
  algorithm: string;
  /** Base64. */
  public_key: string;
}

/**
 * SEMP_BACKUP_BUNDLE per §2.1. Signed by the user's currently active
 * identity private key under the SEMP-RECOVERY-BUNDLE: prefix.
 */
export interface BackupBundle {
  type: typeof BundleType;
  version: string;
  user_id: string;
  bundle_id: string;
  /** ISO 8601 UTC. */
  created_at: string;
  /** Bundle id this one supersedes; nullable. */
  supersedes: string | null;
  kdf: BundleKDF;
  payload_algorithm: string;
  /** Base64 24-byte XChaCha20-Poly1305 nonce. */
  payload_nonce: string;
  /** Base64 AEAD output. */
  encrypted_payload: string;
  recovery_verify_pk: RecoveryVerifyPK;
  signature: RecoverySignatureBlock;
}
