/**
 * Identity-key primitives. Layer 1 surface of `KEY.md`: Ed25519
 * sign / verify and the SEMP fingerprint format. Higher-level
 * registry / revocation logic lands in later waves.
 *
 * @module
 */

export {
  PublicKeySize,
  SeedSize,
  SignatureSize,
  fingerprint,
  publicKeyFromSeed,
  sign,
  verify,
} from "./sign.js";

export {
  type SignSignedDocResult,
  type SignSignedDocSpec,
  type VerifySignedDocResult,
  type VerifySignedDocSpec,
  signSignedDoc,
  verifySignedDoc,
} from "./signed.js";

export {
  type AddressIdentity,
  type CertificateSignature,
  type DeviceCertificate,
  type EntityType,
  type MatcherMode,
  type RateLimitTier,
  type Scope,
  type ScopeEntry,
  type ScopeMatcher,
  type ScopeResource,
  type SignDeviceCertificateInput,
  type SignDeviceCertificateResult,
  type ValidateOptions,
  DeviceAuthorizePrefix,
  DeviceCertificateType,
  MaxDeviceCertificateLifetimeMs,
  MaxScopeMatcherEntries,
  MaxScopeRateLimitTiers,
  scopeAllowsRecipient,
  scopeAllowsSender,
  signDeviceCertificate,
  validateDeviceCertificate,
  validateScope,
  verifyDeviceCertificate,
} from "./device_certificate.js";

export {
  type DeviceAuthorization,
  type DeviceAuthorizationMethod,
  type DeviceDirectory,
  type DeviceDirectoryEntry,
  type DeviceRegistration,
  type DeviceRevocation,
  type DeviceRevocationReason,
  type DeviceRole,
  type KeysSignature,
  type SignDeviceAuthorizationInput,
  DeviceAuthorizeRecordPrefix,
  DeviceDirectoryPrefix,
  DeviceDirectoryType,
  DeviceRecordVersion,
  DeviceRegisterPrefix,
  DeviceRegistrationStep,
  DeviceRegistrationType,
  DeviceRevocationPrefix,
  DeviceRevocationType,
  findDevice,
  requiresIdentityRotation,
  signDeviceAuthorization,
  signDeviceDirectory,
  signDeviceRegistration,
  signDeviceRevocation,
  validateDeviceDirectory,
  validateDeviceRegistration,
  validateDeviceRevocation,
  verifyDeviceAuthorization,
  verifyDeviceDirectory,
  verifyDeviceRegistration,
  verifyDeviceRevocation,
} from "./device_records.js";

export {
  type PublicationSignature,
  type Revocation,
  type RevocationPublication,
  type RevocationReason,
  type RevokedKeyEntry,
  RevocationPrefix,
  RevocationPublicationType,
  RevocationVersion,
  isReversibleReason,
  signRevocationPublication,
  validateRevocationPublication,
  verifyRevocationPublication,
} from "./key_revocation.js";

export {
  type KeyRecord,
  type KeysClientStream,
  type KeysRequest,
  type KeysRequestStep,
  type KeysResponse,
  type KeysResponseResult,
  type KeysResultStatus,
  type KeysSignatureBlock,
  KeysRequestType,
  KeysRequestVersion,
  fetchKeys,
  newKeysRequest,
  newKeysResponse,
  validateKeysRequest,
} from "./request.js";

export {
  type CompromiseRotation,
  type CompromiseRotationInput,
  buildCompromiseRotation,
  verifyCompromiseRotation,
} from "./compromise.js";

export {
  type CertificateCheck,
  DirectoryCache,
  DirectoryRollbackError,
} from "./directory_cache.js";

export {
  type DirectoryStateConfig,
  DirectoryState,
  DirectoryStore,
} from "./directory_state.js";

export {
  type KeyStore,
  type KeyStoreRecord,
  type KeyStoreSignature,
  type KeyType,
  type PrivateKeyStore,
  InMemoryKeyStore,
} from "./store.js";
