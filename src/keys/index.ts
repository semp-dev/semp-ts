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
