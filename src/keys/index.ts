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
