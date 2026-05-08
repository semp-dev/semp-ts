/**
 * Layer 1 cryptographic primitives. Mirrors the semp-go `crypto`
 * package: KDF, MAC, signature, KEM, AEAD, and suite glue. The
 * implementation is the audited @noble suite end-to-end; no native
 * bindings, browser-compatible.
 *
 * @module
 */

export {
  newHKDFSHA512,
  deriveSessionKeys,
  deriveSessionKeysWithResumption,
  deriveResumedSessionKeys,
  deriveRekeyKeys,
  InfoSessionEncC2S,
  InfoSessionEncS2C,
  InfoSessionMACC2S,
  InfoSessionMACS2C,
  InfoSessionEnvMAC,
  InfoSessionResumption,
  SessionKeyLength,
  type KDF,
  type SessionKeys,
} from "./kdf.js";

export { computeMAC, verifyMAC } from "./mac.js";

export { type AEADAlgorithm, aeadOpen, aeadSeal } from "./aead.js";

export { argon2idKDF } from "./argon2.js";

export {
  HybridCiphertextSize,
  HybridPrivateKeySize,
  HybridPublicKeySize,
  HybridSharedSecretSize,
  Kyber768CiphertextSize,
  Kyber768PrivateKeySize,
  Kyber768PublicKeySize,
  Kyber768SharedKeySize,
  X25519Size,
  hybridDecapsulate,
  hybridPrivateKeyFromKyberAndX25519,
  kyber768Decapsulate,
  kyber768EncapsulateDeterministic,
  kyber768KeyPairFromSeed,
  x25519Agree,
  x25519PublicKey,
} from "./kem.js";
