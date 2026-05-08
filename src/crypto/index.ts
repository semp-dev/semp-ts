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
