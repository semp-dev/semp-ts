/**
 * Key transparency layer per TRANSPARENCY.md.
 *
 * RFC 6962 Merkle math + STH sign/verify/freshness +
 * append-only Log with inclusion/consistency proof generation.
 *
 * @module
 */

export {
  type ConsistencyProof,
  type InclusionProof,
  type LogEntry,
  type LogEntryEvent,
  type LogKeyType,
  type SignedTreeHead,
  type TransparencySignature,
  InteriorPrefix,
  LeafPrefix,
  LogEntryVersion,
  MaxSTHFreshnessMs,
  SignedTreeHeadVersion,
} from "./types.js";

export {
  auditPath,
  encodeHash,
  hashInterior,
  hashLeaf,
  hashLeafFromEntry,
  largestPowerOfTwoLessThan,
  subproof,
  subtreeRoot,
  verifyConsistencyProof,
  verifyInclusionProof,
} from "./merkle.js";

export {
  type SignSTHInput,
  type SignSTHResult,
  SignatureAlgorithmEd25519,
  TransparencySTHPrefix,
  checkSTHFresh,
  signSTH,
  validateLogEntry,
  validateSTH,
  verifySTH,
} from "./sign.js";

export { type LogConfig, Log } from "./log.js";
