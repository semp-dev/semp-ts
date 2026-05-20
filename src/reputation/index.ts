/**
 * Reputation layer per REPUTATION.md.
 *
 * Wire records (observation, trust-observations envelope, abuse
 * report, disclosure authorization), bucketing + dedup helpers,
 * sign / verify primitives, in-memory observation store with
 * scoring, gossip hash, and PoW challenge issuer + ledger.
 *
 * @module
 */

export {
  type AbuseCategory,
  type AbuseReport,
  type Assessment,
  type DisclosureAuthorization,
  type DisclosureScope,
  type Evidence,
  type EvidenceHash,
  type GossipHash,
  type Metrics,
  type Observation,
  type ReputationSignature,
  type SealedEnvelopeEvidence,
  type TrustObservations,
  type Window,
  AbuseReportType,
  MaxEvidenceBytes,
  MaxMetricBucket,
  MaxObservationBytes,
  ObservationType,
  ObservationsEnvelopeType,
  PublicationPath,
  Version,
  isKnownAbuseCategory,
} from "./types.js";

export {
  EvidenceHashMismatchError,
  ObservationOversizedError,
  checkObservationSize,
  validateEvidenceFields,
  verifyEvidenceBytes,
} from "./evidence.js";

export {
  MinPublishVolumeEnvelopes,
  allMetricsZero,
  eligibleForPublication,
  meetsPublishVolume,
} from "./eligibility.js";

export {
  type ReferenceEntry,
  type References,
  ReferencesPrefix,
  ReferencesType,
  ReferencesVersion,
  signReferences,
  validateReferences,
  verifyReferences,
} from "./references.js";

export {
  applyBucketing,
  bucketize,
  dedupeAbuseCategories,
} from "./bucketize.js";

export {
  SignatureAlgorithmEd25519,
  authAllowsBrief,
  authAllowsEnclosure,
  signDisclosureAuthorization,
  signObservation,
  signTrustObservations,
  validateAbuseReport,
  verifyDisclosureAuthorization,
  verifyObservation,
  verifyTrustObservations,
} from "./sign.js";

export {
  type Score,
  ObservationStore,
  classifyScore,
} from "./observation_store.js";

export { computeGossipHash } from "./gossip.js";

export {
  type PoWChallenge,
  ChallengeLedger,
  DefaultChallengeTTLMs,
  DifficultyBaseline,
  DifficultyHostile,
  DifficultyRelaxed,
  DifficultySuspicious,
  DomainAgeGateDays,
  MinPrefixBytes,
  PoWAlgorithm,
  challengePrefixBase64,
  difficultyForAge,
  difficultyForAssessment,
  issueChallenge,
} from "./pow.js";

export {
  type WHOIS,
  MinDomainAgeMs,
  meetsMinAge,
} from "./whois.js";

export {
  type AbuseReportInput,
  type UserKeyLookup,
  newAbuseReport,
  validateEvidence,
} from "./abuse_report.js";

export {
  type FetchTrustObservationsOptions,
  TrustGossipMaxBytes,
  fetchTrustObservations,
} from "./gossip_fetch.js";
