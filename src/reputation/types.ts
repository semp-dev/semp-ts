/**
 * Wire-record types for SEMP reputation per REPUTATION.md.
 *
 * @module
 */

/** `type` discriminators per REPUTATION.md. */
export const ObservationType = "SEMP_TRUST_OBSERVATION";
export const ObservationsEnvelopeType = "SEMP_TRUST_OBSERVATIONS";
export const AbuseReportType = "SEMP_ABUSE_REPORT";
export const Version = "1.0.0";

/** Reputation publication path per §5. */
export const PublicationPath = "/.well-known/semp/reputation/";

/** Assessment classification per §4.6. */
export type Assessment = "trusted" | "neutral" | "suspicious" | "hostile";

/**
 * Abuse category per §3.4 + ERRORS.md §9.
 *
 * `observation_record_abuse` covers misbehavior in the trust-
 * gossip observation records themselves: oversized records,
 * evidence-hash mismatches, hostile or non-conforming evidence_uri
 * content, fabricated metrics, and systematic publication of
 * unverifiable assessments.
 */
export type AbuseCategory =
  | "spam"
  | "harassment"
  | "phishing"
  | "malware"
  | "protocol_abuse"
  | "impersonation"
  | "observation_record_abuse"
  | "other";

/**
 * Report whether `c` is one of the categories defined in §3.4.
 * Unknown categories are permitted for forward compatibility.
 */
export function isKnownAbuseCategory(c: string): c is AbuseCategory {
  switch (c) {
    case "spam":
    case "harassment":
    case "phishing":
    case "malware":
    case "protocol_abuse":
    case "impersonation":
    case "observation_record_abuse":
    case "other":
      return true;
    default:
      return false;
  }
}

/** Reusable signature block. */
export interface ReputationSignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/** Time window of an Observation per §4.4. */
export interface Window {
  /** ISO 8601 UTC. */
  start: string;
  /** ISO 8601 UTC. */
  end: string;
}

/** Quantitative payload of an Observation per §4.5. */
export interface Metrics {
  envelopes_received: number;
  envelopes_rejected: number;
  abuse_reports: number;
  abuse_categories?: AbuseCategory[];
  unique_senders_observed?: number;
  handshakes_completed?: number;
  handshakes_rejected?: number;
}

/** Cap applied by Bucketize: counts at/above this clamp here. */
export const MaxMetricBucket = 1 << 20;

/**
 * Binds the bytes returned by an observation's `evidence_uri` to
 * the signed observation record per REPUTATION.md §4.2 / §5.5.1.
 * Consumers MUST compute the digest of the fetched bytes under
 * `algorithm` and MUST treat a mismatch as a verification failure
 * equivalent to a signature failure.
 */
export interface EvidenceHash {
  /** Digest algorithm identifier. "sha-256" is the only value currently defined. */
  algorithm: string;
  /** Base64-encoded digest of the evidence bytes. */
  value: string;
}

/** Single signed observation record per §4.2. */
export interface Observation {
  type: typeof ObservationType;
  version: string;
  id: string;
  observer: string;
  subject: string;
  window: Window;
  metrics: Metrics;
  assessment: Assessment;
  evidence_available: boolean;
  /**
   * URL where evidence can be fetched. REQUIRED when
   * `evidence_available` is true; MUST be absent when false.
   */
  evidence_uri?: string;
  /**
   * Digest binding fetched evidence to the signed observation per
   * §5.5.1. REQUIRED when `evidence_available` is true; MUST be
   * absent when false.
   */
  evidence_hash?: EvidenceHash;
  /** ISO 8601 UTC. */
  timestamp: string;
  /** ISO 8601 UTC hard expiry. */
  expires: string;
  signature: ReputationSignature;
  /** Always emitted (even when empty) so canonical bytes are stable. */
  extensions: Record<string, unknown>;
}

/**
 * §4.6.1 hard upper bound on the canonical UTF-8 JSON form of a
 * single SEMP_TRUST_OBSERVATION record. Servers MUST reject larger
 * records as malformed and MUST NOT propagate them.
 */
export const MaxObservationBytes = 16384;

/**
 * §5.5.2 RECOMMENDED upper bound on a single evidence-fetch
 * response body. Operators MAY tighten further via local
 * configuration; consumers MUST cap their fetch at a
 * locally-configured limit.
 */
export const MaxEvidenceBytes = 1024 * 1024;

/** Publication envelope carrying a list of observations per §5.1. */
export interface TrustObservations {
  type: typeof ObservationsEnvelopeType;
  version: string;
  /** Observer domain. */
  observer: string;
  /** Subject domain (or empty when the response is a per-observer index). */
  subject: string;
  observations: Observation[];
  /** ISO 8601 UTC. */
  timestamp: string;
  signature: ReputationSignature;
}

/** Publishable hash summary per §5. */
export interface GossipHash {
  domain: string;
  /** Lowercase hex SHA-256. */
  hash: string;
  algorithm: string;
  /** ISO 8601 UTC. */
  as_of: string;
}

/** Disclosure scope per §3.5. */
export type DisclosureScope =
  | "brief_only"
  | "enclosure_only"
  | "brief_and_enclosure";

/** Affected user's signed permission to include decrypted content per §3.5 + §3.7. */
export interface DisclosureAuthorization {
  user: string;
  /** ISO 8601 UTC. */
  authorized_at: string;
  scope: DisclosureScope;
  signature: ReputationSignature;
}

/** Sealed-evidence envelope-shaped record per §3.5. */
export interface SealedEnvelopeEvidence {
  postmark: Record<string, unknown>;
  seal: Record<string, unknown>;
  disclosed_brief?: Record<string, unknown>;
  disclosed_enclosure?: Record<string, unknown>;
  disclosure_authorization?: DisclosureAuthorization;
}

/** Polymorphic evidence payload per §3.5. */
export type Evidence =
  | {
      type: "envelope_metadata";
      postmark_ids?: string[];
      count?: number;
      /** ISO 8601 interval string. */
      window?: string;
    }
  | {
      type: "sealed_evidence";
      envelopes: SealedEnvelopeEvidence[];
    };

/** SEMP_ABUSE_REPORT message per §3.2. */
export interface AbuseReport {
  type: typeof AbuseReportType;
  version: string;
  id: string;
  reporter: string;
  reported_domain: string;
  reported_address?: string;
  category: AbuseCategory | string;
  /** ISO 8601 UTC. */
  timestamp: string;
  evidence: Evidence;
  description?: string;
  extensions: Record<string, unknown>;
}
