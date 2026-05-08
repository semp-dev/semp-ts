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

/** Abuse category per §3.4 + ERRORS.md §9. */
export type AbuseCategory =
  | "spam"
  | "harassment"
  | "phishing"
  | "malware"
  | "protocol_abuse"
  | "impersonation"
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
  evidence_uri?: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  /** ISO 8601 UTC hard expiry. */
  expires: string;
  signature: ReputationSignature;
  /** Always emitted (even when empty) so canonical bytes are stable. */
  extensions: Record<string, unknown>;
}

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
