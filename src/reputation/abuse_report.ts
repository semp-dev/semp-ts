/**
 * SEMP_ABUSE_REPORT compose helpers per REPUTATION.md §3.2 / §3.5 /
 * §3.7.
 *
 * Abuse reports flow user → home-server over an authenticated
 * session - the handshake identifies the reporting user so the
 * report itself does NOT carry its own signature. The report's
 * evidence MAY include decrypted envelope fragments, in which case
 * an embedded {@link DisclosureAuthorization} signed by the
 * affected user is required per §3.5 + §3.7.
 *
 * @module
 */

import {
  type AbuseCategory,
  type AbuseReport,
  type DisclosureAuthorization,
  type Evidence,
  AbuseReportType,
  Version,
} from "./types.js";
import {
  authAllowsBrief,
  authAllowsEnclosure,
  verifyDisclosureAuthorization,
} from "./sign.js";

/** Inputs to {@link newAbuseReport}. */
export interface AbuseReportInput {
  /** ULID for the report. */
  id: string;
  reporter: string;
  reported_domain: string;
  reported_address?: string;
  category: AbuseCategory | string;
  evidence: Evidence;
  description?: string;
  extensions?: Record<string, unknown>;
  /** Optional clock; defaults to `() => new Date()`. */
  nowFn?: () => Date;
}

/**
 * Construct a SEMP_ABUSE_REPORT with `type` / `version` /
 * `timestamp` / `extensions` pre-populated.
 *
 * Throws when required fields are missing.
 */
export function newAbuseReport(input: AbuseReportInput): AbuseReport {
  if (input.id === "") {
    throw new Error("reputation: abuse report missing id");
  }
  if (input.reporter === "") {
    throw new Error("reputation: abuse report missing reporter");
  }
  if (input.reported_domain === "") {
    throw new Error("reputation: abuse report missing reported_domain");
  }
  if ((input.category as string) === "") {
    throw new Error("reputation: abuse report missing category");
  }
  const r: AbuseReport = {
    type: AbuseReportType,
    version: Version,
    id: input.id,
    reporter: input.reporter,
    reported_domain: input.reported_domain,
    category: input.category,
    timestamp: isoSecond((input.nowFn ?? (() => new Date()))()),
    evidence: input.evidence,
    extensions: input.extensions ?? {},
  };
  if (input.reported_address !== undefined && input.reported_address !== "") {
    r.reported_address = input.reported_address;
  }
  if (input.description !== undefined && input.description !== "") {
    r.description = input.description;
  }
  return r;
}

/**
 * Lookup hook used by {@link validateEvidence} to resolve a user's
 * identity public key. Returning `null` means "unknown user" -
 * callers MUST treat that as a §3.7 verification failure.
 */
export type UserKeyLookup = (user: string) => Promise<Uint8Array | null>;

/**
 * Walk an evidence payload and enforce the §3.7 rule: decrypted
 * content requires a valid {@link DisclosureAuthorization} signed
 * by the affected user.
 *
 * Metadata-only evidence is always acceptable - postmark + seal
 * data is verifiable from the sender's published domain key without
 * disclosing user content.
 *
 * Sealed evidence with disclosed brief / enclosure requires:
 *
 *  1. An embedded `disclosure_authorization`;
 *  2. The authorization's `scope` covers what's actually disclosed;
 *  3. The authorization's signature verifies under the affected
 *     user's identity public key.
 *
 * Throws on the first violation.
 */
export async function validateEvidence(
  ev: Evidence,
  userKeyLookup: UserKeyLookup | null,
): Promise<void> {
  if (ev.type === "envelope_metadata") {
    return;
  }
  if (ev.type !== "sealed_evidence") {
    throw new Error(
      `reputation: unknown evidence type ${JSON.stringify((ev as { type: string }).type)}`,
    );
  }
  for (let i = 0; i < ev.envelopes.length; i++) {
    const env = ev.envelopes[i]!;
    const discloses =
      env.disclosed_brief !== undefined || env.disclosed_enclosure !== undefined;
    if (!discloses) {
      continue;
    }
    if (env.disclosure_authorization === undefined) {
      throw new Error(
        `reputation: envelope[${i}]: decrypted content without disclosure authorization`,
      );
    }
    const auth = env.disclosure_authorization;
    if (env.disclosed_brief !== undefined && !authAllowsBrief(auth)) {
      throw new Error(
        `reputation: envelope[${i}]: brief disclosure outside authorized scope ${JSON.stringify(auth.scope)}`,
      );
    }
    if (
      env.disclosed_enclosure !== undefined &&
      !authAllowsEnclosure(auth)
    ) {
      throw new Error(
        `reputation: envelope[${i}]: enclosure disclosure outside authorized scope ${JSON.stringify(auth.scope)}`,
      );
    }
    if (userKeyLookup === null) {
      throw new Error(
        `reputation: envelope[${i}]: sealed evidence not accepted (handler lacks user key lookup)`,
      );
    }
    const pub = await userKeyLookup(auth.user);
    if (pub === null || pub.length === 0) {
      throw new Error(
        `reputation: envelope[${i}]: unknown user ${JSON.stringify(auth.user)} in disclosure authorization`,
      );
    }
    if (!verifyDisclosureAuthorization(auth, pub)) {
      throw new Error(
        `reputation: envelope[${i}]: disclosure authorization signature did not verify`,
      );
    }
  }
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

// Convenience re-export so callers can import everything from one place.
export type { DisclosureAuthorization };
