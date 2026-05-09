/**
 * Capability negotiation helpers per HANDSHAKE.md §6.4 + SESSION.md §4.3.
 *
 * `negotiateCapabilities` returns the agreed session parameters from
 * the client's offered capabilities and the server's accepted set,
 * preferring the post-quantum hybrid suite when both peers support
 * it.
 *
 * Selection rules:
 *
 *  - Encryption algorithm: walk the spec preference order (PQ hybrid
 *    first, then baseline). The strongest mutually supported and
 *    library-implemented suite wins.
 *  - Extensions: the intersection of `offered.extensions` and
 *    `accepted.extensions`, in the order they appear in `offered`.
 *  - max_envelope_size / max_batch_size: the smaller of the two
 *    when both sides advertise; the side that advertises when only
 *    one does; absent when neither does.
 *
 * @module
 */

import type { Capabilities, Negotiated } from "./messages.js";

/**
 * Suite preference order from strongest to weakest. Library MUST
 * walk this list and return the first suite that appears in both
 * `offered` AND `accepted` AND is implemented locally.
 *
 * The `pq-kyber768-x25519` hybrid is RECOMMENDED for new
 * deployments per SESSION.md §4; the baseline
 * `x25519-chacha20-poly1305` is mandatory for interoperability
 * per ENVELOPE.md §7.3.2.
 */
export const SuitePreferenceOrder: readonly string[] = [
  "pq-kyber768-x25519",
  "x25519-chacha20-poly1305",
];

/** Library-implemented suite identifiers. */
export const ImplementedSuites: readonly string[] = [
  "pq-kyber768-x25519",
  "x25519-chacha20-poly1305",
];

/** Default capabilities a baseline conformant client advertises. */
export function defaultClientCapabilities(): Capabilities {
  return {
    encryption_algorithms: [
      "pq-kyber768-x25519",
      "x25519-chacha20-poly1305",
    ],
    extensions: [],
  };
}

/** Default capabilities a baseline conformant server accepts. */
export function defaultServerCapabilities(): Capabilities {
  return {
    encryption_algorithms: [
      "pq-kyber768-x25519",
      "x25519-chacha20-poly1305",
    ],
    extensions: [],
  };
}

/**
 * Compute the negotiated session parameters per §6.4. Throws when
 * no encryption suite is mutually supported (caller surfaces this
 * as a `policy_forbidden` rejection).
 */
export function negotiateCapabilities(
  offered: Capabilities,
  accepted: Capabilities,
): Negotiated {
  const offeredSet = new Set(offered.encryption_algorithms);
  const acceptedSet = new Set(accepted.encryption_algorithms);
  const implementedSet = new Set(ImplementedSuites);

  let chosen: string | null = null;
  for (const id of SuitePreferenceOrder) {
    if (offeredSet.has(id) && acceptedSet.has(id) && implementedSet.has(id)) {
      chosen = id;
      break;
    }
  }
  if (chosen === null) {
    throw new Error(
      "handshake: no mutually supported encryption suite",
    );
  }

  const negotiatedExtensions = intersectStrings(
    offered.extensions,
    accepted.extensions,
  );

  // max_envelope_size: the smaller of the two when both sides advertise.
  let maxEnvelope: number | undefined;
  const oMax = (offered as { max_envelope_size?: number }).max_envelope_size;
  const aMax = (accepted as { max_envelope_size?: number }).max_envelope_size;
  if (typeof oMax === "number" && oMax > 0) {
    maxEnvelope = oMax;
  }
  if (typeof aMax === "number" && aMax > 0) {
    maxEnvelope = maxEnvelope === undefined ? aMax : Math.min(maxEnvelope, aMax);
  }

  const out: Negotiated = {
    encryption_algorithm: chosen,
    extensions: negotiatedExtensions,
  };
  if (maxEnvelope !== undefined) {
    out.max_envelope_size = maxEnvelope;
  }
  return out;
}

/** Intersection of `a` and `b`, ordered by `a`. */
function intersectStrings(a: string[], b: string[]): string[] {
  if (a.length === 0 || b.length === 0) {
    return [];
  }
  const set = new Set(b);
  const out: string[] = [];
  for (const v of a) {
    if (set.has(v)) {
      out.push(v);
    }
  }
  return out;
}
